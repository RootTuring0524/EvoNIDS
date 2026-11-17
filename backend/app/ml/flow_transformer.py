"""Flow Transformer with Masked Feature Modeling (MFM) pretraining.

Design follows the project blueprint (§7): every flow field becomes a token that
carries both a value and its field identity, a shallow Transformer encoder learns
cross-field dependencies, and a masked-reconstruction objective (mask ~15% of the
fields, compute the loss only on the masked ones) supplies the self-supervised
signal. The shared encoder then feeds two downstream heads:

* known-attack classification (supervised, on the pooled representation),
* unknown-anomaly scoring (per-field reconstruction error, no attack labels).

Deliberate properties, so the artifact is honest about what it is:

* ``torch`` is imported at module import time here; this module belongs to the ML
  extra, and the API never imports it unless detection is enabled.
* Field identities are optional (``use_field_embeddings=False``) so the
  ablation "drop Field-ID embeddings" from the blueprint can be measured.
* The MFM loss is computed on masked positions only; masking is deterministic
  given the torch generator, so runs are reproducible from a seed.
* Reconstruction error doubles as the anomaly score: no separate model has to be
  trained for the unknown-anomaly channel.

The module deliberately contains no dataset loading or CLI: those live in
``backend/scripts/train_flow_transformer.py`` so this file stays unit-testable
with tiny synthetic tensors on CPU.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

import torch
from torch import nn

# A masked categorical field is encoded with this index (one past the real
# categories) so the encoder can tell "absent" from any observed value.
CATEGORY_MASK_SLOT = "mask"

DEFAULT_MASK_RATIO = 0.15


@dataclass(frozen=True)
class FlowTransformerConfig:
    """Architecture knobs, all of them exposed as training-script flags."""

    numeric_fields: int
    categorical_cardinalities: list[int] = field(default_factory=list)
    d_model: int = 64
    n_layers: int = 2
    n_heads: int = 4
    dim_feedforward: int = 128
    dropout: float = 0.1
    mask_ratio: float = DEFAULT_MASK_RATIO
    use_field_embeddings: bool = True
    n_classes: int = 2

    def __post_init__(self) -> None:
        # Validate at construction so an impossible architecture cannot even be
        # built and then persisted into an artifact.
        _validate(self)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def n_fields(self) -> int:
        return self.numeric_fields + len(self.categorical_cardinalities)


def _validate(config: FlowTransformerConfig) -> None:
    if config.numeric_fields < 1:
        raise ValueError("the encoder needs at least one numeric field")
    if config.d_model % config.n_heads != 0:
        raise ValueError("d_model must be divisible by n_heads")
    if not 0.0 <= config.mask_ratio < 1.0:
        raise ValueError("mask_ratio must be in [0, 1)")


class FlowTransformer(nn.Module):
    """Field-token Transformer with MFM reconstruction and dual downstream heads."""

    def __init__(self, config: FlowTransformerConfig) -> None:
        super().__init__()
        _validate(config)
        self.config = config

        # Per-field numeric projection: token_i = x_i * w_i + b_i. A shared linear
        # over the concatenated vector would lose the field boundary, which is the
        # whole point of tokenising fields separately.
        self.numeric_weight = nn.Parameter(torch.randn(config.numeric_fields, config.d_model) * 0.02)
        self.numeric_bias = nn.Parameter(torch.zeros(config.numeric_fields, config.d_model))

        # Categorical fields get a real embedding table plus one extra slot for the
        # mask token, so a masked category is representable without a fake value.
        self.categorical_embeddings = nn.ModuleList(
            [nn.Embedding(cardinality + 1, config.d_model) for cardinality in config.categorical_cardinalities]
        )

        # Field identity: added to every token so the encoder knows which field it
        # is looking at even when two fields share a numeric range.
        total_tokens = config.n_fields + 1  # + CLS
        self.field_embeddings = (
            nn.Parameter(torch.randn(total_tokens, config.d_model) * 0.02)
            if config.use_field_embeddings
            else None
        )
        self.cls_token = nn.Parameter(torch.randn(1, 1, config.d_model) * 0.02)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=config.d_model,
            nhead=config.n_heads,
            dim_feedforward=config.dim_feedforward,
            dropout=config.dropout,
            batch_first=True,
            norm_first=True,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=config.n_layers, enable_nested_tensor=False)
        self.norm = nn.LayerNorm(config.d_model)

        # MFM heads: one shared regression head for numeric tokens, one shared
        # classifier head for categorical tokens (each field keeps its own slot).
        self.numeric_head = nn.Linear(config.d_model, 1)
        self.categorical_heads = nn.ModuleList(
            [nn.Linear(config.d_model, cardinality + 1) for cardinality in config.categorical_cardinalities]
        )
        self.classification_head = nn.Linear(config.d_model, config.n_classes)

    # ---- tokenisation -----------------------------------------------------
    def _numeric_tokens(self, x_num: Any, numeric_mask: Any | None) -> Any:
        tokens = x_num.unsqueeze(-1) * self.numeric_weight + self.numeric_bias
        if numeric_mask is not None:
            mask_token = self.numeric_bias.detach() * 0.0
            tokens = torch.where(numeric_mask.unsqueeze(-1), mask_token.unsqueeze(0), tokens)
        return tokens

    def _categorical_tokens(self, x_cat: Any, categorical_mask: Any | None) -> list[Any]:
        tokens = []
        for index, cardinality in enumerate(self.config.categorical_cardinalities):
            embedding = self.categorical_embeddings[index]
            values = x_cat[:, index].long()
            if categorical_mask is not None:
                # The table has cardinality + 1 rows, so the mask slot is the last
                # index — expressed as the cardinality itself to keep it obvious.
                mask_index = torch.full_like(values, cardinality)
                values = torch.where(categorical_mask[:, index], mask_index, values)
            tokens.append(embedding(values))
        return tokens

    def _embed(self, x_num: Any, x_cat: Any, numeric_mask: Any | None, categorical_mask: Any | None) -> Any:
        numeric_tokens = self._numeric_tokens(x_num, numeric_mask)  # (B, F_num, d_model)
        categorical_tokens = [token.unsqueeze(1) for token in self._categorical_tokens(x_cat, categorical_mask)]
        sequence = torch.cat([numeric_tokens, *categorical_tokens], dim=1)  # (B, F, d_model)
        if self.field_embeddings is not None:
            sequence = sequence + self.field_embeddings[1 : self.config.n_fields + 1].unsqueeze(0)
        cls = self.cls_token.expand(sequence.shape[0], -1, -1)
        if self.field_embeddings is not None:
            cls = cls + self.field_embeddings[0].view(1, 1, -1)
        return torch.cat([cls, sequence], dim=1)

    # ---- forward ----------------------------------------------------------
    def forward(
        self,
        x_num: Any,
        x_cat: Any | None = None,
        *,
        numeric_mask: Any | None = None,
        categorical_mask: Any | None = None,
    ) -> dict[str, Any]:
        """Return pooled representation plus per-field MFM reconstructions."""

        tokens = self._embed(x_num, x_cat, numeric_mask, categorical_mask)
        encoded = self.norm(self.encoder(tokens))
        cls_repr, field_repr = encoded[:, 0], encoded[:, 1:]

        numeric_pred = self.numeric_head(field_repr[:, : self.config.numeric_fields]).squeeze(-1)
        categorical_logits = []
        offset = self.config.numeric_fields
        for index, head in enumerate(self.categorical_heads):
            categorical_logits.append(head(field_repr[:, offset + index]))

        return {
            "pooled": cls_repr,
            "numeric_pred": numeric_pred,
            "categorical_logits": categorical_logits,
            "class_logits": self.classification_head(cls_repr),
        }

    # ---- objectives -------------------------------------------------------
    def mfm_loss(
        self,
        outputs: dict[str, Any],
        x_num: Any,
        x_cat: Any | None,
        *,
        numeric_mask: Any,
        categorical_mask: Any | None,
    ) -> Any:
        """Masked reconstruction loss: only masked fields contribute."""

        numeric_terms = (outputs["numeric_pred"] - x_num) ** 2
        if numeric_mask.any():
            loss = numeric_terms[numeric_mask].mean()
        else:
            loss = numeric_terms.sum() * 0.0
        if x_cat is not None and categorical_mask is not None and len(self.categorical_heads) > 0:
            categorical_terms = [
                nn.functional.cross_entropy(
                    logits[categorical_mask[:, index]],
                    x_cat[:, index].long()[categorical_mask[:, index]],
                    reduction="sum",
                )
                for index, logits in enumerate(outputs["categorical_logits"])
                if categorical_mask[:, index].any()
            ]
            if categorical_terms:
                loss = loss + torch.stack(categorical_terms).sum() / max(int(categorical_mask.sum()), 1)
        return loss

    def reconstruction_error(self, x_num: Any, x_cat: Any | None = None) -> Any:
        """Per-sample reconstruction error; this is the unknown-anomaly score."""

        outputs = self.forward(x_num, x_cat)
        error = ((outputs["numeric_pred"] - x_num) ** 2).mean(dim=1)
        if x_cat is not None:
            for index, logits in enumerate(outputs["categorical_logits"]):
                error = error + nn.functional.cross_entropy(
                    logits, x_cat[:, index].long(), reduction="none"
                )
        return error


def sample_field_mask(
    batch_size: int,
    config: FlowTransformerConfig,
    *,
    generator: Any | None = None,
    mask_ratio: float | None = None,
) -> tuple[Any, Any | None]:
    """Draw a per-sample field mask; at least one field stays visible.

    Returns ``(numeric_mask, categorical_mask)`` with shapes ``(B, F_num)`` and
    ``(B, F_cat)``. The caller decides the ratio, which keeps the blueprint's
    mask-rate ablation a CLI flag rather than a code edit.
    """

    ratio = config.mask_ratio if mask_ratio is None else mask_ratio
    if not 0.0 <= ratio < 1.0:
        raise ValueError("mask_ratio must be in [0, 1)")
    if ratio == 0.0:
        numeric = torch.zeros(batch_size, config.numeric_fields, dtype=torch.bool)
        categorical = (
            torch.zeros(batch_size, len(config.categorical_cardinalities), dtype=torch.bool)
            if config.categorical_cardinalities
            else None
        )
        return numeric, categorical

    mask = torch.rand(batch_size, config.n_fields, generator=generator) < ratio
    # Never mask every field: with nothing visible the reconstruction task is
    # unsolvable and the gradient carries no information.
    all_masked = mask.all(dim=1)
    if all_masked.any():
        mask[all_masked, 0] = False
    numeric = mask[:, : config.numeric_fields]
    categorical = mask[:, config.numeric_fields :] if config.categorical_cardinalities else None
    return numeric, categorical


def build_model(config: FlowTransformerConfig) -> FlowTransformer:
    model = FlowTransformer(config)
    model.train()
    return model


def state_dict_to_payload(model: FlowTransformer) -> dict[str, Any]:
    """Plain dict of tensors, so joblib can persist it like every other artifact."""

    return {key: value.detach().cpu() for key, value in model.state_dict().items()}


def load_model_from_payload(config: FlowTransformerConfig, payload: dict[str, Any]) -> FlowTransformer:
    model = FlowTransformer(config)
    model.load_state_dict(payload)
    model.eval()
    return model
