"""Masked Feature Modeling for network-flow tokens (Flow Transformer).

See :mod:`app.ml.flow_transformer` for the architecture and the blueprint's §7 for
the design rationale. Importing this package pulls in PyTorch, so only the ML
extras path (training scripts, offline inference) should import it.
"""

from app.ml.flow_transformer import (
    CATEGORY_MASK_SLOT,
    DEFAULT_MASK_RATIO,
    FlowTransformer,
    FlowTransformerConfig,
    build_model,
    load_model_from_payload,
    sample_field_mask,
    state_dict_to_payload,
)

__all__ = [
    "CATEGORY_MASK_SLOT",
    "DEFAULT_MASK_RATIO",
    "FlowTransformer",
    "FlowTransformerConfig",
    "build_model",
    "load_model_from_payload",
    "sample_field_mask",
    "state_dict_to_payload",
]
