"""Feature and prediction drift monitoring.

Drift is computed against the reference distribution stored in the model
artifact at training time. When a model has no reference distribution the
metric is reported as ``not_measured`` - never as zero - because "no data" and
"no drift" are different statements.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models import Flow, ModelVersion
from app.domain.flow_features import ONLINE_FEATURE_VERSION, ONLINE_MODEL_FEATURES
from app.services.online_detection import select_channel_model

PSI_WARN = 0.10
PSI_DRIFT = 0.25
KS_WARN = 0.10
KS_DRIFT = 0.20


@dataclass(frozen=True, slots=True)
class FeatureDrift:
    feature: str
    psi: float | None
    ks: float | None
    status: str
    reference_mean: float | None
    current_mean: float | None
    samples: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "feature": self.feature,
            "psi": self.psi,
            "ks": self.ks,
            "status": self.status,
            "referenceMean": self.reference_mean,
            "currentMean": self.current_mean,
            "samples": self.samples,
            "measured": self.psi is not None or self.ks is not None,
        }


def build_histogram(values: Sequence[float], *, bins: int = 10) -> dict[str, Any]:
    """Equal-width reference histogram (edges + shares) used by PSI.

    Written into the model artifact at training time so drift can be measured
    online without keeping the training rows.
    """
    if not values:
        return {}
    low = float(min(values))
    high = float(max(values))
    if not math.isfinite(low) or not math.isfinite(high):
        return {}
    if high - low < 1e-12:
        high = low + 1.0
    edges = [low + (high - low) * index / bins for index in range(bins + 1)]
    counts = [0] * bins
    for value in values:
        position = int((float(value) - low) / (high - low) * bins)
        counts[min(max(position, 0), bins - 1)] += 1
    total = sum(counts) or 1
    return {"edges": edges, "shares": [count / total for count in counts]}


def _psi(reference: dict[str, Any], current: Sequence[float]) -> float | None:
    """Population Stability Index against the reference histogram.

    The reference histogram (bin edges + shares) is written into the artifact at
    training time; without it the metric is unmeasured rather than guessed.
    """
    histogram = reference.get("histogram")
    if not isinstance(histogram, dict) or not current:
        return None
    edges = histogram.get("edges")
    shares = histogram.get("shares")
    if not isinstance(edges, list) or not isinstance(shares, list) or len(edges) != len(shares) + 1:
        return None
    total = len(current)
    psi = 0.0
    for index, reference_share in enumerate(shares):
        low = float(edges[index])
        high = float(edges[index + 1])
        last = index == len(shares) - 1
        count = sum(1 for value in current if (low <= value < high) or (last and value == high))
        share = max(count / total, 1e-6)
        reference_value = max(float(reference_share), 1e-6)
        psi += (share - reference_value) * math.log(share / reference_value)
    return round(psi, 6)


def _ks(reference: dict[str, Any], current: Sequence[float]) -> float | None:
    """Histogram-based Kolmogorov-Smirnov statistic.

    Comparing a handful of reference quantiles against the current sample would
    report a large distance even for an identical distribution, so the reference
    CDF is reconstructed from the stored histogram bins instead.
    """
    histogram = reference.get("histogram")
    if not isinstance(histogram, dict) or not current:
        return None
    edges = histogram.get("edges")
    shares = histogram.get("shares")
    if not isinstance(edges, list) or not isinstance(shares, list) or len(edges) != len(shares) + 1:
        return None
    total = len(current)
    cumulative_reference = 0.0
    largest = 0.0
    for index, share in enumerate(shares):
        cumulative_reference += float(share)
        upper = float(edges[index + 1])
        cumulative_current = sum(1 for value in current if value <= upper) / total
        largest = max(largest, abs(cumulative_reference - cumulative_current))
    return round(min(largest, 1.0), 6)


def _status(psi: float | None, ks: float | None) -> str:
    if psi is None and ks is None:
        return "not_measured"
    if (psi is not None and psi >= PSI_DRIFT) or (ks is not None and ks >= KS_DRIFT):
        return "drift"
    if (psi is not None and psi >= PSI_WARN) or (ks is not None and ks >= KS_WARN):
        return "warn"
    return "ok"


def feature_drift_report(
    db: Session,
    *,
    channel: str = "baseline",
    window_hours: int = 24,
    limit: int = 5_000,
    features: Sequence[str] | None = None,
    sensor_id: str | None = None,
) -> dict[str, Any]:
    model = select_channel_model(db, "baseline" if channel == "baseline" else "autoencoder")
    since = utc_now() - timedelta(hours=max(1, min(window_hours, 24 * 30)))
    query = select(Flow).where(Flow.time >= since)
    if sensor_id:
        query = query.where(Flow.sensor_id == sensor_id)
    rows = list(db.scalars(query.order_by(Flow.time.desc()).limit(limit)).all())
    reference = (model.artifact.get("referenceDistribution") if model else None) or {}
    reference_samples: dict[str, list[float]] = {}
    for flow in rows:
        contract = (flow.features or {}).get("onlineContract") or {}
        values = contract.get("modelFeatures") if isinstance(contract, dict) else None
        if not isinstance(values, dict):
            continue
        for name, value in values.items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                reference_samples.setdefault(name, []).append(float(value))
    selected_features = list(features or ONLINE_MODEL_FEATURES)
    items: list[FeatureDrift] = []
    for name in selected_features:
        current = reference_samples.get(name, [])
        reference_entry = reference.get(name)
        if not isinstance(reference_entry, dict):
            reference_entry = {}
        quantiles = reference_entry.get("quantiles")
        reference_mean = reference_entry.get("mean")
        if not isinstance(quantiles, dict) or not current:
            items.append(
                FeatureDrift(
                    feature=name,
                    psi=None,
                    ks=None,
                    status="not_measured",
                    reference_mean=float(reference_mean) if isinstance(reference_mean, (int, float)) else None,
                    current_mean=round(sum(current) / len(current), 6) if current else None,
                    samples=len(current),
                )
            )
            continue
        psi_value = _psi(reference_entry, current)
        ks_value = _ks(reference_entry, current)
        items.append(
            FeatureDrift(
                feature=name,
                psi=psi_value,
                ks=ks_value,
                status=_status(psi_value, ks_value),
                reference_mean=round(float(reference_mean), 6) if isinstance(reference_mean, (int, float)) else None,
                current_mean=round(sum(current) / len(current), 6),
                samples=len(current),
            )
        )
    drifted = [item.feature for item in items if item.status == "drift"]
    warned = [item.feature for item in items if item.status == "warn"]
    unmeasured = [item.feature for item in items if item.status == "not_measured"]
    return {
        "channel": channel,
        "modelId": model.model_id if model else None,
        "modelVersion": model.version if model else None,
        "featureContract": ONLINE_FEATURE_VERSION,
        "contractMatches": model.contract_matches if model else False,
        "windowHours": window_hours,
        "flowsScanned": len(rows),
        "thresholds": {"psiWarn": PSI_WARN, "psiDrift": PSI_DRIFT, "ksWarn": KS_WARN, "ksDrift": KS_DRIFT},
        "status": "drift" if drifted else "warn" if warned else "not_measured" if unmeasured and len(unmeasured) == len(items) else "ok",
        "driftedFeatures": drifted,
        "warnedFeatures": warned,
        "unmeasuredFeatures": unmeasured,
        "items": [item.as_dict() for item in items],
        "note": (
            "漂移基于模型制品内的训练参考分布计算；没有参考分布或窗口内没有流量时，"
            "对应特征标记为未测量，绝不显示为 0。"
        ),
    }


def prediction_drift(db: Session, *, window_hours: int = 24) -> dict[str, Any]:
    """Distribution of online verdicts in the window (proxy for prediction drift)."""
    from sqlalchemy import func

    since = utc_now() - timedelta(hours=max(1, min(window_hours, 24 * 30)))
    rows = db.execute(
        select(Flow.verdict, func.count()).where(Flow.time >= since).group_by(Flow.verdict)
    ).all()
    total = sum(int(count) for _, count in rows)
    if total == 0:
        return {"measured": False, "windowHours": window_hours, "counts": {}, "note": "窗口内没有流量"}
    return {
        "measured": True,
        "windowHours": window_hours,
        "counts": {str(verdict): int(count) for verdict, count in rows},
        "shares": {str(verdict): round(int(count) / total, 6) for verdict, count in rows},
        "total": total,
    }


def model_health(db: Session) -> dict[str, Any]:
    """Registry view used by the models page: artifact availability + drift summary."""
    models = list(db.scalars(select(ModelVersion).order_by(ModelVersion.name.asc())).all())
    items = []
    for model in models:
        artifact_state = "missing"
        if model.artifact_uri:
            from pathlib import Path

            artifact_state = "available" if Path(model.artifact_uri).expanduser().is_file() else "missing"
        items.append(
            {
                "id": model.id,
                "name": model.name,
                "role": model.role,
                "version": model.version,
                "state": model.state,
                "featureVersion": model.feature_version,
                "artifactState": artifact_state,
                "contractMatches": (model.parameters or {}).get("featureContract")
                == ONLINE_FEATURE_VERSION,
                "artifactSha256": (model.parameters or {}).get("artifactSha256"),
                "metrics": model.metrics,
                "updatedAt": model.updated_at.isoformat(),
            }
        )
    return {
        "items": items,
        "shadowPolicy": {
            "detectionMode": "shadow means signals are recorded but no alert is raised",
            "onlineContractAvailable": any(item["contractMatches"] for item in items),
        },
        "generatedAt": datetime.now(tz=utc_now().tzinfo).isoformat(),
    }
