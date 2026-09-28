"""Online dual-channel detection with explainable, persisted risk fusion.

Design constraints (see ``docs/adr/0010-online-detection-and-fusion.md``):

* Ingestion must never fail because a model, artifact or runtime is unavailable.
  Every failure degrades to an explicitly recorded ``abstain``/degraded signal.
* Raw facts and inference output stay separate: channels write ``DetectionSignal``
  rows, fusion writes one ``RiskAssessment`` row that references the exact inputs.
* The default mode is ``shadow``: signals and assessments are recorded but no
  alert is raised and no flow verdict is changed, because the shipped baseline
  and autoencoder were trained on CICIDS2017 flow features and only a subset of
  their input contract is observable from a live Suricata EVE ``flow`` event.
  Enabling alerting requires an online-contract model and an evaluated operating
  point (Phase 6); the code path exists and is tested, the policy is explicit.
"""

from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models import Alert, DetectionSignal, Flow, ModelVersion, RiskAssessment, TrainingRun
from app.services.model_registry import rollout_of
from app.domain.flow_features import ONLINE_FEATURE_VERSION, OnlineFeatureVector

DetectionMode = Literal["disabled", "shadow", "enabled"]
ChannelName = Literal["suricata", "baseline", "autoencoder"]

DETECTION_MODES: tuple[DetectionMode, ...] = ("disabled", "shadow", "enabled")
DEFAULT_MODE: DetectionMode = "shadow"
BASELINE_TASK = "known_attack_classification_baseline"
AUTOENCODER_TASK = "unknown_anomaly_detection"

# Verdict thresholds reused from the offline dual-channel backfill so the online
# and offline paths cannot silently disagree about what "suspicious" means.
MALICIOUS_THRESHOLD = 65.0
SUSPICIOUS_THRESHOLD = 40.0

# CICIDS2017 artifact feature -> online contract feature. Features outside this
# map are not observable from a Suricata EVE flow event; they are passed as NaN
# and the artifact's own imputer fills them in, and they are listed in
# ``imputed_features`` so the degradation is visible in the API and the UI.
CONTRACT_TO_MODEL_FEATURES: dict[str, str] = {
    "source_port": "source_port",
    "destination_port": "destination_port",
    "protocol": "protocol_number",
    "total_fwd_packets": "forward_packet_count",
    "total_bwd_packets": "backward_packet_count",
    "total_fwd_bytes": "forward_bytes",
    "total_bwd_bytes": "backward_bytes",
    "fwd_packet_length_mean": "forward_mean_packet_size",
    "bwd_packet_length_mean": "backward_mean_packet_size",
    "flow_bytes_per_second": "bytes_per_second",
    "flow_packets_per_second": "packets_per_second",
    "average_packet_size": "average_packet_size",
    "flow_packet_length_mean": "average_packet_size",
}
# Model feature -> (contract feature, multiplier) for unit conversions.
CONTRACT_TO_MODEL_TRANSFORMS: dict[str, tuple[str, float]] = {
    "duration_us": ("flow_duration_seconds", 1_000_000.0),
}


@dataclass(frozen=True, slots=True)
class ChannelModel:
    model_id: str
    name: str
    version: str
    artifact_path: str
    task: str
    contract_matches: bool
    artifact: dict[str, Any]
    rollout: str = "shadow"


@dataclass(frozen=True, slots=True)
class ChannelSignal:
    channel: str
    channel_version: str
    model_id: str | None
    raw_score: float
    calibrated_score: float
    threshold: float
    decision: Literal["alert", "benign", "abstain"]
    uncertainty: float
    latency_ms: float
    imputed_features: tuple[str, ...]
    degraded: bool
    degraded_reason: str | None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class FusedRisk:
    final_score: float
    uncertainty: float
    decision: Literal["malicious", "suspicious", "benign", "abstain"]
    agreement: Literal["consistent", "partial", "conflicting", "insufficient"]
    lean: str
    weights: dict[str, float]
    explanation: str
    degraded_reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DetectionOutcome:
    mode: str
    flows_scored: int
    signals: int
    assessments: int
    alerts_created: int
    degraded: bool
    degraded_reasons: tuple[str, ...]
    models: dict[str, str | None]


_ARTIFACT_CACHE: dict[str, tuple[float, int, dict[str, Any]]] = {}


def parse_mode(value: str | None) -> DetectionMode:
    normalized = (value or DEFAULT_MODE).strip().lower()
    if normalized not in DETECTION_MODES:
        raise ValueError(f"unknown detection mode {value!r}; expected one of {list(DETECTION_MODES)}")
    return normalized  # type: ignore[return-value]


def load_artifact(path: str) -> dict[str, Any]:
    """Load a joblib artifact with an mtime+size keyed process cache."""
    import joblib

    resolved = Path(path).expanduser().resolve()
    stat = resolved.stat()
    key = str(resolved)
    cached = _ARTIFACT_CACHE.get(key)
    if cached is not None and cached[0] == stat.st_mtime and cached[1] == stat.st_size:
        return cached[2]
    artifact = joblib.load(resolved)
    if not isinstance(artifact, dict):
        raise ValueError(f"artifact {resolved} is not a mapping")
    _ARTIFACT_CACHE[key] = (stat.st_mtime, stat.st_size, artifact)
    return artifact


def clear_artifact_cache() -> None:
    _ARTIFACT_CACHE.clear()


def _candidate_runs(db: Session, task: str) -> list[tuple[TrainingRun, ModelVersion]]:
    rows = db.execute(
        select(TrainingRun, ModelVersion)
        .join(ModelVersion, TrainingRun.model_id == ModelVersion.id)
        .where(TrainingRun.task == task, TrainingRun.state == "succeeded")
        .order_by(TrainingRun.completed_at.desc())
        .limit(20)
    ).all()
    return [(run, model) for run, model in rows if run.artifact_uri and Path(run.artifact_uri).expanduser().is_file()]


def _contract_of(model: ModelVersion, artifact: dict[str, Any]) -> str:
    parameters = model.parameters or {}
    declared = parameters.get("featureContract") or parameters.get("featureVersion")
    if isinstance(declared, str) and declared:
        return declared
    value = artifact.get("featureVersion")
    return str(value) if isinstance(value, str) else ""


def select_channel_model(db: Session, channel: ChannelName) -> ChannelModel | None:
    """Pick the artifact a channel should score with.

    A model trained on the online feature contract is always preferred, even if
    a newer CICIDS2017 artifact exists: the CICIDS artifact requires imputing
    most of its input space from an EVE flow, so choosing it would silently
    degrade every online score. Falls back to the newest CICIDS artifact and
    reports the imputation through ``contract_matches``/``degraded_reason``.
    """
    task = BASELINE_TASK if channel == "baseline" else AUTOENCODER_TASK
    fallback: ChannelModel | None = None
    canary: ChannelModel | None = None
    for run, model in _candidate_runs(db, task):
        assert run.artifact_uri is not None
        rollout = rollout_of(model).state
        if rollout == "retired":
            continue
        try:
            artifact = load_artifact(run.artifact_uri)
        except Exception:  # noqa: BLE001 - a broken artifact must degrade, not crash ingestion
            continue
        candidate = ChannelModel(
            model_id=model.id,
            name=model.name,
            version=model.version,
            artifact_path=run.artifact_uri,
            task=task,
            contract_matches=_contract_of(model, artifact) == ONLINE_FEATURE_VERSION,
            artifact=artifact,
            rollout=rollout,
        )
        if rollout == "active" and candidate.contract_matches:
            return candidate
        if rollout == "active" and fallback is None:
            fallback = candidate
        elif rollout == "canary" and canary is None:
            canary = candidate
        elif fallback is None and candidate.contract_matches:
            fallback = candidate
    return fallback or canary


def detector_status(db: Session, *, mode: DetectionMode) -> dict[str, Any]:
    baseline = select_channel_model(db, "baseline")
    autoencoder = select_channel_model(db, "autoencoder")
    return {
        "mode": mode,
        "featureVersion": ONLINE_FEATURE_VERSION,
        "channels": {
            "baseline": _channel_status(baseline),
            "autoencoder": _channel_status(autoencoder),
        },
        "alerting": mode == "enabled",
        "notes": _status_notes(mode, baseline, autoencoder),
    }


def _channel_status(model: ChannelModel | None) -> dict[str, Any]:
    if model is None:
        return {
            "available": False,
            "modelId": None,
            "version": None,
            "contractMatches": False,
            "reason": "no succeeded training run with a readable artifact",
        }
    return {
        "available": True,
        "modelId": model.model_id,
        "version": model.version,
        "contractMatches": model.contract_matches,
        "reason": None if model.contract_matches else "artifact trained on CICIDS2017 features; online input is imputed",
    }


def _status_notes(
    mode: DetectionMode, baseline: ChannelModel | None, autoencoder: ChannelModel | None
) -> list[str]:
    notes: list[str] = []
    if mode == "disabled":
        notes.append("在线检测已关闭：仅写入证据与规则结果，不计算模型信号。")
        return notes
    if mode == "shadow":
        notes.append("影子模式：写入信号与融合评估，但不创建告警、不修改流量结论。")
    if baseline is None or autoencoder is None:
        notes.append("缺少可用的模型制品，相关通道将返回 abstain 并记录降级原因。")
    if baseline is not None and not baseline.contract_matches:
        notes.append("基线模型未在在线特征契约上训练，缺失特征由模型自带插补填充。")
    if autoencoder is not None and not autoencoder.contract_matches:
        notes.append("AutoEncoder 未在在线特征契约上训练，缺失特征由模型自带插补填充。")
    return notes


def project_model_row(
    values: dict[str, float | int], numeric_features: Sequence[str]
) -> tuple[dict[str, float], tuple[str, ...]]:
    """Project online contract values onto a model's numeric feature list."""
    row: dict[str, float] = {}
    imputed: list[str] = []
    for name in numeric_features:
        if name in values:
            row[name] = float(values[name])
            continue
        mapped = CONTRACT_TO_MODEL_FEATURES.get(name)
        if mapped is not None and mapped in values:
            row[name] = float(values[mapped])
            continue
        transform = CONTRACT_TO_MODEL_TRANSFORMS.get(name)
        if transform is not None and transform[0] in values:
            row[name] = float(values[transform[0]]) * transform[1]
            continue
        row[name] = float("nan")
        imputed.append(name)
    return row, tuple(imputed)


def _numeric_features(artifact: dict[str, Any]) -> list[str]:
    features = artifact.get("numericFeatures")
    if isinstance(features, list) and features:
        return [str(item) for item in features]
    metrics = artifact.get("metrics")
    if isinstance(metrics, dict):
        declared = metrics.get("numeric_features")
        if isinstance(declared, list) and declared:
            return [str(item) for item in declared]
    raise ValueError("artifact does not declare numeric features")


def _calibrator(artifact: dict[str, Any]) -> Any | None:
    value = artifact.get("calibration")
    return value if value is not None else None


def _apply_calibration(calibrator: Any, score: float) -> float:
    if calibrator is None:
        return score
    try:
        calibrated = float(calibrator.predict([score])[0])
    except Exception:  # noqa: BLE001 - an unusable calibrator must not break scoring
        return score
    return min(1.0, max(0.0, calibrated))


def score_baseline(
    model: ChannelModel,
    vectors: Sequence[OnlineFeatureVector],
    *,
    alert_threshold: float = 0.65,
) -> list[ChannelSignal]:
    import pandas as pd

    features = _numeric_features(model.artifact)
    rows = []
    imputed_per_row: list[tuple[str, ...]] = []
    for vector in vectors:
        row, imputed = project_model_row(vector.model_values, features)
        rows.append(row)
        imputed_per_row.append(imputed)
    frame = pd.DataFrame(rows)
    started = time.perf_counter()
    pipeline = model.artifact["pipeline"]
    probabilities = pipeline.predict_proba(frame)
    elapsed_ms = (time.perf_counter() - started) * 1000
    classes = [str(value) for value in pipeline.classes_]
    benign_index = classes.index("BENIGN") if "BENIGN" in classes else None
    calibrator = _calibrator(model.artifact)
    signals: list[ChannelSignal] = []
    per_row_ms = elapsed_ms / max(len(vectors), 1)
    for index, imputed in enumerate(imputed_per_row):
        row_probabilities = probabilities[index]
        best = int(row_probabilities.argmax())
        known_risk = 1.0 - float(row_probabilities[benign_index]) if benign_index is not None else float(
            row_probabilities[best]
        )
        calibrated = _apply_calibration(calibrator, known_risk)
        decision: Literal["alert", "benign", "abstain"] = (
            "alert" if calibrated >= alert_threshold else "benign"
        )
        top_k_candidates: list[dict[str, Any]] = [
            {"label": classes[position], "probability": float(row_probabilities[position])}
            for position in range(len(classes))
        ]
        top_k = sorted(top_k_candidates, key=lambda item: float(item["probability"]), reverse=True)[:3]
        signals.append(
            ChannelSignal(
                channel="baseline",
                channel_version=f"{model.name} {model.version}",
                model_id=model.model_id,
                raw_score=round(known_risk, 6),
                calibrated_score=round(calibrated, 6),
                threshold=alert_threshold,
                decision=decision,
                uncertainty=round(min(1.0, len(imputed) / max(len(features), 1)), 4),
                latency_ms=round(per_row_ms, 4),
                imputed_features=imputed,
                degraded=bool(imputed) or calibrator is None,
                degraded_reason=(
                    f"imputed_features={len(imputed)}/{len(features)}" if imputed else None
                )
                if calibrator is not None
                else "uncalibrated",
                detail={
                    "prediction": classes[best],
                    "topK": top_k,
                    "featureContract": model.artifact.get("featureVersion", ""),
                    "calibration": "artifact" if calibrator is not None else "none",
                },
            )
        )
    return signals


def score_autoencoder(
    model: ChannelModel,
    vectors: Sequence[OnlineFeatureVector],
    *,
    alert_threshold: float = 0.5,
) -> list[ChannelSignal]:
    import pandas as pd

    from app.services.autoencoder import score_frame

    features = _numeric_features(model.artifact)
    rows = []
    imputed_per_row: list[tuple[str, ...]] = []
    for vector in vectors:
        row, imputed = project_model_row(vector.model_values, features)
        rows.append(row)
        imputed_per_row.append(imputed)
    frame = pd.DataFrame(rows)
    started = time.perf_counter()
    result = score_frame(model.artifact, frame)
    elapsed_ms = (time.perf_counter() - started) * 1000
    errors = result["errors"]
    scores = result["scores"]
    exceeds = result["exceeds"]
    feature_errors = result["featureErrors"]
    threshold = float(model.artifact["threshold"])
    calibrator = _calibrator(model.artifact)
    per_row_ms = elapsed_ms / max(len(vectors), 1)
    signals: list[ChannelSignal] = []
    for index, imputed in enumerate(imputed_per_row):
        raw = float(scores[index])
        calibrated = _apply_calibration(calibrator, raw)
        decision: Literal["alert", "benign", "abstain"] = (
            "alert" if bool(exceeds[index]) and calibrated >= alert_threshold else "benign"
        )
        deviation_candidates: list[dict[str, Any]] = [
            {
                "field": features[position],
                "deviation": round(float(math.sqrt(max(feature_errors[index, position], 0.0))), 6),
            }
            for position in range(len(features))
        ]
        top = sorted(deviation_candidates, key=lambda item: float(item["deviation"]), reverse=True)[:5]
        signals.append(
            ChannelSignal(
                channel="autoencoder",
                channel_version=f"{model.name} {model.version}",
                model_id=model.model_id,
                raw_score=round(raw, 6),
                calibrated_score=round(calibrated, 6),
                threshold=alert_threshold,
                decision=decision,
                uncertainty=round(min(1.0, len(imputed) / max(len(features), 1)), 4),
                latency_ms=round(per_row_ms, 4),
                imputed_features=imputed,
                degraded=bool(imputed) or calibrator is None,
                degraded_reason=(
                    f"imputed_features={len(imputed)}/{len(features)}" if imputed else None
                )
                if calibrator is not None
                else "uncalibrated",
                detail={
                    "reconstructionError": round(float(errors[index]), 8),
                    "errorThreshold": threshold,
                    "exceedsThreshold": bool(exceeds[index]),
                    "deviatingFeatures": top,
                    "calibration": "artifact" if calibrator is not None else "none",
                },
            )
        )
    return signals


def abstain(channel: ChannelName, reason: str) -> ChannelSignal:
    return ChannelSignal(
        channel=channel,
        channel_version="unavailable",
        model_id=None,
        raw_score=0.0,
        calibrated_score=0.0,
        threshold=0.0,
        decision="abstain",
        uncertainty=1.0,
        latency_ms=0.0,
        imputed_features=(),
        degraded=True,
        degraded_reason=reason,
        detail={"reason": reason},
    )


def fuse_signals(
    signals: Sequence[ChannelSignal], *, rule_risk: float | None = None
) -> FusedRisk:
    """Fuse channel signals into one explainable, persisted risk assessment."""
    # A channel that abstained (artifact missing, runtime failure) contributed no
    # evidence at all: it must not be treated as a "benign" vote, otherwise a
    # dead channel would silently dilute a real detection.
    active = [signal for signal in signals if signal.decision != "abstain"]
    by_channel = {signal.channel: signal for signal in active}
    baseline = by_channel.get("baseline")
    autoencoder = by_channel.get("autoencoder")
    degraded_reasons = [
        f"{signal.channel}:{signal.degraded_reason}"
        for signal in signals
        if signal.degraded and signal.degraded_reason
    ]
    if baseline is None and autoencoder is None:
        return FusedRisk(
            final_score=0.0,
            uncertainty=1.0,
            decision="abstain",
            agreement="insufficient",
            lean="insufficient_evidence",
            weights={},
            explanation="没有任何模型通道可用，未给出结论。",
            degraded_reasons=tuple(degraded_reasons) or ("no_channel_available",),
        )

    known_attack = baseline is not None and baseline.decision == "alert"
    anomaly = autoencoder is not None and autoencoder.decision == "alert"
    known_risk = baseline.calibrated_score if baseline is not None else 0.0
    anomaly_risk = autoencoder.calibrated_score if autoencoder is not None else 0.0

    if baseline is None or autoencoder is None:
        available = baseline or autoencoder
        assert available is not None
        score = 100.0 * available.calibrated_score
        agreement: Literal["consistent", "partial", "conflicting", "insufficient"] = "insufficient"
        weights = {available.channel: 1.0}
        lean = "single_channel"
        explanation = f"仅 {available.channel} 通道可用，结论基于单通道，已标记为证据不足。"
    elif known_attack and anomaly:
        weights = {"baseline": 0.65, "autoencoder": 0.35}
        agreement = "consistent"
        lean = "dual_confirmed"
        score = 100.0 * (0.65 * known_risk + 0.35 * anomaly_risk)
        explanation = "已知攻击基线与 AutoEncoder 同时命中，双通道一致确认。"
    elif known_attack:
        weights = {"baseline": 0.8, "autoencoder": 0.2}
        agreement = "partial"
        lean = "known_attack"
        score = 100.0 * (0.8 * known_risk + 0.2 * anomaly_risk)
        explanation = "基线判定为已知攻击，AutoEncoder 未超过阈值，以基线为主。"
    elif anomaly:
        weights = {"baseline": 0.3, "autoencoder": 0.7}
        agreement = "conflicting"
        lean = "unknown_anomaly"
        score = 100.0 * (0.3 * known_risk + 0.7 * anomaly_risk)
        explanation = "基线判定为正常但 AutoEncoder 超过阈值，保留为未知异常候选。"
    else:
        weights = {"baseline": 0.7, "autoencoder": 0.3}
        agreement = "consistent"
        lean = "normal"
        score = 100.0 * (0.7 * known_risk + 0.3 * anomaly_risk)
        explanation = "两个模型通道均处于正常决策区域。"

    rule_floor_applied = False
    if rule_risk is not None:
        rule_score = 100.0 * min(max(rule_risk, 0.0), 1.0)
        if rule_score > score:
            score = rule_score
            rule_floor_applied = True
            explanation = f"{explanation} 已应用签名下限：已部署规则命中，风险分不低于 {rule_score:.2f}。"

    disagreement = {
        "conflicting": 1.0,
        "insufficient": 1.0,
        "partial": 0.5,
        "consistent": 0.0,
    }[agreement]
    imputation = max(
        (signal.uncertainty for signal in signals if signal.decision != "abstain"),
        default=1.0,
    )
    degraded_flag = 1.0 if degraded_reasons else 0.0
    uncertainty = round(min(1.0, 0.45 * disagreement + 0.35 * imputation + 0.2 * degraded_flag), 4)
    final_score = round(min(100.0, max(0.0, score)), 2)
    decision: Literal["malicious", "suspicious", "benign", "abstain"]
    if final_score >= MALICIOUS_THRESHOLD:
        decision = "malicious"
    elif final_score >= SUSPICIOUS_THRESHOLD:
        decision = "suspicious"
    else:
        decision = "benign"
    weights = {**weights, "ruleFloorApplied": 1.0 if rule_floor_applied else 0.0}
    return FusedRisk(
        final_score=final_score,
        uncertainty=uncertainty,
        decision=decision,
        agreement=agreement,
        lean=lean,
        weights=weights,
        explanation=explanation,
        degraded_reasons=tuple(degraded_reasons),
    )


def _signal_id(*parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20].upper()
    return f"SIG-{digest}"


def _assessment_id(*parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20].upper()
    return f"RISK-{digest}"


def _alert_id(*parts: str) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:20].upper()
    return f"ALT-ONLINE-{digest}"


def _signal_detail(vector: OnlineFeatureVector) -> dict[str, Any]:
    return {
        "missingFields": list(vector.missing_fields),
        "windowSeconds": vector.window_seconds,
        "contextFeatures": dict(vector.context_values),
    }


def run_online_detection(
    db: Session,
    *,
    flows: Sequence[Flow],
    vectors: dict[str, OnlineFeatureVector],
    mode: DetectionMode,
    rule_risk_by_flow: dict[str, float] | None = None,
    now: datetime | None = None,
    workspace_id: str = "default",
) -> DetectionOutcome:
    """Score ingested flows, persist signals/assessments and (only in ``enabled``) alert."""
    if mode == "disabled" or not flows:
        return DetectionOutcome(
            mode=mode,
            flows_scored=0,
            signals=0,
            assessments=0,
            alerts_created=0,
            degraded=False,
            degraded_reasons=(),
            models={"baseline": None, "autoencoder": None},
        )

    created_at = now or utc_now()
    baseline = select_channel_model(db, "baseline")
    autoencoder = select_channel_model(db, "autoencoder")
    ordered = [flow for flow in flows if flow.id in vectors]
    ordered_vectors = [vectors[flow.id] for flow in ordered]
    degraded_reasons: set[str] = set()

    baseline_signals: list[ChannelSignal]
    if baseline is None:
        baseline_signals = [abstain("baseline", "artifact_unavailable") for _ in ordered]
        degraded_reasons.add("baseline:artifact_unavailable")
    else:
        try:
            baseline_signals = score_baseline(baseline, ordered_vectors)
        except Exception as error:  # noqa: BLE001 - scoring failure must not break ingestion
            baseline_signals = [abstain("baseline", f"scoring_failed:{type(error).__name__}") for _ in ordered]
            degraded_reasons.add("baseline:scoring_failed")

    autoencoder_signals: list[ChannelSignal]
    if autoencoder is None:
        autoencoder_signals = [abstain("autoencoder", "artifact_unavailable") for _ in ordered]
        degraded_reasons.add("autoencoder:artifact_unavailable")
    else:
        try:
            autoencoder_signals = score_autoencoder(autoencoder, ordered_vectors)
        except Exception as error:  # noqa: BLE001
            autoencoder_signals = [
                abstain("autoencoder", f"scoring_failed:{type(error).__name__}") for _ in ordered
            ]
            degraded_reasons.add("autoencoder:scoring_failed")

    rule_risks = rule_risk_by_flow or {}
    signal_rows = 0
    assessment_rows = 0
    alerts_created = 0
    for index, flow in enumerate(ordered):
        vector = ordered_vectors[index]
        flow_signals = [baseline_signals[index], autoencoder_signals[index]]
        persisted: list[DetectionSignal] = []
        for signal in flow_signals:
            row_id = _signal_id(flow.id, signal.channel, signal.channel_version)
            row = db.get(DetectionSignal, row_id)
            detail = {**signal.detail, **_signal_detail(vector)}
            values: dict[str, Any] = {
                "created_at": created_at,
                "workspace_id": workspace_id,
                "flow_id": flow.id,
                "alert_id": None,
                "sensor_id": flow.sensor_id,
                "channel": signal.channel,
                "channel_version": signal.channel_version,
                "model_id": signal.model_id,
                "raw_score": signal.raw_score,
                "calibrated_score": signal.calibrated_score,
                "threshold": signal.threshold,
                "decision": signal.decision,
                "uncertainty": signal.uncertainty,
                "feature_version": ONLINE_FEATURE_VERSION,
                "feature_source": "online",
                "imputed_features": list(signal.imputed_features),
                "latency_ms": signal.latency_ms,
                "degraded": signal.degraded,
                "degraded_reason": signal.degraded_reason,
                "detail": detail,
            }
            if row is None:
                row = DetectionSignal(id=row_id, **values)
                db.add(row)
            else:
                for key, value in values.items():
                    setattr(row, key, value)
            persisted.append(row)
            signal_rows += 1

        rule_risk = rule_risks.get(flow.id)
        fused = fuse_signals(flow_signals, rule_risk=rule_risk)
        degraded_reasons.update(fused.degraded_reasons)
        assessment_id = _assessment_id(flow.id, "online")
        assessment = db.get(RiskAssessment, assessment_id)
        inputs = [
            {
                "signalId": row.id,
                "channel": row.channel,
                "channelVersion": row.channel_version,
                "modelId": row.model_id,
                "rawScore": row.raw_score,
                "calibratedScore": row.calibrated_score,
                "decision": row.decision,
                "imputedFeatures": row.imputed_features,
                "degradedReason": row.degraded_reason,
            }
            for row in persisted
        ]
        if rule_risk is not None:
            inputs.append(
                {
                    "signalId": None,
                    "channel": "suricata",
                    "channelVersion": "deployed_rules",
                    "modelId": None,
                    "rawScore": round(rule_risk, 6),
                    "calibratedScore": round(rule_risk, 6),
                    "decision": "alert" if rule_risk >= 0.5 else "benign",
                    "imputedFeatures": [],
                    "degradedReason": None,
                }
            )
        values = {
            "created_at": created_at,
            "workspace_id": workspace_id,
            "flow_id": flow.id,
            "alert_id": None,
            "sensor_id": flow.sensor_id,
            "signal_ids": [row.id for row in persisted],
            "inputs": inputs,
            "weights": fused.weights,
            "final_score": fused.final_score,
            "uncertainty": fused.uncertainty,
            "decision": fused.decision,
            "explanation": fused.explanation,
            "degraded_reasons": list(fused.degraded_reasons),
            "mode": mode,
        }
        if assessment is None:
            assessment = RiskAssessment(id=assessment_id, **values)
            db.add(assessment)
        else:
            for key, value in values.items():
                setattr(assessment, key, value)
        assessment_rows += 1

        if mode != "enabled":
            continue
        if fused.decision == "benign":
            flow.verdict = "benign"
            flow.anomaly_score = fused.final_score / 100
            continue
        flow.verdict = "malicious" if fused.decision == "malicious" else "suspicious"
        flow.anomaly_score = fused.final_score / 100
        alert_id = _alert_id(flow.id, "online")
        if db.get(Alert, alert_id) is not None:
            continue
        severity = "critical" if fused.final_score >= 85 else "high" if fused.final_score >= 65 else "medium"
        db.add(
            Alert(
                id=alert_id,
                flow_id=flow.id,
                inference_id=None,
                timestamp=flow.time,
                severity=severity,
                status="new",
                title=f"在线双通道检测：{fused.lean}",
                category=_category_for(fused.lean),
                source_ip=flow.source,
                destination_ip=flow.destination,
                destination_port=flow.destination_port,
                protocol=flow.protocol,
                sensor=flow.sensor_id,
                risk_score=fused.final_score,
                confidence=round(100.0 * (1.0 - fused.uncertainty), 2),
                detector=f"online-fusion:{fused.weights.get('baseline', 0)}/{fused.weights.get('autoencoder', 0)}",
                owner=None,
                evidence=[
                    f"风险融合评估 {assessment_id}：{fused.explanation}",
                    *[
                        f"{row.channel} {row.channel_version}：原始 {row.raw_score:.4f} / 校准 "
                        f"{row.calibrated_score:.4f} / 阈值 {row.threshold:.4f} / {row.decision}"
                        for row in persisted
                    ],
                    f"不确定性 {fused.uncertainty:.4f}；降级原因：{', '.join(fused.degraded_reasons) or '无'}",
                    f"特征契约 {ONLINE_FEATURE_VERSION}",
                ],
            )
        )
        assessment.alert_id = alert_id
        for row in persisted:
            row.alert_id = alert_id
        alerts_created += 1

    return DetectionOutcome(
        mode=mode,
        flows_scored=len(ordered),
        signals=signal_rows,
        assessments=assessment_rows,
        alerts_created=alerts_created,
        degraded=bool(degraded_reasons),
        degraded_reasons=tuple(sorted(degraded_reasons)),
        models={
            "baseline": baseline.model_id if baseline else None,
            "autoencoder": autoencoder.model_id if autoencoder else None,
        },
    )


def _category_for(lean: str) -> str:
    return {
        "dual_confirmed": "Known Attack + Anomaly",
        "known_attack": "Known Attack",
        "unknown_anomaly": "Unknown Anomaly",
        "normal": "Normal",
        "single_channel": "Single Channel Detection",
    }.get(lean, "Unknown Anomaly")


def signals_for_flow(db: Session, flow_id: str) -> list[DetectionSignal]:
    return list(
        db.scalars(
            select(DetectionSignal)
            .where(DetectionSignal.flow_id == flow_id)
            .order_by(DetectionSignal.created_at.desc())
        ).all()
    )


def assessments_for_flow(db: Session, flow_id: str) -> list[RiskAssessment]:
    return list(
        db.scalars(
            select(RiskAssessment)
            .where(RiskAssessment.flow_id == flow_id)
            .order_by(RiskAssessment.created_at.desc())
        ).all()
    )
