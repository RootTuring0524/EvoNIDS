from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin


class Sensor(TimestampMixin, Base):
    __tablename__ = "sensors"

    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    location: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(80))
    state: Mapped[str] = mapped_column(String(32), default="offline", nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    # Collector identity and health. ``enrolled_key_id`` binds the sensor to a
    # scoped API key so a stolen shared token is not sufficient identity, and
    # ``certificate_fingerprint`` is the mTLS binding once TLS termination is
    # configured (the column is populated by the enrollment endpoint; the API
    # never trusts a client-supplied fingerprint without a verified TLS peer).
    agent_version: Mapped[str | None] = mapped_column(String(80))
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    clock_skew_seconds: Mapped[float | None] = mapped_column(Float)
    dropped_events: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    spool_depth: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    expected_interval_seconds: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    enrolled_key_id: Mapped[str | None] = mapped_column(ForeignKey("api_keys.id"))
    certificate_fingerprint: Mapped[str | None] = mapped_column(String(128))


class IngestionBatch(Base):
    """Idempotency ledger for collector batch uploads.

    A collector retries a batch after a timeout, so the server must be able to
    recognise a replay and return the original outcome instead of re-ingesting
    (or silently dropping) the events. ``(sensor_id, batch_id)`` is unique and
    the row stores the content hash so a client cannot reuse a batch id for
    different content.
    """

    __tablename__ = "ingestion_batches"
    __table_args__ = (
        Index("uq_ingestion_batch_sensor", "sensor_id", "batch_id", unique=True),
        Index("ix_ingestion_batch_received", "received_at"),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    sensor_id: Mapped[str] = mapped_column(ForeignKey("sensors.id"), nullable=False)
    batch_id: Mapped[str] = mapped_column(String(120), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    encoding: Mapped[str] = mapped_column(String(16), default="identity", nullable=False)
    payload_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    accepted_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duplicate_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    rejected_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_flows: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_alerts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    first_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    clock_skew_seconds: Mapped[float | None] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(16), default="accepted", nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class DetectionSignal(Base):
    """One detection channel's verdict for one flow, with full provenance.

    Raw facts (the flow/evidence rows) are never merged with inference output;
    every channel writes its own signal row so a fused score can be explained
    afterwards from the exact inputs, model version, feature version, imputed
    features and degradation reason that produced it.
    """

    __tablename__ = "detection_signals"
    __table_args__ = (
        Index("ix_detection_signal_flow", "flow_id", "created_at"),
        Index("ix_detection_signal_channel", "channel", "created_at"),
        Index("ix_detection_signal_decision", "decision", "created_at"),
        Index("ix_detection_signal_workspace_created", "workspace_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    # Tenant/workspace inherited from the sensor identity that produced the flow.
    workspace_id: Mapped[str] = mapped_column(String(64), default="default", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    flow_id: Mapped[str | None] = mapped_column(ForeignKey("flows.id"))
    alert_id: Mapped[str | None] = mapped_column(ForeignKey("alerts.id"))
    sensor_id: Mapped[str] = mapped_column(String(80), nullable=False)
    channel: Mapped[str] = mapped_column(String(24), nullable=False)
    channel_version: Mapped[str] = mapped_column(String(96), nullable=False)
    model_id: Mapped[str | None] = mapped_column(ForeignKey("model_versions.id"))
    raw_score: Mapped[float] = mapped_column(Float, nullable=False)
    calibrated_score: Mapped[float] = mapped_column(Float, nullable=False)
    threshold: Mapped[float] = mapped_column(Float, nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    uncertainty: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    feature_version: Mapped[str] = mapped_column(String(32), nullable=False)
    feature_source: Mapped[str] = mapped_column(String(24), default="online", nullable=False)
    imputed_features: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    degraded: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    degraded_reason: Mapped[str | None] = mapped_column(String(160))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class RiskAssessment(Base):
    """Explainable fusion of channel signals for one flow.

    Stores the exact inputs (channel, model version, raw score, calibrated
    score), the weights used, the final decision, the uncertainty and every
    degradation reason, so an analyst can reconstruct why a verdict was issued.
    """

    __tablename__ = "risk_assessments"
    __table_args__ = (
        Index("ix_risk_assessment_flow", "flow_id", "created_at"),
        Index("ix_risk_assessment_decision", "decision", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    flow_id: Mapped[str | None] = mapped_column(ForeignKey("flows.id"))
    workspace_id: Mapped[str] = mapped_column(String(64), default="default", nullable=False)
    alert_id: Mapped[str | None] = mapped_column(ForeignKey("alerts.id"))
    sensor_id: Mapped[str] = mapped_column(String(80), nullable=False)
    signal_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    inputs: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    weights: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    final_score: Mapped[float] = mapped_column(Float, nullable=False)
    uncertainty: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    decision: Mapped[str] = mapped_column(String(24), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, default="", nullable=False)
    degraded_reasons: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mode: Mapped[str] = mapped_column(String(16), default="shadow", nullable=False)



class Flow(TimestampMixin, Base):
    __tablename__ = "flows"
    __table_args__ = (
        Index("ix_flows_time", "time"),
        Index("ix_flows_src_dst", "source", "destination"),
        Index("uq_flows_sensor_external", "sensor_id", "external_id", unique=True),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    external_id: Mapped[str] = mapped_column(String(128), nullable=False)
    sensor_id: Mapped[str] = mapped_column(ForeignKey("sensors.id"), nullable=False)
    time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    destination: Mapped[str] = mapped_column(String(64), nullable=False)
    source_port: Mapped[int] = mapped_column(Integer, nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(24), nullable=False)
    service: Mapped[str] = mapped_column(String(64), default="unknown", nullable=False)
    activity: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    packets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    verdict: Mapped[str] = mapped_column(String(24), default="benign", nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    feature_version: Mapped[str] = mapped_column(String(32), default="flow-v1", nullable=False)
    features: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    raw_reference: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    sensor: Mapped[Sensor] = relationship()


class ModelVersion(TimestampMixin, Base):
    __tablename__ = "model_versions"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    role: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), default="training", nullable=False)
    artifact_uri: Mapped[str | None] = mapped_column(Text)
    feature_version: Mapped[str] = mapped_column(String(32), nullable=False)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class DatasetAsset(TimestampMixin, Base):
    __tablename__ = "dataset_assets"
    __table_args__ = (
        Index("uq_dataset_relative_path", "relative_path", unique=True),
        Index("ix_dataset_state_updated", "state", "updated_at"),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    source_uri: Mapped[str] = mapped_column(Text, default="", nullable=False)
    relative_path: Mapped[str] = mapped_column(Text, nullable=False)
    format: Mapped[str] = mapped_column(String(24), nullable=False)
    state: Mapped[str] = mapped_column(String(24), default="profiling", nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    sha256: Mapped[str | None] = mapped_column(String(64))
    label_column: Mapped[str | None] = mapped_column(String(160))
    normal_labels: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    total_samples: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    normal_samples: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    attack_samples: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    feature_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    missing_values: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    feature_columns: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    label_distribution: Mapped[dict[str, int]] = mapped_column(JSON, default=dict, nullable=False)
    split: Mapped[dict[str, int]] = mapped_column(JSON, default=dict, nullable=False)
    main_training_set: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    unknown_holdout: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    rule_replay: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    uses: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    inspected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    inspection_error: Mapped[str | None] = mapped_column(Text)


class TrainingRun(TimestampMixin, Base):
    __tablename__ = "training_runs"
    __table_args__ = (
        Index("ix_training_state_created", "state", "created_at"),
        Index("ix_training_dataset_created", "dataset_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    dataset_id: Mapped[str] = mapped_column(ForeignKey("dataset_assets.id"), nullable=False)
    model_id: Mapped[str | None] = mapped_column(ForeignKey("model_versions.id"))
    task: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(24), default="queued", nullable=False)
    requested_by: Mapped[str] = mapped_column(String(120), nullable=False)
    dataset_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    feature_version: Mapped[str] = mapped_column(String(32), nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    samples_seen: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    samples_used: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    artifact_uri: Mapped[str | None] = mapped_column(Text)
    artifact_sha256: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)


class Inference(TimestampMixin, Base):
    __tablename__ = "inferences"
    __table_args__ = (Index("ix_inferences_flow_created", "flow_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    flow_id: Mapped[str] = mapped_column(ForeignKey("flows.id"), nullable=False)
    transformer_model_id: Mapped[str | None] = mapped_column(ForeignKey("model_versions.id"))
    autoencoder_model_id: Mapped[str | None] = mapped_column(ForeignKey("model_versions.id"))
    transformer_output: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    autoencoder_output: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    fusion_output: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)


class Alert(TimestampMixin, Base):
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_timestamp", "timestamp"),
        Index("ix_alerts_status_severity", "status", "severity"),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    flow_id: Mapped[str | None] = mapped_column(ForeignKey("flows.id"))
    inference_id: Mapped[str | None] = mapped_column(ForeignKey("inferences.id"))
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    severity: Mapped[str] = mapped_column(String(24), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="new", nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    destination_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    destination_port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(24), nullable=False)
    sensor: Mapped[str] = mapped_column(String(96), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    detector: Mapped[str] = mapped_column(String(160), nullable=False)
    owner: Mapped[str | None] = mapped_column(String(120))
    evidence: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)


class AgentRun(TimestampMixin, Base):
    __tablename__ = "agent_runs"
    __table_args__ = (
        Index("ix_agent_runs_alert_created", "alert_id", "created_at"),
        Index("ix_agent_runs_state_created", "state", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), nullable=False)
    display_model: Mapped[str] = mapped_column(String(120), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False)
    hypothesis: Mapped[str] = mapped_column(Text, nullable=False)
    pattern_decision: Mapped[str] = mapped_column(String(32), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)


class Rule(TimestampMixin, Base):
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    stage: Mapped[str] = mapped_column(String(32), default="candidate", nullable=False)
    source: Mapped[str] = mapped_column(String(32), default="agent", nullable=False)
    severity: Mapped[str] = mapped_column(String(24), nullable=False)
    coverage: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    hit_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    false_positive_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    author: Mapped[str] = mapped_column(String(120), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    content: Mapped[str] = mapped_column(Text, default="", nullable=False)
    rationale: Mapped[str] = mapped_column(Text, default="", nullable=False)
    quality_score: Mapped[float | None] = mapped_column(Float)
    active_version_id: Mapped[str | None] = mapped_column(String(96))
    source_alert_id: Mapped[str] = mapped_column(String(96), default="", nullable=False)
    diff_reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    expected_coverage_change: Mapped[str] = mapped_column(Text, default="", nullable=False)
    false_positive_risk: Mapped[str] = mapped_column(Text, default="", nullable=False)


class RuleVersion(TimestampMixin, Base):
    __tablename__ = "rule_versions"
    __table_args__ = (Index("uq_rule_version", "rule_id", "version", unique=True),)

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey("rules.id"), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    parent_version_id: Mapped[str | None] = mapped_column(ForeignKey("rule_versions.id"))
    structured_rule: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    generated_by: Mapped[str] = mapped_column(String(120), nullable=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)


class RuleValidation(TimestampMixin, Base):
    __tablename__ = "rule_validations"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    rule_version_id: Mapped[str] = mapped_column(ForeignKey("rule_versions.id"), nullable=False)
    state: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    replay_dataset_version: Mapped[str] = mapped_column(String(96), nullable=False)
    executor_version: Mapped[str] = mapped_column(String(64), nullable=False)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    checks: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    passed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class KnowledgeEvidence(TimestampMixin, Base):
    __tablename__ = "knowledge_evidence"
    __table_args__ = (
        Index("ix_knowledge_source", "source_type", "source_id"),
        Index("ix_knowledge_trust_allowed", "trust", "allowed"),
        Index("ix_knowledge_workspace_allowed", "workspace_id", "allowed"),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_id: Mapped[str] = mapped_column(String(128), nullable=False)
    trust: Mapped[str] = mapped_column(String(16), nullable=False)
    excerpt: Mapped[str] = mapped_column(Text, nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    allowed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    prompt_injection_risk: Mapped[str] = mapped_column(String(16), default="none", nullable=False)
    keywords: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    # Hybrid retrieval support (Phase 4): tenant/workspace scope, an embedding
    # vector stored as JSON (pgvector is the documented upgrade path, see
    # docs/adr/0011-llm-gateway-and-hybrid-rag.md), and an optional expiry.
    workspace_id: Mapped[str] = mapped_column(String(64), default="default", nullable=False)
    # none_as_null keeps "no embedding yet" as SQL NULL so backfill queries can
    # find un-embedded rows (SQLAlchemy's JSON type would otherwise store 'null').
    embedding: Mapped[list[float] | None] = mapped_column(JSON(none_as_null=True))
    embedding_model: Mapped[str | None] = mapped_column(String(64))
    embedding_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class InvestigationRun(TimestampMixin, Base):
    """One evidence-constrained AI investigation attempt.

    Every field required to reproduce or audit the run is stored: provider and
    model actually used, prompt/tool/knowledge versions, the retrieval snapshot,
    the evidence whitelist, token usage, latency, cost estimate and every
    degradation reason. ``state`` distinguishes a real success from a run that
    was degraded (no provider) or refused for insufficient evidence.
    """

    __tablename__ = "investigation_runs"
    __table_args__ = (
        Index("ix_investigation_alert_created", "alert_id", "created_at"),
        Index("ix_investigation_state_created", "state", "created_at"),
        Index("ix_investigation_workspace_created", "workspace_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    # Tenant/workspace of the requesting analyst, copied from the principal when
    # the run is queued; the background worker then reads it from the row so it
    # never has to trust a request context that no longer exists.
    workspace_id: Mapped[str] = mapped_column(String(64), default="default", nullable=False)
    alert_id: Mapped[str | None] = mapped_column(ForeignKey("alerts.id"))
    case_id: Mapped[str | None] = mapped_column(String(96))
    requested_by: Mapped[str] = mapped_column(String(120), nullable=False)
    state: Mapped[str] = mapped_column(String(32), default="queued", nullable=False)
    mode: Mapped[str] = mapped_column(String(24), default="llm", nullable=False)
    provider: Mapped[str | None] = mapped_column(String(48))
    model_id: Mapped[str | None] = mapped_column(String(120))
    prompt_template_version: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_registry_version: Mapped[str] = mapped_column(String(64), nullable=False)
    knowledge_version: Mapped[str | None] = mapped_column(String(64))
    max_tool_calls: Mapped[int] = mapped_column(Integer, default=6, nullable=False)
    budget_usd: Mapped[float] = mapped_column(Float, default=0.25, nullable=False)
    input_evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    retrieval: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    uncertainty: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    completion_tokens: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    cost_estimate_usd: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    degraded_reasons: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class InvestigationClaim(TimestampMixin, Base):
    """A single verifiable statement produced by an investigation.

    Claims are stored separately from the run so every statement can be traced
    to the exact evidence ids it cites, and so a claim that fails validation is
    kept with its rejection reason instead of being silently dropped.
    """

    __tablename__ = "investigation_claims"
    __table_args__ = (
        Index("ix_investigation_claim_run", "run_id", "claim_index"),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("investigation_runs.id"), nullable=False)
    claim_index: Mapped[int] = mapped_column(Integer, nullable=False)
    claim_type: Mapped[str] = mapped_column(String(24), nullable=False)
    statement: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    uncertainty: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    mitre_techniques: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    rejection_reason: Mapped[str | None] = mapped_column(String(160))


class ToolExecution(TimestampMixin, Base):
    """Audit record of one whitelisted tool call made during an investigation."""

    __tablename__ = "tool_executions"
    __table_args__ = (Index("ix_tool_execution_run", "run_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("investigation_runs.id"), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(32), nullable=False)
    arguments: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    result_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    state: Mapped[str] = mapped_column(String(16), default="completed", nullable=False)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    error: Mapped[str | None] = mapped_column(String(255))


class AnalystFeedback(TimestampMixin, Base):
    """Human label/verdict captured for a run, claim or alert.

    This is the feedback loop that feeds the next evaluation round; it never
    mutates the original inference output.
    """

    __tablename__ = "analyst_feedback"
    __table_args__ = (Index("ix_analyst_feedback_object", "object_type", "object_id"),)

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    object_type: Mapped[str] = mapped_column(String(24), nullable=False)
    object_id: Mapped[str] = mapped_column(String(96), nullable=False)
    verdict: Mapped[str] = mapped_column(String(24), nullable=False)
    label: Mapped[str | None] = mapped_column(String(64))
    comment: Mapped[str | None] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(120), nullable=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_created", "created_at"),
        Index("ix_audit_workspace_sequence", "workspace_id", "sequence", unique=True),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor: Mapped[str] = mapped_column(String(120), nullable=False)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    object_type: Mapped[str] = mapped_column(String(80), nullable=False)
    object_id: Mapped[str] = mapped_column(String(96), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    request_id: Mapped[str | None] = mapped_column(String(96))
    before_state: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    after_state: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    note: Mapped[str | None] = mapped_column(Text)
    # Tamper-evidence (see app/services/audit_chain.py): per-workspace sequence and
    # hash chain. Pre-existing rows keep NULL and are reported as unchained.
    workspace_id: Mapped[str] = mapped_column(String(64), default="default", nullable=False)
    sequence: Mapped[int | None] = mapped_column(Integer)
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    content_hash: Mapped[str | None] = mapped_column(String(64))


class ApiKey(TimestampMixin, Base):
    """Hashed, scoped machine identity (sensor, admin or analyst).

    Only the salted SHA-256 digest of the secret is stored; the raw secret is
    returned once at creation time. Environment-variable tokens remain the
    legacy bootstrap path (see app.api.security).
    """

    __tablename__ = "api_keys"
    __table_args__ = (
        Index("ix_api_keys_scope_enabled", "scope", "enabled"),
        Index("uq_api_keys_prefix", "prefix", unique=True),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    scope: Mapped[str] = mapped_column(String(24), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(160), nullable=False)
    prefix: Mapped[str] = mapped_column(String(24), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Case(TimestampMixin, Base):
    """Investigation container aggregating related alerts.

    Cases are the analyst-facing unit of work. Alert aggregation into cases is
    performed explicitly today (manual creation plus attach/detach); automatic
    correlation heuristics are a later iteration and will be recorded here.
    """

    __tablename__ = "cases"
    __table_args__ = (
        Index("ix_cases_status_updated", "status", "updated_at"),
        Index("ix_cases_severity_updated", "severity", "updated_at"),
        Index("ix_cases_workspace_updated", "workspace_id", "updated_at"),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    # Tenant/workspace the case belongs to. Stamped from the authenticated
    # principal at creation time (app.services.rbac.effective_workspace) and used
    # as a mandatory read filter; a client-supplied value is never trusted.
    workspace_id: Mapped[str] = mapped_column(String(64), default="default", nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(24), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)
    assignee: Mapped[str | None] = mapped_column(String(120))
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)
    alert_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    highest_risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)


class CaseAlert(TimestampMixin, Base):
    __tablename__ = "case_alerts"
    __table_args__ = (Index("uq_case_alert", "case_id", "alert_id", unique=True),)

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), nullable=False)
    alert_id: Mapped[str] = mapped_column(ForeignKey("alerts.id"), nullable=False)


class CaseTimelineEvent(Base):
    """Human-readable, case-scoped timeline mirror of the immutable audit log.

    The audit log remains the tamper-evident record of truth; this table
    provides the case workbench with a cheap, ordered, case-scoped view.
    """

    __tablename__ = "case_timeline_events"
    __table_args__ = (Index("ix_case_timeline_created", "case_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(120), nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSON)


class EvidenceRecord(TimestampMixin, Base):
    """Generic evidence registry entry created at ingestion time.

    Every accepted raw event gets one row with its content SHA-256, observation
    and receipt times, parser identity and integrity/missing markers. The raw
    object itself is stored in ``EvidenceArtifact`` (bounded size); pointers to
    the derived flow/alert rows live in ``source_ref_type`` / ``source_ref_id``.
    Original facts and derived detections are never merged into one field.
    """

    __tablename__ = "evidence_records"
    __table_args__ = (
        Index("ix_evidence_sensor_time", "sensor_id", "observed_at"),
        Index("ix_evidence_content_hash", "content_sha256"),
        Index("ix_evidence_workspace_observed", "workspace_id", "observed_at"),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    # Tenant/workspace of the event, stamped from the ingestion principal (the
    # sensor credential), never from the uploaded payload.
    workspace_id: Mapped[str] = mapped_column(String(64), default="default", nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    sensor_id: Mapped[str] = mapped_column(String(80), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    external_id: Mapped[str] = mapped_column(String(160), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    integrity: Mapped[str] = mapped_column(String(16), default="complete", nullable=False)
    data_missing: Mapped[str] = mapped_column(String(32), default="none", nullable=False)
    parser_version: Mapped[str] = mapped_column(String(64), nullable=False)
    redacted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    source_ref_type: Mapped[str | None] = mapped_column(String(24))
    source_ref_id: Mapped[str | None] = mapped_column(String(96))
    artifact_size_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    fields: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class EvidenceArtifact(Base):
    """Raw object behind an evidence record (bounded at ingestion time)."""

    __tablename__ = "evidence_artifacts"

    evidence_id: Mapped[str] = mapped_column(
        ForeignKey("evidence_records.id"), primary_key=True
    )
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    content_text: Mapped[str | None] = mapped_column(Text)


class Entity(TimestampMixin, Base):
    """Observed network entity (an IP today) aggregated across sensors.

    Entities are discovered automatically from accepted events; they are never
    hand-curated facts. Counters reflect events seen since discovery.
    """

    __tablename__ = "entities"
    __table_args__ = (
        Index("uq_entity_type_value", "entity_type", "value", unique=True),
        Index("ix_entity_last_seen", "last_seen_at"),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(24), nullable=False)
    value: Mapped[str] = mapped_column(String(160), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    sensor_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)


class EntityRelation(TimestampMixin, Base):
    """Undirected, aggregated relation between two entities (e.g. communicated)."""

    __tablename__ = "entity_relations"
    __table_args__ = (Index("uq_relation_pair", "relation_type", "entity_a", "entity_b", unique=True),)

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    relation_type: Mapped[str] = mapped_column(String(32), nullable=False)
    entity_a: Mapped[str] = mapped_column(String(96), nullable=False)
    entity_b: Mapped[str] = mapped_column(String(96), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class RuleIRVersion(TimestampMixin, Base):
    """Immutable compiled revision of a rule expressed in the normalized Rule IR.

    The IR document, its digest and the compiled Suricata text are stored together
    so a deployment can be reproduced byte-for-byte and a rollback always refers
    to an exact revision.
    """

    __tablename__ = "rule_ir_versions"
    __table_args__ = (
        Index("uq_rule_ir_version", "rule_id", "version", unique=True),
        Index("ix_rule_ir_sid", "sid"),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(96), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    sid: Mapped[int] = mapped_column(Integer, nullable=False)
    rev: Mapped[int] = mapped_column(Integer, nullable=False)
    ir_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    ir_document: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    suricata_text: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(String(24), default="compiled", nullable=False)
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)


class RuleSandboxRun(TimestampMixin, Base):
    """Result of one sandbox validation (Suricata syntax check and/or PCAP replay).

    ``status`` states exactly what happened: a run with
    ``suricata_available = false`` is recorded as ``blocked`` and carries no
    metrics, so no report can claim a Suricata verdict that never happened.
    """

    __tablename__ = "rule_sandbox_runs"
    __table_args__ = (
        Index("ix_rule_sandbox_rule", "rule_id", "created_at"),
        Index("ix_rule_sandbox_status", "status", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(96), nullable=False)
    rule_version_id: Mapped[str] = mapped_column(String(96), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    suricata_available: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    suricata_version: Mapped[str | None] = mapped_column(String(64))
    syntax_passed: Mapped[bool | None] = mapped_column(Boolean)
    executor_version: Mapped[str] = mapped_column(String(64), nullable=False)
    normal_pcap: Mapped[str | None] = mapped_column(Text)
    malicious_pcap: Mapped[str | None] = mapped_column(Text)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    checks: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    passed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    blocked_reason: Mapped[str | None] = mapped_column(String(255))
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class SensorGroup(TimestampMixin, Base):
    """Named set of sensors a rule revision can be deployed to (canary or full)."""

    __tablename__ = "sensor_groups"

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    sensor_ids: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    stage: Mapped[str] = mapped_column(String(16), default="canary", nullable=False)


class RuleDeployment(TimestampMixin, Base):
    """Deployment of one rule revision to one sensor group, with rollback state."""

    __tablename__ = "rule_deployments"
    __table_args__ = (
        Index("ix_rule_deployment_rule", "rule_id", "created_at"),
        Index("ix_rule_deployment_state", "state", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(96), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(96), nullable=False)
    rule_version_id: Mapped[str] = mapped_column(String(96), nullable=False)
    sensor_group_id: Mapped[str] = mapped_column(String(96), nullable=False)
    state: Mapped[str] = mapped_column(String(24), default="canary", nullable=False)
    deployed_by: Mapped[str] = mapped_column(String(120), nullable=False)
    deployed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    promoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rollback_reason: Mapped[str | None] = mapped_column(Text)
    monitoring: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    previous_version_id: Mapped[str | None] = mapped_column(String(96))
