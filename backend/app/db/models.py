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


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_created", "created_at"),)

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
