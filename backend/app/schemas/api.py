from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


def to_camel(value: str) -> str:
    first, *rest = value.split("_")
    return first + "".join(part.capitalize() for part in rest)


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, alias_generator=to_camel, populate_by_name=True)


Severity = Literal["critical", "high", "medium", "low", "info"]
AlertStatus = Literal["new", "investigating", "contained", "closed"]
DetectionCategory = Literal[
    "DoS",
    "DDoS",
    "Port Scan",
    "Brute Force",
    "Botnet",
    "C2 Communication",
    "Web Attack",
    "Infiltration",
    "Abnormal Outbound Connection",
    "Unknown Anomaly",
]
RuleStage = Literal[
    "candidate",
    "validating",
    "validated",
    "rejected",
    "repaired",
    "confirmed",
    "deployed",
    "deprecated",
]
KnowledgeSourceType = Literal[
    "MITRE ATT&CK",
    "历史告警",
    "检测规则",
    "Snort / Suricata",
    "处置手册",
    "协议知识",
    "CVE / CWE / CAPEC",
    "已验证规则",
    "失败规则",
]


class AlertRead(ApiModel):
    id: str
    timestamp: datetime
    severity: Severity
    status: AlertStatus
    title: str
    category: DetectionCategory
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str
    sensor: str
    risk_score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=100)
    detector: str
    owner: str | None
    evidence: list[str]
    agent_state: Literal["completed", "running", "failed", "not_run"] = "not_run"
    agent_decision: Literal["new_pattern", "rule_variant", "known_match", "benign"] | None = None
    agent_run_id: str | None = None


class AlertUpdate(ApiModel):
    status: AlertStatus | None = None
    owner: str | None = Field(default=None, max_length=120)
    note: str | None = Field(default=None, max_length=500)
    actor: str = Field(default="local-analyst", min_length=1, max_length=120)


class AnomalyProfile(BaseModel):
    flow_id: str
    timestamp: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    service: str
    flow_duration: float
    forward_packet_count: int
    backward_packet_count: int
    forward_bytes: int
    backward_bytes: int
    packets_per_second: float
    bytes_per_second: float
    syn_ratio: float
    ack_ratio: float
    rst_ratio: float
    destination_port_count_60s: int
    destination_ip_count_60s: int
    flow_count_60s: int
    average_packet_size: float
    transformer_prediction: str
    transformer_confidence: float
    autoencoder_reconstruction_error: float
    autoencoder_anomaly_score: float
    final_risk_score: float
    suspected_attack_type: str


class TransformerTopK(ApiModel):
    label: str
    probability: float


class AbnormalFeature(ApiModel):
    field: str
    value: str
    contribution: float


class TransformerOutput(ApiModel):
    prediction: str
    confidence: float
    top_k: list[TransformerTopK]
    model_version: str
    inference_ms: float
    abnormal_features: list[AbnormalFeature]
    is_known_class: bool
    pretraining_task: str = "Masked Feature Modeling"


class DeviatingFeature(ApiModel):
    field: str
    observed: float
    baseline: float
    deviation: float


class AutoEncoderOutput(ApiModel):
    reconstruction_error: float
    threshold: float
    anomaly_score: float
    exceeds_threshold: bool
    deviating_features: list[DeviatingFeature]
    model_version: str
    inference_ms: float
    trained_on: Literal["normal_traffic"] = "normal_traffic"


class RiskFusion(ApiModel):
    final_score: float
    transformer_weight: float
    auto_encoder_weight: float
    context_adjustment: float
    agreement: Literal["consistent", "partial", "conflicting"]
    lean: Literal["known_attack", "unknown_anomaly", "dual_confirmed", "normal"]
    explanation: str


class AgentStep(ApiModel):
    id: str
    label: str
    state: Literal["completed", "active", "pending", "failed"]
    tool: str
    duration_ms: float
    result: str


class AgentAnalysis(ApiModel):
    # Display name is configuration-driven on the Nuxt side ("DeepSeek · <model id>"),
    # so any non-empty label up to 80 chars is accepted and stored verbatim.
    display_model: str = Field(min_length=1, max_length=80, default="DeepSeek V4 Pro")
    run_id: str
    state: Literal["completed", "running", "failed"]
    hypothesis: str
    pattern_decision: Literal["new_pattern", "rule_variant", "known_match", "benign"]
    summary: str
    recommendation: str
    evidence_ids: list[str]
    steps: list[AgentStep]


class RagEvidenceRead(ApiModel):
    id: str
    title: str
    source_type: KnowledgeSourceType
    source_id: str
    relevance: float = Field(ge=0, le=100)
    trust: Literal["high", "medium", "low"]
    excerpt: str
    updated_at: str
    purpose: str
    allowed: bool
    used_by_agent: bool
    prompt_injection_risk: Literal["none", "review", "blocked"]
    vector_score: float = Field(ge=0, le=1)
    keyword_score: float = Field(ge=0, le=1)
    rerank_score: float = Field(ge=0, le=1)
    matched_keywords: list[str]


class RagRetrievalStats(ApiModel):
    vector_candidates: int
    keyword_supplement_candidates: int
    filtered_candidates: int
    reranked_candidates: int
    provided_to_agent: int


class RagResponse(ApiModel):
    query: str
    top_k: int
    mode: Literal["keyword_fallback", "hybrid"]
    retrieval: RagRetrievalStats
    items: list[RagEvidenceRead]


class RagEvidenceCreate(ApiModel):
    id: str = Field(min_length=1, max_length=96)
    title: str = Field(min_length=1, max_length=255)
    source_type: KnowledgeSourceType
    source_id: str = Field(min_length=1, max_length=128)
    trust: Literal["high", "medium", "low"]
    excerpt: str = Field(min_length=1, max_length=4000)
    purpose: str = Field(min_length=1, max_length=1000)
    allowed: bool = True
    prompt_injection_risk: Literal["none", "review", "blocked"] = "none"
    keywords: list[str] = Field(default_factory=list, max_length=50)
    published_at: datetime
    metadata_json: dict[str, Any] = Field(default_factory=dict)


class RelatedRule(ApiModel):
    record_id: str | None
    rule_id: str
    label: str


class AlertDetail(ApiModel):
    alert: AlertRead
    profile: AnomalyProfile
    transformer: TransformerOutput
    auto_encoder: AutoEncoderOutput
    fusion: RiskFusion
    rag: list[RagEvidenceRead]
    agent: AgentAnalysis
    rag_query: str
    related_rule: RelatedRule | None


class AlertsResponse(ApiModel):
    items: list[AlertRead]
    total: int
    page: int
    page_size: int
    agent_completed: int = 0
    agent_pending: int = 0
    agent_decisions: dict[str, int] = Field(default_factory=dict)


class FlowRead(ApiModel):
    id: str
    time: datetime
    source: str
    destination: str
    source_port: int
    destination_port: int
    protocol: str
    service: str
    activity: str
    packets: int
    bytes: int
    duration_ms: int
    verdict: Literal["benign", "suspicious", "malicious"]
    anomaly_score: float


class FlowsResponse(ApiModel):
    items: list[FlowRead]
    total: int


class ModelRead(ApiModel):
    id: str
    name: str
    role: str
    version: str
    state: Literal["healthy", "degraded", "training"]
    latency: float
    throughput: float
    quality_label: str
    quality_value: float
    artifact_state: Literal["available", "missing", "unverified"]
    feature_version: str
    training_run_id: str | None = None
    dataset_id: str | None = None
    algorithm: str | None = None
    artifact_sha256: str | None = None
    updated_at: datetime


class ModelsResponse(ApiModel):
    items: list[ModelRead]


class DatasetSplit(ApiModel):
    train: int = Field(ge=0, le=100)
    validation: int = Field(ge=0, le=100)
    test: int = Field(ge=0, le=100)

    @model_validator(mode="after")
    def validate_total(self) -> "DatasetSplit":
        if self.train + self.validation + self.test != 100:
            raise ValueError("Dataset split percentages must add up to 100")
        return self


class DatasetRegistration(ApiModel):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,95}$")
    name: str = Field(min_length=1, max_length=160)
    version: str = Field(min_length=1, max_length=64)
    relative_path: str = Field(min_length=1, max_length=1000)
    source_uri: str = Field(default="", max_length=2000)
    label_column: str | None = Field(default=None, max_length=160)
    normal_labels: list[str] = Field(default_factory=lambda: ["BENIGN", "NORMAL", "0"], max_length=20)
    split: DatasetSplit = Field(default_factory=lambda: DatasetSplit(train=70, validation=15, test=15))
    main_training_set: bool = False
    unknown_holdout: bool = True
    rule_replay: bool = False
    uses: list[str] = Field(default_factory=list, max_length=20)
    actor: str = Field(default="local-admin", min_length=1, max_length=120)
    note: str | None = Field(default=None, max_length=500)


class DatasetDistributionItem(ApiModel):
    label: str
    count: int


class DatasetRead(ApiModel):
    id: str
    name: str
    version: str
    state: Literal["profiling", "ready", "error", "missing"]
    format: str
    relative_path: str
    source_uri: str
    file_size_bytes: int
    sha256: str | None
    label_column: str | None
    total_samples: int
    normal_samples: int
    attack_samples: int
    feature_count: int
    missing_values: int
    split: DatasetSplit
    main_training_set: bool
    unknown_holdout: bool
    rule_replay: bool
    uses: list[str]
    attack_distribution: list[DatasetDistributionItem]
    inspected_at: datetime | None
    inspection_error: str | None
    updated_at: datetime


class DatasetsResponse(ApiModel):
    items: list[DatasetRead]


class TrainingRunCreate(ApiModel):
    dataset_id: str = Field(min_length=1, max_length=96)
    algorithm: Literal["hist_gradient_boosting"] = "hist_gradient_boosting"
    max_rows: int = Field(default=250_000, ge=30, le=2_000_000)
    random_seed: int = Field(default=42, ge=0, le=2_147_483_647)
    max_iter: int = Field(default=200, ge=10, le=1_000)
    learning_rate: float = Field(default=0.08, gt=0, le=1)
    max_leaf_nodes: int = Field(default=31, ge=2, le=255)
    l2_regularization: float = Field(default=0.1, ge=0, le=100)
    actor: str = Field(default="local-ml-operator", min_length=1, max_length=120)


class TrainingClassMetric(ApiModel):
    label: str
    support: int = Field(ge=0)
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    f1: float = Field(ge=0, le=1)


class TrainingMetrics(ApiModel):
    accuracy: float = Field(ge=0, le=1)
    macro_precision: float = Field(ge=0, le=1)
    macro_recall: float = Field(ge=0, le=1)
    macro_f1: float = Field(ge=0, le=1)
    weighted_f1: float = Field(ge=0, le=1)
    validation_macro_f1: float = Field(ge=0, le=1)
    train_samples: int = Field(ge=0)
    validation_samples: int = Field(ge=0)
    test_samples: int = Field(ge=0)
    dropped_target_rows: int = Field(ge=0)
    feature_count: int = Field(ge=0)
    labels: list[str]
    class_metrics: list[TrainingClassMetric]
    confusion_matrix: list[list[int]]
    numeric_features: list[str]
    dropped_features: list[str]
    train_seconds: float = Field(ge=0)
    test_predict_ms: float = Field(ge=0)
    throughput_fps: float = Field(ge=0)

    @model_validator(mode="after")
    def validate_classification_shape(self) -> "TrainingMetrics":
        label_count = len(self.labels)
        if len(self.class_metrics) != label_count:
            raise ValueError("class_metrics must align with labels")
        if len(self.confusion_matrix) != label_count or any(
            len(row) != label_count for row in self.confusion_matrix
        ):
            raise ValueError("confusion_matrix must be square and align with labels")
        return self


class AutoEncoderAttackMetric(ApiModel):
    label: str
    support: int = Field(ge=0)
    detected: int = Field(ge=0)
    recall: float = Field(ge=0, le=1)
    median_error: float = Field(ge=0)


class AutoEncoderTrainingMetrics(ApiModel):
    accuracy: float = Field(ge=0, le=1)
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    f1: float = Field(ge=0, le=1)
    roc_auc: float = Field(ge=0, le=1)
    average_precision: float = Field(ge=0, le=1)
    normal_false_positive_rate: float = Field(ge=0, le=1)
    threshold: float = Field(ge=0)
    threshold_quantile: float = Field(ge=0, le=1)
    normal_validation_error_mean: float = Field(ge=0)
    normal_validation_error_std: float = Field(ge=0)
    normal_test_error_mean: float = Field(ge=0)
    attack_test_error_mean: float = Field(ge=0)
    train_samples: int = Field(ge=0)
    validation_samples: int = Field(ge=0)
    normal_test_samples: int = Field(ge=0)
    attack_test_samples: int = Field(ge=0)
    feature_count: int = Field(ge=0)
    numeric_features: list[str]
    best_epoch: int = Field(ge=1)
    epochs_completed: int = Field(ge=1)
    epoch_history: list[dict[str, int | float]]
    confusion_matrix: list[list[int]]
    per_attack_class: list[AutoEncoderAttackMetric]
    train_seconds: float = Field(ge=0)
    test_predict_ms: float = Field(ge=0)
    throughput_fps: float = Field(ge=0)


TrainingRunState = Literal["queued", "running", "succeeded", "failed"]


class TrainingRunRead(ApiModel):
    id: str
    dataset_id: str
    dataset_name: str
    model_id: str | None
    task: Literal["known_attack_classification_baseline", "unknown_anomaly_detection"]
    algorithm: Literal["hist_gradient_boosting", "mlp_autoencoder"]
    state: TrainingRunState
    requested_by: str
    dataset_sha256: str
    feature_version: str
    config: dict[str, Any]
    samples_seen: int
    samples_used: int
    started_at: datetime | None
    completed_at: datetime | None
    metrics: TrainingMetrics | AutoEncoderTrainingMetrics | None
    artifact_state: Literal["available", "missing", "unverified"]
    artifact_sha256: str | None
    error_message: str | None
    created_at: datetime
    updated_at: datetime


class TrainingRunsResponse(ApiModel):
    items: list[TrainingRunRead]


class RuleRead(ApiModel):
    id: str
    name: str
    stage: RuleStage
    source: Literal["agent", "analyst", "community"]
    severity: Severity
    coverage: str
    hit_rate: float
    false_positive_rate: float
    updated_at: datetime
    author: str
    revision: int
    content: str
    rationale: str
    quality_score: float | None = None


class RuleCondition(BaseModel):
    field: str
    operator: Literal[">", ">=", "<", "<=", "==", "!=", "in"]
    value: int | float | str | list[str]


class StructuredRule(BaseModel):
    rule_id: str
    rule_name: str
    description: str
    attack_type: str
    severity: Severity
    attack_stage: str
    mitre_technique_ids: list[str]
    conditions: list[RuleCondition] = Field(min_length=1)
    evidence_ids: list[str]
    generated_by: str
    version: int = Field(ge=1)
    parent_rule_id: str | None = None


class RuleCheck(ApiModel):
    label: str
    passed: bool
    note: str


class RuleValidationRead(ApiModel):
    quality_score: float
    syntax: float
    attack_hit_ability: float
    low_false_positive: float
    coverage: float
    non_redundancy: float
    evidence_consistency: float
    hit_rate: float
    false_positive_rate: float
    precision: float
    recall: float
    f1: float
    attack_coverage: float
    redundancy: float
    perturbation_robustness: float
    replay_attack_flows: int
    replay_normal_flows: int
    schema_checks: list[RuleCheck]


class RuleDetail(ApiModel):
    record: RuleRead
    structured: StructuredRule
    validation: RuleValidationRead
    source_alert_id: str
    previous_version: StructuredRule | None
    diff_reason: str
    expected_coverage_change: str
    false_positive_risk: str


class RuleAction(ApiModel):
    actor: str = Field(default="local-analyst", min_length=1, max_length=120)
    note: str | None = Field(default=None, max_length=500)
    reason: str | None = Field(default=None, max_length=500)


class RuleCandidateCreate(ApiModel):
    structured: StructuredRule
    source_alert_id: str = ""
    rationale: str = ""
    author: str = Field(default="local-analyst", min_length=1, max_length=120)
    source: Literal["agent", "analyst"] = "analyst"


class RuleTimelineEvent(ApiModel):
    id: str
    stage: RuleStage
    timestamp: datetime
    actor: str
    summary: str
    note: str | None = None
    outcome: Literal["completed", "failed"]


class RuleTimeline(ApiModel):
    current_stage: RuleStage
    items: list[RuleTimelineEvent]


class RulesResponse(ApiModel):
    items: list[RuleRead]
    total: int


class HealthResponse(ApiModel):
    status: Literal["ok", "degraded"]
    service: str
    environment: str
    database: Literal["ok", "error"]
    feature_version: str


class ReadinessCheck(ApiModel):
    id: str
    label: str
    status: Literal["pass", "warn", "block"]
    detail: str


class ReadinessResponse(ApiModel):
    status: Literal["ready", "attention"]
    environment: str
    checked_at: datetime
    blockers: int
    warnings: int
    checks: list[ReadinessCheck]


SensorState = Literal["online", "degraded", "offline", "maintenance"]


class SensorRead(ApiModel):
    id: str
    name: str
    location: str | None
    version: str | None
    state: SensorState
    health_reason: str
    last_seen_at: datetime | None
    flow_count: int
    alert_count: int
    critical_alerts: int
    accepted_events: int
    rejected_events: int
    ingest_source: str
    last_error: str | None
    created_at: datetime
    updated_at: datetime


class SensorSummary(ApiModel):
    total: int
    online: int
    degraded: int
    offline: int
    maintenance: int
    flows: int
    alerts: int
    rejected_events: int


class SensorsResponse(ApiModel):
    items: list[SensorRead]
    summary: SensorSummary


class OverviewRead(ApiModel):
    pending_alerts: int
    high_risk_alerts: int
    unassigned_alerts: int
    flows: int
    anomalous_flows: int
    candidate_rules: int
    deployed_rules: int
    sensors: SensorSummary


class SensorHeartbeat(ApiModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    location: str | None = Field(default=None, max_length=255)
    version: str | None = Field(default=None, max_length=80)
    metadata_json: dict[str, Any] = Field(default_factory=dict)


class SensorUpdate(ApiModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    location: str | None = Field(default=None, max_length=255)
    state: Literal["online", "maintenance"] | None = None
    actor: str = Field(default="local-admin", min_length=1, max_length=120)
    note: str | None = Field(default=None, max_length=500)


class IngestionFailure(ApiModel):
    line_number: int
    reason: str


class EveIngestionResponse(ApiModel):
    sensor_id: str
    accepted_events: int
    created_flows: int
    created_alerts: int
    duplicate_events: int
    rejected_events: int
    failures: list[IngestionFailure]


class AuditEventRead(ApiModel):
    id: str
    created_at: datetime
    actor: str
    action: str
    object_type: str
    object_id: str
    outcome: str
    request_id: str | None
    note: str | None


class AuditEventsResponse(ApiModel):
    items: list[AuditEventRead]
    total: int
    page: int
    page_size: int
