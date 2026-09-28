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
    "Known Attack",
    "Known Attack + Anomaly",
]
RuleStage = Literal[
    "candidate",
    "validating",
    "validated",
    "validation_failed",
    "rejected",
    "repaired",
    "confirmed",
    "canary",
    "deployed",
    "rolled_back",
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
    mode: Literal["keyword_fallback", "keyword_bm25", "hybrid_bm25_vector"]
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
    workspace_id: str = Field(default="default", min_length=1, max_length=64)


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
    agent_version: str | None = None
    last_heartbeat_at: datetime | None = None
    clock_skew_seconds: float | None = None
    spool_depth: int = 0
    dropped_events: int = 0
    expected_interval_seconds: int = 60
    capabilities: list[str] = Field(default_factory=list)
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
    agent_version: str | None = Field(default=None, max_length=80)
    capabilities: list[str] = Field(default_factory=list, max_length=32)
    spool_depth: int = Field(default=0, ge=0)
    dropped_events: int = Field(default=0, ge=0)
    clock_skew_seconds: float | None = Field(default=None, ge=-86400, le=86400)
    expected_interval_seconds: int = Field(default=60, ge=1, le=86400)
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


class EveBatchDetectionResult(ApiModel):
    mode: str
    flows_scored: int
    signals: int
    assessments: int
    alerts_created: int = Field(default=0, alias="alertsCreated")
    degraded: bool = False
    degraded_reasons: list[str] = Field(default_factory=list, alias="degradedReasons")
    models: dict[str, str | None] = Field(default_factory=dict)


class EveIngestionResponse(ApiModel):
    sensor_id: str
    accepted_events: int
    created_flows: int
    created_alerts: int
    duplicate_events: int
    rejected_events: int
    failures: list[IngestionFailure]
    detection: EveBatchDetectionResult | None = None


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


ConsoleAuditAction = Literal[
    "console.login.success",
    "console.login.failure",
    "console.login.locked",
    "console.logout",
]


class ConsoleAuditEvent(ApiModel):
    action: ConsoleAuditAction
    note: str | None = Field(default=None, max_length=500)


ApiKeyScope = Literal["admin", "sensor", "analyst"]


class ApiKeyCreate(ApiModel):
    name: str = Field(min_length=1, max_length=120)
    scope: ApiKeyScope


class ApiKeyRead(ApiModel):
    id: str
    name: str
    scope: ApiKeyScope
    prefix: str
    enabled: bool
    last_used_at: datetime | None = None


class ApiKeyCreated(ApiKeyRead):
    secret: str


class ApiKeysResponse(ApiModel):
    items: list[ApiKeyRead]


CaseSeverity = Literal["critical", "high", "medium", "low"]
CaseStatus = Literal["open", "investigating", "contained", "closed", "archived"]


class CaseCreate(ApiModel):
    title: str = Field(min_length=3, max_length=255)
    summary: str = Field(default="", max_length=4000)
    severity: CaseSeverity = Field(default="medium")


class CaseRead(ApiModel):
    id: str
    title: str
    summary: str
    severity: CaseSeverity
    status: CaseStatus
    assignee: str | None = None
    created_by: str
    alert_count: int
    highest_risk_score: float
    created_at: datetime
    updated_at: datetime


class CaseUpdate(ApiModel):
    summary: str | None = Field(default=None, max_length=4000)
    assignee: str | None = Field(default=None, max_length=120)
    status: CaseStatus | None = None
    note: str | None = Field(default=None, max_length=2000)


class CaseAttachRequest(ApiModel):
    alert_id: str = Field(min_length=1, max_length=96)


class CasesResponse(ApiModel):
    items: list[CaseRead]
    total: int
    page: int
    page_size: int


class CaseTimelineItem(ApiModel):
    id: str
    event_type: str
    actor: str
    note: str | None = None
    created_at: datetime


class CaseDetail(ApiModel):
    case: CaseRead
    alerts: list[AlertRead]
    timeline: list[CaseTimelineItem]


class EvidenceRead(ApiModel):
    id: str
    source_type: str
    sensor_id: str
    event_type: str
    external_id: str
    observed_at: datetime
    received_at: datetime
    content_sha256: str
    integrity: str
    data_missing: str
    parser_version: str
    redacted: bool
    source_ref_type: str | None = None
    source_ref_id: str | None = None
    artifact_size_bytes: int
    created_at: datetime


class EvidenceListResponse(ApiModel):
    items: list[EvidenceRead]
    total: int
    page: int
    page_size: int


class EvidenceDetail(EvidenceRead):
    fields: dict[str, Any]
    artifact_text: str | None = None


class EntityRead(ApiModel):
    id: str
    entity_type: str
    value: str
    first_seen_at: datetime
    last_seen_at: datetime
    event_count: int
    sensor_ids: list[str]
    created_at: datetime


class EntitiesResponse(ApiModel):
    items: list[EntityRead]
    total: int
    page: int
    page_size: int


class EntityRelationItem(ApiModel):
    id: str
    relation_type: str
    other_entity_id: str
    other_entity_value: str
    event_count: int
    first_seen_at: datetime
    last_seen_at: datetime


class EntityDetail(EntityRead):
    relations: list[EntityRelationItem]


class CaseSuggestionItem(ApiModel):
    case_id: str
    case_title: str
    case_status: str
    shared_ips: list[str]
    matching_alert_ids: list[str]
    updated_at: datetime


class CaseSuggestionResponse(ApiModel):
    items: list[CaseSuggestionItem]


DetectionChannel = Literal["suricata", "baseline", "autoencoder"]
DetectionDecision = Literal["alert", "benign", "abstain"]
DetectionModeLiteral = Literal["disabled", "shadow", "enabled"]


class DetectionSignalRead(ApiModel):
    id: str
    created_at: datetime
    flow_id: str | None = None
    alert_id: str | None = None
    sensor_id: str
    channel: DetectionChannel
    channel_version: str
    model_id: str | None = None
    raw_score: float
    calibrated_score: float
    threshold: float
    decision: DetectionDecision
    uncertainty: float
    feature_version: str
    feature_source: str
    imputed_features: list[str]
    latency_ms: float
    degraded: bool
    degraded_reason: str | None = None
    detail: dict[str, Any]


class DetectionSignalsResponse(ApiModel):
    items: list[DetectionSignalRead]
    total: int
    page: int
    page_size: int


class RiskAssessmentRead(ApiModel):
    id: str
    created_at: datetime
    flow_id: str | None = None
    alert_id: str | None = None
    sensor_id: str
    signal_ids: list[str]
    inputs: list[dict[str, Any]]
    weights: dict[str, Any]
    final_score: float
    uncertainty: float
    decision: Literal["malicious", "suspicious", "benign", "abstain"]
    explanation: str
    degraded_reasons: list[str]
    mode: str


class DetectionChannelStatus(ApiModel):
    available: bool
    model_id: str | None = None
    version: str | None = None
    contract_matches: bool
    reason: str | None = None


class DetectionStatusResponse(ApiModel):
    mode: DetectionModeLiteral
    feature_version: str
    channels: dict[str, DetectionChannelStatus]
    alerting: bool
    notes: list[str]


class DetectionFlowDetail(ApiModel):
    flow_id: str
    signals: list[DetectionSignalRead]
    assessments: list[RiskAssessmentRead]


class SensorMetric(ApiModel):
    value: float | None = None
    measured: bool
    unit: str
    note: str | None = None


class SensorDataQuality(ApiModel):
    sensor_id: str
    state: SensorState
    health_reason: str
    window_seconds: int
    batches: int
    events_accepted: int
    events_rejected: int
    events_duplicate: int
    reject_rate: SensorMetric
    duplicate_rate: SensorMetric
    ingest_latency_p50_ms: SensorMetric
    ingest_latency_p95_ms: SensorMetric
    clock_skew_seconds: SensorMetric
    gap_count: SensorMetric
    estimated_missing_seconds: SensorMetric
    spool_depth: int
    dropped_events: int
    expected_interval_seconds: int
    last_batch_at: datetime | None = None
    last_event_at: datetime | None = None
    last_heartbeat_at: datetime | None = None


class SensorHealthResponse(ApiModel):
    items: list[SensorDataQuality]


class IngestionBatchRead(ApiModel):
    id: str
    sensor_id: str
    batch_id: str
    received_at: datetime
    content_sha256: str
    encoding: str
    payload_bytes: int
    event_count: int
    accepted_count: int
    duplicate_count: int
    rejected_count: int
    created_flows: int
    created_alerts: int
    first_event_at: datetime | None = None
    last_event_at: datetime | None = None
    clock_skew_seconds: float | None = None
    status: str


class IngestionBatchesResponse(ApiModel):
    items: list[IngestionBatchRead]
    total: int
    page: int
    page_size: int


class EveBatchIngestionResponse(EveIngestionResponse):
    batch_id: str
    replayed: bool
    content_sha256: str = ""


InvestigationState = Literal[
    "queued", "running", "succeeded", "insufficient_evidence", "degraded", "failed", "cancelled"
]
ClaimType = Literal["observation", "inference", "recommendation", "rejected"]
FeedbackVerdict = Literal["agree", "disagree", "unsure"]
FeedbackObjectType = Literal["investigation_run", "alert", "flow", "claim"]


class InvestigationCreate(ApiModel):
    alert_id: str = Field(min_length=1, max_length=96)
    case_id: str | None = Field(default=None, max_length=96)
    max_tool_calls: int = Field(default=6, ge=1, le=6)
    budget_usd: float | None = Field(default=None, ge=0.0, le=10.0)


class InvestigationClaimRead(ApiModel):
    id: str
    run_id: str
    claim_index: int
    claim_type: ClaimType
    statement: str
    evidence_ids: list[str]
    confidence: float
    uncertainty: float
    mitre_techniques: list[str]
    verified: bool
    rejection_reason: str | None = None
    created_at: datetime


class ToolExecutionRead(ApiModel):
    id: str
    run_id: str
    tool_name: str
    tool_version: str
    arguments: dict[str, Any]
    result_summary: dict[str, Any]
    state: Literal["completed", "rejected", "failed"]
    duration_ms: float
    error: str | None = None
    created_at: datetime


class InvestigationRunRead(ApiModel):
    id: str
    alert_id: str | None = None
    case_id: str | None = None
    requested_by: str
    state: InvestigationState
    mode: str
    provider: str | None = None
    model_id: str | None = None
    prompt_template_version: str
    tool_registry_version: str
    knowledge_version: str | None = None
    max_tool_calls: int
    budget_usd: float
    input_evidence_ids: list[str]
    retrieval: dict[str, Any]
    summary: str
    uncertainty: float
    prompt_tokens: int
    completion_tokens: int
    cost_estimate_usd: float
    latency_ms: float
    attempts: int
    degraded_reasons: list[str]
    error_message: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class FeedbackRead(ApiModel):
    id: str
    object_type: str
    object_id: str
    verdict: FeedbackVerdict
    label: str | None = None
    comment: str | None = None
    actor: str
    created_at: datetime


class InvestigationDetail(ApiModel):
    run: InvestigationRunRead
    claims: list[InvestigationClaimRead]
    tools: list[ToolExecutionRead]
    feedback: list[FeedbackRead]


class InvestigationsResponse(ApiModel):
    items: list[InvestigationRunRead]
    total: int
    page: int
    page_size: int


class FeedbackCreate(ApiModel):
    object_type: FeedbackObjectType = "investigation_run"
    object_id: str = Field(min_length=1, max_length=96)
    verdict: FeedbackVerdict
    label: str | None = Field(default=None, max_length=64)
    comment: str | None = Field(default=None, max_length=1000)


class LlmCircuitState(ApiModel):
    state: Literal["open", "closed"]
    consecutive_failures: int
    reset_in_seconds: float


class LlmBudgetState(ApiModel):
    day: str
    spent_usd: float
    daily_budget_usd: float
    run_budget_usd: float
    remaining_usd: float


class LlmStatusResponse(ApiModel):
    provider: str
    model: str | None = None
    available: bool
    circuit: LlmCircuitState
    concurrency_limit: int
    timeout_seconds: float
    max_attempts: int
    budget: LlmBudgetState
    stats: dict[str, int]
    pricing_known: bool


class LlmProbeResponse(ApiModel):
    available: bool
    models: list[str]
    configured_model_exists: bool
    error: str | None = None


SandboxStatus = Literal["blocked", "partial", "validated", "validation_failed", "failed"]
DeploymentStateLiteral = Literal["canary", "deployed", "rolled_back"]


class RuleIRVersionRead(ApiModel):
    id: str
    rule_id: str
    version: int
    sid: int
    rev: int
    ir_digest: str
    ir_document: dict[str, Any]
    suricata_text: str
    state: str
    created_by: str
    created_at: datetime


class RuleSandboxRunRead(ApiModel):
    id: str
    rule_id: str
    rule_version_id: str
    status: SandboxStatus
    suricata_available: bool
    suricata_version: str | None = None
    syntax_passed: bool | None = None
    executor_version: str
    normal_pcap: str | None = None
    malicious_pcap: str | None = None
    metrics: dict[str, Any]
    checks: list[dict[str, Any]]
    passed: bool
    blocked_reason: str | None = None
    detail: dict[str, Any]
    created_at: datetime


class SandboxCapability(ApiModel):
    suricata_available: bool
    binary: str | None = None
    executor_version: str
    note: str
    # Without these the response_model silently dropped them and the console could
    # not show the corpus inventory or what resource measurement is possible here.
    corpus: dict[str, Any] = Field(default_factory=dict)
    resources: dict[str, Any] = Field(default_factory=dict)


class SensorGroupCreate(ApiModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    sensor_ids: list[str] = Field(default_factory=list, max_length=500)
    stage: Literal["canary", "production"] = "canary"


class SensorGroupRead(ApiModel):
    id: str
    name: str
    description: str
    sensor_ids: list[str]
    stage: str
    created_at: datetime
    updated_at: datetime


class SensorGroupsResponse(ApiModel):
    items: list[SensorGroupRead]


class RuleCompileRequest(ApiModel):
    ir: dict[str, Any]
    sid: int | None = Field(default=None, ge=1_000_000, le=1_999_999)


class RuleSandboxRequest(ApiModel):
    normal_pcap: str | None = Field(default=None, max_length=1_000)
    malicious_pcap: str | None = Field(default=None, max_length=1_000)
    regression_version_id: str | None = Field(default=None, max_length=96)
    malicious_flows: int = Field(default=0, ge=0, le=10_000_000)
    normal_flows: int = Field(default=0, ge=0, le=10_000_000)
    recall_floor: float = Field(default=0.8, ge=0.0, le=1.0)
    false_positives_per_million_ceiling: float = Field(default=1_000.0, ge=0.0)


class RuleDeploymentCreate(ApiModel):
    rule_version_id: str = Field(min_length=1, max_length=96)
    sensor_group_id: str = Field(min_length=1, max_length=96)
    state: DeploymentStateLiteral = "canary"
    note: str | None = Field(default=None, max_length=500)


class RuleDeploymentRead(ApiModel):
    id: str
    rule_id: str
    rule_version_id: str
    sensor_group_id: str
    state: DeploymentStateLiteral
    deployed_by: str
    deployed_at: datetime | None = None
    promoted_at: datetime | None = None
    rolled_back_at: datetime | None = None
    rollback_reason: str | None = None
    monitoring: dict[str, Any]
    previous_version_id: str | None = None
    created_at: datetime


class RuleDeploymentsResponse(ApiModel):
    items: list[RuleDeploymentRead]


class RuleBridgeRequest(ApiModel):
    """Convert a legacy structured rule into normalized Rule IR."""

    structured: dict[str, Any]
    sid: int | None = Field(default=None, ge=1_000_000, le=1_999_999)
    msg: str | None = Field(default=None, max_length=200)
    accept_partial: bool = False


class RuleConditionAssessment(ApiModel):
    condition: dict[str, Any]
    disposition: Literal["supported", "approximate", "unsupported"]
    reason: str


class RuleBridgeResponse(ApiModel):
    compilable: bool
    ir_document: dict[str, Any] | None = None
    suricata_text: str | None = None
    supported: list[RuleConditionAssessment]
    approximate: list[RuleConditionAssessment]
    unsupported: list[RuleConditionAssessment]
    dropped_count: int
    notes: list[str]


class RuleRollbackRequest(ApiModel):
    reason: str = Field(min_length=10, max_length=500)


class RulePromoteRequest(ApiModel):
    note: str | None = Field(default=None, max_length=500)
    target_group_id: str | None = Field(default=None, max_length=96)


ModelRolloutState = Literal["shadow", "canary", "active", "retired"]


class ModelRolloutRequest(ApiModel):
    state: ModelRolloutState
    note: str | None = Field(default=None, max_length=500)


class ModelRollbackRequest(ApiModel):
    role: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=10, max_length=500)


class ModelRolloutRead(ApiModel):
    id: str
    name: str
    role: str
    version: str
    state: str
    rollout: ModelRolloutState
    rollout_updated_at: str | None = None
    rollout_updated_by: str | None = None
    rollout_note: str | None = None
    artifact_state: str
    feature_version: str
    contract_matches: bool


class ModelRolloutsResponse(ApiModel):
    items: list[ModelRolloutRead]
    active: dict[str, str]
