from __future__ import annotations

import uuid
from typing import Any

from fastapi import HTTPException
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models import AgentRun, Alert, AuditEvent, Flow, Inference, Rule
from app.schemas.api import (
    AgentAnalysis,
    AgentStep,
    AlertDetail,
    AlertRead,
    AlertUpdate,
    AnomalyProfile,
    AutoEncoderOutput,
    RiskFusion,
    TransformerOutput,
)
from app.services.knowledge_retrieval import search_evidence


ALLOWED_ALERT_TRANSITIONS = {
    "new": {"investigating", "contained", "closed"},
    "investigating": {"contained", "closed"},
    "contained": {"investigating", "closed"},
    "closed": {"investigating"},
}


def build_alert_detail(db: Session, alert: Alert) -> AlertDetail:
    flow = db.get(Flow, alert.flow_id) if alert.flow_id else None
    inference = db.get(Inference, alert.inference_id) if alert.inference_id else None
    features = flow.features if flow else {}
    transformer_data = inference.transformer_output if inference else {}
    autoencoder_data = inference.autoencoder_output if inference else {}
    fusion_data = inference.fusion_output if inference else {}

    transformer = TransformerOutput.model_validate(
        {
            "prediction": transformer_data.get("prediction", "Not run"),
            "confidence": transformer_data.get("confidence", 0.0),
            "top_k": transformer_data.get("top_k", []),
            "model_version": transformer_data.get("model_version", "not-run"),
            "inference_ms": transformer_data.get("inference_ms", 0.0),
            "abnormal_features": transformer_data.get("abnormal_features", []),
            "is_known_class": transformer_data.get("is_known_class", False),
            "pretraining_task": transformer_data.get(
                "pretraining_task",
                "Masked Feature Modeling" if transformer_data else "Not run",
            ),
        }
    )
    autoencoder = AutoEncoderOutput.model_validate(
        {
            "reconstruction_error": autoencoder_data.get("reconstruction_error", 0.0),
            "threshold": autoencoder_data.get("threshold", 0.0),
            "anomaly_score": autoencoder_data.get("anomaly_score", 0.0),
            "exceeds_threshold": autoencoder_data.get("exceeds_threshold", False),
            "deviating_features": autoencoder_data.get("deviating_features", []),
            "model_version": autoencoder_data.get("model_version", "not-run"),
            "inference_ms": autoencoder_data.get("inference_ms", 0.0),
            "trained_on": "normal_traffic",
        }
    )
    fusion = RiskFusion.model_validate(
        {
            "final_score": fusion_data.get("final_score", alert.risk_score),
            "transformer_weight": fusion_data.get("transformer_weight", 0.0),
            "auto_encoder_weight": fusion_data.get("auto_encoder_weight", 0.0),
            "context_adjustment": fusion_data.get("context_adjustment", 0.0),
            "agreement": fusion_data.get("agreement", "partial"),
            "lean": fusion_data.get(
                "lean",
                "known_attack" if alert.category != "Unknown Anomaly" else "unknown_anomaly",
            ),
            "explanation": fusion_data.get(
                "explanation",
                "This alert was created from a Suricata signature. The dual-channel ML pipeline "
                "has not run, so no Transformer or AutoEncoder result is claimed.",
            ),
        }
    )
    profile = _profile(alert, flow, features, transformer_data, autoencoder_data, fusion_data)
    rag_query = (
        f"{alert.category} {alert.protocol} destination port {alert.destination_port} "
        f"{alert.title}"
    )
    retrieval = search_evidence(db, query=rag_query, top_k=8, agent_limit=4)
    related = db.scalar(
        select(Rule)
        .where(Rule.source_alert_id == alert.id)
        .order_by(desc(Rule.updated_at))
    )
    latest_agent_run = db.scalar(
        select(AgentRun)
        .where(AgentRun.alert_id == alert.id)
        .order_by(desc(AgentRun.created_at))
    )
    evidence_ready = retrieval.retrieval.provided_to_agent > 0
    return AlertDetail(
        alert=AlertRead.model_validate(alert),
        profile=profile,
        transformer=transformer,
        auto_encoder=autoencoder,
        fusion=fusion,
        rag=retrieval.items,
        agent=(
            AgentAnalysis(
                display_model="DeepSeek V4 Pro",
                run_id=latest_agent_run.id,
                state=latest_agent_run.state,
                hypothesis=latest_agent_run.hypothesis,
                pattern_decision=latest_agent_run.pattern_decision,
                summary=latest_agent_run.summary,
                recommendation=latest_agent_run.recommendation,
                evidence_ids=latest_agent_run.evidence_ids,
                steps=[AgentStep.model_validate(step) for step in latest_agent_run.steps],
            )
            if latest_agent_run
            else AgentAnalysis(
                run_id=f"AGENT-NOT-RUN-{alert.id}",
                state="failed",
                hypothesis="No Agent analysis has been executed for this persisted alert.",
                pattern_decision="known_match" if alert.category != "Unknown Anomaly" else "new_pattern",
                summary=(
                    "Trusted RAG evidence is ready, but no large-model conclusion is stored."
                    if evidence_ready
                    else "Only sensor evidence is available. No large-model conclusion is stored."
                ),
                recommendation=(
                    "The server-side Agent may now be run with the filtered evidence set."
                    if evidence_ready
                    else "Register trusted RAG evidence before running the server-side Agent."
                ),
                evidence_ids=[],
                steps=[
                    AgentStep(
                        id="precondition",
                        label="Agent precondition",
                        state="failed",
                        tool="evidence-gate",
                        duration_ms=0,
                        result=(
                            "Trusted evidence is available; an Agent run has not been requested."
                            if evidence_ready
                            else "No trusted RAG evidence or persisted Agent run is available."
                        ),
                    )
                ],
            )
        ),
        rag_query=rag_query,
        related_rule=(
            {
                "record_id": related.id,
                "rule_id": related.id,
                "label": related.name,
            }
            if related
            else None
        ),
    )


def update_alert(
    db: Session,
    alert: Alert,
    update: AlertUpdate,
    *,
    request_id: str | None,
) -> Alert:
    before = _alert_state(alert)
    fields = update.model_fields_set
    if "status" in fields and update.status and update.status != alert.status:
        allowed = ALLOWED_ALERT_TRANSITIONS.get(alert.status, set())
        if update.status not in allowed:
            raise HTTPException(
                status_code=409,
                detail=f"Alert transition {alert.status} -> {update.status} is not allowed",
            )
        if update.status in {"contained", "closed"} and not (update.note or "").strip():
            raise HTTPException(status_code=400, detail="A disposition note is required")
        alert.status = update.status
    if "owner" in fields:
        alert.owner = update.owner
        if update.owner and alert.status == "new":
            alert.status = "investigating"
    after = _alert_state(alert)
    if before == after:
        raise HTTPException(status_code=400, detail="The request does not change the alert")

    db.add(
        AuditEvent(
            id=f"AUD-{uuid.uuid4().hex.upper()}",
            created_at=utc_now(),
            actor=update.actor,
            action="alert.update",
            object_type="alert",
            object_id=alert.id,
            outcome="completed",
            request_id=request_id,
            before_state=before,
            after_state=after,
            note=update.note,
        )
    )
    db.commit()
    db.refresh(alert)
    return alert


def _profile(
    alert: Alert,
    flow: Flow | None,
    features: dict[str, Any],
    transformer: dict[str, Any],
    autoencoder: dict[str, Any],
    fusion: dict[str, Any],
) -> AnomalyProfile:
    duration = float(features.get("flow_duration", (flow.duration_ms / 1000 if flow else 0.0)))
    return AnomalyProfile(
        flow_id=flow.id if flow else (alert.flow_id or "unlinked"),
        timestamp=alert.timestamp.isoformat(),
        src_ip=flow.source if flow else alert.source_ip,
        src_port=flow.source_port if flow else 0,
        dst_ip=flow.destination if flow else alert.destination_ip,
        dst_port=flow.destination_port if flow else alert.destination_port,
        protocol=flow.protocol if flow else alert.protocol,
        service=flow.service if flow else "unknown",
        flow_duration=duration,
        forward_packet_count=int(features.get("forward_packet_count", 0)),
        backward_packet_count=int(features.get("backward_packet_count", 0)),
        forward_bytes=int(features.get("forward_bytes", 0)),
        backward_bytes=int(features.get("backward_bytes", 0)),
        packets_per_second=float(features.get("packets_per_second", 0.0)),
        bytes_per_second=float(features.get("bytes_per_second", 0.0)),
        syn_ratio=float(features.get("syn_ratio", 0.0)),
        ack_ratio=float(features.get("ack_ratio", 0.0)),
        rst_ratio=float(features.get("rst_ratio", 0.0)),
        destination_port_count_60s=int(features.get("destination_port_count_60s", 0)),
        destination_ip_count_60s=int(features.get("destination_ip_count_60s", 0)),
        flow_count_60s=int(features.get("flow_count_60s", 0)),
        average_packet_size=float(features.get("average_packet_size", 0.0)),
        transformer_prediction=str(transformer.get("prediction", "Not run")),
        transformer_confidence=float(transformer.get("confidence", 0.0)),
        autoencoder_reconstruction_error=float(autoencoder.get("reconstruction_error", 0.0)),
        autoencoder_anomaly_score=float(autoencoder.get("anomaly_score", 0.0)),
        final_risk_score=float(fusion.get("final_score", alert.risk_score)),
        suspected_attack_type=alert.category,
    )


def _alert_state(alert: Alert) -> dict[str, Any]:
    return {"status": alert.status, "owner": alert.owner}
