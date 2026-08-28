from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import HTTPException
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.base import utc_now
from app.db.models import Alert, AuditEvent, Flow, Rule, RuleValidation, RuleVersion
from app.domain.rules import (
    RuleCondition as DomainCondition,
    RuleValidationError,
    evaluate_rule,
    require_transition,
    validate_condition,
)
from app.schemas.api import (
    RuleAction,
    RuleCandidateCreate,
    RuleCheck,
    RuleDetail,
    RuleRead,
    RuleTimeline,
    RuleTimelineEvent,
    RuleValidationRead,
    StructuredRule,
)


EMPTY_METRICS = {
    "quality_score": 0.0,
    "syntax": 0.0,
    "attack_hit_ability": 0.0,
    "low_false_positive": 0.0,
    "coverage": 0.0,
    "non_redundancy": 0.0,
    "evidence_consistency": 0.0,
    "hit_rate": 0.0,
    "false_positive_rate": 0.0,
    "precision": 0.0,
    "recall": 0.0,
    "f1": 0.0,
    "attack_coverage": 0.0,
    "redundancy": 0.0,
    "perturbation_robustness": 0.0,
    "replay_attack_flows": 0,
    "replay_normal_flows": 0,
}


def create_candidate(
    db: Session,
    payload: RuleCandidateCreate,
    *,
    request_id: str | None,
) -> RuleDetail:
    structured = payload.structured
    if db.get(Rule, structured.rule_id) is not None:
        raise HTTPException(status_code=409, detail=f"Rule {structured.rule_id} already exists")
    if payload.source_alert_id and db.get(Alert, payload.source_alert_id) is None:
        raise HTTPException(
            status_code=422,
            detail=f"Source alert {payload.source_alert_id} does not exist",
        )
    checks = structural_checks(structured)
    failed = [check.note for check in checks if not check.passed]
    if failed:
        raise HTTPException(status_code=422, detail="; ".join(failed))

    now = utc_now()
    version_id = _version_id(structured.rule_id, structured.version)
    rule = Rule(
        id=structured.rule_id,
        name=structured.rule_name,
        stage="candidate",
        source=payload.source,
        severity=structured.severity,
        coverage=_coverage(structured),
        hit_rate=0.0,
        false_positive_rate=0.0,
        author=payload.author,
        revision=structured.version,
        content=json.dumps(structured.model_dump(), ensure_ascii=False),
        rationale=payload.rationale,
        quality_score=None,
        active_version_id=version_id,
        source_alert_id=payload.source_alert_id,
        diff_reason="",
        expected_coverage_change="Not measured until replay validation completes.",
        false_positive_risk="Not measured until normal-traffic replay completes.",
        created_at=now,
        updated_at=now,
    )
    version = RuleVersion(
        id=version_id,
        rule_id=rule.id,
        version=structured.version,
        parent_version_id=None,
        structured_rule=structured.model_dump(),
        generated_by=structured.generated_by,
        evidence_ids=structured.evidence_ids,
        created_at=now,
        updated_at=now,
    )
    db.add_all([rule, version])
    _audit(
        db,
        rule,
        actor=payload.author,
        action="rule.candidate",
        outcome="completed",
        request_id=request_id,
        before=None,
        note=payload.rationale or "Candidate rule created",
    )
    db.commit()
    return build_rule_detail(db, rule)


def build_rule_detail(db: Session, rule: Rule) -> RuleDetail:
    version = _current_version(db, rule)
    structured = StructuredRule.model_validate(version.structured_rule)
    validation = _latest_validation(db, version.id)
    previous = db.get(RuleVersion, version.parent_version_id) if version.parent_version_id else None
    return RuleDetail(
        record=RuleRead.model_validate(rule),
        structured=structured,
        validation=_validation_read(validation, structured),
        source_alert_id=rule.source_alert_id,
        previous_version=(
            StructuredRule.model_validate(previous.structured_rule) if previous is not None else None
        ),
        diff_reason=rule.diff_reason,
        expected_coverage_change=rule.expected_coverage_change,
        false_positive_risk=rule.false_positive_risk,
    )


def validate_or_advance(
    db: Session,
    rule: Rule,
    action: RuleAction,
    *,
    request_id: str | None,
) -> RuleDetail:
    version = _current_version(db, rule)
    structured = StructuredRule.model_validate(version.structured_rule)
    if rule.stage in {"candidate", "repaired"}:
        before_stage = rule.stage
        _transition(rule, "validating")
        validation = RuleValidation(
            id=f"VAL-{uuid.uuid4().hex.upper()}",
            rule_version_id=version.id,
            state="running",
            replay_dataset_version="local-labeled-flow-corpus",
            executor_version="rule-replay-v1",
            metrics=dict(EMPTY_METRICS),
            checks=[check.model_dump() for check in structural_checks(structured)],
            passed=False,
        )
        db.add(validation)
        _audit_transition(
            db,
            rule,
            actor=action.actor,
            action="rule.validating",
            request_id=request_id,
            before_stage=before_stage,
            note=action.note or "Rule queued for labeled-flow replay",
        )
        db.commit()
        return build_rule_detail(db, rule)
    if rule.stage != "validating":
        raise HTTPException(status_code=409, detail=f"Cannot validate a {rule.stage} rule")

    validation = _latest_validation(db, version.id)
    if validation is None:
        raise HTTPException(status_code=409, detail="No validation run exists for this version")
    metrics, checks, passed = replay_validation(db, structured)
    validation.metrics = metrics
    validation.checks = [check.model_dump() for check in checks]
    validation.passed = passed
    validation.state = "passed" if passed else "failed"
    rule.hit_rate = metrics["hit_rate"]
    rule.false_positive_rate = metrics["false_positive_rate"]
    rule.quality_score = metrics["quality_score"]
    target = "validated" if passed else "rejected"
    _transition(rule, target)
    rule.expected_coverage_change = (
        f"Labeled attack-flow coverage measured at {metrics['attack_coverage']:.2f}%."
    )
    rule.false_positive_risk = (
        f"Normal-flow replay false-positive rate measured at "
        f"{metrics['false_positive_rate']:.2f}%."
    )
    _audit_transition(
        db,
        rule,
        actor="validation-gate",
        action=f"rule.{target}",
        request_id=request_id,
        before_stage="validating",
        note=action.note or _validation_note(metrics, passed),
        outcome="completed" if passed else "failed",
    )
    db.commit()
    return build_rule_detail(db, rule)


def transition_rule(
    db: Session,
    rule: Rule,
    target: str,
    action: RuleAction,
    *,
    request_id: str | None,
) -> RuleDetail:
    before_stage = rule.stage
    note = (action.reason or action.note or "").strip()
    if target in {"rejected", "repaired", "deprecated"} and len(note) < 10:
        raise HTTPException(status_code=400, detail="A reason of at least 10 characters is required")
    if target == "deployed" and len(note) < 12:
        raise HTTPException(status_code=400, detail="A deployment note of at least 12 characters is required")

    if target == "repaired":
        _create_repair_version(db, rule, action)
    else:
        _transition(rule, target)
    if target == "rejected":
        validation = _latest_validation(db, _current_version(db, rule).id)
        if validation is not None:
            validation.state = "rejected"
            validation.passed = False
    _audit_transition(
        db,
        rule,
        actor=action.actor,
        action=f"rule.{target}",
        request_id=request_id,
        before_stage=before_stage,
        note=note or None,
        outcome="failed" if target == "rejected" else "completed",
    )
    db.commit()
    return build_rule_detail(db, rule)


def rule_timeline(db: Session, rule: Rule) -> RuleTimeline:
    rows = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.object_type == "rule", AuditEvent.object_id == rule.id)
        .order_by(AuditEvent.created_at)
    ).all()
    items: list[RuleTimelineEvent] = []
    for row in rows:
        stage = (row.after_state or {}).get("stage")
        if stage not in {
            "candidate",
            "validating",
            "validated",
            "rejected",
            "repaired",
            "confirmed",
            "deployed",
            "deprecated",
        }:
            continue
        items.append(
            RuleTimelineEvent(
                id=row.id,
                stage=stage,
                timestamp=row.created_at,
                actor=row.actor,
                summary=_timeline_summary(stage),
                note=row.note,
                outcome="failed" if row.outcome == "failed" else "completed",
            )
        )
    return RuleTimeline(current_stage=rule.stage, items=items)


def structural_checks(structured: StructuredRule) -> list[RuleCheck]:
    checks = [
        RuleCheck(label="JSON Schema", passed=True, note="Structure conforms to evonids.rule/v1")
    ]
    errors: list[str] = []
    for condition in structured.conditions:
        try:
            validate_condition(
                DomainCondition(
                    field=condition.field,
                    operator=condition.operator,
                    value=condition.value,
                )
            )
        except RuleValidationError as exc:
            errors.append(str(exc))
    checks.append(
        RuleCheck(
            label="Feature and operator validity",
            passed=not errors,
            note="All conditions use registered fields and operators" if not errors else "; ".join(errors),
        )
    )
    checks.append(
        RuleCheck(
            label="RAG evidence linkage",
            passed=bool(structured.evidence_ids),
            note=(
                f"{len(structured.evidence_ids)} evidence identifiers are linked"
                if structured.evidence_ids
                else "No evidence identifiers are linked"
            ),
        )
    )
    return checks


def replay_validation(
    db: Session,
    structured: StructuredRule,
) -> tuple[dict[str, Any], list[RuleCheck], bool]:
    rows = db.scalars(select(Flow)).all()
    attack_rows = [row for row in rows if row.verdict in {"malicious", "suspicious"}]
    normal_rows = [row for row in rows if row.verdict == "benign"]
    domain_conditions = [
        DomainCondition(field=item.field, operator=item.operator, value=item.value)
        for item in structured.conditions
    ]

    attack_hits = sum(evaluate_rule(domain_conditions, row.features) for row in attack_rows)
    normal_hits = sum(evaluate_rule(domain_conditions, row.features) for row in normal_rows)
    recall = _percent(attack_hits, len(attack_rows))
    false_positive_rate = _percent(normal_hits, len(normal_rows))
    precision = _percent(attack_hits, attack_hits + normal_hits)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    syntax = 100.0
    low_false_positive = max(0.0, 100.0 - false_positive_rate)
    evidence_consistency = 100.0 if structured.evidence_ids else 0.0
    non_redundancy = 100.0
    quality = (
        syntax * 0.10
        + recall * 0.30
        + low_false_positive * 0.25
        + recall * 0.15
        + non_redundancy * 0.10
        + evidence_consistency * 0.10
    )
    metrics = {
        "quality_score": round(quality, 2),
        "syntax": syntax,
        "attack_hit_ability": recall,
        "low_false_positive": round(low_false_positive, 2),
        "coverage": recall,
        "non_redundancy": non_redundancy,
        "evidence_consistency": evidence_consistency,
        "hit_rate": recall,
        "false_positive_rate": false_positive_rate,
        "precision": precision,
        "recall": recall,
        "f1": round(f1, 2),
        "attack_coverage": recall,
        "redundancy": 0.0,
        "perturbation_robustness": 0.0,
        "replay_attack_flows": len(attack_rows),
        "replay_normal_flows": len(normal_rows),
    }
    checks = structural_checks(structured)
    corpus_ready = bool(attack_rows) and bool(normal_rows)
    checks.append(
        RuleCheck(
            label="Replay corpus sufficiency",
            passed=corpus_ready,
            note=(
                f"{len(attack_rows)} labeled attack flows and {len(normal_rows)} normal flows"
                if corpus_ready
                else "Replay requires at least one labeled attack flow and one normal flow"
            ),
        )
    )
    checks.append(
        RuleCheck(
            label="Replay acceptance gate",
            passed=corpus_ready and recall >= 70 and false_positive_rate <= 5,
            note=f"Recall {recall:.2f}%; false-positive rate {false_positive_rate:.2f}%",
        )
    )
    passed = all(check.passed for check in checks)
    return metrics, checks, passed


def _create_repair_version(db: Session, rule: Rule, action: RuleAction) -> None:
    _transition(rule, "repaired")
    current = _current_version(db, rule)
    structured = StructuredRule.model_validate(current.structured_rule)
    next_version = current.version + 1
    repaired = structured.model_copy(
        update={
            "version": next_version,
            "parent_rule_id": structured.rule_id,
        }
    )
    new_id = _version_id(rule.id, next_version)
    db.add(
        RuleVersion(
            id=new_id,
            rule_id=rule.id,
            version=next_version,
            parent_version_id=current.id,
            structured_rule=repaired.model_dump(),
            generated_by=action.actor,
            evidence_ids=repaired.evidence_ids,
        )
    )
    rule.active_version_id = new_id
    rule.revision = next_version
    rule.content = json.dumps(repaired.model_dump(), ensure_ascii=False)
    rule.rationale = (action.reason or action.note or "").strip()
    rule.diff_reason = rule.rationale
    rule.quality_score = None
    rule.hit_rate = 0.0
    rule.false_positive_rate = 0.0


def _validation_read(
    validation: RuleValidation | None,
    structured: StructuredRule,
) -> RuleValidationRead:
    metrics = {**EMPTY_METRICS, **(validation.metrics if validation else {})}
    checks = (
        [RuleCheck.model_validate(item) for item in validation.checks]
        if validation
        else structural_checks(structured)
    )
    return RuleValidationRead(**metrics, schema_checks=checks)


def _current_version(db: Session, rule: Rule) -> RuleVersion:
    version = db.get(RuleVersion, rule.active_version_id) if rule.active_version_id else None
    if version is None:
        version = db.scalar(
            select(RuleVersion)
            .where(RuleVersion.rule_id == rule.id)
            .order_by(desc(RuleVersion.version))
        )
    if version is None:
        raise HTTPException(status_code=409, detail=f"Rule {rule.id} has no structured version")
    return version


def _latest_validation(db: Session, version_id: str) -> RuleValidation | None:
    return db.scalar(
        select(RuleValidation)
        .where(RuleValidation.rule_version_id == version_id)
        .order_by(desc(RuleValidation.created_at))
    )


def _transition(rule: Rule, target: str) -> None:
    try:
        require_transition(rule.stage, target)
    except RuleValidationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    rule.stage = target
    rule.updated_at = utc_now()


def _audit_transition(
    db: Session,
    rule: Rule,
    *,
    actor: str,
    action: str,
    request_id: str | None,
    before_stage: str,
    note: str | None,
    outcome: str = "completed",
) -> None:
    _audit(
        db,
        rule,
        actor=actor,
        action=action,
        outcome=outcome,
        request_id=request_id,
        before={"stage": before_stage},
        note=note,
    )


def _audit(
    db: Session,
    rule: Rule,
    *,
    actor: str,
    action: str,
    outcome: str,
    request_id: str | None,
    before: dict[str, Any] | None,
    note: str | None,
) -> None:
    db.add(
        AuditEvent(
            id=f"AUD-{uuid.uuid4().hex.upper()}",
            created_at=utc_now(),
            actor=actor,
            action=action,
            object_type="rule",
            object_id=rule.id,
            outcome=outcome,
            request_id=request_id,
            before_state=before,
            after_state={"stage": rule.stage, "revision": rule.revision},
            note=note,
        )
    )


def _coverage(structured: StructuredRule) -> str:
    techniques = ", ".join(structured.mitre_technique_ids)
    return f"{structured.attack_type} / {techniques}" if techniques else structured.attack_type


def _version_id(rule_id: str, version: int) -> str:
    return f"{rule_id}:v{version}"


def _percent(numerator: int, denominator: int) -> float:
    return round(numerator / denominator * 100, 2) if denominator else 0.0


def _validation_note(metrics: dict[str, Any], passed: bool) -> str:
    result = "passed" if passed else "failed"
    return (
        f"Replay {result}: recall {metrics['recall']:.2f}%, false-positive rate "
        f"{metrics['false_positive_rate']:.2f}%, F1 {metrics['f1']:.2f}%"
    )


def _timeline_summary(stage: str) -> str:
    return {
        "candidate": "Candidate rule created",
        "validating": "Labeled-flow replay started",
        "validated": "Replay validation passed",
        "rejected": "Validation or review rejected the rule",
        "repaired": "A repaired rule version was created",
        "confirmed": "An analyst confirmed the validated version",
        "deployed": "The confirmed rule was approved for deployment",
        "deprecated": "The rule was removed from the active detection set",
    }[stage]
