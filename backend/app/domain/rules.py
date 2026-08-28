from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.domain.features import FEATURES


class RuleStage(StrEnum):
    CANDIDATE = "candidate"
    VALIDATING = "validating"
    VALIDATED = "validated"
    REJECTED = "rejected"
    REPAIRED = "repaired"
    CONFIRMED = "confirmed"
    DEPLOYED = "deployed"
    DEPRECATED = "deprecated"


ALLOWED_TRANSITIONS = {
    RuleStage.CANDIDATE: {RuleStage.VALIDATING},
    RuleStage.REPAIRED: {RuleStage.VALIDATING},
    RuleStage.VALIDATING: {RuleStage.VALIDATED, RuleStage.REJECTED},
    RuleStage.VALIDATED: {RuleStage.CONFIRMED, RuleStage.REPAIRED},
    RuleStage.REJECTED: {RuleStage.REPAIRED},
    RuleStage.CONFIRMED: {RuleStage.DEPLOYED, RuleStage.REPAIRED},
    RuleStage.DEPLOYED: {RuleStage.DEPRECATED, RuleStage.REPAIRED},
    RuleStage.DEPRECATED: {RuleStage.REPAIRED},
}

OPERATORS = {">", ">=", "<", "<=", "==", "!=", "in"}


@dataclass(frozen=True, slots=True)
class RuleCondition:
    field: str
    operator: str
    value: Any


class RuleValidationError(ValueError):
    pass


def require_transition(current: str | RuleStage, target: str | RuleStage) -> RuleStage:
    current_stage = RuleStage(current)
    target_stage = RuleStage(target)
    if target_stage not in ALLOWED_TRANSITIONS.get(current_stage, set()):
        raise RuleValidationError(f"transition {current_stage.value} -> {target_stage.value} is not allowed")
    return target_stage


def validate_condition(condition: RuleCondition) -> None:
    if condition.field not in FEATURES:
        raise RuleValidationError(f"field {condition.field!r} is not in feature schema")
    if condition.operator not in OPERATORS:
        raise RuleValidationError(f"operator {condition.operator!r} is not allowed")
    if condition.operator == "in" and not isinstance(condition.value, (list, tuple, set)):
        raise RuleValidationError("'in' requires a list, tuple or set")


def evaluate_condition(condition: RuleCondition, record: dict[str, Any]) -> bool:
    validate_condition(condition)
    if condition.field not in record or record[condition.field] is None:
        return False
    observed = record[condition.field]
    expected = condition.value
    try:
        return {
            ">": lambda: observed > expected,
            ">=": lambda: observed >= expected,
            "<": lambda: observed < expected,
            "<=": lambda: observed <= expected,
            "==": lambda: observed == expected,
            "!=": lambda: observed != expected,
            "in": lambda: observed in expected,
        }[condition.operator]()
    except TypeError as exc:
        raise RuleValidationError(
            f"cannot compare {condition.field} value {observed!r} using {condition.operator} {expected!r}"
        ) from exc


def evaluate_rule(
    conditions: list[RuleCondition],
    record: dict[str, Any],
    *,
    match: str = "all",
) -> bool:
    if not conditions:
        raise RuleValidationError("a rule requires at least one condition")
    results = [evaluate_condition(condition, record) for condition in conditions]
    if match == "all":
        return all(results)
    if match == "any":
        return any(results)
    raise RuleValidationError("match must be 'all' or 'any'")

