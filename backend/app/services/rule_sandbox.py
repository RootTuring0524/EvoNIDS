"""Real Suricata sandbox: syntax check plus labelled PCAP replay.

The predicate replay in ``app.services.rule_lifecycle`` evaluates conditions
against stored flow rows. It is useful for triage, but it is **not** Suricata
validation and is never reported as such. This module runs the actual Suricata
binary when it is available and otherwise records an explicit ``blocked`` run, so
a rule can never be described as "validated by Suricata" on a host where Suricata
never ran.

Every quantitative field is tri-state: a real number, or ``None`` meaning
"unmeasured", which the API returns as null and the console renders as 未测量.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, Sequence

from sqlalchemy.orm import Session

from app.core.process_usage import ProcessUsage, platform_support, run_measured
from app.db.base import utc_now
from app.db.models import RuleIRVersion, RuleSandboxRun
from app.services.replay_corpus import CorpusPathError, corpus_summary, validate_capture_path

EXECUTOR_VERSION = "suricata-subprocess-v2"
DEFAULT_RECALL_FLOOR = 0.8
DEFAULT_FP_PER_MILLION_CEILING = 1_000.0
MAX_ALERTS_PARSED = 20_000
NOT_MEASURED = None


class SuricataUnavailable(RuntimeError):
    """Raised when the Suricata binary cannot be used on this host."""


@dataclass(frozen=True, slots=True)
class ReplayOutcome:
    exit_code: int
    alerts: tuple[dict[str, Any], ...]
    stdout: str
    stderr: str
    duration_ms: float
    usage: ProcessUsage | None = None

    @property
    def alert_flow_ids(self) -> frozenset[str]:
        return frozenset(
            str(alert.get("flow_id")) for alert in self.alerts if alert.get("flow_id") is not None
        )

    @property
    def alert_sids(self) -> frozenset[int]:
        sids = set()
        for alert in self.alerts:
            data = alert.get("alert")
            if isinstance(data, dict) and isinstance(data.get("signature_id"), int):
                sids.add(int(data["signature_id"]))
        return frozenset(sids)


class SuricataExecutor(Protocol):
    def version(self) -> str | None: ...

    def check_syntax(self, rule_text: str) -> tuple[bool, str]: ...

    def replay(self, pcap_path: str, rule_text: str, *, workdir: str) -> ReplayOutcome: ...


class UnavailableExecutor:
    """Used when the Suricata binary is not installed (the current dev host)."""

    def __init__(self, reason: str = "suricata binary not found on PATH") -> None:
        self.reason = reason

    def version(self) -> str | None:
        return None

    def check_syntax(self, rule_text: str) -> tuple[bool, str]:
        raise SuricataUnavailable(self.reason)

    def replay(self, pcap_path: str, rule_text: str, *, workdir: str) -> ReplayOutcome:
        raise SuricataUnavailable(self.reason)


class SubprocessSuricataExecutor:
    """Runs the real ``suricata`` binary as a subprocess and measures its cost."""

    def __init__(self, *, binary: str = "suricata", timeout_seconds: float = 300.0) -> None:
        self.binary = binary
        self.timeout_seconds = timeout_seconds

    def _run(self, args: Sequence[str], *, cwd: str | None = None) -> tuple[int, str, str, ProcessUsage]:
        try:
            return run_measured([self.binary, *args], cwd=cwd, timeout=self.timeout_seconds)
        except FileNotFoundError as error:
            raise SuricataUnavailable(f"suricata binary not found: {error}") from error
        except TimeoutError as error:
            raise SuricataUnavailable(f"suricata timed out after {self.timeout_seconds}s") from error

    def version(self) -> str | None:
        try:
            code, stdout, stderr, _ = self._run(["-V"])
        except SuricataUnavailable:
            return None
        if code != 0:
            return None
        text = (stdout or stderr).strip().splitlines()
        return text[0][:64] if text else None

    def check_syntax(self, rule_text: str) -> tuple[bool, str]:
        with tempfile.TemporaryDirectory(prefix="evonids-suricata-") as workdir:
            rules_path = Path(workdir) / "evonids.rules"
            rules_path.write_text(rule_text + "\n", encoding="utf-8")
            code, stdout, stderr, _ = self._run(["-T", "-S", str(rules_path), "-l", workdir], cwd=workdir)
            return code == 0, (stdout + stderr).strip()[-4_000:]

    def replay(self, pcap_path: str, rule_text: str, *, workdir: str) -> ReplayOutcome:
        rules_path = Path(workdir) / "evonids.rules"
        rules_path.write_text(rule_text + "\n", encoding="utf-8")
        code, stdout, stderr, usage = self._run(
            [
                "-r",
                pcap_path,
                "-S",
                str(rules_path),
                "-l",
                workdir,
                "--runmode",
                "single",
                "--set",
                "outputs.1.eve-log.enabled=yes",
            ],
            cwd=workdir,
        )
        alerts = _read_eve_alerts(Path(workdir) / "eve.json")
        return ReplayOutcome(
            exit_code=code,
            alerts=alerts,
            stdout=stdout[-4_000:],
            stderr=stderr[-4_000:],
            duration_ms=round(usage.wall_seconds * 1000, 3),
            usage=usage,
        )


def _read_eve_alerts(path: Path) -> tuple[dict[str, Any], ...]:
    if not path.is_file():
        return ()
    alerts: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if len(alerts) >= MAX_ALERTS_PARSED:
                break
            line = line.strip()
            if not line or '"alert"' not in line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and payload.get("event_type") == "alert":
                alerts.append(payload)
    return tuple(alerts)


def default_executor(binary: str = "suricata") -> SuricataExecutor:
    if shutil.which(binary):
        return SubprocessSuricataExecutor(binary=binary)
    return UnavailableExecutor(f"suricata binary {binary!r} was not found on PATH")


@dataclass(slots=True)
class SandboxMetrics:
    normal_flows: int = 0
    malicious_flows: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    recall: float | None = NOT_MEASURED
    precision: float | None = NOT_MEASURED
    f1: float | None = NOT_MEASURED
    false_positive_rate: float | None = NOT_MEASURED
    false_positives_per_million: float | None = NOT_MEASURED
    replay_seconds: float | None = NOT_MEASURED
    cpu_seconds: float | None = None
    peak_rss_kb: int | None = None
    resource_source: str = "unavailable"
    resource_error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "normalFlows": self.normal_flows,
            "maliciousFlows": self.malicious_flows,
            "truePositives": self.true_positives,
            "falsePositives": self.false_positives,
            "falseNegatives": self.false_negatives,
            "recall": self.recall,
            "precision": self.precision,
            "f1": self.f1,
            "falsePositiveRate": self.false_positive_rate,
            "falsePositivesPerMillion": self.false_positives_per_million,
            "replaySeconds": self.replay_seconds,
            "cpuSeconds": self.cpu_seconds,
            "peakRssKb": self.peak_rss_kb,
            "resourceSource": self.resource_source,
            "resourceError": self.resource_error,
            "measured": {
                "recall": self.recall is not None,
                "precision": self.precision is not None,
                "f1": self.f1 is not None,
                "falsePositiveRate": self.false_positive_rate is not None,
                "falsePositivesPerMillion": self.false_positives_per_million is not None,
                "replaySeconds": self.replay_seconds is not None,
                "cpuSeconds": self.cpu_seconds is not None,
                "peakRssKb": self.peak_rss_kb is not None,
            },
        }


@dataclass(slots=True)
class SandboxResult:
    status: str
    passed: bool
    suricata_available: bool
    suricata_version: str | None
    syntax_passed: bool | None
    blocked_reason: str | None
    checks: list[dict[str, Any]] = field(default_factory=list)
    metrics: SandboxMetrics = field(default_factory=SandboxMetrics)
    detail: dict[str, Any] = field(default_factory=dict)


def evaluate_replay(
    *,
    malicious: ReplayOutcome,
    normal: ReplayOutcome,
    sid: int,
    malicious_flows: int,
    normal_flows: int,
) -> SandboxMetrics:
    metrics = SandboxMetrics(
        normal_flows=normal_flows,
        malicious_flows=malicious_flows,
        replay_seconds=round(malicious.duration_ms / 1000 + normal.duration_ms / 1000, 3),
    )
    usage = malicious.usage or normal.usage
    if usage is not None:
        metrics.peak_rss_kb = usage.peak_rss_kb
        metrics.cpu_seconds = usage.cpu_seconds
        metrics.resource_source = usage.source
        metrics.resource_error = usage.error
    if malicious_flows > 0:
        matched_flows = {
            str(alert.get("flow_id"))
            for alert in malicious.alerts
            if _sid_of(alert) == sid and alert.get("flow_id") is not None
        }
        metrics.true_positives = min(len(matched_flows), malicious_flows)
        metrics.false_negatives = max(malicious_flows - metrics.true_positives, 0)
        metrics.recall = round(metrics.true_positives / malicious_flows, 6)
    if normal_flows > 0:
        metrics.false_positives = len(normal.alert_flow_ids)
        metrics.false_positive_rate = round(metrics.false_positives / normal_flows, 8)
        metrics.false_positives_per_million = round(metrics.false_positive_rate * 1_000_000, 3)
    if metrics.recall is not None:
        denominator = metrics.true_positives + metrics.false_positives
        if denominator > 0:
            metrics.precision = round(metrics.true_positives / denominator, 6)
            if metrics.precision is not None:
                metrics.f1 = round(
                    2 * metrics.precision * metrics.recall / (metrics.precision + metrics.recall), 6
                )
    return metrics


def _sid_of(alert: dict[str, Any]) -> int | None:
    data = alert.get("alert")
    if isinstance(data, dict) and isinstance(data.get("signature_id"), int):
        return int(data["signature_id"])
    return None


def _regression_report(
    *,
    candidate: SandboxMetrics,
    reference: SandboxMetrics | None,
    reference_version_id: str | None,
) -> dict[str, Any]:
    """Compare a candidate revision against a deployed/reference revision."""
    if reference is None:
        return {
            "measured": False,
            "referenceVersionId": reference_version_id,
            "note": "未提供参照版本或参照版本无法回放，回归比较未测量。",
        }
    deltas: dict[str, Any] = {}
    regressions: list[str] = []
    for name in ("recall", "precision", "f1"):
        candidate_value = getattr(candidate, name)
        reference_value = getattr(reference, name)
        if candidate_value is None or reference_value is None:
            deltas[name] = None
            continue
        delta = round(candidate_value - reference_value, 6)
        deltas[name] = delta
        if delta < -0.05:
            regressions.append(f"{name} 下降 {abs(delta):.4f}")
    candidate_fp = candidate.false_positives_per_million
    reference_fp = reference.false_positives_per_million
    if candidate_fp is not None and reference_fp is not None:
        deltas["falsePositivesPerMillion"] = round(candidate_fp - reference_fp, 3)
        if reference_fp > 0 and candidate_fp > reference_fp * 1.5:
            regressions.append(f"每百万误报从 {reference_fp} 上升到 {candidate_fp}")
    else:
        deltas["falsePositivesPerMillion"] = None
    return {
        "measured": any(value is not None for value in deltas.values()),
        "referenceVersionId": reference_version_id,
        "deltas": deltas,
        "regressions": regressions,
        "verdict": "regression" if regressions else "ok",
        "note": "与参照版本对比；召回下降超过 0.05 或每百万误报上升超过 50% 记为回归。",
    }


def validate_rule(
    db: Session,
    *,
    rule_id: str,
    version_id: str,
    normal_pcap: str | None = None,
    malicious_pcap: str | None = None,
    malicious_flows: int = 0,
    normal_flows: int = 0,
    executor: SuricataExecutor | None = None,
    recall_floor: float = DEFAULT_RECALL_FLOOR,
    fp_per_million_ceiling: float = DEFAULT_FP_PER_MILLION_CEILING,
    actor: str = "rule-sandbox",
    corpus_root: str | Path | None = None,
    regression_version_id: str | None = None,
) -> RuleSandboxRun:
    """Validate one rule revision with real Suricata when this host has it.

    ``normal_pcap`` / ``malicious_pcap`` are validated against the replay corpus
    root before they are handed to the external binary.
    """
    version = db.get(RuleIRVersion, version_id)
    if version is None or version.rule_id != rule_id:
        raise ValueError(f"rule IR version {version_id} was not found for rule {rule_id}")

    if corpus_root is None:
        from app.core.config import get_settings

        corpus_root = get_settings().replay_corpus_root
    try:
        normal_capture = validate_capture_path(normal_pcap, corpus_root=corpus_root)
        malicious_capture = validate_capture_path(malicious_pcap, corpus_root=corpus_root)
    except CorpusPathError as error:
        return _blocked_run(
            db,
            version=version,
            rule_id=rule_id,
            reason=f"replay capture rejected: {error}",
            check_label="capture_validation",
            check_note=str(error)[:500],
            detail={"corpusRoot": str(corpus_root)},
            actor=actor,
        )

    runner = executor or default_executor()
    checks: list[dict[str, Any]] = []
    suricata_version = runner.version()
    run = RuleSandboxRun(
        id=f"SBX-{version.id[-12:]}-{int(time.time() * 1000) % 10_000_000:07d}",
        rule_id=rule_id,
        rule_version_id=version_id,
        status="blocked",
        suricata_available=suricata_version is not None,
        suricata_version=suricata_version,
        syntax_passed=None,
        executor_version=EXECUTOR_VERSION,
        normal_pcap=str(normal_capture.requested) if normal_capture else None,
        malicious_pcap=str(malicious_capture.requested) if malicious_capture else None,
        metrics={},
        checks=[],
        passed=False,
        blocked_reason=None,
        detail={
            "sid": version.sid,
            "rev": version.rev,
            "irDigest": version.ir_digest,
            "corpusRoot": str(corpus_root),
            "executorVersion": EXECUTOR_VERSION,
        },
    )

    if suricata_version is None:
        reason = getattr(runner, "reason", "suricata binary is unavailable on this host")
        run.status = "blocked"
        run.blocked_reason = str(reason)[:255]
        checks.append(
            {
                "label": "suricata_binary",
                "passed": False,
                "note": f"未执行 Suricata：{reason}；本次运行不产生任何验证指标。",
            }
        )
        run.checks = checks
        db.add(run)
        db.commit()
        db.refresh(run)
        return run

    checks.append({"label": "suricata_binary", "passed": True, "note": f"suricata {suricata_version}"})
    checks.append(
        {
            "label": "capture_validation",
            "passed": True,
            "note": (
                f"正常语料 {normal_capture.size_bytes if normal_capture else 0} 字节 / "
                f"恶意语料 {malicious_capture.size_bytes if malicious_capture else 0} 字节，"
                "均位于语料根目录内。"
            ),
        }
    )
    try:
        syntax_ok, syntax_output = runner.check_syntax(version.suricata_text)
    except SuricataUnavailable as error:
        run.status = "blocked"
        run.blocked_reason = str(error)[:255]
        checks.append({"label": "syntax", "passed": False, "note": str(error)[:500]})
        run.checks = checks
        db.add(run)
        db.commit()
        db.refresh(run)
        return run
    run.syntax_passed = syntax_ok
    checks.append(
        {
            "label": "syntax",
            "passed": syntax_ok,
            "note": syntax_output[-500:] if syntax_output else "suricata -T completed",
        }
    )
    if not syntax_ok:
        run.status = "failed"
        run.checks = checks
        run.detail = {**run.detail, "syntaxOutput": syntax_output[-2_000:]}
        db.add(run)
        db.commit()
        db.refresh(run)
        return run

    if normal_capture is None or malicious_capture is None:
        run.status = "partial"
        run.blocked_reason = "labelled PCAPs were not provided; syntax was checked but no replay metrics exist"
        checks.append(
            {
                "label": "replay",
                "passed": False,
                "note": "缺少标注 PCAP（正常/恶意各一份），本次只完成语法校验，未测量召回与误报。",
            }
        )
        run.checks = checks
        db.add(run)
        db.commit()
        db.refresh(run)
        return run

    with tempfile.TemporaryDirectory(prefix="evonids-sandbox-") as workdir:
        malicious = runner.replay(str(malicious_capture.resolved), version.suricata_text, workdir=workdir)
        normal = runner.replay(str(normal_capture.resolved), version.suricata_text, workdir=workdir)
    metrics = evaluate_replay(
        malicious=malicious,
        normal=normal,
        sid=version.sid,
        malicious_flows=malicious_flows or len(malicious.alert_flow_ids),
        normal_flows=normal_flows or max(len(normal.alert_flow_ids), 1),
    )
    run.metrics = metrics.as_dict()
    checks.append(
        {
            "label": "malicious_replay",
            "passed": (metrics.recall or 0) >= recall_floor,
            "note": (
                f"恶意 PCAP：命中 {metrics.true_positives}/{metrics.malicious_flows} 条流，"
                f"召回 {metrics.recall if metrics.recall is not None else '未测量'}，"
                f"退出码 {malicious.exit_code}"
            ),
        }
    )
    checks.append(
        {
            "label": "normal_replay",
            "passed": metrics.false_positives_per_million is not None
            and metrics.false_positives_per_million <= fp_per_million_ceiling,
            "note": (
                f"正常 PCAP：误报 {metrics.false_positives}/{metrics.normal_flows} 条流，"
                f"每百万正常流误报 "
                f"{metrics.false_positives_per_million if metrics.false_positives_per_million is not None else '未测量'}，"
                f"退出码 {normal.exit_code}"
            ),
        }
    )
    checks.append(
        {
            "label": "resource_usage",
            "passed": metrics.replay_seconds is not None,
            "note": (
                f"回放墙钟 {metrics.replay_seconds if metrics.replay_seconds is not None else '未测量'} 秒；"
                f"CPU 时间 {metrics.cpu_seconds if metrics.cpu_seconds is not None else '未测量'} 秒"
                f"（来源 {metrics.resource_source}）；"
                f"峰值内存 {metrics.peak_rss_kb if metrics.peak_rss_kb is not None else '未测量'} KB"
            ),
        }
    )

    regression: dict[str, Any] = {
        "measured": False,
        "referenceVersionId": regression_version_id,
        "note": "未请求回归比较。",
    }
    if regression_version_id:
        reference_version = db.get(RuleIRVersion, regression_version_id)
        if reference_version is None or reference_version.rule_id != rule_id:
            regression = {
                "measured": False,
                "referenceVersionId": regression_version_id,
                "note": "参照版本不存在，回归比较未测量。",
            }
        else:
            with tempfile.TemporaryDirectory(prefix="evonids-regression-") as workdir:
                reference_malicious = runner.replay(
                    str(malicious_capture.resolved), reference_version.suricata_text, workdir=workdir
                )
                reference_normal = runner.replay(
                    str(normal_capture.resolved), reference_version.suricata_text, workdir=workdir
                )
            reference_metrics = evaluate_replay(
                malicious=reference_malicious,
                normal=reference_normal,
                sid=reference_version.sid,
                malicious_flows=malicious_flows or len(reference_malicious.alert_flow_ids),
                normal_flows=normal_flows or max(len(reference_normal.alert_flow_ids), 1),
            )
            regression = _regression_report(
                candidate=metrics,
                reference=reference_metrics,
                reference_version_id=regression_version_id,
            )
            checks.append(
                {
                    "label": "regression",
                    "passed": regression.get("verdict") == "ok",
                    "note": (
                        "与参照版本无回归。"
                        if regression.get("verdict") == "ok"
                        else "；".join(regression.get("regressions") or ["回归比较不可用"])
                    ),
                }
            )

    passed = (
        run.syntax_passed is True
        and metrics.recall is not None
        and metrics.recall >= recall_floor
        and metrics.false_positives_per_million is not None
        and metrics.false_positives_per_million <= fp_per_million_ceiling
        and regression.get("verdict") != "regression"
    )
    run.status = "validated" if passed else "validation_failed"
    run.passed = passed
    run.checks = checks
    run.detail = {
        **run.detail,
        "recallFloor": recall_floor,
        "falsePositivesPerMillionCeiling": fp_per_million_ceiling,
        "regression": regression,
        "maliciousStderr": malicious.stderr[-1_000:],
        "normalStderr": normal.stderr[-1_000:],
        "actor": actor,
    }
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def _blocked_run(
    db: Session,
    *,
    version: RuleIRVersion,
    rule_id: str,
    reason: str,
    check_label: str,
    check_note: str,
    detail: dict[str, Any],
    actor: str,
) -> RuleSandboxRun:
    run = RuleSandboxRun(
        id=f"SBX-{version.id[-12:]}-{int(time.time() * 1000) % 10_000_000:07d}",
        rule_id=rule_id,
        rule_version_id=version.id,
        status="blocked",
        suricata_available=False,
        suricata_version=None,
        syntax_passed=None,
        executor_version=EXECUTOR_VERSION,
        normal_pcap=None,
        malicious_pcap=None,
        metrics={},
        checks=[{"label": check_label, "passed": False, "note": check_note}],
        passed=False,
        blocked_reason=reason[:255],
        detail={**detail, "sid": version.sid, "rev": version.rev, "actor": actor},
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def sandbox_capability() -> dict[str, Any]:
    """Report what real validation is possible on this host (no invented values)."""
    from app.core.config import get_settings

    settings = get_settings()
    binary = shutil.which(settings.suricata_binary)
    return {
        "suricataAvailable": binary is not None,
        "binary": binary,
        "executorVersion": EXECUTOR_VERSION,
        "corpus": corpus_summary(settings.replay_corpus_root),
        "resources": platform_support(),
        "note": (
            "已检测到 suricata 可执行文件，可执行真实语法校验与 PCAP 回放。"
            if binary
            else "本机未安装 suricata：规则只能完成 IR/编译/结构校验，"
            "真实语法校验与 PCAP 回放会被记录为 blocked，绝不虚构验证结果。"
        ),
    }


def deployment_monitoring(
    db: Session, deployment_id: str, *, window_hours: int = 24, persist: bool = True
) -> dict[str, Any]:
    """Aggregate post-deployment alert volume for one deployment."""
    from datetime import timedelta

    from sqlalchemy import func, select

    from app.db.models import Alert, RuleDeployment

    deployment = db.get(RuleDeployment, deployment_id)
    if deployment is None:
        raise ValueError(f"deployment {deployment_id} was not found")
    version = db.get(RuleIRVersion, deployment.rule_version_id)
    if version is None:
        return {"measured": False, "reason": "rule version missing"}
    window = max(1, min(window_hours, 24 * 30))
    since = utc_now() - timedelta(hours=window)
    total = db.scalar(select(func.count()).select_from(Alert).where(Alert.timestamp >= since)) or 0
    matching = (
        db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(Alert.timestamp >= since, Alert.detector.like(f"%{version.sid}%"))
        )
        or 0
    )
    report = {
        "measured": True,
        "windowHours": window,
        "alertsTotal": int(total),
        "alertsFromRule": int(matching),
        "ruleSid": version.sid,
        "deploymentState": deployment.state,
        "generatedAt": utc_now().isoformat(),
        "note": (
            "仅统计告警数量；精度需要人工反馈（analyst_feedback）才能计算。"
            "窗口内没有流量时计数为 0 属于真实测量值，而不是缺失。"
        ),
    }
    if persist:
        deployment.monitoring = report
        db.commit()
        db.refresh(deployment)
    return report
