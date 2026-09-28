"""Metrics and trace endpoints.

``/metrics`` is the Prometheus scrape target; it is unauthenticated by design
(scrapers rarely carry console credentials) and exposes only aggregate counters,
never payloads, principals or customer data. It must be reachable only from the
monitoring network - see ``docs/deployment.md``.
"""

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_db
from app.services.observability import REGISTRY, collect_runtime_gauges, metrics_snapshot
from app.services.rule_sandbox import sandbox_capability


router = APIRouter()


@router.get("/metrics", include_in_schema=False)
def prometheus_metrics(request: Request, db: Session = Depends(get_db)) -> Response:
    collect_runtime_gauges(db)
    body = REGISTRY.render()
    trace_id = getattr(request.state, "trace_id", None)
    headers = {"X-Trace-ID": trace_id} if trace_id else {}
    return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8", headers=headers)


@router.get("/observability")
def observability_summary(request: Request) -> dict:
    """Human-readable status of what this process observes and what it cannot."""
    settings = get_settings()
    capability = sandbox_capability()
    return {
        "metrics": metrics_snapshot(),
        "traceId": getattr(request.state, "trace_id", None),
        "tracing": {
            "propagation": "W3C traceparent（解析 + 生成 + 回写响应头 + 写入日志）",
            "exporter": None,
            "note": "本环境未安装 OpenTelemetry SDK/Collector：只有传播，没有导出。",
        },
        "detectionMode": settings.detection_mode,
        "llmProvider": settings.llm_provider,
        "suricataAvailable": capability["suricataAvailable"],
        "resourceMeasurement": capability["resources"],
    }
