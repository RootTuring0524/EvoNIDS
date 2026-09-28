from fastapi import APIRouter

from app.api.routes import (
    alerts,
    api_keys,
    audit,
    audit_integrity,
    auth,
    cases,
    correlation,
    datasets,
    detections,
    entities,
    evidence,
    flows,
    health,
    ingestion,
    integrations,
    investigations,
    llm,
    metrics,
    models,
    overview,
    rag,
    rule_governance,
    rules,
    sensors,
    training,
)


api_router = APIRouter()
api_router.include_router(health.router, tags=["system"])
api_router.include_router(auth.router, prefix="/auth", tags=["identity"])
api_router.include_router(ingestion.router, prefix="/ingestion", tags=["ingestion"])
# Correlation is mounted before the alerts router: `/alerts/clusters` would
# otherwise be captured by the `/alerts/{alert_id}` route and 404.
api_router.include_router(correlation.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(cases.router, prefix="/cases", tags=["cases"])
api_router.include_router(evidence.router, prefix="/evidence", tags=["evidence"])
api_router.include_router(entities.router, prefix="/entities", tags=["entities"])
api_router.include_router(flows.router, prefix="/flows", tags=["flows"])
api_router.include_router(rules.router, prefix="/rules", tags=["rules"])
api_router.include_router(rule_governance.router, prefix="/rule-governance", tags=["rules"])
api_router.include_router(audit_integrity.router, prefix="/audit", tags=["audit"])
api_router.include_router(audit.router, prefix="/audit", tags=["audit"])
api_router.include_router(models.router, prefix="/models", tags=["models"])
api_router.include_router(datasets.router, prefix="/datasets", tags=["datasets"])
api_router.include_router(training.router, prefix="/training/runs", tags=["training"])
api_router.include_router(rag.router, prefix="/rag", tags=["knowledge"])
api_router.include_router(sensors.router, prefix="/sensors", tags=["sensors"])
api_router.include_router(detections.router, prefix="/detections", tags=["detections"])
api_router.include_router(investigations.router, prefix="/investigations", tags=["investigations"])
api_router.include_router(llm.router, prefix="/llm", tags=["llm"])
api_router.include_router(metrics.router, tags=["system"])
api_router.include_router(overview.router, prefix="/overview", tags=["operations"])
api_router.include_router(integrations.router, prefix="/integrations", tags=["integrations"])
api_router.include_router(api_keys.router, prefix="/admin/api-keys", tags=["admin"])
