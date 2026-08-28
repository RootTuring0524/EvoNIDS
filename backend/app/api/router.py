from fastapi import APIRouter

from app.api.routes import alerts, audit, datasets, flows, health, ingestion, models, overview, rag, rules, sensors, training


api_router = APIRouter()
api_router.include_router(health.router, tags=["system"])
api_router.include_router(ingestion.router, prefix="/ingestion", tags=["ingestion"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(flows.router, prefix="/flows", tags=["flows"])
api_router.include_router(rules.router, prefix="/rules", tags=["rules"])
api_router.include_router(audit.router, prefix="/audit", tags=["audit"])
api_router.include_router(models.router, prefix="/models", tags=["models"])
api_router.include_router(datasets.router, prefix="/datasets", tags=["datasets"])
api_router.include_router(training.router, prefix="/training/runs", tags=["training"])
api_router.include_router(rag.router, prefix="/rag", tags=["knowledge"])
api_router.include_router(sensors.router, prefix="/sensors", tags=["sensors"])
api_router.include_router(overview.router, prefix="/overview", tags=["operations"])
