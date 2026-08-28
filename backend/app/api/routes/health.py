import os
from pathlib import Path

from fastapi import APIRouter, Depends
from sqlalchemy import func, text, select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.session import get_db
from app.db.base import utc_now
from app.db.models import DatasetAsset, ModelVersion, TrainingRun
from app.domain.features import FEATURE_VERSION
from app.schemas.api import HealthResponse, ReadinessCheck, ReadinessResponse
from app.services.sensor_operations import list_sensors
from app.services.model_registry import artifact_state
from app.services.training import ml_runtime_available


router = APIRouter()


@router.get("/health", response_model=HealthResponse, response_model_by_alias=True)
def health(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> HealthResponse:
    database = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        database = "error"
    return HealthResponse(
        status="ok" if database == "ok" else "degraded",
        service="evonids-api",
        environment=settings.environment,
        database=database,
        feature_version=FEATURE_VERSION,
    )


@router.get("/readiness", response_model=ReadinessResponse, response_model_by_alias=True)
def readiness(
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> ReadinessResponse:
    checks: list[ReadinessCheck] = []
    try:
        db.execute(text("SELECT 1"))
        checks.append(ReadinessCheck(id="database", label="持久化数据库", status="pass", detail="数据库连接和查询正常"))
    except Exception:
        checks.append(ReadinessCheck(id="database", label="持久化数据库", status="block", detail="数据库连接失败"))

    production = settings.environment.lower() not in {"development", "test"}
    database_url = settings.database_url.casefold()
    production_database = database_url.startswith("postgresql")
    placeholder_password = "change-me" in database_url
    database_runtime_ready = production_database and not placeholder_password
    checks.append(
        ReadinessCheck(
            id="database-runtime",
            label="交付数据库配置",
            status="pass" if database_runtime_ready else ("block" if production else "warn"),
            detail=(
                "PostgreSQL 已配置且未检测到示例密码"
                if database_runtime_ready
                else "当前仍是 SQLite 或包含示例密码；正式交付必须使用 PostgreSQL 与独立密钥"
            ),
        )
    )
    checks.append(
        ReadinessCheck(
            id="admin-auth",
            label="管理员写操作鉴权",
            status="pass" if settings.admin_api_token else ("block" if production else "warn"),
            detail="管理员令牌已配置" if settings.admin_api_token else "未配置 EVONIDS_ADMIN_API_TOKEN",
        )
    )
    checks.append(
        ReadinessCheck(
            id="sensor-auth",
            label="探针采集鉴权",
            status="pass" if settings.sensor_ingest_token else ("block" if production else "warn"),
            detail="探针令牌已配置" if settings.sensor_ingest_token else "开发环境允许无令牌采集；生产环境将拒绝",
        )
    )
    sensors = list_sensors(db).summary
    checks.append(
        ReadinessCheck(
            id="collection-plane",
            label="采集平面",
            status="pass" if sensors.online else "warn",
            detail=f"{sensors.online}/{sensors.total} 个探针在线，{sensors.degraded} 个降级，{sensors.offline} 个离线",
        )
    )
    dataset_root = Path(settings.dataset_root).expanduser().resolve()
    checks.append(
        ReadinessCheck(
            id="dataset-root",
            label="数据集受控目录",
            status="pass" if dataset_root.is_dir() else ("block" if production else "warn"),
            detail=(
                f"受控目录可用：{dataset_root}"
                if dataset_root.is_dir()
                else f"目录不存在：{dataset_root}"
            ),
        )
    )
    dataset_total = db.scalar(select(func.count()).select_from(DatasetAsset)) or 0
    dataset_ready = db.scalar(
        select(func.count()).select_from(DatasetAsset).where(DatasetAsset.state == "ready")
    ) or 0
    dataset_problem = db.scalar(
        select(func.count()).select_from(DatasetAsset).where(DatasetAsset.state.in_(["error", "missing"]))
    ) or 0
    checks.append(
        ReadinessCheck(
            id="dataset-assets",
            label="真实数据资产",
            status="pass" if dataset_ready else "warn",
            detail=f"已登记 {dataset_total} 个数据集，{dataset_ready} 个完成真实检查，{dataset_problem} 个异常",
        )
    )
    ml_available = ml_runtime_available()
    checks.append(
        ReadinessCheck(
            id="ml-runtime",
            label="基线训练运行时",
            status="pass" if ml_available else ("block" if production else "warn"),
            detail=(
                "NumPy、pandas、scikit-learn 与 joblib 均可用"
                if ml_available
                else "缺少真实基线训练依赖；安装 backend[ml]"
            ),
        )
    )
    training_total = db.scalar(select(func.count()).select_from(TrainingRun)) or 0
    training_succeeded = db.scalar(
        select(func.count()).select_from(TrainingRun).where(TrainingRun.state == "succeeded")
    ) or 0
    training_failed = db.scalar(
        select(func.count()).select_from(TrainingRun).where(TrainingRun.state == "failed")
    ) or 0
    checks.append(
        ReadinessCheck(
            id="training-runs",
            label="真实训练记录",
            status="pass" if training_succeeded else "warn",
            detail=(
                f"共 {training_total} 次运行，{training_succeeded} 次成功生成真实制品，{training_failed} 次失败"
            ),
        )
    )
    checks.append(
        ReadinessCheck(
            id="training-executor",
            label="训练任务执行器",
            status="block" if production else "warn",
            detail=(
                "当前为 API 进程内任务；异常重启会明确失败并可重试，正式多节点交付前需迁移到持久化任务队列"
            ),
        )
    )
    artifact_root = Path(settings.model_artifact_root).expanduser().resolve()
    artifact_root_ready = artifact_root.is_dir() and os.access(artifact_root, os.W_OK)
    checks.append(
        ReadinessCheck(
            id="model-artifact-root",
            label="模型制品存储",
            status="pass" if artifact_root_ready else ("block" if production else "warn"),
            detail=(
                f"制品目录存在且可写：{artifact_root}"
                if artifact_root_ready
                else f"制品目录不存在或不可写：{artifact_root}"
            ),
        )
    )
    registered_models = db.scalar(select(func.count()).select_from(ModelVersion)) or 0
    model_rows = db.scalars(select(ModelVersion)).all()
    available_models = sum(artifact_state(row.artifact_uri) == "available" for row in model_rows)
    unverified_models = sum(artifact_state(row.artifact_uri) == "unverified" for row in model_rows)
    checks.append(
        ReadinessCheck(
            id="model-artifacts",
            label="模型制品",
            status="pass" if available_models else "warn",
            detail=(
                f"已登记 {registered_models} 个模型版本，{available_models} 个本地制品已验证存在，"
                f"{unverified_models} 个远程制品尚未验证"
            ),
        )
    )
    checks.append(
        ReadinessCheck(
            id="runtime-mode",
            label="运行环境",
            status="pass" if production else "warn",
            detail=f"当前为 {settings.environment}；正式上线前应切换生产配置",
        )
    )
    blockers = sum(item.status == "block" for item in checks)
    warnings = sum(item.status == "warn" for item in checks)
    return ReadinessResponse(
        status="ready" if blockers == 0 and warnings == 0 else "attention",
        environment=settings.environment,
        checked_at=utc_now(),
        blockers=blockers,
        warnings=warnings,
        checks=checks,
    )
