from __future__ import annotations

import csv
import gzip
import hashlib
import uuid
from collections import Counter
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.base import utc_now
from app.db.models import AuditEvent, DatasetAsset, TrainingRun
from app.db.session import SessionLocal
from app.schemas.api import (
    DatasetDistributionItem,
    DatasetRead,
    DatasetRegistration,
    DatasetsResponse,
    DatasetSplit,
)


SUPPORTED_SUFFIXES = (".csv", ".csv.gz")
AUTO_LABEL_COLUMNS = ("label", "attack_cat", "attack category", "class", "target")


def list_dataset_assets(db: Session, settings: Settings) -> DatasetsResponse:
    rows = db.scalars(
        select(DatasetAsset).order_by(DatasetAsset.main_training_set.desc(), DatasetAsset.updated_at.desc())
    ).all()
    return DatasetsResponse(items=[to_dataset_read(row, settings=settings) for row in rows])


def register_dataset_asset(
    db: Session,
    payload: DatasetRegistration,
    *,
    settings: Settings,
    request_id: str | None,
) -> DatasetAsset:
    if db.get(DatasetAsset, payload.id) is not None:
        raise HTTPException(status_code=409, detail=f"Dataset {payload.id} already exists")
    path = resolve_dataset_path(settings, payload.relative_path)
    existing = db.scalar(select(DatasetAsset).where(DatasetAsset.relative_path == payload.relative_path))
    if existing is not None:
        raise HTTPException(status_code=409, detail=f"Dataset path is already registered as {existing.id}")
    now = utc_now()
    row = DatasetAsset(
        id=payload.id,
        name=payload.name.strip(),
        version=payload.version.strip(),
        source_uri=payload.source_uri.strip(),
        relative_path=payload.relative_path.replace("\\", "/"),
        format="csv.gz" if path.name.lower().endswith(".csv.gz") else "csv",
        state="profiling",
        file_size_bytes=path.stat().st_size,
        sha256=None,
        label_column=payload.label_column.strip() if payload.label_column else None,
        normal_labels=[value.strip() for value in payload.normal_labels if value.strip()],
        split=payload.split.model_dump(),
        main_training_set=payload.main_training_set,
        unknown_holdout=payload.unknown_holdout,
        rule_replay=payload.rule_replay,
        uses=[value.strip() for value in payload.uses if value.strip()],
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.add(
        _audit_event(
            actor=payload.actor,
            action="dataset.registered",
            object_id=row.id,
            outcome="accepted",
            request_id=request_id,
            after_state={
                "state": row.state,
                "relativePath": row.relative_path,
                "fileSizeBytes": row.file_size_bytes,
            },
            note=payload.note or "Dataset path accepted; real file profiling queued.",
        )
    )
    db.commit()
    db.refresh(row)
    return row


def queue_reprofile(
    db: Session,
    dataset_id: str,
    *,
    actor: str,
    request_id: str | None,
) -> DatasetAsset:
    row = db.get(DatasetAsset, dataset_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Dataset {dataset_id} not found")
    before = {"state": row.state, "sha256": row.sha256, "totalSamples": row.total_samples}
    row.state = "profiling"
    row.inspection_error = None
    row.updated_at = utc_now()
    db.add(
        _audit_event(
            actor=actor,
            action="dataset.reprofile_requested",
            object_id=row.id,
            outcome="accepted",
            request_id=request_id,
            before_state=before,
            after_state={"state": "profiling"},
            note="Real dataset profiling requested again.",
        )
    )
    db.commit()
    db.refresh(row)
    return row


def delete_dataset_registration(
    db: Session,
    dataset_id: str,
    *,
    actor: str,
    request_id: str | None,
) -> None:
    row = db.get(DatasetAsset, dataset_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Dataset {dataset_id} not found")
    linked_run = db.scalar(
        select(TrainingRun.id).where(TrainingRun.dataset_id == dataset_id).limit(1)
    )
    if linked_run is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Dataset {dataset_id} is referenced by training run {linked_run}; "
                "retain the registration for reproducibility"
            ),
        )
    before = {
        "name": row.name,
        "version": row.version,
        "relativePath": row.relative_path,
        "sha256": row.sha256,
    }
    db.delete(row)
    db.add(
        _audit_event(
            actor=actor,
            action="dataset.registration_deleted",
            object_id=dataset_id,
            outcome="completed",
            request_id=request_id,
            before_state=before,
            note="Registry entry deleted; source file was not modified.",
        )
    )
    db.commit()


def profile_dataset_asset(dataset_id: str) -> None:
    settings = get_settings()
    with SessionLocal() as db:
        row = db.get(DatasetAsset, dataset_id)
        if row is None:
            return
        try:
            path = resolve_dataset_path(settings, row.relative_path)
            digest = _sha256(path)
            linked_run = db.scalar(
                select(TrainingRun.id).where(TrainingRun.dataset_id == dataset_id).limit(1)
            )
            if linked_run is not None and row.sha256 and digest != row.sha256:
                raise ValueError(
                    "Dataset content changed after a training run established immutable lineage; "
                    "register the changed file as a new dataset version"
                )
            profile = _profile_csv(path, requested_label=row.label_column, normal_labels=row.normal_labels)
            row.file_size_bytes = path.stat().st_size
            row.sha256 = digest
            row.label_column = profile["label_column"]
            row.total_samples = profile["total_samples"]
            row.normal_samples = profile["normal_samples"]
            row.attack_samples = profile["attack_samples"]
            row.feature_count = profile["feature_count"]
            row.missing_values = profile["missing_values"]
            row.feature_columns = profile["feature_columns"]
            row.label_distribution = profile["label_distribution"]
            row.state = "ready"
            row.inspection_error = None
            outcome = "completed"
            note = f"Profiled {row.total_samples} real rows from the registered file."
        except Exception as exc:  # profiling failure must be persisted for operations review
            row.state = "missing" if isinstance(exc, FileNotFoundError) else "error"
            row.inspection_error = str(exc)[:1000]
            outcome = "failed"
            note = row.inspection_error
        row.inspected_at = utc_now()
        row.updated_at = row.inspected_at
        db.add(
            _audit_event(
                actor="dataset-profiler",
                action="dataset.profiled",
                object_id=row.id,
                outcome=outcome,
                request_id=None,
                after_state={
                    "state": row.state,
                    "totalSamples": row.total_samples,
                    "featureCount": row.feature_count,
                    "sha256": row.sha256,
                },
                note=note,
            )
        )
        db.commit()


def resolve_dataset_path(settings: Settings, relative_path: str) -> Path:
    root = Path(settings.dataset_root).expanduser().resolve()
    if not root.exists():
        raise HTTPException(status_code=409, detail=f"Dataset root does not exist: {root}")
    candidate = (root / relative_path).resolve()
    if not candidate.is_relative_to(root):
        raise HTTPException(status_code=400, detail="Dataset path must stay inside EVONIDS_DATASET_ROOT")
    if not candidate.exists():
        raise FileNotFoundError(f"Dataset file does not exist: {relative_path}")
    if not candidate.is_file():
        raise HTTPException(status_code=400, detail="Dataset path must point to a file")
    lowered = candidate.name.lower()
    if not lowered.endswith(SUPPORTED_SUFFIXES):
        raise HTTPException(status_code=415, detail="Only .csv and .csv.gz datasets are supported")
    return candidate


def to_dataset_read(row: DatasetAsset, *, settings: Settings) -> DatasetRead:
    state = row.state
    error = row.inspection_error
    try:
        resolve_dataset_path(settings, row.relative_path)
    except (FileNotFoundError, HTTPException) as exc:
        state = "missing"
        error = str(exc.detail) if isinstance(exc, HTTPException) else str(exc)
    normal = {value.strip().casefold() for value in row.normal_labels}
    attacks = [
        DatasetDistributionItem(label=label, count=count)
        for label, count in sorted(row.label_distribution.items(), key=lambda item: item[1], reverse=True)
        if label.strip().casefold() not in normal
    ][:12]
    return DatasetRead(
        id=row.id,
        name=row.name,
        version=row.version,
        state=state,
        format=row.format,
        relative_path=row.relative_path,
        source_uri=row.source_uri,
        file_size_bytes=row.file_size_bytes,
        sha256=row.sha256,
        label_column=row.label_column,
        total_samples=row.total_samples,
        normal_samples=row.normal_samples,
        attack_samples=row.attack_samples,
        feature_count=row.feature_count,
        missing_values=row.missing_values,
        split=DatasetSplit.model_validate(row.split),
        main_training_set=row.main_training_set,
        unknown_holdout=row.unknown_holdout,
        rule_replay=row.rule_replay,
        uses=row.uses,
        attack_distribution=attacks,
        inspected_at=row.inspected_at,
        inspection_error=error,
        updated_at=row.updated_at,
    )


def _profile_csv(path: Path, *, requested_label: str | None, normal_labels: list[str]) -> dict[str, object]:
    last_error: UnicodeDecodeError | None = None
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            return _profile_csv_with_encoding(
                path,
                requested_label=requested_label,
                normal_labels=normal_labels,
                encoding=encoding,
            )
        except UnicodeDecodeError as exc:
            last_error = exc
    raise ValueError(f"Dataset encoding is not supported: {last_error}")


def _profile_csv_with_encoding(
    path: Path,
    *,
    requested_label: str | None,
    normal_labels: list[str],
    encoding: str,
) -> dict[str, object]:
    opener = gzip.open if path.name.lower().endswith(".gz") else open
    with opener(path, "rt", encoding=encoding, newline="") as handle:
        sample = handle.read(65536)
        handle.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.reader(handle, dialect)
        try:
            raw_headers = next(reader)
        except StopIteration as exc:
            raise ValueError("Dataset is empty") from exc
        headers = [value.strip() for value in raw_headers]
        if not headers or any(not value for value in headers):
            raise ValueError("Dataset header contains an empty column name")
        normalized = [value.casefold() for value in headers]
        if len(set(normalized)) != len(normalized):
            raise ValueError("Dataset header contains duplicate column names")
        label_index = _find_label_index(headers, requested_label)
        label_column = headers[label_index] if label_index is not None else None
        normal = {value.strip().casefold() for value in normal_labels}
        label_counts: Counter[str] = Counter()
        total = 0
        missing = 0
        malformed = 0
        for values in reader:
            if not values or all(not value.strip() for value in values):
                continue
            if len(values) != len(headers):
                malformed += 1
                continue
            total += 1
            missing += sum(not value.strip() for value in values)
            if label_index is not None:
                label = values[label_index].strip() or "<missing>"
                label_counts[label] += 1
                if len(label_counts) > 10000:
                    raise ValueError("Selected label column has more than 10,000 distinct values")
        if total == 0:
            raise ValueError("Dataset contains no valid data rows")
        if malformed:
            raise ValueError(f"Dataset contains {malformed} malformed rows with an unexpected column count")
        normal_count = sum(count for label, count in label_counts.items() if label.casefold() in normal)
        attack_count = total - normal_count if label_index is not None else 0
        return {
            "label_column": label_column,
            "total_samples": total,
            "normal_samples": normal_count,
            "attack_samples": attack_count,
            "feature_count": len(headers) - (1 if label_index is not None else 0),
            "missing_values": missing,
            "feature_columns": [name for index, name in enumerate(headers) if index != label_index],
            "label_distribution": dict(label_counts),
        }


def _find_label_index(headers: list[str], requested_label: str | None) -> int | None:
    normalized = [value.strip().casefold() for value in headers]
    if requested_label:
        target = requested_label.strip().casefold()
        if target not in normalized:
            raise ValueError(f"Configured label column was not found: {requested_label}")
        return normalized.index(target)
    for candidate in AUTO_LABEL_COLUMNS:
        if candidate in normalized:
            return normalized.index(candidate)
    return None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _audit_event(
    *,
    actor: str,
    action: str,
    object_id: str,
    outcome: str,
    request_id: str | None,
    note: str,
    before_state: dict[str, object] | None = None,
    after_state: dict[str, object] | None = None,
) -> AuditEvent:
    return AuditEvent(
        id=f"AUD-{uuid.uuid4().hex.upper()}",
        created_at=utc_now(),
        actor=actor,
        action=action,
        object_type="dataset_asset",
        object_id=object_id,
        outcome=outcome,
        request_id=request_id,
        before_state=before_state,
        after_state=after_state,
        note=note,
    )
