"""Durable on-disk spool for the EvoNIDS collector.

The spool is the collector's "do not lose data" guarantee: a batch is written to
disk with ``os.replace`` before any network attempt, and only deleted after the
server acknowledged it. A crash between write and upload therefore loses nothing.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

SEGMENT_SUFFIX = ".ndjson"
META_SUFFIX = ".meta.json"


@dataclass(frozen=True, slots=True)
class SpoolSegment:
    path: Path
    meta_path: Path
    batch_id: str
    event_count: int
    bytes: int
    created_at: float
    clock_skew_seconds: float | None = None


class SpoolFull(RuntimeError):
    """Raised when the spool cannot accept more data without exceeding its cap."""


class DiskSpool:
    """Ordered, crash-safe batch spool with a bounded footprint."""

    def __init__(
        self,
        root: str | Path,
        *,
        max_bytes: int = 512 * 1024 * 1024,
        max_segments: int = 20_000,
    ) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.dead_letter = self.root / "dead-letter"
        self.dead_letter.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.max_segments = max_segments

    def depth(self) -> int:
        return sum(1 for _ in self.root.glob(f"*{SEGMENT_SUFFIX}"))

    def size_bytes(self) -> int:
        return sum(path.stat().st_size for path in self.root.glob(f"*{SEGMENT_SUFFIX}"))

    def append(
        self,
        payload: str,
        *,
        event_count: int,
        batch_id: str | None = None,
        clock_skew_seconds: float | None = None,
    ) -> SpoolSegment:
        encoded = payload.encode("utf-8")
        if self.size_bytes() + len(encoded) > self.max_bytes:
            raise SpoolFull(
                f"spool would exceed {self.max_bytes} bytes; refusing to drop the new batch silently"
            )
        if self.depth() >= self.max_segments:
            raise SpoolFull(f"spool already holds {self.max_segments} segments")
        identifier = batch_id or f"{int(time.time())}-{uuid.uuid4().hex[:12]}"
        created_at = time.time()
        segment_path = self.root / f"{created_at:017.6f}-{identifier}{SEGMENT_SUFFIX}"
        meta_path = self.root / f"{created_at:017.6f}-{identifier}{META_SUFFIX}"
        temporary = segment_path.with_suffix(".tmp")
        with temporary.open("wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, segment_path)
        meta = {
            "batchId": identifier,
            "eventCount": event_count,
            "bytes": len(encoded),
            "createdAt": created_at,
            "clockSkewSeconds": clock_skew_seconds,
        }
        meta_temporary = meta_path.with_suffix(".tmp")
        meta_temporary.write_text(json.dumps(meta), encoding="utf-8")
        os.replace(meta_temporary, meta_path)
        return SpoolSegment(
            path=segment_path,
            meta_path=meta_path,
            batch_id=identifier,
            event_count=event_count,
            bytes=len(encoded),
            created_at=created_at,
            clock_skew_seconds=clock_skew_seconds,
        )

    def pending(self) -> list[SpoolSegment]:
        segments: list[SpoolSegment] = []
        for path in sorted(self.root.glob(f"*{SEGMENT_SUFFIX}")):
            meta_path = path.with_name(path.name.replace(SEGMENT_SUFFIX, META_SUFFIX))
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                meta = {}
            segments.append(
                SpoolSegment(
                    path=path,
                    meta_path=meta_path,
                    batch_id=str(meta.get("batchId") or path.stem.split("-", 1)[-1]),
                    event_count=int(meta.get("eventCount") or 0),
                    bytes=int(meta.get("bytes") or path.stat().st_size),
                    created_at=float(meta.get("createdAt") or path.stat().st_mtime),
                    clock_skew_seconds=meta.get("clockSkewSeconds"),
                )
            )
        return sorted(segments, key=lambda segment: (segment.created_at, segment.path.name))

    def read(self, segment: SpoolSegment) -> str:
        return segment.path.read_text(encoding="utf-8")

    def ack(self, segment: SpoolSegment) -> None:
        segment.path.unlink(missing_ok=True)
        segment.meta_path.unlink(missing_ok=True)

    def dead_letter_segment(self, segment: SpoolSegment, *, reason: str) -> Path:
        target = self.dead_letter / segment.path.name
        os.replace(segment.path, target)
        segment.meta_path.unlink(missing_ok=True)
        note = target.with_name(target.name + ".reason.txt")
        note.write_text(reason, encoding="utf-8")
        return target

    def dead_letter_count(self) -> int:
        return sum(1 for _ in self.dead_letter.glob(f"*{SEGMENT_SUFFIX}"))
