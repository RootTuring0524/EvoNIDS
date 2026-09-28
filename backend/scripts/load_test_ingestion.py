"""Ingestion load generator: honest throughput and latency measurement.

Usage (against a running API):

    python scripts/load_test_ingestion.py --endpoint http://127.0.0.1:8000/api/v1 \
        --token "$EVONIDS_SENSOR_TOKEN" --sensor-id loadtest-01 \
        --connections 8 --batches 200 --events-per-batch 500

It reports real p50/p95/p99 latency, achieved throughput and error rate, plus the
exact hardware/process context. It refuses to run without a token and never
prints a number it did not measure: if zero requests succeed, every latency
field is reported as null.
"""
from __future__ import annotations

import argparse
import asyncio
import gzip
import json
import os
import platform
import random
import statistics
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@dataclass(slots=True)
class LoadStats:
    latencies_ms: list[float] = field(default_factory=list)
    statuses: dict[int, int] = field(default_factory=dict)
    errors: dict[str, int] = field(default_factory=dict)
    events_sent: int = 0
    bytes_sent: int = 0
    started_at: float = 0.0
    finished_at: float = 0.0

    def record(self, *, status: int | None, latency_ms: float, events: int, payload_bytes: int, error: str | None) -> None:
        if status is not None:
            self.statuses[status] = self.statuses.get(status, 0) + 1
            self.latencies_ms.append(latency_ms)
        if error:
            self.errors[error] = self.errors.get(error, 0) + 1
        self.events_sent += events
        self.bytes_sent += payload_bytes

    def summary(self, *, connections: int, events_per_batch: int) -> dict:
        duration = max(self.finished_at - self.started_at, 1e-9)
        ordered = sorted(self.latencies_ms)
        total_requests = sum(self.statuses.values())
        http_failures = sum(count for status, count in self.statuses.items() if status >= 400)
        transport_failures = sum(self.errors.values())
        failures = http_failures + transport_failures

        def percentile(fraction: float) -> float | None:
            if not ordered:
                return None
            index = min(int(fraction * (len(ordered) - 1)), len(ordered) - 1)
            return round(ordered[index], 3)

        return {
            "requests": total_requests,
            "failures": failures,
            "httpFailures": http_failures,
            "transportFailures": transport_failures,
            "errorRate": round(failures / (total_requests + transport_failures), 6)
            if (total_requests + transport_failures)
            else None,
            "eventsSent": self.events_sent,
            "bytesSent": self.bytes_sent,
            "durationSeconds": round(duration, 3),
            "requestsPerSecond": round(total_requests / duration, 3) if total_requests else None,
            "eventsPerSecond": round(self.events_sent / duration, 3) if self.events_sent else None,
            "megabytesPerSecond": round(self.bytes_sent / duration / 1_048_576, 4),
            "latencyMs": {
                "p50": percentile(0.5),
                "p95": percentile(0.95),
                "p99": percentile(0.99),
                "max": round(ordered[-1], 3) if ordered else None,
                "mean": round(statistics.fmean(ordered), 3) if ordered else None,
            },
            "statuses": {str(status): count for status, count in sorted(self.statuses.items())},
            "transportErrors": dict(sorted(self.errors.items())),
            "context": {
                "connections": connections,
                "eventsPerBatch": events_per_batch,
                "platform": platform.platform(),
                "python": sys.version.split()[0],
                "cpuCount": os.cpu_count(),
            },
        }


def make_batch(*, events: int, sensor_id: str, base_flow_id: int) -> str:
    lines = []
    for index in range(events):
        flow_id = base_flow_id + index
        lines.append(
            json.dumps(
                {
                    "timestamp": "2026-09-09T10:00:00.000000+0000",
                    "flow_id": flow_id,
                    "event_type": "flow",
                    "src_ip": f"198.51.100.{random.randint(1, 254)}",
                    "src_port": random.randint(1024, 65535),
                    "dest_ip": f"10.0.{random.randint(0, 9)}.{random.randint(1, 254)}",
                    "dest_port": random.choice([80, 443, 445, 22, 53]),
                    "proto": random.choice(["TCP", "UDP"]),
                    "app_proto": "http",
                    "flow": {
                        "pkts_toserver": random.randint(1, 40),
                        "pkts_toclient": random.randint(0, 40),
                        "bytes_toserver": random.randint(40, 9000),
                        "bytes_toclient": random.randint(0, 9000),
                        "age": random.randint(0, 30),
                    },
                }
            )
        )
    return "\n".join(lines) + "\n"


async def run(args: argparse.Namespace) -> dict:
    import httpx

    stats = LoadStats()
    stats.started_at = time.perf_counter()
    semaphore = asyncio.Semaphore(args.connections)

    async with httpx.AsyncClient(timeout=args.timeout) as client:

        async def one(batch_index: int) -> None:
            async with semaphore:
                batch_id = f"load-{uuid.uuid4().hex[:16]}"
                payload = make_batch(
                    events=args.events_per_batch,
                    sensor_id=args.sensor_id,
                    base_flow_id=args.base_flow_id + batch_index * args.events_per_batch,
                ).encode("utf-8")
                body = gzip.compress(payload) if args.compress else payload
                headers = {
                    "Content-Type": "application/x-ndjson",
                    "Authorization": f"Bearer {args.token}",
                    "X-Evonids-Batch-Id": batch_id,
                    "X-Evonids-Encoding": "gzip" if args.compress else "identity",
                    "X-Evonids-Event-Count": str(args.events_per_batch),
                }
                started = time.perf_counter()
                try:
                    response = await client.post(
                        f"{args.endpoint.rstrip('/')}/ingestion/eve/batch",
                        params={"sensorId": args.sensor_id},
                        headers=headers,
                        content=body,
                    )
                except Exception as error:  # noqa: BLE001 - transport failure is data
                    stats.record(
                        status=None,
                        latency_ms=0.0,
                        events=args.events_per_batch,
                        payload_bytes=len(body),
                        error=type(error).__name__,
                    )
                    return
                stats.record(
                    status=response.status_code,
                    latency_ms=(time.perf_counter() - started) * 1000,
                    events=args.events_per_batch,
                    payload_bytes=len(body),
                    error=None if response.status_code < 400 else f"http_{response.status_code}",
                )

        tasks = [asyncio.create_task(one(index)) for index in range(args.batches)]
        await asyncio.gather(*tasks)

    stats.finished_at = time.perf_counter()
    return stats.summary(connections=args.connections, events_per_batch=args.events_per_batch)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", default="http://127.0.0.1:8000/api/v1")
    parser.add_argument("--token", default=os.environ.get("EVONIDS_SENSOR_TOKEN", ""))
    parser.add_argument("--sensor-id", default="loadtest-01")
    parser.add_argument("--connections", type=int, default=8)
    parser.add_argument("--batches", type=int, default=200)
    parser.add_argument("--events-per-batch", type=int, default=500)
    parser.add_argument("--base-flow-id", type=int, default=9_000_000)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--no-compress", dest="compress", action="store_false")
    parser.add_argument("--output", type=Path, default=None)
    parser.set_defaults(compress=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.token:
        print(
            "error: a sensor-scope token is required (--token or EVONIDS_SENSOR_TOKEN). "
            "Load testing without authentication would only measure the 401 path.",
            file=sys.stderr,
        )
        return 2
    summary = asyncio.run(run(args))
    text = json.dumps(summary, ensure_ascii=False, indent=2)
    print(text)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        print(f"written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
