"""Collector entry point: tail a Suricata EVE file and ship batches to EvoNIDS.

Run it next to Suricata on the sensor host:

    python -m app.collector.cli \
        --eve-file /var/log/suricata/eve.json \
        --endpoint https://evonids.example.com/api/v1 \
        --sensor-id lab-core-01 \
        --token "$EVONIDS_SENSOR_TOKEN" \
        --spool ./collector-spool

The CLI never deletes the source EVE file, never blocks Suricata, and persists
its read offset so a restart resumes where it stopped. Undeliverable batches stay
in the spool and are retried on the next loop.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

from app.collector.client import AGENT_VERSION, CollectorClient, CollectorConfig
from app.collector.transport import HttpTransport


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="EvoNIDS Suricata EVE collector")
    parser.add_argument("--eve-file", required=True, type=Path)
    parser.add_argument("--endpoint", required=True, help="API base, e.g. https://host/api/v1")
    parser.add_argument("--sensor-id", required=True)
    parser.add_argument(
        "--token",
        default=os.environ.get("EVONIDS_SENSOR_TOKEN", ""),
        help="sensor ingest token (prefer the EVONIDS_SENSOR_TOKEN environment variable)",
    )
    parser.add_argument("--spool", type=Path, default=Path("./collector-spool"))
    parser.add_argument("--state-file", type=Path, default=Path("./collector-state.json"))
    parser.add_argument("--batch-max-events", type=int, default=2_000)
    parser.add_argument("--flush-interval", type=float, default=2.0)
    parser.add_argument("--heartbeat-interval", type=float, default=60.0)
    parser.add_argument("--rate-limit-events-per-second", type=float, default=0.0)
    parser.add_argument("--max-attempts", type=int, default=5)
    parser.add_argument("--once", action="store_true", help="read what is available and exit")
    parser.add_argument("--insecure-skip-verify", action="store_true")
    parser.add_argument("--client-cert", default=None)
    parser.add_argument("--client-key", default=None)
    return parser.parse_args(argv)


def load_offset(state_file: Path) -> tuple[int, int]:
    try:
        payload = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0, 0
    return int(payload.get("offset") or 0), int(payload.get("inode") or 0)


def save_offset(state_file: Path, offset: int, inode: int) -> None:
    temporary = state_file.with_suffix(".tmp")
    temporary.write_text(json.dumps({"offset": offset, "inode": inode}), encoding="utf-8")
    os.replace(temporary, state_file)


def read_new_lines(path: Path, offset: int, inode: int, *, max_lines: int) -> tuple[list[str], int, int]:
    """Read complete lines after ``offset``; handles truncation and rotation."""
    try:
        stat = path.stat()
    except OSError:
        return [], offset, inode
    if inode and stat.st_ino != inode:
        offset = 0
    if stat.st_size < offset:
        offset = 0
    lines: list[str] = []
    # ``utf-8-sig`` tolerates a byte-order mark that some log rotators or editors
    # prepend; without it the first JSON line would be rejected as malformed.
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        handle.seek(offset)
        while len(lines) < max_lines:
            position = handle.tell()
            raw = handle.readline()
            if not raw:
                break
            if not raw.endswith("\n"):
                # Partial line: rewind so the next loop reads the complete record.
                handle.seek(position)
                break
            stripped = raw.strip()
            if stripped:
                lines.append(stripped)
        offset = handle.tell()
    return lines, offset, stat.st_ino


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.token:
        print("error: a sensor token is required (--token or EVONIDS_SENSOR_TOKEN)", file=sys.stderr)
        return 2
    if not args.eve_file.exists():
        print(f"error: EVE file not found: {args.eve_file}", file=sys.stderr)
        return 2

    config = CollectorConfig(
        sensor_id=args.sensor_id,
        endpoint=args.endpoint,
        token=args.token,
        spool_root=args.spool,
        batch_max_events=args.batch_max_events,
        max_attempts=args.max_attempts,
        rate_limit_events_per_second=args.rate_limit_events_per_second,
        verify_tls=not args.insecure_skip_verify,
        client_cert=args.client_cert,
        client_key=args.client_key,
    )
    transport = HttpTransport(
        client_cert=args.client_cert,
        client_key=args.client_key,
        verify=not args.insecure_skip_verify,
    )
    client = CollectorClient(config, transport)
    offset, inode = load_offset(args.state_file)
    stopping = False

    def _stop(signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True
        print(f"[collector] signal {signum} received, flushing spool before exit", flush=True)

    signal.signal(signal.SIGINT, _stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _stop)

    print(
        f"[collector] agent={AGENT_VERSION} sensor={config.sensor_id} endpoint={config.endpoint} "
        f"spool={config.spool_root} resumeOffset={offset}",
        flush=True,
    )
    last_heartbeat = 0.0
    while not stopping:
        lines, offset, inode = read_new_lines(
            args.eve_file, offset, inode, max_lines=config.batch_max_events
        )
        if lines:
            for result in client.submit(lines):
                print(
                    "[batch] "
                    + json.dumps(
                        {
                            "batchId": result.batch_id,
                            "status": result.status,
                            "attempts": result.attempts,
                            "accepted": result.accepted_events,
                            "duplicates": result.duplicate_events,
                            "rejected": result.rejected_events,
                            "elapsedMs": result.elapsed_ms,
                            "error": result.error,
                        },
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
            save_offset(args.state_file, offset, inode)
        else:
            for result in client.flush_spool(limit=5):
                print(
                    f"[spool] batchId={result.batch_id} status={result.status} error={result.error}",
                    flush=True,
                )
        now = time.monotonic()
        if now - last_heartbeat >= args.heartbeat_interval:
            outcome = client.heartbeat()
            last_heartbeat = now
            print(f"[heartbeat] {json.dumps(outcome, ensure_ascii=False)}", flush=True)
        if args.once:
            break
        time.sleep(args.flush_interval)

    for result in client.flush_spool():
        print(f"[flush] batchId={result.batch_id} status={result.status}", flush=True)
    print(f"[collector] metrics {json.dumps(client.metrics.as_dict(), ensure_ascii=False)}", flush=True)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
