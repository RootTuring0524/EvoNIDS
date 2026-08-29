"""Full CICIDS2017 extraction: every packet in the WorkingHours captures, no benign downsampling.

Reuses the audited repository extractor scripts/extract_cicids2017_flows.py with:
  * full-day analysis windows -> every packet is parsed into the flow table
  * benign_sample_rate = 1.0       -> no benign downsampling
  * real-time console progress (per 200k packets)

Output: <data dir>\\CICIDS2017\\cicids2017_pcap_flow_full_v1.csv.gz + .metadata.json
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import extract_cicids2017_flows as extractor  # noqa: E402

# Directory that contains the official UNB WorkingHours PCAP files (see DATA_CARD.md).
DEFAULT_INPUT = Path("./data/CICIDS2017")
DEFAULT_OUTPUT = HERE.parent / "data" / "CICIDS2017" / "cicids2017_pcap_flow_full_v1.csv.gz"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-root", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--days", nargs="+", choices=tuple(extractor.DAY_FILES), default=list(extractor.DAY_FILES))
    parser.add_argument(
        "--sweep-interval",
        type=int,
        default=200_000,
        help="Expire idle flows every N packets (memory guard).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    # Full-day windows: parse every packet of the WorkingHours captures.
    extractor.ANALYSIS_WINDOWS_UTC = {day: [(0, 86_400)] for day in args.days}
    extractor.SWEEP_PACKET_INTERVAL = args.sweep_interval

    sources = {day: (args.input_root / extractor.DAY_FILES[day]).resolve() for day in args.days}
    missing = [str(path) for path in sources.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"Missing CICIDS2017 PCAP files: {', '.join(missing)}")

    output = args.output.resolve()
    metadata_path = output.with_name(output.name.removesuffix(".csv.gz") + ".metadata.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".partial")
    started_at = datetime.now(tz=UTC)
    total_started = time.perf_counter()

    print("=" * 78, flush=True)
    print("EvoNIDS FULL extraction  (all working hours, benign sample rate = 1.0)", flush=True)
    print(f"input  : {args.input_root}", flush=True)
    print(f"output : {output}", flush=True)
    print(f"days   : {', '.join(args.days)}", flush=True)
    print("=" * 78, flush=True)

    summaries: list[dict[str, object]] = []
    with gzip.open(temporary, "wt", encoding="utf-8", newline="", compresslevel=5) as handle:
        writer = csv.DictWriter(handle, fieldnames=extractor.FEATURE_COLUMNS)
        writer.writeheader()
        for day in args.days:
            source = sources[day]
            print(f"[start] {day}: {source.name} ({source.stat().st_size / 1e9:.2f} GB)", flush=True)
            summary = extractor.extract_day(
                day=day,
                source=source,
                writer=writer,
                benign_sample_rate=1.0,
            )
            summaries.append(summary)
            print(
                f"[done] {day}: blocks={summary['packetBlocksScanned']:,} "
                f"packets={summary['packetsParsedInSelectedWindows']:,} "
                f"flows={summary['flowsExtracted']:,} elapsed={summary['elapsedSeconds']:.1f}s",
                flush=True,
            )

    temporary.replace(output)

    output_sha256 = hashlib.sha256()
    with output.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            output_sha256.update(chunk)

    combined_labels: Counter[str] = Counter()
    total_blocks = 0
    total_packets = 0
    total_flows = 0
    for summary in summaries:
        combined_labels.update(summary["selectedLabelDistribution"])
        total_blocks += int(summary["packetBlocksScanned"])
        total_packets += int(summary["packetsParsedInSelectedWindows"])
        total_flows += int(summary["flowsExtracted"])

    metadata = {
        "extractorVersion": extractor.EXTRACTOR_VERSION,
        "createdAt": datetime.now(tz=UTC).isoformat(),
        "startedAt": started_at.isoformat(),
        "officialDatasetPage": extractor.OFFICIAL_DATASET_PAGE,
        "sourceFormat": "CICIDS2017 original PCAPNG",
        "labelingBasis": "Official UNB attack schedule plus documented attacker/victim endpoints and service ports",
        "timezoneNormalization": "Official ADT schedule converted to UTC (+3 hours) before interval matching",
        "flowPolicy": {
            "bidirectionalFiveTuple": True,
            "idleTimeoutSeconds": extractor.FLOW_IDLE_TIMEOUT_SECONDS,
            "activeTimeoutSeconds": extractor.FLOW_ACTIVE_TIMEOUT_SECONDS,
            "ipv4Only": True,
            "linkType": "Ethernet",
        },
        "sampling": {
            "attackFlows": "all matched flows",
            "benignMethod": "none - every benign flow is kept",
            "benignSampleRate": 1.0,
        },
        "analysisWindows": "full capture day (every packet parsed; no window cropping)",
        "output": str(output),
        "outputSizeBytes": output.stat().st_size,
        "outputSha256": output_sha256.hexdigest(),
        "featureCount": len(extractor.FEATURE_COLUMNS) - 1,
        "totalPacketBlocksScanned": total_blocks,
        "totalPacketsParsed": total_packets,
        "totalFlowsExtracted": total_flows,
        "labelDistribution": dict(sorted(combined_labels.items())),
        "totalElapsedSeconds": round(time.perf_counter() - total_started, 3),
        "days": summaries,
        "limitations": [
            "This is an EvoNIDS research flow table, not a byte-for-byte reproduction of CICFlowMeter output.",
            "Only Ethernet IPv4 packets are included; non-initial fragments have zero transport ports.",
            "Labels are schedule-and-endpoint derived and should be cross-checked against official labeled CSVs before publication.",
            "Every flow in the WorkingHours captures is kept; no benign downsampling was applied in this full extraction.",
        ],
    }
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")

    print("-" * 78, flush=True)
    print(f"[complete] output={output}", flush=True)
    print(f"[complete] rows={total_flows:,} labels={dict(sorted(combined_labels.items()))}", flush=True)
    print(f"[complete] elapsed={metadata['totalElapsedSeconds']:.1f}s sha256={metadata['outputSha256']}", flush=True)
    print(f"[complete] metadata={metadata_path}", flush=True)


if __name__ == "__main__":
    main()
