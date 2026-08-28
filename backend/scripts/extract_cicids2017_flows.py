from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import math
import socket
import struct
import time
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO, Iterator


EXTRACTOR_VERSION = "evonids-pcapng-flow-v1"
OFFICIAL_DATASET_PAGE = "https://www.unb.ca/cic/datasets/ids-2017.html"
FLOW_IDLE_TIMEOUT_SECONDS = 60.0
FLOW_ACTIVE_TIMEOUT_SECONDS = 120.0
SWEEP_PACKET_INTERVAL = 500_000

DAY_FILES = {
    "Monday": "Monday-WorkingHours.pcap",
    "Tuesday": "Tuesday-WorkingHours.pcap",
    "Wednesday": "Wednesday-WorkingHours.pcap",
    "Thursday": "Thursday-WorkingHours.pcap",
    "Friday": "Friday-WorkingHours.pcap",
}

# UTC intervals selected for the local research set. Attack intervals include a small
# guard band; the remaining intervals provide normal controls from different parts of
# each working day. Every source file is still read and hashed in full.
ANALYSIS_WINDOWS_UTC = {
    "Monday": [(12 * 3600, 13 * 3600), (15 * 3600, 16 * 3600), (19 * 3600, 20 * 3600)],
    "Tuesday": [
        (12 * 3600 + 15 * 60, 13 * 3600 + 25 * 60),
        (14 * 3600, 15 * 3600),
        (16 * 3600 + 55 * 60, 18 * 3600 + 5 * 60),
        (19 * 3600, 20 * 3600),
    ],
    "Wednesday": [
        (12 * 3600 + 40 * 60, 14 * 3600 + 30 * 60),
        (15 * 3600, 16 * 3600),
        (18 * 3600 + 5 * 60, 18 * 3600 + 40 * 60),
        (19 * 3600, 20 * 3600),
    ],
    "Thursday": [
        (12 * 3600 + 15 * 60, 13 * 3600 + 50 * 60),
        (14 * 3600, 15 * 3600),
        (17 * 3600 + 10 * 60, 18 * 3600 + 50 * 60),
        (19 * 3600, 20 * 3600),
    ],
    "Friday": [
        (12 * 3600 + 55 * 60, 14 * 3600 + 10 * 60),
        (15 * 3600, 16 * 3600),
        (16 * 3600 + 50 * 60, 18 * 3600 + 35 * 60),
        (18 * 3600 + 50 * 60, 19 * 3600 + 20 * 60),
        (19 * 3600 + 30 * 60, 20 * 3600),
    ],
}

FEATURE_COLUMNS = [
    "capture_day",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
    "start_time",
    "duration_us",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "fwd_packet_length_mean",
    "fwd_packet_length_std",
    "fwd_packet_length_min",
    "fwd_packet_length_max",
    "bwd_packet_length_mean",
    "bwd_packet_length_std",
    "bwd_packet_length_min",
    "bwd_packet_length_max",
    "flow_packet_length_mean",
    "flow_packet_length_std",
    "flow_packet_length_min",
    "flow_packet_length_max",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_min",
    "flow_iat_max",
    "fwd_iat_mean",
    "fwd_iat_std",
    "fwd_iat_min",
    "fwd_iat_max",
    "bwd_iat_mean",
    "bwd_iat_std",
    "bwd_iat_min",
    "bwd_iat_max",
    "flow_bytes_per_second",
    "flow_packets_per_second",
    "syn_flag_count",
    "ack_flag_count",
    "rst_flag_count",
    "fin_flag_count",
    "psh_flag_count",
    "urg_flag_count",
    "down_up_ratio",
    "average_packet_size",
    "Label",
]


@dataclass(frozen=True)
class Packet:
    timestamp: float
    source_ip: bytes
    destination_ip: bytes
    source_port: int
    destination_port: int
    protocol: int
    wire_length: int
    tcp_flags: int


class RunningStats:
    __slots__ = ("count", "maximum", "minimum", "sum", "sum_squares")

    def __init__(self) -> None:
        self.count = 0
        self.sum = 0.0
        self.sum_squares = 0.0
        self.minimum = math.inf
        self.maximum = -math.inf

    def add(self, value: float) -> None:
        self.count += 1
        self.sum += value
        self.sum_squares += value * value
        self.minimum = min(self.minimum, value)
        self.maximum = max(self.maximum, value)

    def mean(self) -> float:
        return self.sum / self.count if self.count else 0.0

    def std(self) -> float:
        if self.count <= 1:
            return 0.0
        variance = max(0.0, (self.sum_squares / self.count) - (self.mean() ** 2))
        return math.sqrt(variance)

    def min_value(self) -> float:
        return self.minimum if self.count else 0.0

    def max_value(self) -> float:
        return self.maximum if self.count else 0.0


class Flow:
    __slots__ = (
        "ack",
        "bwd_bytes",
        "bwd_iat",
        "bwd_lengths",
        "bwd_packets",
        "destination_ip",
        "destination_port",
        "fin",
        "first_seen",
        "flow_iat",
        "fwd_bytes",
        "fwd_iat",
        "fwd_lengths",
        "fwd_packets",
        "last_bwd",
        "last_fwd",
        "last_seen",
        "packet_lengths",
        "protocol",
        "psh",
        "rst",
        "source_ip",
        "source_port",
        "syn",
        "urg",
    )

    def __init__(self, packet: Packet) -> None:
        self.source_ip = packet.source_ip
        self.destination_ip = packet.destination_ip
        self.source_port = packet.source_port
        self.destination_port = packet.destination_port
        self.protocol = packet.protocol
        self.first_seen = packet.timestamp
        self.last_seen = packet.timestamp
        self.last_fwd: float | None = None
        self.last_bwd: float | None = None
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.fwd_lengths = RunningStats()
        self.bwd_lengths = RunningStats()
        self.packet_lengths = RunningStats()
        self.flow_iat = RunningStats()
        self.fwd_iat = RunningStats()
        self.bwd_iat = RunningStats()
        self.syn = 0
        self.ack = 0
        self.rst = 0
        self.fin = 0
        self.psh = 0
        self.urg = 0
        self.add(packet)

    def add(self, packet: Packet) -> None:
        is_forward = (
            packet.source_ip == self.source_ip
            and packet.source_port == self.source_port
            and packet.destination_ip == self.destination_ip
            and packet.destination_port == self.destination_port
        )
        if self.packet_lengths.count:
            self.flow_iat.add(max(0.0, (packet.timestamp - self.last_seen) * 1_000_000))
        self.packet_lengths.add(packet.wire_length)
        if is_forward:
            if self.last_fwd is not None:
                self.fwd_iat.add(max(0.0, (packet.timestamp - self.last_fwd) * 1_000_000))
            self.last_fwd = packet.timestamp
            self.fwd_packets += 1
            self.fwd_bytes += packet.wire_length
            self.fwd_lengths.add(packet.wire_length)
        else:
            if self.last_bwd is not None:
                self.bwd_iat.add(max(0.0, (packet.timestamp - self.last_bwd) * 1_000_000))
            self.last_bwd = packet.timestamp
            self.bwd_packets += 1
            self.bwd_bytes += packet.wire_length
            self.bwd_lengths.add(packet.wire_length)
        self.syn += int(bool(packet.tcp_flags & 0x02))
        self.ack += int(bool(packet.tcp_flags & 0x10))
        self.rst += int(bool(packet.tcp_flags & 0x04))
        self.fin += int(bool(packet.tcp_flags & 0x01))
        self.psh += int(bool(packet.tcp_flags & 0x08))
        self.urg += int(bool(packet.tcp_flags & 0x20))
        self.last_seen = packet.timestamp

    def should_rollover(self, packet: Packet) -> bool:
        return (
            packet.timestamp - self.last_seen > FLOW_IDLE_TIMEOUT_SECONDS
            or packet.timestamp - self.first_seen > FLOW_ACTIVE_TIMEOUT_SECONDS
        )

    def row(self, day: str, label: str) -> dict[str, object]:
        duration_seconds = max(self.last_seen - self.first_seen, 0.000001)
        total_packets = self.fwd_packets + self.bwd_packets
        total_bytes = self.fwd_bytes + self.bwd_bytes
        return {
            "capture_day": day,
            "source_ip": socket.inet_ntoa(self.source_ip),
            "source_port": self.source_port,
            "destination_ip": socket.inet_ntoa(self.destination_ip),
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "start_time": datetime.fromtimestamp(self.first_seen, tz=UTC).isoformat(),
            "duration_us": round(duration_seconds * 1_000_000, 3),
            "total_fwd_packets": self.fwd_packets,
            "total_bwd_packets": self.bwd_packets,
            "total_fwd_bytes": self.fwd_bytes,
            "total_bwd_bytes": self.bwd_bytes,
            "fwd_packet_length_mean": round(self.fwd_lengths.mean(), 6),
            "fwd_packet_length_std": round(self.fwd_lengths.std(), 6),
            "fwd_packet_length_min": round(self.fwd_lengths.min_value(), 6),
            "fwd_packet_length_max": round(self.fwd_lengths.max_value(), 6),
            "bwd_packet_length_mean": round(self.bwd_lengths.mean(), 6),
            "bwd_packet_length_std": round(self.bwd_lengths.std(), 6),
            "bwd_packet_length_min": round(self.bwd_lengths.min_value(), 6),
            "bwd_packet_length_max": round(self.bwd_lengths.max_value(), 6),
            "flow_packet_length_mean": round(self.packet_lengths.mean(), 6),
            "flow_packet_length_std": round(self.packet_lengths.std(), 6),
            "flow_packet_length_min": round(self.packet_lengths.min_value(), 6),
            "flow_packet_length_max": round(self.packet_lengths.max_value(), 6),
            "flow_iat_mean": round(self.flow_iat.mean(), 6),
            "flow_iat_std": round(self.flow_iat.std(), 6),
            "flow_iat_min": round(self.flow_iat.min_value(), 6),
            "flow_iat_max": round(self.flow_iat.max_value(), 6),
            "fwd_iat_mean": round(self.fwd_iat.mean(), 6),
            "fwd_iat_std": round(self.fwd_iat.std(), 6),
            "fwd_iat_min": round(self.fwd_iat.min_value(), 6),
            "fwd_iat_max": round(self.fwd_iat.max_value(), 6),
            "bwd_iat_mean": round(self.bwd_iat.mean(), 6),
            "bwd_iat_std": round(self.bwd_iat.std(), 6),
            "bwd_iat_min": round(self.bwd_iat.min_value(), 6),
            "bwd_iat_max": round(self.bwd_iat.max_value(), 6),
            "flow_bytes_per_second": round(total_bytes / duration_seconds, 6),
            "flow_packets_per_second": round(total_packets / duration_seconds, 6),
            "syn_flag_count": self.syn,
            "ack_flag_count": self.ack,
            "rst_flag_count": self.rst,
            "fin_flag_count": self.fin,
            "psh_flag_count": self.psh,
            "urg_flag_count": self.urg,
            "down_up_ratio": round(self.bwd_packets / max(self.fwd_packets, 1), 6),
            "average_packet_size": round(total_bytes / max(total_packets, 1), 6),
            "Label": label,
        }


class PcapNgReader:
    def __init__(self, path: Path, *, intervals_utc: list[tuple[int, int]]) -> None:
        self.path = path
        self.intervals_utc = intervals_utc
        self.sha256 = hashlib.sha256()
        self.bytes_read = 0
        self.packet_blocks_seen = 0
        self.packet_count = 0
        self._endian = "<"
        self._interfaces: dict[int, tuple[int, float]] = {}

    def packets(self) -> Iterator[Packet]:
        with self.path.open("rb", buffering=32 * 1024 * 1024) as handle:
            while header := handle.read(8):
                if len(header) != 8:
                    raise ValueError(f"Truncated PCAPNG block header in {self.path.name}")
                block_type_bytes = header[:4]
                if block_type_bytes == b"\x0a\x0d\x0d\x0a":
                    yield from self._read_section_header(handle, header)
                    continue
                block_type, block_length = struct.unpack(self._endian + "II", header)
                if block_length < 12:
                    raise ValueError(f"Invalid PCAPNG block length {block_length} in {self.path.name}")
                body = self._read_exact(handle, block_length - 12)
                trailer = self._read_exact(handle, 4)
                self._hash_block(header, body, trailer)
                if struct.unpack(self._endian + "I", trailer)[0] != block_length:
                    raise ValueError(f"PCAPNG block length mismatch in {self.path.name}")
                if block_type == 1:
                    self._register_interface(body)
                elif block_type == 6:
                    self.packet_blocks_seen += 1
                    packet = self._enhanced_packet(body)
                    if packet is not None:
                        self.packet_count += 1
                        yield packet

    def _read_section_header(self, handle: BinaryIO, header: bytes) -> Iterator[Packet]:
        raw_length = header[4:8]
        lengths = [("<", struct.unpack("<I", raw_length)[0]), (">", struct.unpack(">I", raw_length)[0])]
        endian, block_length = next(
            ((candidate, length) for candidate, length in lengths if 28 <= length <= 16 * 1024 * 1024),
            (None, None),
        )
        if endian is None or block_length is None:
            raise ValueError(f"Invalid PCAPNG section header in {self.path.name}")
        body = self._read_exact(handle, block_length - 12)
        trailer = self._read_exact(handle, 4)
        byte_order_magic = body[:4]
        expected_endian = "<" if byte_order_magic == b"\x4d\x3c\x2b\x1a" else ">"
        if expected_endian != endian:
            raise ValueError(f"Unsupported PCAPNG section byte order in {self.path.name}")
        self._endian = endian
        self._interfaces = {}
        self._hash_block(header, body, trailer)
        return iter(())

    def _register_interface(self, body: bytes) -> None:
        if len(body) < 8:
            return
        link_type, _, _ = struct.unpack(self._endian + "HHI", body[:8])
        resolution = 1_000_000.0
        offset = 8
        while offset + 4 <= len(body):
            code, length = struct.unpack(self._endian + "HH", body[offset : offset + 4])
            offset += 4
            value = body[offset : offset + length]
            offset += ((length + 3) // 4) * 4
            if code == 0:
                break
            if code == 9 and value:
                raw = value[0]
                resolution = float(2 ** (raw & 0x7F) if raw & 0x80 else 10**raw)
        self._interfaces[len(self._interfaces)] = (link_type, resolution)

    def _enhanced_packet(self, body: bytes) -> Packet | None:
        if len(body) < 20:
            return None
        interface_id, timestamp_high, timestamp_low, captured_length, original_length = struct.unpack(
            self._endian + "IIIII", body[:20]
        )
        interface = self._interfaces.get(interface_id)
        if interface is None:
            return None
        link_type, resolution = interface
        if link_type != 1:
            return None
        packet_data = body[20 : 20 + captured_length]
        timestamp = ((timestamp_high << 32) | timestamp_low) / resolution
        second_of_day = int(timestamp % 86_400)
        if not any(start <= second_of_day <= end for start, end in self.intervals_utc):
            return None
        return decode_ethernet_ipv4(timestamp, packet_data, original_length)

    def _read_exact(self, handle: BinaryIO, length: int) -> bytes:
        value = handle.read(length)
        if len(value) != length:
            raise ValueError(f"Truncated PCAPNG block in {self.path.name}")
        return value

    def _hash_block(self, header: bytes, body: bytes, trailer: bytes) -> None:
        self.sha256.update(header)
        self.sha256.update(body)
        self.sha256.update(trailer)
        self.bytes_read += len(header) + len(body) + len(trailer)


def decode_ethernet_ipv4(timestamp: float, packet: bytes, original_length: int) -> Packet | None:
    if len(packet) < 34:
        return None
    ether_type = struct.unpack("!H", packet[12:14])[0]
    offset = 14
    if ether_type in (0x8100, 0x88A8):
        if len(packet) < 38:
            return None
        ether_type = struct.unpack("!H", packet[16:18])[0]
        offset = 18
    if ether_type != 0x0800 or len(packet) < offset + 20:
        return None
    version_ihl = packet[offset]
    if version_ihl >> 4 != 4:
        return None
    ip_header_length = (version_ihl & 0x0F) * 4
    if ip_header_length < 20 or len(packet) < offset + ip_header_length:
        return None
    protocol = packet[offset + 9]
    source_ip = packet[offset + 12 : offset + 16]
    destination_ip = packet[offset + 16 : offset + 20]
    fragment_offset = struct.unpack("!H", packet[offset + 6 : offset + 8])[0] & 0x1FFF
    transport_offset = offset + ip_header_length
    source_port = 0
    destination_port = 0
    tcp_flags = 0
    if fragment_offset == 0 and protocol in (6, 17) and len(packet) >= transport_offset + 4:
        source_port, destination_port = struct.unpack("!HH", packet[transport_offset : transport_offset + 4])
        if protocol == 6 and len(packet) >= transport_offset + 14:
            tcp_flags = packet[transport_offset + 13]
    ip_total_length = struct.unpack("!H", packet[offset + 2 : offset + 4])[0]
    wire_length = ip_total_length if ip_total_length > 0 else original_length
    return Packet(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        wire_length=wire_length,
        tcp_flags=tcp_flags,
    )


def flow_key(packet: Packet) -> tuple[tuple[bytes, int], tuple[bytes, int], int]:
    source = (packet.source_ip, packet.source_port)
    destination = (packet.destination_ip, packet.destination_port)
    return (source, destination, packet.protocol) if source <= destination else (destination, source, packet.protocol)


def overlaps(flow: Flow, start_utc: int, end_utc: int) -> bool:
    day_start = math.floor(flow.first_seen / 86_400) * 86_400
    return flow.last_seen >= day_start + start_utc and flow.first_seen <= day_start + end_utc


def endpoints(flow: Flow) -> set[str]:
    return {socket.inet_ntoa(flow.source_ip), socket.inet_ntoa(flow.destination_ip)}


def has_port(flow: Flow, *ports: int) -> bool:
    return flow.source_port in ports or flow.destination_port in ports


def classify_flow(day: str, flow: Flow) -> str:
    pair = endpoints(flow)
    attacker_to_web = pair == {"172.16.0.1", "192.168.10.50"}
    attacker_to_ubuntu = pair == {"172.16.0.1", "192.168.10.51"}
    if day == "Tuesday" and attacker_to_web:
        if overlaps(flow, 12 * 3600 + 20 * 60, 13 * 3600 + 20 * 60) and has_port(flow, 21):
            return "FTP-Patator"
        if overlaps(flow, 17 * 3600, 18 * 3600) and has_port(flow, 22):
            return "SSH-Patator"
    if day == "Wednesday":
        if attacker_to_web and has_port(flow, 80):
            if overlaps(flow, 12 * 3600 + 47 * 60, 13 * 3600 + 10 * 60):
                return "DoS slowloris"
            if overlaps(flow, 13 * 3600 + 14 * 60, 13 * 3600 + 35 * 60):
                return "DoS Slowhttptest"
            if overlaps(flow, 13 * 3600 + 43 * 60, 14 * 3600):
                return "DoS Hulk"
            if overlaps(flow, 14 * 3600 + 10 * 60, 14 * 3600 + 23 * 60):
                return "DoS GoldenEye"
        if (
            attacker_to_ubuntu
            and has_port(flow, 444)
            and overlaps(flow, 18 * 3600 + 12 * 60, 18 * 3600 + 32 * 60)
        ):
            return "Heartbleed"
    if day == "Thursday":
        if attacker_to_web and has_port(flow, 80):
            if overlaps(flow, 12 * 3600 + 20 * 60, 13 * 3600):
                return "Web Attack Brute Force"
            if overlaps(flow, 13 * 3600 + 15 * 60, 13 * 3600 + 35 * 60):
                return "Web Attack XSS"
            if overlaps(flow, 13 * 3600 + 40 * 60, 13 * 3600 + 42 * 60):
                return "Web Attack SQL Injection"
        if pair == {"172.16.0.1", "192.168.10.8"} and (
            overlaps(flow, 17 * 3600 + 19 * 60, 17 * 3600 + 21 * 60)
            or overlaps(flow, 17 * 3600 + 33 * 60, 17 * 3600 + 35 * 60)
            or overlaps(flow, 18 * 3600 + 4 * 60, 18 * 3600 + 45 * 60)
        ):
            return "Infiltration"
        if pair == {"172.16.0.1", "192.168.10.25"} and overlaps(flow, 17 * 3600 + 53 * 60, 18 * 3600):
            return "Infiltration"
        if "192.168.10.8" in pair and overlaps(flow, 18 * 3600 + 4 * 60, 18 * 3600 + 45 * 60):
            return "Infiltration"
    if day == "Friday":
        bot_victims = {"192.168.10.15", "192.168.10.9", "192.168.10.14", "192.168.10.5", "192.168.10.8"}
        if (
            "172.16.0.1" in pair
            and bool(pair & bot_victims)
            and overlaps(flow, 13 * 3600 + 2 * 60, 14 * 3600 + 2 * 60)
        ):
            return "Bot"
        if attacker_to_web and overlaps(flow, 16 * 3600 + 55 * 60, 18 * 3600 + 29 * 60):
            return "PortScan"
        if attacker_to_web and overlaps(flow, 18 * 3600 + 56 * 60, 19 * 3600 + 16 * 60):
            return "DDoS"
    return "BENIGN"


def keep_benign(day: str, flow: Flow, sample_rate: float) -> bool:
    identity = (
        day.encode()
        + flow.source_ip
        + flow.destination_ip
        + struct.pack("!HHBd", flow.source_port, flow.destination_port, flow.protocol, flow.first_seen)
    )
    digest = hashlib.blake2b(identity, digest_size=8).digest()
    value = int.from_bytes(digest, "big") / ((1 << 64) - 1)
    return value < sample_rate


def extract_day(
    *,
    day: str,
    source: Path,
    writer: csv.DictWriter,
    benign_sample_rate: float,
) -> dict[str, object]:
    intervals_utc = ANALYSIS_WINDOWS_UTC[day]
    reader = PcapNgReader(source, intervals_utc=intervals_utc)
    active: dict[tuple[tuple[bytes, int], tuple[bytes, int], int], Flow] = {}
    label_counts: Counter[str] = Counter()
    all_label_counts: Counter[str] = Counter()
    flow_count = 0
    selected_count = 0
    parse_started = time.perf_counter()
    first_timestamp = 0.0
    last_timestamp = 0.0

    def finish(flow: Flow) -> None:
        nonlocal flow_count, selected_count
        flow_count += 1
        label = classify_flow(day, flow)
        all_label_counts[label] += 1
        if label == "BENIGN" and not keep_benign(day, flow, benign_sample_rate):
            return
        writer.writerow(flow.row(day, label))
        label_counts[label] += 1
        selected_count += 1

    for packet in reader.packets():
        if not first_timestamp:
            first_timestamp = packet.timestamp
        last_timestamp = packet.timestamp
        key = flow_key(packet)
        flow = active.get(key)
        if flow is None:
            active[key] = Flow(packet)
        elif flow.should_rollover(packet):
            finish(flow)
            active[key] = Flow(packet)
        else:
            flow.add(packet)
        if reader.packet_count % SWEEP_PACKET_INTERVAL == 0:
            expired = [
                key
                for key, candidate in active.items()
                if packet.timestamp - candidate.last_seen > FLOW_IDLE_TIMEOUT_SECONDS
                or packet.timestamp - candidate.first_seen > FLOW_ACTIVE_TIMEOUT_SECONDS
            ]
            for expired_key in expired:
                finish(active.pop(expired_key))
            elapsed = max(time.perf_counter() - parse_started, 0.001)
            print(
                f"[{day}] packets={reader.packet_count:,} "
                f"read={reader.bytes_read / 1_000_000_000:.2f}GB "
                f"flows={flow_count:,} selected={selected_count:,} "
                f"active={len(active):,} rate={reader.packet_count / elapsed:,.0f} pkt/s",
                flush=True,
            )
    for flow in active.values():
        finish(flow)
    elapsed = time.perf_counter() - parse_started
    return {
        "day": day,
        "source": str(source),
        "sourceSizeBytes": source.stat().st_size,
        "sourceSha256": reader.sha256.hexdigest(),
        "packetBlocksScanned": reader.packet_blocks_seen,
        "packetsParsedInSelectedWindows": reader.packet_count,
        "flowsExtracted": flow_count,
        "flowsSelected": selected_count,
        "selectedLabelDistribution": dict(sorted(label_counts.items())),
        "fullLabelDistributionBeforeBenignSampling": dict(sorted(all_label_counts.items())),
        "analysisWindowsUtc": intervals_utc,
        "firstPacketUtc": datetime.fromtimestamp(first_timestamp, tz=UTC).isoformat() if first_timestamp else None,
        "lastPacketUtc": datetime.fromtimestamp(last_timestamp, tz=UTC).isoformat() if last_timestamp else None,
        "elapsedSeconds": round(elapsed, 3),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract a reproducible CICIDS2017 research flow table directly from the official PCAPNG files."
    )
    parser.add_argument("--input-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--benign-sample-rate", type=float, default=0.08)
    parser.add_argument("--days", nargs="+", choices=tuple(DAY_FILES), default=list(DAY_FILES))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not 0 < args.benign_sample_rate <= 1:
        raise ValueError("--benign-sample-rate must be in the interval (0, 1]")
    sources = {day: (args.input_root / DAY_FILES[day]).resolve() for day in args.days}
    missing = [str(path) for path in sources.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"Missing CICIDS2017 PCAP files: {', '.join(missing)}")
    output = args.output.resolve()
    metadata_path = (
        args.metadata.resolve()
        if args.metadata
        else output.with_name(output.name.removesuffix(".csv.gz") + ".metadata.json")
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".partial")
    started_at = datetime.now(tz=UTC)
    summaries: list[dict[str, object]] = []
    with gzip.open(temporary, "wt", encoding="utf-8", newline="", compresslevel=5) as handle:
        writer = csv.DictWriter(handle, fieldnames=FEATURE_COLUMNS)
        writer.writeheader()
        for day, source in sources.items():
            print(f"[start] {day}: {source}", flush=True)
            summary = extract_day(
                day=day,
                source=source,
                writer=writer,
                benign_sample_rate=args.benign_sample_rate,
            )
            summaries.append(summary)
            print(
                f"[done] {day}: scanned={summary['packetBlocksScanned']:,} "
                f"selected_packets={summary['packetsParsedInSelectedWindows']:,} "
                f"flows={summary['flowsExtracted']:,} selected={summary['flowsSelected']:,}",
                flush=True,
            )
    temporary.replace(output)
    output_sha256 = hashlib.sha256()
    with output.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            output_sha256.update(chunk)
    combined_labels: Counter[str] = Counter()
    total_packet_blocks = 0
    total_selected_packets = 0
    total_flows = 0
    total_selected = 0
    for summary in summaries:
        combined_labels.update(summary["selectedLabelDistribution"])
        total_packet_blocks += int(summary["packetBlocksScanned"])
        total_selected_packets += int(summary["packetsParsedInSelectedWindows"])
        total_flows += int(summary["flowsExtracted"])
        total_selected += int(summary["flowsSelected"])
    metadata = {
        "extractorVersion": EXTRACTOR_VERSION,
        "createdAt": datetime.now(tz=UTC).isoformat(),
        "startedAt": started_at.isoformat(),
        "officialDatasetPage": OFFICIAL_DATASET_PAGE,
        "sourceFormat": "CICIDS2017 original PCAPNG",
        "labelingBasis": "Official UNB attack schedule plus documented attacker/victim endpoints and service ports",
        "timezoneNormalization": "Official ADT schedule converted to UTC (+3 hours) before interval matching",
        "flowPolicy": {
            "bidirectionalFiveTuple": True,
            "idleTimeoutSeconds": FLOW_IDLE_TIMEOUT_SECONDS,
            "activeTimeoutSeconds": FLOW_ACTIVE_TIMEOUT_SECONDS,
            "ipv4Only": True,
            "linkType": "Ethernet",
        },
        "sampling": {
            "attackFlows": "all matched flows",
            "benignMethod": "deterministic BLAKE2b threshold sample",
            "benignSampleRate": args.benign_sample_rate,
        },
        "output": str(output),
        "outputSizeBytes": output.stat().st_size,
        "outputSha256": output_sha256.hexdigest(),
        "featureCount": len(FEATURE_COLUMNS) - 1,
        "totalPacketBlocksScanned": total_packet_blocks,
        "totalPacketsParsedInSelectedWindows": total_selected_packets,
        "totalFlowsExtracted": total_flows,
        "totalFlowsSelected": total_selected,
        "selectedLabelDistribution": dict(sorted(combined_labels.items())),
        "days": summaries,
        "limitations": [
            "This is an EvoNIDS research flow table, not a byte-for-byte reproduction of CICFlowMeter output.",
            "Only Ethernet IPv4 packets are included; non-initial fragments have zero transport ports.",
            "Labels are schedule-and-endpoint derived and should be cross-checked against official labeled CSVs before publication.",
            "Benign traffic is deterministically sampled to keep local CPU experiments tractable.",
        ],
    }
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        f"[complete] output={output} selected={total_selected:,} "
        f"labels={dict(sorted(combined_labels.items()))}",
        flush=True,
    )
    print(f"[complete] metadata={metadata_path}", flush=True)


if __name__ == "__main__":
    main()
