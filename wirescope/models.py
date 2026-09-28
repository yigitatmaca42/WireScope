"""Data models shared across WireScope.

This module holds plain, serialization-friendly dataclasses. Nothing here
imports Scapy or touches packets directly - the packet engine and protocol
parsers translate raw packets into these structures, and everything
downstream (detection, reporting, exporters) only ever sees these models.
That boundary is what keeps WireScope from being hard-locked to one packet
engine: swap the parsing layer and the rest of the pipeline is unaffected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Forensic finding severity. WireScope is a triage aid, not an IDS -
    these are hints for where to look first, not verdicts."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class ProtocolCounts:
    """Packet counts broken down by network/transport protocol."""

    ipv4: int = 0
    ipv6: int = 0
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    arp: int = 0
    other: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "tcp": self.tcp,
            "udp": self.udp,
            "icmp": self.icmp,
            "arp": self.arp,
            "other": self.other,
        }


@dataclass
class CaptureInfo:
    """High-level metadata about the capture file itself."""

    file_name: str
    file_size_bytes: int
    capture_start: float | None
    capture_end: float | None
    total_packets: int = 0
    total_bytes: int = 0
    protocol_counts: ProtocolCounts = field(default_factory=ProtocolCounts)

    @property
    def duration_seconds(self) -> float:
        if self.capture_start is None or self.capture_end is None:
            return 0.0
        return max(0.0, self.capture_end - self.capture_start)

    @property
    def average_packet_size(self) -> float:
        if self.total_packets == 0:
            return 0.0
        return self.total_bytes / self.total_packets

    @property
    def packets_per_second(self) -> float:
        if self.duration_seconds <= 0:
            return float(self.total_packets)
        return self.total_packets / self.duration_seconds

    @property
    def bytes_per_second(self) -> float:
        if self.duration_seconds <= 0:
            return float(self.total_bytes)
        return self.total_bytes / self.duration_seconds

    def as_dict(self) -> dict[str, Any]:
        return {
            "file_name": self.file_name,
            "file_size_bytes": self.file_size_bytes,
            "capture_start": self.capture_start,
            "capture_end": self.capture_end,
            "duration_seconds": round(self.duration_seconds, 3),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "average_packet_size": round(self.average_packet_size, 2),
            "packets_per_second": round(self.packets_per_second, 2),
            "bytes_per_second": round(self.bytes_per_second, 2),
            "protocol_counts": self.protocol_counts.as_dict(),
        }


@dataclass
class HostStats:
    """Aggregated activity for a single IP address."""

    ip: str
    packet_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    peers: set[str] = field(default_factory=set)
    ports_used: set[int] = field(default_factory=set)

    @property
    def total_bytes(self) -> int:
        return self.bytes_sent + self.bytes_received

    def as_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "packet_count": self.packet_count,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "total_bytes": self.total_bytes,
            "unique_peers": len(self.peers),
            "ports_used": sorted(self.ports_used),
        }


@dataclass
class PortStats:
    """Aggregated activity for a single (port, transport protocol) pair."""

    port: int
    protocol: str  # "TCP" or "UDP"
    packet_count: int = 0
    service_name: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "service_name": self.service_name,
        }


@dataclass
class Conversation:
    """A normalized 5-tuple flow. The (src, dst) side is picked once, on
    first sight, and packets seen in the reverse direction are folded into
    the same conversation rather than creating a mirrored duplicate."""

    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    protocol: str
    packet_count: int = 0
    byte_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

    @property
    def duration_seconds(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def key(self) -> tuple[str, int | None, str, int | None, str]:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol)

    def as_dict(self) -> dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": round(self.duration_seconds, 3),
        }


@dataclass
class DnsRecord:
    """A single DNS query or query+response pair, keyed by transaction id."""

    query_name: str
    query_type: str
    source: str
    destination: str
    timestamp: float
    is_response: bool = False
    response_code: str | None = None
    answers: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "query_name": self.query_name,
            "query_type": self.query_type,
            "source": self.source,
            "destination": self.destination,
            "timestamp": self.timestamp,
            "is_response": self.is_response,
            "response_code": self.response_code,
            "answers": self.answers,
        }


@dataclass
class HttpTransaction:
    """A plaintext HTTP request or response observed on the wire."""

    direction: str  # "request" or "response"
    src_ip: str
    dst_ip: str
    timestamp: float
    method: str | None = None
    host: str | None = None
    path: str | None = None
    user_agent: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    server: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "direction": self.direction,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "timestamp": self.timestamp,
            "method": self.method,
            "host": self.host,
            "path": self.path,
            "user_agent": self.user_agent,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "server": self.server,
        }


@dataclass
class TlsInfo:
    """Metadata extracted from a TLS ClientHello. WireScope never attempts
    to decrypt TLS traffic; this is handshake metadata only."""

    src_ip: str
    dst_ip: str
    timestamp: float
    sni: str | None = None
    record_version: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "timestamp": self.timestamp,
            "sni": self.sni,
            "record_version": self.record_version,
        }


@dataclass
class ArpEntry:
    """Everything observed for a single IP's ARP behaviour."""

    ip: str
    mac_addresses: set[str] = field(default_factory=set)
    requests: int = 0
    replies: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "mac_addresses": sorted(self.mac_addresses),
            "requests": self.requests,
            "replies": self.replies,
        }


@dataclass
class IcmpStats:
    echo_request: int = 0
    echo_reply: int = 0
    type_code_counts: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "echo_request": self.echo_request,
            "echo_reply": self.echo_reply,
            "type_code_counts": dict(self.type_code_counts),
        }


@dataclass
class TcpFlagStats:
    syn: int = 0
    ack: int = 0
    fin: int = 0
    rst: int = 0
    psh: int = 0
    syn_only: int = 0  # SYN without ACK - i.e. connection attempts

    def as_dict(self) -> dict[str, Any]:
        return {
            "syn": self.syn,
            "ack": self.ack,
            "fin": self.fin,
            "rst": self.rst,
            "psh": self.psh,
            "syn_only": self.syn_only,
        }


@dataclass
class Finding:
    """An interpretation produced by the detection layer. Findings are
    hypotheses for a human analyst to review, never verdicts - see
    detection/heuristics.py and SECURITY.md/README's Detection Philosophy
    section for why the wording is deliberately hedged."""

    title: str
    severity: Severity
    description: str
    evidence: str
    confidence: str  # "low" | "medium" | "high"
    host: str | None = None
    timestamp: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "host": self.host,
            "timestamp": self.timestamp,
        }


@dataclass
class CollectionLimits:
    """Bounded-collection bookkeeping so unbounded DNS/HTTP/flow lists can't
    exhaust memory on a huge or malicious capture. When a cap is hit we keep
    counting totals but stop retaining new detailed records, and we say so
    in the report instead of silently dropping data."""

    max_dns_records: int = 20_000
    max_http_transactions: int = 20_000
    max_tls_records: int = 20_000
    max_conversations: int = 100_000

    dns_truncated: bool = False
    http_truncated: bool = False
    tls_truncated: bool = False
    conversations_truncated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "dns_truncated": self.dns_truncated,
            "http_truncated": self.http_truncated,
            "tls_truncated": self.tls_truncated,
            "conversations_truncated": self.conversations_truncated,
        }


@dataclass
class AnalysisResult:
    """The complete set of facts produced by the analyzer for one capture.
    This is the single object that reporting, exporters, and the detection
    engine all consume."""

    capture: CaptureInfo
    hosts: dict[str, HostStats] = field(default_factory=dict)
    ports_src: dict[tuple[int, str], PortStats] = field(default_factory=dict)
    ports_dst: dict[tuple[int, str], PortStats] = field(default_factory=dict)
    conversations: dict[tuple, Conversation] = field(default_factory=dict)
    dns_records: list[DnsRecord] = field(default_factory=list)
    http_transactions: list[HttpTransaction] = field(default_factory=list)
    tls_records: list[TlsInfo] = field(default_factory=list)
    arp_entries: dict[str, ArpEntry] = field(default_factory=dict)
    icmp_stats: IcmpStats = field(default_factory=IcmpStats)
    tcp_flag_stats: TcpFlagStats = field(default_factory=TcpFlagStats)
    limits: CollectionLimits = field(default_factory=CollectionLimits)
    findings: list[Finding] = field(default_factory=list)
    high_entropy_packet_count: int = 0
    high_entropy_hosts: set[str] = field(default_factory=set)
    # Per-second timeline: {int(timestamp): [packet_count, byte_count]}.
    # Bounded by the capture's duration in seconds, not by packet count.
    timeline: dict[int, list[int]] = field(default_factory=dict)

    def top_hosts(self, n: int = 10) -> list[HostStats]:
        return sorted(self.hosts.values(), key=lambda h: h.packet_count, reverse=True)[:n]

    def top_ports_src(self, n: int = 10) -> list[PortStats]:
        return sorted(self.ports_src.values(), key=lambda p: p.packet_count, reverse=True)[:n]

    def top_ports_dst(self, n: int = 10) -> list[PortStats]:
        return sorted(self.ports_dst.values(), key=lambda p: p.packet_count, reverse=True)[:n]

    def top_conversations(self, n: int = 10) -> list[Conversation]:
        return sorted(
            self.conversations.values(), key=lambda c: c.byte_count, reverse=True
        )[:n]
