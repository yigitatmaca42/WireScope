"""The streaming packet engine.

`Analyzer.run()` opens a capture with Scapy's PcapReader (which transparently
handles classic pcap and pcapng via magic-byte detection - see
https://github.com/secdev/scapy) and processes one packet at a time,
updating running aggregates. Packets themselves are never retained; only
small per-packet summaries flow into the protocol parsers, which is what
keeps memory bounded on multi-gigabyte captures.

This module produces FACTS only (AnalysisResult). Turning those facts into
suspicions is the detection package's job - see detection/heuristics.py.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

# Importing these registers Scapy's linktype -> layer bindings (e.g. DLT_EN10MB
# -> Ether) in `conf.l2types`. That registration MUST happen before a
# PcapReader is constructed, since PcapReader resolves its dissection class
# once, at construction time - importing them lazily inside the per-packet
# loop (as an earlier version of this module did) left every packet
# undissected ("Raw") whenever this was the first code in the process to
# touch Scapy.
from scapy.error import Scapy_Exception  # noqa: E402
from scapy.layers.dns import DNS  # noqa: E402, F401
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402
from scapy.layers.l2 import ARP  # noqa: E402
from scapy.utils import PcapReader  # noqa: E402

from wirescope.exceptions import (
    CaptureNotFoundError,
    CapturePermissionError,
    CorruptCaptureError,
    EmptyCaptureError,
    UnsupportedCaptureError,
)
from wirescope.filters import PacketFilter
from wirescope.models import (
    AnalysisResult,
    ArpEntry,
    CaptureInfo,
    Conversation,
    HostStats,
    PortStats,
)
from wirescope.protocols.arp import parse_arp
from wirescope.protocols.dns import parse_dns
from wirescope.protocols.http import parse_http
from wirescope.protocols.icmp import ECHO_REPLY, ECHO_REQUEST, parse_icmp
from wirescope.protocols.tcp import parse_tcp_flags
from wirescope.protocols.tls import parse_tls_client_hello
from wirescope.utils.entropy import is_high_entropy
from wirescope.utils.ports import lookup_service

_SUPPORTED_SUFFIXES = {".pcap", ".pcapng", ".cap"}

ProgressCallback = Callable[[int], None]


class Analyzer:
    """Streams a capture file and builds an AnalysisResult."""

    def __init__(self, path: str | Path, packet_filter: PacketFilter | None = None) -> None:
        self.path = Path(path)
        self.filter = packet_filter or PacketFilter()

    def _validate_file(self) -> None:
        if not self.path.exists():
            raise CaptureNotFoundError(f"Capture file not found: {self.path}")
        if self.path.suffix.lower() not in _SUPPORTED_SUFFIXES:
            raise UnsupportedCaptureError(
                f"Unsupported file extension '{self.path.suffix}'. "
                f"Expected one of: {', '.join(sorted(_SUPPORTED_SUFFIXES))}"
            )
        if not os.access(self.path, os.R_OK):
            raise CapturePermissionError(f"Permission denied reading: {self.path}")
        if self.path.stat().st_size == 0:
            raise EmptyCaptureError(f"Capture file is empty: {self.path}")

    def run(self, progress_callback: ProgressCallback | None = None) -> AnalysisResult:
        self._validate_file()

        result = AnalysisResult(
            capture=CaptureInfo(
                file_name=self.path.name,
                file_size_bytes=self.path.stat().st_size,
                capture_start=None,
                capture_end=None,
            )
        )

        packet_count = 0
        try:
            with PcapReader(str(self.path)) as reader:
                for pkt in reader:
                    packet_count += 1
                    self._process_packet(pkt, result)
                    if progress_callback is not None and packet_count % 500 == 0:
                        progress_callback(packet_count)
        except Scapy_Exception as exc:
            raise CorruptCaptureError(f"Could not parse capture: {exc}") from exc
        except (OSError, EOFError) as exc:
            raise CorruptCaptureError(f"Error reading capture: {exc}") from exc

        if progress_callback is not None:
            progress_callback(packet_count)

        if packet_count == 0:
            raise EmptyCaptureError(f"Capture file contains no packets: {self.path}")

        return result

    # -- per-packet processing -------------------------------------------------

    def _process_packet(self, pkt, result: AnalysisResult) -> None:  # noqa: ANN001
        timestamp = float(pkt.time)
        length = int(getattr(pkt, "wirelen", None) or len(bytes(pkt)))

        has_ip4 = pkt.haslayer(IP)
        has_ip6 = (not has_ip4) and pkt.haslayer(IPv6)
        has_tcp = pkt.haslayer(TCP)
        has_udp = pkt.haslayer(UDP)
        has_icmp = pkt.haslayer(ICMP)
        has_arp = pkt.haslayer(ARP)

        protocols_present: set[str] = set()
        if has_tcp:
            protocols_present.add("tcp")
        if has_udp:
            protocols_present.add("udp")
        if has_icmp:
            protocols_present.add("icmp")
        if has_arp:
            protocols_present.add("arp")

        src_ip = dst_ip = None
        if has_ip4:
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        elif has_ip6:
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst

        sport = dport = None
        if has_tcp:
            sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
        elif has_udp:
            sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)

        # DNS/HTTP/TLS are protocol-level tags used for --protocol filtering
        # even before we know whether parsing will succeed.
        if has_udp and (sport == 53 or dport == 53):
            protocols_present.add("dns")
        if has_tcp and (sport in (80, 8080, 8000) or dport in (80, 8080, 8000)):
            protocols_present.add("http")
        if has_tcp and (sport == 443 or dport == 443):
            protocols_present.add("tls")

        if not self.filter.is_empty and not self.filter.matches(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=sport,
            dst_port=dport,
            protocols_present=protocols_present,
        ):
            return

        # Everything below only runs for packets that passed the filter (or
        # when no filter is set), so a filtered run's capture-level summary
        # reflects the filtered packet set too, not the whole file.
        capture = result.capture
        capture.total_packets += 1
        capture.total_bytes += length

        bucket = result.timeline.setdefault(int(timestamp), [0, 0])
        bucket[0] += 1
        bucket[1] += length
        if capture.capture_start is None or timestamp < capture.capture_start:
            capture.capture_start = timestamp
        if capture.capture_end is None or timestamp > capture.capture_end:
            capture.capture_end = timestamp

        if has_ip4:
            capture.protocol_counts.ipv4 += 1
        elif has_ip6:
            capture.protocol_counts.ipv6 += 1
        if has_tcp:
            capture.protocol_counts.tcp += 1
        elif has_udp:
            capture.protocol_counts.udp += 1
        elif has_icmp:
            capture.protocol_counts.icmp += 1
        elif has_arp:
            capture.protocol_counts.arp += 1
        elif not (has_ip4 or has_ip6):
            capture.protocol_counts.other += 1

        if src_ip and dst_ip:
            self._update_hosts(result, src_ip, dst_ip, length, sport, dport)
            if sport is not None:
                self._update_ports(result.ports_src, sport, "TCP" if has_tcp else "UDP")
            if dport is not None:
                self._update_ports(result.ports_dst, dport, "TCP" if has_tcp else "UDP")
            if has_tcp or has_udp:
                self._update_conversation(
                    result, src_ip, sport, dst_ip, dport, "TCP" if has_tcp else "UDP", length, timestamp
                )

        if has_udp and (sport == 53 or dport == 53):
            self._try_parse_dns(pkt, timestamp, src_ip, dst_ip, result)

        if has_tcp:
            payload = bytes(pkt[TCP].payload)
            if payload:
                if sport in (80, 8080, 8000) or dport in (80, 8080, 8000):
                    self._try_parse_http(payload, src_ip, dst_ip, timestamp, result)
                if sport == 443 or dport == 443:
                    self._try_parse_tls(payload, src_ip, dst_ip, timestamp, result)
                elif sport != 22 and dport != 22:
                    # Skip 443 (TLS is expected to be high-entropy) and 22
                    # (SSH is expected to be encrypted) - only flag entropy
                    # on ports where plaintext would normally be assumed.
                    self._check_entropy(payload, src_ip, dst_ip, result)
            flags = parse_tcp_flags(pkt)
            if flags is not None:
                tfs = result.tcp_flag_stats
                tfs.syn += flags.syn
                tfs.ack += flags.ack
                tfs.fin += flags.fin
                tfs.rst += flags.rst
                tfs.psh += flags.psh
                if flags.syn and not flags.ack:
                    tfs.syn_only += 1

        if has_icmp:
            icmp_event = parse_icmp(pkt)
            if icmp_event is not None:
                stats = result.icmp_stats
                if icmp_event.icmp_type == ECHO_REQUEST:
                    stats.echo_request += 1
                elif icmp_event.icmp_type == ECHO_REPLY:
                    stats.echo_reply += 1
                key = f"type={icmp_event.icmp_type},code={icmp_event.icmp_code}"
                stats.type_code_counts[key] = stats.type_code_counts.get(key, 0) + 1

        if has_arp:
            arp_event = parse_arp(pkt)
            if arp_event is not None:
                entry = result.arp_entries.setdefault(arp_event.sender_ip, ArpEntry(ip=arp_event.sender_ip))
                entry.mac_addresses.add(arp_event.sender_mac)
                if arp_event.is_request:
                    entry.requests += 1
                else:
                    entry.replies += 1

    @staticmethod
    def _update_hosts(
        result: AnalysisResult,
        src_ip: str,
        dst_ip: str,
        length: int,
        sport: int | None,
        dport: int | None,
    ) -> None:
        src = result.hosts.setdefault(src_ip, HostStats(ip=src_ip))
        dst = result.hosts.setdefault(dst_ip, HostStats(ip=dst_ip))
        src.packet_count += 1
        dst.packet_count += 1
        src.bytes_sent += length
        dst.bytes_received += length
        src.peers.add(dst_ip)
        dst.peers.add(src_ip)
        if sport is not None:
            src.ports_used.add(sport)
        if dport is not None:
            dst.ports_used.add(dport)

    @staticmethod
    def _update_ports(bucket: dict[tuple[int, str], PortStats], port: int, protocol: str) -> None:
        key = (port, protocol)
        stats = bucket.setdefault(
            key, PortStats(port=port, protocol=protocol, service_name=lookup_service(port, protocol))
        )
        stats.packet_count += 1

    @staticmethod
    def _update_conversation(
        result: AnalysisResult,
        src_ip: str,
        sport: int | None,
        dst_ip: str,
        dport: int | None,
        protocol: str,
        length: int,
        timestamp: float,
    ) -> None:
        # Normalize direction so A->B and B->A packets land in one flow:
        # the lexicographically smaller (ip, port) pair is always "src".
        forward = (src_ip, sport or 0, dst_ip, dport or 0)
        reverse = (dst_ip, dport or 0, src_ip, sport or 0)
        key = (
            (src_ip, sport, dst_ip, dport, protocol)
            if forward <= reverse
            else (dst_ip, dport, src_ip, sport, protocol)
        )

        if key not in result.conversations and len(result.conversations) >= result.limits.max_conversations:
            result.limits.conversations_truncated = True
            return

        convo = result.conversations.setdefault(
            key,
            Conversation(
                src_ip=key[0],
                src_port=key[1],
                dst_ip=key[2],
                dst_port=key[3],
                protocol=protocol,
                first_seen=timestamp,
                last_seen=timestamp,
            ),
        )
        convo.packet_count += 1
        convo.byte_count += length
        convo.first_seen = min(convo.first_seen, timestamp)
        convo.last_seen = max(convo.last_seen, timestamp)

    @staticmethod
    def _try_parse_dns(pkt, timestamp: float, src_ip: str | None, dst_ip: str | None, result: AnalysisResult) -> None:  # noqa: ANN001
        if not pkt.haslayer(DNS) or src_ip is None or dst_ip is None:
            return
        record = parse_dns(pkt, timestamp, src_ip, dst_ip)
        if record is None:
            return
        if len(result.dns_records) >= result.limits.max_dns_records:
            result.limits.dns_truncated = True
            return
        result.dns_records.append(record)

    @staticmethod
    def _try_parse_http(payload: bytes, src_ip: str | None, dst_ip: str | None, timestamp: float, result: AnalysisResult) -> None:
        if src_ip is None or dst_ip is None:
            return
        record = parse_http(payload, src_ip, dst_ip, timestamp)
        if record is None:
            return
        if len(result.http_transactions) >= result.limits.max_http_transactions:
            result.limits.http_truncated = True
            return
        result.http_transactions.append(record)

    @staticmethod
    def _check_entropy(payload: bytes, src_ip: str | None, dst_ip: str | None, result: AnalysisResult) -> None:
        if not is_high_entropy(payload):
            return
        result.high_entropy_packet_count += 1
        if src_ip and len(result.high_entropy_hosts) < 20:
            result.high_entropy_hosts.add(src_ip)

    @staticmethod
    def _try_parse_tls(payload: bytes, src_ip: str | None, dst_ip: str | None, timestamp: float, result: AnalysisResult) -> None:
        if src_ip is None or dst_ip is None:
            return
        record = parse_tls_client_hello(payload, src_ip, dst_ip, timestamp)
        if record is None:
            return
        if len(result.tls_records) >= result.limits.max_tls_records:
            result.limits.tls_truncated = True
            return
        result.tls_records.append(record)
