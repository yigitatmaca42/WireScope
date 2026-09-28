"""Forensic heuristics: turning the analyzer's FACTS into hedged, reviewable
INTERPRETATIONS.

WireScope is a triage aid, not an IDS. Every finding here is phrased as a
possibility for a human analyst to check, never as a verdict - see the
project's README "Detection Philosophy" section and SECURITY.md. None of
these thresholds are tuned against real-world traffic baselines; they are
reasonable starting points and are expected to produce false positives on
some legitimate traffic (e.g. NAT gateways, DHCP churn, CDNs).
"""

from __future__ import annotations

from wirescope.models import AnalysisResult, Finding, Severity
from wirescope.utils.ports import PLAINTEXT_PORTS

# Tunable thresholds - intentionally simple constants, not learned/adaptive.
SYN_ONLY_MIN_COUNT = 20
SYN_TO_ACK_RATIO_THRESHOLD = 5.0
MANY_PORTS_THRESHOLD = 15
MANY_PEERS_THRESHOLD = 20
DNS_BURST_THRESHOLD = 100
LONG_DNS_LABEL_LENGTH = 50
LARGE_TRANSFER_BYTES = 50 * 1024 * 1024  # 50 MB
UNCOMMON_PORT_PACKET_THRESHOLD = 50
HIGH_ENTROPY_PACKET_THRESHOLD = 20

_SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}


def _plaintext_protocol_findings(result: AnalysisResult) -> list[Finding]:
    findings: list[Finding] = []

    if result.http_transactions:
        requests = [t for t in result.http_transactions if t.direction == "request"]
        findings.append(
            Finding(
                title="Plaintext HTTP traffic observed",
                severity=Severity.LOW,
                description=(
                    "HTTP requests were observed in plaintext. Any credentials, "
                    "session cookies, or sensitive data in these requests would be "
                    "visible to anyone able to capture this traffic."
                ),
                evidence=f"{len(requests)} plaintext HTTP request(s) observed.",
                confidence="high",
            )
        )

    for port, name in PLAINTEXT_PORTS.items():
        if name == "HTTP":
            continue  # covered above with more detail
        stats = result.ports_dst.get((port, "TCP"))
        if stats and stats.packet_count > 0:
            findings.append(
                Finding(
                    title=f"Plaintext {name} traffic observed",
                    severity=Severity.MEDIUM if name == "Telnet" else Severity.LOW,
                    description=(
                        f"Traffic to port {port} ({name}) was observed. {name} does not "
                        "encrypt its traffic; credentials sent over it would be exposed."
                    ),
                    evidence=f"{stats.packet_count} packet(s) to destination port {port}.",
                    confidence="medium",
                )
            )

    return findings


def _uncommon_port_findings(result: AnalysisResult) -> list[Finding]:
    findings: list[Finding] = []
    for stats in result.ports_dst.values():
        if stats.service_name is not None:
            continue
        if stats.packet_count < UNCOMMON_PORT_PACKET_THRESHOLD:
            continue
        findings.append(
            Finding(
                title="Traffic to an uncommon port",
                severity=Severity.INFO,
                description=(
                    "A meaningful volume of traffic was observed on a port with no "
                    "well-known service mapping. This is common for custom "
                    "applications and is not inherently suspicious."
                ),
                evidence=f"Port {stats.port}/{stats.protocol}: {stats.packet_count} packets.",
                confidence="low",
            )
        )
    return findings


def _scanning_behavior_findings(result: AnalysisResult) -> list[Finding]:
    findings: list[Finding] = []

    tfs = result.tcp_flag_stats
    if tfs.syn_only >= SYN_ONLY_MIN_COUNT:
        ratio = tfs.syn_only / tfs.ack if tfs.ack else float(tfs.syn_only)
        if ratio >= SYN_TO_ACK_RATIO_THRESHOLD:
            findings.append(
                Finding(
                    title="High SYN-to-ACK ratio",
                    severity=Severity.MEDIUM,
                    description=(
                        "A high proportion of TCP packets were SYN packets with no "
                        "matching ACK activity. Potential scanning behavior - review "
                        "recommended. This can also occur with aggressive connection "
                        "retries or an asymmetric capture vantage point."
                    ),
                    evidence=f"{tfs.syn_only} SYN-only packets vs {tfs.ack} ACK packets (ratio {ratio:.1f}).",
                    confidence="medium",
                )
            )

    dest_ports_by_src: dict[str, set[int]] = {}
    peers_by_src: dict[str, set[str]] = {}
    for convo in result.conversations.values():
        if convo.dst_port is not None:
            dest_ports_by_src.setdefault(convo.src_ip, set()).add(convo.dst_port)
        peers_by_src.setdefault(convo.src_ip, set()).add(convo.dst_ip)

    for host, ports in dest_ports_by_src.items():
        if len(ports) >= MANY_PORTS_THRESHOLD:
            findings.append(
                Finding(
                    title="Host contacted many distinct destination ports",
                    severity=Severity.MEDIUM,
                    description=(
                        "One host initiated conversations to an unusually large number "
                        "of distinct destination ports. Potential scanning behavior - "
                        "review recommended."
                    ),
                    evidence=f"{host} contacted {len(ports)} distinct destination ports.",
                    confidence="medium",
                    host=host,
                )
            )

    for host, peers in peers_by_src.items():
        if len(peers) >= MANY_PEERS_THRESHOLD:
            findings.append(
                Finding(
                    title="Host communicated with many unique peers",
                    severity=Severity.LOW,
                    description=(
                        "One host initiated conversations with an unusually large "
                        "number of distinct destination hosts. This can indicate "
                        "scanning, a busy server, or a proxy/gateway - review "
                        "recommended."
                    ),
                    evidence=f"{host} contacted {len(peers)} distinct peer hosts.",
                    confidence="low",
                    host=host,
                )
            )

    return findings


def _dns_findings(result: AnalysisResult) -> list[Finding]:
    findings: list[Finding] = []
    queries = [r for r in result.dns_records if not r.is_response]

    queries_by_source: dict[str, int] = {}
    for record in queries:
        queries_by_source[record.source] = queries_by_source.get(record.source, 0) + 1
    for host, count in queries_by_source.items():
        if count >= DNS_BURST_THRESHOLD:
            findings.append(
                Finding(
                    title="DNS query burst from a single host",
                    severity=Severity.LOW,
                    description=(
                        "One host issued an unusually large number of DNS queries. "
                        "This can be normal for a DNS resolver or busy client, or can "
                        "indicate malware beaconing / domain generation algorithm "
                        "activity - review recommended."
                    ),
                    evidence=f"{host} issued {count} DNS queries.",
                    confidence="low",
                    host=host,
                )
            )

    long_label_examples: list[str] = []
    for record in queries:
        labels = record.query_name.split(".")
        if any(len(label) >= LONG_DNS_LABEL_LENGTH for label in labels):
            long_label_examples.append(record.query_name)
    if long_label_examples:
        findings.append(
            Finding(
                title="Unusually long DNS label observed",
                severity=Severity.MEDIUM,
                description=(
                    "One or more DNS queries contained an unusually long label. "
                    "This is a weak, well-known signal for possible DNS tunneling, "
                    "but is also produced by some legitimate CDN/anti-spam/tracking "
                    "systems - unconfirmed, review recommended."
                ),
                evidence=f"Example: {long_label_examples[0]!r} ({len(long_label_examples)} total).",
                confidence="low",
            )
        )

    nxdomain_count = sum(1 for r in result.dns_records if r.is_response and r.response_code == "NXDOMAIN")
    if nxdomain_count:
        findings.append(
            Finding(
                title="NXDOMAIN responses observed",
                severity=Severity.INFO,
                description="One or more DNS queries resolved to NXDOMAIN (non-existent domain).",
                evidence=f"{nxdomain_count} NXDOMAIN response(s) observed.",
                confidence="high",
            )
        )

    return findings


def _large_transfer_findings(result: AnalysisResult) -> list[Finding]:
    findings: list[Finding] = []
    for convo in result.conversations.values():
        if convo.byte_count >= LARGE_TRANSFER_BYTES:
            findings.append(
                Finding(
                    title="Large data transfer observed",
                    severity=Severity.INFO,
                    description=(
                        "A single conversation transferred an unusually large amount "
                        "of data. This is often entirely legitimate (downloads, "
                        "backups, streaming) - noted for awareness."
                    ),
                    evidence=(
                        f"{convo.src_ip}:{convo.src_port} <-> {convo.dst_ip}:{convo.dst_port} "
                        f"({convo.protocol}): {convo.byte_count:,} bytes."
                    ),
                    confidence="high",
                )
            )
    return findings


def _arp_findings(result: AnalysisResult) -> list[Finding]:
    findings: list[Finding] = []
    for entry in result.arp_entries.values():
        if len(entry.mac_addresses) > 1:
            findings.append(
                Finding(
                    title="Possible ARP inconsistency",
                    severity=Severity.MEDIUM,
                    description=(
                        "One IP address was observed associated with more than one "
                        "MAC address. This can indicate ARP spoofing, but is also "
                        "produced by DHCP lease changes, NAT, VM migration, or "
                        "failover/HA setups - unconfirmed, review recommended."
                    ),
                    evidence=f"{entry.ip} seen with MAC addresses: {', '.join(sorted(entry.mac_addresses))}.",
                    confidence="low",
                    host=entry.ip,
                )
            )
    return findings


def _entropy_findings(result: AnalysisResult) -> list[Finding]:
    if result.high_entropy_packet_count < HIGH_ENTROPY_PACKET_THRESHOLD:
        return []
    return [
        Finding(
            title="High-entropy payload observed",
            severity=Severity.INFO,
            description=(
                "A number of packets outside of standard TLS/SSH ports carried "
                "payload with high byte-level entropy, consistent with encrypted, "
                "compressed, or otherwise obfuscated data. This is a weak signal "
                "on its own - review recommended, not a confirmed finding."
            ),
            evidence=(
                f"{result.high_entropy_packet_count} high-entropy packet(s) observed "
                f"across {len(result.high_entropy_hosts)} host(s)."
            ),
            confidence="low",
        )
    ]


def run_heuristics(result: AnalysisResult) -> list[Finding]:
    """Run every heuristic and return findings sorted by severity (most
    severe first), then by title for stable ordering."""
    findings: list[Finding] = []
    findings.extend(_plaintext_protocol_findings(result))
    findings.extend(_uncommon_port_findings(result))
    findings.extend(_scanning_behavior_findings(result))
    findings.extend(_dns_findings(result))
    findings.extend(_large_transfer_findings(result))
    findings.extend(_arp_findings(result))
    findings.extend(_entropy_findings(result))

    findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.title))
    return findings
