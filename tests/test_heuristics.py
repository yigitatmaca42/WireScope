from __future__ import annotations

from wirescope.detection.heuristics import run_heuristics
from wirescope.models import (
    AnalysisResult,
    ArpEntry,
    CaptureInfo,
    Conversation,
    DnsRecord,
    HttpTransaction,
    PortStats,
)


def _empty_result() -> AnalysisResult:
    return AnalysisResult(
        capture=CaptureInfo(file_name="x", file_size_bytes=0, capture_start=0.0, capture_end=1.0)
    )


def test_plaintext_http_finding():
    result = _empty_result()
    result.http_transactions.append(
        HttpTransaction(direction="request", src_ip="a", dst_ip="b", timestamp=1.0, method="GET")
    )
    findings = run_heuristics(result)
    assert any("Plaintext HTTP" in f.title for f in findings)


def test_plaintext_telnet_finding_from_port_stats():
    result = _empty_result()
    result.ports_dst[(23, "TCP")] = PortStats(port=23, protocol="TCP", packet_count=5, service_name="Telnet")
    findings = run_heuristics(result)
    telnet = [f for f in findings if "Telnet" in f.title]
    assert len(telnet) == 1
    assert telnet[0].severity.value == "MEDIUM"


def test_many_destination_ports_triggers_scanning_finding():
    result = _empty_result()
    for port in range(2000, 2020):  # 20 distinct ports >= threshold (15)
        key = ("scanner", None, "victim", port, "TCP")
        result.conversations[key] = Conversation(
            src_ip="scanner", src_port=None, dst_ip="victim", dst_port=port, protocol="TCP"
        )
    findings = run_heuristics(result)
    assert any("many distinct destination ports" in f.title for f in findings)


def test_many_peers_triggers_finding():
    result = _empty_result()
    for i in range(25):
        key = ("host", None, f"peer{i}", None, "TCP")
        result.conversations[key] = Conversation(
            src_ip="host", src_port=None, dst_ip=f"peer{i}", dst_port=None, protocol="TCP"
        )
    findings = run_heuristics(result)
    assert any("many unique peers" in f.title for f in findings)


def test_arp_inconsistency_finding():
    result = _empty_result()
    entry = ArpEntry(ip="10.0.0.1")
    entry.mac_addresses.update({"aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"})
    result.arp_entries["10.0.0.1"] = entry
    findings = run_heuristics(result)
    assert any("ARP inconsistency" in f.title for f in findings)


def test_no_arp_finding_when_single_mac():
    result = _empty_result()
    entry = ArpEntry(ip="10.0.0.1")
    entry.mac_addresses.add("aa:aa:aa:aa:aa:aa")
    result.arp_entries["10.0.0.1"] = entry
    findings = run_heuristics(result)
    assert not any("ARP inconsistency" in f.title for f in findings)


def test_long_dns_label_finding():
    result = _empty_result()
    long_label = "a" * 60
    result.dns_records.append(
        DnsRecord(query_name=f"{long_label}.example.com", query_type="A", source="a", destination="b", timestamp=1.0)
    )
    findings = run_heuristics(result)
    assert any("long DNS label" in f.title for f in findings)


def test_dns_burst_finding():
    result = _empty_result()
    for i in range(150):
        result.dns_records.append(
            DnsRecord(query_name=f"q{i}.example.com", query_type="A", source="10.0.0.5", destination="b", timestamp=float(i))
        )
    findings = run_heuristics(result)
    assert any("DNS query burst" in f.title for f in findings)


def test_large_transfer_finding():
    result = _empty_result()
    result.conversations[("a", 1, "b", 2, "TCP")] = Conversation(
        src_ip="a", src_port=1, dst_ip="b", dst_port=2, protocol="TCP", byte_count=100 * 1024 * 1024
    )
    findings = run_heuristics(result)
    assert any("Large data transfer" in f.title for f in findings)


def test_no_findings_on_boring_capture():
    result = _empty_result()
    findings = run_heuristics(result)
    assert findings == []


def test_findings_are_sorted_by_severity():
    result = _empty_result()
    entry = ArpEntry(ip="10.0.0.1")  # MEDIUM
    entry.mac_addresses.update({"aa", "bb"})
    result.arp_entries["10.0.0.1"] = entry
    result.dns_records.append(  # generates an INFO (NXDOMAIN) - not present here, skip
        DnsRecord(query_name="x.com", query_type="A", source="a", destination="b", timestamp=1.0)
    )
    result.conversations[("a", 1, "b", 2, "TCP")] = Conversation(  # INFO
        src_ip="a", src_port=1, dst_ip="b", dst_port=2, protocol="TCP", byte_count=100 * 1024 * 1024
    )
    findings = run_heuristics(result)
    severities = [f.severity.value for f in findings]
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    assert severities == sorted(severities, key=lambda s: order[s])
