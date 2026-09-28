from __future__ import annotations

from wirescope.models import (
    AnalysisResult,
    CaptureInfo,
    Conversation,
    Finding,
    HostStats,
    ProtocolCounts,
    Severity,
)


def test_capture_info_duration_and_rates():
    cap = CaptureInfo(
        file_name="x.pcap",
        file_size_bytes=100,
        capture_start=10.0,
        capture_end=20.0,
        total_packets=100,
        total_bytes=1000,
    )
    assert cap.duration_seconds == 10.0
    assert cap.average_packet_size == 10.0
    assert cap.packets_per_second == 10.0
    assert cap.bytes_per_second == 100.0


def test_capture_info_zero_duration_falls_back_to_totals():
    cap = CaptureInfo(
        file_name="x.pcap", file_size_bytes=1, capture_start=5.0, capture_end=5.0,
        total_packets=7, total_bytes=70,
    )
    assert cap.duration_seconds == 0.0
    assert cap.packets_per_second == 7
    assert cap.bytes_per_second == 70


def test_capture_info_no_packets_average_is_zero():
    cap = CaptureInfo(file_name="x.pcap", file_size_bytes=0, capture_start=None, capture_end=None)
    assert cap.average_packet_size == 0.0
    assert cap.duration_seconds == 0.0


def test_host_stats_total_bytes_and_as_dict():
    host = HostStats(ip="1.2.3.4", packet_count=5, bytes_sent=100, bytes_received=50)
    host.peers.add("5.6.7.8")
    host.ports_used.update({80, 443})
    assert host.total_bytes == 150
    d = host.as_dict()
    assert d["unique_peers"] == 1
    assert d["ports_used"] == [80, 443]


def test_conversation_duration_never_negative():
    convo = Conversation(
        src_ip="a", src_port=1, dst_ip="b", dst_port=2, protocol="TCP",
        first_seen=10.0, last_seen=5.0,  # out of order on purpose
    )
    assert convo.duration_seconds == 0.0


def test_protocol_counts_as_dict():
    counts = ProtocolCounts(ipv4=5, tcp=3)
    d = counts.as_dict()
    assert d["ipv4"] == 5
    assert d["tcp"] == 3
    assert d["udp"] == 0


def test_finding_as_dict_includes_severity_value():
    finding = Finding(
        title="t", severity=Severity.HIGH, description="d", evidence="e", confidence="high"
    )
    assert finding.as_dict()["severity"] == "HIGH"


def test_analysis_result_top_n_helpers():
    result = AnalysisResult(capture=CaptureInfo(file_name="x", file_size_bytes=0, capture_start=None, capture_end=None))
    for i in range(5):
        result.hosts[str(i)] = HostStats(ip=str(i), packet_count=i)
    top = result.top_hosts(3)
    assert [h.ip for h in top] == ["4", "3", "2"]
