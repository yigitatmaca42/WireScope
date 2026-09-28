from __future__ import annotations

import pytest

from wirescope.analyzer import Analyzer
from wirescope.exceptions import (
    CaptureNotFoundError,
    EmptyCaptureError,
    UnsupportedCaptureError,
)
from wirescope.filters import PacketFilter


def test_analyzer_basic_counts(sample_pcap_path):
    result = Analyzer(sample_pcap_path).run()
    assert result.capture.total_packets == 7
    assert result.capture.protocol_counts.arp == 1
    assert result.capture.protocol_counts.udp == 2
    assert result.capture.protocol_counts.tcp == 4

    assert "10.0.0.5" in result.hosts
    assert "93.184.216.34" in result.hosts


def test_analyzer_dns_extraction(sample_pcap_path):
    result = Analyzer(sample_pcap_path).run()
    assert len(result.dns_records) == 2
    query = next(r for r in result.dns_records if not r.is_response)
    assert query.query_name == "example.com"
    response = next(r for r in result.dns_records if r.is_response)
    assert response.answers == ["1.2.3.4"]


def test_analyzer_http_extraction(sample_pcap_path):
    result = Analyzer(sample_pcap_path).run()
    assert len(result.http_transactions) == 1
    http = result.http_transactions[0]
    assert http.method == "GET"
    assert http.path == "/index.html"
    assert http.host == "example.com"


def test_analyzer_conversations_normalize_direction(sample_pcap_path):
    result = Analyzer(sample_pcap_path).run()
    tcp_convos = [c for c in result.conversations.values() if c.protocol == "TCP"]
    assert len(tcp_convos) == 1
    convo = tcp_convos[0]
    assert convo.packet_count == 4  # SYN, SYN-ACK, ACK, HTTP request


def test_analyzer_arp_entries(sample_pcap_path):
    result = Analyzer(sample_pcap_path).run()
    assert "10.0.0.5" in result.arp_entries
    assert result.arp_entries["10.0.0.5"].requests == 1


def test_analyzer_file_not_found():
    with pytest.raises(CaptureNotFoundError):
        Analyzer("/no/such/file.pcap").run()


def test_analyzer_unsupported_extension(tmp_path):
    bad_file = tmp_path / "not_a_pcap.txt"
    bad_file.write_text("hello")
    with pytest.raises(UnsupportedCaptureError):
        Analyzer(bad_file).run()


def test_analyzer_empty_capture(empty_pcap_path):
    with pytest.raises(EmptyCaptureError):
        Analyzer(empty_pcap_path).run()


def test_analyzer_with_ip_filter(sample_pcap_path):
    packet_filter = PacketFilter(ips={"10.0.0.1"})
    result = Analyzer(sample_pcap_path, packet_filter).run()
    # Only DNS packets (to/from 10.0.0.1) should remain.
    assert set(result.hosts) == {"10.0.0.5", "10.0.0.1"}
    assert result.capture.total_packets == 2


def test_analyzer_with_protocol_filter(sample_pcap_path):
    packet_filter = PacketFilter(protocols={"dns"})
    result = Analyzer(sample_pcap_path, packet_filter).run()
    assert result.capture.total_packets == 2
    assert len(result.dns_records) == 2


def test_analyzer_with_port_filter(sample_pcap_path):
    packet_filter = PacketFilter(ports={80})
    result = Analyzer(sample_pcap_path, packet_filter).run()
    assert result.capture.protocol_counts.arp == 0
    assert result.capture.protocol_counts.udp == 0
    assert result.capture.total_packets == 4


def test_a_malformed_packet_does_not_abort_the_whole_analysis(sample_pcap_path, monkeypatch):
    """One packet blowing up inside a protocol parser must not take the
    entire run down with it - the capture has 7 packets and only one (a DNS
    query) will trigger the injected failure."""
    import wirescope.analyzer as analyzer_module

    real_parse_dns = analyzer_module.parse_dns
    calls = {"n": 0}

    def flaky_parse_dns(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("simulated malformed DNS layer")
        return real_parse_dns(*args, **kwargs)

    monkeypatch.setattr(analyzer_module, "parse_dns", flaky_parse_dns)

    result = Analyzer(sample_pcap_path).run()

    assert result.capture.total_packets == 7  # every packet still counted
    assert result.malformed_packet_count == 1
    # The DNS response (second DNS packet) should still have parsed fine.
    assert len(result.dns_records) == 1
    # Everything else in the capture (HTTP, ARP, hosts) is unaffected.
    assert len(result.http_transactions) == 1
    assert "10.0.0.5" in result.arp_entries


def test_hosts_truncate_at_limit_and_flag_it():
    from wirescope.models import AnalysisResult, CaptureInfo

    result = AnalysisResult(
        capture=CaptureInfo(file_name="t.pcap", file_size_bytes=0, capture_start=None, capture_end=None)
    )
    result.limits.max_hosts = 2

    Analyzer._update_hosts(result, "10.0.0.1", "10.0.0.2", 100, 1, 2)
    assert result.limits.hosts_truncated is False
    assert len(result.hosts) == 2

    Analyzer._update_hosts(result, "10.0.0.1", "10.0.0.3", 100, 1, 2)
    assert result.limits.hosts_truncated is True
    assert len(result.hosts) == 2  # the new host (10.0.0.3) was not added


def test_ports_truncate_at_limit_and_flag_it():
    from wirescope.models import AnalysisResult, CaptureInfo

    result = AnalysisResult(
        capture=CaptureInfo(file_name="t.pcap", file_size_bytes=0, capture_start=None, capture_end=None)
    )
    result.limits.max_ports = 1

    Analyzer._update_ports(result.ports_dst, 80, "TCP", result.limits)
    assert result.limits.ports_truncated is False
    Analyzer._update_ports(result.ports_dst, 443, "TCP", result.limits)
    assert result.limits.ports_truncated is True
    assert len(result.ports_dst) == 1
