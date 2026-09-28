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
