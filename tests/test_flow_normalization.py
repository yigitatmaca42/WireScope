"""Dedicated coverage for Analyzer._update_conversation's A<->B folding.

Built directly against the static method rather than round-tripping through
a pcap file, so each case is explicit about which side is "first seen" and
what the expected normalized key looks like - this is easy to get subtly
wrong (e.g. an asymmetric tie-break, or IPv6 addresses sorting differently
from IPv4) and worth pinning down precisely.
"""

from __future__ import annotations

from wirescope.analyzer import Analyzer
from wirescope.models import AnalysisResult, CaptureInfo


def _fresh_result() -> AnalysisResult:
    return AnalysisResult(capture=CaptureInfo(file_name="t.pcap", file_size_bytes=0, capture_start=None, capture_end=None))


def test_forward_then_reverse_fold_into_one_conversation_ipv4_tcp():
    result = _fresh_result()
    Analyzer._update_conversation(result, "10.0.0.5", 52000, "10.0.0.1", 80, "TCP", 100, 1.0)
    Analyzer._update_conversation(result, "10.0.0.1", 80, "10.0.0.5", 52000, "TCP", 200, 2.0)

    assert len(result.conversations) == 1
    convo = next(iter(result.conversations.values()))
    assert convo.packet_count == 2
    assert convo.byte_count == 300
    assert convo.first_seen == 1.0
    assert convo.last_seen == 2.0


def test_forward_then_reverse_fold_into_one_conversation_udp():
    result = _fresh_result()
    Analyzer._update_conversation(result, "10.0.0.5", 51000, "10.0.0.1", 53, "UDP", 64, 1.0)
    Analyzer._update_conversation(result, "10.0.0.1", 53, "10.0.0.5", 51000, "UDP", 128, 1.5)

    assert len(result.conversations) == 1
    convo = next(iter(result.conversations.values()))
    assert convo.packet_count == 2
    assert convo.byte_count == 192


def test_forward_then_reverse_fold_into_one_conversation_ipv6():
    result = _fresh_result()
    a, b = "2001:db8::5", "2001:db8::1"
    Analyzer._update_conversation(result, a, 52000, b, 443, "TCP", 100, 1.0)
    Analyzer._update_conversation(result, b, 443, a, 52000, "TCP", 100, 2.0)

    assert len(result.conversations) == 1
    convo = next(iter(result.conversations.values()))
    assert convo.packet_count == 2


def test_different_ports_are_not_folded_together():
    """Same two hosts, two different port pairs -> two distinct flows, not
    one - normalization folds direction, not distinct 5-tuples."""
    result = _fresh_result()
    Analyzer._update_conversation(result, "10.0.0.5", 52000, "10.0.0.1", 80, "TCP", 100, 1.0)
    Analyzer._update_conversation(result, "10.0.0.5", 52001, "10.0.0.1", 80, "TCP", 100, 1.0)

    assert len(result.conversations) == 2


def test_different_protocols_same_addresses_are_not_folded_together():
    """TCP and UDP between the same two (ip, port) pairs must stay separate
    flows - protocol is part of the identity, not just a label."""
    result = _fresh_result()
    Analyzer._update_conversation(result, "10.0.0.5", 5000, "10.0.0.1", 5000, "TCP", 100, 1.0)
    Analyzer._update_conversation(result, "10.0.0.5", 5000, "10.0.0.1", 5000, "UDP", 100, 1.0)

    assert len(result.conversations) == 2


def test_normalized_key_is_order_independent_regardless_of_who_spoke_first():
    """Whichever side happens to send the first packet, the same two hosts
    talking on the same ports must always converge on the same stored key -
    otherwise a real flow could accidentally get split into two if traffic
    is asymmetric or reordered."""
    result_a_first = _fresh_result()
    Analyzer._update_conversation(result_a_first, "192.168.1.50", 6000, "8.8.8.8", 53, "UDP", 64, 1.0)
    key_a_first = next(iter(result_a_first.conversations))

    result_b_first = _fresh_result()
    Analyzer._update_conversation(result_b_first, "8.8.8.8", 53, "192.168.1.50", 6000, "UDP", 64, 1.0)
    key_b_first = next(iter(result_b_first.conversations))

    assert key_a_first == key_b_first


def test_conversations_truncate_at_limit_and_flag_it():
    result = _fresh_result()
    result.limits.max_conversations = 2
    Analyzer._update_conversation(result, "10.0.0.1", 1, "10.0.0.2", 1, "TCP", 10, 1.0)
    Analyzer._update_conversation(result, "10.0.0.1", 2, "10.0.0.2", 2, "TCP", 10, 1.0)
    assert result.limits.conversations_truncated is False

    Analyzer._update_conversation(result, "10.0.0.1", 3, "10.0.0.2", 3, "TCP", 10, 1.0)
    assert len(result.conversations) == 2
    assert result.limits.conversations_truncated is True
