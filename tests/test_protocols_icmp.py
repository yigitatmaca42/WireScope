from __future__ import annotations

from wirescope.protocols.icmp import ECHO_REPLY, ECHO_REQUEST, parse_icmp


def test_parse_icmp_echo_request():
    from scapy.layers.inet import ICMP, IP

    pkt = IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(type=ECHO_REQUEST, code=0)
    event = parse_icmp(pkt)
    assert event is not None
    assert event.icmp_type == ECHO_REQUEST
    assert event.icmp_code == 0


def test_parse_icmp_echo_reply():
    from scapy.layers.inet import ICMP, IP

    pkt = IP(src="2.2.2.2", dst="1.1.1.1") / ICMP(type=ECHO_REPLY, code=0)
    event = parse_icmp(pkt)
    assert event is not None
    assert event.icmp_type == ECHO_REPLY


def test_parse_icmp_other_type_code():
    """E.g. type 3 (destination unreachable), code 1 (host unreachable) -
    anything beyond echo request/reply must still parse, just without a
    named constant."""
    from scapy.layers.inet import ICMP, IP

    pkt = IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(type=3, code=1)
    event = parse_icmp(pkt)
    assert event is not None
    assert event.icmp_type == 3
    assert event.icmp_code == 1


def test_parse_icmp_returns_none_for_non_icmp_packet():
    from scapy.layers.inet import IP, TCP

    pkt = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=80, dport=12345)
    assert parse_icmp(pkt) is None
