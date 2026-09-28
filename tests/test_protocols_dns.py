from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR, DNSRR

from wirescope.protocols.dns import parse_dns


def test_parse_dns_query():
    pkt = DNS(qr=0, qd=DNSQR(qname="example.com", qtype="A"))
    record = parse_dns(pkt, timestamp=1.0, src_ip="1.1.1.1", dst_ip="8.8.8.8")
    assert record is not None
    assert record.query_name == "example.com"
    assert record.query_type == "A"
    assert record.is_response is False
    assert record.answers == []


def test_parse_dns_response_with_answer():
    pkt = DNS(
        qr=1, rcode=0,
        qd=DNSQR(qname="example.com", qtype="A"),
        an=DNSRR(rrname="example.com", type=1, rdata="1.2.3.4", ttl=60),
        ancount=1,
    )
    record = parse_dns(pkt, timestamp=1.0, src_ip="8.8.8.8", dst_ip="1.1.1.1")
    assert record is not None
    assert record.is_response is True
    assert record.response_code == "NOERROR"
    assert record.answers == ["1.2.3.4"]


def test_parse_dns_nxdomain():
    pkt = DNS(qr=1, rcode=3, qd=DNSQR(qname="nope.invalid", qtype="A"), ancount=0)
    record = parse_dns(pkt, timestamp=1.0, src_ip="8.8.8.8", dst_ip="1.1.1.1")
    assert record is not None
    assert record.response_code == "NXDOMAIN"
    assert record.answers == []


def test_parse_dns_no_question_returns_none():
    pkt = DNS(qr=0, qdcount=0, qd=[])
    assert parse_dns(pkt, timestamp=1.0, src_ip="a", dst_ip="b") is None


def test_parse_dns_strips_trailing_dot():
    pkt = DNS(qr=0, qd=DNSQR(qname="example.com.", qtype="A"))
    record = parse_dns(pkt, timestamp=1.0, src_ip="a", dst_ip="b")
    assert record.query_name == "example.com"
