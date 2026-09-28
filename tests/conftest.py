"""Shared pytest fixtures.

Builds a small synthetic capture directly with Scapy (DNS query/response,
an HTTP request, and a TCP SYN handshake) and writes it to a temp pcap file,
so the test suite never depends on a real, potentially sensitive PCAP.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def sample_pcap_path(tmp_path):
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import ARP, Ether
    from scapy.utils import wrpcap

    eth = Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:fe")
    client, dns_server, web_server = "10.0.0.5", "10.0.0.1", "93.184.216.34"

    packets = [
        eth / ARP(op=1, psrc=client, pdst=dns_server, hwsrc="aa:bb:cc:00:00:01"),
        eth / IP(src=client, dst=dns_server) / UDP(sport=51000, dport=53)
        / DNS(id=1, qr=0, qd=DNSQR(qname="example.com", qtype="A")),
        eth / IP(src=dns_server, dst=client) / UDP(sport=53, dport=51000)
        / DNS(
            id=1, qr=1, rcode=0,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type=1, rdata="1.2.3.4", ttl=60),
            ancount=1,
        ),
        eth / IP(src=client, dst=web_server) / TCP(sport=52000, dport=80, flags="S", seq=100),
        eth / IP(src=web_server, dst=client) / TCP(sport=80, dport=52000, flags="SA", seq=200, ack=101),
        eth / IP(src=client, dst=web_server) / TCP(sport=52000, dport=80, flags="A", seq=101, ack=201),
        eth / IP(src=client, dst=web_server)
        / TCP(sport=52000, dport=80, flags="PA", seq=101, ack=201)
        / (b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: pytest\r\n\r\n"),
    ]

    for i, pkt in enumerate(packets):
        pkt.time = 1_700_000_000 + i

    path = tmp_path / "test_capture.pcap"
    wrpcap(str(path), packets)
    return path


@pytest.fixture
def empty_pcap_path(tmp_path):
    path = tmp_path / "empty.pcap"
    path.touch()
    return path
