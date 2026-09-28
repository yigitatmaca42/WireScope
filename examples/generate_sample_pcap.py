#!/usr/bin/env python3
"""Generate a small synthetic capture with mixed traffic for trying out
WireScope without needing a real, potentially sensitive, PCAP file.

Produces examples/sample_capture.pcap containing:
  - ARP request/reply
  - DNS queries + responses (A, AAAA, CNAME records; one NXDOMAIN)
  - A plaintext HTTP request + response
  - A TLS ClientHello with SNI
  - A TCP three-way handshake plus a short burst of SYN-only packets
    (to exercise the "high SYN activity" heuristic)
  - ICMP echo request/reply
"""

from __future__ import annotations

import time
from pathlib import Path

from scapy.all import wrpcap
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

OUT_PATH = Path(__file__).parent / "sample_capture.pcap"


def build_packets() -> list:
    packets = []
    t = time.time() - 60

    def stamp(pkt, dt: float = 0.05):
        nonlocal t
        t += dt
        pkt.time = t
        return pkt

    client, server, gateway = "192.168.1.50", "93.184.216.34", "192.168.1.1"
    client_mac, gw_mac = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:fe"
    eth = Ether(src=client_mac, dst=gw_mac)

    # --- ARP: client asks who has the gateway, gateway replies ---
    packets.append(stamp(Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=client, pdst=gateway, hwsrc=client_mac)))
    packets.append(stamp(Ether(src=gw_mac, dst=client_mac) / ARP(op=2, psrc=gateway, pdst=client, hwsrc=gw_mac)))

    # --- DNS: A, AAAA, CNAME, and one NXDOMAIN ---
    dns_id = 1000
    for qname, qtype, answer in [
        ("example.com", "A", ("1.2.3.4", 1)),
        ("example.com", "AAAA", ("2001:db8::1", 28)),
        ("www.example.com", "CNAME", ("example.com", 5)),
    ]:
        dns_id += 1
        packets.append(
            stamp(
                eth / IP(src=client, dst="8.8.8.8")
                / UDP(sport=51000, dport=53)
                / DNS(id=dns_id, qr=0, qd=DNSQR(qname=qname, qtype=qtype))
            )
        )
        rdata, rtype = answer
        packets.append(
            stamp(
                eth / IP(src="8.8.8.8", dst=client)
                / UDP(sport=53, dport=51000)
                / DNS(
                    id=dns_id,
                    qr=1,
                    rcode=0,
                    qd=DNSQR(qname=qname, qtype=qtype),
                    an=DNSRR(rrname=qname, type=rtype, rdata=rdata, ttl=300),
                    ancount=1,
                )
            )
        )

    dns_id += 1
    packets.append(
        stamp(
            eth / IP(src=client, dst="8.8.8.8")
            / UDP(sport=51001, dport=53)
            / DNS(id=dns_id, qr=0, qd=DNSQR(qname="this-domain-does-not-exist.invalid", qtype="A"))
        )
    )
    packets.append(
        stamp(
            eth / IP(src="8.8.8.8", dst=client)
            / UDP(sport=53, dport=51001)
            / DNS(id=dns_id, qr=1, rcode=3, qd=DNSQR(qname="this-domain-does-not-exist.invalid", qtype="A"), ancount=0)
        )
    )

    # --- TCP handshake + plaintext HTTP request/response ---
    isn_c, isn_s = 1000, 5000
    packets.append(stamp(eth / IP(src=client, dst=server) / TCP(sport=52000, dport=80, flags="S", seq=isn_c)))
    packets.append(stamp(eth / IP(src=server, dst=client) / TCP(sport=80, dport=52000, flags="SA", seq=isn_s, ack=isn_c + 1)))
    packets.append(stamp(eth / IP(src=client, dst=server) / TCP(sport=52000, dport=80, flags="A", seq=isn_c + 1, ack=isn_s + 1)))

    http_request = (
        b"GET /login HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: WireScope-Sample/1.0\r\n"
        b"\r\n"
    )
    packets.append(
        stamp(
            eth / IP(src=client, dst=server)
            / TCP(sport=52000, dport=80, flags="PA", seq=isn_c + 1, ack=isn_s + 1)
            / http_request
        )
    )
    http_response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Server: nginx\r\n"
        b"\r\n"
        b"<html>ok</html>"
    )
    packets.append(
        stamp(
            eth / IP(src=server, dst=client)
            / TCP(sport=80, dport=52000, flags="PA", seq=isn_s + 1, ack=isn_c + 1 + len(http_request))
            / http_response
        )
    )
    packets.append(stamp(eth / IP(src=client, dst=server) / TCP(sport=52000, dport=80, flags="FA", seq=isn_c + 1 + len(http_request), ack=isn_s + 1 + len(http_response))))
    packets.append(stamp(eth / IP(src=server, dst=client) / TCP(sport=80, dport=52000, flags="FA", seq=isn_s + 1 + len(http_response), ack=isn_c + 2 + len(http_request))))

    # --- Minimal, hand-built TLS ClientHello with an SNI extension ---
    sni_host = b"secure.example.net"
    server_name_entry = bytes([0x00]) + len(sni_host).to_bytes(2, "big") + sni_host
    server_name_list = len(server_name_entry).to_bytes(2, "big") + server_name_entry
    sni_extension = (0x0000).to_bytes(2, "big") + len(server_name_list).to_bytes(2, "big") + server_name_list
    extensions = sni_extension
    client_hello_body = (
        bytes([0x03, 0x03])  # client version TLS 1.2
        + b"\x00" * 32  # random
        + bytes([0x00])  # session id length
        + (0x02).to_bytes(2, "big") + bytes([0x00, 0x2f])  # one cipher suite
        + bytes([0x01, 0x00])  # compression methods
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = bytes([0x01]) + len(client_hello_body).to_bytes(3, "big") + client_hello_body
    tls_record = bytes([0x16, 0x03, 0x01]) + len(handshake).to_bytes(2, "big") + handshake

    packets.append(stamp(eth / IP(src=client, dst=server) / TCP(sport=52500, dport=443, flags="S", seq=2000)))
    packets.append(stamp(eth / IP(src=server, dst=client) / TCP(sport=443, dport=52500, flags="SA", seq=6000, ack=2001)))
    packets.append(
        stamp(
            eth / IP(src=client, dst=server)
            / TCP(sport=52500, dport=443, flags="PA", seq=2001, ack=6001)
            / tls_record
        )
    )

    # --- SYN-only burst to a range of ports, to exercise scanning heuristics ---
    scanner = "192.168.1.99"
    for port in range(2000, 2030):
        packets.append(stamp(eth / IP(src=scanner, dst=server) / TCP(sport=40000 + port, dport=port, flags="S", seq=port), dt=0.01))

    # --- ICMP echo request/reply ---
    packets.append(stamp(eth / IP(src=client, dst=gateway) / ICMP(type=8, code=0, id=1, seq=1) / b"ping"))
    packets.append(stamp(eth / IP(src=gateway, dst=client) / ICMP(type=0, code=0, id=1, seq=1) / b"ping"))

    return packets


def main() -> None:
    packets = build_packets()
    wrpcap(str(OUT_PATH), packets)
    print(f"Wrote {len(packets)} packets to {OUT_PATH}")


if __name__ == "__main__":
    main()
