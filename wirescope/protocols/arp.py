"""ARP packet parsing.

In both ARP requests and replies, the sender fields (psrc/hwsrc) are the
one IP-MAC pairing the packet actually vouches for - the target fields
(pdst/hwdst) are just "who I'm asking about" and hwdst is usually all
zeroes in a request. So IP->MAC mapping is always built from psrc/hwsrc;
op (request vs reply) only affects the request/reply counters.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ArpEvent:
    sender_ip: str
    sender_mac: str
    is_request: bool


def parse_arp(pkt) -> ArpEvent | None:  # noqa: ANN001 - scapy ARP layer
    from scapy.layers.l2 import ARP

    if not pkt.haslayer(ARP):
        return None
    arp = pkt[ARP]
    if arp.op not in (1, 2):  # 1 = who-has, 2 = is-at
        return None
    return ArpEvent(sender_ip=arp.psrc, sender_mac=arp.hwsrc, is_request=arp.op == 1)
