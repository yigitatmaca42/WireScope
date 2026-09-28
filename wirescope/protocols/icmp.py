"""ICMP packet parsing."""

from __future__ import annotations

from dataclasses import dataclass

ECHO_REQUEST = 8
ECHO_REPLY = 0


@dataclass
class IcmpEvent:
    icmp_type: int
    icmp_code: int


def parse_icmp(pkt) -> IcmpEvent | None:  # noqa: ANN001 - scapy ICMP layer
    from scapy.layers.inet import ICMP

    if not pkt.haslayer(ICMP):
        return None
    icmp = pkt[ICMP]
    return IcmpEvent(icmp_type=int(icmp.type), icmp_code=int(icmp.code))
