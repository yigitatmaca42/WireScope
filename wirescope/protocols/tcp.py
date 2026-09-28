"""TCP flag parsing."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TcpFlagEvent:
    syn: bool
    ack: bool
    fin: bool
    rst: bool
    psh: bool


def parse_tcp_flags(pkt) -> TcpFlagEvent | None:  # noqa: ANN001 - scapy TCP layer
    from scapy.layers.inet import TCP

    if not pkt.haslayer(TCP):
        return None
    flags = pkt[TCP].flags
    return TcpFlagEvent(
        syn=bool(flags & 0x02),
        ack=bool(flags & 0x10),
        fin=bool(flags & 0x01),
        rst=bool(flags & 0x04),
        psh=bool(flags & 0x08),
    )
