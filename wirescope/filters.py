"""CLI-level packet filtering.

A filter is applied as a full inclusion filter: a packet only contributes
to any statistic, conversation, DNS/HTTP/TLS record, or finding if it
matches every filter dimension that was specified (multiple values within
one dimension - e.g. two --ip flags - are OR'd together; different
dimensions are AND'd).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PacketFilter:
    ips: set[str] = field(default_factory=set)
    ports: set[int] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)  # lower-case: "tcp", "udp", "dns", ...

    @property
    def is_empty(self) -> bool:
        return not (self.ips or self.ports or self.protocols)

    def matches(
        self,
        *,
        src_ip: str | None,
        dst_ip: str | None,
        src_port: int | None,
        dst_port: int | None,
        protocols_present: set[str],
    ) -> bool:
        if self.ips and not ({src_ip, dst_ip} & self.ips):
            return False
        if self.ports and not ({src_port, dst_port} & self.ports):
            return False
        if self.protocols:
            return bool(protocols_present & self.protocols)
        return True
