"""DNS packet parsing.

Uses Scapy's built-in DNS/DNSQR/DNSRR layers, which are reliable enough for
the common record types WireScope cares about (A, AAAA, CNAME, MX, TXT).
"""

from __future__ import annotations

from wirescope.models import DnsRecord

_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

_SUPPORTED_RR_TYPES = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT"}


def _decode_name(name: bytes | str) -> str:
    if isinstance(name, bytes):
        name = name.decode(errors="replace")
    return name.rstrip(".")


def _decode_rdata(rr) -> str:  # noqa: ANN001 - scapy DNSRR, typed loosely on purpose
    rdata = rr.rdata
    if isinstance(rdata, bytes):
        try:
            return rdata.decode(errors="replace")
        except Exception:
            return repr(rdata)
    return str(rdata)


def parse_dns(pkt, timestamp: float, src_ip: str, dst_ip: str) -> DnsRecord | None:  # noqa: ANN001
    """Extract a DnsRecord from a packet already known to contain a DNS layer.

    Returns None if the DNS layer has no question (malformed/truncated).
    """
    from scapy.layers.dns import (
        DNS,  # local import keeps Scapy off the import path of callers that never touch DNS
    )

    dns = pkt[DNS]
    if dns.qdcount == 0 or dns.qd is None:
        return None

    question = dns.qd[0] if hasattr(dns.qd, "__getitem__") else dns.qd
    query_name = _decode_name(question.qname)
    query_type = _SUPPORTED_RR_TYPES.get(int(question.qtype), str(int(question.qtype)))

    is_response = bool(dns.qr)
    response_code = _RCODES.get(int(dns.rcode), str(int(dns.rcode))) if is_response else None

    answers: list[str] = []
    if is_response and dns.ancount and dns.an is not None:
        answer_list = dns.an if isinstance(dns.an, list) else [dns.an]
        for rr in answer_list:
            rtype = _SUPPORTED_RR_TYPES.get(int(rr.type))
            if rtype is None:
                continue
            answers.append(_decode_rdata(rr))

    return DnsRecord(
        query_name=query_name,
        query_type=query_type,
        source=src_ip,
        destination=dst_ip,
        timestamp=timestamp,
        is_response=is_response,
        response_code=response_code,
        answers=answers,
    )
