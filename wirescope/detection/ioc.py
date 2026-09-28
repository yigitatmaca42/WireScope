"""Simple Indicator-of-Compromise matching against IPs and domains.

The IOC file format is deliberately trivial: one IP or domain per line,
blank lines and '#' comments ignored. Hash/URL support is left for a
future version (see README Roadmap) - matching those correctly against
capture data (payload hashing, URL reconstruction) is materially more
work than IP/domain string matching and isn't implemented here.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

from wirescope.models import AnalysisResult, Finding, Severity


@dataclass
class IocSet:
    ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)

    @property
    def is_empty(self) -> bool:
        return not (self.ips or self.domains)


def load_iocs(path: str | Path) -> IocSet:
    ioc_set = IocSet()
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ipaddress.ip_address(line)
            ioc_set.ips.add(line)
        except ValueError:
            ioc_set.domains.add(line.lower().rstrip("."))
    return ioc_set


def match_iocs(result: AnalysisResult, iocs: IocSet) -> list[Finding]:
    """Match known-bad IPs/domains against hosts and DNS activity observed
    in the capture. Unlike the heuristics module, an IOC match is a direct
    string match against a list the analyst supplied - so the finding is
    phrased more directly, but the confidence and quality of that match
    still depends entirely on the IOC list's own accuracy."""
    findings: list[Finding] = []

    if iocs.ips:
        matched_ips = set(result.hosts) & iocs.ips
        for ip in sorted(matched_ips):
            findings.append(
                Finding(
                    title="IOC match: known IP address observed",
                    severity=Severity.HIGH,
                    description=(
                        "An IP address in this capture matches an entry in the "
                        "supplied IOC list. Verify the IOC list's provenance and "
                        "freshness before acting on this."
                    ),
                    evidence=f"IP {ip} matched a supplied IOC entry.",
                    confidence="high",
                    host=ip,
                )
            )

    if iocs.domains:
        for record in result.dns_records:
            name = record.query_name.lower().rstrip(".")
            if name in iocs.domains:
                findings.append(
                    Finding(
                        title="IOC match: known domain observed",
                        severity=Severity.HIGH,
                        description=(
                            "A domain name in this capture's DNS traffic matches an "
                            "entry in the supplied IOC list."
                        ),
                        evidence=f"Domain {record.query_name!r} queried by {record.source} matched a supplied IOC entry.",
                        confidence="high",
                        host=record.source,
                        timestamp=record.timestamp,
                    )
                )

    return findings
