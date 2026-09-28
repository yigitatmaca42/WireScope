"""Simple Indicator-of-Compromise matching against IPs and domains.

The IOC file format is deliberately trivial: one IP (v4 or v6) or domain per
line, blank lines and '#' comments ignored. Hash/URL support is left for a
future version (see README Roadmap) - matching those correctly against
capture data (payload hashing, URL reconstruction) is materially more
work than IP/domain string matching and isn't implemented here.

Domain matching is suffix-based: an IOC entry of "example.com" matches
DNS activity for "example.com" itself AND any subdomain of it (e.g.
"sub.example.com"), but not "notexample.com" or "evil-example.com" - this
is the same convention most threat-intel domain-block lists use, since a
malicious domain's subdomains are typically also attacker-controlled.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

from wirescope.models import AnalysisResult, Finding, Severity

# Loose hostname-label validation - not a full RFC 1035 validator, just
# enough to reject obviously-malformed lines (stray punctuation, spaces
# that survived quoting, etc.) instead of silently treating them as
# domains that will simply never match anything.
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")


@dataclass
class IocSet:
    ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    # (line_number, raw_text) for lines that were neither a valid IP nor a
    # plausible domain - surfaced so the CLI can warn instead of silently
    # dropping a typo'd indicator.
    malformed_lines: list[tuple[int, str]] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (self.ips or self.domains)


def load_iocs(path: str | Path) -> IocSet:
    ioc_set = IocSet()
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ipaddress.ip_address(line)
            ioc_set.ips.add(line)
            continue
        except ValueError:
            pass
        domain = line.lower().rstrip(".")
        if _DOMAIN_RE.match(domain):
            ioc_set.domains.add(domain)
        else:
            ioc_set.malformed_lines.append((line_number, raw_line))
    return ioc_set


def _domain_matches(query_name: str, ioc_domains: set[str]) -> str | None:
    """Return the IOC entry `query_name` matches (exact or as a
    subdomain), or None. `query_name` must already be lowercased with any
    trailing dot stripped."""
    if query_name in ioc_domains:
        return query_name
    for ioc_domain in ioc_domains:
        if query_name.endswith("." + ioc_domain):
            return ioc_domain
    return None


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
            matched = _domain_matches(name, iocs.domains)
            if matched is not None:
                suffix_note = "" if matched == name else f" (as a subdomain of {matched!r})"
                findings.append(
                    Finding(
                        title="IOC match: known domain observed",
                        severity=Severity.HIGH,
                        description=(
                            "A domain name in this capture's DNS traffic matches an "
                            "entry in the supplied IOC list."
                        ),
                        evidence=(
                            f"Domain {record.query_name!r} queried by {record.source} matched "
                            f"a supplied IOC entry{suffix_note}."
                        ),
                        confidence="high",
                        host=record.source,
                        timestamp=record.timestamp,
                    )
                )

    return findings
