from __future__ import annotations

from wirescope.detection.ioc import IocSet, load_iocs, match_iocs
from wirescope.models import AnalysisResult, CaptureInfo, DnsRecord, HostStats


def _empty_result() -> AnalysisResult:
    return AnalysisResult(
        capture=CaptureInfo(file_name="x", file_size_bytes=0, capture_start=0.0, capture_end=1.0)
    )


def test_load_iocs_splits_ips_and_domains(tmp_path):
    ioc_file = tmp_path / "iocs.txt"
    ioc_file.write_text("# comment\n1.2.3.4\nevil.example.com\n\n8.8.8.8\n")
    iocs = load_iocs(ioc_file)
    assert iocs.ips == {"1.2.3.4", "8.8.8.8"}
    assert iocs.domains == {"evil.example.com"}


def test_load_iocs_normalizes_domain_case_and_trailing_dot(tmp_path):
    ioc_file = tmp_path / "iocs.txt"
    ioc_file.write_text("Evil.Example.com.\n")
    iocs = load_iocs(ioc_file)
    assert iocs.domains == {"evil.example.com"}


def test_match_iocs_ip_hit():
    result = _empty_result()
    result.hosts["6.6.6.6"] = HostStats(ip="6.6.6.6")
    from wirescope.detection.ioc import IocSet

    iocs = IocSet(ips={"6.6.6.6"})
    findings = match_iocs(result, iocs)
    assert len(findings) == 1
    assert findings[0].severity.value == "HIGH"
    assert findings[0].host == "6.6.6.6"


def test_match_iocs_domain_hit():
    result = _empty_result()
    result.dns_records.append(
        DnsRecord(query_name="evil.example.com", query_type="A", source="10.0.0.5", destination="b", timestamp=1.0)
    )
    from wirescope.detection.ioc import IocSet

    iocs = IocSet(domains={"evil.example.com"})
    findings = match_iocs(result, iocs)
    assert len(findings) == 1
    assert findings[0].host == "10.0.0.5"


def test_match_iocs_no_hit_returns_empty():
    result = _empty_result()
    result.hosts["1.1.1.1"] = HostStats(ip="1.1.1.1")
    from wirescope.detection.ioc import IocSet

    iocs = IocSet(ips={"9.9.9.9"})
    assert match_iocs(result, iocs) == []


def test_load_iocs_accepts_ipv6(tmp_path):
    ioc_file = tmp_path / "iocs.txt"
    ioc_file.write_text("2001:db8::1\n")
    iocs = load_iocs(ioc_file)
    assert iocs.ips == {"2001:db8::1"}


def test_load_iocs_flags_malformed_lines_instead_of_treating_them_as_domains(tmp_path):
    ioc_file = tmp_path / "iocs.txt"
    ioc_file.write_text("good.example.com\nnot a domain!!\n***\n1.2.3.4\n")
    iocs = load_iocs(ioc_file)
    assert iocs.domains == {"good.example.com"}
    assert iocs.ips == {"1.2.3.4"}
    malformed_texts = {text for _, text in iocs.malformed_lines}
    assert "not a domain!!" in malformed_texts
    assert "***" in malformed_texts


def test_domain_ioc_matches_are_suffix_based():
    """An IOC entry of example.com must match a subdomain query
    (sub.example.com) but not an unrelated domain that merely contains the
    same substring (notexample.com)."""
    result = _empty_result()
    result.dns_records.append(
        DnsRecord(query_name="sub.example.com", query_type="A", source="10.0.0.5", destination="b", timestamp=1.0)
    )
    result.dns_records.append(
        DnsRecord(query_name="notexample.com", query_type="A", source="10.0.0.6", destination="b", timestamp=1.0)
    )
    iocs = IocSet(domains={"example.com"})
    findings = match_iocs(result, iocs)
    assert len(findings) == 1
    assert findings[0].host == "10.0.0.5"
