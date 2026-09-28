from __future__ import annotations

import csv
import json

from wirescope.analyzer import Analyzer
from wirescope.exporters.csv_exporter import write_csv
from wirescope.exporters.html_exporter import render_html, write_html
from wirescope.exporters.json_exporter import to_json_dict, write_json
from wirescope.models import AnalysisResult, CaptureInfo, DnsRecord, Finding, HttpTransaction, Severity, TlsInfo


def test_json_export_schema(sample_pcap_path):
    result = Analyzer(sample_pcap_path).run()
    data = to_json_dict(result)
    for key in ("capture", "statistics", "hosts", "ports", "conversations", "dns", "http", "tls", "arp", "findings"):
        assert key in data
    assert data["capture"]["total_packets"] == 7
    assert len(data["dns"]) == 2
    assert "source" in data["ports"] and "destination" in data["ports"]


def test_write_json_creates_parent_dirs_and_valid_json(sample_pcap_path, tmp_path):
    result = Analyzer(sample_pcap_path).run()
    out_path = tmp_path / "nested" / "dir" / "report.json"
    write_json(result, out_path)
    assert out_path.exists()
    data = json.loads(out_path.read_text())
    assert data["capture"]["total_packets"] == 7


def test_write_csv_creates_all_expected_files(sample_pcap_path, tmp_path):
    result = Analyzer(sample_pcap_path).run()
    out_dir = tmp_path / "reports"
    written = write_csv(result, out_dir)
    names = {p.name for p in written}
    assert names == {"hosts.csv", "ports.csv", "conversations.csv", "dns.csv", "http.csv", "findings.csv"}

    with (out_dir / "dns.csv").open() as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 2
    assert any(row["query_name"] == "example.com" for row in rows)

    with (out_dir / "http.csv").open() as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["method"] == "GET"


def test_csv_export_neutralizes_formula_injection(tmp_path):
    """A DNS query name (or any other capture-derived field) starting with
    =, +, -, or @ must not survive into the CSV as a raw formula trigger -
    Excel/LibreOffice/Sheets would otherwise execute it as a formula."""
    result = _malicious_csv_result()
    out_dir = tmp_path / "reports"
    write_csv(result, out_dir)

    with (out_dir / "dns.csv").open() as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["query_name"] == "'=cmd|' /C calc'!A1"

    with (out_dir / "findings.csv").open() as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["evidence"].startswith("'@SUM")


def _malicious_csv_result() -> AnalysisResult:
    result = AnalysisResult(
        capture=CaptureInfo(file_name="evil.pcap", file_size_bytes=1, capture_start=1.0, capture_end=2.0)
    )
    result.dns_records.append(
        DnsRecord(
            query_name="=cmd|' /C calc'!A1", query_type="A",
            source="10.0.0.5", destination="10.0.0.1", timestamp=1.0,
        )
    )
    result.findings.append(
        Finding(
            title="t", severity=Severity.LOW, description="d",
            evidence="@SUM(1+1)*cmd|' /C calc'!A0", confidence="low",
        )
    )
    return result


def test_render_html_contains_expected_sections(sample_pcap_path):
    result = Analyzer(sample_pcap_path).run()
    html = render_html(result)
    assert "<!doctype html>" in html.lower()
    assert "WireScope" in html
    assert "Capture Overview" in html
    assert "example.com" in html
    assert "GET" in html
    # No external CDN / network dependency: no <script src="http...">, no cdn refs.
    assert "cdn." not in html.lower()
    assert "<script src=" not in html.lower()
    assert "<link " not in html.lower()  # no external stylesheet link


def test_write_html_creates_parent_dirs(sample_pcap_path, tmp_path):
    result = Analyzer(sample_pcap_path).run()
    out_path = tmp_path / "nested" / "report.html"
    write_html(result, out_path)
    assert out_path.exists()
    assert "WireScope" in out_path.read_text()


def _malicious_result() -> AnalysisResult:
    """A hand-built AnalysisResult carrying capture-derived strings an
    attacker fully controls (DNS query name, HTTP Host/User-Agent, TLS SNI,
    a finding's evidence text) crafted to break out of HTML if any of them
    is written into the report unescaped."""
    payload = "<script>alert(1)</script>"
    result = AnalysisResult(
        capture=CaptureInfo(file_name="evil.pcap", file_size_bytes=1, capture_start=1.0, capture_end=2.0)
    )
    result.dns_records.append(
        DnsRecord(query_name=payload, query_type="A", source="10.0.0.5", destination="10.0.0.1", timestamp=1.0)
    )
    result.http_transactions.append(
        HttpTransaction(
            direction="request", src_ip="10.0.0.5", dst_ip="10.0.0.1", timestamp=1.0,
            method="GET", host=payload, path=payload, user_agent=payload,
        )
    )
    result.tls_records.append(
        TlsInfo(src_ip="10.0.0.5", dst_ip="10.0.0.1", timestamp=1.0, sni=payload, record_version="TLS 1.2")
    )
    result.findings.append(
        Finding(
            title=payload, severity=Severity.LOW, description=payload,
            evidence=payload, confidence="low", host=payload,
        )
    )
    return result


def test_html_export_escapes_attacker_controlled_capture_data():
    """Every capture-derived string (DNS query name, HTTP host/path/UA, TLS
    SNI, finding text) must be HTML-escaped. If this ever regresses, an
    attacker who controls what a monitored host queries/sends could get
    script execution in whoever opens the generated report."""
    html = render_html(_malicious_result())

    assert "<script>alert(1)</script>" not in html
    # The escaped form must still be present somewhere (proves the data
    # made it into the report - this isn't just failing because the field
    # was silently dropped).
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
