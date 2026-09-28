from __future__ import annotations

import csv
import json

from wirescope.analyzer import Analyzer
from wirescope.exporters.csv_exporter import write_csv
from wirescope.exporters.html_exporter import render_html, write_html
from wirescope.exporters.json_exporter import to_json_dict, write_json


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
