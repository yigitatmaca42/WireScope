from __future__ import annotations

import json

from typer.testing import CliRunner

from wirescope.cli import app

runner = CliRunner()


def test_cli_runs_default_analysis(sample_pcap_path):
    result = runner.invoke(app, [str(sample_pcap_path)])
    assert result.exit_code == 0
    assert "WireScope" in result.stdout
    assert "Capture Summary" in result.stdout


def test_cli_missing_file_gives_clean_error_not_traceback():
    result = runner.invoke(app, ["/no/such/file.pcap"])
    assert result.exit_code == 1
    assert "Traceback" not in result.output
    assert "Error" in result.output


def test_cli_unsupported_extension_gives_clean_error(tmp_path):
    bad = tmp_path / "not_a_pcap.txt"
    bad.write_text("hello")
    result = runner.invoke(app, [str(bad)])
    assert result.exit_code == 1
    assert "Traceback" not in result.output
    assert "Unsupported" in result.output


def test_cli_empty_capture_gives_clean_error(empty_pcap_path):
    result = runner.invoke(app, [str(empty_pcap_path)])
    assert result.exit_code == 1
    assert "Traceback" not in result.output


def test_cli_json_export_writes_valid_json(sample_pcap_path, tmp_path):
    out_path = tmp_path / "out.json"
    result = runner.invoke(app, [str(sample_pcap_path), "--json", str(out_path), "--quiet"])
    assert result.exit_code == 0
    assert out_path.exists()
    data = json.loads(out_path.read_text())
    assert data["capture"]["total_packets"] == 7


def test_cli_dns_flag_shows_dns_table(sample_pcap_path):
    result = runner.invoke(app, [str(sample_pcap_path), "--dns"])
    assert result.exit_code == 0
    assert "example.com" in result.stdout


def test_cli_ip_filter_reduces_output(sample_pcap_path, tmp_path):
    out_path = tmp_path / "out.json"
    result = runner.invoke(
        app, [str(sample_pcap_path), "--ip", "10.0.0.1", "--json", str(out_path), "--quiet"]
    )
    assert result.exit_code == 0
    data = json.loads(out_path.read_text())
    assert data["capture"]["total_packets"] == 2


def test_cli_verbose_debug_shows_traceback_on_error():
    result = runner.invoke(app, ["/no/such/file.pcap", "-vv"])
    assert result.exit_code == 1
    assert "Traceback" in result.output
