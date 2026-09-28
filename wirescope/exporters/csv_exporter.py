"""CSV export - one focused file per category rather than one giant sheet."""

from __future__ import annotations

import csv
from pathlib import Path

from wirescope.models import AnalysisResult


def _write_rows(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_csv(result: AnalysisResult, output_dir: str | Path) -> list[Path]:
    """Write hosts.csv, ports.csv, conversations.csv, dns.csv, http.csv,
    findings.csv into output_dir (created if missing). Returns the list of
    files written."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    hosts_path = out / "hosts.csv"
    _write_rows(
        hosts_path,
        ["ip", "packet_count", "bytes_sent", "bytes_received", "total_bytes", "unique_peers", "ports_used"],
        [
            {**h.as_dict(), "ports_used": ",".join(str(p) for p in h.as_dict()["ports_used"])}
            for h in result.top_hosts(n=len(result.hosts))
        ],
    )
    written.append(hosts_path)

    ports_path = out / "ports.csv"
    port_rows = [dict(p.as_dict(), direction="source") for p in result.top_ports_src(n=len(result.ports_src))]
    port_rows += [dict(p.as_dict(), direction="destination") for p in result.top_ports_dst(n=len(result.ports_dst))]
    _write_rows(ports_path, ["direction", "port", "protocol", "packet_count", "service_name"], port_rows)
    written.append(ports_path)

    convos_path = out / "conversations.csv"
    _write_rows(
        convos_path,
        ["src_ip", "src_port", "dst_ip", "dst_port", "protocol", "packet_count", "byte_count", "first_seen", "last_seen", "duration_seconds"],
        [c.as_dict() for c in result.top_conversations(n=len(result.conversations))],
    )
    written.append(convos_path)

    dns_path = out / "dns.csv"
    _write_rows(
        dns_path,
        ["query_name", "query_type", "source", "destination", "timestamp", "is_response", "response_code", "answers"],
        [{**d.as_dict(), "answers": ";".join(d.as_dict()["answers"])} for d in result.dns_records],
    )
    written.append(dns_path)

    http_path = out / "http.csv"
    _write_rows(
        http_path,
        ["direction", "src_ip", "dst_ip", "timestamp", "method", "host", "path", "user_agent", "status_code", "content_type", "server"],
        [h.as_dict() for h in result.http_transactions],
    )
    written.append(http_path)

    findings_path = out / "findings.csv"
    _write_rows(
        findings_path,
        ["title", "severity", "description", "evidence", "confidence", "host", "timestamp"],
        [f.as_dict() for f in result.findings],
    )
    written.append(findings_path)

    return written
