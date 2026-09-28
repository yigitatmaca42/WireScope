"""Rich-based terminal output. Clean and table-driven, no ASCII banners."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from wirescope.models import AnalysisResult, Severity
from wirescope.utils.formatting import human_bytes, human_duration, human_timestamp

_SEVERITY_STYLE = {
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "yellow",
    Severity.INFO: "cyan",
}


def render_header(console: Console, result: AnalysisResult) -> None:
    cap = result.capture
    console.print(f"[bold]WireScope[/bold]  [dim]{cap.file_name}[/dim]")
    console.print(
        f"Packets: [bold]{cap.total_packets:,}[/bold]   "
        f"Duration: [bold]{human_duration(cap.duration_seconds)}[/bold]   "
        f"Size: [bold]{human_bytes(cap.total_bytes)}[/bold]"
    )
    if result.malformed_packet_count:
        console.print(
            f"[yellow]{result.malformed_packet_count} packet(s) could not be parsed and were skipped.[/yellow]"
        )
    console.print()


def render_summary(console: Console, result: AnalysisResult) -> None:
    cap = result.capture
    table = Table(title="Capture Summary", show_header=False, box=None, padding=(0, 2, 0, 0))
    table.add_row("File size", human_bytes(cap.file_size_bytes))
    table.add_row("Capture start", human_timestamp(cap.capture_start))
    table.add_row("Capture end", human_timestamp(cap.capture_end))
    table.add_row("Duration", human_duration(cap.duration_seconds))
    table.add_row("Total packets", f"{cap.total_packets:,}")
    table.add_row("Total bytes", human_bytes(cap.total_bytes))
    table.add_row("Average packet size", f"{cap.average_packet_size:.1f} B")
    table.add_row("Packets / second", f"{cap.packets_per_second:.2f}")
    table.add_row("Bytes / second", human_bytes(cap.bytes_per_second))
    console.print(table)
    console.print()

    proto_table = Table(title="Protocols")
    proto_table.add_column("Protocol")
    proto_table.add_column("Packets", justify="right")
    for name, count in cap.protocol_counts.as_dict().items():
        if count:
            proto_table.add_row(name.upper(), f"{count:,}")
    console.print(proto_table)


def render_hosts(console: Console, result: AnalysisResult, limit: int = 10) -> None:
    table = Table(title=f"Top Hosts (by packets, top {limit})")
    table.add_column("IP")
    table.add_column("Packets", justify="right")
    table.add_column("Bytes Sent", justify="right")
    table.add_column("Bytes Received", justify="right")
    table.add_column("Peers", justify="right")
    table.add_column("Ports Used", justify="right")
    for host in result.top_hosts(limit):
        table.add_row(
            host.ip,
            f"{host.packet_count:,}",
            human_bytes(host.bytes_sent),
            human_bytes(host.bytes_received),
            str(len(host.peers)),
            str(len(host.ports_used)),
        )
    console.print(table)


def render_ports(console: Console, result: AnalysisResult, limit: int = 10) -> None:
    for title, ports in (("Top Source Ports", result.top_ports_src(limit)), ("Top Destination Ports", result.top_ports_dst(limit))):
        table = Table(title=title)
        table.add_column("Port")
        table.add_column("Protocol")
        table.add_column("Service")
        table.add_column("Packets", justify="right")
        for p in ports:
            table.add_row(str(p.port), p.protocol, p.service_name or "-", f"{p.packet_count:,}")
        console.print(table)


def render_conversations(console: Console, result: AnalysisResult, limit: int = 15) -> None:
    table = Table(title=f"Top Conversations (by bytes, top {limit})")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Protocol")
    table.add_column("Packets", justify="right")
    table.add_column("Bytes", justify="right")
    table.add_column("Duration", justify="right")
    for c in result.top_conversations(limit):
        table.add_row(
            f"{c.src_ip}:{c.src_port}" if c.src_port is not None else c.src_ip,
            f"{c.dst_ip}:{c.dst_port}" if c.dst_port is not None else c.dst_ip,
            c.protocol,
            f"{c.packet_count:,}",
            human_bytes(c.byte_count),
            human_duration(c.duration_seconds),
        )
    console.print(table)


def render_dns(console: Console, result: AnalysisResult, limit: int = 30) -> None:
    table = Table(title=f"DNS (showing up to {limit} of {len(result.dns_records)})")
    table.add_column("Time")
    table.add_column("Query")
    table.add_column("Type")
    table.add_column("Source")
    table.add_column("Kind")
    table.add_column("Response Code")
    for record in result.dns_records[:limit]:
        table.add_row(
            human_timestamp(record.timestamp),
            record.query_name,
            record.query_type,
            record.source,
            "response" if record.is_response else "query",
            record.response_code or "-",
        )
    console.print(table)
    if result.limits.dns_truncated:
        console.print("[yellow]DNS collection limit reached - some records were not retained.[/yellow]")

    unique_domains = {r.query_name for r in result.dns_records if not r.is_response}
    nxdomain = sum(1 for r in result.dns_records if r.is_response and r.response_code == "NXDOMAIN")
    console.print(f"Unique domains queried: [bold]{len(unique_domains)}[/bold]   NXDOMAIN responses: [bold]{nxdomain}[/bold]")


def render_http(console: Console, result: AnalysisResult, limit: int = 30) -> None:
    table = Table(title=f"HTTP (showing up to {limit} of {len(result.http_transactions)})")
    table.add_column("Time")
    table.add_column("Dir")
    table.add_column("Method/Status")
    table.add_column("Host")
    table.add_column("Path")
    table.add_column("User-Agent / Server")
    for t in result.http_transactions[:limit]:
        table.add_row(
            human_timestamp(t.timestamp),
            t.direction,
            t.method or (str(t.status_code) if t.status_code else "-"),
            t.host or "-",
            t.path or "-",
            t.user_agent or t.server or "-",
        )
    console.print(table)


def render_tls(console: Console, result: AnalysisResult, limit: int = 30) -> None:
    table = Table(title=f"TLS ClientHello / SNI (showing up to {limit} of {len(result.tls_records)})")
    table.add_column("Time")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("SNI")
    table.add_column("Record Version")
    for t in result.tls_records[:limit]:
        table.add_row(human_timestamp(t.timestamp), t.src_ip, t.dst_ip, t.sni or "-", t.record_version or "-")
    console.print(table)


def render_findings(console: Console, result: AnalysisResult) -> None:
    if not result.findings:
        console.print("[dim]No heuristic findings were raised for this capture.[/dim]")
        return
    table = Table(title=f"Findings ({len(result.findings)})")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Evidence")
    table.add_column("Confidence")
    for f in result.findings:
        style = _SEVERITY_STYLE[f.severity]
        table.add_row(f"[{style}]{f.severity.value}[/{style}]", f.title, f.evidence, f.confidence)
    console.print(table)
    console.print(
        "[dim]WireScope is a triage aid, not an IDS - findings are hedged hypotheses "
        "for review, not confirmed verdicts.[/dim]"
    )
