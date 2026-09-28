"""WireScope's command-line interface.

    wirescope capture.pcap
    wirescope capture.pcap --dns --http
    wirescope capture.pcap --ip 10.0.0.5 --protocol dns
    wirescope capture.pcap --json report.json --csv reports/ --html report.html

A single flag-based command, deliberately: mixing a positional "default"
command with separate subcommands runs into a real Click/Typer limitation
(the parser can't reliably tell a flag like --dns apart from an attempted
subcommand name once a Group has more than one command). One command with
clear, focused flags is both simpler and more robust.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from wirescope import reporting
from wirescope.analyzer import Analyzer
from wirescope.detection.heuristics import run_heuristics
from wirescope.detection.ioc import load_iocs, match_iocs
from wirescope.exceptions import WireScopeError
from wirescope.exporters import write_csv, write_html, write_json
from wirescope.filters import PacketFilter
from wirescope.models import AnalysisResult

app = typer.Typer(add_completion=False, no_args_is_help=True, help=__doc__)
console = Console()
error_console = Console(stderr=True)


def _build_filter(ip: list[str], port: list[int], protocol: list[str]) -> PacketFilter:
    return PacketFilter(
        ips=set(ip),
        ports=set(port),
        protocols={p.lower() for p in protocol},
    )


def _configure_logging(verbose: int) -> None:
    level = logging.WARNING
    if verbose == 1:
        level = logging.INFO
    elif verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


def _analyze_with_progress(pcap: Path, packet_filter: PacketFilter, verbose: int) -> AnalysisResult:
    analyzer = Analyzer(pcap, packet_filter)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("{task.fields[count]} packets"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Analyzing capture...", total=None, count=0)

        def on_progress(count: int) -> None:
            progress.update(task, count=f"{count:,}")

        try:
            result = analyzer.run(progress_callback=on_progress)
        except WireScopeError as exc:
            progress.stop()
            _print_clean_error(exc, verbose)
            raise typer.Exit(code=1) from None
    return result


def _print_clean_error(exc: Exception, verbose: int) -> None:
    error_console.print(f"[bold red]Error:[/bold red] {exc}")
    if verbose >= 2:
        error_console.print_exception()


def _apply_ioc(result: AnalysisResult, ioc_path: Path | None) -> None:
    if ioc_path is None:
        return
    try:
        iocs = load_iocs(ioc_path)
    except OSError as exc:
        error_console.print(f"[bold red]Error reading IOC file:[/bold red] {exc}")
        raise typer.Exit(code=1) from None
    if iocs.malformed_lines:
        examples = ", ".join(f"line {n}: {text!r}" for n, text in iocs.malformed_lines[:3])
        more = f" (+{len(iocs.malformed_lines) - 3} more)" if len(iocs.malformed_lines) > 3 else ""
        error_console.print(
            f"[yellow]Warning:[/yellow] {len(iocs.malformed_lines)} IOC line(s) were neither a "
            f"valid IP nor a plausible domain and were ignored: {examples}{more}"
        )
    result.findings.extend(match_iocs(result, iocs))


def _finish(result: AnalysisResult) -> None:
    ioc_findings = [f for f in result.findings if f.title.startswith("IOC match")]
    result.findings = run_heuristics(result) + ioc_findings


def _handle_exports(
    result: AnalysisResult,
    json_out: Path | None,
    csv_out: Path | None,
    html_out: Path | None,
) -> None:
    try:
        if json_out is not None:
            write_json(result, json_out)
            console.print(f"[green]JSON report written to[/green] {json_out}")
        if csv_out is not None:
            written = write_csv(result, csv_out)
            console.print(f"[green]CSV report written to[/green] {csv_out} ({len(written)} files)")
        if html_out is not None:
            write_html(result, html_out)
            console.print(f"[green]HTML report written to[/green] {html_out}")
    except OSError as exc:
        error_console.print(f"[bold red]Error writing report:[/bold red] {exc}")
        raise typer.Exit(code=1) from None


@app.command()
def main(
    pcap: Annotated[Path, typer.Argument(help="Path to a .pcap/.pcapng/.cap capture file.")],
    summary: Annotated[bool, typer.Option("--summary", help="Show only the capture summary + hosts/ports.")] = False,
    dns: Annotated[bool, typer.Option("--dns", help="Show DNS analysis.")] = False,
    http: Annotated[bool, typer.Option("--http", help="Show plaintext HTTP analysis.")] = False,
    tls: Annotated[bool, typer.Option("--tls", help="Show TLS/SNI analysis.")] = False,
    conversations: Annotated[bool, typer.Option("--conversations", help="Show top conversations/flows.")] = False,
    findings: Annotated[bool, typer.Option("--findings", help="Show heuristic findings.")] = False,
    ip: Annotated[list[str], typer.Option("--ip", help="Filter: only this/these IP(s) (repeatable).")] = [],  # noqa: B006
    port: Annotated[list[int], typer.Option("--port", help="Filter: only this/these port(s) (repeatable).")] = [],  # noqa: B006
    protocol: Annotated[
        list[str],
        typer.Option("--protocol", help="Filter: only this/these protocol(s) - tcp, udp, dns, http, tls, arp, icmp (repeatable)."),
    ] = [],  # noqa: B006
    ioc: Annotated[Path | None, typer.Option("--ioc", help="Path to a text file of IOC IPs/domains, one per line.")] = None,
    json_out: Annotated[Path | None, typer.Option("--json", help="Write a JSON report to this path.")] = None,
    csv_out: Annotated[Path | None, typer.Option("--csv", help="Write CSV reports into this directory.")] = None,
    html_out: Annotated[Path | None, typer.Option("--html", help="Write a standalone HTML report to this path.")] = None,
    verbose: Annotated[int, typer.Option("-v", "--verbose", count=True, help="Increase output verbosity (-v, -vv).")] = 0,
    quiet: Annotated[bool, typer.Option("-q", "--quiet", help="Suppress the terminal report (useful with --json/--csv/--html).")] = False,
) -> None:
    _configure_logging(verbose)
    try:
        packet_filter = _build_filter(ip, port, protocol)
        result = _analyze_with_progress(pcap, packet_filter, verbose)
        _finish(result)
        _apply_ioc(result, ioc)

        if not quiet:
            any_section = any([summary, dns, http, tls, conversations, findings])

            reporting.render_header(console, result)

            if not any_section or summary:
                reporting.render_summary(console, result)
                console.print()
                reporting.render_hosts(console, result)
                console.print()
                reporting.render_ports(console, result)
            if dns:
                console.print()
                reporting.render_dns(console, result)
            if http:
                console.print()
                reporting.render_http(console, result)
            if tls:
                console.print()
                reporting.render_tls(console, result)
            if conversations:
                console.print()
                reporting.render_conversations(console, result)
            if findings or not any_section:
                console.print()
                reporting.render_findings(console, result)

        _handle_exports(result, json_out, csv_out, html_out)
    except typer.Exit:
        # Already a clean, intentional exit (WireScopeError/IOC/export
        # errors above already printed their own message) - let it through
        # unchanged rather than treating it as an unexpected error below.
        raise
    except KeyboardInterrupt:
        error_console.print("\n[bold yellow]Analysis interrupted.[/bold yellow]")
        raise typer.Exit(code=130) from None
    except Exception as exc:  # noqa: BLE001 - last-resort net for genuinely
        # unexpected bugs; every known failure mode above already has its
        # own specific, clean handling. Exit code 2 distinguishes this from
        # the code-1 "bad input" exits above.
        _print_clean_error(exc, verbose)
        raise typer.Exit(code=2) from None


def _main() -> None:
    try:
        app()
    except WireScopeError as exc:  # safety net for anything that slips through
        error_console.print(f"[bold red]Error:[/bold red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    _main()
