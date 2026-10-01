"""Static HTML forensic report.

No external CDN dependencies, no heavy charting library: the handful of
visualizations are hand-built inline SVG bar charts, and section
collapsing uses native <details>/<summary> instead of JavaScript. The
report is a single self-contained file that opens fine straight off disk.
"""

from __future__ import annotations

import html
from pathlib import Path

from wirescope import __version__
from wirescope.models import AnalysisResult
from wirescope.utils.formatting import human_bytes, human_duration, human_timestamp
from wirescope.utils.timeline import bucketize_timeline

_CSS = """
:root {
  --bg: #0b0d12; --bg-elevated: #12151c; --surface: #171b24; --border: #262b36;
  --text: #e7eaf0; --text-muted: #9aa3b2; --accent: #4dc3ff; --accent-soft: rgba(77,195,255,.12);
  --high: #ff5d6c; --medium: #ffb15c; --low: #ffe27a; --info: #7fd9a6;
}
* { box-sizing: border-box; }
body {
  background: var(--bg); color: var(--text); margin: 0;
  font: 15px/1.55 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
header { padding: 2.5rem 2rem 1.5rem; border-bottom: 1px solid var(--border); }
header h1 { margin: 0 0 .25rem; font-size: 1.8rem; letter-spacing: -0.02em; }
header .tagline { color: var(--text-muted); font-size: .95rem; }
main { max-width: 1080px; margin: 0 auto; padding: 2rem; }
section { margin-bottom: 2.5rem; }
h2 { font-size: 1.05rem; text-transform: uppercase; letter-spacing: .08em;
     color: var(--text-muted); border-bottom: 1px solid var(--border); padding-bottom: .5rem; }
.stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; }
.stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1rem; }
.stat-card .value { font-size: 1.4rem; font-weight: 600; }
.stat-card .label { color: var(--text-muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .06em; }
table { width: 100%; border-collapse: collapse; font-size: .88rem; }
th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid var(--border); }
th { color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: .72rem; letter-spacing: .05em; }
tr:hover td { background: var(--bg-elevated); }
.mono { font-family: "SFMono-Regular", Consolas, monospace; }
.badge { display: inline-block; padding: .15rem .5rem; border-radius: 999px; font-size: .72rem; font-weight: 600; }
.badge.HIGH { background: rgba(255,93,108,.15); color: var(--high); }
.badge.MEDIUM { background: rgba(255,177,92,.15); color: var(--medium); }
.badge.LOW { background: rgba(255,226,122,.15); color: var(--low); }
.badge.INFO { background: rgba(127,217,166,.15); color: var(--info); }
.bar-row { display: flex; align-items: center; gap: .6rem; margin: .35rem 0; font-size: .85rem; }
.bar-label { width: 160px; flex-shrink: 0; color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bar-track { flex: 1; background: var(--bg-elevated); border-radius: 4px; height: 14px; overflow: hidden; }
.bar-fill { height: 100%; background: var(--accent); }
.bar-value { width: 90px; text-align: right; color: var(--text-muted); font-size: .78rem; }
.empty { color: var(--text-muted); font-style: italic; padding: .5rem 0; }
footer { text-align: center; color: var(--text-muted); font-size: .78rem; padding: 2rem; }
details > summary { cursor: pointer; }
.finding { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1rem; margin-bottom: .75rem; }
.finding .title { font-weight: 600; }
.finding .evidence { color: var(--text-muted); font-size: .82rem; margin-top: .4rem; }
.caveat { color: var(--text-muted); font-size: .82rem; margin: .5rem 0 1rem; }
.table-wrap { overflow-x: auto; }
@media (max-width: 480px) {
  header { padding: 1.5rem 1rem 1rem; }
  main { padding: 1rem; }
  .bar-label { width: 90px; }
  .bar-value { width: 60px; font-size: .72rem; }
}
@media print {
  body { background: #fff; color: #000; }
  .bar-track, .badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
"""


def _esc(value: object) -> str:
    return html.escape(str(value)) if value is not None else ""


def _bar_chart(rows: list[tuple[str, float, str]]) -> str:
    """rows: list of (label, value, display_value). Renders horizontal bars
    scaled to the max value in the set."""
    if not rows:
        return "<p class='empty'>No data.</p>"
    max_value = max(v for _, v, _ in rows) or 1
    parts = []
    for label, value, display in rows:
        pct = max(2, round((value / max_value) * 100))
        parts.append(
            f"<div class='bar-row'>"
            f"<div class='bar-label mono' title='{_esc(label)}'>{_esc(label)}</div>"
            f"<div class='bar-track'><div class='bar-fill' style='width:{pct}%'></div></div>"
            f"<div class='bar-value'>{_esc(display)}</div>"
            f"</div>"
        )
    return "".join(parts)


def _timeline_svg(result: AnalysisResult, width: int = 1000, height: int = 140) -> str:
    buckets = bucketize_timeline(result.timeline, num_buckets=48)
    if not buckets:
        return "<p class='empty'>No timeline data.</p>"
    max_packets = max(p for _, p, _ in buckets) or 1
    bar_width = width / len(buckets)
    bars = []
    for i, (_, packets, _) in enumerate(buckets):
        bar_height = (packets / max_packets) * (height - 20)
        x = i * bar_width
        y = height - bar_height
        bars.append(
            f"<rect x='{x:.1f}' y='{y:.1f}' width='{max(bar_width - 1, 1):.1f}' "
            f"height='{bar_height:.1f}' fill='#4dc3ff' opacity='0.85'><title>{packets} packets</title></rect>"
        )
    return (
        f"<svg viewBox='0 0 {width} {height}' width='100%' height='{height}' "
        f"role='img' aria-label='Packets per time bucket'>{''.join(bars)}</svg>"
    )


def _table(headers: list[str], rows: list[list[str]], empty_message: str) -> str:
    if not rows:
        return f"<p class='empty'>{_esc(empty_message)}</p>"
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows
    )
    return f"<div class='table-wrap'><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"


def render_html(result: AnalysisResult) -> str:
    cap = result.capture

    stat_cards = "".join(
        f"<div class='stat-card'><div class='value'>{_esc(v)}</div><div class='label'>{_esc(k)}</div></div>"
        for k, v in [
            ("Total Packets", f"{cap.total_packets:,}"),
            ("Total Size", human_bytes(cap.total_bytes)),
            ("Duration", human_duration(cap.duration_seconds)),
            ("Avg Packet Size", f"{cap.average_packet_size:.0f} B"),
            ("Packets / sec", f"{cap.packets_per_second:.1f}"),
            ("Bytes / sec", human_bytes(cap.bytes_per_second)),
            ("Hosts", f"{len(result.hosts):,}"),
            ("Conversations", f"{len(result.conversations):,}"),
        ]
    )

    proto = cap.protocol_counts.as_dict()
    protocol_bars = _bar_chart(
        [(name.upper(), count, f"{count:,}") for name, count in proto.items() if count > 0]
    )

    top_hosts = result.top_hosts(15)
    host_bars = _bar_chart(
        [(h.ip, h.total_bytes, human_bytes(h.total_bytes)) for h in top_hosts]
    )
    host_rows = [
        [
            f"<span class='mono'>{_esc(h.ip)}</span>",
            f"{h.packet_count:,}",
            human_bytes(h.bytes_sent),
            human_bytes(h.bytes_received),
            str(len(h.peers)),
            str(len(h.ports_used)),
        ]
        for h in top_hosts
    ]

    top_ports = result.top_ports_dst(15)
    port_bars = _bar_chart(
        [
            (f"{p.port}/{p.protocol}" + (f" ({p.service_name})" if p.service_name else ""), p.packet_count, f"{p.packet_count:,}")
            for p in top_ports
        ]
    )

    dns_rows = [
        [
            human_timestamp(d.timestamp),
            _esc(d.query_name),
            _esc(d.query_type),
            _esc(d.source),
            "response" if d.is_response else "query",
            _esc(d.response_code or "-"),
            _esc(", ".join(d.answers) or "-"),
        ]
        for d in result.dns_records[:200]
    ]

    http_rows = [
        [
            human_timestamp(t.timestamp),
            _esc(t.direction),
            f"{_esc(t.method or '-')} {_esc(t.path or '')}".strip(),
            _esc(t.host or "-"),
            _esc(t.status_code if t.status_code is not None else "-"),
            _esc(t.user_agent or t.server or "-"),
        ]
        for t in result.http_transactions[:200]
    ]

    tls_rows = [
        [human_timestamp(t.timestamp), _esc(t.src_ip), _esc(t.dst_ip), _esc(t.sni or "-"), _esc(t.record_version or "-")]
        for t in result.tls_records[:200]
    ]

    convo_rows = [
        [
            f"{_esc(c.src_ip)}:{_esc(c.src_port)}",
            f"{_esc(c.dst_ip)}:{_esc(c.dst_port)}",
            _esc(c.protocol),
            f"{c.packet_count:,}",
            human_bytes(c.byte_count),
            human_duration(c.duration_seconds),
        ]
        for c in result.top_conversations(50)
    ]

    findings_html = "".join(
        f"""<div class="finding">
            <div class="title"><span class="badge {f.severity.value}">{f.severity.value}</span> {_esc(f.title)}</div>
            <div>{_esc(f.description)}</div>
            <div class="evidence">Evidence: {_esc(f.evidence)} &middot; Confidence: {_esc(f.confidence)}{f' &middot; Host: {_esc(f.host)}' if f.host else ''}</div>
        </div>"""
        for f in result.findings
    ) or "<p class='empty'>No heuristic findings were raised for this capture.</p>"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WireScope Report - {_esc(cap.file_name)}</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <h1>WireScope</h1>
  <div class="tagline">Network Forensics Report &middot; {_esc(cap.file_name)} &middot; generated offline, no external resources</div>
</header>
<main>

<section>
  <h2>Capture Overview</h2>
  <div class="stat-grid">{stat_cards}</div>
  {f"<p class='caveat'>{result.malformed_packet_count} packet(s) could not be parsed and were skipped rather than aborting the analysis.</p>" if result.malformed_packet_count else ""}
</section>

<section>
  <h2>Activity Timeline</h2>
  <p class="caveat">Packets per time bucket across the capture duration.</p>
  {_timeline_svg(result)}
</section>

<section>
  <h2>Protocol Distribution</h2>
  {protocol_bars}
</section>

<section>
  <h2>Top Hosts</h2>
  {host_bars}
  {_table(["IP", "Packets", "Bytes Sent", "Bytes Received", "Unique Peers", "Ports Used"], host_rows, "No host data.")}
</section>

<section>
  <h2>Top Ports (Destination)</h2>
  {port_bars}
</section>

<section>
  <h2>DNS</h2>
  <p class="caveat">Showing up to 200 of {len(result.dns_records)} DNS record(s).{" DNS collection limit was reached - some records were not retained." if result.limits.dns_truncated else ""}</p>
  {_table(["Time", "Query", "Type", "Source", "Kind", "Response Code", "Answers"], dns_rows, "No DNS traffic observed.")}
</section>

<section>
  <h2>HTTP</h2>
  <p class="caveat">Plaintext HTTP only - TLS-encrypted traffic is never decrypted. Showing up to 200 of {len(result.http_transactions)} transaction(s).</p>
  {_table(["Time", "Direction", "Request", "Host", "Status", "User-Agent / Server"], http_rows, "No plaintext HTTP traffic observed.")}
</section>

<section>
  <h2>TLS</h2>
  <p class="caveat">SNI metadata only, extracted from ClientHello. Showing up to 200 of {len(result.tls_records)} handshake(s).</p>
  {_table(["Time", "Source", "Destination", "SNI", "Record Version"], tls_rows, "No TLS handshakes observed.")}
</section>

<section>
  <h2>Conversations</h2>
  <p class="caveat">Top 50 by byte count, out of {len(result.conversations)} total.</p>
  {_table(["Source", "Destination", "Protocol", "Packets", "Bytes", "Duration"], convo_rows, "No conversations recorded.")}
</section>

<section>
  <h2>Findings</h2>
  <p class="caveat">WireScope is a triage aid, not an intrusion detection system. Findings are hedged
  hypotheses for an analyst to review, not confirmed verdicts - false positives are expected.</p>
  {findings_html}
</section>

</main>
<footer>Generated by WireScope {__version__} &middot; offline PCAP analysis, no network activity performed.</footer>
</body>
</html>
"""


def write_html(result: AnalysisResult, path: str | Path) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(result), encoding="utf-8")
