"""Structured JSON export.

The schema is intentionally stable and flat-ish:
{
  "capture": {...},
  "statistics": {...},
  "hosts": [...],
  "ports": {"source": [...], "destination": [...]},
  "conversations": [...],
  "dns": [...],
  "http": [...],
  "tls": [...],
  "arp": [...],
  "findings": [...]
}
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from wirescope.models import AnalysisResult

SCHEMA_VERSION = "0.1.0"


def to_json_dict(result: AnalysisResult) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "capture": result.capture.as_dict(),
        "statistics": {
            "icmp": result.icmp_stats.as_dict(),
            "tcp_flags": result.tcp_flag_stats.as_dict(),
            "high_entropy_packet_count": result.high_entropy_packet_count,
            "collection_limits": result.limits.as_dict(),
        },
        "hosts": [h.as_dict() for h in result.top_hosts(n=len(result.hosts))],
        "ports": {
            "source": [p.as_dict() for p in result.top_ports_src(n=len(result.ports_src))],
            "destination": [p.as_dict() for p in result.top_ports_dst(n=len(result.ports_dst))],
        },
        "conversations": [c.as_dict() for c in result.top_conversations(n=len(result.conversations))],
        "dns": [d.as_dict() for d in result.dns_records],
        "http": [h.as_dict() for h in result.http_transactions],
        "tls": [t.as_dict() for t in result.tls_records],
        "arp": [a.as_dict() for a in result.arp_entries.values()],
        "findings": [f.as_dict() for f in result.findings],
    }


def write_json(result: AnalysisResult, path: str | Path) -> None:
    data = to_json_dict(result)
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, sort_keys=False), encoding="utf-8")
