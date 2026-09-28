"""Plaintext HTTP/1.x parsing from raw TCP payload bytes.

Scapy has no bundled, reliable HTTP layer (the old scapy_http contrib is
unmaintained and not installed by default), so this module parses the
handful of header lines WireScope needs directly out of the TCP payload.
This is intentionally narrow: it only recognizes a request/response line
plus a small set of headers, and it never tries to reassemble TCP streams
across multiple packets - a single-packet HTTP request/response line is
what CTF/lab captures almost always look like, and partial data is simply
skipped rather than guessed at.
"""

from __future__ import annotations

from wirescope.models import HttpTransaction

_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
)


def _split_headers(payload: bytes) -> tuple[str, dict[str, str]] | None:
    """Split raw payload into (start_line, headers). Returns None if this
    doesn't look like a well-formed HTTP header block."""
    try:
        head = payload.split(b"\r\n\r\n", 1)[0]
        lines = head.split(b"\r\n")
        start_line = lines[0].decode("latin-1", errors="replace")
    except Exception:
        return None

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        try:
            key, _, value = line.decode("latin-1", errors="replace").partition(":")
        except Exception:
            continue
        headers[key.strip().lower()] = value.strip()
    return start_line, headers


def parse_http_request(payload: bytes, src_ip: str, dst_ip: str, timestamp: float) -> HttpTransaction | None:
    if not payload.startswith(_METHODS):
        return None
    parsed = _split_headers(payload)
    if parsed is None:
        return None
    start_line, headers = parsed

    parts = start_line.split(" ", 2)
    if len(parts) < 2:
        return None
    method, path = parts[0], parts[1]

    return HttpTransaction(
        direction="request",
        src_ip=src_ip,
        dst_ip=dst_ip,
        timestamp=timestamp,
        method=method,
        host=headers.get("host"),
        path=path,
        user_agent=headers.get("user-agent"),
    )


def parse_http_response(payload: bytes, src_ip: str, dst_ip: str, timestamp: float) -> HttpTransaction | None:
    if not payload.startswith(b"HTTP/"):
        return None
    parsed = _split_headers(payload)
    if parsed is None:
        return None
    start_line, headers = parsed

    parts = start_line.split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        return None

    return HttpTransaction(
        direction="response",
        src_ip=src_ip,
        dst_ip=dst_ip,
        timestamp=timestamp,
        status_code=int(parts[1]),
        content_type=headers.get("content-type"),
        server=headers.get("server"),
    )


def parse_http(payload: bytes, src_ip: str, dst_ip: str, timestamp: float) -> HttpTransaction | None:
    """Try request first, then response. Returns None for anything else."""
    if not payload:
        return None
    record = parse_http_request(payload, src_ip, dst_ip, timestamp)
    if record is not None:
        return record
    return parse_http_response(payload, src_ip, dst_ip, timestamp)
