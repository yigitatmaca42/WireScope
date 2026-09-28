"""Minimal TLS ClientHello parsing - SNI extraction only.

WireScope never attempts to decrypt TLS and does not parse certificates
(X.509 parsing correctly is its own substantial project; a half-reliable
implementation would be worse than none, per the "don't overclaim" rule).
This module reads just enough of the record + handshake header to find the
Server Name Indication extension, entirely by hand - no external TLS
library dependency.
"""

from __future__ import annotations

from wirescope.models import TlsInfo

_RECORD_VERSIONS = {
    (3, 1): "TLS 1.0",
    (3, 2): "TLS 1.1",
    (3, 3): "TLS 1.2 / TLS 1.3 (record layer)",
}

_HANDSHAKE_CLIENT_HELLO = 0x01
_CONTENT_TYPE_HANDSHAKE = 0x16
_EXTENSION_SNI = 0x0000


def _extract_sni(extensions: bytes) -> str | None:
    offset = 0
    while offset + 4 <= len(extensions):
        ext_type = int.from_bytes(extensions[offset : offset + 2], "big")
        ext_len = int.from_bytes(extensions[offset + 2 : offset + 4], "big")
        ext_data = extensions[offset + 4 : offset + 4 + ext_len]
        if ext_type == _EXTENSION_SNI and len(ext_data) >= 2:
            list_len = int.from_bytes(ext_data[0:2], "big")
            server_name_list = ext_data[2 : 2 + list_len]
            pos = 0
            while pos + 3 <= len(server_name_list):
                name_type = server_name_list[pos]
                name_len = int.from_bytes(server_name_list[pos + 1 : pos + 3], "big")
                name = server_name_list[pos + 3 : pos + 3 + name_len]
                if name_type == 0:  # host_name
                    try:
                        return name.decode("ascii")
                    except UnicodeDecodeError:
                        return name.decode("latin-1", errors="replace")
                pos += 3 + name_len
        offset += 4 + ext_len
    return None


def parse_tls_client_hello(
    payload: bytes, src_ip: str, dst_ip: str, timestamp: float
) -> TlsInfo | None:
    """Parse a TCP payload that is expected to start with a TLS record
    containing a ClientHello. Returns None for anything that doesn't match,
    rather than guessing."""
    if len(payload) < 43 or payload[0] != _CONTENT_TYPE_HANDSHAKE:
        return None

    record_major, record_minor = payload[1], payload[2]
    # Truncated captures (small snaplen) are common; we don't validate the
    # declared record length against the actual payload length and just
    # parse whatever bytes are present.
    if payload[5] != _HANDSHAKE_CLIENT_HELLO:
        return None

    pos = 5  # after the 5-byte record header (type + version + length)
    pos += 4  # handshake header: 1 type byte + 3 length bytes
    pos += 2  # client version
    pos += 32  # random
    if pos >= len(payload):
        return None

    session_id_len = payload[pos]
    pos += 1 + session_id_len
    if pos + 2 > len(payload):
        return None

    cipher_suites_len = int.from_bytes(payload[pos : pos + 2], "big")
    pos += 2 + cipher_suites_len
    if pos + 1 > len(payload):
        return None

    compression_len = payload[pos]
    pos += 1 + compression_len
    if pos + 2 > len(payload):
        return None

    extensions_total_len = int.from_bytes(payload[pos : pos + 2], "big")
    pos += 2
    extensions = payload[pos : pos + extensions_total_len]

    sni = _extract_sni(extensions) if extensions else None

    return TlsInfo(
        src_ip=src_ip,
        dst_ip=dst_ip,
        timestamp=timestamp,
        sni=sni,
        record_version=_RECORD_VERSIONS.get((record_major, record_minor), "unknown"),
    )
