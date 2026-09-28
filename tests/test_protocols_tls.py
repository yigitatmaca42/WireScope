from __future__ import annotations

from wirescope.protocols.tls import parse_tls_client_hello


def _build_client_hello(sni_host: bytes) -> bytes:
    server_name_entry = bytes([0x00]) + len(sni_host).to_bytes(2, "big") + sni_host
    server_name_list = len(server_name_entry).to_bytes(2, "big") + server_name_entry
    sni_extension = (0x0000).to_bytes(2, "big") + len(server_name_list).to_bytes(2, "big") + server_name_list
    extensions = sni_extension
    body = (
        bytes([0x03, 0x03])  # client version
        + b"\x00" * 32  # random
        + bytes([0x00])  # session id length
        + (0x02).to_bytes(2, "big") + bytes([0x00, 0x2f])  # cipher suites
        + bytes([0x01, 0x00])  # compression methods
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
    return bytes([0x16, 0x03, 0x01]) + len(handshake).to_bytes(2, "big") + handshake


def test_parse_tls_client_hello_extracts_sni():
    payload = _build_client_hello(b"secure.example.net")
    info = parse_tls_client_hello(payload, "1.1.1.1", "2.2.2.2", 1.0)
    assert info is not None
    assert info.sni == "secure.example.net"
    assert info.record_version == "TLS 1.0"


def test_parse_tls_client_hello_different_sni():
    payload = _build_client_hello(b"a.b.c")
    info = parse_tls_client_hello(payload, "1.1.1.1", "2.2.2.2", 1.0)
    assert info.sni == "a.b.c"


def test_parse_tls_rejects_non_handshake_payload():
    assert parse_tls_client_hello(b"not tls at all" * 5, "a", "b", 1.0) is None


def test_parse_tls_rejects_short_payload():
    assert parse_tls_client_hello(b"\x16\x03\x01", "a", "b", 1.0) is None


def test_parse_tls_rejects_non_client_hello_handshake():
    # content type handshake, but handshake type is ServerHello (0x02), not ClientHello.
    payload = bytes([0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00]) + b"\x00" * 40
    assert parse_tls_client_hello(payload, "a", "b", 1.0) is None
