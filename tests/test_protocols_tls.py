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


def _build_client_hello_with_leading_unknown_extension(sni_host: bytes) -> bytes:
    """Same as _build_client_hello but with an unrecognized extension type
    placed before the SNI extension - the parser must walk past it using
    its declared length rather than assuming SNI is first."""
    unknown_extension = (0x00FF).to_bytes(2, "big") + (0x0004).to_bytes(2, "big") + b"\xde\xad\xbe\xef"

    server_name_entry = bytes([0x00]) + len(sni_host).to_bytes(2, "big") + sni_host
    server_name_list = len(server_name_entry).to_bytes(2, "big") + server_name_entry
    sni_extension = (0x0000).to_bytes(2, "big") + len(server_name_list).to_bytes(2, "big") + server_name_list

    extensions = unknown_extension + sni_extension
    body = (
        bytes([0x03, 0x03])
        + b"\x00" * 32
        + bytes([0x00])
        + (0x02).to_bytes(2, "big") + bytes([0x00, 0x2f])
        + bytes([0x01, 0x00])
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
    return bytes([0x16, 0x03, 0x01]) + len(handshake).to_bytes(2, "big") + handshake


def test_parse_tls_finds_sni_past_an_unknown_leading_extension():
    payload = _build_client_hello_with_leading_unknown_extension(b"secure.example.net")
    info = parse_tls_client_hello(payload, "a", "b", 1.0)
    assert info is not None
    assert info.sni == "secure.example.net"


def test_parse_tls_truncated_at_every_offset_never_raises():
    """A capture with a small snaplen can hand us a ClientHello cut off at
    any byte boundary. None of those truncations should raise - each must
    either parse partial-but-safe data or return None."""
    full_payload = _build_client_hello(b"secure.example.net")
    for cut in range(len(full_payload)):
        result = parse_tls_client_hello(full_payload[:cut], "a", "b", 1.0)
        assert result is None or result.sni is None or isinstance(result.sni, str)


def test_parse_tls_does_not_crash_on_random_garbage_of_various_lengths():
    """Fuzz-lite: random bytes must never raise, even when they happen to
    pass the first two header-byte checks by chance."""
    import os

    for length in (0, 1, 5, 16, 43, 64, 512, 4096):
        garbage = bytearray(os.urandom(length))
        if len(garbage) > 5:
            garbage[0] = 0x16  # force content-type=handshake so more of the
            garbage[5] = 0x01  # parser's internal logic actually gets exercised
        result = parse_tls_client_hello(bytes(garbage), "a", "b", 1.0)
        assert result is None or result.sni is None or isinstance(result.sni, str)
