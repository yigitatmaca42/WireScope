from __future__ import annotations

from wirescope.protocols.http import parse_http, parse_http_request, parse_http_response


def test_parse_http_request_basic():
    payload = b"GET /login HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test-agent\r\n\r\n"
    record = parse_http_request(payload, "1.1.1.1", "2.2.2.2", 1.0)
    assert record is not None
    assert record.method == "GET"
    assert record.path == "/login"
    assert record.host == "example.com"
    assert record.user_agent == "test-agent"
    assert record.direction == "request"


def test_parse_http_response_basic():
    payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx\r\n\r\n<html></html>"
    record = parse_http_response(payload, "2.2.2.2", "1.1.1.1", 1.0)
    assert record is not None
    assert record.status_code == 200
    assert record.content_type == "text/html"
    assert record.server == "nginx"
    assert record.direction == "response"


def test_parse_http_ignores_non_http_payload():
    assert parse_http(b"\x00\x01\x02binarygarbage", "a", "b", 1.0) is None


def test_parse_http_ignores_empty_payload():
    assert parse_http(b"", "a", "b", 1.0) is None


def test_parse_http_dispatches_request_and_response():
    req = b"POST /api HTTP/1.1\r\nHost: x\r\n\r\n"
    resp = b"HTTP/1.1 404 Not Found\r\n\r\n"
    assert parse_http(req, "a", "b", 1.0).direction == "request"
    assert parse_http(resp, "a", "b", 1.0).direction == "response"


def test_parse_http_request_missing_headers_leaves_fields_none():
    record = parse_http_request(b"GET /\r\n\r\n", "a", "b", 1.0)
    assert record is not None
    assert record.path == "/"
    assert record.host is None
    assert record.user_agent is None


def test_parse_http_host_header_is_case_insensitive():
    for header_name in (b"Host", b"host", b"HOST", b"HoSt"):
        payload = b"GET / HTTP/1.1\r\n" + header_name + b": example.com\r\n\r\n"
        record = parse_http_request(payload, "a", "b", 1.0)
        assert record is not None
        assert record.host == "example.com", f"failed for header name {header_name!r}"


def test_parse_http_post_and_head_methods_recognized():
    for method in (b"POST", b"HEAD"):
        payload = method + b" /x HTTP/1.1\r\nHost: h\r\n\r\n"
        record = parse_http_request(payload, "a", "b", 1.0)
        assert record is not None
        assert record.method == method.decode()


def test_parse_http_malformed_header_lines_are_skipped_not_fatal():
    """A header line with no colon must be ignored rather than raising."""
    payload = b"GET / HTTP/1.1\r\nNotAHeaderLine\r\nHost: example.com\r\n\r\n"
    record = parse_http_request(payload, "a", "b", 1.0)
    assert record is not None
    assert record.host == "example.com"


def test_parse_http_does_not_crash_on_random_garbage_of_various_lengths():
    """Fuzz-lite: a range of random byte strings must never raise - this is
    untrusted wire data. Random bytes essentially never happen to start with
    a real HTTP method or "HTTP/", so the expected result is None; the
    actual point of this test is that no exception escapes."""
    import os

    from wirescope.models import HttpTransaction

    for length in (0, 1, 5, 16, 64, 512, 4096):
        result = parse_http(os.urandom(length), "a", "b", 1.0)
        assert result is None or isinstance(result, HttpTransaction)


def test_parse_http_no_crlf_terminator_does_not_crash():
    """A payload with no \\r\\n\\r\\n terminator at all (truncated capture /
    small snaplen, only the start line present) must not raise. The parser
    is intentionally lenient here: it still extracts what it can from a
    bare start line, since a single unterminated request/status line is a
    common truncated-capture shape and is more useful reported than
    discarded."""
    request = parse_http(b"GET /never-ends-HTTP/1.1", "a", "b", 1.0)
    assert request is not None
    assert request.method == "GET"

    response = parse_http(b"HTTP/1.1 200", "a", "b", 1.0)
    assert response is not None
    assert response.status_code == 200
