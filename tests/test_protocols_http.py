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
