"""The edge server as the internet sees it (VPN off). Needs `domain`."""

from __future__ import annotations

import http.client
import socket
import ssl

import pytest

pytestmark = pytest.mark.external


def test_certificate_is_publicly_trusted(target) -> None:
    domain = target("domain")
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=domain) as tls:
            assert tls.version() in ("TLSv1.2", "TLSv1.3")


def test_http_redirects_to_https(target) -> None:
    domain = target("domain")
    connection = http.client.HTTPConnection(domain, 80, timeout=10)
    connection.request("GET", "/probe?x=1")
    response = connection.getresponse()
    assert response.status == 301
    assert response.getheader("Location") == f"https://{domain}/probe?x=1"


def test_sql_injection_probe_is_blocked(target) -> None:
    domain = target("domain")
    connection = http.client.HTTPSConnection(domain, 443, timeout=10, context=ssl.create_default_context())
    connection.request("GET", "/?id=1%27%20OR%20%271%27%3D%271")
    assert connection.getresponse().status == 403


def get(domain: str, path: str, cookie: str | None = None) -> http.client.HTTPResponse:
    connection = http.client.HTTPSConnection(domain, 443, timeout=10, context=ssl.create_default_context())
    headers = {"Cookie": f"__Host-secureedge={cookie}"} if cookie else {}
    connection.request("GET", path, headers=headers)
    return connection.getresponse()


def test_signed_in_browser_gets_the_app(target, session_cookie) -> None:
    assert get(target("domain"), "/", session_cookie).status == 200


def test_signed_in_api_call_works(target, session_cookie) -> None:
    assert get(target("domain"), "/api/v1/portfolios", session_cookie).status == 200


def test_api_without_a_session_is_refused(target, session_cookie) -> None:
    assert get(target("domain"), "/api/v1/portfolios").status == 401
