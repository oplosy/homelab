"""What tls and edge_proxy guarantee on the edge server.

Every request runs curl on the edge server against its own NGINX, with SNI
for the application's name. Checks that need a passing auth check or an
upstream start test-only stubs, so they run only in Molecule.
"""

from __future__ import annotations

import secrets
import shlex
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import pytest
import testinfra
from testinfra.utils.ansible_runner import AnsibleRunner

from support.commands import require_success
from support.inventory import group_for

pytestmark = pytest.mark.host

STUB = "/usr/local/lib/secureedge-test/http_stub.py"
AUDIT_LOG = "/var/log/nginx/modsec_audit.log"
SQL_INJECTION = "/?id=1%27%20OR%20%27{marker}%27%3D%27{marker}"
XSS = "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"


@pytest.fixture
def app(expected) -> dict:
    return expected["secureedge_app"]


def curl(host, domain: str, url: str, *options: str) -> str:
    args = ["curl", "-sk", "--max-time", "20",
            "--resolve", f"{domain}:443:127.0.0.1", "--resolve", f"{domain}:80:127.0.0.1",
            *options, url]
    return host.check_output(shlex.join(args))


def status(host, domain: str, url: str, *options: str) -> int:
    return int(curl(host, domain, url, "-o", "/dev/null", "-w", "%{http_code}", *options))


def certificate(host, domain: str) -> str:
    return host.check_output(
        f"echo | openssl s_client -connect 127.0.0.1:443 -servername {domain} 2>/dev/null"
        " | openssl x509 -noout -issuer -subject -serial -ext subjectAltName"
    )


def serial(host, domain: str) -> str:
    return next(line for line in certificate(host, domain).splitlines() if line.startswith("serial="))


@contextmanager
def stub(run: Callable[[str], str], unit: str, address: str, port: int, code: int) -> Iterator[Callable[[], str]]:
    log = f"/run/{unit}.log"
    run(f"rm -f {log}; systemd-run --unit={unit} --collect python3 {STUB} {address} {port} {code} {log}")
    try:
        run(f"for i in $(seq 100); do ss -Hltn | grep -q '{address}:{port} ' && exit 0; sleep 0.1; done; exit 1")
        yield lambda: run(f"cat {log} 2>/dev/null || true")
    finally:
        run(f"systemctl stop {unit} || true")


@pytest.fixture
def app_root(request: pytest.FixtureRequest) -> Callable[[str], str]:
    """Root shell on the app server, from a check running for the edge server."""
    inventory = request.config.getoption("ansible_inventory")
    name = next(h for h in AnsibleRunner(inventory).get_hosts("all") if group_for(h) == "app")
    other = testinfra.get_host(f"ansible://{name}?ansible_inventory={inventory}&force_ansible=True")

    def run(command: str) -> str:
        result = other.ansible("ansible.builtin.shell", command, become=True, check=False)
        return require_success(result, command)

    return run


@pytest.fixture
def stubs_allowed(edge_host, in_container) -> None:
    if not in_container:
        pytest.skip("stub checks start listeners; they run only in Molecule")


@pytest.fixture
def auth_stub(stubs_allowed, root) -> Iterator[Callable[[], str]]:
    with stub(root, "se-auth-stub", "127.0.0.1", 4180, 202) as requests:
        yield requests


@pytest.fixture
def upstream_stub(stubs_allowed, app_root, app) -> Iterator[Callable[[], str]]:
    upstream = app["upstream"]
    with stub(app_root, "se-upstream-stub", upstream["address"], upstream["port"], 200) as requests:
        yield requests


def test_nginx_runs_with_a_valid_config(edge_host, root) -> None:
    nginx = edge_host.service("nginx")
    assert nginx.is_enabled
    assert nginx.is_running
    root("nginx -t")


def test_responses_do_not_reveal_the_version(edge_host, app) -> None:
    domain = app["domain"]
    headers = curl(edge_host, domain, f"https://{domain}/", "-D", "-", "-o", "/dev/null")
    server = [line for line in headers.splitlines() if line.lower().startswith("server:")]
    assert server, headers
    assert "/" not in server[0]


def test_certificate_is_issued_not_the_placeholder(edge_host, app) -> None:
    domain = app["domain"]
    text = certificate(edge_host, domain)
    fields = dict(line.split("=", 1) for line in text.splitlines() if line.startswith(("issuer=", "subject=")))
    assert fields["issuer"] != fields["subject"], text
    assert f"DNS:{domain}" in text


@pytest.mark.disruptive
def test_renewal_installs_the_new_certificate(edge_host, root, app, expected) -> None:
    # On real servers this asks Let's Encrypt for a duplicate certificate,
    # which counts against its weekly limit of five.
    domain = app["domain"]
    before = serial(edge_host, domain)
    bundle = expected.get("tls_acme_ca_bundle", "")
    env = f"REQUESTS_CA_BUNDLE={bundle} " if bundle else ""
    root(f"{env}certbot renew --force-renewal --non-interactive --cert-name {app['name']}")
    for _ in range(50):
        if serial(edge_host, domain) != before:
            break
        time.sleep(0.1)
    assert serial(edge_host, domain) != before
    assert edge_host.service("nginx").is_running


def test_http_redirects_to_https(edge_host, app) -> None:
    domain = app["domain"]
    result = curl(edge_host, domain, f"http://{domain}/some/path?x=1",
                  "-o", "/dev/null", "-w", "%{http_code} %{redirect_url}")
    assert result == f"301 https://{domain}/some/path?x=1"


def test_acme_challenges_are_served_over_http(edge_host, root, app, expected) -> None:
    domain = app["domain"]
    challenges = expected.get("tls_webroot", "/var/lib/secureedge/acme") + "/.well-known/acme-challenge"
    token = secrets.token_hex(8)
    root(f"mkdir -p {challenges} && echo {token} > {challenges}/se-probe")
    try:
        assert curl(edge_host, domain, f"http://{domain}/.well-known/acme-challenge/se-probe").strip() == token
    finally:
        root(f"rm -f {challenges}/se-probe")


def test_unknown_names_get_no_tls_handshake(edge_host) -> None:
    other = edge_host.run("curl -sk --max-time 10 --resolve other.invalid:443:127.0.0.1 https://other.invalid/")
    assert other.rc == 35, other.stderr
    no_sni = edge_host.run("curl -sk --max-time 10 https://127.0.0.1/")
    assert no_sni.rc == 35, no_sni.stderr


@pytest.mark.parametrize("version", ["1.2", "1.3"])
def test_tls_versions_are_accepted(edge_host, app, version) -> None:
    domain = app["domain"]
    assert status(edge_host, domain, f"https://{domain}/", f"--tlsv{version}", "--tls-max", version) > 0


def test_security_headers_are_sent(edge_host, app, expected) -> None:
    domain = app["domain"]
    headers = curl(edge_host, domain, f"https://{domain}/", "-D", "-", "-o", "/dev/null").lower()
    max_age = expected.get("edge_proxy_hsts_max_age", 31536000)
    assert f"strict-transport-security: max-age={max_age}" in headers
    assert "x-content-type-options: nosniff" in headers
    assert "referrer-policy: same-origin" in headers
    assert "content-security-policy: frame-ancestors 'none'" in headers


@pytest.mark.parametrize("probe", [SQL_INJECTION.format(marker="se"), XSS], ids=["sql-injection", "xss"])
def test_waf_blocks_attacks_before_the_auth_check(edge_host, app, probe) -> None:
    # Without a session the auth check answers 500 (Molecule) or redirects;
    # 403 proves ModSecurity ran first.
    domain = app["domain"]
    assert status(edge_host, domain, f"https://{domain}{probe}") == 403


def test_waf_log_omits_cookies_and_bodies(edge_host, root, app) -> None:
    domain = app["domain"]
    secret = secrets.token_hex(16)
    marker = secrets.token_hex(6)
    before = int(root(f"stat -c %s {AUDIT_LOG} 2>/dev/null || echo 0"))
    code = status(edge_host, domain, f"https://{domain}{SQL_INJECTION.format(marker=marker)}",
                  "-H", f"Cookie: se_session={secret}", "--data", f"note={secret}")
    assert code == 403
    entry = ""
    for _ in range(50):
        entry = root(f"tail -c +{before + 1} {AUDIT_LOG}")
        if marker in entry:
            break
        time.sleep(0.1)
    assert marker in entry
    assert secret not in entry


def test_api_requests_are_rate_limited(edge_host, app) -> None:
    domain = app["domain"]
    url = f"https://{domain}{app['api_prefix']}rate-probe"
    count = app["rate_limits"]["api"]["burst"] * 3
    # One curl process, one connection: -o /dev/null URL repeated, the last
    # URL appended by curl().
    options = ["-w", "%{http_code}\n"] + ["-o", "/dev/null", url] * (count - 1) + ["-o", "/dev/null"]
    try:
        codes = curl(edge_host, domain, url, *options).split()
        assert "429" in codes, codes
    finally:
        time.sleep(3)  # let the bucket refill for later checks


def test_without_auth_nothing_reaches_the_app(edge_host, app, upstream_stub) -> None:
    domain = app["domain"]
    assert status(edge_host, domain, f"https://{domain}/") == 500
    assert status(edge_host, domain, f"https://{domain}{app['api_prefix']}v1/portfolios") == 500
    assert upstream_stub() == ""


def test_with_auth_requests_reach_the_app_over_wireguard(edge_host, app, auth_stub, upstream_stub) -> None:
    domain = app["domain"]
    prefix = app["api_prefix"]
    assert f"{app['name']} is not deployed yet" in curl(edge_host, domain, f"https://{domain}/")
    assert curl(edge_host, domain, f"https://{domain}{prefix}v1/portfolios").strip() == "secureedge-stub"
    assert f"GET {prefix}v1/portfolios" in upstream_stub()
    assert "/oauth2/auth" in auth_stub()


def test_unreachable_app_gives_502(edge_host, app, auth_stub) -> None:
    domain = app["domain"]
    assert status(edge_host, domain, f"https://{domain}{app['api_prefix']}v1/portfolios") == 502


def test_imports_up_to_the_body_limit_pass(edge_host, root, app, auth_stub, upstream_stub) -> None:
    domain = app["domain"]
    url = f"https://{domain}{app['api_prefix']}v1/imports/se-probe"
    root("head -c 11534336 /dev/zero | tr '\\0' a > /tmp/se-11m && "
         "head -c 13631488 /dev/zero | tr '\\0' a > /tmp/se-13m && chmod 0644 /tmp/se-11m /tmp/se-13m")
    try:
        accepted = status(edge_host, domain, url, "-F", "file=@/tmp/se-11m")
        rejected = status(edge_host, domain, url, "-F", "file=@/tmp/se-13m")
    finally:
        root("rm -f /tmp/se-11m /tmp/se-13m")
    assert accepted == 200
    assert rejected == 413


def test_large_json_api_bodies_pass_the_waf(edge_host, root, app, auth_stub, upstream_stub) -> None:
    domain = app["domain"]
    root(
        "python3 -c \"import json; print(json.dumps({'positions': [{'symbol': 'SYM%04d' % i, "
        "'quantity': i + 0.5, 'note': 'position note ' * 300} for i in range(200)]}))\" "
        "> /tmp/se-json.json && chmod 0644 /tmp/se-json.json"
    )
    try:
        code = status(edge_host, domain, f"https://{domain}{app['api_prefix']}v1/risk/runs",
                      "-H", "Content-Type: application/json", "--data-binary", "@/tmp/se-json.json")
    finally:
        root("rm -f /tmp/se-json.json")
    assert code == 200
