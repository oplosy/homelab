"""What tls and edge_proxy guarantee on the edge server.

Every request runs curl on the edge server against its own NGINX, with SNI
for the application's name. Checks that need a passing auth check or an
upstream start test-only stubs, so they run only in Molecule.
"""

from __future__ import annotations

import json
import secrets
import shlex
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from urllib.parse import parse_qs, urlsplit

import pytest
import testinfra
from testinfra.utils.ansible_runner import AnsibleRunner

from support.commands import require_success
from support.inventory import group_for

pytestmark = pytest.mark.host

STUB = "/usr/local/lib/secureedge-test/http_stub.py"
AUDIT_LOG = "/var/log/modsecurity/audit.log"
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


def wait_for_port(run: Callable[[str], str], address: str, port: int) -> None:
    run(f"for i in $(seq 100); do ss -Hltn | grep -q '{address}:{port} ' && exit 0; sleep 0.1; done; exit 1")


@contextmanager
def stub(run: Callable[[str], str], unit: str, address: str, port: int, code: int) -> Iterator[Callable[[], str]]:
    log = f"/run/{unit}.log"
    run(f"rm -f {log}; systemd-run --unit={unit} --collect python3 {STUB} {address} {port} {code} {log}")
    try:
        wait_for_port(run, address, port)
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
    # oauth2-proxy holds 127.0.0.1:4180: stop it for the stub, start it after.
    root("systemctl stop oauth2-proxy")
    try:
        with stub(root, "se-auth-stub", "127.0.0.1", 4180, 202) as requests:
            yield requests
    finally:
        root("systemctl start oauth2-proxy")
        wait_for_port(root, "127.0.0.1", 4180)


@pytest.fixture
def upstream_stub(stubs_allowed, app_root, app) -> Iterator[Callable[[], str]]:
    # The release's API holds the upstream port: stop it for the stub.
    compose = "docker compose --project-directory /etc/atlasrisk"
    if app.get("release"):
        app_root(f"{compose} stop api")
    try:
        upstream = app["upstream"]
        with stub(app_root, "se-upstream-stub", upstream["address"], upstream["port"], 200) as requests:
            yield requests
    finally:
        if app.get("release"):
            app_root(f"{compose} start api")


@pytest.fixture
def release(app) -> dict:
    if not app.get("release"):
        pytest.skip("no AtlasRisk release is configured yet")
    return app["release"]


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


def test_other_host_headers_get_no_page(edge_host, app) -> None:
    # SNI matches the app, Host does not: NGINX falls back to the default
    # server, which must not serve anything or reveal its version.
    domain = app["domain"]
    result = edge_host.run(shlex.join([
        "curl", "-sk", "--max-time", "10", "--resolve", f"{domain}:443:127.0.0.1",
        "-H", "Host: other.invalid", "-D", "-", "-o", "/dev/null", "-w", "\n%{http_code}",
        f"https://{domain}/",
    ]))
    lines = result.stdout.strip().splitlines()
    assert not lines or not lines[-1].startswith("2"), result.stdout
    assert "nginx/" not in result.stdout


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


def test_oauth2_proxy_runs_unprivileged_on_localhost(edge_host, root) -> None:
    service = edge_host.service("oauth2-proxy")
    assert service.is_enabled
    assert service.is_running
    assert root("systemctl show -p User --value oauth2-proxy") == "oauth2-proxy"
    listeners = root("ss -Hltnp | grep oauth2-proxy || true").splitlines()
    assert listeners
    assert all("127.0.0.1:4180 " in line for line in listeners), listeners
    assert root("stat -c '%U %G %a' /etc/oauth2-proxy/oauth2-proxy.cfg") == "root oauth2-proxy 640"
    assert root("stat -c '%U %a' /etc/oauth2-proxy/oauth2-proxy.env") == "root 600"


def test_browser_routes_redirect_to_login(edge_host, app) -> None:
    domain = app["domain"]
    result = curl(edge_host, domain, f"https://{domain}/some/page",
                  "-o", "/dev/null", "-w", "%{http_code} %{redirect_url}")
    assert result == f"302 https://{domain}/oauth2/start?rd=/some/page"


def test_login_starts_at_github(edge_host, app, expected) -> None:
    domain = app["domain"]
    result = curl(edge_host, domain, f"https://{domain}/oauth2/start?rd=%2F",
                  "-o", "/dev/null", "-w", "%{http_code} %{redirect_url}")
    code, location = result.split(" ", 1)
    assert code == "302"
    assert location.startswith("https://github.com/login/oauth/authorize?"), location
    query = parse_qs(urlsplit(location).query)
    # Molecule keeps the throwaway client id in group_vars; production keeps
    # it in the vault, which the expected settings don't read.
    client_id = expected.get("vault_oauth2_proxy_client_id")
    assert query["client_id"] == [client_id] if client_id else query["client_id"]
    assert query["redirect_uri"] == [f"https://{domain}/oauth2/callback"]
    assert set(query["scope"][0].split()) == {"user:email", "read:org"}


@pytest.mark.parametrize(
    "headers",
    [[], ["Origin: https://evil.example"], ["Origin: https://{domain}", "Sec-Fetch-Site: cross-site"]],
    ids=["no-origin", "other-origin", "cross-site-fetch"],
)
def test_cross_site_writes_are_refused_before_auth(edge_host, app, headers) -> None:
    # Without a session the auth check would answer 401: 403 proves the
    # origin check runs first. The same-origin control must reach the auth
    # check (401).
    domain = app["domain"]
    url = f"https://{domain}{app['api_prefix']}v1/decisions"
    options = ["-X", "POST", "-H", "Content-Type: application/json", "--data", "{}"]
    for header in headers:
        options += ["-H", header.format(domain=domain)]
    assert status(edge_host, domain, url, *options) == 403
    same_origin = options[:6] + ["-H", f"Origin: https://{domain}", "-H", "Sec-Fetch-Site: same-origin"]
    assert status(edge_host, domain, url, *same_origin) == 401


def test_identity_headers_and_cookies_never_reach_the_app(edge_host, app, auth_stub, upstream_stub) -> None:
    domain = app["domain"]
    path = f"{app['api_prefix']}v1/portfolios"
    code = status(edge_host, domain, f"https://{domain}{path}",
                  "-H", "X-Forwarded-User: mallory", "-H", "X-Auth-Request-Email: mallory@example.com",
                  "-H", "Authorization: Bearer mallory-token", "-H", "Cookie: __Host-secureedge=se-session-value")
    assert code == 200
    seen = upstream_stub()
    assert f"GET {path}" in seen
    assert "mallory" not in seen
    assert "se-session-value" not in seen


@pytest.mark.disruptive
def test_stopped_oauth2_proxy_fails_closed(edge_host, root, app) -> None:
    domain = app["domain"]
    root("systemctl stop oauth2-proxy")
    try:
        assert status(edge_host, domain, f"https://{domain}/") == 500
        assert status(edge_host, domain, f"https://{domain}{app['api_prefix']}v1/portfolios") == 500
    finally:
        root("systemctl start oauth2-proxy")
        wait_for_port(root, "127.0.0.1", 4180)
    # Back in service: the login redirect and the API's 401 return.
    assert status(edge_host, domain, f"https://{domain}/") == 302
    assert status(edge_host, domain, f"https://{domain}{app['api_prefix']}v1/portfolios") == 401


@pytest.mark.parametrize("probe", [SQL_INJECTION.format(marker="se"), XSS], ids=["sql-injection", "xss"])
def test_waf_blocks_attacks_before_the_auth_check(edge_host, app, probe) -> None:
    # Without a session the auth check would redirect to the login (302);
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


def test_waf_log_survives_rotation(edge_host, root, app) -> None:
    domain = app["domain"]
    root("logrotate -f /etc/logrotate.d/secureedge-modsecurity")
    marker = secrets.token_hex(6)
    assert status(edge_host, domain, f"https://{domain}{SQL_INJECTION.format(marker=marker)}") == 403
    text = ""
    for _ in range(50):
        text = root(f"cat {AUDIT_LOG}")
        if marker in text:
            break
        time.sleep(0.1)
    assert marker in text
    assert root("stat -c '%U %G %a' /var/log/modsecurity") == "root adm 750"


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


def test_without_a_session_nothing_reaches_the_app(edge_host, app, upstream_stub) -> None:
    domain = app["domain"]
    assert status(edge_host, domain, f"https://{domain}/") == 302
    assert status(edge_host, domain, f"https://{domain}{app['api_prefix']}v1/portfolios") == 401
    assert upstream_stub() == ""


def test_with_auth_requests_reach_the_app_over_wireguard(edge_host, app, auth_stub, upstream_stub) -> None:
    domain = app["domain"]
    prefix = app["api_prefix"]
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
        origin = ["-H", f"Origin: https://{domain}"]
        accepted = status(edge_host, domain, url, *origin, "-F", "file=@/tmp/se-11m")
        rejected = status(edge_host, domain, url, *origin, "-F", "file=@/tmp/se-13m")
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
                      "-H", f"Origin: https://{domain}",
                      "-H", "Content-Type: application/json", "--data-binary", "@/tmp/se-json.json")
    finally:
        root("rm -f /tmp/se-json.json")
    assert code == 200


def test_the_web_bundle_is_served_from_its_checksum_directory(edge_host, root, app, release) -> None:
    target = root("readlink -f /var/www/" + app["name"])
    assert target == f"/var/lib/secureedge/web/{release['web_bundle_sha256']}"
    root(f"test -f {target}/index.html")
    assert root(f"find {target} ! -user root | head -n 1") == ""


def test_the_web_bundle_is_served_behind_the_login(edge_host, app, auth_stub, release) -> None:
    domain = app["domain"]
    page = curl(edge_host, domain, f"https://{domain}/")
    assert "is not deployed yet" not in page
    assert "<!doctype html>" in page.lower()
    # Client-side routes fall back to the bundle's index.html.
    assert curl(edge_host, domain, f"https://{domain}/portfolio/123") == page


def test_the_api_answers_over_wireguard(edge_host, app, release) -> None:
    upstream = app["upstream"]
    url = f"http://{upstream['address']}:{upstream['port']}{app['api_prefix']}v1/instruments"
    assert edge_host.check_output(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 10 {url}") == "200"


def test_the_api_reaches_its_database_and_archive(edge_host, app, auth_stub, release, in_container) -> None:
    if not in_container:
        pytest.skip("reads the Molecule stand-in's self-report")
    domain = app["domain"]
    report = json.loads(curl(edge_host, domain, f"https://{domain}{app['api_prefix']}v1/instruments"))
    assert report["stand_in"] == "atlasrisk-api"
    assert report["path"] == f"{app['api_prefix']}v1/instruments"
    assert report["database"] == "postgres:5432/atrisk"
    assert report["database_reachable"] is True
    assert report["s3_endpoint"] == "http://garage:3900"
