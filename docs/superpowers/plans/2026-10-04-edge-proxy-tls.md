# Edge Proxy and TLS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve the application's domain on edge01 over HTTPS with an ACME certificate, NGINX with ModSecurity and OWASP CRS in blocking mode, an API route with a rate limit, and a fail-closed `auth_request` hook for the future oauth2-proxy.

**Architecture:** `tls` installs certbot, a deploy hook, and a placeholder certificate so NGINX can start. `edge_proxy` installs NGINX, ModSecurity, and CRS from Ubuntu and renders one `conf.d` file plus one ModSecurity rules file from `secureedge_app`. `tls` then runs a second time (`tasks_from: issue`) to get the real certificate through NGINX's port-80 webroot. In Molecule, Pebble on edge01 plays Let's Encrypt, and HTTP stubs started by the host checks play oauth2-proxy and AtlasRisk.

**Tech Stack:** Ansible, Ubuntu 26.04 `nginx` 1.28, `libnginx-mod-http-modsecurity` 1.0.3 with `libmodsecurity3t64` 3.0.14, `modsecurity-crs` 3.3.8, `certbot` 4.0, Pebble 2.6, Molecule, pytest and testinfra.

**Spec:** `docs/superpowers/specs/2026-10-04-edge-proxy-tls-design.md`

## Global Constraints

- Every edge package comes from Ubuntu 26.04. The edge server gets no Docker.
- `tls` and `edge_proxy` read only `secureedge_app` and their own defaults, and both reject malformed `secureedge_app` values at their first task, before changing anything.
- WAF: `SecRuleEngine On`, CRS paranoia level 1, default anomaly threshold.
- The ModSecurity audit log uses `SecAuditLogParts AHZ`: no request headers (cookies), request bodies, or response bodies.
- No application request is ever forwarded without a passing `auth_request`. With nothing at `edge_proxy_auth_url`, application routes answer `500`.
- `auth_request` may only point at `127.0.0.1`.
- Ports: edge01 adds tcp 80 and 443 from any. The app server's production firewall is unchanged.
- Re-running the play never re-issues a certificate for an unchanged domain.
- Commit subjects are conventional, imperative, at most 72 characters, and end with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Deviations from the spec (call out in review)

1. **One Molecule red run and one green run,** as in the earlier plans. Each `scripts/molecule-check` run takes 30–40 minutes. Task 1 adds every host check and runs Molecule once to see them fail. Tasks 2–4 are verified by unit tests and lint. Task 5 runs Molecule once to see everything pass.
2. **`SecRequestBodyNoFilesLimit` equals `max_body` too.** The spec names only the request body limit. The package's 128 KiB no-files limit would reject AtlasRisk's JSON bodies (its handlers accept up to 4 MiB) and any large non-multipart body.
3. **`limit_req ... nodelay`.** Without `nodelay`, NGINX queues requests over the rate instead of rejecting them, so a sequential client never sees `429`.
4. **Security headers use `always`,** so `403`, `429`, and `500` responses carry them too.
5. **`proxy_connect_timeout 5s`.** An unreachable upstream fails within seconds. A refused connection gives `502`; a dropped one gives `504` after the timeout.
6. **Stub-based host checks skip outside containers** (the existing `in_container` fixture). Run against real servers, the host checks never start listeners on `127.0.0.1:4180` or the upstream port.
7. **`edge_host` and `app_host` move to `tests/host/conftest.py`,** because two test files now need them.

## Execution environment

- **Same as the earlier plans:** WSL venv, `ANSIBLE_CONFIG`, script files for any command with `$`, and Docker Desktop with WSL integration.
- **Unit and lint commands** (run from the repo root inside WSL, venv active):
  - `pytest tests/unit -q`
  - `ansible-lint`
- **Run Molecule detached,** so the tool's 10-minute limit can't kill it:
  - `setsid nohup bash -c 'scripts/molecule-check > ~/se-mol.log 2>&1; echo "exit=$?" > ~/se-mol.done' &`
  - Watch `~/se-mol.log` with a monitor that exits when `~/se-mol.done` exists. Delete `~/se-mol.done` before starting.
  - Don't pipe the monitor through `tr`, which buffers its output.
- **Branch:** before Task 1, branch from `docs/edge-proxy-tls-spec`: `git switch -c feat/edge-proxy-tls`.

## Review Focus

1. **An attack request without a session** must be blocked by the WAF (`403`), not merely failed by the auth check (`500`). This proves ModSecurity runs before `auth_request`. Pinned in Task 1, `test_waf_blocks_attacks_before_the_auth_check`.
2. **A domain or path value that would inject NGINX configuration** (for example `atlasrisk.example.com; return 200`, an upper-case domain, or an API prefix without a trailing slash) must be rejected before anything changes. Pinned in Task 3, `test_edge_proxy_rejects_bad_input`, and in Task 2, `test_tls_rejects_bad_input`.
3. **A second run of the play** must not ask the ACME server for a new certificate (Let's Encrypt allows five duplicates a week). Pinned by Molecule's idempotence step and the `changed_when` in Task 2.
4. **An AtlasRisk JSON body of about 1 MiB with a few hundred fields** must pass the WAF. The package's 128 KiB no-files limit and argument limits would reject it. Pinned in Task 1, `test_large_json_api_bodies_pass_the_waf`.
5. **An upstream that is down while auth passes** must give a quick `502`, never a hang or a different backend. Pinned in Task 1, `test_unreachable_app_gives_502`.

---

### Task 1: Molecule wiring and host checks (red run)

**Files:**
- Modify: `molecule/default/molecule.yml` (add the `prepare` playbook)
- Create: `molecule/default/prepare.yml`
- Create: `molecule/default/files/http_stub.py`
- Modify: `molecule/default/inventory/group_vars/all/main.yml` (`secureedge_app`)
- Modify: `molecule/default/inventory/group_vars/edge/main.yml` (Pebble settings, ports 80 and 443)
- Modify: `molecule/default/inventory/group_vars/app/main.yml` (test-only upstream port)
- Modify: `tests/host/conftest.py` (add `edge_host` and `app_host`)
- Modify: `tests/host/test_app_service.py` (drop its local `edge_host` and `app_host`)
- Create: `tests/host/test_edge_proxy.py`

**Interfaces:**
- Consumes: the `root`, `expected` and `in_container` fixtures; `support.inventory.group_for`; `support.commands.require_success`.
- Produces: the host checks that Tasks 2–4 must satisfy (run in Task 5). The fixtures `edge_host(host)` and `app_host(host)` in `tests/host/conftest.py`. The stub at `/usr/local/lib/secureedge-test/http_stub.py`, with arguments `ADDRESS PORT STATUS LOGFILE`, that answers every request with `STATUS` and body `secureedge-stub\n`, and appends `METHOD PATH CONTENT_LENGTH` to `LOGFILE`.

- [ ] **Step 1: Branch**

```bash
git switch -c feat/edge-proxy-tls
```

- [ ] **Step 2: Molecule prepare playbook**

In `molecule/default/molecule.yml`, under `provisioner.playbooks`, add `prepare` next to `converge`:

```yaml
  playbooks:
    prepare: prepare.yml
    converge: converge.yml
```

`molecule converge` runs `prepare` once after `create`, so `scripts/molecule-check` needs no change.

Create `molecule/default/prepare.yml`:

```yaml
---
# Test-only setup that real servers never get: Pebble (a local ACME server)
# on edge01, the application name pointing at edge01, curl and openssl for
# the host checks, and an HTTP stub the edge proxy checks start on demand.
- name: Prepare the edge test container
  hosts: edge
  become: true
  tasks:
    - name: Install Pebble, curl and openssl
      ansible.builtin.apt:
        name:
          - pebble
          - curl
          - openssl
        state: present
        update_cache: true

    - name: Create the Pebble directory
      ansible.builtin.file:
        path: /etc/pebble
        state: directory
        owner: root
        group: root
        mode: "0755"

    - name: Create Pebble's test CA and server certificate
      ansible.builtin.shell: |
        set -eu
        cd /etc/pebble
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
          -days 30 -subj "/CN=SecureEdge Molecule test CA" -keyout ca.key -out ca.pem
        openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
          -subj "/CN=localhost" -keyout key.pem -out server.csr
        printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > san.ext
        openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
          -days 30 -extfile san.ext -out cert.pem
      args:
        executable: /bin/bash
        creates: /etc/pebble/cert.pem

    - name: Configure Pebble
      ansible.builtin.copy:
        dest: /etc/pebble/pebble-config.json
        owner: root
        group: root
        mode: "0644"
        content: |
          {"pebble": {"listenAddress": "127.0.0.1:14000",
                      "managementListenAddress": "127.0.0.1:15000",
                      "certificate": "/etc/pebble/cert.pem",
                      "privateKey": "/etc/pebble/key.pem",
                      "httpPort": 80,
                      "tlsPort": 5001,
                      "ocspResponderURL": "",
                      "externalAccountBindingRequired": false}}

    - name: Install the Pebble service
      ansible.builtin.copy:
        dest: /etc/systemd/system/pebble.service
        owner: root
        group: root
        mode: "0644"
        content: |
          [Unit]
          Description=Pebble test ACME server (Molecule only)

          [Service]
          Environment=PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0
          ExecStart=/usr/bin/pebble -config /etc/pebble/pebble-config.json

          [Install]
          WantedBy=multi-user.target

    - name: Run Pebble
      ansible.builtin.systemd_service:
        name: pebble
        enabled: true
        state: started
        daemon_reload: true

    # Pebble validates HTTP-01 by connecting to this name on port 80.
    - name: Point the application name at edge01
      ansible.builtin.lineinfile:
        path: /etc/hosts
        line: "127.0.0.1 {{ secureedge_app.domain }}"
        unsafe_writes: true  # Docker bind-mounts /etc/hosts; a rename fails

- name: Install the HTTP stub on every test container
  hosts: all
  become: true
  tasks:
    - name: Create the test helper directory
      ansible.builtin.file:
        path: /usr/local/lib/secureedge-test
        state: directory
        owner: root
        group: root
        mode: "0755"

    - name: Install the HTTP stub
      ansible.builtin.copy:
        src: http_stub.py
        dest: /usr/local/lib/secureedge-test/http_stub.py
        owner: root
        group: root
        mode: "0644"
```

Create `molecule/default/files/http_stub.py`:

```python
"""Test-only HTTP stub for the edge proxy host checks (Molecule only).

Usage: http_stub.py ADDRESS PORT STATUS LOGFILE

Answers every request with STATUS and the body "secureedge-stub", and
appends "METHOD PATH CONTENT_LENGTH" to LOGFILE so checks can see what
reached it.
"""

from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ADDRESS, PORT, STATUS, LOG = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
BODY = b"secureedge-stub\n"


class Handler(BaseHTTPRequestHandler):
    def answer(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)
        with open(LOG, "a", encoding="utf-8") as log:
            log.write(f"{self.command} {self.path} {length}\n")
        self.send_response(STATUS)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = answer

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


ThreadingHTTPServer((ADDRESS, PORT), Handler).serve_forever()
```

- [ ] **Step 3: Molecule inventory values**

Append to `molecule/default/inventory/group_vars/all/main.yml`:

```yaml

# The application, as in production but with a test-only name.
secureedge_app:
  name: atlasrisk
  domain: atlasrisk.test
  upstream:
    address: 10.8.0.2
    port: 8080
  api_prefix: /api/
  max_body: 12m
  rate_limits:
    api:
      rate: 10r/s
      burst: 20
```

Replace `molecule/default/inventory/group_vars/edge/main.yml` with:

```yaml
---
base_reboot_time: "01:00"
firewall_allowed:
  - name: test-any
    proto: tcp
    port: 8443
    from: any
  - name: wireguard
    proto: udp
    port: 51820
    from: any
  - name: http
    proto: tcp
    port: 80
    from: any
  - name: https
    proto: tcp
    port: 443
    from: any

# Pebble (molecule/default/prepare.yml) plays Let's Encrypt.
tls_acme_server: https://localhost:14000/dir
tls_acme_ca_bundle: /etc/pebble/ca.pem
```

In `molecule/default/inventory/group_vars/app/main.yml`, add a test-only upstream rule to `firewall_allowed`, after the `wireguard` entry:

```yaml
  # Test-only: the host checks' upstream stub on 10.8.0.2:8080.
  - name: test-upstream
    proto: tcp
    port: 8080
    from: wireguard
```

- [ ] **Step 4: Shared host fixtures**

Move the two fixtures out of `tests/host/test_app_service.py` (delete them there, and drop its now-unused `group_for` import) and add them to the end of `tests/host/conftest.py`:

```python
@pytest.fixture
def app_host(host):
    if group_for(host.check_output("hostname")) != "app":
        pytest.skip("app servers only")
    return host


@pytest.fixture
def edge_host(host):
    if group_for(host.check_output("hostname")) != "edge":
        pytest.skip("edge servers only")
    return host
```

`tests/host/conftest.py` already imports `group_for` and `pytest`.

- [ ] **Step 5: Write the host checks**

Create `tests/host/test_edge_proxy.py`:

```python
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
```

The rate-limit check sends every request from one curl process over one connection, fast enough to exceed the burst.

- [ ] **Step 6: Lint and unit tests still pass**

Run: `pytest tests/unit -q && ansible-lint`
Expected: unit tests pass; `ansible-lint` passes (it lints `molecule/default/prepare.yml` too).

- [ ] **Step 7: Red Molecule run**

Run Molecule detached (see Execution environment) and wait for `~/se-mol.done`.
Expected: `prepare` and `converge` succeed (no edge roles yet). Every `test_edge_proxy.py` check fails on edge01 (nothing listens on 80 or 443) and skips on app01; the disruptive renewal check fails too. Every other host check passes as before, including `test_allowed_ports_follow_the_inventory`, because the firewall role already renders the new 80, 443 and 8080 entries. Record the failed/passed/skipped counts in the ledger. The exit is non-zero.

- [ ] **Step 8: Commit**

```bash
git add molecule/default tests/host/conftest.py tests/host/test_app_service.py tests/host/test_edge_proxy.py
git commit -m "test: add host checks for the edge proxy and TLS" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Role `tls`

**Files:**
- Create: `roles/tls/defaults/main.yml`
- Create: `roles/tls/tasks/main.yml`
- Create: `roles/tls/tasks/issue.yml`
- Create: `roles/tls/templates/secureedge-tls-deploy.j2`
- Modify: `tests/unit/test_role_guards.py` (tls guard tests)

**Interfaces:**
- Consumes: `secureedge_app.name`, `secureedge_app.domain`.
- Produces: `tls_dir` (`/etc/secureedge/tls`, holding `fullchain.pem` and root-only `privkey.pem`), `tls_webroot` (`/var/lib/secureedge/acme`), the hook `/usr/local/sbin/secureedge-tls-deploy`, and `tasks_from: issue` for `playbooks/edge.yml` (Task 4).

- [ ] **Step 1: Write the failing guard tests**

Append to `tests/unit/test_role_guards.py`:

```python
GOOD_SECUREEDGE_APP = {
    "name": "atlasrisk",
    "domain": "atlasrisk.example.com",
    "upstream": {"address": "10.8.0.2", "port": 8080},
    "api_prefix": "/api/",
    "max_body": "12m",
    "rate_limits": {"api": {"rate": "10r/s", "burst": 20}},
}


def app_with(**changes: object) -> dict:
    return {"secureedge_app": {**GOOD_SECUREEDGE_APP, **changes}}


@pytest.mark.parametrize(
    "role_vars",
    [
        {},
        app_with(domain="AtlasRisk.example.com"),
        app_with(domain="atlasrisk.example.com; return 200"),
        app_with(name="Atlas Risk"),
        {**app_with(), "tls_acme_server": "http://acme.example.com/dir"},
        {**app_with(), "tls_acme_email": "not-an-email"},
    ],
    ids=["no-app", "uppercase-domain", "injected-domain", "bad-name", "plain-http-acme", "bad-email"],
)
def test_tls_rejects_bad_input(tmp_path: Path, role_vars: dict) -> None:
    result = run_role(tmp_path, "tls", role_vars)
    assert result.returncode != 0
    assert "Check TLS settings" in result.stdout
    assert "Install certbot and openssl" not in result.stdout


def test_tls_accepts_good_input(tmp_path: Path) -> None:
    result = run_role(tmp_path, "tls", app_with())
    assert "Check TLS settings" in result.stdout
    assert "tls needs" not in result.stdout
```

- [ ] **Step 2: Run them to see them fail**

Run: `pytest tests/unit/test_role_guards.py -q -k tls`
Expected: FAIL. The role `tls` does not exist, so `Check TLS settings` never appears in the output.

- [ ] **Step 3: Write the role**

`roles/tls/defaults/main.yml`:

```yaml
---
# ACME directory. Molecule points this at Pebble.
tls_acme_server: https://acme-v02.api.letsencrypt.org/directory
# Optional contact address; empty registers without one.
tls_acme_email: ""
# CA bundle certbot trusts for tls_acme_server; empty uses the system store.
tls_acme_ca_bundle: ""
# HTTP-01 challenge files; edge_proxy serves this directory on port 80.
# edge_proxy_acme_webroot must be equal.
tls_webroot: /var/lib/secureedge/acme
# Where NGINX reads the certificate; edge_proxy_tls_dir must be equal.
tls_dir: /etc/secureedge/tls
tls_cert_name: "{{ secureedge_app.name }}"
```

`roles/tls/tasks/main.yml`:

```yaml
---
- name: Check TLS settings
  ansible.builtin.assert:
    that:
      - secureedge_app is defined
      - secureedge_app.name | default('') is match('^[a-z][a-z0-9-]{0,62}$')
      - secureedge_app.domain | default('') is match('^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
      - tls_acme_server is match('^https://\S+$')
      - tls_acme_email == '' or tls_acme_email is match('^[^@\s]+@[^@\s]+\.[^@\s]+$')
    fail_msg: >-
      tls needs secureedge_app.name and a lower-case secureedge_app.domain,
      and an https ACME server. See docs/runbooks/setup.md, section "Domain
      and certificates".
    quiet: true

- name: Install certbot and openssl
  ansible.builtin.apt:
    name:
      - certbot
      - openssl
    state: present

- name: Create the TLS directories
  ansible.builtin.file:
    path: "{{ item }}"
    state: directory
    owner: root
    group: root
    mode: "0755"
  loop:
    - "{{ tls_webroot }}"
    - "{{ tls_dir }}"

- name: Install the certificate deploy hook
  ansible.builtin.template:
    src: secureedge-tls-deploy.j2
    dest: /usr/local/sbin/secureedge-tls-deploy
    owner: root
    group: root
    mode: "0755"

# NGINX needs a certificate to start; tasks/issue.yml replaces this one.
- name: Write a placeholder certificate until the real one is issued
  ansible.builtin.command:
    argv:
      - openssl
      - req
      - -x509
      - -newkey
      - ec
      - -pkeyopt
      - ec_paramgen_curve:prime256v1
      - -nodes
      - -days
      - "30"
      - -subj
      - "/CN={{ secureedge_app.domain }}"
      - -keyout
      - "{{ tls_dir }}/privkey.pem"
      - -out
      - "{{ tls_dir }}/fullchain.pem"
    creates: "{{ tls_dir }}/fullchain.pem"

- name: Keep the private key root-only
  ansible.builtin.file:
    path: "{{ tls_dir }}/privkey.pem"
    owner: root
    group: root
    mode: "0600"
```

`roles/tls/tasks/issue.yml`:

```yaml
---
# Runs after edge_proxy, once NGINX serves tls_webroot on port 80. certbot
# stores the server and the deploy hook in the lineage's renewal
# configuration, so certbot.timer renews the same way.
- name: Issue the certificate
  ansible.builtin.command:
    argv: "{{ tls_certbot_argv }}"
  environment: "{{ {'REQUESTS_CA_BUNDLE': tls_acme_ca_bundle} if tls_acme_ca_bundle else {} }}"
  register: tls_issue
  changed_when: "'not yet due for renewal' not in (tls_issue.stdout + tls_issue.stderr)"
  vars:
    tls_certbot_argv: >-
      {{ ['certbot', 'certonly', '--non-interactive', '--agree-tos',
          '--webroot', '-w', tls_webroot,
          '--cert-name', tls_cert_name, '-d', secureedge_app.domain,
          '--server', tls_acme_server,
          '--deploy-hook', '/usr/local/sbin/secureedge-tls-deploy',
          '--keep-until-expiring']
         + (['--email', tls_acme_email] if tls_acme_email
            else ['--register-unsafely-without-email']) }}

- name: Renew certificates on the package's timer
  ansible.builtin.systemd_service:
    name: certbot.timer
    enabled: true
    state: started
```

`roles/tls/templates/secureedge-tls-deploy.j2`:

```sh
#!/bin/sh
# Managed by SecureEdge (role tls). certbot deploy hook: put the new
# certificate where NGINX reads it, then reload NGINX if its configuration
# still validates. A failing check exits non-zero and certbot logs it.
set -eu
dir={{ tls_dir | quote }}
umask 077
cp "$RENEWED_LINEAGE/privkey.pem" "$dir/privkey.pem.new"
cp "$RENEWED_LINEAGE/fullchain.pem" "$dir/fullchain.pem.new"
chmod 0644 "$dir/fullchain.pem.new"
mv "$dir/privkey.pem.new" "$dir/privkey.pem"
mv "$dir/fullchain.pem.new" "$dir/fullchain.pem"
if systemctl is-active --quiet nginx; then
  nginx -t -q
  systemctl reload nginx
fi
```

- [ ] **Step 4: Run the guard tests to see them pass**

Run: `pytest tests/unit/test_role_guards.py -q -k tls`
Expected: 7 passed.

- [ ] **Step 5: Lint**

Run: `ansible-lint`
Expected: passes. If `command-instead-of-module` or `no-changed-when` fires on the placeholder task, `creates:` already answers it; fix only what it reports and note it.

- [ ] **Step 6: Commit**

```bash
git add roles/tls tests/unit/test_role_guards.py
git commit -m "feat: add tls role with certbot webroot and deploy hook" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Role `edge_proxy`

**Files:**
- Create: `roles/edge_proxy/defaults/main.yml`
- Create: `roles/edge_proxy/tasks/main.yml`
- Create: `roles/edge_proxy/handlers/main.yml`
- Create: `roles/edge_proxy/templates/secureedge.conf.j2`
- Create: `roles/edge_proxy/templates/modsecurity.conf.j2`
- Create: `roles/edge_proxy/templates/index.html.j2`
- Create: `tests/unit/test_edge_proxy_templates.py`
- Modify: `tests/unit/test_role_guards.py` (edge_proxy guard tests)

**Interfaces:**
- Consumes: `secureedge_app` (all keys); `tls_dir` and `tls_webroot` defaults from Task 2 (compared in a unit test, never read by this role); `GOOD_SECUREEDGE_APP`, `app_with` and `run_role` from `tests/unit/test_role_guards.py`.
- Produces: NGINX serving port 80 (`/.well-known/acme-challenge/` from `edge_proxy_acme_webroot`) before the role ends, which `tls`'s `issue` tasks need (Task 4 runs them after this role). Handler `Reload NGINX`.

- [ ] **Step 1: Write the failing guard tests**

Append to `tests/unit/test_role_guards.py`:

```python
@pytest.mark.parametrize(
    "role_vars",
    [
        {},
        app_with(domain="atlasrisk.example.com; return 200"),
        app_with(upstream={"address": "10.8.0.2:8080", "port": 8080}),
        app_with(upstream={"address": "10.8.0.2", "port": "8080"}),
        app_with(upstream={"address": "10.8.0.2", "port": 70000}),
        app_with(api_prefix="/api"),
        app_with(max_body="12MB"),
        app_with(rate_limits={"api": {"rate": "10/s", "burst": 20}}),
        app_with(rate_limits={"api": {"rate": "10r/s", "burst": -1}}),
        {**app_with(), "edge_proxy_auth_url": "http://10.8.0.1:4180/oauth2/auth"},
        {**app_with(), "edge_proxy_crs_paranoia": 5},
    ],
    ids=["no-app", "injected-domain", "address-with-port", "port-as-string", "port-range",
         "prefix-without-slash", "bad-body-size", "bad-rate", "negative-burst",
         "remote-auth-url", "bad-paranoia"],
)
def test_edge_proxy_rejects_bad_input(tmp_path: Path, role_vars: dict) -> None:
    result = run_role(tmp_path, "edge_proxy", role_vars)
    assert result.returncode != 0
    assert "Check edge proxy settings" in result.stdout
    assert "Install NGINX, ModSecurity and OWASP CRS" not in result.stdout


def test_edge_proxy_accepts_good_input(tmp_path: Path) -> None:
    result = run_role(tmp_path, "edge_proxy", app_with())
    assert "Check edge proxy settings" in result.stdout
    assert "edge_proxy needs" not in result.stdout
```

- [ ] **Step 2: Write the failing template tests**

Create `tests/unit/test_edge_proxy_templates.py`:

```python
"""The rendered NGINX and ModSecurity configuration, without a server."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
ROLE = REPO / "roles" / "edge_proxy"
APP = {
    "name": "atlasrisk",
    "domain": "atlasrisk.example.com",
    "upstream": {"address": "10.8.0.2", "port": 8080},
    "api_prefix": "/api/",
    "max_body": "12m",
    "rate_limits": {"api": {"rate": "10r/s", "burst": 20}},
}


def render(tmp_path: Path, template: str, app: dict | None = None) -> str:
    out = tmp_path / template.removesuffix(".j2")
    playbook = tmp_path / "render.yml"
    playbook.write_text(
        "- hosts: localhost\n  gather_facts: false\n  tasks:\n"
        "    - ansible.builtin.template:\n"
        f"        src: {ROLE}/templates/{template}\n"
        f"        dest: {out}\n"
        "        mode: '0644'\n",
        encoding="utf-8",
    )
    vault_pass = tmp_path / "vault_pass"
    vault_pass.write_text("unused\n", encoding="utf-8")
    env = {**os.environ, "ANSIBLE_CONFIG": str(REPO / "ansible.cfg"),
           "ANSIBLE_VAULT_PASSWORD_FILE": str(vault_pass)}
    args = ["ansible-playbook", "-i", "localhost,", "-c", "local", str(playbook),
            "-e", f"@{ROLE}/defaults/main.yml",
            "-e", json.dumps({"secureedge_app": app or APP})]
    result = subprocess.run(args, cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    return out.read_text(encoding="utf-8")


def block(text: str, opener: str) -> str:
    """The text between `opener {` and its matching closing brace."""
    start = text.index(opener + " {") + len(opener) + 2
    depth = 1
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index]
    raise AssertionError(f"unclosed block {opener!r}")


def test_app_server_block_follows_secureedge_app(tmp_path: Path) -> None:
    text = render(tmp_path, "secureedge.conf.j2")
    assert "server_name atlasrisk.example.com;" in text
    assert "server 10.8.0.2:8080;" in block(text, "upstream secureedge_app")
    assert "limit_req_zone $binary_remote_addr zone=secureedge_api:10m rate=10r/s;" in text
    assert "client_max_body_size 12m;" in text
    assert "root /var/www/atlasrisk;" in text
    assert "ssl_certificate /etc/secureedge/tls/fullchain.pem;" in text


def test_api_route_is_rate_limited_authenticated_and_proxied(tmp_path: Path) -> None:
    api = block(render(tmp_path, "secureedge.conf.j2"), "location /api/")
    assert "auth_request /_secureedge_auth;" in api
    assert "limit_req zone=secureedge_api burst=20 nodelay;" in api
    assert "proxy_pass http://secureedge_app;" in api


def test_every_application_route_needs_the_auth_check(tmp_path: Path) -> None:
    text = render(tmp_path, "secureedge.conf.j2")
    app_server = text.split("server_name atlasrisk.example.com;", 1)[1]
    assert "auth_request /_secureedge_auth;" in block(app_server, "location /")
    auth = block(text, "location = /_secureedge_auth")
    assert "internal;" in auth
    assert "proxy_pass http://127.0.0.1:4180/oauth2/auth;" in auth
    assert "proxy_pass_request_body off;" in auth


def test_port_80_only_serves_challenges_and_redirects(tmp_path: Path) -> None:
    text = render(tmp_path, "secureedge.conf.j2")
    http = block(text, "server")  # the first server block is port 80
    assert "listen 80 default_server;" in http
    assert "root /var/lib/secureedge/acme;" in block(http, "location ^~ /.well-known/acme-challenge/")
    assert "return 301 https://$host$request_uri;" in http
    assert "modsecurity on;" not in http


def test_unknown_names_are_refused_at_the_handshake(tmp_path: Path) -> None:
    text = render(tmp_path, "secureedge.conf.j2")
    assert "listen 443 ssl default_server;" in text
    assert "ssl_reject_handshake on;" in text


def test_waf_and_headers_are_on_for_the_app(tmp_path: Path) -> None:
    text = render(tmp_path, "secureedge.conf.j2")
    assert "modsecurity on;" in text
    assert "modsecurity_rules_file /etc/nginx/secureedge/modsecurity.conf;" in text
    assert 'add_header Strict-Transport-Security "max-age=31536000" always;' in text
    assert "add_header X-Content-Type-Options nosniff always;" in text


def test_modsecurity_blocks_with_crs_and_logs_no_secrets(tmp_path: Path) -> None:
    text = render(tmp_path, "modsecurity.conf.j2")
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    assert lines[0] == "Include /etc/nginx/modsecurity.conf"
    assert "SecRuleEngine On" in lines
    assert "SecAuditLogParts AHZ" in lines
    assert "SecRequestBodyLimit 12582912" in lines
    assert "SecRequestBodyNoFilesLimit 12582912" in lines
    assert "setvar:tx.paranoia_level=1" in text
    assert lines.index("Include /etc/modsecurity/crs/crs-setup.conf") < lines.index(
        "Include /usr/share/modsecurity-crs/rules/*.conf")


def test_body_limit_follows_max_body_in_kilobytes(tmp_path: Path) -> None:
    text = render(tmp_path, "modsecurity.conf.j2", {**APP, "max_body": "512k"})
    assert "SecRequestBodyLimit 524288" in text


def test_tls_and_edge_proxy_agree_on_paths() -> None:
    tls = yaml.safe_load((REPO / "roles" / "tls" / "defaults" / "main.yml").read_text(encoding="utf-8"))
    edge = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert edge["edge_proxy_tls_dir"] == tls["tls_dir"]
    assert edge["edge_proxy_acme_webroot"] == tls["tls_webroot"]
```

- [ ] **Step 3: Run them to see them fail**

Run: `pytest tests/unit/test_edge_proxy_templates.py tests/unit/test_role_guards.py -q -k "edge_proxy or templates or agree"`
Expected: FAIL. The role and its templates don't exist.

- [ ] **Step 4: Write the role**

`roles/edge_proxy/defaults/main.yml`:

```yaml
---
# Must equal tls_dir and tls_webroot (tests/unit/test_edge_proxy_templates.py).
edge_proxy_tls_dir: /etc/secureedge/tls
edge_proxy_acme_webroot: /var/lib/secureedge/acme
# The web bundle. A placeholder index.html is written only if none exists.
edge_proxy_web_root: "/var/www/{{ secureedge_app.name }}"
# The auth check; oauth2-proxy listens here once that role exists. Nothing
# listening means every application request gets 500 (fail closed).
edge_proxy_auth_url: http://127.0.0.1:4180/oauth2/auth
edge_proxy_crs_paranoia: 1
edge_proxy_hsts_max_age: 31536000
```

`roles/edge_proxy/tasks/main.yml`:

```yaml
---
- name: Check edge proxy settings
  ansible.builtin.assert:
    that:
      - secureedge_app is defined
      - secureedge_app.name | default('') is match('^[a-z][a-z0-9-]{0,62}$')
      - secureedge_app.domain | default('') is match('^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
      - secureedge_app.upstream.address | default('') is match('^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$')
      - secureedge_app.upstream.port | default('') is integer
      - (secureedge_app.upstream.port | default(0) | int) >= 1
      - (secureedge_app.upstream.port | default(0) | int) <= 65535
      - secureedge_app.api_prefix | default('') is match('^/([a-z0-9_-]+/)+$')
      - secureedge_app.max_body | default('') is match('^[1-9][0-9]{0,3}[km]$')
      - secureedge_app.rate_limits.api.rate | default('') is match('^[1-9][0-9]{0,4}r/[sm]$')
      - secureedge_app.rate_limits.api.burst | default('') is integer
      - (secureedge_app.rate_limits.api.burst | default(-1) | int) >= 0
      - edge_proxy_auth_url is match('^http://127\.0\.0\.1:[0-9]{1,5}/[A-Za-z0-9/_-]*$')
      - edge_proxy_crs_paranoia | int in [1, 2, 3, 4]
      - edge_proxy_hsts_max_age | int >= 0
    fail_msg: >-
      edge_proxy needs a complete secureedge_app (lower-case domain, IPv4
      upstream address and integer port, api_prefix like /api/, max_body like
      12m, rate like 10r/s, integer burst) and an auth URL on 127.0.0.1. See
      docs/runbooks/setup.md, section "Domain and certificates".
    quiet: true

- name: Install NGINX, ModSecurity and OWASP CRS
  ansible.builtin.apt:
    name:
      - nginx
      - libnginx-mod-http-modsecurity
      - modsecurity-crs
    state: present

- name: Disable the package's default site
  ansible.builtin.file:
    path: /etc/nginx/sites-enabled/default
    state: absent
  notify: Reload NGINX

- name: Create the edge proxy directories
  ansible.builtin.file:
    path: "{{ item }}"
    state: directory
    owner: root
    group: root
    mode: "0755"
  loop:
    - /etc/nginx/secureedge
    - "{{ edge_proxy_web_root }}"

- name: Write the ModSecurity rules file
  ansible.builtin.template:
    src: modsecurity.conf.j2
    dest: /etc/nginx/secureedge/modsecurity.conf
    owner: root
    group: root
    mode: "0644"
  notify: Reload NGINX

- name: Write the NGINX site
  ansible.builtin.template:
    src: secureedge.conf.j2
    dest: /etc/nginx/conf.d/secureedge.conf
    owner: root
    group: root
    mode: "0644"
  notify: Reload NGINX

- name: Write a placeholder page until the web bundle is deployed
  ansible.builtin.template:
    src: index.html.j2
    dest: "{{ edge_proxy_web_root }}/index.html"
    owner: root
    group: root
    mode: "0644"
    force: false

- name: Run NGINX at boot
  ansible.builtin.systemd_service:
    name: nginx
    enabled: true
    state: started

# tls's issue tasks run next and need port 80 serving the challenge files.
- name: Apply NGINX changes before the certificate is requested
  ansible.builtin.meta: flush_handlers
```

`roles/edge_proxy/handlers/main.yml`:

```yaml
---
# Both run, in this order, on "Reload NGINX": a failing check stops the play
# before the reload, so NGINX keeps its running configuration.
- name: Check the NGINX configuration
  ansible.builtin.command: nginx -t
  changed_when: false
  listen: Reload NGINX

- name: Reload the NGINX service
  ansible.builtin.systemd_service:
    name: nginx
    state: reloaded
  listen: Reload NGINX
```

`roles/edge_proxy/templates/secureedge.conf.j2`:

```nginx
# Managed by SecureEdge (role edge_proxy). Order of checks on the
# application host: ModSecurity (rewrite and pre-access phases), the API
# rate limit (pre-access), auth_request (access), then the content.
{% set app = secureedge_app %}

limit_req_zone $binary_remote_addr zone=secureedge_api:10m rate={{ app.rate_limits.api.rate }};
limit_req_status 429;

upstream secureedge_app {
    server {{ app.upstream.address }}:{{ app.upstream.port }};
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    server_tokens off;

    location ^~ /.well-known/acme-challenge/ {
        root {{ edge_proxy_acme_webroot }};
        default_type text/plain;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    ssl_reject_handshake on;
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name {{ app.domain }};
    server_tokens off;

    ssl_certificate {{ edge_proxy_tls_dir }}/fullchain.pem;
    ssl_certificate_key {{ edge_proxy_tls_dir }}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:secureedge_tls:10m;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age={{ edge_proxy_hsts_max_age }}" always;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy same-origin always;
    add_header Content-Security-Policy "frame-ancestors 'none'" always;

    client_max_body_size {{ app.max_body }};
    modsecurity on;
    modsecurity_rules_file /etc/nginx/secureedge/modsecurity.conf;

    root {{ edge_proxy_web_root }};

    location = /_secureedge_auth {
        internal;
        proxy_pass {{ edge_proxy_auth_url }};
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Host $host;
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location {{ app.api_prefix }} {
        auth_request /_secureedge_auth;
        limit_req zone=secureedge_api burst={{ app.rate_limits.api.burst }} nodelay;
        proxy_pass http://secureedge_app;
        proxy_connect_timeout 5s;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        auth_request /_secureedge_auth;
        try_files $uri /index.html;
    }
}
```

`roles/edge_proxy/templates/modsecurity.conf.j2`:

```text
# Managed by SecureEdge (role edge_proxy). The package's recommended base
# configuration, then SecureEdge's overrides, then OWASP CRS.
{% set size = secureedge_app.max_body[:-1] | int %}
{% set bytes = size * (1024 if secureedge_app.max_body[-1] == 'k' else 1048576) %}
Include /etc/nginx/modsecurity.conf

SecRuleEngine On
SecRequestBodyLimit {{ bytes }}
SecRequestBodyNoFilesLimit {{ bytes }}
SecAuditEngine RelevantOnly
# Audit header and matched rules only: no request headers (cookies), no
# request or response bodies.
SecAuditLogParts AHZ
SecAuditLog /var/log/nginx/modsec_audit.log

Include /etc/modsecurity/crs/crs-setup.conf
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.paranoia_level={{ edge_proxy_crs_paranoia }}"
Include /etc/modsecurity/crs/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
Include /usr/share/modsecurity-crs/rules/*.conf
Include /etc/modsecurity/crs/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
```

The package's `/etc/nginx/modsecurity.conf` loads `unicode.mapping` by a relative path. If `nginx -t` in Molecule (Task 5) cannot open it from this include, override the directive after the `Include` with `SecUnicodeMapFile /etc/nginx/unicode.mapping 20127` and ledger the ruling.

`roles/edge_proxy/templates/index.html.j2`:

```html
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{{ secureedge_app.name }}</title></head>
<body><p>{{ secureedge_app.name }} is not deployed yet.</p></body>
</html>
```

- [ ] **Step 5: Run the tests to see them pass**

Run: `pytest tests/unit/test_edge_proxy_templates.py tests/unit/test_role_guards.py -q -k "edge_proxy or templates or agree"`
Expected: 21 passed (12 guard, 9 template).

- [ ] **Step 6: Lint and the whole unit suite**

Run: `ansible-lint && pytest tests/unit -q`
Expected: both pass.

- [ ] **Step 7: Commit**

```bash
git add roles/edge_proxy tests/unit/test_edge_proxy_templates.py tests/unit/test_role_guards.py
git commit -m "feat: add edge_proxy role with NGINX, ModSecurity and CRS" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Inventory, playbook and external checks

**Files:**
- Modify: `inventories/production/group_vars/all/main.yml` (`secureedge_app`)
- Modify: `inventories/production/group_vars/edge/main.yml` (ports 80 and 443)
- Modify: `playbooks/edge.yml`
- Modify: `tests/unit/test_production_vars.py`
- Create: `tests/external/test_edge.py`

**Interfaces:**
- Consumes: roles `tls` (with `tasks_from: issue`) and `edge_proxy`; the `target` fixture from `tests/conftest.py`.
- Produces: the production `secureedge_app`; `playbooks/edge.yml` running `base`, `wireguard`, `firewall`, `tls`, `edge_proxy`, then `tls`'s `issue` tasks.

- [ ] **Step 1: Write the failing production-vars tests**

In `tests/unit/test_production_vars.py`, replace `test_only_wireguard_is_open_on_its_port` with:

```python
def test_open_ports_per_group() -> None:
    port = load_vars(HOSTS, "edge")["wireguard_port"]
    wireguard = {"name": "wireguard", "proto": "udp", "port": port, "from": "any"}
    assert load_vars(HOSTS, "edge")["firewall_allowed"] == [
        wireguard,
        {"name": "http", "proto": "tcp", "port": 80, "from": "any"},
        {"name": "https", "proto": "tcp", "port": 443, "from": "any"},
    ]
    assert load_vars(HOSTS, "app")["firewall_allowed"] == [wireguard]


def test_application_upstream_is_app01_over_wireguard() -> None:
    app = load_vars(HOSTS, "edge")["secureedge_app"]
    assert app["upstream"] == {"address": "10.8.0.2", "port": 8080}
    assert app["api_prefix"] == "/api/"
    assert app["max_body"] == "12m"
```

- [ ] **Step 2: Run them to see them fail**

Run: `pytest tests/unit/test_production_vars.py -q`
Expected: FAIL. `test_open_ports_per_group` fails because edge has no `http` entry. `test_application_upstream_is_app01_over_wireguard` fails with `KeyError: 'secureedge_app'`.

- [ ] **Step 3: Production inventory**

Append to `inventories/production/group_vars/all/main.yml`:

```yaml

# The application SecureEdge fronts. Set domain to your own name before the
# first edge run: docs/runbooks/setup.md, section "Domain and certificates".
secureedge_app:
  name: atlasrisk
  domain: atlasrisk.example.com
  upstream:
    address: 10.8.0.2
    port: 8080
  api_prefix: /api/
  max_body: 12m
  rate_limits:
    api:
      rate: 10r/s
      burst: 20
```

Append to the `firewall_allowed` list in `inventories/production/group_vars/edge/main.yml`:

```yaml
  - name: http
    proto: tcp
    port: 80
    from: any
  - name: https
    proto: tcp
    port: 443
    from: any
```

- [ ] **Step 4: Playbook**

Replace `playbooks/edge.yml` with:

```yaml
---
- name: Configure edge servers
  hosts: edge
  become: true
  roles:
    - base
    - wireguard
    - firewall
    - tls
    - edge_proxy
  tasks:
    # edge_proxy ends by flushing its handlers, so NGINX already serves the
    # challenge directory on port 80 here.
    - name: Issue the TLS certificate
      ansible.builtin.include_role:
        name: tls
        tasks_from: issue
```

- [ ] **Step 5: External checks**

Create `tests/external/test_edge.py`:

```python
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
```

- [ ] **Step 6: Run the tests**

Run: `pytest tests/unit -q && pytest tests/external -q -rs && ansible-lint`
Expected: unit suite passes; `tests/external` reports 3 skipped naming `SECUREEDGE_DOMAIN`; lint passes.

- [ ] **Step 7: Commit**

```bash
git add inventories/production/group_vars playbooks/edge.yml tests/unit/test_production_vars.py tests/external
git commit -m "feat: serve the application from the edge with TLS and WAF" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Green Molecule run and documentation

**Files:**
- Modify: `docs/runbooks/setup.md` (new section 2, renumber the rest)
- Create: `docs/adr/0008-edge-stack-from-ubuntu-packages.md`
- Modify: `docs/architecture.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: everything above.
- Produces: a green `scripts/molecule-check` and the docs.

- [ ] **Step 1: Green Molecule run**

Run Molecule detached (see Execution environment) and wait for `~/se-mol.done`.
Expected: `exit=0`. Converge, idempotence (no changed task on the second run, including `Issue the certificate`) and the second converge all succeed. The host checks pass, with no failures; the skip count is the earlier run's plus the edge checks' app01 skips. If a check fails, use superpowers:systematic-debugging. Fix the role, not the check, unless the check contradicts the spec. Ledger every such ruling.

- [ ] **Step 2: Runbook**

In `docs/runbooks/setup.md`, insert this section after section 1 and renumber the following sections (2→3 … 8→9). Then update every in-text section reference (`grep -n "§" docs/runbooks/setup.md`).

````markdown
## 2. Domain and certificates

The edge server serves the application at `secureedge_app.domain` with a
Let's Encrypt certificate. The certificate needs a domain that already
points at edge01:

1. Buy a domain from any registrar.
2. In its DNS, create an `A` record for the application name (for example
   `atlasrisk.<your domain>`) pointing at the edge server's public IPv4, and
   an `AAAA` record if the VPS has IPv6.
3. Set `domain` under `secureedge_app` in
   `inventories/production/group_vars/all/main.yml` and commit it.
4. Wait until `getent hosts <name>` returns the edge server's address, then
   apply (§5).

Applying the `tls` role accepts the Let's Encrypt subscriber agreement.
Until a certificate is issued, NGINX serves a placeholder certificate and
browsers show a certificate error. Until `oauth2_proxy` is deployed, every
application request answers `500` by design: nothing is forwarded without
a login. Changing the domain later issues a new certificate on the next
run.
````

- [ ] **Step 3: ADR 0008**

Create `docs/adr/0008-edge-stack-from-ubuntu-packages.md`:

```markdown
# 0008: Edge stack from Ubuntu packages

- **Status:** Accepted
- **Date:** 2026-10-04

## Context

The edge server needs NGINX, ModSecurity with OWASP CRS, and an ACME client.
It runs no Docker. Ubuntu 26.04 packages NGINX 1.28, the ModSecurity
connector 1.0.3 with libmodsecurity 3.0.14, CRS 3.3.8, and certbot 4.0.
CRS 4.x exists upstream but is not packaged.

## Decision

Install every edge component from Ubuntu. Run CRS 3.3.8 in blocking mode at
paranoia level 1. Use certbot with the webroot authenticator (HTTP-01), a
deploy hook that copies the certificate to `/etc/secureedge/tls` and
reloads NGINX, and the package's `certbot.timer`.

## Consequences

- Security updates for every edge component arrive through
  `unattended-upgrades`.
- CRS 3.3 has more false positives on JSON APIs than 4.x. Switching to a
  pinned 4.x release later only changes where `edge_proxy` loads the rules
  from.
- HTTP-01 works with any DNS host but needs port 80 open on the edge.
- Molecule tests issuance and renewal against Pebble on edge01.
```

- [ ] **Step 4: Architecture and README**

In `docs/architecture.md`:
- In "Request flow" step 3, add after the first sentence: "Until oauth2-proxy is deployed, nothing answers there and NGINX returns 500 for every application request."
- Add a section "## Edge proxy" after "## AtlasRisk data services":

```markdown
## Edge proxy

On `edge01`, NGINX serves `secureedge_app.domain` with a Let's Encrypt
certificate (certbot, HTTP-01 through `/.well-known/acme-challenge/` on
port 80). Each application request passes, in order: ModSecurity with OWASP
CRS 3.3 (blocking, paranoia level 1), the API rate limit (`429` beyond the
burst), the `auth_request` check against `127.0.0.1:4180`, then either the
static web root or the AtlasRisk upstream over WireGuard. Names other than
the application's get no TLS handshake. The WAF audit log keeps the matched
rules only, never cookies or bodies. See
[adr/0008-edge-stack-from-ubuntu-packages.md](adr/0008-edge-stack-from-ubuntu-packages.md).
```

- In "Decisions", remove "ACME client" from the list of open choices.

In `README.md`:
- Replace the "Role tests (Molecule)" paragraph's first sentence after the command with: "It builds two Ubuntu 26.04 containers, prepares them (Pebble as a local ACME server on `edge01`, and an HTTP stub for the edge checks), applies `playbooks/site.yml`, checks idempotence, runs the host checks, and removes the containers."
- Replace "`roles/` holds `base` and `firewall`;" with "`roles/` holds `base`, `firewall`, `wireguard`, `tls`, `edge_proxy`, `container_runtime` and `app_service`;".

- [ ] **Step 5: Docs checks**

Run: `pytest tests/unit -q`
Expected: passes, including `test_docs_links.py`.

- [ ] **Step 6: Commit**

```bash
git add docs/runbooks/setup.md docs/adr/0008-edge-stack-from-ubuntu-packages.md docs/architecture.md README.md
git commit -m "docs: add edge proxy runbook section, ADR, and architecture" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
