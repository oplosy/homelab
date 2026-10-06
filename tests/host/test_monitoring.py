"""What the monitoring role guarantees on every server."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.host

STUB = "/usr/local/lib/secureedge-test/http_stub.py"
STATE = "/var/lib/secureedge/monitoring/problems"


def test_checks_run_every_five_minutes(host, root) -> None:
    timer = host.service("secureedge-monitor.timer")
    assert timer.is_enabled
    assert timer.is_running
    assert root("stat -c '%U %a' /etc/secureedge/monitoring/ntfy.env") == "root 600"


def test_the_servers_services_and_peers_are_fine(host, root) -> None:
    # Container quirks (memory, load, failed units) may show up in Molecule;
    # what this role must never report on a healthy setup is below.
    output = root("/usr/local/sbin/secureedge-status || true")
    for unexpected in ("does not answer over WireGuard", "is not running", "container ",
                       "TLS certificate", "no successful backup"):
        assert unexpected not in output, output


def test_alerts_are_sent_when_problems_change(host, root, in_container) -> None:
    if not in_container:
        pytest.skip("starts a stub on 127.0.0.1:8099; runs only in Molecule")
    log = "/run/se-ntfy-stub.log"
    root(f"rm -f {log}; systemd-run --unit=se-ntfy-stub --collect python3 {STUB} 127.0.0.1 8099 200 {log}")
    try:
        root("for i in $(seq 100); do ss -Hltn | grep -q '127.0.0.1:8099 ' && exit 0; sleep 0.1; done; exit 1")
        root("/usr/local/sbin/secureedge-monitor --notify || true")  # settle the baseline

        root("systemd-run --unit=se-monitor-probe /bin/false; sleep 1")
        root("/usr/local/sbin/secureedge-monitor --notify")
        assert "se-monitor-probe" in root(f"cat {STATE}")
        alerts = root(f"grep -c '^POST /' {log} || true")

        root("systemctl reset-failed se-monitor-probe")
        root("/usr/local/sbin/secureedge-monitor --notify")
        assert "se-monitor-probe" not in root(f"cat {STATE} 2>/dev/null || true")
        assert int(root(f"grep -c '^POST /' {log}")) == int(alerts) + 1

        sent = root(f"cat {log}")
        assert "POST /molecule-only-ntfy-topic-0123456789" in sent
        assert "Title: SecureEdge " in sent
    finally:
        root("systemctl reset-failed se-monitor-probe 2>/dev/null || true")
        root("systemctl stop se-ntfy-stub || true")
