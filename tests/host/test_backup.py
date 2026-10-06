"""What the backup role guarantees on the app server, including a restore drill."""

from __future__ import annotations

import json
import secrets

import pytest

pytestmark = pytest.mark.host

COMPOSE = "docker compose --project-directory /etc/atlasrisk"
RESTIC = "/usr/local/sbin/secureedge-restic"
STATE = "/var/lib/secureedge/backup"


def psql(root, sql: str) -> str:
    return root(f'{COMPOSE} exec -T postgres psql -U atrisk -d atrisk -tAc "{sql}"').strip()


def latest_snapshot(root) -> str:
    snapshots = json.loads(root(f"{RESTIC} snapshots --tag atlasrisk --latest 1 --json"))
    return snapshots[-1]["id"] if snapshots else ""


def test_backup_runs_nightly(app_host, root) -> None:
    timer = app_host.service("secureedge-backup.timer")
    assert timer.is_enabled
    assert timer.is_running
    assert "03:00:00" in root("systemctl show -p TimersCalendar --value secureedge-backup.timer")


def test_repository_settings_are_root_only(app_host, root) -> None:
    assert root("stat -c '%U %a' /etc/secureedge/backup/restic.env") == "root 600"
    assert root(f"stat -c '%U %a' {STATE}") == "root 700"
    root(f"{RESTIC} cat config >/dev/null")


def test_a_backup_run_adds_a_snapshot(app_host, root) -> None:
    # Compare the newest snapshot, not the count: on a real server retention
    # may remove an older snapshot in the same run.
    before = latest_snapshot(root)
    root("systemctl start secureedge-backup.service")
    after = latest_snapshot(root)
    assert after
    assert after != before
    assert root(f"cat {STATE}/last-success").startswith("20")
    # The staged dump and Garage metadata copy stay root-only.
    assert root(f"stat -c '%a' {STATE}/staging/atrisk.dump") == "600"
    assert root(f"{RESTIC} check >/dev/null && echo ok") == "ok"


@pytest.mark.disruptive
def test_restore_brings_back_deleted_data(app_host, root) -> None:
    token = secrets.token_hex(6)
    bucket = f"se-restore-{token}"
    psql(root, f"CREATE TABLE se_restore_marker (v text); INSERT INTO se_restore_marker VALUES ('{token}')")
    root(f"{COMPOSE} exec -T garage /garage bucket create {bucket}")
    try:
        root("systemctl start secureedge-backup.service")
        psql(root, "DROP TABLE se_restore_marker")
        root(f"{COMPOSE} exec -T garage /garage bucket delete --yes {bucket}")
        assert bucket not in root(f"{COMPOSE} exec -T garage /garage bucket list")

        root("/usr/local/sbin/secureedge-restore latest")

        assert psql(root, "SELECT v FROM se_restore_marker") == token
        assert bucket in root(f"{COMPOSE} exec -T garage /garage bucket list")
        assert "atlasrisk-raw" in root(f"{COMPOSE} exec -T garage /garage bucket list")
        # The replaced data was moved aside, not deleted.
        aside = root("ls -d /srv/atlasrisk-before-restore-* | tail -n 1")
        root(f"test -d {aside}/postgres && test -d {aside}/garage/data")
        for service in ("postgres", "garage"):
            container_id = root(f"{COMPOSE} ps -q {service}")
            health = json.loads(root(f"docker inspect {container_id}"))[0]["State"]["Health"]["Status"]
            assert health == "healthy", service
    finally:
        psql(root, "DROP TABLE IF EXISTS se_restore_marker")
        root(f"{COMPOSE} exec -T garage /garage bucket delete --yes {bucket} || true")
