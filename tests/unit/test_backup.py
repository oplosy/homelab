"""The backup role's scripts, units and settings, without a server."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from support.render import REPO, render_template

ROLE = REPO / "roles" / "backup"
R2 = {
    "backup_r2_account_id": "0123456789abcdef0123456789abcdef",
    "backup_r2_bucket": "secureedge-backups",
    "vault_backup_restic_password": "x" * 40,
    "vault_backup_r2_access_key_id": "0123456789abcdef0123456789abcdef",
    "vault_backup_r2_secret_access_key": "f" * 64,
}


def render(tmp_path: Path, template: str, **overrides: object) -> str:
    return render_template(tmp_path, "backup", template, {**R2, **overrides})


def test_repository_is_the_r2_bucket_by_default() -> None:
    defaults = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert defaults["backup_repository"] == (
        "s3:https://{{ backup_r2_account_id }}.r2.cloudflarestorage.com/{{ backup_r2_bucket }}/atlasrisk"
    )


def test_backup_paths_match_app_service() -> None:
    backup = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text(encoding="utf-8"))
    app = yaml.safe_load((REPO / "roles" / "app_service" / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert backup["backup_compose_dir"] == app["app_service_config_dir"]
    assert backup["backup_data_root"] == app["app_service_root"]
    assert backup["backup_postgres_user"] == app["app_service_postgres_user"]
    assert backup["backup_postgres_db"] == app["app_service_postgres_db"]


def test_env_file_carries_the_r2_credentials(tmp_path: Path) -> None:
    env = render(tmp_path, "restic.env.j2")
    assert ("RESTIC_REPOSITORY='s3:https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com/"
            "secureedge-backups/atlasrisk'") in env
    assert f"RESTIC_PASSWORD='{'x' * 40}'" in env
    assert "AWS_ACCESS_KEY_ID='0123456789abcdef0123456789abcdef'" in env
    assert f"AWS_SECRET_ACCESS_KEY='{'f' * 64}'" in env
    assert "AWS_DEFAULT_REGION='auto'" in env


def test_local_repository_needs_no_r2_credentials(tmp_path: Path) -> None:
    env = render(tmp_path, "restic.env.j2", backup_repository="/var/backups/secureedge-restic")
    assert "RESTIC_REPOSITORY='/var/backups/secureedge-restic'" in env
    assert "AWS_" not in env


def test_backup_dumps_snapshots_backs_up_prunes_and_checks(tmp_path: Path) -> None:
    script = render(tmp_path, "secureedge-backup.j2")
    assert "set -euo pipefail" in script
    steps = [
        "pg_dump -U atrisk -Fc atrisk",
        "/garage meta snapshot",
        '"$restic" backup --retry-lock 10m --tag atlasrisk',
        '"$restic" forget --retry-lock 10m --tag atlasrisk --keep-within 3d --keep-daily 7 --keep-weekly 4 '
        '--keep-monthly 6 --prune',
        '"$restic" check',
        "last-success",
    ]
    positions = [script.index(step) for step in steps]
    assert positions == sorted(positions)
    # The live SQLite files change while Garage runs; the snapshot copy is used.
    assert '--exclude "$meta/db.sqlite*"' in script


def test_restore_moves_current_data_aside_and_never_deletes_it(tmp_path: Path) -> None:
    script = render(tmp_path, "secureedge-restore.j2")
    assert "set -euo pipefail" in script
    assert re.search(r"\^\(latest\|\[0-9a-f\]\{8,64\}\)\$", script)
    assert 'mv "$root/postgres" "$root/garage" "$aside/"' in script
    assert not re.search(r'rm -rf "?\$root', script)
    assert "pg_restore -U atrisk -d atrisk --no-owner" in script
    assert script.index('"${compose[@]}" down') < script.index('mv "$root/postgres"')


def test_timer_runs_nightly_and_catches_up(tmp_path: Path) -> None:
    timer = render(tmp_path, "secureedge-backup.timer.j2").splitlines()
    assert "OnCalendar=*-*-* 03:00:00" in timer
    assert "RandomizedDelaySec=15m" in timer
    assert "Persistent=true" in timer


def test_a_stale_lock_cannot_stop_every_later_backup(tmp_path: Path) -> None:
    script = render(tmp_path, "secureedge-backup.j2")
    assert script.index('"$restic" unlock') < script.index('"$restic" backup')
    for command in ('"$restic" backup', '"$restic" forget', '"$restic" check'):
        line = next(line for line in script.splitlines() if line.strip().startswith(command))
        assert "--retry-lock 10m" in line, line


def test_a_manual_backup_survives_later_runs_the_same_day(tmp_path: Path) -> None:
    script = render(tmp_path, "secureedge-backup.j2")
    assert "--keep-within 3d" in script


def test_garage_writes_during_the_backup_do_not_fail_it(tmp_path: Path) -> None:
    # restic exits 3 when files vanish mid-scan (Garage's temporary and
    # deleted blocks): keep the snapshot, log it, and carry on.
    script = render(tmp_path, "secureedge-backup.j2")
    assert '--exclude "*.tmp*"' in script
    assert "3)" in script


def test_restic_keeps_a_cache(tmp_path: Path) -> None:
    assert "RESTIC_CACHE_DIR='/var/cache/secureedge-restic'" in render(tmp_path, "restic.env.j2")


def test_the_backup_cannot_hang_forever(tmp_path: Path) -> None:
    assert "TimeoutStartSec=3h" in render(tmp_path, "secureedge-backup.service.j2").splitlines()


def test_restore_waits_for_the_real_server_and_loads_all_or_nothing(tmp_path: Path) -> None:
    # On first start the postgres entrypoint runs a temporary socket-only
    # server; only a TCP answer means the real one is up.
    script = render(tmp_path, "secureedge-restore.j2")
    assert "pg_isready -h 127.0.0.1" in script
    assert script.index("pg_isready -h 127.0.0.1") < script.index("pg_restore")
    assert "pg_restore -U atrisk -d atrisk --no-owner --exit-on-error --single-transaction" in script
