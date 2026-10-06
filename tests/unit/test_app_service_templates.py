"""The app_service Compose project and its secrets file, without a server."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest
import yaml

from support.render import render_template

SECRETS = {
    # Every character the password check allows that a URL must escape.
    "vault_atlasrisk_postgres_password": "a+b/c=d.e_f-0123456789abcdefghijklmnopqrstuv",
    "vault_atlasrisk_garage_access_key": "GKcfe3c374687e6e82648563ea",
    "vault_atlasrisk_garage_secret_key": "d" * 64,
    "vault_atlasrisk_garage_rpc_secret": "5" * 64,
}
API = "ghcr.io/oplosy/atrisk-api:v1.0.0@sha256:" + "a" * 64
WORKER = "ghcr.io/oplosy/atrisk-risk-worker:v1.0.0@sha256:" + "b" * 64
APP = {
    "name": "atlasrisk",
    "upstream": {"address": "10.8.0.2", "port": 8080},
}
RELEASE = {
    "api_image": API,
    "worker_image": WORKER,
    "web_bundle_url": "https://github.com/oplosy/atrisk/releases/download/v1.0.0/atlasrisk-web-v1.0.0.tar.gz",
    "web_bundle_sha256": "c" * 64,
}
APP_SERVICES = ("migrate", "api", "worker")


def compose(tmp_path: Path, release: dict | None) -> dict:
    app = {**APP, "release": release} if release else APP
    rendered = render_template(tmp_path, "app_service", "compose.yaml.j2",
                               {**SECRETS, "secureedge_app": app})
    return yaml.safe_load(rendered)["services"]


def test_without_a_release_only_the_data_services_run(tmp_path: Path) -> None:
    assert set(compose(tmp_path, None)) == {"postgres", "garage"}


def test_a_release_adds_the_api_worker_and_migration(tmp_path: Path) -> None:
    services = compose(tmp_path, RELEASE)
    assert services["api"]["image"] == API
    assert services["migrate"]["image"] == API
    assert services["worker"]["image"] == WORKER
    assert services["migrate"]["command"] == ["migrate"]
    # The migration runs only when Ansible asks for it, never on `up`.
    assert services["migrate"]["profiles"] == ["migrate"]
    assert "restart" not in services["migrate"]


def test_only_the_api_is_published_and_only_on_the_wireguard_address(tmp_path: Path) -> None:
    services = compose(tmp_path, RELEASE)
    assert services["api"]["ports"] == ["10.8.0.2:8080:8080"]
    assert services["api"]["command"] == ["-listen", "0.0.0.0:8080"]
    for name, service in services.items():
        if name != "api":
            assert "ports" not in service, name


def test_app_containers_are_locked_down(tmp_path: Path) -> None:
    services = compose(tmp_path, RELEASE)
    for name in APP_SERVICES:
        service = services[name]
        assert service["read_only"] is True, name
        assert service["cap_drop"] == ["ALL"], name
        assert service["security_opt"] == ["no-new-privileges:true"], name
        assert service["depends_on"]["postgres"]["condition"] == "service_healthy", name


def test_app_containers_get_their_settings_from_the_env_file(tmp_path: Path) -> None:
    services = compose(tmp_path, RELEASE)
    for name in APP_SERVICES:
        assert services[name]["environment"]["ATLASRISK_DATABASE_URL"] == "${ATLASRISK_DATABASE_URL}", name
    api = services["api"]["environment"]
    assert api["ATLASRISK_S3_ENDPOINT"] == "http://garage:3900"
    assert api["ATLASRISK_S3_REGION"] == "garage"
    assert api["ATLASRISK_S3_BUCKET"] == "${GARAGE_BUCKET}"
    assert api["AWS_ACCESS_KEY_ID"] == "${GARAGE_ACCESS_KEY}"
    assert api["AWS_SECRET_ACCESS_KEY"] == "${GARAGE_SECRET_KEY}"
    assert services["api"]["depends_on"]["garage"]["condition"] == "service_healthy"
    # The worker needs only the database.
    assert set(services["worker"]["environment"]) == {"ATLASRISK_DATABASE_URL"}


@pytest.mark.parametrize("password", [SECRETS["vault_atlasrisk_postgres_password"], "x" * 40])
def test_database_url_carries_the_password_intact(tmp_path: Path, password: str) -> None:
    env = render_template(tmp_path, "app_service", "env.j2",
                          {**SECRETS, "vault_atlasrisk_postgres_password": password})
    line = next(line for line in env.splitlines() if line.startswith("ATLASRISK_DATABASE_URL="))
    url = urlsplit(line.removeprefix("ATLASRISK_DATABASE_URL="))
    assert url.scheme == "postgres"
    assert (url.hostname, url.port, url.path, url.query) == ("postgres", 5432, "/atrisk", "sslmode=disable")
    assert url.username == "atrisk"
    assert unquote(url.password) == password
    assert "/" not in url.password and "+" not in url.password


def test_wireguard_interface_matches_the_wireguard_role() -> None:
    roles = Path(__file__).resolve().parents[2] / "roles"
    app = yaml.safe_load((roles / "app_service" / "defaults" / "main.yml").read_text(encoding="utf-8"))
    wireguard = yaml.safe_load((roles / "wireguard" / "defaults" / "main.yml").read_text(encoding="utf-8"))
    assert app["app_service_wireguard_interface"] == wireguard["wireguard_interface"]
