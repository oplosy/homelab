"""What container_runtime and app_service guarantee (and that edge has no Docker)."""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.host

COMPOSE = "docker compose --project-directory /etc/atlasrisk"


def container(root, service: str) -> dict:
    container_id = root(f"{COMPOSE} ps -q {service}").strip()
    assert container_id, f"no {service} container"
    return json.loads(root(f"docker inspect {container_id}"))[0]


def test_docker_runs_with_live_restore(app_host, root) -> None:
    docker = app_host.service("docker")
    assert docker.is_enabled
    assert docker.is_running
    info = json.loads(root("docker info --format json"))
    assert info["LiveRestoreEnabled"] is True
    assert info["LoggingDriver"] == "local"


def test_data_services_are_healthy(app_host, root) -> None:
    for service in ("postgres", "garage"):
        state = container(root, service)["State"]
        assert state["Running"], service
        assert state["Health"]["Status"] == "healthy", service


@pytest.fixture
def release(expected) -> dict:
    release = expected.get("secureedge_app", {}).get("release")
    if not release:
        pytest.skip("no AtlasRisk release is configured yet")
    return release


def published_ports(details: dict) -> dict:
    published = details["NetworkSettings"]["Ports"] or {}
    return {port: bindings for port, bindings in published.items() if bindings}


def test_only_the_api_publishes_a_port_and_only_on_wireguard(app_host, root, expected) -> None:
    app = expected.get("secureedge_app", {})
    api = root(f"{COMPOSE} ps -q api 2>/dev/null || true").strip() if app.get("release") else ""
    for container_id in root("docker ps -q --no-trunc").split():
        details = json.loads(root(f"docker inspect {container_id}"))[0]
        if container_id == api:
            upstream = app["upstream"]
            port = str(upstream["port"])
            assert published_ports(details) == {
                f"{port}/tcp": [{"HostIp": upstream["address"], "HostPort": port}]
            }
        else:
            assert not details["HostConfig"]["PortBindings"], details["Name"]
            assert not published_ports(details), details["Name"]


def test_the_release_runs_locked_down(app_host, root, release) -> None:
    for service in ("api", "worker"):
        details = container(root, service)
        assert details["State"]["Running"], service
        assert details["HostConfig"]["ReadonlyRootfs"] is True, service
        assert details["HostConfig"]["CapDrop"] == ["ALL"], service
        assert details["Config"]["User"] not in ("", "0", "root"), service
        assert details["HostConfig"]["LogConfig"]["Type"] == "local", service


def test_migrations_leave_no_container_behind(app_host, root, release) -> None:
    assert root("docker ps -a -q --filter label=com.docker.compose.service=migrate") == ""


def test_docker_starts_after_wireguard(app_host) -> None:
    after = app_host.check_output("systemctl show docker --property After --value")
    assert "wg-quick@wg0.service" in after.split()


def test_postgres_accepts_connections(app_host, root, expected) -> None:
    user = expected.get("app_service_postgres_user", "atrisk")
    db = expected.get("app_service_postgres_db", "atrisk")
    assert "accepting connections" in root(f"{COMPOSE} exec -T postgres pg_isready -U {user} -d {db}")


def test_garage_has_the_bucket(app_host, root, expected) -> None:
    bucket = expected.get("app_service_garage_bucket", "atlasrisk-raw")
    assert bucket in root(f"{COMPOSE} exec -T garage /garage bucket list")


def test_secrets_file_is_root_only(app_host, root) -> None:
    assert root("stat -c '%U %a' /etc/atlasrisk/.env") == "root 600"
    for path in ("/srv/atlasrisk/postgres", "/srv/atlasrisk/garage/meta", "/srv/atlasrisk/garage/data"):
        root(f"test -d {path}")


def test_admin_is_not_in_the_docker_group(app_host, expected) -> None:
    assert "docker" not in app_host.user(expected["base_admin_user"]).groups


def test_containers_use_the_rotated_log_driver(app_host, root) -> None:
    # Containers keep the log driver they were created with, so the daemon
    # default alone does not prove their logs are bounded.
    for service in ("postgres", "garage"):
        assert container(root, service)["HostConfig"]["LogConfig"]["Type"] == "local", service


@pytest.mark.disruptive
def test_containers_survive_a_docker_restart(app_host, root) -> None:
    before = {service: container(root, service) for service in ("postgres", "garage")}
    root("systemctl restart docker")
    for service, old in before.items():
        new = container(root, service)
        assert new["Id"] == old["Id"], f"{service} was recreated"
        assert new["State"]["Running"], service
        # Without live-restore, "restart: unless-stopped" restarts the same
        # container with a new StartedAt; with it, the process never stops.
        assert new["State"]["StartedAt"] == old["State"]["StartedAt"], f"{service} was restarted"


def test_edge_has_no_docker(edge_host) -> None:
    assert not edge_host.package("docker.io").is_installed
