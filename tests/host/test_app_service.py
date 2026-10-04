"""What container_runtime and app_service guarantee (and that edge has no Docker)."""

from __future__ import annotations

import json

import pytest

from support.inventory import group_for

pytestmark = pytest.mark.host

COMPOSE = "docker compose --project-directory /etc/atlasrisk"


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


def test_no_container_publishes_a_port(app_host, root) -> None:
    for container_id in root("docker ps -q").split():
        details = json.loads(root(f"docker inspect {container_id}"))[0]
        assert not details["HostConfig"]["PortBindings"], details["Name"]
        published = details["NetworkSettings"]["Ports"] or {}
        assert all(not bindings for bindings in published.values()), details["Name"]


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


@pytest.mark.disruptive
def test_containers_survive_a_docker_restart(app_host, root) -> None:
    before = {service: container(root, service)["Id"] for service in ("postgres", "garage")}
    root("systemctl restart docker")
    for service, container_id in before.items():
        details = container(root, service)
        assert details["Id"] == container_id, f"{service} was recreated"
        assert details["State"]["Running"], service


def test_edge_has_no_docker(edge_host) -> None:
    assert not edge_host.package("docker.io").is_installed
