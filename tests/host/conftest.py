"""Host checks: run only against hosts named with testinfra's --hosts."""

from __future__ import annotations

from pathlib import Path

import pytest

from support.inventory import group_for, load_vars


@pytest.fixture(autouse=True)
def _require_hosts(request: pytest.FixtureRequest) -> None:
    if not request.config.getoption("hosts", default=None):
        pytest.skip(
            "host checks need --hosts, e.g. --hosts=ansible://all "
            "--ansible-inventory=inventories/production/hosts.yml"
        )


@pytest.fixture
def expected(host, request: pytest.FixtureRequest) -> dict:
    inventory = request.config.getoption("ansible_inventory", default=None)
    if not inventory:
        pytest.fail("host checks need --ansible-inventory to know the expected settings")
    return load_vars(Path(inventory), group_for(host.check_output("hostname")))


@pytest.fixture
def in_container(host) -> bool:
    return host.run("systemd-detect-virt --container").rc == 0
