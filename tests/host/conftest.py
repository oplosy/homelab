"""Host checks: run only against hosts named with testinfra's --hosts."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from support.commands import require_success
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
def root(host) -> Callable[[str], str]:
    """Run a shell command as root and return its stdout.

    Goes through Ansible's become, which uses the inventory's sudo password;
    testinfra's host.sudo() only prefixes "sudo" and cannot send a password.
    A non-zero exit fails the test.
    """

    def run(command: str) -> str:
        result = host.ansible("ansible.builtin.shell", command, become=True, check=False)
        return require_success(result, command)

    return run


@pytest.fixture
def in_container(host) -> bool:
    return host.run("systemd-detect-virt --container").rc == 0
