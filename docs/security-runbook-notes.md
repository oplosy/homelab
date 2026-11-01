# Security Runbook Notes

Orientation for `secure-edge`'s security-related assets.

## Where things are

- `roles/` and `playbooks/` — the automation that applies hardening and network controls.
- `molecule/` — scenario tests for those roles.
- `tests/` — end-to-end checks; `pytest.ini` configures them.
- `PROJECT.md` — scope and goals of the project.

## Habits

- Security-relevant task changes require a molecule run, not just a syntax check.
- Never embed credentials in inventories; reference a secret source instead.
- Changes that widen network access get a second reviewer.

Update this file when adding a new role or test class so the map stays true.
