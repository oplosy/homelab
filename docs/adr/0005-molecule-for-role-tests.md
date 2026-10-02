# 0005: Molecule with Docker for role tests

- **Status:** Accepted
- **Date:** 2026-10-02

## Context

Roles must be tested before any VPS exists, locally and in CI.

## Decision

One Molecule scenario (`molecule/default`) runs the real `site.yml` against
two Ubuntu 26.04 systemd containers, `edge01` and `app01`.
`scripts/molecule-check` converges, checks idempotence, runs the host
checks in `tests/host/` through the Molecule inventory, and always destroys
the containers.

## Consequences

- The same host checks later run against the real servers.
- Containers cannot prove that a real SSH login survives a firewall change;
  the setup runbook's lockout drill covers that once per server.
- Docker Desktop with WSL integration must be running for local runs.
