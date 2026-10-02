# 0001: Ansible for server configuration

- **Status:** Accepted
- **Date:** 2026-10-02

## Context

Two VPSs need host-level setup (users, SSH, nftables, WireGuard, systemd
services) and application deployment from a container image. One person
maintains them from a Windows machine. Changes must be repeatable, and a
failed change must be reversible.

## Decision

Use Ansible, run from WSL2, with one role per component, one inventory per
environment, and playbooks per server group. VPSs are created by hand in the
provider's panel; Ansible takes over once SSH works.

## Consequences

- Runs are idempotent. Rollback means checking out the previous `deploy-*`
  git tag and re-running `site.yml`.
- Fronting another application needs a new inventory, not role changes.
- Ansible must run from WSL, and `ANSIBLE_CONFIG` must be exported when the
  repository sits under `/mnt/c`.
- There is no provisioning layer. The required VPS specification lives in
  the setup runbook.
