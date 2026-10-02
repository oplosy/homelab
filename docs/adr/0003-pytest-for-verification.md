# 0003: pytest for verification

- **Status:** Accepted
- **Date:** 2026-10-02

## Context

The project counts as done only with evidence that the access boundaries
hold: HTTPS, rejected unauthenticated access, WAF blocks, rate limits, closed
backend ports, and fail-closed behaviour. The checks run from three vantage
points: the internet, over the VPN, and on the servers.

## Decision

Use pytest with `requests` and sockets for network checks, and
`pytest-testinfra` over the Ansible inventory for on-host checks. Tests are
grouped under `tests/external`, `tests/vpn` and `tests/host`, with markers
of the same names. Service-stopping tests are marked `disruptive` and need
`--run-disruptive`.

## Consequences

- One command reruns all checks after any change, and the report doubles as
  evidence.
- Missing targets or a missing session cookie produce skips, never passes,
  so the evidence stays honest.
- Targets are never committed. They come from `SECUREEDGE_*` environment
  variables or the gitignored `tests/targets.yml`.
