# 0011: Self-checks on each server with ntfy alerts

- **Status:** Accepted
- **Date:** 2026-10-06

## Context

PROJECT.md asks for enough visibility to explain access failures,
application connectivity, certificate problems and resource pressure,
without exposing secrets or financial content, and without infrastructure
added only for its own sake. The owner wants alerts on their phone.

## Decision

Each server runs a small check script every five minutes from a systemd
timer. The checks cover disk, memory, load, failed units, the other server
over WireGuard, edge services and the certificate, and app containers and
backup age. When the set of problems changes, the script sends one ntfy
message (`ntfy.sh`, a long random topic kept in the vault). The message
names the failed checks only. `secureedge-status` runs the same checks on
demand.

## Consequences

- No metrics store, dashboard or extra daemon to secure and update.
- A server that dies entirely is reported by the other one, because each
  checks its peer over WireGuard. Losing both at once, or losing the
  network, produces no alert.
- ntfy.sh is an external service. The topic is the only secret: anyone who
  knows it can read the alerts. Self-hosting ntfy is possible later without
  changing the script.
- Logs stay where they are (journald, NGINX, the ModSecurity audit log) and
  are read on the server when an alert needs explaining.
