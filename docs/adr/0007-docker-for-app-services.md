# 0007: Docker Compose for AtlasRisk's services

- **Status:** Accepted; published ports and forwarding amended by
  [0012](0012-atlasrisk-releases.md)
- **Date:** 2026-10-04

## Context

AtlasRisk needs PostgreSQL 18 and an S3-compatible store (Garage) and will
add its API and risk worker as containers once it publishes images. Its own
documentation assumes Docker Compose.

## Decision

Install Ubuntu's `docker.io` and `docker-compose-v2` on the app server, and
run a SecureEdge-owned Compose project in `/etc/atlasrisk` with digest-pinned
images, secrets from the vault in a root-only `.env`, data in
`/srv/atlasrisk`, and no published ports. The firewall drops forwarding from
WireGuard except DNAT'd traffic.

## Consequences

- Docker security updates arrive through the existing security-only
  `unattended-upgrades`; `live-restore` keeps containers running when Docker
  restarts.
- Docker group membership is root-equivalent, so the admin user is not in it;
  maintenance uses `sudo docker compose`.
- Molecule runs Docker inside a privileged `app01` container with separate
  volumes for `/var/lib/docker` and `/var/lib/containerd`.
