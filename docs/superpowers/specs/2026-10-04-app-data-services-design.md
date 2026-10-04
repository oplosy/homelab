# `container_runtime` and `app_service` roles (data services) — design

- **Date:** 2026-10-04
- **Status:** Draft, awaiting owner review
- **Builds on:** `PROJECT.md`, `docs/architecture.md`, and the layout,
  base/firewall, and WireGuard specs in this folder
- **Scope:** Docker on the app server, AtlasRisk's PostgreSQL and Garage
  running there under a SecureEdge-owned Compose project, a firewall
  `forward` chain, tests, and the runbook section. AtlasRisk's own services
  (API, risk worker, migrations, web assets), backups, and the edge proxy are
  out of scope.

## 1. Context

### What AtlasRisk provides today (repository `atrisk`, V1 candidate `dfaf88c`)

| Part | Deployable now? |
|---|---|
| Go API (`apps/api`) | Runs; listens on `:8080`; config from `ATLASRISK_DATABASE_URL`, `ATLASRISK_S3_*`, `AWS_*` |
| Web (`apps/web`) | Static build (`npm run build` → `dist/`); calls the API with relative paths, so it expects the same origin |
| PostgreSQL 18, Garage 2.x | Yes; digest-pinned images in `infra/compose/compose.yaml` |
| Migrations | goose files in `db/migrations`; only tests apply them — no migration command |
| Risk worker (Python) | No runnable entry point (`main` prints diagnostics only) |
| Collector | Skeleton only |
| Container images | None: no Dockerfile, nothing published |

AtlasRisk's ADR-001 already expects an external OIDC proxy for remote access,
and its web client treats 401/403 as `unauthorized-proxy`.

### Decision

AtlasRisk is deployed from its own artifacts (PROJECT.md), and those do not
exist yet. Work proceeds on two tracks:

1. **This spec:** SecureEdge runs AtlasRisk's data services now.
2. **Separately, in the AtlasRisk repository:** a packaging task produces what
   SecureEdge needs to run the application itself (§8).

| Topic | Decision |
|---|---|
| Container runtime | Ubuntu's `docker.io` and `docker-compose-v2` packages, so security updates arrive through the existing `unattended-upgrades` security origin |
| Orchestration | A SecureEdge-owned Compose project rendered by Ansible and applied with `community.docker.docker_compose_v2` |
| Exposure | No published ports at all, not even on `127.0.0.1`; services talk on the Compose network only |
| Data | Bind mounts under `/srv/atlasrisk` |
| Secrets | Vault, rendered into a root-only `.env` |

### Approaches considered

1. **SecureEdge-owned Compose file (chosen).** Same shape AtlasRisk uses, so
   the API and worker slot in later; debuggable with `docker compose ps/logs`.
2. **Per-container Ansible modules.** Rejected: ordering and health checks
   spread across tasks as services grow.
3. **AtlasRisk's own `compose.yaml`.** Rejected: it is a development file with
   local placeholder credentials, loopback ports, and a test-only service.

### Feasibility check (2026-10-04)

In a privileged Ubuntu 26.04 systemd container with separate volumes for
`/var/lib/docker` and `/var/lib/containerd`, Ubuntu's Docker 29.1.3 started
with `live-restore` and the `local` log driver, Compose 2.40.3 was present,
the pinned PostgreSQL image pulled and became healthy, and the container kept
running across `systemctl restart docker`. Without the `/var/lib/containerd`
volume, image layers failed to unpack (nested overlay). The proposed `forward`
chain loaded beside Docker's `ip`/`ip6` tables.

## 2. Role `container_runtime` (app group only)

- Install `docker.io` and `docker-compose-v2`.
- Write `/etc/docker/daemon.json`:
  `{"live-restore": true, "no-new-privileges": true, "log-driver": "local",
  "log-opts": {"max-size": "20m", "max-file": "5"}}`; restart Docker when it
  changes.
- Enable and start `docker`.
- The admin user is **not** added to the `docker` group (membership is
  root-equivalent); Ansible uses `become`.
- Docker keeps managing its own `ip`/`ip6` tables; the `inet secureedge`
  table and its restart behaviour already leave them alone.

## 3. Role `app_service` (app group only)

### Variables

| Variable | Where | Default / content |
|---|---|---|
| `app_service_project` | role default | `atlasrisk` |
| `app_service_root` | role default | `/srv/atlasrisk` |
| `app_service_config_dir` | role default | `/etc/atlasrisk` |
| `app_service_postgres_image` | role default | `postgres:18.6-bookworm@sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af` |
| `app_service_garage_image` | role default | `dxflrs/garage:v2.4.1@sha256:9c96caa2612d3411acc5b0e6701fb238dbfba33e533a6d7d3d811a4b12d0d020` |
| `app_service_postgres_db`, `app_service_postgres_user` | role defaults | `atrisk`, `atrisk` |
| `app_service_garage_bucket` | role default | `atlasrisk-raw` |
| `vault_atlasrisk_postgres_password` | vault | at least 32 characters |
| `vault_atlasrisk_garage_access_key` | vault | `GK` + 24 lowercase hex characters |
| `vault_atlasrisk_garage_secret_key` | vault | 64 lowercase hex characters |
| `vault_atlasrisk_garage_rpc_secret` | vault | 64 lowercase hex characters |

Image defaults match AtlasRisk's `infra/compose/compose.yaml`; updating them is
an explicit inventory change.

### Behaviour

1. **Input check first:** every vault value exists and matches its format;
   both images are pinned by `@sha256:` digest. Failure names the runbook
   section; secret values are never printed (`no_log`).
2. Create `/srv/atlasrisk/postgres`, `/srv/atlasrisk/garage/meta`,
   `/srv/atlasrisk/garage/data`, and `/etc/atlasrisk` (root-owned; the data
   directories get the ownership each image needs).
3. Render `/etc/atlasrisk/compose.yaml`, `/etc/atlasrisk/garage.toml`, and
   `/etc/atlasrisk/.env` (mode `0600`, `no_log`).
4. `docker_compose_v2` with `state: present`, `wait: true`: services are
   created or updated only when their definition changed, and the task fails
   if a health check does not pass.

### Compose project

- `postgres`: pinned image, `POSTGRES_DB/USER/PASSWORD` from `.env`,
  `PGDATA: /var/lib/postgresql/18/docker`, bind mount
  `/srv/atlasrisk/postgres:/var/lib/postgresql`, AtlasRisk's `pg_isready`
  health check.
- `garage`: pinned image, AtlasRisk's
  `server --single-node --default-bucket --default-access-key` command,
  `GARAGE_DEFAULT_ACCESS_KEY/SECRET_KEY/BUCKET` from `.env`,
  `GARAGE_RPC_SECRET` from `.env` (replacing AtlasRisk's generated-secret
  volume), `garage.toml` and the two data directories bind-mounted, AtlasRisk's
  `/garage status` health check.
- Both: `restart: unless-stopped`, `security_opt: [no-new-privileges:true]`,
  **no `ports:`**, one Compose network.
- `garage.toml` is AtlasRisk's file (`metadata_dir`, `data_dir`, `sqlite`,
  replication 1, compression 2, RPC on `garage:3901`, S3 on `:3900`, region
  `garage`).

### Failure behaviour

- A service that never becomes healthy fails the run with the Compose error.
- Missing or malformed secrets stop the run before any change.
- The role never deletes containers' data directories or volumes; there is no
  equivalent of AtlasRisk's destructive `infra-reset`.

## 4. Firewall change: a `forward` chain

Docker enables IP forwarding on the app server, so a WireGuard peer could try
to route through it. The `firewall` role adds to `inet secureedge`, on both
servers:

```text
chain forward {
    type filter hook forward priority filter; policy accept;
    iifname "<firewall_wireguard_interface>" ct status dnat accept
    iifname "<firewall_wireguard_interface>" drop
}
```

Docker's own container traffic is untouched (policy `accept`, rules match only
`wg0`). A later container port published on the app server's WireGuard
address stays reachable from the edge (DNAT'd), and nothing else from `wg0` is
forwarded.

## 5. Playbooks

`playbooks/app.yml` becomes `base`, `wireguard`, `firewall`,
`container_runtime`, `app_service`. `playbooks/edge.yml` is unchanged.

## 6. Testing

### Molecule

- `app01` becomes `privileged: true` with separate volumes for
  `/var/lib/docker` and `/var/lib/containerd`; `edge01` is unchanged.
- Molecule's `group_vars/app` carries throwaway values for the four vault
  variables, marked test-only.
- Converges pull the real pinned images, so runs take longer.

### Host checks (`tests/host/test_app_service.py`)

On `app` hosts:

- Docker is enabled and active; `docker info` reports `LiveRestoreEnabled`
  true and logging driver `local`.
- Containers `postgres` and `garage` of project `atlasrisk` are running and
  healthy.
- No container publishes a port.
- `pg_isready` succeeds inside `postgres`; the configured bucket exists in
  Garage.
- `/etc/atlasrisk/.env` is root-owned, mode `0600`; the data directories exist.
- The admin user is not in the `docker` group.
- `disruptive`: after `systemctl restart docker` both containers are still
  running (live restore).

On `edge` hosts: Docker is not installed.

In `tests/host/test_firewall.py`, on both groups: the `forward` chain has the
two `wg0` rules.

### Unit tests

The `app_service` input check rejects a missing PostgreSQL password, an image
without a digest, and malformed Garage keys or RPC secret, each before any
task that changes the host.

## 7. Runbook (`docs/runbooks/setup.md`, new section)

1. Generate the values and add them to the vault:
   `openssl rand -base64 36` (PostgreSQL password),
   `printf 'GK%s\n' "$(openssl rand -hex 12)"` (access key),
   `openssl rand -hex 32` (secret key), `openssl rand -hex 32` (RPC secret).
2. Run `site.yml`.
3. Run the host checks.

## 8. What SecureEdge needs from AtlasRisk (input to the AtlasRisk task)

- Container images for the API and the risk worker: non-root, configured only
  through environment variables, published to a private GHCR repository on
  each release tag, referenced by digest.
- A runnable risk-worker entry point that processes the PostgreSQL job queue.
- A migration command (for example `api migrate` or a one-shot image) that
  applies `db/migrations` and exits.
- The web `dist/` bundle as a release artifact for the edge proxy.
- The API's listen address configurable (it already has `-listen`) so it can
  bind to the app server's WireGuard address.

## 9. Documentation updates

- `docs/adr/0007-docker-for-app-services.md`.
- `docs/architecture.md`: the Compose project, no published ports, data
  locations, and the `forward` chain.
- `README.md`: Molecule now needs a privileged app container.

## 10. Out of scope

AtlasRisk's API, worker, migrations and web assets; backups; the edge proxy;
SSH behind WireGuard; Garage clustering or replication.
