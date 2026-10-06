# 0012: AtlasRisk releases on the servers

- **Status:** Accepted
- **Date:** 2026-10-06

## Context

AtlasRisk now publishes each release as an API image (which also applies the
database migrations), a risk-worker image, and a web bundle with its
SHA-256, all named in the release's `images.txt` and notes. SecureEdge must
run them without the source tree, update them without manual steps on the
servers, and keep the API reachable only through the edge proxy.

## Decision

- One inventory block, `secureedge_app.release`, names a release: both images
  by digest, the web bundle URL and its SHA-256. Without it the servers run
  as before: data services and a placeholder page.
- On `app01`, the API and worker join the `atlasrisk` Compose project with a
  read-only root filesystem, no capabilities, and `no-new-privileges`. Before
  they (re)start, Ansible runs the API image's `migrate` command once
  (`docker compose --profile migrate run --rm migrate`); restores do the
  same, because a backup can predate the running release.
- The API is the one published port, on the WireGuard address only. The
  firewall forwards DNAT'd WireGuard traffic only from the addresses in
  `firewall_published_from`, which on `app01` are the edge servers'. This
  amends 0007's "no published ports" and replaces its "any WireGuard peer"
  forward rule.
- Docker on `app01` starts after `wg-quick@wg0`, so the API's address exists
  when containers restart at boot.
- On `edge01`, the web bundle is downloaded with its checksum checked,
  unpacked into a directory named by that checksum, and served through a
  link that switches atomically.

## Consequences

- Upgrading is: back up, change `secureedge_app.release`, run `site.yml`.
- Owner devices on WireGuard reach the application only through the edge,
  like everyone else.
- Migrations are forward-only. Rolling back to an older release works only
  if the newer one added no migration; otherwise restore the backup.
- Old web bundles stay under `/var/lib/secureedge/web` (a few hundred KB
  each) until removed by hand.
- Molecule has no real release to pull, so it publishes a stand-in image with
  the same command line to a registry on `app01`'s loopback.
