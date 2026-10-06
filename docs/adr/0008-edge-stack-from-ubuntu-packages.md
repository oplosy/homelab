# 0008: Edge stack from Ubuntu packages

- **Status:** Accepted
- **Date:** 2026-10-04

## Context

The edge server needs NGINX, ModSecurity with OWASP CRS, and an ACME client.
It runs no Docker. Ubuntu 26.04 packages NGINX 1.28, the ModSecurity
connector 1.0.3 with libmodsecurity 3.0.14, CRS 3.3.8, and certbot 4.0.
CRS 4.x exists upstream but is not packaged.

## Decision

Install every edge component from Ubuntu. Run CRS 3.3.8 in blocking mode at
paranoia level 1. Use certbot with the webroot authenticator (HTTP-01), a
deploy hook that copies the certificate to `/etc/secureedge/tls` and
reloads NGINX, and the package's `certbot.timer`.

## Consequences

- Security updates for every edge component arrive through
  `unattended-upgrades`.
- CRS 3.3 has more false positives on JSON APIs than 4.x. Switching to a
  pinned 4.x release later only changes where `edge_proxy` loads the rules
  from.
- HTTP-01 works with any DNS host but needs port 80 open on the edge.
- Molecule tests issuance and renewal against Pebble on edge01.
