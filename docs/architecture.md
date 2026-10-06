# Architecture

This is the target design. What is implemented today is tracked in
[evidence/README.md](evidence/README.md).

## Overview

```text
Owner -> WireGuard -> private application access and server administration

Browser -> HTTPS -> edge: NGINX + ModSecurity/CRS -> oauth2-proxy auth check
        -> WireGuard -> app: AtlasRisk container

Databases, object storage, and management interfaces stay private.
```

## Hosts

| Host | Group | Runs |
|---|---|---|
| `edge01` | `edge` | NGINX with ModSecurity and OWASP CRS, oauth2-proxy, ACME certificates, WireGuard |
| `app01` | `app` | Container runtime, AtlasRisk and its private dependencies, backups, WireGuard |

## Request flow

1. The browser connects to `edge01` over HTTPS (443). Plain HTTP on 80 only
   serves ACME challenges and redirects to HTTPS.
2. ModSecurity with OWASP CRS inspects the request.
3. NGINX asks oauth2-proxy (localhost only) whether the session is valid.
   oauth2-proxy accepts only the GitHub accounts in
   `secureedge_auth.github_users`; if it is down, NGINX returns 500 for every
   application request.
   Without a valid session, browser routes redirect to login and API routes
   get 401. State-changing API requests (POST, PUT, PATCH, DELETE) must come
   from the site itself (`Origin`, `Sec-Fetch-Site`); others get 403 before
   the login check.
4. API routes have rate limits; excess requests get 429.
5. NGINX forwards to AtlasRisk on `app01` through the WireGuard tunnel.

## Open ports

| Host | Port | Reachable from | Purpose |
|---|---|---|---|
| `edge01` | 80/tcp | internet | ACME challenges, redirect to HTTPS |
| `edge01` | 443/tcp | internet | HTTPS |
| `edge01` | WireGuard/udp | internet | Tunnel to `app01` and owner devices |
| `edge01` | oauth2-proxy/tcp | 127.0.0.1 only | Auth checks from NGINX |
| `app01` | WireGuard/udp | internet | Tunnel to `edge01` and owner devices |
| `app01` | AtlasRisk/tcp | `edge01` over WireGuard only | Application upstream |
| both | 22/tcp | key-only from the internet during first setup, at most 10 new connections per minute per source IP; WireGuard only afterwards | SSH administration |

Every other inbound connection is dropped. Port numbers are set in the
inventory when the matching roles are built.

## WireGuard

| Peer | Address | Connects to |
|---|---|---|
| `edge01` | `10.8.0.1` | `app01`, both devices |
| `app01` | `10.8.0.2` | `edge01`, both devices |
| `pc-windows` | `10.8.0.11` | both servers |
| `phone-android` | `10.8.0.12` | both servers |

Both servers listen on UDP 51820. Devices route only the two server
addresses through the tunnel and keep it alive every 25 seconds; servers
forward nothing. See [adr/0006-wireguard-mesh.md](adr/0006-wireguard-mesh.md).

## AtlasRisk data services

On `app01`, Docker runs the Compose project `atlasrisk` from
`/etc/atlasrisk`: PostgreSQL 18.6 and Garage 2.4.1, pinned by digest, with
data under `/srv/atlasrisk`. No container publishes a port; services reach
each other only on the Compose network. See
[adr/0007-docker-for-app-services.md](adr/0007-docker-for-app-services.md).

## Backups

Every night at 03:00, app01 dumps PostgreSQL (`pg_dump -Fc`), takes a
consistent copy of Garage's metadata (`garage meta snapshot`), and backs
both up with Garage's data blocks to a Cloudflare R2 bucket with restic
(encrypted; 7 daily, 4 weekly, 6 monthly). `playbooks/restore.yml` restores
a snapshot and moves the current data aside instead of deleting it. See
[adr/0010-restic-backups-to-r2.md](adr/0010-restic-backups-to-r2.md) and
[runbooks/restore.md](runbooks/restore.md).

## Monitoring

Both servers run `secureedge-monitor` every five minutes. It checks disk,
memory, load, failed units, and the other server over WireGuard. On edge01
it also checks NGINX, oauth2-proxy and the certificate. On app01 it also
checks Docker, the AtlasRisk containers and the backup age. When the set
of problems changes, it sends one ntfy push alert that names the checks,
never logs or data. See
[adr/0011-self-checks-with-ntfy-alerts.md](adr/0011-self-checks-with-ntfy-alerts.md).

## Edge proxy

On `edge01`, NGINX serves `secureedge_app.domain` with a Let's Encrypt
certificate (certbot, HTTP-01 through `/.well-known/acme-challenge/` on
port 80). Each application request passes, in order: ModSecurity with OWASP
CRS 3.3 (blocking, paranoia level 1), the API rate limit (`429` beyond the
burst), the `auth_request` check against `127.0.0.1:4180`, then either the
static web root or the AtlasRisk upstream over WireGuard. Names other than
the application's get no TLS handshake, and a request for another Host is
closed without a response. Only the API accepts large bodies; other routes
take at most 64 KiB. The WAF audit log (`/var/log/modsecurity/audit.log`,
readable by root and `adm` only) keeps the matched rules, never request
headers or bodies as such; a value that triggers a rule is logged with it.
See
[adr/0008-edge-stack-from-ubuntu-packages.md](adr/0008-edge-stack-from-ubuntu-packages.md).
oauth2-proxy runs as a sandboxed service on `127.0.0.1:4180`; identity
headers and cookies are stripped before AtlasRisk. See
[adr/0009-oauth2-proxy-with-github.md](adr/0009-oauth2-proxy-with-github.md).

## Firewall

The `firewall` role owns one nftables table, `inet secureedge`, whose
`input` chain drops by default. It never flushes the whole ruleset, so
tables owned by other software (Docker) survive reloads and restarts.
Ports open only through `firewall_allowed`, which each service role extends
when it is added.

Every change is checked with `nft -c` and applied behind a lockout guard: a
one-off timer restores the previous ruleset after 120 seconds unless a
fresh SSH connection succeeds and cancels it.

Ports published by Docker bypass the `input` chain. Containers must
therefore publish only on the WireGuard address or `127.0.0.1`.

A `forward` chain drops anything arriving from WireGuard that would be
routed onward, except DNAT'd traffic to a published container port, so a VPN
device cannot use the app server as a router.

## Failure behaviour

- **oauth2-proxy down:** NGINX returns an error. Requests are never forwarded
  unauthenticated.
- **Tunnel down:** AtlasRisk listens only on its WireGuard address, so there
  is no route to it at all. It is never reachable another way.
- **WireGuard or firewall mistake that locks out SSH:** recover through the
  provider's web console.

## Decisions

See [adr/](adr/0001-ansible-for-configuration.md). The VPS provider is the
remaining open choice from the layout spec.
