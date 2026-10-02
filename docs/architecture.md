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
   Without a valid session, browser routes redirect to login and API routes
   get 401.
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
| both | 22/tcp | key-only from the internet during first setup; WireGuard only afterwards | SSH administration |

Every other inbound connection is dropped. Port numbers are set in the
inventory when the matching roles are built.

## Failure behaviour

- **oauth2-proxy down:** NGINX returns an error. Requests are never forwarded
  unauthenticated.
- **Tunnel down:** AtlasRisk listens only on its WireGuard address, so there
  is no route to it at all. It is never reachable another way.
- **WireGuard or firewall mistake that locks out SSH:** recover through the
  provider's web console.

## Decisions

See [adr/](adr/0001-ansible-for-configuration.md). Open choices (VPS provider,
container runtime, identity provider, ACME client, backup and monitoring
tools) are listed in the layout spec and get an ADR when decided.
