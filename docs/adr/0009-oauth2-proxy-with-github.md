# 0009: oauth2-proxy with GitHub as the identity provider

- **Status:** Accepted
- **Date:** 2026-10-06

## Context

AtlasRisk is single-user and expects an external login in front of it
(its ADR-001). PROJECT.md asks for a verified identity with MFA through the
identity provider, and cross-site request protection for state-changing API
calls. Ubuntu 26.04 does not package oauth2-proxy, and the edge server runs
no Docker.

## Decision

Run oauth2-proxy 7.15.5 from its GitHub release archive, verified against a
pinned sha256, as a sandboxed systemd service on 127.0.0.1:4180. Use the
GitHub provider limited to the owner's account, with scope `user:email read:org`
(no repository access; the provider reads the account's organizations, teams
and e-mail addresses at every login, so `read:user` alone fails); MFA is
the account's GitHub two-factor authentication. Sessions last seven days in
a `__Host-` cookie (`Secure`, `HttpOnly`, `SameSite=Lax`). NGINX refuses
state-changing API requests whose `Origin` is not the site or whose
`Sec-Fetch-Site` is not `same-origin`, and strips identity headers and
cookies before AtlasRisk.

## Consequences

- oauth2-proxy updates are manual: bump the version and checksum together.
- GitHub is an external dependency: if it is down, nobody can sign in, but
  existing sessions keep working until they expire.
- GitHub uses OAuth 2.0 plus its API rather than OIDC; the identity is still
  verified by GitHub.
- Molecule checks the redirect to GitHub but cannot sign in; the full
  sign-in is checked by hand per the runbook.
