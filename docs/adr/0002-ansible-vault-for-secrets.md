# 0002: Ansible Vault for secrets

- **Status:** Accepted
- **Date:** 2026-10-02

## Context

The deployment needs secrets: WireGuard private keys, the OIDC client secret,
the oauth2-proxy cookie secret, backup encryption keys, and host addresses.
None may be committed in plain text.

## Decision

Keep secrets in `group_vars/<group>/vault.yml` files encrypted with Ansible
Vault. Variables are prefixed `vault_` and referenced from the plain
`main.yml` beside them. The vault password lives at
`~/.config/secureedge/vault_pass` inside WSL (mode 600), with a copy in the
owner's password manager.

## Consequences

- No extra tool beyond Ansible.
- Diffs of an encrypted file are unreadable; `ansible-vault view` or `edit`
  is needed to review changes.
- A guard test fails CI if any tracked `vault.yml` is not encrypted.
- Losing the password means re-creating every secret.
