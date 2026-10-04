# 0006: WireGuard mesh with keys in the vault

- **Status:** Accepted
- **Date:** 2026-10-02

## Context

The edge server must reach AtlasRisk on the app server privately, and the
owner needs private access to both servers from a Windows PC and an Android
phone.

## Decision

Run `wg-quick@wg0` on both servers in a mesh: edge and app peer with each
other, and each device peers with each server. Devices use a split tunnel
(only `10.8.0.1/32` and `10.8.0.2/32`). Key pairs are created once in WSL
with `scripts/wireguard-keys`; private keys live in the vault and public
keys in `group_vars`.

## Consequences

- A rebuilt server gets its old key back, so no other peer changes.
- Either server stays reachable over the VPN when the other is down.
- Servers forward nothing, so devices cannot reach each other.
- Device configs live in `~/.config/secureedge/wireguard` inside WSL, never
  in the repository.
- Molecule brings up a real tunnel between two containers; this needs
  WireGuard support in the host kernel (Docker Desktop and GitHub runners).
