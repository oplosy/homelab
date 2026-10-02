# `wireguard` role — design

- **Date:** 2026-10-02
- **Status:** Draft, awaiting owner review
- **Builds on:** `PROJECT.md`, `docs/architecture.md`,
  `docs/superpowers/specs/2026-10-02-repo-layout-design.md`,
  `docs/superpowers/specs/2026-10-02-base-firewall-design.md`
- **Scope:** the WireGuard mesh between both servers and the owner's devices,
  key generation, device configs, the firewall entry, tests, and the runbook
  section. Moving SSH behind the VPN (`firewall_ssh_from: wireguard`) and
  the AtlasRisk upstream rule are out of scope.

## 1. Context and decisions

The edge server must reach AtlasRisk on the app server over an encrypted
tunnel, and the owner needs private access to both servers for the app and
for administration.

| Topic | Decision |
|---|---|
| Topology | Mesh: edge ↔ app, and each device ↔ each server directly. Servers forward nothing |
| Device routing | Split tunnel: devices route only the two server addresses through WireGuard |
| Implementation | `wg-quick@wg0` with a templated `/etc/wireguard/wg0.conf` |
| Keys | Generated once in WSL by `scripts/wireguard-keys`; private keys in the vault, public keys committed |
| Pre-shared keys | Not used for now |
| Owner devices | `pc-windows` (WireGuard for Windows, `.conf` import) and `phone-android` (WireGuard app, QR code) |
| Port | UDP `51820`: `wireguard_port` in `group_vars/all`, repeated literally in the two firewall entries, with a unit test that keeps them equal |

### Approaches considered

1. **`wg-quick` (chosen).** Standard unit, simple config file, live peer
   changes with `wg syncconf` (Ubuntu's `wg-quick@.service` uses it for
   `ExecReload`, verified 2026-10-02).
2. **systemd-networkd.** Rejected: changes go through the same stack that
   carries the provider's primary interface.
3. **netplan WireGuard.** Rejected: private keys end up in netplan YAML,
   entangled with provider and cloud-init netplan files.

### Feasibility check (2026-10-02)

Two `ubuntu:26.04` containers on a custom Docker network with `NET_ADMIN`
brought `wg0` up with `wg-quick`, completed a handshake, and passed ping
over the tunnel under Docker Desktop on WSL2. GitHub's `ubuntu-latest`
kernel has not been checked yet; the first CI run on the implementation PR
is that check.

## 2. Network and keys

### Addresses (`wireguard_subnet: 10.8.0.0/24`)

| Peer | Kind | Address | Endpoint |
|---|---|---|---|
| `edge01` | server | `10.8.0.1` | `vault_edge01_ansible_host`, UDP `wireguard_port` |
| `app01` | server | `10.8.0.2` | `vault_app01_ansible_host`, UDP `wireguard_port` |
| `pc-windows` | device | `10.8.0.11` | none |
| `phone-android` | device | `10.8.0.12` | none |

### Peering

- Each server has one `[Peer]` per other server (with `Endpoint`) and one
  per device (no `Endpoint`), each with `AllowedIPs = <address>/32`.
- Each device has one `[Peer]` per server with `Endpoint`,
  `AllowedIPs = <server address>/32`, and `PersistentKeepalive = 25`.
- No IP forwarding, no `DNS=` line in device configs, IPv4 only inside the
  tunnel.

### `scripts/wireguard-keys NAME...`

A Python script run in the venv. It uses the `cryptography` package
(already installed with Ansible), so WSL needs no `wireguard-tools`. For
each name it creates an X25519 key pair and prints two YAML blocks:

1. `vault_wireguard_private_keys:` with one entry per name, to paste into
   `ansible-vault edit inventories/production/group_vars/all/vault.yml`;
2. the matching `public_key:` values, to paste into the `wireguard_peers`
   list in `inventories/production/group_vars/all/main.yml`.

The owner runs it; private keys never pass through anyone else. Keys are
standard WireGuard base64 (44 characters).

## 3. Role `wireguard`

Runs on both groups. Playbook order becomes `base`, `wireguard`,
`firewall` in `edge.yml` and `app.yml`.

### Variables

| Variable | Where | Default / content |
|---|---|---|
| `wireguard_interface` | role default | `wg0` |
| `wireguard_port` | role default, and set in `group_vars/all/main.yml` | `51820` |
| `wireguard_subnet` | role default | `10.8.0.0/24` |
| `wireguard_peers` | `group_vars/all/main.yml` | required list of `{name, kind: server\|device, address, public_key}`, plus `endpoint` for servers and optional `qr: true` for devices |
| `vault_wireguard_private_keys` | `vault.yml` | required mapping of peer name → private key |

### Behaviour

1. **Input check first** (`ansible.builtin.assert`), before any change:
   every peer has a name matching `^[a-z0-9-]+$`, a kind of `server` or
   `device`, a 44-character base64 `public_key`, and an `address` inside
   `wireguard_subnet`; names and addresses are unique; every server has an
   `endpoint`; this host's `inventory_hostname` is a `server` peer; and
   `vault_wireguard_private_keys[inventory_hostname]` exists and is a
   44-character base64 key.
2. Install `wireguard-tools`.
3. Template `/etc/wireguard/wg0.conf` (owner root, mode `0600`, `no_log`).
4. Enable and start `wg-quick@wg0`. A config change notifies a handler that
   reloads the unit (`wg syncconf`), keeping existing tunnels up. Changing
   a server's own address or port needs a restart; the runbook says so.

### Firewall wiring

The WireGuard port is a `firewall_allowed` entry:
`{name: wireguard, proto: udp, port: 51820, from: any}`. Because a group's
`firewall_allowed` replaces the `all` list rather than merging with it, the
entry is listed in both `group_vars/edge/main.yml` and
`group_vars/app/main.yml`. Later roles append their own entries to those
group lists. The port is written literally there (host checks read the raw
`group_vars`, so a `{{ wireguard_port }}` template would not resolve), and a
unit test asserts both entries equal `wireguard_port` from
`group_vars/all/main.yml`.

### Failure behaviour

- Tunnel down: no route between edge and app, so AtlasRisk access fails
  closed.
- Bad or missing key: the input check stops the run. A key that is valid in
  form but wrong shows as a missing handshake in the host check.
- Peer added or removed: live reload, other tunnels unaffected.

## 4. Device configs (`playbooks/wireguard-clients.yml`)

Runs on `localhost` in WSL, reads the same `wireguard_peers` and vault, and
for each `device` peer:

- writes `<wireguard_clients_dir>/<name>.conf` (default
  `~/.config/secureedge/wireguard`, directory `0700`, files `0600`), never
  inside the repository;
- for peers with `qr: true`, prints the config as a terminal QR code using
  the `segno` package (added to `requirements-dev.txt`).

The Windows config is imported in WireGuard for Windows from
`\\wsl.localhost\Ubuntu\home\atlas\.config\secureedge\wireguard\pc-windows.conf`.

## 5. Testing

### Molecule

- Both containers join a custom Docker network so `edge01` and `app01`
  resolve each other by name; their `endpoint` values are the container
  names.
- Throwaway key pairs for `edge01`, `app01`, and two device peers are
  committed in Molecule's `group_vars`, marked test-only.
- Molecule's `group_vars/edge` and `group_vars/app` add the `wireguard`
  entry to their existing `firewall_allowed` test lists.

### Host checks (`tests/host/test_wireguard.py`)

- `wg0` is up with this host's `/24` address; `wg-quick@wg0` is enabled and
  active.
- `/etc/wireguard/wg0.conf` is owned by root with mode `0600`.
- `wg show wg0 peers` lists exactly the other peers' public keys;
  `wg show wg0 listen-port` is `wireguard_port`.
- Each server pings the other server's WireGuard address, and the
  handshake with the other server is recent (within 180 seconds).

### Unit tests

- `scripts/wireguard-keys`: keys are 44-character base64, each public key
  matches its private key, and output contains both YAML blocks.
- `playbooks/wireguard-clients.yml`, run against a temporary inventory and
  output directory: file modes, `AllowedIPs` limited to the two server
  `/32`s, `PersistentKeepalive = 25`, no `DNS` line, a QR code printed only
  for `qr: true` peers.
- Role input check: duplicate address, address outside the subnet, missing
  private key, and this host missing from `wireguard_peers` each fail at the
  first task.
- Production inventory: `firewall_allowed` for both groups is exactly the
  `wireguard` entry, and its port equals `wireguard_port`.

## 6. Runbook (`docs/runbooks/setup.md`, new section after §5)

1. `scripts/wireguard-keys edge01 app01 pc-windows phone-android`; paste
   the private keys into the vault and the public keys plus addresses into
   `wireguard_peers`; commit the public part.
2. `ansible-playbook playbooks/site.yml`.
3. `ansible-playbook playbooks/wireguard-clients.yml`; import
   `pc-windows.conf` on Windows and scan the QR code on the phone.
4. Check from Windows and the phone: `ping 10.8.0.1` and `ping 10.8.0.2`.
5. Check from WSL: `ping 10.8.0.1`. Record whether WSL reaches the tunnel
   through Windows; moving SSH behind the VPN depends on it.

Until step 1 is done, `site.yml` stops at the `wireguard` input check with
a message pointing to this section.

## 7. Documentation updates

- `docs/adr/0006-wireguard-mesh.md`: mesh, split tunnel, keys in the vault.
- `docs/architecture.md`: address table, peering, and the device configs.
- `docs/evidence/README.md` stays "Not yet" until the runbook has run on real
  servers.

## 8. Out of scope

Moving SSH behind WireGuard, the AtlasRisk upstream rule on the app server,
pre-shared keys, IPv6 inside the tunnel, device-to-device traffic, and
devices beyond `pc-windows` and `phone-android`.
