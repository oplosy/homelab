# `base` and `firewall` roles — design

- **Date:** 2026-10-02
- **Status:** Draft, awaiting owner review
- **Builds on:** `PROJECT.md`, `docs/superpowers/specs/2026-10-02-repo-layout-design.md`
- **Scope:** the first two roles, the playbooks and inventory variables they
  need, Molecule testing, host checks, CI, and the setup runbook. WireGuard,
  NGINX, and every other role are out of scope.

## 1. Context and decisions

Both VPSs need the same hardened baseline and a default-deny firewall before
any service is installed. No VPS exists yet, so everything must be testable
locally and in CI.

| Topic | Decision |
|---|---|
| Server OS | Ubuntu 26.04 LTS on both servers |
| Role testing before a VPS exists | Molecule with Docker; the same host checks later run against real servers |
| SSH exposure during first setup | Reachable from anywhere, key-only, rate-limited per source IP in nftables; no fail2ban |
| Kernel and security updates | unattended-upgrades, security origin only, automatic reboot when required, at a different time per server |
| Firewall ownership | SecureEdge owns only its own nftables table, `inet secureedge`; other tables (Docker's) are left alone |
| sudo | Admin user needs a password for sudo; the hash and the plain password live in the vault |

### Approaches considered for the firewall

1. **Own table `inet secureedge` (chosen).** Replaced atomically; never
   touches other tables, so Docker on the app server keeps working.
2. **Own the whole ruleset (`flush ruleset`).** Rejected: every run would
   delete Docker's rules and break container networking.
3. **ufw.** Rejected: the design disables ufw, and ufw hides the nftables
   rules the architecture documents.

## 2. Role `base`

Runs on both groups. Fails before changing anything if a required variable
is missing (`ansible.builtin.assert` as the first task).

### Variables

| Variable | Default | Notes |
|---|---|---|
| `base_admin_user` | required | Login name for the owner |
| `base_admin_ssh_keys` | required | List of public keys; public keys may be committed |
| `base_admin_password_hash` | required | SHA-512 crypt hash, from the vault |
| `base_reboot_time` | required | `HH:MM` in UTC; edge `"01:00"`, app `"01:30"` (04:00 and 04:30 Turkey time) |
| `base_timezone` | `UTC` | |
| `base_journald_max_use` | `500M` | journald `SystemMaxUse` |
| `base_sshd_max_auth_tries` | `3` | |
| `base_remove_snapd` | `true` | |
| `base_set_hostname` | `true` | Set to `false` in Molecule (Docker forbids it) |

### Behaviour

- **Admin user.** Creates `base_admin_user` with the password hash, adds it
  to the `sudo` group, and installs `base_admin_ssh_keys` as its only
  authorized keys (`exclusive: true`). sudo asks for the password.
- **sshd.** Writes `/etc/ssh/sshd_config.d/10-secureedge.conf`:
  `PermitRootLogin no`, `PasswordAuthentication no`,
  `KbdInteractiveAuthentication no`, `PubkeyAuthentication yes`,
  `AllowUsers <base_admin_user>`, `MaxAuthTries <base_sshd_max_auth_tries>`,
  `X11Forwarding no`. sshd keeps the first value it reads and includes files
  in lexical order, so `10-` wins over cloud-init's `50-cloud-init.conf`. The
  file is validated with `sshd -t` before a reload of `ssh.service`. The SSH
  port stays 22, so Ubuntu's socket activation needs no change.
- **Updates.** Installs `unattended-upgrades`, enables the periodic run,
  limits origins to the security pocket, and sets `Automatic-Reboot "true"`,
  `Automatic-Reboot-Time "<base_reboot_time>"`, and
  `Remove-Unused-Dependencies "true"`.
- **Ubuntu cleanup.** Removes snapd when `base_remove_snapd` is true; stops,
  disables, and purges ufw. cloud-init is not touched.
- **Time and logs.** Sets the timezone. Asserts the distribution's default
  time service is enabled and running, without reconfiguring it. Writes a
  journald drop-in with `SystemMaxUse=<base_journald_max_use>`.
- **Hostname.** Sets it to `inventory_hostname` when `base_set_hostname`.

### First connection (`playbooks/bootstrap.yml`)

Runs `base` once on all hosts, connecting as the provider's initial user
(`-e bootstrap_user=root` or `ubuntu`) with the SSH key the owner added in the
provider panel. After it, every playbook connects as `base_admin_user`. The
provider's initial user is left in place; `AllowUsers` keeps it from logging
in over SSH.

## 3. Role `firewall`

Runs on both groups, after `base`.

### Variables

| Variable | Default | Notes |
|---|---|---|
| `firewall_ssh_from` | `any` | `any` or `wireguard` (only via `firewall_wireguard_interface`) |
| `firewall_ssh_rate` | `10/minute` | New SSH connections per source IP |
| `firewall_ssh_burst` | `5` | |
| `firewall_allowed` | `[]` | List of `{name, proto: tcp\|udp, port: 1-65535, from: any\|wireguard}` |
| `firewall_wireguard_interface` | `wg0` | |
| `firewall_revert_seconds` | `120` | Lockout guard window |
| `firewall_log_drops` | `true` | Rate-limited log of dropped packets |

The role asserts the shape of every `firewall_allowed` entry and the value of
`firewall_ssh_from` before changing anything. `firewall_allowed` starts empty
in every group: each later role adds its own entry when the service exists
(NGINX adds 80 and 443, WireGuard adds its UDP port).

### Ruleset

One table, `inet secureedge` (IPv4 and IPv6), one base chain:

- `input`, hook `input`, priority `filter`, **policy `drop`**:
  1. `ct state established,related` accept; `ct state invalid` drop.
  2. `iif lo` accept.
  3. ICMPv4: echo-request (rate-limited), destination-unreachable,
     time-exceeded. ICMPv6: echo-request (rate-limited), destination-
     unreachable, packet-too-big, time-exceeded, parameter-problem, and
     neighbour/router discovery.
  4. SSH (tcp 22, new connections): per-source-IP limit of
     `firewall_ssh_rate` with burst `firewall_ssh_burst` using dynamic sets
     for IPv4 and IPv6; over-limit packets are dropped. Accepted from
     anywhere when `firewall_ssh_from: any`, only on
     `firewall_wireguard_interface` when `wireguard`.
  5. One accept rule per `firewall_allowed` entry, restricted to the
     WireGuard interface when its `from` is `wireguard`.
  6. When `firewall_log_drops`: rate-limited `log prefix "secureedge-drop: "`
     before the policy drop.

No `forward` or `output` chains. Outbound traffic is allowed; Docker manages
forwarding on the app server.

### Files on the host

| Path | Content |
|---|---|
| `/etc/nftables.conf` | Only `include "/etc/nftables.d/*.nft"`; no `flush ruleset` |
| `/etc/nftables.d/secureedge.nft` | `table inet secureedge` / `delete table inet secureedge` / full table definition, so one `nft -f` replaces the table atomically |
| `/etc/systemd/system/nftables.service.d/secureedge.conf` | Clears `ExecStop` and sets it to `nft delete table inet secureedge`, so stopping the service never flushes other tables |
| `/var/lib/secureedge/firewall/secureedge.nft.prev` | Backup used by the lockout guard |
| `/usr/local/sbin/secureedge-firewall-revert` | Restores the backup and loads it; with no backup, removes our file and deletes our table |

`nftables.service` is enabled so the ruleset loads at boot.

### Lockout guard

1. Render the new ruleset to a temporary file and check it with
   `nft -c -f`. An invalid ruleset fails the run with nothing changed.
2. If it differs from the installed file: copy the installed file (if any)
   to the backup path, then schedule
   `systemd-run --unit=secureedge-firewall-revert --on-active=<firewall_revert_seconds> /usr/local/sbin/secureedge-firewall-revert`.
3. Install the new file and load it with `nft -f`.
4. `meta: reset_connection`, then `wait_for_connection` (timeout 30 s), so a
   brand-new SSH login must succeed under the new rules.
5. On success, stop `secureedge-firewall-revert.timer`. On failure, the run
   fails and the timer restores the previous ruleset within
   `firewall_revert_seconds`.

In Molecule the connection is `docker exec`, so step 4 proves little there.
The runbook includes a one-time drill on a real VPS (§6).

### Docker interaction

Ports that Docker publishes are DNATed before the `input` hook, so this
firewall cannot protect them. Rule for every later role: containers publish
ports only on the WireGuard address or `127.0.0.1`. The future `app_service`
role enforces it, and a host check verifies it.

## 4. Playbooks, inventory, and dependencies

- `playbooks/bootstrap.yml`: `hosts: all`, `remote_user: "{{ bootstrap_user }}"`, `become: true`, role `base`.
- `playbooks/edge.yml`: `hosts: edge`, `become: true`, roles `base`, `firewall`.
- `playbooks/app.yml`: `hosts: app`, `become: true`, roles `base`, `firewall`.
- `playbooks/site.yml`: imports `edge.yml` then `app.yml`.
- `inventories/production/group_vars/all/main.yml`: `base_admin_user`,
  `base_admin_ssh_keys`, `ansible_user: "{{ base_admin_user }}"`,
  `ansible_become_password: "{{ vault_base_admin_password }}"`,
  `base_admin_password_hash: "{{ vault_base_admin_password_hash }}"`.
  The admin user name and public key are the owner's real values. The owner
  supplies both before implementation starts; the committed file uses them,
  not placeholders.
- `inventories/production/group_vars/edge/main.yml`: `base_reboot_time: "01:00"`.
- `inventories/production/group_vars/app/main.yml`: `base_reboot_time: "01:30"`.
- `inventories/production/group_vars/all/vault.yml` (owner-created, encrypted):
  `vault_edge01_ansible_host`, `vault_app01_ansible_host`,
  `vault_base_admin_password`, `vault_base_admin_password_hash`.
- `requirements.yml`: collections `ansible.posix`, `community.docker`.
- `requirements-dev.txt`: add `molecule` and `molecule-plugins[docker]`.

## 5. Testing

### Molecule (`molecule/default/`)

- Two containers, `edge01` (group `edge`) and `app01` (group `app`), built
  from a local Dockerfile: `ubuntu:26.04` plus `systemd`, `systemd-sysv`,
  `python3`, `sudo`, `openssh-server`, running `/sbin/init`, with
  `NET_ADMIN`, host cgroup namespace, and `/sys/fs/cgroup` mounted
  read-write.
- Converge imports `playbooks/site.yml`, so playbook wiring is tested, not
  only each role.
- Test values replace the vault (a throwaway admin user, key, and password
  hash) and `base_set_hostname: false`.
- `scripts/molecule-check`: create → converge → idempotence → host checks
  (`pytest -m host --hosts=docker://edge01,docker://app01`) → destroy, with
  destroy always running. Docker must be running (Docker Desktop locally).

### Host checks (`tests/host/`)

The same files run against Molecule containers and, later, real servers
(`pytest -m host --hosts=ansible://all --ansible-inventory=inventories/production`).
A host's group is taken from its hostname prefix (`edge` or `app`).
Every test under `tests/host/` carries the `host` marker and is skipped when
pytest runs without `--hosts`. Otherwise testinfra would default to the local
machine, and a plain `pytest` in WSL or CI would check the wrong host.

`tests/host/test_base.py`:
- admin user exists, is in `sudo`, and has exactly the configured keys;
- `sshd -T` shows `permitrootlogin no`, `passwordauthentication no`,
  `kbdinteractiveauthentication no`, `allowusers <admin>`, `maxauthtries 3`;
- unattended-upgrades is installed and configured with automatic reboot at
  the group's time;
- journald drop-in present; timezone is UTC;
- snapd and ufw are not installed.

`tests/host/test_firewall.py`:
- table `inet secureedge` exists and its `input` chain has policy `drop`;
- SSH rule and rate-limit sets are present;
- `/etc/nftables.conf` contains no `flush ruleset`; the systemd drop-in is
  present; `nftables.service` is enabled;
- no `secureedge-firewall-revert` timer is left active;
- `disruptive`: create a dummy table, run `systemctl reload nftables` and
  `systemctl restart nftables`, and assert the dummy table still exists;
  then delete it.

### CI

A second job in `.github/workflows/ci.yml`, `molecule`, runs
`scripts/molecule-check` on `ubuntu-latest`. The existing `check` job is
unchanged.

## 6. Runbook (`docs/runbooks/setup.md`)

From a bought VPS to a hardened server:

1. Confirm the provider meets the requirements in the layout spec §8 and
   offers Ubuntu 26.04; add your SSH public key in the provider panel.
2. Create the vault password (README), generate the admin password and its
   SHA-512 hash, create `group_vars/all/vault.yml` with
   `ansible-vault create`, and set the admin user name and public key in
   `group_vars/all/main.yml`.
3. `ansible-playbook playbooks/bootstrap.yml -e bootstrap_user=<root|ubuntu>`.
4. `ansible-playbook playbooks/site.yml`.
5. `pytest -m host --hosts=ansible://all --ansible-inventory=inventories/production`.
6. Lockout drill (once): set `firewall_ssh_from: wireguard` for one host,
   run `site.yml` and watch it fail at the reconnect step; wait
   `firewall_revert_seconds`; confirm SSH works and the old ruleset is back;
   set the value back.

## 7. Documentation updates

- `docs/adr/0004-ubuntu-26-04.md` and `docs/adr/0005-molecule-for-role-tests.md`.
- `docs/architecture.md`: SSH rate limit, the `inet secureedge` table, and
  the Docker publish rule.
- `README.md`: Molecule prerequisites and `scripts/molecule-check`.
- `docs/evidence/README.md` stays "Not yet" until the runbook has run on
  real servers.

## 8. Additions to the layout spec

`molecule/`, `scripts/`, and `docs/runbooks/setup.md` are new top-level
paths not drawn in the layout spec's tree; they follow its rule that
directories appear only with real content.

## 9. Out of scope

WireGuard and the switch of `firewall_ssh_from` to `wireguard` in
production, all other roles, outbound filtering, fail2ban, Livepatch, and
removing the provider's initial user.
