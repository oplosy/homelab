# Setup: from a new VPS to a hardened server

Run every command inside WSL at the repository root, with the venv active
and `export ANSIBLE_CONFIG="$PWD/ansible.cfg"`.

## 1. Buy and prepare the servers

- Check the provider against the requirements in the
  [layout spec](../superpowers/specs/2026-10-02-repo-layout-design.md) §8:
  KVM, Ubuntu 26.04, public IPv4, WireGuard UDP not filtered, a web console.
- Choose Ubuntu 26.04 and add the public key
  `C:\Users\mesut\.ssh\server_ed25519.pub` in the provider panel.
- Copy the private key into WSL once:

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
cp /mnt/c/Users/mesut/.ssh/server_ed25519 ~/.ssh/server_ed25519
chmod 600 ~/.ssh/server_ed25519
```

## 2. Domain and certificates

The edge server serves the application at `secureedge_app.domain` with a
Let's Encrypt certificate. The certificate needs a domain that already
points at edge01:

1. Buy a domain from any registrar.
2. In its DNS, create an `A` record for the application name (for example
   `atlasrisk.<your domain>`) pointing at the edge server's public IPv4, and
   an `AAAA` record if the VPS has IPv6.
3. Set `domain` under `secureedge_app` in
   `inventories/production/group_vars/all/main.yml` and commit it.
4. Wait until `getent hosts <name>` returns the edge server's address, then
   apply (§5).

Applying the `tls` role accepts the Let's Encrypt subscriber agreement.
Until a certificate is issued, NGINX serves a placeholder certificate and
browsers show a certificate error. The edge run also needs the login
values from §10; until they are in the vault, the `oauth2_proxy` role stops
and points there. Changing the domain later issues a new certificate on the
next run.

## 3. Create the vault

Create the vault password first (see the README), then generate the admin
sudo password's hash. `openssl` prompts for the password twice:

```bash
openssl passwd -6
```

Create the vault and fill in the real values:

```bash
ansible-vault create inventories/production/group_vars/all/vault.yml
```

```yaml
vault_edge01_ansible_host: <edge server IP>
vault_app01_ansible_host: <app server IP>
vault_base_admin_password: <the sudo password you just chose>
vault_base_admin_password_hash: <the line openssl printed>
```

## 4. Bootstrap

Use the provider's initial user (`root` or `ubuntu`). Compare the host key
fingerprint with the one in the provider console when asked.

```bash
ansible-playbook playbooks/bootstrap.yml -e bootstrap_user=root
```

From now on every run connects as `atlas`.

## 5. Apply everything

```bash
ansible-playbook playbooks/site.yml
```

## 6. Check the servers

```bash
pytest -m host --hosts=ansible://all --force-ansible --ansible-inventory=inventories/production/hosts.yml
```

`--force-ansible` makes every check go through Ansible, so the vault-backed
host addresses resolve and root-only checks can use the sudo password.

## 7. WireGuard

Run this before the first `site.yml` (step 5): until it is done, the
`wireguard` role stops with a message pointing here.

Create the key pairs:

```bash
scripts/wireguard-keys edge01 app01 pc-windows phone-android
```

Paste the first block into the vault:

```bash
ansible-vault edit inventories/production/group_vars/all/vault.yml
```

Add this to `inventories/production/group_vars/all/main.yml`, with the
public keys from the second block, and commit it (public keys are not
secret):

```yaml
wireguard_peers:
  - name: edge01
    kind: server
    address: 10.8.0.1
    public_key: <edge01 public key>
    endpoint: "{{ vault_edge01_ansible_host }}"
  - name: app01
    kind: server
    address: 10.8.0.2
    public_key: <app01 public key>
    endpoint: "{{ vault_app01_ansible_host }}"
  - name: pc-windows
    kind: device
    address: 10.8.0.11
    public_key: <pc-windows public key>
  - name: phone-android
    kind: device
    address: 10.8.0.12
    public_key: <phone-android public key>
    qr: true
```

After `site.yml` has run, create the device configs:

```bash
ansible-playbook playbooks/wireguard-clients.yml
```

- **Windows:** in WireGuard for Windows, choose "Import tunnel(s) from file"
  and open
  `\\wsl.localhost\Ubuntu\home\atlas\.config\secureedge\wireguard\pc-windows.conf`.
- **Android:** in the WireGuard app, choose "Scan from QR code" and scan
  `phone-android.png` from the same folder, opened on the PC screen.

Check from Windows and from the phone (with the tunnel on): `ping 10.8.0.1`
and `ping 10.8.0.2`. Then check from WSL:

```bash
ping -c 2 10.8.0.1
```

Write down whether WSL reaches the tunnel through Windows. Moving SSH behind
WireGuard depends on it.

Changing a server's own WireGuard address or the port needs
`sudo systemctl restart wg-quick@wg0` on that server after `site.yml`;
peer changes apply live.

## 8. AtlasRisk data services

PostgreSQL and Garage run on the app server in the Compose project
`/etc/atlasrisk`, with data in `/srv/atlasrisk` and no published ports.
Generate their secrets once:

```bash
openssl rand -base64 36                 # PostgreSQL password
printf 'GK%s\n' "$(openssl rand -hex 12)"  # Garage access key
openssl rand -hex 32                     # Garage secret key
openssl rand -hex 32                     # Garage RPC secret
```

Add them to the vault:

```bash
ansible-vault edit inventories/production/group_vars/all/vault.yml
```

```yaml
vault_atlasrisk_postgres_password: <PostgreSQL password>
vault_atlasrisk_garage_access_key: <GK… access key>
vault_atlasrisk_garage_secret_key: <secret key>
vault_atlasrisk_garage_rpc_secret: <RPC secret>
```

Then run `ansible-playbook playbooks/site.yml` and the host checks (§6).
On the server, `sudo docker compose --project-directory /etc/atlasrisk ps`
shows both services; `sudo docker compose --project-directory /etc/atlasrisk
exec postgres psql -U atrisk atrisk` opens a database shell.

## 9. Backups

app01 backs up PostgreSQL and Garage every night at 03:00 with restic to a
Cloudflare R2 bucket, keeping 7 daily, 4 weekly and 6 monthly snapshots.

1. In Cloudflare: R2 → create a bucket (for example `secureedge-backups`).
   Then R2 → Manage API tokens → create a token with **Object Read & Write**
   on that bucket only. Note the access key id, the secret access key, and
   your account id (shown in the R2 overview).
2. Generate the restic password and **store it in your password manager as
   well**: without it the backups cannot be decrypted.

```bash
openssl rand -base64 36
```

3. Set the non-secret values in `inventories/production/group_vars/app/main.yml`:

```yaml
backup_r2_account_id: <32-character account id>
backup_r2_bucket: secureedge-backups
```

4. Add the secrets to the vault:

```bash
ansible-vault edit inventories/production/group_vars/all/vault.yml
```

```yaml
vault_backup_restic_password: <restic password>
vault_backup_r2_access_key_id: <access key id>
vault_backup_r2_secret_access_key: <secret access key>
```

5. Apply. The first run creates the repository. Take a backup and list it:

```bash
ansible-playbook playbooks/backup.yml
```

Restoring is described in [restore.md](restore.md). Run the restore drill
there once and record it in [evidence/README.md](../evidence/README.md).

## 10. Login (GitHub)

Only the GitHub accounts in `secureedge_auth.github_users` can sign in.
Multi-factor authentication comes from GitHub, so turn on two-factor
authentication for those accounts first.

1. On GitHub: Settings → Developer settings → OAuth Apps → New OAuth App.
   Homepage `https://<domain>`, authorization callback
   `https://<domain>/oauth2/callback`. Generate a client secret.
2. Generate the cookie secret:

```bash
openssl rand -base64 32 | tr -- '+/' '-_'
```

3. Add the values to the vault:

```bash
ansible-vault edit inventories/production/group_vars/all/vault.yml
```

```yaml
vault_oauth2_proxy_client_id: <client ID>
vault_oauth2_proxy_client_secret: <client secret>
vault_oauth2_proxy_cookie_secret: <cookie secret>
```

4. Apply (`ansible-playbook playbooks/site.yml`) and check by hand:
   open `https://<domain>/` in a private window; you are sent to GitHub and
   back to the app. Signing in with another GitHub account is refused.
   `https://<domain>/oauth2/sign_out` ends the session.

Sessions last seven days. To run the authenticated external checks, copy
the `__Host-secureedge` cookie's value from the browser into
`SECUREEDGE_SESSION_COOKIE`.

## 11. Lockout drill (once per server)

Prove the firewall rolls itself back. This makes SSH reachable only over a
WireGuard interface that does not exist yet:

```bash
ansible-playbook playbooks/site.yml --limit edge01 -e firewall_ssh_from=wireguard
```

The run fails at "Prove a fresh connection still works". Wait two minutes,
then confirm SSH works again and the normal run changes nothing:

```bash
ssh -i ~/.ssh/server_ed25519 atlas@<edge server IP> true
ansible-playbook playbooks/site.yml --limit edge01
```

Repeat with `--limit app01`. Record the result in
[evidence/README.md](../evidence/README.md).
