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

## 2. Create the vault

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

## 3. Bootstrap

Use the provider's initial user (`root` or `ubuntu`). Compare the host key
fingerprint with the one in the provider console when asked.

```bash
ansible-playbook playbooks/bootstrap.yml -e bootstrap_user=root
```

From now on every run connects as `atlas`.

## 4. Apply everything

```bash
ansible-playbook playbooks/site.yml
```

## 5. Check the servers

```bash
pytest -m host --hosts=ansible://all --force-ansible --ansible-inventory=inventories/production/hosts.yml
```

`--force-ansible` makes every check go through Ansible, so the vault-backed
host addresses resolve and root-only checks can use the sudo password.

## 6. Lockout drill (once per server)

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
