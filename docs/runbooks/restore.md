# Restore AtlasRisk's data

Backups are restic snapshots of the PostgreSQL dump and Garage's data and
metadata, taken nightly on app01 (setup: [setup.md](setup.md) §9). Run every
command inside WSL at the repository root, as in the setup runbook.

## List the backups

```bash
ansible app -b -m ansible.builtin.command -a "/usr/local/sbin/secureedge-restic snapshots --tag atlasrisk"
```

## Take a backup now

Before a risky change:

```bash
ansible-playbook playbooks/backup.yml
```

## Restore

```bash
ansible-playbook playbooks/restore.yml -e restore_snapshot=latest -e restore_confirm=atlasrisk
```

Use a snapshot id instead of `latest` to go further back. The restore:

1. Checks that the snapshot exists and holds a database dump and Garage's data and metadata.
   If any of these is missing, it stops before changing anything.
2. Stops the Compose project.
3. Moves the current `/srv/atlasrisk/postgres` and `/srv/atlasrisk/garage` to
   `/srv/atlasrisk-before-restore-<time>/`. Nothing is deleted.
4. Puts Garage's data and metadata back.
5. Starts a fresh PostgreSQL and loads the dump.
6. Starts everything and waits until both services are healthy.

Check the result with the host checks (setup.md §6).

## Go back to the data from before the restore

If the restored data is wrong, or the restore stopped halfway, on app01:

```bash
sudo docker compose --project-directory /etc/atlasrisk down
sudo mv /srv/atlasrisk/postgres /srv/atlasrisk/garage /srv/atlasrisk-before-restore-<time>/restored/  # keep it for inspection
sudo mv /srv/atlasrisk-before-restore-<time>/postgres /srv/atlasrisk-before-restore-<time>/garage /srv/atlasrisk/
sudo docker compose --project-directory /etc/atlasrisk up -d --wait
```

Create the `restored/` directory first with `sudo mkdir`. Once you are sure,
delete the `/srv/atlasrisk-before-restore-*` directory you no longer need.

## Restore drill

Do this once after setup, and again after big changes:

1. Take a backup.
2. Change something you will notice: for example, add a test portfolio in AtlasRisk.
3. Restore `latest`.
4. Check that AtlasRisk shows the data from the backup.
5. Record the date and the snapshot id in [evidence/README.md](../evidence/README.md).

Molecule runs the same drill automatically: `test_restore_brings_back_deleted_data`.
