# 0010: restic backups to Cloudflare R2

- **Status:** Accepted
- **Date:** 2026-10-06

## Context

AtlasRisk's data lives on app01: PostgreSQL and Garage's object store.
PROJECT.md asks for off-server backups and a restore that has actually been
exercised. The budget is small, and the data is personal-sized.

## Decision

Back up nightly with restic (Ubuntu package) to a Cloudflare R2 bucket over
its S3 API, keeping 7 daily, 4 weekly and 6 monthly snapshots, and run
`restic check` after each backup.

Take the data without stopping anything:

- **PostgreSQL:** `pg_dump -Fc` from the running server.
- **Garage:** `garage meta snapshot` for a consistent SQLite copy, plus the
  data blocks, which are content-addressed and never rewritten.

A restore moves the current data aside instead of deleting it.

## Consequences

- R2's free tier (10 GB, no egress fees) covers the expected size.
- The restic password is the only key to the backups: it lives in the vault
  and in the owner's password manager.
- R2 is an external dependency; a failed nightly run leaves the
  `last-success` marker stale, for the monitoring role to report.
- Molecule backs up to a local repository and runs the restore drill;
  the R2 path is checked by hand after setup.
- A restore needs a short downtime while the Compose project restarts.
- The R2 token on app01 can delete objects (R2 has no write-only
  permission), so root on app01 could delete the backups. Accepted for now;
  an R2 bucket lock rule, or pruning from another machine with a separate
  token, would remove that risk.
- Retention also keeps every snapshot of the last 3 days, so a backup taken
  before a risky change survives later runs the same day.
