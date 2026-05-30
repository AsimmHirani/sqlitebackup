# sqlitebackup

Dump, compress, encrypt, and upload a SQLite database to any S3-compatible bucket.

Each backup is one encrypted object — `tar(backup.toml + dump.sql)` &rarr; gzip &rarr; AES-256-GCM under an Argon2id-derived key, wrapped in a small self-describing envelope. Designed for low-effort scheduled backups of small operational databases (single-digit MB compressed) to Cloudflare R2 or any S3-compatible bucket.

## Install

From source:

```
git clone https://github.com/AsimmHirani/sqlitebackup
cd sqlitebackup
cargo build --release
# binary at target/release/sqlitebackup
```

Or directly:

```
cargo install --git https://github.com/AsimmHirani/sqlitebackup
```

The `sqlite3` CLI must be on `$PATH` at runtime — the tool shells out to it for `.dump`.

## Configure

Each project gets a `backup.toml` next to its database. See [`example-backup.toml`](example-backup.toml) for the annotated template; the minimum is:

```toml
name = "database"
metadata = "prod-web01"
db_path = "/var/lib/myapp/database.db"

[s3]
bucket = "my-backups"
region = "auto"
endpoint_url = "https://<account-id>.r2.cloudflarestorage.com"
```

Secrets come from the environment — typically a `.env` file next to `backup.toml`, mode 0400, sourced before invocation:

```
SQLITEBACKUP_SECRET=<your backup passphrase>
AWS_ACCESS_KEY_ID=<r2-or-aws-access-key-id>
AWS_SECRET_ACCESS_KEY=<r2-or-aws-secret-access-key>
```

## Use

```
sqlitebackup backup                                                # uses ./backup.toml
sqlitebackup list                                                  # show all projects in the bucket
sqlitebackup restore -o restored.sql                               # latest backup, SQL to a file
sqlitebackup restore --config-out recovered.toml -o restored.sql   # disaster recovery
sqlitebackup --config /path/backup.toml backup                     # explicit config path
```

### Disaster recovery

If the local `backup.toml` is lost, you only need three things to restore: the bucket name, S3 credentials, and the `SQLITEBACKUP_SECRET` passphrase. `sqlitebackup list` shows what's in the bucket without a passphrase; `restore --config-out` recovers both the SQL dump and the original `backup.toml`:

```
sqlitebackup list
sqlitebackup --config <(echo -e "[s3]\nbucket=\"my-backups\"\nendpoint_url=\"...\"") \
    restore --config-out recovered.toml -o restored.sql
```

### Scheduled backups

```
sudo sqlitebackup --config /path/backup.toml backup --install-systemd 1h
```

Writes a `oneshot` service + recurring timer to `/etc/systemd/system/`, sourcing your `.env` via `/bin/sh -c` before invoking the backup. Intervals are passed through to systemd verbatim (`30min`, `1h`, `1d`, etc.).

## Security model

- **Encryption.** Argon2id derives an AES-256-GCM key from `SQLITEBACKUP_SECRET` and a per-backup random salt. Salt + Argon2 cost parameters live inside a self-describing on-disk envelope (`ISBK1`), so historical backups remain decryptable after parameter defaults evolve.
- **AAD binding.** AES-GCM additional data is the full project prefix `{name}-{metadata}`. A backup encrypted under one project's prefix cannot be decrypted as another, even if the ciphertext is dropped into the wrong prefix.
- **Passphrase invariant.** Every backup decrypts the latest existing blob in the prefix before writing a new one. If the passphrase doesn't match the prior backups, the operation is refused — `--force` only skips the *identity tuple comparison*, never the passphrase check.
- **Confidential metadata.** The S3 key prefix encodes `{name}-{metadata}` (intentionally human-readable, so `list` and recovery work without the passphrase). Everything else — `db_path`, any future config fields — lives inside the encrypted blob.

## S3 / R2 notes

- **Key layout.** `s3://<bucket>/<name>-<metadata>/<ISO-8601 UTC, ms precision>.tar.gz.enc`. One object per backup, never overwritten.
- **Object Lock compatible.** Because every backup writes a fresh timestamped key, R2 Object Lock (immutable for N days) works out of the box. Pair with a Lifecycle rule for time-based retention (e.g. delete after 120 days) to get a rolling window.
- **R2 token type.** Use the R2-specific API token page (R2 &rarr; Manage R2 API Tokens &rarr; Create API Token). The Secret Access Key is a 64-character lowercase hex string. Generic Cloudflare API tokens (40–53 chars, often starting with `cfat...`) sign sigv4 requests cleanly but return bare `401 Unauthorized` against `*.r2.cloudflarestorage.com`.

## On-disk format

```
[4]  magic "ISBK"
[1]  version (=1)
[1]  salt_len (=16)
[16] Argon2id salt
[4]  Argon2id m_cost  (little-endian)
[4]  Argon2id t_cost  (little-endian)
[4]  Argon2id p_cost  (little-endian)
[..] AES-256-GCM ciphertext (nonce(12) | cipher | tag(16))
```

The plaintext is a gzipped tar with exactly two entries — `backup.toml` then `dump.sql`. Unbundle (after manual decrypt) with `tar tvf -`.

## Build & test

```
cargo build --release
cargo test
```

A `.kg/graph.toml` ships at the repo root with the architectural decisions and gotchas behind the current code (AAD widening, ISBK1 envelope rationale, Object Lock compatibility, the `--force` semantics, etc.) — useful background if you're modifying the pipeline.

## License

MIT — see [`LICENSE`](LICENSE).
