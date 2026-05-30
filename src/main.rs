//! sqlitebackup — dump/encrypt/upload + download/decrypt for a SQLite DB on S3.
//!
//! ## backup
//!
//!     sqlite3 <db> .dump  +  backup.toml  →  tar  →  gzip  →  encrypt(prefix, 0, gz)  →  envelope  →  PutObject
//!
//! ## restore
//!
//!     GetObject  →  envelope  →  decrypt(prefix, 0, ct)  →  gunzip  →  untar  →  SQL (+ optional recovered toml)
//!
//! ## list
//!
//!     ListObjectsV2(delim='/')  →  per-prefix count of *.tar.gz.enc + latest timestamp
//!     (no decryption; passphrase not required)
//!
//! Each backup is a *single* S3 object: a tar containing two entries
//! (`backup.toml` + `dump.sql`), gzipped together, encrypted end-to-end with
//! the project passphrase, and wrapped in the ISBK1 envelope. AAD is the
//! full prefix `{name}-{metadata}`. Half the object count of the prior
//! design, and the config metadata (db_path, future fields) is now behind
//! the encryption boundary instead of plaintext alongside.
//!
//! Project identity is the tuple `(name, metadata, db_path)`:
//!   - `name` is the logical service name (e.g. "database")
//!   - `metadata` is a human-meaningful disambiguator (`{service}-{env}-{host}`)
//! Together `{name}-{metadata}` is the S3 prefix *and* the AAD.
//!
//! Before the first data PutObject, `backup` fetches the latest existing
//! blob in the prefix and decrypts it with the current passphrase. If
//! decryption fails (wrong passphrase, AAD mismatch, corrupt blob), the
//! backup refuses — even with `--force`. `--force` only skips the *identity
//! tuple comparison*, so the same passphrase is enforced on every backup to
//! a given prefix.
//!
//! On-disk envelope layout (all multi-byte ints little-endian):
//!
//!     [4]  magic "ISBK"
//!     [1]  version (=1)
//!     [1]  salt_len (=16)
//!     [16] salt
//!     [4]  argon2 m_cost
//!     [4]  argon2 t_cost
//!     [4]  argon2 p_cost
//!     [..] ciphertext from deaddrop-crypto (nonce(12) | cipher | tag(16))
//!
//! Auth model:
//!   - $SQLITEBACKUP_SECRET         → Argon2id passphrase
//!   - AWS_ACCESS_KEY_ID/SECRET_KEY → S3 creds, picked up by the standard provider chain

use std::{
    io::{Read as _, Write},
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::{Context, Result, anyhow, bail};
use aws_config::BehaviorVersion;
use aws_sdk_s3::{Client as S3Client, config::Region, primitives::ByteStream};
use chrono::Utc;
use clap::{Parser, Subcommand};
use deaddrop_crypto::{
    ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST, PasswordKey, random_bytes,
};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncReadExt, process::Command};
use zeroize::Zeroizing;

const ENV_PASSPHRASE: &str = "SQLITEBACKUP_SECRET";
const ENVELOPE_MAGIC: &[u8; 4] = b"ISBK";
const ENVELOPE_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const FIXED_HEADER_LEN: usize = 4 + 1 + 1 + SALT_LEN + 4 + 4 + 4;

// Each backup is one S3 object: a tar of these two entries, gzipped + encrypted.
const BACKUP_SUFFIX: &str = ".tar.gz.enc";
const BUNDLE_TOML_NAME: &str = "backup.toml";
const BUNDLE_SQL_NAME: &str = "dump.sql";

#[derive(Parser)]
#[command(name = "sqlitebackup", about = "Encrypted SQLite backup + restore on S3")]
struct Cli {
    /// Path to backup.toml.
    #[arg(short, long, default_value = "./backup.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Dump, compress, encrypt, and upload the configured SQLite DB to S3.
    Backup {
        /// Skip the identity tuple comparison against the latest existing
        /// backup in this prefix. The passphrase check (decryption of the
        /// latest blob) still runs — so --force never lets you overwrite a
        /// prefix you don't have the passphrase for. Use when intentionally
        /// repointing a prefix's metadata or db_path.
        #[arg(long)]
        force: bool,
        /// Install a systemd timer that runs this backup at INTERVAL instead
        /// of running it now. INTERVAL is any systemd time span ("6h", "1d",
        /// "30min"). Writes {prefix}.{service,timer} into /etc/systemd/system/
        /// and runs daemon-reload + enable --now. Needs root.
        #[arg(long, value_name = "INTERVAL")]
        install_systemd: Option<String>,
    },
    /// Download an encrypted backup from S3 and recover the SQL text.
    Restore {
        /// S3 key to restore (e.g. "<name>-<metadata>/2026-05-28T01:42:17Z.tar.gz.enc").
        /// Defaults to the most-recent object under "<name>-<metadata>/".
        #[arg(short, long)]
        key: Option<String>,
        /// Write SQL here. "-" (default) writes to stdout; pipe into
        /// `sqlite3 newdb.db` to materialize the DB.
        #[arg(short, long, default_value = "-")]
        output: String,
        /// Optionally write the recovered backup.toml here. Useful in disaster
        /// recovery when the local toml is lost. "-" writes to stdout (mutually
        /// exclusive with `--output -`). Unset = don't write the toml.
        #[arg(long, value_name = "PATH")]
        config_out: Option<String>,
    },
    /// List every project enrolled in the bucket. Reads S3 metadata only —
    /// no decryption, no passphrase required.
    List,
}

#[derive(Deserialize, Serialize, Debug)]
struct Config {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    metadata: Option<String>,
    #[serde(default)]
    db_path: Option<PathBuf>,
    s3: S3Config,
}

#[derive(Deserialize, Serialize, Debug)]
struct S3Config {
    bucket: String,
    region: String,
    endpoint_url: Option<String>,
    #[serde(default)]
    force_path_style: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let (cfg, raw_toml) = load_config(&cli.config)?;
    let s3 = build_s3_client(&cfg.s3).await;

    match cli.cmd {
        Cmd::Backup {
            force,
            install_systemd,
        } => match install_systemd {
            Some(interval) => install_systemd_units(&cfg, &cli.config, &interval),
            None => {
                let passphrase = load_passphrase()?;
                run_backup(&cfg, &raw_toml, &passphrase, &s3, force).await
            }
        },
        Cmd::Restore {
            key,
            output,
            config_out,
        } => {
            let passphrase = load_passphrase()?;
            run_restore(
                &cfg,
                &passphrase,
                &s3,
                key.as_deref(),
                &output,
                config_out.as_deref(),
            )
            .await
        }
        Cmd::List => run_list(&cfg.s3.bucket, &s3).await,
    }
}

// ---------------------------------------------------------------------------
// backup
// ---------------------------------------------------------------------------

async fn run_backup(
    cfg: &Config,
    raw_toml: &str,
    passphrase: &Zeroizing<String>,
    s3: &S3Client,
    force: bool,
) -> Result<()> {
    let prefix = project_prefix(cfg)?;
    let db_path = require_db_path(cfg)?;

    eprintln!("→ identity check on s3://{}/{}/", cfg.s3.bucket, prefix);
    check_identity(s3, &cfg.s3.bucket, &prefix, passphrase, cfg, force).await?;
    if force {
        eprintln!("  --force: passphrase verified; identity tuple compare skipped");
    }

    eprintln!("→ dumping {} ...", db_path.display());
    let sql = dump_sqlite(db_path).await?;
    eprintln!("  {} bytes SQL", sql.len());

    eprintln!("→ bundling + compressing ...");
    let tar_bytes = bundle_tar(raw_toml.as_bytes(), &sql)?;
    let gz = gzip(&tar_bytes)?;
    eprintln!("  {} bytes compressed", gz.len());

    eprintln!("→ deriving key + encrypting ...");
    let salt = random_bytes(SALT_LEN).map_err(|e| anyhow!("salt rng: {e}"))?;
    let key = PasswordKey::derive(
        passphrase.as_str(),
        &salt,
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
    )
    .map_err(|e| anyhow!("argon2 derive: {e}"))?;
    let ciphertext = key
        .encrypt_chunk(&prefix, 0, &gz)
        .map_err(|e| anyhow!("encrypt_chunk: {e}"))?;
    let envelope = pack_envelope(
        &salt,
        ARGON2_M_COST,
        ARGON2_T_COST,
        ARGON2_P_COST,
        &ciphertext,
    );

    // Millisecond precision so two backups in the same second don't collide
    // on a locked key. Lex sort still works: within a second, .000Z < .500Z;
    // across seconds, the integer second field dominates.
    let ts = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
    let data_key = format!("{prefix}/{ts}{BACKUP_SUFFIX}");
    eprintln!(
        "→ uploading s3://{}/{} ({} bytes)",
        cfg.s3.bucket,
        data_key,
        envelope.len()
    );
    s3.put_object()
        .bucket(&cfg.s3.bucket)
        .key(&data_key)
        .body(ByteStream::from(envelope))
        .content_type("application/octet-stream")
        .send()
        .await
        .with_context(|| format!("put_object s3://{}/{}", cfg.s3.bucket, data_key))?;

    eprintln!("✓ uploaded s3://{}/{}", cfg.s3.bucket, data_key);
    Ok(())
}

async fn check_identity(
    s3: &S3Client,
    bucket: &str,
    prefix: &str,
    passphrase: &Zeroizing<String>,
    local: &Config,
    skip_identity_compare: bool,
) -> Result<()> {
    let latest = match latest_backup_key(s3, bucket, prefix).await? {
        Some(k) => k,
        None => return Ok(()), // empty prefix — first backup here
    };
    let envelope_bytes = fetch_object_bytes(s3, bucket, &latest).await?;
    // Decryption (with current passphrase + the prefix as AAD) is the
    // passphrase-agreement gate. --force does NOT bypass this — if the
    // existing blob was encrypted under a different passphrase, the AEAD
    // tag check fails and the backup refuses.
    let tar_bytes = decrypt_envelope(passphrase, prefix, &envelope_bytes)
        .with_context(|| format!("verify passphrase against {latest}"))?;
    if skip_identity_compare {
        return Ok(());
    }
    let (remote_toml, _sql) = unbundle_tar(&tar_bytes)?;
    let text = std::str::from_utf8(&remote_toml).context("remote backup.toml not utf8")?;
    let remote: Config = toml::from_str(text).context("parse remote backup.toml")?;
    let local_id = identity(local);
    let remote_id = identity(&remote);
    if local_id != remote_id {
        bail!(
            "prefix s3://{bucket}/{prefix}/ is already owned by a different project:\n  \
             remote: name={:?} metadata={:?} db_path={:?}\n  \
             local:  name={:?} metadata={:?} db_path={:?}\n\
             Change `metadata` in backup.toml, or pass --force to overwrite (passphrase must still agree).",
            remote_id.0, remote_id.1, remote_id.2, local_id.0, local_id.1, local_id.2,
        );
    }
    Ok(())
}

fn identity(cfg: &Config) -> (Option<&str>, Option<&str>, Option<&Path>) {
    (
        cfg.name.as_deref(),
        cfg.metadata.as_deref(),
        cfg.db_path.as_deref(),
    )
}

async fn dump_sqlite(db_path: &Path) -> Result<Vec<u8>> {
    let mut child = Command::new("sqlite3")
        .arg(db_path)
        .arg(".dump")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn sqlite3 (is the sqlite3 CLI installed?)")?;

    let mut stdout = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
    let mut stderr = child.stderr.take().ok_or_else(|| anyhow!("no stderr"))?;

    let mut out = Vec::new();
    stdout
        .read_to_end(&mut out)
        .await
        .context("read sqlite3 stdout")?;

    let mut err = String::new();
    stderr.read_to_string(&mut err).await.ok();
    let status = child.wait().await.context("wait sqlite3")?;
    if !status.success() {
        bail!("sqlite3 .dump failed (exit {}): {}", status, err.trim());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// restore
// ---------------------------------------------------------------------------

async fn run_restore(
    cfg: &Config,
    passphrase: &Zeroizing<String>,
    s3: &S3Client,
    key: Option<&str>,
    output: &str,
    config_out: Option<&str>,
) -> Result<()> {
    if output == "-" && config_out == Some("-") {
        bail!("--output - and --config-out - cannot both write to stdout");
    }
    let prefix = project_prefix(cfg)?;
    let s3_key = match key {
        Some(k) => k.to_string(),
        None => latest_backup_key(s3, &cfg.s3.bucket, &prefix)
            .await?
            .ok_or_else(|| anyhow!("no backups found at s3://{}/{prefix}/", cfg.s3.bucket))?,
    };
    eprintln!("→ downloading s3://{}/{}", cfg.s3.bucket, s3_key);
    let envelope_bytes = fetch_object_bytes(s3, &cfg.s3.bucket, &s3_key).await?;
    eprintln!("  {} bytes downloaded", envelope_bytes.len());

    eprintln!("→ deriving key + decrypting + gunzipping ...");
    let tar_bytes = decrypt_envelope(passphrase, &prefix, &envelope_bytes)?;
    let (toml, sql) = unbundle_tar(&tar_bytes)?;
    eprintln!("  {} bytes SQL, {} bytes toml", sql.len(), toml.len());

    if output == "-" {
        std::io::stdout().write_all(&sql).context("write stdout")?;
    } else {
        std::fs::write(output, &sql).with_context(|| format!("write {output}"))?;
        eprintln!("✓ wrote SQL to {output}");
    }
    if let Some(cfg_path) = config_out {
        if cfg_path == "-" {
            std::io::stdout()
                .write_all(&toml)
                .context("write toml to stdout")?;
        } else {
            std::fs::write(cfg_path, &toml)
                .with_context(|| format!("write {cfg_path}"))?;
            eprintln!("✓ wrote recovered backup.toml to {cfg_path}");
        }
    }
    Ok(())
}

async fn latest_backup_key(s3: &S3Client, bucket: &str, prefix: &str) -> Result<Option<String>> {
    let resp = s3
        .list_objects_v2()
        .bucket(bucket)
        .prefix(format!("{prefix}/"))
        .send()
        .await
        .with_context(|| format!("list_objects_v2 s3://{bucket}/{prefix}/"))?;
    // ISO-8601 keys sort correctly lexically. Filter to BACKUP_SUFFIX so any
    // operator-uploaded files or stale objects from prior code versions don't
    // confuse us.
    Ok(resp
        .contents()
        .iter()
        .filter_map(|o| o.key())
        .filter(|k| k.ends_with(BACKUP_SUFFIX))
        .max()
        .map(String::from))
}

async fn fetch_object_bytes(s3: &S3Client, bucket: &str, key: &str) -> Result<Vec<u8>> {
    let resp = s3
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .with_context(|| format!("get_object s3://{bucket}/{key}"))?;
    Ok(resp
        .body
        .collect()
        .await
        .context("read object body")?
        .into_bytes()
        .to_vec())
}

fn decrypt_envelope(
    passphrase: &Zeroizing<String>,
    prefix: &str,
    envelope_bytes: &[u8],
) -> Result<Vec<u8>> {
    let parsed = parse_envelope(envelope_bytes)?;
    let key = PasswordKey::derive(
        passphrase.as_str(),
        parsed.salt,
        parsed.m_cost,
        parsed.t_cost,
        parsed.p_cost,
    )
    .map_err(|e| anyhow!("argon2 derive: {e}"))?;
    let gz = key
        .decrypt_chunk(prefix, 0, parsed.ciphertext)
        .map_err(|e| anyhow!("decrypt failed: {e} (wrong passphrase or AAD mismatch)"))?;
    gunzip(&gz)
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

async fn run_list(bucket: &str, s3: &S3Client) -> Result<()> {
    let resp = s3
        .list_objects_v2()
        .bucket(bucket)
        .delimiter("/")
        .send()
        .await
        .with_context(|| format!("list_objects_v2 s3://{bucket}/"))?;
    let prefixes: Vec<String> = resp
        .common_prefixes()
        .iter()
        .filter_map(|cp| cp.prefix())
        .map(|p| p.trim_end_matches('/').to_string())
        .collect();

    if prefixes.is_empty() {
        println!("(no projects found in s3://{bucket}/)");
        return Ok(());
    }
    for prefix in prefixes {
        match summarize_project(s3, bucket, &prefix).await {
            Ok(s) => print!("{s}"),
            Err(e) => println!("s3://{bucket}/{prefix}/\n  (skipped: {e:#})\n"),
        }
    }
    Ok(())
}

async fn summarize_project(s3: &S3Client, bucket: &str, prefix: &str) -> Result<String> {
    let resp = s3
        .list_objects_v2()
        .bucket(bucket)
        .prefix(format!("{prefix}/"))
        .send()
        .await
        .with_context(|| format!("list backups s3://{bucket}/{prefix}/"))?;
    let backup_keys: Vec<&str> = resp
        .contents()
        .iter()
        .filter_map(|o| o.key())
        .filter(|k| k.ends_with(BACKUP_SUFFIX))
        .collect();
    let latest = backup_keys
        .iter()
        .max()
        .and_then(|k| k.rsplit('/').next())
        .map(|f| f.trim_end_matches(BACKUP_SUFFIX))
        .unwrap_or("(none)");
    Ok(format!(
        "s3://{bucket}/{prefix}/\n  backups: {} (latest {latest})\n\n",
        backup_keys.len(),
    ))
}

// ---------------------------------------------------------------------------
// bundle
// ---------------------------------------------------------------------------

fn bundle_tar(toml: &[u8], sql: &[u8]) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(toml.len() + sql.len() + 1024);
    {
        let mut builder = tar::Builder::new(&mut buf);
        append_entry(&mut builder, BUNDLE_TOML_NAME, toml)?;
        append_entry(&mut builder, BUNDLE_SQL_NAME, sql)?;
        builder.finish().context("tar finish")?;
    }
    Ok(buf)
}

fn append_entry<W: Write>(builder: &mut tar::Builder<W>, name: &str, data: &[u8]) -> Result<()> {
    let mut hdr = tar::Header::new_gnu();
    hdr.set_path(name)
        .with_context(|| format!("tar set_path {name}"))?;
    hdr.set_size(data.len() as u64);
    hdr.set_mode(0o644);
    hdr.set_cksum();
    builder
        .append(&hdr, data)
        .with_context(|| format!("tar append {name}"))?;
    Ok(())
}

fn unbundle_tar(tar_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut archive = tar::Archive::new(tar_bytes);
    let mut toml: Option<Vec<u8>> = None;
    let mut sql: Option<Vec<u8>> = None;
    for entry in archive.entries().context("tar entries")? {
        let mut entry = entry.context("tar entry")?;
        let path = entry
            .path()
            .context("tar entry path")?
            .to_string_lossy()
            .into_owned();
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf).context("read tar entry")?;
        match path.as_str() {
            BUNDLE_TOML_NAME => toml = Some(buf),
            BUNDLE_SQL_NAME => sql = Some(buf),
            _ => {} // ignore unknown entries for forward-compat
        }
    }
    Ok((
        toml.ok_or_else(|| anyhow!("{BUNDLE_TOML_NAME} not found in archive"))?,
        sql.ok_or_else(|| anyhow!("{BUNDLE_SQL_NAME} not found in archive"))?,
    ))
}

fn gzip(plain: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::<u8>::with_capacity(plain.len() / 4), Compression::default());
    encoder.write_all(plain).context("gzip write")?;
    encoder.finish().context("gzip finish")
}

fn gunzip(gz: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(gz);
    let mut out = Vec::with_capacity(gz.len() * 4);
    decoder.read_to_end(&mut out).context("gunzip")?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// systemd install
// ---------------------------------------------------------------------------

fn install_systemd_units(cfg: &Config, config_path: &Path, interval: &str) -> Result<()> {
    let prefix = project_prefix(cfg)?;
    let unit_name = format!("sqlitebackup-{prefix}");
    let bin = std::env::current_exe().context("resolve current executable path")?;
    let config_abs = config_path
        .canonicalize()
        .with_context(|| format!("canonicalize {}", config_path.display()))?;
    let env_path = config_abs
        .parent()
        .unwrap_or(Path::new("."))
        .join(".env");
    if !env_path.exists() {
        eprintln!(
            "warn: no .env at {} — the timer will fail at runtime until you put one there",
            env_path.display()
        );
    }

    let service = format!(
        r#"[Unit]
Description=sqlitebackup for {prefix}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'set -a; . "{env}"; set +a; exec "{bin}" --config "{cfg}" backup'
"#,
        prefix = prefix,
        env = env_path.display(),
        bin = bin.display(),
        cfg = config_abs.display(),
    );

    let timer = format!(
        r#"[Unit]
Description=Run sqlitebackup for {prefix} every {interval}

[Timer]
Unit={unit_name}.service
OnBootSec=15min
OnUnitActiveSec={interval}
AccuracySec=1min
Persistent=true

[Install]
WantedBy=timers.target
"#,
        prefix = prefix,
        interval = interval,
        unit_name = unit_name,
    );

    eprintln!("=== {unit_name}.service ===");
    eprint!("{service}");
    eprintln!("\n=== {unit_name}.timer ===");
    eprint!("{timer}");
    eprintln!();

    let systemd_dir = Path::new("/etc/systemd/system");
    let service_path = systemd_dir.join(format!("{unit_name}.service"));
    let timer_path = systemd_dir.join(format!("{unit_name}.timer"));

    eprintln!("→ writing {}", service_path.display());
    std::fs::write(&service_path, &service).with_context(|| {
        format!(
            "write {} (need root? re-run with sudo)",
            service_path.display()
        )
    })?;
    eprintln!("→ writing {}", timer_path.display());
    std::fs::write(&timer_path, &timer)
        .with_context(|| format!("write {}", timer_path.display()))?;

    eprintln!("→ systemctl daemon-reload");
    run_cmd("systemctl", &["daemon-reload"])?;
    let timer_unit = format!("{unit_name}.timer");
    eprintln!("→ systemctl enable --now {timer_unit}");
    run_cmd("systemctl", &["enable", "--now", &timer_unit])?;

    eprintln!();
    eprintln!("✓ installed; inspect with:");
    eprintln!("    systemctl list-timers {timer_unit}");
    eprintln!("    systemctl status {unit_name}.service");
    eprintln!("    journalctl -u {unit_name}.service -e");
    Ok(())
}

fn run_cmd(prog: &str, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new(prog)
        .args(args)
        .status()
        .with_context(|| format!("spawn {prog}"))?;
    if !status.success() {
        bail!("{prog} {} failed (exit {status})", args.join(" "));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// shared
// ---------------------------------------------------------------------------

fn load_config(path: &Path) -> Result<(Config, String)> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let cfg: Config =
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    let text_no_comments = toml::to_string_pretty(&cfg).with_context(|| format!("clean_parse {}", path.display()))?;
    Ok((cfg, text_no_comments))
}

fn load_passphrase() -> Result<Zeroizing<String>> {
    let v = std::env::var(ENV_PASSPHRASE)
        .with_context(|| format!("${ENV_PASSPHRASE} not set; source your .env first"))?;
    if v.is_empty() {
        bail!("${ENV_PASSPHRASE} is empty");
    }
    Ok(Zeroizing::new(v))
}

fn project_prefix(cfg: &Config) -> Result<String> {
    let name = cfg
        .name
        .as_deref()
        .context("config.name is required for backup/restore")?;
    let metadata = cfg
        .metadata
        .as_deref()
        .context("config.metadata is required for backup/restore")?;
    if name.is_empty() || metadata.is_empty() {
        bail!("config.name and config.metadata must be non-empty");
    }
    if name.contains('/') || metadata.contains('/') {
        bail!("config.name and config.metadata must not contain '/'");
    }
    Ok(format!("{name}-{metadata}"))
}

fn require_db_path(cfg: &Config) -> Result<&Path> {
    cfg.db_path
        .as_deref()
        .context("config.db_path is required for backup")
}

fn pack_envelope(
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(FIXED_HEADER_LEN + ciphertext.len());
    out.extend_from_slice(ENVELOPE_MAGIC);
    out.push(ENVELOPE_VERSION);
    out.push(salt.len() as u8);
    out.extend_from_slice(salt);
    out.extend_from_slice(&m_cost.to_le_bytes());
    out.extend_from_slice(&t_cost.to_le_bytes());
    out.extend_from_slice(&p_cost.to_le_bytes());
    out.extend_from_slice(ciphertext);
    out
}

#[cfg_attr(test, derive(Debug))]
struct Envelope<'a> {
    salt: &'a [u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    ciphertext: &'a [u8],
}

fn parse_envelope(bytes: &[u8]) -> Result<Envelope<'_>> {
    if bytes.len() < FIXED_HEADER_LEN {
        bail!("envelope too short ({} < {FIXED_HEADER_LEN})", bytes.len());
    }
    let (magic, rest) = bytes.split_at(4);
    if magic != ENVELOPE_MAGIC {
        bail!("not an ISBK envelope (magic mismatch)");
    }
    let (version, rest) = rest.split_first().unwrap();
    if *version != ENVELOPE_VERSION {
        bail!(
            "unsupported envelope version {} (this build understands v{ENVELOPE_VERSION})",
            version
        );
    }
    let (salt_len, rest) = rest.split_first().unwrap();
    if *salt_len as usize != SALT_LEN {
        bail!("unexpected salt length {} (expected {SALT_LEN})", salt_len);
    }
    let (salt, rest) = rest.split_at(SALT_LEN);
    let (m_bytes, rest) = rest.split_at(4);
    let (t_bytes, rest) = rest.split_at(4);
    let (p_bytes, ciphertext) = rest.split_at(4);
    Ok(Envelope {
        salt,
        m_cost: u32::from_le_bytes(m_bytes.try_into().unwrap()),
        t_cost: u32::from_le_bytes(t_bytes.try_into().unwrap()),
        p_cost: u32::from_le_bytes(p_bytes.try_into().unwrap()),
        ciphertext,
    })
}

async fn build_s3_client(s3: &S3Config) -> S3Client {
    let mut loader = aws_config::defaults(BehaviorVersion::latest())
        .region(Region::new(s3.region.clone()));
    if let Some(ref ep) = s3.endpoint_url {
        loader = loader.endpoint_url(ep);
    }
    let shared = loader.load().await;

    let mut builder = aws_sdk_s3::config::Builder::from(&shared);
    if s3.force_path_style {
        builder = builder.force_path_style(true);
    }
    S3Client::from_conf(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(name: Option<&str>, metadata: Option<&str>, db_path: Option<&str>) -> Config {
        Config {
            name: name.map(str::to_string),
            metadata: metadata.map(str::to_string),
            db_path: db_path.map(PathBuf::from),
            s3: S3Config {
                bucket: "b".into(),
                region: "auto".into(),
                endpoint_url: None,
                force_path_style: false,
            },
        }
    }

    #[test]
    fn envelope_roundtrip() {
        let salt = [0xAAu8; SALT_LEN];
        let ct = b"\x01\x02\x03nonce-then-ciphertext-then-tag";
        let packed = pack_envelope(&salt, 65536, 2, 1, ct);
        let parsed = parse_envelope(&packed).expect("parse");
        assert_eq!(parsed.salt, &salt);
        assert_eq!(parsed.m_cost, 65536);
        assert_eq!(parsed.t_cost, 2);
        assert_eq!(parsed.p_cost, 1);
        assert_eq!(parsed.ciphertext, ct);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut packed = pack_envelope(&[0u8; SALT_LEN], 1, 1, 1, b"x");
        packed[0] = b'X';
        let err = parse_envelope(&packed).unwrap_err().to_string();
        assert!(err.contains("magic"), "{err}");
    }

    #[test]
    fn rejects_bad_version() {
        let mut packed = pack_envelope(&[0u8; SALT_LEN], 1, 1, 1, b"x");
        packed[4] = 99;
        let err = parse_envelope(&packed).unwrap_err().to_string();
        assert!(err.contains("version"), "{err}");
    }

    #[test]
    fn prefix_joins_name_and_metadata() {
        let c = cfg(Some("database"), Some("prod-host"), Some("/x"));
        assert_eq!(project_prefix(&c).unwrap(), "database-prod-host");
    }

    #[test]
    fn prefix_requires_both_fields() {
        let c = cfg(Some("database"), None, Some("/x"));
        assert!(project_prefix(&c).is_err());
        let c = cfg(None, Some("m"), Some("/x"));
        assert!(project_prefix(&c).is_err());
    }

    #[test]
    fn prefix_rejects_slash() {
        let c = cfg(Some("a/b"), Some("m"), Some("/x"));
        assert!(project_prefix(&c).is_err());
        let c = cfg(Some("a"), Some("m/n"), Some("/x"));
        assert!(project_prefix(&c).is_err());
    }

    #[test]
    fn identity_compares_three_fields() {
        let a = cfg(Some("n"), Some("m"), Some("/x"));
        let b = cfg(Some("n"), Some("m"), Some("/x"));
        let c = cfg(Some("n"), Some("m"), Some("/y"));
        assert_eq!(identity(&a), identity(&b));
        assert_ne!(identity(&a), identity(&c));
    }

    #[test]
    fn bundle_roundtrip() {
        let toml = b"name = \"x\"\nmetadata = \"y\"\n";
        let sql = b"CREATE TABLE t(id INTEGER);\nINSERT INTO t VALUES (1);\n";
        let tar_bytes = bundle_tar(toml, sql).expect("bundle");
        let (out_toml, out_sql) = unbundle_tar(&tar_bytes).expect("unbundle");
        assert_eq!(out_toml.as_slice(), toml);
        assert_eq!(out_sql.as_slice(), sql);
    }

    #[test]
    fn bundle_rejects_missing_entries() {
        // A tar with only the sql, no toml — unbundle should refuse.
        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);
            append_entry(&mut builder, BUNDLE_SQL_NAME, b"x").unwrap();
            builder.finish().unwrap();
        }
        let err = unbundle_tar(&buf).unwrap_err().to_string();
        assert!(err.contains(BUNDLE_TOML_NAME), "{err}");
    }

    #[test]
    fn gzip_roundtrip() {
        let plain = b"the quick brown fox jumps over the lazy dog";
        let gz = gzip(plain).unwrap();
        let back = gunzip(&gz).unwrap();
        assert_eq!(back, plain);
    }
}
