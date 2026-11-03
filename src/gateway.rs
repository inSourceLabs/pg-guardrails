//! Governed execution against PostgreSQL.
//!
//! A query here has already passed the statement policy. This layer adds the
//! runtime controls: a read-only session, a row cap, a per-source column deny
//! list, a wall clock, and an audit record. The database role is the fourth
//! line of defence: a role with only SELECT grants cannot write even if a
//! statement slipped past the policy.

use crate::audit::{Audit, AuditRecord, truncate, utc_now};
use crate::config::Source;
use crate::policy::{Dialect, validate};

use serde_json::Value;
use std::time::Duration;
use tokio_postgres::{Client, NoTls, Row};

pub const DEFAULT_LIMIT: usize = 50;
pub const MAX_LIMIT: usize = 500;

#[derive(Debug)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub hidden_columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    pub truncated: bool,
    pub elapsed_ms: u128,
    pub statement: String,
    pub touched_tables: Vec<String>,
}

#[derive(Debug)]
pub struct ProbeInfo {
    pub tables: Vec<String>,
    pub first_table_rows: i64,
    pub elapsed_ms: u128,
    pub rows_returned: usize,
}

#[derive(Debug)]
pub enum GatewayError {
    Refused(String),
    Timeout(u64),
    Database(String),
}

impl GatewayError {
    pub fn message(&self) -> String {
        match self {
            GatewayError::Refused(m) => m.clone(),
            GatewayError::Timeout(s) => format!(
                "the query exceeded the {s}s wall clock and was cancelled; narrow it with WHERE or LIMIT"
            ),
            GatewayError::Database(m) => m.clone(),
        }
    }
}

pub struct Gateway {
    pub sources: Vec<Source>,
    audit: std::sync::Arc<Audit>,
    /// Hosts the gateway will connect to. Empty means the operator accepts the
    /// host written in the registry. A non-empty list stops a registry file that
    /// was edited (or copied from somewhere else) from quietly pointing the agent
    /// at a database nobody approved.
    allowed_source_hosts: Vec<String>,
    /// Used when a transport cannot name the caller (stdio). Every HTTP request
    /// carries its own principal from the token label.
    default_principal: String,
    /// PEM bundle used to verify the database certificate. Set with --tls-ca.
    tls_ca: Option<std::path::PathBuf>,
    /// Table names per source, cached so the renderer can say which tables a
    /// statement touched without an extra round trip on every call.
    table_cache: std::sync::Mutex<std::collections::HashMap<String, Vec<String>>>,
}

impl Gateway {
    pub fn new(
        sources: Vec<Source>,
        audit: std::sync::Arc<Audit>,
        allowed_source_hosts: Vec<String>,
        default_principal: String,
        tls_ca: Option<std::path::PathBuf>,
    ) -> Gateway {
        Gateway {
            sources,
            audit,
            allowed_source_hosts,
            default_principal,
            tls_ca,
            table_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn audit(&self) -> &Audit {
        &self.audit
    }

    pub fn tls_ca(&self) -> Option<&std::path::Path> {
        self.tls_ca.as_deref()
    }

    pub fn default_principal(&self) -> &str {
        &self.default_principal
    }

    /// The host in a libpq connection string, either key/value form or URI form.
    fn dsn_host(dsn: &str) -> String {
        if let Some(rest) = dsn
            .strip_prefix("postgres://")
            .or_else(|| dsn.strip_prefix("postgresql://"))
        {
            let after_auth = match rest.find('@') {
                Some(i) => &rest[i + 1..],
                None => rest,
            };
            return after_auth
                .split(':')
                .next()
                .unwrap_or("")
                .split('/')
                .next()
                .unwrap_or("")
                .to_string();
        }
        for token in dsn.split_whitespace() {
            if let Some(value) = token.strip_prefix("host=") {
                return value.split(',').next().unwrap_or("").to_string();
            }
        }
        String::new()
    }

    /// Port in a libpq connection string, key/value or URI form.
    fn dsn_port(dsn: &str) -> String {
        if let Some(rest) = dsn
            .strip_prefix("postgres://")
            .or_else(|| dsn.strip_prefix("postgresql://"))
        {
            let after_auth = match rest.find('@') {
                Some(i) => &rest[i + 1..],
                None => rest,
            };
            if let Some(colon) = after_auth.find(':') {
                return after_auth[colon + 1..]
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .to_string();
            }
        }
        for token in dsn.split_whitespace() {
            if let Some(value) = token.strip_prefix("port=") {
                return value.to_string();
            }
        }
        String::new()
    }

    fn host_guard(
        &self,
        src: &Source,
        operation: &str,
        principal: &str,
    ) -> Result<(), GatewayError> {
        if self.allowed_source_hosts.is_empty() {
            return Ok(());
        }
        let host = if Self::dsn_host(&src.dsn).is_empty() {
            // libpq uses an empty host for a unix socket.
            "unix".to_string()
        } else {
            Self::dsn_host(&src.dsn)
        };
        let port = Self::dsn_port(&src.dsn);
        let target = if port.is_empty() {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        // An entry may name the host alone or the exact host:port pair.
        if self
            .allowed_source_hosts
            .iter()
            .any(|h| h == &host || h == &target)
        {
            return Ok(());
        }
        self.audit.record(&AuditRecord {
            principal: principal.to_string(),
            ts: utc_now(),
            source: src.id.clone(),
            operation: operation.into(),
            statement: None,
            rows: 0,
            truncated: false,
            elapsed_ms: 0,
            ok: false,
            error: Some(format!(
                "source host '{host}' is not in the operator allowlist"
            )),
        });
        Err(GatewayError::Refused(format!(
            "source '{}' points at host '{host}', which the operator did not allow (allowed: {})",
            src.id,
            self.allowed_source_hosts.join(", ")
        )))
    }

    fn find(&self, id: &str) -> Result<Source, GatewayError> {
        self.sources
            .iter()
            .find(|s| s.id == id)
            .cloned()
            .ok_or_else(|| {
                GatewayError::Refused(format!("unknown source '{id}'; call list_sources first"))
            })
    }

    pub async fn query(
        &self,
        source_id: &str,
        sql: &str,
        limit: Option<usize>,
        principal: &str,
    ) -> Result<QueryResult, GatewayError> {
        let src = self.find(source_id)?;
        self.host_guard(&src, "query", principal)?;
        let cleaned = match validate(sql, Dialect::Postgres) {
            Ok(cleaned) => cleaned,
            Err(reason) => {
                // Refusals are evidence too: a policy trip is recorded before
                // any connection is opened.
                self.audit.record(&AuditRecord {
                    principal: principal.to_string(),
                    ts: utc_now(),
                    source: src.id.clone(),
                    operation: "query".into(),
                    statement: Some(truncate(sql)),
                    rows: 0,
                    truncated: false,
                    elapsed_ms: 0,
                    ok: false,
                    error: Some(reason.to_string()),
                });
                return Err(GatewayError::Refused(reason.to_string()));
            }
        };
        let cap = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        let started = std::time::Instant::now();

        let result = self.run(&src, &cleaned, cap).await;
        let elapsed = started.elapsed().as_millis();
        let touched = self.referenced_tables(&src, &cleaned).await;

        self.audit.record(&AuditRecord {
            principal: principal.to_string(),
            ts: utc_now(),
            source: src.id.clone(),
            operation: "query".into(),
            statement: Some(truncate(&cleaned)),
            rows: result.as_ref().map(|q| q.rows.len()).unwrap_or(0),
            truncated: result.as_ref().map(|q| q.truncated).unwrap_or(false),
            elapsed_ms: elapsed,
            ok: result.is_ok(),
            error: result.as_ref().err().map(|e| e.message()),
        });
        result.map(|mut q| {
            q.elapsed_ms = elapsed;
            q.statement = cleaned;
            q.touched_tables = touched;
            q
        })
    }

    /// Which of the source's real tables appear in the statement. Identifiers
    /// are matched against the catalog, so a false positive is limited to a
    /// column that happens to share a table name.
    async fn referenced_tables(&self, src: &Source, sql: &str) -> Vec<String> {
        let catalog = self.cached_tables(src).await;
        if catalog.is_empty() {
            return Vec::new();
        }
        let lower = sql.to_lowercase();
        catalog
            .into_iter()
            .filter(|t| {
                lower
                    .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .any(|tok| tok == t)
            })
            .collect()
    }

    async fn cached_tables(&self, src: &Source) -> Vec<String> {
        if let Some(hit) = self
            .table_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&src.id)
        {
            return hit.clone();
        }
        // Best effort: the catalog is a nicety for the render, not a gate.
        let tables = self
            .raw(src, "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name")
            .await
            .unwrap_or_default();
        let names: Vec<String> = tables.iter().map(|r| r.get::<usize, String>(0)).collect();
        self.table_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(src.id.clone(), names.clone());
        names
    }

    pub async fn table_list(
        &self,
        source_id: &str,
        principal: &str,
    ) -> Result<Vec<String>, GatewayError> {
        let src = self.find(source_id)?;
        self.host_guard(&src, "schema", principal)?;
        let rows = self
            .raw(
                &src,
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name",
            )
            .await?;
        Ok(rows.iter().map(|r| r.get::<usize, String>(0)).collect())
    }

    /// Connectivity check for the `source test` command: a trivial read, the
    /// public table list, and a row count for the first table. Not audited: the
    /// audit trail records what agents asked for, not operator diagnostics.
    pub async fn probe(&self, source_id: &str, principal: &str) -> Result<ProbeInfo, GatewayError> {
        let src = self.find(source_id)?;
        self.host_guard(&src, "test", principal)?;
        let started = std::time::Instant::now();
        let one = self.raw(&src, "SELECT 1 AS ok").await?;
        let elapsed_ms = started.elapsed().as_millis();
        let tables = self
            .raw(
                &src,
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name",
            )
            .await?
            .iter()
            .map(|r| r.get::<usize, String>(0))
            .collect::<Vec<String>>();
        let first_table_rows = match tables.first() {
            Some(t) if valid_ident(t) => self
                .raw(&src, &format!("SELECT count(*) FROM \"{t}\""))
                .await?
                .first()
                .and_then(|r| r.try_get::<usize, i64>(0).ok())
                .unwrap_or(0),
            _ => 0,
        };
        Ok(ProbeInfo {
            tables,
            first_table_rows,
            elapsed_ms,
            rows_returned: one.len(),
        })
    }

    pub async fn table_stats(
        &self,
        source_id: &str,
        table: &str,
        principal: &str,
    ) -> Result<Value, GatewayError> {
        if !valid_ident(table) {
            return Err(GatewayError::Refused(format!(
                "invalid table name '{table}'"
            )));
        }
        let src = self.find(source_id)?;
        self.host_guard(&src, "describe", principal)?;
        let cols = self
            .raw(
                &src,
                &format!(
                    "SELECT column_name, data_type, is_nullable FROM information_schema.columns \
                     WHERE table_schema = 'public' AND table_name = '{}' ORDER BY ordinal_position",
                    table
                ),
            )
            .await?;
        let count = self
            .raw(&src, &format!("SELECT count(*) FROM \"{}\"", table))
            .await?;
        let total = count
            .first()
            .and_then(|r| r.try_get::<usize, i64>(0).ok())
            .unwrap_or(0);
        Ok(serde_json::json!({
            "source": src.id,
            "table": table,
            "row_count": total,
            "columns": cols
                .iter()
                .map(|r| {
                    let name: String = r.get(0);
                    let ty: String = r.get(1);
                    serde_json::json!({
                        "name": name,
                        "type": ty,
                        "not_null": r.get::<usize, String>(2) == "no",
                        "hidden_by_policy": src.columns_deny.iter().any(|d| d == &name),
                    })
                })
                .collect::<Vec<_>>(),
        }))
    }

    async fn run(&self, src: &Source, sql: &str, cap: usize) -> Result<QueryResult, GatewayError> {
        let client = connect(src, self.tls_ca.as_deref()).await?;

        client
            .execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY", &[])
            .await
            .map_err(|e| {
                GatewayError::Database(format!(
                    "could not open a read-only session: {}",
                    database_error(&e)
                ))
            })?;

        let stmt = client.prepare(sql).await.map_err(|e| {
            GatewayError::Database(format!(
                "the database rejected the statement: {}",
                database_error(&e)
            ))
        })?;

        let rows = match tokio::time::timeout(
            Duration::from_secs(src.timeout_s),
            client.query(&stmt, &[]),
        )
        .await
        {
            Ok(rows) => rows.map_err(|e| {
                GatewayError::Database(format!("query failed: {}", database_error(&e)))
            })?,
            Err(_) => {
                // Stop the server from burning a connection on a runaway query.
                let _ = client.cancel_token().cancel_query(NoTls).await;
                return Err(GatewayError::Timeout(src.timeout_s));
            }
        };

        let columns: Vec<String> = stmt
            .columns()
            .iter()
            .map(|c| c.name().to_string())
            .collect();
        // An allow list, when declared, is the only set of columns the operator
        // has approved. A deny list still applies on top of it.
        let allowed = &src.columns_allow;
        let kept: Vec<usize> = columns
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                !src.columns_deny.iter().any(|d| d == *c)
                    && (allowed.is_empty() || allowed.iter().any(|a| a == *c))
            })
            .map(|(i, _)| i)
            .collect();
        let kept_columns: Vec<String> = kept.iter().map(|i| columns[*i].clone()).collect();

        let mut out = Vec::with_capacity(rows.len().min(cap));
        for (i, row) in rows.iter().enumerate() {
            if i >= cap {
                break;
            }
            out.push(kept.iter().map(|k| cell(row, *k)).collect());
        }

        let hidden: Vec<String> = columns
            .iter()
            .filter(|c| {
                src.columns_deny.iter().any(|d| d == *c)
                    || (!allowed.is_empty() && !allowed.iter().any(|a| a == *c))
            })
            .cloned()
            .collect();
        Ok(QueryResult {
            columns: kept_columns,
            hidden_columns: hidden,
            rows: out,
            truncated: rows.len() > cap,
            elapsed_ms: 0,
            statement: String::new(),
            touched_tables: Vec::new(),
        })
    }

    async fn raw(&self, src: &Source, sql: &str) -> Result<Vec<Row>, GatewayError> {
        let client = connect(src, self.tls_ca.as_deref()).await?;
        client
            .execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY", &[])
            .await
            .map_err(|e| {
                GatewayError::Database(format!(
                    "could not open a read-only session: {}",
                    database_error(&e)
                ))
            })?;
        tokio::time::timeout(Duration::from_secs(src.timeout_s), client.query(sql, &[]))
            .await
            .map_err(|_| GatewayError::Timeout(src.timeout_s))?
            .map_err(|e| GatewayError::Database(database_error(&e)))
    }
}

// The connection task is spawned here so callers only ever hold a Client.
/// sslmode from a key/value or URI connection string.
fn dsn_sslmode(dsn: &str) -> Option<String> {
    for token in dsn.split_whitespace() {
        if let Some(v) = token.strip_prefix("sslmode=") {
            return Some(v.to_lowercase());
        }
    }
    if let Some(query) = dsn.split_once('?').map(|x| x.1) {
        for pair in query.split('&') {
            if let Some(v) = pair.strip_prefix("sslmode=") {
                return Some(v.to_lowercase());
            }
        }
    }
    None
}

/// Decide whether the database connection must be encrypted, and whether this
/// binary can do it. Everything is checked before a socket opens, so a source
/// that asks for TLS is never quietly served in clear text.
fn tls_required(dsn: &str, tls_ca: Option<&std::path::Path>) -> Result<bool, GatewayError> {
    let sslmode = dsn_sslmode(dsn);
    // "disable" and "allow" do not require encryption; everything else does.
    let wants_tls = sslmode
        .as_deref()
        .map(|m| m != "disable" && m != "allow")
        .unwrap_or(false);
    let built_with_tls = cfg!(feature = "tls");

    if tls_ca.is_some() && !built_with_tls {
        return Err(GatewayError::Database(
            "--tls-ca was given but this binary was built without the `tls` feature; \
             rebuild with `cargo build --features tls`"
                .to_string(),
        ));
    }
    if tls_ca.is_some() && sslmode.as_deref() == Some("disable") {
        return Err(GatewayError::Database(
            "the connection string says sslmode=disable while --tls-ca was supplied; \
             drop one of them"
                .to_string(),
        ));
    }
    if !wants_tls {
        return Ok(false);
    }
    if !built_with_tls {
        return Err(GatewayError::Database(
            "this build cannot talk to a database over TLS. A connection string asking for \
             sslmode=require or stricter is refused instead of being sent in clear text. \
             Build with `cargo build --features tls`, connect over loopback or a unix socket, \
             or front the database with a proxy."
                .to_string(),
        ));
    }
    if tls_ca.is_none() {
        return Err(GatewayError::Database(
            "sslmode=require needs a certificate authority: pass --tls-ca <pem>. The gateway \
             will not connect to a certificate it cannot verify."
                .to_string(),
        ));
    }
    if Gateway::dsn_host(dsn).is_empty() {
        return Err(GatewayError::Database(
            "TLS needs a host:port; a unix socket connection cannot be encrypted".to_string(),
        ));
    }
    Ok(true)
}

#[cfg(feature = "tls")]
fn rustls_config(ca_path: &std::path::Path) -> Result<rustls::ClientConfig, GatewayError> {
    let bytes = std::fs::read(ca_path).map_err(|e| {
        GatewayError::Database(format!(
            "cannot read the CA file {}: {e}",
            ca_path.display()
        ))
    })?;
    let mut store = rustls::RootCertStore::empty();
    let mut added = 0usize;
    for cert in rustls_pemfile::certs(&mut &bytes[..]) {
        let cert = cert.map_err(|e| {
            GatewayError::Database(format!(
                "cannot parse the CA file {}: {e}",
                ca_path.display()
            ))
        })?;
        store.add(cert).map_err(|e| {
            GatewayError::Database(format!(
                "rejected a certificate in {}: {e}",
                ca_path.display()
            ))
        })?;
        added += 1;
    }
    if added == 0 {
        return Err(GatewayError::Database(format!(
            "no certificates found in {}",
            ca_path.display()
        )));
    }
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(std::sync::Arc::new(store))
        .with_no_client_auth())
}

async fn connect(src: &Source, tls_ca: Option<&std::path::Path>) -> Result<Client, GatewayError> {
    let cfg = src
        .dsn
        .parse::<tokio_postgres::Config>()
        .map_err(|e| GatewayError::Database(format!("invalid connection string: {e}")))?;
    let use_tls = tls_required(&src.dsn, tls_ca)?;
    if tls_ca.is_some() && !use_tls {
        // The operator supplied a CA but this source's DSN does not ask for TLS.
        // Refusing would break a legitimately local source; warning keeps the
        // operator from assuming the connection is encrypted when it is not.
        eprintln!(
            "[pg-guardrails] warning: source '{}' has no sslmode (or sslmode=disable), so the \
             connection is not encrypted even though --tls-ca was given",
            src.id
        );
    }
    #[cfg(not(feature = "tls"))]
    let _ = use_tls;
    // A dead or unreachable host can stall the handshake indefinitely. The
    // per-source wall clock bounds the attempt as well, so a bad source cannot
    // hang the gateway.
    let connect_secs = src.timeout_s.clamp(5, 60);

    #[cfg(feature = "tls")]
    if use_tls {
        let config = rustls_config(tls_ca.expect("tls_required checked the CA"))?;
        let (client, connection) = match tokio::time::timeout(
            Duration::from_secs(connect_secs),
            cfg.connect(tokio_postgres_rustls::MakeRustlsConnect::new(config)),
        )
        .await
        {
            Ok(result) => result.map_err(|e| {
                GatewayError::Database(format!("cannot connect over TLS: {}", database_error(&e)))
            })?,
            Err(_) => {
                return Err(GatewayError::Database(format!(
                    "the TLS connection attempt timed out after {connect_secs}s"
                )));
            }
        };
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("[pg-guardrails] connection error: {e}");
            }
        });
        return Ok(client);
    }

    let (client, connection) =
        match tokio::time::timeout(Duration::from_secs(connect_secs), cfg.connect(NoTls)).await {
            Ok(result) => result.map_err(|e| {
                GatewayError::Database(format!("cannot connect: {}", database_error(&e)))
            })?,
            Err(_) => {
                return Err(GatewayError::Database(format!(
                    "the connection attempt timed out after {connect_secs}s"
                )));
            }
        };
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("[pg-guardrails] connection error: {e}");
        }
    });
    Ok(client)
}

fn valid_ident(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 128 {
        return false;
    }
    if !(b[0].is_ascii_alphabetic() || b[0] == b'_') {
        return false;
    }
    b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

fn one_line(s: &str) -> String {
    s.lines().next().unwrap_or("").to_string()
}

/// Postgres keeps the useful text behind the error's source: `to_string` on the
/// wrapper says only "db error". An agent cannot recover from that, and an
/// operator cannot debug it, so the message carries the database's own words
/// and its SQLSTATE. Credentials are never part of a database error message.
fn database_error(err: &tokio_postgres::Error) -> String {
    match err.as_db_error() {
        Some(db) => format!(
            "{} (SQLSTATE {})",
            one_line(&db.to_string()),
            db.code().code()
        ),
        None => one_line(&err.to_string()),
    }
}

/// Postgres sends NUMERIC as a packed base-10000 binary value that
/// tokio-postgres does not decode, so a money column would otherwise arrive as
/// null. Decoding here keeps exact decimal text and needs no extra crate.
/// Postgres sends numeric as: ndigits, weight, sign, dscale, then ndigits
/// base-10000 digit groups. tokio-postgres has no NUMERIC decoder, so the
/// bytes are unpacked here. Reading the header one field short silently turns
/// every money column into a wrong number, which is why the wire bytes are
/// pinned in the tests below.
fn decode_numeric(raw: &[u8]) -> String {
    if raw.len() < 8 {
        return String::new();
    }
    let ndigits = i16::from_be_bytes([raw[0], raw[1]]) as usize;
    let weight = i16::from_be_bytes([raw[2], raw[3]]) as i32;
    let sign = u16::from_be_bytes([raw[4], raw[5]]);
    let dscale = i16::from_be_bytes([raw[6], raw[7]]) as usize;
    if sign & 0xC000 == 0xC000 {
        // NaN and infinity are not money; the gateway prints them as null.
        return String::new();
    }
    if raw.len() < 8 + 2 * ndigits {
        return String::new();
    }
    // weight is the index of the most significant group: the value is
    // digits[0] * 10000^weight + digits[1] * 10000^(weight-1) + ... Postgres
    // strips trailing zero groups, so 10000 arrives as one group with weight 1.
    let int_groups = (weight + 1).max(0) as usize;
    let mut int_part = String::new();
    let mut frac_part = String::new();
    for i in 0..int_groups.max(ndigits) {
        let digit = if i < ndigits {
            u16::from_be_bytes([raw[8 + 2 * i], raw[9 + 2 * i]])
        } else {
            0
        };
        if i < int_groups {
            if i == 0 {
                int_part.push_str(&digit.to_string());
            } else {
                int_part.push_str(&format!("{digit:04}"));
            }
        } else {
            frac_part.push_str(&format!("{digit:04}"));
        }
    }
    if int_part.is_empty() {
        int_part.push('0');
    }
    // dscale is the display scale the column declares. Pad or trim to it so a
    // NUMERIC(12,2) column prints 100.00 rather than 100.
    if frac_part.len() < dscale {
        frac_part.push_str(&"0".repeat(dscale - frac_part.len()));
    } else if frac_part.len() > dscale {
        frac_part.truncate(dscale);
    }
    let body = if dscale == 0 {
        int_part
    } else {
        format!("{int_part}.{frac_part}")
    };
    if sign == 0x4000 && body != "0" {
        format!("-{body}")
    } else {
        body
    }
}

struct NumericText(String);

impl tokio_postgres::types::FromSql<'_> for NumericText {
    fn from_sql(
        _ty: &tokio_postgres::types::Type,
        raw: &[u8],
    ) -> Result<NumericText, Box<dyn std::error::Error + Sync + Send>> {
        Ok(NumericText(decode_numeric(raw)))
    }

    fn accepts(ty: &tokio_postgres::types::Type) -> bool {
        ty == &tokio_postgres::types::Type::NUMERIC
    }
}

fn cell(row: &Row, idx: usize) -> Value {
    if let Ok(v) = row.try_get::<usize, Option<NumericText>>(idx) {
        let text = v.map(|n| n.0).unwrap_or_default();
        return if text.is_empty() {
            Value::Null
        } else {
            Value::String(text)
        };
    }
    if let Ok(v) = row.try_get::<usize, Option<String>>(idx) {
        return v.map(Value::String).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<usize, Option<i64>>(idx) {
        return v.map(Value::from).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<usize, Option<i32>>(idx) {
        return v.map(Value::from).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<usize, Option<f64>>(idx) {
        return v.map(Value::from).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<usize, Option<bool>>(idx) {
        return v.map(Value::from).unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<usize, Option<chrono::NaiveDateTime>>(idx) {
        return v
            .map(|d| Value::String(d.to_string()))
            .unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<usize, Option<chrono::NaiveDate>>(idx) {
        return v
            .map(|d| Value::String(d.to_string()))
            .unwrap_or(Value::Null);
    }
    if let Ok(v) = row.try_get::<usize, Option<Vec<u8>>>(idx) {
        return v
            .map(|b| Value::String(String::from_utf8_lossy(&b).to_string()))
            .unwrap_or(Value::Null);
    }
    Value::Null
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_binary_is_decoded_exactly() {
        // Wire bytes copied from a live Postgres 17 result set: ndigits, weight,
        // sign, dscale, then base-10000 digit groups anchored at the decimal point.
        let a = [0u8, 2, 0, 0, 0, 0, 0, 4, 0x04, 0xD2, 0x16, 0x2E]; // 1234.5678
        assert_eq!(decode_numeric(&a), "1234.5678");
        let b = [0u8, 1, 0xFF, 0xFF, 0, 0, 0, 4, 0, 1]; // 0.0001 (weight -1)
        assert_eq!(decode_numeric(&b), "0.0001");
        let c = [0u8, 2, 0, 0, 0x40, 0, 0, 1, 0, 5, 0x13, 0x88]; // -5.5
        assert_eq!(decode_numeric(&c), "-5.5");
        // Postgres drops the trailing zero group: 10000 is one digit at weight 1.
        let g = [0u8, 1, 0, 1, 0, 0, 0, 0, 0, 1]; // 10000
        assert_eq!(decode_numeric(&g), "10000");
        let h = [0u8, 2, 0, 0, 0x40, 0, 0, 2, 0, 12, 0x0B, 0xB8]; // -12.30
        assert_eq!(decode_numeric(&h), "-12.30");
        let d = [0u8, 0, 0, 0, 0, 0, 0, 0]; // zero carries no digits
        assert_eq!(decode_numeric(&d), "0");
        // A NUMERIC(12,2) column keeps its declared scale in the display.
        let e = [0u8, 1, 0, 0, 0, 0, 0, 2, 0, 100]; // 100.00
        assert_eq!(decode_numeric(&e), "100.00");
        let f = [0u8, 4, 0, 2, 0, 0, 0, 2, 0, 10, 0, 0, 0, 0, 0x26, 0xAC]; // 1000000000.99
        assert_eq!(decode_numeric(&f), "1000000000.99");
        let nan = [0u8, 0, 0, 0, 0xC0, 0, 0, 0]; // NaN
        assert_eq!(decode_numeric(&nan), "");
    }

    #[tokio::test]
    async fn numeric_values_survive_a_live_round_trip() {
        // Only runs when a test database is configured, so the gate set stays
        // usable without Postgres. Set PGG_TEST_DSN to the demo cluster dsn.
        let Some(dsn) = std::env::var("PGG_TEST_DSN").ok() else {
            return;
        };
        let (client, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
            .await
            .expect("the test database is not reachable");
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {e}");
            }
        });

        for (literal, want) in [
            ("63.45", "63.45"),
            ("25117275.81", "25117275.81"),
            ("0.0001", "0.0001"),
            ("1000000000.99", "1000000000.99"),
            ("-12.30", "-12.30"),
            ("100.00", "100.00"),
            ("0", "0"),
        ] {
            let row = client
                .query_one(&format!("SELECT {literal}::numeric AS n"), &[])
                .await
                .expect("the query should succeed");
            let decoded = row
                .get::<usize, Option<NumericText>>(0)
                .map(|n| n.0)
                .unwrap_or_default();
            assert_eq!(decoded, want, "{literal} decoded as {decoded}");
            assert_eq!(
                cell(&row, 0),
                Value::String(want.to_string()),
                "{literal} reached the tool output as something other than its decimal text"
            );
        }
    }

    #[test]
    fn dsn_host_is_extracted() {
        assert_eq!(
            Gateway::dsn_host("host=127.0.0.1 port=5433 dbname=x user=y"),
            "127.0.0.1"
        );
        assert_eq!(
            Gateway::dsn_host("postgres://agent_ro:secret@db.internal:5432/warehouse"),
            "db.internal"
        );
        assert_eq!(Gateway::dsn_host("dbname=x"), "");
    }

    #[test]
    fn the_source_allowlist_admits_loopback_and_refuses_other_hosts() {
        let gateway = Gateway::new(
            vec![],
            std::sync::Arc::new(Audit::new(std::path::PathBuf::from(
                "/tmp/pgg-allowlist-test.jsonl",
            ))),
            vec!["127.0.0.1".into()],
            "test".into(),
            None,
        );
        let admitted = Source {
            id: "demo".into(),
            engine: "postgres".into(),
            description: String::new(),
            dsn: "host=127.0.0.1 port=5433 dbname=demo user=agent_ro".into(),
            timeout_s: 30,
            columns_deny: vec![],
            columns_allow: vec![],
            column_formats: vec![],
        };
        let refused = Source {
            id: "elsewhere".into(),
            engine: "postgres".into(),
            description: String::new(),
            dsn: "host=db.internal.example port=5432 dbname=x user=y".into(),
            timeout_s: 5,
            columns_deny: vec![],
            columns_allow: vec![],
            column_formats: vec![],
        };
        assert!(gateway.host_guard(&admitted, "query", "test").is_ok());
        let error = gateway
            .host_guard(&refused, "query", "test")
            .expect_err("a host outside the allowlist must be refused");
        assert!(format!("{error:?}").contains("did not allow"));
        let audit = std::fs::read_to_string("/tmp/pgg-allowlist-test.jsonl").unwrap();
        assert!(
            audit.contains("\"ok\":false"),
            "the refusal must be audited"
        );
        assert!(audit.contains("db.internal.example"));
    }

    #[test]
    fn the_allowlist_matches_host_and_host_port_and_unix() {
        let mk = |hosts: Vec<String>| {
            Gateway::new(
                vec![],
                std::sync::Arc::new(Audit::new(std::path::PathBuf::from(
                    "/tmp/pgg-hostguard-test.jsonl",
                ))),
                hosts,
                "test".into(),
                None,
            )
        };
        let source = |dsn: &str| Source {
            id: "demo".into(),
            engine: "postgres".into(),
            description: String::new(),
            dsn: dsn.into(),
            timeout_s: 30,
            columns_deny: vec![],
            columns_allow: vec![],
            column_formats: vec![],
        };
        let exact = mk(vec!["127.0.0.1:5433".into()]);
        assert!(
            exact
                .host_guard(
                    &source("host=127.0.0.1 port=5433 dbname=x"),
                    "query",
                    "test"
                )
                .is_ok()
        );
        assert!(
            exact
                .host_guard(
                    &source("host=127.0.0.1 port=5434 dbname=x"),
                    "query",
                    "test"
                )
                .is_err()
        );
        let host_only = mk(vec!["127.0.0.1".into()]);
        assert!(
            host_only
                .host_guard(
                    &source("host=127.0.0.1 port=5434 dbname=x"),
                    "query",
                    "test"
                )
                .is_ok()
        );
        let uri = mk(vec!["127.0.0.1:5433".into()]);
        assert!(
            uri.host_guard(
                &source("postgres://agent_ro@127.0.0.1:5433/db"),
                "query",
                "test"
            )
            .is_ok()
        );
        let socket = mk(vec!["unix".into()]);
        assert!(
            socket
                .host_guard(&source("dbname=x user=agent_ro"), "query", "test")
                .is_ok(),
            "a DSN with no host is a unix socket connection"
        );
    }

    #[test]
    fn table_names_are_validated() {
        assert!(valid_ident("transactions"));
        assert!(valid_ident("_x1"));
        assert!(!valid_ident("t;drop"));
        assert!(!valid_ident("1abc"));
        assert!(!valid_ident(""));
    }

    #[tokio::test]
    async fn a_bad_statement_reports_the_database_message() {
        // Needs the demo cluster. Without PGG_TEST_DSN the gate set still runs
        // with no database at all.
        let Some(dsn) = std::env::var("PGG_TEST_DSN").ok() else {
            return;
        };
        let source = Source {
            id: "live".into(),
            engine: "postgres".into(),
            description: String::new(),
            dsn,
            timeout_s: 10,
            columns_deny: vec![],
            columns_allow: vec![],
            column_formats: vec![],
        };
        let gateway = Gateway::new(
            vec![source],
            std::sync::Arc::new(Audit::new(std::path::PathBuf::from(
                "/tmp/pgg-error-test-audit.jsonl",
            ))),
            vec![],
            "test".into(),
            None,
        );
        let error = gateway
            .query(
                "live",
                "SELECT * FROM table_that_does_not_exist",
                None,
                "test",
            )
            .await
            .expect_err("the database must reject an unknown table");
        let message = error.message();
        assert!(
            message.contains("does not exist") && message.contains("SQLSTATE 42P01"),
            "the gateway must pass on what the database said, got: {message}"
        );
    }

    #[cfg(not(feature = "tls"))]
    #[test]
    fn a_plain_build_refuses_a_dsn_that_asks_for_tls() {
        let error = tls_required("host=db.internal sslmode=require user=agent_ro", None)
            .expect_err("a build without TLS must not send the statement in clear text");
        assert!(error.message().contains("TLS"), "got: {error:?}");
    }

    #[test]
    fn sslmode_disable_and_allow_stay_plain() {
        assert!(!tls_required("host=127.0.0.1 sslmode=disable", None).unwrap());
        assert!(!tls_required("host=127.0.0.1 sslmode=allow", None).unwrap());
        assert!(!tls_required("dbname=demo user=agent_ro", None).unwrap());
    }

    #[test]
    fn the_tls_ca_flag_needs_a_build_that_can_use_it() {
        #[cfg(not(feature = "tls"))]
        {
            let error = tls_required(
                "host=127.0.0.1 sslmode=require",
                Some(std::path::Path::new("/tmp/ca.pem")),
            )
            .expect_err("the flag without the feature is a configuration mistake");
            assert!(error.message().contains("--features tls"), "got: {error:?}");
        }
        #[cfg(feature = "tls")]
        {
            // With the feature present, the CA is what makes the connection
            // possible: no CA, no connection.
            let error = tls_required("host=db.internal sslmode=require", None)
                .expect_err("verification needs a certificate authority");
            assert!(
                error.message().contains("certificate authority"),
                "got: {error:?}"
            );
            let unix = tls_required(
                "dbname=x sslmode=require",
                Some(std::path::Path::new("/tmp/ca.pem")),
            )
            .expect_err("a unix socket cannot carry TLS");
            assert!(unix.message().contains("unix socket"), "got: {unix:?}");
            let contradiction = tls_required(
                "host=127.0.0.1 sslmode=disable",
                Some(std::path::Path::new("/tmp/ca.pem")),
            )
            .expect_err("sslmode=disable and --tls-ca cannot both be true");
            assert!(
                contradiction.message().contains("sslmode=disable"),
                "got: {contradiction:?}"
            );
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn a_ca_file_without_certificates_is_refused() {
        let dir = std::env::temp_dir().join(format!("pgg-tls-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("empty-ca.pem");
        std::fs::write(&path, "not a certificate\n").expect("write");
        let error = rustls_config(&path)
            .expect_err("a CA file with no certificates cannot verify anything");
        assert!(error.message().contains("certificate"), "got: {error:?}");
    }
}
