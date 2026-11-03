//! Append-only, tamper-evident audit trail.
//!
//! Each query is recorded as one line: who asked, which source, the statement
//! (truncated), rows returned, elapsed time and the outcome. Raw result values
//! are not stored: the statement and its row count are the evidence, and storing
//! row data would turn the audit log into a data store.
//!
//! Line format (all records, one per line):
//!
//!   <hash>|<prev_hash>|<record json>
//!
//! `hash` is SHA-256 over `prev_hash` followed by the record JSON, so every line
//! depends on the line before it. Editing or deleting a line in the middle breaks
//! every hash after it, and `audit verify` reports exactly where the chain broke.
//! Lines without a hash prefix are accepted by the reader (a log created before
//! the chain existed) but are reported as unverifiable by `audit verify`.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const CHAIN_SEED: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_STATEMENT: usize = 4000;

#[derive(Debug, Serialize)]
pub struct AuditRecord {
    pub ts: String,
    pub source: String,
    pub operation: String,
    /// Who made the call. "stdio" for the stdio transport, the token label for
    /// an authenticated HTTP client, "-" when the transport cannot tell.
    pub principal: String,
    pub statement: Option<String>,
    pub rows: usize,
    pub truncated: bool,
    pub elapsed_ms: u128,
    pub ok: bool,
    pub error: Option<String>,
}

pub struct Audit {
    path: PathBuf,
    // The chain has one writer at a time: appends and the running hash must not
    // interleave, or the chain would break under concurrent sessions.
    chain: std::sync::Mutex<ChainState>,
}

struct ChainState {
    prev_hash: String,
    // The file length we expect after the last append. If the file is shorter or
    // longer than expected (deleted, truncated, or written by another process),
    // the cached hash is stale and the chain would break on the next record. The
    // tail is re-read in that case so the trail keeps linking.
    expected_len: u64,
}

fn hex_sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let out = hasher.finalize();
    let mut s = String::with_capacity(64);
    for byte in out {
        s.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        s.push(char::from(b"0123456789abcdef"[(byte & 0xF) as usize]));
    }
    s
}

fn last_line_hash(path: &PathBuf) -> String {
    // Rebuilding the chain from the tail is enough: only the final hash matters
    // for the next append, and a full read of a long log is wasteful.
    const TAIL: u64 = 512 * 1024;
    let Ok(mut f) = std::fs::File::open(path) else {
        return CHAIN_SEED.to_string();
    };
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    if size == 0 {
        return CHAIN_SEED.to_string();
    }
    let start = size.saturating_sub(TAIL);
    if f.seek(SeekFrom::Start(start)).is_err() {
        return CHAIN_SEED.to_string();
    }
    let mut buf = String::new();
    if f.read_to_string(&mut buf).is_err() {
        return CHAIN_SEED.to_string();
    }
    for line in buf.lines().rev() {
        if let Some((hash, _)) = line.split_once('|')
            && hash.len() == 64
            && hash.chars().all(|c| c.is_ascii_hexdigit())
        {
            return hash.to_string();
        }
    }
    CHAIN_SEED.to_string()
}

impl Audit {
    pub fn new(path: PathBuf) -> Audit {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // The audit log is evidence. Owner-only from the start.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if path.exists() {
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
        Audit {
            chain: std::sync::Mutex::new(ChainState {
                prev_hash: last_line_hash(&path),
                expected_len: std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0),
            }),
            path,
        }
    }

    pub fn record(&self, r: &AuditRecord) {
        let json = serde_json::to_string(r).unwrap_or_else(|_| "{}".to_string());
        let mut state = self.chain.lock().unwrap_or_else(|e| e.into_inner());
        let on_disk = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if on_disk != state.expected_len {
            // The file moved under us. Rebuild the chain end from the last line.
            state.prev_hash = last_line_hash(&self.path);
            state.expected_len = on_disk;
        }
        let hash = hex_sha256(&format!("{}{}", state.prev_hash, json));
        let line = format!("{hash}|{}|{json}", state.prev_hash);
        state.prev_hash = hash;
        state.expected_len = on_disk + line.len() as u64 + 1;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)
        {
            let _ = f.write_all(line.as_bytes());
            let _ = f.write_all(b"\n");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
            }
        }
        // Audit failure must never break a query; the log is a record, not a gate.
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Walk the whole file and check every hash. Returns the number of lines,
    /// how many verified, and the first problem found (1-based line number).
    pub fn verify(&self) -> (usize, usize, Option<String>) {
        let Ok(content) = std::fs::read_to_string(&self.path) else {
            return (0, 0, Some(format!("cannot read {}", self.path.display())));
        };
        let mut prev = CHAIN_SEED.to_string();
        let mut total = 0usize;
        let mut verified = 0usize;
        let mut first_problem: Option<String> = None;
        for (idx, line) in content.lines().enumerate() {
            let i = idx + 1;
            if line.trim().is_empty() {
                continue;
            }
            total += 1;
            let Some((hash, rest)) = line.split_once('|') else {
                if first_problem.is_none() {
                    first_problem = Some(format!(
                        "line {i}: no chain hash (written before the chain existed)"
                    ));
                }
                continue;
            };
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                if first_problem.is_none() {
                    first_problem = Some(format!("line {i}: malformed hash"));
                }
                continue;
            }
            let Some((claimed_prev, json)) = rest.split_once('|') else {
                if first_problem.is_none() {
                    first_problem = Some(format!("line {i}: missing previous hash"));
                }
                continue;
            };
            if claimed_prev != prev {
                if first_problem.is_none() {
                    first_problem = Some(format!(
                        "line {i}: previous hash does not match the line before it"
                    ));
                }
                prev = hash.to_string();
                continue;
            }
            if hex_sha256(&format!("{}{}", claimed_prev, json)) != hash {
                if first_problem.is_none() {
                    first_problem = Some(format!("line {i}: hash does not match the record"));
                }
                prev = hash.to_string();
                continue;
            }
            verified += 1;
            prev = hash.to_string();
        }
        (total, verified, first_problem)
    }

    /// Return the most recent records, oldest first. Only the tail of the file is
    /// read, so a long-lived audit log is not parsed in full.
    pub fn recent(&self, limit: usize) -> Vec<serde_json::Value> {
        let limit = limit.clamp(1, 500);
        if !self.path.exists() {
            return Vec::new();
        }
        const TAIL_BYTES: i64 = 512 * 1024;
        let mut lines: Vec<String> = Vec::new();
        if let Ok(mut f) = std::fs::File::open(&self.path) {
            let size = f.metadata().map(|m| m.len()).unwrap_or(0);
            let sought = size > TAIL_BYTES as u64;
            if sought {
                // End(-N) is N bytes before the end of the file.
                let _ = f.seek(SeekFrom::End(-TAIL_BYTES));
            }
            let mut buf = String::new();
            if f.read_to_string(&mut buf).is_ok() {
                lines = buf.lines().map(|l| l.to_string()).collect();
            }
            // A mid-file read starts in the middle of a record.
            if sought && !lines.is_empty() {
                lines.remove(0);
            }
        }
        let kept: Vec<String> = lines.into_iter().rev().take(limit).collect();
        kept.iter()
            .rev()
            .filter_map(|l| record_json(l.as_str()))
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }
}

fn record_json(line: &str) -> Option<&str> {
    // New format: hash|prev_hash|json. Anything else is a legacy plain-JSON line.
    match line.split_once('|') {
        Some((hash, rest)) if hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit()) => {
            rest.split_once('|').map(|(_, json)| json)
        }
        _ => Some(line),
    }
}

pub fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(|| format!("unix:{secs}"))
}

pub fn truncate(s: &str) -> String {
    if s.len() <= MAX_STATEMENT {
        s.to_string()
    } else {
        format!("{} ...[truncated]", &s[..MAX_STATEMENT])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pgg-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir.join("audit.jsonl")
    }

    fn sample(i: usize) -> AuditRecord {
        AuditRecord {
            ts: utc_now(),
            source: "demo".into(),
            operation: "query".into(),
            principal: "stdio".into(),
            statement: Some(format!("SELECT {i}")),
            rows: 1,
            truncated: false,
            elapsed_ms: 5,
            ok: true,
            error: None,
        }
    }

    #[test]
    fn truncates_long_statements() {
        let long = "SELECT ".to_string() + &"a".repeat(5000);
        let t = truncate(&long);
        assert!(t.len() <= MAX_STATEMENT + 15);
        assert!(t.ends_with("...[truncated]"));
    }

    #[test]
    fn appends_one_line_per_record() {
        let a = Audit::new(scratch("append"));
        a.record(&sample(1));
        let content = std::fs::read_to_string(a.path()).unwrap();
        assert_eq!(
            content
                .lines()
                .filter(|l| l.contains("\"source\":\"demo\""))
                .count(),
            1
        );
    }

    #[test]
    fn chain_verifies_when_untouched() {
        let path = scratch("chain");
        let a = Audit::new(path.clone());
        for i in 0..10 {
            a.record(&sample(i));
        }
        let (total, verified, problem) = a.verify();
        assert_eq!(total, 10);
        assert_eq!(verified, 10, "every record's hash matched: {problem:?}");
        assert!(problem.is_none());
    }

    #[test]
    fn chain_detects_a_tampered_line() {
        let path = scratch("tamper");
        let a = Audit::new(path.clone());
        for i in 0..10 {
            a.record(&sample(i));
        }
        // Replace the statement in line 4 without recomputing any hash.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        let mut broken = lines[4].clone();
        broken = broken.replace("SELECT 4", "SELECT 999");
        lines[4] = broken;
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        let (total, verified, problem) = a.verify();
        assert_eq!(total, 10);
        assert!(verified < 10, "the chain must not verify after an edit");
        assert!(
            problem.unwrap_or_default().contains("line 5"),
            "the report names the line"
        );
    }

    #[test]
    fn chain_survives_a_restart() {
        let path = scratch("restart");
        {
            let a = Audit::new(path.clone());
            for i in 0..5 {
                a.record(&sample(i));
            }
        }
        let b = Audit::new(path.clone());
        b.record(&sample(6));
        let (total, verified, problem) = b.verify();
        assert_eq!(total, 6);
        assert_eq!(
            verified, 6,
            "the chain continues across processes: {problem:?}"
        );
    }

    #[test]
    fn the_chain_resyncs_when_the_file_is_cut_behind_the_process() {
        let path = scratch("resync");
        let a = Audit::new(path.clone());
        a.record(&sample(1));
        a.record(&sample(2));
        let content = std::fs::read_to_string(&path).unwrap();
        // Delete every record but the first while the gateway is running.
        std::fs::write(&path, format!("{}\n", content.lines().next().unwrap())).unwrap();
        a.record(&sample(3));
        let (total, verified, problem) = a.verify();
        assert_eq!(total, 2, "one record was deleted, two remain");
        assert_eq!(
            verified, 2,
            "the chain re-linked to what is actually on disk: {problem:?}",
        );
    }

    #[test]
    fn audit_file_is_owner_only() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = scratch("perms");
            let a = Audit::new(path.clone());
            a.record(&sample(1));
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "audit log must not be readable by others");
        }
    }

    #[test]
    fn recent_returns_the_tail_in_order() {
        let a = Audit::new(scratch("recent"));
        for i in 0..20 {
            a.record(&sample(i));
        }
        let last = a.recent(5);
        assert_eq!(last.len(), 5);
        assert_eq!(last[0]["statement"], "SELECT 15");
        assert_eq!(last[4]["statement"], "SELECT 19");
        assert_eq!(a.recent(100).len(), 20);
    }

    #[test]
    fn legacy_plain_json_lines_are_still_readable() {
        let path = scratch("legacy");
        std::fs::write(&path, "{\"ts\":\"2026-01-01T00:00:00Z\",\"source\":\"demo\",\"operation\":\"query\",\"principal\":\"-\",\"statement\":\"SELECT 1\",\"rows\":1,\"truncated\":false,\"elapsed_ms\":1,\"ok\":true,\"error\":null}\n").unwrap();
        let a = Audit::new(path);
        let records = a.recent(10);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["statement"], "SELECT 1");
        let (_, verified, problem) = a.verify();
        assert_eq!(verified, 0);
        assert!(problem.unwrap_or_default().contains("no chain hash"));
    }

    #[test]
    fn recent_survives_a_log_larger_than_the_read_window() {
        let a = Audit::new(scratch("big"));
        let padding = "a".repeat(2000);
        for i in 0..400 {
            a.record(&AuditRecord {
                ts: utc_now(),
                source: "demo".into(),
                operation: "query".into(),
                principal: "stdio".into(),
                statement: Some(format!("SELECT {i}, {padding}")),
                rows: 0,
                truncated: false,
                elapsed_ms: 0,
                ok: true,
                error: None,
            });
        }
        let last = a.recent(10);
        assert_eq!(last.len(), 10);
        assert_eq!(last[9]["statement"], format!("SELECT 399, {padding}"));
    }
}
