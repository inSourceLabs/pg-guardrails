//! Data source registry and its validation.
//!
//! A source is a named, read-only connection. The model sees the name; it never
//! sees the credential. Credentials are read from the registry file only.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Presentation rules declared by the operator. Numbers are never converted
/// and never guessed: a column only gets a unit or a decimal place if the
/// registry says so.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnFormat {
    pub name: String,
    #[serde(default)]
    pub unit: String,
    #[serde(default)]
    pub decimals: Option<usize>,
    #[serde(default = "default_grouping")]
    pub group: bool,
    /// Marks a column whose value is a change against a baseline, so a positive
    /// value is printed with a leading '+'.
    #[serde(default)]
    pub delta: bool,
}

fn default_grouping() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    pub id: String,
    pub engine: String,
    #[serde(default)]
    pub description: String,
    /// libpq connection string. Password lives here, never in tool output.
    #[serde(default)]
    pub dsn: String,
    #[serde(default)]
    pub timeout_s: u64,
    #[serde(default)]
    pub columns_deny: Vec<String>,
    /// Optional allow list. When present, only these columns are returned; anything
    /// else is dropped from the result and named in `columns_hidden`.
    #[serde(default)]
    pub columns_allow: Vec<String>,
    #[serde(default)]
    pub column_formats: Vec<ColumnFormat>,
}

#[derive(Debug, Serialize)]
pub struct SourceView {
    pub id: String,
    pub engine: String,
    pub description: String,
    pub timeout_s: u64,
    pub columns_deny: Vec<String>,
    pub columns_allow: Vec<String>,
    pub column_formats: Vec<ColumnFormat>,
    /// True when a credential is present. The value is never surfaced.
    pub has_credential: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Registry {
    sources: Vec<Source>,
}

pub fn default_config_path() -> PathBuf {
    dirs_home().join(".config/pg-guardrails/sources.json")
}

fn dirs_home() -> PathBuf {
    match std::env::var("HOME") {
        Ok(h) => PathBuf::from(h),
        Err(_) => PathBuf::from("."),
    }
}

pub fn load(path: &PathBuf) -> Result<Vec<Source>, String> {
    if !path.exists() {
        return Err(format!(
            "no data sources registered: {} does not exist. Create it with a top-level 'sources' array.",
            path.display()
        ));
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let reg: Registry = serde_json::from_str(&raw)
        .map_err(|e| format!("{} is not valid JSON: {e}", path.display()))?;
    if reg.sources.is_empty() {
        return Err(format!("{} has no entries in 'sources'", path.display()));
    }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (i, s) in reg.sources.into_iter().enumerate() {
        let s = validate_source(s, i)?;
        if !seen.insert(s.id.clone()) {
            return Err(format!("duplicate source id '{}'", s.id));
        }
        out.push(s);
    }
    Ok(out)
}

/// Write the registry atomically. The file holds connection strings, so it is
/// written to a temp file in the same directory with owner-only permissions and
/// then renamed: a crash mid-write never leaves a half-written registry.
pub fn save(path: &PathBuf, sources: &[Source]) -> Result<(), String> {
    let raw = serde_json::to_string_pretty(&Registry {
        sources: sources.to_vec(),
    })
    .map_err(|e| format!("cannot serialise the registry: {e}"))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("sources.json");
    let tmp = parent.join(format!("{name}.tmp-{}", std::process::id()));
    write_owner_only(&tmp, &raw)?;
    fs::rename(&tmp, path).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(())
}

fn write_owner_only(path: &Path, contents: &str) -> Result<(), String> {
    fs::write(path, contents).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot set permissions on {}: {e}", path.display()))?;
    }
    Ok(())
}

/// Add one source. The whole registry is re-validated before anything is
/// written, so a bad entry cannot slip past a good one.
pub fn add_source(path: &PathBuf, source: Source) -> Result<Source, String> {
    let mut sources = if path.exists() {
        load(path)?
    } else {
        Vec::new()
    };
    if sources.iter().any(|s| s.id == source.id) {
        return Err(format!(
            "source '{}' already exists in {}; use remove first to replace it",
            source.id,
            path.display()
        ));
    }
    let checked = validate_source(source, sources.len())?;
    sources.push(checked.clone());
    save(path, &sources)?;
    Ok(checked)
}

/// Remove one source by id. Returns how many entries were dropped.
pub fn remove_source(path: &PathBuf, id: &str) -> Result<usize, String> {
    let sources = load(path)?;
    let kept: Vec<Source> = sources.iter().filter(|s| s.id != id).cloned().collect();
    let removed = sources.len() - kept.len();
    if removed == 0 {
        return Err(format!("no source with id '{id}' in {}", path.display()));
    }
    save(path, &kept)?;
    Ok(removed)
}

/// Strip anything that looks like a credential before a message reaches stdout
/// or an audit line. Connection strings are never printed, even on failure.
pub fn redact(text: &str) -> String {
    let mut out = String::new();
    for token in text.split_whitespace() {
        if token.starts_with("password=") || token.starts_with("Password=") {
            out.push_str("password=REDACTED");
        } else if let Some(scheme_end) = token.find("://") {
            let rest = &token[scheme_end + 3..];
            match rest.find('@') {
                Some(at) => out.push_str(&format!(
                    "{}://REDACTED@{}",
                    &token[..scheme_end],
                    &rest[at + 1..]
                )),
                None => out.push_str(token),
            }
        } else {
            out.push_str(token);
        }
        out.push(' ');
    }
    out.trim().to_string()
}

fn validate_source(s: Source, i: usize) -> Result<Source, String> {
    if s.id.trim().is_empty() {
        return Err(format!("source #{i} is missing 'id'"));
    }
    if !valid_source_id(&s.id) {
        return Err(format!(
            "source #{i}: invalid id '{}'; use letters, digits, '-' and '_'",
            s.id
        ));
    }
    let engine = s.engine.to_lowercase();
    if engine != "postgres" && engine != "postgresql" {
        return Err(format!(
            "source '{}': this release supports the postgres engine only, got '{}'",
            s.id, s.engine
        ));
    }
    if !valid_source_id(&engine) {
        return Err(format!("source '{}': invalid engine name", s.id));
    }
    if s.dsn.trim().is_empty() {
        return Err(format!("source '{}': 'dsn' is required", s.id));
    }
    let timeout = if s.timeout_s == 0 {
        30
    } else {
        s.timeout_s.min(300)
    };
    for c in &s.columns_deny {
        if !valid_identifier(c) {
            return Err(format!(
                "source '{}': invalid column name in deny list: '{c}'",
                s.id
            ));
        }
    }
    for c in &s.columns_allow {
        if !valid_identifier(c) {
            return Err(format!(
                "source '{}': invalid column name in allow list: '{c}'",
                s.id
            ));
        }
    }
    let mut seen_formats = std::collections::HashSet::new();
    for f in &s.column_formats {
        let name = f.name.clone();
        if !valid_identifier(&name) {
            return Err(format!(
                "source '{}': invalid column name in format list: '{name}'",
                s.id
            ));
        }
        if !seen_formats.insert(name.clone()) {
            return Err(format!(
                "source '{}': duplicate format for column '{name}'",
                s.id
            ));
        }
        if f.unit.chars().count() > 16 || f.unit.chars().any(|c| c.is_control()) {
            return Err(format!(
                "source '{}': unit for '{name}' must be 16 characters or fewer",
                s.id
            ));
        }
        if f.decimals.unwrap_or(0) > 6 {
            return Err(format!(
                "source '{}': decimals for '{name}' must be 0 to 6",
                s.id
            ));
        }
    }
    Ok(Source {
        id: s.id.trim().to_string(),
        engine,
        description: s.description.trim().to_string(),
        dsn: s.dsn,
        timeout_s: timeout,
        columns_deny: s.columns_deny,
        columns_allow: s.columns_allow,
        column_formats: s.column_formats,
    })
}

fn valid_source_id(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return false;
    }
    if !(b[0].is_ascii_alphabetic() || b[0] == b'_') {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-')
}

fn valid_identifier(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 128 {
        return false;
    }
    if !(b[0].is_ascii_alphabetic() || b[0] == b'_') {
        return false;
    }
    b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

impl Source {
    pub fn to_view(&self) -> SourceView {
        SourceView {
            id: self.id.clone(),
            engine: self.engine.clone(),
            description: self.description.clone(),
            timeout_s: self.timeout_s,
            columns_deny: self.columns_deny.clone(),
            columns_allow: self.columns_allow.clone(),
            column_formats: self.column_formats.clone(),
            has_credential: !self.dsn.is_empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(json: &str) -> Result<Vec<Source>, String> {
        let reg: Registry = serde_json::from_str(json).unwrap();
        let mut out = Vec::new();
        for (i, s) in reg.sources.into_iter().enumerate() {
            out.push(validate_source(s, i)?);
        }
        Ok(out)
    }

    #[test]
    fn accepts_a_wellformed_source() {
        let s = check(r#"{"sources":[{"id":"demo","engine":"Postgres","dsn":"host=127.0.0.1 dbname=x user=y"}]}"#).unwrap();
        assert_eq!(s[0].engine, "postgres");
        assert_eq!(s[0].timeout_s, 30);
    }

    #[test]
    fn rejects_missing_dsn() {
        let e = check(r#"{"sources":[{"id":"demo","engine":"postgres"}]}"#).unwrap_err();
        assert!(e.contains("dsn"));
    }

    #[test]
    fn rejects_invalid_allow_list_column() {
        let e = check(
            r#"{"sources":[{"id":"demo","engine":"postgres","dsn":"x","columns_allow":["good","bad name"]}]}"#,
        )
        .unwrap_err();
        assert!(e.contains("allow list"), "got: {e}");
    }

    #[test]
    fn accepts_an_allow_list() {
        let s = check(
            r#"{"sources":[{"id":"demo","engine":"postgres","dsn":"x","columns_allow":["amount","status"]}]}"#,
        )
        .unwrap();
        assert_eq!(
            s[0].columns_allow,
            vec!["amount".to_string(), "status".to_string()]
        );
    }

    #[test]
    fn rejects_unsupported_engine() {
        let e = check(r#"{"sources":[{"id":"demo","engine":"oracle","dsn":"x"}]}"#).unwrap_err();
        assert!(e.contains("postgres engine only"));
    }

    #[test]
    fn clamps_timeout() {
        let s =
            check(r#"{"sources":[{"id":"demo","engine":"postgres","dsn":"x","timeout_s":9999}]}"#)
                .unwrap();
        assert_eq!(s[0].timeout_s, 300);
    }

    #[test]
    fn add_then_remove_round_trip() {
        let path = std::env::temp_dir().join(format!("pgg-registry-{}", std::process::id()));
        let source = Source {
            id: "demo".to_string(),
            engine: "postgres".to_string(),
            description: String::new(),
            dsn: "host=127.0.0.1 dbname=demo user=agent_ro".to_string(),
            timeout_s: 0,
            columns_deny: vec!["phone".to_string()],
            columns_allow: vec![],
            column_formats: vec![],
        };
        let added = add_source(&path, source).unwrap();
        assert_eq!(added.timeout_s, 30, "defaults are applied before writing");
        assert_eq!(load(&path).unwrap().len(), 1);
        assert_eq!(remove_source(&path, "demo").unwrap(), 1);
        let missing = load(&path).unwrap_err();
        assert!(missing.contains("no entries"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn duplicate_ids_are_refused_before_writing() {
        let path = std::env::temp_dir().join(format!("pgg-registry-dup-{}", std::process::id()));
        let source = Source {
            id: "demo".to_string(),
            engine: "postgres".to_string(),
            description: String::new(),
            dsn: "host=127.0.0.1 dbname=demo user=agent_ro".to_string(),
            timeout_s: 30,
            columns_deny: vec![],
            columns_allow: vec![],
            column_formats: vec![],
        };
        add_source(&path, source.clone()).unwrap();
        let err = add_source(&path, source).unwrap_err();
        assert!(err.contains("already exists"));
        assert_eq!(
            load(&path).unwrap().len(),
            1,
            "the registry is unchanged after a refusal"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn bad_entries_never_reach_the_file() {
        let path = std::env::temp_dir().join(format!("pgg-reg-bad-{}", std::process::id()));
        let err = add_source(
            &path,
            Source {
                id: "demo".to_string(),
                engine: "oracle".to_string(),
                description: String::new(),
                dsn: "x".to_string(),
                timeout_s: 0,
                columns_deny: vec![],
                columns_allow: vec![],
                column_formats: vec![],
            },
        )
        .unwrap_err();
        assert!(err.contains("postgres engine only"));
        assert!(!path.exists(), "nothing is written when validation fails");
    }

    #[test]
    fn redaction_covers_both_dsn_styles() {
        assert_eq!(
            redact("connection error: host=127.0.0.1 password=hunter2 user=y"),
            "connection error: host=127.0.0.1 password=REDACTED user=y"
        );
        assert_eq!(
            redact("could not connect to postgres://agent_ro:hunter2@127.0.0.1/db"),
            "could not connect to postgres://REDACTED@127.0.0.1/db"
        );
    }

    #[test]
    fn credential_never_reaches_the_view() {
        let s = check(r#"{"sources":[{"id":"demo","engine":"postgres","dsn":"host=127.0.0.1 password=secret user=y"}]}"#).unwrap();
        let v = serde_json::to_string(&s[0].to_view()).unwrap();
        assert!(!v.contains("secret"));
        assert!(v.contains("\"has_credential\":true"));
    }
}
