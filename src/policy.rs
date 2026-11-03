//! Statement policy for read-only SQL.
//!
//! The policy is a pure function of the statement text and the target dialect.
//! It runs before any connection is opened, so a refused statement never reaches
//! the database.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Postgres,
    Sqlite,
    Duckdb,
    Mysql,
    Mssql,
}

impl Dialect {
    pub fn parse(s: &str) -> Option<Dialect> {
        match s.to_lowercase().as_str() {
            "postgres" | "postgresql" | "pg" => Some(Dialect::Postgres),
            "sqlite" => Some(Dialect::Sqlite),
            "duckdb" => Some(Dialect::Duckdb),
            "mysql" | "mariadb" => Some(Dialect::Mysql),
            "mssql" | "sqlserver" | "postgres_mssql" => Some(Dialect::Mssql),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Refusal {
    pub reason: String,
    pub hint: String,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.reason, self.hint)
    }
}

const ALLOWED_LEAD: [&str; 7] = [
    "SELECT", "WITH", "EXPLAIN", "DESCRIBE", "SHOW", "VALUES", "TABLE",
];

const BLOCKED_WORDS: [&str; 31] = [
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "ALTER",
    "CREATE",
    "TRUNCATE",
    "GRANT",
    "REVOKE",
    "ATTACH",
    "DETACH",
    "VACUUM",
    "REINDEX",
    "COPY",
    "CALL",
    "EXEC",
    "EXECUTE",
    "SET",
    "PRAGMA",
    "MERGE",
    "REPLACE",
    "LOAD",
    "IMPORT",
    "EXPORT",
    // Dialect-specific escape hatches that a SELECT-leading statement can smuggle.
    "LOAD_FILE",
    "SLEEP",
    "BENCHMARK",
    "PG_SLEEP",
    "WAITFOR",
    "OPENROWSET",
    "OPENDATASOURCE",
];

/// True when `needle` occurs as a whole word, case-insensitively.
fn contains_word(haystack_upper: &str, needle: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = haystack_upper[start..].find(needle) {
        let at = start + pos;
        let before_ok = at == 0 || !is_ident_char(haystack_upper.as_bytes()[at - 1]);
        let after = at + needle.len();
        let after_ok =
            after >= haystack_upper.len() || !is_ident_char(haystack_upper.as_bytes()[after]);
        if before_ok && after_ok {
            return true;
        }
        start = at + 1;
    }
    false
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn strip_quotes(s: &str) -> String {
    // Remove single- and double-quoted literals so a blocked word inside a
    // string literal does not trip the keyword scan, and so stacked-statement
    // detection is not fooled by a semicolon inside a literal.
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '\'' || c == '"' || c == '`' {
            let quote = c;
            i += 1;
            while i < bytes.len() && bytes[i] as char != quote {
                i += 1;
            }
            i += 1;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Statements longer than this are refused before they reach the database. The
/// audit log truncates at 4000 characters for storage reasons; this limit is an
/// execution limit, so an oversized statement never hits the server at all.
const MAX_SQL_CHARS: usize = 8000;

pub fn validate(sql: &str, dialect: Dialect) -> Result<String, Refusal> {
    let s = sql.trim().to_string();
    if s.chars().count() > MAX_SQL_CHARS {
        return Err(Refusal {
            reason: format!(
                "statement is {} characters, over the {MAX_SQL_CHARS} character limit",
                s.chars().count()
            ),
            hint: "narrow the query or split it into two calls".into(),
        });
    }
    if s.is_empty() {
        return Err(Refusal {
            reason: "empty query".into(),
            hint: "pass a SQL statement".into(),
        });
    }

    let skeleton = strip_quotes(&s);
    let skeleton = skeleton.trim().trim_end_matches(';').trim().to_string();
    if skeleton.is_empty() {
        return Err(Refusal {
            reason: "empty query".into(),
            hint: "pass a SQL statement".into(),
        });
    }
    if skeleton.contains(';') {
        return Err(Refusal {
            reason: "only a single statement is allowed".into(),
            hint: "stacked statements are refused by policy".into(),
        });
    }

    let upper = skeleton.to_uppercase();
    let first_word: String = upper
        .split(|c: char| !c.is_ascii_alphanumeric())
        .next()
        .unwrap_or("")
        .to_string();

    if !ALLOWED_LEAD.contains(&first_word.as_str()) {
        return Err(Refusal {
            reason: format!("statement starting with '{}' is not read-only", first_word),
            hint: "allowed: SELECT, WITH, EXPLAIN, DESCRIBE, SHOW, VALUES".into(),
        });
    }

    for w in BLOCKED_WORDS {
        if contains_word(&upper, w) {
            return Err(Refusal {
                reason: format!("query contains the blocked keyword '{}'", w),
                hint: "writes, DDL and server-side file access are refused".into(),
            });
        }
    }

    if upper.contains("INTO") {
        match dialect {
            Dialect::Postgres | Dialect::Mssql => {
                return Err(Refusal {
                    reason: "SELECT ... INTO is refused".into(),
                    hint: "it would create a table; use the returned result set instead".into(),
                });
            }
            Dialect::Mysql => {
                let tail = upper
                    .find("INTO")
                    .map(|p| upper[p + 4..].trim_start())
                    .unwrap_or_default();
                if !tail.starts_with('@') {
                    return Err(Refusal {
                        reason: "SELECT ... INTO is refused".into(),
                        hint: "INTO writes a file or creates a table; INTO @variable is allowed"
                            .into(),
                    });
                }
            }
            _ => {}
        }
    }

    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use Dialect::*;

    fn ok(sql: &str, d: Dialect) {
        validate(sql, d).unwrap_or_else(|e| panic!("expected allow, got: {e}"));
    }
    fn no(sql: &str, d: Dialect) -> Refusal {
        match validate(sql, d) {
            Ok(_) => Refusal {
                reason: "NOT REFUSED".into(),
                hint: String::new(),
            },
            Err(e) => e,
        }
    }

    #[test]
    fn basic_select_allowed() {
        for d in [Postgres, Sqlite, Duckdb, Mysql, Mssql] {
            ok("SELECT * FROM t WHERE a = 1", d);
            ok("SELECT 1;", d);
            ok("WITH x AS (SELECT 1 AS a) SELECT * FROM x", d);
            ok("EXPLAIN SELECT 1", Postgres);
            ok("VALUES (1, 'a')", d);
        }
    }

    #[test]
    fn oversized_statement_refused_before_execution() {
        let big = format!("SELECT {}", "a".repeat(9000));
        let r = validate(&big, Dialect::Postgres);
        assert!(r.is_err(), "a 9000 character statement must be refused");
        assert!(format!("{r:?}").contains("character limit"));
    }

    #[test]
    fn empty_refused() {
        let r = no("   ", Postgres);
        assert!(r.reason.contains("empty"));
    }

    #[test]
    fn stacked_statements_refused() {
        let r = no("SELECT 1; DROP TABLE t", Postgres);
        assert!(r.reason.contains("single statement"));
    }

    #[test]
    fn dml_and_ddl_refused() {
        for d in [Postgres, Sqlite, Duckdb, Mysql, Mssql] {
            for stmt in [
                "INSERT INTO t VALUES (1)",
                "UPDATE t SET a = 2",
                "DELETE FROM t",
                "DROP TABLE t",
                "CREATE TABLE t (a int)",
                "TRUNCATE t",
            ] {
                let r = no(stmt, d);
                assert!(
                    r.reason.contains("read-only") || r.reason.contains("not read-only"),
                    "{stmt}"
                );
            }
        }
    }

    #[test]
    fn blocked_words_inside_select_refused() {
        let r = no("SELECT pg_sleep(10)", Postgres);
        assert!(r.reason.contains("PG_SLEEP"));
        let r = no("SELECT LOAD_FILE('/etc/passwd')", Mysql);
        assert!(r.reason.contains("LOAD_FILE"));
        let r = no("SELECT SLEEP(5)", Mysql);
        assert!(r.reason.contains("SLEEP"));
    }

    #[test]
    fn word_boundary_respected() {
        // "sleep" inside a column name is not the SLEEP function.
        ok("SELECT sleeping_hours FROM roster", Postgres);
        ok("SELECT created_at FROM t", Postgres);
    }

    #[test]
    fn quoted_literals_do_not_trip_the_scan() {
        ok("SELECT 'please insert later' AS note", Postgres);
        ok("SELECT 'a;b' AS s", Postgres);
    }

    #[test]
    fn select_into_refused_by_dialect() {
        let r = no("SELECT * INTO backup FROM t", Postgres);
        assert!(r.reason.contains("INTO"));
        let r = no("SELECT * INTO backup FROM t", Mssql);
        assert!(r.reason.contains("INTO"));
        let r = no("SELECT * INTO OUTFILE '/tmp/x' FROM t", Mysql);
        assert!(r.reason.contains("INTO"));
        // MySQL user-variable form is a legitimate read.
        ok("SELECT count(*) INTO @total FROM t", Mysql);
    }
}
