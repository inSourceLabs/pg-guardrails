//! Human-readable rendering of tool results.
//!
//! Every tool result carries two representations of the same data:
//!   - `content[0].text`: Markdown, readable in a plain client and cheap for a
//!     model's context window
//!   - `structuredContent`: the raw, typed payload
//!
//! Rendering is presentation only. It never runs SQL, never converts values,
//! never invents numbers, and never needs a network. Anything the operator has
//! not declared (a unit, a decimal place) is left exactly as the database
//! returned it, so a rendered number can always be traced back to the row it
//! came from.

use std::collections::HashMap;

use serde_json::{Number, Value};

use crate::config::ColumnFormat;

const MAX_CELL: usize = 120;
const MAX_TABLE_ROWS: usize = 200;

/// Format one cell. `format` comes from the source registry; when a column has
/// no declared format the value is printed as the database gave it.
pub fn cell(value: &Value, format: Option<&ColumnFormat>) -> String {
    let text = match value {
        Value::Null => "NULL".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(_) => format_number(value, format),
        // NUMERIC columns reach the gateway as exact decimal text. When the
        // operator declared a format for the column, print it as a number; when
        // they did not, the text is passed through unchanged so no precision is
        // lost.
        Value::String(s) => match format {
            Some(f) => match s.parse::<f64>() {
                Ok(x) => Number::from_f64(x)
                    .map(Value::Number)
                    .map(|n| format_number(&n, Some(f)))
                    .unwrap_or_else(|| s.clone()),
                Err(_) => s.clone(),
            },
            None => s.clone(),
        },
        other => other.to_string(),
    };
    let one_line = text.replace(['\n', '\r'], " ");
    let escaped = one_line.replace('|', "\\|");
    if escaped.chars().count() > MAX_CELL {
        let kept: String = escaped.chars().take(MAX_CELL).collect();
        format!("{kept}...")
    } else {
        escaped
    }
}

fn format_number(n: &Value, format: Option<&ColumnFormat>) -> String {
    let Some(f) = format else {
        return n.to_string();
    };
    let Some(x) = n.as_f64() else {
        return n.to_string();
    };
    let decimals = f.decimals.unwrap_or(0);
    let mut body = if f.group {
        group_thousands(x, decimals)
    } else {
        format!("{x:.decimals$}")
    };
    if f.delta && x > 0.0 {
        body = format!("+{body}");
    }
    if f.unit.is_empty() {
        body
    } else {
        format!("{body} {unit}", unit = f.unit)
    }
}

/// 1234567.5 with 2 decimals -> "1,234,567.50". Grouping is by thousands only.
fn group_thousands(x: f64, decimals: usize) -> String {
    let negative = x < 0.0;
    let abs = x.abs();
    let scaled = abs * 10f64.powi(decimals as i32);
    let digits = (scaled.round() as i128).to_string();
    let (int_part, frac_part) = if decimals == 0 {
        (digits, String::new())
    } else if digits.len() <= decimals {
        (
            "0".to_string(),
            format!("{}{}", "0".repeat(decimals - digits.len()), digits),
        )
    } else {
        let len = digits.len();
        (
            digits[..len - decimals].to_string(),
            digits[len - decimals..].to_string(),
        )
    };
    let mut grouped = String::new();
    let bytes = int_part.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(*b as char);
    }
    let out = if frac_part.is_empty() {
        grouped
    } else {
        format!("{grouped}.{frac_part}")
    };
    if negative { format!("-{out}") } else { out }
}

pub fn markdown_table(
    columns: &[String],
    rows: &[Vec<Value>],
    formats: &HashMap<String, ColumnFormat>,
) -> String {
    if columns.is_empty() {
        return "(no columns)".to_string();
    }
    let mut out = String::new();
    out.push('|');
    for c in columns {
        out.push_str(&format!(
            " {} |",
            cell(&Value::String(c.clone()), formats.get(c))
        ));
    }
    out.push('\n');
    out.push('|');
    for _ in columns {
        out.push_str(" --- |");
    }
    out.push('\n');
    for row in rows.iter().take(MAX_TABLE_ROWS) {
        out.push('|');
        for (i, v) in row.iter().enumerate() {
            let name = columns.get(i).and_then(|c| formats.get(c));
            out.push_str(&format!(" {} |", cell(v, name)));
        }
        out.push('\n');
    }
    if rows.len() > MAX_TABLE_ROWS {
        // Blank line, otherwise the note is swallowed by the last table row.
        out.push_str(&format!(
            "\n\n- the table shows the first {MAX_TABLE_ROWS} of {} rows; re-run with LIMIT/OFFSET to page\n",
            rows.len()
        ));
    }
    out
}

/// Markdown view of a table description: one row per column.
pub fn column_table(columns: &[Value]) -> String {
    if columns.is_empty() {
        return "(no columns)".to_string();
    }
    let mut out = String::from(
        "| column | type | not null | hidden by policy |\n| --- | --- | --- | --- |\n",
    );
    for c in columns {
        let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let ty = c.get("type").and_then(|v| v.as_str()).unwrap_or("?");
        let not_null = if c.get("not_null").and_then(|v| v.as_bool()).unwrap_or(false) {
            "yes"
        } else {
            "no"
        };
        let hidden = if c
            .get("hidden_by_policy")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            "yes"
        } else {
            "no"
        };
        out.push_str(&format!("| {name} | {ty} | {not_null} | {hidden} |\n"));
    }
    out
}

/// A short, Markdown-safe summary of a query. The first line is bold so chat
/// clients that sniff for Markdown structure render the result as formatted
/// text rather than a raw monospace blob.
pub fn query_summary(
    source: &str,
    row_count: usize,
    truncated: bool,
    limit: usize,
    elapsed_ms: u128,
    hidden_columns: &[String],
    touched: &[String],
) -> String {
    let mut lines = vec![format!(
        "**{row_count} row{}** from `{source}` in {elapsed_ms} ms",
        if row_count == 1 { "" } else { "s" },
    )];
    if row_count == 0 {
        lines.push("- no rows matched".to_string());
    }
    if !touched.is_empty() {
        lines.push(format!("- reads: {}", touched.join(", ")));
    }
    if truncated {
        lines.push(format!(
            "- capped at {limit}: the source has more rows than shown, narrow with WHERE or page with LIMIT/OFFSET"
        ));
    }
    if !hidden_columns.is_empty() {
        lines.push(format!("- hidden by policy: {}", hidden_columns.join(", ")));
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn null_bool_and_escaping() {
        assert_eq!(cell(&Value::Null, None), "NULL");
        assert_eq!(cell(&json!(true), None), "true");
        assert_eq!(cell(&json!("a|b"), None), "a\\|b");
        assert_eq!(cell(&json!("line\nnext"), None), "line next");
    }

    #[test]
    fn long_cells_are_cut() {
        let long = "x".repeat(200);
        let c = cell(&Value::String(long), None);
        assert_eq!(c.len(), MAX_CELL + 3);
        assert!(c.ends_with("..."));
    }

    #[test]
    fn undeclared_columns_are_untouched() {
        assert_eq!(cell(&json!(1234567), None), "1234567");
        assert_eq!(cell(&json!(12.3456), None), "12.3456");
    }

    #[test]
    fn declared_currency_is_grouped_and_suffixed() {
        let money = ColumnFormat {
            name: "amount".to_string(),
            unit: "GBP".to_string(),
            decimals: Some(2),
            group: true,
            delta: false,
        };
        assert_eq!(cell(&json!(1234567), Some(&money)), "1,234,567.00 GBP");
        assert_eq!(cell(&json!(-45.5), Some(&money)), "-45.50 GBP");
        assert_eq!(cell(&json!(0.999), Some(&money)), "1.00 GBP");
    }

    #[test]
    fn delta_columns_carry_a_sign() {
        let d = ColumnFormat {
            name: "mom_change".to_string(),
            unit: "%".to_string(),
            decimals: Some(1),
            group: false,
            delta: true,
        };
        assert_eq!(cell(&json!(3.2), Some(&d)), "+3.2 %");
        assert_eq!(cell(&json!(-3.2), Some(&d)), "-3.2 %");
        assert_eq!(cell(&json!(0), Some(&d)), "0.0 %");
    }

    #[test]
    fn grouping_edge_cases() {
        assert_eq!(group_thousands(999.0, 0), "999");
        assert_eq!(group_thousands(1000.0, 0), "1,000");
        assert_eq!(group_thousands(1000000.0, 2), "1,000,000.00");
        assert_eq!(group_thousands(0.001, 2), "0.00");
        assert_eq!(group_thousands(-1234.5, 1), "-1,234.5");
    }

    #[test]
    fn table_rows_and_truncation_note() {
        let cols = vec!["name".to_string(), "amount".to_string()];
        let rows: Vec<Vec<Value>> = (0..250).map(|i| vec![json!(i), json!(i * 100)]).collect();
        let t = markdown_table(&cols, &rows, &HashMap::new());
        assert!(t.contains("| name | amount |"));
        assert!(t.contains("the table shows the first 200 of 250 rows"));
    }

    #[test]
    fn summary_mentions_caps_masking_and_tables() {
        let s = query_summary(
            "demo",
            10,
            true,
            50,
            12,
            &["phone".to_string()],
            &["transactions".to_string()],
        );
        assert!(s.starts_with("**10 rows** from `demo` in 12 ms"));
        assert!(s.contains("- reads: transactions"));
        assert!(s.contains("- capped at 50"));
        assert!(s.contains("- hidden by policy: phone"));
    }

    #[test]
    fn empty_result_is_stated_as_empty() {
        let s = query_summary("demo", 0, false, 50, 4, &[], &[]);
        assert!(s.contains("**0 rows**"));
        assert!(s.contains("no rows matched"));
    }

    #[test]
    fn column_table_lists_types_and_masking() {
        let cols = vec![
            json!({"name": "id", "type": "integer", "not_null": true, "hidden_by_policy": false}),
            json!({"name": "phone", "type": "text", "not_null": false, "hidden_by_policy": true}),
        ];
        let t = column_table(&cols);
        assert!(t.contains("| id | integer | yes | no |"));
        assert!(t.contains("| phone | text | no | yes |"));
    }
}
