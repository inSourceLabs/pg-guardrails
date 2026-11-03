//! MCP tool surface.
//!
//! Four data tools plus an audit tool, all read-only. The model is never handed
//! a connection string or a credential; it is handed a source id and gets back
//! rows.
//!
//! Every result ships two representations of the same data: a Markdown text
//! block for the chat transcript and `structuredContent` for anything that
//! wants typed data. The Markdown is derived from the payload, never the other
//! way round, and rendering cannot fail a query: if formatting is disabled with
//! `--format json`, the raw payload is returned as text.

use crate::config::SourceView;
use crate::gateway::{DEFAULT_LIMIT, Gateway, MAX_LIMIT};
use crate::render::{column_table, markdown_table, query_summary};

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ErrorData as McpError, JsonObject};
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;

use http::request::Parts;
use rmcp::service::{RequestContext, RoleServer};

use crate::auth;

/// Who made this tool call. The HTTP auth middleware stamps the token label
/// into the request extensions; the stdio transport has no per-request
/// identity, so the transport default is used.
fn principal_from_parts(parts: &Parts, fallback: &str) -> String {
    parts
        .extensions
        .get::<auth::Principal>()
        .map(|p| p.0.clone())
        .unwrap_or_else(|| fallback.to_string())
}

fn call_principal(ctx: &RequestContext<RoleServer>, fallback: &str) -> String {
    match ctx.extensions.get::<Parts>() {
        Some(parts) => principal_from_parts(parts, fallback),
        None => fallback.to_string(),
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SourceArg {
    /// Source id exactly as returned by list_sources (not the MCP server name)
    pub source: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct QueryArg {
    /// Source id exactly as returned by list_sources (not the MCP server name)
    pub source: String,
    /// One read-only SQL statement
    pub sql: String,
    /// Maximum rows to return. Default 50, hard maximum 500.
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TableArg {
    /// Source id exactly as returned by list_sources (not the MCP server name)
    pub source: String,
    /// Table name
    pub table: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AuditArg {
    /// How many recent records to return (default 20, maximum 200)
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Clone)]
pub struct Guardrails {
    gateway: std::sync::Arc<Gateway>,
    markdown: bool,
}

impl Guardrails {
    pub fn new(gateway: Gateway, markdown: bool) -> Guardrails {
        Guardrails {
            gateway: std::sync::Arc::new(gateway),
            markdown,
        }
    }

    fn ok(payload: serde_json::Value, human: String) -> CallToolResult {
        let text = if human.is_empty() {
            serde_json::to_string_pretty(&payload).unwrap_or_default()
        } else {
            human
        };
        let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
        result.structured_content = Some(payload);
        result
    }

    fn err(msg: &str) -> CallToolResult {
        let mut result = CallToolResult::error(vec![ContentBlock::text(msg.to_string())]);
        result.structured_content = Some(json!({ "error": msg }));
        result
    }
}

/// Output schemas describe `structuredContent`, so a client can validate the
/// typed payload instead of parsing the Markdown text. Every tool can also
/// return `{ "error": "..." }`, and strict clients validate structured content
/// even for error results, so both shapes are declared.
///
/// The MCP spec requires the root of `outputSchema` to be an object, and strict
/// clients (the MCP SDK validates tools/list with Zod) reject a root-level
/// `oneOf`. The root stays an object and the two cases are separated with
/// `anyOf`, so a schema is both spec-compliant and precise.
fn schema(success: Value) -> std::sync::Arc<JsonObject> {
    let mut properties = match success.get("properties") {
        Some(Value::Object(m)) => m.clone(),
        _ => serde_json::Map::new(),
    };
    properties.insert("error".into(), json!({ "type": "string" }));

    let required = match success.get("required") {
        Some(Value::Array(a)) => a.clone(),
        _ => vec![],
    };

    let both = json!({
        "type": "object",
        "properties": properties,
        "anyOf": [
            { "required": required },
            {
                "type": "object",
                "properties": { "error": { "type": "string" } },
                "required": ["error"]
            }
        ]
    });
    match both {
        Value::Object(m) => std::sync::Arc::new(m),
        _ => std::sync::Arc::new(JsonObject::new()),
    }
}

#[tool_router]
impl Guardrails {
    #[tool(
        description = "List the data sources this gateway can reach, with their access rules and any number-formatting rules the operator declared. Credentials are never returned.",
        annotations(read_only_hint = true),
        output_schema = schema(json!({
            "type": "object",
            "properties": {
                "sources": { "type": "array", "items": { "type": "object" } }
            },
            "required": ["sources"]
        }))
    )]
    async fn list_sources(&self) -> Result<CallToolResult, McpError> {
        let views: Vec<SourceView> = self.gateway.sources.iter().map(|s| s.to_view()).collect();
        let mut human = String::new();
        if views.is_empty() {
            human = "**No data sources** are registered with this gateway.".to_string();
        } else {
            human.push_str(&format!(
                "**{} source(s)** available to this agent\n",
                views.len()
            ));
            for v in &views {
                human.push_str(&format!(
                    "- '{}': {} engine, {}s wall clock{}{}\n",
                    v.id,
                    v.engine,
                    v.timeout_s,
                    if v.columns_deny.is_empty() {
                        String::new()
                    } else {
                        format!(", columns hidden by policy: {}", v.columns_deny.join(", "))
                    },
                    if v.description.is_empty() {
                        String::new()
                    } else {
                        format!(", {}", v.description)
                    }
                ));
            }
            human.push_str("Credentials stay in the registry file and are never shown here.");
        }
        Ok(Self::ok(json!({ "sources": views }), human))
    }

    #[tool(
        description = "List the tables in a source. Call this before writing SQL.",
        annotations(read_only_hint = true),
        output_schema = schema(json!({
            "type": "object",
            "properties": {
                "source": { "type": "string" },
                "tables": { "type": "array", "items": { "type": "string" } }
            },
            "required": ["source", "tables"]
        }))
    )]
    async fn schema(
        &self,
        Parameters(arg): Parameters<SourceArg>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let principal = call_principal(&ctx, self.gateway.default_principal());
        match self.gateway.table_list(&arg.source, &principal).await {
            Ok(tables) => {
                let human = if tables.is_empty() {
                    format!(
                        "**Source `{}`** has no tables in the public schema.",
                        arg.source
                    )
                } else {
                    let mut lines =
                        vec![format!("**{} table(s)** in `{}`", tables.len(), arg.source)];
                    lines.extend(tables.iter().map(|t| format!("- `{t}`")));
                    lines.join("\n")
                };
                Ok(Self::ok(
                    json!({ "source": arg.source, "tables": tables }),
                    human,
                ))
            }
            Err(e) => Ok(Self::err(&e.message())),
        }
    }

    #[tool(
        description = "Describe a table: columns, types, nullability, which columns are hidden by policy, and the row count.",
        annotations(read_only_hint = true),
        output_schema = schema(json!({
            "type": "object",
            "properties": {
                "source": { "type": "string" },
                "table": { "type": "string" },
                "row_count": { "type": "integer" },
                "columns": { "type": "array", "items": { "type": "object" } }
            },
            "required": ["source", "table", "row_count", "columns"]
        }))
    )]
    async fn describe(
        &self,
        Parameters(arg): Parameters<TableArg>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let principal = call_principal(&ctx, self.gateway.default_principal());
        match self
            .gateway
            .table_stats(&arg.source, &arg.table, &principal)
            .await
        {
            Ok(v) => {
                let human = format!(
                    "**`{}`: {} row(s), {} column(s)**\n\n{}",
                    arg.table,
                    v["row_count"].as_i64().unwrap_or(0),
                    v["columns"].as_array().map(|a| a.len()).unwrap_or(0),
                    column_table(&v["columns"].as_array().cloned().unwrap_or_default(),)
                );
                Ok(Self::ok(v, human))
            }
            Err(e) => Ok(Self::err(&e.message())),
        }
    }

    #[tool(
        description = "Run one read-only SQL statement. Writes, DDL, stacked statements and server-side file access are refused before the query reaches the database. Results are capped, and columns hidden by policy are removed. `source` is the exact id returned by list_sources.",
        annotations(read_only_hint = true),
        output_schema = schema(json!({
            "type": "object",
            "properties": {
                "source": { "type": "string" },
                "statement": { "type": "string" },
                "tables_read": { "type": "array", "items": { "type": "string" } },
                "columns": { "type": "array", "items": { "type": "string" } },
                "rows": { "type": "array", "items": { "type": "array" } },
                "row_count": { "type": "integer" },
                "truncated": { "type": "boolean" },
                "limit": { "type": "integer" },
                "elapsed_ms": { "type": "integer" },
                "columns_hidden": { "type": "array", "items": { "type": "string" } }
            },
            "required": ["source", "statement", "columns", "rows", "row_count"]
        }))
    )]
    async fn query(
        &self,
        Parameters(arg): Parameters<QueryArg>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let principal = call_principal(&ctx, self.gateway.default_principal());
        let limit = arg.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        match self
            .gateway
            .query(&arg.source, &arg.sql, Some(limit), &principal)
            .await
        {
            Ok(q) => {
                let formats: HashMap<String, crate::config::ColumnFormat> = self
                    .gateway
                    .sources
                    .iter()
                    .find(|s| s.id == arg.source)
                    .map(|s| {
                        s.column_formats
                            .iter()
                            .filter(|f| q.columns.iter().any(|c| c == &f.name))
                            .map(|f| (f.name.clone(), f.clone()))
                            .collect::<HashMap<_, _>>()
                    })
                    .unwrap_or_default();
                let payload = json!({
                    "source": arg.source,
                    "statement": q.statement,
                    "tables_read": q.touched_tables,
                    "columns": q.columns,
                    "rows": q.rows,
                    "row_count": q.rows.len(),
                    "truncated": q.truncated,
                    "limit": limit,
                    "elapsed_ms": q.elapsed_ms,
                    "columns_hidden": q.hidden_columns,
                });
                let human = if self.markdown {
                    let summary = query_summary(
                        &arg.source,
                        q.rows.len(),
                        q.truncated,
                        limit,
                        q.elapsed_ms,
                        &q.hidden_columns,
                        &q.touched_tables,
                    );
                    if q.rows.is_empty() {
                        summary
                    } else {
                        // A blank line between the notes and the table matters:
                        // without it the table lines are read as a lazy
                        // continuation of the bullet list and render raw.
                        format!(
                            "{}\n\n{}",
                            summary,
                            markdown_table(&q.columns, &q.rows, &formats)
                        )
                    }
                } else {
                    String::new()
                };
                Ok(Self::ok(payload, human))
            }
            Err(e) => Ok(Self::err(&e.message())),
        }
    }

    #[tool(
        description = "This gateway's own activity record: which statements ran, which were refused, how many rows came back, and how long each took. Row values are never stored, so this returns no data from the database itself.",
        annotations(read_only_hint = true),
        output_schema = schema(json!({
            "type": "object",
            "properties": {
                "records": { "type": "array", "items": { "type": "object" } },
                "count": { "type": "integer" },
                "refused": { "type": "integer" }
            },
            "required": ["records", "count", "refused"]
        }))
    )]
    async fn audit(
        &self,
        Parameters(arg): Parameters<AuditArg>,
    ) -> Result<CallToolResult, McpError> {
        let records = self.gateway.audit().recent(arg.limit.unwrap_or(20));
        let refused = records.iter().filter(|r| r["ok"] == json!(false)).count();
        let human = if records.is_empty() {
            "**Nothing** has been queried through this gateway yet.".to_string()
        } else {
            format!(
                "**{} record(s)**, {} refused by policy. Statements only, no row values.\n\n{}",
                records.len(),
                refused,
                records
                    .iter()
                    .map(|r| format!(
                        "- {}: {} {} rows in {} ms",
                        r["ts"].as_str().unwrap_or(""),
                        r["statement"].as_str().unwrap_or("(no statement)"),
                        r["rows"].as_u64().unwrap_or(0),
                        r["elapsed_ms"].as_u64().unwrap_or(0)
                    ))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        };
        Ok(Self::ok(
            json!({ "records": records, "count": records.len(), "refused": refused }),
            human,
        ))
    }
}

#[tool_handler(
    name = "pg-guardrails",
    version = "0.1.0",
    instructions = "Read-only SQL over governed sources. Call list_sources first, then schema or describe, then query with one SELECT statement. Statements that write, create, alter, copy or reach the filesystem are refused. The audit tool reports what this gateway has already run."
)]
impl ServerHandler for Guardrails {}

#[cfg(test)]
mod tests {
    use super::{principal_from_parts, schema};
    use crate::auth;
    use serde_json::json;

    #[test]
    fn output_schema_root_is_an_object() {
        // The MCP spec and strict clients require outputSchema to declare
        // type: object at the root; a bare oneOf is rejected by the MCP SDK.
        let s = schema(json!({
            "type": "object",
            "properties": { "tables": { "type": "array", "items": { "type": "string" } } },
            "required": ["tables"]
        }));
        assert_eq!(s.get("type").and_then(|t| t.as_str()), Some("object"));
        assert!(s.get("anyOf").is_some(), "both result shapes are declared");
        assert!(s.get("oneOf").is_none(), "no root-level union");
    }

    #[test]
    fn the_principal_is_taken_from_the_middleware_stamp() {
        // No stamp (stdio, or a transport that carries no HTTP request) falls
        // back to the transport default; a stamped request reports the label.
        let mut parts = http::Request::new(()).into_parts().0;
        assert_eq!(principal_from_parts(&parts, "stdio"), "stdio");
        parts.extensions.insert(auth::Principal("auditor".into()));
        assert_eq!(principal_from_parts(&parts, "stdio"), "auditor");
    }

    #[test]
    fn error_field_is_available_in_properties() {
        let s = schema(json!({ "type": "object", "properties": { "rows": { "type": "array" } } }));
        let props = s.get("properties").expect("properties");
        assert!(props.get("error").is_some());
    }
}
