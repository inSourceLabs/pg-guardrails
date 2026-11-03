use clap::Parser;
use pg_guardrails::audit::{Audit, AuditRecord, utc_now};
use pg_guardrails::auth;
use pg_guardrails::config::{
    ColumnFormat, Source, add_source, default_config_path, load, redact, remove_source,
};
use pg_guardrails::gateway::Gateway;
use pg_guardrails::server::Guardrails;
use rmcp::ServiceExt;

use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "pg-guardrails",
    about = "Read-only, governed SQL for AI agents over MCP",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::ValueEnum, Clone)]
enum Format {
    /// Markdown table in the text content (default)
    Markdown,
    /// Raw JSON in the text content
    Json,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Serve over stdio. This is what an MCP client launches as a child process.
    Serve {
        #[arg(long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long, default_value_os_t = PathBuf::from("./pg-guardrails-audit.jsonl"))]
        audit: PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Markdown)]
        format: Format,
        #[arg(
            long,
            value_delimiter = ',',
            help = "Restrict which hosts the gateway will connect to. Empty means the host \n                    written in the registry is accepted."
        )]
        allow_source_hosts: Vec<String>,
        #[arg(
            long,
            help = "PEM bundle used to verify the database certificate. Required whenever a \n                    connection string asks for sslmode=require or stricter, and this build was \n                    compiled with the `tls` feature."
        )]
        tls_ca: Option<PathBuf>,
    },
    /// Serve over streamable HTTP, bound to loopback.
    Http {
        #[arg(long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long, default_value_os_t = PathBuf::from("./pg-guardrails-audit.jsonl"))]
        audit: PathBuf,
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        #[arg(
            long,
            default_value_t = 8411,
            help = "Loopback port. Deliberately not 8080: common ports are more likely to collide."
        )]
        port: u16,
        #[arg(long, value_enum, default_value_t = Format::Markdown)]
        format: Format,
        #[arg(
            long,
            help = "Permit a bind address other than loopback. There is no built-in \
                    authentication, so the default is loopback only."
        )]
        allow_non_loopback: bool,
        #[arg(
            long,
            help = "Hosts accepted in the Host header. Defaults to the bind address."
        )]
        allowed_host: Vec<String>,
        #[arg(
            long,
            help = "File of 'label=token' lines. Every request must carry one of these as \n                    'Authorization: Bearer <token>'. Required for any non-loopback bind."
        )]
        auth_file: Option<PathBuf>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "Restrict which hosts the gateway will connect to. Empty means the host \n                    written in the registry is accepted."
        )]
        allow_source_hosts: Vec<String>,
        #[arg(
            long,
            help = "PEM bundle used to verify the database certificate. Required whenever a \n                    connection string asks for sslmode=require or stricter, and this build was \n                    compiled with the `tls` feature."
        )]
        tls_ca: Option<PathBuf>,
    },
    /// Check the hash chain of an audit log: proves no record was edited or removed.
    Audit {
        #[arg(long, default_value_os_t = PathBuf::from("./pg-guardrails-audit.jsonl"))]
        audit: PathBuf,
    },
    /// Print the registered sources. Credentials are never shown.
    Sources {
        #[arg(long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
    /// Edit the registry from the command line instead of by hand.
    Source {
        #[command(subcommand)]
        action: SourceAction,
    },
}

#[derive(clap::Subcommand)]
enum SourceAction {
    /// Register a new source.
    Add {
        #[arg(long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long, help = "Source id the agent will use. Letters, digits, - and _")]
        id: String,
        #[arg(
            long,
            help = "libpq connection string. Prefer --dsn-file: a DSN on the command line lands in shell history"
        )]
        dsn: Option<String>,
        #[arg(
            long,
            help = "Read the connection string from a file instead of the command line"
        )]
        dsn_file: Option<PathBuf>,
        #[arg(long, default_value = "postgres")]
        engine: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(
            long,
            default_value_t = 30,
            help = "Query wall clock limit in seconds (max 300)"
        )]
        timeout: u64,
        #[arg(long, value_delimiter = ',', help = "Columns hidden from every result")]
        deny: Vec<String>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "If set, only these columns are returned; every other column is dropped"
        )]
        allow: Vec<String>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "Presentation rules, e.g. --format amount:unit=GBP:decimals=2"
        )]
        format: Vec<String>,
    },
    /// Remove a source.
    Remove {
        #[arg(long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long)]
        id: String,
    },
    /// Connect and run a trivial read to prove the source works.
    Test {
        #[arg(long, default_value_os_t = default_config_path())]
        config: PathBuf,
        #[arg(long, default_value_os_t = PathBuf::from("./pg-guardrails-audit.jsonl"))]
        audit: PathBuf,
        #[arg(long)]
        id: String,
        #[arg(long, help = "PEM bundle used to verify the database certificate")]
        tls_ca: Option<PathBuf>,
    },
    /// Show the registry without printing credentials.
    List {
        #[arg(long, default_value_os_t = default_config_path())]
        config: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve {
            config,
            audit,
            format,
            allow_source_hosts,
            tls_ca,
        } => run_stdio(config, audit, markdown(format), allow_source_hosts, tls_ca),
        Command::Http {
            config,
            audit,
            bind,
            port,
            format,
            allow_non_loopback,
            allowed_host,
            auth_file,
            allow_source_hosts,
            tls_ca,
        } => run_http(HttpOptions {
            config,
            audit,
            bind,
            port,
            markdown: markdown(format),
            allow_non_loopback,
            allowed_host,
            auth_file,
            allow_source_hosts,
            tls_ca,
        }),
        Command::Audit { audit } => {
            let log = Audit::new(audit.clone());
            let (total, verified, problem) = log.verify();
            if total == 0 {
                println!("audit log {} is empty", audit.display());
                return;
            }
            if verified == total {
                println!(
                    "audit log {} intact: {total} record(s), every hash verified",
                    audit.display()
                );
            } else {
                println!(
                    "audit log {} BROKEN: {verified}/{total} records verified; first problem: {}",
                    audit.display(),
                    problem.unwrap_or_else(|| "unknown".to_string())
                );
                std::process::exit(1);
            }
        }
        Command::Sources { config } => print_sources(&config),
        Command::Source { action } => match action {
            SourceAction::Add {
                config,
                id,
                dsn,
                dsn_file,
                engine,
                description,
                timeout,
                deny,
                allow,
                format,
            } => {
                // A DSN is a credential. Reading it from a file keeps it out of
                // shell history and out of the process table.
                let dsn = match dsn_file {
                    Some(p) => match std::fs::read_to_string(&p) {
                        Ok(text) => text.trim().to_string(),
                        Err(e) => {
                            eprintln!("error: cannot read {}: {e}", p.display());
                            std::process::exit(1);
                        }
                    },
                    None => match dsn {
                        Some(text) if !text.trim().is_empty() => text.trim().to_string(),
                        _ => {
                            eprintln!(
                                "error: give --dsn or --dsn-file; a source needs a connection string"
                            );
                            std::process::exit(1);
                        }
                    },
                };
                let formats = match format
                    .iter()
                    .map(|spec| parse_format(spec))
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                };
                let source = Source {
                    id,
                    engine,
                    description,
                    dsn,
                    timeout_s: timeout,
                    columns_deny: deny,
                    columns_allow: allow,
                    column_formats: formats,
                };
                match add_source(&config, source) {
                    Ok(s) => {
                        let v = s.to_view();
                        println!(
                            "registered '{}' in {} (engine={}, timeout={}s, deny={:?}, allow={:?}, formats={}, credential={})",
                            v.id,
                            config.display(),
                            v.engine,
                            v.timeout_s,
                            v.columns_deny,
                            v.columns_allow,
                            v.column_formats.len(),
                            if v.has_credential { "present" } else { "none" }
                        );
                    }
                    Err(e) => {
                        eprintln!("error: {}", redact(&e));
                        std::process::exit(1);
                    }
                }
            }
            SourceAction::Remove { config, id } => match remove_source(&config, &id) {
                Ok(n) => println!(
                    "removed {n} source(s) named '{id}' from {}",
                    config.display()
                ),
                Err(e) => {
                    eprintln!("error: {}", redact(&e));
                    std::process::exit(1);
                }
            },
            SourceAction::List { config } => print_sources(&config),
            SourceAction::Test {
                config,
                audit,
                id,
                tls_ca,
            } => {
                let sources = match load(&config) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("error: {}", redact(&e));
                        std::process::exit(1);
                    }
                };
                let gateway = Gateway::new(
                    sources,
                    std::sync::Arc::new(Audit::new(audit)),
                    Vec::new(),
                    "cli".to_string(),
                    tls_ca,
                );
                let rt = tokio::runtime::Runtime::new().unwrap();
                let outcome = rt.block_on(async { gateway.probe(&id, "cli").await });
                match outcome {
                    Ok(info) => {
                        println!(
                            "source '{id}' is reachable: SELECT 1 returned {} row(s) in {} ms, {} table(s) in the public schema, {} row(s) in the first table",
                            info.rows_returned,
                            info.elapsed_ms,
                            info.tables.len(),
                            info.first_table_rows
                        );
                        if !info.tables.is_empty() {
                            println!(
                                "  tables: {}",
                                info.tables
                                    .iter()
                                    .take(20)
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("source '{id}' is not usable: {}", redact(&e.message()));
                        std::process::exit(1);
                    }
                }
            }
        },
    }
}

fn print_sources(config: &PathBuf) {
    match load(config) {
        Ok(sources) => {
            if sources.is_empty() {
                println!("no sources registered in {}", config.display());
                return;
            }
            for s in sources {
                let v = s.to_view();
                println!(
                    "{:<20} engine={}  timeout={}s  deny={:?}  allow={:?}  credential={}",
                    v.id,
                    v.engine,
                    v.timeout_s,
                    v.columns_deny,
                    v.columns_allow,
                    if v.has_credential { "present" } else { "none" }
                );
            }
        }
        Err(e) => {
            eprintln!("error: {}", redact(&e));
            std::process::exit(1);
        }
    }
}

fn parse_format(spec: &str) -> Result<ColumnFormat, String> {
    let parts: Vec<&str> = spec.split(':').collect();
    if parts[0].is_empty() {
        return Err(format!(
            "bad --format '{spec}'; expected name:unit=<unit>:decimals=<number>"
        ));
    }
    let mut f = ColumnFormat {
        name: parts[0].to_string(),
        unit: String::new(),
        decimals: None,
        group: true,
        delta: false,
    };
    for kv in &parts[1..] {
        let (key, value) = kv
            .split_once('=')
            .ok_or_else(|| format!("bad --format token '{kv}'; expected key=value"))?;
        match key {
            "unit" => f.unit = value.to_string(),
            "decimals" => {
                f.decimals = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| format!("decimals must be a whole number, got '{value}'"))?,
                )
            }
            "group" => {
                f.group = value
                    .parse::<bool>()
                    .map_err(|_| format!("group must be true or false, got '{value}'"))?
            }
            "delta" => {
                f.delta = value
                    .parse::<bool>()
                    .map_err(|_| format!("delta must be true or false, got '{value}'"))?
            }
            other => {
                return Err(format!(
                    "unknown --format key '{other}'; use unit, decimals, group or delta"
                ));
            }
        }
    }
    Ok(f)
}

/// Minimal CORS handling for the MCP endpoint. Loopback origins are accepted by
/// default; anything else gets no CORS headers, so a random site cannot read the
/// response of a gateway running on this machine.
async fn cors_gateway(
    allowed_origins: Vec<String>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::http::Response<axum::body::Body> {
    use axum::http::{HeaderName, HeaderValue, Method, StatusCode};

    let origin = req
        .headers()
        .get("Origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let allowed = origin.is_empty() || allowed_origins.iter().any(|o| origin_host(&origin) == *o);

    if req.method() == Method::OPTIONS {
        if !allowed {
            return axum::http::Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(axum::body::Body::from("origin not allowed"))
                .unwrap();
        }
        return axum::http::Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(
                HeaderName::from_static("access-control-allow-origin"),
                &origin,
            )
            .header(
                HeaderName::from_static("access-control-allow-methods"),
                "POST, GET, OPTIONS, DELETE",
            )
            // Echo the requested headers so MCP-specific headers (session id,
            // protocol version, method) work without a growing allowlist. The
            // origin is still restricted above.
            .header(
                HeaderName::from_static("access-control-allow-headers"),
                req.headers()
                    .get("Access-Control-Request-Headers")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("Content-Type, Accept, Mcp-Session-Id, Mcp-Protocol-Version, Mcp-Method, Last-Event-ID")
                    .to_string(),
            )
            .header(HeaderName::from_static("access-control-max-age"), "600")
            .body(axum::body::Body::empty())
            .unwrap();
    }

    let mut response = next.run(req).await;
    if allowed && !origin.is_empty() {
        response.headers_mut().insert(
            HeaderName::from_static("access-control-allow-origin"),
            HeaderValue::from_str(&origin).unwrap(),
        );
        response.headers_mut().insert(
            HeaderName::from_static("access-control-expose-headers"),
            HeaderValue::from_static("Mcp-Session-Id"),
        );
    }
    response
}

fn origin_host(origin: &str) -> String {
    let without_scheme = origin
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    without_scheme.split(':').next().unwrap_or("").to_string()
}

fn markdown(format: Format) -> bool {
    matches!(format, Format::Markdown)
}

fn run_stdio(
    config: PathBuf,
    audit: PathBuf,
    markdown: bool,
    allow_source_hosts: Vec<String>,
    tls_ca: Option<PathBuf>,
) {
    let sources = match load(&config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    let service = Guardrails::new(
        Gateway::new(
            sources,
            std::sync::Arc::new(Audit::new(audit)),
            allow_source_hosts,
            "stdio".to_string(),
            tls_ca,
        ),
        markdown,
    );
    let rt = tokio::runtime::Runtime::new().unwrap();
    let outcome = rt.block_on(async {
        match service.serve(rmcp::transport::stdio()).await {
            Ok(server) => Ok(server.waiting().await),
            Err(e) => Err(e),
        }
    });
    if let Err(e) = outcome {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}

struct HttpOptions {
    config: PathBuf,
    audit: PathBuf,
    bind: String,
    port: u16,
    markdown: bool,
    allow_non_loopback: bool,
    allowed_host: Vec<String>,
    auth_file: Option<PathBuf>,
    allow_source_hosts: Vec<String>,
    tls_ca: Option<PathBuf>,
}

/// Rejects any request without a valid bearer token and records the refusal.
async fn auth_gate(
    auth: std::sync::Arc<auth::Auth>,
    audit: std::sync::Arc<Audit>,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());
    if let Some(principal) = auth.check(header) {
        // Stamp the label onto the request so every tool call is attributed to it
        // in the audit trail. Accepted requests are not logged here: the tool call
        // itself carries the principal, and an entry per HTTP request (initialize,
        // tools/list, ping) would bury the trail in noise. Refusals are logged: they
        // are the events an operator wants to see.
        req.extensions_mut().insert(auth::Principal(principal));
        return next.run(req).await;
    }
    audit.record(&AuditRecord {
        ts: utc_now(),
        source: "-".into(),
        operation: "auth".into(),
        principal: "-".into(),
        statement: None,
        rows: 0,
        truncated: false,
        elapsed_ms: 0,
        ok: false,
        error: Some("missing or invalid Authorization: Bearer token".into()),
    });
    let mut response = axum::response::Response::new(axum::body::Body::from(
        "{\"error\":\"unauthorized: a bearer token is required\"}",
    ));
    *response.status_mut() = axum::http::StatusCode::UNAUTHORIZED;
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    response
}

fn run_http(options: HttpOptions) {
    let HttpOptions {
        config,
        audit,
        bind,
        port,
        markdown,
        allow_non_loopback,
        allowed_host,
        auth_file,
        allow_source_hosts,
        tls_ca,
    } = options;
    let loopback = bind == "127.0.0.1" || bind == "localhost" || bind == "::1";
    let auth = match auth_file {
        Some(path) => match auth::load(&path) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        },
        None => auth::Auth::none(),
    };
    if !loopback && !allow_non_loopback {
        eprintln!(
            "refusing to bind to {bind}: the server has no built-in authentication, so it \
             defaults to loopback. Pass --allow-non-loopback if you are fronting it with a \
             reverse proxy that handles TLS and authentication, or if you know the network it \
             is exposed to."
        );
        std::process::exit(1);
    }
    if !loopback && auth.is_empty() {
        eprintln!(
            "refusing to bind to {bind}: a gateway reachable from outside loopback must \n             require a token. Pass --auth-file with 'label=token' lines."
        );
        std::process::exit(1);
    }
    // Origins whose MCP client may read responses from this gateway.
    let allowed_origins: Vec<String> = vec!["127.0.0.1".to_string(), "localhost".to_string()];
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        use rmcp::transport::streamable_http_server::{
            StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
        };
        let http_config = if loopback {
            StreamableHttpServerConfig::default()
        } else {
            let hosts = if allowed_host.is_empty() {
                vec![bind.clone()]
            } else {
                allowed_host.clone()
            };
            StreamableHttpServerConfig::default().with_allowed_hosts(hosts)
        };
        let shared_audit = std::sync::Arc::new(Audit::new(audit.clone()));
        let audit_for_gate = shared_audit.clone();
        let service = StreamableHttpService::new(
            move || {
                Ok(Guardrails::new(
                    Gateway::new(
                        load(&config).unwrap_or_else(|e| {
                            eprintln!("error: {e}");
                            Vec::new()
                        }),
                        shared_audit.clone(),
                        allow_source_hosts.clone(),
                        "http".to_string(),
                        tls_ca.clone(),
                    ),
                    markdown,
                ))
            },
            LocalSessionManager::default().into(),
            http_config,
        );
        let mut router = axum::Router::new().nest_service("/mcp", service);
        if !auth.is_empty() {
            let auth_state = std::sync::Arc::new(auth.clone());
            let audit_state = audit_for_gate.clone();
            router = router.layer(axum::middleware::from_fn(move |req, next| {
                auth_gate(auth_state.clone(), audit_state.clone(), req, next)
            }));
        }
        router = router.layer(axum::middleware::from_fn(move |req, next| {
            cors_gateway(allowed_origins.clone(), req, next)
        }));
        let listener = match tokio::net::TcpListener::bind(format!("{bind}:{port}")).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("cannot listen on {bind}:{port}: {e}");
                std::process::exit(1);
            }
        };
        println!("pg-guardrails listening on http://{bind}:{port}/mcp");
        if let Err(e) = axum::serve(listener, router).await {
            eprintln!("server error: {e}");
        }
    });
}
