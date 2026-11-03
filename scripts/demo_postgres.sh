#!/usr/bin/env bash
# demo_postgres.sh - start a throwaway PostgreSQL 17 cluster for the demo.
#
# Uses the system PostgreSQL binaries if present, otherwise a podman container.
# Nothing is created outside DEMO_DIR (default ./demo-db).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
DEMO_DIR="${DEMO_DIR:-$ROOT/demo-db}"
PORT="${PORT:-5433}"
PGBIN="${PGBIN:-}"

if [ -z "$PGBIN" ]; then
  for c in /usr/lib/postgresql/17/bin /usr/lib/postgresql/16/bin /usr/local/bin; do
    if [ -x "$c/initdb" ]; then PGBIN="$c"; break; fi
  done
fi

if [ -z "$PGBIN" ]; then
  echo "No PostgreSQL binaries found. Install PostgreSQL 16+ or use podman:"
  echo "  podman run -d --name pg-guardrails -e POSTGRES_PASSWORD=demo -p 5433:5433 postgres:17"
  exit 1
fi

if [ ! -f "$DEMO_DIR/PG_VERSION" ]; then
  mkdir -p "$DEMO_DIR"; chmod 700 "$DEMO_DIR"
  "$PGBIN/initdb" -D "$DEMO_DIR" -U demo --auth=trust >/dev/null
  mkdir -p "$DEMO_DIR/socket"
  cat >> "$DEMO_DIR/postgresql.conf" <<CFG
listen_addresses = '127.0.0.1'
port = $PORT
unix_socket_directories = '$DEMO_DIR/socket'
max_connections = 40
CFG
fi

if ! "$PGBIN/pg_isready" -h 127.0.0.1 -p "$PORT" -q; then
  "$PGBIN/pg_ctl" -D "$DEMO_DIR" -l "$DEMO_DIR/pg.log" -w -t 20 start
fi

PSQL=("$PGBIN/psql" -h 127.0.0.1 -p "$PORT" -U demo -d postgres)
"${PSQL[@]}" -q -c "DROP DATABASE IF EXISTS guardrails_demo"
"${PSQL[@]}" -q -c "CREATE DATABASE guardrails_demo"
"${PSQL[@]}" -d guardrails_demo -v ON_ERROR_STOP=1 -q -f "$ROOT/assets/demo/schema.sql"
"${PSQL[@]}" -d guardrails_demo -v ON_ERROR_STOP=1 -q -f "$ROOT/assets/demo/seed.sql"

"${PSQL[@]}" -d guardrails_demo -q <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'agent_ro') THEN
    CREATE ROLE agent_ro LOGIN;
  END IF;
END
\$\$;
ALTER ROLE agent_ro SET default_transaction_read_only = on;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM agent_ro;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO agent_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO agent_ro;
SQL

echo "demo ready: postgres://agent_ro@127.0.0.1:$PORT/guardrails_demo"
