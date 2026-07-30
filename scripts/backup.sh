#!/usr/bin/env bash
# Back up a running HoneyPot MCP deployment.
#
# The database is the evidence. Everything else in this project can be rebuilt
# from the repo; captured attack data cannot, and neither can the honeytoken
# values — a token whose secret is lost can never be attributed if it fires.
#
# SQLite is backed up with the `.backup` command rather than `cp`, because the
# server runs in WAL mode: copying the .db file while a write is in flight
# yields a file that opens fine and is missing recent transactions. `.backup`
# takes a consistent snapshot of a live database. That distinction is the whole
# reason this script exists instead of a one-line cp in the docs.
set -euo pipefail

DEST="${1:-./backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$DEST/honeypot-$STAMP"
mkdir -p "$OUT"

DB_PATH="${HONEYPOT_DB_PATH:-./honeypot_mcp.db}"
if [ -f "$DB_PATH" ]; then
  sqlite3 "$DB_PATH" ".backup '$OUT/honeypot_mcp.db'"
  echo "  database  -> $OUT/honeypot_mcp.db ($(du -h "$OUT/honeypot_mcp.db" | cut -f1))"
elif [ -n "${DATABASE_URL:-}" ] && [[ "$DATABASE_URL" == postgresql* ]]; then
  # Strip the async driver suffix; pg_dump speaks libpq URLs.
  pg_dump "$(echo "$DATABASE_URL" | sed 's|+asyncpg||')" > "$OUT/honeypot_mcp.sql"
  echo "  database  -> $OUT/honeypot_mcp.sql ($(du -h "$OUT/honeypot_mcp.sql" | cut -f1))"
else
  echo "  !! no database found at $DB_PATH and DATABASE_URL is not PostgreSQL" >&2
  exit 1
fi

# TLS keys are per-honeypot and pinned by scanners across restarts, so losing
# them changes every decoy's identity — which is itself a detectable event.
[ -d ./tls ] && cp -R ./tls "$OUT/tls" && echo "  tls certs -> $OUT/tls"
# Generated file tokens: the planted copies in the field reference these.
[ -d ./reports ] && cp -R ./reports "$OUT/reports" && echo "  reports   -> $OUT/reports"

# .env holds the auth token and API keys, so the backup inherits its secrecy.
if [ -f .env ]; then
  cp .env "$OUT/.env"
  chmod 600 "$OUT/.env"
  echo "  .env      -> $OUT/.env (mode 600)"
fi
chmod -R go-rwx "$OUT"

echo
echo "Backup complete: $OUT"
echo "It contains secrets. Store it where you would store the .env itself."
