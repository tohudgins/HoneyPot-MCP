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

# The backup holds the database, honeytoken values, TLS keys and .env. Set the
# umask before the first file or directory is created so nothing is ever, even
# briefly, readable by other local users (a later chmod leaves that window open).
umask 077

DEST="${1:-./backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$DEST/honeypot-$STAMP"
mkdir -p "$OUT"


# Where is the database? Same answer the server gives, not a guess: an explicit
# HONEYPOT_DB_PATH wins, then DATABASE_URL (from the environment, or from ./.env
# when run from cron), then the default. A PostgreSQL URL always means a
# pg_dump/psql round-trip, even if a stale ./honeypot_mcp.db is lying around.
if [ -z "${DATABASE_URL:-}" ] && [ -f ./.env ]; then
  DATABASE_URL="$(grep -E '^DATABASE_URL=' ./.env | tail -n1 | cut -d= -f2- | tr -d "\"'")"
fi
DB_PATH="${HONEYPOT_DB_PATH:-}"
if [ -z "$DB_PATH" ]; then
  case "${DATABASE_URL:-}" in
    sqlite*:///*) DB_PATH="${DATABASE_URL#*:///}" ;;
    *) DB_PATH="./honeypot_mcp.db" ;;
  esac
fi
IS_POSTGRES=0
case "${DATABASE_URL:-}" in postgresql*) [ -z "${HONEYPOT_DB_PATH:-}" ] && IS_POSTGRES=1 ;; esac
if [ "$IS_POSTGRES" = 0 ] && [ -f "$DB_PATH" ]; then
  sqlite3 "$DB_PATH" ".backup '$OUT/honeypot_mcp.db'"
  echo "  database  -> $OUT/honeypot_mcp.db ($(du -h "$OUT/honeypot_mcp.db" | cut -f1))"
elif [ "$IS_POSTGRES" = 1 ]; then
  # Strip the async driver suffix; pg_dump speaks libpq URLs. The password is
  # moved out of the URL (and so out of argv, where `ps` shows it to every local
  # user) into a mode-0600 PGPASSFILE that is removed on exit.
  PGPASSFILE="$(mktemp)"
  export PGPASSFILE
  trap 'rm -f "$PGPASSFILE"' EXIT
  PG_CLEAN_URL="$(python3 "$(dirname "${BASH_SOURCE[0]}")/_pgurl.py" "$DATABASE_URL" "$PGPASSFILE")"
  pg_dump "$PG_CLEAN_URL" > "$OUT/honeypot_mcp.sql"
  echo "  database  -> $OUT/honeypot_mcp.sql ($(du -h "$OUT/honeypot_mcp.sql" | cut -f1))"
else
  echo "  !! no database found at $DB_PATH and DATABASE_URL is not PostgreSQL (set HONEYPOT_DB_PATH or DATABASE_URL)" >&2
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
