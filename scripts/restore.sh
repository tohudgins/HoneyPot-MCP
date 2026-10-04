#!/usr/bin/env bash
# Restore a HoneyPot MCP backup produced by scripts/backup.sh.
#
# Stop the server first. Restoring underneath a running server leaves it
# holding an open handle to the replaced file: it keeps working, keeps
# reporting success, and writes into a database nobody will ever read again.
set -euo pipefail

SRC="${1:?usage: restore.sh <backup-dir>}"
[ -d "$SRC" ] || { echo "no such backup: $SRC" >&2; exit 1; }

# Match both invocation forms: `python -m honeypot_mcp.server` (argv contains
# the module path literally) and the `honeypot-mcp` console-script entry
# point (pyproject.toml's [project.scripts], and what the Docker image's
# ENTRYPOINT uses) — a console script's argv is just its own wrapper path
# ("…/bin/honeypot-mcp"), which never contains the string "honeypot_mcp.server"
# even though that's the module it imports internally. Checking only the
# first form let a server started the documented/default-deployment way run
# straight through this guard.
if pgrep -f "honeypot_mcp\.server|honeypot-mcp" >/dev/null 2>&1; then
  echo "!! the server is still running — stop it first, or the restore is silently discarded" >&2
  exit 1
fi

# Restored files hold the evidence and key material: never world-readable.
umask 077

# Same override as backup.sh, so a deployment that keeps its DB under ./data
# (see deploy/honeypot-mcp.service) is restored to where the server reads it.

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

if [ "$IS_POSTGRES" = 0 ] && [ -f "$SRC/honeypot_mcp.db" ]; then
  # Keep whatever is currently there; a restore onto the wrong host is
  # recoverable, an overwrite is not.
  STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
  [ -f "$DB_PATH" ] && mv "$DB_PATH" "$DB_PATH.replaced-$STAMP"
  # A WAL/SHM pair left over from the old database does not belong to the
  # restored file. SQLite would replay the stale WAL into it (or refuse to open
  # it), silently corrupting the restore. Park them with the old DB they match.
  for suffix in -wal -shm; do
    [ -f "$DB_PATH$suffix" ] && mv "$DB_PATH$suffix" "$DB_PATH.replaced-$STAMP$suffix"
  done
  cp "$SRC/honeypot_mcp.db" "$DB_PATH"
  echo "  database restored"
elif [ -f "$SRC/honeypot_mcp.sql" ] || [ "$IS_POSTGRES" = 1 ]; then
  [ -n "${DATABASE_URL:-}" ] || { echo "set DATABASE_URL for a PostgreSQL restore" >&2; exit 1; }
  # Password via PGPASSFILE, not argv (visible to every local user in `ps`).
  PGPASSFILE="$(mktemp)"
  export PGPASSFILE
  trap 'rm -f "$PGPASSFILE"' EXIT
  PG_CLEAN_URL="$(python3 "$(dirname "${BASH_SOURCE[0]}")/_pgurl.py" "$DATABASE_URL" "$PGPASSFILE")"
  # ON_ERROR_STOP + single transaction: a half-applied dump must roll back
  # rather than leave a database that looks restored and is not.
  psql -v ON_ERROR_STOP=1 -1 "$PG_CLEAN_URL" < "$SRC/honeypot_mcp.sql"
  echo "  database restored"
fi

# `tls/.` copies the *contents*; `cp -R tls ./tls` would nest tls/tls on a
# second restore (or whenever ./tls already exists).
if [ -d "$SRC/tls" ]; then
  mkdir -p ./tls
  cp -R "$SRC/tls/." ./tls/
  echo "  tls certs restored"
fi
# Generated file-token artefacts (PDF/DOCX trackers, honeytoken SSH private keys
# exist ONLY here — the database holds just the fingerprint).
if [ -d "$SRC/reports" ]; then
  mkdir -p ./reports
  cp -R "$SRC/reports/." ./reports/
  echo "  reports restored"
fi
[ -f "$SRC/.env" ] && echo "  .env present in the backup — copy it manually once you have checked it"

echo
echo "Restore complete. Start the server, then confirm: curl -s localhost:9090/readyz"
