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

if [ -f "$SRC/honeypot_mcp.db" ]; then
  # Keep whatever is currently there; a restore onto the wrong host is
  # recoverable, an overwrite is not.
  [ -f ./honeypot_mcp.db ] && mv ./honeypot_mcp.db "./honeypot_mcp.db.replaced-$(date -u +%Y%m%dT%H%M%SZ)"
  cp "$SRC/honeypot_mcp.db" ./honeypot_mcp.db
  echo "  database restored"
elif [ -f "$SRC/honeypot_mcp.sql" ]; then
  [ -n "${DATABASE_URL:-}" ] || { echo "set DATABASE_URL for a PostgreSQL restore" >&2; exit 1; }
  psql "$(echo "$DATABASE_URL" | sed 's|+asyncpg||')" < "$SRC/honeypot_mcp.sql"
  echo "  database restored"
fi

[ -d "$SRC/tls" ] && cp -R "$SRC/tls" ./tls && echo "  tls certs restored"
[ -f "$SRC/.env" ] && echo "  .env present in the backup — copy it manually once you have checked it"

echo
echo "Restore complete. Start the server, then confirm: curl -s localhost:9090/readyz"
