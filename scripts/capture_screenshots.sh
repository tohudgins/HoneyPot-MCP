#!/usr/bin/env bash
#
# Regenerate the dashboard PNGs embedded in README.md.
#
# Brings up the demo stack with Grafana's headless-Chromium renderer attached,
# seeds demo data if the DB is empty, and renders each dashboard to
# docs/screenshots/. Idempotent — safe to re-run whenever a dashboard changes.
#
#   ./scripts/capture_screenshots.sh
#
# Requires Docker. Everything else runs in containers.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_DIR="$REPO_ROOT/docker"
OUT_DIR="$REPO_ROOT/docs/screenshots"

GRAFANA_URL="${GRAFANA_URL:-http://localhost:3000}"
GRAFANA_USER="${GRAFANA_USER:-admin}"
GRAFANA_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-honeypot}"
WIDTH="${WIDTH:-1920}"
HEIGHT="${HEIGHT:-1080}"

# dashboard-uid:output-filename
DASHBOARDS=(
  "honeypot-overview:overview.png"
  "honeypot-threat-map:threat-map.png"
  "honeypot-mitre:mitre.png"
)

compose() {
  docker compose -f "$DOCKER_DIR/docker-compose.yml" \
                 -f "$DOCKER_DIR/docker-compose.screenshots.yml" "$@"
}

echo "==> Starting demo stack with the renderer sidecar"
compose up -d --build

echo "==> Waiting for Grafana"
for _ in $(seq 1 60); do
  if curl -sf "$GRAFANA_URL/api/health" >/dev/null 2>&1; then break; fi
  sleep 2
done
curl -sf "$GRAFANA_URL/api/health" >/dev/null || {
  echo "Grafana did not become healthy at $GRAFANA_URL" >&2
  exit 1
}

# The dashboards render a `now-24h` window, and the seed spreads events over
# the 24h preceding the seed run — so a DB seeded yesterday is full of rows
# yet renders empty. Count what falls inside the render window, not the table.
echo "==> Checking for demo data inside the last 24h"
RECENT_COUNT="$(compose exec -T honeypot-mcp python -c "
import sqlite3
try:
    c = sqlite3.connect('file:/app/data/honeypot_mcp.db?mode=ro', uri=True)
    print(c.execute(
        \"SELECT COUNT(*) FROM alerts \"
        \"WHERE timestamp >= datetime(strftime('%s','now') - 86400, 'unixepoch')\"
    ).fetchone()[0])
except Exception:
    print(0)
" 2>/dev/null | tr -d '[:space:]')"
if [ "${RECENT_COUNT:-0}" -lt 100 ]; then
  echo "    only ${RECENT_COUNT:-0} alerts in the last 24h — reseeding"
  compose exec -T honeypot-mcp python scripts/seed_demo_data.py
else
  echo "    $RECENT_COUNT alerts in window — skipping seed"
fi

mkdir -p "$OUT_DIR"

echo "==> Rendering dashboards at ${WIDTH}x${HEIGHT}"
for entry in "${DASHBOARDS[@]}"; do
  uid="${entry%%:*}"
  file="${entry##*:}"
  echo "    $uid -> docs/screenshots/$file"
  # `kiosk` strips Grafana chrome; the renderer needs a generous timeout
  # because the SQLite panels scan the full alerts table on cold cache.
  curl -sf --get \
    -u "$GRAFANA_USER:$GRAFANA_PASSWORD" \
    --data-urlencode "orgId=1" \
    --data-urlencode "from=now-24h" \
    --data-urlencode "to=now" \
    --data-urlencode "width=$WIDTH" \
    --data-urlencode "height=$HEIGHT" \
    --data-urlencode "theme=dark" \
    --data-urlencode "kiosk=true" \
    --data-urlencode "timeout=60" \
    -o "$OUT_DIR/$file" \
    "$GRAFANA_URL/render/d/$uid/dashboard"

  # A failed render still returns 200 with a JSON error body; catch that.
  if ! file "$OUT_DIR/$file" | grep -q "PNG image"; then
    echo "    !! $file is not a PNG — render failed:" >&2
    head -c 400 "$OUT_DIR/$file" >&2
    echo >&2
    exit 1
  fi
done

echo
echo "==> Done. Wrote:"
ls -la "$OUT_DIR"/*.png
echo
echo "Tear the renderer back down with:"
echo "  docker compose -f docker/docker-compose.yml -f docker/docker-compose.screenshots.yml down"
