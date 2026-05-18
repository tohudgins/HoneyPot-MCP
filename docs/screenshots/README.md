# Dashboard screenshots

Drop captured PNGs here and they'll render in the main README:

- `overview.png` — `HoneyPot MCP — Overview` dashboard
- `threat-map.png` — `HoneyPot MCP — Threat Map` dashboard
- `mitre.png` — `HoneyPot MCP — MITRE ATT&CK Coverage` dashboard

## How to capture them

```bash
# Stand up the stack
cd docker
docker compose up -d --build

# Wait ~20s for Grafana to start, then seed demo data
docker compose exec honeypot-mcp python scripts/seed_demo_data.py

# Open Grafana
#   URL:       http://localhost:3000
#   username:  admin
#   password:  honeypot   (override with GRAFANA_ADMIN_PASSWORD env var)

# Browse to each dashboard. Use the share menu in Grafana
# (chain icon) → "Share externally" → toggle "Render image"
# for a PNG export with the current time range.
```

## Sizing tips

- 1920×1080 is the right capture size for README embedding — Grafana
  renders cleanly at that resolution and the panels stay readable.
- Set the time range to "Last 24h" before capturing so the seed data
  fully fills the panels.
- The Threat Map dashboard looks best in dark mode (Grafana's default
  for this deployment via `GF_USERS_DEFAULT_THEME=dark`).
