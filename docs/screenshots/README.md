# Screenshots

These are embedded in the main [README](../../README.md) and are **generated,
not hand-captured** — regenerate them rather than replacing by hand, so they
cannot drift from what the software actually renders.

| File | What it shows |
|---|---|
| `console.png` | The built-in operations console (`:8090`) — live attack feed, sensor health, volume by severity |
| `overview.png` | Grafana — severity over time, top attackers, per-engine breakdown |
| `threat-map.png` | Grafana — geo-located attacker origins |
| `mitre.png` | Grafana — MITRE ATT&CK tactic coverage |

## Regenerating

```bash
./scripts/capture_screenshots.sh
```

That brings the demo stack up with a headless-Chromium renderer sidecar, seeds
demo data if the last 24 hours are empty, and writes all four PNGs here at
1920px wide. Requires Docker; everything else runs in containers.

Tear the renderer back down afterwards — it is a ~400 MB image a normal demo
run has no use for:

```bash
docker compose -f docker/docker-compose.yml \
               -f docker/docker-compose.screenshots.yml down
```

## Notes for whoever touches this next

- The seed check counts events **inside the render window**, not rows in the
  table. A database seeded yesterday is full of data and still renders empty
  panels, so a stale window triggers a reseed.
- Dark throughout: the Grafana stack sets `GF_USERS_DEFAULT_THEME=dark`, and
  the console is dark by design.
- If a Grafana panel shows "No data" while the same SQL works through the API,
  check that every target carries `rawQueryText`. The SQLite plugin's frontend
  interpolates from that field, and without it the browser sends an empty
  query — which is exactly how all three dashboards were silently broken.
