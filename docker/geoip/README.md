# GeoIP database mount point

Drop MaxMind GeoLite2 databases here to enable geo + network enrichment inside
the MCP container. Both downloads are free with a MaxMind registration:

https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

| File | Enables | Used for |
|---|---|---|
| `GeoLite2-City.mmdb` | country / city / lat-long / timezone | threat-map dashboard, geo fields on every enriched alert |
| `GeoLite2-ASN.mmdb` | origin AS number + organisation | spotting hosting / VPN / botnet networks — the highest-signal pivot on an attacker IP |

The compose file bind-mounts this directory read-only into the MCP container
at `/app/geoip/` and points `GEOIP_DB_PATH` / `GEOIP_ASN_DB_PATH` at the two
files. Each database is independently optional: whatever is missing just
leaves its fields out of the enrichment — nothing else breaks.

MaxMind's license forbids redistribution, which is why neither file ships in
the repo.
