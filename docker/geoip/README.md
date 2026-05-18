# GeoIP database mount point

Drop `GeoLite2-City.mmdb` here to enable GeoIP enrichment inside the MCP
container. Download is free with a MaxMind registration:

https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

The compose file bind-mounts this directory read-only into the MCP container
at `/app/geoip/`. If the file is missing, GeoIP enrichment silently degrades
to `available: false` — nothing else breaks.

MaxMind's license forbids redistribution, which is why the file isn't shipped
in the repo.
