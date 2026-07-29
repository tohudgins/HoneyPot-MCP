# config/

Runtime files you supply. Nothing here ships with the project, and nothing here
is required — every feature that reads this directory degrades cleanly when it
is empty.

| Path | Purpose | Where to get it |
|---|---|---|
| `GeoLite2-City.mmdb` | Country/city/coordinates on every enriched alert; feeds the threat map | [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data), free with registration |
| `GeoLite2-ASN.mmdb` | Origin AS number + organisation — the strongest "is this hosting/VPN/botnet?" pivot | Same account, separate download |
| `mitre_attack.json` | Full ATT&CK technique descriptions | [mitre/cti](https://github.com/mitre/cti) `enterprise-attack.json` |
| `suppression_presets/<name>.yaml` | Your own suppression preset, or an override of a bundled one | Write your own |

All of the above are gitignored. MaxMind's licence forbids redistributing the
`.mmdb` files, so the ignore rule matches `config/*.mmdb` by extension rather
than by filename — an earlier rule named only the City database and let the ASN
one slip into a commit.

## Notes

- **Bundled suppression presets** (`shodan`, `censys`, `internal-rfc1918`) ship
  inside the installed package, not here. A file placed at
  `config/suppression_presets/<name>.yaml` takes precedence over the bundled
  preset of the same name.
- **There is no `settings.yaml`.** One used to sit here and was loaded at
  startup, but nothing ever read from it — editing it silently changed nothing.
  Configuration is environment variables and `.env` only; see
  [`.env.example`](../.env.example) for every available setting.
- **In Docker**, this directory is not copied into the image. Mount your files
  in, or use the `docker/geoip/` bind mount that the compose file already wires
  to `GEOIP_DB_PATH` / `GEOIP_ASN_DB_PATH`.
