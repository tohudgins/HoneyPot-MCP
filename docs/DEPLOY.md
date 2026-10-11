# Deployment Guide — getting real attack data in under 30 minutes

This guide takes you from "code on your laptop" to "honeypot on the public
internet logging real attack traffic" with a focus on the SSH honeypot
because that's what catches traffic fastest. Expect your first events
within minutes of the deploy on any public IP.

Two paths:

1. [Cheap VPS deploy](#cheap-vps-deploy) — DigitalOcean / Hetzner / Linode,
   ~$5/month, ~15 minutes of work. **Recommended for real attack collection.**
2. [Home lab deploy](#home-lab-deploy) — your own machine + a reverse tunnel
   (ngrok / Cloudflare Tunnel). Good for testing the pipeline without renting
   a VPS, but won't catch internet-scale traffic unless you're exposing real
   ports.

---

## Before you start — a non-negotiable safety note

A honeypot on the public internet **is the target**. Treat the host as
compromised by design: assume the day you stop watching it, someone exploits
something in your Docker image or your host configuration that you didn't
anticipate. Concrete rules:

- **One dedicated host per deployment**. Never run honeypots on a machine
  that also holds anything you care about — your dev environment, your
  password manager, your SSH keys to other servers.
- **Never SSH into the honeypot host using the same keys you use for
  production**. Generate a deploy-only key, store it on a single laptop.
- **Move the real admin SSH port off 22** before you start the honeypot.
  If you forget this step you're locking yourself out the moment the
  honeypot starts.
- **Set up alerts before traffic arrives**, not after. Slack, Teams and email
  are first-class formats — `alert_subscribe(url=..., format="slack",
  severity_threshold="high")`. Use `high` or `critical`; at `medium` a single
  scanner will bury the channel. (Repeats are coalesced automatically per
  `NOTIFY_THROTTLE_SECONDS`, and CRITICAL is never held back.)
- **Decide about packet capture before you need it.** `PCAP_ENABLED=true` plus
  `sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)` gives you full
  pcap for malware carving, Suricata/Zeek replay and evidence. It only records
  from the moment you turn it on, so switching it on after an interesting
  attack is too late. Check `PCAP_FILE_MB × PCAP_FILES` (default 1 GB) against
  free disk — a full disk stops the database and ends collection entirely.
  Capture is scoped to honeypot ports, so your own admin SSH is never recorded.

---

## Cheap VPS deploy

### 1. Provision the VPS (5 min)

Pick any provider. The cheapest tier is fine — 1 vCPU, 1 GB RAM, 25 GB disk.

| Provider | Recommended size | Cost |
|---|---|---|
| Hetzner CX22 | 2 vCPU, 4 GB | €4.51/mo |
| DigitalOcean Basic | 1 vCPU, 1 GB | $6/mo |
| Linode Nanode | 1 vCPU, 1 GB | $5/mo |
| Vultr Cloud Compute | 1 vCPU, 1 GB | $6/mo |

Pick **Ubuntu 22.04 LTS** as the OS. Note the public IPv4 address.

### 2. First SSH — create your admin user, then harden (the script moves the port)

```bash
ssh root@<your-ip>
```

Create a non-root admin account with your **deploy-only** public key. Root login and password
login are about to be disabled, so do this first. (The provider's browser console will stop
working too, because it logs in as root: the safety net is the rollback timer plus the Recovery
Console password in "Getting back in" below.)

```bash
adduser --disabled-password --gecos "" deploy
usermod -aG sudo deploy
echo "deploy ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/deploy && chmod 440 /etc/sudoers.d/deploy
install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
echo "<your deploy-only public key>" > /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys && chmod 600 /home/deploy/.ssh/authorized_keys
```

From your laptop, confirm the key works **before** going on:

```bash
ssh -i ~/.ssh/honeypot_deploy deploy@<your-ip>      # logged in as deploy: good
```

Moving sshd off port 22 and turning off root/password login is done by
`deploy/harden-host.sh` in step 5, in two phases so you cannot lock yourself out: first sshd
listens on 22 *and* 2200 until you have logged in on 2200, then it moves to 2200 only. Do not
edit `sshd_config` by hand.

### 3. Install Docker + clone the repo (5 min)

```bash
# Docker — the SSH/Cowrie engine manages honeypot containers through it. Ubuntu's own
# `docker.io` package is what the hardening was rehearsed and run with (Docker 29.1.3 on
# 22.04); the get.docker.com script installs a different build that was not tested.
sudo apt-get update && sudo apt-get install -y docker.io

# uv to build the Python environment (step 5 builds it)
apt update && apt install -y git
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env

git clone https://github.com/tohudgins/HoneyPot-MCP.git /opt/honeypot-mcp
cd /opt/honeypot-mcp
```

> **Architecture — read this once.** The MCP server is the *control plane*:
> you talk to it in natural language and it deploys/monitors honeypots.
> The in-process engines (HTTP/SMTP/FTP/DNS/RDP/VNC/Redis/MySQL/Elasticsearch)
> run *inside the server process* and bind host ports directly; the SSH engine
> launches Cowrie as its own Docker container. Because the honeypots live in
> the server process, **the server must run persistently** — not spawned per
> chat. So on a VPS you run it as an HTTP daemon (this section) and connect
> your MCP client to it over the network. (Locally, Claude Desktop/Code spawn
> it over stdio per chat — fine for testing, wrong for 24/7 collection.)

### 4. Configure (2 min)

> **On the VPS, skip to step 5**: it installs `deploy/env.production.example`, the hardened
> profile (loopback binds, moved ports, three role tokens, console off). What follows explains
> every setting, for a laptop or for changing the profile.

```bash
cp .env.example .env
```

Open `.env` and set:

```bash
# Run as a persistent HTTP daemon so honeypots survive across chats.
MCP_TRANSPORT=http
MCP_HOST=127.0.0.1        # loopback only — reach it over the SSH tunnel (step 7)
MCP_PORT=8000
# REQUIRED for http/sse — the daemon refuses to start without it. Clients must
# present it as `Authorization: Bearer <token>`. Generate a fresh one:
#   openssl rand -hex 32
MCP_AUTH_TOKEN=<paste-openssl-rand-hex-32-here>   # min 16 chars; 64-hex recommended

# The systemd unit (step 5) can write ONLY data/, reports/, tls/ and pcap/, so
# the SQLite database must live under data/:
DATABASE_URL=sqlite+aiosqlite:///./data/honeypot_mcp.db

# ALTERNATIVE to the single token above: hand out multiple tokens with
# different access levels instead of one shared full-access token. Takes
# priority over MCP_AUTH_TOKEN when set. Format: "token:role,token:role",
# role is one of viewer (read-only triage/analysis), operator (also
# deploy/stop honeypots, manage honeytokens, acknowledge alerts — everything
# reversible and contained to this system's own data), or admin (also prune
# alerts, push to a real external firewall/WAF, read the audit log). See
# src/honeypot_mcp/rbac.py for exactly which tool needs which role.
#   openssl rand -hex 32   # once per token you hand out
# MCP_AUTH_TOKENS=<viewer-token>:viewer,<operator-token>:operator,<admin-token>:admin

# For a TEAM: treat MCP_AUTH_TOKEN/MCP_AUTH_TOKENS above as a break-glass
# bootstrap credential, not something you hand to every team member. Once
# the server is up, use that admin token to mint real per-person keys —
# these can be issued and revoked live, no restart, and each carries a real
# name so audit_log_search can say who did what, not just what happened:
#
#   > create an operator API key for alice
#   (admin-only tool api_key_create returns the plaintext token ONCE — copy
#   it immediately, there is no way to retrieve it again)
#
#   > revoke alice's API key          (api_key_revoke, takes effect in ~30s)
#   > list active API keys            (api_key_list)

# Canary tokens that call back over the internet need the callback server reachable. The
# production profile binds it to loopback (a first run uses no URL canaries); to use them set
# CANARY_CALLBACK_HOST=0.0.0.0, open its port in the firewall, and:
CANARY_PUBLIC_URL=http://<your-vps-ip>:8888

# RECOMMENDED — sign up for the free tiers, paste real keys here. Leave them
# EMPTY otherwise: any non-empty placeholder is treated as a key.
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=

# OPTIONAL — drop GeoLite2 databases in config/ for geo + network enrichment
GEOIP_DB_PATH=config/GeoLite2-City.mmdb
GEOIP_ASN_DB_PATH=config/GeoLite2-ASN.mmdb
```

If you want geographic and network data in alerts, register at
[maxmind.com](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
and download two databases: `GeoLite2-City.mmdb` (country/city/coords — feeds
the threat map) and `GeoLite2-ASN.mmdb` (origin AS number + org — the
highest-signal pivot for spotting hosting/VPN/botnet networks). Place both
under `config/`. Each is independently optional; a missing one just leaves its
fields out. MaxMind's license forbids redistribution, so neither is in the repo.

> **Secure the control-plane port.** `MCP_PORT` can deploy honeypots and
> read all captured data. It's bearer-token authenticated (`MCP_AUTH_TOKEN` or
> `MCP_AUTH_TOKENS` — the daemon refuses to start without one), but treat the token as
> defence-in-depth, not the only layer: keep `MCP_HOST=127.0.0.1`, let the firewall make the
> port unreachable from outside, and reach it over an SSH tunnel (step 7). The production
> profile also moves it off 8000 (to 18443); that only keeps a stray `localhost:8000` from
> being this server, the protection is the loopback bind, the firewall and the tokens. If
> several people need it, put a TLS reverse proxy (Caddy/nginx) in front on 443 rather than
> binding it to `0.0.0.0` — the token travels in clear text over plain HTTP.

### 5. Run the server as a persistent daemon (5 min)

Everything in this step and the next is scripted and explained in
[HARDENING.md](HARDENING.md); this is the short version. The service runs as its own
unprivileged user, in a systemd sandbox, **not** in the `docker` group (it reaches Docker only
through a validating guard process), and it listens only on loopback.

```bash
cd /opt/honeypot-mcp

# 1. Build the venv with an interpreter the service user can execute. A plain `uv sync` as root
#    puts Python under /root/.local/share/uv/python, which the service cannot reach (the unit
#    dies with "Permission denied").
sudo rm -rf .venv
sudo UV_PYTHON_INSTALL_DIR=/opt/uv-python uv sync --frozen --no-dev --python 3.12

# 2. Users, sshd (listening on 22 AND 2200 for now), kernel hardening, Docker daemon settings,
#    unattended security updates, and the systemd units. Touches no firewall rule.
sudo deploy/harden-host.sh prepare --admin-user deploy
#    -> from a NEW terminal confirm:  ssh -p 2200 deploy@<vps-ip>

# 3. Production configuration: three role tokens, everything on loopback, moved ports.
sudo install -m 0640 -o root -g honeypot deploy/env.production.example .env
sudo $EDITOR .env          # replace the three CHANGE_ME_* tokens (openssl rand -hex 32 each)
sudo chown -R root:root /opt/honeypot-mcp
sudo install -d -m 0700 -o honeypot -g honeypot data reports tls pcap
sudo chown root:honeypot .env && sudo chmod 0640 .env

# 4. Start it. The Docker guard starts first (the unit requires it).
sudo systemctl enable --now honeypot-mcp
sudo systemctl status honeypot-mcp honeypot-docker-guard   # both active (running)
journalctl -u honeypot-mcp -f                              # live logs
```

The unit is sandboxed (`ProtectSystem=strict`, no capabilities, a syscall deny-list,
`ProtectProc=invisible`, `MemoryMax=1G`, `TasksMax=512`, IP/Unix/netlink sockets only;
`systemd-analyze security` scores it 1.4 and the guard 0.6). Tune `MemoryMax` to the machine.
Packet capture (`PCAP_ENABLED=true`) needs the `CAP_NET_RAW`/`CAP_NET_ADMIN` + `AF_PACKET`
drop-in documented at the bottom of the unit file. Honeypot ports below 1024 (80, 110, ...) are
not bound directly (the unit has no `CAP_NET_BIND_SERVICE`): deploy the engine on a high port
and let the firewall redirect (`80>8080`, step 6). The SSH/Telnet honeypots are Docker
containers whose published ports (22, 23) Docker forwards itself.

> **Why the guard.** Membership in the `docker` group is root-equivalent: anyone who can talk
> to the daemon can start a privileged container that mounts `/`. This service parses
> attacker-controlled bytes all day, so a bug in it must not reach that. The guard
> (`honeypot-docker-guard.service`, `hardening/docker_guard.py`) forwards only the Cowrie
> container operations the SSH engine makes, from the pinned image with the engine's own
> security settings, and refuses everything else with 403: no privileged containers, no host
> mounts, no exec, no other images. See HARDENING.md.

The daemon serves the MCP endpoint at `http://127.0.0.1:18443/mcp` and Prometheus `/metrics` on
`127.0.0.1:19090`; the console is disabled and the canary callback server is loopback-only.

### 6. Load the firewall (3 min)

Open **only the honeypot ports and your admin SSH port**. Nothing else is reachable: not the
control plane, not metrics, not a service somebody installs later. The honeypot ports are open
to the whole internet with no rate limit, geo-block or ban: they exist to be attacked. The
admin SSH port is rate-limited per source and can be restricted to your own address.

```bash
# Moves sshd to 2200 ONLY (port 22 becomes the SSH honeypot), loads the nftables firewall, and
# arms a rollback timer: if you cannot log in afterwards, do nothing and it removes itself.
sudo deploy/harden-host.sh finalize --admin-user deploy --confirm-admin-port-tested \
    --ports "80>8080,3389,110>1110" --docker-ports 22,23
#    -> from a NEW terminal confirm you can still log in:  ssh -p 2200 deploy@<vps-ip>
sudo deploy/harden-host.sh confirm      # persists the firewall and the guard across reboots
```

`--ports "80>8080,3389,110>1110"` means: the world connects to 80 and the HTTP engine listens
on 8080; RDP listens on 3389; POP3 is reached on 110 and listens on 1110. Deploy each engine on
its *listening* port in step 8 (HTTP on 8080, POP3 on 1110). Add `--admin-allow <your-ip>/32`
to let only your own address reach admin SSH, and `--egress limited --dns <resolver>` to let
Cowrie fetch malware samples (see HARDENING.md, "Malware sample capture").

> **ufw does not protect Docker-published ports**, which is one reason this uses nftables
> directly: Docker's published ports are forwarded, not input, so the firewall's `forward`
> chain is where a container's outbound connections are refused (a hijacked Cowrie cannot scan,
> relay or reach the cloud metadata service).

### 7. Connect your MCP client over an SSH tunnel (2 min)

From your laptop, tunnel the control port so you can drive the daemon without
exposing it to the internet. Use a key that exists only for this host:

```bash
ssh -i ~/.ssh/honeypot_deploy -p 2200 -N -L 18443:127.0.0.1:18443 deploy@<vps-ip> &
```

Then register the daemon with Claude Code as a networked MCP server, passing
a bearer token. **Use the `viewer` token for reading** and `operator` only while you deploy:

```bash
claude mcp add --transport http honeypot-mcp http://127.0.0.1:18443/mcp \
  --header "Authorization: Bearer <your-viewer-or-operator-token>"
```

(Claude Desktop: add an `mcpServers` entry with `"url":
"http://127.0.0.1:18443/mcp"` and a `"headers": {"Authorization": "Bearer
<token>"}` — a URL, not a spawn command.) Without a valid token the server answers
`401`. Every deploy you make now lands in the daemon on the VPS and keeps
running after you disconnect. A `viewer` session cannot even see the deploy tools. The tunnel
allows 6 new SSH connections a minute from one address; one long-lived tunnel is one connection.

### 8. Deploy honeypots and wire an alert channel (2 min)

Connect with the `operator` token for this step. In a chat with the connected client, deploy on
the ports the engines **listen** on (the firewall maps the public ports to them, step 6):

```
> Deploy an SSH honeypot on port 22.            (Cowrie in Docker; Docker publishes 22)
> Deploy an HTTP honeypot on port 8080.         (the world reaches it on 80)
> Deploy an RDP honeypot on port 3389.
> Deploy a POP3 honeypot on port 1110.          (the world reaches it on 110)
> alert_subscribe url=https://hooks.slack.com/services/... severity_threshold=high
> honeypot_self_test <name>      # confirm the pipeline end-to-end
```

`honeypot_self_test` sends a synthetic probe and confirms it lands as an alert
within ~1s (`alert_received: True`). Because the daemon is persistent, these
honeypots keep collecting after your chat and your SSH tunnel close. Leave the SMTP and DNS
honeypots out of a first run on a cloud provider: to an automated relay or resolver check they
look like an open relay / open resolver, which several providers' acceptable-use policies
prohibit (nothing is ever relayed or resolved, but the check cannot tell). When you are done
deploying, switch the client to the `viewer` token.

### 9. (Optional) Bring up the Grafana dashboards

The data directory is private (`0700`), which Grafana (a container, uid 472)
cannot read. Rather than loosening it for everyone, give read access to one
dedicated group and give that group only to the Grafana container:

```bash
# A group that exists only to read the database.
sudo groupadd --system honeypot-db

# The directory belongs to the service user as before, but its group is the new one,
# setgid so every file the daemon creates inherits it. 2750 = owner rwx, group r-x.
sudo chgrp honeypot-db /opt/honeypot-mcp/data
sudo chmod 2750 /opt/honeypot-mcp/data

# Files the daemon creates from now on should be group-readable (0640), not 0600.
sudo mkdir -p /etc/systemd/system/honeypot-mcp.service.d
sudo cp deploy/grafana-readable.conf /etc/systemd/system/honeypot-mcp.service.d/
sudo systemctl daemon-reload && sudo systemctl restart honeypot-mcp
# Existing database files keep their old mode; fix them once:
sudo chgrp honeypot-db /opt/honeypot-mcp/data/honeypot_mcp.db*
sudo chmod 0640 /opt/honeypot-mcp/data/honeypot_mcp.db*

cd /opt/honeypot-mcp/docker
export GRAFANA_ADMIN_PASSWORD="$(openssl rand -hex 16)"   # required, no default — keep it
HONEYPOT_DB_GID="$(getent group honeypot-db | cut -d: -f3)" \
HONEYPOT_DB_DIR=/opt/honeypot-mcp/data \
  docker compose -f docker-compose.observability.yml up -d
```

`HONEYPOT_DB_GID` is required and gives Grafana that one supplementary group. If
you skip the dashboards entirely, skip all of this: the unit's `UMask=0077` and the
`0700` directory stay as they are.

This starts Prometheus + Grafana pointed at the daemon's SQLite DB and
`/metrics` endpoint (both read-only). `HONEYPOT_DB_DIR` is required and must be
a directory holding only the database — never the repo root, which contains
`.env` and `tls/` keys. Grafana binds `127.0.0.1:3000`, with anonymous access
off; tunnel `-L 3000:127.0.0.1:3000` and log in as `admin`. Its SQLite
datasource can read the whole database (captured credentials, honeytoken
values), so never publish it. For Prometheus (in a container) to scrape the
host daemon, set `METRICS_HOST` to the Docker bridge gateway (e.g.
`172.17.0.1`) rather than `0.0.0.0`. Dashboards: Overview, Threat Map, MITRE
Coverage.

### 10. Pre-flight, then go live

Run the checks before you open the firewall to the world. They take seconds and find the
mistakes that are cheap now and expensive once traffic arrives:

```bash
# harden-host.sh finalize prints this command with the right ports for your layout.
scripts/preflight.sh \
  --ports 80,3389,110,22 --listen-ports 1110,3389,8080,22 --admin-port 2200 \
  --metrics-url http://127.0.0.1:19090 \
  --mcp-url http://127.0.0.1:18443/mcp --token "$OPERATOR_TOKEN" \
  --backup-dir /var/backups/honeypot
```

Run it as root on the VPS: the host checks read the firewall and the effective sshd
configuration, and probe the Docker guard as the service user. It checks the control plane (a
token, and a strong one), that the console and metrics are bound to loopback, `.env`
permissions, a persistent database, free disk against `MIN_FREE_DISK_MB` (plus the
packet-capture ring), Docker, that every port you plan to use is free, and that the port you
are SSH'd in on is not one a honeypot is about to take (the lock-out). **On the host** it also
checks that nothing listens on a public address except the ports you named (`--listen-ports`
is what the engines bind after the firewall's redirects; `--ports` is what the world
connects to), that the nftables firewall is loaded with a default-drop input chain, that the
service is not in the `docker` group and its Docker socket is the guard (which refuses a
daemon-wide call), that sshd is key-only and allow-listed, that the kernel hardening applied,
and that security updates are on. Against the running server it asks `/readyz`, confirms this
process owns the sensors, that each sensor answers, that a synthetic probe to **each** sensor
becomes an alert (`honeypot_self_test`), and that someone is subscribed to alerts. It exits
non-zero on any failure, so it can gate a script; `--strict` also fails on warnings. The
self-test leaves a clearly marked probe alert behind, so run it before go-live (or pass
`--no-self-test`).

Two things it will tell you that are not bugs: a port you have *already* deployed a honeypot
on shows as "in use" (the port check is for before you deploy; the "public listeners" check is
the one that covers the deployed state), and `--no-host-checks` skips the Linux checks when you
run it from a laptop.

**A sensible first estate** is small, so a surprise is easy to attribute: SSH (Cowrie), HTTP,
RDP, SMTP and POP3. `deception_plan` describes the rest.

**Before you walk away**

- [ ] Pre-flight is green (`0 failed`).
- [ ] An alert channel is subscribed at `high`, and you have seen a test message arrive.
- [ ] You know how you will notice a dead sensor without looking: alert on `/readyz` going
      non-200, on `honeypot_sensor_up == 0`, and on the `disk_space_low` / `sensor_ownership_lost`
      CRITICAL alerts.
- [ ] A backup exists (`scripts/backup.sh`) and the database is not on the volume that
      holds the packet-capture ring.
- [ ] Your own SSH access is on a port the honeypots do not use, and you have a second way in:
      the provider's **Recovery Console** (VNC, works without sshd) with a recovery password set
      for `deploy` (see "Getting back in" below). The browser Droplet Console is **not** a way in
      once the host is hardened.

**During the run: do not tune.** If something looks wrong, write it down and keep collecting.
A changed configuration halfway through makes the data uninterpretable, and a honeypot that is
reconfigured after the first contact teaches the scanners something.

**After 24 hours**

```
> soc_brief                      # what needs a human, separated from background radiation
> deception_coverage             # what the estate could and could not have caught
> fingerprint_clusters           # many addresses, one toolkit?
> alerts_recent severity=critical
> generate_report format=markdown
```

Then look for what real traffic did that the synthetic traffic did not: protocol quirks a
scanner tripped on, event volumes, false CRITICALs. That is where the next round of fixes
comes from.

### 11. Wait

You'll see your first Mirai-family scanner usually within 5–10 minutes.
Within an hour you'll have dozens of failed SSH logins. Within 24 hours
you'll have a substantial dataset.

```
> alerts_recent severity=high
> analyze_attacker_journey ip=<top attacker>
> generate_report format=markdown
```

### 12. Getting your data off the droplet (and checking the run worked)

From your laptop, any time (it is read-only on the honeypots and safe mid-run):

```bash
scripts/fetch_backup.sh --host <droplet-ip> --key ~/.ssh/honeypot_deploy --dest ~/hp-backups --samples
```

It pulls a consistent backup, verifies the transfer and the database, quarantines any malware
samples, and prints a report: events per sensor, sensors that are dead or silent, outages,
top sources and credentials, honeytoken trips, and a PASS/WARN/FAIL verdict. A sensor with no
events early on is a warning, not a failure (some protocols are scanned rarely); *every* sensor
silent means suspect the network path. Details, the `--delete-remote` and `--expect-types`
options, and what is and is not in a backup: [HARDENING.md](HARDENING.md#end-of-the-run). Turning
the droplet off does not save the data: copy it off first, then destroy the droplet.

---

## Home lab deploy

For testing the pipeline without a public IP. Two options:

### Option A — Cloudflare Tunnel for canary callbacks only

You don't need to expose your honeypots to the internet to test the system.
Run them locally and just expose the canary callback so file/URL tokens can
fire from anywhere.

```bash
# Install cloudflared from cloudflare.com/products/tunnel/
cloudflared tunnel --url http://localhost:8888
```

Cloudflare prints a URL like `https://random-words.trycloudflare.com`.
Set `CANARY_PUBLIC_URL` to that. Canary tokens planted in documents will
phone home to that URL from anywhere on the internet.

### Option B — ngrok TCP for SSH brute-force collection

This exposes your local SSH honeypot to the internet via ngrok, which lets
you collect real attack traffic without a VPS. Note: ngrok's free tier
gives a different hostname every time it restarts, so you can't use this
for long-running collection.

```bash
ngrok tcp 22
```

Note the public address ngrok prints — that's where attackers (will, very
quickly) find your honeypot.

---

## Ongoing operations

### Daily

- Glance at the alert stream / dashboard
- Acknowledge / dismiss low-severity noise
- Check `alert_subscriptions_list` for any subscriptions that have started
  failing — usually a stale Slack webhook

### Weekly

- `alerts_prune older_than_days=30` (or whatever retention you want)
- Update suppression rules for newly-discovered scanner traffic that doesn't
  add signal (Censys, internal vuln scanners, your own monitoring)
- Pull the repo, redeploy if there are updates

### Monthly

- Rotate the canary callback URL if you've shared it widely (so old
  attackers can't keep hammering it)
- Rebuild the host from scratch — assume drift / compromise over time
- Export attack data: `export_stix` + `export_blocklist` for upstream
  threat-intel feeds

### Updating the deployment

```bash
cd /opt/honeypot-mcp
git pull
uv sync --extra dev
sudo systemctl restart honeypot-mcp        # reconcile re-establishes honeypots
# If you run the Grafana stack too:
cd docker && docker compose -f docker-compose.observability.yml pull \
  && docker compose -f docker-compose.observability.yml up -d
```

Schema migrations are idempotent — Alembic upgrades on next server start, and
the `reconcile` step brings the running honeypots back after the restart.
If migrations fail, the server falls back to `create_all` (logged but
non-fatal).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| No events after 30 minutes | Firewall not open or port blocked upstream by provider | Test from your laptop: `nc -zv <your-ip> 22` |
| `honeypot_self_test` returns `alert_received: False` | Engine is up but alert pipeline is broken | Check suppression rules; check DB connectivity; check the buffer flusher is running (it's a single asyncio task — usually fine) |
| Canary URLs never fire | `CANARY_PUBLIC_URL` wrong or port 8888 not reachable | Test: `curl http://<canary-url>/t/test` — should return 200 OK |
| Cowrie not catching anything but port is open | Cowrie image not pulled, or the container died | `docker logs honeypot-<name>` (the SSH engine names containers `honeypot-<honeypot-name>`); `honeypot_health <name>` |
| Webhook deliveries failing | Stale Slack/Discord URL, or HMAC mismatch on consumer side | `alert_subscriptions_list` shows `last_error` |
| Out of disk space | Alert payloads accumulating | Run `alerts_prune` more aggressively, or set up a cron job |
| Host SSH down (locked out) | The admin port was changed by hand, or the firewall blocks you | The browser **Droplet Console does not work** once hardened (it logs in as root). Use the **Recovery Console** with the `deploy` recovery password; see "Getting back in" below |
| Client can't connect / tools don't appear | Daemon not running, tunnel down, or wrong/missing bearer token (401) | `systemctl status honeypot-mcp`; re-open `ssh -p 2200 -L 18443:127.0.0.1:18443 …`; confirm the `Authorization: Bearer` header matches a token in `MCP_AUTH_TOKENS`. A `viewer` token cannot see the deploy tools |
| Daemon exits immediately on start with an auth message | `MCP_TRANSPORT=http` but `MCP_AUTH_TOKEN` is unset (fail-closed) | Set `MCP_AUTH_TOKEN` (`openssl rand -hex 32`), or `MCP_ALLOW_UNAUTHENTICATED=true` if you front it with your own auth |
| SSH honeypots won't deploy (`403 ... honeypot docker guard`) | The Docker guard refused the request, or is not running. The service is deliberately **not** in the `docker` group; do not add it | `systemctl status honeypot-docker-guard`; `journalctl -u honeypot-docker-guard -n 30` names the refused rule |
| Daemon won't start / crashes on boot | Config or DB error | `journalctl -u honeypot-mcp -e` — the last lines show the traceback |
| Honeypots vanished after a reboot | Expected — they're re-established on daemon start | `reconcile` runs on startup; confirm with `honeypot_list`. If any show ERROR, check `journalctl` |
| Need to read Prometheus metrics from another host | Metrics are bound to loopback (19090) for security | SSH-tunnel it: `ssh -p 2200 -L 19090:127.0.0.1:19090 deploy@<vps>` |
| Service dies with `status=203/EXEC ... Permission denied` | The venv's Python is under `/root/.local/share/uv/python`, which the service user cannot execute | `rm -rf .venv && UV_PYTHON_INSTALL_DIR=/opt/uv-python uv sync --frozen --no-dev --python 3.12` (`harden-host.sh prepare` checks this) |
| `finalize` says sshd is not listening on 2200 | sshd re-binds a moment after the reload, or the new config was rejected | It waits and, if sshd never comes up, restores port 22 for you. Check `journalctl -u ssh` and `sshd -t` |
| Locked out after `finalize` | The firewall rules block your address | Do nothing: the rollback timer removes the firewall after `--rollback-seconds`. If you already ran `confirm`, see "Getting back in" below |

### Getting back in

Hardening disables root login and password logins over SSH, so DigitalOcean's browser **Droplet
Console** (which connects over the network as root with keys its agent fetches) fails with "all
authentication methods failed". That is expected and not something to fix by loosening sshd. Two
real ways back in if your SSH key or port stops working:

1. **The rollback timer** undoes a bad firewall within `--rollback-seconds` of `finalize` (unless
   you ran `confirm`). It does not undo a wrong SSH port.
2. **The Recovery Console** (Droplet page -> Access -> Recovery Console): a VNC session, like a
   keyboard and monitor on the machine, available even if sshd or the network is broken. It needs
   a local password, and the setup leaves every account password-less, so set one for `deploy`
   *before you need it*:

   ```bash
   openssl rand -base64 24 | tr -d '/+=\n' | cut -c1-24 > ~/.ssh/honeypot_recovery_password
   chmod 600 ~/.ssh/honeypot_recovery_password
   printf 'deploy:%s\n' "$(tr -d '\n' < ~/.ssh/honeypot_recovery_password)" \
     | ssh -p 2200 deploy@<ip> 'sudo chpasswd'
   ```

   sshd still refuses passwords (`PasswordAuthentication no`, `AuthenticationMethods publickey`),
   so the password only works at the console. From there `sudo nft delete table inet hp_fw`
   removes the firewall and `sudo systemctl restart ssh` restarts sshd. Pasting does not work in
   the Recovery Console, so keep the password typeable (the command above drops `/+=`).

If both fail, the data is the only thing worth saving: rebuild the droplet and start over.

---

## What good looks like

After 7 days on a typical $5 VPS you should expect, roughly:

- **5,000–50,000 SSH login attempts** (Mirai, Hydra, Patator, default-cred sweepers)
- **A few hundred unique attacker IPs** spread across ~20 countries
- **Dozens of unique commands** attempted — most are credential brute force,
  some try `wget`/`curl` of dropper binaries, occasional manual probes
- **HTTP**: hundreds-to-thousands of probes for `/admin`, `/.env`,
  `/.git/config`, `/wp-login.php`, common JS framework env files
- **RDP** (if enabled): often higher volume than SSH; many tools leak the
  intended username in the `Cookie: mstshash=` field

If you see substantially less, check the firewall and the self-test.

---

## Running it in production

The sections above get a sensor collecting. These are the things that decide
whether it keeps collecting, and whether you can prove what it collected.

### Health checks: liveness is not readiness

Two endpoints on the metrics port (default `9090`, localhost-only):

| Endpoint | Answers | Use for |
|---|---|---|
| `GET /healthz` | Is the process alive? | restart policy / liveness probe |
| `GET /readyz` | Is it actually *collecting*? | alerting, load-balancer readiness |

The distinction is not academic. Every in-process engine keeps accepting
connections and answering attackers whether or not the database is reachable —
the listeners never touch it. Remove the database underneath a running server
and the honeypots carry on perfectly while nothing is persisted; a liveness
probe sees a healthy process the entire time. `/readyz` runs a real query
against a real table and returns **503** when it cannot, which is the only
signal that distinguishes "running" from "collecting".

It also fails on a runaway ingest backlog. The event queue is unbounded, so a
database that cannot keep up becomes a memory problem before it becomes a
data-loss one, and `honeypot_event_queue_depth` in `/metrics` shows the trend.

**Alert on `/readyz`, not `/healthz`.** A honeypot that has silently stopped
recording is worse than one that is obviously down.

```bash
curl -s localhost:19090/readyz | jq     # 9090 outside the production profile
```

The compose stack already wires the container healthcheck to `/readyz`.

### Backups — the database is the evidence

Everything else can be rebuilt from the repo. Captured attack data cannot, and
neither can honeytoken values: a token whose secret is lost can never be
attributed if it fires later.

```bash
./scripts/backup.sh /var/backups/honeypot     # database + TLS certs + reports + .env
./scripts/restore.sh /var/backups/honeypot/honeypot-20260730T013016Z
```

Two details the script exists to get right:

- **It uses SQLite's `.backup`, never `cp`.** The server runs in WAL mode, so
  copying the `.db` file while a write is in flight produces a file that opens
  cleanly and is quietly missing recent transactions — the worst way for a
  backup to fail. Verified: a `.backup` of a 5,000-row uncheckpointed database
  restores all 5,000.
- **The backup contains secrets** — `.env`, honeytoken values, captured
  credentials. It is written mode 600 and should be stored wherever you keep
  the `.env` itself.

`restore.sh` refuses to run while the server is up. Restoring underneath a
running process leaves it holding an open handle to the replaced file: it keeps
working, keeps reporting success, and writes into a database nobody will read
again.

Schedule it:

```
0 3 * * *  cd /opt/honeypot-mcp && ./scripts/backup.sh /var/backups/honeypot
```

### Upgrades

Migrations run automatically at startup, so the procedure is:

```bash
./scripts/backup.sh /var/backups/honeypot   # 1. always, before anything
git pull                                    # 2. update (then rebuild the venv with the
sudo UV_PYTHON_INSTALL_DIR=/opt/uv-python uv sync --frozen --no-dev --python 3.12   # shared interpreter)
sudo systemctl restart honeypot-docker-guard honeypot-mcp   # 3. restart (compose stack: docker compose up -d --build)
curl -s localhost:19090/readyz              # 4. confirm it came back collecting (9090 outside the production profile)
```

Step 4 matters: a failed migration falls back to `create_all()` so the server
still starts, which means a broken upgrade can look like a successful one.
`/readyz` and the startup logs are how you tell.

### File permissions

`.env` holds the MCP bearer token, threat-intel API keys and webhook HMAC
secrets. A default umask produces mode 0644, so `cp .env.example .env` leaves
it world-readable — on a shared host that hands the control plane to any local
account, and the control plane can deploy honeypots and read every captured
credential.

```bash
chmod 600 .env
```

The server warns at startup if the mode is wrong.
