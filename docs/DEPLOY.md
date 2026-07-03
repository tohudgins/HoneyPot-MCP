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
- **Set up alerts before traffic arrives**, not after. Webhook a Slack or
  Discord channel so you see CRITICAL events the moment they fire.

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

### 2. First SSH — and move the admin port off 22

```bash
ssh root@<your-ip>
```

The first thing you do, before *anything* else: move the admin SSH to a
non-default port so the honeypot can bind 22 later.

```bash
# Edit the SSH server config
sed -i 's/^#\?Port .*/Port 2200/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config

# Make sure your public key is in place BEFORE restart, or you lock yourself out
# (If the provider's web console option exists, keep that tab open as a safety net)
cat ~/.ssh/authorized_keys  # confirm your key is here

systemctl restart ssh
```

From your laptop, re-connect on the new port to confirm:

```bash
ssh -p 2200 root@<your-ip>
```

If this works, you have a safe management channel. If not, use the
provider's web console to debug — do NOT close your current SSH session
until you've confirmed.

### 3. Install Docker + clone the repo (5 min)

```bash
# Docker — the SSH/Cowrie engine manages honeypot containers through it
curl -fsSL https://get.docker.com | sh

# Python + uv to run the MCP server
apt update && apt install -y python3-pip python3-venv git
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env

git clone https://github.com/tohudgins/HoneyPot-MCP.git /opt/honeypot-mcp
cd /opt/honeypot-mcp
uv sync --extra dev
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

```bash
cp .env.example .env
```

Open `.env` and set:

```bash
# Run as a persistent HTTP daemon so honeypots survive across chats.
MCP_TRANSPORT=http
MCP_HOST=0.0.0.0          # so your MCP client can reach it over the network
MCP_PORT=8000

# REQUIRED for canary tokens to fire from the internet
CANARY_PUBLIC_URL=http://<your-vps-ip>:8888

# RECOMMENDED — sign up for the free tiers, paste keys here
VIRUSTOTAL_API_KEY=...
ABUSEIPDB_API_KEY=...

# OPTIONAL — drop a GeoLite2-City.mmdb in config/ for geo enrichment
GEOIP_DB_PATH=config/GeoLite2-City.mmdb
```

If you want geographic data in alerts, register at
[maxmind.com](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data),
download `GeoLite2-City.mmdb`, and place it at `config/GeoLite2-City.mmdb`.
MaxMind's license forbids redistribution, so it's intentionally not in the repo.

> **Secure the control-plane port.** `MCP_PORT` (8000) is an authenticated-by-
> nothing management interface — anyone who can reach it can deploy honeypots.
> Do **not** open it in the firewall. Reach it from your laptop over an SSH
> tunnel instead (step 7), or bind it to `127.0.0.1` and tunnel in.

### 5. Run the server as a persistent daemon (2 min)

Install the bundled systemd unit so the control plane runs 24/7 and survives
reboots and crashes (the startup `reconcile` step re-establishes running
honeypots automatically):

```bash
# Dedicated non-login user with Docker access (for the SSH engine)
sudo useradd --system --home /opt/honeypot-mcp --shell /usr/sbin/nologin honeypot
sudo usermod -aG docker honeypot
sudo chown -R honeypot:honeypot /opt/honeypot-mcp

sudo cp deploy/honeypot-mcp.service /etc/systemd/system/
# Edit ExecStart's uv path if `which uv` differs from /usr/local/bin/uv
sudo systemctl daemon-reload
sudo systemctl enable --now honeypot-mcp
sudo systemctl status honeypot-mcp        # should be active (running)
journalctl -u honeypot-mcp -f             # live logs
```

The daemon now serves the MCP endpoint at `http://<vps-ip>:8000/mcp`, plus the
canary callback (`:8888`) and Prometheus `/metrics` (`:9090`).

### 6. Open the firewall (1 min)

Open **only the honeypot ports and the canary callback** — never the MCP
control port (8000) or metrics (9090). You choose which honeypots to run in
step 8; open the ports you plan to use:

- 22 (SSH honeypot — biggest traffic generator)
- 23 (Telnet — optional, Mirai-class volume)
- 80, 443 (HTTP/HTTPS honeypot)
- 3389 (RDP — second-biggest after SSH)
- 21 (FTP), 2525 (SMTP) — optional
- 8888 (canary callbacks)
- **2200** (your admin SSH, moved earlier)
- UDP 53 (DNS honeypot) — optional

```bash
ufw allow 2200/tcp comment 'admin SSH'
ufw allow 22/tcp 23/tcp 80/tcp 443/tcp 3389/tcp 21/tcp 2525/tcp 8888/tcp
ufw allow 53/udp
ufw --force enable
# NB: 8000 (MCP control) and 9090 (metrics) are deliberately NOT opened.
```

### 7. Connect your MCP client over an SSH tunnel (2 min)

From your laptop, tunnel the control port so you can drive the daemon without
exposing it to the internet:

```bash
ssh -p 2200 -N -L 8000:127.0.0.1:8000 honeypot@<vps-ip> &
```

Then register the daemon with Claude Code as a networked MCP server:

```bash
claude mcp add --transport http honeypot-mcp http://127.0.0.1:8000/mcp
```

(Claude Desktop: add an `mcpServers` entry with `"url":
"http://127.0.0.1:8000/mcp"` — a URL, not a spawn command.) Every deploy you
make now lands in the daemon on the VPS and keeps running after you disconnect.

### 8. Deploy honeypots and wire an alert channel (2 min)

In a chat with the connected client:

```
> Deploy an SSH honeypot on port 22.
> Deploy an HTTP honeypot on port 80.
> Deploy an RDP honeypot on port 3389.
> alert_subscribe url=https://hooks.slack.com/services/... severity_threshold=high
> honeypot_self_test <name>      # confirm the pipeline end-to-end
```

`honeypot_self_test` sends a synthetic probe and confirms it lands as an alert
within ~1s (`alert_received: True`). Because the daemon is persistent, these
honeypots keep collecting after your chat and your SSH tunnel close.

### 9. (Optional) Bring up the Grafana dashboards

```bash
cd /opt/honeypot-mcp/docker
HONEYPOT_DB_DIR=/opt/honeypot-mcp \
  docker compose -f docker-compose.observability.yml up -d
```

This starts Prometheus + Grafana pointed at the daemon's SQLite DB and
`/metrics` endpoint (both read-only). Tunnel `-L 3000:127.0.0.1:3000` to view
it; don't expose 3000 publicly. Dashboards: Overview, Threat Map, MITRE
Coverage.

### 10. Wait

You'll see your first Mirai-family scanner usually within 5–10 minutes.
Within an hour you'll have dozens of failed SSH logins. Within 24 hours
you'll have a substantial dataset.

```
> alerts_recent severity=high
> analyze_attacker_journey ip=<top attacker>
> generate_report format=markdown
```

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
| Host SSH down (locked out) | You forgot to move admin SSH off 22 before starting the honeypot | Use provider web console; edit `/etc/ssh/sshd_config`; restart sshd |
| Client can't connect / tools don't appear | Daemon not running, or the SSH tunnel to port 8000 is down | `systemctl status honeypot-mcp`; re-open `ssh -L 8000:127.0.0.1:8000 …`; confirm `MCP_TRANSPORT=http` in `.env` |
| SSH honeypots won't deploy | Daemon's user isn't in the `docker` group | `sudo usermod -aG docker honeypot` then `systemctl restart honeypot-mcp` |
| Daemon won't start / crashes on boot | Config or DB error | `journalctl -u honeypot-mcp -e` — the last lines show the traceback |
| Honeypots vanished after a reboot | Expected — they're re-established on daemon start | `reconcile` runs on startup; confirm with `honeypot_list`. If any show ERROR, check `journalctl` |
| Need to read Prometheus metrics from another host | Port 9090 is bound locally for security | SSH-tunnel it: `ssh -L 9090:127.0.0.1:9090 honeypot@<vps>` |

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
