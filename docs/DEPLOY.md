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
# Docker — convenience installer is fine for a disposable honeypot host
curl -fsSL https://get.docker.com | sh

# Python + uv for running the MCP server / management tools
apt update && apt install -y python3-pip python3-venv git
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env

# Clone
git clone https://github.com/tohudgins/HoneyPot-MCP.git /opt/honeypot-mcp
cd /opt/honeypot-mcp
uv sync --extra dev
```

### 4. Configure (2 min)

```bash
cp .env.example .env
```

Open `.env` and set:

```bash
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
download `GeoLite2-City.mmdb`, and scp it to `docker/geoip/` on the VPS
(the compose file bind-mounts that directory read-only into the container).
MaxMind's license forbids redistribution, so the DB is intentionally not in
the repo.

### 5. Start the SSH honeypot via Docker Compose (1 min)

```bash
cd /opt/honeypot-mcp/docker
docker compose up -d --build
```

`--build` is required on the first run because the MCP image is built from
the local `docker/Dockerfile.mcp` — there's no published image yet.

This boots four services:

- **socket-proxy** — internal-only sidecar that exposes a restricted Docker
  API to the MCP container. The MCP server can manage Cowrie containers but
  cannot escape to root-on-host even if the MCP process is exploited.
- **honeypot-mcp** — server + canary callback (port 8888) + Prometheus
  `/metrics` (port 9090, bound to localhost only).
- **cowrie-ssh** — Cowrie SSH/Telnet honeypot.
- **http-honeypot** — HTTP honeypot.

Confirm everything is alive:

```bash
docker compose ps
```

All four services should be `Up`. The MCP container has a HEALTHCHECK; give
it ~30s on first start (DB migration runs once).

### 6. Open the firewall (1 min)

Whatever firewall your provider uses, open inbound TCP for:

- 22 (SSH honeypot)
- 23 (Telnet honeypot — optional)
- 80, 443 (HTTP/HTTPS honeypot)
- 2525 (SMTP honeypot — optional)
- 21 (FTP honeypot — optional)
- 3389 (RDP honeypot — optional, biggest traffic generator after SSH)
- 8888 (canary callbacks)
- **2200** (your admin SSH, the port you moved earlier)

Leave UDP 53 open if you want DNS honeypot traffic.

On a vanilla Ubuntu VPS with `ufw`:

```bash
ufw allow 2200/tcp comment 'admin SSH'
ufw allow 22/tcp 23/tcp 80/tcp 443/tcp 3389/tcp 8888/tcp
ufw allow 53/udp
ufw --force enable
```

### 7. Wire up an alert channel (2 min)

Don't deploy a honeypot you can't see. From your laptop (or from Claude Code
configured to talk to the MCP server), subscribe a Slack/Discord/Telegram
webhook:

```
> alert_subscribe url=https://hooks.slack.com/services/... severity_threshold=high
```

Now you'll get a notification on every HIGH+ event.

### 8. Confirm the pipeline works end-to-end

```
> honeypot_self_test
```

This sends a probe at each running honeypot and confirms it lands as an alert
in the DB within ~1 second. If `alert_received: True` for every engine,
you're done.

### 9. Wait

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
cd docker && docker compose pull && docker compose up -d
```

Schema migrations are idempotent — Alembic upgrades on next server start.
If migrations fail, the server falls back to `create_all` (logged but
non-fatal).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| No events after 30 minutes | Firewall not open or port blocked upstream by provider | Test from your laptop: `nc -zv <your-ip> 22` |
| `honeypot_self_test` returns `alert_received: False` | Engine is up but alert pipeline is broken | Check suppression rules; check DB connectivity; check the buffer flusher is running (it's a single asyncio task — usually fine) |
| Canary URLs never fire | `CANARY_PUBLIC_URL` wrong or port 8888 not reachable | Test: `curl http://<canary-url>/t/test` — should return 200 OK |
| Cowrie not catching anything but port is open | Cowrie image not pulled, or the wrong Cowrie image | `docker compose logs cowrie` |
| Webhook deliveries failing | Stale Slack/Discord URL, or HMAC mismatch on consumer side | `alert_subscriptions_list` shows `last_error` |
| Out of disk space | Alert payloads accumulating | Run `alerts_prune` more aggressively, or set up a cron job |
| Host SSH down (locked out) | You forgot to move admin SSH off 22 before starting the honeypot | Use provider web console; edit `/etc/ssh/sshd_config`; restart sshd |
| `honeypot-mcp` container can't deploy SSH honeypots dynamically | The socket-proxy sidecar is down or unreachable | `docker compose logs socket-proxy`. The MCP container talks to it on `tcp://socket-proxy:2375` over the internal `honeypot-net`. |
| MCP container HEALTHCHECK reporting unhealthy | `/metrics` is failing — usually a DB init problem on first start | `docker compose logs honeypot-mcp`. Allow 30s on cold start for Alembic to run. |
| Need to read Prometheus metrics from another host | Port 9090 is intentionally bound to `127.0.0.1` for security | SSH-tunnel it: `ssh -L 9090:127.0.0.1:9090 root@<vps>` |

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
