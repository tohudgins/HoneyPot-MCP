# Deployment guide

How to run HoneyPot MCP on a public-IP VPS, collect real attack traffic, get the data off the
host, and analyse it afterwards.

**Who it is for.** Someone comfortable with a Linux shell and `systemd` who wants the SSH-first
deployment the project was exercised with. [HARDENING.md](HARDENING.md) explains what the host
hardening does and what risk remains; this guide is the procedure.

**What you will have at the end.** A dedicated Ubuntu 22.04 host running the MCP server as a
sandboxed daemon, with a default-drop firewall that opens only the honeypot ports and your admin
SSH port; the control plane reachable only through an SSH tunnel; an alert channel; backups; and a
way to analyse a copy of the data offline.

**Prerequisites.**

- A disposable VPS with a public IPv4 address, root access and Ubuntu 22.04 LTS. 1 vCPU, 1 GB RAM
  and 25 GB of disk is the practical minimum; plan disk around the growth rate in
  [step 11](#step-11--leave-it-running).
- A deploy-only SSH key pair, used for nothing else.
- An MCP client that supports HTTP servers (Claude Code or Claude Desktop) on your own machine.
- Optional: a Slack/Teams/email destination for alerts, free VirusTotal and AbuseIPDB keys,
  MaxMind GeoLite2 databases.

There are two paths: the [VPS deployment](#vps-deployment) (steps 1-13, recommended for real
collection) and the [home lab](#home-lab-deployment) (pipeline testing only).

## Contents

- [Safety rules](#safety-rules)
- [VPS deployment](#vps-deployment)
  - [Step 1 — Provision the VPS](#step-1--provision-the-vps)
  - [Step 2 — Create the admin user](#step-2--create-the-admin-user)
  - [Step 3 — Install Docker and the code](#step-3--install-docker-and-the-code)
  - [Step 4 — Configure](#step-4--configure)
  - [Step 5 — Run the server as a daemon](#step-5--run-the-server-as-a-daemon)
  - [Step 6 — Load the firewall](#step-6--load-the-firewall)
  - [Step 7 — Connect your MCP client](#step-7--connect-your-mcp-client)
  - [Step 8 — Deploy honeypots and an alert channel](#step-8--deploy-honeypots-and-an-alert-channel)
  - [Step 9 — Grafana dashboards (optional)](#step-9--grafana-dashboards-optional)
  - [Step 10 — Pre-flight and go-live checklist](#step-10--pre-flight-and-go-live-checklist)
  - [Step 11 — Leave it running](#step-11--leave-it-running)
  - [Step 12 — Get the data off the host](#step-12--get-the-data-off-the-host)
  - [Step 13 — Analyse the data (analysis mode)](#step-13--analyse-the-data-analysis-mode)
- [Home lab deployment](#home-lab-deployment)
- [Ongoing operations](#ongoing-operations)
- [Troubleshooting](#troubleshooting)
- [What to expect](#what-to-expect)
- [Running it in production](#running-it-in-production): health checks, backups, upgrades, file permissions

---

## Safety rules

A honeypot on the public internet **is the target**. Treat the host as compromised by design.

- **One dedicated host per deployment.** Never run honeypots on a machine that also holds anything
  you care about: a development environment, a password manager, keys to other servers.
- **Use a deploy-only SSH key** for this host, stored on a single machine, never one you use for
  production.
- **Move the real admin SSH port off 22 before the SSH honeypot starts.** Otherwise you lock
  yourself out the moment it binds. `deploy/harden-host.sh` does this safely in two phases
  (steps 5 and 6).
- **Set up alerts before traffic arrives.** Slack, Teams and email are first-class formats:
  `alert_subscribe(url=..., format="slack", severity_threshold="high")`. Use `high` or `critical`;
  at `medium` a single scanner buries the channel. Repeats are coalesced per
  `NOTIFY_THROTTLE_SECONDS`, and CRITICAL is never held back.
- **Decide about packet capture before you need it.** `PCAP_ENABLED=true` plus
  `sudo setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)` records pcap for malware carving,
  Suricata/Zeek replay and evidence. It records only from the moment it is on. Check
  `PCAP_FILE_MB × PCAP_FILES` (default 100 MB × 10 = 1 GB) against free disk: a full disk stops
  the database and ends collection. Capture is scoped to honeypot ports, so your admin SSH is
  never recorded. Under the production systemd unit it also needs the drop-in described at the
  bottom of `deploy/honeypot-mcp.service`.

---

## VPS deployment

Architecture in one paragraph: the MCP server is the *control plane*; you talk to it in natural
language and it deploys and monitors honeypots. The in-process engines (every engine except SSH
and Telnet) run inside the server process and bind host ports directly; the SSH and Telnet engines
launch Cowrie as a Docker container. Because the honeypots live in the server process, the server
must run persistently, so on a VPS it runs as an HTTP daemon and your client connects over the
network. (Locally, Claude Desktop/Code spawn it over stdio per chat, which is fine for testing and
wrong for continuous collection.)

### Step 1 — Provision the VPS

Any provider works. Choose **Ubuntu 22.04 LTS** (the hardening scripts were exercised on it), note
the public IPv4 address, and add your deploy-only public key if the provider offers it.

### Step 2 — Create the admin user

```bash
ssh root@<vps-ip>
```

Create a non-root admin account with your deploy-only public key. Root login and password login are
about to be disabled, so do this first. (A provider's browser console logs in as root and will stop
working too; the safety nets are the rollback timer and the recovery-console password in
[Getting back in](#getting-back-in).)

```bash
adduser --disabled-password --gecos "" deploy
usermod -aG sudo deploy
echo "deploy ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/deploy && chmod 440 /etc/sudoers.d/deploy
install -d -m 700 -o deploy -g deploy /home/deploy/.ssh
echo "<your deploy-only public key>" > /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys && chmod 600 /home/deploy/.ssh/authorized_keys
```

From your own machine, confirm the key works **before** going on:

```bash
ssh -i ~/.ssh/honeypot_deploy deploy@<vps-ip>
```

Moving sshd off port 22 and disabling root and password login is done by `deploy/harden-host.sh`
in steps 5 and 6, in two phases: first sshd listens on 22 *and* 2200 until you have logged in on
2200, then it moves to 2200 only. Do not edit `sshd_config` by hand.

### Step 3 — Install Docker and the code

```bash
# Docker: the SSH/Telnet engines manage Cowrie containers through it. Ubuntu's own docker.io
# package is what the hardening was tested with; other builds were not.
sudo apt-get update && sudo apt-get install -y docker.io git

# uv builds the Python environment (step 5)
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env

git clone https://github.com/tohudgins/HoneyPot-MCP.git /opt/honeypot-mcp
cd /opt/honeypot-mcp
```

### Step 4 — Configure

> **On the VPS, skip to step 5.** It installs `deploy/env.production.example`, the hardened
> profile (loopback binds, moved ports, three role tokens, console off). This step explains every
> setting, for a laptop or for changing the profile.

```bash
cp .env.example .env
```

Settings that matter for a daemon:

```bash
# Run as a persistent HTTP daemon so honeypots survive across chats.
MCP_TRANSPORT=http
MCP_HOST=127.0.0.1        # loopback only; reach it over the SSH tunnel (step 7)
MCP_PORT=8000
# Required for http/sse: the daemon refuses to start without it. Clients send it as
# `Authorization: Bearer <token>`. Generate with `openssl rand -hex 32`.
MCP_AUTH_TOKEN=<token>    # minimum 16 characters; 64 hex recommended

# The production systemd unit can write only data/, reports/, tls/ and pcap/, so the SQLite
# database must live under data/:
DATABASE_URL=sqlite+aiosqlite:///./data/honeypot_mcp.db
```

**Scoped tokens instead of one shared token.** `MCP_AUTH_TOKENS` takes priority over
`MCP_AUTH_TOKEN`. Format `token:role,token:role`, where role is one of:

| Role | Can |
|---|---|
| `viewer` | Read-only triage and analysis |
| `operator` | Also deploy/stop honeypots, manage honeytokens, acknowledge alerts: everything reversible and contained to this system's own data |
| `admin` | Also prune alerts, manage subscriptions, read the audit log, manage API keys, back up the database |

`src/honeypot_mcp/rbac.py` lists exactly which tool needs which role. Example:
`MCP_AUTH_TOKENS=<viewer-token>:viewer,<operator-token>:operator,<admin-token>:admin`.

**Teams.** Treat the static tokens as a break-glass bootstrap credential. Once the server is up,
use the admin token to mint per-person keys that can be issued and revoked live, without a restart,
and that carry a name so `audit_log_search` records who did what:

```text
> create an operator API key for alice     (api_key_create: the plaintext token is shown ONCE)
> revoke alice's API key                   (api_key_revoke: takes effect within ~30 s)
> list active API keys                     (api_key_list)
```

**Canary URLs.** The callback server (`CANARY_CALLBACK_PORT`) binds loopback and the firewall
closes it, so nothing is exposed by default. If an HTTP honeypot answers on port 80, point the
public URL at it instead: it serves `/t/<token>` itself (unknown ids are an ordinary 404), so a
canary URL embedded in a decoy can call back from the internet with no new open port.

```bash
CANARY_PUBLIC_URL=http://<vps-ip>
```

Create tokens **after** setting this and restarting, because the URL is baked into each token:

```text
> create a canary URL token labelled env-canary          (honeytoken_create, canary_url)
> generate one mysql credential labelled env-mysql       (honeytoken_create, credential)
```

The HTTP honeypot then serves the credential as the database login, and the canary URL as an
error-reporting webhook, in `/.env`, `/config.json` and `/wp-config.php`. A scanner that replays
the login against your MySQL honeypot, or follows the URL, trips a CRITICAL alert. A revoked token
stops being served within 30 seconds. Cloud keys in the decoys stay random on purpose.

**Threat intelligence** (optional, off unless a key is set; leave empty otherwise, because any
non-empty placeholder counts as a key):

```bash
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
# Extra providers: GREYNOISE_API_KEY=  ABUSECH_AUTH_KEY=  OTX_API_KEY=  SHODAN_INTERNETDB_ENABLED=true
GEOIP_DB_PATH=config/GeoLite2-City.mmdb
GEOIP_ASN_DB_PATH=config/GeoLite2-ASN.mmdb
```

For geographic and network data in alerts, register at
[maxmind.com](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) and download
`GeoLite2-City.mmdb` (country, city, coordinates; feeds the threat map) and `GeoLite2-ASN.mmdb`
(origin AS number and organisation; the best pivot for spotting hosting, VPN and botnet networks).
Place both under `config/`. Each is independently optional. MaxMind's license forbids
redistribution, so neither is in the repository.

> **Secure the control-plane port.** `MCP_PORT` can deploy honeypots and read all captured data.
> It is bearer-token authenticated, but treat the token as defence in depth: keep
> `MCP_HOST=127.0.0.1`, let the firewall make the port unreachable from outside, and reach it over
> an SSH tunnel (step 7). The production profile moves it from 8000 to 18443; that only keeps a
> stray `localhost:8000` from being this server. The protection is the loopback bind, the firewall
> and the tokens. If several people need access, put a TLS reverse proxy (Caddy or nginx) in
> front on 443 instead of binding to `0.0.0.0`: over plain HTTP the token travels in clear text.

### Step 5 — Run the server as a daemon

This step and the next are scripted and explained in [HARDENING.md](HARDENING.md). The service runs
as its own unprivileged user in a systemd sandbox, is **not** in the `docker` group (it reaches
Docker only through a validating guard process), and listens only on loopback.

```bash
cd /opt/honeypot-mcp

# 1. Build the venv with an interpreter the service user can execute. A plain `uv sync` as root
#    puts Python under /root/.local/share/uv/python, which the service cannot reach (the unit
#    fails with "Permission denied").
sudo rm -rf .venv
sudo UV_PYTHON_INSTALL_DIR=/opt/uv-python uv sync --frozen --no-dev --python 3.12

# 2. Users, sshd (listening on 22 AND 2200 for now), kernel hardening, Docker daemon settings,
#    unattended security updates, systemd units. Touches no firewall rule.
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

The unit is sandboxed: `ProtectSystem=strict`, no capabilities, a syscall deny-list,
`ProtectProc=invisible`, `MemoryMax=1G`, `TasksMax=512`, and IP/Unix/netlink sockets only. Tune
`MemoryMax` to the machine. Honeypot ports below 1024 are not bound directly (the unit has no
`CAP_NET_BIND_SERVICE`): deploy those engines on a high port and let the firewall redirect
(`80>8080`, step 6). The SSH and Telnet honeypots are Docker containers whose published ports
(22, 23) Docker forwards itself.

> **Why the guard.** Membership of the `docker` group is root-equivalent: anyone who can talk to
> the daemon can start a privileged container that mounts `/`. This service parses
> attacker-controlled bytes all day, so a bug in it must not reach that. The guard
> (`honeypot-docker-guard.service`, `src/honeypot_mcp/hardening/docker_guard.py`) forwards only the
> Cowrie container operations the SSH engine makes, from the pinned image with the engine's own
> security settings, and refuses everything else with 403: no privileged containers, no host
> mounts, no exec, no other images.

The daemon serves the MCP endpoint at `http://127.0.0.1:18443/mcp` and Prometheus `/metrics` on
`127.0.0.1:19090`; the console is disabled and the canary callback server is loopback-only.

### Step 6 — Load the firewall

Open **only the honeypot ports and your admin SSH port**. Nothing else is reachable: not the
control plane, not metrics, not a service installed later. The honeypot ports are open to the whole
internet with no rate limit, geo-block or ban, because they exist to be attacked. The admin SSH
port is rate-limited per source and can be restricted to your own address.

```bash
# Moves sshd to 2200 ONLY (port 22 becomes the SSH honeypot), loads the nftables firewall, and
# arms a rollback timer: if you cannot log in afterwards, do nothing and it removes itself.
sudo deploy/harden-host.sh finalize --admin-user deploy --confirm-admin-port-tested \
    --ports "80>8080,3389,110>1110" --docker-ports 22,23
#    -> from a NEW terminal confirm you can still log in:  ssh -p 2200 deploy@<vps-ip>
sudo deploy/harden-host.sh confirm      # persists the firewall and the guard across reboots
```

`--ports "80>8080,3389,110>1110"` means: the world connects to 80 and the HTTP engine listens on
8080; RDP listens on 3389; POP3 is reached on 110 and listens on 1110. Deploy each engine on its
*listening* port in step 8. Add `--admin-allow <your-ip>/32` to let only your own address reach
admin SSH, and `--egress limited --dns <resolver>` to let Cowrie fetch malware samples (see
[HARDENING.md](HARDENING.md#malware-sample-capture-optional)).

**FTP.** If you deploy the FTP honeypot, also pass `--ftp-pasv-ports 30000-30049` and set
`FTP_PASV_PORT_MIN=30000` and `FTP_PASV_PORT_MAX=30049` in `.env`. FTP moves files over a second
connection to a port the server names; without an opened range that connection is dropped, so a
real client logs in and then every `LIST`, `RETR` and `STOR` times out. Nothing listens in the
range except during a session.

**NFS.** If you deploy the NFS honeypot, run it on an internal port and redirect both NFS ports to
it: `--ports "...,2049>12049,111>12049"`, and deploy `nfs` on **12049**. NFS clients (`showmount`,
nmap's `nfs-*` and `rpcinfo` scripts) ask the portmapper on 111 where mountd is before they touch
2049, so with only 2049 open the sensor's headline detection (`nfs_export_enumeration`) cannot
fire. The engine answers the portmapper in versions 2, 3 and 4 and always points clients back at
2049. TCP only: a client that insists on UDP (macOS `showmount`) is not served.

> **ufw does not protect Docker-published ports**, which is one reason this uses nftables
> directly: published ports are forwarded, not input, so the firewall's `forward` chain is where a
> container's outbound connections are refused (a hijacked Cowrie cannot scan, relay or reach the
> cloud metadata service).

### Step 7 — Connect your MCP client

From your own machine, tunnel the control port so you can drive the daemon without exposing it:

```bash
ssh -i ~/.ssh/honeypot_deploy -p 2200 -N -L 18443:127.0.0.1:18443 deploy@<vps-ip> &
```

Register the daemon with Claude Code as a networked MCP server with a bearer token. **Use the
`viewer` token for reading** and `operator` only while you deploy:

```bash
claude mcp add --transport http honeypot-mcp http://127.0.0.1:18443/mcp \
  --header "Authorization: Bearer <your-viewer-or-operator-token>"
```

For Claude Desktop, add an `mcpServers` entry with `"url": "http://127.0.0.1:18443/mcp"` and
`"headers": {"Authorization": "Bearer <token>"}`: a URL, not a spawn command. Without a valid
token the server answers `401`. A `viewer` session cannot even see the deploy tools. Every deploy
lands in the daemon on the VPS and keeps running after you disconnect. The admin port allows 6 new
SSH connections a minute per address; one long-lived tunnel is one connection.

### Step 8 — Deploy honeypots and an alert channel

Connect with the `operator` token. Deploy on the ports the engines **listen** on (the firewall maps
the public ports to them, step 6):

```text
> Deploy an SSH honeypot on port 22.            (Cowrie in Docker; Docker publishes 22)
> Deploy an HTTP honeypot on port 8080.         (the world reaches it on 80)
> Deploy an RDP honeypot on port 3389.
> Deploy a POP3 honeypot on port 1110.          (the world reaches it on 110)
> alert_subscribe url=https://hooks.slack.com/services/... severity_threshold=high
> honeypot_self_test <name>                     (confirm the pipeline end to end)
```

`honeypot_self_test` sends a synthetic probe and confirms it lands as an alert within about a
second (`alert_received: True`). Because the daemon is persistent, the honeypots keep collecting
after your chat and tunnel close.

Leave the SMTP and DNS honeypots out of a first deployment on a cloud provider: to an automated
relay or resolver check they look like an open relay or open resolver, which several providers'
acceptable-use policies prohibit (nothing is ever relayed or resolved, but the check cannot tell).
When you are done deploying, switch the client to the `viewer` token.

### Step 9 — Grafana dashboards (optional)

The data directory is private (`0700`), which Grafana (a container, uid 472) cannot read. Rather
than loosening it for everyone, give read access to one dedicated group and give that group only to
the Grafana container. If you skip the dashboards, skip all of this.

```bash
# A group that exists only to read the database.
sudo groupadd --system honeypot-db

# The directory stays owned by the service user, but its group is the new one, setgid so every
# file the daemon creates inherits it. 2750 = owner rwx, group r-x.
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
export GRAFANA_ADMIN_PASSWORD="$(openssl rand -hex 16)"   # required, no default: keep it
HONEYPOT_DB_GID="$(getent group honeypot-db | cut -d: -f3)" \
HONEYPOT_DB_DIR=/opt/honeypot-mcp/data \
  docker compose -f docker-compose.observability.yml up -d
```

`HONEYPOT_DB_GID` gives Grafana that one supplementary group. `HONEYPOT_DB_DIR` is required and
must be a directory holding only the database, never the repository root, which contains `.env`
and `tls/` keys.

This starts Prometheus and Grafana against the daemon's SQLite database and `/metrics` endpoint
(both read-only). Grafana binds `127.0.0.1:3000` with anonymous access off; tunnel
`-L 3000:127.0.0.1:3000` and log in as `admin`. Its SQLite datasource can read the whole database
(captured credentials, honeytoken values), so never publish it. For Prometheus (in a container) to
scrape the host daemon, set `METRICS_HOST` to the Docker bridge gateway (for example `172.17.0.1`),
not `0.0.0.0`. Dashboards: Overview, Threat Map, MITRE Coverage, Query (a read-only SQL box; see
step 13) and Alerts (a filterable alert browser).

### Step 10 — Pre-flight and go-live checklist

Run the checks before you walk away. They take seconds and find the mistakes that are cheap now and
expensive once traffic arrives:

```bash
# `deploy/harden-host.sh status` prints this command with the right ports for your layout.
scripts/preflight.sh \
  --ports 80,3389,110,22 --listen-ports 1110,3389,8080,22 --admin-port 2200 \
  --metrics-url http://127.0.0.1:19090 \
  --mcp-url http://127.0.0.1:18443/mcp --token "$OPERATOR_TOKEN" \
  --backup-dir /var/backups/honeypot
```

Run it as root on the VPS: the host checks read the firewall and the effective sshd configuration,
and probe the Docker guard as the service user. `--ports` is what the world connects to;
`--listen-ports` is what the engines bind after the firewall's redirects. It checks:

- **Configuration:** a strong control-plane token; console and metrics bound to loopback; `.env`
  permissions; a persistent database; free disk against `MIN_FREE_DISK_MB` (plus the packet-capture
  ring); Docker; that every planned port is free and that the port you are SSH'd in on is not one a
  honeypot is about to take.
- **Host:** nothing listens on a public address except the ports you named; the nftables firewall
  is loaded with a default-drop input chain; the service is not in the `docker` group and its
  Docker socket is the guard; sshd is key-only and allow-listed; kernel hardening and security
  updates are on.
- **Running server:** `/readyz`; that this process owns the sensors; that each sensor answers; that
  a synthetic probe to **each** sensor becomes an alert (`honeypot_self_test`); that someone is
  subscribed to alerts.

It exits non-zero on any failure, so it can gate a script; `--strict` also fails on warnings. The
self-test leaves a clearly marked probe alert behind, so run it before go-live or pass
`--no-self-test`. Two results that are not bugs: a port you have *already* deployed shows as "in
use" (the "public listeners" check covers the deployed state), and `--no-host-checks` skips the
Linux checks when you run it from a laptop.

**A sensible first estate** is small, so a surprise is easy to attribute: SSH (Cowrie), HTTP, RDP
and POP3 (SMTP only where your provider allows it). `deception_plan` describes the rest.

**Go-live checklist**

- [ ] Pre-flight is green (`0 failed`).
- [ ] An alert channel is subscribed at `high` and you have seen a test message arrive.
- [ ] You know how you will notice a dead sensor without looking: alert on `/readyz` going non-200,
      on `honeypot_sensor_up == 0`, and on the `disk_space_low` / `sensor_ownership_lost` CRITICAL
      alerts.
- [ ] A backup exists (`scripts/backup.sh`) and the database is not on the volume that holds the
      packet-capture ring.
- [ ] Your own SSH access is on a port the honeypots do not use, and you have a second way in: the
      provider's recovery console with a recovery password set for `deploy` (see
      [Getting back in](#getting-back-in)). A browser console that logs in as root is not a way in
      once the host is hardened.

**During the run, do not tune.** If something looks wrong, write it down and keep collecting. A
configuration changed halfway through makes the data hard to interpret, and a honeypot reconfigured
after first contact teaches scanners something.

**After 24 hours**

```text
> soc_brief                      (what needs a human, separated from background noise)
> deception_coverage             (what the estate could and could not have caught)
> fingerprint_clusters           (many addresses, one toolkit?)
> alerts_recent severity=critical
> generate_report format=markdown
```

Then compare against what synthetic traffic did not exercise: protocol quirks a scanner tripped
on, event volumes, false CRITICALs.

### Step 11 — Leave it running

On any public IP the first scanners usually arrive within minutes, and a substantial dataset builds
over the first day.

```text
> alerts_recent severity=high
> analyze_attacker_journey ip=<top attacker>
> generate_report format=markdown
```

**Unattended runs: watch the disk.** Under heavy scanning the database grew by several GB a day
(one source can be most of the traffic), so a typical VPS disk is a runway of days to a couple of
weeks, not an open-ended deployment.

- Set `MIN_FREE_DISK_MB` to about two days of growth (for example `10000`). Below it the watchdog
  raises a CRITICAL `disk_space_low` alert; the default `500` only fires when a full disk has
  already stopped collection.
- Copy the data off (step 12) regularly, at least every ten days at that growth rate, and after
  the first night: a suspended account would otherwise take the data with it.
- A sensor that fails one health probe and recovers is logged, not paged; three recoveries in an
  hour raise one HIGH `honeypot_unstable` alert.

### Step 12 — Get the data off the host

Run this from your own machine, at any time. It is read-only on the honeypots and safe mid-run:

```bash
scripts/fetch_backup.sh --host <vps-ip> --key ~/.ssh/honeypot_deploy --dest ./backups --samples
```

It takes a consistent backup, verifies the transfer and the database, quarantines malware samples,
and prints a report: events per sensor, dead or silent sensors, outages, top sources and
credentials, honeytoken trips, and a PASS/WARN/FAIL verdict. A sensor with no events early on is a
warning, not a failure (some protocols are scanned rarely); *every* sensor silent means suspect the
network path. Options (`--delete-remote`, `--expect-types`, what is and is not in a backup) are in
[HARDENING.md](HARDENING.md#end-of-the-run) and `scripts/fetch_backup.sh --help`. Powering the VPS
off does not save the data: copy it off first, then destroy the VPS.

### Step 13 — Analyse the data (analysis mode)

The server can open a backup without running any sensor. Set `ANALYSIS_MODE=true` and point
`DATABASE_URL` at a **copy** of the database. Without it, a restored database lists every sensor as
RUNNING and the server would try to launch all of them on your machine (ports, Docker). In this
mode nothing is started: no honeypots, packet capture, canary, watchdog, notifications or
retention, and sensor-changing tools say they are unavailable. Alerts, ATT&CK mapping, campaigns,
triage, reports and exports work normally. Opening a database also upgrades its schema, so always
work on a copy:

```bash
B=$(ls -dt ./backups/honeypot-* | head -1)
mkdir -p analysis && cp -c "$B/honeypot_mcp.db" analysis/   # macOS clone; Linux: cp --reflink=auto
claude mcp add honeypot-analysis \
  -e ANALYSIS_MODE=true -e MCP_TRANSPORT=stdio -e REPORTS_DIR="$PWD/analysis/reports" \
  -e DATABASE_URL="sqlite+aiosqlite:///$PWD/analysis/honeypot_mcp.db" \
  -- /path/to/HoneyPot-MCP/.venv/bin/python -m honeypot_mcp.server
```

In analysis mode every `since_hours` window ends at the newest alert in the database, not at the current time, so "the last 12 hours" of a week-old backup describes the end of the run instead of coming back empty; results say so (`window_anchor`). Enrichment keys come from the environment or the `.env` in the server's working directory, as on a live server; a missing one makes `enrich_ip` or `lookup_hash` report `available: false` for that provider (add `-e ABUSECH_AUTH_KEY=...` to the `claude mcp add` command, for example).

| To answer | Tool |
|---|---|
| What happened, what needs triage | `soc_brief`, `alerts_stats`, `alerts_recent`, `alerts_search` |
| Which ATT&CK techniques | `attack_summary` (whole run, by tactic, exact counts; or with an IP, event types or text, what that behaviour maps to), `deception_coverage` |
| Who is this attacker, what did they do in order | `analyze_attacker`, `analyze_attacker_journey`, `analyze_session` |
| Which sources act together | `analyze_campaign` (ranked by a documented score, behavioural campaigns before connection sweeps, recurring windows of one botnet merged into one entry), `fingerprint_clusters` (SSH client fingerprints) |
| Record a verdict | `alerts_acknowledge` (a source, an event type or ids; sets true/false positive) |
| Hand it on | `generate_report` (markdown, html or attack_navigator), `export_indicators` (blocklist or STIX), `alerts_export` |
| A question no tool anticipated | `sql_query`: one read-only `SELECT` over `alerts`, `alert_rollups`, `honeypots` (secret tables refused; at most 1,000 rows and `SQL_QUERY_TIMEOUT_SECONDS`, default 15, up to 300). Prefer `alert_rollups` for anything over the whole run. Grafana's **Query** dashboard takes SQL in its `sql` box. |
| What attackers did, without SQL | `attack_patterns` with `kind` = `credentials`, `commands`, `files`, `clients`, `sip_dialling`, `http` or `concentration` (top logins, command shapes, dropped files, SSH client families, dial-prefix cycling, how concentrated the volume is) |
| Who used a planted credential and what they did first | `bait_trips` |
| What is in a packet capture | `pcap_analyze` (extracts in `REPORTS_DIR`; protocol and conversation digest, SIP/HTTP/DNS/SSH/TLS decoding, credentials), `pcap_files`; `pcap_detect` replays it through Suricata or Zeek in a sandbox container (run `detection_rules_update` first for the Suricata ruleset) |
| What captured files contain | `sample_collect` (live server: copies downloads and terminal recordings out of the sensor containers into the quarantine), `sample_scan` (hash, type, YARA, capture context; needs `pip install -e ".[forensics]"`) |
| The whole post-run workflow in one call | `run_analysis` (headline, ATT&CK table, busiest sources, campaigns, clusters, exports, `analysis-summary.md`) |
| Dashboards on this database | `grafana_start` (loopback only, read-only datasource; the admin password goes to a file whose path is returned), `grafana_status`, `grafana_stop` |
| A verified copy of the database | `database_backup` (online backup, integrity check, manifest, inside `BACKUP_DIR`; SQLite only) |

Statistics read pre-aggregated rollups rather than the alerts table, so on a database with millions
of alerts opening takes seconds and these calls return in about that time. Event types that are
connection or session bookkeeping are deliberately not mapped to a technique, so the ATT&CK numbers
count behaviour, not connections.

For a first pass without a chat, one command does the lot:

```bash
scripts/analyze_backup.py ./backups/honeypot-<timestamp> --top 5 --hours 168 --workdir ./analysis
```

It works on a copy, runs the server in analysis mode over real MCP stdio, and writes
`analysis/reports/analysis-summary.md` (headline numbers, the ATT&CK table by tactic, the busiest
sources' journeys, campaigns and clusters) next to the HTML/Markdown reports, the STIX bundle and
the blocklist. Triage and follow-up questions then go to the MCP client above. The script is a thin
client: the work is the `run_analysis` tool, so asking your MCP client to "analyse this run" does the
same thing without the script.

---

## Home lab deployment

For testing the pipeline without a public IP.

### Option A — Cloudflare Tunnel for canary callbacks only

You do not need to expose honeypots to the internet to test the system. Run them locally and expose
only the canary callback so file and URL tokens can fire from anywhere:

```bash
# Install cloudflared from https://www.cloudflare.com/products/tunnel/
cloudflared tunnel --url http://localhost:8888
```

Cloudflare prints a URL like `https://random-words.trycloudflare.com`. Set `CANARY_PUBLIC_URL` to
it; canary tokens planted in documents then phone home to it from anywhere.

### Option B — ngrok TCP for SSH collection

This exposes a local SSH honeypot to the internet, which collects real attack traffic without a
VPS. ngrok's free tier gives a different hostname each restart, so this suits short tests, not
long-running collection.

```bash
ngrok tcp 22
```

The address ngrok prints is where attackers will find the honeypot.

---

## Ongoing operations

**Daily**

- Glance at the alert stream or dashboard; acknowledge or dismiss low-severity noise.
- Check `alert_subscriptions_list` for subscriptions that have started failing (usually a stale
  Slack webhook).

**Weekly**

- `alerts_prune older_than_days=30` (or your retention; it archives to JSON Lines first).
- Update suppression rules for scanner traffic that adds no signal (Censys, internal vulnerability
  scanners, your own monitoring).
- Check for repository updates and redeploy using [Upgrades](#upgrades).

**Monthly**

- Rotate the canary callback URL if you have shared it widely.
- Rebuild the host from scratch: assume drift and compromise over time.
- Export attack data (`export_indicators` with `format=stix` or a blocklist format) for upstream threat-intel feeds.

If you run the Grafana stack, update it with:

```bash
cd /opt/honeypot-mcp/docker && docker compose -f docker-compose.observability.yml pull \
  && docker compose -f docker-compose.observability.yml up -d
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| No events after 30 minutes | Firewall not open, or port blocked upstream by the provider | Test from another machine: `nc -zv <vps-ip> 22` |
| `honeypot_self_test` returns `alert_received: False` | Engine is up but the alert pipeline is not | Check suppression rules, DB connectivity, and that the buffer flusher is running |
| Canary URLs never fire | `CANARY_PUBLIC_URL` wrong, or the callback is not reachable | `curl http://<canary-url>/t/test` should return 200 OK. Under the production profile the callback is loopback-only (18888): point `CANARY_PUBLIC_URL` at an HTTP honeypot on port 80 (step 4) |
| Cowrie catches nothing but the port is open | Image not pulled, or the container died | `docker logs honeypot-<name>` (containers are named `honeypot-<honeypot-name>`); `honeypot_status <name>` |
| Webhook deliveries failing | Stale Slack/Discord URL, or HMAC mismatch on the consumer | `alert_subscriptions_list` shows `last_error` |
| Out of disk space | Alert payloads accumulating | `alerts_prune` more aggressively, or schedule it; see step 11 |
| Host SSH down (locked out) | Admin port changed by hand, or the firewall blocks you | A browser console that logs in as root does not work once hardened. Use the recovery console; see [Getting back in](#getting-back-in) |
| Client can't connect / tools don't appear | Daemon not running, tunnel down, or wrong or missing bearer token (401) | `systemctl status honeypot-mcp`; reopen the tunnel (`ssh -p 2200 -L 18443:127.0.0.1:18443 …`); check the `Authorization: Bearer` header matches a token in `MCP_AUTH_TOKENS`. A `viewer` token cannot see the deploy tools |
| Daemon exits immediately with an auth message | `MCP_TRANSPORT=http` but no token set (fail-closed) | Set `MCP_AUTH_TOKEN` (`openssl rand -hex 32`), or `MCP_ALLOW_UNAUTHENTICATED=true` if you front it with your own auth |
| SSH honeypots won't deploy (`403 ... honeypot docker guard`) | The guard refused the request, or is not running. The service is deliberately **not** in the `docker` group; do not add it | `systemctl status honeypot-docker-guard`; `journalctl -u honeypot-docker-guard -n 30` names the refused rule |
| Daemon won't start / crashes on boot | Config or DB error | `journalctl -u honeypot-mcp -e` shows the traceback |
| Honeypots vanished after a reboot | Expected: they are re-established on daemon start | `reconcile` runs on startup; confirm with `honeypot_list`; if any show ERROR, check `journalctl` |
| Need Prometheus metrics from another host | Metrics are bound to loopback (19090) | Tunnel it: `ssh -p 2200 -L 19090:127.0.0.1:19090 deploy@<vps-ip>` |
| Service dies with `status=203/EXEC ... Permission denied` | The venv's Python is under `/root/.local/share/uv/python`, which the service user cannot execute | `rm -rf .venv && UV_PYTHON_INSTALL_DIR=/opt/uv-python uv sync --frozen --no-dev --python 3.12` (`harden-host.sh prepare` checks this) |
| `finalize` says sshd is not listening on 2200 | sshd re-binds a moment after the reload, or the new config was rejected | It waits and, if sshd never comes up, restores port 22. Check `journalctl -u ssh` and `sshd -t` |
| Locked out after `finalize` | The firewall rules block your address | Do nothing: the rollback timer removes the firewall after `--rollback-seconds`. If you already ran `confirm`, see [Getting back in](#getting-back-in) |

### Getting back in

Hardening disables root login and password login over SSH, so a provider's browser console that
connects over the network as root (DigitalOcean's Droplet Console, for example) fails with "all
authentication methods failed". That is expected; do not loosen sshd to fix it. Two real ways back
in if your key or port stops working:

1. **The rollback timer** undoes a bad firewall within `--rollback-seconds` of `finalize` (unless
   you ran `confirm`). It does not undo a wrong SSH port.
2. **The provider's recovery console**: a VNC session, like a keyboard and monitor on the machine,
   available even if sshd or the network is broken (on DigitalOcean: Droplet page, Access,
   Recovery Console). It needs a local password, and the setup leaves every account password-less,
   so set one for `deploy` *before you need it*:

   ```bash
   PW="$(openssl rand -base64 24 | tr -d '/+=\n' | cut -c1-24)"
   echo "Recovery password for deploy (store it in your password manager): $PW"
   printf 'deploy:%s\n' "$PW" | ssh -p 2200 deploy@<vps-ip> 'sudo chpasswd'
   ```

   sshd still refuses passwords (`PasswordAuthentication no`, `AuthenticationMethods publickey`),
   so the password only works at the console. From there `sudo nft delete table inet hp_fw`
   removes the firewall and `sudo systemctl restart ssh` restarts sshd. Pasting does not work in
   the recovery console, so keep the password typeable (the command above drops `/+=`).

If both fail, the data is the only thing worth saving: rebuild the VPS and start over.

---

## What to expect

Volume depends heavily on the provider's address range and on which engines you deploy. On a public
IP expect, in roughly this order of volume: credential brute force against SSH, Telnet and RDP
(many RDP tools leak the intended username in the `Cookie: mstshash=` field); HTTP probes for
`/admin`, `/.env`, `/.git/config`, `/wp-login.php` and framework env files; a small number of
commands in SSH sessions, mostly reconnaissance with occasional `wget`/`curl` of dropper binaries;
and a long tail of exploit attempts. A real deployment's figures are in
[RESULTS.md](RESULTS.md). If you see almost nothing, check the firewall and the self-test.

---

## Running it in production

The sections above get a sensor collecting. These decide whether it keeps collecting, and whether
you can prove what it collected.

### Health checks: liveness is not readiness

Two endpoints on the metrics port (`METRICS_PORT`, default `9090`, `19090` in the production
profile, loopback-only):

| Endpoint | Answers | Use for |
|---|---|---|
| `GET /healthz` | Is the process alive? | restart policy, liveness probe |
| `GET /readyz` | Is it actually *collecting*? | alerting, load-balancer readiness |

The distinction matters. Every in-process engine keeps accepting connections and answering
attackers whether or not the database is reachable, because the listeners never touch it. Remove
the database underneath a running server and the honeypots carry on while nothing is persisted; a
liveness probe sees a healthy process the whole time. `/readyz` runs a real query against a real
table and returns **503** when it cannot, which is the only signal that separates "running" from
"collecting". It also fails on a runaway ingest backlog: the event queue is unbounded, so a
database that cannot keep up becomes a memory problem before it becomes a data-loss one, and
`honeypot_event_queue_depth` in `/metrics` shows the trend.

**Alert on `/readyz`, not `/healthz`.**

```bash
curl -s localhost:19090/readyz | jq     # 9090 outside the production profile
```

The compose stack wires the container healthcheck to `/readyz`.

### Backups: the database is the evidence

Everything else can be rebuilt from the repository. Captured attack data cannot, and neither can
honeytoken values: a token whose secret is lost can never be attributed if it fires later.

```bash
./scripts/backup.sh /var/backups/honeypot     # database + TLS certs + reports + .env
./scripts/restore.sh /var/backups/honeypot/honeypot-<timestamp>
```

- **It uses SQLite's `VACUUM INTO`, never `cp`.** The server runs in WAL mode, so copying the
  `.db` file while a write is in flight produces a file that opens cleanly and is quietly missing
  recent transactions. `VACUUM INTO` takes a consistent snapshot in one read transaction without
  blocking the server, and the copy is a compact rollback-mode file (no `-wal`/`-shm`). SQLite's
  `.backup` was rejected because it restarts whenever the server writes between its copy steps and,
  on a multi-GB database under constant writes, did not finish.
- **The backup contains secrets** (`.env`, honeytoken values, captured credentials). It is written
  mode 600; store it wherever you keep the `.env` itself.

`restore.sh` refuses to run while the server is up: restoring underneath a running process leaves
it holding an open handle to the replaced file, still reporting success while writing into a
database nobody will read.

Schedule it:

```text
0 3 * * *  cd /opt/honeypot-mcp && ./scripts/backup.sh /var/backups/honeypot
```

### Upgrades

Migrations run automatically at startup:

```bash
./scripts/backup.sh /var/backups/honeypot   # 1. always, before anything
git pull                                    # 2. update, then rebuild the venv:
sudo UV_PYTHON_INSTALL_DIR=/opt/uv-python uv sync --frozen --no-dev --python 3.12
sudo systemctl restart honeypot-docker-guard honeypot-mcp   # 3. restart; reconcile re-establishes the honeypots
curl -s localhost:19090/readyz              # 4. confirm it came back collecting
```

For the all-in-one compose stack, use `docker compose up -d --build` instead of step 3. Step 4
matters: a failed migration falls back to `create_all()` so the server still starts, which means a
broken upgrade can look like a successful one. `/readyz` and the startup logs are how you tell.

### File permissions

`.env` holds the MCP bearer tokens, threat-intel API keys and webhook HMAC secrets. A default umask
produces mode 0644, so `cp .env.example .env` leaves it world-readable; on a shared host that hands
the control plane to any local account, and the control plane can deploy honeypots and read every
captured credential.

```bash
chmod 600 .env                                              # laptop or single-user host
sudo chown root:honeypot .env && sudo chmod 0640 .env       # production profile (step 5)
```

The server warns at startup if the mode is too open.
