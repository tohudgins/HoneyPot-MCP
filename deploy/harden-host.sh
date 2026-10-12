#!/usr/bin/env bash
# Harden a fresh Ubuntu/Debian VPS for a public honeypot deployment.
#
#   sudo deploy/harden-host.sh prepare  --admin-user deploy [--admin-port 2200] [options]
#   # -> from a NEW terminal confirm:  ssh -p 2200 deploy@<ip>
#   sudo deploy/harden-host.sh finalize --admin-user deploy --confirm-admin-port-tested [options]
#   # -> from a NEW terminal confirm you can still log in, then:
#   sudo deploy/harden-host.sh confirm
#   sudo deploy/harden-host.sh status
#   sudo deploy/harden-host.sh teardown --i-have-a-backup        # end of the run
#
# prepare   users, packages, sshd (listens on 22 AND the admin port, so you cannot lock yourself
#           out), kernel hardening, Docker daemon settings, unattended security updates, systemd
#           units. Touches no firewall rule and does not move sshd off 22.
# finalize  sshd moves to the admin port only (port 22 is then free for the SSH honeypot) and the
#           firewall is loaded with a dead-man's switch: unless you run `confirm` within
#           --rollback-seconds the firewall removes itself.
# confirm   cancels the rollback and persists the firewall and Docker guard across reboots.
# status    what is listening, what the firewall and sshd say, and the preflight command to run.
# teardown  stops the honeypots, removes their containers and the firewall. Back up first.
#
# Options:
#   --admin-user NAME           the account you log in as (required; must have an SSH key)
#   --admin-port N              admin SSH port (default 2200; not 22, not a honeypot port)
#   --admin-allow CIDR[,CIDR]   only these addresses may reach admin SSH (default: anyone, rate limited)
#   --ports SPEC                honeypot ports the engines listen on: "3389,80>8080,110>1110"
#                               (A>B: the world connects to A, the engine listens on B)
#   --docker-ports LIST         ports Docker publishes for Cowrie (default 22; add 23 for telnet)
#   --ftp-pasv-ports MIN-MAX    passive data ports of the FTP honeypot, e.g. 30000-30049 (also set
#                               FTP_PASV_PORT_MIN/MAX in .env). Without it every FTP session over the
#                               internet stalls after login: the data connection is dropped.
#   --egress closed|limited     closed (default): containers start no connections;
#                               limited: public web servers only, rate limited (needs --dns)
#   --dns IP[,IP]               resolver(s) the containers use (required for --egress limited)
#   --install-dir DIR           where the project is installed (default /opt/honeypot-mcp)
#   --rollback-seconds N        firewall rollback timer (default 120)
#   --dry-run                   print what would be done, change nothing
#
# Idempotent: every step can be re-run. Tested on Ubuntu 22.04 (see docs/HARDENING.md).
set -euo pipefail

INSTALL_DIR=/opt/honeypot-mcp
ADMIN_USER=""
ADMIN_PORT=2200
ADMIN_ALLOW=""
PORTS="80>8080,3389,110>1110"
DOCKER_PORTS="22"
FTP_PASV=""
EGRESS=closed
DNS=""
ROLLBACK_SECONDS=120
DRY=0
CONFIRM_ADMIN=0
HAVE_BACKUP=0
CMD="${1:-}"
[ $# -gt 0 ] && shift

SSHD_DROPIN=/etc/ssh/sshd_config.d/10-honeypot-host.conf
SYSCTL_FILE=/etc/sysctl.d/90-honeypot-host.conf
FIREWALL_FILE=/etc/honeypot/firewall.nft
ROLLBACK_UNIT=hp-fw-rollback

say() { printf '==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --admin-user) ADMIN_USER="${2:?}"; shift 2 ;;
    --admin-port) ADMIN_PORT="${2:?}"; shift 2 ;;
    --admin-allow) ADMIN_ALLOW="${2:?}"; shift 2 ;;
    --ports) PORTS="${2:?}"; shift 2 ;;
    --docker-ports) DOCKER_PORTS="${2:?}"; shift 2 ;;
    --ftp-pasv-ports) FTP_PASV="${2:?}"; shift 2 ;;
    --egress) EGRESS="${2:?}"; shift 2 ;;
    --dns) DNS="${2:?}"; shift 2 ;;
    --install-dir) INSTALL_DIR="${2:?}"; shift 2 ;;
    --rollback-seconds) ROLLBACK_SECONDS="${2:?}"; shift 2 ;;
    --confirm-admin-port-tested) CONFIRM_ADMIN=1; shift ;;
    --i-have-a-backup) HAVE_BACKUP=1; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

[ -n "$CMD" ] || { usage; exit 2; }

# Run a command, or only print it with --dry-run.
run() {
  if [ "$DRY" = 1 ]; then printf '[dry-run] %s\n' "$*"; else "$@"; fi
}

# Write stdin to $1 (mode $2) when it differs; with --dry-run show the diff instead.
write_file() {
  local path="$1" mode="${2:-0644}" tmp
  tmp="$(mktemp)"
  cat > "$tmp"
  if [ -f "$path" ] && cmp -s "$tmp" "$path"; then
    say "unchanged: $path"; rm -f "$tmp"; return 0
  fi
  if [ "$DRY" = 1 ]; then
    printf '[dry-run] would write %s (mode %s)\n' "$path" "$mode"
    diff -u "$path" "$tmp" 2>/dev/null | sed 's/^/    /' || sed 's/^/    + /' "$tmp"
    rm -f "$tmp"; return 0
  fi
  install -D -m "$mode" "$tmp" "$path"; rm -f "$tmp"; say "wrote $path"
}

need_root() { [ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || die "run as root (sudo)"; }

validate_inputs() {
  case "$ADMIN_PORT" in ''|*[!0-9]*) die "--admin-port must be a number" ;; esac
  { [ "$ADMIN_PORT" -ge 1024 ] && [ "$ADMIN_PORT" -le 65535 ]; } || die "--admin-port must be 1024-65535"
  [ "$ADMIN_PORT" != 2222 ] && [ "$ADMIN_PORT" != 2223 ] || die "--admin-port must not be a Cowrie port"
  case "$EGRESS" in closed|limited) ;; *) die "--egress must be closed or limited" ;; esac
  if [ "$EGRESS" = limited ] && [ -z "$DNS" ]; then
    # Containers inherit the host's UPSTREAM resolvers (not systemd-resolved's 127.0.0.53 stub),
    # and those are the only addresses the firewall lets them query.
    DNS="$({ awk '/^nameserver/ {print $2}' /run/systemd/resolve/resolv.conf /etc/resolv.conf 2>/dev/null \
      | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -Ev '^127\.' | sort -u | paste -sd, -; } || true)"
    [ -n "$DNS" ] || die "--egress limited needs --dns: no upstream resolver could be detected"
    say "container DNS limited to the host's upstream resolver(s): $DNS"
  fi
}

# ── helpers ──────────────────────────────────────────────────────────────────────────────────

python_bin() {
  if [ -x "$INSTALL_DIR/.venv/bin/python" ]; then echo "$INSTALL_DIR/.venv/bin/python"; else echo python3; fi
}

fw_args() {
  local args=(--admin-port "$ADMIN_PORT" --ports "$PORTS" --docker-ports "$DOCKER_PORTS" --egress "$EGRESS")
  [ -n "$ADMIN_ALLOW" ] && args+=(--admin-allow "$ADMIN_ALLOW")
  [ -n "$DNS" ] && args+=(--dns "$DNS")
  [ -n "$FTP_PASV" ] && args+=(--ftp-pasv-ports "$FTP_PASV")
  printf '%s\n' "${args[@]}"
}

render_firewall() {
  local args; mapfile -t args < <(fw_args)
  PYTHONPATH="$INSTALL_DIR/src${PYTHONPATH:+:$PYTHONPATH}" "$(python_bin)" -m honeypot_mcp.hardening.firewall "${args[@]}" "$@"
}

reload_sshd() {
  if [ "$DRY" = 1 ]; then echo "[dry-run] sshd -t && systemctl reload ssh"; return; fi
  sshd -t || die "sshd rejected the new configuration; nothing was reloaded"
  systemctl reload ssh 2>/dev/null || systemctl reload sshd
}

listening_on() { ss -Hltn "sport = :$1" 2>/dev/null | grep -q .; }

# sshd re-binds a moment AFTER `systemctl reload` returns, so poll rather than race it.
wait_listening() {
  local port="$1" tries="$2"
  while [ "$tries" -gt 0 ]; do listening_on "$port" && return 0; sleep 1; tries=$((tries - 1)); done
  return 1
}
wait_free() {
  local port="$1" tries="$2"
  while [ "$tries" -gt 0 ]; do listening_on "$port" || return 0; sleep 1; tries=$((tries - 1)); done
  return 1
}

sshd_dropin() {
  # $1: space-separated list of ports sshd should listen on.
  local port_lines="" p
  for p in $1; do port_lines+="Port $p"$'\n'; done
  cat <<EOF
# Managed by honeypot-mcp deploy/harden-host.sh. Do not edit: re-run the script.
# sshd uses the FIRST value it reads for a keyword, and the main file includes this directory
# before its own settings, so these win.
${port_lines}PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowUsers ${ADMIN_USER}
MaxAuthTries 3
LoginGraceTime 20
MaxStartups 5:50:20
X11Forwarding no
AllowAgentForwarding no
# The MCP client reaches the control plane through \`ssh -L\`: local forwarding stays on, remote
# forwarding (a way to expose something from the host) is off.
AllowTcpForwarding local
GatewayPorts no
PermitTunnel no
PermitUserEnvironment no
ClientAliveInterval 60
ClientAliveCountMax 3
LogLevel VERBOSE
EOF
}

# ── commands ─────────────────────────────────────────────────────────────────────────────────

cmd_prepare() {
  need_root; validate_inputs
  [ -n "$ADMIN_USER" ] || die "--admin-user is required"
  if [ "$DRY" != 1 ]; then
    id "$ADMIN_USER" >/dev/null 2>&1 || die "user $ADMIN_USER does not exist"
    [ "$ADMIN_USER" != root ] || die "the admin user must not be root"
    local keys; keys="$(getent passwd "$ADMIN_USER" | cut -d: -f6)/.ssh/authorized_keys"
    [ -s "$keys" ] || die "$keys is empty: password logins are about to be disabled, so $ADMIN_USER needs an SSH key first"
    getent group docker >/dev/null || die "Docker is not installed (no docker group): install it first (docs/DEPLOY.md step 3)"
    grep -q '^Include /etc/ssh/sshd_config.d/\*.conf' /etc/ssh/sshd_config || die "sshd_config does not include sshd_config.d"
  fi

  say "packages"
  run apt-get update -qq
  # sqlite3: scripts/backup.sh takes a consistent snapshot of the live database with it.
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables unattended-upgrades python3 ca-certificates sqlite3

  say "service accounts (the honeypot service must not be in the docker group)"
  getent passwd honeypot >/dev/null || run useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin honeypot
  getent passwd hp-guard >/dev/null || run useradd --system --no-create-home --shell /usr/sbin/nologin hp-guard
  run usermod -aG docker hp-guard
  if getent group docker | tr ':,' '\n' | grep -qx honeypot; then run gpasswd -d honeypot docker; fi
  if [ -d "$INSTALL_DIR" ]; then
    for d in data reports tls pcap; do
      run install -d -m 0750 -o honeypot -g honeypot "$INSTALL_DIR/$d"
    done
  fi
  if [ "$DRY" != 1 ] && [ -x "$INSTALL_DIR/.venv/bin/python" ]; then
    # `uv sync` as root puts the interpreter under /root/.local/share/uv/python, which the service
    # user (and ProtectHome=true) cannot reach: the unit then dies with "Permission denied".
    local interpreter; interpreter="$(readlink -f "$INSTALL_DIR/.venv/bin/python")"
    if ! runuser -u honeypot -- test -x "$interpreter"; then
      die "the service user cannot execute $interpreter. Rebuild the venv with a shared interpreter: cd $INSTALL_DIR && rm -rf .venv && UV_PYTHON_INSTALL_DIR=/opt/uv-python uv sync --frozen --no-dev --python 3.12"
    fi
    say "the service user can execute the venv interpreter ($interpreter)"
  fi

  # Re-running `prepare` after `finalize` must not reopen port 22: sshd would then block the SSH
  # honeypot from binding it. A drop-in that already lacks `Port 22` means finalize ran.
  local sshd_ports="22 $ADMIN_PORT"
  if [ -f "$SSHD_DROPIN" ] && ! grep -qx 'Port 22' "$SSHD_DROPIN"; then
    sshd_ports="$ADMIN_PORT"
    say "sshd is already admin-port-only (finalized): keeping it that way"
  else
    say "sshd: key-only, allow-listed user; listening on 22 and $ADMIN_PORT until you have tested $ADMIN_PORT"
  fi
  if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
    # Ubuntu 24.04 activates sshd from a socket that ignores Port in the config.
    run systemctl disable --now ssh.socket
    run systemctl enable --now ssh.service
  fi
  sshd_dropin "$sshd_ports" | write_file "$SSHD_DROPIN" 0644
  reload_sshd

  say "kernel hardening (ip_forward stays on: Docker needs it)"
  write_file "$SYSCTL_FILE" 0644 <<'EOF'
# Managed by honeypot-mcp deploy/harden-host.sh.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
EOF
  run sysctl --system >/dev/null || warn "some sysctl keys could not be applied (a container or hypervisor may restrict them)"

  say "Docker daemon: no userland proxy, no inter-container traffic, no new privileges"
  docker_daemon_json
  say "unattended security updates (no automatic reboot)"
  write_file /etc/apt/apt.conf.d/20auto-upgrades 0644 <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  write_file /etc/apt/apt.conf.d/52honeypot-unattended-upgrades 0644 <<'EOF'
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF

  say "systemd units"
  for unit in honeypot-mcp honeypot-docker-guard honeypot-firewall; do
    [ -f "$INSTALL_DIR/deploy/$unit.service" ] || { [ "$DRY" = 1 ] || die "$INSTALL_DIR/deploy/$unit.service not found"; }
    run install -m 0644 "$INSTALL_DIR/deploy/$unit.service" "/etc/systemd/system/$unit.service"
  done
  run systemctl daemon-reload

  if [ "$sshd_ports" = "$ADMIN_PORT" ]; then
    cat <<EOF

prepare done (already finalized: sshd stays on $ADMIN_PORT only). Nothing else to do here.
EOF
    return
  fi
  cat <<EOF

prepare done. sshd now listens on 22 and $ADMIN_PORT. BEFORE going on, open a NEW terminal and
confirm you can log in on the new port (keep this session open):

    ssh -p $ADMIN_PORT $ADMIN_USER@<this host>

Then:  sudo $0 finalize --admin-user $ADMIN_USER --admin-port $ADMIN_PORT --confirm-admin-port-tested ...
EOF
}

docker_daemon_json() {
  local target=/etc/docker/daemon.json
  if [ "$DRY" = 1 ]; then echo "[dry-run] merge hardening keys into $target"; return; fi
  mkdir -p /etc/docker
  local changed
  changed="$(python3 - "$target" <<'PY'
import json, os, sys
path = sys.argv[1]
want = {
    "userland-proxy": False,
    "no-new-privileges": True,
    "live-restore": True,
    "icc": False,
    "log-driver": "json-file",
    "log-opts": {"max-size": "10m", "max-file": "3"},
}
try:
    have = json.load(open(path))
except (OSError, ValueError):
    have = {}
merged = {**have, **want}
if merged != have:
    tmp = path + ".tmp"
    json.dump(merged, open(tmp, "w"), indent=2); open(tmp, "a").write("\n")
    os.replace(tmp, path)
    print("changed")
PY
)"
  if [ "$changed" = changed ]; then
    if [ -n "$(docker ps -q --filter label=honeypot-mcp=true 2>/dev/null)" ]; then
      warn "daemon.json changed but honeypot containers are running: restart Docker when convenient (live-restore keeps them up)"
    else
      say "restarting Docker to apply daemon.json"; systemctl restart docker
    fi
  else
    say "unchanged: $target"
  fi
}

cmd_finalize() {
  need_root; validate_inputs
  [ -n "$ADMIN_USER" ] || die "--admin-user is required"
  [ "$CONFIRM_ADMIN" = 1 ] || die "pass --confirm-admin-port-tested once you have logged in on port $ADMIN_PORT from a second terminal"
  if [ "$DRY" != 1 ]; then
    listening_on "$ADMIN_PORT" || die "nothing is listening on $ADMIN_PORT: run prepare first"
    [ -x "$INSTALL_DIR/.venv/bin/python" ] || die "$INSTALL_DIR/.venv is missing (uv sync --frozen --no-dev)"
  fi

  say "validating the firewall ruleset before anything changes"
  render_firewall --out /dev/null || die "the firewall specification is invalid"
  if [ "$DRY" != 1 ]; then
    local tmp; tmp="$(mktemp)"
    render_firewall --out "$tmp"
    nft -c -f "$tmp" || die "nft rejected the ruleset (nothing was loaded)"
    rm -f "$tmp"
  fi

  say "sshd moves to port $ADMIN_PORT only (port 22 is for the SSH honeypot)"
  sshd_dropin "$ADMIN_PORT" | write_file "$SSHD_DROPIN" 0644
  reload_sshd
  if [ "$DRY" != 1 ]; then
    if ! wait_listening "$ADMIN_PORT" 15; then
      # Never leave the host with no way in: put port 22 back and stop.
      sshd_dropin "22 $ADMIN_PORT" | write_file "$SSHD_DROPIN" 0644
      reload_sshd
      die "sshd did not start listening on $ADMIN_PORT; port 22 was restored. Check: journalctl -u ssh"
    fi
    wait_free 22 10 || warn "something still listens on 22 (ssh.socket, or an old sshd): the SSH honeypot cannot bind it"
  fi

  say "loading the firewall (it removes itself in ${ROLLBACK_SECONDS}s unless you run: $0 confirm)"
  if [ "$DRY" = 1 ]; then
    echo "[dry-run] render to $FIREWALL_FILE, nft -f, arm rollback timer"
  else
    install -d -m 0755 "$(dirname "$FIREWALL_FILE")"
    render_firewall --out "$FIREWALL_FILE"
    systemctl stop "$ROLLBACK_UNIT.timer" "$ROLLBACK_UNIT.service" 2>/dev/null || true
    systemd-run --quiet --unit="$ROLLBACK_UNIT" --on-active="${ROLLBACK_SECONDS}s" /usr/sbin/nft delete table inet hp_fw
    nft -f "$FIREWALL_FILE"
  fi
  local listen="" public=""
  listen="$(render_firewall --print-listen 2>/dev/null || true)"
  # The ports the world connects to: the redirect sources (80, not 8080) and the Docker ports.
  public="$(printf '%s,%s' "$PORTS" "$DOCKER_PORTS" | sed -E 's/>[0-9]+//g; s/^,|,$//g')"
  cat <<EOF

Firewall loaded. From a NEW terminal, confirm you can still log in:

    ssh -p $ADMIN_PORT $ADMIN_USER@<this host>

If it works, within ${ROLLBACK_SECONDS}s run:   sudo $0 confirm
If it does not, do nothing: the firewall removes itself.

Preflight command for this layout:
    scripts/preflight.sh --ports $public --listen-ports $listen --admin-port $ADMIN_PORT \\
        --metrics-url http://127.0.0.1:19090 --mcp-url http://127.0.0.1:18443/mcp --token \$OPERATOR_TOKEN
EOF
}

cmd_confirm() {
  need_root
  run systemctl stop "$ROLLBACK_UNIT.timer" "$ROLLBACK_UNIT.service" 2>/dev/null || true
  if [ "$DRY" != 1 ]; then
    nft list table inet hp_fw >/dev/null 2>&1 || die "the firewall is not loaded (the rollback already fired?): re-run finalize"
  fi
  run systemctl enable honeypot-firewall.service honeypot-docker-guard.service
  say "firewall confirmed and persisted; the Docker guard is enabled"
  say "start the service when .env is ready:  sudo systemctl enable --now honeypot-mcp"
}

cmd_status() {
  echo "--- listening sockets (public ones are the attack surface)"
  ss -Htulnp 2>/dev/null | awk '{print $1, $5, $7}' | sort -u | column -t || true
  echo "--- firewall"
  nft list table inet hp_fw 2>/dev/null | grep -E "policy|dport|redirect" | head -30 || echo "NOT LOADED"
  echo "--- sshd (effective)"
  sshd -T 2>/dev/null | grep -E '^(port|permitrootlogin|passwordauthentication|allowusers|allowtcpforwarding|maxauthtries) ' || true
  echo "--- docker group members (honeypot must not be one)"
  getent group docker | cut -d: -f4
  echo "--- units"
  systemctl is-active honeypot-docker-guard honeypot-mcp honeypot-firewall 2>/dev/null || true
  echo "--- preflight (host checks)"
  PYTHONPATH="$INSTALL_DIR/src${PYTHONPATH:+:$PYTHONPATH}" "$(python_bin)" -m honeypot_mcp.preflight \
    --no-self-test --admin-port "$ADMIN_PORT" --listen-ports "$(render_firewall --print-listen 2>/dev/null || echo "")" || true
}

cmd_teardown() {
  need_root
  [ "$HAVE_BACKUP" = 1 ] || die "back up first (scripts/backup.sh), then pass --i-have-a-backup: teardown removes the honeypots' containers"
  run systemctl stop honeypot-mcp.service || true
  if [ "$DRY" != 1 ]; then
    docker ps -aq --filter label=honeypot-mcp=true 2>/dev/null | xargs -r docker rm -f -v >/dev/null
  fi
  run systemctl disable honeypot-firewall.service || true
  run systemctl stop "$ROLLBACK_UNIT.timer" 2>/dev/null || true
  run nft delete table inet hp_fw 2>/dev/null || true
  say "honeypots stopped, containers removed, firewall removed. sshd stays hardened on port $ADMIN_PORT."
  say "The database is in $INSTALL_DIR/data. If you have not already, run scripts/fetch_backup.sh from your laptop NOW,"
  say "then destroy the VPS. (Cowrie's downloaded samples lived in the containers just removed; fetch_backup.sh --samples must run BEFORE teardown.)"
}

case "$CMD" in
  prepare) cmd_prepare ;;
  finalize) cmd_finalize ;;
  confirm) cmd_confirm ;;
  status) cmd_status ;;
  teardown) cmd_teardown ;;
  -h|--help|help) usage ;;
  *) die "unknown command: $CMD (prepare | finalize | confirm | status | teardown)" ;;
esac
