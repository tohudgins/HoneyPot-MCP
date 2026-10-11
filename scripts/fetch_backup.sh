#!/usr/bin/env bash
# Fetch a backup from the honeypot VPS to this machine, verify it, and report whether the run worked.
#
#   scripts/fetch_backup.sh --host <droplet-ip> --key ~/.ssh/honeypot_deploy [options]
#   scripts/fetch_backup.sh report <backup-dir | honeypot_mcp.db>      # analyse a backup you already have
#
# What the first form does, over ONE ssh connection (the admin port allows 6 new connections a
# minute per address, so everything shares a ControlMaster):
#   1. runs scripts/backup.sh on the VPS (a consistent snapshot of the live SQLite database, plus the
#      TLS certs, reports and .env);
#   2. streams the backup back as a tar and unpacks it here - the VPS is treated as hostile, so the
#      archive's member names are checked first, and symlinks/special files are removed after;
#   3. checks the transfer (the database's SHA-256 here equals the one computed on the VPS) and the
#      database (PRAGMA integrity_check);
#   4. optionally (--samples) copies Cowrie's downloaded files and TTY recordings out of each
#      container. They live in a tmpfs, which `docker cp` does not see, so this runs Python inside
#      the container;
#   5. prints a report: the time window, events per sensor, silent or dead sensors, outages, the top
#      sources and credentials, honeytoken trips, platform alerts, and a PASS/WARN/FAIL verdict.
#
# The backup holds secrets (.env tokens, honeytoken values, TLS keys): it is created mode 0700 and
# you should store it where you would store the .env. Captured samples are LIVE MALWARE: they are
# stripped of every permission bit and kept in a quarantine folder; never run them.
#
# Options:
#   --host IP             the droplet (required)           --user NAME     login user (default deploy)
#   --port N              admin SSH port (default 2200)    --key PATH      SSH private key
#   --dest DIR            where to keep backups (default ./hp-backups)
#   --install-dir DIR     project dir on the VPS (default /opt/honeypot-mcp)
#   --remote-dir DIR      backups dir on the VPS (default /var/backups/honeypot)
#   --samples             also pull Cowrie downloads/TTY recordings (needs docker on the VPS)
#   --delete-remote       delete the VPS copy of the backup after it verified
#   --expect-types LIST   comma list of honeypot types you deployed, e.g. ssh,http,rdp; the report
#                         warns about any that are missing from the database
#   --no-report           fetch and verify only
# Exit status: 0 backup verified and the run looks healthy (warnings are printed, not fatal); 1 the
# transfer did not verify, or the report has a FAIL (the message says which); 2 usage/setup.
#
# Works with macOS's bash 3.2 and its sqlite3; needs ssh, tar and sqlite3 here.
set -euo pipefail

HOST=""; USER_NAME="deploy"; PORT=2200; KEY=""; DEST="./hp-backups"
INSTALL_DIR="/opt/honeypot-mcp"; REMOTE_DIR="/var/backups/honeypot"
SAMPLES=0; DELETE_REMOTE=0; EXPECT_TYPES=""; DO_REPORT=1
MODE="fetch"

say() { printf '==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit "${2:-1}"; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; }

if [ "${1:-}" = "report" ]; then
  MODE="report"; shift
  REPORT_TARGET="${1:?usage: fetch_backup.sh report <backup-dir | honeypot_mcp.db> [--expect-types LIST]}"; shift
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="${2:?}"; shift 2 ;;
    --user) USER_NAME="${2:?}"; shift 2 ;;
    --port) PORT="${2:?}"; shift 2 ;;
    --key) KEY="${2:?}"; shift 2 ;;
    --dest) DEST="${2:?}"; shift 2 ;;
    --install-dir) INSTALL_DIR="${2:?}"; shift 2 ;;
    --remote-dir) REMOTE_DIR="${2:?}"; shift 2 ;;
    --expect-types) EXPECT_TYPES="${2:?}"; shift 2 ;;
    --samples) SAMPLES=1; shift ;;
    --delete-remote) DELETE_REMOTE=1; shift ;;
    --no-report) DO_REPORT=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" 2 ;;
  esac
done

command -v sqlite3 >/dev/null 2>&1 || die "sqlite3 is needed here (macOS ships it; apt install sqlite3)" 2
umask 077

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

# ── the report ───────────────────────────────────────────────────────────────────────────────

# Rows are `LEVEL|message` so the verdict below is just a list. Everything runs on a read-only
# connection with the schema untrusted: the database came from a host we do not trust.
q() { sqlite3 -readonly -batch -separator '|' "$DBOPEN" "PRAGMA trusted_schema=OFF; $PRELUDE $1"; }
qt() { sqlite3 -readonly -batch -header -column "$DBOPEN" "PRAGMA trusted_schema=OFF; $PRELUDE $1"; }

# `act` is attacker activity: not a platform alert (0.0.0.0), not an internal address and not one
# of our own self-test probes (which carry a selftest_ marker). Internal means loopback, link-local
# and the private ranges (10/8, 172.16/12, 192.168/16): an attacker on the internet cannot appear
# from those, but the platform does (the Docker bridge 172.17.0.1 is the source Cowrie sees for
# the self-tests and the pre-flight probes, and only some of those events carry the marker).
PRELUDE="CREATE TEMP VIEW act AS SELECT * FROM alerts WHERE source_ip NOT IN ('0.0.0.0','127.0.0.1','::1','') AND source_ip NOT GLOB '10.*' AND source_ip NOT GLOB '192.168.*' AND source_ip NOT GLOB '169.254.*' AND source_ip NOT GLOB '172.1[6-9].*' AND source_ip NOT GLOB '172.2[0-9].*' AND source_ip NOT GLOB '172.3[01].*' AND LOWER(source_ip) NOT GLOB 'fe80:*' AND LOWER(source_ip) NOT GLOB 'fc*' AND LOWER(source_ip) NOT GLOB 'fd*' AND IFNULL(CAST(payload AS TEXT),'') NOT LIKE '%selftest_%'; CREATE TEMP VIEW ref AS SELECT IFNULL(MAX(timestamp), datetime('now')) AS t FROM alerts;"

report() {
  local target="$1" out failures=0 warnings=0
  if [ -d "$target" ]; then DB="$target/honeypot_mcp.db"; OUTDIR="$target"; else DB="$target"; OUTDIR="$(dirname "$target")"; fi
  [ -f "$DB" ] || die "no database at $DB" 2
  # The server's database is in WAL mode, and a plain read-only open of a WAL database needs its
  # -shm/-wal side files to exist ("unable to open database file" otherwise). `immutable=1` opens
  # the downloaded snapshot without any side files and without writing a byte, so the bytes the
  # checksum vouched for stay exactly as they were. Percent-escape the characters a URI cares about.
  DBOPEN="file:$(printf '%s' "$DB" | sed -e 's/%/%25/g' -e 's/?/%3f/g' -e 's/#/%23/g' -e 's/ /%20/g')?immutable=1"
  out="$OUTDIR/report.txt"
  {
    printf 'HoneyPot-MCP run report  (generated %s)\n' "$(date -u '+%Y-%m-%d %H:%M UTC')"
    printf 'database: %s\n\n' "$DB"

    local integrity; integrity="$(sqlite3 -readonly -batch "$DBOPEN" 'PRAGMA integrity_check;' 2>&1 | head -1)"
    printf -- '--- time window (attacker activity, self-tests excluded)\n'
    qt "SELECT MIN(timestamp) AS first_event, MAX(timestamp) AS last_event, ROUND((julianday(MAX(timestamp))-julianday(MIN(timestamp)))*24,1) AS hours, COUNT(*) AS events, COUNT(DISTINCT source_ip) AS source_ips FROM act;"
    printf '\n--- sensors\n'
    qt "SELECT h.name, h.type, h.port, LOWER(h.status) AS status, COUNT(a.id) AS events, IFNULL(MAX(a.timestamp),'never') AS last_event, CASE WHEN MAX(a.timestamp) IS NULL THEN 'n/a' ELSE ROUND((julianday((SELECT t FROM ref))-julianday(MAX(a.timestamp)))*24,1) END AS hours_silent FROM honeypots h LEFT JOIN act a ON a.honeypot_id=h.id GROUP BY h.id ORDER BY events DESC, h.name;"
    printf '\n--- event types\n'
    qt "SELECT event_type, severity, COUNT(*) AS n FROM act GROUP BY event_type, severity ORDER BY n DESC LIMIT 20;"
    printf '\n--- top sources\n'
    qt "SELECT source_ip, COUNT(*) AS events, COUNT(DISTINCT honeypot_id) AS sensors_hit, MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen FROM act GROUP BY source_ip ORDER BY events DESC LIMIT 10;"
    printf '\n--- activity by hour (UTC)\n'
    qt "WITH c AS (SELECT SUBSTR(timestamp,1,13) AS hour, COUNT(*) AS n FROM act GROUP BY 1) SELECT hour, n, REPLACE(HEX(ZEROBLOB(1 + (n*40)/(SELECT MAX(n) FROM c))),'00','#') AS bar FROM c ORDER BY hour;"
    printf '\n--- credentials tried (top 10 each)\n'
    if [ "$(q "SELECT json_valid('{}');" 2>/dev/null || echo 0)" = "1" ]; then
      qt "SELECT json_extract(payload,'\$.username') AS username, COUNT(*) AS n FROM act WHERE json_extract(payload,'\$.username') IS NOT NULL GROUP BY 1 ORDER BY n DESC LIMIT 10;"
      qt "SELECT json_extract(payload,'\$.password') AS password, COUNT(*) AS n FROM act WHERE json_extract(payload,'\$.password') IS NOT NULL GROUP BY 1 ORDER BY n DESC LIMIT 10;"
    else
      printf '(this sqlite3 has no JSON functions; skipped)\n'
    fi
    printf '\n--- honeytokens\n'
    qt "SELECT status, COUNT(*) AS n FROM honeytokens GROUP BY status;"
    qt "SELECT label, triggered_at FROM honeytokens WHERE LOWER(status)='triggered' ORDER BY triggered_at;"
    printf '\n--- platform alerts (a healthy run has none of these, or only briefly)\n'
    qt "SELECT event_type, COUNT(*) AS n, MAX(timestamp) AS last FROM alerts WHERE event_type IN ('honeypot_health_failed','honeypot_restart_failed','disk_space_low','sensor_ownership_lost') GROUP BY event_type;"

    printf '\n=== verdict\n'
    if [ "$integrity" = "ok" ]; then printf 'PASS|database integrity_check is ok\n'; else printf 'FAIL|database integrity_check: %s\n' "$integrity"; fi
    q "WITH s AS (SELECT COUNT(*) AS n, COUNT(DISTINCT source_ip) AS ips, ROUND((julianday(MAX(timestamp))-julianday(MIN(timestamp)))*24,1) AS hrs FROM act)
       SELECT CASE WHEN n=0 THEN 'FAIL|no attacker activity was recorded at all (is anything reachable? run honeypot_self_test, check the firewall and the provider)'
                   ELSE 'PASS|'||n||' attacker events from '||ips||' source addresses over '||hrs||' hours' END FROM s;"
    q "SELECT 'FAIL|sensor '||name||' ('||type||'/'||port||') is '||LOWER(status)||' in the database' FROM honeypots WHERE LOWER(status) NOT IN ('running');"
    q "SELECT 'WARN|sensor '||h.name||' ('||h.type||'/'||h.port||') recorded no attacker events (normal for a rarely scanned protocol early on; if every sensor is silent suspect the network path)' FROM honeypots h WHERE LOWER(h.status)='running' AND NOT EXISTS (SELECT 1 FROM act a WHERE a.honeypot_id=h.id);"
    q "SELECT 'WARN|sensor '||h.name||' has been silent for '||ROUND((julianday((SELECT t FROM ref))-julianday(MAX(a.timestamp)))*24,1)||' hours while others were active' FROM honeypots h JOIN act a ON a.honeypot_id=h.id GROUP BY h.id HAVING (julianday((SELECT t FROM ref))-julianday(MAX(a.timestamp)))*24 > 12;"
    q "SELECT 'WARN|'||n||' health failure alert(s) on sensor id(s) '||ids||', last '||last FROM (SELECT COUNT(*) AS n, GROUP_CONCAT(DISTINCT honeypot_id) AS ids, MAX(timestamp) AS last FROM alerts WHERE event_type IN ('honeypot_health_failed','honeypot_restart_failed')) WHERE n>0;"
    q "SELECT 'WARN|disk space was low '||n||' time(s), last '||last FROM (SELECT COUNT(*) AS n, MAX(timestamp) AS last FROM alerts WHERE event_type='disk_space_low') WHERE n>0;"
    q "SELECT 'WARN|the server lost sensor ownership '||n||' time(s), last '||last FROM (SELECT COUNT(*) AS n, MAX(timestamp) AS last FROM alerts WHERE event_type='sensor_ownership_lost') WHERE n>0;"
    q "WITH RECURSIVE h(t) AS (SELECT STRFTIME('%Y-%m-%d %H:00:00', MIN(timestamp)) FROM act UNION ALL SELECT DATETIME(t,'+1 hour') FROM h WHERE t < (SELECT STRFTIME('%Y-%m-%d %H:00:00', MAX(timestamp)) FROM act)),
            gaps AS (SELECT COUNT(*) AS n FROM h WHERE SUBSTR(t,1,13) NOT IN (SELECT DISTINCT SUBSTR(timestamp,1,13) FROM act) AND t IS NOT NULL)
       SELECT 'WARN|'||n||' hour(s) between the first and last event had no activity at all (a sleeping scanner, or an outage: compare with the hour table)' FROM gaps WHERE n > 3;"
    q "SELECT 'INFO|honeytoken '||label||' was TRIGGERED at '||triggered_at FROM honeytokens WHERE LOWER(status)='triggered';"
    q "SELECT 'INFO|'||n||' event(s) came from internal addresses (loopback, the Docker bridge, private ranges): the platform''s own probes and container traffic, not attackers, and not counted above' FROM (SELECT COUNT(*) AS n FROM alerts WHERE source_ip NOT IN ('0.0.0.0','') AND source_ip NOT IN (SELECT source_ip FROM act)) WHERE n>0;"
    if [ -n "$EXPECT_TYPES" ]; then
      local t
      for t in $(printf '%s' "$EXPECT_TYPES" | tr ',' ' '); do
        case "$t" in *[!a-z0-9_]*|"") continue ;; esac
        q "SELECT CASE WHEN COUNT(*)=0 THEN 'FAIL|expected a $t honeypot but the database has none' ELSE 'PASS|'||COUNT(*)||' $t honeypot(s) present' END FROM honeypots WHERE type='$t';"
      done
    fi
  } > "$out.body" 2>&1

  # Split the verdict rows from the tables, count levels, and print the whole thing once.
  awk '/^=== verdict/{v=1; print; next} v && /^[A-Z]+\|/{split($0,a,"|"); printf "  [%s] %s\n", a[1], substr($0, length(a[1])+2); next} {print}' "$out.body" > "$out"
  failures="$(grep -c '^  \[FAIL\]' "$out" || true)"
  warnings="$(grep -c '^  \[WARN\]' "$out" || true)"
  rm -f "$out.body"
  cat "$out"
  printf '\n%s failed, %s warning(s). Report saved to %s\n' "$failures" "$warnings" "$out"
  [ "$failures" -eq 0 ]
}

if [ "$MODE" = "report" ]; then
  report "$REPORT_TARGET"
  exit $?
fi

# ── fetch ────────────────────────────────────────────────────────────────────────────────────

[ -n "$HOST" ] || { usage; exit 2; }
for v in "$INSTALL_DIR" "$REMOTE_DIR" "$USER_NAME" "$HOST"; do
  case "$v" in *[!A-Za-z0-9_./:-]*|"") die "refusing an unusual value: $v" 2 ;; esac
done
case "$PORT" in ''|*[!0-9]*) die "--port must be a number" 2 ;; esac
case "$KEY" in *[[:space:]]*) die "--key must be a path without spaces" 2 ;; esac
command -v ssh >/dev/null 2>&1 || die "ssh is needed here" 2
command -v tar >/dev/null 2>&1 || die "tar is needed here" 2

CTL_DIR="$(mktemp -d "${TMPDIR:-/tmp}/hpfetch.XXXXXX")"
trap 'ssh -O exit -o ControlPath="$CTL_DIR/cm" "$USER_NAME@$HOST" >/dev/null 2>&1 || true; rm -rf "$CTL_DIR"' EXIT
SSH_OPTS="-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -o ControlMaster=auto -o ControlPath=$CTL_DIR/cm -o ControlPersist=120 -p $PORT"
[ -n "$KEY" ] && SSH_OPTS="$SSH_OPTS -o IdentitiesOnly=yes -i $KEY"
# SC2086: SSH_OPTS is a word list on purpose. SC2029: the remote command is built here, on purpose
# (every interpolated value was validated against a strict character set above).
# shellcheck disable=SC2086,SC2029
remote() { ssh $SSH_OPTS "$USER_NAME@$HOST" "$@"; }

say "connecting to $USER_NAME@$HOST:$PORT"
remote true || die "cannot log in. Is the tunnel/firewall up, is the key right, and has the 'confirm' step been run? (admin SSH allows 6 new connections a minute per address)"
remote 'sudo -n true' || die "$USER_NAME cannot run sudo without a password on the VPS (the setup creates /etc/sudoers.d/deploy)"

say "taking a consistent backup on the VPS"
OUT="$(remote "sudo -n sh -c 'cd $INSTALL_DIR && ./scripts/backup.sh $REMOTE_DIR'" 2>&1)" || { printf '%s\n' "$OUT" >&2; die "the remote backup failed"; }
RPATH="$(printf '%s\n' "$OUT" | sed -n 's/^Backup complete: //p' | tail -1)"
[ -n "$RPATH" ] || { printf '%s\n' "$OUT" >&2; die "could not find the backup path in backup.sh's output"; }
NAME="$(basename "$RPATH")"
case "$NAME" in honeypot-[0-9T]*Z) ;; *) die "unexpected backup name from the VPS: $NAME" ;; esac
say "remote backup: $RPATH"

REMOTE_SHA="$(remote "sudo -n sha256sum '$RPATH/honeypot_mcp.db'" 2>/dev/null | cut -d' ' -f1 || true)"

mkdir -p "$DEST"; chmod 700 "$DEST"
FINAL="$DEST/$NAME"
[ ! -e "$FINAL" ] || die "$FINAL already exists here"
WORK="$DEST/$NAME.partial"
rm -rf "$WORK"; mkdir -p "$WORK"

# The archive comes from a host we do not trust: list it and refuse anything that is not
# strictly inside $NAME/ before a single byte is unpacked.
safe_tar_listing() {
  # $1 = tar file, $2 = required top-level name, $3.. = allowed first components (optional)
  local tarfile="$1" top="$2" bad
  bad="$(tar -tf "$tarfile" | awk -v top="$top" 'index($0, top "/")!=1 && $0 != top && $0 != top"/" {print} /(^|\/)\.\.(\/|$)/ {print} /^\// {print}' | head -3)"
  [ -z "$bad" ] || { printf '%s\n' "$bad" >&2; return 1; }
}
strip_unsafe() {
  # Remove symlinks, devices and sockets from an unpacked tree, then drop group/other access.
  find "$1" \( -type l -o -type b -o -type c -o -type p -o -type s \) -exec rm -f {} + 2>/dev/null || true
  chmod -R go-rwx "$1"
}

say "downloading the backup"
remote "sudo -n tar -C '$REMOTE_DIR' -cf - '$NAME'" > "$WORK.tar" || { rm -rf "$WORK" "$WORK.tar"; die "the download failed"; }
safe_tar_listing "$WORK.tar" "$NAME" || { rm -rf "$WORK" "$WORK.tar"; die "the archive contains paths outside $NAME/: refusing to unpack it"; }
tar -xf "$WORK.tar" -C "$WORK"
rm -f "$WORK.tar"
strip_unsafe "$WORK/$NAME"
mv "$WORK/$NAME" "$FINAL"; rmdir "$WORK"
say "saved to $FINAL"

FAILED=0
LOCAL_DB="$FINAL/honeypot_mcp.db"
if [ -f "$LOCAL_DB" ]; then
  LOCAL_SHA="$(sha256_of "$LOCAL_DB")"
  if [ -n "$REMOTE_SHA" ] && [ "$REMOTE_SHA" = "$LOCAL_SHA" ]; then
    say "transfer verified: the database's SHA-256 matches the VPS copy ($LOCAL_SHA)"
  else
    warn "SHA-256 mismatch or unavailable (remote '${REMOTE_SHA:-none}', local '$LOCAL_SHA'): do not trust this copy"; FAILED=1
  fi
else
  warn "no honeypot_mcp.db in the backup (a PostgreSQL deployment?): fetched the files but cannot report on them"; DO_REPORT=0
fi

if [ "$SAMPLES" = 1 ]; then
  say "pulling Cowrie downloads and TTY recordings (LIVE MALWARE: quarantined, no permissions)"
  # Python inside the container, because `docker cp` does not see a tmpfs. The script is passed
  # base64-encoded so no shell quoting can mangle it.
  PYSRC='import os, sys, tarfile
# Cowrie keeps its state under /cowrie/cowrie-git in the image the honeypots use, and under /cowrie in
# others; look in both and exit 3 (not an empty archive) when neither exists.
root = next((r for r in ("/cowrie/cowrie-git/var/lib/cowrie", "/cowrie/var/lib/cowrie") if os.path.isdir(r)), None)
if root is None:
    sys.exit(3)
t = tarfile.open(fileobj=sys.stdout.buffer, mode="w|")
for d in ("downloads", "tty"):
    p = os.path.join(root, d)
    if os.path.isdir(p):
        t.add(p, arcname=d)
t.close()'
  B64="$(printf '%s' "$PYSRC" | base64 | tr -d '\n')"
  CONTAINERS="$(remote "sudo -n docker ps --filter label=honeypot-mcp=true --format '{{.Names}}'" 2>/dev/null || true)"
  QDIR="$FINAL/samples-QUARANTINE"; mkdir -p "$QDIR"
  printf 'LIVE MALWARE captured by the honeypots. Never execute, open or upload these files from a machine you care about. Files are named by SHA-256; see SHA256SUMS.\n' > "$QDIR/README.txt"
  TOTAL=0
  for c in $CONTAINERS; do
    case "$c" in *[!A-Za-z0-9_.-]*|"") continue ;; esac
    TMP_TAR="$QDIR/.$c.tar"
    rc=0; remote "sudo -n docker exec $c python3 -c \"import base64;exec(base64.b64decode('$B64'))\"" > "$TMP_TAR" 2>/dev/null || rc=$?
    if [ "$rc" = 3 ]; then
      # The container is running but Cowrie's data directory is in neither known place: report it as a
      # failure. "0 files" here would be indistinguishable from "no malware yet" and hide a real loss.
      warn "  $c: Cowrie's data directory was not found in the container; samples were NOT collected"; FAILED=1
    elif [ "$rc" = 0 ] && [ -s "$TMP_TAR" ]; then
      if tar -tf "$TMP_TAR" | awk '/^\// {bad=1} /(^|\/)\.\.(\/|$)/ {bad=1} !/^(downloads|tty)(\/|$)/ {bad=1} END {exit bad}'; then
        mkdir -p "$QDIR/$c"; tar -xf "$TMP_TAR" -C "$QDIR/$c"; strip_unsafe "$QDIR/$c"
        find "$QDIR/$c" -type f -exec chmod 000 {} + 2>/dev/null || true
        n="$(find "$QDIR/$c" -type f | wc -l | tr -d ' ')"; TOTAL=$((TOTAL + n))
        say "  $c: $n file(s)"
      else
        warn "  $c: the sample archive had unsafe paths; skipped"; FAILED=1
      fi
    else
      say "  $c: nothing to copy (not a Cowrie container)"
    fi
    rm -f "$TMP_TAR"
  done
  # Hash the files without needing to read them as the quarantine user: read mode is restored only
  # for the moment of hashing.
  : > "$QDIR/SHA256SUMS"
  find "$QDIR" -type f ! -name README.txt ! -name SHA256SUMS | while read -r f; do
    chmod 400 "$f"; printf '%s  %s\n' "$(sha256_of "$f")" "${f#"$QDIR"/}" >> "$QDIR/SHA256SUMS"; chmod 000 "$f"
  done
  say "samples: $TOTAL file(s) in $QDIR"
fi

if [ "$DELETE_REMOTE" = 1 ] && [ "$FAILED" = 0 ]; then
  remote "sudo -n rm -rf '$RPATH'" && say "removed the VPS copy $RPATH"
fi

RUN_FAILED=0
if [ "$DO_REPORT" = 1 ]; then
  echo
  report "$FINAL" || RUN_FAILED=1
fi

echo
if [ "$FAILED" != 0 ]; then
  warn "the transfer did not verify: see above. Backup (unverified): $FINAL"
elif [ "$RUN_FAILED" != 0 ]; then
  say "the backup is VERIFIED and safe to keep. The run report above has failures about the honeypots themselves (dead sensors, missing types, no activity): that is what to investigate. Backup: $FINAL"
else
  say "done. The backup is verified and the run looks healthy. Backup: $FINAL"
fi
cat <<EOF

Next:
  - The backup contains secrets (.env tokens, honeytoken values, TLS keys): keep it private.
  - Analyse it with the full tools: restore it into a local checkout (scripts/restore.sh $FINAL, with no
    server running), then run the server over stdio against that database.
  - Before you destroy the droplet: harden-host.sh teardown --i-have-a-backup, then delete it in the
    DigitalOcean console (a powered-off droplet is still billed).
EOF
[ "$FAILED" = 0 ] && [ "$RUN_FAILED" = 0 ]
