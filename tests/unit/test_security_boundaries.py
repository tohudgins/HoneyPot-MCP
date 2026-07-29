"""Security regression tests.

Each case here corresponds to a boundary that was found crossable during a
security review of the codebase. They are grouped by the boundary rather than
by module, because that is how they would be re-broken: by someone adding a new
tool that writes a file, or a new caller that turns a name into a path.

The threat model that makes these matter is specific to this product: the
control plane is driven by a language model that *reads attacker-authored
data*. Captured usernames, paths, commands and User-Agents all reach the same
context that decides which tools to call with which arguments. Any tool
parameter that reaches the filesystem is therefore reachable, in principle, by
someone who never authenticated to anything.
"""

import os

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage.database import close_db, init_db

    await init_db()
    yield
    await close_db()


async def _seed(n: int = 20, ip: str = "9.9.9.9"):
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    async with get_session() as session:
        for _ in range(n):
            session.add(
                Alert(
                    source_ip=ip,
                    event_type="ssh_login_failed",
                    payload={"username": "root", "note": "CAPTURED-ATTACKER-CONTENT"},
                    severity=AlertSeverity.LOW,
                )
            )


# ── Artifact writes stay inside reports_dir ──────────────────────────────────


ESCAPE_ATTEMPTS = [
    "../../../../tmp/escaped.txt",
    "/tmp/absolute_escape.txt",
    "~/escaped_via_home.txt",
    "subdir/../../../escaped.txt",
]


@pytest.mark.parametrize("bad_path", ESCAPE_ATTEMPTS)
def test_artifact_path_refuses_to_escape_reports_dir(bad_path):
    from honeypot_mcp.tools._format import resolve_artifact_path

    result = resolve_artifact_path(bad_path, prefix="x", extension="txt")
    assert isinstance(result, str), f"{bad_path} was accepted"
    assert "Refusing to write outside" in result


def test_artifact_path_allows_ordinary_filenames_and_subdirectories():
    from pathlib import Path

    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools._format import resolve_artifact_path

    root = get_settings().reports_dir.resolve()
    for good in ("weekly.csv", "exports/weekly.csv", str(root / "abs.csv")):
        result = resolve_artifact_path(good, prefix="x", extension="csv")
        assert isinstance(result, Path), f"{good} was rejected: {result}"
        assert root in result.parents or result == root


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_path", ESCAPE_ATTEMPTS)
async def test_every_export_tool_refuses_to_write_outside_reports_dir(bad_path):
    """All four bulk writers must share the boundary — a new export tool that
    forgets it reintroduces an arbitrary-file-write primitive."""
    from honeypot_mcp.tools.alerts import alerts_export
    from honeypot_mcp.tools.analysis import export_blocklist, export_stix, generate_report

    await _seed()

    results = {
        "alerts_export": await alerts_export(format="csv", output_path=bad_path),
        "export_stix": await export_stix(hours=24, min_hits=1, output_path=bad_path),
        "export_blocklist": await export_blocklist(hours=24, min_hits=5, output_path=bad_path),
        "generate_report": await generate_report(format="markdown", output_path=bad_path),
    }
    for tool, result in results.items():
        assert "error" in result, f"{tool} accepted {bad_path}: {result}"
        assert "path" not in result


@pytest.mark.asyncio
async def test_export_still_works_for_legitimate_filenames():
    """The boundary must not break the normal case."""
    from honeypot_mcp.tools.alerts import alerts_export

    await _seed()
    result = await alerts_export(format="csv", output_path="legit-export.csv")
    assert "error" not in result
    assert result["path"].endswith("legit-export.csv")


# ── Honeypot names never become paths ────────────────────────────────────────


@pytest.mark.parametrize(
    "bad_name",
    ["../../etc/passwd", "a/b", "..", "", "name with spaces", "x" * 65, "-leading-dash"],
)
def test_unsafe_honeypot_names_are_rejected(bad_name):
    from honeypot_mcp.tools._format import validate_honeypot_name

    assert validate_honeypot_name(bad_name) is not None, f"{bad_name!r} accepted"


@pytest.mark.parametrize("good_name", ["web-01", "ssh_prod.1", "a", "A1", "x" * 64])
def test_reasonable_honeypot_names_are_accepted(good_name):
    from honeypot_mcp.tools._format import validate_honeypot_name

    assert validate_honeypot_name(good_name) is None, f"{good_name!r} rejected"


@pytest.mark.asyncio
async def test_deploy_rejects_a_traversal_name_before_touching_the_filesystem():
    from honeypot_mcp.tools.honeypot import honeypot_deploy

    result = await honeypot_deploy(type="http", name="../../../../tmp/evil", port=9)
    assert "error" in result
    assert "Invalid honeypot name" in result["error"]


def test_cert_directory_refuses_to_escape_the_tls_tree():
    """Defence in depth: the deploy tool validates names, but this is where a
    name actually becomes a path, and reconciliation and cloning also call it."""
    from honeypot_mcp.engines.tls import _cert_dir

    for bad in ("../../etc", "../outside", "/tmp/abs"):
        with pytest.raises(ValueError, match="Unsafe honeypot name"):
            _cert_dir(bad)


def test_cert_directory_accepts_a_normal_name(tmp_path, monkeypatch):
    from honeypot_mcp.engines import tls

    monkeypatch.chdir(tmp_path)
    path = tls._cert_dir("web-01")
    assert path.is_dir()
    assert path.name == "web-01"


# ── Secrets never reach the audit log ────────────────────────────────────────


def test_audit_log_redacts_credential_shaped_arguments():
    from honeypot_mcp.tools._audit import redact_arguments

    redacted = redact_arguments(
        {
            "hmac_secret": "s3cret-signing-key",
            "api_key": "AKIAIOSFODNN7EXAMPLE",
            "password": "hunter2",
            "auth_token": "bearer-abc",
            "nested": {"aws_secret_access_key": "wJalr", "label": "prod"},
            "url": "https://splunk.example.com",
        }
    )
    blob = str(redacted)
    for secret in ("s3cret-signing-key", "AKIAIOSFODNN7EXAMPLE", "hunter2", "bearer-abc", "wJalr"):
        assert secret not in blob, f"{secret} leaked into the audit log"
    assert redacted["url"] == "https://splunk.example.com"
    assert redacted["nested"]["label"] == "prod"


# ── The console is a view, never a control plane ─────────────────────────────


def test_console_exposes_no_state_changing_routes():
    """The console has no authentication, so a non-GET route on it would be an
    unauthenticated control plane."""
    from honeypot_mcp.console import build_console_app

    methods = {route.method for route in build_console_app().router.routes()}
    assert methods <= {"GET", "HEAD"}, f"console exposes {methods}"


# ── Cloud-event ingest stays closed until explicitly configured ──────────────


@pytest.mark.asyncio
async def test_cloud_event_ingest_refuses_when_no_secret_is_configured():
    """An unsigned ingest endpoint would let anyone forge CRITICAL alerts."""
    from honeypot_mcp import canary

    class _Req:
        headers: dict = {}

        async def read(self):
            return b'{"forged": true}'

        @property
        def remote(self):
            return "203.0.113.1"

    response = await canary._handle_cloud_event(_Req())
    assert response.status == 503
