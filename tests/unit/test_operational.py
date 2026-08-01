"""Operational-hygiene tests: suppression presets, canary rate limiting,
Prometheus /metrics endpoint."""

import asyncio
import os
import socket
from collections import deque

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    await asyncio.sleep(0.05)
    event_buffer.reset_for_tests()
    await close_db()


# ── Suppression presets ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_suppression_load_preset_shodan_installs_rules():
    """Loading the shodan preset installs all its rules and they're active."""
    from sqlalchemy import select

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import SuppressionRule
    from honeypot_mcp.tools.integrations import suppression_load_preset

    result = await suppression_load_preset("shodan")
    assert "error" not in result, result
    assert result["preset"] == "shodan"
    assert len(result["applied"]) >= 3

    async with get_session() as session:
        rules = list(
            (await session.execute(select(SuppressionRule).where(SuppressionRule.active.is_(True))))
            .scalars()
            .all()
        )
    labels = [r.label for r in rules]
    assert any(label.startswith("shodan-scanner-") for label in labels)


@pytest.mark.asyncio
async def test_suppression_load_preset_unknown_returns_error():
    from honeypot_mcp.tools.integrations import suppression_load_preset

    result = await suppression_load_preset("does-not-exist")
    assert "error" in result
    assert "not found" in result["error"].lower()


@pytest.mark.asyncio
async def test_suppression_load_preset_idempotent():
    """Loading the same preset twice should skip duplicates rather than
    create them — protects against accidental double-runs."""
    from honeypot_mcp.tools.integrations import suppression_load_preset

    r1 = await suppression_load_preset("censys")
    r2 = await suppression_load_preset("censys")
    assert len(r1["applied"]) > 0
    # Second run should mostly skip
    assert len(r2["skipped"]) >= len(r1["applied"])


@pytest.mark.asyncio
async def test_suppression_list_presets_finds_bundled():
    from honeypot_mcp.tools.integrations import suppression_list_presets

    presets = await suppression_list_presets()
    assert "shodan" in presets
    assert "censys" in presets
    assert "internal-rfc1918" in presets


# ── Canary rate limiting ────────────────────────────────────────────────


def test_canary_rate_limit_under_threshold_passes():
    """A handful of hits from one IP shouldn't trip the limit."""
    from honeypot_mcp import canary

    canary._rate_state.clear()
    for _ in range(5):
        assert canary._rate_limit_check("1.2.3.4") is False


def test_canary_rate_limit_over_threshold_blocks():
    """After 30 hits in the same window, additional hits are blocked."""
    from honeypot_mcp import canary

    canary._rate_state.clear()
    for _ in range(canary._RATE_MAX_PER_WINDOW):
        assert canary._rate_limit_check("9.9.9.9") is False
    # The next hit should be blocked
    assert canary._rate_limit_check("9.9.9.9") is True


def test_canary_rate_limit_isolates_per_ip():
    """One noisy IP can't suppress another's traffic."""
    from honeypot_mcp import canary

    canary._rate_state.clear()
    # Burn through the limit for one IP
    for _ in range(canary._RATE_MAX_PER_WINDOW):
        canary._rate_limit_check("8.8.8.8")
    assert canary._rate_limit_check("8.8.8.8") is True
    # A different IP still passes
    assert canary._rate_limit_check("1.1.1.1") is False


def test_canary_rate_limit_window_expiry():
    """Old timestamps drop off the window. Manually simulate by injecting
    timestamps older than the window."""
    import time

    from honeypot_mcp import canary

    canary._rate_state.clear()
    src = "5.5.5.5"
    # Inject 30 old timestamps (well outside the window)
    canary._rate_state[src] = deque(
        [time.monotonic() - canary._RATE_WINDOW_SECONDS - 10] * canary._RATE_MAX_PER_WINDOW
    )
    # A new hit should clean them up and pass
    assert canary._rate_limit_check(src) is False


def test_canary_rate_limit_evicts_stale_windows():
    """Once the table grows past the cap, fully-decayed IP windows are swept
    so memory stays bounded on a long-lived public deployment."""
    import time

    from honeypot_mcp import canary

    canary._rate_state.clear()
    old = time.monotonic() - canary._RATE_WINDOW_SECONDS - 100
    # Seed the table past the eviction cap with stale (decayed) windows.
    for i in range(canary._RATE_STATE_MAX_IPS + 5):
        canary._rate_state[f"10.0.{i // 256}.{i % 256}"] = deque([old])
    before = len(canary._rate_state)
    # An active hit crosses the cap and triggers the sweep.
    canary._rate_limit_check("203.0.113.7")
    assert len(canary._rate_state) < before
    # The active IP survives; the stale ones are gone.
    assert "203.0.113.7" in canary._rate_state


# ── MCP transport config ─────────────────────────────────────────────────


def test_mcp_transport_defaults_to_stdio():
    from honeypot_mcp.config import Settings

    assert Settings().mcp_transport == "stdio"


def test_mcp_transport_accepts_http_case_insensitive(monkeypatch):
    from honeypot_mcp.config import Settings

    monkeypatch.setenv("MCP_TRANSPORT", "HTTP")
    assert Settings().mcp_transport == "http"


def test_mcp_transport_rejects_garbage(monkeypatch):
    import pytest as _pytest

    from honeypot_mcp.config import Settings

    monkeypatch.setenv("MCP_TRANSPORT", "carrier-pigeon")
    with _pytest.raises(ValueError, match="mcp_transport"):
        Settings()


def test_mcp_transport_accepts_collector_mode(monkeypatch):
    """`none` runs the capture plane with no control plane — the only mode that
    works in a detached container, where stdio reads EOF and exits at once."""
    from honeypot_mcp.config import Settings

    monkeypatch.setenv("MCP_TRANSPORT", "none")
    assert Settings().mcp_transport == "none"


@pytest.mark.asyncio
async def test_collector_mode_runs_lifespan_and_stops_on_signal(monkeypatch):
    """_run_collector must actually enter the lifespan (so honeypots, the
    watchdog and webhook delivery come up) and unblock when signalled."""
    import signal as _signal
    from contextlib import asynccontextmanager

    from honeypot_mcp import server

    entered = asyncio.Event()

    @asynccontextmanager
    async def fake_lifespan(_app):
        entered.set()
        yield

    monkeypatch.setattr(server, "lifespan", fake_lifespan)

    task = asyncio.create_task(server._run_collector())
    await asyncio.wait_for(entered.wait(), timeout=5)
    assert not task.done(), "collector should stay running until signalled"

    # The real stop path: the handler _run_collector registered for SIGINT.
    asyncio.get_running_loop().call_soon(lambda: _signal.raise_signal(_signal.SIGINT))
    await asyncio.wait_for(task, timeout=5)


# ── Prometheus /metrics ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_metrics_endpoint_returns_text_format():
    """Bring up the metrics server and confirm `/metrics` returns Prometheus
    text-format exposition."""
    import httpx

    from honeypot_mcp.metrics import start_metrics_server

    port = _free_port()
    runner = await start_metrics_server("127.0.0.1", port)
    assert runner is not None
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"http://127.0.0.1:{port}/metrics")
    finally:
        await runner.cleanup()

    assert r.status_code == 200
    assert "text/plain" in r.headers["Content-Type"]
    body = r.text
    # Required metric names appear (zero-value counters are fine)
    assert "honeypot_active_honeypots" in body
    # Must contain HELP/TYPE comments for at least one metric
    assert "# HELP" in body
    assert "# TYPE" in body


@pytest.mark.asyncio
async def test_metrics_endpoint_counts_alerts_by_severity():
    """Seed a few alerts then scrape /metrics; the severity counters reflect
    what was written."""
    import httpx

    from honeypot_mcp.metrics import start_metrics_server
    from honeypot_mcp.storage import queries
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import AlertSeverity

    async with get_session() as session:
        for severity in (AlertSeverity.HIGH, AlertSeverity.HIGH, AlertSeverity.CRITICAL):
            await queries.create_alert(
                session,
                honeypot_id=None,
                source_ip="1.2.3.4",
                source_port=None,
                event_type="metric_test",
                payload={},
                severity=severity,
            )

    port = _free_port()
    runner = await start_metrics_server("127.0.0.1", port)
    assert runner is not None
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"http://127.0.0.1:{port}/metrics")
    finally:
        await runner.cleanup()

    body = r.text
    assert 'honeypot_alerts_total{severity="high"} 2' in body
    assert 'honeypot_alerts_total{severity="critical"} 1' in body


# ── MCP control-plane authentication ─────────────────────────────────────────


def _settings_ns(transport, token="", allow=False, tokens=""):
    from types import SimpleNamespace

    return SimpleNamespace(
        mcp_transport=transport,
        mcp_auth_token=token,
        mcp_auth_tokens=tokens,
        mcp_allow_unauthenticated=allow,
    )


def test_stdio_never_requires_auth():
    from honeypot_mcp.server import _networked_auth_error

    assert _networked_auth_error(_settings_ns("stdio")) is None


def test_collector_mode_never_requires_auth():
    """Collector mode exposes no control plane, so there is nothing to gate."""
    from honeypot_mcp.server import _networked_auth_error

    assert _networked_auth_error(_settings_ns("none")) is None


def test_networked_without_token_is_refused():
    from honeypot_mcp.server import _networked_auth_error

    err = _networked_auth_error(_settings_ns("http"))
    assert err is not None
    assert "MCP_AUTH_TOKEN" in err


def test_networked_with_token_is_allowed():
    from honeypot_mcp.server import _networked_auth_error

    assert _networked_auth_error(_settings_ns("http", token="s3cret")) is None


def test_networked_unauthenticated_override_is_allowed():
    from honeypot_mcp.server import _networked_auth_error

    assert _networked_auth_error(_settings_ns("http", allow=True)) is None


def test_build_auth_none_for_stdio():
    from honeypot_mcp.server import _build_auth

    # Default transport is stdio → no auth provider.
    assert _build_auth() is None


def test_build_auth_verifier_for_networked_token(monkeypatch):
    from honeypot_mcp import config
    from honeypot_mcp.server import _build_auth

    monkeypatch.setenv("MCP_TRANSPORT", "http")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "abc123")
    monkeypatch.setattr(config, "_settings", None)  # force re-read
    try:
        auth = _build_auth()
        assert auth is not None
        assert type(auth).__name__ == "StaticTokenVerifier"
    finally:
        monkeypatch.setattr(config, "_settings", None)  # don't leak to other tests


# ── Packaging ────────────────────────────────────────────────────────────────


def test_bundled_presets_load_from_the_installed_package():
    """Presets must resolve through package resources, not the repo layout.

    They previously lived in `config/suppression_presets/` beside the source
    tree, with a fallback that resolved to a path inside site-packages which
    never exists. A pip-installed user therefore saw zero bundled presets from
    a feature the README advertises and DEPLOY.md tells you to use before going
    live — and nothing failed loudly, the list was simply empty.
    """
    from honeypot_mcp.tools.integrations import _list_available_presets, _read_preset

    available = set(_list_available_presets())
    assert {"shodan", "censys", "internal-rfc1918"} <= available, available

    for name in ("shodan", "censys", "internal-rfc1918"):
        text = _read_preset(name)
        assert text and "rules:" in text, f"{name} preset did not load"


def test_console_asset_ships_with_the_package():
    """The console serves a 500 if its HTML is not packaged."""
    from importlib.resources import files

    page = files("honeypot_mcp") / "console" / "static" / "index.html"
    assert page.is_file()
    assert "HoneyPot MCP" in page.read_text(encoding="utf-8")


def test_declared_version_is_parseable_and_matches_dunder():
    from importlib.metadata import version

    import honeypot_mcp

    installed = version("honeypot-mcp")
    assert installed == honeypot_mcp.__version__, (
        f"pyproject version {installed} != __init__ {honeypot_mcp.__version__}"
    )
