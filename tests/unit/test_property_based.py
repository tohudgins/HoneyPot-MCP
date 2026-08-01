"""Property-based tests for the pure functions attacker-controlled data
reaches most directly.

Different technique from the rest of the suite: example-based unit tests
pin specific known-important cases; the mutation fuzzing done elsewhere this
session mutates one real seed against a live engine. This explores the input
*space* of isolated functions systematically — hypothesis generates hundreds
of adversarial cases per run (embedded nulls, unicode, extreme lengths,
empty/near-empty values) rather than the handful a person would think to
write by hand.

Two real bugs were found writing these, both fixed and pinned as regular
example-based tests too (so they show up without needing hypothesis
installed to fail): resolve_artifact_path crashed uncaught on an embedded
null byte instead of returning a clean rejection, and digest_payload could
leak a raw nested dict through a _DIGEST_KEYS field when the catch-all loop
for unrecognised keys explicitly excludes that same shape.
"""

from __future__ import annotations

import os

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

# Deadline off: some of these touch the filesystem (resolve_artifact_path
# calls .resolve(), which is a real syscall) and CI runners are slower than
# a laptop — a flaky timeout-based failure here would be about scheduling,
# not the code under test.
_SETTINGS = settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])

# A JSON-like recursive strategy for payload shapes: what an alert.payload
# actually looks like, but hypothesis explores combinations no one would
# hand-write (deep nesting, empty containers at every level, huge strings).
_json_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=200),
)
_json_value = st.recursive(
    _json_scalar,
    lambda children: st.one_of(
        st.lists(children, max_size=8),
        st.dictionaries(st.text(max_size=20), children, max_size=8),
    ),
    max_leaves=30,
)
_payload_dict = st.dictionaries(st.text(max_size=20), _json_value, max_size=15)


# ── resolve_artifact_path: the arbitrary-file-write boundary ────────────────


@_SETTINGS
@given(output_path=st.text(max_size=300))
def test_resolve_artifact_path_never_escapes_reports_dir_or_crashes(output_path):
    from pathlib import Path

    from honeypot_mcp.config import get_settings
    from honeypot_mcp.tools._format import resolve_artifact_path

    root = get_settings().reports_dir.resolve()
    result = resolve_artifact_path(output_path or None, prefix="fuzz", extension="txt")
    assert isinstance(result, (str, Path)), f"unexpected return type: {result!r}"
    if isinstance(result, Path):
        assert result == root or root in result.parents, (
            f"{output_path!r} escaped reports_dir to {result}"
        )


def test_resolve_artifact_path_null_byte_is_a_clean_rejection_not_a_crash():
    """Path.resolve() raises ValueError on an embedded null byte — this is
    the concrete case the hypothesis test above found. Pinned as an
    example-based test too, so it fails without hypothesis installed."""
    from honeypot_mcp.tools._format import resolve_artifact_path

    result = resolve_artifact_path("a\x00b.txt", prefix="x", extension="txt")
    assert isinstance(result, str)
    assert "not a usable path" in result


def test_resolve_artifact_path_unresolvable_tilde_user_is_a_clean_rejection():
    """Path.expanduser() raises RuntimeError for a `~user` form where `user`
    doesn't exist on the system (e.g. "~0") — a second, different exception
    type hypothesis found from the same call chain in the same run as the
    null-byte case above. Pinned separately since it's a distinct failure
    mode, not a duplicate."""
    from honeypot_mcp.tools._format import resolve_artifact_path

    result = resolve_artifact_path("~0", prefix="x", extension="txt")
    assert isinstance(result, str)
    assert "not a usable path" in result


# ── validate_honeypot_name: names become filesystem + Docker container paths ─


@_SETTINGS
@given(name=st.text(max_size=200))
def test_accepted_honeypot_names_are_always_path_safe(name):
    from honeypot_mcp.tools._format import validate_honeypot_name

    error = validate_honeypot_name(name)
    if error is None:
        assert "/" not in name and "\\" not in name
        assert ".." not in name
        assert "\x00" not in name
        assert 1 <= len(name) <= 64


# ── digest_payload / truncate_payload: never crash, respect size bounds ─────


@_SETTINGS
@given(payload=_payload_dict)
def test_digest_payload_never_crashes_and_bounds_string_length(payload):
    from honeypot_mcp.tools._format import _MAX_DIGEST_VALUE_CHARS, digest_payload

    digest = digest_payload(payload)
    assert isinstance(digest, dict)
    for value in digest.values():
        if isinstance(value, str):
            # The clip marker adds its own suffix, so allow generous headroom
            # rather than pinning the exact overhead string.
            assert len(value) <= _MAX_DIGEST_VALUE_CHARS + 60


@_SETTINGS
@given(payload=_payload_dict)
def test_truncate_payload_never_crashes_and_bounds_string_length(payload):
    from honeypot_mcp.tools._format import _MAX_FULL_VALUE_CHARS, truncate_payload

    def _check(node):
        if isinstance(node, dict):
            for v in node.values():
                _check(v)
        elif isinstance(node, str):
            assert len(node) <= _MAX_FULL_VALUE_CHARS + 60

    result = truncate_payload(payload)
    _check(result)


def test_digest_payload_does_not_leak_a_raw_nested_dict_through_a_known_key():
    """The catch-all loop for unrecognised keys explicitly skips nested
    dicts ("belong in the full payload"), but a _DIGEST_KEYS field (e.g.
    "command") going through _clip() has no such guard — _clip only
    special-cases str/list, so a dict value passes through unchanged. An
    engine that ever captures a structured (not string) command/path value
    would silently violate the digest's own stated contract."""
    from honeypot_mcp.tools._format import digest_payload

    payload = {"command": {"nested": "structure", "should": "not appear raw"}}
    digest = digest_payload(payload)
    assert not isinstance(digest.get("command"), dict), (
        f"digest_payload let a raw nested dict through a known key: {digest}"
    )


# ── credential_verify: fixed-shape crypto math over attacker-chosen bytes ───


@_SETTINGS
@given(
    salt=st.binary(min_size=0, max_size=64),
    auth_response=st.binary(min_size=0, max_size=64),
    candidate_password=st.text(max_size=200),
)
def test_verify_mysql_never_crashes(salt, auth_response, candidate_password):
    from honeypot_mcp.credential_verify import verify_mysql

    result = verify_mysql(salt, auth_response, candidate_password)
    assert isinstance(result, bool)


@_SETTINGS
@given(
    challenge=st.binary(min_size=0, max_size=64),
    response=st.binary(min_size=0, max_size=64),
    candidate_password=st.text(max_size=200),
)
def test_verify_vnc_never_crashes(challenge, response, candidate_password):
    from honeypot_mcp.credential_verify import verify_vnc

    result = verify_vnc(challenge, response, candidate_password)
    assert isinstance(result, bool)


@_SETTINGS
@given(password=st.text(max_size=200), salt=st.binary(min_size=20, max_size=20))
def test_verify_mysql_round_trips_for_the_correct_password(password, salt):
    """The positive case: a scramble genuinely computed from `password` and
    `salt` must verify against that same password (not just "never
    crashes" — it has to actually still work)."""
    from honeypot_mcp.credential_verify import mysql_native_token, verify_mysql

    token = mysql_native_token(password.encode("utf-8", "surrogatepass"), salt)
    assert verify_mysql(salt, token, password) is True
    assert verify_mysql(salt, token, password + "x") is False
