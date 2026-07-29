"""Cowrie has to emit JSON on stdout or the SSH honeypot captures nothing.

`SSHEngine._ingest_logs` reads `container.logs()` and `json.loads` each line,
skipping anything that does not parse. Cowrie's stdout is Twisted's *text* log,
so with the image defaults every single line was skipped: the container ran,
answered SSH, recorded the whole attack in its own logs, reported healthy to
the watchdog — and produced zero alerts. Silent total capture failure in the
engine SSH honeypots exist for.

`cowrie_env_vars` fixes it by redirecting Cowrie's jsonlog output to stdout.
Both settings are load-bearing:

* `COWRIE_OUTPUT_JSONLOG_LOGFILE=/proc/self/fd/1` — where the JSON goes.
* `COWRIE_HONEYPOT_LOGTYPE=plain` — *how* it is opened. The image default,
  `rotating`, wraps the path in Twisted's `LogFile`, which seeks on open and
  raises `OSError: [Errno 29] Illegal seek` against a pipe. That takes the
  whole jsonlog plugin down at startup ("Failed to load output engine:
  jsonlog") while Cowrie itself starts normally — so the failure looks exactly
  like the original bug. `plain` uses a bare `open(path, "w")`, which a pipe
  accepts.

These assertions are deliberately about the literal values. Anything that
"tidies" them reintroduces a bug with no visible symptom.
"""

from __future__ import annotations

import json
import os

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


def _env() -> dict[str, str]:
    from honeypot_mcp.engines.ssh_personas import (
        cowrie_env_vars,
        get_persona,
        pick_random_persona_id,
    )

    persona = get_persona(pick_random_persona_id())
    return cowrie_env_vars(persona, "test-host")


def test_json_output_is_enabled_and_points_at_stdout():
    env = _env()
    assert env["COWRIE_OUTPUT_JSONLOG_ENABLED"] == "true"
    assert env["COWRIE_OUTPUT_JSONLOG_LOGFILE"] == "/proc/self/fd/1"


def test_logtype_is_plain_not_rotating():
    """`rotating` seeks on open and kills the jsonlog plugin on a pipe."""
    assert _env()["COWRIE_HONEYPOT_LOGTYPE"] == "plain"


def test_every_persona_carries_the_json_settings():
    """A persona added later must not be able to opt out of capture."""
    from honeypot_mcp.engines.ssh_personas import _PERSONAS, cowrie_env_vars

    required = {
        "COWRIE_HONEYPOT_LOGTYPE",
        "COWRIE_OUTPUT_JSONLOG_ENABLED",
        "COWRIE_OUTPUT_JSONLOG_LOGFILE",
    }
    assert _PERSONAS, "no personas defined"
    for persona_id, persona in _PERSONAS.items():
        env = cowrie_env_vars(persona, "h")
        assert required <= env.keys(), f"persona {persona_id} would capture nothing"


@pytest.mark.parametrize(
    "line",
    [
        # Verbatim from a real container, trimmed. The mix matters: the parser
        # must take the JSON and skip the Twisted text around it.
        '{"eventid":"cowrie.session.connect","src_ip":"192.168.65.1","src_port":48162,'
        '"session":"2192b6a3baea","protocol":"ssh","message":"New connection"}',
        '{"eventid":"cowrie.login.success","username":"admin","password":"password123",'
        '"src_ip":"192.168.65.1","session":"2192b6a3baea"}',
        '{"eventid":"cowrie.command.input","input":"cat /etc/passwd",'
        '"src_ip":"192.168.65.1","session":"2192b6a3baea"}',
    ],
)
def test_real_cowrie_json_maps_to_an_event_type(line):
    """The events we rely on are in `_EVENT_MAP` under their real eventids."""
    from honeypot_mcp.engines.ssh import _EVENT_MAP

    eventid = json.loads(line)["eventid"]
    assert eventid in _EVENT_MAP, f"{eventid} would be dropped by the ingester"


def test_twisted_text_log_lines_are_not_json():
    """Documents why the bug was invisible: these are what stdout used to be."""
    for line in (
        "2026-07-29T06:01:08+0000 [-] Ready to accept SSH connections",
        "2026-07-29T06:01:08+0000 [HoneyPotSSHTransport,0,192.168.65.1] avatar admin logging out",
    ):
        with pytest.raises(ValueError):
            json.loads(line)
