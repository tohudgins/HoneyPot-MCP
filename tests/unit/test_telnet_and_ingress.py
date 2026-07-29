"""Telnet is its own attack surface, and downloads come in, not out.

Two analyst-facing defects that both came from taking Cowrie's event ids at
face value.

**Telnet was recorded as SSH.** One Cowrie container serves both protocols and
their event ids are identical — a Telnet login emits `cowrie.login.success`
exactly like an SSH one, distinguished only by the `protocol` field. Everything
was filed under `ssh_*`, so Telnet vanished as a distinct surface in every
dashboard and statistic, ATT&CK attributed it to SSH, and planted credentials
tried over Telnet were cross-referenced against the wrong service. Telnet on 23
is a large share of internet background radiation (Mirai and its descendants),
so it is worth counting on its own.

**File downloads were mapped to Exfiltration.** Cowrie's
`session.file_download` fires when the attacker pulls a payload *into* the
honeypot — `wget http://…/bins.sh` is the defining Mirai behaviour. Filing that
under Exfiltration inverts the direction of the most valuable artifact a
honeypot produces, and it is the kind of error a SOC analyst spots immediately.
"""

from __future__ import annotations

import os

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"


@pytest.mark.parametrize(
    ("event_type", "protocol", "expected"),
    [
        ("ssh_login_success", "telnet", "telnet_login_success"),
        ("ssh_login_failed", "telnet", "telnet_login_failed"),
        ("ssh_command_input", "telnet", "telnet_command_input"),
        ("ssh_session_connect", "telnet", "telnet_session_connect"),
        # SSH and anything unlabelled stay exactly as they are.
        ("ssh_login_success", "ssh", "ssh_login_success"),
        ("ssh_login_success", None, "ssh_login_success"),
    ],
)
def test_events_are_retagged_by_cowrie_protocol(event_type, protocol, expected):
    from honeypot_mcp.engines.ssh import _retag_for_protocol

    assert _retag_for_protocol(event_type, protocol) == expected


def test_retagging_only_rewrites_the_ssh_prefix():
    """A non-`ssh_` type must pass through untouched rather than gain a prefix."""
    from honeypot_mcp.engines.ssh import _retag_for_protocol

    assert _retag_for_protocol("honeypot_health_failed", "telnet") == "honeypot_health_failed"


def test_telnet_is_a_known_credential_matching_service():
    """Otherwise a planted credential tried over Telnet matches nothing."""
    from honeypot_mcp.credential_match import _infer_service

    assert _infer_service("telnet_login_failed") == "telnet"
    assert _infer_service("ssh_login_failed") == "ssh"


def test_cowrie_file_upload_is_ingested():
    """An eventid missing from `_EVENT_MAP` is silently dropped by the ingester.

    SCP/SFTP pushes of a payload carry the same value as a wget download.
    """
    from honeypot_mcp.engines.ssh import _EVENT_MAP

    assert "cowrie.session.file_upload" in _EVENT_MAP
    assert "cowrie.session.file_download" in _EVENT_MAP


@pytest.mark.parametrize(
    "event_type",
    ["ssh_file_download", "ssh_file_upload", "telnet_file_download", "telnet_file_upload"],
)
async def test_payload_transfer_into_the_honeypot_is_ingress_not_exfiltration(event_type):
    from honeypot_mcp.intel.mitre import map_to_attack

    result = await map_to_attack([event_type])
    ids = {t["technique_id"] for t in result}
    tactics = {t["tactic"] for t in result}

    assert "T1105" in ids, f"{event_type} should map to Ingress Tool Transfer"
    assert "T1041" not in ids, (
        f"{event_type} is a download *into* the honeypot; mapping it to "
        "Exfiltration reverses the direction of the attack"
    )
    assert "Exfiltration" not in tactics


@pytest.mark.parametrize("event_type", ["postgresql_lo_export", "mysql_outfile_/tmp/x", "sftp_get"])
async def test_genuine_exfiltration_still_maps_to_t1041(event_type):
    """Narrowing the rule must not remove real exfil coverage."""
    from honeypot_mcp.intel.mitre import map_to_attack

    result = await map_to_attack([event_type])
    assert "T1041" in {t["technique_id"] for t in result}


async def test_telnet_keeps_the_same_attack_coverage_as_ssh():
    """Retagging must not drop an event out of the ATT&CK mappings."""
    from honeypot_mcp.intel.mitre import map_to_attack

    for ssh_type, telnet_type in [
        ("ssh_login_failed", "telnet_login_failed"),
        ("ssh_command_input", "telnet_command_input"),
    ]:
        ssh_ids = {t["technique_id"] for t in await map_to_attack([ssh_type])}
        telnet_ids = {t["technique_id"] for t in await map_to_attack([telnet_type])}
        assert ssh_ids and ssh_ids == telnet_ids, f"{telnet_type} lost coverage vs {ssh_type}"
