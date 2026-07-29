"""Unit tests for MITRE ATT&CK mapper."""

import pytest

from honeypot_mcp.intel.mitre import map_to_attack


@pytest.mark.asyncio
async def test_ssh_brute_force_maps_to_t1110():
    results = await map_to_attack(["ssh_login_failed", "ssh brute force attempt"])
    ids = [r["technique_id"] for r in results]
    assert "T1110.001" in ids


@pytest.mark.asyncio
async def test_port_scan_maps_to_t1046():
    results = await map_to_attack(["port_scan", "nmap detected"])
    ids = [r["technique_id"] for r in results]
    assert "T1046" in ids


@pytest.mark.asyncio
async def test_dns_canary_maps_to_c2():
    results = await map_to_attack(["dns_canary_callback"])
    ids = [r["technique_id"] for r in results]
    assert "T1071.004" in ids


@pytest.mark.asyncio
async def test_empty_terms_returns_empty():
    results = await map_to_attack([])
    assert results == []


@pytest.mark.asyncio
async def test_unknown_terms_returns_empty():
    results = await map_to_attack(["totally_unknown_event_xyz_abc"])
    assert results == []


@pytest.mark.asyncio
async def test_results_have_required_fields():
    results = await map_to_attack(["ssh_login_failed"])
    for r in results:
        assert "technique_id" in r
        assert "technique_name" in r
        assert "tactic" in r
        assert "url" in r
        assert "matched_by" in r


@pytest.mark.asyncio
async def test_deduplication():
    results = await map_to_attack(["ssh_login_failed", "ssh brute", "ssh failed login"])
    ids = [r["technique_id"] for r in results]
    assert len(ids) == len(set(ids))  # No duplicates


# ── Coverage of what the engines actually capture ────────────────────────────
#
# An unmapped capture is invisible in the ATT&CK dashboard and the kill-chain
# timeline, so the platform's headline detections each need a technique. These
# also guard the tactic labels: analysts know ATT&CK, and a technique filed
# under the wrong tactic discredits every other number on the page.


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("event_type", "expected_technique", "expected_tactic"),
    [
        ("redis_rce_dropper", "T1059", "Execution"),
        ("postgresql_copy_program_rce", "T1059", "Execution"),
        ("mysql_udf_rce", "T1059", "Execution"),
        ("mongodb_ransom_note", "T1486", "Impact"),
        ("mongodb_destructive", "T1485", "Impact"),
        ("mysql_outfile_write", "T1505.003", "Persistence"),
        ("smb_exploit_attempt", "T1210", "Lateral Movement"),
        ("rdp_mcs_handshake", "T1021.001", "Lateral Movement"),
        ("dns_tunneling_suspected", "T1071.004", "Command and Control"),
        ("smtp_open_relay", "T1071.003", "Command and Control"),
        ("elasticsearch_data_access", "T1213", "Collection"),
        ("dns_zone_transfer", "T1590.002", "Reconnaissance"),
        ("ftp_file_upload", "T1105", "Command and Control"),
    ],
)
async def test_engine_captures_map_to_expected_technique(
    event_type, expected_technique, expected_tactic
):
    results = await map_to_attack([event_type])
    pairs = {(r["technique_id"], r["tactic"]) for r in results}
    assert (expected_technique, expected_tactic) in pairs, (
        f"{event_type} produced {pairs or 'nothing'}"
    )


@pytest.mark.asyncio
async def test_brute_force_is_credential_access_for_every_protocol():
    """T1110 is Credential Access in ATT&CK. An earlier revision filed the
    SSH/FTP/RDP variants under Initial Access while filing the identical
    technique under Credential Access three entries later."""
    for event_type in (
        "ssh_login_failed",
        "ftp_login_attempt",
        "rdp_connection_login",
        "smtp_auth_attempt",
        "vnc_auth_attempt",
        "mysql_login_attempt",
        "mssql_login_attempt",
        "postgresql_login_attempt",
        "redis_auth_attempt",
    ):
        results = await map_to_attack([event_type])
        brute = [r for r in results if r["technique_id"].startswith("T1110")]
        assert brute, f"{event_type} did not map to a brute-force technique"
        assert all(r["tactic"] == "Credential Access" for r in brute), (
            f"{event_type} filed T1110 under {[r['tactic'] for r in brute]}"
        )


@pytest.mark.asyncio
async def test_exploit_is_not_mistaken_for_brute_force():
    """`smb_exploit_attempt` contains 'attempt' but is not a password guess;
    mislabelling it inflates Credential Access and buries the Lateral Movement
    finding that actually matters."""
    results = await map_to_attack(["smb_exploit_attempt"])
    assert not [r for r in results if r["technique_id"].startswith("T1110")]


@pytest.mark.asyncio
async def test_unrecognised_input_maps_to_nothing():
    """The mapper must not invent techniques for arbitrary strings."""
    assert await map_to_attack(["completely_unrelated_gibberish_xyz"]) == []
