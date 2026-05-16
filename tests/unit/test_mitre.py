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
