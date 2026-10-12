"""Decoy tells found by running real nmap scripts against the live droplet.

Each of these was visible in the output of a stock NSE script: an LDAP rootDSE clock six days in the
past (`ldap-rootdse`), a MySQL connection id that was always 12345 (`mysql-info`), uptimes that
never advanced (`mongodb-info`, `redis-info`), and three different kernels reported by engines that
share one IP (`redis-info`, `docker-version`, the Kubernetes node). A real server's time and
counters move and one machine has one kernel.
"""

from __future__ import annotations

import re
import struct
from datetime import UTC, datetime, timedelta


def _root_dse_values(raw: bytes) -> dict[str, list[str]]:
    """Pull attribute names and values out of the BER rootDSE by scanning the printable runs."""
    return {
        "currentTime": re.findall(rb"\d{14}\.0Z", raw)
        and [m.decode() for m in re.findall(rb"\d{14}\.0Z", raw)]
    }


def test_the_ldap_root_dse_reports_the_real_time():
    from honeypot_mcp.engines.ldap import build_root_dse, directory_time

    assert directory_time(datetime(2026, 10, 12, 15, 43, 30, tzinfo=UTC)) == "20261012154330.0Z"
    before = datetime.now(UTC).replace(microsecond=0)
    stamp = _root_dse_values(build_root_dse(7, ["currentTime"]))["currentTime"][0]
    shown = datetime.strptime(stamp[:14], "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    assert before <= shown <= before + timedelta(seconds=5), "the clock must not be frozen"
    assert stamp != "20261006201500.0Z"


def test_the_ldap_root_dse_keeps_the_clock_when_all_attributes_are_requested():
    from honeypot_mcp.engines.ldap import build_root_dse

    raw = build_root_dse(7, [])
    assert b"currentTime" in raw and re.search(rb"\d{14}\.0Z", raw)


def test_mysql_connection_ids_count_up_instead_of_always_being_12345():
    from honeypot_mcp.engines import mysql

    ids = [next(mysql._CONNECTION_IDS) for _ in range(4)]
    assert ids == sorted(set(ids)) and 12345 not in ids[:1] + ids[-1:]
    packet = mysql._build_handshake_packet(b"A" * 8, b"B" * 12, 4321)
    assert struct.pack("<I", 4321) in packet and struct.pack("<I", 12345) not in packet


def test_uptimes_keep_counting(monkeypatch):
    from honeypot_mcp.engines import _uptime, mongodb, redis

    clock = {"now": 1000.0}
    monkeypatch.setattr(_uptime.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(_uptime, "_STARTED", 1000.0)

    first = mongodb._server_status_reply()["uptimeEstimate"]
    redis_first = int(re.search(r"uptime_in_seconds:(\d+)", redis._info_response()).group(1))
    clock["now"] += 3600  # an hour later
    second = mongodb._server_status_reply()["uptimeEstimate"]
    redis_second = int(re.search(r"uptime_in_seconds:(\d+)", redis._info_response()).group(1))

    assert first == redis_first == _uptime.BASE_UPTIME_SECONDS
    assert second - first == 3600 and redis_second - redis_first == 3600
    status = mongodb._server_status_reply()
    assert status["uptimeMillis"] == status["uptime"] * 1000 == status["uptimeEstimate"] * 1000


def test_every_engine_on_the_host_reports_the_same_kernel_and_os():
    from honeypot_mcp.engines import _host_identity as host
    from honeypot_mcp.engines import docker_api, kubernetes, redis

    assert f"os:Linux {host.KERNEL_RELEASE} x86_64" in redis._info_response()
    assert docker_api._KERNEL_VERSION == host.KERNEL_RELEASE
    node = kubernetes._Cluster("any-seed").nodes()[0]["status"]["nodeInfo"]
    assert node["kernelVersion"] == host.KERNEL_RELEASE and node["osImage"] == host.OS_PRETTY_NAME


def _stats(uptime: int, conn_id: int = 1) -> dict[str, str]:
    from honeypot_mcp.engines.memcached import _stats_lines

    return dict(line.split(" ", 2)[1:] for line in _stats_lines(uptime, conn_id))


def test_memcached_stats_keep_working_between_scans():
    """`memcached-info` printed the same pid and a restarted uptime on every connection."""
    from honeypot_mcp.engines.memcached import _BASE_UPTIME_SECONDS as base

    first, later = _stats(base), _stats(base + 3600, conn_id=9)
    assert first["pid"] == later["pid"], "a daemon keeps its pid across connections"
    assert int(later["uptime"]) - int(first["uptime"]) == 3600
    for counter in ("cmd_get", "cmd_set", "bytes_read", "bytes_written", "total_items"):
        assert int(later[counter]) > int(first[counter]), counter
    for stats in (first, later):
        assert int(stats["get_hits"]) + int(stats["get_misses"]) == int(stats["cmd_get"])
        assert stats["cmd_set"] == stats["total_items"]
