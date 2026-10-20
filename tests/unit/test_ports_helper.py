"""`tests/_ports.py` hands out ports that cannot collide across xdist workers or pytest runs."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

from tests import _ports
from tests._ports import free_port, free_port_range

ROOT = Path(__file__).resolve().parents[2]


def test_ports_are_unique_bindable_and_outside_every_ephemeral_range():
    ports = [free_port() for _ in range(50)]
    assert len(set(ports)) == 50
    for port in ports:
        assert _ports._LOW <= port < _ports._LOW + _ports._SLICE * _ports._SLICES
        assert port < 32768  # below the Linux and macOS/BSD ephemeral ranges
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(socket.AF_INET, kind) as probe:
                probe.bind(("0.0.0.0", port))


def test_a_port_in_use_by_something_else_is_never_offered():
    taken = free_port()
    # Give up our claim and let an unrelated socket hold the port, as a real service would, then
    # park the cursor on it: the lock is free again, so only the bind probe can reject it.
    os.close(_ports._held.pop(taken))
    with socket.socket() as squatter:
        squatter.bind(("0.0.0.0", taken))
        squatter.listen()
        _ports._cursor = taken - _ports._LOW
        assert free_port() != taken


def test_a_range_is_consecutive_and_reserved():
    low, high = free_port_range(5)
    assert high - low == 4
    taken = {free_port() for _ in range(20)}
    assert not taken & set(range(low, high + 1))


_CHILD = (
    "import json, sys\n"
    "from tests._ports import free_port\n"
    "print(json.dumps([free_port() for _ in range(40)]), flush=True)\n"
    "sys.stdin.read()  # keep the claims until the parent has heard from every child\n"
)


def test_two_processes_never_share_a_port():
    # No PYTEST_XDIST_WORKER in the children's slice choice would matter here: they inherit this
    # process's environment, so several pytest runs on one machine (each with a `gw0`) are
    # modelled by children that share a slice. The cross-process lock is what keeps them apart.
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _CHILD],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        for _ in range(4)
    ]
    try:
        sets = [set(json.loads(proc.stdout.readline())) for proc in procs]
    finally:
        for proc in procs:
            proc.stdin.close()
            proc.wait(timeout=30)
    assert all(len(s) == 40 for s in sets)
    for i, a in enumerate(sets):
        for b in sets[i + 1 :]:
            assert not a & b
