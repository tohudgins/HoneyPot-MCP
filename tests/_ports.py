"""Ports for tests that start a listener and need its number up front.

The pattern this replaces, `s.bind(("", 0)); port = s.getsockname()[1]; s.close()`, is a
check-then-bind race: between the close and the engine's own `bind` the kernel is free to hand
the same number to anyone, and under `pytest -n N` the "anyone" is another worker doing the
same thing (or an outgoing connection's ephemeral source port). It failed as
`OSError: [Errno 48] Address already in use` roughly once in a few dozen parallel runs and
never when run alone.

`free_port()` removes the race instead of narrowing it:

* every worker draws from its own slice of a range that lies *below* both the Linux (32768) and
  macOS/BSD (49152) ephemeral ranges, so a client socket can never be handed the number;
* a number is *reserved* by an advisory `flock` on a per-port file, held until the process
  exits (and released by the kernel if it dies), so two workers, or two concurrent pytest runs,
  can never both own it;
* a port is never handed out twice by one process, so a listener that has just been closed
  (and may still be in TIME_WAIT) cannot be reused by the next test;
* a candidate that something outside the test suite already holds (TCP or UDP, any address) is
  skipped, because the bind probe fails on it.

Where the code under test can bind port 0 and report the real port, that is still better, and
the tests that can do so already read `server.sockets[0].getsockname()[1]` after binding.
"""

from __future__ import annotations

import os
import random
import socket
import tempfile
from pathlib import Path

try:  # POSIX only; the suite's Docker/firewall tests are Linux/macOS anyway
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

# Below Linux's 32768 and macOS's 49152 ephemeral ranges, above the well-known/registered
# services most hosts run.
_LOW = 12000
_SLICE = 1000
_SLICES = 20  # worker gw0..gw19 get their own slice; more wrap around and rely on the lock

_LOCK_DIR = Path(tempfile.gettempdir()) / f"honeypot-mcp-test-ports-{os.getuid()}"

_held: dict[int, int] = {}  # port -> open lock fd, kept for the life of the process
_cursor: int | None = None


def _worker_index() -> int:
    worker = os.environ.get("PYTEST_XDIST_WORKER", "gw0")
    digits = "".join(c for c in worker if c.isdigit())
    return int(digits) if digits else 0


def _reserve(port: int) -> bool:
    """Take the cross-process claim on `port`; False if another process owns it."""
    if fcntl is None:  # pragma: no cover
        _held[port] = -1
        return True
    _LOCK_DIR.mkdir(parents=True, exist_ok=True)
    fd = os.open(_LOCK_DIR / f"{port}.lock", os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return False
    _held[port] = fd
    return True


def _bindable(port: int) -> bool:
    """True when nothing holds `port` for TCP or UDP on any address."""
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        with socket.socket(socket.AF_INET, kind) as probe:
            try:
                probe.bind(("0.0.0.0", port))
            except OSError:
                return False
    return True


def free_port() -> int:
    """A port nothing is listening on, that no other test process will be given."""
    global _cursor
    span = _SLICE * _SLICES
    if _cursor is None:
        # Start inside this worker's own slice, at a random offset: concurrent pytest runs
        # each have a gw0, and a fixed start would make them all contend for the same ports.
        _cursor = (_worker_index() % _SLICES) * _SLICE + random.SystemRandom().randrange(_SLICE)
    for _ in range(span):
        port = _LOW + _cursor
        _cursor = (_cursor + 1) % span  # spills into the next slices once this one is used up
        if port in _held:
            continue
        if _reserve(port) and _bindable(port):
            return port
        # Claimed by another process, or held by something outside the suite: never offer it.
    raise RuntimeError(f"no free test port left in {_LOW}-{_LOW + span}")


def free_port_range(size: int) -> tuple[int, int]:
    """`(low, high)`, `high - low + 1 == size`: consecutive ports, all reserved and unbound."""
    global _cursor
    span = _SLICE * _SLICES
    if _cursor is None:
        free_port()  # seeds the cursor inside this worker's slice
    for _ in range(span):
        start = _cursor
        if start + size > span:  # never straddle the wrap
            _cursor = 0
            continue
        ports = [_LOW + start + i for i in range(size)]
        if all(p not in _held for p in ports) and all(_reserve(p) and _bindable(p) for p in ports):
            _cursor = start + size
            return ports[0], ports[-1]
        _cursor = start + 1
    raise RuntimeError(f"no run of {size} free test ports left in {_LOW}-{_LOW + span}")
