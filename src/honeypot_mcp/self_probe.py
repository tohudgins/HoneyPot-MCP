"""Keep the watchdog's own health probes out of the attack data.

Ten in-process engines log a bare `<proto>_connection` event the moment a TCP
peer connects — correctly, because on a honeypot an unsolicited connection *is*
the signal. The watchdog then connects to every running honeypot every 30s to
check it is still accepting connections, and each of those probes is
indistinguishable, at the engine, from a real one.

Left alone that is roughly 2,880 self-generated events per engine per day. On a
full deployment the alert table becomes mostly the tool observing itself:
`127.0.0.1` dominates "top attackers", volume charts measure the watchdog's
period rather than attacker activity, and every configured SIEM and webhook
receives the noise too. Measured on the demo stack, it was 33% of all rows with
only four honeypots running.

The fix is to match the probe's own socket rather than guess from its shape.
Before a probe's connection closes, `register()` records the local `(ip, port)`
the kernel assigned it; `claim()` in `submit_event` drops the one event that
arrives from exactly that address. Matching on the full tuple is what makes
this safe to do silently:

* The ephemeral port is bound by our socket for the probe's lifetime, so no
  other process can be sourcing traffic from it at the same time.
* Entries expire after `_TTL_SECONDS`, so a probe that somehow never produces
  an event cannot suppress a later, unrelated one.

Suppressing by rule instead — "drop `*_connection` from 127.0.0.1" — would have
been simpler and wrong: it also blinds the honeypot to anything genuinely
arriving over loopback, which is exactly what a container escape or a malicious
process on the host looks like.
"""

from __future__ import annotations

import logging
import time

log = logging.getLogger(__name__)

# Generous relative to the microseconds an event actually takes to reach
# `submit_event`, but short enough that a stale entry cannot outlive the
# 30s watchdog cycle that created it.
_TTL_SECONDS = 10.0

# (source_ip, source_port) -> monotonic deadline
_probes: dict[tuple[str, int], float] = {}


def register(sockname: object) -> None:
    """Record the local address of an outbound health probe.

    Accepts the raw return of `socket.getsockname()` /
    `transport.get_extra_info("sockname")`, which is a 2-tuple for IPv4 and a
    4-tuple for IPv6, and is `None` on a socket that never connected.
    """
    if not isinstance(sockname, tuple) or len(sockname) < 2:
        return
    host, port = sockname[0], sockname[1]
    if not isinstance(host, str) or not isinstance(port, int):
        return
    now = time.monotonic()
    _evict(now)
    _probes[(host, port)] = now + _TTL_SECONDS


def claim(source_ip: str | None, source_port: int | None) -> bool:
    """True if this event came from one of our own probes.

    A claim covers the whole probe connection, not one event, and stays valid
    until it expires. One connection routinely produces several events — Cowrie
    alone emits session-connect, client-version and session-closed — so
    consuming the claim on first use dropped the first and let the rest through,
    which is exactly what left `ssh_session_closed` in the alert stream after
    the connect had been suppressed.

    Leaving the entry in place until the TTL does mean a real connection from
    the identical `(ip, port)` inside the window would also be dropped. That
    needs an attacker to source traffic from the exact ephemeral port the
    watchdog just used, on the same host, within seconds, while that port sits
    in TIME_WAIT — and the payoff is hiding a couple of low-severity events.
    Against that, letting probes through is a certainty on every sweep.
    """
    if source_ip is None or source_port is None:
        return False
    now = time.monotonic()
    _evict(now)
    if (source_ip, source_port) not in _probes:
        return False
    log.debug("Dropped self-probe event from %s:%s", source_ip, source_port)
    return True


def _evict(now: float) -> None:
    if not _probes:
        return
    for key in [k for k, deadline in _probes.items() if deadline <= now]:
        _probes.pop(key, None)


def reset_for_tests() -> None:
    _probes.clear()


def pending_count() -> int:
    """Number of un-claimed probes still inside their TTL. Tests only."""
    _evict(time.monotonic())
    return len(_probes)
