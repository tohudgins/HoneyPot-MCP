"""Telnet honeypot engine — Cowrie's telnet listener as a first-class type.

Telnet on port 23 is one of the largest single categories of unsolicited
internet traffic. Mirai and its descendants scan it continuously with a short
list of factory default credentials (`root/xc3511`, `admin/admin`,
`root/vizxv`), and a Telnet sensor fills with that traffic within minutes of
being exposed — usually faster than SSH.

Cowrie already implements this: one container serves SSH on 2222 and Telnet on
2223, sharing the same fake filesystem, command emulation and session logging.
Telnet used to be reachable only as `config={"telnet_enabled": True}` on an SSH
honeypot, which meant "deploy a telnet honeypot" did not work, the honeypot was
listed as type `ssh`, and its default port was SSH's. For a system whose whole
premise is being driven in natural language, a capability that exists but
cannot be asked for is close to not existing.

So this is a thin subclass: same image, same ingestion, same personas — it just
publishes 2223 instead of 2222 and switches Cowrie's telnet listener on. Event
retagging is already handled in `ssh.py:_retag_for_protocol`, which reads
Cowrie's `protocol` field, so captures land as `telnet_*` on either engine.
"""

from __future__ import annotations

import logging

from honeypot_mcp.engines.ssh import COWRIE_TELNET_PORT, SSHEngine

log = logging.getLogger(__name__)


class TelnetEngine(SSHEngine):
    """Cowrie with the telnet listener published as the primary service."""

    _PRIMARY_CONTAINER_PORT = COWRIE_TELNET_PORT
    _PRIMARY_IS_TELNET = True
