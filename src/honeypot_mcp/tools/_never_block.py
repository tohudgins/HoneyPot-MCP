"""Networks that must never reach a blocklist export.

The operator's own allowlist plus this server's own canary address. A spoofed or
reflected hit "from" our own public IP would otherwise get the sensor's callback
endpoint blocked by the operator's own firewall.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def never_block_networks() -> list[IPNetwork]:
    """Return the networks a blocklist must not contain.

    Raises ValueError on a malformed allowlist entry: an entry the operator
    wrote to protect something must not silently become a no-op.
    """
    from honeypot_mcp.config import get_settings

    settings = get_settings()
    nets: list[IPNetwork] = []
    for raw in settings.blocklist_allowlist.split(","):
        entry = raw.strip()
        if not entry:
            continue
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            raise ValueError(
                f"BLOCKLIST_ALLOWLIST entry {entry!r} is not an IP address or CIDR; "
                "refusing to export until it is fixed."
            ) from None
    own_hosts = [settings.canary_callback_host, urlparse(settings.canary_public_url).hostname]
    for host in own_hosts:
        if not host:
            continue
        try:
            nets.append(ipaddress.ip_network(ipaddress.ip_address(host)))
        except ValueError:
            continue  # a hostname, not an IP literal
    return nets
