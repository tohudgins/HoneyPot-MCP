"""Source-address filters and address scopes for the analysis tools.

Nothing here decides what is "test traffic". Whether a loopback or private source is noise (the
operator's own probe of an internet-facing honeypot) or the whole signal (a LAN tripwire, a hostile
process on the host) depends on the deployment, so the tools never guess: the caller names what to set
aside (`parse_source_filters`), and every example says what kind of address it came from
(`source_scope`), taken from the standard `ipaddress` properties.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Iterable

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

# Entries per call: a filter list is a handful of addresses and ranges, not a blocklist.
MAX_FILTERS = 200


def parse_source_filters(values: Iterable[str] | None) -> tuple[list[Network], list[str]]:
    """(networks, errors) for a list of addresses and CIDR ranges.

    A bare address is a /32 (or /128). Anything that is not an address or a range is an error: a
    typo here would silently exclude nothing and look like a clean result."""
    items = list(values or [])
    networks: list[Network] = []
    errors: list[str] = []
    for raw in items[:MAX_FILTERS]:
        text = str(raw).strip()
        if not text:
            continue
        try:
            networks.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            errors.append(f"{text!r} is not an IP address or CIDR range")
    if len(items) > MAX_FILTERS:
        errors.append(f"at most {MAX_FILTERS} addresses or ranges per call")
    return networks, errors


def make_matcher(networks: list[Network]) -> Callable[[str], bool]:
    """A predicate `source_ip -> bool` for 'is inside one of these networks' (cached per address)."""
    cache: dict[str, bool] = {}

    def matches(source_ip: str) -> bool:
        hit = cache.get(source_ip)
        if hit is None:
            try:
                addr = ipaddress.ip_address(source_ip)
            except ValueError:
                hit = False
            else:
                hit = any(addr in net for net in networks if net.version == addr.version)
            cache[source_ip] = hit
        return hit

    return matches


def source_scope(source_ip: str) -> str:
    """What kind of address this is: public, private, loopback, link_local, multicast or
    other_non_public (for example the carrier-grade NAT range), or unparseable."""
    try:
        addr = ipaddress.ip_address(source_ip)
    except ValueError:
        return "unparseable"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private and not addr.is_global:
        return "private"
    return "public" if addr.is_global else "other_non_public"
