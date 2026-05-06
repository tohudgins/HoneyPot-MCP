"""Shodan removed — replaced by AbuseIPDB + GreyNoise (both free).

Import from honeypot_mcp.intel.abuseipdb or honeypot_mcp.intel.greynoise instead.
This file is kept as a placeholder to avoid breaking any cached imports.
"""

from honeypot_mcp.intel.abuseipdb import lookup_abuseipdb as lookup_shodan  # noqa: F401

__all__ = ["lookup_shodan"]
