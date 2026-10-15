#!/usr/bin/env python3
"""OPTIONAL live smoke test of the optional reputation providers.

NOT part of the test suite and never run by CI: it talks to the real vendor APIs. The unit tests
(tests/unit/test_intel_providers.py) already cover each provider against strict stubs of the
published contracts; this script is how an operator with keys checks that the contracts still match
the live services.

Keys come from the environment / .env, exactly as the server reads them:

    GREYNOISE_API_KEY   GreyNoise community   -> 8.8.8.8
    ABUSECH_AUTH_KEY    MalwareBazaar         -> the sample hash from abuse.ch's own API docs
                        URLhaus / ThreatFox   -> 8.8.8.8 (expected: not listed)
    OTX_API_KEY         AlienVault OTX        -> 8.8.8.8
    (no key)            Shodan InternetDB     -> 8.8.8.8 (enabled for this run automatically)

A provider with no key is reported "not configured" and skipped. Exit status is 1 if any provider
that WAS configured failed (auth rejected, rate limited, timed out, unexpected response).

    uv run python scripts/intel_smoke.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

# The keyless service is opt-in in the server; this script exists to exercise it.
os.environ.setdefault("SHODAN_INTERNETDB_ENABLED", "true")

IP = "8.8.8.8"
# The example hash printed in https://bazaar.abuse.ch/api/ (query a malware sample).
MALWAREBAZAAR_HASH = "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d"


async def main() -> int:
    from honeypot_mcp.intel import abusech, greynoise, internetdb, otx

    checks = [
        ("GreyNoise community", f"{IP}", greynoise.lookup_greynoise(IP)),
        ("Shodan InternetDB", f"{IP}", internetdb.lookup_internetdb(IP)),
        ("AlienVault OTX", f"{IP}", otx.lookup_otx(IP)),
        (
            "abuse.ch MalwareBazaar",
            MALWAREBAZAAR_HASH[:16] + "…",
            abusech.lookup_malwarebazaar(MALWAREBAZAAR_HASH),
        ),
        ("abuse.ch URLhaus host", IP, abusech.lookup_urlhaus_host(IP)),
        (
            "abuse.ch ThreatFox IOC",
            IP,
            abusech.lookup_threatfox(IP, exact=False, address_only=True),
        ),
    ]
    results = await asyncio.gather(*(c[2] for c in checks), return_exceptions=True)

    failed = 0
    for (name, subject, _coro), result in zip(checks, results, strict=True):
        if isinstance(result, BaseException):
            status, detail = "CRASH", repr(result)
            failed += 1
        elif result.get("available"):
            status, detail = "ok", json.dumps(result, default=str)[:400]
        elif "error" in result:
            status, detail = "FAILED", result["error"]
            failed += 1
        else:
            status, detail = "skipped", result.get("note", "")
        print(f"[{status:>7}] {name} ({subject})\n          {detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
