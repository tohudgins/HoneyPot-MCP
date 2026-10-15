"""The four optional reputation providers as one fan-out, for `enrich_ip` and alert enrichment.

Result keys: `greynoise`, `abusech`, `otx`, `internetdb`. A provider that is not configured is left
out (`include_unconfigured=False`, the stored-alert and notification paths: a stored alert should
not carry four "not configured" notes) or reported with its not-configured note
(`include_unconfigured=True`, the `enrich_ip` tool, so the caller learns what could be enabled).

Providers run concurrently and the whole fan-out has a deadline. Whatever answered in time is kept;
the rest become `{"available": False, "error": "timed out"}` and are cancelled. That is what lets a
notification add these lines without ever taking longer than the lookup it was already making.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from honeypot_mcp.intel import abusech, greynoise, internetdb, otx
from honeypot_mcp.intel._common import provider_timeout

log = logging.getLogger(__name__)

# key -> (configured?, lookup). Looked up through the module at call time so tests (and callers)
# patching a provider's `lookup_*` are honoured.
_PROVIDERS: dict[str, tuple[Callable[[], bool], Callable[[str], Awaitable[dict[str, Any]]]]] = {
    "greynoise": (greynoise.configured, lambda ip: greynoise.lookup_greynoise(ip)),
    "abusech": (abusech.configured, lambda ip: abusech.lookup_abusech_ip(ip)),
    "otx": (otx.configured, lambda ip: otx.lookup_otx(ip)),
    "internetdb": (internetdb.configured, lambda ip: internetdb.lookup_internetdb(ip)),
}


async def lookup_optional_providers(
    ip: str,
    *,
    include_unconfigured: bool = False,
    deadline: float | None = None,
) -> dict[str, dict[str, Any]]:
    """Query every configured optional provider for `ip`, within `deadline` seconds in total
    (default: the per-request provider timeout)."""
    chosen = {
        name: lookup
        for name, (is_configured, lookup) in _PROVIDERS.items()
        if include_unconfigured or is_configured()
    }
    if not chosen:
        return {}
    budget = deadline if deadline is not None else provider_timeout()
    tasks = {name: asyncio.ensure_future(lookup(ip)) for name, lookup in chosen.items()}
    _done, pending = await asyncio.wait(tasks.values(), timeout=budget)
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)

    out: dict[str, dict[str, Any]] = {}
    for name, task in tasks.items():
        if task in pending:
            out[name] = {"available": False, "error": f"timed out after {budget:g}s"}
            continue
        exc = task.exception()
        if exc is not None:
            log.warning("%s lookup raised: %s", name, exc)
            out[name] = {"available": False, "error": f"lookup failed: {type(exc).__name__}"}
        else:
            out[name] = task.result()
    return out
