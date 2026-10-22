"""Replay a capture through Suricata or Zeek, and keep the Suricata ruleset current.

`pcap_extract` writes one attacker's packets to a file; `pcap_detect` is the next step an analyst
used to do by hand with `suricata -r` or `zeek -r`. The engine runs in a sandboxed container with
no network (see `pcap_detect.py`), so these tools work against a live server, a restored backup in
ANALYSIS_MODE, and with packet capture switched off: they read a capture file and never touch the
honeypot sensors, so the read-only gate that blocks deploy/stop does not apply.

`detection_rules_update` is separate, and admin, because it is the one operation that gives a
container a network.
"""

from __future__ import annotations

from typing import Any, Literal

from honeypot_mcp import pcap_detect as detection
from honeypot_mcp.rbac import require_role
from honeypot_mcp.server import mcp
from honeypot_mcp.tool_hints import hints
from honeypot_mcp.tools import _audit
from honeypot_mcp.tools._format import mark_untrusted


@mcp.tool(auth=require_role("operator"), **hints("pcap_detect"))
async def pcap_detect(
    path: str | None = None,
    engine: Literal["suricata", "zeek"] = "suricata",
) -> dict[str, Any]:
    """Replay a saved packet capture through Suricata (or Zeek) and report what it detected.

    Use it for "what does Suricata say about 203.0.113.7?", "any signature hits?", "run Zeek on
    it". The engine runs in a throwaway container with no network (the capture is
    attacker-controlled); Docker must be running. Returns a digest: Suricata alerts by signature,
    category and severity plus protocol counts; Zeek connection, notice and protocol-log counts.
    Suricata uses the rules cached by `detection_rules_update`; with none it still runs and says
    `rules_loaded: 0`, so no alerts is not read as clean. Quoted text is attacker-controlled.

    Args:
        path: A capture file name or an attacker IP (its newest capture). Default: the newest
              capture. A wrong name returns the names that exist.
        engine: `suricata` (default, signatures) or `zeek` (protocol logs), if the user asks for Zeek.
    """
    result = await detection.detect(path, engine)
    ok = "error" not in result
    name = (result.get("file") or {}).get("name")
    if ok:
        outcome = (
            f"{result.get('count', 0)} detection(s) in {result.get('packets', 0)} packet(s)"
            if result.get("ran")
            else "empty capture, nothing replayed"
        )
        summary = f"{engine} replay of {name}: {outcome}"
    else:
        summary = f"{engine} replay failed"
    await _audit.record_action(
        "pcap_detect",
        summary,
        arguments={"path": str(path)[:200] if path else None, "engine": engine},
        target=name,
        outcome="ok" if ok else "error",
        error=None if ok else str(result["error"])[:500],
    )
    return mark_untrusted(result)


@mcp.tool(auth=require_role("admin"), **hints("detection_rules_update"))
async def detection_rules_update() -> dict[str, Any]:
    """Download the Emerging Threats Open ruleset for Suricata and cache it for `pcap_detect`.

    Use it for "update the Suricata rules", or when `pcap_detect` reports `rules_loaded: 0`.
    Needs internet and a running Docker; the first run pulls the Suricata image. Suricata validates
    the rules before they replace the cached ones, so a failed update keeps the old set. Takes no
    arguments. Admin only: it is the one container this server gives a network.
    """
    result = await detection.update_rules()
    ok = "error" not in result
    await _audit.record_action(
        "detection_rules_update",
        (
            f"{result.get('ruleset')} cached: {result.get('rules_loaded')} rules loaded by "
            f"Suricata {result.get('suricata_version')}"
            if ok
            else "Detection rules update failed"
        ),
        arguments={},
        target=result.get("image") if ok else None,
        outcome="ok" if ok else "error",
        error=None if ok else str(result["error"])[:500],
    )
    return result
