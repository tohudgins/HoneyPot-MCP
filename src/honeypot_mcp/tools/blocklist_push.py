"""Blocklist push integrations: ship offender IPs straight to live appliances.

The `export_blocklist` tool in `tools/analysis.py` produces text that an
operator pastes into their own automation. These tools close the loop by
pushing directly to:

- Cloudflare custom lists (used for WAF/IP rules)
- pfSense firewall aliases (Netgate v2 REST API)
- AWS WAFv2 IPSets

All three follow the same pattern:
1. Pull the current set of offender IPs from the DB (via the same
   `queries.get_top_offenders` that `export_blocklist` uses).
2. Read the destination's current state (existing list / alias / IPSet).
3. Compute the diff — only push IPs that aren't already blocked.
4. Apply the change (or report what would happen if `dry_run=True`).
5. Return a uniform `{added, skipped, failed, dry_run}` shape so a
   downstream automation can reason about each result identically.

All three are idempotent — re-running is a no-op when nothing changed.

Note: `boto3` is gated behind a runtime import so the WAF tool can fail
gracefully on installations without it. The other two tools use `httpx`
which is already a runtime dep.
"""

from __future__ import annotations

import asyncio
from typing import Any, Literal

import httpx

from honeypot_mcp.server import mcp
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session


async def _offender_ips(hours: int, min_hits: int) -> list[str]:
    """Pull offender IPs via the same path as `export_blocklist`."""
    async with get_session() as session:
        rows = await queries.get_top_offenders(session, hours, min_hits)
    return [ip for ip, _cnt in rows]


# ── Cloudflare ──────────────────────────────────────────────────────────────


@mcp.tool
async def blocklist_push_cloudflare(
    account_id: str,
    list_id: str,
    api_token: str,
    hours: int = 24,
    min_hits: int = 5,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Push offender IPs to a Cloudflare custom list (lists API).

    Cloudflare custom lists hold IPs you can reference in WAF / firewall
    expressions. The list must already exist — create it once in the
    Cloudflare dashboard, then call this tool to keep it current.

    Args:
        account_id: Cloudflare account ID (URL-friendly hex string).
        list_id: ID of the custom list to update.
        api_token: API token with `Account:Account Filter Lists:Edit` scope.
        hours: Time window for offenders (default 24).
        min_hits: Minimum alert count to include (default 5).
        dry_run: If True, compute the diff but don't apply.

    Returns:
        `{added: [...], skipped: [...], failed: [...], dry_run: bool}`.
        `skipped` IPs were already on the list.
    """
    offenders = await _offender_ips(hours, min_hits)
    if not offenders:
        return {"added": [], "skipped": [], "failed": [], "dry_run": dry_run}

    base = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/rules/lists/{list_id}/items"
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}

    # 1. Read current items (paginated)
    existing: set[str] = set()
    async with httpx.AsyncClient(timeout=15.0) as client:
        cursor: str | None = None
        while True:
            params: dict[str, str] = {"per_page": "200"}
            if cursor:
                params["cursor"] = cursor
            resp = await client.get(base, headers=headers, params=params)
            if resp.status_code != 200:
                return {
                    "added": [],
                    "skipped": [],
                    "failed": [{"ip": "*", "error": f"list read HTTP {resp.status_code}"}],
                    "dry_run": dry_run,
                }
            body = resp.json()
            for item in body.get("result") or []:
                ip = item.get("ip")
                if ip:
                    existing.add(ip)
            cursor = (body.get("result_info") or {}).get("cursors", {}).get("after")
            if not cursor:
                break

    to_add = [ip for ip in offenders if ip not in existing]
    skipped = [ip for ip in offenders if ip in existing]

    if dry_run or not to_add:
        return {"added": to_add, "skipped": skipped, "failed": [], "dry_run": dry_run}

    # 2. Push new items in batches (Cloudflare accepts up to 1000 per call)
    added: list[str] = []
    failed: list[dict[str, str]] = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        for chunk_start in range(0, len(to_add), 1000):
            chunk = to_add[chunk_start : chunk_start + 1000]
            payload = [{"ip": ip, "comment": f"honeypot-mcp:{hours}h"} for ip in chunk]
            resp = await client.post(base, headers=headers, json=payload)
            if 200 <= resp.status_code < 300:
                added.extend(chunk)
            else:
                for ip in chunk:
                    failed.append({"ip": ip, "error": f"HTTP {resp.status_code}"})

    return {"added": added, "skipped": skipped, "failed": failed, "dry_run": dry_run}


# ── pfSense ─────────────────────────────────────────────────────────────────


@mcp.tool
async def blocklist_push_pfsense(
    base_url: str,
    api_key: str,
    alias_name: str,
    hours: int = 24,
    min_hits: int = 5,
    dry_run: bool = False,
    verify_tls: bool = True,
) -> dict[str, Any]:
    """Push offender IPs to a pfSense firewall alias via the Netgate v2 REST API.

    The alias must already exist and be of type `host` or `network`. After
    updating the alias, the API call to `/firewall/apply` actually commits
    the change to the running ruleset — without that, the alias contents
    update but the firewall keeps using the old version.

    Args:
        base_url: pfSense base URL, e.g. `https://pfsense.local`.
        api_key: API key (admin → User Manager → user → API key).
        alias_name: Name of the existing firewall alias to update.
        hours: Time window for offenders.
        min_hits: Minimum alert count to include.
        dry_run: If True, compute the diff but don't apply.
        verify_tls: Verify the appliance's TLS certificate (default True).
              pfSense's REST API commonly runs on a self-signed cert out of
              the box — set this to False ONLY for that case, and only once
              you've confirmed you're actually talking to your own appliance
              (e.g. over a trusted network segment or VPN). Disabling this
              makes the API key and the blocklist push vulnerable to MITM by
              anyone on the network path, not just to the appliance's own
              self-signed cert.

    Returns:
        `{added, skipped, failed, dry_run}` uniform shape.
    """
    offenders = await _offender_ips(hours, min_hits)
    if not offenders:
        return {"added": [], "skipped": [], "failed": [], "dry_run": dry_run}

    headers = {"Authorization": api_key, "Content-Type": "application/json"}
    base = base_url.rstrip("/")

    async with httpx.AsyncClient(timeout=15.0, verify=verify_tls) as client:
        # 1. Read the current alias
        resp = await client.get(
            f"{base}/api/v2/firewall/alias", headers=headers, params={"name": alias_name}
        )
        if resp.status_code != 200:
            return {
                "added": [],
                "skipped": [],
                "failed": [{"ip": "*", "error": f"alias read HTTP {resp.status_code}"}],
                "dry_run": dry_run,
            }
        body = resp.json()
        data = body.get("data") or body
        # Address list can be a space-separated string or an array depending
        # on pfSense's serialiser — normalise.
        addresses_raw = data.get("address") or data.get("addresses") or []
        if isinstance(addresses_raw, str):
            existing = set(addresses_raw.split())
        else:
            existing = set(addresses_raw)

        to_add = [ip for ip in offenders if ip not in existing]
        skipped = [ip for ip in offenders if ip in existing]

        if dry_run or not to_add:
            return {"added": to_add, "skipped": skipped, "failed": [], "dry_run": dry_run}

        # 2. PUT whole alias with merged address list
        merged = sorted(existing | set(to_add))
        put_body = dict(data)
        put_body["address"] = " ".join(merged)
        put_resp = await client.put(f"{base}/api/v2/firewall/alias", headers=headers, json=put_body)
        if not 200 <= put_resp.status_code < 300:
            return {
                "added": [],
                "skipped": skipped,
                "failed": [
                    {"ip": ip, "error": f"PUT HTTP {put_resp.status_code}"} for ip in to_add
                ],
                "dry_run": dry_run,
            }

        # 3. Commit to running config
        apply_resp = await client.post(f"{base}/api/v2/firewall/apply", headers=headers)
        if not 200 <= apply_resp.status_code < 300:
            # Alias updated but commit failed — surface as failures so the
            # operator knows to retry apply.
            return {
                "added": [],
                "skipped": skipped,
                "failed": [
                    {"ip": ip, "error": f"apply HTTP {apply_resp.status_code}"} for ip in to_add
                ],
                "dry_run": dry_run,
            }

    return {"added": to_add, "skipped": skipped, "failed": [], "dry_run": dry_run}


# ── AWS WAFv2 ───────────────────────────────────────────────────────────────


@mcp.tool
async def blocklist_push_aws_waf(
    ip_set_id: str,
    ip_set_name: str,
    region: str,
    scope: Literal["REGIONAL", "CLOUDFRONT"] = "REGIONAL",
    hours: int = 24,
    min_hits: int = 5,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Push offender IPs to an AWS WAFv2 IPSet.

    The IPSet must already exist. Bare IPs are converted to `/32` since
    WAFv2 requires CIDR. Credentials are picked up from the standard
    boto3 chain (env vars, IAM role, profile).

    Args:
        ip_set_id: WAFv2 IPSet ID (the `Id` field of the IPSet resource).
        ip_set_name: IPSet name (WAFv2 requires both for update).
        region: AWS region of the IPSet (use `us-east-1` for CLOUDFRONT scope).
        scope: `REGIONAL` for ALB/API Gateway, `CLOUDFRONT` for CloudFront.
        hours: Time window for offenders.
        min_hits: Minimum alert count to include.
        dry_run: If True, compute the diff but don't apply.

    Returns:
        `{added, skipped, failed, dry_run}` uniform shape.
    """
    offenders = await _offender_ips(hours, min_hits)
    if not offenders:
        return {"added": [], "skipped": [], "failed": [], "dry_run": dry_run}

    try:
        import boto3
    except ImportError:
        return {
            "added": [],
            "skipped": [],
            "failed": [{"ip": "*", "error": "boto3 not installed (pip install boto3)"}],
            "dry_run": dry_run,
        }

    offender_cidrs = [ip if "/" in ip else f"{ip}/32" for ip in offenders]

    # boto3 is synchronous — every in-process engine (HTTP, SMTP, FTP,
    # Redis, MySQL, ...) shares this one event loop, so a bare boto3 call
    # here would stall all of them for the duration of each AWS round trip
    # (worse under throttling, where boto3's own retry/backoff can take
    # seconds). engines/ssh.py wraps every docker-py call in
    # run_in_executor for the identical reason; boto3 gets the same
    # treatment via asyncio.to_thread.
    try:
        client = await asyncio.to_thread(boto3.client, "wafv2", region_name=region)
        current = await asyncio.to_thread(
            client.get_ip_set, Name=ip_set_name, Id=ip_set_id, Scope=scope
        )
    except Exception as e:
        return {
            "added": [],
            "skipped": [],
            "failed": [{"ip": "*", "error": f"get_ip_set: {e!s}"[:200]}],
            "dry_run": dry_run,
        }

    existing = set(current.get("IPSet", {}).get("Addresses") or [])
    lock_token = current.get("LockToken")

    to_add = [cidr for cidr in offender_cidrs if cidr not in existing]
    skipped = [cidr for cidr in offender_cidrs if cidr in existing]

    if dry_run or not to_add:
        return {"added": to_add, "skipped": skipped, "failed": [], "dry_run": dry_run}

    merged = sorted(existing | set(to_add))
    try:
        await asyncio.to_thread(
            client.update_ip_set,
            Name=ip_set_name,
            Id=ip_set_id,
            Scope=scope,
            Addresses=merged,
            LockToken=lock_token,
        )
    except Exception as e:
        return {
            "added": [],
            "skipped": skipped,
            "failed": [{"ip": cidr, "error": f"update_ip_set: {e!s}"[:200]} for cidr in to_add],
            "dry_run": dry_run,
        }

    return {"added": to_add, "skipped": skipped, "failed": [], "dry_run": dry_run}
