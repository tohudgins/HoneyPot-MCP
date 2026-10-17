"""Blocklist push integrations: ship offender IPs straight to live appliances.

The `export_blocklist` tool in `tools/analysis.py` produces text that an
operator pastes into their own automation. These tools close the loop by
pushing directly to:

- Cloudflare custom lists (used for WAF/IP rules)
- pfSense firewall aliases (Netgate v2 REST API)
- AWS WAFv2 IPSets

All three follow the same pattern:
1. Pull the current set of offender IPs from the DB (via the same
   `queries.get_top_offenders` that `export_blocklist` uses), keeping only
   globally routable sources not seen solely on spoofable UDP sensors, and
   never anything in `BLOCKLIST_ALLOWLIST` or this server's own canary IP.
2. Read the destination's current state (existing list / alias / IPSet).
3. Compute the diff — only push IPs that aren't already blocked.
4. Apply the change (or report what would happen if `dry_run=True`).
5. Return a uniform `{added, skipped, failed, dry_run}` shape so a
   downstream automation can reason about each result identically.

All three are idempotent — re-running is a no-op when nothing changed. Every
call is written to the audit log (destination host, counts, dry_run — never
the credential).

Note: `boto3` is gated behind a runtime import so the WAF tool can fail
gracefully on installations without it. The other two tools use `httpx`
which is already a runtime dep.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Any, Literal
from urllib.parse import urlparse

import httpx

from honeypot_mcp.rbac import require_role
from honeypot_mcp.server import mcp
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.tool_hints import hints
from honeypot_mcp.tools._audit import record_action
from honeypot_mcp.tools._window import window_end

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Cloudflare account and list ids are interpolated into the API URL path, so
# anything beyond this alphabet could redirect the authenticated request.
_CF_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


_WAF_IP_SET_LIMIT = 10_000  # AWS WAFv2 addresses per IP set


def _push_failed(exc: Exception, dry_run: bool) -> dict[str, Any]:
    """Uniform failure for a push that died on the network or on a malformed reply.

    Names the exception type only: httpx error text includes the request URL,
    which for pfSense can carry credentials, and this lands in the audit log."""
    return {
        "added": [],
        "skipped": [],
        "failed": [{"ip": "*", "error": f"{type(exc).__name__} while contacting the API"}],
        "dry_run": dry_run,
    }


def _never_push() -> list[IPNetwork]:
    """Networks that must never reach a blocklist: the operator's allowlist plus
    this server's own canary address. The latter matters because a spoofed or
    reflected hit "from" our own public IP would otherwise get the sensor's
    callback endpoint blocked by the operator's own firewall.

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
                "refusing to push until it is fixed."
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


def _pushable(ip: str, never: list[IPNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not any(addr in net for net in never)


async def _offender_ips(hours: int, min_hits: int) -> tuple[list[str], int]:
    """Pull offender IPs via the same path as `export_blocklist`.

    Returns `(pushable, excluded_count)`. Non-global addresses, sources seen
    only on spoofable UDP sensors, allowlisted networks and our own address
    are dropped — a blocklist entry for any of them lets an attacker (or a
    typo) cut off the operator's own infrastructure.
    """
    never = _never_push()
    end = await window_end()
    async with get_session() as session:
        rows = await queries.get_top_offenders(
            session, hours, min_hits, global_only=True, exclude_udp_only=True, now=end
        )
    ips = [ip for ip, _cnt in rows]
    pushable = [ip for ip in ips if _pushable(ip, never)]
    return pushable, len(ips) - len(pushable)


def _rejected(error: str, dry_run: bool) -> dict[str, Any]:
    return {"added": [], "skipped": [], "failed": [{"ip": "*", "error": error}], "dry_run": dry_run}


async def _finish(
    tool: str,
    target: str,
    arguments: dict[str, Any],
    result: dict[str, Any],
    excluded: int = 0,
) -> dict[str, Any]:
    """Audit the push and hand the result back. Callers never pass credentials
    in `arguments` — redaction is a backstop, not the plan."""
    failed = result.get("failed") or []
    verb = "dry run: would push" if result.get("dry_run") else "pushed"
    await record_action(
        tool,
        summary=(
            f"{verb} {len(result.get('added') or [])} IP(s) to {target} "
            f"({len(result.get('skipped') or [])} already present, {excluded} excluded)"
        ),
        arguments={**arguments, "excluded": excluded},
        target=target,
        outcome="error" if failed else "ok",
        error="; ".join(f"{f.get('ip')}: {f.get('error')}" for f in failed[:20]) or None,
    )
    return result


# ── Cloudflare ──────────────────────────────────────────────────────────────


@mcp.tool(auth=require_role("admin"), **hints("blocklist_push_cloudflare"))
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
    tool = "blocklist_push_cloudflare"
    target = "api.cloudflare.com"
    args: dict[str, Any] = {
        "account_id": account_id,
        "list_id": list_id,
        "hours": hours,
        "min_hits": min_hits,
        "dry_run": dry_run,
    }
    if not (_CF_ID_RE.fullmatch(account_id) and _CF_ID_RE.fullmatch(list_id)):
        msg = "account_id and list_id must each match [A-Za-z0-9_-]{1,64}."
        return await _finish(tool, target, args, _rejected(msg, dry_run))
    try:
        offenders, excluded = await _offender_ips(hours, min_hits)
    except ValueError as e:
        return await _finish(tool, target, args, _rejected(str(e), dry_run))
    if not offenders:
        result: dict[str, Any] = {"added": [], "skipped": [], "failed": [], "dry_run": dry_run}
    else:
        try:
            result = await _cloudflare_push(
                account_id, list_id, api_token, offenders, hours, dry_run
            )
        except (httpx.HTTPError, ValueError, AttributeError, KeyError) as e:
            result = _push_failed(e, dry_run)
    return await _finish(tool, target, args, result, excluded)


_CF_OPERATION_TIMEOUT = 30.0  # seconds to wait for one bulk operation
_CF_POLL_INTERVAL = 0.5
_CF_CHUNK = 1000  # items Cloudflare accepts in one create call


async def _cloudflare_push(
    account_id: str,
    list_id: str,
    api_token: str,
    offenders: list[str],
    hours: int,
    dry_run: bool,
) -> dict[str, Any]:
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
            try:
                resp = await client.get(base, headers=headers, params=params)
            except httpx.HTTPError as e:
                return _push_failed(e, dry_run)
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

    # 2. Push new items in batches (Cloudflare accepts up to 1000 per call). Creating items is an
    # asynchronous bulk operation and an account may have only ONE pending: the next chunk is
    # refused until this one finishes, and a 200 only means "accepted", not "on the list".
    added: list[str] = []
    failed: list[dict[str, str]] = []
    ops_url = (
        f"https://api.cloudflare.com/client/v4/accounts/{account_id}/rules/lists/bulk_operations"
    )
    async with httpx.AsyncClient(timeout=30.0) as client:
        for chunk_start in range(0, len(to_add), _CF_CHUNK):
            chunk = to_add[chunk_start : chunk_start + _CF_CHUNK]
            payload = [{"ip": ip, "comment": f"honeypot-mcp:{hours}h"} for ip in chunk]
            try:
                resp = await client.post(base, headers=headers, json=payload)
                error = None
                if 200 <= resp.status_code < 300:
                    operation_id = (resp.json().get("result") or {}).get("operation_id")
                    if operation_id:
                        error = await _cloudflare_wait(client, ops_url, headers, operation_id)
                else:
                    error = f"HTTP {resp.status_code}"
            except (httpx.HTTPError, ValueError, AttributeError) as e:
                # Earlier chunks already went through; losing track of them
                # because a later one timed out would misreport the blocklist.
                error = type(e).__name__
            if error is None:
                added.extend(chunk)
            else:
                failed.extend({"ip": ip, "error": error} for ip in chunk)

    return {"added": added, "skipped": skipped, "failed": failed, "dry_run": dry_run}


async def _cloudflare_wait(
    client: httpx.AsyncClient, ops_url: str, headers: dict[str, str], operation_id: str
) -> str | None:
    """Wait for a bulk operation; None when it completed, otherwise why it did not."""
    if not _CF_ID_RE.fullmatch(operation_id):
        return "unexpected operation id"
    deadline = asyncio.get_running_loop().time() + _CF_OPERATION_TIMEOUT
    while True:
        resp = await client.get(f"{ops_url}/{operation_id}", headers=headers)
        if resp.status_code != 200:
            return f"operation status HTTP {resp.status_code}"
        result = resp.json().get("result") or {}
        status = result.get("status")
        if status == "completed":
            return None
        if status == "failed":
            return f"operation failed: {str(result.get('error', 'unknown'))[:120]}"
        if asyncio.get_running_loop().time() >= deadline:
            return f"operation still {status or 'pending'} after {_CF_OPERATION_TIMEOUT:g}s"
        await asyncio.sleep(_CF_POLL_INTERVAL)


# ── pfSense ─────────────────────────────────────────────────────────────────


@mcp.tool(auth=require_role("admin"), **hints("blocklist_push_pfsense"))
async def blocklist_push_pfsense(
    base_url: str,
    api_key: str,
    alias_name: str,
    hours: int = 24,
    min_hits: int = 5,
    dry_run: bool = False,
    verify_tls: bool = True,
) -> dict[str, Any]:
    """Push offender IPs to a pfSense firewall alias via the pfrest v2 REST API.

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
    tool = "blocklist_push_pfsense"
    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    args: dict[str, Any] = {
        "host": host,
        "alias_name": alias_name,
        "hours": hours,
        "min_hits": min_hits,
        "dry_run": dry_run,
        "verify_tls": verify_tls,
    }
    if err := _pfsense_url_error(parsed.scheme, host):
        return await _finish(tool, host or "pfsense", args, _rejected(err, dry_run))
    try:
        offenders, excluded = await _offender_ips(hours, min_hits)
    except ValueError as e:
        return await _finish(tool, host, args, _rejected(str(e), dry_run))
    if not offenders:
        result: dict[str, Any] = {"added": [], "skipped": [], "failed": [], "dry_run": dry_run}
    else:
        try:
            result = await _pfsense_push(
                base_url, api_key, alias_name, offenders, dry_run, verify_tls
            )
        except (httpx.HTTPError, ValueError, AttributeError, KeyError) as e:
            result = _push_failed(e, dry_run)
    return await _finish(tool, host, args, result, excluded)


def _pfsense_url_error(scheme: str, host: str) -> str | None:
    """The API key rides in every request header, so it must not cross the
    network in the clear. Plain http is tolerated only to a loopback host
    (an SSH tunnel or local proxy), where there is no network to cross."""
    if not host:
        return "base_url must be an absolute URL, e.g. https://pfsense.local."
    if scheme == "https":
        return None
    if scheme == "http":
        try:
            loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if loopback:
            return None
    return "base_url must use https:// (http is only accepted for a loopback host)."


async def _pfsense_push(
    base_url: str,
    api_key: str,
    alias_name: str,
    offenders: list[str],
    dry_run: bool,
    verify_tls: bool,
) -> dict[str, Any]:
    # pfrest (the pfSense REST API package) authenticates with `X-API-Key`, addresses an alias by
    # its integer `id` rather than its name, and updates it with PATCH; there is no PUT.
    headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
    base = base_url.rstrip("/")

    async with httpx.AsyncClient(timeout=15.0, verify=verify_tls) as client:
        # 1. Find the alias (the plural endpoint filters by name and returns each entry's id)
        resp = await client.get(
            f"{base}/api/v2/firewall/aliases", headers=headers, params={"name": alias_name}
        )
        if resp.status_code != 200:
            return {
                "added": [],
                "skipped": [],
                "failed": [{"ip": "*", "error": f"alias read HTTP {resp.status_code}"}],
                "dry_run": dry_run,
            }
        rows = resp.json().get("data") or []
        # A filter is a request, not a guarantee: take only the alias that is exactly the one named.
        alias = next((r for r in rows if r.get("name") == alias_name and "id" in r), None)
        if alias is None:
            return {
                "added": [],
                "skipped": [],
                "failed": [{"ip": "*", "error": f"alias {alias_name!r} not found"}],
                "dry_run": dry_run,
            }
        addresses_raw = alias.get("address") or []
        # Older serialisers return a space-separated string, pfrest v2 an array.
        existing = addresses_raw.split() if isinstance(addresses_raw, str) else list(addresses_raw)
        known = set(existing)

        to_add = [ip for ip in offenders if ip not in known]
        skipped = [ip for ip in offenders if ip in known]

        if dry_run or not to_add:
            return {"added": to_add, "skipped": skipped, "failed": [], "dry_run": dry_run}

        # 2. PATCH the alias. `detail` is positional with `address`, so keep the existing order,
        # pad any missing descriptions, and append ours: sorting would misalign every comment.
        details = [str(d) for d in (alias.get("detail") or [])]
        details += [""] * (len(existing) - len(details))
        patch_body = {
            "id": alias["id"],
            "address": existing + to_add,
            "detail": details[: len(existing)] + ["honeypot-mcp"] * len(to_add),
        }
        put_resp = await client.patch(
            f"{base}/api/v2/firewall/alias", headers=headers, json=patch_body
        )
        if not 200 <= put_resp.status_code < 300:
            return {
                "added": [],
                "skipped": skipped,
                "failed": [
                    {"ip": ip, "error": f"PATCH HTTP {put_resp.status_code}"} for ip in to_add
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


@mcp.tool(auth=require_role("admin"), **hints("blocklist_push_aws_waf"))
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

    The IPSet must already exist. Bare IPs are converted to `/32` (IPv4) or
    `/128` (IPv6) since WAFv2 requires CIDR. Credentials are picked up from
    the standard boto3 chain (env vars, IAM role, profile).

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
    tool = "blocklist_push_aws_waf"
    target = f"wafv2:{region}/{ip_set_name}"
    args: dict[str, Any] = {
        "ip_set_id": ip_set_id,
        "ip_set_name": ip_set_name,
        "region": region,
        "scope": scope,
        "hours": hours,
        "min_hits": min_hits,
        "dry_run": dry_run,
    }
    try:
        offenders, excluded = await _offender_ips(hours, min_hits)
    except ValueError as e:
        return await _finish(tool, target, args, _rejected(str(e), dry_run))
    if not offenders:
        result: dict[str, Any] = {"added": [], "skipped": [], "failed": [], "dry_run": dry_run}
    else:
        result = await _waf_push(ip_set_id, ip_set_name, region, scope, offenders, dry_run)
    return await _finish(tool, target, args, result, excluded)


async def _waf_push(
    ip_set_id: str,
    ip_set_name: str,
    region: str,
    scope: str,
    offenders: list[str],
    dry_run: bool,
) -> dict[str, Any]:
    try:
        import boto3
    except ImportError:
        return {
            "added": [],
            "skipped": [],
            "failed": [{"ip": "*", "error": "boto3 not installed (pip install boto3)"}],
            "dry_run": dry_run,
        }

    # WAFv2 wants CIDRs: a host route is /32 for IPv4 and /128 for IPv6
    # (`2001:db8::1/32` would block a whole /32 of someone else's space).
    offender_cidrs: list[str] = []
    for ip in offenders:
        addr = ipaddress.ip_address(ip)
        offender_cidrs.append(f"{addr}/{addr.max_prefixlen}")

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

    ip_set = current.get("IPSet", {})
    existing = set(ip_set.get("Addresses") or [])
    lock_token = current.get("LockToken")

    # A WAFv2 IP set holds addresses of ONE family, fixed when it was created; an
    # update that mixes in the other family is rejected as a whole, which would
    # report every valid IP as failed. Push only what fits and say what did not.
    family = {"IPV4": 4, "IPV6": 6}.get(str(ip_set.get("IPAddressVersion") or ""))
    wrong_family: list[str] = []
    if family is not None:
        fitting = [c for c in offender_cidrs if ipaddress.ip_network(c).version == family]
        wrong_family = [c for c in offender_cidrs if c not in fitting]
        offender_cidrs = fitting

    to_add = [cidr for cidr in offender_cidrs if cidr not in existing]
    skipped = [cidr for cidr in offender_cidrs if cidr in existing]
    failed_up_front: list[dict[str, str]] = [
        {"ip": cidr, "error": f"IP set holds IPv{6 if family == 4 else 4} only"}
        for cidr in wrong_family
    ]
    room = _WAF_IP_SET_LIMIT - len(existing)
    if len(to_add) > max(room, 0):
        failed_up_front += [
            {"ip": cidr, "error": f"IP set is at the {_WAF_IP_SET_LIMIT}-address limit"}
            for cidr in to_add[max(room, 0) :]
        ]
        to_add = to_add[: max(room, 0)]

    if dry_run or not to_add:
        return {"added": to_add, "skipped": skipped, "failed": failed_up_front, "dry_run": dry_run}

    merged = sorted(existing | set(to_add))
    update: dict[str, Any] = {
        "Name": ip_set_name,
        "Id": ip_set_id,
        "Scope": scope,
        "Addresses": merged,
        "LockToken": lock_token,
    }
    # UpdateIPSet replaces the description with whatever it is given, so omitting it would blank
    # the operator's own description of the set on every push.
    if ip_set.get("Description"):
        update["Description"] = ip_set["Description"]
    try:
        await asyncio.to_thread(client.update_ip_set, **update)
    except Exception as e:
        return {
            "added": [],
            "skipped": skipped,
            "failed": failed_up_front
            + [{"ip": cidr, "error": f"update_ip_set: {e!s}"[:200]} for cidr in to_add],
            "dry_run": dry_run,
        }

    return {"added": to_add, "skipped": skipped, "failed": failed_up_front, "dry_run": dry_run}
