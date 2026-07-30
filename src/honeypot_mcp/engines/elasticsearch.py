"""Elasticsearch honeypot engine — credential-less data-exfil target mock.

Exposed Elasticsearch is a recurring incident pattern — companies leave
9200 open without auth, attackers dump entire indexes (PII, credentials,
log archives). This honeypot mimics an unauthenticated Elasticsearch
8.x cluster so scanners that probe `GET /` and `GET /_cluster/health` get
realistic cluster info, then any actual data-exfil attempt (`*_search`,
`*_doc`, `*_bulk`) lights up as HIGH severity.

Routes:
* `GET /` — realistic cluster banner with version + tagline.
* `GET /_cluster/health` — green-cluster JSON.
* `GET /_cat/indices?v` — fake index list.
* `GET /_nodes`, `GET /_nodes/stats` — minimal node JSON.
* `POST` / `GET` on any `*_search` / `*_msearch` / `*_count` / `*_doc` path
  — HIGH severity exfil-attempt event with the request body preserved.
* Everything else — log, return 404 with realistic Elasticsearch error
  envelope.

Every request body is also fed through `token_matchers.scan_payload` so a
planted JWT or canary-email embedded by an attacker in a query payload
triggers immediately.
"""

from __future__ import annotations

import json
import logging
import secrets
import uuid
from typing import Any

from aiohttp import web

from honeypot_mcp.engines.base import HoneypotEngine
from honeypot_mcp.http_identity import NGINX_BANNER, identity_runner, server_identity_middleware
from honeypot_mcp.storage import queries
from honeypot_mcp.storage.database import get_session
from honeypot_mcp.storage.event_buffer import PendingEvent, submit_event
from honeypot_mcp.storage.models import AlertSeverity

log = logging.getLogger(__name__)


# Cluster identifier stays stable per honeypot instance so a scanner that
# pings `/` twice doesn't see the cluster_uuid change. Generated once at
# engine construction; persists for the life of the process.
def _cluster_identity() -> dict[str, str]:
    return {
        "name": f"node-{secrets.token_hex(4)}",
        "cluster_name": "elastic-prod",
        "cluster_uuid": str(uuid.uuid4()),
    }


# Realistic Elasticsearch 8.11.3 version block — matches what `curl /`
# returns against a stock OSS install.
_VERSION_BLOCK: dict[str, Any] = {
    "number": "8.11.3",
    "build_flavor": "default",
    "build_type": "deb",
    "build_hash": "64cf052f3b56b1fd4449f5454cb88aca7e739d9a",
    "build_date": "2023-12-08T11:33:53.634979452Z",
    "build_snapshot": False,
    "lucene_version": "9.8.0",
    "minimum_wire_compatibility_version": "7.17.0",
    "minimum_index_compatibility_version": "7.0.0",
}


# Paths that indicate actual data access — these should escalate severity
# even without payload inspection. Match by suffix because Elasticsearch
# routes typically encode the index as a path prefix:
# `GET /logs-2024.01.15/_search`, `POST /users/_bulk`, etc.
_EXFIL_SUFFIXES = (
    "/_search",
    "/_msearch",
    "/_count",
    "/_bulk",
    "/_mget",
    "/_doc",
    "/_pit",
)


class ElasticsearchEngine(HoneypotEngine):
    def __init__(self) -> None:
        self._runners: dict[str, web.AppRunner] = {}

    async def start(self, name: str, port: int, config: dict[str, Any]) -> str:
        hp_id: int | None = None
        async with get_session() as session:
            hp = await queries.get_honeypot_by_name(session, name)
            if hp:
                hp_id = hp.id

        identity = _cluster_identity()
        app = self._build_app(name, hp_id, identity)
        runner = identity_runner(app, NGINX_BANNER)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", port)
        await site.start()

        cid = f"elastic-{secrets.token_hex(8)}"
        self._runners[cid] = runner
        log.info(
            "Elasticsearch honeypot '%s' listening on port %d (cluster=%s)",
            name,
            port,
            identity["cluster_name"],
        )
        return cid

    async def stop(self, container_id: str, remove: bool = False) -> None:
        runner = self._runners.pop(container_id, None)
        if runner:
            await runner.cleanup()

    async def status(self, container_id: str) -> dict[str, Any]:
        return {
            "running": container_id in self._runners,
            "type": "aiohttp_elasticsearch",
        }

    async def get_logs(self, container_id: str, lines: int = 50) -> list[str]:
        return [
            "Elasticsearch honeypot is in-process — events are stored directly in the database."
        ]

    @staticmethod
    def _identity_headers() -> dict[str, str]:
        """Headers that make a response look like it came from Elasticsearch."""
        return dict(_ELASTIC_HEADERS)

    def _build_app(
        self,
        honeypot_name: str,
        hp_id: int | None,
        identity: dict[str, str],
    ) -> web.Application:
        app = web.Application(middlewares=[_elastic_headers])

        async def _record(
            request: web.Request,
            event_type: str,
            severity: AlertSeverity,
            extra: dict[str, Any] | None = None,
        ) -> None:
            payload: dict[str, Any] = {
                "method": request.method,
                "path": request.path,
                "query": dict(request.query),
                "user_agent": request.headers.get("User-Agent", ""),
                "headers": dict(request.headers),
            }
            if extra:
                payload.update(extra)
            await submit_event(
                PendingEvent(
                    honeypot_id=hp_id,
                    source_ip=request.remote or "0.0.0.0",
                    event_type=event_type,
                    payload=payload,
                    severity=severity,
                )
            )

        async def _read_body(request: web.Request) -> str:
            """Read up to 64 KB of body. Elasticsearch query bodies above
            that size are unusual on the wild internet — scanners send
            short probes."""
            if request.body_exists:
                try:
                    raw = await request.read()
                    return raw[:65536].decode("utf-8", errors="replace")
                except Exception:
                    return ""
            return ""

        async def _handle_root(request: web.Request) -> web.Response:
            await _record(request, "elasticsearch_recon_probe", AlertSeverity.LOW)
            body = {
                "name": identity["name"],
                "cluster_name": identity["cluster_name"],
                "cluster_uuid": identity["cluster_uuid"],
                "version": _VERSION_BLOCK,
                "tagline": "You Know, for Search",
            }
            return web.json_response(body)

        async def _handle_health(request: web.Request) -> web.Response:
            await _record(request, "elasticsearch_health_probe", AlertSeverity.LOW)
            body = {
                "cluster_name": identity["cluster_name"],
                "status": "green",
                "timed_out": False,
                "number_of_nodes": 3,
                "number_of_data_nodes": 3,
                "active_primary_shards": 64,
                "active_shards": 128,
                "relocating_shards": 0,
                "initializing_shards": 0,
                "unassigned_shards": 0,
                "delayed_unassigned_shards": 0,
                "number_of_pending_tasks": 0,
                "number_of_in_flight_fetch": 0,
                "task_max_waiting_in_queue_millis": 0,
                "active_shards_percent_as_number": 100.0,
            }
            return web.json_response(body)

        async def _handle_cat_indices(request: web.Request) -> web.Response:
            await _record(
                request,
                "elasticsearch_recon_probe",
                AlertSeverity.MEDIUM,
                {"target": "_cat/indices"},
            )
            text = (
                "health status index                   uuid                   pri rep docs.count docs.deleted store.size pri.store.size\n"
                "green  open   logs-2024.01.15         abcdef1234567890abcd     1   1    1843291            0      2.1gb          1.0gb\n"
                "green  open   users                   bcdef0987654321         1   1      94532            0     12.4mb          6.2mb\n"
                "green  open   .kibana_security        cdef98abcdef76543210     1   0          7            0      8.4kb          8.4kb\n"
                "green  open   metrics-2024.01         def0123456789abcdef0    1   1    8392108            0      4.6gb          2.3gb\n"
            )
            return web.Response(text=text, content_type="text/plain")

        async def _handle_nodes(request: web.Request) -> web.Response:
            await _record(
                request,
                "elasticsearch_recon_probe",
                AlertSeverity.MEDIUM,
                {"target": "_nodes"},
            )
            node_id = secrets.token_hex(11)
            body = {
                "_nodes": {"total": 1, "successful": 1, "failed": 0},
                "cluster_name": identity["cluster_name"],
                "nodes": {
                    node_id: {
                        "name": identity["name"],
                        "transport_address": "10.0.1.42:9300",
                        "host": "10.0.1.42",
                        "ip": "10.0.1.42",
                        "version": _VERSION_BLOCK["number"],
                        "build_flavor": "default",
                        "roles": ["master", "data", "ingest"],
                    }
                },
            }
            return web.json_response(body)

        async def _handle_catchall(request: web.Request) -> web.Response:
            path = request.path
            body_text = await _read_body(request)

            # Exfil-shaped paths escalate to HIGH. Path-suffix check covers
            # both `/_search` and `/logs-2024/_search`.
            severity = AlertSeverity.MEDIUM
            event_type = "elasticsearch_query_probe"
            if any(
                path.endswith(suf) or path.rstrip("/").endswith(suf) for suf in _EXFIL_SUFFIXES
            ) or any(suf + "/" in path for suf in _EXFIL_SUFFIXES):
                severity = AlertSeverity.HIGH
                event_type = "elasticsearch_data_access"

            await _record(
                request,
                event_type,
                severity,
                {"body_preview": body_text[:4096]},
            )

            # Scan the body for planted token shapes. The same matcher the
            # event-buffer uses for SSH / HTTP / FTP / SMTP triggers, so
            # a JWT or canary email in an attacker's query lights up
            # CRITICAL via the standard path.
            try:
                from honeypot_mcp.storage.event_buffer import PendingEvent as _PE
                from honeypot_mcp.token_matchers import match as token_match

                probe_event = _PE(
                    honeypot_id=hp_id,
                    source_ip=request.remote or "0.0.0.0",
                    event_type=event_type,
                    payload={"body": body_text, "path": path},
                    severity=severity,
                )
                token_id, match_type = await token_match(probe_event)
                if token_id is not None:
                    # token_matchers identified a planted token in the body —
                    # fire a separate CRITICAL alert tagged with the token id
                    # so dashboards correlate it back to the planted asset.
                    await submit_event(
                        PendingEvent(
                            honeypot_id=hp_id,
                            source_ip=request.remote or "0.0.0.0",
                            event_type=f"honeytoken_triggered_{match_type}_via_elasticsearch",
                            payload={
                                "matched_token_id": token_id,
                                "match_type": match_type,
                                "path": path,
                            },
                            severity=AlertSeverity.CRITICAL,
                            honeytoken_id=token_id,
                        )
                    )
            except Exception as e:
                log.debug("token_matchers scan failed on ES body: %s", e)

            # If the path looks like an index path (single segment that
            # isn't an underscore-route), return index-not-found. Real
            # Elasticsearch always serves SOME JSON, never raw 404 HTML.
            body = {
                "error": {
                    "root_cause": [
                        {
                            "type": "index_not_found_exception",
                            "reason": "no such index",
                            "resource.type": "index_or_alias",
                            "resource.id": path.strip("/").split("/", 1)[0] or "_",
                            "index": path.strip("/").split("/", 1)[0] or "_",
                            "index_uuid": "_na_",
                        }
                    ],
                    "type": "index_not_found_exception",
                    "reason": "no such index",
                    "index_uuid": "_na_",
                    "index": path.strip("/").split("/", 1)[0] or "_",
                },
                "status": 404,
            }
            return web.json_response(body, status=404)

        app.router.add_get("/", _handle_root)
        app.router.add_get("/_cluster/health", _handle_health)
        app.router.add_get("/_cat/indices", _handle_cat_indices)
        app.router.add_get("/_nodes", _handle_nodes)
        app.router.add_get("/_nodes/stats", _handle_nodes)
        app.router.add_route("*", "/{tail:.*}", _handle_catchall)

        return app


# Avoid lint complaints about unused import (we keep json in case future
# variants want to render custom error envelopes)
_ = json


# Real Elasticsearch runs on Netty and sends no `Server` header, but does stamp
# every 8.x response with `X-elastic-product` — clients check that header to
# confirm they're talking to genuine Elasticsearch rather than a compatible
# fork, so its absence is itself a tell.
_ELASTIC_HEADERS = {
    "X-elastic-product": "Elasticsearch",
}

# Bare Elasticsearch sends no `Server` header, but aiohttp always emits one and
# an empty value is its own anomaly. Internet-exposed Elasticsearch is almost
# always behind a reverse proxy, so `nginx` is both plausible and consistent
# with the banner the protocol-level error path emits.
_elastic_headers = server_identity_middleware(NGINX_BANNER, _ELASTIC_HEADERS)
