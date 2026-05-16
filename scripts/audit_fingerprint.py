"""Honeypot fingerprint-resistance auditor.

Runs scanner-style probes against running honeypots and reports detected
tells. The point: turn "the persona system defeats fingerprinting" from an
assertion into a test you can run before deploying.

Usage:

    python scripts/audit_fingerprint.py --host 127.0.0.1 \
        --ssh 22 --http 8080 --https 8443 --smtp 25 --ftp 21 --rdp 3389

Each probed engine is graded across a fixed set of fingerprint surfaces:
banner / extension list / response timing / header consistency. The output
is a markdown report you can paste into a PR or a deployment write-up.

This script doesn't need MCP — it's plain asyncio + httpx + ssl. Run it
from your laptop against a deployed honeypot, or locally against a Docker
Compose stack.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import socket
import ssl
import statistics
import sys
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    surface: str
    verdict: str  # "ok" | "tell" | "warn"
    detail: str


@dataclass
class EngineReport:
    name: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, surface: str, verdict: str, detail: str) -> None:
        self.findings.append(Finding(surface, verdict, detail))

    def to_markdown(self) -> str:
        if not self.findings:
            return f"### {self.name}\n\n_(no probes ran)_\n"
        lines = [f"### {self.name}", ""]
        lines.append("| Surface | Verdict | Detail |")
        lines.append("|---|---|---|")
        for f in self.findings:
            badge = {"ok": "✓ ok", "warn": "⚠ warn", "tell": "✗ tell"}[f.verdict]
            lines.append(f"| {f.surface} | {badge} | {f.detail.replace('|', '/')} |")
        lines.append("")
        return "\n".join(lines)


# ── SSH ─────────────────────────────────────────────────────────────────


async def _probe_ssh(host: str, port: int) -> EngineReport:
    r = EngineReport("SSH")
    banners: list[str] = []
    timings: list[float] = []
    for _ in range(3):
        try:
            t0 = time.monotonic()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5.0
            )
            banner = await asyncio.wait_for(reader.readline(), timeout=5.0)
            timings.append(time.monotonic() - t0)
            banners.append(banner.decode("utf-8", errors="replace").strip())
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        except Exception as e:
            r.add("connect", "tell", f"connection failed: {e}")
            return r

    if not banners:
        r.add("banner", "tell", "no banner received")
        return r

    banner = banners[0]
    r.add("banner", "ok" if banner.startswith("SSH-") else "tell", banner)

    # Default Cowrie identifier — the most obvious fingerprint.
    if "ubuntu-server" in banner.lower():
        r.add("banner identity", "tell", "default Cowrie hostname leaked")
    else:
        r.add("banner identity", "ok", "non-default hostname")

    if len(set(banners)) == 1:
        r.add("banner stability", "ok", "banner stable across reconnects")
    else:
        r.add("banner stability", "warn", f"banner varies: {set(banners)}")

    avg_ms = statistics.mean(timings) * 1000
    if avg_ms < 1.0:
        r.add("response timing", "tell", f"sub-ms response ({avg_ms:.2f}ms) — no jitter")
    else:
        r.add("response timing", "ok", f"~{avg_ms:.0f}ms")
    return r


# ── HTTP / HTTPS ────────────────────────────────────────────────────────


async def _probe_http(host: str, port: int, use_tls: bool) -> EngineReport:
    import httpx

    scheme = "https" if use_tls else "http"
    r = EngineReport(f"{scheme.upper()} (port {port})")

    verify: Any = not use_tls

    try:
        async with httpx.AsyncClient(verify=verify, timeout=5.0) as client:
            # Check well-known endpoints — absence = single-curl tell.
            for path in (
                "/robots.txt",
                "/favicon.ico",
                "/sitemap.xml",
                "/.well-known/security.txt",
            ):
                resp = await client.get(f"{scheme}://{host}:{port}{path}")
                if resp.status_code == 200 and len(resp.content) > 0:
                    r.add(f"GET {path}", "ok", f"{resp.status_code} ({len(resp.content)} bytes)")
                else:
                    r.add(f"GET {path}", "tell", f"{resp.status_code} (real servers serve this)")

            # Server header
            root = await client.get(f"{scheme}://{host}:{port}/")
            server = root.headers.get("Server", "(none)")
            if server == "(none)":
                r.add("Server header", "warn", "no Server header (uncommon for real servers)")
            elif "honeypot" in server.lower() or server == "Python":
                r.add("Server header", "tell", server)
            else:
                r.add("Server header", "ok", server)

            # Persona consistency: Apache personas should put Server in the 404 body too.
            r404 = await client.get(
                f"{scheme}://{host}:{port}/this-does-not-exist-{int(time.time())}"
            )
            if r404.status_code == 404:
                body = r404.text.lower()
                if "apache" in server.lower() and "apache" not in body:
                    r.add(
                        "persona consistency",
                        "tell",
                        "Apache header but no Apache signature in 404",
                    )
                elif "nginx" in server.lower() and "<center>" not in body:
                    r.add(
                        "persona consistency", "tell", "Nginx header but missing Nginx 404 marker"
                    )
                else:
                    r.add("persona consistency", "ok", "404 body matches header persona")
            else:
                r.add(
                    "persona consistency",
                    "warn",
                    f"non-404 ({r404.status_code}) for nonexistent path",
                )

            # Response timing — uniform sub-ms is a fingerprint.
            timings = []
            for _ in range(5):
                t0 = time.monotonic()
                await client.get(f"{scheme}://{host}:{port}/")
                timings.append((time.monotonic() - t0) * 1000)
            mean = statistics.mean(timings)
            std = statistics.stdev(timings) if len(timings) > 1 else 0
            if std < 2.0:
                r.add("response jitter", "tell", f"std={std:.1f}ms — too uniform")
            else:
                r.add("response jitter", "ok", f"mean={mean:.0f}ms std={std:.1f}ms")

            # Session cookie issuance
            if any(c for c in root.cookies):
                r.add("session cookie", "ok", f"cookies: {dict(root.cookies)}")
            else:
                r.add(
                    "session cookie", "warn", "no session cookie (modern stacks usually issue one)"
                )
    except Exception as e:
        r.add("connect", "tell", f"probe failed: {e}")
    return r


# ── SMTP ────────────────────────────────────────────────────────────────


async def _probe_smtp(host: str, port: int) -> EngineReport:
    r = EngineReport("SMTP")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5.0)
        banner = await asyncio.wait_for(reader.readline(), timeout=3.0)
        r.add(
            "banner",
            "ok" if banner.startswith(b"220") else "tell",
            banner.decode(errors="replace").strip(),
        )

        writer.write(b"EHLO audit.local\r\n")
        await writer.drain()

        ehlo_lines: list[bytes] = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=3.0)
            ehlo_lines.append(line)
            if not line or (len(line) >= 4 and line[3:4] == b" "):
                break
        ehlo = b"".join(ehlo_lines).decode(errors="replace")
        required = ["PIPELINING", "STARTTLS", "AUTH PLAIN LOGIN", "ENHANCEDSTATUSCODES"]
        missing = [ext for ext in required if ext not in ehlo]
        if missing:
            r.add("EHLO extensions", "tell", f"missing: {', '.join(missing)}")
        else:
            r.add("EHLO extensions", "ok", "Postfix-realistic extension list")

        # VRFY behaviour — Postfix default is 252.
        writer.write(b"VRFY root\r\n")
        await writer.drain()
        vrfy = await asyncio.wait_for(reader.readline(), timeout=3.0)
        if vrfy.startswith(b"252"):
            r.add("VRFY response", "ok", "252 (Postfix default)")
        elif vrfy.startswith(b"550") or vrfy.startswith(b"502"):
            r.add("VRFY response", "warn", f"unusual: {vrfy.decode(errors='replace').strip()}")
        else:
            r.add("VRFY response", "tell", vrfy.decode(errors="replace").strip())

        writer.write(b"QUIT\r\n")
        await writer.drain()
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    except Exception as e:
        r.add("connect", "tell", f"probe failed: {e}")
    return r


# ── FTP ─────────────────────────────────────────────────────────────────


async def _probe_ftp(host: str, port: int) -> EngineReport:
    r = EngineReport("FTP")
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5.0)
        banner = await asyncio.wait_for(reader.readline(), timeout=3.0)
        r.add(
            "banner",
            "ok" if banner.startswith(b"220") else "tell",
            banner.decode(errors="replace").strip(),
        )

        # FEAT capability list
        writer.write(b"FEAT\r\n")
        await writer.drain()
        feat_lines: list[bytes] = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=3.0)
            feat_lines.append(line)
            if line.startswith(b"211 "):
                break
        feat = b"".join(feat_lines).decode(errors="replace")
        required = ["PASV", "SIZE", "MDTM", "UTF8"]
        missing = [f for f in required if f not in feat]
        r.add(
            "FEAT list",
            "tell" if missing else "ok",
            f"missing: {missing}" if missing else "complete",
        )

        # Anonymous login flow
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.readline(), timeout=3.0)
        writer.write(b"PASS audit@audit.local\r\n")
        await writer.drain()
        pass_resp = await asyncio.wait_for(reader.readline(), timeout=3.0)
        if pass_resp.startswith(b"230"):
            r.add("anonymous login", "ok", "230 accepted (realistic for public FTP)")
        else:
            r.add("anonymous login", "warn", pass_resp.decode(errors="replace").strip())

        writer.write(b"QUIT\r\n")
        await writer.drain()
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    except Exception as e:
        r.add("connect", "tell", f"probe failed: {e}")
    return r


# ── RDP ─────────────────────────────────────────────────────────────────


async def _probe_rdp(host: str, port: int) -> EngineReport:
    r = EngineReport("RDP")
    # Construct a minimal X.224 Connection Request with a Cookie field.
    cookie = b"Cookie: mstshash=audit@AUDIT\r\n"
    neg = bytes([0x01, 0x00]) + (8).to_bytes(2, "little") + (1).to_bytes(4, "little")
    var = cookie + neg
    x224 = bytes([6 + len(var), 0xE0, 0, 0, 0, 0, 0]) + var
    tpkt = bytes([3, 0]) + (4 + len(x224)).to_bytes(2, "big") + x224

    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5.0)
        writer.write(tpkt)
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(64), timeout=3.0)
        if not resp:
            r.add("X.224 CC response", "tell", "no response (real RDP servers always respond)")
        elif resp[0:1] == b"\x03" and len(resp) >= 6 and resp[5] == 0xD0:
            r.add("X.224 CC response", "ok", "valid TPKT + X.224 ConnectionConfirm")
            # Negotiation response type
            if len(resp) >= 12:
                neg_type = resp[11]
                if neg_type in (0x02, 0x03):
                    name = "success" if neg_type == 0x02 else "failure"
                    r.add("RDP negotiation", "ok", f"type {neg_type:#x} ({name})")
        else:
            r.add("X.224 CC response", "tell", f"malformed response: {resp[:8].hex()}")
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
    except Exception as e:
        r.add("connect", "tell", f"probe failed: {e}")
    return r


# ── TLS handshake fingerprinting ────────────────────────────────────────


def _probe_tls(host: str, port: int) -> EngineReport:
    """Synchronous TLS probe — checks cert is presented and handshake works
    against modern clients."""
    r = EngineReport(f"TLS (port {port})")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection((host, port), timeout=5.0) as raw,
            ctx.wrap_socket(raw, server_hostname=host) as s,
        ):
            cert = s.getpeercert(binary_form=True)
            cipher = s.cipher()
            version = s.version()
            r.add("handshake", "ok", f"completed: {version} {cipher[0] if cipher else '?'}")
            if cert:
                r.add("cert presented", "ok", f"{len(cert)} bytes")
            else:
                r.add("cert presented", "tell", "no certificate")
    except Exception as e:
        r.add("handshake", "tell", f"failed: {e}")
    return r


# ── Main ────────────────────────────────────────────────────────────────


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--ssh", type=int, help="SSH port")
    p.add_argument("--http", type=int, help="HTTP port")
    p.add_argument("--https", type=int, help="HTTPS port")
    p.add_argument("--smtp", type=int, help="SMTP port")
    p.add_argument("--ftp", type=int, help="FTP port")
    p.add_argument("--rdp", type=int, help="RDP port")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of markdown")
    return p.parse_args()


async def _run(args: argparse.Namespace) -> list[EngineReport]:
    reports: list[EngineReport] = []
    if args.ssh:
        reports.append(await _probe_ssh(args.host, args.ssh))
    if args.http:
        reports.append(await _probe_http(args.host, args.http, use_tls=False))
    if args.https:
        reports.append(await _probe_http(args.host, args.https, use_tls=True))
        reports.append(_probe_tls(args.host, args.https))
    if args.smtp:
        reports.append(await _probe_smtp(args.host, args.smtp))
    if args.ftp:
        reports.append(await _probe_ftp(args.host, args.ftp))
    if args.rdp:
        reports.append(await _probe_rdp(args.host, args.rdp))
    return reports


def main() -> int:
    args = parse_args()
    if not any([args.ssh, args.http, args.https, args.smtp, args.ftp, args.rdp]):
        print("error: pass at least one --<engine> port", file=sys.stderr)
        return 2

    reports = asyncio.run(_run(args))

    if args.json:
        out = {
            r.name: [
                {"surface": f.surface, "verdict": f.verdict, "detail": f.detail} for f in r.findings
            ]
            for r in reports
        }
        print(json.dumps(out, indent=2))
    else:
        print(f"# Honeypot Fingerprint Audit — {args.host}\n")
        for r in reports:
            print(r.to_markdown())

    total = sum(len(r.findings) for r in reports)
    tells = sum(1 for r in reports for f in r.findings if f.verdict == "tell")
    if not args.json:
        print(f"\n**Summary**: {tells} tell(s) / {total} surfaces probed.")
    return 1 if tells else 0


if __name__ == "__main__":
    sys.exit(main())
