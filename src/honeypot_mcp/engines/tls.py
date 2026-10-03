"""Self-signed TLS cert helper for the HTTPS / SMTP STARTTLS engines.

Generated cert is per-honeypot, persisted to `tls/{honeypot_name}/`, and
reused across restarts so a scanner that pins certs sees a stable identity.

We don't try to look like a public CA-issued cert — JA3/JA4 fingerprinting
doesn't depend on the cert chain, it depends on the TLS handshake (cipher
suites, extensions, supported groups), and aiohttp / Python's `ssl` module
handle that. The cert is plausibly self-signed-corporate-CA shape: 2048-bit
RSA, SHA-256 signature, 1-year validity, CN from the persona/hostname or a
generic placeholder.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from honeypot_mcp.secure_io import ensure_private_dir, write_private_file

log = logging.getLogger(__name__)

# Serialises first-time generation. Two concurrent first starts for the same
# honeypot (HTTPS deploy racing a STARTTLS upgrade) would otherwise each write a
# cert and a key and could leave a cert from one run beside a key from the other.
_generate_lock = threading.Lock()


def _cert_dir(honeypot_name: str) -> Path:
    """Per-honeypot cert directory, confined to `tls/`.

    Defence in depth: `honeypot_deploy` already rejects unsafe names, but this
    is the point where a name becomes a filesystem path, and it has other
    callers (restart reconciliation, cloning). A name like `../../etc` would
    otherwise write a private key outside the intended tree.
    """
    root = Path("tls").resolve()
    p = (root / honeypot_name).resolve()
    if p != root and root not in p.parents:
        raise ValueError(f"Unsafe honeypot name for a certificate directory: {honeypot_name!r}")
    # Private-key material lives under here: owner-only from the first instant.
    ensure_private_dir(root)
    ensure_private_dir(p)
    return p


def _generate_cert(common_name: str, cert_path: Path, key_path: Path) -> None:
    """Generate a self-signed RSA-2048 cert at the given paths.

    `cryptography` is a transitive dep through `joserfc` / `authlib`, so it's
    available at runtime without adding a top-level dependency."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Internal"),
        ]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name), x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    # Key first: a cert on disk then always has its key beside it, so the
    # "both exist" check in ensure_cert never sees a cert without a key.
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    write_private_file(key_path, key_pem)
    write_private_file(cert_path, cert.public_bytes(serialization.Encoding.PEM))


def ensure_cert(honeypot_name: str, common_name: str | None = None) -> tuple[Path, Path]:
    """Return `(cert_path, key_path)` for this honeypot, generating if absent."""
    d = _cert_dir(honeypot_name)
    cert_path = d / "server.crt"
    key_path = d / "server.key"
    if not cert_path.exists() or not key_path.exists():
        with _generate_lock:
            if not cert_path.exists() or not key_path.exists():
                cn = common_name or honeypot_name
                log.info(
                    "Generating self-signed TLS cert for honeypot '%s' (CN=%s)", honeypot_name, cn
                )
                _generate_cert(cn, cert_path, key_path)
    return cert_path, key_path


def build_server_ssl_context(honeypot_name: str, common_name: str | None = None) -> ssl.SSLContext:
    """Build an `ssl.SSLContext` configured for server-side TLS with our
    self-signed cert. Loaded with broad cipher support so we don't reject
    older scanners (which would itself be a fingerprint)."""
    cert_path, key_path = ensure_cert(honeypot_name, common_name)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx


async def build_server_ssl_context_async(
    honeypot_name: str, common_name: str | None = None
) -> ssl.SSLContext:
    """`build_server_ssl_context` off the event loop.

    First-time generation is RSA-2048 key generation (tens to hundreds of ms of
    CPU), which freezes every honeypot sharing the loop if run inline. Callers in
    async code should prefer this variant.
    """
    return await asyncio.to_thread(build_server_ssl_context, honeypot_name, common_name)
