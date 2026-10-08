"""TLS certificate helper for the HTTPS / SMTP STARTTLS / MySQL / RDP / Kubernetes engines.

A generated cert is per-honeypot, persisted to `tls/{honeypot_name}/`, and reused across
restarts so a scanner that pins certs sees a stable identity.

JA3/JA4 fingerprinting depends on the TLS handshake (cipher suites, extensions, supported
groups), which aiohttp / Python's `ssl` module handle. The *certificate* is what `nmap
--script ssl-cert`, `openssl s_client` and every scanner read next, so its shape has to be
the shape of the service being impersonated, and that differs:

* a kubeadm API server presents a leaf issued by a CA named `kubernetes` (`CN=kube-apiserver`,
  no organisation, one-year validity from cluster creation, the in-cluster service names and
  IPs as SANs, `serverAuth` only);
* MySQL 8 presents `CN=MySQL_Server_<ver>_Auto_Generated_Server_Certificate` issued by
  `CN=MySQL_Server_<ver>_Auto_Generated_CA_Certificate`, valid ten years, with no SAN;
* Windows RDP presents a self-signed `CN=<computer FQDN>` valid about six months;
* a distro "snakeoil" web or mail certificate is self-signed `CN=<hostname>`, ten years.

`CertProfile` describes one of these. A CA-issued profile signs the leaf with a CA key made
for that purpose and discarded (servers send only the leaf), so the issuer is a different
name from the subject, as it is for the real thing. A persisted certificate that no longer
matches the requested profile (a changed hostname, an upgrade that changed the shape) or
that is close to expiring is regenerated, the way an operator renews one.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import ssl
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from honeypot_mcp.config import get_settings
from honeypot_mcp.secure_io import ensure_private_dir, write_private_file

log = logging.getLogger(__name__)

# Serialises first-time generation. Two concurrent first starts for the same
# honeypot (HTTPS deploy racing a STARTTLS upgrade) would otherwise each write a
# cert and a key and could leave a cert from one run beside a key from the other.
_generate_lock = threading.Lock()

SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
REMOTE_DESKTOP_AUTH = "1.3.6.1.4.1.311.54.1.2"  # what a self-signed Windows RDP cert carries


@dataclass(frozen=True)
class CertProfile:
    """The shape of the certificate a service presents. Every field defaults to a distro
    "snakeoil" self-signed certificate named after the honeypot."""

    common_name: str | None = None  # default: the honeypot's name
    issuer_common_name: str | None = None  # None: self-signed
    days: int = 3650
    # None: backdated by a stable 1-13 months derived from the honeypot name, so the cert looks
    # installed some time ago and every restart agrees.
    not_before: datetime | None = None
    dns_names: tuple[str, ...] | None = None  # None: just the common name
    ip_addresses: tuple[str, ...] = ()
    # Whether to add a critical digitalSignature+keyEncipherment keyUsage, and the extended key
    # usage OIDs (dotted) to add; () adds none. A bare snakeoil cert has neither.
    key_usage: bool = False
    extended_key_usage: tuple[str, ...] = ()


# A certificate this close to `notAfter` is renewed, as an operator would, rather than served
# expired (a tell once the clock passes it).
_RENEW_WINDOW = timedelta(days=30)


def _cert_dir(honeypot_name: str) -> Path:
    """Per-honeypot cert directory, confined to `tls/`.

    Defence in depth: `honeypot_deploy` already rejects unsafe names, but this
    is the point where a name becomes a filesystem path, and it has other
    callers (restart reconciliation, cloning). A name like `../../etc` would
    otherwise write a private key outside the intended tree.
    """
    root = get_settings().tls_dir.resolve()
    p = (root / honeypot_name).resolve()
    if p != root and root not in p.parents:
        raise ValueError(f"Unsafe honeypot name for a certificate directory: {honeypot_name!r}")
    # Private-key material lives under here: owner-only from the first instant.
    ensure_private_dir(root)
    ensure_private_dir(p)
    return p


def _stable_backdate(honeypot_name: str) -> timedelta:
    digest = hashlib.sha256(f"tls-age:{honeypot_name}".encode()).digest()
    days = 30 + int.from_bytes(digest[:2], "big") % 360
    return timedelta(days=days, seconds=int.from_bytes(digest[2:5], "big") % 86400)


def _generate_cert(
    honeypot_name: str, profile: CertProfile, cert_path: Path, key_path: Path
) -> None:
    """Generate an RSA-2048 leaf for `profile` at the given paths.

    `cryptography` is a transitive dep through `joserfc` / `authlib`, so it's
    available at runtime without adding a top-level dependency."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ObjectIdentifier

    cn = profile.common_name or honeypot_name
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    ca_key = None
    if profile.issuer_common_name:
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, profile.issuer_common_name)])
        signing_key = ca_key
    else:
        issuer, signing_key = subject, key

    now = datetime.now(UTC)
    start = profile.not_before or (now - _stable_backdate(honeypot_name))
    if start + timedelta(days=profile.days) < now + _RENEW_WINDOW:
        # The profile's own start date leaves no life in the certificate (a fixed creation date
        # in the past): issue it now instead.
        start = now - timedelta(days=1)
    names = profile.dns_names if profile.dns_names is not None else (cn,)
    sans: list[x509.GeneralName] = [x509.DNSName(n) for n in names]
    sans += [x509.IPAddress(ipaddress.ip_address(a)) for a in profile.ip_addresses]

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + timedelta(days=profile.days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if profile.key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if profile.extended_key_usage:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ObjectIdentifier(o) for o in profile.extended_key_usage]),
            critical=False,
        )
    if ca_key is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    cert = builder.sign(signing_key, hashes.SHA256())

    # Key first: a cert on disk then always has its key beside it, so the
    # "both exist" check in ensure_cert never sees a cert without a key.
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    write_private_file(key_path, key_pem)
    write_private_file(cert_path, cert.public_bytes(serialization.Encoding.PEM))


def _is_current(cert_path: Path, honeypot_name: str, profile: CertProfile) -> bool:
    """True if the persisted certificate still has the identity `profile` asks for and is not
    about to expire. An unreadable certificate is not current."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except (OSError, ValueError):
        return False

    def cn_of(name: x509.Name) -> str | None:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return str(attrs[0].value) if attrs else None

    wanted_subject = profile.common_name or honeypot_name
    wanted_issuer = profile.issuer_common_name or wanted_subject
    return (
        cn_of(cert.subject) == wanted_subject
        and cn_of(cert.issuer) == wanted_issuer
        # A certificate from before profiles carried an organisation no real service adds.
        and not cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        and cert.not_valid_after_utc > datetime.now(UTC) + _RENEW_WINDOW
    )


def ensure_cert(
    honeypot_name: str,
    common_name: str | None = None,
    profile: CertProfile | None = None,
) -> tuple[Path, Path]:
    """Return `(cert_path, key_path)` for this honeypot, generating if absent or no longer
    matching `profile` (which defaults to a self-signed cert named `common_name`)."""
    wanted = profile or CertProfile(common_name=common_name)
    d = _cert_dir(honeypot_name)
    cert_path = d / "server.crt"
    key_path = d / "server.key"

    def current() -> bool:
        return (
            cert_path.exists()
            and key_path.exists()
            and _is_current(cert_path, honeypot_name, wanted)
        )

    if not current():
        with _generate_lock:
            if not current():
                log.info(
                    "Generating TLS cert for honeypot '%s' (CN=%s, issuer=%s)",
                    honeypot_name,
                    wanted.common_name or honeypot_name,
                    wanted.issuer_common_name or "self-signed",
                )
                _generate_cert(honeypot_name, wanted, cert_path, key_path)
    return cert_path, key_path


def build_server_ssl_context(
    honeypot_name: str,
    common_name: str | None = None,
    profile: CertProfile | None = None,
) -> ssl.SSLContext:
    """Build an `ssl.SSLContext` configured for server-side TLS with our cert. Loaded with
    broad cipher support so we don't reject older scanners (which would itself be a
    fingerprint)."""
    cert_path, key_path = ensure_cert(honeypot_name, common_name, profile)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx


async def build_server_ssl_context_async(
    honeypot_name: str,
    common_name: str | None = None,
    profile: CertProfile | None = None,
) -> ssl.SSLContext:
    """`build_server_ssl_context` off the event loop.

    First-time generation is RSA-2048 key generation (tens to hundreds of ms of
    CPU), which freezes every honeypot sharing the loop if run inline. Callers in
    async code should prefer this variant.
    """
    return await asyncio.to_thread(build_server_ssl_context, honeypot_name, common_name, profile)
