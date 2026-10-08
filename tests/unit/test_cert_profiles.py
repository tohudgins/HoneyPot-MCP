"""The certificate each engine presents, and the port Apache's 404 page names.

`nmap --script ssl-cert`, `openssl s_client` and every scanner read the certificate right
after the handshake, so its shape is part of the fingerprint: a kubeadm API server's leaf is
issued by a CA called `kubernetes`, MySQL's by an auto-generated CA, a Windows RDP cert is
self-signed and named for the computer (the name the NTLM challenge discloses). A single
generic self-signed `O=Internal` certificate gave all of them away.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")


def _load(path):
    return x509.load_pem_x509_certificate(path.read_bytes())


def _cn(name: x509.Name) -> str:
    return str(name.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)


def _sans(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return (
        ext.get_values_for_type(x509.DNSName),
        [str(ip) for ip in ext.get_values_for_type(x509.IPAddress)],
    )


def _days(cert: x509.Certificate) -> float:
    return (cert.not_valid_after_utc - cert.not_valid_before_utc).total_seconds() / 86400


def test_kubernetes_certificate_is_a_leaf_issued_by_a_ca_named_kubernetes():
    from honeypot_mcp.engines.kubernetes import _CERT_PROFILE
    from honeypot_mcp.engines.tls import ensure_cert

    cert_path, _ = ensure_cert("k8s-cert", profile=_CERT_PROFILE)
    cert = _load(cert_path)

    assert _cn(cert.subject) == "kube-apiserver" and _cn(cert.issuer) == "kubernetes"
    assert not cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    dns, ips = _sans(cert)
    assert {"kubernetes", "kubernetes.default.svc.cluster.local"} <= set(dns)
    assert "10.96.0.1" in ips
    assert _days(cert) == 365
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    # An issued certificate names its issuer's key; a self-signed one needs no such field here.
    cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert cert.not_valid_after_utc > datetime.now(UTC), "never served expired"


def test_mysql_certificate_matches_the_one_mysql_8_generates_at_first_start():
    from honeypot_mcp.engines.mysql import _CERT_PROFILE
    from honeypot_mcp.engines.tls import ensure_cert

    cert = _load(ensure_cert("mysql-cert", profile=_CERT_PROFILE)[0])

    assert _cn(cert.subject) == "MySQL_Server_8.0.36_Auto_Generated_Server_Certificate"
    assert _cn(cert.issuer) == "MySQL_Server_8.0.36_Auto_Generated_CA_Certificate"
    assert _days(cert) == 3650
    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)


def test_rdp_certificate_is_self_signed_and_named_like_the_ntlm_identity():
    """`rdp-ntlm-info` reports the computer name from the NTLM challenge; `ssl-cert` reports the
    certificate's. Two different names are two different hosts."""
    from honeypot_mcp.engines.rdp import _cert_profile
    from honeypot_mcp.engines.rdp_nla import identity_for
    from honeypot_mcp.engines.tls import REMOTE_DESKTOP_AUTH, ensure_cert

    config = {"rdp_hostname": "FS-RDP01", "rdp_domain": "corp.example"}
    cert = _load(ensure_cert("rdp-cert", profile=_cert_profile("rdp-cert", config))[0])

    ident = identity_for("rdp-cert", config)
    assert _cn(cert.subject) == ident.dns_computer == "fs-rdp01.corp.example"
    assert cert.subject == cert.issuer
    assert _days(cert) == 182
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert [o.dotted_string for o in eku] == [REMOTE_DESKTOP_AUTH]


def test_default_certificate_is_a_bare_self_signed_cn_without_localhost_or_organisation():
    from honeypot_mcp.engines.tls import ensure_cert

    cert = _load(ensure_cert("plain-host", common_name="web01.example.com")[0])

    assert cert.subject == cert.issuer
    assert [a.oid for a in cert.subject] == [NameOID.COMMON_NAME]
    assert _sans(cert) == (["web01.example.com"], []), "a `localhost` SAN names the sensor"
    assert _days(cert) == 3650
    # Installed some time ago, the same on every restart of this honeypot.
    assert datetime.now(UTC) - cert.not_valid_before_utc > timedelta(days=29)


def test_a_matching_certificate_is_kept_and_a_changed_identity_is_reissued():
    from honeypot_mcp.engines.tls import CertProfile, ensure_cert

    first, _ = ensure_cert("keep-me", common_name="a.example.com")
    kept = first.read_bytes()
    ensure_cert("keep-me", common_name="a.example.com")
    assert first.read_bytes() == kept, "a restart must present the same certificate"

    ensure_cert("keep-me", common_name="b.example.com")
    assert _cn(_load(first).subject) == "b.example.com"

    ensure_cert(
        "keep-me", profile=CertProfile(common_name="b.example.com", issuer_common_name="CA")
    )
    assert _cn(_load(first).issuer) == "CA"


def test_a_certificate_from_before_profiles_is_replaced_and_an_expiring_one_is_renewed():
    """Existing deployments hold `O=Internal` certificates; an expiring one is a tell too."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    from honeypot_mcp.engines.tls import _cert_dir, ensure_cert

    def write(name: str, org: str | None, days_left: int) -> bytes:
        d = _cert_dir(name)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        attrs = [x509.NameAttribute(NameOID.COMMON_NAME, name)]
        if org:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
        subject = x509.Name(attrs)
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(now - timedelta(days=300))
            .not_valid_after(now + timedelta(days=days_left))
            .sign(key, hashes.SHA256())
        )
        (d / "server.key").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        (d / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return (d / "server.crt").read_bytes()

    old = write("legacy-org", "Internal", 300)
    assert ensure_cert("legacy-org")[0].read_bytes() != old
    assert not _load(ensure_cert("legacy-org")[0]).subject.get_attributes_for_oid(
        NameOID.ORGANIZATION_NAME
    )

    soon = write("about-to-expire", None, 5)
    renewed = _load(ensure_cert("about-to-expire")[0])
    assert ensure_cert("about-to-expire")[0].read_bytes() != soon
    assert renewed.not_valid_after_utc > datetime.now(UTC) + timedelta(days=300)


def test_a_profile_dated_in_the_past_still_yields_a_certificate_with_life_left():
    """The Kubernetes profile starts at a fixed cluster-creation date; once its year is nearly
    up the certificate is issued now rather than served expired."""
    from honeypot_mcp.engines.tls import CertProfile, ensure_cert

    profile = CertProfile(
        common_name="old", days=365, not_before=datetime.now(UTC) - timedelta(days=360)
    )
    cert = _load(ensure_cert("past-start", profile=profile)[0])
    assert cert.not_valid_after_utc > datetime.now(UTC) + timedelta(days=300)


# ── Apache's 404 page names the port the request used ────────────────────────────────────────


@pytest.mark.parametrize(
    ("host_header", "local_port", "host", "port"),
    [
        ("shop.example.com:8443", 9999, "shop.example.com", 8443),
        ("shop.example.com", 8443, "shop.example.com", 8443),
        ("", 8080, "", 8080),
        ("[::1]:8443", 80, "[::1]", 8443),
        ("[::1]", 8443, "[::1]", 8443),
        ("host:notaport", 8443, "host", 8443),
        ("host:99999", 8443, "host", 8443),
    ],
)
def test_split_host_port(host_header, local_port, host, port):
    from honeypot_mcp.engines.http_personas import split_host_port

    assert split_host_port(host_header, local_port) == (host, port)


def test_apache_404_names_the_host_without_a_port_and_the_port_actually_used():
    from honeypot_mcp.engines.http_personas import get_persona

    body = get_persona("apache_ubuntu").render_not_found("shop.example.com:8443", 9999)
    assert "<address>Apache/2.4.41 (Ubuntu) Server at shop.example.com Port 8443</address>" in body
    assert "Port 80<" not in body
    # The other stacks have no port in their page and are unaffected.
    assert "Port" not in get_persona("nginx_stable").render_not_found("h:1", 1)


@pytest.fixture
async def _db():
    from honeypot_mcp import suppression
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    suppression.invalidate_rule_cache()
    event_buffer.reset_for_tests()
    await init_db()
    buffer = event_buffer.get_buffer()
    await buffer.start()
    yield
    await buffer.stop()
    await close_db()
    event_buffer.reset_for_tests()


@pytest.mark.asyncio
async def test_live_apache_404_on_a_non_default_port_says_so(_db):
    """A 404 on a listener that is not on port 80 used to claim `Port 80`."""
    import socket

    import httpx

    from honeypot_mcp.engines.http import HTTPEngine

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    engine = HTTPEngine()
    cid = await engine.start("apache-404-port", port, {"persona": "apache_ubuntu"})
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            no_port_in_host = await client.get(
                f"http://127.0.0.1:{port}/definitely-missing", headers={"Host": "intranet.local"}
            )
            with_port = await client.get(
                f"http://127.0.0.1:{port}/definitely-missing",
                headers={"Host": "intranet.local:8443"},
            )
    finally:
        await engine.stop(cid)
    assert f"Server at intranet.local Port {port}</address>" in no_port_in_host.text
    assert "Server at intranet.local Port 8443</address>" in with_port.text
