"""SSH-key honeytoken provider — planted private keys with fingerprint tracking.

Generates a real RSA-2048 SSH keypair. The private key is what the operator
plants somewhere attractive (a developer's home directory backup, a leaked
S3 bucket, a git repository's commit history). The token's metadata records
the public-key fingerprint so when an attacker uses the key to authenticate
against our SSH honeypot, we match the fingerprint and fire CRITICAL.

Trigger path:

    Attacker → SSH honeypot with planted key → Cowrie's public-key auth
    log records the fingerprint → ssh_key_match.py recognises it →
    severity escalates to CRITICAL, alert tagged with honeytoken_id,
    token flips ACTIVE → TRIGGERED.

Documented as a real-world detection technique because SSH keys leak through
specific vectors that credential matchers can't see (`git log -p` history,
public S3 buckets, dev-laptop backups). A key with a known fingerprint
appearing in any auth attempt is high-fidelity evidence of compromise.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import uuid
from pathlib import Path
from typing import Any

from honeypot_mcp.tokens.base import HoneytokenProvider


def _generate_keypair() -> tuple[str, str, str]:
    """Generate an RSA-2048 SSH keypair.

    Returns:
        (private_key_pem, public_key_openssh, sha256_fingerprint)
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_openssh = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
        .decode("utf-8")
    )

    # SHA256 fingerprint, OpenSSH format: `SHA256:<base64-no-padding>`
    # Compute against the binary SSH wire-format public key (the part of
    # public_openssh between the algorithm name and the comment).
    parts = public_openssh.strip().split()
    if len(parts) >= 2:
        key_blob = base64.b64decode(parts[1])
        digest = hashlib.sha256(key_blob).digest()
        fp = base64.b64encode(digest).rstrip(b"=").decode("ascii")
        fingerprint = f"SHA256:{fp}"
    else:
        fingerprint = "SHA256:unknown"

    return private_pem, public_openssh, fingerprint


class SSHKeyProvider(HoneytokenProvider):
    async def create(self, options: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        token_uid = uuid.uuid4().hex
        comment = options.get("comment", f"deploy-{token_uid[:8]}@server")

        private_pem, public_openssh, fingerprint = _generate_keypair()
        # Append the comment to the public key like real ssh-keygen output.
        public_openssh = f"{public_openssh.strip()} {comment}\n"

        # Write the private key to reports/generated/ so the operator can
        # actually plant it. The path is the token_value so the operator can
        # find it again via honeytoken_export.
        out_dir = Path("reports/generated")
        out_dir.mkdir(parents=True, exist_ok=True)
        key_path = out_dir / f"id_rsa_{token_uid}"
        key_path.write_text(private_pem)
        # Match real ssh-keygen permissions on POSIX. Best-effort on Windows.
        with contextlib.suppress(OSError):
            key_path.chmod(0o600)

        meta = {
            "token_uid": token_uid,
            "fingerprint": fingerprint,
            "public_key": public_openssh.strip(),
            "private_key_path": str(key_path),
            "comment": comment,
            "key_type": "rsa-2048",
        }
        return fingerprint, meta

    def plant_instructions(self, token_value: str, metadata: dict[str, Any]) -> str:
        return (
            f"SSH-key honeytoken created.\n\n"
            f"  Fingerprint: {metadata.get('fingerprint')}\n"
            f"  Private key: {metadata.get('private_key_path')}\n"
            f"  Public key:  {metadata.get('public_key')}\n\n"
            f"Plant the private key file where an attacker would discover it:\n"
            f"  - ~/.ssh/id_rsa on a backup drive image\n"
            f"  - Hard-coded in a 'forgotten' git commit (use BFG to extract from history)\n"
            f"  - Leaked S3 bucket or public Pastebin under a realistic filename\n"
            f"  - Inside a Docker image layer that 'accidentally' shipped a build secret\n\n"
            f"When an attacker tries to authenticate to your SSH honeypot using this\n"
            f"key, Cowrie's public-key-auth event records the SHA256 fingerprint and\n"
            f"the alert pipeline matches it back to this token, escalating to\n"
            f"CRITICAL with the originating honeytoken_id linked.\n\n"
            f"You can also paste the public key into a real SSH server's\n"
            f"~/.ssh/authorized_keys (with a `command=` restriction or `from=`\n"
            f"clause to make it harmless) so a real-world auth attempt fires audit\n"
            f"logs you can ship to your SIEM."
        )
