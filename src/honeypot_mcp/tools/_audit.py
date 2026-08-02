"""Recording of state-changing control-plane actions.

The control plane here is driven by a language model, so after an incident the
question isn't only "what did the attacker do" but "what did the agent do".
`alerts_prune` can delete months of evidence; `honeypot_stop` can silently end
collection. Neither previously left any trace.

Three rules shape this module:

* **Auditing must never break the action.** A failure to write the audit row is
  logged and swallowed — refusing to stop a honeypot because the audit table is
  unavailable would be a worse outcome than a missing row.
* **Secrets never land in the log.** Tool arguments are recorded so an operator
  can see what was requested, which means anything credential-shaped has to be
  redacted on the way in.
* **The actor is resolved here, not by the caller.** Every `record_action`
  call site used to record *what* happened with no way to say *who* did it —
  fine for a solo operator, useless for a team sharing role-scoped tokens.
  Resolving `rbac.current_actor()` inside this function instead of threading
  an `actor=` parameter through every one of the ~10 call sites means new
  call sites get correct attribution for free and none of the existing ones
  needed to change.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

# Argument names whose values must never be persisted. Matched case-insensitively
# as substrings, so `hmac_secret`, `api_token` and `aws_secret_access_key` are
# all covered without enumerating every caller's spelling.
_SECRET_HINTS = (
    "secret",
    "token",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "credential",
    "auth",
)

_REDACTED = "[redacted]"
_MAX_VALUE_CHARS = 200


def redact_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Strip credential-shaped values and clip long ones."""
    out: dict[str, Any] = {}
    for key, value in arguments.items():
        if value is None:
            continue
        if any(hint in key.lower() for hint in _SECRET_HINTS):
            out[key] = _REDACTED
            continue
        out[key] = _redact_value(value)
    return out


def _redact_value(value: Any) -> Any:
    """Recurse into dicts AND lists so a secret nested inside either is still
    caught — e.g. a list of {"username": ..., "password": ...} pairs. A bare
    dict value used to be the only recursed case; a list of dicts fell
    through untouched to the caller's `else: out[key] = value`."""
    if isinstance(value, dict):
        return redact_arguments(value)
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    if isinstance(value, str) and len(value) > _MAX_VALUE_CHARS:
        return value[:_MAX_VALUE_CHARS] + "…"
    return value


async def record_action(
    tool: str,
    summary: str,
    *,
    arguments: dict[str, Any] | None = None,
    target: str | None = None,
    outcome: str = "ok",
    error: str | None = None,
) -> None:
    """Append one audit row. Never raises."""
    try:
        from honeypot_mcp.rbac import current_actor
        from honeypot_mcp.storage.database import get_session
        from honeypot_mcp.storage.models import AuditLog

        async with get_session() as session:
            session.add(
                AuditLog(
                    tool=tool,
                    summary=summary,
                    arguments=redact_arguments(arguments or {}),
                    target=target,
                    outcome=outcome,
                    error=error[:2000] if error else None,
                    actor=current_actor(),
                )
            )
    except Exception:
        # An unwritable audit table must not prevent the operator from acting.
        log.exception("Failed to write audit log entry for %s", tool)
