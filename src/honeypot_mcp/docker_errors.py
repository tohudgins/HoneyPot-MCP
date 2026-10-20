"""Recognise a request the hardened Docker guard refused, and say so plainly.

On a hardened host the honeypot service has no Docker socket: it talks to
`hardening/docker_guard.py`, which forwards only the Cowrie operations and answers everything else
with a JSON `{"message": "honeypot docker guard: <reason>"}` (403 for policy, 400/413 for malformed
or oversized requests). The Docker SDK raises that as `docker.errors.APIError`, so an analysis tool
that starts its own container (Grafana, Suricata, Zeek) used to report "Unexpected failure (APIError)"
or "Docker could not look up <image>", which reads as a Docker fault. Nothing is wrong: the guard did
its job. This module turns that into an error that says so and a hint that says where to run the tool.
"""

from __future__ import annotations

from typing import Final

#: The prefix the guard puts on every refusal message (`docker_guard._deny_response`).
GUARD_MARKER: Final = "honeypot docker guard:"

_MAX_CHAIN: Final = 8


def _texts(exc: BaseException) -> list[str]:
    out = [str(exc)]
    explanation = getattr(exc, "explanation", None)
    if isinstance(explanation, str):
        out.append(explanation)
    response = getattr(exc, "response", None)
    body = getattr(response, "text", None)
    if isinstance(body, str):
        out.append(body)
    return out


def guard_refusal_reason(exc: BaseException | None) -> str | None:
    """The guard's stated reason when `exc` (or anything it wraps) is a guard refusal, else None.

    Follows `__cause__`/`__context__`, because the SDK wraps `requests.HTTPError` in `APIError`
    and callers wrap that again in `DockerException`.
    """
    seen: set[int] = set()
    current = exc
    for _ in range(_MAX_CHAIN):
        if current is None or id(current) in seen:
            return None
        seen.add(id(current))
        for text in _texts(current):
            pos = text.find(GUARD_MARKER)
            if pos >= 0:
                reason = text[pos + len(GUARD_MARKER) :].strip()
                # The SDK appends `")` after the quoted message, and callers clip long text.
                return reason.rstrip('")').strip() or None
        current = current.__cause__ or current.__context__
    return None


def guard_refusal(exc: BaseException | None, what: str = "this tool") -> dict[str, str] | None:
    """`{error, hint}` when the hardened Docker guard refused the request, else None.

    `what` names the tool for the message ("grafana_start", "pcap_detect", ...).
    """
    reason = guard_refusal_reason(exc)
    if reason is None:
        return None
    return {
        "error": (
            f"The hardened Docker guard refused a container request from {what} ({reason}). "
            "Docker itself is running; the guard only permits the honeypot's own Cowrie "
            "containers, and this tool starts one of its own."
        ),
        "hint": (
            "These analysis tools (grafana_start, pcap_detect, detection_rules_update) start "
            "containers of their own, so run them where Docker is yours to use, on a copy of the "
            "data (analysis mode on your own machine), not on the sensor host behind the guard. "
            "See docs/HARDENING.md: 'The analysis tools that start containers need Docker access "
            "the guard does not give'."
        ),
    }
