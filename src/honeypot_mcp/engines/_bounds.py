"""Small shared helpers for the per-connection bounds the binary engines enforce."""

from __future__ import annotations

import asyncio


def write_backlogged(transport: asyncio.Transport, limit: int) -> bool:
    """True when the peer is not reading its replies: the transport's write buffer
    has grown past `limit` bytes. Callers close the connection rather than keep
    queueing replies for a peer that never drains them."""
    try:
        return transport.get_write_buffer_size() > limit
    except NotImplementedError:  # bare asyncio.Transport subclasses (test doubles)
        return False
