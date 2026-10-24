"""Matching a honeytoken by what a person says, not by how it was spelled when it was made.

A token made as `public-bait-mysql-env` is "the public bait credential" to the person asking. The
words of what they said must all appear in the label or the token's type, whatever separates them
in the stored name, and filler like "the" or "token" says nothing about which token is meant.
"""

from __future__ import annotations

import re

# Words around a token's name that say nothing about which token is meant ("the bait token").
FILLER_WORDS = frozenset({"the", "a", "an", "my", "our", "that", "this", "token", "tokens"})


def label_words(text: str | None) -> list[str]:
    """The words of `text` that identify a token, lower-cased; empty when it holds none."""
    return [w for w in re.findall(r"[a-z0-9]+", (text or "").lower()) if w not in FILLER_WORDS]


def label_matches(label: str | None, type_name: str, words: list[str]) -> bool:
    """True when every word is in the token's label or type (False for no words at all)."""
    if not words:
        return False
    haystack = f"{(label or '').lower()} {type_name.lower()}"
    return all(w in haystack for w in words)
