"""Defang / refang helpers.

Analysts share IOCs in a "defanged" form so they can't be clicked or auto-resolved,
e.g. ``hxxp://evil[.]com`` or ``user[at]evil[.]net``. iocsift refangs input before
extraction so defanged indicators are still detected, and can defang output for safe
sharing.
"""
from __future__ import annotations

import re

_REFANG_REPLACEMENTS = [
    (re.compile(r"\[\s*\.\s*\]"), "."),
    (re.compile(r"\(\s*\.\s*\)"), "."),
    (re.compile(r"\{\s*\.\s*\}"), "."),
    (re.compile(r"\[\s*dot\s*\]", re.IGNORECASE), "."),
    (re.compile(r"\[\s*://\s*\]"), "://"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*at\s*\]", re.IGNORECASE), "@"),
    (re.compile(r"\(\s*at\s*\)", re.IGNORECASE), "@"),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
]


def refang(text: str) -> str:
    """Convert defanged indicators in ``text`` back to their real form."""
    for pattern, repl in _REFANG_REPLACEMENTS:
        text = pattern.sub(repl, text)
    return text


def defang(value: str) -> str:
    """Defang a single indicator so it is safe to paste/share."""
    value = re.sub(r"https?", lambda m: m.group(0).replace("http", "hxxp"), value)
    value = value.replace("://", "[://]")
    value = value.replace(".", "[.]")
    value = value.replace("@", "[at]")
    return value
