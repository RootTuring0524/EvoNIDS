"""Redaction for everything that leaves the platform.

This is a **local, small implementation** of the same idea as
``app.services.agent_tools.redact_text`` / ``_redact_mapping``. It is duplicated
on purpose: importing ``app.services.agent_tools`` would pull the investigation
tool registry (and its SQLAlchemy model imports) into the outbound integration
package, creating an import cycle risk for a helper that is 40 lines long. The
patterns are kept intentionally identical so a secret masked in one place is
masked in the other; :mod:`tests.test_integrations` asserts the behaviour.

Rules:

* credential-shaped substrings are replaced, never truncated away silently;
* every string is bounded, and the truncation is *stated* (``...[truncated N
  chars]``) so a reader can tell an incomplete payload from a complete one;
* mappings and sequences are walked with bounded depth and breadth so a hostile
  or enormous payload cannot turn redaction itself into a denial of service.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

MAX_TEXT_CHARS = 600
MAX_DEPTH = 6
MAX_ITEMS = 40

SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Generic high-entropy API keys (sk-..., pk-..., also covers sk_live_ style).
    # The body may contain hyphens/underscores (sk-live-..., pk_test_...), so the
    # character class has to allow them or a real key would slip through.
    (re.compile(r"\b(?:sk|pk)[-_][A-Za-z0-9][A-Za-z0-9_-]{14,}\b"), "[redacted-key]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "[redacted-jwt]"),
    (re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|apikey)\s*[=:]\s*\S+"), r"\1=[redacted]"),
    # Bearer runs before the authorization rule below: that rule consumes only the
    # scheme word, which would leave the token itself in cleartext right after it.
    (re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{8,}"), "Bearer [redacted]"),
    (
        re.compile(r"(?i)\b(authorization)\s*[=:]\s*(?:Bearer\s+)?[^\s,;]+"),
        r"\1=[redacted]",
    ),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        "[redacted-private-key]",
    ),
)

# Keys that never leave the process regardless of their value's shape: an
# integration payload keyed "apiKey" is a secret even when the value looks
# harmless (for example a one-character test key).
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|apikey|authorization|credential|private[_-]?key|signature|hmac)"
)


def redact_text(value: str, *, limit: int = MAX_TEXT_CHARS) -> str:
    """Mask credential-shaped content and bound the length of a string."""
    redacted = value
    for pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    if len(redacted) > limit:
        return redacted[:limit] + f"...[truncated {len(redacted) - limit} chars]"
    return redacted


def redact_mapping(value: Any, *, depth: int = 0, limit: int = MAX_TEXT_CHARS) -> Any:
    """Recursively redact a JSON-shaped value with bounded depth and breadth."""
    if depth >= MAX_DEPTH:
        return "[redacted: max depth]"
    if isinstance(value, str):
        return redact_text(value, limit=limit)
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_ITEMS:
                result["...[truncated]"] = f"{len(value) - MAX_ITEMS} more keys"
                break
            key_text = str(key)
            if SENSITIVE_KEY_PATTERN.search(key_text):
                result[key_text] = "[redacted]"
            else:
                result[key_text] = redact_mapping(item, depth=depth + 1, limit=limit)
        return result
    if isinstance(value, Sequence):
        items = list(value)
        redacted_items = [redact_mapping(item, depth=depth + 1, limit=limit) for item in items[:MAX_ITEMS]]
        if len(items) > MAX_ITEMS:
            redacted_items.append(f"...[truncated {len(items) - MAX_ITEMS} items]")
        return redacted_items
    return redact_text(str(value), limit=limit)
