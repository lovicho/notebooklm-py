"""Dependency-free validation and expiry normalization for cookie rows.

Cookie rows come from browser stores, rookiepy, and hand-editable JSON.  Keep
the small amount of schema handling in this leaf so every loader and writer
agrees about session cookies and malformed expiry values before a stdlib
``Cookie`` object is constructed.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any


class CookieRowError(ValueError):
    """A cookie row is structurally or semantically unusable.

    The message is deliberately structural only.  Callers may use the
    ``field`` attribute for bounded diagnostics without ever including a
    credential, raw expiry, or arbitrary converter exception text.
    """

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"invalid cookie row field {field}: {reason}")


@dataclass(frozen=True)
class NormalizedExpiry:
    """Normalized expiry plus whether it represents a session cookie."""

    value: int | float | None
    session: bool


def normalize_cookie_expiry(raw: Any) -> NormalizedExpiry:
    """Normalize a storage expiry without allowing ``Cookie`` to guess.

    ``None`` and the exact non-boolean integer ``-1`` are Playwright's
    session-cookie forms.  Every other accepted numeric representation is a
    dated value, including ``-1.0`` and ``"-1"``.  Dated values use the same
    ``int(float(value))`` conversion as ``http.cookiejar``.
    """
    if raw is None or (type(raw) is int and raw == -1):
        return NormalizedExpiry(None, True)

    if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
        raise CookieRowError("expires", "unsupported type")

    try:
        numeric = float(raw)
        if not math.isfinite(numeric):
            raise CookieRowError("expires", "non-finite number")
        value = int(numeric)
    except CookieRowError:
        raise
    except (ValueError, TypeError, OverflowError) as exc:
        raise CookieRowError("expires", "not numeric") from exc

    # Preserve the distinction between a dated -1 and Playwright's session
    # sentinel after the row is handed to ``http.cookiejar.Cookie``.
    if value == -1:
        return NormalizedExpiry(-1.0, False)
    return NormalizedExpiry(value, False)


def validate_cookie_shape(
    entry: Any, *, check_value: bool = True, require_nonempty_value: bool = True
) -> dict[str, Any]:
    """Validate identity/value fields and return a shallow normalized copy.

    The canonical "is this row usable?" predicate.  The load- and write-path
    spellings are adapters over this one, differing only in how they report a
    defect: :func:`notebooklm._auth.cookies._sanitize_cookie_entry` returns
    ``None`` and logs a redacted diagnostic, the write-time domain filter
    (:func:`notebooklm._auth.storage.filter_storage_state_cookies_by_domain_policy`) maps
    :attr:`CookieRowError.field` to a bounded per-field warning, and callers that
    want the raise take it straight.  Keeping the *checks* here and the *failure
    mode* at the boundary is what stops "is this row usable" from being
    re-derived per call site.

    ``check_value=False`` skips the value field entirely, for the callers that
    gate on identity alone: the write-time filter keeps rows whose value it never
    reads, and the recovery observation deliberately records identities for
    value-less rows so a rotation can replace them.  ``require_nonempty_value``
    narrows the check when it *is* performed (a present-but-empty value is a
    usable identity for the CLI import preview, but not for a request jar).

    Expiry is intentionally not touched here.  Recovery's persisted-liveness
    predicate needs to recognize a structurally valid row with a malformed
    expiry as present on disk, while routing and conversion must reject it.

    Not yet universal: ``_auth/storage.py``'s snapshot helper still re-derives
    the same four checks with a third failure mode (silent ``None``). Routing it
    is a follow-up — ``cookie_semantics`` is a leaf with no first-party imports,
    so the edge would be cycle-free.
    """
    if not isinstance(entry, dict):
        raise CookieRowError("row", "not a dict")

    for field in ("name", "domain"):
        value = entry.get(field)
        if not isinstance(value, str) or not value:
            raise CookieRowError(field, "missing or non-string")

    if check_value:
        value = entry.get("value")
        if not isinstance(value, str) or (require_nonempty_value and not value):
            raise CookieRowError("value", "missing or non-string")

    path = entry.get("path")
    if path is not None and not isinstance(path, str):
        raise CookieRowError("path", "non-string")

    normalized = dict(entry)
    normalized["path"] = path or "/"
    return normalized


def sanitize_cookie_entry(entry: Any, *, check_value: bool = True) -> dict[str, Any]:
    """Validate a row and replace its expiry with a safe canonical value.

    :func:`validate_cookie_shape` plus expiry normalization — the full row
    contract for anything that will be rebuilt into an ``http.cookiejar.Cookie``
    or persisted, since every such path goes through ``int(float(expires))``.
    ``check_value`` is forwarded verbatim.
    """
    normalized = validate_cookie_shape(entry, check_value=check_value)
    normalized["expires"] = normalize_cookie_expiry(entry.get("expires")).value
    return normalized
