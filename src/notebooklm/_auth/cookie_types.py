"""The canonical cookie types: :class:`Cookie` and :class:`CookieJar`.

ADR-0031 Stage 1. A cookie currently exists in the auth layer in six shapes —
the raw Playwright storage-state row, the rookiepy row, ``DomainCookieMap``
(``(name, domain, path) -> value``), ``FlatCookieMap`` (``name -> value``),
the legacy 2-tuple ``LegacyDomainCookieMap``, and the "sanitized entries"
list — and the conversions between them are free functions scattered across
:mod:`notebooklm._auth.cookies` and :mod:`notebooklm._auth.cookie_policy`.
Because no type owns "a set of auth cookies", the questions callers ask about
one ("which names are here?", "is this set usable?", "does it still bind?")
have no method to be, so every flow reaches independently for the same
scattered private helpers. That fan-out is what makes the auth layer hard to
move: see ADR-0031's Context.

This module introduces the types those questions belong to. It completes the
``cookie_*`` family: :mod:`~notebooklm._auth.cookie_semantics` owns row
validation/normalization, :mod:`~notebooklm._auth.cookie_policy` owns which
cookies are required and allowed, and this module owns the shape callers
hold. (Not named ``cookie_jar`` — ``cli/services/login/cookie_jar.py`` is a
different thing: the CLI's browser-account enumeration service.) It is deliberately
a **wrapper, not a replacement**: every policy decision still delegates to the
existing free function that owns it, so this stage changes no behavior and no
public shape. ``AuthTokens`` keeps its ``cookies`` / ``cookie_jar`` field pair
until ADR-0031 Stage 4.

Round-tripping is lossy in one direction, by design:
:meth:`CookieJar.from_storage_state` applies the same allowlist +
row-sanitization filter the rest of the auth layer applies
(:func:`notebooklm._auth.cookies._sanitized_auth_entries`), so a jar built
from a storage state holds only routable, structurally valid auth rows.
:meth:`CookieJar.to_storage_state` therefore reproduces *that filtered view*,
not the original file. Callers persisting cookies must keep using the
canonical storage writer (ADR-0029), which owns merge semantics this type
deliberately does not.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

import httpx

from . import cookie_policy as _cookie_policy
from . import cookies as _auth_cookies


@dataclass(frozen=True)
class Cookie:
    """One auth cookie, keyed by its RFC 6265 §5.3 identity.

    ``(name, domain, path)`` is the identity: two cookies sharing a name at
    distinct domains or paths are independent entries, never one shadowing the
    other (issue #369). ``expires`` is the Playwright epoch-seconds convention
    where ``-1`` means a session cookie.

    ``same_site`` is carried rather than defaulted: dropping a stored value is
    the exact regression ``storage._preserved_same_site`` exists to prevent, so
    ``None`` here means "the row carried none", never "assume ``None``".
    """

    name: str
    domain: str
    path: str
    value: str
    expires: float | int | None = None
    http_only: bool = False
    secure: bool = False
    same_site: str | None = None

    @property
    def identity(self) -> tuple[str, str, str]:
        """The RFC 6265 §5.3 ``(name, domain, path)`` identity."""
        return (self.name, self.domain, self.path)


class CookieJar:
    """An ordered, immutable set of auth cookies.

    Construct through the ``from_*`` classmethods rather than ``__init__`` —
    each one routes through the conversion the auth layer already trusts for
    that input shape, so a jar can never hold rows the rest of the layer would
    have filtered out.
    """

    __slots__ = ("_cookies",)

    def __init__(self, cookies: tuple[Cookie, ...] = ()) -> None:
        self._cookies = tuple(cookies)

    # -- constructors ------------------------------------------------------

    @classmethod
    def from_storage_state(cls, storage_state: Mapping[str, Any]) -> CookieJar:
        """Build from a parsed Playwright ``storage_state`` mapping.

        Rows are filtered and normalized by
        :func:`notebooklm._auth.cookies._sanitized_auth_entries` — the same
        allowlist + row-sanitization gate every other reader applies — so
        malformed rows and non-auth domains are dropped here exactly as they
        are everywhere else.
        """
        entries = _auth_cookies._sanitized_auth_entries(dict(storage_state))
        return cls(tuple(_cookie_from_entry(entry) for entry in entries))

    @classmethod
    def from_rookiepy(cls, rows: list[dict[str, Any]]) -> CookieJar:
        """Build from rookiepy's browser-extraction rows.

        Delegates the snake_case → camelCase field mapping and the
        session-cookie expiry convention to
        :func:`notebooklm._auth.cookies.convert_rookiepy_cookies_to_storage_state`.
        """
        return cls.from_storage_state(_auth_cookies.convert_rookiepy_cookies_to_storage_state(rows))

    @classmethod
    def from_domain_map(cls, cookies: Any) -> CookieJar:
        """Build from any legacy cookie-map shape.

        Accepts all three shapes :func:`notebooklm._auth.cookies.normalize_cookie_map`
        accepts (path-aware 3-tuple keys, legacy 2-tuple keys, and flat
        ``name -> value``), widening the shorter forms exactly as that function
        does. The map shapes carry no expiry/flags, so those default.
        """
        normalized = _auth_cookies.normalize_cookie_map(cookies)
        return cls(
            tuple(
                Cookie(name=name, domain=domain, path=path, value=value)
                for (name, domain, path), value in normalized.items()
            )
        )

    # -- converters --------------------------------------------------------

    def to_domain_map(self) -> dict[tuple[str, str, str], str]:
        """Return the path-aware ``(name, domain, path) -> value`` map.

        First occurrence wins for a repeated identity, matching
        :func:`notebooklm._auth.cookies.extract_cookies_with_domains`.
        """
        result: dict[tuple[str, str, str], str] = {}
        for cookie in self._cookies:
            result.setdefault(cookie.identity, cookie.value)
        return result

    # NOTE: there is deliberately no ``to_flat_map`` / ``FlatCookieMap`` export.
    # Flattening to ``name -> value`` collapses the path component (#369) and
    # picks an arbitrary winner among same-tier domains — ``AuthTokens.flat_cookies``
    # documents itself as "lossy, and not correct for building a request", with a
    # survivor that changes when ``storage_state`` is reordered (#2054). Every
    # remaining caller of ``flatten_cookie_map`` is back-compat: the public
    # ``flat_cookies`` property and ``_update_cookie_input``'s write-back into a
    # legacy-shaped caller dict. Giving the canonical type a method for it would
    # carry that footgun into the model meant to retire it, so the legacy shape
    # stays reachable only through the legacy free function. Callers that want
    # bytes on the wire use :meth:`to_httpx`, which is path- and domain-correct.

    def to_httpx(self) -> httpx.Cookies:
        """Return a domain-preserving ``httpx.Cookies`` jar.

        Delegates to :func:`notebooklm._auth.cookies.build_cookie_jar`, the
        single authoritative jar constructor.
        """
        return _auth_cookies.build_cookie_jar(cookies=self.to_domain_map())

    def to_storage_state(self) -> dict[str, Any]:
        """Return a Playwright-shaped ``storage_state`` dict for these cookies.

        Reproduces the jar's *filtered* view, not any original file — see the
        module docstring. ``origins`` is empty: this type models cookies only.
        """
        rows: list[dict[str, Any]] = []
        for c in self._cookies:
            row: dict[str, Any] = {
                "name": c.name,
                "value": c.value,
                "domain": c.domain,
                "path": c.path,
                "expires": -1 if c.expires is None else c.expires,
                "httpOnly": c.http_only,
                "secure": c.secure,
            }
            # Emitted only when the source row carried one, so this never
            # invents a value the way a bare default would.
            if c.same_site is not None:
                row["sameSite"] = c.same_site
            rows.append(row)
        return {"cookies": rows, "origins": []}

    # -- queries -----------------------------------------------------------

    def names(self) -> set[str]:
        """Return the set of cookie names present, on any domain."""
        return {c.name for c in self._cookies}

    def has_secondary_binding(self) -> bool:
        """Whether the Tier-2 binding (``OSID``, or ``APISID`` + ``SAPISID`` +
        ``LSID``) is intact — see
        :func:`notebooklm._auth.cookie_policy._has_valid_secondary_binding`."""
        return _cookie_policy._has_valid_secondary_binding(self.names())

    def is_rotatable(self) -> bool:
        """Whether a ``RotateCookies`` attempt is worth making.

        Deliberately weaker than :meth:`has_secondary_binding` — see
        :func:`notebooklm._auth.cookie_policy._has_rotatable_secondary_binding`.
        """
        return _cookie_policy._has_rotatable_secondary_binding(self.names())

    def validate_required(self, *, context: str = "") -> None:
        """Raise unless the Tier-1 required cookies are present.

        Delegates the policy — including the Tier-2 warning — to
        :func:`notebooklm._auth.cookie_policy._validate_required_cookies`,
        raising its ``RequiredCookieValidationError`` (a ``ValueError``) with
        the same closed-enum ``reason`` every other caller sees.
        """
        _cookie_policy._validate_required_cookies(self.names(), context=context)

    def missing_hint(self, *, browser_label: str | None = None) -> str:
        """Return the actionable recovery hint for this jar's missing cookies."""
        return _cookie_policy.missing_cookies_hint(self.names(), browser_label=browser_label)

    # -- container protocol ------------------------------------------------

    def __iter__(self) -> Iterator[Cookie]:
        return iter(self._cookies)

    def __len__(self) -> int:
        return len(self._cookies)

    def __bool__(self) -> bool:
        return bool(self._cookies)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CookieJar):
            return NotImplemented
        return self._cookies == other._cookies

    def __repr__(self) -> str:
        """Redacted: names and count only — values are credential-equivalent."""
        return f"CookieJar({len(self._cookies)} cookies: {sorted(self.names())})"


def _cookie_from_entry(entry: Mapping[str, Any]) -> Cookie:
    """Build a :class:`Cookie` from an already-sanitized storage-state row.

    Callers must pass rows that have been through
    ``_sanitized_auth_entries`` / ``sanitize_cookie_entry``: identity and value
    fields are trusted here, and ``path`` has already been defaulted to ``/``.
    """
    same_site = entry.get("sameSite", entry.get("same_site"))
    return Cookie(
        name=entry["name"],
        domain=entry["domain"],
        path=entry.get("path") or "/",
        value=entry["value"],
        expires=entry.get("expires"),
        http_only=bool(entry.get("httpOnly", entry.get("http_only", False))),
        secure=bool(entry.get("secure", False)),
        same_site=same_site if isinstance(same_site, str) else None,
    )
