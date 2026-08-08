"""Google account discovery over the NETWORK, and the identity repair built on it.

This module owns the half of "account" that talks to Google: probing
``?authuser=N`` for the accounts a cookie jar can authenticate as
(:func:`enumerate_accounts` / :func:`_probe_authuser`), pulling the active
user's email out of a NotebookLM page (:func:`extract_email_from_html`), and
formatting the routing value those indices/emails become on the wire
(:func:`format_authuser_value` / :func:`authuser_query`).

It does NOT own the account RECORD. Reading, writing, promoting and scrubbing
the persisted ``{authuser, email}`` binding is *persistence* — one profile
document, one lock, one atomic write — so ADR-0033 PR 5.2 relocated all of it
next to the other ``storage_state.json`` readers and writers in
:mod:`notebooklm._auth.storage` (see that module's "account records" section).
The split retired the whole ``account`` <-> ``storage`` deferred-import pair
(3 sites here, 5 there): the record helpers and the writers they drove are now
same-module calls, and what is left is a **one-way** module-scope edge,
``account`` -> ``storage``, for the one function that legitimately spans both
halves.

That function is :func:`repair_account_metadata_from_playwright_storage`: it
probes the network for the accounts a freshly-captured jar can reach, picks the
one Playwright just logged into, and then *persists* the binding. It composes
over both halves by design, and it is the reason this module imports
``storage`` rather than the other way round.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

import httpx

from .._env import get_base_url
from .._url_utils import is_google_auth_redirect

# Module scope, not deferred: since ADR-0033 PR 5.2 the edge is one-way.
# ``storage`` imports nothing from here (its five function-local
# ``from . import account`` sites all resolved to record helpers that now live
# in ``storage`` itself), so there is no cycle left to dodge — and a module-scope
# import keeps the binding late (``_storage.write_account_metadata`` resolves on
# the module object at CALL time, so whitebox tests patch the owning module).
from . import storage as _storage

logger = logging.getLogger("notebooklm.auth")


@dataclass(frozen=True)
class Account:
    """A Google account discovered via authuser=N probing.

    Attributes:
        authuser: The integer index used in ``?authuser=N`` URL parameters.
            Index 0 is the default account; subsequent indices follow the
            order Google reports for the browser session.
        email: The account's email address as it appears in the NotebookLM
            page's ``WIZ_global_data`` block.
        is_default: True only for the account at ``authuser=0``.
        browser_profile: For Chromium-family browsers with multiple
            user-data profiles, the on-disk directory name (``"Default"``,
            ``"Profile 1"``) the cookies came from. ``None`` for non-chromium
            browsers and for the legacy single-jar path where source isn't
            tracked.
    """

    authuser: int
    email: str
    is_default: bool
    browser_profile: str | None = None


# Hard cap on how many ``authuser`` indices to probe before giving up.
# Google supports up to ~10 simultaneously signed-in accounts in a browser
# session; ten covers every realistic case and bounds the worst-case probe.
MAX_AUTHUSER_PROBE = 10

# Local-parts of well-known non-user emails that NotebookLM may embed in page
# chrome (footer links, support contacts) and must not be misread as the
# active account. Combined with ``_NON_USER_EMAIL_DOMAINS`` so we only drop
# the address when *both* match — otherwise legitimate Workspace users like
# ``support@customer.com`` would be filtered out.
_NON_USER_EMAIL_LOCALS = frozenset(
    {
        "abuse",
        "feedback",
        "info",
        "mail-noreply",
        "googlemail-noreply",
        "no-reply",
        "noreply",
        "press",
        "privacy",
        "support",
    }
)
_NON_USER_EMAIL_DOMAINS = frozenset({"google.com", "accounts.google.com", "gmail.com"})

# Match a quoted email address, e.g. ``"alice@example.com"``. Mirrors how
# emails appear in the page's WIZ_global_data JSON.
_EMAIL_RE = re.compile(r'"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"')


def extract_email_from_html(html: str) -> str | None:
    """Extract the active user's email from a NotebookLM page response.

    Returns the first plausible Google account email found in the HTML,
    skipping addresses that look like Google's own contact endpoints
    (e.g. ``support@google.com``, ``noreply@accounts.google.com``).

    Args:
        html: Page HTML from ``<configured base URL>/?authuser=N``.

    Returns:
        The account's email, or ``None`` if no plausible address was found
        (typically because the response was a login redirect or the page
        structure changed).
    """
    for match in _EMAIL_RE.finditer(html):
        email = match.group(1)
        local, _, domain = email.partition("@")
        if local.lower() in _NON_USER_EMAIL_LOCALS and domain.lower() in _NON_USER_EMAIL_DOMAINS:
            continue
        return email
    return None


# Chromium-style User-Agent for ``enumerate_accounts``. Without a real-browser
# UA, Google serves a stripped-down page that omits the WIZ_global_data block
# (and therefore the active user's email), and ``extract_email_from_html``
# returns None — looking like "no signed-in account". Empirically validated
# against ``<configured base URL>/?authuser=N``.
_BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
)


async def _probe_authuser(client: httpx.AsyncClient, n: int) -> str | None:
    """Probe one ``authuser`` index and return the active email or ``None``.

    Returns ``None`` for auth-redirect or unparseable responses; lets the
    caller decide whether that means "past the last account" or a real error.
    HTTP transport errors propagate.

    Only checks the *final* URL for an auth redirect. The page body is not
    scanned because a healthy NotebookLM page legitimately contains many
    ``accounts.google.com`` links (account chooser, manage-account menu)
    that would fool ``contains_google_auth_redirect``.
    """
    response = await client.get(
        f"{get_base_url()}/?{authuser_query(n)}",
        headers={"User-Agent": _BROWSER_UA, "Accept": "text/html,*/*"},
    )
    if response.status_code != 200:
        return None
    if is_google_auth_redirect(str(response.url)):
        return None
    return extract_email_from_html(response.text)


async def enumerate_accounts(
    cookie_jar: httpx.Cookies,
    *,
    max_authuser: int = MAX_AUTHUSER_PROBE,
    poke_session: Callable[[httpx.AsyncClient, Path | None], Awaitable[None]] | None = None,
) -> list[Account]:
    """Enumerate Google accounts visible to the given cookie jar.

    Probes ``<configured base URL>/?authuser=N`` (see
    :func:`~notebooklm._env.get_base_url`) for ``N`` in
    ``0..max_authuser`` and parses the active user's email from each response.

    Stop condition: when the email at index ``N>0`` matches the email at
    index 0, Google has silently fallen back to the default account, meaning
    ``N`` is past the real count. Without this check the caller would record
    duplicate phantom accounts; Google does not redirect to login in this
    case.

    Args:
        cookie_jar: ``httpx.Cookies`` jar with auth cookies. Not mutated.
        max_authuser: Hard cap on indices probed (default
            :data:`MAX_AUTHUSER_PROBE`).
        poke_session: Optional freshness hook run before probes. The public
            ``notebooklm.auth`` facade passes the standard keepalive hook.

    Returns:
        Accounts ordered by ``authuser`` index. ``is_default`` is true for
        index 0 only.

    Raises:
        ValueError: If ``authuser=0`` itself does not return a signed-in
            account (cookies expired or invalid).
        httpx.HTTPError: If the HTTP transport fails.
    """
    from .._curl_cffi_transport import resolve_transport_factory

    async with resolve_transport_factory()(
        cookies=cookie_jar,
        follow_redirects=True,
        timeout=httpx.Timeout(10.0, read=60.0),
    ) as client:
        # The browser's on-disk cookie DB rotates ``__Secure-1PSIDTS`` every
        # few minutes, but only when Chrome itself is actively running. A
        # ``--browser-cookies`` extraction against an idle Chrome lands here
        # with a stale SIDTS — the SID is fine, but the app host
        # responds with a redirect to ``accounts.google.com`` and we'd
        # incorrectly conclude the user is signed out. Poke once to fetch
        # fresh SIDTS via Set-Cookie before the probes start.
        if poke_session is not None:
            await poke_session(client, None)
        default_email = await _probe_authuser(client, 0)
        if default_email is None:
            raise ValueError(
                "Authentication expired or invalid; "
                "authuser=0 did not return a signed-in account. "
                "Run 'notebooklm login' to re-authenticate."
            )
        accounts = [Account(authuser=0, email=default_email, is_default=True)]
        for n in range(1, max_authuser + 1):
            email = await _probe_authuser(client, n)
            if email is None or email == default_email:
                break
            accounts.append(Account(authuser=n, email=email, is_default=False))
        return accounts


def format_authuser_value(authuser: int = 0, account_email: str | None = None) -> str:
    """Return the explicit NotebookLM auth routing value.

    Google accepts either an integer account index or the account email in the
    ``authuser`` field. Email is stable across browser account reordering, so it
    wins when available; otherwise callers retain the existing integer behavior.
    """
    if account_email:
        stripped = account_email.strip()
        if stripped:
            return stripped
    return str(authuser)


def authuser_query(authuser: int = 0, account_email: str | None = None) -> str:
    """Return a URL-encoded ``authuser=...`` query string."""
    return urlencode({"authuser": format_authuser_value(authuser, account_email)})


def _select_playwright_account(
    accounts: list[Account],
    *,
    active_email: str | None,
) -> tuple[Account | None, str | None]:
    """Select the account Playwright just logged into, or an ambiguity reason."""
    if active_email:
        normalized = active_email.casefold()
        matches = [
            account
            for account in accounts
            if isinstance(account.email, str) and account.email.casefold() == normalized
        ]
        if len(matches) == 1:
            return matches[0], None
        if matches:
            return None, f"multiple discovered accounts matched {active_email}"
        return None, f"current NotebookLM page email {active_email} was not discovered"

    if len(accounts) == 1:
        return accounts[0], None
    if accounts:
        return (
            None,
            "multiple Google accounts were discovered but the active page email was unavailable",
        )
    return None, "no Google accounts were discovered"


@dataclass(frozen=True)
class PlaywrightAccountRepairResult:
    """Outcome of :func:`repair_account_metadata_from_playwright_storage`.

    Exactly one of ``ambiguity_reason`` / ``error`` is set when ``written`` is
    ``False`` — callers use which one is set to pick between the two distinct
    user-facing warnings (a clean "could not disambiguate" vs. an unexpected
    failure worth surfacing exception detail for).
    """

    written: bool
    email: str | None = None
    ambiguity_reason: str | None = None
    error: str | None = None


async def repair_account_metadata_from_playwright_storage(
    storage_path: Path,
    *,
    page_html: str | None = None,
) -> PlaywrightAccountRepairResult:
    """Populate ``notebooklm.account`` from Playwright storage when unambiguous.

    Consolidates a recipe that used to live in ``cli/services/playwright_login.py``
    (auth cross-boundary ledger shrink, follow-up to #2103): identify the active
    page's account from ``page_html`` if given, probe the storage's cookie jar for
    every Google account it can authenticate as, and select the one Playwright
    just logged into. Ambiguous multi-account states are left unbound after
    clearing stale metadata, matching the pre-consolidation behavior exactly —
    including the best-effort clear (and its own swallowed-failure log) on an
    unexpected ``OSError`` / ``ValueError`` / ``RuntimeError`` /
    ``httpx.HTTPError`` from the probe or the write.

    This is the function that recomposes the two halves ADR-0033 PR 5.2 split
    apart: the probe is network identity (this module), the clear/write is
    persistence (``storage.clear_account_metadata`` /
    ``storage.write_account_metadata``). Both are reached through the module
    object so the seam stays patchable at call time.

    No presentation side effects: the CLI caller (``cli/services/playwright_login.py``)
    owns the ``LoginIO``-mediated user-facing messages, keyed off which field of
    the result is set.
    """
    from .cookies import build_httpx_cookies_from_storage
    from .keepalive import _poke_session

    active_email = extract_email_from_html(page_html) if isinstance(page_html, str) else None
    try:
        # ``build_httpx_cookies_from_storage`` is synchronous (blocking file I/O
        # and, on a missing/expired PSIDTS, an inline recovery POST) — this
        # function is ``async`` now (it wasn't before this consolidation), so
        # the call must go through a thread like every other async caller of
        # this function in ``_auth`` (``recovery.py``, ``refresh.py``,
        # ``master_token.py``) rather than blocking the event loop directly.
        jar = await asyncio.to_thread(build_httpx_cookies_from_storage, storage_path)
        # ``poke_session`` matches what the ``notebooklm.auth`` facade's own
        # ``enumerate_accounts`` wrapper injects — this internal call must not
        # silently drop the keepalive session-freshness poke.
        accounts = await enumerate_accounts(jar, poke_session=_poke_session)
        selected, reason = _select_playwright_account(accounts, active_email=active_email)
        if selected is None:
            _storage.clear_account_metadata(storage_path)
            return PlaywrightAccountRepairResult(written=False, ambiguity_reason=reason)
        _storage.write_account_metadata(
            storage_path, authuser=selected.authuser, email=selected.email
        )
        return PlaywrightAccountRepairResult(written=True, email=selected.email)
    except (OSError, ValueError, RuntimeError, httpx.HTTPError) as exc:
        try:
            _storage.clear_account_metadata(storage_path)
        except Exception as clear_exc:  # noqa: BLE001 — best-effort cleanup must not mask exc
            logger.warning(
                "Failed to clear stale account metadata for %s: %s", storage_path, clear_exc
            )
        return PlaywrightAccountRepairResult(written=False, error=str(exc))
