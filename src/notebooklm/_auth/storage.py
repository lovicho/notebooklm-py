"""Profile persistence for authentication: storage state, its lock, and its writers.

One deep module for the whole ``storage_state.json`` seam. It merges what used to
be three cap-split files — ``storage.py`` (snapshot/CAS merge math + the file-lock
primitive), ``storage_writer.py`` (the canonical writer, ADR-0029) and
``storage_transaction.py`` (the write transaction template, ADR-0031 Stage 3) —
under ADR-0033's sanctioned-merge policy. The split existed only to satisfy the
ADR-0008 module-size cap, and it was re-joined at runtime by function-local
imports in both directions; merging removes those without changing any behaviour.
ADR-0033 PR 4.2 then relocated ``_browser_cookie_filter.py``'s write-time
cookie-domain filter in as well — misfiled under a ``browser_`` name, but write
policy applied by three of the writers here — retiring three more lazy imports.
ADR-0033 PR 5.2 relocated the account-RECORD helpers from ``_auth/account.py``
(section 7b): reading the record, deriving an in-band-shaped one from a legacy
sibling, the detached durable-promotion one-shot, and the sibling scrub. They
are persistence — same document, same lock, driving the writers here directly —
and splitting them from those writers cost a bidirectional function-local
import pair (3 sites there, 5 here) which that relocation retires in full.
``account.py`` keeps the NETWORK identity half (``enumerate_accounts``,
``_probe_authuser``, page-email extraction, the routing-value formatters) and
imports this module at module scope; the edge is now one-way.

The file is organised in labelled sections mirroring the former modules:

1. **Lock primitives** — the contention/backoff tuning shared by both bounded
   acquire paths, the per-path in-process lock registry, the OS-level acquire,
   :func:`_file_lock` and the blocking :func:`_file_lock_exclusive`.
2. **Lock acquisition for writers** — the secure-parent-dir prep and the
   platform-neutral bounded :func:`_acquire_storage_lock`. (Lock *path*
   derivation itself stays in :mod:`notebooklm._auth.paths`:
   :func:`_storage_state_lock_path`.)
3. **The storage-write transaction template** — :func:`in_storage_transaction`
   plus the three lock-unavailable policies.
4. **Snapshot types** — the path-aware cookie identity/value tuples and
   :class:`CookieSaveResult`.
5. **CAS + merge math** — snapshotting, the legacy and snapshot/delta merges, and
   :func:`save_cookies_to_storage`, the ADR-0029-pinned monkeypatchable delegate
   seam (``_runtime/lifecycle.py`` late-binds it; ~20 test files patch it).
6. **Writer outcome types** — the value-free enums/records the intent writers
   return.
7. **The write-time cookie-domain filter** —
   :func:`filter_storage_state_cookies_by_domain_policy` and its value-free
   malformed-row diagnostics, relocated here from ``_browser_cookie_filter.py``
   (ADR-0033 PR 4.2). It is write-time policy, not browser code: three of its
   six call sites are the intent writers below, which apply it *under the
   lock* as ADR-0029's entry-path-independent guarantee.
8. **The intent writers** — the seven sanctioned mutations of
   ``storage_state.json`` and its sibling credential files.
9. **Account records** (labelled ``SECTION 7b`` in the source, where it sits
   directly after the two in-band account writers it drives) — the record
   readers, the ``_sanitize_legacy_account_record`` derivation that gives
   ADR-0029 its anti-wrong-account guarantee, the detached durable-promotion
   one-shot with its ``atexit`` drain, and :func:`_drop_legacy_account_key`,
   the sibling ``context.json`` scrub. Relocated from ``_auth/account.py``
   (ADR-0033 PR 5.2).

This module is the **single sanctioned home** for mutations of
``storage_state.json``. It is the only module under :mod:`notebooklm._auth`
permitted to import the ``_atomic_io`` write primitives, and it reaches the
module-private bypass under the local alias ``_write_state_unchecked``. The
boundary is enforced by ``tests/_guardrails/test_storage_writer_boundary.py``,
which since ADR-0033 pins it at **function** granularity: an equality-asserted
allowlist of the intent-writer function names permitted to reach the bypass
(a module-granular assertion over a module this size would say almost nothing).

Intent-shaped API (all synchronous, all serialize on the canonical storage lock,
all write via ``_atomic_io``):

* :func:`merge_cookie_delta` — the CAS delta merge behind
  :func:`save_cookies_to_storage`. It is a **CAS** intent and therefore **fails
  open** on lock unavailability (status quo): availability wins, and the
  snapshot/delta CAS guards keep correctness.
* :func:`update_account_metadata` / :func:`clear_in_band_account` — the in-band
  account writers relocated from :mod:`notebooklm._auth.account`. These are
  **full-file RMW** intents: :func:`update_account_metadata` **fails closed**
  (raises :class:`LockUnavailableError`) because failing open could overwrite a
  concurrent CAS delta; :func:`clear_in_band_account` is best-effort cleanup and
  swallows lock unavailability, matching the pre-refactor semantics.
* :func:`replace_from_remint` — the full cookie-replace re-mint persister for the
  BROWSER-CAPTURE arms (L3 headless-launch + interactive + CDP), relocated from
  the bare ``atomic_write_json`` sites in :mod:`notebooklm._auth.browser_capture`.
  Applies the write-time domain filter internally under the lock, then either
  carries the existing ``notebooklm`` account namespace (``carry_account=True`` —
  the unattended profile-launch arm, closing [capture-1]) or drops the stale
  binding (``carry_account=False`` — the interactive arm, whose CLI adapter
  re-establishes it). **Fails closed** (returns
  :class:`WriteOutcome` with ``lock_unavailable``). Closes [capture-2].
* :func:`replace_from_login` — the login/import full-replace, whose write-time
  domain filter and required-cookie revalidation run inside the lock.
  **Fails closed.**
* :func:`persist_minted_jar` — the master-token L4 re-mint persister relocated
  from :mod:`notebooklm._auth.master_token`, routed through ``_atomic_io`` (so it
  gains fsync durability + temp cleanup) while keeping its storage lock and its
  rebind-to-minted-account semantics. b-PR2 adds the write-time domain filter
  here (the L4 unfiltered-persist gap). **Fails closed.**
* :func:`write_master_token` — the ``master_token.json`` writer, now routed
  through ``_atomic_io`` **and** guarded by a bounded sibling lock (it was
  previously lockless). **Fails closed.**

Lock unification (see ADR-0029): the full-file RMW / re-mint intents drop
``filelock`` in favour of the project-internal :func:`_file_lock` primitive
via a **platform-neutral bounded acquire** (:func:`_acquire_storage_lock`):
a non-blocking probe plus deadline/jitter retry (default 90 s), then the
per-intent failure policy above. The CAS merge keeps the status-quo blocking
:func:`_file_lock_exclusive` acquire (fail-open). An in-process ``threading.Lock``
keyed per canonical lock-path (ordering: in-process lock -> OS lock) is added in
:func:`_file_lock` itself so threads within one process serialize before the
OS lock; the distinct ``.{name}.rotate.lock`` sentinel is never collapsed into
the storage lock.

The fail-closed writers raise :class:`~notebooklm.exceptions.LockUnavailableError`
(public via ``notebooklm.exceptions`` / the ``notebooklm.auth`` facade). It
subclasses :class:`TimeoutError` — itself an :class:`OSError` — exactly mirroring
the ``filelock.Timeout`` MRO it replaces, so callers' existing
``except OSError`` / ``except TimeoutError`` arms (``_auth/recovery.py`` around
``persist_minted_jar``; the CLI login writers around ``write_account_metadata``)
keep catching a lock failure unchanged; only the exception type and the 10 s->90 s
bound differ.

Permission contract (POSIX): every writer ensures the parent directory is
``0700`` on creation and the file is ``0600`` (the latter via the atomic write's
default mode). On Windows we rely on ``%USERPROFILE%`` ACL inheritance.

Outcome types are **value-free by contract**: :class:`WriteOutcome` may carry
only an enum status — never cookie values, state dicts, jar objects, or caught
exceptions.
"""

from __future__ import annotations

import atexit
import contextlib
import errno
import json
import logging
import os
import random
import shutil
import sys
import threading
import time
import warnings
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, NamedTuple, Protocol, TypeAlias

import httpx
from filelock import FileLock

# This module is the SOLE sanctioned user of the module-private
# ``_atomic_write_json_unchecked`` bypass: the public ``atomic_write_json``
# rejects ``storage_state.json`` paths (#1215-style runtime guard, b-PR3), and
# the writers below legitimately write them under the canonical dotted lock.
# Bound as ``_write_state_unchecked`` — the former alias spelled it
# ``atomic_write_json``, colliding with the name of the public primitive the
# guard protects (ADR-0033 decision 2). The boundary is enforced at function
# granularity in ``tests/_guardrails/test_storage_writer_boundary.py``.
#
# The PUBLIC ``atomic_write_json`` is imported alongside it (ADR-0033 PR 5.2):
# the relocated legacy-account scrub :func:`_drop_legacy_account_key` writes the
# SIBLING ``context.json``, not ``storage_state.json``, so it must go through the
# guarded public primitive — the same primitive it used in ``account.py``.
from .._atomic_io import _atomic_write_json_unchecked as _write_state_unchecked
from .._atomic_io import atomic_write_json

# ``LockUnavailableError`` is the public, canonical home for the fail-closed
# lock-failure exception (``notebooklm.exceptions`` — also re-exported on the
# ``notebooklm.auth`` facade). It subclasses ``TimeoutError`` (an ``OSError``),
# exactly mirroring the ``filelock.Timeout`` MRO it replaces, so existing
# ``except OSError`` arms keep catching a lock failure. Re-exported here for the
# writers that raise it.
from ..exceptions import LockUnavailableError
from . import cookie_policy as _cookie_policy
from . import cookie_semantics as _cookie_semantics
from . import cookies as _auth_cookies
from .paths import _storage_state_lock_path, canonical_storage_key, resolve_auth_json_env

logger = logging.getLogger("notebooklm.auth")

CookieKey: TypeAlias = _auth_cookies.CookieKey
_cookie_is_http_only = _auth_cookies._cookie_is_http_only
_cookie_key_variants = _auth_cookies._cookie_key_variants
_cookie_to_storage_state = _auth_cookies._cookie_to_storage_state
_find_cookie_for_storage = _auth_cookies._find_cookie_for_storage
_is_allowed_cookie_domain = _cookie_policy._is_allowed_cookie_domain
# Recovery-target rows: one definition in the ``cookie_policy`` leaf, shared
# with ``psidts_recovery`` (which observes these rows before the RotateCookies
# POST that produces the deltas ``_merge_recovery_target_rows`` below merges).
_RECOVERY_TARGET_COOKIE_NAMES = _cookie_policy._RECOVERY_TARGET_COOKIE_NAMES

__all__ = [
    "CLEAR_ACCOUNT",
    "KEEP_ACCOUNT",
    "AccountRecord",
    "CookieSaveResult",
    "LockUnavailableError",
    "LoginWriteOutcome",
    "LoginWriteStatus",
    "WriteOutcome",
    "WriteStatus",
    "advance_cookie_snapshot_after_save",
    "clear_account_metadata",
    "clear_in_band_account",
    "get_account_email_for_storage",
    "get_authuser_for_storage",
    "in_storage_transaction",
    "merge_cookie_delta",
    "persist_minted_jar",
    "promote_legacy_account",
    "raise_on_lock_unavailable",
    "read_account_metadata",
    "read_account_metadata_from_storage_state",
    "replace_from_login",
    "replace_from_remint",
    "report_on_lock_unavailable",
    "resolve_account_identity",
    "save_cookies_to_storage",
    "skip_on_lock_unavailable",
    "snapshot_cookie_jar",
    "update_account_metadata",
    "write_account_metadata",
    "write_master_token",
]


# ==========================================================================
# SECTION 1 — LOCK PRIMITIVES
# Contention classification, bounded-acquire tuning, the per-path in-process
# lock registry, the OS-level acquire, and the two file-lock context managers.
# ==========================================================================


# Errnos that a non-blocking lock acquire raises to mean "held elsewhere"
# (contended), NOT "infrastructure broken". EWOULDBLOCK/EAGAIN are the POSIX
# ``flock(LOCK_NB)`` contention signals. ``EACCES`` is here specifically because
# it is the errno Windows ``msvcrt.locking(LK_NBLCK)`` raises under contention —
# POSIX ``flock`` never returns EACCES for contention, and a POSIX *permission*
# failure surfaces earlier at the ``os.open`` step (yielded as "unavailable").
# So do NOT drop EACCES to "fix" it: on Windows that would misclassify real
# contention as an infrastructure failure (fail-open) instead of a skip.
_LOCK_CONTENTION_ERRNOS = {errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES}


# --- Bounded-acquire tuning (single source of truth) ------------------------
#
# Shared by BOTH bounded acquire paths so they honour the same deadline and the
# same jittered exponential backoff:
#   * the blocking Windows ``msvcrt`` retry loop in ``_acquire_os_lock`` below
#     ([storage-F4]: Windows has no blocking-without-internal-timeout primitive,
#     so the blocking path drives ``LK_NBLCK`` probes to this deadline instead
#     of letting ``LK_LOCK`` fail open after its internal ~10x1s), and
#   * :func:`_acquire_storage_lock` (the non-blocking-probe bounded helper that
#     the fail-closed RMW / re-mint writers use), in section 2 below.
# 90 s is a generous worst-case wait that still bounds a crashed/wedged holder.
# See ADR-0029.
_LOCK_ACQUIRE_DEADLINE_SECONDS = 90.0
_LOCK_ACQUIRE_INITIAL_DELAY_SECONDS = 0.01
_LOCK_ACQUIRE_MAX_DELAY_SECONDS = 0.5


def _sleep_backoff(delay: float, deadline: float) -> float | None:
    """Sleep one jittered exponential-backoff step of a bounded-acquire loop.

    The single home for the deadline-check + jitter + sleep + delay-bump
    arithmetic shared by BOTH bounded-acquire loops — the Windows ``msvcrt``
    retry in :func:`_acquire_os_lock` below and
    :func:`_acquire_storage_lock` — so future tuning edits one site
    (b-PR4 review NIT). Behaviour is identical to the two former inline copies:
    equal jitter (``delay + U[0, delay]``) clamped to the remaining budget,
    then ``delay`` doubled and capped at :data:`_LOCK_ACQUIRE_MAX_DELAY_SECONDS`.

    Returns the next ``delay`` to use, or ``None`` when the ``deadline`` has
    already elapsed — the caller must then stop retrying and fall through to
    ``"unavailable"`` (each caller keeps its own site-specific give-up log line).
    """
    now = time.monotonic()
    if now >= deadline:
        return None
    sleep_for = min(delay + random.uniform(0.0, delay), max(0.0, deadline - now))
    time.sleep(sleep_for)
    return min(delay * 2, _LOCK_ACQUIRE_MAX_DELAY_SECONDS)


# In-process lock registry, keyed per canonical lock-path (never global — distinct
# profiles and the rotate sentinel must not couple). Acquired BEFORE the OS lock
# (ordering: in-process lock -> OS lock) so threads within one process serialize
# on a storage sentinel before touching the OS flock, which both bounds Windows
# ``msvcrt`` contention and lets the non-blocking rotate path observe an
# in-process holder as "contended" without an OS round-trip. See ADR-0029.
_INPROCESS_LOCKS: dict[str, threading.Lock] = {}
_INPROCESS_LOCKS_GUARD = threading.Lock()


def _inprocess_lock_for(lock_path: Path) -> threading.Lock:
    """Return the process-wide :class:`threading.Lock` for ``lock_path``."""
    key = os.fspath(lock_path)
    with _INPROCESS_LOCKS_GUARD:
        lock = _INPROCESS_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _INPROCESS_LOCKS[key] = lock
        return lock


def _acquire_os_lock(fd: int, *, blocking: bool, log_prefix: str) -> str:
    """Acquire the OS-level exclusive lock on ``fd``; return the tristate.

    Returns one of ``"held"`` / ``"contended"`` / ``"unavailable"``. The caller
    (:func:`_file_lock`) has already taken the per-path in-process
    :class:`threading.Lock` (ordering: in-process lock -> OS lock), so any
    contention observed here is from **another process**, never another thread in
    this process.

    * **POSIX** — ``flock(LOCK_EX)`` when blocking (a kernel-level wait: unbounded
      but non-spinning, unchanged), ``LOCK_EX | LOCK_NB`` when non-blocking.
    * **Windows** — ``msvcrt`` has no blocking-without-internal-timeout primitive:
      the blocking ``LK_LOCK`` mode gives up after ~10x1s and would fail open
      long before the 90 s deadline ([storage-F4]). So the Windows **blocking**
      path drives a bounded deadline retry over the **non-blocking** ``LK_NBLCK``
      probe using the same jittered exponential backoff as
      :func:`_acquire_storage_lock`, retrying **only** on the
      contention errno and falling through to ``"unavailable"`` when the deadline
      elapses (never ``while True`` without a deadline break). A non-contention
      errno (``EBADF`` etc.) falls through immediately with **no** retry spin.
      Windows non-blocking is a single ``LK_NBLCK`` probe.
    """
    if sys.platform != "win32":
        import fcntl

        op = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
        try:
            fcntl.flock(fd, op)
            return "held"
        except OSError as exc:
            if not blocking and exc.errno in _LOCK_CONTENTION_ERRNOS:
                logger.debug("%s: lock contended (%s)", log_prefix, type(exc).__name__)
                return "contended"
            logger.debug("%s: lock op unavailable (%s)", log_prefix, type(exc).__name__)
            return "unavailable"

    import msvcrt

    deadline = time.monotonic() + _LOCK_ACQUIRE_DEADLINE_SECONDS
    delay = _LOCK_ACQUIRE_INITIAL_DELAY_SECONDS
    while True:
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return "held"
        except OSError as exc:
            if exc.errno not in _LOCK_CONTENTION_ERRNOS:
                # EBADF and other non-contention errnos: retrying cannot help.
                # Fall through immediately — no spin.
                logger.debug("%s: lock op unavailable (%s)", log_prefix, type(exc).__name__)
                return "unavailable"
            if not blocking:
                # Non-blocking caller: another process holds the byte-range lock
                # (in-process contention was already resolved by the threading
                # lock in _file_lock). Report the skip signal without retrying.
                logger.debug("%s: lock contended (%s)", log_prefix, type(exc).__name__)
                return "contended"
            # Blocking caller under contention: retry the non-blocking probe with
            # jittered exponential backoff until the bounded deadline, then fall
            # through to "unavailable" so the caller applies its per-intent fail
            # policy (CAS fail-open with a one-shot warning).
            next_delay = _sleep_backoff(delay, deadline)
            if next_delay is None:
                logger.debug(
                    "%s: bounded msvcrt lock acquire exceeded %.0fs deadline; giving up",
                    log_prefix,
                    _LOCK_ACQUIRE_DEADLINE_SECONDS,
                )
                return "unavailable"
            delay = next_delay


@contextlib.contextmanager
def _file_lock(lock_path: Path, *, blocking: bool, log_prefix: str) -> Iterator[str]:
    """Cross-process exclusive lock on ``lock_path``.

    Yields one of:
      - ``"held"``  — the lock is held; release it on exit.
      - ``"contended"`` — non-blocking acquire saw the lock held elsewhere
        (by another in-process thread OR another process). Only ever yielded
        when ``blocking=False``.
      - ``"unavailable"`` — lock infrastructure failed (cannot mkdir, cannot
        open the sentinel, NFS without flock support). Caller should
        **fail open** (proceed without coordination) rather than retry forever.

    Wrappers translate this tristate into bool. Distinguishing contention from
    infrastructure failure matters: a non-blocking caller should **skip** on
    contention (someone else is rotating) but **proceed** on infrastructure
    failure (otherwise a read-only auth dir would permanently suppress
    rotation).

    Locking order is **in-process lock -> OS lock**: the per-path
    :class:`threading.Lock` is taken first (blockingly for ``blocking=True``,
    non-blockingly for ``blocking=False`` where a failed acquire maps straight to
    ``"contended"``), then the OS-level flock/``msvcrt`` lock. The in-process
    lock is released last.
    """
    inprocess_lock = _inprocess_lock_for(lock_path)
    if not inprocess_lock.acquire(blocking=blocking):
        # Only reachable with ``blocking=False``: another thread in this process
        # holds the sentinel. Report contention without touching the OS lock.
        logger.debug("%s: in-process lock contended", log_prefix)
        yield "contended"
        return
    try:
        try:
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            # Read-only directory, permission denied, ENOSPC, etc. Yield
            # "unavailable" so the wrapper can fail open.
            logger.debug(
                "%s: lock file unavailable %s (%s)",
                log_prefix,
                lock_path,
                type(exc).__name__,
            )
            yield "unavailable"
            return
        locked = False
        try:
            # OS-lock acquisition (in-process lock already held above). On Windows
            # the blocking path is a bounded ``LK_NBLCK`` retry to the shared 90 s
            # deadline rather than ``LK_LOCK``'s internal ~10x1s ([storage-F4]).
            state = _acquire_os_lock(fd, blocking=blocking, log_prefix=log_prefix)
            locked = state == "held"
            yield state
        finally:
            if locked:
                try:
                    if sys.platform == "win32":
                        import msvcrt

                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError as exc:
                    logger.debug(
                        "%s: failed to release file lock (%s)",
                        log_prefix,
                        type(exc).__name__,
                    )
            os.close(fd)
    finally:
        inprocess_lock.release()


# Dedupe contract: best-effort under threads, exactly-once on a single
# event loop. ``_file_lock_exclusive`` below reads ``_FLOCK_UNAVAILABLE_WARNED``
# and sets it to ``True`` in one synchronous block with no intervening
# ``await``, so concurrent coroutines on one loop cannot interleave between
# the check and the set — the warning fires exactly once per process. Under
# genuine OS threads (out of scope per the documented concurrency contract),
# duplicate warnings are possible. We accept that rather than serialize a
# logging side-effect behind a lock for an unsupported configuration.
#
# Note: ``functools.lru_cache`` and ``logging.LoggerAdapter`` do NOT solve
# this — ``lru_cache`` memoizes return values, not the ``logger.warning``
# side-effect; ``LoggerAdapter`` only rewrites records, it does not filter
# duplicates.
_FLOCK_UNAVAILABLE_WARNED = False


@contextlib.contextmanager
def _file_lock_exclusive(lock_path: Path) -> Iterator[None]:
    """Blocking cross-process exclusive lock on ``lock_path``.

    Multiple Python processes that all save to the same ``storage_state.json``
    (e.g. a long-running ``NotebookLMClient(keepalive=...)`` worker plus a
    cron-driven ``notebooklm auth refresh``) would otherwise race on the read-
    merge-write cycle and lose updates. The lock is held on a sentinel file
    sibling to the storage file (``.storage_state.json.lock``, derived by
    :func:`notebooklm._auth.paths._storage_state_lock_path`), since locking the
    storage file itself would interfere with the atomic temp-rename below.

    Every ``storage_state.json`` mutator now lives in THIS module and takes
    this sentinel through ``_file_lock`` / :func:`_acquire_storage_lock` — the
    account-metadata writers included (ADR-0033 PR 5.2 moved them here). No
    ``filelock.FileLock`` holder of this sentinel remains, so the old
    cross-mechanism POSIX interop is no longer load-bearing; this module's one
    remaining ``filelock`` use targets the *sibling* ``context.json``.

    The lock is per-process: threads within one process aren't serialized —
    that's the intra-process ``threading.Lock`` held by the client. If the
    lock can't be acquired (e.g. NFS where flock semantics vary, read-only
    parent dir, fd exhaustion), the save proceeds anyway; correctness in
    that mode is best-effort and relies on the snapshot/delta CAS guards in
    :func:`_merge_cookies_with_snapshot` alone. The first time this
    fallback fires per process emits a WARNING so operators learn their
    deployment is running without cross-process coordination.
    """
    global _FLOCK_UNAVAILABLE_WARNED
    with _file_lock(lock_path, blocking=True, log_prefix="save_cookies_to_storage") as state:
        if state == "unavailable" and not _FLOCK_UNAVAILABLE_WARNED:
            _FLOCK_UNAVAILABLE_WARNED = True
            logger.warning(
                "Cross-process file lock unavailable at %s; cookie saves will "
                "proceed without cross-process coordination and rely solely on "
                "snapshot/delta CAS guards. Common causes: NFS without flock "
                "support, read-only parent directory, fd exhaustion. (Logged "
                "once per process.)",
                lock_path,
            )
        yield


# ==========================================================================
# SECTION 2 — LOCK ACQUISITION FOR THE WRITERS
# Secure-parent-dir prep + the platform-neutral bounded acquire the full-file
# RMW / re-mint intents use. Lock PATH derivation lives in ``paths.py``
# (``_storage_state_lock_path``) and is unchanged.
# ==========================================================================


def _ensure_secure_parent_dir(path: Path) -> None:
    """Ensure ``path.parent`` exists and is ``0700`` on POSIX.

    Closes the master-token path's mode-less ``mkdir(parents=True)`` gap. The
    chmod is applied UNCONDITIONALLY (not only when this call creates the dir),
    restoring the pre-refactor self-heal that ``cli/services/login/cookie_writes.py``
    performed after every successful write: a credentials directory loosened by a
    backup / restore / sync tool (e.g. to 0755) is re-tightened to 0700 on the
    next login / refresh, so session-cookie files never sit under a
    world-traversable parent. Windows is skipped (POSIX modes are a no-op there
    and can confuse ACL inheritance from ``%USERPROFILE%``).
    """
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if sys.platform != "win32":
        with contextlib.suppress(OSError):
            os.chmod(parent, 0o700)


@contextlib.contextmanager
def _acquire_storage_lock(
    lock_path: Path,
    *,
    log_prefix: str,
    deadline_seconds: float = _LOCK_ACQUIRE_DEADLINE_SECONDS,
) -> Iterator[str]:
    """Platform-neutral **bounded** exclusive acquire of a storage sentinel lock.

    Non-blocking probe (via :func:`_file_lock` with ``blocking=False``, which takes
    the per-path in-process ``threading.Lock`` before the OS lock) plus a
    deadline/jitter retry loop. Yields one of:

    * ``"held"`` — the lock is held; released when the ``with`` block exits.
    * ``"unavailable"`` — the deadline elapsed under contention, or the lock
      infrastructure failed (read-only dir, NFS without flock, fd exhaustion).

    The caller maps ``"unavailable"`` to its per-intent policy: fail-open
    callers proceed, fail-closed callers raise :class:`LockUnavailableError`.
    """
    deadline = time.monotonic() + deadline_seconds
    delay = _LOCK_ACQUIRE_INITIAL_DELAY_SECONDS
    while True:
        with _file_lock(lock_path, blocking=False, log_prefix=log_prefix) as state:
            if state == "held":
                yield "held"
                return
            if state == "unavailable":
                # Infrastructure failure — no amount of retrying will help.
                yield "unavailable"
                return
            # state == "contended": another holder (thread or process) has it.
        # Jittered exponential backoff (shared with ``_acquire_os_lock``'s
        # Windows retry via :func:`_sleep_backoff` — one tuning site).
        next_delay = _sleep_backoff(delay, deadline)
        if next_delay is None:
            logger.debug(
                "%s: bounded storage-lock acquire exceeded %.0fs deadline; giving up",
                log_prefix,
                deadline_seconds,
            )
            yield "unavailable"
            return
        delay = next_delay


# ==========================================================================
# SECTION 3 — THE STORAGE-WRITE TRANSACTION TEMPLATE (ADR-0031 Stage 3)
# ``in_storage_transaction`` owns the four-step preamble every writer used to
# hand-roll; the not-held policy is a parameter because it genuinely differs.
# ==========================================================================


# Six of this module's writers each hand-rolled the same four-step preamble —
# secure the parent dir, derive the sentinel lock path, take the bounded lock,
# and branch on whether it was held. **All six route through this template**
# since ADR-0033 PR 1.2, and the ratchet
# ``tests/_guardrails/test_storage_transaction_ratchet.py`` now has an EMPTY
# exception list, so a seventh writer cannot hand-roll it. Only the last step
# differs, and it differs in three genuinely incompatible ways, so the policy is
# a parameter rather than a decision baked into the template: a version that
# picked one behavior would be a silent semantic change in a credential-write
# path.
#
# ``merge_cookie_delta`` deliberately does NOT use this. It takes the BLOCKING
# ``_file_lock_exclusive`` rather than the bounded acquire, and skips the
# parent-dir prep because it only ever updates a file that already exists. Its
# lock semantics are a different operation, not a variant of this one.


#
# THE POLICIES — two intents, three constructors
# ----------------------------------------------
# There are only TWO intents here, and it is worth stating which is which,
# because the surface count of three invites the wrong mental model:
#
#   MUST-KNOW  the write mattered; a caller that proceeds as though it happened
#              is wrong. Five writers. A master token that was not persisted
#              means the mint was wasted; account metadata that was not written
#              means routing silently targets the wrong Google account; a login
#              that was not persisted means the user believes they are signed in.
#
#   TOLERABLE  the write was cleanup; missing it degrades gracefully. One writer.
#
# MUST-KNOW has *two constructors* only because the writers' return channels
# differ in what they can express — not because the intent differs:
#
#   ``-> None``            no channel at all                      -> raise
#   ``-> bool``            ``False`` already means "deliberately   -> raise
#                          skipped (only_if_absent)", so reusing
#                          it would conflate *chose not to* with
#                          *could not*
#   ``-> WriteOutcome``    a rich enum with room for a distinct    -> report
#   ``-> LoginWriteOutcome`` LOCK_UNAVAILABLE status
#
# Each choice is locally forced. The inconsistency lives one level up, in
# writers that do morally identical things having different return types.
# Unifying that means giving every MUST-KNOW writer a rich outcome type, which
# is a breaking change for callers that today catch ``OSError``/``TimeoutError``
# around ``persist_minted_jar`` and ``update_account_metadata`` — a deprecation
# runway, not a refactor stage. Tracked in ADR-0031.


class _LockUnavailablePolicy(Protocol):
    """What a writer does when the storage lock could not be acquired."""

    def __call__(self, lock_path: Path) -> Any: ...


def raise_on_lock_unavailable(operation: str) -> _LockUnavailablePolicy:
    """MUST-KNOW, via exception — for writers with no usable return channel.

    Used where the return type is ``None`` (``persist_minted_jar``,
    ``write_master_token``) or a ``bool`` whose ``False`` already carries a
    different meaning (``update_account_metadata``).
    """

    def _policy(lock_path: Path) -> Any:
        raise LockUnavailableError(f"{operation}: storage lock unavailable at {lock_path}")

    return _policy


def report_on_lock_unavailable(outcome: Any) -> _LockUnavailablePolicy:
    """MUST-KNOW, via return value — for writers with a rich outcome type.

    Same intent as :func:`raise_on_lock_unavailable`; different mechanism only
    because the caller has somewhere unambiguous to put it. The two full-replace
    writers have their OWN outcome types (:class:`WriteOutcome` vs
    :class:`LoginWriteOutcome`), so the value comes from the caller.

    .. note::
       The designated callers are ``replace_from_remint`` and
       ``replace_from_login`` — the only writers whose return type can carry a
       distinct lock-unavailable status. That is pinned rather than merely
       noted: the ratchet asserts exactly one caller per CONVERTED member of
       that pair, so this helper can neither be reached from a writer whose
       return channel cannot express the report, nor quietly outlive its reason
       to exist.
    """

    def _policy(lock_path: Path) -> Any:
        return outcome

    return _policy


def skip_on_lock_unavailable(message: str) -> _LockUnavailablePolicy:
    """TOLERABLE — log at DEBUG and do nothing.

    Args:
        message: a logging format string with **exactly one** ``%s``, which
            receives the lock path. A message with no placeholder (or more than
            one) raises inside ``logging``, which swallows it and prints to
            stderr instead of logging — an unpleasant failure to trace back,
            since it surfaces nowhere near this call.

    The only genuinely different intent, and it has exactly one user today:
    ``clear_in_band_account``. Its justification is functional — a missed clear
    leaves the legacy reader still able to resolve the account record.

    .. note::
       That justification is narrower than the operation's motive. Clearing the
       in-band account is **privacy**-motivated ("a stale key must not leave the
       account email at rest" — see ``auth.py``), and a swallowed failure leaves
       precisely that email on disk until the next successful write. Functional
       degradation is graceful; the privacy miss is silent. Rare — it needs 90 s
       of lock contention or a lock-infrastructure failure — but the swallow is
       justified on a different axis than the one that matters most here.
       Flagged in ADR-0031 rather than changed unilaterally, since promoting it
       to MUST-KNOW would make a best-effort cleanup able to fail a caller.
    """

    def _policy(lock_path: Path) -> Any:
        logger.debug(message, lock_path)
        return None

    return _policy


def in_storage_transaction(
    path: Path,
    body: Callable[[], Any],
    *,
    log_prefix: str,
    on_unavailable: _LockUnavailablePolicy,
    deadline_seconds: float = _LOCK_ACQUIRE_DEADLINE_SECONDS,
) -> Any:
    """Run ``body()`` under the bounded storage lock for ``path``.

    Owns the four steps every writer repeated: secure-parent-dir prep, lock-path
    derivation, the bounded acquire, and the not-held branch. ``body`` returns
    the writer's own return value, so an early ``return`` inside it (the
    ``only_if_absent`` short-circuit, for instance) propagates unchanged.

    The lock is held for the whole of ``body``, including its atomic write
    — the read-decide-write sequence must not be re-entered by a concurrent
    writer partway through.
    """
    # Before ADR-0033's persistence merge this reached ``_acquire_storage_lock``
    # and ``_ensure_secure_parent_dir`` through a function-local import back into
    # ``storage_writer`` (the module this template was split out of). Both now
    # live in this module, so the cycle-breaking lazy import is gone.
    _ensure_secure_parent_dir(path)
    lock_path = _storage_state_lock_path(path)
    with _acquire_storage_lock(
        lock_path, log_prefix=log_prefix, deadline_seconds=deadline_seconds
    ) as state:
        if state != "held":
            return on_unavailable(lock_path)
        return body()


# ==========================================================================
# SECTION 4 — SNAPSHOT TYPES
# Path-aware cookie identity/value tuples and the detailed save result.
# ==========================================================================


class CookieSnapshotKey(NamedTuple):
    """Path-aware cookie identity used by the snapshot/delta save machinery.

    RFC 6265 treats ``path`` as part of cookie identity: two cookies with the
    same ``(name, domain)`` but different paths are distinct entries. The
    snapshot/delta path widens the legacy ``(name, domain)`` key (still used
    elsewhere for back-compat — see ``CookieKey``) to ``(name, domain, path)``
    so that path-scoped cookies (e.g. ``OSID`` on a per-product path) survive
    a load → save round trip and so that a sibling-process write to a
    different-path variant of the same name is not silently overwritten.
    """

    name: str
    domain: str
    path: str


class CookieSnapshotValue(NamedTuple):
    """Snapshot value tuple: ``(value, expires, secure, http_only)``.

    Widened from a bare ``str`` so that a ``Set-Cookie`` which keeps the same
    value but renews ``expires`` (or flips ``secure`` / ``httpOnly``) still
    registers as a delta. The legacy save path compared ``expires`` directly
    and would write the new expiry through; the snapshot path previously
    keyed on value alone and silently dropped attribute-only refreshes.
    """

    value: str
    expires: int | None
    secure: bool
    http_only: bool


CookieSnapshot: TypeAlias = dict[CookieSnapshotKey, CookieSnapshotValue]
# ``None`` is a private observation marker for a pre-existing target row whose
# value was empty, missing, or non-string.  It lets recovery replace an unusable
# row while still treating a newly-written non-empty sibling as a CAS conflict.
RecoveryCookieObservation: TypeAlias = dict[CookieSnapshotKey, frozenset[str | None]]


@dataclass(frozen=True)
class CookieSaveResult:
    """Detailed result for callers that need to maintain a save baseline."""

    ok: bool
    cas_rejected_keys: frozenset[CookieSnapshotKey] = frozenset()


# ==========================================================================
# SECTION 5 — CAS + MERGE MATH (and the pinned delegate seam)
# Snapshotting, baseline advancement, the legacy and snapshot/delta merges, and
# ``save_cookies_to_storage`` — the ADR-0029-pinned monkeypatchable delegate.
# ==========================================================================


def snapshot_cookie_jar(cookie_jar: httpx.Cookies) -> CookieSnapshot:
    """Capture an open-time snapshot of an httpx cookie jar.

    Snapshots are the input to the dirty-flag/delta merge in
    :func:`save_cookies_to_storage`: at save time, only cookies whose
    in-memory value differs from the snapshot — plus cookies absent from
    the jar but present in the snapshot (deletions) — are propagated to
    disk. Cookies the in-process code never touched are left to whatever
    a sibling process may have written (closes the Appendix A2
    stale-overwrite-fresh hazard).

    The key shape is path-aware ``(name, domain, path)`` (also closes
    the Appendix A2 path-collapse hazard). Cookies with no name or no domain
    are skipped — the storage format requires both.

    Args:
        cookie_jar: The httpx.Cookies object to snapshot.

    Returns:
        Mapping of ``CookieSnapshotKey -> CookieSnapshotValue`` capturing
        each cookie's value and the attributes the storage_state schema
        persists (``expires``, ``secure``, ``httpOnly``).
    """
    return {
        CookieSnapshotKey(cookie.name, cookie.domain, cookie.path or "/"): CookieSnapshotValue(
            value=cookie.value,
            expires=cookie.expires,
            secure=bool(cookie.secure),
            http_only=_cookie_is_http_only(cookie),
        )
        for cookie in cookie_jar.jar
        if cookie.name and cookie.domain and cookie.value is not None
    }


def _cookie_snapshot_key_variants(key: CookieSnapshotKey) -> set[CookieSnapshotKey]:
    """Return equivalent host/domain snapshot keys for leading-dot domains.

    Mirrors :func:`_cookie_key_variants` but preserves the path component so
    storage entries on the same path match snapshot entries regardless of
    whether ``http.cookiejar`` normalized the domain to a leading dot.
    """
    variants = {key}
    if key.domain.startswith("."):
        variants.add(CookieSnapshotKey(key.name, key.domain[1:], key.path))
    else:
        variants.add(CookieSnapshotKey(key.name, f".{key.domain}", key.path))
    return variants


def _stored_cookie_snapshot_key(stored_cookie: Any) -> CookieSnapshotKey | None:
    """Build a path-aware snapshot key from a Playwright storage_state cookie."""
    if not isinstance(stored_cookie, dict):
        return None
    name = stored_cookie.get("name")
    domain = stored_cookie.get("domain", "")
    if not isinstance(name, str) or not name:
        return None
    if not isinstance(domain, str) or not domain:
        return None
    raw_path = stored_cookie.get("path")
    if raw_path is not None and not isinstance(raw_path, str):
        return None
    path = raw_path or "/"
    return CookieSnapshotKey(name, domain, path)


def advance_cookie_snapshot_after_save(
    original_snapshot: CookieSnapshot | None,
    post_save_snapshot: CookieSnapshot,
    cas_rejected_keys: frozenset[CookieSnapshotKey],
) -> CookieSnapshot | None:
    """Advance save baseline for successful keys while preserving rejected ones.

    A save can partially succeed: one cookie delta may write through while a
    sibling-process CAS conflict rejects another. Advancing the whole baseline
    would lose the rejected delta; keeping the whole old baseline would replay
    already-written deltas and wedge future saves. This helper advances every
    key to ``post_save_snapshot`` except the CAS-rejected keys, which retain
    their old baseline value or absence. Rejected keys are matched through
    leading-dot variants because the merge path can reject a normalized variant
    of the key captured in ``original_snapshot``.
    """
    if original_snapshot is None:
        return None

    advanced = dict(post_save_snapshot)
    for key in cas_rejected_keys:
        original_key = next(
            (
                variant
                for variant in _cookie_snapshot_key_variants(key)
                if variant in original_snapshot
            ),
            None,
        )
        for variant in _cookie_snapshot_key_variants(key):
            advanced.pop(variant, None)
        if original_key is not None:
            advanced[original_key] = original_snapshot[original_key]
    return advanced


def _cookie_save_return(
    result: CookieSaveResult, *, return_result: bool
) -> bool | CookieSaveResult:
    """Return either the detailed save result or its public bool projection."""
    return result if return_result else result.ok


def save_cookies_to_storage(
    cookie_jar: httpx.Cookies,
    path: Path | None = None,
    *,
    original_snapshot: CookieSnapshot | None = None,
    recovery_observation: RecoveryCookieObservation | None = None,
    return_result: bool = False,
) -> bool | CookieSaveResult:
    """Save an updated httpx.Cookies jar back to Playwright storage_state.json.

    This ensures that when Google issues short-lived token refreshes (e.g.
    during 302 redirects to accounts.google.com), those updated cookies are
    serialized back to disk so the session remains valid across CLI invocations.

    If auth was loaded from an environment variable (no file), this is a no-op.

    Cross-process safety: the read-merge-write cycle is wrapped in an OS-level
    file lock (``.storage_state.json.lock``) so concurrent writers from
    different Python processes (e.g. an in-process ``NotebookLMClient`` keepalive
    plus a cron-driven ``notebooklm auth refresh``) serialize cleanly rather
    than tearing or losing updates.

    Two merge modes:

    - **Legacy (``original_snapshot=None``)**: every in-memory cookie whose
      value differs from disk wins. Vulnerable to the stale-overwrite-fresh
      race documented in ``docs/auth-cookie-lifecycle.md`` Appendix A2 and emits a
      ``RuntimeWarning`` safety advisory about that race (this is a permanent
      back-compat shim, not a scheduled deprecation, so the advisory is a
      ``RuntimeWarning`` and is not silenced by ``NOTEBOOKLM_QUIET_DEPRECATIONS``).
      Kept only as a public-API back-compat shim for callers outside this repo;
      every first-party caller passes ``original_snapshot``.
    - **Snapshot/delta (``original_snapshot`` provided)**: only cookies
      whose in-memory persisted tuple differs from the snapshot are written, and
      cookies present in the snapshot but no longer in the jar are
      deleted from disk. Cookies the in-process code never touched are
      left untouched on disk so a sibling-process write survives.
      Path-aware ``(name, domain, path)`` keys are used here (also closes
      the Appendix A2 path-collapse hazard).

    Args:
        cookie_jar: The httpx.Cookies object containing the latest cookies.
        path: Path to storage_state.json. If None, cookie sync is skipped.
        original_snapshot: Open-time snapshot from
            :func:`snapshot_cookie_jar`. When provided, only deltas and
            deletions relative to the snapshot are persisted.
        return_result: Internal escape hatch for callers that need CAS-rejected
            keys to maintain a per-cookie baseline. Public callers should use
            the default bool return.

    Returns:
        ``True`` if the disk state now reflects the caller's intent (write
        succeeded, was a successful no-op, or the call was a deliberate skip
        because auth was loaded from an env var). ``False`` if an I/O error
        prevented the save or a CAS guard preserved a sibling-process write.
        With ``return_result=True``, callers can inspect CAS-rejected keys and
        advance their baseline for the keys that did write through.
    """
    if original_snapshot is None and path is not None:
        # NOT a deprecation: the original_snapshot=None form is a *permanent*
        # public-API back-compat shim (docs/auth-cookie-lifecycle.md Appendix A2),
        # not a scheduled removal — every in-tree caller already passes a
        # snapshot. The warning is a runtime safety advisory about the
        # stale-overwrite-fresh race that path is vulnerable to, so it is a
        # RuntimeWarning, not a DeprecationWarning. It is therefore outside
        # ADR-0018's scope: no NOTEBOOKLM_QUIET_DEPRECATIONS gate, no removal
        # version, and emitted directly here rather than via warn_deprecated.
        # Emitted on THIS delegate (not the relocated merge body) so
        # ``stacklevel=2`` still points at the caller.
        warnings.warn(
            "save_cookies_to_storage called without original_snapshot; the "
            "legacy full-merge path is vulnerable to the stale-overwrite-fresh "
            "race (docs/auth-cookie-lifecycle.md Appendix A2). Pass an original_snapshot "
            "captured via snapshot_cookie_jar() at jar-open time.",
            RuntimeWarning,
            stacklevel=2,
        )

    # Canonical patch seam: the CAS delta merge body lives in
    # :func:`merge_cookie_delta` (section 5 below). This module-level
    # ``save_cookies_to_storage`` symbol stays here as the monkeypatchable
    # delegate (~18 test files patch it; ``_runtime/lifecycle.py`` late-binds it).
    # Before ADR-0033's persistence merge the delegate reached the body through a
    # function-local ``from . import storage_writer``; it is now a same-module call.
    return merge_cookie_delta(
        cookie_jar,
        path,
        original_snapshot=original_snapshot,
        recovery_observation=recovery_observation,
        return_result=return_result,
    )


def _preserved_same_site(stored_cookie: dict[str, Any], fresh_state: dict[str, Any]) -> str:
    """Keep a stored ``sameSite`` instead of the merge default that erases it.

    ``http.cookiejar.Cookie`` carries no SameSite attribute, so
    :func:`_cookie_to_storage_state` can only emit the ``"None"`` default. Writing
    that back over a row captured with ``"Lax"``/``"Strict"`` would downgrade it on
    every rotation, quietly undoing the attribute preservation the capture and
    rookiepy converters perform.
    """
    stored = stored_cookie.get("sameSite")
    if stored in {"Strict", "Lax", "None"}:
        return str(stored)
    return str(fresh_state["sameSite"])


def _merge_cookies_legacy(cookie_jar: httpx.Cookies, storage_data: dict[str, Any]) -> int:
    """Legacy merge: trust in-memory whenever it differs from disk.

    Vulnerable to the stale-overwrite-fresh race (Appendix A2). Kept only for
    callers that have not yet opted into snapshot semantics. New callers
    must pass ``original_snapshot`` to :func:`save_cookies_to_storage`.

    Returns:
        Number of cookie entries added or modified in ``storage_data``.
    """
    cookies_by_key: dict[CookieKey, Any] = {
        (cookie.name, cookie.domain, cookie.path or "/"): cookie
        for cookie in cookie_jar.jar
        if cookie.name and cookie.domain and _is_allowed_cookie_domain(cookie.domain)
    }

    updated_count = 0
    stored_keys: set[CookieKey] = set()
    for stored_cookie in storage_data["cookies"]:
        if not isinstance(stored_cookie, dict):
            continue
        name = stored_cookie.get("name")
        domain = stored_cookie.get("domain", "")
        if not isinstance(name, str) or not name or not isinstance(domain, str) or not domain:
            continue

        stored_key = _stored_cookie_snapshot_key(stored_cookie)
        if stored_key is None:
            continue
        key: CookieKey = stored_key
        stored_keys.update(_cookie_key_variants(key))
        refreshed_cookie = _find_cookie_for_storage(cookies_by_key, key, stored_cookie.get("value"))
        if refreshed_cookie is None:
            continue

        fresh_state = _cookie_to_storage_state(refreshed_cookie)
        new_expires = fresh_state["expires"]
        changed = (
            stored_cookie.get("value") != refreshed_cookie.value
            or stored_cookie.get("expires") != new_expires
        )
        if changed:
            stored_cookie["value"] = refreshed_cookie.value
            stored_cookie["expires"] = new_expires
            # Normalize present-but-empty ``"path": ""`` to ``"/"`` so the row
            # we write matches the path normalization used to build the
            # identity key one block up (and used by every loader). Without
            # the trailing ``or "/"`` an on-disk row with ``"path": ""`` would
            # survive across save cycles while every other code path treats
            # it as ``"/"``.
            stored_cookie["path"] = refreshed_cookie.path or stored_cookie.get("path") or "/"
            stored_cookie["secure"] = refreshed_cookie.secure
            stored_cookie["httpOnly"] = _cookie_is_http_only(refreshed_cookie)
            stored_cookie["sameSite"] = _preserved_same_site(stored_cookie, fresh_state)
            updated_count += 1

    for key, cookie in cookies_by_key.items():
        if key in stored_keys:
            continue
        storage_data["cookies"].append(_cookie_to_storage_state(cookie))
        updated_count += 1

    return updated_count


def _merge_recovery_target_rows(
    storage_cookies: list[Any],
    deltas: dict[CookieSnapshotKey, Any],
    observation: RecoveryCookieObservation | None,
) -> tuple[list[Any], int, set[CookieSnapshotKey], set[CookieSnapshotKey]]:
    """Collapse observed recovery targets while preserving sibling conflicts."""
    if observation is None:
        return storage_cookies, 0, set(), set()

    replacements: dict[int, dict[str, Any]] = {}
    removals: set[int] = set()
    appends: list[dict[str, Any]] = []
    handled: set[CookieSnapshotKey] = set()
    cas_rejected: set[CookieSnapshotKey] = set()
    updated_count = 0

    for delta_key, cookie in deltas.items():
        if delta_key.name not in _RECOVERY_TARGET_COOKIE_NAMES:
            continue

        variants = _cookie_snapshot_key_variants(delta_key)
        observed_values: set[str | None] = set()
        for variant in variants:
            observed_values.update(observation.get(variant, frozenset()))
        if not observed_values:
            # No target row was observed before the POST. Let the ordinary
            # snapshot/CAS path decide whether a same-key sibling appeared.
            continue

        row_indices: list[int] = []
        for index, stored_cookie in enumerate(storage_cookies):
            stored_key = _stored_cookie_snapshot_key(stored_cookie)
            if stored_key is not None and variants & _cookie_snapshot_key_variants(stored_key):
                row_indices.append(index)

        fresh_state = _cookie_to_storage_state(cookie)
        replaceable: list[int] = []
        conflicts: list[int] = []
        for index in row_indices:
            stored_cookie = storage_cookies[index]
            stored_value = stored_cookie.get("value") if isinstance(stored_cookie, dict) else None
            stored_value_is_unusable = not isinstance(stored_value, str) or not stored_value
            observed_unusable = None in observed_values
            if (
                stored_value == cookie.value
                or stored_value in observed_values
                or (stored_value_is_unusable and observed_unusable)
            ):
                replaceable.append(index)
            else:
                conflicts.append(index)

        if conflicts:
            # This is the recovery-specific CAS rejection. The sibling rows
            # remain byte-for-byte intact; no stale recovery value may clobber
            # a value that did not exist when the POST started.
            #
            # Deliberately whole-key, even in the mixed case where another row
            # for this identity *was* replaced below: the key is reported as
            # rejected, so ``advance_cookie_snapshot_after_save`` leaves the
            # baseline where it is. A conflicting row is still on disk and the
            # loaders pick a winner among duplicates, so we cannot claim the
            # identity now reads as the value we wrote. Advancing on a partial
            # write would retire a delta that never fully landed.
            cas_rejected.add(delta_key)

        if replaceable:
            winner = replaceable[0]
            # Same ``sameSite`` preservation the ordinary merges apply: only the
            # cookie's *value* and expiry are being refreshed by the rotation,
            # and ``fresh_state`` can only carry the ``"None"`` default, so
            # taking it wholesale would downgrade a captured ``Lax``/``Strict``
            # on the one path recovery owns.
            stored_winner = storage_cookies[winner]
            replacements[winner] = {
                **fresh_state,
                "sameSite": _preserved_same_site(
                    stored_winner if isinstance(stored_winner, dict) else {}, fresh_state
                ),
            }
            removals.update(replaceable[1:])
            updated_count += 1 + len(replaceable[1:])
            handled.add(delta_key)
        elif not row_indices:
            appends.append(fresh_state)
            updated_count += 1
            handled.add(delta_key)
        elif conflicts:
            # Preserve an unobserved sibling exactly. The ordinary new-cookie
            # CAS path would likewise decline to append over an existing row.
            handled.add(delta_key)

    merged: list[Any] = []
    for index, stored_cookie in enumerate(storage_cookies):
        if index in removals:
            continue
        merged.append(replacements.get(index, stored_cookie))
    merged.extend(appends)
    return merged, updated_count, cas_rejected, handled


def _merge_cookies_with_snapshot(
    cookie_jar: httpx.Cookies,
    storage_data: dict[str, Any],
    original_snapshot: CookieSnapshot,
    *,
    recovery_observation: RecoveryCookieObservation | None = None,
) -> tuple[int, frozenset[CookieSnapshotKey]]:
    """Snapshot/delta merge: write only what this process actually changed.

    Closes the Appendix A2 stale-overwrite-fresh and path-collapse hazards:

    - **Deltas (CAS-guarded for keys in the snapshot)**: cookies in the
      jar whose snapshot tuple (``value, expires, secure, http_only``)
      differs from ``original_snapshot`` are written to disk **only if**
      the on-disk value still matches the snapshot value. If disk has
      rotated since open time, a sibling process has written it; we
      preserve their write rather than clobber it with our local
      rotation. New cookies acquired during the session are written only
      when no same-key storage row exists yet; an existing row means a
      sibling acquired the same cookie first. Comparing the full snapshot
      tuple keeps attribute-only refreshes (same value, new ``expires``)
      flowing to disk, but CAS remains value-only because attribute-only
      sibling drift is routine session metadata and should not wedge later
      value rotations.
    - **Deletions (CAS-guarded)**: a key present in the snapshot but
      absent from the jar is dropped from disk **only if** the on-disk
      value still matches the snapshot value — symmetric with the
      value-update CAS above. An ``Max-Age=0`` that evicted our
      locally-expired copy must not erase the sibling's freshly-issued
      replacement.
    - **Untouched**: cookies in the jar whose tuple matches the snapshot
      are not written, so a sibling-process write to the same key
      survives. Cookies on disk that are not in the snapshot are also
      left alone (they belong to a sibling process or another path).

    Args:
        cookie_jar: Current in-memory cookie jar.
        storage_data: Mutable storage_state.json dict (modified in place).
        original_snapshot: Open-time snapshot of the same jar.

    Returns:
        Tuple of ``(updated_count, cas_rejected_keys)``:

        - ``updated_count``: cookie entries added, modified, or removed
          (drives whether the temp-write step runs).
        - ``cas_rejected_keys``: keys whose CAS check rejected a delta or
          deletion. Caller uses this to advance the baseline only for keys
          that were actually written or already matched.
    """
    current_snapshot = snapshot_cookie_jar(cookie_jar)

    # Path-aware index of jar cookies for delta application. Restricting to
    # _is_allowed_cookie_domain matches the legacy save's allowlist gate so
    # this PR doesn't inadvertently widen the persisted-domain set.
    # Filter ``cookie.value is not None`` to mirror ``snapshot_cookie_jar``: a
    # value-less cookie is treated as a deletion (absent from this index, absent
    # from ``current_snapshot``) rather than a delta that would write ``null``
    # to disk.
    cookies_by_snapshot_key = {
        CookieSnapshotKey(cookie.name, cookie.domain, cookie.path or "/"): cookie
        for cookie in cookie_jar.jar
        if (
            cookie.name
            and cookie.domain
            and cookie.value is not None
            and _is_allowed_cookie_domain(cookie.domain)
        )
    }

    deltas = {
        snapshot_key: cookie
        for snapshot_key, cookie in cookies_by_snapshot_key.items()
        if original_snapshot.get(snapshot_key) != current_snapshot.get(snapshot_key)
    }

    deletion_candidates: set[CookieSnapshotKey] = {
        snapshot_key
        for snapshot_key in original_snapshot
        if snapshot_key not in current_snapshot
        # Only delete cookies the merge would otherwise be allowed to write.
        # Snapshot may include sibling-product domains the allowlist filters
        # out at write time; treating those as deletions would silently drop
        # disk entries we never persisted to begin with.
        and _is_allowed_cookie_domain(snapshot_key.domain)
    }

    updated_count = 0
    cas_rejected_keys: set[CookieSnapshotKey] = set()

    recovery_rows, recovery_updated, recovery_rejected, recovery_handled = (
        _merge_recovery_target_rows(storage_data["cookies"], deltas, recovery_observation)
    )
    updated_count += recovery_updated
    cas_rejected_keys.update(recovery_rejected)
    storage_data["cookies"] = recovery_rows
    merge_deltas = {key: cookie for key, cookie in deltas.items() if key not in recovery_handled}

    # Apply deltas + deletions to the existing storage entries in place.
    new_cookies: list[dict[str, Any]] = []
    matched_delta_keys: set[CookieSnapshotKey] = set(recovery_handled)
    for stored_cookie in storage_data["cookies"]:
        stored_key = _stored_cookie_snapshot_key(stored_cookie)
        if stored_key is None:
            new_cookies.append(stored_cookie)
            continue

        # Find the delta (or deletion) that maps to this stored entry.
        # Match leading-dot domain variants so e.g. snapshot
        # ``.accounts.google.com`` lines up with stored ``accounts.google.com``.
        # A delta wins over a deletion: if the same stored entry matches
        # both (which can happen when httpx normalized one variant), we
        # prefer to update rather than drop, because dropping would lose
        # the rotation we just applied.
        matched_delta_cookie = None
        matched_delta_key: CookieSnapshotKey | None = None
        for variant in _cookie_snapshot_key_variants(stored_key):
            if variant in merge_deltas:
                matched_delta_cookie = merge_deltas[variant]
                matched_delta_key = variant
                break

        if matched_delta_cookie is not None:
            if matched_delta_key is None:  # pragma: no cover - loop invariant
                raise RuntimeError("matched_delta_cookie set without matched_delta_key")
            # CAS-guard for value updates: if our snapshot had this key in any
            # leading-dot variant and disk's current value differs from the
            # snapshot value, a sibling process has rewritten the row between
            # our open and our save. Preserve their write rather than clobber,
            # unless disk has already converged to our current value; in that
            # case the save intent is satisfied and the caller may advance its
            # baseline.
            # Variant-aware lookup mirrors the delta match above: if the snapshot
            # was keyed on ``accounts.google.com`` but the matched delta key is
            # the leading-dot variant, a plain ``.get(matched_delta_key)`` would
            # miss the entry and silently bypass the CAS.
            snapshot_entry = next(
                (
                    original_snapshot[variant]
                    for variant in _cookie_snapshot_key_variants(matched_delta_key)
                    if variant in original_snapshot
                ),
                None,
            )
            stored_value = stored_cookie.get("value")
            if (
                snapshot_entry is not None
                and stored_value != snapshot_entry.value
                and stored_value != matched_delta_cookie.value
            ):
                logger.debug(
                    "Skipped CAS-guarded value update of %s on %s: disk value "
                    "differs from snapshot (sibling write preserved)",
                    matched_delta_key.name,
                    matched_delta_key.domain,
                )
                cas_rejected_keys.add(matched_delta_key)
                matched_delta_keys.add(matched_delta_key)
                new_cookies.append(stored_cookie)
                continue
            if snapshot_entry is None and stored_value != matched_delta_cookie.value:
                logger.debug(
                    "Skipped CAS-guarded value update of new cookie %s on %s: "
                    "disk row already exists (sibling write preserved)",
                    matched_delta_key.name,
                    matched_delta_key.domain,
                )
                cas_rejected_keys.add(matched_delta_key)
                matched_delta_keys.add(matched_delta_key)
                new_cookies.append(stored_cookie)
                continue
            fresh_state = _cookie_to_storage_state(matched_delta_cookie)
            stored_cookie["value"] = matched_delta_cookie.value
            stored_cookie["expires"] = fresh_state["expires"]
            # Mirror :func:`_merge_cookies_legacy`: ``or "/"`` normalizes a
            # present-but-empty ``"path": ""`` so the written row matches the
            # path normalization used by the identity key and every loader.
            stored_cookie["path"] = matched_delta_cookie.path or stored_cookie.get("path") or "/"
            stored_cookie["secure"] = matched_delta_cookie.secure
            stored_cookie["httpOnly"] = _cookie_is_http_only(matched_delta_cookie)
            stored_cookie["sameSite"] = _preserved_same_site(stored_cookie, fresh_state)
            matched_delta_keys.add(matched_delta_key)
            updated_count += 1
            new_cookies.append(stored_cookie)
            continue

        deletion_match = next(
            (
                variant
                for variant in _cookie_snapshot_key_variants(stored_key)
                if variant in deletion_candidates
            ),
            None,
        )
        if deletion_match is not None:
            # CAS-guard: only drop the disk row if its value still matches
            # what we observed at snapshot time. A sibling process may have
            # rewritten this key between our open and our save; clobbering
            # their fresh value with our local eviction would resurrect the
            # exact stale-overwrite-fresh hazard the snapshot path exists
            # to close (just inverted — deletion-of-fresh instead of
            # value-write-of-stale).
            snapshot_value = original_snapshot[deletion_match].value
            if stored_cookie.get("value") == snapshot_value:
                updated_count += 1
                continue  # drop the entry from disk
            cas_rejected_keys.add(deletion_match)

        new_cookies.append(stored_cookie)

    # Append delta cookies that didn't match any existing storage entry
    # (genuinely new cookies acquired during the session).
    for snapshot_key, cookie in merge_deltas.items():
        if snapshot_key in matched_delta_keys:
            continue
        new_cookies.append(_cookie_to_storage_state(cookie))
        updated_count += 1

    storage_data["cookies"] = new_cookies
    return updated_count, frozenset(cas_rejected_keys)


# ==========================================================================
# SECTION 6 — WRITER OUTCOME TYPES
# Value-free status enums and records the intent writers return.
# ==========================================================================


class WriteStatus(Enum):
    """Closed-enum status for a full-file / RMW storage write."""

    OK = "ok"
    LOCK_UNAVAILABLE = "lock_unavailable"


@dataclass(frozen=True)
class WriteOutcome:
    """Value-free outcome for full-replace / RMW storage writers.

    Carries only an enum status — never cookie values, jars, state dicts, or
    caught exceptions — so it is always safe to ``repr``/log.
    """

    status: WriteStatus

    @property
    def ok(self) -> bool:
        return self.status is WriteStatus.OK

    @property
    def lock_unavailable(self) -> bool:
        return self.status is WriteStatus.LOCK_UNAVAILABLE


# ---------------------------------------------------------------------------
# Account-metadata sentinel for the login/import full-replace intent
# ---------------------------------------------------------------------------


class _AccountAction(Enum):
    """Sentinel actions for :func:`replace_from_login`'s ``account`` param."""

    KEEP = "keep"
    CLEAR = "clear"


#: Leave the account binding untouched — carry whatever the input state holds
#: (import-cookies has none, so the result carries none). The default.
KEEP_ACCOUNT = _AccountAction.KEEP
#: Drop any stale account binding (the refresh default-account login branch —
#: the user may have re-logged into a different Google account).
CLEAR_ACCOUNT = _AccountAction.CLEAR


@dataclass(frozen=True)
class AccountRecord:
    """An explicit account binding to embed in the ``notebooklm`` namespace.

    ``authuser`` is the internal Google account index; ``email`` is the stable
    routing identity (optional). Passed as ``replace_from_login(account=...)`` to
    embed the binding in the SAME atomic write as the cookies (replacing the
    former separate ``write_account_metadata`` step, which had its own lock and a
    partial-failure window).
    """

    authuser: int
    email: str | None = None


# The ``account`` argument sentinel: KEEP_ACCOUNT | CLEAR_ACCOUNT | AccountRecord.
AccountArg = _AccountAction | AccountRecord


class LoginWriteStatus(Enum):
    """Closed-enum status for a login/import full-replace storage write."""

    OK = "ok"
    LOCK_UNAVAILABLE = "lock_unavailable"
    REQUIRED_COOKIES_DROPPED = "required_cookies_dropped"


@dataclass(frozen=True)
class LoginWriteOutcome:
    """Value-free outcome for :func:`replace_from_login`.

    Carries only an enum status, cookie **names** (keys, never values), and a
    filesystem path — never cookie values, jars, state dicts, or caught
    exceptions — so it is always safe to ``repr``/log.

    * ``missing_required`` — names of ``MINIMUM_REQUIRED_COOKIES`` that the
      write-time domain filter dropped (only set on ``REQUIRED_COOKIES_DROPPED``).
    * ``present_names`` — names surviving the filter, so the CLI can build the
      same ``missing_cookies_hint`` #2086 produced without re-reading disk.
    * ``backup_path`` — path of the ``.bak`` copy taken inside the lock for the
      import flavour (``None`` when no backup was taken).
    """

    status: LoginWriteStatus
    missing_required: tuple[str, ...] = ()
    present_names: tuple[str, ...] = ()
    backup_path: Path | None = None

    @property
    def ok(self) -> bool:
        return self.status is LoginWriteStatus.OK

    @property
    def lock_unavailable(self) -> bool:
        return self.status is LoginWriteStatus.LOCK_UNAVAILABLE

    @property
    def required_cookies_dropped(self) -> bool:
        return self.status is LoginWriteStatus.REQUIRED_COOKIES_DROPPED


# ==========================================================================
# SECTION 7 — THE INTENT WRITERS
# The seven sanctioned mutations of ``storage_state.json`` and its sibling
# credential files. These are the only functions permitted to reach
# ``_write_state_unchecked`` (equality-asserted in test_storage_writer_boundary).
# ==========================================================================


# --- CAS delta merge (behind ``save_cookies_to_storage``) -------------------


def merge_cookie_delta(
    cookie_jar: httpx.Cookies,
    path: Path | None = None,
    *,
    original_snapshot: CookieSnapshot | None = None,
    recovery_observation: RecoveryCookieObservation | None = None,
    return_result: bool = False,
) -> bool | CookieSaveResult:
    """CAS snapshot/delta merge of ``cookie_jar`` into ``storage_state.json``.

    Relocated verbatim (behaviour-preserving) from
    ``save_cookies_to_storage``; that function remains the public,
    monkeypatchable delegate seam. The ``original_snapshot=None`` legacy-warning
    branch stays on the delegate so its ``stacklevel`` still points at the
    caller.

    This is a **CAS** intent: on lock unavailability it **fails open** (status
    quo — the snapshot/delta CAS guards preserve correctness), driven by
    :func:`_file_lock_exclusive`. The full signature (incl.
    ``recovery_observation``) and the :class:`CookieSaveResult` return with
    ``cas_rejected_keys`` are load-bearing for the PSIDTS-recovery and
    cookie-persistence baseline callers.
    """
    if path is None and resolve_auth_json_env() is not None:
        logger.debug("Skipping cookie sync: Auth loaded from NOTEBOOKLM_AUTH_JSON env var")
        return _cookie_save_return(CookieSaveResult(True), return_result=return_result)

    if path is None:
        logger.debug("Skipping cookie sync: No storage file path available")
        return _cookie_save_return(CookieSaveResult(True), return_result=return_result)

    lock_path = _storage_state_lock_path(path)
    with _file_lock_exclusive(lock_path):
        if not path.exists():
            logger.debug("Skipping cookie sync: Storage file not found at %s", path)
            return _cookie_save_return(CookieSaveResult(False), return_result=return_result)

        try:
            storage_data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning(
                "Failed to read storage state for cookie sync: %s",
                type(e).__name__,
            )
            return _cookie_save_return(CookieSaveResult(False), return_result=return_result)

        cookies = storage_data.get("cookies") if isinstance(storage_data, dict) else None
        if not isinstance(cookies, list):
            logger.warning(
                "storage_state at %s has an invalid 'cookies' key/payload; "
                "rotated cookies will not be persisted",
                path,
            )
            return _cookie_save_return(CookieSaveResult(False), return_result=return_result)

        if original_snapshot is None:
            updated_count = _merge_cookies_legacy(cookie_jar, storage_data)
            cas_rejected_keys: frozenset[Any] = frozenset()
        else:
            updated_count, cas_rejected_keys = _merge_cookies_with_snapshot(
                cookie_jar,
                storage_data,
                original_snapshot,
                recovery_observation=recovery_observation,
            )

        if updated_count == 0:
            # A CAS rejection with no other successful work means disk does
            # not reflect our intent; the caller must not advance baseline.
            return _cookie_save_return(
                CookieSaveResult(not cas_rejected_keys, cas_rejected_keys),
                return_result=return_result,
            )

        try:
            _write_state_unchecked(path, storage_data)
            logger.debug("Successfully synced %d refreshed cookies to %s", updated_count, path)
            # Even on a successful disk write, if any CAS arm rejected work,
            # disk diverges from ``post`` for at least one key — caller must
            # not advance baseline.
            return _cookie_save_return(
                CookieSaveResult(not cas_rejected_keys, cas_rejected_keys),
                return_result=return_result,
            )
        except Exception as e:
            logger.warning(
                "Failed to write updated cookies to %s: %s",
                path,
                type(e).__name__,
            )
            return _cookie_save_return(CookieSaveResult(False), return_result=return_result)


# --- In-band account writers (relocated from ``account.py``) ----------------
# The WRITE half of the account record; its readers, the promotion one-shot and
# the sibling scrub follow in section 7b (ADR-0033 PR 5.2).


def update_account_metadata(
    storage_path: Path,
    *,
    authuser: int,
    email: str | None = None,
    only_if_absent: bool = False,
) -> bool:
    """Persist account metadata atomically inside ``storage_state.json``.

    Relocated from ``account.write_account_metadata`` (ADR-0033 PR 1.1 — the
    in-band write only). Its two remaining halves, the facade wrapper
    :func:`write_account_metadata` and the sibling ``context.json`` cleanup
    :func:`_drop_legacy_account_key`, joined it here in PR 5.2 and are now
    same-module calls. Full-file RMW intent: **fails closed**, raising
    :class:`LockUnavailableError` on lock unavailability.

    ``only_if_absent`` closes a check-then-act race in
    :func:`promote_legacy_account`: that caller reads the legacy
    record and checks whether an in-band record is already present — both
    OUTSIDE this function's lock — before deciding to call this function at
    all. Without a re-check taken under the SAME lock as the write, a
    concurrent fresh login/account-switch (``write_account_metadata``,
    ``replace_from_login``) landing in that unlocked gap would commit its new
    record first, and this call would then unconditionally overwrite it with
    the stale legacy values the caller captured before the gap — silently
    re-clobbering a just-completed account switch with a promotion nobody
    asked to happen. ``write_account_metadata`` (an intentional overwrite —
    the whole point of a real login) always passes ``only_if_absent=False``
    (the default); only the promotion caller opts in.

    There is no ``deadline_seconds`` override: every caller takes the standard
    90s full-file-RMW deadline. One used to pass 2s —
    :func:`promote_legacy_account`, back when it ran INSIDE
    :func:`read_account_metadata` and a 90s lock wait would have frozen
    an event loop in the middle of what its callers treat as a fast, lock-free
    read. ADR-0033 PR 5.1 moved promotion off that read path onto a detached
    one-shot worker, so nothing is waiting on this acquire any more and
    outlasting real contention beats giving up (the one-shot does not retry).

    Returns:
        ``True`` if a write happened; ``False`` if ``only_if_absent`` was set
        and an in-band record was already present under the lock (no-op —
        the caller's stale values were correctly discarded).
    """
    account_payload: dict[str, Any] = {"authuser": authuser}
    if email:
        account_payload["email"] = email

    def _write() -> bool:
        data = _load_storage_state_for_write(storage_path)
        namespace = data.get(_STORAGE_NAMESPACE_KEY)
        if not isinstance(namespace, dict):
            namespace = {}
        elif only_if_absent and isinstance(namespace.get(_ACCOUNT_CONTEXT_KEY), dict):
            return False
        namespace["version"] = _STORAGE_NAMESPACE_VERSION
        namespace[_ACCOUNT_CONTEXT_KEY] = account_payload
        data[_STORAGE_NAMESPACE_KEY] = namespace
        _write_state_unchecked(storage_path, data)
        return True

    # MUST-KNOW via exception: the ``bool`` return already spends ``False`` on
    # the ``only_if_absent`` no-op above, so it cannot also carry "could not
    # acquire" without conflating *chose not to* with *could not*.
    return bool(
        in_storage_transaction(
            storage_path,
            _write,
            log_prefix="write_account_metadata",
            on_unavailable=raise_on_lock_unavailable("write_account_metadata"),
        )
    )


def clear_in_band_account(storage_path: Path) -> None:
    """Remove the ``notebooklm.account`` key from ``storage_state.json``.

    Relocated from ``account._clear_in_band_account`` (ADR-0033 PR 1.1); the
    one-line delegate that survived in ``account.py`` to reach it was deleted in
    PR 5.2 when :func:`clear_account_metadata` moved here. Best-effort cleanup:
    swallows lock unavailability and read/parse errors, matching the
    pre-refactor semantics (the reader falls back to the legacy record). No-op if
    the file is missing, unreadable, or carries no in-band record.
    """
    if not storage_path.exists():
        return

    def _clear() -> None:
        try:
            data = json.loads(storage_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            logger.debug("in-band account clear skipped at %s: %s", storage_path, e)
            return
        if not isinstance(data, dict):
            return
        namespace = data.get(_STORAGE_NAMESPACE_KEY)
        if not isinstance(namespace, dict) or _ACCOUNT_CONTEXT_KEY not in namespace:
            return
        del namespace[_ACCOUNT_CONTEXT_KEY]
        if set(namespace.keys()) <= {"version"}:
            del data[_STORAGE_NAMESPACE_KEY]
        else:
            data[_STORAGE_NAMESPACE_KEY] = namespace
        _write_state_unchecked(storage_path, data)

    # TOLERABLE: the same failure mode the old filelock OSError arm swallowed.
    # See the caveat on ``skip_on_lock_unavailable`` — the functional argument
    # (the legacy reader still resolves the record) is narrower than this
    # operation's privacy motive, and that tension is tracked in ADR-0031.
    in_storage_transaction(
        storage_path,
        _clear,
        log_prefix="clear_account_metadata",
        on_unavailable=skip_on_lock_unavailable(
            "in-band account clear skipped: storage lock unavailable at %s"
        ),
    )


# ==========================================================================
# SECTION 7b — ACCOUNT RECORDS: READERS, THE LEGACY ONE-SHOT, AND THE SCRUB
# Relocated from ``_auth/account.py`` (ADR-0033 PR 5.2), which kept the NETWORK
# identity half. Everything below is *persistence*: it reads and writes the same
# ``storage_state.json`` document as the writers above, under the same lock, and
# drives them directly — which is why all EIGHT function-local imports the split
# used to need (3 there, 5 here) are now plain same-module references.
# ==========================================================================


_ACCOUNT_CONTEXT_KEY = "account"

# The unified atomic profile-state format embeds account metadata
# inside ``storage_state.json`` under a ``notebooklm`` namespace key, so
# a single ``atomic_write_json`` covers both cookies and account in one
# crash-safe commit. ``version`` is bumped only when the in-band schema
# changes incompatibly — version 1 is the initial shape.
_STORAGE_NAMESPACE_KEY = "notebooklm"
_STORAGE_NAMESPACE_VERSION = 1

# --- Detached one-shot legacy-account promotion (ADR-0033 PR 5.1) ------------
#
# ``read_account_metadata`` is a READ. It is called per RPC on the token-route
# path (``refresh._resolve_token_route_kwargs`` -> ``get_authuser_for_storage``),
# so it must never take the storage WRITE lock. Durable promotion of a
# pre-v0.5.0 sibling record is therefore fired off the read path as a detached
# one-shot: the read derives its answer read-only from the legacy record (see
# :func:`_sanitize_legacy_account_record` — byte-identical to what promotion
# embeds) and returns immediately, while a background worker does the write.
#
# Two pieces of process-global state, both guarded by ONE plain
# ``threading.Lock``:
#
# * ``_PROMOTION_ONCE_PATHS`` — canonical ``storage_path`` strings a promotion
#   has already been scheduled for in this process. This IS the single flight:
#   N concurrent reads of one profile schedule exactly ONE promotion, and a
#   promotion that fails is not retried in-process. Retrying would buy nothing
#   — the read already returns the right record without it — and would put a
#   failing write back on a per-RPC path, which is the whole problem. Unbounded
#   growth is not a concern: real deployments have a handful of profiles.
# * ``_PROMOTION_THREADS`` — the workers still in flight, so tests can join
#   them deterministically (:func:`_drain_promotions_for_tests`). Production
#   never joins; each worker deregisters itself when it finishes.
#
# ``_PROMOTION_LOCK`` is a *scheduling* lock, not a storage lock: it is taken
# only on the legacy-only branch of the read, is held for a set lookup plus a
# ``Thread.start()``, and is never held across file I/O. The in-band fast path
# every per-RPC read walks takes NO lock at all (pinned by
# ``test_auth_account_promotion.py``).
#
# Deliberately ``threading``, not ``asyncio``: ``read_account_metadata`` is a
# synchronous function reached from CLI code with no running event loop as
# often as from ``async`` code, and the work it defers (``filelock`` acquire +
# atomic write) is blocking I/O. ``_auth.single_flight`` is the coalescing core
# for *awaitable* work — it requires a running loop (``asyncio.get_running_loop``
# in ``_claim``) and would leave the CLI entry path uncovered. Using threads
# also keeps this module free of lazily-constructed loop-bound primitives (the
# #1196 class the loop-affinity guard polices).
_PROMOTION_LOCK = threading.Lock()
_PROMOTION_ONCE_PATHS: set[str] = set()
_PROMOTION_THREADS: set[threading.Thread] = set()


def _account_context_path(storage_path: Path) -> Path:
    """Return the context.json path that annotates ``storage_path``.

    Legacy two-file layout: this sibling held ``account`` metadata before
    the unified format embedded it in ``storage_state.json``. Post-migration,
    it keeps CLI context state (``notebook_id``, ``conversation_id``) but no
    longer stores the ``account`` key.
    """
    return storage_path.with_name("context.json")


def _read_in_band_account(storage_path: Path) -> dict[str, Any]:
    """Read account metadata from inside ``storage_state.json``.

    Returns ``{}`` when the namespace key is missing, malformed, or the file
    cannot be read. Callers fall back to the legacy sibling ``context.json``.
    """
    if not storage_path.exists():
        return {}
    try:
        data = json.loads(storage_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.debug("in-band account read failed at %s: %s", storage_path, e)
        return {}
    return read_account_metadata_from_storage_state(data)


def read_account_metadata_from_storage_state(storage_state: Any) -> dict[str, Any]:
    """Read in-band account metadata from parsed Playwright storage state."""
    if not isinstance(storage_state, dict):
        return {}
    namespace = storage_state.get(_STORAGE_NAMESPACE_KEY)
    if not isinstance(namespace, dict):
        return {}
    account = namespace.get(_ACCOUNT_CONTEXT_KEY)
    return account if isinstance(account, dict) else {}


def _read_legacy_account(storage_path: Path) -> dict[str, Any]:
    """Read the pre-v0.5.0 sibling ``context.json`` account record.

    Consumed ONLY by :func:`promote_legacy_account` (the one-shot in-band
    migration). Never a standing read path — see ``read_account_metadata``.
    """
    context_path = _account_context_path(storage_path)
    if not context_path.exists():
        return {}
    try:
        data = json.loads(context_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.debug("account metadata read failed at %s: %s", context_path, e)
        return {}
    if not isinstance(data, dict):
        return {}
    account = data.get(_ACCOUNT_CONTEXT_KEY)
    return account if isinstance(account, dict) else {}


def read_account_metadata(storage_path: Path | None) -> dict[str, Any]:
    """Read profile account metadata, self-healing a legacy two-file profile.

    **This is a read. It takes no lock and issues no write.** Per-RPC token
    routing calls it on every request (``_resolve_token_route_kwargs`` ->
    :func:`get_authuser_for_storage`), so the durable half of the legacy
    migration is *detached* from it: see :func:`_schedule_legacy_promotion`.

    Unified layout: account metadata lives inside ``storage_state.json`` under
    the ``notebooklm`` namespace key. This reader never returns a raw
    pass-through of the pre-v0.5.0 sibling ``context.json`` — a standing read
    fallback trusting an unmigrated value is #2103's hazard.

    Instead the three branches are:

    1. **In-band present** — the overwhelming majority of calls, and the only
       one per-RPC routing walks once any profile has been read: one file read,
       one dict lookup, zero locks, zero threads.
    2. **Nothing anywhere** — ``{}``, but only after a SECOND in-band read. A
       promotion committing between this reader's two file samples would
       otherwise leave it holding a pre-embed in-band sample and a post-strip
       sibling sample, neither carrying the binding — ``authuser=0``, i.e.
       #2103 reached by timing rather than staleness. The strip follows the
       embed, so a vanished sibling implies a committed record; the re-read
       finds it. ``TestPromotionRacingTheReader`` spells out the interleaving.
    3. **Legacy-only** — the record is DERIVED read-only, through the very
       function promotion uses to build what it embeds
       (:func:`_sanitize_legacy_account_record`), so the caller sees a genuinely
       in-band-shaped record — never a raw pass-through — whether or not the
       durable write has landed. That write is scheduled once per path, in the
       background; the read does not wait.

    That derivation is the anti-wrong-account contract, and it makes promotion
    timing irrelevant to correctness: one that is slow, contended, or
    permanently failing (read-only dir, full disk) changes nothing observable
    except how long the sibling survives. ``test_auth_account_promotion.py``
    pins the derived record field-by-field against the promoted one.

    The ``account`` object records the Google ``authuser`` index used when the
    profile was authenticated. Profiles from before account-binding shipped
    (and single-Google-account users) have none, and use ``authuser=0``.

    Args:
        storage_path: Path to ``storage_state.json``. ``None`` means the profile
            is loaded from ``NOTEBOOKLM_AUTH_JSON`` — no sibling to promote
            from, so env-auth skips promotion and its record is read from the
            parsed payload by :func:`read_account_metadata_from_storage_state`.

    Returns:
        Parsed metadata dict, or ``{}`` only when no legacy OR in-band record
        exists at all.
    """
    if storage_path is None:
        return {}
    in_band = _read_in_band_account(storage_path)
    if in_band:
        return in_band
    legacy = _read_legacy_account(storage_path)
    if not legacy:
        # Never ``{}`` outright — a promotion may have landed between our two
        # samples. See branch 2.
        return _read_in_band_account(storage_path)
    # Re-read in-band before trusting the legacy record. A concurrent fresh
    # login / account-switch (or this process's own promotion worker) may have
    # committed one while we were reading the sibling, and in-band ALWAYS wins:
    # it is the newer, authoritative binding, and preferring a stale legacy
    # record over it is precisely the wrong-account-routing hazard. Cheap —
    # this branch is only reached on a not-yet-migrated profile.
    in_band_after = _read_in_band_account(storage_path)
    if in_band_after:
        return in_band_after
    _schedule_legacy_promotion(storage_path)
    return _sanitize_legacy_account_record(legacy)


def _schedule_legacy_promotion(storage_path: Path) -> threading.Thread | None:
    """Fire the durable promotion in the background, once per canonical path.

    The caller has already derived its answer read-only, so this exists purely
    to make the migration *durable* (and to scrub the legacy sibling, a privacy
    obligation). Nothing downstream of the read depends on it succeeding, or on
    when it finishes.

    Single-flight: the ``_PROMOTION_ONCE_PATHS`` membership test and the
    insertion happen under one ``_PROMOTION_LOCK`` hold, so N concurrent
    readers of the same profile produce exactly ONE worker. It is a one-shot,
    not a retry loop — a failed promotion is not re-attempted in this process
    (see the state block above for why).

    ``Thread.start()`` runs INSIDE the lock so a concurrent
    :func:`_drain_promotions_for_tests` can never observe a worker that is
    registered but not yet started (``join`` on an unstarted thread raises).
    ``start()`` returns as soon as the worker is bootstrapped, not when it
    finishes, so the reader is not made to wait on the write.

    Returns:
        The worker that was started, or ``None`` when this path had already
        scheduled one (test/diagnostic affordance; production ignores it).
    """
    # Keyed on the CANONICAL path, like every other in-process dedupe in
    # ``_auth`` (the keepalive throttle, the poke-lock registry, the refresh
    # flock): two spellings of one file — relative vs absolute, ``~``-prefixed,
    # or through a symlink — must collapse to one key or the single flight is
    # silently bypassed.
    canonical = str(canonical_storage_key(storage_path))
    with _PROMOTION_LOCK:
        if canonical in _PROMOTION_ONCE_PATHS:
            return None
        _PROMOTION_ONCE_PATHS.add(canonical)
        worker = threading.Thread(
            target=_run_promotion_once,
            args=(storage_path,),
            name="notebooklm-account-promotion",
            daemon=True,
        )
        _PROMOTION_THREADS.add(worker)
        worker.start()
    return worker


def _run_promotion_once(storage_path: Path) -> None:
    """Worker body: promote durably, then deregister.

    :func:`promote_legacy_account` is already best-effort and swallows every
    realistic failure itself. The broad guard here is for the two things it
    cannot promise a *detached* caller: an unexpected exception has no caller
    to surface it to (it would land in ``threading``'s excepthook as a stray
    traceback), and a daemon worker torn down mid-interpreter-shutdown can
    raise from arbitrary places.
    """
    try:
        promote_legacy_account(storage_path)
    except BaseException as e:  # noqa: BLE001 — a detached worker must never escape
        logger.debug("Background legacy account promotion crashed for %s: %s", storage_path, e)
    finally:
        with _PROMOTION_LOCK:
            _PROMOTION_THREADS.discard(threading.current_thread())


def _drain_promotions(timeout: float) -> None:
    """Join every in-flight promotion worker, each bounded by ``timeout``."""
    with _PROMOTION_LOCK:
        workers = list(_PROMOTION_THREADS)
    for worker in workers:
        worker.join(timeout)


def _drain_promotions_for_tests(timeout: float = 30.0) -> None:
    """Join every in-flight promotion worker (test/diagnostic helper).

    No production READ waits on this — the whole point of the one-shot is that
    the durable write never sits on the read path. Tests use it to make the
    durable half observable, and ``tests/conftest.py`` drains + clears the
    process-global state between tests so a worker started by one test cannot
    write into another's ``tmp_path``.
    """
    _drain_promotions(timeout)


#: PER-WORKER bound on the interpreter-exit wait, NOT an aggregate:
#: :func:`_drain_promotions` joins sequentially, so N legacy profiles wait up to
#: N times this. Workers are daemons, so a hung one is killed, not waited on.
_PROMOTION_EXIT_JOIN_SECONDS = 2.0


@atexit.register
def _drain_promotions_at_exit() -> None:
    """Let the detached promotion land before a short-lived process exits.

    Without this the one-shot is effectively dead in the CLI, which is where
    legacy profiles actually live. Measured on the first draft: a real
    ``notebooklm profile list`` against a legacy-only profile migrated it 0
    times out of 6, and ``auth check`` 1 out of 6 — a pure timing race that
    real commands lose, because they read the account binding at the very end
    of their work and the process exits before a daemon worker gets scheduled.
    The READ was correct every time; what silently never happened was the
    durable promotion and, with it, the privacy scrub that removes a stale
    account email from ``context.json`` at rest.

    ``atexit`` handlers run BEFORE daemon threads are torn down, so joining
    here is what makes the write land. It is bounded and best-effort: a
    hard-killed process, ``os._exit`` or a fatal signal skips it, and the next
    read schedules a fresh one-shot — the promotion is idempotent.

    Registration moved modules with the code (ADR-0033 PR 5.2) and that is
    safe by construction, not by luck: the hook is registered at import time of
    whichever module DEFINES :func:`read_account_metadata`, and every entry path
    that can schedule a promotion must first import that module in order to call
    the read at all. The hazard would be an alias — a shim that re-exports the
    read from a module the hook does NOT live in — so there is none.
    """
    _drain_promotions(_PROMOTION_EXIT_JOIN_SECONDS)


def _sanitize_legacy_account_record(legacy: dict[str, Any]) -> dict[str, Any]:
    """Normalize a raw legacy ``context.json[account]`` dict into the exact
    record :func:`promote_legacy_account` embeds in-band.

    This is the anti-wrong-account contract's load-bearing piece, and the
    reason it is ONE function rather than two agreeing implementations:
    :func:`read_account_metadata` returns this on a legacy-only profile
    *before* (and, if promotion never lands, instead of) the durable write, so
    "derived read-only" and "read back after promotion" must be
    indistinguishable field-for-field. Keeping it shared makes them so by
    construction; ``tests/unit/test_auth_account_promotion.py`` proves it over
    a matrix of malformed legacy shapes. Mirrors ``get_authuser_for_storage`` /
    ``get_account_email_for_storage``'s own sanitization rules."""
    raw_authuser = legacy.get("authuser")
    result: dict[str, Any] = {
        "authuser": raw_authuser if type(raw_authuser) is int and raw_authuser >= 0 else 0
    }
    raw_email = legacy.get("email")
    if isinstance(raw_email, str) and raw_email.strip():
        result["email"] = raw_email.strip()
    return result


def promote_legacy_account(storage_path: Path) -> bool:
    """One-shot migration: move a legacy sibling ``account`` record in-band.

    The pre-v0.5.0 two-file layout stored account metadata (``authuser`` /
    ``email``) in the sibling ``context.json``. This helper promotes that
    record into ``storage_state.json`` via the canonical storage writer and
    strips the legacy key.

    **Never called on a read's own thread.** Its three callers are the
    detached one-shot worker :func:`_run_promotion_once` (scheduled by
    :func:`read_account_metadata`), the startup layout migration
    (``migration.py``, which only fires for pre-v0.5.0 two-file profiles), and
    :func:`replace_from_login`'s ``KEEP_ACCOUNT``-with-no-in-band-record
    arm, where promoting instead of scrubbing is what stops
    ``auth import-cookies`` from permanently destroying a legacy profile's only
    copy of its binding. The read's correctness does not depend on any of them:
    it derives the same record read-only (:func:`_sanitize_legacy_account_record`)
    and this function only makes that durable.

    Ordering is crash-safe for the BINDING (never lost), not for the RESIDUE
    (not guaranteed promptly cleaned up). **Two files, two locks, no shared
    critical section** — the window is structural, not an oversight:

    * step 1 embeds into ``storage_state.json`` under the dotted storage
      sentinel ``.storage_state.json.lock`` (:func:`_file_lock`, via
      :func:`update_account_metadata`);
    * step 2 strips ``context.json[account]`` under the *separate*
      ``context.json.lock`` (``filelock.FileLock``, via
      :func:`_drop_legacy_account_key`).

    Nothing spans both, and nothing may: the two files are locked by two
    different sentinels held by two different mechanisms, and widening either
    hold to cover the other step would either invert an existing lock order or
    unify mechanisms (ADR-0033 plan §1/§5 rules both out). The compensation is
    therefore *ordering*, not atomicity: embed-then-strip means a crash in
    between leaves both records present, never neither — the account binding is
    never lost, which is the correctness property this function exists for. The
    reverse order would have a window in which the binding exists nowhere.

    What that compensation does NOT buy is prompt cleanup. The NEXT call does
    NOT reliably take a strip-only branch: :func:`read_account_metadata`'s
    fast path (``if in_band: return in_band``) returns as soon as in-band is
    present and never calls this function again (and the one-shot would not
    schedule a second worker for that path even if it did), so a
    crash-mid-flight residue can survive indefinitely rather than being cleaned
    up on the very next read. This is a privacy nicety, not a correctness gap
    (the authoritative binding is the in-band record, already committed) — it
    is NOT worth a ``context.json`` existence probe on every read's fast path
    to close eagerly. A subsequent :func:`write_account_metadata` /
    :func:`clear_account_metadata` call for the same profile does still strip it
    (both call :func:`_drop_legacy_account_key` unconditionally).

    When the in-band record already exists for another reason — including a
    CONCURRENT fresh login/account-switch that won a race against THIS call
    (see ``only_if_absent`` below) — any stale legacy key IS stripped
    immediately as residue cleanup (privacy: the old account email must not
    live on at rest after a re-login); that path runs through this function,
    not through the fast path above.

    Race-safe: the write is issued with ``only_if_absent=True``, so the
    decision "is in-band still empty" is made under the SAME lock as the
    write, not by a separate unlocked check beforehand. Without that, a
    concurrent fresh login could commit its new record in the gap between
    this function's own (now-removed) unlocked check and its locked write,
    and this call would silently overwrite it with the stale legacy values
    it had already captured — reintroducing the wrong-account hazard this
    whole migration exists to close, via a race instead of a stale read.

    Best-effort by design — it must degrade to the pre-promotion state rather
    than raise, both because ``migration.py`` and :func:`replace_from_login`
    treat it as a completeness step and because its detached worker has no
    caller to report to. Returns ``True`` only when a legacy record was embedded
    by THIS call (``False`` both when there was nothing to promote and when a
    concurrent writer won the race — either way no action was needed from this
    call).

    Never creates ``storage_state.json``: if it doesn't exist yet, promotion
    is skipped (returning ``False``) rather than synthesizing a cookie-less
    file to embed into. Without this guard, a plain READ (``profile list``,
    ``auth check``) on a legacy profile whose cookies had never been captured
    (or had been removed, e.g. by the ``COOKIE_VALIDATION_FAILED`` not-exists
    contract) would itself CREATE a persistent ``storage_state.json`` with no
    cookies at all — and ``_app/profile.py``'s ``authenticated=storage.exists()``
    check runs immediately after calling this (transitively, via
    :func:`read_account_metadata`), so it would flip from correctly reporting
    "not authenticated" to incorrectly reporting "authenticated" for a profile
    with zero cookies, purely as a side effect of having been looked at.

    Args:
        storage_path: Path to ``storage_state.json`` (must be a real file
            path — env-auth profiles have no sibling and are skipped by the
            caller).
    """
    if not storage_path.exists():
        return False
    legacy = _read_legacy_account(storage_path)
    if not legacy:
        return False
    sanitized = _sanitize_legacy_account_record(legacy)
    try:
        # only_if_absent=True: the decision "should this write happen" is made
        # HERE, under the writer's own lock, not by a separate unlocked
        # _read_in_band_account check beforehand — a check-then-act split
        # would let a concurrent fresh login/account-switch land in the gap
        # and then be silently overwritten by these stale legacy values.
        #
        # No deadline override: the usual 90s full-file-RMW deadline applies.
        # It used to be shortened to 2s because this ran INSIDE
        # read_account_metadata, where a 90s lock wait would freeze an event
        # loop mid-"read". It no longer does (ADR-0033 PR 5.1) — the caller is
        # a detached worker with nobody waiting on it, and waiting out real
        # contention is strictly better than giving up, because the one-shot
        # never retries in this process.
        promoted = update_account_metadata(
            storage_path,
            authuser=sanitized["authuser"],
            email=sanitized.get("email"),
            only_if_absent=True,
        )
    except Exception as e:  # noqa: BLE001 — promotion must never raise at its callers
        # Plain WARNING, no per-path throttle: a persistent cause (read-only
        # profile dir, full disk) leaves the profile un-migrated, so an
        # operator needs a default-visible signal rather than one gated behind
        # -v/--debug. The throttle this replaced existed because promotion ran
        # on the per-RPC read path and would otherwise have warned twice per
        # request forever; the one-shot makes that structurally impossible —
        # a read schedules at most ONE promotion per path per process, so this
        # branch can fire at most once per path from the read path (plus at
        # most one each from startup migration and replace_from_login).
        logger.warning("Legacy account promotion failed for %s: %s", storage_path, e)
        return False
    # Reached whether we promoted or lost a race to a concurrent writer —
    # either way in-band now holds a real record, so the legacy residue is
    # safe (and, for privacy, necessary) to scrub. _drop_legacy_account_key
    # already swallows every realistic failure internally (OSError family,
    # including filelock.Timeout — a TimeoutError/OSError subclass — and
    # JSONDecodeError), but this call is NOT inside the try/except above, and
    # read_account_metadata calls this function with no try/except of its
    # own, trusting it never to raise. Wrap defensively anyway: an embed that
    # already committed must not be erased by an unexpected exception in an
    # unrelated cosmetic cleanup step — that would violate this function's
    # own "never break the read" contract for a reason that has nothing to do
    # with the embed's success.
    try:
        _drop_legacy_account_key(storage_path)
    except Exception as e:  # noqa: BLE001 — cosmetic cleanup must not undo a committed embed
        logger.warning("Legacy account context cleanup failed for %s: %s", storage_path, e)
    if promoted:
        logger.info("Promoted legacy account metadata in-band for %s", storage_path)
    return promoted


def get_authuser_for_storage(storage_path: Path | None) -> int:
    """Return the ``authuser`` index recorded for a profile, defaulting to 0.

    Profiles without account metadata (legacy single-account installs and
    fresh logins that never set an authuser) are treated as ``authuser=0``,
    preserving existing behavior.

    Returns:
        Non-negative ``authuser`` index. Malformed values fall back to 0.
    """
    raw = read_account_metadata(storage_path).get("authuser")
    if isinstance(raw, int) and raw >= 0:
        return raw
    return 0


def get_account_email_for_storage(storage_path: Path | None) -> str | None:
    """Return the persisted account email for stable routing, if available."""
    raw = read_account_metadata(storage_path).get("email")
    if isinstance(raw, str):
        email = raw.strip()
        if email:
            return email
    return None


def resolve_account_identity(
    *,
    has_env_auth: bool,
    storage_path: Path | None = None,
    env_auth_storage_state: Any = None,
) -> dict[str, Any]:
    """Resolve the persisted ``{email, authuser}`` identity for a profile.

    Consolidates a sanitization recipe that used to be duplicated verbatim at
    ``cli/auth_runtime.py::get_auth_tokens`` and ``_app/auth_check.py::_account_info``
    (auth cross-boundary ledger shrink, follow-up to #2103): both callers read the
    in-band account record then apply the identical authuser/email cleanup — an
    ``int`` authuser clamped to ``>= 0`` (default 0; ``bool`` excluded since it is
    an ``int`` subclass), and an email stripped-or-``None``.

    The two callers differ only in WHERE the record comes from, not in what they
    do with it: env-var auth carries no profile directory, so the caller must pass
    its own already-parsed ``env_auth_storage_state`` (``_app/`` never reads
    ``os.environ`` directly, and ``cli/auth_runtime.py`` already has the CLI's
    consolidated ``read_env_auth_json()`` payload in hand by the time it gets
    here); file-based auth resolves straight from ``storage_path`` via
    :func:`read_account_metadata`.
    """
    if has_env_auth:
        meta = read_account_metadata_from_storage_state(env_auth_storage_state)
    else:
        meta = read_account_metadata(storage_path)
    raw_email = meta.get("email")
    email = raw_email.strip() if isinstance(raw_email, str) else ""
    raw_authuser = meta.get("authuser")
    authuser = raw_authuser if type(raw_authuser) is int and raw_authuser >= 0 else 0
    return {"email": email or None, "authuser": authuser}


def _drop_legacy_account_key(storage_path: Path) -> None:
    """Scrub the legacy ``account`` key from the sibling ``context.json``.

    Preserves all other CLI context state (``notebook_id``,
    ``conversation_id``, …). Best-effort: a failure here does not abort the
    in-band write. Since the legacy READ path was removed (the reader is
    in-band-only; :func:`promote_legacy_account` owns the migration), this
    survives purely as a privacy scrub — a stale legacy key would leave the
    account email at rest forever with no reader and no writer to remove it.
    Called by :func:`write_account_metadata` / :func:`clear_account_metadata` /
    :func:`promote_legacy_account` / :func:`replace_from_login` (the CLI login
    writer, after its own atomic write).

    This is the one writer in this module that does NOT touch
    ``storage_state.json``: it writes the SIBLING ``context.json``, so it goes
    through the guarded public ``atomic_write_json`` and the sibling
    ``context.json.lock`` (``filelock``) — never the storage sentinel, never the
    ``_write_state_unchecked`` bypass. Its lock mechanism is deliberately NOT
    unified with :func:`_file_lock` (ADR-0033 plan §5: that is a cross-version
    interop change, explicitly deferred).
    """
    context_path = _account_context_path(storage_path)
    if not context_path.exists():
        return
    lock_path = context_path.with_suffix(context_path.suffix + ".lock")
    try:
        with FileLock(str(lock_path), timeout=10.0):
            if not context_path.exists():
                return
            try:
                data = json.loads(context_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as e:
                logger.debug("legacy account-key cleanup skipped at %s: %s", context_path, e)
                return
            if not isinstance(data, dict) or _ACCOUNT_CONTEXT_KEY not in data:
                return
            del data[_ACCOUNT_CONTEXT_KEY]
            if data:
                atomic_write_json(context_path, data)
            else:
                context_path.unlink()
    except OSError as e:
        # Best-effort migration; the in-band reader wins.
        logger.debug("legacy account-key cleanup failed at %s: %s", context_path, e)


def write_account_metadata(storage_path: Path, *, authuser: int, email: str | None = None) -> None:
    """Persist account metadata atomically inside ``storage_state.json``.

    The account record lands under the ``notebooklm`` namespace key so the
    (cookies, account) pair commits together via a single
    :func:`atomic_write_json`. An external reader observing the file
    mid-update sees either the fully-old or fully-new commit — never a mix.

    The legacy sibling ``context.json[account]`` is best-effort cleaned up
    after the in-band write succeeds. CLI context state in the same file
    (``notebook_id`` / ``conversation_id``) is preserved.

    This is the ``notebooklm.auth``-exported facade symbol; it keeps its
    raise-on-lock-failure semantics (:func:`update_account_metadata` raises
    :class:`LockUnavailableError` — the documented replacement for the former
    ``filelock.Timeout``).

    Args:
        storage_path: Path to ``storage_state.json``. The file is created
            with empty ``cookies`` / ``origins`` arrays if missing — matching
            the previous semantics of "writing account metadata never fails
            because cookies haven't been written yet."
        authuser: ``authuser`` index used when extracting cookies for this
            profile (0 for the default account).
        email: Optional account email to record alongside the index.
    """
    update_account_metadata(storage_path, authuser=authuser, email=email)

    # Best-effort: drop the legacy account key from sibling context.json so
    # the next reader doesn't see the same data in two places.
    _drop_legacy_account_key(storage_path)


def _load_storage_state_for_write(storage_path: Path) -> dict[str, Any]:
    """Read ``storage_state.json`` for a read-modify-write under the lock.

    Returns a synthetic empty document if the file is missing — matches
    the earlier behavior where account writes never failed just because the
    cookie file hadn't been written yet. Corruption is fatal because the
    primary cookie data can't be recovered from account metadata; surface
    a ``RuntimeError`` so the caller can prompt the user to re-run login.
    """
    if not storage_path.exists():
        return {"cookies": [], "origins": []}
    try:
        loaded = json.loads(storage_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"storage state at {storage_path} is corrupted: {e}") from e
    if not isinstance(loaded, dict):
        raise RuntimeError(
            f"storage state at {storage_path} has unexpected shape: {type(loaded).__name__}"
        )
    return loaded


def clear_account_metadata(storage_path: Path | None) -> None:
    """Remove account metadata from both in-band and legacy locations.

    Two documents, two locks, in that order: the in-band record under the
    canonical storage lock (:func:`clear_in_band_account`), then the legacy
    sibling under its own ``context.json.lock``
    (:func:`_drop_legacy_account_key`).
    """
    if storage_path is None:
        return
    # 1. Strip the in-band record from ``storage_state.json``.
    clear_in_band_account(storage_path)
    # 2. Strip the legacy sibling record too (back-compat with old installs).
    _drop_legacy_account_key(storage_path)


# --- Write-time cookie-domain filter (relocated from ``_browser_cookie_filter.py``) ---
#
# ADR-0033. This is write-time policy, not browser code: three of its SIX call
# sites are the intent writers immediately below (``replace_from_remint``,
# ``replace_from_login``, ``persist_minted_jar``), which is why it now lives
# beside them instead of behind a ``browser_``-prefixed leaf. The other three:
# the two capture arms in :mod:`notebooklm._auth.browser_capture`, which
# re-export these names and filter BEFORE their in-memory PSIDTS heal (see the
# comments there for why that pass is NOT the writer's pass repeated); and
# ``cli/_cookie_import.py``, which reaches this function through the
# ``playwright_login`` re-export and filters immediately before persisting —
# itself a write path, so it strengthens rather than dilutes the thesis.
#
# Logger note (ADR-0030 c-PR5): the dropped-cookie / malformed-row warnings below
# must reach the documented ``notebooklm.auth`` namespace operators subscribe to,
# never a private per-module child. That holds here for free — this module's
# ``logger`` is ``logging.getLogger("notebooklm.auth")`` by NAME, not ``__name__``
# (see the top of the file), which is the same logger the donor module bound.


def _safe_cookie_shape(cookie: dict[str, Any]) -> str:
    """A VALUE-FREE structural summary of a cookie dict, safe to log.

    Returns the sorted key set plus the Python type of each field — but NEVER
    any field *value*. A cookie ``value`` is a live credential (and, on the CDP
    arm, comes straight from the operator's running browser), so the
    malformed-row warnings must not echo the row. Example output:
    ``keys=['domain', 'name', 'value'] types={domain: int, name: str, value: str}``.

    Iterates ``items()`` (sorted by the string form of each key) rather than
    re-subscripting by a stringified key, so a malformed cookie with a non-str
    key (e.g. an ``int``) cannot raise ``KeyError`` here — this helper exists to
    describe malformed rows, so it must itself never choke on one.
    """
    sorted_items = sorted(cookie.items(), key=lambda item: str(item[0]))
    keys = [str(k) for k, _ in sorted_items]
    types = ", ".join(f"{k}: {type(v).__name__}" for k, v in sorted_items)
    return f"keys={keys} types={{{types}}}"


#: ``CookieRowError.field`` -> the bounded warning the filter emits for it.
#: The *checks* live in :func:`notebooklm._auth.cookie_semantics.sanitize_cookie_entry`
#: (the one row-shape predicate); only the failure mode is local. Every message
#: takes exactly one ``%s`` — the value-free shape from :func:`_safe_cookie_shape`.
_MALFORMED_ROW_WARNINGS: dict[str, str] = {
    "name": "Skipping storage_state cookie with missing/empty/non-str name (%s)",
    "domain": "Skipping storage_state cookie with non-str domain (%s)",
    "path": "Skipping storage_state cookie with non-str path (%s)",
    "expires": "Skipping storage_state cookie with unusable expires (%s)",
}


def _report_malformed_row(cookie: Any, exc: _cookie_semantics.CookieRowError) -> None:
    """Log one bounded, value-free warning for a row the predicate rejected.

    ``exc.field == "row"`` means the entry is not a dict at all, so
    :func:`_safe_cookie_shape` cannot describe it — log the Python type instead.
    Never log the row itself: a cookie ``value`` is a live credential and, on the
    CDP arm, comes straight from the operator's running browser.

    An absent or empty-string ``domain`` is dropped **silently**: such a row is
    never on the allowlist, and a warning here would be new noise on every
    domain-less row a browser exports.

    Be precise about what changed, because the obvious reading is wrong. Before
    the shared predicate, ``domain`` was checked for ``isinstance(str)`` only and
    LAST, so a domain-less row fell through to the ``name`` / ``path`` /
    ``expires`` checks and could still warn about one of those. The shared
    predicate rejects an empty ``domain`` up front, so this branch now also
    swallows the ``expires`` diagnostic such a row used to get. Rows dropped are
    identical either way; only the diagnostic is quieter. A row malformed in BOTH
    ``name`` and ``domain`` now reports the name defect rather than the domain
    defect, because the shared predicate iterates ``(name, domain)`` in that
    order.
    """
    if exc.field == "row":
        logger.warning(
            "Skipping malformed storage_state cookie entry (not a dict): type=%s",
            type(cookie).__name__,
        )
        return
    if exc.field == "domain" and isinstance(cookie.get("domain", ""), str):
        return
    message = _MALFORMED_ROW_WARNINGS.get(exc.field, "Skipping malformed storage_state cookie (%s)")
    logger.warning(message, _safe_cookie_shape(cookie))


def filter_storage_state_cookies_by_domain_policy(
    state: dict[str, Any],
    *,
    include_optional: bool = False,
    include_domains: set[str] | None = None,
) -> dict[str, Any]:
    """Filter a Playwright ``storage_state`` dict to the configured cookie-domain policy.

    The Playwright login flow captures every cookie the browser context holds.
    Without this filter, unrelated non-Google cookies and origin storage from
    the user's browser context can leak into the persisted
    ``storage_state.json`` and inflate the blast radius. This applies the
    shared allowlist
    (:func:`notebooklm._auth.cookie_policy.build_cookie_domain_allowlist`, the
    same set the rookiepy extraction request is built from) at write time; the
    rookiepy/Firefox persist path (``_write_extracted_cookies`` /
    ``_login_with_browser_cookies``) runs this same filter before its atomic
    write — the Firefox extractor suffix-matches dot-prefixed domains, so
    extraction-time narrowing alone is not enough — so both login paths
    produce equivalent on-disk state. Distinct optional roots remain opt-in
    via ``--include-domains=...``.
    Exact allowlist entries use leading-dot/no-dot equivalence
    (``http.cookiejar`` may normalize either). In addition, trusted Google
    roots use boundary-aware suffix matching. This compatibility-first rule
    preserves unknown ``*.google.com``, ``*.googleusercontent.com``, and
    regional Google subdomains until they can be narrowed with live-flow
    evidence, while still rejecting lookalikes such as ``evilgoogle.com``.

    Two hardening behaviors (#1513) ride on top of the allowlist:

    * **Malformed rows are skipped, not raised.** rookiepy / Playwright can
      emit malformed rows; a non-dict entry, a cookie whose ``domain`` is not
      a str, or a cookie whose ``name`` is not a non-empty str (all malformed
      under Playwright's own ``storage_state`` schema) is dropped with one
      bounded ``logger.warning`` per row instead of crashing the whole persist.
      The warning logs only a **value-free shape** (:func:`_safe_cookie_shape`:
      the row's keys + per-field types) — never the row itself — so a cookie
      ``value`` (a live credential, and for the CDP arm one that comes straight
      from the operator's running browser) cannot leak into the logs.
    * **Exact-identity duplicate dedup.** Rows are keyed by their full
      RFC 6265 identity ``(name, domain, path)`` (path normalized via
      ``or "/"``, matching every loader). For exact-identity duplicates —
      where only metadata such as ``value`` / ``expires`` / flags can differ —
      the **last occurrence in input order wins** and replaces the earlier row
      in place, kept whole (fields are never merged). This mirrors the
      persistence-merge rule in :func:`save_cookies_to_storage` (this module),
      where the newer observation overwrites the stored row for the same
      ``(name, domain, path)`` key.

      Same-name rows on *different* domains or paths are deliberately ALL
      kept: cross-domain same-name resolution is a **load-time** concern (the
      flat loaders :func:`notebooklm._auth.cookies.extract_cookies_from_storage`
      / :func:`notebooklm._auth.cookies.flatten_cookie_map` rank by
      ``_auth_domain_priority``). Deduping by bare name at write time would
      starve the ``(name, domain, path)``-keyed runtime loader
      (:func:`notebooklm._auth.cookies.build_httpx_cookies_from_storage`),
      which legitimately holds e.g. the per-product ``OSID`` cookie on
      ``notebooklm.google.com`` and ``myaccount.google.com`` as distinct
      jar entries.

    Args:
        state: Playwright ``storage_state`` dict (``BrowserContext.storage_state()``).
        include_optional: When ``True``, opt in to every label in
            :data:`notebooklm._auth.cookie_policy.OPTIONAL_COOKIE_DOMAINS_BY_LABEL`.
        include_domains: Optional-domain labels to opt in (``"all"`` = every
            label). Mirrors the rookiepy path semantics.

    Returns:
        A new ``storage_state`` dict with ``cookies`` filtered and ``origins``
        cleared. Origin localStorage / IndexedDB is not used for cookie auth
        and must not bypass the domain policy. The input dict is not mutated.
    """
    allowed_list = _cookie_policy.build_cookie_domain_allowlist(
        include_optional=include_optional, include_domains=include_domains
    )
    allowed: frozenset[str] = frozenset(allowed_list)
    allowed_stripped: frozenset[str] = frozenset(d.lstrip(".").lower() for d in allowed_list)

    def _is_allowed(domain: str) -> bool:
        normalized = domain[1:] if domain.startswith(".") else domain
        return (
            domain in allowed
            or normalized.lower() in allowed_stripped
            or _cookie_policy._is_trusted_google_cookie_domain(domain)
        )

    filtered_cookies: list[dict[str, Any]] = []
    index_by_identity: dict[tuple[str, str, Any], int] = {}

    for cookie in state.get("cookies", []):
        # ONE row-shape predicate, shared with every loader (ADR-0033 PR 2.1).
        # It rejects a non-dict entry, a missing/empty/non-str ``name`` or
        # ``domain``, a present-but-non-str ``path`` (which would slip past the
        # ``or "/"`` normalization below and later crash http.cookiejar/httpx
        # path matching), and an ``expires`` that cannot be normalized — the
        # last one because every loader that rebuilds the row goes through
        # ``int(float(expires))`` inside ``http.cookiejar.Cookie``, so dropping
        # it at capture time keeps the persisted state loadable instead of
        # deferring the failure to the first authed call (#2061).
        #
        # ``check_value=False``: this filter is domain policy, not a request
        # jar. It has never inspected ``value`` and must not start — a row's
        # value is a credential it only ever copies through.
        try:
            normalized = _cookie_semantics.sanitize_cookie_entry(cookie, check_value=False)
        except _cookie_semantics.CookieRowError as exc:
            _report_malformed_row(cookie, exc)
            continue
        name = normalized["name"]
        domain = normalized["domain"]
        if not _is_allowed(domain):
            continue

        # Full RFC 6265 identity. The predicate's ``path or "/"`` normalization
        # mirrors the loaders and the save_cookies_to_storage merge key, so an
        # empty-path twin can't survive as a phantom duplicate row.
        identity = (name, domain, normalized["path"])
        existing = index_by_identity.get(identity)
        if existing is None:
            index_by_identity[identity] = len(filtered_cookies)
            filtered_cookies.append(cookie)
        else:
            # Exact-identity duplicate: the later observation wins whole,
            # replacing the earlier row in place — mirroring the
            # save_cookies_to_storage merge, where the newer observation
            # overwrites the stored row for the same (name, domain, path) key.
            logger.debug(
                "Cookie %s: exact-identity duplicate on (%s, %s); keeping later observation",
                name,
                domain,
                identity[2],
            )
            filtered_cookies[existing] = cookie

    return {
        "cookies": filtered_cookies,
        "origins": [],
    }


# --- Browser-capture re-mint (relocated from ``browser_capture.py``) --------


def replace_from_remint(
    path: Path,
    captured_state: dict[str, Any],
    *,
    carry_account: bool,
    include_domains: set[str] | None = None,
) -> WriteOutcome:
    """Full cookie replace for a browser-capture re-mint, under the storage lock.

    The single sanctioned persist for the :mod:`notebooklm._auth.browser_capture`
    arms (interactive login, L3 headless-launch re-auth, CDP re-auth). Replaces
    ``storage_state.json``'s cookies with ``captured_state`` — a re-mint is a
    brand-new session, so cookies are *replaced*, never merged. Full-file replace
    intent: **fails closed**, returning ``WriteOutcome(lock_unavailable)`` on lock
    unavailability so the capture caller can surface/retry rather than race a
    concurrent keepalive write ([capture-2]).

    Everything below happens **inside** the canonical storage lock:

    * The write-time domain filter
      (:func:`filter_storage_state_cookies_by_domain_policy`) is applied so
      sibling-product cookies never reach disk. ``include_domains`` carries the
      interactive ``--include-domains`` opt-in through unchanged; the default
      policy preserves trusted Google roots (``*.googleusercontent.com`` / Drive
      etc.), matching main's preserve-trusted-roots behavior. **This pass is
      ADR-0029's entry-path-independent guarantee**, not a repeat of the capture
      arms' filter call: it is what makes "nothing sibling-product ever reaches
      ``storage_state.json``" true for EVERY caller of this writer, including
      ones that never filtered. The capture arms filter for a different reason
      (their pass feeds ``heal_captured_state``; see
      :mod:`notebooklm._auth.browser_capture`) — neither pass substitutes for the
      other and neither may be deleted. Being idempotent, this pass simply does
      not narrow a caller that already filtered with the same ``include_domains``.
    * Account namespace handling branches on ``carry_account``:

      - ``carry_account=True`` (unattended profile-launch arm): the existing
        ``notebooklm`` namespace is read from the current file and CARRIED OVER
        into the new state, so an in-place re-mint against our own profile no
        longer destroys the account binding ([capture-1]).
      - ``carry_account=False`` (interactive arm, and the CDP no-resolve
        fallback): the stale binding is DROPPED — the user may have signed into a
        different account. On the INTERACTIVE login arm the CLI adapter's
        ``repair_playwright_account_metadata`` re-establishes it immediately
        after the write. On the library / mid-RPC CDP arm there is NO such
        repair, so it lands on the authuser=0 default (repair happens only via
        CLI ``auth refresh``); carrying a stale index blindly would instead
        relocate [capture-1], so authuser=0 is the deliberate safe fallback.

    CDP arm caveat: CDP attaches to the operator's daily Chrome, whose account
    set may not match the stored binding. The CALLER re-resolves the stored email
    against the captured jar (any network lookup happens OUTSIDE this held lock)
    and passes the verdict as ``carry_account``; on no-resolve it passes
    ``carry_account=False`` rather than carry a possibly-misrouting index.

    Args:
        path: Destination ``storage_state.json``.
        captured_state: The (already healed) captured storage-state dict.
        carry_account: Whether to carry the existing account namespace forward.
        include_domains: Optional ``--include-domains`` opt-in labels, applied by
            the internal filter (mirrors the capture caller's filter call).

    Returns:
        :class:`WriteOutcome` — ``ok`` on success, ``lock_unavailable`` if the
        bounded storage-lock acquire timed out / the lock infra failed.
    """

    def _replace() -> WriteOutcome:
        # Carry the existing account namespace BEFORE overwriting (read under the
        # same lock so it can't tear against a concurrent writer).
        carried_namespace: dict[str, Any] | None = None
        if carry_account and path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                existing = None
            if isinstance(existing, dict):
                namespace = existing.get(_STORAGE_NAMESPACE_KEY)
                if isinstance(namespace, dict):
                    carried_namespace = namespace

        # Write-time domain filter (preserve-trusted-roots). Returns a fresh
        # ``{"cookies": [...], "origins": []}`` — the captured browser state
        # never carries our ``notebooklm`` namespace, so it is only (re)attached
        # from the carried value below.
        filtered = filter_storage_state_cookies_by_domain_policy(
            dict(captured_state), include_domains=include_domains
        )
        if carried_namespace is not None:
            filtered[_STORAGE_NAMESPACE_KEY] = carried_namespace
        _write_state_unchecked(path, filtered)
        return WriteOutcome(WriteStatus.OK)

    # MUST-KNOW via RETURN VALUE, not exception: ``WriteOutcome`` has a distinct
    # ``LOCK_UNAVAILABLE`` status, and the capture callers branch on it. Using
    # ``raise_on_lock_unavailable`` here would turn fail-closed-by-return into
    # fail-closed-by-raise — a breaking change for every caller of this writer.
    outcome: WriteOutcome = in_storage_transaction(
        path,
        _replace,
        log_prefix="replace_from_remint",
        on_unavailable=report_on_lock_unavailable(WriteOutcome(WriteStatus.LOCK_UNAVAILABLE)),
    )
    return outcome


# --- Login / import full-replace -------------------------------------------
# Hoisted from the CLI ``cli/services/login`` and ``cli/_cookie_import``
# writers — the #2086 filter + revalidation moved HERE.


def replace_from_login(
    path: Path,
    state: dict[str, Any],
    *,
    include_domains: set[str] | None,
    include_optional: bool = False,
    account: AccountArg = KEEP_ACCOUNT,
    backup: bool = False,
    io_policy: object | None = None,
) -> LoginWriteOutcome:
    """Full cookie replace for the CLI login / import flows, under the storage lock.

    The single sanctioned persist for ``notebooklm login --browser-cookies``,
    ``notebooklm auth refresh --browser-cookies``, and ``notebooklm auth
    import-cookies``. Replaces ``storage_state.json``'s cookies with ``state`` —
    a login is a brand-new session, so cookies are *replaced*, never merged.
    Everything below happens **inside** the canonical storage lock; the writer
    **fails closed** (``LoginWriteOutcome(lock_unavailable)``) so a caller can
    surface/retry rather than race a concurrent keepalive write.

    Under the lock, in order:

    1. **Write-time domain filter.** ``state``'s cookies are run through
       :func:`filter_storage_state_cookies_by_domain_policy` (hoisted from the
       #2086 CLI call sites) so sibling-product cookies never reach disk.
       ``include_domains`` / ``include_optional`` carry the CLI opt-ins through;
       the default policy preserves trusted Google roots
       (``*.googleusercontent.com`` / Drive) — main's preserve-trusted-roots
       behaviour. As in :func:`replace_from_remint`, this pass is ADR-0029's
       entry-path-independent guarantee — it holds for every login/import caller,
       filtered or not — and being idempotent it does not narrow a caller
       (import) that already pre-filtered with the same opts.
    2. **Post-filter required-cookie revalidation.** ``MINIMUM_REQUIRED_COOKIES``
       is re-checked on the FILTERED names. If a required cookie's only copy sat
       on a now-dropped domain, the writer returns
       ``LoginWriteOutcome(required_cookies_dropped, ...)`` and writes NOTHING —
       preserving #2086's contract (the CLI maps this to
       ``CookieValidationFailure(code="COOKIE_VALIDATION_FAILED")`` + ``io.fail(1)``
       + ``not storage_path.exists()``). Both ``missing_required`` and
       ``present_names`` are value-free cookie NAMES.
    3. **Account metadata**, embedded in the same atomic write via the ``account``
       sentinel:

       - :data:`KEEP_ACCOUNT` (default; the import flavour) — carry whatever
         ``state`` already holds in the ``notebooklm`` namespace (import has none,
         so the result carries none). No account key is synthesised.
       - :data:`CLEAR_ACCOUNT` (the refresh default-account login branch) — no
         account binding is written, so stale routing cannot survive.
       - :class:`AccountRecord` (the targeted login branches) — the
         ``{authuser, email}`` binding is embedded, replacing the former separate
         ``write_account_metadata`` step (one atomic write, no partial-failure
         window).
    4. **Opt-in recording.** The resolved ``include_domains`` (and
       ``include_optional``) are recorded in the ``notebooklm`` namespace so a
       future merge-gate narrowing can consult per-profile opt-ins (plan §b.5);
       additive — old readers ignore unknown namespace keys.
    5. **Import backup.** When ``backup=True`` (the import flavour), a pre-overwrite
       ``.bak`` copy of any existing target is taken INSIDE the lock (0600 on
       POSIX) so it cannot race a concurrent keepalive write; its path is returned
       in the outcome.

    Args:
        path: Destination ``storage_state.json``.
        state: The captured / coerced storage-state dict to persist.
        include_domains: ``--include-domains`` opt-in labels (or ``None``).
        include_optional: Persist all optional sibling-product domains (the
            import-cookies flavour).
        account: Account-metadata action (see above).
        backup: Take a pre-overwrite ``.bak`` backup inside the lock (import).
        io_policy: Reserved for a future per-intent lock/IO policy override;
            currently unused (accepted for forward-compatible call sites).

    Returns:
        :class:`LoginWriteOutcome`.
    """
    del io_policy  # reserved; see docstring
    from .cookie_policy import (  # noqa: PLC0415 (deferred; true leaf, no cycle either way)
        MINIMUM_REQUIRED_COOKIES,
        cookie_names_from_storage,
    )

    # Hoisted out of ``_replace`` so the post-lock legacy-account step can read
    # it: that step branches on whether an account key was embedded, and the
    # writer's return value must stay the outcome the template propagates.
    namespace: dict[str, Any] = {}

    def _replace() -> LoginWriteOutcome:
        nonlocal namespace

        # (1) Write-time domain filter (preserve-trusted-roots). Returns a fresh
        # ``{"cookies": [...], "origins": []}`` — the browser/import state never
        # carries our ``notebooklm`` namespace.
        filtered = filter_storage_state_cookies_by_domain_policy(
            dict(state), include_optional=include_optional, include_domains=include_domains
        )

        # (2) Post-filter required-cookie revalidation on the FILTERED names.
        present = cookie_names_from_storage(filtered)
        missing_required = tuple(sorted(MINIMUM_REQUIRED_COOKIES.difference(present)))
        if missing_required:
            # Count-only breadcrumb — never cookie names or values.
            logger.debug(
                "replace_from_login: %d required cookie(s) dropped by the write-time "
                "domain policy for %s; writing nothing",
                len(missing_required),
                path,
            )
            return LoginWriteOutcome(
                LoginWriteStatus.REQUIRED_COOKIES_DROPPED,
                missing_required=missing_required,
                present_names=tuple(sorted(present)),
            )

        # (3) + (4) Build the ``notebooklm`` namespace (account + opt-ins).
        namespace = {}
        if account is KEEP_ACCOUNT:
            existing_ns = state.get(_STORAGE_NAMESPACE_KEY)
            if isinstance(existing_ns, dict):
                namespace = dict(existing_ns)
        elif isinstance(account, AccountRecord):
            payload: dict[str, Any] = {"authuser": account.authuser}
            if account.email:
                payload["email"] = account.email
            namespace[_ACCOUNT_CONTEXT_KEY] = payload
        # CLEAR_ACCOUNT: leave the account key absent.
        if include_domains:
            namespace["include_domains"] = sorted(include_domains)
        if include_optional:
            namespace["include_optional"] = True
        if namespace:
            namespace.setdefault("version", _STORAGE_NAMESPACE_VERSION)
            filtered[_STORAGE_NAMESPACE_KEY] = namespace

        # (5) Import backup, inside the lock, before overwriting.
        backup_path: Path | None = None
        if backup and path.exists():
            candidate = path.with_name(path.name + ".bak")
            shutil.copy2(path, candidate)
            # ``copy2`` preserves the SOURCE mode; force 0600 so a backup of a
            # legacy/world-readable storage_state never leaks credentials at rest.
            if sys.platform != "win32":
                with contextlib.suppress(OSError):
                    os.chmod(candidate, 0o600)
            backup_path = candidate

        _write_state_unchecked(path, filtered)
        return LoginWriteOutcome(LoginWriteStatus.OK, backup_path=backup_path)

    # MUST-KNOW via RETURN VALUE, not exception: ``LoginWriteOutcome`` has a
    # distinct ``LOCK_UNAVAILABLE`` status the CLI already branches on, so
    # ``raise_on_lock_unavailable`` here would be a breaking change.
    outcome: LoginWriteOutcome = in_storage_transaction(
        path,
        _replace,
        log_prefix="replace_from_login",
        on_unavailable=report_on_lock_unavailable(
            LoginWriteOutcome(LoginWriteStatus.LOCK_UNAVAILABLE)
        ),
    )
    # Both non-OK outcomes (lock unavailable, required cookies dropped) wrote
    # nothing, so neither reaches the legacy-account step below.
    if outcome.status is not LoginWriteStatus.OK:
        return outcome

    # Outside the storage lock (its own sibling ``.lock``, matching
    # ``write_account_metadata``'s ordering): the in-band write just committed
    # (or explicitly cleared) the account binding.
    #
    # KEEP_ACCOUNT (the import-cookies default) with NO existing in-band record
    # to carry is NOT an intentional "no account" decision — it means the caller
    # (typically a fresh browser/import jar with no ``notebooklm`` namespace of
    # its own) never considered the account question at all. Scrubbing the
    # legacy sibling unconditionally in that case PERMANENTLY DESTROYS a
    # pre-v0.5.0 profile's only copy of its account binding: nothing was
    # embedded in-band, and the legacy record is gone from disk with no reader
    # left to find it (verified: `auth import-cookies` on such a profile drops
    # authuser 3 -> 0 irrecoverably). Promote instead — it embeds a legacy
    # record if one exists (then scrubs it) and is a safe no-op otherwise.
    #
    # An EXPLICIT decision — CLEAR_ACCOUNT, or an AccountRecord that did embed —
    # must still scrub directly: CLEAR_ACCOUNT means the caller deliberately
    # wants no account bound, and promoting there would resurrect a binding
    # that was just intentionally cleared.
    if account is KEEP_ACCOUNT and _ACCOUNT_CONTEXT_KEY not in namespace:
        promote_legacy_account(path)
    else:
        _drop_legacy_account_key(path)
    return outcome


# --- Master-token writers (relocated from ``master_token.py``) --------------


def persist_minted_jar(
    path: Path,
    jar: httpx.Cookies,
    *,
    email: str | None,
    force: bool = False,
    refuse_unknown_owner: bool = True,
) -> None:
    """Replace the cookies in ``storage_state.json`` with a freshly-minted jar.

    Relocated from ``master_token.persist_minted_jar``, now routed through
    :func:`_write_state_unchecked` (fsync durability + temp cleanup, closing
    [storage-F5]) while keeping the storage lock it already held and its
    rebind-to-minted-account namespace semantics. Old cookies are *replaced*, not
    merged — a re-mint is a brand-new session. Full-file replace intent:
    **fails closed**.

    b-PR2 additionally applies the write-time domain filter
    (:func:`filter_storage_state_cookies_by_domain_policy`, default policy —
    preserve-trusted-roots) to the minted cookies before they reach disk, closing
    the L4 unfiltered-persist gap. The rebind to the minted account
    (``authuser=0`` + the minted ``email``) is unaffected: the filter only
    narrows the cookie rows, never the account namespace.

    #2103 PR-2 D6: the authoritative account-ownership guard lives HERE, under
    the storage-write lock this function already holds — not only in
    :func:`notebooklm._auth.master_token.assert_account_writable`'s pre-mint
    advisory check, which cannot see a caller that mints and persists directly
    (the documented low-level recipe does exactly that) and cannot close the
    TOCTOU window between a pre-check and this write. Existing storage bound to
    a DIFFERENT recorded email than ``email`` always raises
    :class:`notebooklm._auth.master_token.MasterTokenError` unless ``force``.
    No existing storage: proceeds unconditionally (nothing to protect yet).

    ``refuse_unknown_owner`` (default ``True``) additionally refuses existing
    storage with NO recorded owner at all, unless ``force``. Callers re-minting
    from a master token ALREADY paired with this exact ``storage_path`` (the
    L4 recovery rung, the no-prompt operator re-mint —
    :func:`notebooklm._auth.master_token.remint_from_stored_token`) pass
    ``refuse_unknown_owner=False``: that pairing was already trusted when the
    token was first bootstrapped for this profile, so an account-less
    profile (never bound to an ``--account``, e.g. a cookie-only
    ``import-cookies`` profile — empirically the COMMON case, not the "rare"
    one D6 originally assumed) must not lose mid-session self-recovery. A
    caller *selecting* an account for the first time
    (:func:`notebooklm._auth.master_token.bootstrap_from_oauth_token`) keeps
    the default: minting into an existing, unrecorded-owner profile is
    exactly the ambiguous case worth refusing without an explicit ``force``.
    """
    from . import (
        master_token as _master_token,
    )  # deferred; no cycle either way (verified)

    def _persist() -> None:
        data: dict[str, Any] = {}
        existed = path.exists()
        if existed:
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                data = loaded if isinstance(loaded, dict) else {}
            except json.JSONDecodeError:
                data = {}
        if existed and force:
            logger.debug("persist_minted_jar: force=True bypasses the account-ownership guard.")
        elif existed:
            existing_owner = read_account_metadata_from_storage_state(data).get("email")
            existing_owner = existing_owner.strip() if isinstance(existing_owner, str) else None
            if not existing_owner:
                if refuse_unknown_owner:
                    raise _master_token.MasterTokenError(
                        "This profile has no recorded account owner; refusing to overwrite "
                        "its session with a freshly minted one without force=True."
                    )
                logger.debug(
                    "persist_minted_jar: existing storage has no recorded owner; proceeding "
                    "with refuse_unknown_owner=False (re-mint from a token already paired "
                    "with this storage_path, not a fresh account selection)."
                )
            elif existing_owner.casefold() != (email or "").casefold():
                raise _master_token.MasterTokenError(
                    f"This profile already belongs to {existing_owner}, but the mint is "
                    f"for {email or '(no account)'}. Minting here would overwrite "
                    f"{existing_owner}'s session and master token. Pass force=True to "
                    "overwrite this profile intentionally."
                )
        # Apply the write-time domain filter to the minted jar (L4 gap): the
        # minted cookies were previously persisted raw. Default policy — trusted
        # Google roots are preserved (main's preserve-trusted-roots behavior).
        minted_state = _master_token.storage_state_from_jar(jar)
        filtered_minted = filter_storage_state_cookies_by_domain_policy(minted_state)
        data["cookies"] = filtered_minted["cookies"]
        data.setdefault("origins", [])
        ns_raw = data.get("notebooklm")
        ns: dict[str, Any] = ns_raw if isinstance(ns_raw, dict) else {}
        ns["version"] = 1
        ns["account"] = {"authuser": 0, **({"email": email} if email else {})}
        data["notebooklm"] = ns
        _write_state_unchecked(path, data)

    # MUST-KNOW via exception: the return type is ``None``, so there is no
    # channel to report into. ``raise_on_lock_unavailable`` formats the message
    # this writer raised when it hand-rolled the branch, verbatim; the #2108
    # ownership guard and its write ordering stay inside ``_persist``, untouched.
    in_storage_transaction(
        path,
        _persist,
        log_prefix="persist_minted_jar",
        on_unavailable=raise_on_lock_unavailable("persist_minted_jar"),
    )


def write_master_token(path: Path, *, email: str, master_token: str, android_id: str) -> None:
    """Persist a ``master_token.json`` record at mode 0600 (full-account credential).

    Relocated from ``master_token.write_master_token``, now routed through
    :func:`_write_state_unchecked` (atomic + fsync-durable + temp cleanup) and guarded
    by a bounded sibling ``.master_token.json.lock`` — it was previously lockless
    (part of [storage-F5]). RMW intent: **fails closed**.
    """
    from . import (
        master_token as _master_token,
    )  # deferred; no cycle either way (verified)

    payload = {
        "version": _master_token._MASTER_TOKEN_VERSION,
        "email": email,
        "android_id": android_id,
        "master_token": master_token,
    }

    def _write() -> None:
        _write_state_unchecked(path, payload)

    # The transaction template derives the sibling dotted lock for this
    # credential file (distinct from the profile's storage-state lock — a
    # different file) and ensures the parent dir is secure before taking it.
    in_storage_transaction(
        path,
        _write,
        log_prefix="write_master_token",
        on_unavailable=raise_on_lock_unavailable("write_master_token"),
    )
