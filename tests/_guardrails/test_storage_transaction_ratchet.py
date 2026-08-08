"""Shrink-only ratchet: storage writers take the lock via the transaction template.

ADR-0031 Stage 3. Six writers in ``_auth/storage.py`` USED TO each
hand-roll the same four-step preamble — secure the parent dir, derive the
sentinel lock path, take the bounded lock, branch on whether it was held.
:func:`~notebooklm._auth.storage.in_storage_transaction` now owns
those four steps. (Both the writers and the template lived in their own
cap-split modules until ADR-0033's persistence merge folded them into
``storage.py``; this gate now scans one file where it used to scan two.) **All six
route through it** as of ADR-0033 PR 1.2, which completed ADR-0031 Stage 3, so
:data:`_UNCONVERTED` is empty. The fourth step (the not-held branch) is supplied
by the caller because it genuinely differs three ways:

* **raise** ``LockUnavailableError`` — fail closed, where proceeding without the
  lock could lose a concurrent writer's commit;
* **skip** with a DEBUG log — best-effort, only where a miss degrades gracefully;
* **report** a typed outcome — and the two full-replace writers have *different*
  outcome types, so the value comes from the caller.

A template that picked one of those would be a silent semantic change in a
credential-write path, which is why the policy is a parameter and why this gate
checks *routing through the template*, not uniformity of behavior.

Migration was opportunistic per this repo's ratchet convention: the gate blocked
a NEW hand-rolled acquire and pinned the remaining ones so the list could only
shrink. It has now shrunk to nothing, so the gate is absolute — ANY function
hand-rolling the acquire is red, with no pre-approved exceptions left.
``merge_cookie_delta`` is exempt by design — it takes the BLOCKING
``storage._file_lock_exclusive`` rather than the bounded acquire, which is a
different operation, not a variant.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_lint

_AUTH = Path(__file__).resolve().parents[2] / "src" / "notebooklm" / "_auth"
#: ADR-0033's persistence merge folded ``storage_writer.py`` AND
#: ``storage_transaction.py`` into ``storage.py``, so the writers and the
#: template they route through are now scanned in the same file. The two former
#: modules survive only as re-export shims and define nothing.
_WRITER = _AUTH / "storage.py"
_TEMPLATE = _AUTH / "storage.py"

#: Excluded from the direct-call scan: ``in_storage_transaction`` IS the
#: template, so of course it calls ``_acquire_storage_lock``. Before the merge
#: that call was invisible to this gate because it crossed a module boundary
#: (a function-local ``from .storage_writer import _acquire_storage_lock``);
#: same-module now, it would otherwise read as the template hand-rolling the
#: very lock it exists to own.
_TEMPLATE_FUNCTIONS: frozenset[str] = frozenset({"in_storage_transaction"})


def test_template_exemption_is_frozen_and_real() -> None:
    """The blanket exemption must name exactly the template, and it must exist.

    Two holes this closes, both verified to slip otherwise: adding a NEW writer's
    name here would grant it a silent blanket exemption from the direct-call
    scan, and renaming :func:`in_storage_transaction` would leave a stale entry
    exempting nothing while the gate still reported green. Every other allowlist
    in this file and its sibling is equality-asserted for the same reason.
    """
    assert frozenset({"in_storage_transaction"}) == _TEMPLATE_FUNCTIONS
    defined = {
        node.name
        for node in ast.parse(_TEMPLATE.read_text("utf-8")).body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    missing = sorted(_TEMPLATE_FUNCTIONS - defined)
    assert missing == [], (
        f"exempted name(s) not defined in {_TEMPLATE.name}: {missing} — a rename "
        "left a stale blanket exemption"
    )


#: Functions still calling ``_acquire_storage_lock`` directly. SHRINK-ONLY —
#: never add. **Now empty.** The three writers #2152 held back from its bulk pass
#: converted in ADR-0033 PR 1.2, each proven behavior-identical against the
#: pre-conversion implementation rather than converted on the template's say-so,
#: because their bodies carry semantics the bulk pass would not have exercised:
#:   * ``replace_from_remint`` — the browser-capture re-mint, which carries or
#:     drops the account namespace under the same lock. Converted with
#:     ``report_on_lock_unavailable``, so its value-carrying
#:     ``WriteOutcome(lock_unavailable)`` contract is unchanged.
#:   * ``replace_from_login`` — the login/import full-replace, whose write-time
#:     domain filter and required-cookie revalidation run INSIDE the lock while
#:     its legacy-account promote/drop step runs OUTSIDE it. Converted with
#:     ``report_on_lock_unavailable`` for the same value-carrying reason; the
#:     in/out-of-lock split survives as an explicit post-transaction branch.
#:   * ``persist_minted_jar`` — the #2108 cross-account ownership guard and the
#:     write-ordering it depends on; sits on the client's own L4 recovery path.
#:     Converted with ``raise_on_lock_unavailable`` (its return type is ``None``,
#:     so there is no channel to report into), preserving the exception type and
#:     message verbatim — ``raise_on_lock_unavailable`` formats the identical
#:     string the writer used to build inline.
#:
#: Kept as an (empty) frozenset rather than deleted: it is what
#: :func:`test_no_new_hand_rolled_storage_lock` subtracts, so empty is the
#: STRONGEST form of this gate, not a vestige.
_UNCONVERTED: frozenset[str] = frozenset()


def test_unconverted_list_is_exhausted() -> None:
    """A drained list is not self-locking (ADR-0007's stays-empty precedent).

    Verified to matter: a function that genuinely hand-rolls the acquire, with
    its name re-added here, satisfies BOTH
    :func:`test_no_new_hand_rolled_storage_lock` (which *subtracts* this set)
    and :func:`test_unconverted_list_is_shrink_only` (which only rejects STALE
    entries). Re-adding a name would also manufacture the "``_UNCONVERTED``
    shrinks" evidence ADR-0033's third cap-lift class requires, so this gate is
    load-bearing for the ceiling policy too. A new writer converts; it does not
    get re-pinned.
    """
    assert frozenset() == _UNCONVERTED, (
        "_UNCONVERTED is exhausted (ADR-0033 template-adoption class) — a new "
        "hand-rolled acquire must route through in_storage_transaction, not be "
        f"re-listed: {sorted(_UNCONVERTED)}"
    )


#: The three not-held policies the template exposes.
_POLICIES: tuple[str, ...] = (
    "raise_on_lock_unavailable",
    "skip_on_lock_unavailable",
    "report_on_lock_unavailable",
)

#: The writers that use ``report_on_lock_unavailable`` — the only two whose
#: return type (``WriteOutcome`` / ``LoginWriteOutcome``) has room for a distinct
#: ``LOCK_UNAVAILABLE`` status. Every other writer returns ``None`` or a ``bool``
#: already spoken for, so it must raise instead. Both converted in PR 1.2, so the
#: caller-count assertion below is now live at its full expected value of two
#: rather than vacuously satisfied at zero.
_REPORT_POLICY_WRITERS: frozenset[str] = frozenset({"replace_from_login", "replace_from_remint"})


def _policy_call_counts() -> dict[str, int]:
    """Count real call sites of each policy across ``_auth/``.

    Definitions do not count — only ``<policy>(...)`` calls. Counting by AST
    rather than substring keeps a mention inside a docstring or an error
    message (this module puts the policy names in both) from reading as a use.
    """
    counts = dict.fromkeys(_POLICIES, 0)
    for source_file in sorted(_AUTH.glob("*.py")):
        tree = ast.parse(source_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in counts:
                    counts[node.func.id] += 1
    return counts


def _policy_callers() -> dict[str, set[str]]:
    """Attribute each policy call site to its enclosing function.

    A bare COUNT is defeated by a compensating swap (verified): converting a
    designated writer to ``raise_on_lock_unavailable`` while a non-designated
    writer reaches for ``report_on_lock_unavailable`` keeps the total at two and
    the gate green — which is precisely the double failure the assertion's own
    message claims to catch.
    """
    callers: dict[str, set[str]] = {policy: set() for policy in _POLICIES}
    for source_file in sorted(_AUTH.glob("*.py")):
        tree = ast.parse(source_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for inner in ast.walk(node):
                if (
                    isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Name)
                    and inner.func.id in callers
                ):
                    callers[inner.func.id].add(node.name)
    return callers


def _functions_calling_directly() -> set[str]:
    """Return writer functions that call ``_acquire_storage_lock`` themselves."""
    tree = ast.parse(_WRITER.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        # ``AsyncFunctionDef`` is NOT a subclass of ``FunctionDef`` — matching
        # only the latter would leave an ``async def`` writer free to hand-roll
        # the acquire without ever tripping this gate. Every storage writer is
        # sync today, so this closes a hole that is empty rather than one that
        # leaks; a ratchet that only covers the shapes in use when it was
        # written stops being a ratchet the moment someone adds a new shape.
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        # The template now lives in this same module (ADR-0033), so it is
        # excluded by name; nothing else here should call the primitive except
        # the writers still awaiting conversion.
        if node.name in _TEMPLATE_FUNCTIONS:
            continue
        for inner in ast.walk(node):
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Name)
                and inner.func.id == "_acquire_storage_lock"
            ):
                found.add(node.name)
    return found


def test_no_new_hand_rolled_storage_lock() -> None:
    """A new writer must route through ``in_storage_transaction``."""
    new = _functions_calling_directly() - _UNCONVERTED
    assert not new, (
        "Writer(s) calling _acquire_storage_lock directly instead of routing "
        f"through in_storage_transaction: {sorted(new)}\n\n"
        "Use:\n"
        "    in_storage_transaction(path, _body, log_prefix=..., \n"
        "                           on_unavailable=raise_on_lock_unavailable(...))\n"
        "picking the on_unavailable policy deliberately — raise_ / skip_ / "
        "report_on_lock_unavailable are NOT interchangeable."
    )


def test_unconverted_list_is_shrink_only() -> None:
    """A converted writer must be removed from the list.

    Without this the list becomes a graveyard and stops describing the real
    remaining work — the failure mode that makes ratchets rot.
    """
    stale = _UNCONVERTED - _functions_calling_directly()
    assert not stale, (
        f"These writers no longer hand-roll the lock — delete them from "
        f"_UNCONVERTED: {sorted(stale)}"
    )


def test_merge_cookie_delta_is_not_expected_to_convert() -> None:
    """The CAS merge is exempt by design, so it must not appear in the list.

    It takes the blocking ``_file_lock_exclusive`` and skips the parent-dir prep
    (it only updates a file that already exists). Listing it would imply a
    conversion we do not intend and that would change its lock semantics.
    """
    assert "merge_cookie_delta" not in _UNCONVERTED
    assert "merge_cookie_delta" not in _functions_calling_directly()

    # Both assertions above are satisfied by ABSENCE — verified: renaming the
    # function leaves this test green, and with _UNCONVERTED empty the first is
    # permanently vacuous. Assert positively that the writer exists and still
    # takes the BLOCKING lock, which is the semantics the exemption rests on.
    writer = next(
        (
            node
            for node in ast.parse(_WRITER.read_text(encoding="utf-8")).body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "merge_cookie_delta"
        ),
        None,
    )
    assert writer is not None, (
        "merge_cookie_delta is missing or renamed — its exemption from the "
        "transaction template rests on its blocking-lock semantics, so the "
        "exemption must not outlive the function it names"
    )
    blocking_calls = {
        inner.func.id
        for inner in ast.walk(writer)
        if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name)
    }
    assert "_file_lock_exclusive" in blocking_calls, (
        "merge_cookie_delta no longer takes the blocking _file_lock_exclusive — "
        "the reason it is exempt from in_storage_transaction no longer holds"
    )


def test_the_three_lock_policies_are_all_defined() -> None:
    """Each policy still exists — deleting one silently is a semantic change."""
    tree = ast.parse(_TEMPLATE.read_text(encoding="utf-8"))
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }
    missing = set(_POLICIES) - defined
    assert not missing, f"lock policy/policies disappeared from {_TEMPLATE.name}: {sorted(missing)}"


def test_in_use_policies_have_real_callers() -> None:
    """``raise_`` and ``skip_`` are load-bearing, not decoration.

    Counts real call sites across ``_auth/`` rather than asserting the
    definition exists in the file that defines it — the latter is a tautology
    that cannot fail while the function is present, and would stay green if
    every caller in the repo were deleted.
    """
    counts = _policy_call_counts()
    for policy in ("raise_on_lock_unavailable", "skip_on_lock_unavailable"):
        assert counts[policy] >= 1, (
            f"{policy} has no callers left in _auth/. Either a writer regressed "
            f"to hand-rolling its not-held branch, or the policy is now dead and "
            f"should be deleted rather than kept as a just-in-case helper."
        )


def test_report_policy_is_pinned_until_its_writers_convert() -> None:
    """``report_on_lock_unavailable`` is self-retiring, in both directions.

    Its caller count is not a fixed number: it tracks how many of the two
    full-replace writers have converted — they are the only writers with a rich
    enough outcome type to report into. So the expectation is conditional on
    :data:`_UNCONVERTED` (it was ZERO while both were unconverted, and reaches
    two when both have):

    * while they are pinned, a caller appearing means someone reached for the
      report policy from a writer whose return channel cannot express it;
    * the moment they convert, zero callers means the conversion quietly used a
      different policy — silently changing fail-closed-by-return into
      fail-closed-by-raise for callers — or that the helper is now dead and
      should be deleted.

    This is what the previous version of this gate *claimed* to check and did
    not: it asserted ``"def <policy>(" in <the file defining it>``, which is a
    tautology. It read as proof that all three policies were live, and that
    reading was wrong — one of them never had a caller at all.
    """
    converted = _REPORT_POLICY_WRITERS - _UNCONVERTED
    callers = _policy_callers()["report_on_lock_unavailable"]
    # Compare the caller SET, not a count. A count is defeated by a compensating
    # swap — converting a designated writer to ``raise_`` while a non-designated
    # writer reaches for ``report_`` keeps the total at two — which is exactly
    # the double failure this assertion's message claims to catch. Comparing
    # sets still permits a correct one-writer-at-a-time migration: with one of
    # the two converted, the expectation is that one name (CodeRabbit finding
    # on #2152).
    assert callers == converted, (
        "report_on_lock_unavailable caller count drifted from its converted "
        f"writers.\n  converted report-policy writers: {sorted(converted) or '(none)'}\n"
        f"  expected callers: {sorted(converted) or '(none)'}  actual: {sorted(callers) or '(none)'}\n"
        "If a caller appeared from a writer NOT in the designated set, that "
        "writer's return channel cannot express the report — use "
        "raise_on_lock_unavailable. If a designated writer converted without a "
        "caller appearing, it was converted to the wrong policy (changing "
        "fail-closed-by-return into fail-closed-by-raise, a breaking change "
        "for its callers)."
    )
