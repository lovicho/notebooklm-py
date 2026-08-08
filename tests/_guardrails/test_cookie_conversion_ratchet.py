"""Shrink-only ratchet on the scattered cookie-conversion free functions.

ADR-0031 Stage 1. A cookie has lived in six shapes in this layer, with the
conversions between them as free functions any module could reach for. That is
what let "which cookies are here / is this set usable" get re-derived
independently at a dozen call sites, and it is why the auth layer resisted the
#2139 boundary moves: the coupling had no owner.

:class:`notebooklm._auth.cookie_types.CookieJar` is now that owner. This gate
does **not** force a migration — per this repo's ratchet convention, existing
call sites migrate opportunistically, not in an eager burndown. It blocks the
*next* one: new code converts through ``CookieJar`` instead of adding a
thirteenth bespoke call.

Sanctioned homes (never flagged):

* ``_auth/cookies.py`` — where these functions are defined and compose.
* ``_auth/cookie_types.py`` — the wrapper whose whole job is delegating to them.

Everything else is in :data:`_GRANDFATHERED`, which pins each surviving call
site at its **measured call count** and is **shrink-only** in both directions:
a count may never rise (``test_no_new_bespoke_cookie_conversions``), and one
that no longer matches reality must be lowered or deleted
(``test_grandfathered_entries_are_all_live``). Counting, rather than merely
listing the pairs, is what stops a module already on the list from growing a
second bespoke call for free.
"""

from __future__ import annotations

import ast
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_lint

_SRC_ROOT = Path(__file__).resolve().parents[2] / "src" / "notebooklm"

#: The conversions ``CookieJar`` now owns a typed route for.
_RATCHETED = frozenset(
    {
        "normalize_cookie_map",
        "flatten_cookie_map",
        "extract_cookies_with_domains",
        "convert_rookiepy_cookies_to_storage_state",
    }
)

#: Modules that legitimately call these directly.
_SANCTIONED = frozenset({"_auth/cookies.py", "_auth/cookie_types.py"})

#: (module path relative to ``src/notebooklm``, function) -> the number of calls
#: measured when the ratchet landed. SHRINK-ONLY — never add a pair, never raise
#: a count. Pinning the *count* rather than just the pair matters: a bare pair
#: would let an already-listed module grow a second, third … bespoke call for
#: free, which is the same debt the gate exists to stop. Each entry is a
#: candidate for a later stage.
_GRANDFATHERED: dict[tuple[str, str], int] = {
    # AuthTokens.__post_init__ widens legacy caller-supplied maps, and the
    # back-compat flat-map property flattens them back. Both retire in
    # ADR-0031 Stage 4, when the dual cookies/cookie_jar fields collapse
    # into a single CookieJar and these become jar methods.
    ("_auth/tokens.py", "normalize_cookie_map"): 1,
    ("_auth/tokens.py", "flatten_cookie_map"): 1,
    # The L3 heal converts rookiepy rows twice (before and after recovery).
    # Retires with the Stage 2 validate/heal split. Relocated 1:1 from
    # ``_auth/browser_cookie_recovery.py`` when ADR-0033's load-composition merge
    # absorbed that leaf into the recovery module (same two calls, new home).
    ("_auth/psidts_recovery.py", "convert_rookiepy_cookies_to_storage_state"): 2,
    # The CLI browser-extraction probe path. Its converter choice is pinned
    # to the routability predicates by design (see the module docstring in
    # _auth/psidts_recovery.py), so it moves only with Stage 5's mode split.
    ("cli/services/login/cookie_jar.py", "convert_rookiepy_cookies_to_storage_state"): 1,
    ("cli/services/login/cookie_jar.py", "extract_cookies_with_domains"): 1,
}


def _local_bindings(tree: ast.AST) -> dict[str, str]:
    """Map local binding -> ratcheted function, for both rebinding idioms.

    Either spelling puts a non-ratcheted name on the call node, so a scan that
    only matched literal names would have a real bypass rather than a
    theoretical one — both idioms are live in this package:

    * ``from … import f as g`` — ``_auth/storage.py`` imports
      ``_atomic_write_json_unchecked as _write_state_unchecked``.
    * ``g = mod.f`` — the compat re-export surface in ``auth.py`` rebinds ALL
      FOUR ratcheted names this way, and ``_auth/refresh.py`` rebinds
      ``flatten_cookie_map``. Neither module calls its rebind today, but the
      bindings sit in the module where such a call is most plausible.

    Resolved back to the canonical name so ``_GRANDFATHERED`` stays keyed on the
    real function regardless of what a caller called it. The re-export
    statements themselves are ``ast.Assign``, not ``ast.Call``, so recognizing
    them here does not make them count as call sites.

    **Assignments are honored only at module level, deliberately.** ``ast.walk``
    flattens every scope into one view, so a function-local ``alias = mod.f``
    would otherwise resolve an unrelated ``alias(...)`` in a *different*
    function as a conversion — a binding Python never shared. The accepted cost
    is a narrow false negative: a function-local rebind is no longer caught.
    That trade is the right way round for a block-new-debt ratchet. A missed
    obscure local alias costs one uncaught call; reding on unrelated code costs
    the gate its credibility and teaches people to route around it. Every real
    binding in this repo today (``auth.py`` 126-131, ``_auth/refresh.py`` 59) is
    module level.

    Resolution is also one hop only: ``g = mod.f`` binds, but a chain through
    it (``h = g``) does not, since ``g`` is not itself a ratcheted name. Both
    idioms present in this repo are one hop, so that is where the gate stops.
    """
    bindings: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in _RATCHETED and alias.asname:
                    bindings[alias.asname] = alias.name
    for node in tree.body if isinstance(tree, ast.Module) else []:
        if isinstance(node, ast.Assign):
            source = _callee_name(node.value)
            if source in _RATCHETED:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        bindings[target.id] = source
    return bindings


def _callee_name(node: ast.expr) -> str | None:
    """The bare name of ``f`` / ``mod.f``, or ``None`` for any other expression."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _module_call_sites(rel: str, tree: ast.AST) -> Counter[tuple[str, str]]:
    """Count the ``(module, ratcheted function)`` calls in one module."""
    bindings = _local_bindings(tree)
    found: Counter[tuple[str, str]] = Counter()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # Matches both ``f(...)`` and ``mod.f(...)`` so aliasing a module
        # (the ``_auth_cookies.f(...)`` idiom used throughout _auth) does
        # not slip past the gate.
        name = _callee_name(node.func)
        if name is None:
            continue
        resolved = bindings.get(name, name)
        if resolved in _RATCHETED:
            found[(rel, resolved)] += 1
    return found


def _call_sites() -> Counter[tuple[str, str]]:
    """Count every ``(module, ratcheted function)`` call under ``src/``."""
    found: Counter[tuple[str, str]] = Counter()
    for path in sorted(_SRC_ROOT.rglob("*.py")):
        rel = path.relative_to(_SRC_ROOT).as_posix()
        if rel in _SANCTIONED:
            continue
        found += _module_call_sites(rel, ast.parse(path.read_text(encoding="utf-8")))
    return found


def _grown(measured: Mapping[tuple[str, str], int]) -> dict[tuple[str, str], tuple[int, int]]:
    """Sites over their pinned count → ``{site: (measured, ceiling)}``.

    A site absent from :data:`_GRANDFATHERED` has a ceiling of 0, so a brand-new
    call site and an extra call in an already-listed module fail the same way.
    """
    return {
        site: (count, _GRANDFATHERED.get(site, 0))
        for site, count in measured.items()
        if count > _GRANDFATHERED.get(site, 0)
    }


def _slack(measured: Mapping[tuple[str, str], int]) -> dict[tuple[str, str], tuple[int, int]]:
    """Entries pinned above reality → ``{site: (measured, ceiling)}``.

    Covers both a fully migrated entry (measured 0) and a partially migrated
    one, so the pin always describes the debt that is actually there.
    """
    return {
        site: (measured.get(site, 0), ceiling)
        for site, ceiling in _GRANDFATHERED.items()
        if measured.get(site, 0) < ceiling
    }


def test_no_new_bespoke_cookie_conversions() -> None:
    """New code converts through ``CookieJar``, not the raw free functions."""
    grown = _grown(_call_sites())
    assert not grown, (
        "New direct call(s) to a ratcheted cookie conversion:\n"
        + "\n".join(
            f"  {module}: {func}() — {count} call(s), pinned at {ceiling}"
            for (module, func), (count, ceiling) in sorted(grown.items())
        )
        + "\n\nUse notebooklm._auth.cookie_types.CookieJar instead — e.g.\n"
        "  CookieJar.from_storage_state(state).to_domain_map()\n"
        "  CookieJar.from_rookiepy(rows).to_httpx()\n"
        "flatten_cookie_map has NO jar equivalent on purpose: the flat shape is\n"
        "lossy (path collapsed, arbitrary same-tier winner — #369/#2054) and\n"
        "legacy-only. For cookies on the wire use CookieJar.to_httpx().\n"
        "If the call genuinely cannot route through the jar, say why in the PR "
        "and add it to _GRANDFATHERED with that reason."
    )


@pytest.mark.parametrize(
    "source",
    [
        pytest.param("from x import normalize_cookie_map\nnormalize_cookie_map({})\n", id="bare"),
        pytest.param("import x\nx.normalize_cookie_map({})\n", id="module-attr"),
        pytest.param(
            "from x import normalize_cookie_map as _n\n_n({})\n",
            id="renamed-on-import",
        ),
        pytest.param(
            "import x\n_n = x.normalize_cookie_map\n_n({})\n",
            id="rebound-by-assignment",
        ),
    ],
)
def test_every_call_spelling_is_caught(source: str) -> None:
    """A ratcheted call counts however it is spelled, including renamed.

    The rename form is the one a name-only scan misses, and it is the spelling
    this package already uses elsewhere — so it is checked here rather than
    assumed impossible.
    """
    assert _module_call_sites("_auth/probe.py", ast.parse(source)) == Counter(
        {("_auth/probe.py", "normalize_cookie_map"): 1}
    )


def test_grandfathered_entries_are_all_live() -> None:
    """The allowlist is shrink-only: a migrated call must lower its pin.

    Without this, the list silently becomes a graveyard and stops describing
    the real remaining debt — the failure mode that makes ratchets rot. Slack
    is as bad as staleness: a pin of 2 against 1 remaining call is headroom for
    a future call to reappear for free.
    """
    slack = _slack(_call_sites())
    assert not slack, (
        "Grandfathered entries pinned above the calls that remain — lower the "
        "count, or delete the entry if it reached 0:\n"
        + "\n".join(
            f"  {module}: {func}() — {count} call(s) left, pinned at {ceiling}"
            for (module, func), (count, ceiling) in sorted(slack.items())
        )
    )


def test_function_local_rebinding_does_not_leak_across_scopes() -> None:
    """A binding made inside one function must not resolve a call in another.

    ``ast.walk`` flattens scopes, so without the module-level restriction the
    ``alias`` bound in ``a`` would resolve ``b``'s unrelated ``alias`` parameter
    as a conversion — a false positive on code that converts nothing. Also pins
    the accepted cost: ``a``'s own in-scope call is not counted either.
    """
    tree = ast.parse(
        "import x\n"
        "def a():\n"
        "    alias = x.normalize_cookie_map\n"
        "    return alias({})\n"
        "def b(alias):\n"
        "    return alias({})\n"
    )
    assert _module_call_sites("_auth/probe.py", tree) == Counter()


def test_a_reexport_assignment_is_not_a_call_site() -> None:
    """Rebinding for re-export is not a conversion, and must stay uncounted.

    ``auth.py`` rebinds all four ratcheted names this way for its compat
    surface. Counting the assignment itself would put four phantom sites on a
    module that performs no conversion, which would either red the gate or
    force bogus pins.
    """
    tree = ast.parse("import x\nnormalize_cookie_map = x.normalize_cookie_map\n")
    assert _module_call_sites("auth.py", tree) == Counter()


def test_an_extra_call_in_a_grandfathered_module_is_caught() -> None:
    """Being on the list buys the measured calls, not unlimited ones."""
    site = ("_auth/tokens.py", "normalize_cookie_map")
    assert _grown({site: _GRANDFATHERED[site] + 1})
    assert not _grown({site: _GRANDFATHERED[site]})


def test_a_migrated_call_must_lower_its_pin() -> None:
    """Shrink-only in the other direction: reality drops, the pin must follow."""
    site = ("_auth/psidts_recovery.py", "convert_rookiepy_cookies_to_storage_state")
    assert _slack({site: _GRANDFATHERED[site] - 1})
    assert not _slack(dict(_GRANDFATHERED))


def test_cookie_jar_is_the_sanctioned_wrapper() -> None:
    """``cookie_types`` really does delegate — the premise of the whole gate.

    If a future edit reimplemented a conversion inline instead of delegating,
    the ratchet would be pointing callers at a second implementation rather
    than at the single owner.
    """
    source = (_SRC_ROOT / "_auth" / "cookie_types.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    delegated = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    missing = {"normalize_cookie_map", "build_cookie_jar"} - delegated
    assert not missing, f"cookie_types.py stopped delegating to: {sorted(missing)}"
