#!/usr/bin/env python3
"""Count the test-suite patch sites that reach into ``notebooklm._auth``.

This script is the **definition** of the patch-site metric used by the ``_auth``
deepening effort (ADR-0033 plan §7/§9). Ad-hoc greps for the same thing ranged
from 73 to 219 depending on which idiom the author happened to match, so the
reduction target is meaningless unless one instrument owns the count.

What counts as a site
---------------------
A call to ``monkeypatch.setattr`` or ``patch.object`` whose FIRST argument is a
**module object** resolving to ``notebooklm._auth.<module>``, and whose second
argument is a string literal naming the attribute being replaced::

    from notebooklm._auth import refresh as _auth_refresh
    monkeypatch.setattr(_auth_refresh, "_poke_session", fake)   # <- one site

**Plain assignment counts too**::

    _auth_storage._FLOCK_UNAVAILABLE_WARNED = False             # <- one site

It reaches into a module's private state exactly like ``setattr`` does, and it is
strictly worse because pytest never restores it. Counting only the call idioms
would let a later PR "improve" this metric by rewriting monkeypatch calls as
assignments while making the coupling worse. An assignment counts only when the
attribute is a real module-level name of the resolved module: a test file's alias
map is file-global while a Python binding is function-scoped, so a local can
shadow a module alias imported inside a different test (``mock.return_value = …``
is the common shape), and that check rejects it without special-casing mocks.

Each site is classified ``private`` when the attribute name starts with an
underscore and ``public`` otherwise, because §9's acceptance criterion is about
private-attribute coupling specifically.

Baseline (2026-08-07, PR 0.2 — the figures §9's reduction target measures against)
---------------------------------------------------------------------------------
TOTAL 131 public / 87 private / 218 sites. The three modules scoped for deps
records in plan §7 carry 127 of those and 66 of the private ones::

    refresh           31 public / 41 private /  72
    headless_reauth   23 public / 13 private /  36
    psidts_recovery    7 public / 12 private /  19

These figures REPLACE an earlier 155/107/262 baseline, which was inflated by
function-scoped shadowing in the call idioms (see below) — 44 sites that were
never module patches at all. The correction moved both sides of the comparison
by the same amount, so deltas measured against the old baseline still hold; the
absolute numbers do not. Re-measure rather than quoting either from memory.

Re-run this script to compare; do not trust a number quoted elsewhere.

Known limits — read before trusting a delta
-------------------------------------------
* **Privacy-class gaming.** §9 measures *private* sites, so renaming a private
  attribute to a public one moves a site between columns without reducing
  coupling. Check the ``total`` column and the per-attribute list, not just
  ``private``, when reading a delta.
This is a static count, so two things can move it without the coupling changing:
* **Helper indirection.** Collapsing N patches into one shared fixture reduces the
  count to 1 while the coupling is unchanged. A falling count next to a new
  conftest helper deserves a look at the helper, not applause.
* **Function-scoped shadowing** is now rejected for BOTH idioms: a scope that
  rebinds a module alias (assignment, walrus, ``for``/``with``/``except`` target,
  parameter, nested import) no longer resolves through it, and nested scopes
  inherit that. Before this, ``storage = object()`` followed by
  ``storage.SEAM = 1`` counted as a patch of the real module whenever ``SEAM``
  happened to be a genuine module-level name — the ``mock.return_value`` shape,
  and 44 of the original 262 sites.

Deliberate exclusions
---------------------
* **String targets** (``monkeypatch.setattr("notebooklm._auth.refresh.x", …)``)
  are NOT counted. They are a separate, separately-banned idiom — see
  ``tests/_guardrails/test_no_forbidden_monkeypatches.py`` — and counting them
  here would double-book the same debt against two gates.
* Patches of non-module objects (classes, instances, fixtures) are not module
  seams and are out of scope.
* ``monkeypatch.delattr`` / ``patch`` (non-``.object``) are likewise out of
  scope; the metric tracks module-attribute REBINDING.
* Stdlib/third-party modules reached THROUGH an ``_auth`` namespace --
  ``monkeypatch.setattr(_auth_refresh.os, "name", "nt")``,
  ``browser_capture.time``, ``_auth_refresh.httpx`` -- rebind that other
  module, not an ``_auth`` seam attribute, so they are not sites.

Resolution handles the aliased-import idiom the suite actually uses --
``from notebooklm._auth import refresh as _auth_refresh``,
``import notebooklm._auth.refresh as _auth_refresh``, plain
``import notebooklm._auth.refresh`` (dotted attribute access), and
``from notebooklm import _auth`` followed by ``_auth.refresh``.

It also resolves INDIRECT sites, where a test reaches one ``_auth`` module
through another's alias for it: ``psidts_recovery.py`` binds
``from . import storage as _auth_storage``, so
``monkeypatch.setattr(psidts_recovery._auth_storage, "save_cookies_to_storage", …)``
is a patch of ``_auth.storage`` and is billed to ``storage``. Getting this
wrong is not cosmetic -- it moved 12 sites between modules during this
script's own verification.

Pure stdlib + ``ast``: the package under test is never imported, so the count is
stable regardless of the environment the audit runs in. Output is sorted, so a
diff between two runs is a real change.

Usage::

    python scripts/audit_auth_patch_sites.py
    python scripts/audit_auth_patch_sites.py --json
    python scripts/audit_auth_patch_sites.py --tests-dir tests --module refresh
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

AUTH_PACKAGE = ("notebooklm", "_auth")
AUTH_DOTTED = ".".join(AUTH_PACKAGE)
PATCH_FUNCS = {"setattr"}  # matched as <something>.setattr(...)
REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True, order=True)
class PatchSite:
    """One resolved module-object patch of a ``notebooklm._auth`` attribute."""

    module: str  # the _auth submodule, e.g. "refresh"
    attribute: str  # the attribute being rebound, e.g. "_poke_session"
    path: str  # repo-relative test file
    lineno: int
    idiom: str  # "monkeypatch.setattr" | "patch.object" | "assignment"

    @property
    def is_private(self) -> bool:
        return self.attribute.startswith("_")


def _dotted_name(node: ast.AST) -> str | None:
    """Render ``a.b.c`` attribute/name chains as a dotted string, else ``None``."""
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return ".".join(reversed(parts))


def _locally_shadowed_aliases(tree: ast.Module, aliases: dict[str, str]) -> dict[int, set[str]]:
    """Per function scope, which module aliases it REBINDS to something local.

    ``load_module_level_names`` was the first half of keeping the ``assignment``
    idiom honest: it rejects ``storage.NOT_A_REAL_NAME = 1`` because the alias
    map is file-global while a Python binding is function-scoped. It cannot
    reject ``storage = object()`` followed by ``storage.SEAM = 1``, because
    ``SEAM`` *is* a real module-level name — so that shadowed local was counted
    as a patch of the module it merely shares a name with, inflating the metric.
    This is the other half: a scope that rebinds the alias no longer resolves
    through it.

    Keyed by ``id(scope_node)``. Rebinding means anything that makes the name
    local: assignment, walrus, ``for`` target, ``with ... as``, ``except ... as``,
    a parameter, or a nested import — not merely reading it.
    """
    shadowed: dict[int, set[str]] = {}
    for scope in ast.walk(tree):
        if not isinstance(scope, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            continue
        names: set[str] = set()
        args = scope.args
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            names.add(arg.arg)
        for extra in (args.vararg, args.kwarg):
            if extra is not None:
                names.add(extra.arg)
        for node in ast.walk(scope):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                if node is not scope:
                    names.add(node.name)
                continue
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                names.add(node.id)
            elif isinstance(node, ast.alias):
                names.add((node.asname or node.name).split(".")[0])
            elif isinstance(node, ast.ExceptHandler) and node.name:
                names.add(node.name)
        hits = names & set(aliases)
        if hits:
            shadowed[id(scope)] = hits
    return shadowed


def _is_shadowed(target: ast.AST, shadowed: frozenset[str]) -> bool:
    """Does this target expression start from a locally-rebound alias?"""
    dotted = _dotted_name(target)
    return dotted is not None and dotted.split(".")[0] in shadowed


def _shadow_context(tree: ast.Module, aliases: dict[str, str]) -> dict[int, frozenset[str]]:
    """Per NODE, the aliases shadowed by the scope chain enclosing it.

    Accumulated down the chain so a nested function inherits its enclosing
    scope's shadowing — the inner body reads the outer local, not the module.
    """
    shadowed = _locally_shadowed_aliases(tree, aliases)
    context: dict[int, frozenset[str]] = {}

    def _descend(node: ast.AST, active: frozenset[str]) -> None:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            active = active | shadowed.get(id(node), set())
        context[id(node)] = active
        for child in ast.iter_child_nodes(node):
            _descend(child, active)

    _descend(tree, frozenset())
    return context


def _build_alias_map(tree: ast.Module) -> dict[str, str]:
    """Map local binding -> ``notebooklm._auth.<module>`` for one test file.

    Covers every module-binding idiom in the suite. Bare ``import
    notebooklm._auth.refresh`` binds only ``notebooklm``, so it is recorded as
    the dotted path itself and resolved through :func:`_resolve_target`.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == AUTH_DOTTED:
                # from notebooklm._auth import refresh [as _auth_refresh]
                for alias in node.names:
                    aliases[alias.asname or alias.name] = f"{AUTH_DOTTED}.{alias.name}"
            elif module == AUTH_PACKAGE[0]:
                # from notebooklm import _auth [as auth_pkg]
                for alias in node.names:
                    if alias.name == AUTH_PACKAGE[1]:
                        aliases[alias.asname or alias.name] = AUTH_DOTTED
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if not alias.name.startswith(f"{AUTH_DOTTED}."):
                    continue
                if alias.asname:
                    # import notebooklm._auth.refresh as _auth_refresh
                    aliases[alias.asname] = alias.name
                else:
                    # import notebooklm._auth.refresh -> only `notebooklm` is bound;
                    # the dotted form is resolved directly.
                    aliases.setdefault(alias.name, alias.name)
    return aliases


def load_source_aliases(auth_dir: Path) -> dict[str, dict[str, str]]:
    """Per ``_auth`` module, its module-level aliases for OTHER ``_auth`` modules.

    ``psidts_recovery.py`` does ``from . import storage as _auth_storage``, so a
    test writing ``monkeypatch.setattr(psidts_recovery._auth_storage, …)`` is
    really patching ``_auth.storage``. Without this map such a site is either
    dropped (undercount) or billed to ``psidts_recovery`` (mis-attribution).
    """
    source_aliases: dict[str, dict[str, str]] = {}
    if not auth_dir.is_dir():
        return source_aliases
    known = {path.stem for path in auth_dir.glob("*.py")}
    for path in sorted(auth_dir.glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError):
            continue
        local: dict[str, str] = {}
        for node in tree.body:  # module level only
            if not isinstance(node, ast.ImportFrom) or node.level != 1:
                continue
            if node.module is None:
                # from . import storage as _auth_storage
                for alias in node.names:
                    if alias.name in known:
                        local[alias.asname or alias.name] = alias.name
        source_aliases[path.stem] = local
    return source_aliases


def load_module_level_names(auth_dir: Path) -> dict[str, set[str]]:
    """Per ``_auth`` module, the names actually bound at module level.

    Used to keep the ``assignment`` idiom honest. A test file's alias map is
    file-global while a Python binding is function-scoped, so a local variable
    can shadow a module alias imported inside a different test — e.g.
    ``test_auth_cold_start_recovery.py`` imports ``headless_reauth as headless``
    inside three tests, and elsewhere binds ``headless`` to an ``AsyncMock``.
    Requiring the assigned attribute to be a real module-level name of the
    resolved module rejects ``mock.return_value = …`` without special-casing
    mock internals, and costs nothing for genuine rebinding.
    """
    names: dict[str, set[str]] = {}
    if not auth_dir.is_dir():
        return names
    for path in sorted(auth_dir.glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError):
            continue
        bound: set[str] = set()
        for node in tree.body:  # module level only
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                bound.add(node.name)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        bound.add(target.id)
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                bound.add(node.target.id)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    bound.add(alias.asname or alias.name.split(".")[0])
        names[path.stem] = bound
    return names


def _resolve_target(
    node: ast.AST,
    aliases: dict[str, str],
    source_aliases: dict[str, dict[str, str]] | None = None,
) -> str | None:
    """Resolve a patch target expression to the ``_auth`` submodule it patches.

    A bare module reference resolves to that module. A single trailing
    attribute is resolved through the *source* module's own aliases: if it
    names another ``_auth`` module the site is attributed THERE
    (``psidts_recovery._auth_storage`` -> ``storage``); if it names a stdlib or
    third-party module reached through the namespace
    (``_auth_refresh.os``, ``browser_capture.time``) it is not an ``_auth``
    seam coupling and resolves to ``None``.
    """
    source_aliases = source_aliases or {}
    dotted = _dotted_name(node)
    if dotted is None:
        return None

    # Fully-qualified: notebooklm._auth.<module>[.<attr>]
    if dotted.startswith(f"{AUTH_DOTTED}."):
        tail = dotted[len(AUTH_DOTTED) + 1 :].split(".")
        if len(tail) == 1:
            return tail[0]
        if len(tail) == 2:
            return source_aliases.get(tail[0], {}).get(tail[1])
        return None

    head, _, rest = dotted.partition(".")
    target = aliases.get(head)
    if target is None:
        return None

    if target == AUTH_DOTTED:
        # `_auth.refresh` off the package binding.
        parts = rest.split(".") if rest else []
        if len(parts) == 1:
            return parts[0]
        if len(parts) == 2:
            return source_aliases.get(parts[0], {}).get(parts[1])
        return None

    if target.startswith(f"{AUTH_DOTTED}."):
        module = target[len(AUTH_DOTTED) + 1 :].split(".")[0]
        if not rest:
            return module
        parts = rest.split(".")
        if len(parts) == 1:
            return source_aliases.get(module, {}).get(parts[0])
        return None
    return None


def _patch_idiom(call: ast.Call) -> str | None:
    """Return ``monkeypatch.setattr`` / ``patch.object`` for a matching call."""
    func = call.func
    if not isinstance(func, ast.Attribute):
        return None
    if func.attr in PATCH_FUNCS:
        # <fixture>.setattr(...) — the monkeypatch fixture is conventionally
        # named `monkeypatch`, but accept any receiver so renamed fixtures and
        # `mp.setattr` helpers still register.
        return "monkeypatch.setattr"
    if func.attr == "object":
        # patch.object / mock.patch.object / unittest.mock.patch.object
        receiver = _dotted_name(func.value)
        if receiver and receiver.split(".")[-1] == "patch":
            return "patch.object"
    return None


def collect_sites(tests_dir: Path, auth_dir: Path | None = None) -> list[PatchSite]:
    """Walk ``tests_dir`` and return every resolved ``_auth`` patch site."""
    if auth_dir is None:
        auth_dir = REPO_ROOT / "src" / "notebooklm" / "_auth"
    source_aliases = load_source_aliases(auth_dir)
    module_names = load_module_level_names(auth_dir)
    sites: list[PatchSite] = []
    for path in sorted(tests_dir.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError):
            continue
        aliases = _build_alias_map(tree)
        if not aliases:
            continue
        shadow = _shadow_context(tree, aliases)
        try:
            rel = path.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            rel = path.as_posix()
        for node in ast.walk(tree):
            # Plain rebinding: ``_auth_storage._FLOCK_UNAVAILABLE_WARNED = False``.
            # This is a patch site by every meaning that matters — it reaches into a
            # module's private state — and it is STRICTLY WORSE than monkeypatch
            # because pytest never restores it. Counting only the call idioms would
            # let a later PR "improve" the metric by converting monkeypatch calls
            # into assignments while making the coupling worse.
            if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                # AnnAssign carries ONE target and may have no value at all
                # (``x.y: int``) — a bare annotation rebinds nothing, so it is
                # not a patch site.
                if isinstance(node, ast.Assign):
                    targets = node.targets
                elif isinstance(node, ast.AugAssign):
                    targets = [node.target]
                else:
                    targets = [node.target] if node.value is not None else []
                for target_node in targets:
                    if not isinstance(target_node, ast.Attribute):
                        continue
                    if _is_shadowed(target_node.value, shadow.get(id(node), frozenset())):
                        continue
                    module = _resolve_target(target_node.value, aliases, source_aliases)
                    if module is None:
                        continue
                    # Reject a local that merely shadows a module alias (see
                    # load_module_level_names): only a real module-level name counts.
                    if target_node.attr not in module_names.get(module, set()):
                        continue
                    sites.append(
                        PatchSite(
                            module=module,
                            attribute=target_node.attr,
                            path=rel,
                            lineno=node.lineno,
                            idiom="assignment",
                        )
                    )
                continue
            if not isinstance(node, ast.Call):
                continue
            idiom = _patch_idiom(node)
            if idiom is None:
                continue
            # Both idioms accept their first two arguments by KEYWORD:
            # ``monkeypatch.setattr(target=..., name="x")`` and
            # ``patch.object(target=..., attribute="x")``. A positional-only
            # scan silently under-counts, which reads as "the metric improved".
            keywords = {kw.arg: kw.value for kw in node.keywords if kw.arg}
            target = node.args[0] if node.args else keywords.get("target")
            attr_node = (
                node.args[1]
                if len(node.args) > 1
                else keywords.get("name") or keywords.get("attribute")
            )
            if target is None or attr_node is None:
                continue
            # String targets are a different, separately-banned idiom.
            if isinstance(target, ast.Constant):
                continue
            if not (isinstance(attr_node, ast.Constant) and isinstance(attr_node.value, str)):
                continue
            if _is_shadowed(target, shadow.get(id(node), frozenset())):
                continue
            module = _resolve_target(target, aliases, source_aliases)
            if module is None:
                continue
            sites.append(
                PatchSite(
                    module=module,
                    attribute=attr_node.value,
                    path=rel,
                    lineno=node.lineno,
                    idiom=idiom,
                )
            )
    return sorted(sites)


def summarize(sites: list[PatchSite]) -> dict[str, dict[str, int]]:
    """Per-module public/private/total counts, plus a ``TOTAL`` row."""
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"public": 0, "private": 0, "total": 0})
    for site in sites:
        row = counts[site.module]
        row["private" if site.is_private else "public"] += 1
        row["total"] += 1
    summary = {module: counts[module] for module in sorted(counts)}
    summary["TOTAL"] = {
        "public": sum(row["public"] for row in summary.values()),
        "private": sum(row["private"] for row in summary.values()),
        "total": sum(row["total"] for row in summary.values()),
    }
    return summary


def render_table(summary: dict[str, dict[str, int]]) -> str:
    """Render the per-module count table as fixed-width text."""
    width = max((len(name) for name in summary), default=6)
    width = max(width, len("module"))
    lines = [
        f"{'module'.ljust(width)}  {'public':>7}  {'private':>7}  {'total':>7}",
        f"{'-' * width}  {'-' * 7}  {'-' * 7}  {'-' * 7}",
    ]
    for name, row in summary.items():
        if name == "TOTAL":
            lines.append(f"{'-' * width}  {'-' * 7}  {'-' * 7}  {'-' * 7}")
        lines.append(
            f"{name.ljust(width)}  {row['public']:>7}  {row['private']:>7}  {row['total']:>7}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--tests-dir",
        type=Path,
        default=REPO_ROOT / "tests",
        help="directory to walk (default: <repo>/tests)",
    )
    parser.add_argument(
        "--auth-dir",
        type=Path,
        default=REPO_ROOT / "src" / "notebooklm" / "_auth",
        help="the _auth package to resolve aliases against (default: <repo>/src/notebooklm/_auth)",
    )
    parser.add_argument(
        "--module",
        action="append",
        default=None,
        help="restrict output to this _auth submodule (repeatable)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    parser.add_argument(
        "--list-sites",
        action="store_true",
        help="also print every site (file:line attribute) in text mode",
    )
    args = parser.parse_args(argv)

    if not args.tests_dir.is_dir():
        parser.error(f"not a directory: {args.tests_dir}")
    # Fail loudly rather than under-report: a missing/renamed _auth dir silently
    # drops every indirect site (12 of them at the 2026-08-07 baseline) and still
    # exits 0, which would read as "the count went down".
    if not args.auth_dir.is_dir():
        parser.error(f"not a directory: {args.auth_dir}")

    sites = collect_sites(args.tests_dir, args.auth_dir)
    if args.module:
        wanted = set(args.module)
        sites = [site for site in sites if site.module in wanted]
    summary = summarize(sites)

    if args.json:
        json.dump(
            {"summary": summary, "sites": [asdict(site) for site in sites]},
            sys.stdout,
            indent=2,
            sort_keys=True,
        )
        sys.stdout.write("\n")
        return 0

    print(render_table(summary))
    if args.list_sites:
        print()
        for site in sites:
            kind = "private" if site.is_private else "public "
            print(f"{kind}  {site.module}.{site.attribute}  ({site.path}:{site.lineno})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
