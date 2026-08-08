"""Tests for ``scripts/audit_auth_patch_sites.py``.

The script is the source of the ADR-0033 patch-site metric quoted in review and
in PR descriptions, and it has already miscounted twice: once by resolving
aliases too loosely, and twice more under review on #2156: it read only
POSITIONAL arguments, so every keyword-form ``monkeypatch.setattr`` /
``patch.object`` went uncounted; and it credited a function-local that merely
SHADOWED a module alias, which over-counted by 44 sites. The first biases the
number down and the second up, and both are silent.

A detector nobody tests is a number nobody can trust, so these pin the shapes it
must see and the shapes it must not count.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.repo_lint

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "audit_auth_patch_sites.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("audit_auth_patch_sites", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def script():
    return _load_module()


def _sites(script, tmp_path: Path, body: str, *, auth_module: str, module_body: str):
    """Run ``collect_sites`` over a one-file fake tests tree and fake ``_auth``."""
    auth_dir = tmp_path / "_auth"
    auth_dir.mkdir()
    (auth_dir / "__init__.py").write_text("", encoding="utf-8")
    (auth_dir / f"{auth_module}.py").write_text(module_body, encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_fake.py").write_text(body, encoding="utf-8")
    return script.collect_sites(tests_dir, auth_dir)


_MODULE_BODY = "SEAM = None\n_PRIVATE_SEAM = None\n"

# Assembled rather than written literally. A literal ``patch("notebooklm…")`` in
# this file is indistinguishable, to a source-scanning gate, from a real
# string-target patch — and it correctly trips both ADR-0007 guardrails
# (``test_no_forbidden_monkeypatches`` and ``test_string_patch_ratchet``). This is
# fixture TEXT the detector under test parses, not a patch this file performs, so
# the honest fix is to keep the pattern out of the source rather than allowlist a
# file that patches nothing.
_STRING_TARGET_FIXTURE = (
    "from unittest.mock import patch\n"
    "def test_x():\n"
    "    patch(" + repr("notebooklm._auth.storage.SEAM") + ")\n"
)


@pytest.mark.parametrize(
    ("label", "body", "expected"),
    [
        (
            "positional-setattr",
            "from notebooklm._auth import storage\n"
            "def test_x(monkeypatch):\n"
            "    monkeypatch.setattr(storage, 'SEAM', 1)\n",
            {("storage", "SEAM")},
        ),
        # The regression this file exists for: both idioms take their first two
        # arguments by keyword, and a positional-only scan silently drops them.
        (
            "keyword-setattr",
            "from notebooklm._auth import storage\n"
            "def test_x(monkeypatch):\n"
            "    monkeypatch.setattr(target=storage, name='SEAM', value=1)\n",
            {("storage", "SEAM")},
        ),
        (
            "keyword-patch-object",
            "from unittest.mock import patch\n"
            "from notebooklm._auth import storage\n"
            "def test_x():\n"
            "    patch.object(target=storage, attribute='SEAM')\n",
            {("storage", "SEAM")},
        ),
        (
            "mixed-positional-and-keyword",
            "from notebooklm._auth import storage\n"
            "def test_x(monkeypatch):\n"
            "    monkeypatch.setattr(storage, name='SEAM', value=1)\n",
            {("storage", "SEAM")},
        ),
        (
            "plain-assignment-rebinding",
            "from notebooklm._auth import storage\ndef test_x():\n    storage.SEAM = 1\n",
            {("storage", "SEAM")},
        ),
        (
            "annotated-assignment-rebinding",
            "from notebooklm._auth import storage\ndef test_x():\n    storage.SEAM: int = 1\n",
            {("storage", "SEAM")},
        ),
        (
            "aliased-module-import",
            "from notebooklm._auth import storage as _st\n"
            "def test_x(monkeypatch):\n"
            "    monkeypatch.setattr(_st, '_PRIVATE_SEAM', 1)\n",
            {("storage", "_PRIVATE_SEAM")},
        ),
    ],
)
def test_counted_shapes(script, tmp_path, label, body, expected):
    sites = _sites(script, tmp_path, body, auth_module="storage", module_body=_MODULE_BODY)
    assert {(s.module, s.attribute) for s in sites} == expected
    # Cardinality too: a set comparison collapses duplicates, so a collector that
    # reported one source site twice would inflate the metric and still pass.
    assert len(sites) == len(expected)


@pytest.mark.parametrize(
    ("label", "body"),
    [
        # A BARE annotation rebinds nothing — ``storage.SEAM: int`` is a type
        # statement, not a patch. Counting it would inflate the metric.
        (
            "bare-annotation-no-value",
            "from notebooklm._auth import storage\ndef test_x():\n    storage.SEAM: int\n",
        ),
        # String-target patching is a separately-banned idiom, not this metric's
        # subject. See _STRING_TARGET_FIXTURE for why it is assembled.
        ("string-target", _STRING_TARGET_FIXTURE),
        # A local that merely SHADOWS a module alias is not a module patch. Note
        # the attribute is a REAL module-level name: an earlier version of this
        # fixture used an invented one, which passed for the wrong reason (the
        # module-level-name check rejected it) and so never exercised shadowing
        # at all. With a real name it is the genuine false positive, and it was
        # one until the scope check landed.
        (
            "shadowed-local-assignment",
            "from notebooklm._auth import storage\n"
            "def test_x():\n"
            "    storage = object()\n"
            "    storage.SEAM = 1\n",
        ),
        (
            "shadowed-local-setattr",
            "from notebooklm._auth import storage\n"
            "def test_x(monkeypatch):\n"
            "    storage = object()\n"
            "    monkeypatch.setattr(storage, 'SEAM', 1)\n",
        ),
        # A nested scope reads the ENCLOSING local, not the module.
        (
            "shadowed-in-enclosing-scope",
            "from notebooklm._auth import storage\n"
            "def test_x():\n"
            "    storage = object()\n"
            "    def inner():\n"
            "        storage.SEAM = 1\n"
            "    inner()\n",
        ),
        # A parameter shadows just as effectively as an assignment.
        (
            "shadowed-by-parameter",
            "from notebooklm._auth import storage\ndef test_x(storage):\n    storage.SEAM = 1\n",
        ),
        ("unrelated-module", "import os\ndef test_x():\n    os.environ = {}\n"),
    ],
)
def test_uncounted_shapes(script, tmp_path, label, body):
    sites = _sites(script, tmp_path, body, auth_module="storage", module_body=_MODULE_BODY)
    assert sites == [], f"{label} must not be counted, got {sites}"


def test_private_and_public_are_split(script, tmp_path):
    body = (
        "from notebooklm._auth import storage\n"
        "def test_x(monkeypatch):\n"
        "    monkeypatch.setattr(storage, 'SEAM', 1)\n"
        "    monkeypatch.setattr(storage, '_PRIVATE_SEAM', 1)\n"
    )
    summary = script.summarize(
        _sites(script, tmp_path, body, auth_module="storage", module_body=_MODULE_BODY)
    )
    assert summary["storage"] == {"public": 1, "private": 1, "total": 2}
    # The whole row: a regression in aggregate public/private split would slip
    # past a bare total.
    assert summary["TOTAL"] == {"public": 1, "private": 1, "total": 2}


def test_missing_auth_dir_is_loud_not_a_silent_zero(script, tmp_path):
    """A renamed/missing ``_auth`` must not read as "the metric went down"."""
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_fake.py").write_text("", encoding="utf-8")
    with pytest.raises(SystemExit) as exc_info:
        script.main(["--tests-dir", str(tests_dir), "--auth-dir", str(tmp_path / "nope")])
    # A bare ``raises(SystemExit)`` also accepts a CLEAN exit, which is exactly
    # the "silently counted nothing" outcome this guards against.
    assert exc_info.value.code not in (None, 0)


def test_script_parses_and_exposes_its_contract(script):
    """Guards the loader itself: the API these tests drive must exist."""
    for name in ("collect_sites", "summarize", "main", "load_module_level_names"):
        assert hasattr(script, name), f"{name} disappeared from the audit script"
    ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
