"""Unit + equivalence tests for the ADR-0031 Stage 1 ``CookieJar`` wrapper.

The point of this stage is that ``CookieJar`` changes **nothing** — it gives
the scattered cookie conversions and policy questions a type to hang off,
while every decision still delegates to the free function that owns it. So the
load-bearing tests here are the *equivalence* ones: for each method, assert the
jar's answer is identical to the legacy call it wraps. If a future edit makes
the jar diverge (e.g. reimplements a filter instead of delegating), these fail
even though the jar's own behavior might look self-consistent.
"""

from __future__ import annotations

import pytest

from notebooklm._auth import cookie_policy as _cookie_policy
from notebooklm._auth import cookies as _auth_cookies
from notebooklm._auth.cookie_types import Cookie, CookieJar


def _storage_state() -> dict:
    """A realistic multi-domain storage state, including rows that must drop."""
    return {
        "cookies": [
            {"name": "SID", "value": "sid-base", "domain": ".google.com", "path": "/"},
            # Same name, regional domain — lower priority tier than .google.com.
            {"name": "SID", "value": "sid-regional", "domain": ".google.com.sg", "path": "/"},
            {
                "name": "__Secure-1PSIDTS",
                "value": "psidts",
                "domain": ".google.com",
                "path": "/",
                "expires": 1800000000,
                "httpOnly": True,
                "secure": True,
            },
            {"name": "APISID", "value": "apisid", "domain": ".google.com", "path": "/"},
            {"name": "SAPISID", "value": "sapisid", "domain": ".google.com", "path": "/"},
            {"name": "LSID", "value": "lsid", "domain": "accounts.google.com", "path": "/"},
            {"name": "OSID", "value": "osid", "domain": "notebook.google.com", "path": "/"},
            # Must be dropped: not an allowlisted auth domain.
            {"name": "TRACKER", "value": "nope", "domain": ".evil.example", "path": "/"},
            # Must be dropped: malformed (no domain).
            {"name": "BROKEN", "value": "x", "path": "/"},
        ],
        "origins": [],
    }


class TestConstructorEquivalence:
    """Each constructor must agree with the legacy conversion it wraps."""

    def test_from_storage_state_matches_extract_cookies_with_domains(self) -> None:
        state = _storage_state()
        jar = CookieJar.from_storage_state(state)
        assert jar.to_domain_map() == _auth_cookies.extract_cookies_with_domains(
            state, validate_required=False
        )

    def test_from_storage_state_applies_the_allowlist_filter(self) -> None:
        """Non-auth domains and malformed rows drop, exactly as elsewhere."""
        jar = CookieJar.from_storage_state(_storage_state())
        assert "TRACKER" not in jar.names()
        assert "BROKEN" not in jar.names()

    def test_from_rookiepy_matches_convert_then_extract(self) -> None:
        rows = [
            {
                "name": "SID",
                "value": "sid",
                "domain": ".google.com",
                "path": "/",
                "http_only": True,
                "secure": True,
                "expires": None,
            },
            {
                "name": "__Secure-1PSIDTS",
                "value": "psidts",
                "domain": ".google.com",
                "path": "/",
                "http_only": True,
                "secure": True,
                "expires": 1800000000,
            },
        ]
        jar = CookieJar.from_rookiepy(rows)
        legacy_state = _auth_cookies.convert_rookiepy_cookies_to_storage_state(rows)
        assert jar.to_domain_map() == _auth_cookies.extract_cookies_with_domains(
            legacy_state, validate_required=False
        )

    def test_session_cookie_expiry_uses_the_canonical_internal_form(self) -> None:
        """A session cookie is ``expires=None`` *in* the jar, ``-1`` *on the wire*.

        Two representations, deliberately: ``normalize_cookie_expiry`` collapses
        both ``None`` and the exact non-boolean int ``-1`` to ``None`` (see
        ``_auth/cookie_semantics.py``), so ``None`` is the canonical in-memory
        session form the whole auth layer already uses. Playwright's file format
        spells the same thing ``-1``, which is what ``to_storage_state`` emits.
        Pinning both halves keeps a future edit from "simplifying" one into the
        other and silently turning session cookies into dated ones.
        """
        jar = CookieJar.from_rookiepy(
            [{"name": "SID", "value": "s", "domain": ".google.com", "path": "/", "expires": None}]
        )
        assert next(iter(jar)).expires is None
        assert jar.to_storage_state()["cookies"][0]["expires"] == -1

    def test_dated_minus_one_is_not_a_session_cookie(self) -> None:
        """``-1.0`` / ``"-1"`` are dated values, not the session sentinel.

        The distinction is load-bearing enough that ``normalize_cookie_expiry``
        calls it out explicitly; assert the jar inherits it rather than
        flattening every -1-ish input to the sentinel.
        """
        jar = CookieJar.from_storage_state(
            {"cookies": [{"name": "SID", "value": "s", "domain": ".google.com", "expires": -1.0}]}
        )
        assert next(iter(jar)).expires == -1.0
        assert next(iter(jar)).expires is not None

    @pytest.mark.parametrize(
        "shape",
        [
            pytest.param({("SID", ".google.com", "/"): "v"}, id="path-aware-3-tuple"),
            pytest.param({("SID", ".google.com"): "v"}, id="legacy-2-tuple"),
            pytest.param({"SID": "v"}, id="flat"),
        ],
    )
    def test_from_domain_map_widens_every_legacy_shape(self, shape: dict) -> None:
        """All three legacy map shapes widen exactly as normalize_cookie_map does."""
        assert CookieJar.from_domain_map(shape).to_domain_map() == (
            _auth_cookies.normalize_cookie_map(shape)
        )


class TestConverterEquivalence:
    def test_no_flat_map_method_is_exposed(self) -> None:
        """Flattening is legacy-only and must NOT be on the canonical type.

        ``name -> value`` collapses the path component (#369) and picks an
        arbitrary winner among same-tier domains, so the survivor changes when
        storage_state is reordered (#2054) — ``AuthTokens.flat_cookies`` says as
        much in its own docstring. Every remaining caller is back-compat. Pinned
        as a test because "add a convenience to_flat_map()" is the obvious,
        wrong-looking-right change for a future contributor to make.
        """
        assert not hasattr(CookieJar, "to_flat_map")

    def test_to_httpx_matches_build_cookie_jar(self) -> None:
        jar = CookieJar.from_storage_state(_storage_state())
        expected = _auth_cookies.build_cookie_jar(cookies=jar.to_domain_map())
        actual = jar.to_httpx()
        as_identity = lambda j: sorted(  # noqa: E731
            (c.name, c.domain, c.path, c.value) for c in j.jar
        )
        assert as_identity(actual) == as_identity(expected)

    def test_storage_state_round_trip_is_stable(self) -> None:
        """Re-reading a jar's own storage_state yields the same jar.

        Not a claim that the ORIGINAL file round-trips — the allowlist filter
        drops rows on the way in (documented in the module docstring). What
        must hold is idempotence from the filtered view onward, so a jar that
        is written and re-read is unchanged.
        """
        jar = CookieJar.from_storage_state(_storage_state())
        assert CookieJar.from_storage_state(jar.to_storage_state()) == jar

    def test_to_storage_state_preserves_flags_and_expiry(self) -> None:
        jar = CookieJar.from_storage_state(_storage_state())
        row = next(c for c in jar.to_storage_state()["cookies"] if c["name"] == "__Secure-1PSIDTS")
        assert row["expires"] == 1800000000
        assert row["httpOnly"] is True
        assert row["secure"] is True

    def test_to_storage_state_preserves_same_site(self) -> None:
        """A stored ``sameSite`` survives the jar.

        Losing one is the regression ``storage._preserved_same_site`` exists to
        prevent, and ``convert_rookiepy_cookies_to_storage_state`` documents
        preserving it — so a jar that silently dropped it would reintroduce the
        bug through the type meant to become canonical.
        """
        jar = CookieJar.from_storage_state(
            {
                "cookies": [
                    {
                        "name": "SID",
                        "value": "s",
                        "domain": ".google.com",
                        "path": "/",
                        "sameSite": "Lax",
                    }
                ]
            }
        )
        assert next(iter(jar)).same_site == "Lax"
        assert jar.to_storage_state()["cookies"][0]["sameSite"] == "Lax"

    def test_to_storage_state_omits_same_site_when_the_row_had_none(self) -> None:
        """Absent stays absent: the jar must not invent a default.

        ``_preserved_same_site`` treats a missing value as "nothing to keep";
        emitting an invented ``"None"`` here would turn that into a real
        downgrade on the next merge.
        """
        jar = CookieJar.from_storage_state(
            {"cookies": [{"name": "SID", "value": "s", "domain": ".google.com", "path": "/"}]}
        )
        assert next(iter(jar)).same_site is None
        assert "sameSite" not in jar.to_storage_state()["cookies"][0]

    def test_from_rookiepy_matches_the_converters_same_site(self) -> None:
        """The jar route and the legacy converter agree on ``sameSite``."""
        rows = [
            {
                "name": "SID",
                "value": "s",
                "domain": ".google.com",
                "path": "/",
                "sameSite": "Strict",
            }
        ]
        legacy = _auth_cookies.convert_rookiepy_cookies_to_storage_state(rows)
        assert CookieJar.from_rookiepy(rows).to_storage_state() == legacy


class TestQueryEquivalence:
    def test_names_matches_cookie_names_from_storage(self) -> None:
        """The jar's name set equals the legacy reader's — on the FILTERED view.

        ``cookie_names_from_storage`` reads raw rows (no allowlist), so it is
        compared against the jar's own storage_state, which is the filtered
        view both then share.
        """
        jar = CookieJar.from_storage_state(_storage_state())
        assert jar.names() == _cookie_policy.cookie_names_from_storage(jar.to_storage_state())

    def test_has_secondary_binding_matches_policy(self) -> None:
        jar = CookieJar.from_storage_state(_storage_state())
        assert jar.has_secondary_binding() == _cookie_policy._has_valid_secondary_binding(
            jar.names()
        )
        assert jar.has_secondary_binding() is True

    def test_is_rotatable_matches_policy(self) -> None:
        jar = CookieJar.from_storage_state(_storage_state())
        assert jar.is_rotatable() == _cookie_policy._has_rotatable_secondary_binding(jar.names())

    def test_validate_required_passes_on_a_complete_jar(self) -> None:
        CookieJar.from_storage_state(_storage_state()).validate_required()

    def test_validate_required_raises_the_canonical_error(self) -> None:
        """The raise is the policy's own error type, not a lookalike."""
        state = _storage_state()
        state["cookies"] = [c for c in state["cookies"] if c["name"] != "__Secure-1PSIDTS"]
        jar = CookieJar.from_storage_state(state)
        with pytest.raises(_cookie_policy.RequiredCookieValidationError) as excinfo:
            jar.validate_required()
        assert "__Secure-1PSIDTS" in str(excinfo.value)

    def test_missing_hint_matches_policy(self) -> None:
        state = _storage_state()
        state["cookies"] = [c for c in state["cookies"] if c["name"] != "SID"]
        jar = CookieJar.from_storage_state(state)
        assert jar.missing_hint(browser_label="chrome") == _cookie_policy.missing_cookies_hint(
            jar.names(), browser_label="chrome"
        )


class TestContainerAndSafety:
    def test_empty_jar_is_falsy_and_empty(self) -> None:
        jar = CookieJar()
        assert not jar
        assert len(jar) == 0
        assert jar.names() == set()

    def test_iteration_yields_cookie_objects(self) -> None:
        jar = CookieJar.from_storage_state(_storage_state())
        assert all(isinstance(c, Cookie) for c in jar)
        assert len(jar) == len(jar.to_storage_state()["cookies"])

    def test_cookie_identity_is_rfc6265_triple(self) -> None:
        c = Cookie(name="SID", domain=".google.com", path="/x", value="v")
        assert c.identity == ("SID", ".google.com", "/x")

    def test_same_name_different_path_are_independent(self) -> None:
        """#369: a path-distinct twin must not shadow its sibling."""
        jar = CookieJar.from_storage_state(
            {
                "cookies": [
                    {"name": "SID", "value": "root", "domain": ".google.com", "path": "/"},
                    {"name": "SID", "value": "scoped", "domain": ".google.com", "path": "/app"},
                ]
            }
        )
        assert len(jar.to_domain_map()) == 2

    def test_repr_redacts_cookie_values(self) -> None:
        """Values are credential-equivalent and must never reach logs/diffs."""
        jar = CookieJar.from_storage_state(_storage_state())
        rendered = repr(jar)
        assert "sid-base" not in rendered
        assert "psidts" not in rendered
        assert "SID" in rendered  # names are safe and useful

    def test_jar_is_immutable_from_the_outside(self) -> None:
        """Mutating a derived map must not write through to the jar."""
        jar = CookieJar.from_storage_state(_storage_state())
        before = jar.names()
        jar.to_domain_map()[("INJECTED", "x", "/")] = "v"
        assert jar.names() == before
