"""Tests for ``packages.sca.registry_metadata_walk``.

Stubs the HttpClient at the registry boundary so no real PyPI / npm
/ crates.io traffic fires. Validates per-ecosystem parsing + the
recursive walk's cycle detection / depth bound / cache behaviour.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.http import HttpError
from core.json import JsonCache
from packages.sca.models import Confidence, Dependency, PinStyle
from packages.sca.registry_metadata_walk import (
    _lower_bound,
    _norm_name,
    walk_transitive,
)


def _direct(eco: str, name: str, version: str = "1.0.0") -> Dependency:
    return Dependency(
        ecosystem=eco, name=name, version=version,
        declared_in=Path("/x/manifest"),
        scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=True,
        purl=f"pkg:{eco.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


class _StubHttp:
    """Records URLs hit + serves canned JSON per URL prefix.

    Each entry maps a URL substring to either:
      - A dict (returned verbatim for any URL containing the substring)
      - A list of dicts (consumed in order)
      - A callable taking the URL and returning a dict
    """

    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self.calls: list[str] = []

    def get_json(self, url: str, *args, **kwargs) -> Any:
        self.calls.append(url)
        for key, body in self._responses.items():
            if key in url:
                if callable(body):
                    return body(url)
                if isinstance(body, list):
                    if not body:
                        raise HttpError(f"no more responses for {url}")
                    return body.pop(0)
                return body
        raise HttpError(f"no canned response for {url}")


# ---------------------------------------------------------------------------
# _lower_bound
# ---------------------------------------------------------------------------

def test_lower_bound_handles_pep440_specs():
    assert _lower_bound(">=1.2.3") == "1.2.3"
    assert _lower_bound("==1.2.3") == "1.2.3"
    assert _lower_bound("~=1.2") == "1.2"
    assert _lower_bound(">=1.2,<2.0") == "1.2"
    assert _lower_bound(">=1.0,!=1.5") == "1.0"


def test_lower_bound_handles_npm_semver():
    assert _lower_bound("^1.2.3") == "1.2.3"
    assert _lower_bound("~1.2.3") == "1.2.3"
    assert _lower_bound(">=2.0.0") == "2.0.0"


def test_lower_bound_handles_cargo_semver():
    assert _lower_bound("^1") == "1"
    assert _lower_bound("0.4.5") == "0.4.5"   # bare version = exact match


def test_lower_bound_returns_none_for_unparseable():
    """Wildcards / pure exclusions / branch refs have no version-pickable
    lower bound — the caller emits the dep with version=None."""
    assert _lower_bound("*") is None
    assert _lower_bound("any") is None
    assert _lower_bound("") is None
    assert _lower_bound("!=1.0") is None
    assert _lower_bound("main") is None      # git-branch ref


def test_lower_bound_strips_pep508_extras_and_markers():
    # The fetcher already strips ``[extras]`` and ``;markers`` before
    # passing to _lower_bound; sanity that bare specs work.
    assert _lower_bound(">=1.0.0  ") == "1.0.0"


# ---------------------------------------------------------------------------
# _norm_name
# ---------------------------------------------------------------------------

def test_norm_name_pep503_for_pypi():
    assert _norm_name("Pillow", "PyPI") == "pillow"
    assert _norm_name("python-dateutil", "PyPI") == "python-dateutil"
    assert _norm_name("python_dateutil", "PyPI") == "python-dateutil"
    assert _norm_name("Python.dateutil", "PyPI") == "python-dateutil"


def test_norm_name_lowercases_npm():
    assert _norm_name("Lodash", "npm") == "lodash"
    assert _norm_name("@scope/Pkg", "npm") == "@scope/pkg"


def test_norm_name_preserves_cargo_case():
    assert _norm_name("Serde_JSON", "crates.io") == "Serde_JSON"


# ---------------------------------------------------------------------------
# walk_transitive — PyPI
# ---------------------------------------------------------------------------

def test_pypi_walks_one_level_of_transitive():
    """``pydantic==2.9.2`` declares typing-extensions, annotated-types,
    pydantic-core. All three should land as transitives."""
    pydantic_meta = {"info": {"requires_dist": [
        "typing-extensions>=4.6.1",
        "annotated-types>=0.6.0",
        "pydantic-core==2.23.4",
    ]}}
    # Children all return empty deps.
    leaf = {"info": {"requires_dist": []}}
    http = _StubHttp({
        "/pypi/pydantic/2.9.2/json": pydantic_meta,
        "/pypi/typing-extensions/4.6.1/json": leaf,
        "/pypi/annotated-types/0.6.0/json": leaf,
        "/pypi/pydantic-core/2.23.4/json": leaf,
    })
    result = walk_transitive(
        [_direct("PyPI", "pydantic", "2.9.2")],
        http=http,
    )
    names = {d.name for d in result.deps_added}
    assert names == {"typing-extensions", "annotated-types", "pydantic-core"}
    assert all(d.source_kind == "metadata_walk" for d in result.deps_added)
    assert all(d.direct is False for d in result.deps_added)
    assert all(d.parser_confidence.level == "low" for d in result.deps_added)


def test_pypi_does_not_re_emit_direct_deps_as_transitive():
    """If a direct dep is itself in some other dep's requires_dist,
    skip it — the operator already declared it.

    NOTE the version strings match exactly; the visited check is
    string-equality, not PEP 440 version-equivalence (a direct dep at
    ``1.0`` whose parent declares ``>=1.0.0`` would currently get
    re-emitted — see ``walk_transitive`` docstring for the
    deferred-normalisation note).
    """
    a_meta = {"info": {"requires_dist": ["b>=1.0"]}}
    b_meta = {"info": {"requires_dist": []}}
    http = _StubHttp({
        "/pypi/a/1.0/json": a_meta,
        "/pypi/b/1.0/json": b_meta,
    })
    deps = [
        _direct("PyPI", "a", "1.0"),
        _direct("PyPI", "b", "1.0"),     # also direct
    ]
    result = walk_transitive(deps, http=http)
    # b would be a transitive of a, but it's already direct → skip.
    assert all(d.name != "b" for d in result.deps_added)


def test_pypi_includes_extras_only_entries():
    """``foo ; extra == 'test'`` — included, per the module's
    always-true marker semantics: the walk cannot know which extras
    the target environment installed, and skipping meant an installed
    extras-gated transitive with a CVE was invisible. Over-inclusion
    is the scanner-safe direction."""
    meta = {"info": {"requires_dist": [
        "real-dep>=1.0.0",
        "extras-only-dep>=1.0.0 ; extra == 'test'",
    ]}}
    http = _StubHttp({
        "/pypi/x/1.0/json": meta,
        "/pypi/real-dep/1.0.0/json": {"info": {"requires_dist": []}},
        "/pypi/extras-only-dep/1.0.0/json": {"info": {"requires_dist": []}},
    })
    result = walk_transitive([_direct("PyPI", "x", "1.0")], http=http)
    assert {d.name for d in result.deps_added} == {
        "real-dep", "extras-only-dep",
    }


def test_pypi_two_levels_deep():
    """A → B → C; we should see both B and C as transitives."""
    a = {"info": {"requires_dist": ["b>=1.0"]}}
    b = {"info": {"requires_dist": ["c>=1.0"]}}
    c = {"info": {"requires_dist": []}}
    http = _StubHttp({
        "/pypi/a/1.0/json": a,
        "/pypi/b/1.0/json": b,
        "/pypi/c/1.0/json": c,
    })
    result = walk_transitive([_direct("PyPI", "a", "1.0")], http=http)
    assert {d.name for d in result.deps_added} == {"b", "c"}


def test_pypi_cycle_detection():
    """A → B → A. Walker visits B once and stops."""
    a = {"info": {"requires_dist": ["b>=1.0"]}}
    b = {"info": {"requires_dist": ["a>=1.0"]}}     # cycle back to a
    http = _StubHttp({
        "/pypi/a/1.0/json": a,
        "/pypi/b/1.0/json": b,
    })
    result = walk_transitive([_direct("PyPI", "a", "1.0")], http=http)
    # Only "b" added; "a" is already in the visited set as a direct dep.
    names = {d.name for d in result.deps_added}
    assert "b" in names
    assert "a" not in names


def test_walk_respects_max_depth():
    """A → B → C → D → ... — max_depth=1 stops after B."""
    chain = ["b", "c", "d", "e"]
    responses = {
        "/pypi/a/1.0/json": {"info": {"requires_dist": ["b>=1.0"]}},
    }
    for i, n in enumerate(chain):
        nxt = chain[i + 1] if i + 1 < len(chain) else None
        responses[f"/pypi/{n}/1.0/json"] = {"info": {
            "requires_dist": [f"{nxt}>=1.0"] if nxt else [],
        }}
    http = _StubHttp(responses)
    result = walk_transitive(
        [_direct("PyPI", "a", "1.0")], http=http, max_depth=1,
    )
    # depth=0 is `a`; depth=1 is `b` (its children NOT walked).
    assert "b" in {d.name for d in result.deps_added}
    assert "c" not in {d.name for d in result.deps_added}


# ---------------------------------------------------------------------------
# walk_transitive — npm
# ---------------------------------------------------------------------------

def test_npm_walks_dependencies_and_peer_deps():
    """``dependencies`` and ``peerDependencies`` both walked; peer deps
    are commonly the supply-chain delivery vehicle."""
    meta = {
        "dependencies": {"axios": "^0.21.0"},
        "peerDependencies": {"react": ">=18.0.0"},
        "devDependencies": {"jest": "^29.0.0"},   # NOT walked
    }
    leaf = {"dependencies": {}}
    http = _StubHttp({
        "/registry.npmjs.org/myapp/1.0.0": meta,
        "/registry.npmjs.org/axios/0.21.0": leaf,
        "/registry.npmjs.org/react/18.0.0": leaf,
    })
    result = walk_transitive(
        [_direct("npm", "myapp", "1.0.0")], http=http,
    )
    names = {d.name for d in result.deps_added}
    assert names == {"axios", "react"}     # jest excluded


def test_npm_walks_optional_dependencies():
    meta = {
        "dependencies": {},
        "optionalDependencies": {"fsevents": "^2.0.0"},
    }
    leaf = {"dependencies": {}}
    http = _StubHttp({
        "/registry.npmjs.org/myapp/1.0.0": meta,
        "/registry.npmjs.org/fsevents/2.0.0": leaf,
    })
    result = walk_transitive(
        [_direct("npm", "myapp", "1.0.0")], http=http,
    )
    assert {d.name for d in result.deps_added} == {"fsevents"}


# ---------------------------------------------------------------------------
# walk_transitive — crates.io
# ---------------------------------------------------------------------------

def test_cargo_walks_only_normal_deps():
    """Cargo's registry returns dev / build / normal kinds. Walker
    only follows ``normal`` so the transitive set matches what
    ``cargo build`` actually links into the binary."""
    meta = {"dependencies": [
        {"crate_id": "serde", "req": "^1.0", "kind": "normal"},
        {"crate_id": "tempfile", "req": "^3.0", "kind": "dev"},
        {"crate_id": "cc", "req": "^1.0", "kind": "build"},
    ]}
    leaf = {"dependencies": []}
    http = _StubHttp({
        "/api/v1/crates/myapp/1.0.0/dependencies": meta,
        "/api/v1/crates/serde/1.0/dependencies": leaf,
    })
    result = walk_transitive(
        [_direct("crates.io", "myapp", "1.0.0")], http=http,
    )
    assert {d.name for d in result.deps_added} == {"serde"}


def test_cargo_skips_optional_deps():
    """``optional=True`` means Cargo only pulls it in if a feature
    flag is enabled. Don't walk; we don't track features."""
    meta = {"dependencies": [
        {"crate_id": "rayon", "req": "^1.5", "kind": "normal",
         "optional": True},
        {"crate_id": "log", "req": "^0.4", "kind": "normal"},
    ]}
    leaf = {"dependencies": []}
    http = _StubHttp({
        "/api/v1/crates/myapp/1.0.0/dependencies": meta,
        "/api/v1/crates/log/0.4/dependencies": leaf,
    })
    result = walk_transitive(
        [_direct("crates.io", "myapp", "1.0.0")], http=http,
    )
    assert {d.name for d in result.deps_added} == {"log"}


# ---------------------------------------------------------------------------
# Caching + failure isolation
# ---------------------------------------------------------------------------

def test_walk_caches_metadata_per_name_version(tmp_path):
    """Same (name, version) hit twice → second call uses the cache,
    no extra HTTP request."""
    http = _StubHttp({
        "/pypi/a/1.0/json": {"info": {"requires_dist": []}},
    })
    cache = JsonCache(root=tmp_path / "cache")
    walk_transitive(
        [_direct("PyPI", "a", "1.0")], http=http, cache=cache,
    )
    n_after_first = len(http.calls)
    walk_transitive(
        [_direct("PyPI", "a", "1.0")], http=http, cache=cache,
    )
    assert len(http.calls) == n_after_first, (
        "expected cache hit, but HTTP fired again"
    )


def test_fetcher_failure_does_not_break_walk():
    """Registry hiccup on one transitive shouldn't fail the whole walk."""
    http = _StubHttp({
        "/pypi/a/1.0/json": {"info": {
            "requires_dist": ["good>=1.0", "missing>=1.0"],
        }},
        "/pypi/good/1.0/json": {"info": {"requires_dist": []}},
        # 'missing' has no canned response → fetcher raises.
    })
    result = walk_transitive([_direct("PyPI", "a", "1.0")], http=http)
    names = {d.name for d in result.deps_added}
    # The "missing" dep IS still emitted — we just couldn't recurse
    # into its own deps. Operator gets to see it.
    assert "good" in names
    assert "missing" in names
    assert result.failures >= 1


def test_unsupported_ecosystem_silently_skipped():
    """Cargo's a supported ecosystem; ``hex`` (Erlang) isn't. The walk
    just doesn't visit hex deps — no error."""
    http = _StubHttp({
        # Cargo seeds → walk; hex seeds → skipped.
        "/api/v1/crates/serde/1.0/dependencies": {"dependencies": []},
    })
    deps = [
        _direct("crates.io", "serde", "1.0"),
        _direct("Hex", "phoenix", "1.7.0"),
    ]
    result = walk_transitive(deps, http=http)
    # Just no transitives discovered for hex; serde walked fine.
    assert result.failures == 0


def test_ecosystems_filter_restricts_walk():
    """``ecosystems={'PyPI'}`` walks only PyPI deps; npm seeds skipped."""
    http = _StubHttp({
        "/pypi/a/1.0/json": {"info": {"requires_dist": []}},
        # No npm canned response — would fail if walked.
    })
    deps = [
        _direct("PyPI", "a", "1.0"),
        _direct("npm", "lodash", "4.17.21"),
    ]
    result = walk_transitive(deps, http=http, ecosystems={"PyPI"})
    assert result.failures == 0


def test_walk_emits_dep_with_breadcrumb_to_host_manifest():
    """Each transitive's ``declared_in`` points at the host manifest
    of the first direct dep in the ecosystem — gives operators a
    breadcrumb back to "where did this come from"."""
    http = _StubHttp({
        "/pypi/a/1.0/json": {"info": {"requires_dist": ["b>=1.0"]}},
        "/pypi/b/1.0/json": {"info": {"requires_dist": []}},
    })
    direct = _direct("PyPI", "a", "1.0")
    direct.__dict__["declared_in"] = Path("/proj/requirements.txt")
    result = walk_transitive([direct], http=http)
    transitive = next(d for d in result.deps_added if d.name == "b")
    assert transitive.declared_in == Path("/proj/requirements.txt")


# ---------------------------------------------------------------------------
# walk_transitive — total-visit + per-node fan-out caps
# ---------------------------------------------------------------------------

def test_walk_visit_cap_truncates_and_records():
    """A deep chain hits ``max_visits``; the result records the drop
    instead of silently presenting partial coverage as complete."""
    chain = ["a", "b", "c", "d", "e", "f", "g", "h"]
    responses = {}
    for i, n in enumerate(chain):
        nxt = chain[i + 1] if i + 1 < len(chain) else None
        responses[f"/pypi/{n}/1.0/json"] = {"info": {
            "requires_dist": [f"{nxt}>=1.0"] if nxt else [],
        }}
    http = _StubHttp(responses)
    result = walk_transitive(
        [_direct("PyPI", "a", "1.0")], http=http,
        max_depth=99, max_visits=3,
    )
    assert result.visits == 3
    assert result.truncated is True
    assert result.visits_capped >= 1
    # Only the lookups inside the budget produced deps.
    assert {d.name for d in result.deps_added} == {"b", "c", "d"}


def test_walk_fanout_cap_truncates_and_records():
    """A node declaring more children than ``max_fanout`` only
    contributes the first ``max_fanout``; the drop is recorded."""
    children = [f"c{i}" for i in range(10)]
    responses = {
        "/pypi/a/1.0/json": {"info": {
            "requires_dist": [f"{c}>=1.0" for c in children],
        }},
    }
    for c in children:
        responses[f"/pypi/{c}/1.0/json"] = {"info": {"requires_dist": []}}
    http = _StubHttp(responses)
    result = walk_transitive(
        [_direct("PyPI", "a", "1.0")], http=http, max_fanout=3,
    )
    assert result.truncated is True
    assert result.fanout_capped == 7
    assert {d.name for d in result.deps_added} == {"c0", "c1", "c2"}


def test_walk_within_caps_reports_complete_coverage():
    """No cap fired → ``truncated=False`` and zero capped counts, so
    consumers can distinguish bounded from complete walks."""
    responses = {
        "/pypi/a/1.0/json": {"info": {"requires_dist": ["b>=1.0"]}},
        "/pypi/b/1.0/json": {"info": {"requires_dist": []}},
    }
    http = _StubHttp(responses)
    result = walk_transitive([_direct("PyPI", "a", "1.0")], http=http)
    assert result.truncated is False
    assert result.visits_capped == 0
    assert result.fanout_capped == 0


def test_walk_default_caps_are_bounded():
    """The defaults must stay proportionate to the walk's purpose —
    an approximation pass, not a full closure."""
    from packages.sca.registry_metadata_walk import (
        DEFAULT_MAX_FANOUT,
        DEFAULT_MAX_VISITS,
    )
    assert 0 < DEFAULT_MAX_VISITS <= 500
    assert 0 < DEFAULT_MAX_FANOUT <= 100


# ---------------------------------------------------------------------------
# degenerate dep names must never abort the scan
# ---------------------------------------------------------------------------


def test_degenerate_dep_name_does_not_abort_walk(tmp_path):
    """A hostile dep literally named ``..`` (or ``.``, or ``""``) used
    to raise ValueError out of JsonCache and abort the whole scan; the
    cache-key components are now encoded past the degenerate-segment
    refusal."""
    http = _StubHttp({
        "/pypi/a/1.0/json": {"info": {"requires_dist": []}},
    })
    cache = JsonCache(root=tmp_path / "cache")
    for name in ("..", ".", ""):
        result = walk_transitive(
            [_direct("PyPI", name, "1.0")], http=http, cache=cache,
        )
        assert result is not None  # walk completed — no abort


def test_cache_key_component_injective_and_safe():
    from packages.sca.registry_metadata_walk import _cache_key_component

    # Degenerate segments neutralised.
    assert _cache_key_component("..") == "%2E%2E"
    assert _cache_key_component(".") == "%2E"
    assert _cache_key_component("") == "(empty)"
    # Injective: inputs that would collide under flattening stay apart.
    assert _cache_key_component("a/b") != _cache_key_component("a_b")
    assert _cache_key_component("%2E") != _cache_key_component(".")
    assert _cache_key_component("(empty)") != _cache_key_component("")
    # Plain names unchanged.
    assert _cache_key_component("requests") == "requests"
