"""Tests for the reachability orchestrator (``packages.sca.reachability``)."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import Confidence, Dependency, PinStyle
from packages.sca.reachability import scan


def _dep(name: str, ecosystem: str = "PyPI",
         path: Path = Path("/x/manifest"),
         version: str = "1.0.0") -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=path,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def test_scan_dispatches_to_python_and_npm(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import requests\n", encoding="utf-8")
    (repo / "client.js").write_text("require('lodash');\n", encoding="utf-8")
    deps = [
        _dep("requests", ecosystem="PyPI"),
        _dep("django", ecosystem="PyPI"),
        _dep("lodash", ecosystem="npm"),
        _dep("missing-pkg", ecosystem="npm"),
    ]
    out = scan(repo, deps)
    assert out[deps[0].key()].verdict == "imported"
    assert out[deps[1].key()].verdict == "not_reachable"
    assert out[deps[2].key()].verdict == "imported"
    assert out[deps[3].key()].verdict == "not_reachable"


def test_unsupported_ecosystem_returns_not_evaluated(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    # Debian deps come from inline-installs (Dockerfile RUN apt-get
    # install) — no source-tree module-level scanner exists for
    # them today; verify the orchestrator stays honest.
    deps = [_dep("nginx", ecosystem="Debian")]
    out = scan(repo, deps)
    assert out[deps[0].key()].verdict == "not_evaluated"
    assert "not implemented for Debian" in out[deps[0].key()].confidence.reason


def test_scanner_failure_falls_back_to_not_evaluated(tmp_path: Path,
                                                     monkeypatch) -> None:
    from packages.sca.reachability import _HANDLERS

    def boom(_p):
        raise RuntimeError("synthetic")

    repo = tmp_path / "repo"
    repo.mkdir()

    monkeypatch.setitem(
        _HANDLERS, "PyPI",
        (boom, _HANDLERS["PyPI"][1]),
    )
    deps = [_dep("requests", ecosystem="PyPI")]
    out = scan(repo, deps)
    assert out[deps[0].key()].verdict == "not_evaluated"


def test_same_dep_resolved_once_per_ecosystem(tmp_path: Path,
                                               monkeypatch) -> None:
    """Multiple version rows for the same package only invoke the
    resolver once."""
    from packages.sca.reachability import _HANDLERS

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import requests\n", encoding="utf-8")

    calls = {"n": 0}
    real_scanner, real_resolver = _HANDLERS["PyPI"]

    def counting_resolver(name, scan_result, target=None):
        calls["n"] += 1
        return real_resolver(name, scan_result, target)

    monkeypatch.setitem(_HANDLERS, "PyPI", (real_scanner, counting_resolver))

    deps = [
        _dep("requests"),
        _dep("requests"),    # duplicate same name, different "row"
    ]
    scan(repo, deps)
    assert calls["n"] == 1


# ---------------------------------------------------------------------------
# Tier-3 escalation: PyPI not_reachable + CVE-bearing → wheel fetch
# ---------------------------------------------------------------------------

def test_tier3_escalation_fires_for_pypi_cve_not_reachable(
    tmp_path, monkeypatch,
):
    """A PyPI dep that's CVE-bearing AND came up not_reachable in
    tiers 1+2 must trigger ``python_modules.resolve_modules`` with
    the right ``(name, version, http, cache)``."""
    repo = tmp_path / "repo"
    repo.mkdir()
    # Empty source — nothing imported at all → PyPI deps land as
    # not_reachable from tier 1+2.
    (repo / "app.py").write_text("", encoding="utf-8")

    captured = []

    def fake_resolve_modules(name, version, *, http, cache=None,
                              max_wheel_bytes=None):
        captured.append({
            "name": name, "version": version,
            "http_is_set": http is not None,
            "cache_is_set": cache is not None,
        })
        # Return a module name that ALSO isn't in the empty scan —
        # the verdict should remain not_reachable (we're testing
        # the wiring, not the resolver).
        return ("unknown_module",)

    monkeypatch.setattr(
        "packages.sca.python_modules.resolve_modules",
        fake_resolve_modules,
    )

    deps = [_dep("mystery-pkg", version="1.2.3")]
    cve_keys = {deps[0].key()}
    fake_http = object()
    fake_cache = object()

    scan(
        repo, deps,
        http=fake_http, cache=fake_cache, cve_dep_keys=cve_keys,
    )

    assert len(captured) == 1, f"expected 1 wheel fetch, got {captured}"
    assert captured[0]["name"] == "mystery-pkg"
    assert captured[0]["version"] == "1.2.3"
    assert captured[0]["http_is_set"]
    assert captured[0]["cache_is_set"]


def test_tier3_skipped_for_non_cve_deps(tmp_path, monkeypatch):
    """A PyPI not_reachable dep that ISN'T in cve_dep_keys must
    NOT trigger the wheel fetch — that's the cost-control gate."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("", encoding="utf-8")

    captured = []

    def boom_if_called(name, version, *, http, cache=None,
                        max_wheel_bytes=None):
        captured.append(name)
        return None

    monkeypatch.setattr(
        "packages.sca.python_modules.resolve_modules",
        boom_if_called,
    )

    deps = [_dep("clean-pkg", version="1.0")]
    scan(
        repo, deps,
        http=object(), cve_dep_keys=set(),     # no CVE-bearing deps
    )
    assert captured == [], (
        "wheel fetch fired despite empty cve_dep_keys"
    )


def test_tier3_skipped_when_dep_already_imported(tmp_path, monkeypatch):
    """A PyPI dep that came back ``imported`` from tier 1/2 doesn't
    need the wheel fetch — escalation only upgrades not_reachable."""
    repo = tmp_path / "repo"
    repo.mkdir()
    # `import requests` resolves via tier 1 (curated map / PEP 503).
    (repo / "app.py").write_text("import requests\n", encoding="utf-8")

    captured = []

    def track(name, version, *, http, cache=None, max_wheel_bytes=None):
        captured.append(name)
        return None

    monkeypatch.setattr(
        "packages.sca.python_modules.resolve_modules", track,
    )

    deps = [_dep("requests", version="2.31.0")]
    cve_keys = {deps[0].key()}
    scan(
        repo, deps,
        http=object(), cve_dep_keys=cve_keys,
    )
    assert "requests" not in captured, (
        f"wheel fetch fired for an already-imported dep: {captured}"
    )


def test_tier3_skipped_for_non_pypi_ecosystems(tmp_path, monkeypatch):
    """Other ecosystems' resolvers don't yet support wheel-style
    on-demand metadata; the escalation pass must skip them entirely."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Cargo.toml").write_text("", encoding="utf-8")

    captured = []

    def track(name, version, *, http, cache=None, max_wheel_bytes=None):
        captured.append(name)
        return None

    monkeypatch.setattr(
        "packages.sca.python_modules.resolve_modules", track,
    )

    cargo_dep = _dep("serde", ecosystem="Cargo", version="1.0")
    cve_keys = {cargo_dep.key()}
    scan(
        repo, [cargo_dep],
        http=object(), cve_dep_keys=cve_keys,
    )
    assert captured == [], (
        f"wheel fetch fired for non-PyPI dep: {captured}"
    )


def test_tier3_failed_fetch_downgrades_to_not_evaluated(
    tmp_path, monkeypatch,
):
    """When resolve_modules returns None (any reason — server didn't
    honour Range, wheel too big, sdist-only, parse error), the dep's
    verdict must downgrade from not_reachable to not_evaluated. The
    risk-score multiplier difference is significant, so this is a
    correctness contract not just a cosmetic verdict choice."""
    from packages.sca.reachability import scan
    from packages.sca.models import Reachability

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("", encoding="utf-8")

    def fake_resolve_modules(name, version, *, http, cache=None,
                              max_wheel_bytes=None):
        return None        # simulate any failure mode

    monkeypatch.setattr(
        "packages.sca.python_modules.resolve_modules",
        fake_resolve_modules,
    )

    deps = [_dep("mystery-pkg", version="1.0")]
    cve_keys = {deps[0].key()}
    out = scan(repo, deps, http=object(), cve_dep_keys=cve_keys)
    verdict: Reachability = out[deps[0].key()]
    assert verdict.verdict == "not_evaluated", (
        f"got {verdict.verdict}, want not_evaluated — failed tier-3 "
        f"fetch should downgrade verdict for honest risk-scoring"
    )
    assert "tier-3" in (verdict.confidence.reason or "")


def test_tier3_modules_not_in_scan_downgrades_to_not_evaluated(
    tmp_path, monkeypatch,
):
    """Wheel fetched successfully but the modules it lists don't
    appear in the project scan. Same honest verdict as a fetch
    failure: tier-3 ran, didn't help — not_evaluated."""
    from packages.sca.reachability import scan

    repo = tmp_path / "repo"
    repo.mkdir()
    # Project imports nothing relevant.
    (repo / "app.py").write_text("import argparse\n", encoding="utf-8")

    def fake_resolve_modules(name, version, *, http, cache=None,
                              max_wheel_bytes=None):
        # Return a module that's NOT in the scan.
        return ("never_imported_module",)

    monkeypatch.setattr(
        "packages.sca.python_modules.resolve_modules",
        fake_resolve_modules,
    )

    deps = [_dep("mystery-pkg", version="1.0")]
    cve_keys = {deps[0].key()}
    out = scan(repo, deps, http=object(), cve_dep_keys=cve_keys)
    assert out[deps[0].key()].verdict == "not_evaluated"


def test_tier3_success_yields_imported_verdict(tmp_path, monkeypatch):
    """Positive case: wheel fetch returns modules that DO match the
    scan → verdict upgrades to imported (the whole point of tier-3)."""
    from packages.sca.reachability import scan

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import obscure_internal_name\n", encoding="utf-8")

    def fake_resolve_modules(name, version, *, http, cache=None,
                              max_wheel_bytes=None):
        return ("obscure_internal_name",)

    monkeypatch.setattr(
        "packages.sca.python_modules.resolve_modules",
        fake_resolve_modules,
    )

    deps = [_dep("opaque-dist-name", version="1.0")]
    cve_keys = {deps[0].key()}
    out = scan(repo, deps, http=object(), cve_dep_keys=cve_keys)
    assert out[deps[0].key()].verdict == "imported"


# ---------------------------------------------------------------------------
# Go function-level reachability (osv_results → advisory symbols)
# ---------------------------------------------------------------------------

class _FakeOsvResult:
    """Minimal stand-in for an OSV query result with advisory symbols."""
    def __init__(self, dep_key, advisories):
        self.dep_key = dep_key
        self.advisories = advisories


class _FakeAdvisory:
    def __init__(self, ecosystem_specific=None):
        self.ecosystem_specific = ecosystem_specific


def test_go_advisory_symbols_upgrade_to_likely_called(tmp_path: Path) -> None:
    """When OSV advisories carry symbols that appear in the Go source,
    the verdict should be ``likely_called`` instead of ``imported``."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.go").write_text(
        'package main\n\n'
        'import "golang.org/x/crypto/ssh"\n\n'
        'func main() {\n\tssh.ParsePrivateKey(nil)\n}\n',
        encoding="utf-8",
    )
    dep = _dep("golang.org/x/crypto", ecosystem="Go", version="0.10.0")
    osv_results = [
        _FakeOsvResult(
            dep_key=dep.key(),
            advisories=[
                _FakeAdvisory(ecosystem_specific={
                    "imports": [
                        {"path": "golang.org/x/crypto/ssh",
                         "symbols": ["ParsePrivateKey"]},
                    ],
                }),
            ],
        ),
    ]
    out = scan(repo, [dep], osv_results=osv_results)
    assert out[dep.key()].verdict == "likely_called"


def test_go_advisory_symbols_no_match_downgrades(tmp_path: Path) -> None:
    """Advisory symbols that don't appear in source: the
    function-level Go tier downgrades verdict from ``imported`` to
    ``not_function_reachable`` — operator has positive evidence
    the vulnerable code path isn't exercised."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.go").write_text(
        'package main\n\n'
        'import "golang.org/x/crypto/ssh"\n\n'
        'func main() {\n\tssh.Dial("tcp", "host:22", nil)\n}\n',
        encoding="utf-8",
    )
    dep = _dep("golang.org/x/crypto", ecosystem="Go", version="0.10.0")
    osv_results = [
        _FakeOsvResult(
            dep_key=dep.key(),
            advisories=[
                _FakeAdvisory(ecosystem_specific={
                    "imports": [
                        {"path": "golang.org/x/crypto/ssh",
                         "symbols": ["ParsePrivateKey"]},
                    ],
                }),
            ],
        ),
    ]
    out = scan(repo, [dep], osv_results=osv_results)
    assert out[dep.key()].verdict == "not_function_reachable"


def test_go_no_osv_results_falls_back_to_imported(tmp_path: Path) -> None:
    """Without osv_results, Go deps follow the normal imported/not_reachable path."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.go").write_text(
        'package main\n\nimport "github.com/pkg/errors"\n',
        encoding="utf-8",
    )
    dep = _dep("github.com/pkg/errors", ecosystem="Go")
    out = scan(repo, [dep])
    assert out[dep.key()].verdict == "imported"


def test_go_advisory_empty_symbols_stays_imported(tmp_path: Path) -> None:
    """Advisory with imports but empty symbols list: no upgrade possible."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.go").write_text(
        'package main\n\nimport "github.com/pkg/errors"\n',
        encoding="utf-8",
    )
    dep = _dep("github.com/pkg/errors", ecosystem="Go")
    osv_results = [
        _FakeOsvResult(
            dep_key=dep.key(),
            advisories=[
                _FakeAdvisory(ecosystem_specific={
                    "imports": [{"path": "github.com/pkg/errors", "symbols": []}],
                }),
            ],
        ),
    ]
    out = scan(repo, [dep], osv_results=osv_results)
    assert out[dep.key()].verdict == "imported"


# ---------------------------------------------------------------------------
# Tier-3 escalation: PyPI not_reachable + CVE-bearing → wheel fetch
# (continued)
# ---------------------------------------------------------------------------

def test_tier3_skipped_when_http_not_provided(tmp_path, monkeypatch):
    """Tests / pipelines that don't want network calls just don't
    pass http; the escalation must be inert in that case."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("", encoding="utf-8")

    captured = []

    def track(name, version, *, http, cache=None, max_wheel_bytes=None):
        captured.append(name)
        return None

    monkeypatch.setattr(
        "packages.sca.python_modules.resolve_modules", track,
    )

    deps = [_dep("mystery", version="1.0")]
    cve_keys = {deps[0].key()}
    scan(repo, deps, cve_dep_keys=cve_keys)   # no http kwarg
    assert captured == [], (
        f"wheel fetch fired without http: {captured}"
    )


def test_npm_alias_resolves_reachability_by_alias_spelling(
    tmp_path: Path,
) -> None:
    """An aliased dep (``"my-lodash": "npm:lodash@^4"``) is imported
    by its ALIAS (``require('my-lodash')``) — the real package's row
    must read as imported, not not_reachable."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "client.js").write_text(
        "require('my-lodash');\n", encoding="utf-8",
    )
    aliased = _dep("lodash", ecosystem="npm")
    aliased.alias_name = "my-lodash"
    plain = _dep("ms", ecosystem="npm")
    out = scan(repo, [aliased, plain])
    assert out[aliased.key()].verdict == "imported"
    assert out[plain.key()].verdict == "not_reachable"


def test_npm_alias_dual_declared_resolves_stronger_spelling(
    tmp_path: Path,
) -> None:
    """A canonical row can cover a plain AND an aliased declaration of
    the same package — either spelling's import must count. Alias-only
    resolution demoted a plainly-imported dual-declared package."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "client.js").write_text(
        "require('lodash');\n", encoding="utf-8",
    )
    dual = _dep("lodash", ecosystem="npm")
    dual.alias_name = "my-lodash"
    out = scan(repo, [dual])
    assert out[dual.key()].verdict == "imported"


def test_failed_inventory_build_not_retried_per_tier(
    tmp_path: Path, monkeypatch,
) -> None:
    """When the shared inventory build fails, the function-level
    tiers must be SKIPPED — not each fall back to its own tempdir
    rebuild of the builder that just failed (up to 8 redundant
    expensive builds with 8 warning stacks on istio-scale trees)."""
    import core.inventory.builder as builder_mod
    from packages.sca.reachability import scan as _scan

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import requests\nrequests.get('u')\n", encoding="utf-8",
    )

    calls: list[str] = []

    def _failing_build(target, cache_dir, *a, **kw):
        calls.append(str(target))
        raise RuntimeError("inventory builder down")

    monkeypatch.setattr(builder_mod, "build_inventory", _failing_build)

    dep = _dep("requests", ecosystem="PyPI")

    class _Adv:
        ecosystem_specific = None
        database_specific = {"affected_functions": ["get"]}

    class _Osv:
        dep_key = dep.key()
        advisories = [_Adv()]

    out = _scan(repo, [dep], osv_results=[_Osv()])
    # One shared attempt; no per-tier retry of the failed builder.
    assert len(calls) == 1, calls
    # Tier skipped → the module-level verdict is preserved.
    assert out[dep.key()].verdict == "imported"


def test_go_junk_advisory_symbol_element_does_not_crash_scan(
    tmp_path: Path,
) -> None:
    """One non-string element in an OSV ``imports[].symbols`` list
    must degrade to the counted unresolved marker — not propagate a
    TypeError through resolve_dep and kill the whole scan. String
    siblings in the same list keep working."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.go").write_text(
        'package main\n\n'
        'import "golang.org/x/crypto/ssh"\n\n'
        'func main() {\n\tssh.ParsePrivateKey(nil)\n}\n',
        encoding="utf-8",
    )
    dep = _dep("golang.org/x/crypto", ecosystem="Go", version="0.10.0")
    osv_results = [
        _FakeOsvResult(
            dep_key=dep.key(),
            advisories=[
                _FakeAdvisory(ecosystem_specific={
                    "imports": [
                        {"path": "golang.org/x/crypto/ssh",
                         "symbols": [123, "ParsePrivateKey"]},
                    ],
                }),
            ],
        ),
    ]
    out = scan(repo, [dep], osv_results=osv_results)
    assert out[dep.key()].verdict == "likely_called"


def test_go_junk_only_advisory_symbols_stay_imported(
    tmp_path: Path,
) -> None:
    """An advisory whose symbols are ALL junk elements keeps the
    module-level verdict (imported) — visible marker, no crash, no
    fabricated upgrade."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.go").write_text(
        'package main\n\n'
        'import "golang.org/x/crypto/ssh"\n\n'
        'func main() {\n\tssh.Dial("tcp", "h:22", nil)\n}\n',
        encoding="utf-8",
    )
    dep = _dep("golang.org/x/crypto", ecosystem="Go", version="0.10.0")
    osv_results = [
        _FakeOsvResult(
            dep_key=dep.key(),
            advisories=[
                _FakeAdvisory(ecosystem_specific={
                    "imports": [
                        {"path": "golang.org/x/crypto/ssh",
                         "symbols": [123, None]},
                    ],
                }),
            ],
        ),
    ]
    out = scan(repo, [dep], osv_results=osv_results)
    assert out[dep.key()].verdict == "imported"


def test_go_string_valued_symbols_container_not_iterated_charwise(
    tmp_path: Path,
) -> None:
    """A STRING-valued ``symbols`` container used to iterate
    char-by-char, turning one advisory into single-letter grep
    probes — spurious identifier matches upgraded the verdict from
    garbage data. A non-list container is junk-shaped and degrades
    to the marker."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "main.go").write_text(
        'package main\n\n'
        'import "golang.org/x/crypto/ssh"\n\n'
        'func main() {\n\tl := 1\n\t_ = l\n\tssh.Dial("tcp", "h:22", nil)\n}\n',
        encoding="utf-8",
    )
    dep = _dep("golang.org/x/crypto", ecosystem="Go", version="0.10.0")
    osv_results = [
        _FakeOsvResult(
            dep_key=dep.key(),
            advisories=[
                _FakeAdvisory(ecosystem_specific={
                    "imports": [
                        {"path": "golang.org/x/crypto/ssh",
                         # "Dial" IS called — but as a container this
                         # is junk, and its chars ('l' matches the
                         # local identifier) must not become probes.
                         "symbols": "Dial"},
                    ],
                }),
            ],
        ),
    ]
    out = scan(repo, [dep], osv_results=osv_results)
    assert out[dep.key()].verdict == "imported"
