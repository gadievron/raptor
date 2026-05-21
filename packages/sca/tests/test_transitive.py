"""Tests for ``packages.sca.transitive.expand_missing_transitives``.

The orchestrator is a thin coordinator over (b) cascade resolver and
(c) registry-metadata walk. The two underlying mechanisms have their
own dedicated test suites; here we exercise the per-(ecosystem,
project_dir) decision tree:

  - sibling lockfile present → skip
  - --no-resolve-transitive AND no fallback → skip
  - cascade succeeds → emit cascade_resolver-tagged deps
  - cascade fails AND fallback enabled → emit metadata_walk-tagged deps
  - cascade fails AND fallback disabled → emit skip status

Mocks: cascade resolver via ``get_resolver`` patch; metadata walker
via direct ``walk_transitive`` patch. No real network or subprocess
fires.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock


from packages.sca.models import Confidence, Dependency, Manifest, PinStyle
from packages.sca.resolvers import ResolverResult
from packages.sca.transitive import (
    expand_missing_transitives,
)


def _manifest(eco: str, path: Path, *, is_lockfile: bool = False) -> Manifest:
    return Manifest(path=path, ecosystem=eco, is_lockfile=is_lockfile)


def _direct(eco: str, name: str, version: str, host: Path) -> Dependency:
    return Dependency(
        ecosystem=eco, name=name, version=version,
        declared_in=host, scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT,
        direct=True, purl=f"pkg:{eco.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def _transitive_dep(eco: str, name: str, version: str,
                     host: Path, source_kind: str = "lockfile") -> Dependency:
    return Dependency(
        ecosystem=eco, name=name, version=version,
        declared_in=host, scope="main", is_lockfile=False,
        pin_style=PinStyle.EXACT, direct=False,
        purl=f"pkg:{eco.lower()}/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
        source_kind=source_kind,
    )


# ---------------------------------------------------------------------------
# Skip cases
# ---------------------------------------------------------------------------

def test_skips_when_sibling_lockfile_present(tmp_path):
    """A manifest with a sibling lockfile already on disk → skip
    transitive expansion; the lockfile parser handled it."""
    proj = tmp_path / "proj"
    proj.mkdir()
    manifests = [
        _manifest("PyPI", proj / "requirements.txt"),
        _manifest("PyPI", proj / "Pipfile.lock", is_lockfile=True),
    ]
    direct = [_direct("PyPI", "a", "1.0", proj / "requirements.txt")]
    deps, statuses = expand_missing_transitives(manifests, direct)
    assert deps == []
    assert len(statuses) == 1
    assert statuses[0].method == "skipped_lockfile_present"
    assert "Pipfile.lock" in (statuses[0].reason or "")


def test_skips_when_resolver_disabled_and_no_fallback(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    manifests = [_manifest("PyPI", proj / "requirements.txt")]
    direct = [_direct("PyPI", "a", "1.0", proj / "requirements.txt")]
    deps, statuses = expand_missing_transitives(
        manifests, direct,
        enable_resolver=False, enable_metadata_fallback=False,
    )
    assert deps == []
    assert statuses[0].method == "skipped_resolver_disabled"


# ---------------------------------------------------------------------------
# Cascade resolver path (mode b)
# ---------------------------------------------------------------------------

def test_cascade_succeeds_emits_cascade_tagged_deps(tmp_path, monkeypatch):
    """When cascade resolver succeeds, transitives are emitted with
    source_kind="cascade_resolver" so operators can distinguish from
    a checked-in lockfile."""
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("a==1.0\n", encoding="utf-8")
    manifests = [_manifest("PyPI", proj / "requirements.txt")]
    direct = [_direct("PyPI", "a", "1.0", proj / "requirements.txt")]

    # Stub the resolver: pretend pip-compile produced a pinned reqs
    # file containing both the direct dep AND a transitive.
    fake_resolver = MagicMock()
    fake_resolver.is_available.return_value = True
    fake_resolver.dry_run.return_value = ResolverResult(
        ecosystem="PyPI", success=True, available=True,
        proposed_lockfile=b"a==1.0\nb==2.0\n",
    )
    monkeypatch.setattr(
        "packages.sca.transitive.get_resolver"
        if False else "packages.sca.resolvers.get_resolver",
        lambda eco, project_dir=None: fake_resolver,
    )

    deps, statuses = expand_missing_transitives(manifests, direct)

    assert len(deps) == 1
    assert deps[0].name == "b"
    assert deps[0].version == "2.0"
    assert deps[0].source_kind == "cascade_resolver"
    assert deps[0].direct is False
    assert statuses[0].method == "cascade_resolver"
    assert statuses[0].deps_added == 1


def test_cascade_resolver_unavailable_falls_through(tmp_path, monkeypatch):
    """No toolchain → resolver returns is_available=False → cascade
    falls through. With fallback off, status records the skip."""
    proj = tmp_path / "proj"
    proj.mkdir()
    manifests = [_manifest("PyPI", proj / "requirements.txt")]
    direct = [_direct("PyPI", "a", "1.0", proj / "requirements.txt")]

    fake_resolver = MagicMock()
    fake_resolver.is_available.return_value = False
    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver",
        lambda eco, project_dir=None: fake_resolver,
    )

    deps, statuses = expand_missing_transitives(manifests, direct)
    assert deps == []
    assert statuses[0].method == "skipped_no_method_succeeded"


def test_cascade_resolver_fails_falls_through(tmp_path, monkeypatch):
    """Resolver runs but exits non-zero (registry refused / can't
    satisfy). Fall through to skip status (no fallback)."""
    proj = tmp_path / "proj"
    proj.mkdir()
    manifests = [_manifest("PyPI", proj / "requirements.txt")]
    direct = [_direct("PyPI", "a", "1.0", proj / "requirements.txt")]

    fake_resolver = MagicMock()
    fake_resolver.is_available.return_value = True
    fake_resolver.dry_run.return_value = ResolverResult(
        ecosystem="PyPI", success=False, available=True,
        error="ResolutionImpossible: a requires b<1, c requires b>=2",
    )
    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver",
        lambda eco, project_dir=None: fake_resolver,
    )

    deps, statuses = expand_missing_transitives(manifests, direct)
    assert deps == []
    assert statuses[0].method == "skipped_no_method_succeeded"


# ---------------------------------------------------------------------------
# Metadata-walk fallback (mode c)
# ---------------------------------------------------------------------------

def test_fallback_to_metadata_walk_when_cascade_fails(tmp_path, monkeypatch):
    """Cascade unavailable + fallback enabled → metadata walk fires,
    deps emitted with source_kind=metadata_walk."""
    proj = tmp_path / "proj"
    proj.mkdir()
    manifests = [_manifest("PyPI", proj / "requirements.txt")]
    direct = [_direct("PyPI", "a", "1.0", proj / "requirements.txt")]

    # Cascade unavailable.
    fake_resolver = MagicMock()
    fake_resolver.is_available.return_value = False
    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver",
        lambda eco, project_dir=None: fake_resolver,
    )

    # Stub the metadata walker.
    from packages.sca.registry_metadata_walk import WalkResult
    walked = [_transitive_dep("PyPI", "b", "2.0",
                                proj / "requirements.txt",
                                source_kind="metadata_walk")]
    monkeypatch.setattr(
        "packages.sca.registry_metadata_walk.walk_transitive",
        lambda deps, **kw: WalkResult(
            deps_added=walked, visits=1, cache_hits=0,
            cache_misses=1, failures=0,
        ),
    )

    deps, statuses = expand_missing_transitives(
        manifests, direct,
        http=MagicMock(),
        enable_metadata_fallback=True,
    )
    assert len(deps) == 1
    assert deps[0].source_kind == "metadata_walk"
    assert statuses[0].method == "metadata_walk"
    assert "approximate" in (statuses[0].reason or "").lower()


def test_no_metadata_fallback_when_http_not_provided(tmp_path, monkeypatch):
    """Even with --fallback-registry-metadata, walk needs http.
    Without it, fall through to skip."""
    proj = tmp_path / "proj"
    proj.mkdir()
    manifests = [_manifest("PyPI", proj / "requirements.txt")]
    direct = [_direct("PyPI", "a", "1.0", proj / "requirements.txt")]

    fake_resolver = MagicMock()
    fake_resolver.is_available.return_value = False
    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver",
        lambda eco, project_dir=None: fake_resolver,
    )

    deps, statuses = expand_missing_transitives(
        manifests, direct,
        http=None,                 # no http
        enable_metadata_fallback=True,
    )
    assert deps == []
    assert statuses[0].method == "skipped_no_method_succeeded"


# ---------------------------------------------------------------------------
# Dedup against direct deps
# ---------------------------------------------------------------------------

def test_dedup_against_direct_deps(tmp_path, monkeypatch):
    """If cascade output includes a dep that's ALSO already declared
    direct, don't re-emit it as a transitive — operator already saw
    it via the manifest."""
    proj = tmp_path / "proj"
    proj.mkdir()
    manifests = [_manifest("PyPI", proj / "requirements.txt")]
    direct = [
        _direct("PyPI", "a", "1.0", proj / "requirements.txt"),
        _direct("PyPI", "b", "2.0", proj / "requirements.txt"),
    ]

    fake_resolver = MagicMock()
    fake_resolver.is_available.return_value = True
    # Cascade output includes both direct deps + a new transitive.
    fake_resolver.dry_run.return_value = ResolverResult(
        ecosystem="PyPI", success=True, available=True,
        proposed_lockfile=b"a==1.0\nb==2.0\nc==3.0\n",
    )
    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver",
        lambda eco, project_dir=None: fake_resolver,
    )

    deps, _ = expand_missing_transitives(manifests, direct)
    names = {d.name for d in deps}
    assert names == {"c"}     # b stripped (already direct)


# ---------------------------------------------------------------------------
# Multi-ecosystem orchestration
# ---------------------------------------------------------------------------

def test_per_ecosystem_independent_decisions(tmp_path, monkeypatch):
    """A project with PyPI + npm: PyPI cascade succeeds, npm has no
    toolchain → falls back. Each ecosystem reports its own status."""
    proj = tmp_path / "proj"
    proj.mkdir()
    manifests = [
        _manifest("PyPI", proj / "requirements.txt"),
        _manifest("npm", proj / "package.json"),
    ]
    direct = [
        _direct("PyPI", "a", "1.0", proj / "requirements.txt"),
        _direct("npm", "lodash", "4.17.21", proj / "package.json"),
    ]

    def fake_get_resolver(eco, project_dir=None):
        r = MagicMock()
        if eco == "PyPI":
            r.is_available.return_value = True
            r.dry_run.return_value = ResolverResult(
                ecosystem="PyPI", success=True, available=True,
                proposed_lockfile=b"a==1.0\npy_trans==1.0\n",
            )
        else:
            r.is_available.return_value = False
        return r

    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver", fake_get_resolver,
    )

    deps, statuses = expand_missing_transitives(manifests, direct)
    by_eco = {s.ecosystem: s for s in statuses}
    assert by_eco["PyPI"].method == "cascade_resolver"
    assert by_eco["npm"].method == "skipped_no_method_succeeded"
    # PEP 503: parser normalises "py_trans" → "py-trans".
    assert any(d.name == "py-trans" for d in deps)
    assert all(d.ecosystem != "npm" for d in deps)


# ---------------------------------------------------------------------------
# Batched cascade dispatch — shared venv, parallel manifests
# ---------------------------------------------------------------------------


def test_dry_run_batch_default_loops_dry_run():
    """The free-function default for resolvers without
    ``SUPPORTS_BATCH`` falls back to a sequential ``dry_run`` loop.
    Defends the fallback so non-PipResolver consumers (npm, Maven,
    Cargo, …) keep working without per-resolver opt-in."""
    from packages.sca.resolvers import dry_run_batch

    class _StubNoBatch:
        def __init__(self):
            self.calls: list = []

        def dry_run(self, project_dir, *, timeout=120):
            self.calls.append(project_dir)
            return ResolverResult(
                ecosystem="PyPI", success=True, available=True,
                proposed_lockfile=b"x==1.0\n",
            )

    stub = _StubNoBatch()
    out = dry_run_batch(stub, [Path("/p1"), Path("/p2"), Path("/p3")])
    assert len(out) == 3
    assert all(r.success for r in out)
    assert stub.calls == [Path("/p1"), Path("/p2"), Path("/p3")]


def test_dry_run_batch_uses_class_flag_not_attr_presence():
    """Resolvers opt into batching via class-level
    ``SUPPORTS_BATCH = True``. Mere attribute presence (e.g. a
    MagicMock auto-attr) must NOT trigger the batch path —
    ``list(MagicMock())`` returns an empty list, which would silently
    zero out test results."""
    from packages.sca.resolvers import dry_run_batch
    from unittest.mock import MagicMock

    fake = MagicMock()
    fake.is_available.return_value = True
    fake.dry_run.return_value = ResolverResult(
        ecosystem="PyPI", success=True, available=True,
        proposed_lockfile=b"x==1.0\n",
    )
    out = dry_run_batch(fake, [Path("/p1"), Path("/p2")])
    assert len(out) == 2
    assert all(r.success for r in out)
    assert fake.dry_run.call_count == 2


def test_dry_run_batch_uses_resolver_method_when_flag_set():
    """When ``SUPPORTS_BATCH=True`` the free function delegates to
    the resolver's ``dry_run_batch`` and returns its result verbatim
    (no extra wrapping)."""
    from packages.sca.resolvers import dry_run_batch

    class _StubBatch:
        SUPPORTS_BATCH = True

        def __init__(self):
            self.calls: list = []

        def dry_run(self, *a, **kw):
            raise AssertionError("dry_run shouldn't be called")

        def dry_run_batch(self, project_dirs, *, common_root=None,
                          timeout=120):
            self.calls.append((tuple(project_dirs), common_root, timeout))
            return [
                ResolverResult(
                    ecosystem="PyPI", success=True, available=True,
                    proposed_lockfile=f"{p}==1.0\n".encode(),
                ) for p in project_dirs
            ]

    stub = _StubBatch()
    out = dry_run_batch(
        stub, [Path("/a"), Path("/b")], common_root=Path("/"),
    )
    assert len(out) == 2
    assert stub.calls == [((Path("/a"), Path("/b")), Path("/"), 120)]


def test_dry_run_batch_falls_back_when_batch_raises():
    """A buggy ``dry_run_batch`` must not abort the scan — the free
    function catches and falls back to sequential ``dry_run``. The
    operator sees a warning + complete results, never a crash."""
    from packages.sca.resolvers import dry_run_batch

    class _StubBuggyBatch:
        SUPPORTS_BATCH = True

        def __init__(self):
            self.dry_run_calls = 0

        def dry_run_batch(self, project_dirs, *, common_root=None,
                          timeout=120):
            raise RuntimeError("simulated batch crash")

        def dry_run(self, project_dir, *, timeout=120):
            self.dry_run_calls += 1
            return ResolverResult(
                ecosystem="PyPI", success=True, available=True,
                proposed_lockfile=b"x==1.0\n",
            )

    stub = _StubBuggyBatch()
    out = dry_run_batch(stub, [Path("/p1"), Path("/p2")])
    assert len(out) == 2
    assert all(r.success for r in out)
    assert stub.dry_run_calls == 2


# ---------------------------------------------------------------------------
# _common_ancestor — sandbox cwd sizing
# ---------------------------------------------------------------------------


def test_common_ancestor_single_path_returns_self():
    from packages.sca.transitive import _common_ancestor
    assert _common_ancestor([Path("/a/b/c")]) == Path("/a/b/c")


def test_common_ancestor_multiple_paths_finds_shared_prefix(tmp_path):
    from packages.sca.transitive import _common_ancestor
    (tmp_path / "a/x").mkdir(parents=True)
    (tmp_path / "a/y/z").mkdir(parents=True)
    common = _common_ancestor([tmp_path / "a/x", tmp_path / "a/y/z"])
    assert common == (tmp_path / "a").resolve()


def test_common_ancestor_disjoint_paths_returns_root():
    from packages.sca.transitive import _common_ancestor
    common = _common_ancestor([Path("/x/y"), Path("/p/q")])
    assert common == Path("/")


# ---------------------------------------------------------------------------
# Cross-ecosystem parallel dispatch
# ---------------------------------------------------------------------------


def test_cross_ecosystem_parallel_runs_concurrently(tmp_path, monkeypatch):
    """Two ecosystems' batches dispatch on separate threads. Each
    cascade sleeps briefly to simulate the sandbox subprocess; the
    total wallclock is bounded by the slower one, not the sum.

    Defends the cross-ecosystem parallelism — without threads each
    ecosystem's batch would serialise behind the previous one."""
    import time as _time
    from packages.sca.transitive import _run_cascades_parallel

    def fake_try(eco, work_items, cache=None):
        _time.sleep(0.3)
        return [(pd, host, [], None) for pd, host in work_items]

    monkeypatch.setattr(
        "packages.sca.transitive._try_cascade_batch", fake_try,
    )

    work = {
        "PyPI": [(tmp_path / "a", tmp_path / "a/req.txt")],
        "npm":  [(tmp_path / "b", tmp_path / "b/pkg.json")],
    }
    t0 = _time.time()
    out = _run_cascades_parallel(work)
    elapsed = _time.time() - t0
    assert ("PyPI", tmp_path / "a") in out
    assert ("npm", tmp_path / "b") in out
    # Sequential would be ~0.6s; parallel should be ~0.3s. Generous
    # slack for CI noise but still detects serialisation.
    assert elapsed < 0.55, f"expected parallel <0.55s, got {elapsed:.2f}s"


def test_cross_ecosystem_one_crashes_others_proceed(tmp_path, monkeypatch):
    """A crash in one ecosystem's batch shouldn't take down the
    others. The crashed ecosystem gets per-item failure rows so
    downstream can still emit a meaningful TransitiveStatus."""
    from packages.sca.transitive import _run_cascades_parallel

    def fake_try(eco, work_items, cache=None):
        if eco == "PyPI":
            raise RuntimeError("PyPI batch blew up")
        return [(pd, host, [], None) for pd, host in work_items]

    monkeypatch.setattr(
        "packages.sca.transitive._try_cascade_batch", fake_try,
    )

    work = {
        "PyPI": [(tmp_path / "a", tmp_path / "a/req.txt")],
        "npm":  [(tmp_path / "b", tmp_path / "b/pkg.json")],
    }
    out = _run_cascades_parallel(work)
    py = out[("PyPI", tmp_path / "a")]
    assert py[0] is None
    assert "blew up" in (py[1] or "")
    npm = out[("npm", tmp_path / "b")]
    assert npm[0] == []
    assert npm[1] is None


# ---------------------------------------------------------------------------
# Pre-resolution typosquat gate
# ---------------------------------------------------------------------------


def test_typosquat_dep_skips_cascade(tmp_path, monkeypatch):
    """A direct dep flagged as a confident typosquat causes its
    (ecosystem, project_dir) to skip the cascade resolver — we don't
    want pip-compile / npm install fetching metadata for an
    attacker-controlled name. Status row records the refusal."""
    from packages.sca.supply_chain.typosquat import TyposquatFinding

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("requessts==1.0\n")
    manifests = [_manifest("PyPI", proj / "requirements.txt")]
    direct = [_direct("PyPI", "requessts", "1.0", proj / "requirements.txt")]

    # Stub the typosquat scanner to flag 'requessts' as a HIGH-
    # confidence squat of 'requests'.
    def fake_scan(deps):
        return [
            TyposquatFinding(
                dependency=d,
                nearest_popular="requests",
                distance=1,
                severity="medium",
                confidence=Confidence("high",
                                       reason="distance=1 from popular"),
            )
            for d in deps if d.name == "requessts"
        ]
    monkeypatch.setattr(
        "packages.sca.supply_chain.typosquat.scan_deps", fake_scan,
    )

    # Stub the resolver too, so if cascade WERE invoked we'd notice
    # (it would return a fake result instead of raising).
    fake_resolver = MagicMock()
    fake_resolver.is_available.return_value = True
    fake_resolver.dry_run.return_value = ResolverResult(
        ecosystem="PyPI", success=True, available=True,
        proposed_lockfile=b"requessts==1.0\nrequests==1.0\n",
    )
    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver",
        lambda eco, project_dir=None: fake_resolver,
    )

    deps, statuses = expand_missing_transitives(manifests, direct)

    # Cascade was refused — no transitive deps emerged.
    assert deps == []
    assert len(statuses) == 1
    s = statuses[0]
    assert s.method == "skipped_typosquat_refused"
    assert "requessts" in (s.reason or "")
    # And the resolver was NEVER called — the gate fired upstream.
    fake_resolver.dry_run.assert_not_called()


def test_medium_confidence_typosquat_does_not_skip(tmp_path, monkeypatch):
    """The gate only refuses on HIGH-confidence flags. Medium-confidence
    ones still surface as findings but don't block cascade — the
    operator may have a legitimate package with a similar name."""
    from packages.sca.supply_chain.typosquat import TyposquatFinding

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("requestz==1.0\n")
    manifests = [_manifest("PyPI", proj / "requirements.txt")]
    direct = [_direct("PyPI", "requestz", "1.0", proj / "requirements.txt")]

    def fake_scan(deps):
        return [
            TyposquatFinding(
                dependency=d, nearest_popular="requests",
                distance=2, severity="medium",
                confidence=Confidence("medium", reason="distance=2"),
            )
            for d in deps if d.name == "requestz"
        ]
    monkeypatch.setattr(
        "packages.sca.supply_chain.typosquat.scan_deps", fake_scan,
    )

    fake_resolver = MagicMock()
    fake_resolver.is_available.return_value = True
    fake_resolver.dry_run.return_value = ResolverResult(
        ecosystem="PyPI", success=True, available=True,
        proposed_lockfile=b"requestz==1.0\n",
    )
    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver",
        lambda eco, project_dir=None: fake_resolver,
    )

    _, statuses = expand_missing_transitives(manifests, direct)
    # Medium confidence → cascade still runs (different status).
    assert statuses[0].method != "skipped_typosquat_refused"
