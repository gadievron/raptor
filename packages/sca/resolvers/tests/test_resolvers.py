"""Tests for the per-ecosystem native-resolver wrappers.

We never call real ``npm`` / ``pip`` / ``go`` in CI; both exec seams —
bare ``subprocess.run`` (the unsandboxed ``_check_tool`` availability
probes) and ``core.sandbox.context.run`` (the resolver's sandboxed
tool invocations, see ``_run``) — are monkeypatched via ``_patch_exec``
to return canned ``CompletedProcess`` objects. The behaviour we
exercise:

  - ``is_available()`` reflects the toolchain probe result.
  - ``dry_run()`` returns the right ``ResolverResult`` shape on
    success, on failure, and when the toolchain is missing.
  - The wrappers never run install hooks (npm gets ``--ignore-scripts``,
    pip gets ``--only-binary=:all:`` for the dry-run fallback).
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from packages.sca.resolvers import get_resolver
from packages.sca.resolvers._cache import manifest_hash
from packages.sca.resolvers.gomod import GoResolver
from packages.sca.resolvers.npm import NpmResolver
from packages.sca.resolvers.pip import PipResolver, _find_pip_manifest


@pytest.fixture(autouse=True)
def _reset_sandbox_probe_caches(monkeypatch):
    """Reset ``core.sandbox.state`` probe caches before each test, and
    short-circuit the proxy-hosts auto-calibration so no resolver test
    can trigger a real landlock probe.

    The calibration short-circuit is the load-bearing half for CI cost.
    ``_proxy_hosts._calibrated_profile`` → ``load_or_calibrate`` →
    ``_spawn_probe`` runs a REAL sandbox probe (landlock/seccomp/
    namespace). Tests that only patch ``subprocess.run`` (via
    ``_patch_run``) leave that path live, so on the 2-core CI runner it
    costs 30-80s per test (it was 84s for test_pip_resolver_failure_*,
    20s for test_npm_always_passes_ignore_scripts) — and it once hung
    test_composer_proxy_hosts outright. Stubbing it to None here (the
    function's documented "calibration unavailable" path → static-layer
    proxy_hosts) makes EVERY resolver test immune, present and future,
    rather than relying on each remembering to call _capture_sandbox_call.

    Several module-level caches in ``core.sandbox.state`` record
    whether unprivileged user-namespaces work on this host
    (``_net_available_cache``, ``_mount_available_cache``, etc.).
    They're per-process singletons populated on first probe — once
    a prior test runs ``analyze_binary`` (or anything that
    successfully unshare-probes), the cache flips to ``True``, and
    every subsequent ``NpmResolver().dry_run()`` engages real
    sandbox wrapping. The wrapped command becomes
    ``[/usr/bin/unshare, --user, --pid, ..., npm, install, ...]``
    rather than ``[npm, install, ...]`` — which slips past the
    test's ``cmd[:2] == ["npm", "install"]`` matcher.

    Resetting these caches before each test makes the tests
    order-independent: every test gets a fresh probe, and since
    ``subprocess.run`` is monkeypatched to return non-zero for
    the unshare probe, the sandbox stays disabled inside the
    test — so the resolver invokes ``[npm, install, ...]``
    directly + the matcher matches.

    Idempotent + cheap; safe to run unconditionally.
    """
    from core.sandbox import state
    from packages.sca.resolvers import _proxy_hosts as _ph
    state._net_available_cache = None
    state._mount_available_cache = None
    # Never let a resolver test reach real proxy-hosts calibration.
    monkeypatch.setattr(_ph, "_calibrated_profile", lambda *a, **k: None)
    # ``_resolve_sandbox_binary`` also caches per-binary paths in
    # ``state._<name>_path_cache`` attributes — they're keyed on
    # the binary name (``unshare`` / ``prlimit``) and the path
    # doesn't change at runtime, so we leave those alone.
    yield
    state._net_available_cache = None
    state._mount_available_cache = None


# ---------------------------------------------------------------------------
# subprocess fake
# ---------------------------------------------------------------------------

class _FakeProc(subprocess.CompletedProcess):
    def __init__(self, returncode: int, stdout: str = "",
                 stderr: str = "") -> None:
        super().__init__(args=[], returncode=returncode,
                          stdout=stdout, stderr=stderr)


def _strip_env_prefix(cmd: list[str]) -> list[str]:
    """Drop a leading ``env VAR=VALUE ...`` prefix so matchers can
    check the underlying tool argv. The pip resolver prepends
    ``env PIP_ONLY_BINARY=:all:`` to enforce its metadata-only
    policy (wheels only, no sdist build-backend execution)."""
    if not cmd or cmd[0] != "env":
        return cmd
    i = 1
    while i < len(cmd) and "=" in cmd[i]:
        i += 1
    return cmd[i:]


def _is_pip_compile(cmd: list[str]) -> bool:
    stripped = _strip_env_prefix(cmd)
    return bool(stripped) and stripped[0] == "pip-compile"


def _patch_exec(
    monkeypatch: pytest.MonkeyPatch,
    fake_run: Callable[..., subprocess.CompletedProcess],
) -> None:
    """Install ``fake_run`` at BOTH exec seams a resolver can reach:

    * bare ``subprocess.run`` — the unsandboxed ``_check_tool``
      availability probes;
    * ``core.sandbox.context.run`` — the resolver's documented seam
      for the actual tool invocation (``_run`` routes every resolver
      subprocess through :func:`core.sandbox.run`).

    Stubbing only ``subprocess.run`` (the pre-2026-08 shape) reached
    the tool call by accident: the real sandbox pipeline executed and
    its *fallback* exec happened to be ``subprocess.run``. When the
    no-pid-namespace timeout path moved to a ``Popen``-based
    teardown-first wrapper, the stub was bypassed and the REAL
    npm/go/sh ran in CI — real network attempts, real /tmp writes
    under sandbox constraints. Patching the sandbox seam keeps these
    unit tests hermetic regardless of how the sandbox executes
    internally.
    """
    from core.sandbox import context as _ctx
    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(_ctx, "run", fake_run)


def _patch_run(monkeypatch, plan: list):
    """``plan`` is a list of (matcher_fn, _FakeProc) — first match wins.

    matcher_fn takes the cmd list and returns True when it should fire.
    """
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        for matcher, result in plan:
            if matcher(cmd):
                return result
        # Default: pretend exit 1 with no output.
        return _FakeProc(returncode=1)

    _patch_exec(monkeypatch, fake_run)
    return calls


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

def test_npm_unavailable(monkeypatch, tmp_path: Path) -> None:
    _patch_run(monkeypatch, [
        (lambda c: c == ["npm", "--version"], _FakeProc(returncode=127)),
    ])
    r = NpmResolver()
    assert r.is_available() is False
    res = r.dry_run(tmp_path)
    assert res.available is False
    assert res.success is False


def test_npm_no_package_json(monkeypatch, tmp_path: Path) -> None:
    _patch_run(monkeypatch, [
        (lambda c: c == ["npm", "--version"],
         _FakeProc(returncode=0, stdout="10.0.0\n")),
    ])
    r = NpmResolver()
    res = r.dry_run(tmp_path)
    assert res.available is True
    assert res.success is False
    assert "no package.json" in (res.error or "")


def test_npm_dry_run_success(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"name":"app","dependencies":{"lodash":"^4"}}',
        encoding="utf-8",
    )
    # Lockfile gets written by the fake "install" — simulate.
    # The resolver copies manifest files into an internal tempdir and
    # runs npm there, so the mock must write the lockfile to the cwd
    # kwarg (the resolver's tempdir), not to tmp_path.
    fake_lock = b'{"name":"app","lockfileVersion":3,"packages":{}}'

    def smart_run(cmd, **kwargs):
        cwd = kwargs.get("cwd")
        for matcher, result in [
            (lambda c: c == ["npm", "--version"],
             _FakeProc(returncode=0, stdout="10.0.0\n")),
            (lambda c: c[:2] == ["npm", "install"],
             _FakeProc(returncode=0, stdout="ok")),
        ]:
            if matcher(cmd):
                if cmd[:2] == ["npm", "install"] and cwd:
                    (Path(cwd) / "package-lock.json").write_bytes(fake_lock)
                return result
        return _FakeProc(returncode=1)

    _patch_exec(monkeypatch, smart_run)
    r = NpmResolver()
    res = r.dry_run(tmp_path)
    assert res.success is True
    assert res.proposed_lockfile == fake_lock


def test_npm_always_passes_ignore_scripts(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"name":"app"}', encoding="utf-8")
    calls = _patch_run(monkeypatch, [
        (lambda c: c == ["npm", "--version"],
         _FakeProc(returncode=0, stdout="10.0.0\n")),
        (lambda c: c[:2] == ["npm", "install"],
         _FakeProc(returncode=0)),
    ])
    NpmResolver().dry_run(tmp_path)
    install_call = next(c for c in calls if c[:2] == ["npm", "install"])
    assert "--ignore-scripts" in install_call


def test_npm_resolver_failure(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name":"app"}', encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["npm", "--version"],
         _FakeProc(returncode=0, stdout="10.0.0\n")),
        (lambda c: c[:2] == ["npm", "install"],
         _FakeProc(returncode=1, stderr="ERESOLVE could not satisfy")),
    ])
    res = NpmResolver().dry_run(tmp_path)
    assert res.success is False
    assert "ERESOLVE" in (res.error or "")


# ---------------------------------------------------------------------------
# pip
# ---------------------------------------------------------------------------

def test_pip_unavailable(monkeypatch, tmp_path: Path) -> None:
    _patch_run(monkeypatch, [
        (lambda c: c == ["pip", "--version"], _FakeProc(returncode=127)),
    ])
    res = PipResolver().dry_run(tmp_path)
    assert res.available is False


def test_pip_no_manifest(monkeypatch, tmp_path: Path) -> None:
    _patch_run(monkeypatch, [
        (lambda c: c == ["pip", "--version"],
         _FakeProc(returncode=0, stdout="pip 23.0\n")),
    ])
    res = PipResolver().dry_run(tmp_path)
    assert res.success is False
    assert "no requirements" in (res.error or "")


def test_pip_requirements_in_preferred_over_glob_variant(
    tmp_path: Path,
) -> None:
    """The stale-cache trigger scenario: requirements.in + a glob
    variant, no pyproject / requirements.txt. The declared (hashed)
    file must be the one resolved."""
    (tmp_path / "requirements.in").write_text("django\n", encoding="utf-8")
    (tmp_path / "requirements-dev.txt").write_text("pytest\n",
                                                   encoding="utf-8")
    selected = _find_pip_manifest(tmp_path)
    assert selected == tmp_path / "requirements.in"


def test_pip_pyproject_and_canonical_still_win(tmp_path: Path) -> None:
    (tmp_path / "requirements.in").write_text("a\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("b\n", encoding="utf-8")
    assert _find_pip_manifest(tmp_path) == tmp_path / "requirements.txt"
    (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    assert _find_pip_manifest(tmp_path) == tmp_path / "pyproject.toml"


def test_pip_glob_fallback_still_engages_when_only_variant(
    tmp_path: Path,
) -> None:
    (tmp_path / "requirements-dev.txt").write_text("pytest\n",
                                                   encoding="utf-8")
    assert _find_pip_manifest(tmp_path) == tmp_path / "requirements-dev.txt"


def test_pip_manifest_nothing_found(tmp_path: Path) -> None:
    assert _find_pip_manifest(tmp_path) is None


def test_pip_selected_manifest_is_hashed_whenever_cache_keyed(
    tmp_path: Path,
) -> None:
    """Invariant that closes the staleness window: if manifest_hash
    is non-None, the selected manifest is one of the hashed files;
    if the selected manifest is glob-only, the hash is None (cache
    bypass)."""
    resolver = PipResolver()

    # Declared file present → hash keyed AND selected file declared.
    (tmp_path / "requirements.in").write_text("django\n", encoding="utf-8")
    (tmp_path / "requirements-dev.txt").write_text("pytest\n",
                                                   encoding="utf-8")
    assert manifest_hash(resolver, tmp_path) is not None
    assert _find_pip_manifest(tmp_path).name in PipResolver.MANIFEST_FILES

    # Edits to the resolved file must change the hash.
    before = manifest_hash(resolver, tmp_path)
    (tmp_path / "requirements.in").write_text("django==5.0\n",
                                              encoding="utf-8")
    assert manifest_hash(resolver, tmp_path) != before


def test_pip_glob_only_project_bypasses_cache(tmp_path: Path) -> None:
    (tmp_path / "requirements-dev.txt").write_text("pytest\n",
                                                   encoding="utf-8")
    assert _find_pip_manifest(tmp_path) is not None
    assert manifest_hash(PipResolver(), tmp_path) is None


def test_pip_compile_path(monkeypatch, tmp_path: Path) -> None:
    """When pip-compile is on PATH, it's preferred."""
    (tmp_path / "requirements.txt").write_text(
        "django>=4.0\n", encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["pip", "--version"],
         _FakeProc(returncode=0, stdout="pip 23.0")),
        (lambda c: c == ["pip-compile", "--version"],
         _FakeProc(returncode=0, stdout="pip-compile 7.0")),
        (lambda c: _is_pip_compile(c),
         _FakeProc(returncode=0,
                    stdout="django==4.2.10\nasgiref==3.7\n")),
    ])
    res = PipResolver().dry_run(tmp_path)
    assert res.success is True
    assert res.proposed_lockfile is not None
    assert b"django==4.2.10" in res.proposed_lockfile


@pytest.mark.slow
def test_pip_no_system_pipcompile_falls_back_to_venv(
    monkeypatch, tmp_path: Path,
) -> None:
    """No system pip-compile → resolver goes straight to the venv
    pipeline (which always works given network access to PyPI)."""
    (tmp_path / "requirements.txt").write_text(
        "django>=4.0\n", encoding="utf-8")
    venv_dir = _resolver_venv_dir(tmp_path)
    plan = [
        (lambda c: c == ["pip", "--version"],
         _FakeProc(returncode=0, stdout="pip 23.0")),
        # No system pip-compile — probe returns non-zero.
        (lambda c: c == ["pip-compile", "--version"],
         _FakeProc(returncode=127)),
        # Fall straight to combined venv pipeline.
        (lambda c: c[0] == "sh" and len(c) >= 3
                   and "venv" in c[2] and "pip-compile" in c[2],
         _FakeProc(returncode=0, stdout="django==4.2.10\n")),
    ]
    _patch_run_with_callable(monkeypatch, plan)
    try:
        res = PipResolver().dry_run(tmp_path)
        assert res.success is True, f"got: {res.error!r}"
        assert b"django==4.2.10" in (res.proposed_lockfile or b"")
    finally:
        if venv_dir.exists():
            import shutil
            shutil.rmtree(venv_dir, ignore_errors=True)


def test_pip_resolver_failure_propagates_via_venv(
    monkeypatch, tmp_path: Path,
) -> None:
    """If both system pip-compile AND the venv pipeline fail, the
    venv pipeline's error message is what the operator sees.
    """
    (tmp_path / "requirements.txt").write_text(
        "impossible>=99\n", encoding="utf-8")
    venv_dir = _resolver_venv_dir(tmp_path)
    plan = [
        (lambda c: c == ["pip", "--version"],
         _FakeProc(returncode=0, stdout="pip 23.0")),
        (lambda c: c == ["pip-compile", "--version"],
         _FakeProc(returncode=0, stdout="pip-compile 7.0")),
        # System pip-compile fails with 'Cannot satisfy'.
        (lambda c: _is_pip_compile(c) and "--output-file" in c,
         _FakeProc(returncode=2, stderr="Cannot satisfy")),
        # Venv pipeline ALSO fails (manifest is impossible).
        (lambda c: c[0] == "sh" and len(c) >= 3 and "venv" in c[2],
         _FakeProc(returncode=2, stderr="Cannot satisfy in venv too")),
    ]
    _patch_run_with_callable(monkeypatch, plan)
    try:
        res = PipResolver().dry_run(tmp_path)
        assert res.success is False
        # Venv pipeline's error surfaces (the system attempt's error
        # is logged at debug, not propagated).
        assert "Cannot satisfy" in (res.error or "")
    finally:
        if venv_dir.exists():
            import shutil
            shutil.rmtree(venv_dir, ignore_errors=True)


def _make_pep668_plan(venv_dir: Path, lockfile_text: str = "django==4.2.10\n"):
    """Build a fake-run plan that simulates the PEP 668 fallback path.

    The venv-create matcher creates ``<venv>/bin/python`` on the disk so
    the resolver's existence check passes when it runs after the mock
    venv command. ``shutil.rmtree`` may have wiped a pre-existing dir
    just before, so creation has to happen inside the matcher.
    """
    pep668_stderr = (
        "error: externally-managed-environment\n"
        "× This environment is externally managed\n"
    )

    def _create_files_then_succeed(cmd):
        bin_dir = venv_dir / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        (bin_dir / "python").touch()
        (bin_dir / "pip-compile").touch()
        return _FakeProc(returncode=0)

    return [
        (lambda c: c == ["pip", "--version"],
         _FakeProc(returncode=0, stdout="pip 23.0")),
        (lambda c: c == ["pip-compile", "--version"],
         _FakeProc(returncode=0, stdout="pip-compile 7.0")),
        # First pip-compile — system Python, refused by PEP 668.
        (lambda c: _is_pip_compile(c) and "--output-file" in c,
         _FakeProc(returncode=1, stderr=pep668_stderr)),
        # Combined venv pipeline (``sh -c "venv && ensurepip && pip
        # install pip-tools && pip-compile"`` runs as a single
        # sandbox call). The script string contains "venv" + the
        # lockfile text via pip-compile.
        (lambda c: c[0] == "sh" and len(c) >= 3
                   and "venv" in c[2] and "pip-compile" in c[2],
         _FakeProc(returncode=0, stdout=lockfile_text)),
        # Fallback for the dry-run combined pipeline.
        (lambda c: c[0] == "sh" and len(c) >= 3
                   and "venv" in c[2] and "--dry-run" in c[2],
         _FakeProc(returncode=0)),
    ]


def _patch_run_with_callable(monkeypatch, plan):
    """Same as ``_patch_run`` but tolerates plan entries whose result is
    a callable (called with cmd to produce the _FakeProc on the fly)."""
    calls = []
    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        for matcher, result in plan:
            if matcher(cmd):
                if callable(result):
                    return result(cmd)
                return result
        return _FakeProc(returncode=1)
    _patch_exec(monkeypatch, fake_run)
    return calls


def _resolver_venv_dir(project_dir: Path) -> Path:
    """Compute the venv path the resolver would use for ``project_dir``.

    Mirrors ``PipResolver._venv_dir`` so tests can target the same
    location for pre-mocking and cleanup assertions.
    """
    return PipResolver()._venv_dir(project_dir)


def test_pip_compile_pep668_falls_back_to_venv(
    monkeypatch, tmp_path: Path,
) -> None:
    """System pip-compile blocked by PEP 668 → resolver retries via
    an ephemeral venv and succeeds."""
    (tmp_path / "requirements.txt").write_text(
        "django>=4.0\n", encoding="utf-8")
    venv_dir = _resolver_venv_dir(tmp_path)
    _patch_run_with_callable(monkeypatch, _make_pep668_plan(venv_dir))
    try:
        res = PipResolver().dry_run(tmp_path)
        assert res.success is True, \
            f"expected success, got error: {res.error!r}"
        assert res.proposed_lockfile is not None
        assert b"django==4.2.10" in res.proposed_lockfile
    finally:
        # Test-side cleanup — the resolver's cleanup is inside _run
        # which is monkeypatched, so the dir we pre-created may
        # outlive the test if the resolver's finally clause never
        # ran a real shutil.rmtree.
        if venv_dir.exists():
            import shutil
            shutil.rmtree(venv_dir, ignore_errors=True)


def test_pep668_fallback_cleans_up_venv(
    monkeypatch, tmp_path: Path,
) -> None:
    """The ephemeral venv directory is removed after the resolver
    finishes, success or failure."""
    (tmp_path / "requirements.txt").write_text(
        "django>=4.0\n", encoding="utf-8")
    venv_dir = _resolver_venv_dir(tmp_path)
    _patch_run_with_callable(monkeypatch, _make_pep668_plan(venv_dir))

    PipResolver().dry_run(tmp_path)

    # Venv directory should be removed by the resolver's finally clause.
    assert not venv_dir.exists(), (
        f"venv leaked at {venv_dir}; contents: "
        f"{list(venv_dir.rglob('*')) if venv_dir.exists() else '(gone)'}"
    )


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------

def test_go_unavailable(monkeypatch, tmp_path: Path) -> None:
    _patch_run(monkeypatch, [
        (lambda c: c == ["go", "version"], _FakeProc(returncode=127)),
    ])
    res = GoResolver().dry_run(tmp_path)
    assert res.available is False


def test_go_no_gomod(monkeypatch, tmp_path: Path) -> None:
    _patch_run(monkeypatch, [
        (lambda c: c == ["go", "version"],
         _FakeProc(returncode=0, stdout="go version go1.22\n")),
    ])
    res = GoResolver().dry_run(tmp_path)
    assert res.success is False
    assert "no go.mod" in (res.error or "")


def test_go_tidy_success(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example\n\nrequire github.com/foo/bar v1.0.0\n",
        encoding="utf-8")

    fake_sum = b"github.com/foo/bar v1.0.0 h1:abc\n"

    # We install a bespoke fake via ``_patch_exec`` (rather than the
    # shared ``_patch_run`` helper) because the simulated
    # ``go mod tidy`` needs to write ``go.sum`` into the resolver's
    # cwd, and that path needs access to the ``cwd=`` kwarg —
    # which the simpler matcher-only helper doesn't expose.
    def smart_run(cmd, **kwargs):
        cwd = kwargs.get("cwd")
        for matcher, result in [
            (lambda c: c == ["go", "version"],
             _FakeProc(returncode=0, stdout="go version go1.22")),
            (lambda c: c[:3] == ["go", "mod", "tidy"],
             _FakeProc(returncode=0, stdout="ok")),
        ]:
            if matcher(cmd):
                if cmd[:3] == ["go", "mod", "tidy"] and cwd:
                    (Path(cwd) / "go.sum").write_bytes(fake_sum)
                return result
        return _FakeProc(returncode=1)

    _patch_exec(monkeypatch, smart_run)

    res = GoResolver().dry_run(tmp_path)
    assert res.success is True
    assert res.proposed_lockfile == fake_sum


def test_go_tidy_failure(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example\nrequire github.com/foo/bar v1.0.0\n",
        encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["go", "version"],
         _FakeProc(returncode=0, stdout="go version go1.22")),
        (lambda c: c[:3] == ["go", "mod", "tidy"],
         _FakeProc(returncode=1,
                    stderr="github.com/foo/bar: unknown revision")),
    ])
    res = GoResolver().dry_run(tmp_path)
    assert res.success is False
    assert "unknown revision" in (res.error or "")


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_get_resolver_returns_resolver_for_known_ecosystem() -> None:
    """For each ecosystem we ship, ``get_resolver`` (no project_dir)
    returns the MOST-GENERIC resolver of that ecosystem — the one
    whose error messages best describe "no recognised manifest"
    when an operator runs cascade against an empty / unusual tree."""
    expected = {
        "npm":      NpmResolver,         # not yarn / pnpm
        "PyPI":     PipResolver,         # not poetry
        "Maven":    "MavenResolver",     # not Gradle (string-compare since
                                          # we don't import the class above)
        "Go":       GoResolver,
        "Cargo":       "CargoResolver",
        "RubyGems":    "BundlerResolver",
        "NuGet":       "NugetResolver",
        "Packagist":   "ComposerResolver",
    }
    for eco, want in expected.items():
        r = get_resolver(eco)
        assert r is not None, f"no resolver for {eco}"
        assert r.ecosystem == eco
        if isinstance(want, str):
            assert type(r).__name__ == want, (
                f"get_resolver({eco!r}) = {type(r).__name__}, want {want}"
            )
        else:
            assert isinstance(r, want), (
                f"get_resolver({eco!r}) = {type(r).__name__}, want {want.__name__}"
            )


def test_get_resolver_falls_back_to_generic_when_no_match(tmp_path):
    """Project_dir present but missing EVERY recognised manifest —
    fallback returns the most-generic resolver (npm for npm-eco, pip
    for PyPI-eco), not the most-specific (yarn / poetry). The generic
    resolver's dry_run produces a sensible "no <canonical-manifest>"
    error rather than yarn complaining about yarn.lock specifically."""
    # tmp_path is empty.
    assert isinstance(get_resolver("npm", project_dir=tmp_path), NpmResolver)
    assert isinstance(get_resolver("PyPI", project_dir=tmp_path), PipResolver)
    from packages.sca.resolvers.maven import MavenResolver
    assert isinstance(
        get_resolver("Maven", project_dir=tmp_path), MavenResolver,
    )


def test_get_resolver_unknown_returns_none() -> None:
    """Ecosystems we don't ship a resolver for return None."""
    assert get_resolver("Hex") is None         # Erlang — no resolver
    assert get_resolver("Pub") is None         # Dart — no resolver
    assert get_resolver("nonsense") is None


def test_get_resolver_picks_yarn_when_yarn_lock_present(tmp_path):
    """With multiple npm-ecosystem resolvers, project-dir-aware
    selection picks the tool whose lockfile is present."""
    from packages.sca.resolvers.yarn import YarnResolver
    (tmp_path / "package.json").write_text('{}', encoding="utf-8")
    (tmp_path / "yarn.lock").write_text("", encoding="utf-8")
    r = get_resolver("npm", project_dir=tmp_path)
    assert isinstance(r, YarnResolver)


def test_get_resolver_picks_pnpm_when_pnpm_lock_present(tmp_path):
    from packages.sca.resolvers.pnpm import PnpmResolver
    (tmp_path / "package.json").write_text('{}', encoding="utf-8")
    (tmp_path / "pnpm-lock.yaml").write_text("", encoding="utf-8")
    r = get_resolver("npm", project_dir=tmp_path)
    assert isinstance(r, PnpmResolver)


def test_get_resolver_picks_poetry_for_poetry_pyproject(tmp_path):
    from packages.sca.resolvers.poetry import PoetryResolver
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry]\nname="x"\n', encoding="utf-8")
    r = get_resolver("PyPI", project_dir=tmp_path)
    assert isinstance(r, PoetryResolver)


def test_get_resolver_picks_pip_for_plain_requirements(tmp_path):
    """A pyproject.toml with PEP 621 ``[project]`` only — not Poetry —
    falls through to PipResolver, not PoetryResolver."""
    (tmp_path / "requirements.txt").write_text("django\n", encoding="utf-8")
    r = get_resolver("PyPI", project_dir=tmp_path)
    assert isinstance(r, PipResolver)


def test_get_resolver_picks_gradle_when_build_gradle_present(tmp_path):
    from packages.sca.resolvers.gradle import GradleResolver
    (tmp_path / "build.gradle").write_text("", encoding="utf-8")
    r = get_resolver("Maven", project_dir=tmp_path)
    assert isinstance(r, GradleResolver)


def test_get_resolver_picks_maven_for_pom_only(tmp_path):
    """A pure-Maven project (only pom.xml, no build.gradle) goes to
    MavenResolver, not GradleResolver."""
    from packages.sca.resolvers.maven import MavenResolver
    (tmp_path / "pom.xml").write_text(
        "<project></project>", encoding="utf-8")
    r = get_resolver("Maven", project_dir=tmp_path)
    assert isinstance(r, MavenResolver)


# ---------------------------------------------------------------------------
# Sandbox plumbing
# ---------------------------------------------------------------------------

def _capture_sandbox_call(monkeypatch):
    """Replace ``core.sandbox.context.run`` with a recorder that captures
    every kwarg the resolver passes through ``_run`` and returns a
    canned successful CompletedProcess.

    Also stubs the proxy-hosts auto-calibration short-circuit to
    None so resolver tests don't trip into ``calibrate.load_or_calibrate``
    → ``_spawn_probe`` (which expects a real ``CompletedProcess``
    carrying ``sandbox_info`` and otherwise blocks indefinitely on
    landlock-audited readers). Static-layer proxy_hosts still flow
    through, so the assertions that hostname X appears in
    ``kwargs["proxy_hosts"]`` keep working — they were never reading
    calibration output to begin with.

    Returns the list of (cmd, kwargs) tuples the recorder collected.
    """
    captured: list = []

    def fake_sandbox_run(cmd, **kwargs):
        captured.append((list(cmd), dict(kwargs)))
        return _FakeProc(returncode=0, stdout="", stderr="")

    from core.sandbox import context as _ctx
    from packages.sca.resolvers import _proxy_hosts as _ph
    monkeypatch.setattr(_ctx, "run", fake_sandbox_run)
    monkeypatch.setattr(_ph, "_calibrated_profile", lambda *a, **k: None)
    return captured


def test_npm_run_routes_through_sandbox_with_proxy(monkeypatch, tmp_path):
    """The npm install invocation must reach core.sandbox.run with
    the npm-specific proxy_hosts allowlist + Landlock target/output
    pinned to the project dir, not raw subprocess.run."""
    (tmp_path / "package.json").write_text('{"name":"a"}', encoding="utf-8")
    # is_available() is unsandboxed (deliberate, performance) — keep
    # the bare-subprocess monkeypatch for that, then capture the
    # sandboxed install call separately.
    _patch_run(monkeypatch, [
        (lambda c: c == ["npm", "--version"],
         _FakeProc(returncode=0, stdout="10.0.0")),
    ])
    captured = _capture_sandbox_call(monkeypatch)

    NpmResolver().dry_run(tmp_path)

    install_calls = [(c, k) for c, k in captured if c[:2] == ["npm", "install"]]
    assert len(install_calls) == 1, (
        f"expected exactly one sandboxed npm install, got {len(install_calls)}"
    )
    _cmd, kwargs = install_calls[0]
    assert kwargs["use_egress_proxy"] is True
    assert kwargs["proxy_hosts"] == ["registry.npmjs.org"]
    # target= is the resolver's copy-dir (manifest files copied into a
    # writable tempdir so the sandbox can confine reads to it), NOT the
    # original project dir.
    assert kwargs["target"] != str(tmp_path)
    assert "raptor-sca-npm-" in kwargs["target"]
    # output= is a per-call tempdir, NOT the project dir. Asserts the
    # fix for the .home/ contamination bug: routing the sandbox's
    # writable surface to a tempdir avoids polluting the operator's
    # project tree with the fake-HOME directory hierarchy.
    assert kwargs["output"] != str(tmp_path)
    assert "raptor-sca-resolver-" in kwargs["output"]
    assert kwargs["restrict_reads"] is True
    assert kwargs["fake_home"] is True
    assert kwargs["caller_label"] == "sca-resolver"


def test_pip_compile_routes_through_sandbox_with_proxy(monkeypatch, tmp_path):
    (tmp_path / "requirements.txt").write_text("django>=4\n", encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["pip", "--version"],
         _FakeProc(returncode=0, stdout="pip 23.0")),
        (lambda c: c == ["pip-compile", "--version"],
         _FakeProc(returncode=0, stdout="pip-compile 7.0")),
    ])
    captured = _capture_sandbox_call(monkeypatch)

    PipResolver().dry_run(tmp_path)

    compile_calls = [(c, k) for c, k in captured if _is_pip_compile(c)]
    assert len(compile_calls) == 1
    _, kwargs = compile_calls[0]
    assert kwargs["proxy_hosts"] == [
        "pypi.org", "files.pythonhosted.org",
    ]
    assert kwargs["target"] == str(tmp_path)
    assert kwargs["restrict_reads"] is True


def test_go_routes_through_sandbox_with_proxy(monkeypatch, tmp_path):
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["go", "version"],
         _FakeProc(returncode=0, stdout="go1.22")),
    ])
    captured = _capture_sandbox_call(monkeypatch)

    GoResolver().dry_run(tmp_path)

    tidy_calls = [(c, k) for c, k in captured if c[:3] == ["go", "mod", "tidy"]]
    assert len(tidy_calls) == 1
    _, kwargs = tidy_calls[0]
    assert kwargs["proxy_hosts"] == ["proxy.golang.org", "sum.golang.org"]
    # Go runs in a temp copy of go.mod, not the project dir itself —
    # but target/output should still be set so Landlock engages.
    assert kwargs["target"] is not None
    assert kwargs["output"] is not None
    assert kwargs["restrict_reads"] is True


# ---------------------------------------------------------------------------
# yarn / pnpm / poetry / cargo / gradle / maven / bundler / nuget / composer
# ---------------------------------------------------------------------------
#
# Per-resolver shape tests. Each covers:
#   - toolchain unavailable → available=False
#   - manifest missing      → available=True, success=False with message
#   - happy path through the sandbox with the right proxy_hosts
#   - resolver error        → success=False, stderr surfaced
#
# All sandbox calls are captured via _capture_sandbox_call so no real
# subprocess fires in CI.

def _ok_proc(stdout: str = "ok") -> _FakeProc:
    return _FakeProc(returncode=0, stdout=stdout)


# ----- yarn -----

def test_yarn_unavailable(monkeypatch, tmp_path):
    from packages.sca.resolvers.yarn import YarnResolver
    _patch_run(monkeypatch, [
        (lambda c: c == ["yarn", "--version"], _FakeProc(returncode=127)),
    ])
    res = YarnResolver().dry_run(tmp_path)
    assert res.available is False


def test_yarn_no_package_json(monkeypatch, tmp_path):
    from packages.sca.resolvers.yarn import YarnResolver
    _patch_run(monkeypatch, [
        (lambda c: c == ["yarn", "--version"], _ok_proc("3.6.0")),
    ])
    res = YarnResolver().dry_run(tmp_path)
    assert res.available is True and res.success is False


def test_yarn_classic_v1_uses_legacy_flags(monkeypatch, tmp_path):
    from packages.sca.resolvers.yarn import YarnResolver
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["yarn", "--version"], _ok_proc("1.22.19")),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    YarnResolver().dry_run(tmp_path)
    install = next(c for c, _ in captured if c[:2] == ["yarn", "install"])
    assert "--frozen-lockfile=false" in install
    assert "--ignore-scripts" in install


def test_yarn_berry_uses_update_lockfile_mode(monkeypatch, tmp_path):
    from packages.sca.resolvers.yarn import YarnResolver
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["yarn", "--version"], _ok_proc("3.6.0")),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    YarnResolver().dry_run(tmp_path)
    install = next(c for c, _ in captured if c[:2] == ["yarn", "install"])
    assert "--mode=update-lockfile" in install


def test_yarn_berry_disables_scripts(monkeypatch, tmp_path):
    from packages.sca.resolvers.yarn import YarnResolver
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["yarn", "--version"], _ok_proc("3.6.0")),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    YarnResolver().dry_run(tmp_path)
    _, kwargs = next((c, k) for c, k in captured if c[:2] == ["yarn", "install"])
    env = kwargs.get("env") or {}
    assert env.get("YARN_ENABLE_SCRIPTS") == "false"


def test_yarn_proxy_hosts(monkeypatch, tmp_path):
    from packages.sca.resolvers.yarn import YarnResolver
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["yarn", "--version"], _ok_proc("3.6.0")),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    YarnResolver().dry_run(tmp_path)
    _, kwargs = next((c, k) for c, k in captured if c[:2] == ["yarn", "install"])
    assert "registry.yarnpkg.com" in kwargs["proxy_hosts"]
    assert "registry.npmjs.org" in kwargs["proxy_hosts"]


# ----- pnpm -----

def test_pnpm_unavailable(monkeypatch, tmp_path):
    from packages.sca.resolvers.pnpm import PnpmResolver
    _patch_run(monkeypatch, [
        (lambda c: c == ["pnpm", "--version"], _FakeProc(returncode=127)),
    ])
    res = PnpmResolver().dry_run(tmp_path)
    assert res.available is False


def test_pnpm_routes_through_sandbox(monkeypatch, tmp_path):
    from packages.sca.resolvers.pnpm import PnpmResolver
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["pnpm", "--version"], _ok_proc("8.0.0")),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    PnpmResolver().dry_run(tmp_path)
    install_calls = [(c, k) for c, k in captured if c[:2] == ["pnpm", "install"]]
    assert len(install_calls) == 1
    cmd, kwargs = install_calls[0]
    assert "--lockfile-only" in cmd
    assert "--ignore-scripts" in cmd
    assert kwargs["proxy_hosts"] == ["registry.npmjs.org"]


# ----- poetry -----

def test_poetry_unavailable(monkeypatch, tmp_path):
    from packages.sca.resolvers.poetry import PoetryResolver
    _patch_run(monkeypatch, [
        (lambda c: c == ["poetry", "--version"], _FakeProc(returncode=127)),
    ])
    res = PoetryResolver().dry_run(tmp_path)
    assert res.available is False


def test_poetry_matches_only_with_tool_poetry_section(tmp_path):
    from packages.sca.resolvers.poetry import PoetryResolver
    # PEP 621 only — not Poetry
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\n', encoding="utf-8")
    assert PoetryResolver().matches(tmp_path) is False
    # Poetry config — matches
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry]\nname="x"\n', encoding="utf-8")
    assert PoetryResolver().matches(tmp_path) is True


def test_poetry_lock_routes_through_sandbox(monkeypatch, tmp_path):
    from packages.sca.resolvers.poetry import PoetryResolver
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry]\nname="x"\n', encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["poetry", "--version"], _ok_proc("1.6.0")),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    PoetryResolver().dry_run(tmp_path)
    cmd, kwargs = next(
        (c, k) for c, k in captured if c[:2] == ["poetry", "lock"])
    assert "--no-update" in cmd
    assert kwargs["proxy_hosts"] == ["pypi.org", "files.pythonhosted.org"]


# ----- cargo -----

def test_cargo_unavailable(monkeypatch, tmp_path):
    from packages.sca.resolvers.cargo import CargoResolver
    _patch_run(monkeypatch, [
        (lambda c: c == ["cargo", "--version"], _FakeProc(returncode=127)),
    ])
    res = CargoResolver().dry_run(tmp_path)
    assert res.available is False


def test_cargo_no_manifest(monkeypatch, tmp_path):
    from packages.sca.resolvers.cargo import CargoResolver
    _patch_run(monkeypatch, [
        (lambda c: c == ["cargo", "--version"], _ok_proc("1.75")),
    ])
    res = CargoResolver().dry_run(tmp_path)
    assert res.available is True and res.success is False


def test_cargo_proxy_hosts_include_sparse_index(monkeypatch, tmp_path):
    from packages.sca.resolvers.cargo import CargoResolver
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "x"\nversion = "0.1.0"\n', encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["cargo", "--version"], _ok_proc("1.75")),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    CargoResolver().dry_run(tmp_path)
    _cmd, kwargs = next(
        (c, k) for c, k in captured if c[:2] == ["cargo", "update"])
    assert "index.crates.io" in kwargs["proxy_hosts"]   # sparse index 1.74+
    assert "static.crates.io" in kwargs["proxy_hosts"]  # crate downloads


# ----- gradle -----

def test_gradle_unavailable_without_wrapper(monkeypatch, tmp_path):
    from packages.sca.resolvers.gradle import GradleResolver
    _patch_run(monkeypatch, [
        (lambda c: c == ["gradle", "--version"], _FakeProc(returncode=127)),
    ])
    res = GradleResolver().dry_run(tmp_path)
    assert res.available is False


def test_gradle_uses_wrapper_when_present(monkeypatch, tmp_path):
    from packages.sca.resolvers.gradle import GradleResolver
    (tmp_path / "build.gradle").write_text("", encoding="utf-8")
    (tmp_path / "gradlew").write_text("#!/bin/sh\n", encoding="utf-8")
    # System gradle absent, wrapper present.
    _patch_run(monkeypatch, [
        (lambda c: c == ["gradle", "--version"], _FakeProc(returncode=127)),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    GradleResolver().dry_run(tmp_path)
    cmd, _ = next(
        (c, k) for c, k in captured if "dependencies" in c)
    assert cmd[0] == "./gradlew"


def test_gradle_proxy_hosts(monkeypatch, tmp_path):
    from packages.sca.resolvers.gradle import GradleResolver
    (tmp_path / "build.gradle").write_text("", encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["gradle", "--version"], _ok_proc("8.5")),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    GradleResolver().dry_run(tmp_path)
    _, kwargs = next(
        (c, k) for c, k in captured if "dependencies" in c)
    assert "repo.maven.apache.org" in kwargs["proxy_hosts"]
    assert "plugins.gradle.org" in kwargs["proxy_hosts"]


# ----- maven -----

def test_maven_unavailable(monkeypatch, tmp_path):
    from packages.sca.resolvers.maven import MavenResolver
    _patch_run(monkeypatch, [
        (lambda c: c == ["mvn", "--version"], _FakeProc(returncode=127)),
    ])
    res = MavenResolver().dry_run(tmp_path)
    assert res.available is False


def test_maven_does_not_match_when_gradle_present(tmp_path):
    """In a project with both ``pom.xml`` and ``build.gradle``, the
    Gradle resolver wins via registry order. ``MavenResolver.matches``
    only checks for pom.xml — registry order handles tie-breaking."""
    from packages.sca.resolvers.maven import MavenResolver
    (tmp_path / "pom.xml").write_text("<project></project>", encoding="utf-8")
    (tmp_path / "build.gradle").write_text("", encoding="utf-8")
    # MavenResolver itself still matches (it's pom-based) — the
    # tie-break happens at the registry level via get_resolver.
    assert MavenResolver().matches(tmp_path) is True


def test_maven_routes_through_sandbox(monkeypatch, tmp_path):
    from packages.sca.resolvers.maven import MavenResolver
    (tmp_path / "pom.xml").write_text("<project></project>", encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["mvn", "--version"], _ok_proc("3.9.0")),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    MavenResolver().dry_run(tmp_path)
    cmd, kwargs = next(
        (c, k) for c, k in captured if "dependency:resolve" in c)
    assert "--batch-mode" in cmd
    assert kwargs["proxy_hosts"] == ["repo.maven.apache.org",
                                       "repo1.maven.org"]


# ----- bundler -----

def test_bundler_unavailable(monkeypatch, tmp_path):
    from packages.sca.resolvers.bundler import BundlerResolver
    _patch_run(monkeypatch, [
        (lambda c: c == ["bundle", "--version"], _FakeProc(returncode=127)),
    ])
    res = BundlerResolver().dry_run(tmp_path)
    assert res.available is False


def test_bundler_no_gemfile(monkeypatch, tmp_path):
    from packages.sca.resolvers.bundler import BundlerResolver
    _patch_run(monkeypatch, [
        (lambda c: c == ["bundle", "--version"], _ok_proc("2.4.10")),
    ])
    res = BundlerResolver().dry_run(tmp_path)
    assert res.available is True and res.success is False


def test_bundler_proxy_hosts(monkeypatch, tmp_path):
    from packages.sca.resolvers.bundler import BundlerResolver
    (tmp_path / "Gemfile").write_text("source 'https://rubygems.org'\n",
                                       encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["bundle", "--version"], _ok_proc("2.4.10")),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    BundlerResolver().dry_run(tmp_path)
    _, kwargs = next(
        (c, k) for c, k in captured if c[:2] == ["bundle", "lock"])
    assert "rubygems.org" in kwargs["proxy_hosts"]


# ----- nuget -----

def test_nuget_unavailable(monkeypatch, tmp_path):
    from packages.sca.resolvers.nuget import NugetResolver
    _patch_run(monkeypatch, [
        (lambda c: c == ["dotnet", "--version"], _FakeProc(returncode=127)),
    ])
    res = NugetResolver().dry_run(tmp_path)
    assert res.available is False


def test_nuget_matches_csproj(tmp_path):
    from packages.sca.resolvers.nuget import NugetResolver
    (tmp_path / "x.csproj").write_text("<Project></Project>", encoding="utf-8")
    assert NugetResolver().matches(tmp_path) is True


def test_nuget_matches_sln(tmp_path):
    from packages.sca.resolvers.nuget import NugetResolver
    (tmp_path / "x.sln").write_text("Microsoft Visual Studio Solution",
                                     encoding="utf-8")
    assert NugetResolver().matches(tmp_path) is True


def test_nuget_proxy_hosts(monkeypatch, tmp_path):
    from packages.sca.resolvers.nuget import NugetResolver
    (tmp_path / "x.csproj").write_text("<Project></Project>", encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["dotnet", "--version"], _ok_proc("8.0.0")),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    NugetResolver().dry_run(tmp_path)
    cmd, kwargs = next(
        (c, k) for c, k in captured if c[:2] == ["dotnet", "restore"])
    assert "--use-lock-file" in cmd
    assert "api.nuget.org" in kwargs["proxy_hosts"]


# ----- composer -----

def test_composer_unavailable(monkeypatch, tmp_path):
    from packages.sca.resolvers.composer import ComposerResolver
    _patch_run(monkeypatch, [
        (lambda c: c == ["composer", "--version"], _FakeProc(returncode=127)),
    ])
    res = ComposerResolver().dry_run(tmp_path)
    assert res.available is False


def test_composer_proxy_hosts(monkeypatch, tmp_path):
    from packages.sca.resolvers.composer import ComposerResolver
    (tmp_path / "composer.json").write_text("{}", encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["composer", "--version"], _ok_proc("2.6.0")),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    ComposerResolver().dry_run(tmp_path)
    cmd, kwargs = next(
        (c, k) for c, k in captured if c[:2] == ["composer", "update"])
    assert "--no-install" in cmd
    assert "repo.packagist.org" in kwargs["proxy_hosts"]


def test_composer_always_disables_scripts_and_plugins(monkeypatch, tmp_path):
    """Composer runs root-package script events + plugins on ``update``
    even with ``--no-install`` — the resolver must disable both so
    resolution stays metadata-only."""
    from packages.sca.resolvers.composer import ComposerResolver
    (tmp_path / "composer.json").write_text("{}", encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["composer", "--version"], _ok_proc("2.6.0")),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    ComposerResolver().dry_run(tmp_path)
    cmd, _ = next(
        (c, k) for c, k in captured if c[:2] == ["composer", "update"])
    assert "--no-scripts" in cmd
    assert "--no-plugins" in cmd


# ---------------------------------------------------------------------------
# pip metadata-only policy (PIP_ONLY_BINARY=:all:)
# ---------------------------------------------------------------------------

def test_pip_compile_sets_only_binary_env_by_default(monkeypatch, tmp_path):
    """The system pip-compile invocation carries PIP_ONLY_BINARY=:all:
    (via an ``env`` prefix) so pip never builds an sdist — building one
    would run the package's build backend."""
    (tmp_path / "requirements.txt").write_text(
        "django>=4\n", encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["pip", "--version"], _ok_proc("pip 23.0")),
        (lambda c: c == ["pip-compile", "--version"],
         _ok_proc("pip-compile 7.0")),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    PipResolver().dry_run(tmp_path)
    cmd, _ = next((c, k) for c, k in captured if _is_pip_compile(c))
    assert cmd[:3] == ["env", "PIP_ONLY_BINARY=:all:", "pip-compile"]


def test_pip_compile_allow_sdist_builds_skips_only_binary(
    monkeypatch, tmp_path,
):
    """The operator escape hatch drops the env prefix so sdist-only
    manifests can resolve (build backends run inside the sandbox)."""
    (tmp_path / "requirements.txt").write_text(
        "django>=4\n", encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["pip", "--version"], _ok_proc("pip 23.0")),
        (lambda c: c == ["pip-compile", "--version"],
         _ok_proc("pip-compile 7.0")),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    PipResolver(allow_sdist_builds=True).dry_run(tmp_path)
    cmd, _ = next((c, k) for c, k in captured if _is_pip_compile(c))
    assert cmd[0] == "pip-compile"
    assert "env" not in cmd
    assert not any("PIP_ONLY_BINARY" in a for a in cmd)


def test_pip_venv_pipeline_exports_only_binary(monkeypatch, tmp_path):
    """The combined venv shell pipeline exports PIP_ONLY_BINARY=:all:
    in its preamble so pip-compile inside the venv inherits it."""
    (tmp_path / "requirements.txt").write_text(
        "django>=4\n", encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["pip", "--version"], _ok_proc("pip 23.0")),
        # No system pip-compile — go straight to the venv pipeline.
        (lambda c: c == ["pip-compile", "--version"],
         _FakeProc(returncode=127)),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    PipResolver().dry_run(tmp_path)
    script = next(c[2] for c, k in captured if c[:2] == ["sh", "-c"])
    assert "export PIP_ONLY_BINARY=:all:; " in script


def test_pip_venv_pipeline_allow_sdist_builds_no_export(
    monkeypatch, tmp_path,
):
    (tmp_path / "requirements.txt").write_text(
        "django>=4\n", encoding="utf-8")
    _patch_run(monkeypatch, [
        (lambda c: c == ["pip", "--version"], _ok_proc("pip 23.0")),
        (lambda c: c == ["pip-compile", "--version"],
         _FakeProc(returncode=127)),
    ])
    captured = _capture_sandbox_call(monkeypatch)
    PipResolver(allow_sdist_builds=True).dry_run(tmp_path)
    script = next(c[2] for c, k in captured if c[:2] == ["sh", "-c"])
    assert "PIP_ONLY_BINARY" not in script


def test_pip_batch_script_exports_only_binary(tmp_path):
    """The batched venv script shares the same preamble, so every
    per-manifest pip-compile subshell inherits the wheels-only policy."""
    manifests = [(tmp_path, Path("."), Path("requirements.txt"))]
    venv_dir = Path("/tmp/raptor-test-venv")
    script = PipResolver()._build_batch_script(venv_dir, manifests)
    assert "export PIP_ONLY_BINARY=:all:; " in script
    script_sdist = PipResolver(
        allow_sdist_builds=True,
    )._build_batch_script(venv_dir, manifests)
    assert "PIP_ONLY_BINARY" not in script_sdist


def test_pip_set_allow_sdist_builds_process_default():
    """``set_allow_sdist_builds`` flips the process-wide default (the
    CLI-flag plumbing for the registry's import-time singleton), while
    an explicitly-pinned instance keeps its own value."""
    from packages.sca.resolvers import pip as pip_mod
    r = PipResolver()
    assert r.allow_sdist_builds is False
    pip_mod.set_allow_sdist_builds(True)
    try:
        assert r.allow_sdist_builds is True
        # A pinned instance ignores the process-wide default.
        assert PipResolver(
            allow_sdist_builds=False,
        ).allow_sdist_builds is False
    finally:
        pip_mod.set_allow_sdist_builds(False)
    assert r.allow_sdist_builds is False
