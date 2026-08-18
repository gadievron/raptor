"""Robustness tests for the single repo-trust switchboard.

Pre-fix, the SCA entry points set the process-wide ``cc_trust``
override directly from the raw ``--trust-repo`` flag while the
pipeline resolved trust separately via
``core.project.trust.apply_project_trust_flags``. Two halves of one
run could disagree:

* marker-only runs — the pipeline honoured the active project's
  ``config`` marker but the process-wide override stayed off;
* ``--trust-repo --no-trust-repo`` — the pipeline correctly resolved
  untrusted (negative wins) but the raw-flag path had already set the
  override to trusted.

Post-fix every entry point routes through
``packages.sca._scan_args.resolve_repo_trust``, which resolves ONCE
(``--no-trust-repo`` > ``--trust-repo`` > ``config`` marker > off)
and drives BOTH consumers — ``RunOptions.trust_repo`` and the
process-wide ``cc_trust`` / ``codeql_trust`` overrides — from the
same resolved value. These tests pin that invariant per entry point.
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages.sca._scan_args import (
    add_scan_args,
    apply_no_llm_umbrella,
    options_from_args,
    resolve_repo_trust,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]

_MARKER = {"config": "2026-01-01T00:00:00Z"}


@pytest.fixture(autouse=True)
def _no_project_trust_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin "no active project" so tests don't depend on the developer
    machine's ``~/.raptor`` state. Marker tests override this."""
    from core.project import trust
    monkeypatch.setattr(trust, "active_project_trust",
                        lambda: ({}, None))


@pytest.fixture
def override_spy(monkeypatch: pytest.MonkeyPatch) -> dict:
    """Replace both process-wide ``set_trust_override`` targets with
    recorders. Patching the module attribute is enough: every caller
    imports the function at call time, so the patched attribute is
    what gets bound. Also keeps the real process-global untouched, so
    trust state never leaks between tests."""
    calls: dict = {"cc": [], "codeql": []}
    from core.security import cc_trust, codeql_trust
    monkeypatch.setattr(cc_trust, "set_trust_override",
                        lambda v: calls["cc"].append(v))
    monkeypatch.setattr(codeql_trust, "set_trust_override",
                        lambda v: calls["codeql"].append(v))
    return calls


def _set_marker(monkeypatch: pytest.MonkeyPatch) -> None:
    from core.project import trust
    monkeypatch.setattr(trust, "active_project_trust",
                        lambda: (dict(_MARKER), "proj"))
    # Markers only apply when the run target matches the project
    # target; these tests exercise the precedence table, so pin a
    # match. Target-mismatch behaviour is pinned in
    # core/project/tests/test_trust_consumption.py.
    monkeypatch.setattr(trust, "run_target_matches_project",
                        lambda target: True)


def _assert_both_overrides(calls: dict, expected: bool) -> None:
    """Both process-wide gates must have been driven, last value ==
    the resolved one."""
    assert calls["cc"], "cc_trust.set_trust_override never called"
    assert calls["codeql"], "codeql_trust.set_trust_override never called"
    assert calls["cc"][-1] is expected
    assert calls["codeql"][-1] is expected


# ---------------------------------------------------------------------------
# resolve_repo_trust — the shared switchboard
# ---------------------------------------------------------------------------

class TestResolveRepoTrust:

    def _args(self, *, trust: bool = False, no_trust: bool = False,
              ) -> argparse.Namespace:
        return argparse.Namespace(trust_repo=trust, no_trust_repo=no_trust)

    def test_marker_only_resolves_trusted(
        self, monkeypatch: pytest.MonkeyPatch, override_spy: dict,
        capsys: pytest.CaptureFixture,
    ) -> None:
        """Project ``config`` marker with no per-run flags → trusted,
        override propagated, banner printed."""
        _set_marker(monkeypatch)
        args = self._args()
        assert resolve_repo_trust(args) is True
        assert args.trust_repo is True
        _assert_both_overrides(override_spy, True)
        assert "project trust: config" in capsys.readouterr().out

    def test_both_flags_resolve_untrusted(
        self, override_spy: dict,
    ) -> None:
        """--trust-repo AND --no-trust-repo → negative wins for BOTH
        consumers. Pre-fix the override was left trusted."""
        args = self._args(trust=True, no_trust=True)
        assert resolve_repo_trust(args) is False
        assert args.trust_repo is False
        _assert_both_overrides(override_spy, False)

    def test_flag_only_resolves_trusted(self, override_spy: dict) -> None:
        args = self._args(trust=True)
        assert resolve_repo_trust(args) is True
        assert args.trust_repo is True
        _assert_both_overrides(override_spy, True)

    def test_neither_resolves_untrusted(self, override_spy: dict) -> None:
        args = self._args()
        assert resolve_repo_trust(args) is False
        assert args.trust_repo is False
        _assert_both_overrides(override_spy, False)

    def test_negative_flag_beats_marker(
        self, monkeypatch: pytest.MonkeyPatch, override_spy: dict,
    ) -> None:
        _set_marker(monkeypatch)
        args = self._args(no_trust=True)
        assert resolve_repo_trust(args) is False
        _assert_both_overrides(override_spy, False)

    def test_idempotent_and_single_banner(
        self, monkeypatch: pytest.MonkeyPatch, override_spy: dict,
        capsys: pytest.CaptureFixture,
    ) -> None:
        """Entry point + ``options_from_args`` may both resolve; the
        second pass must reach the same value and not re-print the
        marker banner."""
        _set_marker(monkeypatch)
        args = self._args()
        assert resolve_repo_trust(args) is True
        assert resolve_repo_trust(args) is True
        assert args.trust_repo is True
        _assert_both_overrides(override_spy, True)
        assert capsys.readouterr().out.count("project trust:") == 1

    def test_survives_missing_security_modules(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Environments without ``core.security`` still resolve the
        pipeline value — the override propagation degrades to a
        debug log instead of crashing the run."""
        import builtins
        real_import = builtins.__import__

        def _blocking_import(name, *a, **kw):
            if name.startswith("core.security"):
                raise ImportError(f"blocked for test: {name}")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", _blocking_import)
        args = self._args(trust=True)
        assert resolve_repo_trust(args) is True
        assert args.trust_repo is True


# ---------------------------------------------------------------------------
# scan surface — options_from_args (packages/sca/cli.py AND
# libexec/raptor-sca-run both funnel through it)
# ---------------------------------------------------------------------------

class TestScanOptionsPropagation:

    def _parse(self, argv: list) -> argparse.Namespace:
        p = argparse.ArgumentParser(prog="test")
        p.add_argument("target")
        add_scan_args(p)
        args = p.parse_args(argv)
        apply_no_llm_umbrella(args)
        return args

    def test_marker_only_trusts_pipeline_and_overrides(
        self, monkeypatch: pytest.MonkeyPatch, override_spy: dict,
    ) -> None:
        _set_marker(monkeypatch)
        opts = options_from_args(self._parse(["./t"]))
        assert opts.trust_repo is True
        _assert_both_overrides(override_spy, True)

    def test_both_flags_untrust_pipeline_and_overrides(
        self, override_spy: dict,
    ) -> None:
        opts = options_from_args(
            self._parse(["./t", "--trust-repo", "--no-trust-repo"]))
        assert opts.trust_repo is False
        _assert_both_overrides(override_spy, False)

    def test_flag_only_trusts_both(self, override_spy: dict) -> None:
        opts = options_from_args(self._parse(["./t", "--trust-repo"]))
        assert opts.trust_repo is True
        _assert_both_overrides(override_spy, True)

    def test_neither_untrusts_both(self, override_spy: dict) -> None:
        opts = options_from_args(self._parse(["./t"]))
        assert opts.trust_repo is False
        _assert_both_overrides(override_spy, False)


# ---------------------------------------------------------------------------
# scan CLI entry point (packages/sca/cli.py::_run_analyse)
# ---------------------------------------------------------------------------

class TestScanCliEntrypoint:

    @pytest.fixture(autouse=True)
    def _preserve_root_logging(self):
        """``_run_analyse`` attaches a run-directory file handler to
        the root logger; restore root handlers/level afterwards."""
        root = logging.getLogger()
        saved_handlers = list(root.handlers)
        saved_level = root.level
        yield
        for h in root.handlers:
            if h not in saved_handlers:
                root.removeHandler(h)
                h.close()
        root.setLevel(saved_level)

    def _run(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
             extra_flags: list) -> int:
        import packages.sca.cli as sca_cli
        target = tmp_path / "target"
        target.mkdir(exist_ok=True)
        monkeypatch.setattr(sca_cli, "run_sca",
                            lambda **kw: SimpleNamespace())
        monkeypatch.setattr(sca_cli, "_print_summary", lambda r: None)
        return sca_cli._run_analyse(
            [str(target), "--out", str(tmp_path / "out"), "--no-llm",
             *extra_flags],
        )

    def test_marker_only(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        override_spy: dict,
    ) -> None:
        _set_marker(monkeypatch)
        assert self._run(monkeypatch, tmp_path, []) == 0
        _assert_both_overrides(override_spy, True)

    def test_both_flags(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        override_spy: dict,
    ) -> None:
        rc = self._run(monkeypatch, tmp_path,
                       ["--trust-repo", "--no-trust-repo"])
        assert rc == 0
        _assert_both_overrides(override_spy, False)

    def test_flag_only(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        override_spy: dict,
    ) -> None:
        assert self._run(monkeypatch, tmp_path, ["--trust-repo"]) == 0
        _assert_both_overrides(override_spy, True)

    def test_neither(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        override_spy: dict,
    ) -> None:
        assert self._run(monkeypatch, tmp_path, []) == 0
        _assert_both_overrides(override_spy, False)


# ---------------------------------------------------------------------------
# bump entry point (packages/sca/bump/cli.py)
# ---------------------------------------------------------------------------

class TestBumpEntrypoint:
    """Trust resolution happens before the target-existence check, so
    a nonexistent target exercises the switchboard hermetically (no
    network, no registries) and exits 2."""

    def _run(self, extra_flags: list) -> int:
        from packages.sca.bump import cli as bump_cli
        return bump_cli.main(["/nonexistent/raptor-test-target",
                              *extra_flags])

    def test_marker_only(
        self, monkeypatch: pytest.MonkeyPatch, override_spy: dict,
    ) -> None:
        _set_marker(monkeypatch)
        assert self._run([]) == 2
        _assert_both_overrides(override_spy, True)

    def test_both_flags(self, override_spy: dict) -> None:
        assert self._run(["--trust-repo", "--no-trust-repo"]) == 2
        _assert_both_overrides(override_spy, False)

    def test_flag_only(self, override_spy: dict) -> None:
        assert self._run(["--trust-repo"]) == 2
        _assert_both_overrides(override_spy, True)

    def test_neither(self, override_spy: dict) -> None:
        assert self._run([]) == 2
        _assert_both_overrides(override_spy, False)

    def _run_with_stub(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        extra_flags: list,
    ) -> tuple:
        """Run the bump CLI against an existing (empty) target with
        ``run_bump`` stubbed out, returning ``(rc, trust_repo seen by
        run_bump)``."""
        from packages.sca.bump import cli as bump_cli
        from packages.sca.bump import orchestrator
        seen: dict = {}

        def _fake_run_bump(*, target, trust_repo=None, **kw):
            seen["trust_repo"] = trust_repo
            return SimpleNamespace(target=target, candidates=[],
                                   results=[], skipped=[])

        monkeypatch.setattr(orchestrator, "run_bump", _fake_run_bump)
        rc = bump_cli.main([str(tmp_path), "--json", "--no-cache",
                            *extra_flags])
        return rc, seen.get("trust_repo")

    def test_resolved_untrust_reaches_run_bump(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        override_spy: dict,
    ) -> None:
        """--no-trust-repo with a project marker must reach run_bump
        as untrusted. The orchestrator's own fallback resolver has no
        negative-flag input — if the CLI didn't pass the resolved
        value explicitly, the marker would re-trust the policy gate."""
        _set_marker(monkeypatch)
        rc, trust = self._run_with_stub(monkeypatch, tmp_path,
                                        ["--no-trust-repo"])
        assert rc == 0
        assert trust is False
        _assert_both_overrides(override_spy, False)

    def test_resolved_trust_reaches_run_bump(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
        override_spy: dict,
    ) -> None:
        _set_marker(monkeypatch)
        rc, trust = self._run_with_stub(monkeypatch, tmp_path, [])
        assert rc == 0
        assert trust is True
        _assert_both_overrides(override_spy, True)


# ---------------------------------------------------------------------------
# fix --harden entry point (packages/sca/harden.py)
# ---------------------------------------------------------------------------

class TestHardenEntrypoint:
    """Same hermetic pattern as bump: trust resolution precedes the
    target-existence check."""

    def _run(self, extra_flags: list) -> int:
        from packages.sca import harden
        return harden.main(["/nonexistent/raptor-test-target",
                            *extra_flags])

    def test_marker_only(
        self, monkeypatch: pytest.MonkeyPatch, override_spy: dict,
    ) -> None:
        _set_marker(monkeypatch)
        assert self._run([]) == 2
        _assert_both_overrides(override_spy, True)

    def test_both_flags(self, override_spy: dict) -> None:
        assert self._run(["--trust-repo", "--no-trust-repo"]) == 2
        _assert_both_overrides(override_spy, False)

    def test_flag_only(self, override_spy: dict) -> None:
        assert self._run(["--trust-repo"]) == 2
        _assert_both_overrides(override_spy, True)

    def test_neither(self, override_spy: dict) -> None:
        assert self._run([]) == 2
        _assert_both_overrides(override_spy, False)


# ---------------------------------------------------------------------------
# raw-flag override calls must not come back
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rel_path", [
    "packages/sca/cli.py",
    "packages/sca/bump/cli.py",
    "packages/sca/harden.py",
    "libexec/raptor-sca-run",
])
def test_entrypoints_have_no_raw_flag_override(rel_path: str) -> None:
    """The direct ``set_trust_override(True)``-from-raw-flag pattern
    is the regression these entry points just shed. All propagation
    must route through ``resolve_repo_trust`` so the pipeline value
    and the process-wide gates can never disagree."""
    src = (_REPO_ROOT / rel_path).read_text(encoding="utf-8")
    assert "set_trust_override(True)" not in src, (
        f"{rel_path}: raw-flag trust override reintroduced; route "
        f"through packages.sca._scan_args.resolve_repo_trust instead"
    )
