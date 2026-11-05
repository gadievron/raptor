"""Tests for extra scan targets and the sandbox scratch layout.

``extra_targets`` lets one semgrep invocation carry ride-along
targets (the negative-control fixture batching in core/audit/sweep).
The sandbox scratch is a process-shared PARENT with one fresh
fake-HOME subdirectory per invocation; scan results must never depend
on scratch contents, and no invocation may share its writable scratch
with another (fake-home symlink-TOCTOU isolation).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import packages.semgrep.runner as runner_mod
from packages.semgrep.runner import (
    _default_sandbox_runner,
    build_cmd,
    run_rule,
)


def _sarif_result(rule_id: str, uri: str, line: int) -> dict:
    return {
        "ruleId": rule_id,
        "message": {"text": rule_id},
        "level": "warning",
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line},
            },
        }],
    }


@pytest.fixture(autouse=True)
def _fresh_scratch(semgrep_scratch):
    return semgrep_scratch


class TestBuildCmdExtraTargets:
    def test_extra_targets_appended_after_target(self, tmp_path: Path):
        cmd = build_cmd(
            Path("/src/a.c"), "p/x", semgrep_bin="semgrep",
            extra_targets=[Path("/ctrl/fixture.c")],
        )
        assert cmd[-2:] == ["/src/a.c", "/ctrl/fixture.c"]

    def test_default_is_single_target(self):
        cmd = build_cmd(Path("/src/a.c"), "p/x", semgrep_bin="semgrep")
        assert cmd[-1] == "/src/a.c"


class TestSandboxScratch:

    def test_each_invocation_gets_a_fresh_scratch_dir(self, tmp_path: Path):
        """Per-invocation isolation is the TOCTOU defence: a live
        (compromised) child of call A holds write access to ITS
        output dir, so a dir shared with call B would let it race B's
        parent-side ``.home`` lstat sweep vs makedirs. Distinct dirs
        remove the shared write surface entirely."""
        captured: list[str] = []

        def fake_sandbox_run(cmd, **kwargs):
            captured.append(kwargs["output"])
            # Hostile child: damage this call's own scratch. Must not
            # be able to poison the NEXT call's scratch.
            home = Path(kwargs["output"]) / ".home"
            home.mkdir(parents=True, exist_ok=True)
            return MagicMock(stdout="", stderr="", returncode=0)

        with patch("core.sandbox.context.run", side_effect=fake_sandbox_run):
            for _ in range(2):
                runner = _default_sandbox_runner(tmp_path, "/local/rules.yaml")
                runner(["semgrep"], capture_output=True)

        assert len(captured) == 2
        assert captured[0] != captured[1]
        for out in captured:
            assert not Path(out).exists()
        # The second invocation started from an empty dir — nothing
        # the first call's child wrote persists into it.
        assert not (Path(captured[1]) / ".home" / "poison").exists()

    def test_invocation_dirs_share_one_atexit_parent(self, tmp_path: Path):
        """Invocations share an empty parent while per-call scratch is
        reclaimed immediately; atexit owns only the final backstop."""
        captured: list[str] = []

        def fake_sandbox_run(cmd, **kwargs):
            captured.append(kwargs["output"])
            return MagicMock(stdout="", stderr="", returncode=0)

        with patch("core.sandbox.context.run", side_effect=fake_sandbox_run):
            for _ in range(2):
                runner = _default_sandbox_runner(tmp_path, "/local/rules.yaml")
                runner(["semgrep"], capture_output=True)

        parent = runner_mod._sandbox_scratch_parent()
        assert [str(Path(c).parent) for c in captured] == [parent, parent]

    def test_reset_removes_scratch(self):
        parent = runner_mod._sandbox_scratch_parent()
        sub = runner_mod._invocation_scratch_dir()
        assert Path(parent).is_dir()
        assert Path(sub).is_dir()
        runner_mod._reset_sandbox_scratch()
        assert not Path(parent).exists()
        assert not Path(sub).exists()

    def test_leftover_scratch_state_does_not_reach_results(
        self, tmp_path: Path,
    ):
        """Results parse from stdout/--json-output only: junk an
        invocation's child leaves in its scratch (fake-HOME logs,
        settings) must never surface in a later result."""
        t = tmp_path / "src"
        t.mkdir()
        (t / "a.c").write_text("void f(void) {}\n", encoding="utf-8")
        sarif = json.dumps(
            {"runs": [{"results": [_sarif_result("r1", "src/a.c", 1)]}]},
        )

        def fake_sandbox_run(cmd, **kwargs):
            home = Path(kwargs["output"]) / ".home" / ".semgrep"
            home.mkdir(parents=True, exist_ok=True)
            (home / "semgrep.log").open("a").write("per-call log noise\n")
            (home / "settings.yml").write_text("anonymous_user_id: x\n")
            return MagicMock(stdout=sarif, stderr="", returncode=1)

        with patch("packages.semgrep.runner.is_available", return_value=True), \
             patch("core.sandbox.context.run", side_effect=fake_sandbox_run), \
             patch("packages.semgrep.runner._default_sandbox_runner",
                   wraps=runner_mod._default_sandbox_runner):
            first = run_rule(t, "/local/rules.yaml")
            second = run_rule(t, "/local/rules.yaml")

        assert [f.to_dict() for f in first.findings] == [
            f.to_dict() for f in second.findings
        ]
        assert first.errors == second.errors == []


class TestExplicitTargetsUnderProjectRoot:
    def test_argv_is_explicit_and_read_scope_is_project(self, tmp_path, monkeypatch):
        from types import SimpleNamespace

        root = tmp_path / "project"
        root.mkdir()
        first, second = root / "a.c", root / "b.c"
        first.touch()
        second.touch()
        observed = []
        monkeypatch.setattr(runner_mod, "is_available", lambda: True)
        monkeypatch.setattr(runner_mod, "scope_isolation_available", lambda: True)

        def fake_sandbox(cmd, **kwargs):
            observed.append((cmd, kwargs))
            output = Path(cmd[cmd.index("--json-output") + 1])
            output.write_text(json.dumps({"paths": {"scanned": [str(first), str(second)]}, "errors": []}))
            return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps({"version": "2.1.0", "runs": []}))

        monkeypatch.setattr("core.sandbox.context.run", fake_sandbox)
        result = run_rule(first, "/local/candidates.yml", extra_targets=(second,), target_root=root)
        assert result.ok, result.errors
        cmd, kwargs = observed[0]
        assert cmd[-2:] == [str(first), str(second)]
        assert str(root) not in cmd
        assert kwargs["target"] == str(root)
        assert str(first) not in kwargs["tool_paths"]
        assert str(second) not in kwargs["tool_paths"]
        assert kwargs["block_network"] is True

    @pytest.mark.parametrize("kind", ["primary", "extra", "symlink"])
    def test_outside_target_is_refused_before_launch(self, tmp_path, monkeypatch, kind):
        root = tmp_path / "project"
        root.mkdir()
        inside = root / "a.c"
        inside.touch()
        outside = tmp_path / "secret.c"
        outside.touch()
        link = root / "link.c"
        link.symlink_to(outside)
        monkeypatch.setattr(runner_mod, "is_available", lambda: pytest.fail("invalid scope reached tool discovery"))
        first, extras = ((outside, ()) if kind == "primary" else
                         (inside, (outside if kind == "extra" else link,)))
        result = run_rule(first, "rules.yml", extra_targets=extras, target_root=root)
        assert not result.ok and result.errors
        assert "target_root" in result.errors[0]

    def test_declared_root_never_becomes_a_tool_path_if_its_type_changes(self, tmp_path, monkeypatch):
        from types import SimpleNamespace
        root = tmp_path / "project"
        root.mkdir()
        first = root / "a.c"
        first.touch()
        outside = tmp_path / "secret"
        outside.write_text("outside project")
        monkeypatch.setattr(runner_mod, "is_available", lambda: True)
        monkeypatch.setattr(runner_mod, "scope_isolation_available", lambda: True)
        original = runner_mod._default_sandbox_runner
        scopes = []

        def change_after_validation(*args, **kwargs):
            root.rename(tmp_path / "original-project")
            root.symlink_to(outside)
            return original(*args, **kwargs)

        def observe(command, **scope):
            scopes.append(scope)
            return SimpleNamespace(returncode=2, stdout="", stderr="source unavailable")

        monkeypatch.setattr(runner_mod, "_default_sandbox_runner", change_after_validation)
        monkeypatch.setattr("core.sandbox.context.run", observe)
        result = run_rule(first, "local.yml", target_root=root)
        assert not result.ok
        assert scopes[0]["target"] == str(root)
        assert str(root) not in scopes[0]["tool_paths"]
        assert str(outside) not in scopes[0]["tool_paths"]
