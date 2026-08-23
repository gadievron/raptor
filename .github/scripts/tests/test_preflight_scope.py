"""Unit tests for the preflight changed-test-file scoper."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "preflight_scope.py"


@pytest.fixture(scope="module")
def ps():
    spec = importlib.util.spec_from_file_location("preflight_scope", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _tree(root: Path, files: list[str]) -> Path:
    for rel in files:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("", encoding="utf-8")
    return root


class TestChangedTestFiles:
    def test_keeps_only_existing_test_files(self, ps, tmp_path):
        repo = _tree(tmp_path, [
            "core/audit/tests/test_b.py",
            "core/audit/tests/test_a.py",
            "core/audit/validate.py",
            "docs/audit.md",
        ])
        changed = [
            "core/audit/tests/test_b.py",
            "core/audit/tests/test_a.py",
            "core/audit/validate.py",       # not a test
            "docs/audit.md",                # not Python
            "core/audit/tests/test_gone.py",  # deleted in this PR
        ]
        assert ps.changed_test_files(changed, repo) == [
            "core/audit/tests/test_a.py",
            "core/audit/tests/test_b.py",
        ]

    def test_excludes_conftest_and_fixtures(self, ps, tmp_path):
        repo = _tree(tmp_path, [
            "conftest.py",
            "core/audit/tests/conftest.py",
            "core/audit/tests/fixtures/test_app.py",
            "core/audit/tests/test_real.py",
        ])
        changed = [
            "conftest.py",
            "core/audit/tests/conftest.py",
            "core/audit/tests/fixtures/test_app.py",
            "core/audit/tests/test_real.py",
        ]
        assert ps.changed_test_files(changed, repo) == [
            "core/audit/tests/test_real.py",
        ]

    def test_deduplicates(self, ps, tmp_path):
        repo = _tree(tmp_path, ["packages/sca/tests/test_x.py"])
        changed = ["packages/sca/tests/test_x.py"] * 3
        assert ps.changed_test_files(changed, repo) == [
            "packages/sca/tests/test_x.py",
        ]


class TestMain:
    def _run(self, ps, tmp_path, monkeypatch, changed_lines=None,
             changed_arg=True):
        out = tmp_path / "github_output.txt"
        out.write_text("", encoding="utf-8")
        monkeypatch.setenv("GITHUB_OUTPUT", str(out))
        argv = ["--repo", str(tmp_path)]
        if changed_arg:
            cf = tmp_path / "changed_files.txt"
            if changed_lines is not None:
                cf.write_text("\n".join(changed_lines), encoding="utf-8")
            argv += ["--changed-files", str(cf)]
        rc = ps.main(argv)
        assert rc == 0
        return dict(
            line.split("=", 1)
            for line in out.read_text(encoding="utf-8").splitlines()
        )

    def test_emits_run_true_and_sorted_file_list(
        self, ps, tmp_path, monkeypatch
    ):
        _tree(tmp_path, [
            "core/x/tests/test_b.py",
            "core/x/tests/test_a.py",
        ])
        outputs = self._run(
            ps, tmp_path, monkeypatch,
            changed_lines=[
                "core/x/tests/test_b.py",
                "core/x/tests/test_a.py",
            ],
        )
        assert outputs["run"] == "true"
        assert outputs["test_files"] == (
            "core/x/tests/test_a.py core/x/tests/test_b.py"
        )

    def test_no_changed_tests_emits_run_false(
        self, ps, tmp_path, monkeypatch
    ):
        _tree(tmp_path, ["core/x/module.py"])
        outputs = self._run(
            ps, tmp_path, monkeypatch, changed_lines=["core/x/module.py"],
        )
        assert outputs["run"] == "false"
        assert outputs["test_files"] == ""

    def test_missing_list_file_emits_run_false(
        self, ps, tmp_path, monkeypatch
    ):
        outputs = self._run(
            ps, tmp_path, monkeypatch, changed_lines=None,
        )
        assert outputs["run"] == "false"

    def test_no_list_argument_emits_run_false(
        self, ps, tmp_path, monkeypatch
    ):
        outputs = self._run(
            ps, tmp_path, monkeypatch, changed_arg=False,
        )
        assert outputs["run"] == "false"
