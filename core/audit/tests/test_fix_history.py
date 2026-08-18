"""Fix-history mining: variant hunts + regression hypotheses.

The target's git history was consulted only per-finding, after the
fact, as corroboration. These tests pin the new pre-loop enrichment:
past security fixes mined under the hardened read-only git substrate,
structurally similar un-fixed sites injected as high-priority gaps
with hypotheses, and "was the fix lost?" hypotheses when a fix's added
lines vanished from the current tree. Fixture repos are built in
tmp_path; the sandbox chokepoint is spied and executes git directly.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from core.audit.fix_history import (
    FIX_HISTORY_BOOST,
    MAX_FIXES_PER_RUN,
    SecurityFix,
    apply_fix_history,
    fix_pattern_variant_gaps,
    fix_sweep_targets,
    mine_security_fixes,
    parse_show_diff,
    regression_gaps,
)
from core.testing import git_run, init_scratch_repo

HAVE_GIT = shutil.which("git") is not None
needs_git = pytest.mark.skipif(not HAVE_GIT, reason="git not installed")


@pytest.fixture
def sandbox_spy(monkeypatch):
    """Record sandbox kwargs, then execute git directly."""
    calls: list[dict] = []

    def fake_sandbox_run(cmd, **kwargs):
        calls.append({"cmd": cmd, **kwargs})
        fwd = {
            k: kwargs[k]
            for k in ("capture_output", "text", "timeout", "cwd", "env")
            if k in kwargs and kwargs[k] is not None
        }
        return subprocess.run(cmd, check=False, **fwd)

    monkeypatch.setattr("core.sandbox.context.run", fake_sandbox_run)
    return calls


# Hermetic git fixture helpers — shared scaffolding from core.testing
# (this file used to carry byte-for-byte copies of test_git_oracle's).
_git = git_run
_init_repo = init_scratch_repo


VULN_HANDLER = (
    "void handler(char *p) {\n"
    "    write_config(p);\n"
    "}\n"
)
FIXED_HANDLER = (
    "void handler(char *p) {\n"
    "    validate_path(p);\n"
    "    write_config(p);\n"
    "}\n"
)
OTHER_CALLER = (
    "void other_caller(char *p) {\n"
    "    write_config(p);\n"
    "}\n"
)


def _make_fix_repo(tmp_path: Path) -> Path:
    """Repo with a security fix in handler.c and an un-fixed sibling
    call site in other.c."""
    repo = _init_repo(tmp_path)
    (repo / "handler.c").write_text(VULN_HANDLER)
    (repo / "other.c").write_text(OTHER_CALLER)
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "initial import")
    (repo / "handler.c").write_text(FIXED_HANDLER)
    _git(repo, "add", "handler.c")
    _git(
        repo, "commit", "-q", "-m",
        "Fix path traversal vulnerability in handler (CVE-2024-1234)",
    )
    return repo


def _checklist() -> dict:
    return {
        "files": [
            {
                "path": "handler.c",
                "items": [
                    {
                        "name": "handler",
                        "kind": "function",
                        "line_start": 1,
                        "line_end": 4,
                    }
                ],
            },
            {
                "path": "other.c",
                "items": [
                    {
                        "name": "other_caller",
                        "kind": "function",
                        "line_start": 1,
                        "line_end": 3,
                    }
                ],
            },
        ]
    }


class TestParseShowDiff:
    def test_parses_added_and_removed_with_line_numbers(self):
        diff = (
            "diff --git a/handler.c b/handler.c\n"
            "--- a/handler.c\n"
            "+++ b/handler.c\n"
            "@@ -1,0 +2 @@ void handler\n"
            "+    validate_path(p);\n"
            "@@ -5 -5,0 @@\n"
        )
        parsed = parse_show_diff(diff)
        assert parsed["handler.c"]["added"] == [
            (2, "    validate_path(p);")
        ]

    def test_removed_lines_collected(self):
        diff = (
            "+++ b/x.c\n"
            "@@ -3,1 +3,0 @@\n"
            "-    strcpy(dst, src);\n"
        )
        parsed = parse_show_diff(diff)
        assert parsed["x.c"]["removed"] == ["    strcpy(dst, src);"]

    def test_garbage_is_survivable(self):
        assert parse_show_diff("") == {}
        assert parse_show_diff("random text\n+not a diff") == {}


class TestFixSweepTargets:
    def test_sensitive_from_removed_guard_from_added(self):
        fix = SecurityFix(
            sha="a" * 40,
            subject="fix overflow",
            category="overflow",
            added={"x.c": [(2, "    validate_path(p);"),
                           (3, "    write_config(p);")]},
            removed={"x.c": ["    write_config(p);"]},
        )
        sensitive, guard = fix_sweep_targets(fix)
        assert sensitive == "write_config"
        assert guard == "validate_path"

    def test_pure_addition_fix_has_no_sweep_anchor(self):
        fix = SecurityFix(
            sha="a" * 40, subject="s", category="cve",
            added={"x.c": [(2, "    validate_path(p);")]},
        )
        sensitive, _guard = fix_sweep_targets(fix)
        assert sensitive is None


@needs_git
class TestMineSecurityFixes:
    def test_mines_fix_with_diff(self, tmp_path, sandbox_spy):
        repo = _make_fix_repo(tmp_path)
        fixes = mine_security_fixes(repo)
        assert len(fixes) == 1
        fix = fixes[0]
        assert fix.category in ("cve", "vulnerability", "security")
        assert "handler.c" in fix.added
        added_texts = [t for _ln, t in fix.added["handler.c"]]
        assert any("validate_path" in t for t in added_texts)

    def test_non_repo_returns_empty(self, tmp_path, sandbox_spy):
        assert mine_security_fixes(tmp_path) == []

    def test_hardened_invocation(self, tmp_path, sandbox_spy):
        repo = _make_fix_repo(tmp_path)
        mine_security_fixes(repo)
        assert sandbox_spy, "git ran outside the sandbox chokepoint"
        for call in sandbox_spy:
            cmd = call["cmd"]
            assert call.get("block_network") is True
            assert "--no-pager" in cmd
            # Strict read-only overrides ride every invocation.
            assert any(
                a == "protocol.allow=never" for a in cmd
            ), cmd
        show_calls = [
            c for c in sandbox_spy if "show" in c["cmd"]
        ]
        assert show_calls
        for c in show_calls:
            assert "--no-ext-diff" in c["cmd"]

    def test_bounded(self, tmp_path, sandbox_spy):
        repo = _init_repo(tmp_path)
        f = repo / "a.c"
        f.write_text("int x;\n")
        _git(repo, "add", ".")
        _git(repo, "commit", "-q", "-m", "initial")
        for i in range(MAX_FIXES_PER_RUN + 3):
            f.write_text(f"int x{i}; overflow_guard();\n")
            _git(repo, "add", "a.c")
            _git(repo, "commit", "-q", "-m", f"fix buffer overflow #{i}")
        fixes = mine_security_fixes(repo)
        assert len(fixes) == MAX_FIXES_PER_RUN


@needs_git
class TestVariantGaps:
    def test_unfixed_sibling_site_becomes_gap(self, tmp_path, sandbox_spy):
        repo = _make_fix_repo(tmp_path)
        fixes = mine_security_fixes(repo)
        gaps = fix_pattern_variant_gaps(fixes, _checklist(), repo)
        assert len(gaps) == 1
        gap = gaps[0]
        assert gap["file"] == "other.c"
        assert gap["name"] == "other_caller"
        assert gap["from_fix_history"] is True
        assert gap["priority_score"] >= FIX_HISTORY_BOOST
        hyp = gap["injected_hypotheses"][0]
        assert hyp["source"] == "fix_history_variant"
        assert "write_config" in hyp["mechanism"]
        assert "validate_path" in hyp["mechanism"]

    def test_guarded_site_not_flagged(self, tmp_path, sandbox_spy):
        repo = _make_fix_repo(tmp_path)
        # The sibling now carries the guard — no variant.
        (repo / "other.c").write_text(
            "void other_caller(char *p) {\n"
            "    validate_path(p);\n"
            "    write_config(p);\n"
            "}\n"
        )
        fixes = mine_security_fixes(repo)
        gaps = fix_pattern_variant_gaps(fixes, _checklist(), repo)
        assert gaps == []

    def test_fix_own_file_skipped(self, tmp_path, sandbox_spy):
        repo = _make_fix_repo(tmp_path)
        (repo / "other.c").unlink()
        fixes = mine_security_fixes(repo)
        gaps = fix_pattern_variant_gaps(fixes, _checklist(), repo)
        assert all(g["file"] != "handler.c" for g in gaps)

    def test_inprocess_fallback_when_semgrep_absent(
        self, tmp_path, sandbox_spy, monkeypatch,
    ):
        import packages.semgrep.runner as semgrep_runner

        monkeypatch.setattr(semgrep_runner, "is_available", lambda: False)
        repo = _make_fix_repo(tmp_path)
        fixes = mine_security_fixes(repo)
        gaps = fix_pattern_variant_gaps(fixes, _checklist(), repo)
        assert len(gaps) == 1
        assert gaps[0]["name"] == "other_caller"

    def test_semgrep_machinery_used_when_injected(
        self, tmp_path, sandbox_spy,
    ):
        repo = _make_fix_repo(tmp_path)
        fixes = mine_security_fixes(repo)
        calls = []

        class _Finding:
            file = "other.c"
            line = 2

        class _Result:
            findings = [_Finding()]  # noqa: RUF012 — stub result
            returncode = 0

        def fake_run_rule(target, config, *, timeout=0, **kw):
            calls.append((target, config))
            return _Result()

        gaps = fix_pattern_variant_gaps(
            fixes, _checklist(), repo, run_rule_fn=fake_run_rule,
        )
        assert calls, "semgrep sweep not invoked"
        assert len(gaps) == 1
        assert gaps[0]["name"] == "other_caller"


@needs_git
class TestRegressionGaps:
    def test_lost_fix_generates_hypothesis(self, tmp_path, sandbox_spy):
        repo = _make_fix_repo(tmp_path)
        # Refactor away the fix: the added validate_path line vanishes.
        (repo / "handler.c").write_text(VULN_HANDLER)
        fixes = mine_security_fixes(repo)
        gaps = regression_gaps(fixes, _checklist(), repo)
        assert len(gaps) == 1
        gap = gaps[0]
        assert gap["file"] == "handler.c"
        assert gap["name"] == "handler"
        hyp = gap["injected_hypotheses"][0]
        assert hyp["source"] == "fix_history_regression"
        assert "was the fix lost" in hyp["mechanism"].lower()

    def test_surviving_fix_generates_nothing(self, tmp_path, sandbox_spy):
        repo = _make_fix_repo(tmp_path)
        fixes = mine_security_fixes(repo)
        assert regression_gaps(fixes, _checklist(), repo) == []

    def test_deleted_file_generates_nothing(self, tmp_path, sandbox_spy):
        repo = _make_fix_repo(tmp_path)
        (repo / "handler.c").unlink()
        fixes = mine_security_fixes(repo)
        assert regression_gaps(fixes, _checklist(), repo) == []


@needs_git
class TestApplyFixHistory:
    def test_merges_into_existing_gap_and_appends_new(
        self, tmp_path, sandbox_spy,
    ):
        repo = _make_fix_repo(tmp_path)
        existing = [
            {
                "file": "other.c",
                "name": "other_caller",
                "priority": 1,
                "priority_score": 4,
                "sloc": 3,
                "strategies": [],
            }
        ]
        merged = apply_fix_history(
            existing, _checklist(), repo, out_dir=tmp_path / "out",
        )
        assert len(merged) == 1
        gap = merged[0]
        assert gap["priority_score"] == 4 + FIX_HISTORY_BOOST
        assert gap["injected_hypotheses"]

    def test_appends_gap_for_unlisted_function(self, tmp_path, sandbox_spy):
        repo = _make_fix_repo(tmp_path)
        merged = apply_fix_history([], _checklist(), repo)
        assert len(merged) == 1
        assert merged[0]["name"] == "other_caller"

    def test_writes_artifact(self, tmp_path, sandbox_spy):
        import json

        repo = _make_fix_repo(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        apply_fix_history([], _checklist(), repo, out_dir=out)
        data = json.loads((out / "fix-history.json").read_text())
        assert data["fixes"]
        assert data["variant_gaps"]

    def test_non_repo_is_noop(self, tmp_path):
        gaps = [{"file": "a.c", "name": "f", "priority": 1}]
        assert apply_fix_history(gaps, _checklist(), tmp_path) is gaps


class TestNeverAVerdict:
    def test_no_evidence_tier_vocabulary(self):
        import inspect

        import core.audit.fix_history as mod

        src = inspect.getsource(mod)
        assert "VALID_EVIDENCE_TOOLS" not in src
        assert "evidence_tool" not in src

    def test_orchestrator_wiring_is_pre_budget(self):
        import inspect

        from core.audit import orchestrator as orch_mod

        src = inspect.getsource(orch_mod._compute_audit_prep)
        idx_fix = src.index("apply_fix_history(")
        # The budget cut is the truncation-reporting helper (the raw
        # slice it replaced would silently drop the tail).
        idx_budget = src.index("truncate_gaps_to_budget(")
        assert idx_fix < idx_budget


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
