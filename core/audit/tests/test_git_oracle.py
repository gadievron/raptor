"""Tests for core.audit.git_oracle.

The sandbox entry (``core.sandbox.context.run``) is monkeypatched in
every test that runs git: the spy records the sandbox kwargs (so we can
assert ``block_network=True`` and the per-invocation hardening flags)
and then runs git directly — the suite must pass on hosts where
namespace isolation is unavailable, and must never require network.

Real git is used where present; every git-running test is guarded by a
skipif so the suite degrades gracefully on hosts without it.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from core.audit import git_oracle
from core.audit.evidence_grade import VALID_EVIDENCE_TOOLS, is_tool_evidence
from core.audit.git_oracle import (
    CORROBORATION_KIND,
    NOT_A_VERDICT_NOTE,
    CorroborationRecord,
    GitCorroboration,
    _match_labels,
    _parse_log_records,
    _parse_sha_lines,
    corroborate_finding,
    corroboration_for_journal,
)
from core.audit.sweep import SweepResult
from core.git.clone import safe_git_readonly_command
from core.testing import git_run, init_scratch_repo

HAVE_GIT = shutil.which("git") is not None

needs_git = pytest.mark.skipif(not HAVE_GIT, reason="git not installed")


@pytest.fixture(autouse=True)
def _fresh_cache():
    git_oracle._reset_cache()
    yield
    git_oracle._reset_cache()


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


# Hermetic git for FIXTURE SETUP (RAPTOR-authored content only) —
# shared scaffolding from core.testing.
_git = git_run


def _make_repo(tmp_path: Path) -> Path:
    """A local clone with security-relevant and irrelevant history."""
    repo = init_scratch_repo(tmp_path)
    src = repo / "src.c"
    lines = [f"int line_{i};" for i in range(1, 11)]
    src.write_text("\n".join(lines) + "\n")
    (repo / "other.c").write_text("int other;\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "initial import")

    # Security fix touching src.c line 2 (in-range for 1..5).
    lines[1] = "int line_2_fixed;"
    src.write_text("\n".join(lines) + "\n")
    _git(repo, "add", "src.c")
    _git(repo, "commit", "-q", "-m",
         "Fix buffer overflow in parser (CVE-2021-1234)")

    # Unrelated commit on another file.
    (repo / "other.c").write_text("int other2;\n")
    _git(repo, "add", "other.c")
    _git(repo, "commit", "-q", "-m", "unrelated refactor")

    # Non-security commit on src.c.
    lines[5] = "int line_6;  "
    src.write_text("\n".join(lines) + "\n")
    _git(repo, "add", "src.c")
    _git(repo, "commit", "-q", "-m", "cleanup whitespace")

    # Second security fix touching src.c line 9 (out of range 1..5).
    lines[8] = "int line_9_sanitized;"
    src.write_text("\n".join(lines) + "\n")
    _git(repo, "add", "src.c")
    _git(repo, "commit", "-q", "-m",
         "sanitize input length to close a use-after-free window")

    return repo


# ---------------------------------------------------------------------------
# Corroboration behaviour
# ---------------------------------------------------------------------------


@needs_git
class TestCorroboration:
    def test_security_commits_found(self, tmp_path, sandbox_spy):
        repo = _make_repo(tmp_path)
        result = corroborate_finding(
            target_path=repo, file_path="src.c", out_dir=tmp_path / "out",
        )
        assert result.available
        subjects = [r.subject for r in result.records]
        assert any("CVE-2021-1234" in s for s in subjects)
        assert any("sanitize" in s for s in subjects)
        # Non-security and other-file commits never surface.
        assert not any("whitespace" in s for s in subjects)
        assert not any("refactor" in s for s in subjects)

    def test_record_structure(self, tmp_path, sandbox_spy):
        repo = _make_repo(tmp_path)
        result = corroborate_finding(
            target_path=repo, file_path="src.c", out_dir=tmp_path / "out",
        )
        for r in result.records:
            assert len(r.sha) == 40
            assert r.date  # iso-strict committer date
            assert "src.c" in r.files
            assert r.matched_patterns
        cve = next(r for r in result.records if "CVE" in r.subject)
        assert "cve" in cve.matched_patterns
        assert "overflow" in cve.matched_patterns

    def test_line_range_annotation(self, tmp_path, sandbox_spy):
        repo = _make_repo(tmp_path)
        result = corroborate_finding(
            target_path=repo, file_path="src.c",
            line_start=1, line_end=5, out_dir=tmp_path / "out",
        )
        by_subject = {r.subject: r for r in result.records}
        cve = next(v for k, v in by_subject.items() if "CVE" in k)
        uaf = next(v for k, v in by_subject.items() if "sanitize" in k)
        assert cve.touches_range is True    # changed line 2
        assert uaf.touches_range is False   # changed line 9

    def test_no_range_leaves_annotation_absent(self, tmp_path, sandbox_spy):
        repo = _make_repo(tmp_path)
        result = corroborate_finding(
            target_path=repo, file_path="src.c", out_dir=tmp_path / "out",
        )
        assert all(r.touches_range is None for r in result.records)

    def test_file_without_security_history_is_empty(self, tmp_path, sandbox_spy):
        repo = _make_repo(tmp_path)
        result = corroborate_finding(
            target_path=repo, file_path="other.c", out_dir=tmp_path / "out",
        )
        assert result.available
        assert result.records == []

    def test_max_commits_cap(self, tmp_path, sandbox_spy):
        repo = _make_repo(tmp_path)
        result = corroborate_finding(
            target_path=repo, file_path="src.c", max_commits=1,
            out_dir=tmp_path / "out",
        )
        assert len(result.records) == 1

    def test_file_level_query_is_cached(self, tmp_path, sandbox_spy):
        repo = _make_repo(tmp_path)
        for _ in range(3):
            corroborate_finding(
                target_path=repo, file_path="src.c", out_dir=tmp_path / "out",
            )
        grep_calls = [
            c for c in sandbox_spy
            if any(str(a).startswith("--grep=") for a in c["cmd"])
        ]
        assert len(grep_calls) == 1


# ---------------------------------------------------------------------------
# NEVER a verdict — impossible by construction
# ---------------------------------------------------------------------------


class TestNeverAVerdict:
    def test_stamp_is_not_tool_evidence(self):
        assert not is_tool_evidence(CORROBORATION_KIND)
        assert not is_tool_evidence("git_history")
        assert not is_tool_evidence("git_history:cve")
        assert not is_tool_evidence("git_history:CVE-2021-1234")
        # Composites containing it must not pass either.
        assert not is_tool_evidence("semgrep+git_history")

    def test_namespace_not_registered_as_evidence_tool(self):
        assert CORROBORATION_KIND not in VALID_EVIDENCE_TOOLS
        assert not any("git_history" in t for t in VALID_EVIDENCE_TOOLS)

    def test_result_types_have_no_outcome(self):
        corr = GitCorroboration(file_path="a.c")
        rec = CorroborationRecord(sha="0" * 40, subject="s", date="d")
        assert not hasattr(corr, "outcome")
        assert not hasattr(rec, "outcome")
        assert not isinstance(corr, SweepResult)

    def test_journal_payload_is_marked_corroboration(self):
        corr = GitCorroboration(
            file_path="a.c",
            records=[CorroborationRecord(sha="0" * 40, subject="s", date="d")],
        )
        payload = corr.to_journal_dict()
        assert payload["kind"] == "corroboration"
        assert payload["source"] == CORROBORATION_KIND
        assert payload["note"] == NOT_A_VERDICT_NOTE
        assert "outcome" not in payload
        assert "verdict" not in payload

    def test_oracle_module_never_imports_sweep_or_evidence(self):
        import ast
        import inspect
        tree = ast.parse(inspect.getsource(git_oracle))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported.add(node.module or "")
            elif isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
        assert not any("sweep" in m for m in imported)
        assert not any("evidence" in m for m in imported)


# ---------------------------------------------------------------------------
# Graceful emptiness
# ---------------------------------------------------------------------------


class TestGracefulEmptiness:
    def test_not_a_git_repo(self, tmp_path):
        target = tmp_path / "plain"
        target.mkdir()
        (target / "a.c").write_text("int x;\n")
        result = corroborate_finding(target_path=target, file_path="a.c")
        assert not result.available
        assert result.records == []
        assert "not a git repository" in result.reason

    def test_git_absent(self, tmp_path, monkeypatch):
        target = tmp_path / "repo"
        (target / ".git").mkdir(parents=True)
        monkeypatch.setattr(shutil, "which", lambda *a, **k: None)
        result = corroborate_finding(target_path=target, file_path="a.c")
        assert not result.available
        assert result.records == []
        assert "git not installed" in result.reason

    def test_path_escape(self, tmp_path):
        target = tmp_path / "repo"
        (target / ".git").mkdir(parents=True)
        result = corroborate_finding(
            target_path=target, file_path="../evil.c",
        )
        assert not result.available
        assert result.records == []

    @needs_git
    def test_sandbox_unavailable_refuses_to_run(self, tmp_path, monkeypatch):
        repo = _make_repo(tmp_path)
        import builtins
        real_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name == "core.sandbox.context":
                raise ImportError("blocked for test")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", blocked)
        result = corroborate_finding(target_path=repo, file_path="src.c")
        assert not result.available
        assert result.records == []

    @needs_git
    def test_journal_helper_none_when_empty(self, tmp_path, sandbox_spy):
        repo = _make_repo(tmp_path)
        assert corroboration_for_journal(
            target_path=repo, file_path="other.c", out_dir=tmp_path / "out",
        ) is None

    @needs_git
    def test_journal_helper_payload_when_corroborated(self, tmp_path, sandbox_spy):
        repo = _make_repo(tmp_path)
        payload = corroboration_for_journal(
            target_path=repo, file_path="src.c", out_dir=tmp_path / "out",
        )
        assert payload is not None
        assert payload["kind"] == "corroboration"
        assert payload["records"]

    def test_journal_helper_swallows_exceptions(self, monkeypatch):
        def boom(**kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(git_oracle, "corroborate_finding", boom)
        assert corroboration_for_journal(
            target_path=Path("/nonexistent"), file_path="a.c",
        ) is None


# ---------------------------------------------------------------------------
# Hardened, sandboxed invocation contract
# ---------------------------------------------------------------------------


@needs_git
class TestHardenedInvocation:
    def test_sandbox_kwargs_and_hardening_flags(self, tmp_path, sandbox_spy):
        repo = _make_repo(tmp_path)
        corroborate_finding(
            target_path=repo, file_path="src.c",
            line_start=1, line_end=5, out_dir=tmp_path / "out",
        )
        assert sandbox_spy  # every git run went through the sandbox
        for call in sandbox_spy:
            cmd = call["cmd"]
            assert isinstance(cmd, list)
            assert all(isinstance(a, str) for a in cmd)
            assert call["block_network"] is True
            assert call["target"] == str(repo)
            assert "timeout" in call
            # Per-invocation hardening — the FULL shared strict
            # read-only posture from core.git (single source of
            # truth), asserted via the shared helper rather than
            # duplicated literals.  argv[0] is the resolved absolute
            # git path; the rest of the prefix must match exactly.
            expected = safe_git_readonly_command()
            assert cmd[1:len(expected)] == expected[1:]

    def test_shared_posture_carries_spec_mandated_pins(self):
        """Guard against a silent weakening of the SHARED constant: the
        oracle's spec-mandated pins must still be present in what
        ``safe_git_readonly_command`` emits."""
        cmd = safe_git_readonly_command()
        assert "--no-pager" in cmd
        for override in (
            "core.hooksPath=/dev/null",
            "protocol.allow=never",
            "protocol.file.allow=never",
            "core.sshCommand=false",
        ):
            idx = cmd.index(override)
            assert cmd[idx - 1] == "-c"
        # fsmonitor neutralised (an empty value disables the monitor
        # regardless of hostile per-repo config; `false` would too).
        fsmon = [a for a in cmd if str(a).startswith("core.fsmonitor=")]
        assert fsmon and fsmon[0] in ("core.fsmonitor=", "core.fsmonitor=false")

    def test_line_range_log_is_ext_diff_proof(self, tmp_path, sandbox_spy):
        """``git log -L`` forces patch output (diff-family) and
        diff.external cannot be neutralised via ``-c`` — the invocation
        must carry ``--no-ext-diff``."""
        repo = _make_repo(tmp_path)
        corroborate_finding(
            target_path=repo, file_path="src.c",
            line_start=1, line_end=5, out_dir=tmp_path / "out",
        )
        l_calls = [c for c in sandbox_spy if "-L" in c["cmd"]]
        assert l_calls
        for call in l_calls:
            assert "--no-ext-diff" in call["cmd"]

    def test_no_shell_string_ever(self, tmp_path, sandbox_spy):
        repo = _make_repo(tmp_path)
        corroborate_finding(
            target_path=repo, file_path="src.c", out_dir=tmp_path / "out",
        )
        for call in sandbox_spy:
            assert not isinstance(call["cmd"], str)
            assert "shell" not in call or not call["shell"]

    def test_hostile_fsmonitor_config_is_neutralised(self, tmp_path, sandbox_spy):
        # A hostile clone ships .git/config pointing fsmonitor and
        # hooksPath at attacker scripts.  The -c overrides must win:
        # the query still succeeds and no marker file appears.
        repo = _make_repo(tmp_path)
        marker = tmp_path / "pwned"
        evil = repo / ".git" / "evil.sh"
        evil.write_text(f"#!/bin/sh\ntouch {marker}\n")
        evil.chmod(0o755)
        hooks = repo / ".git" / "evil-hooks"
        hooks.mkdir()
        for hook in ("post-checkout", "post-commit", "pre-auto-gc"):
            h = hooks / hook
            h.write_text(f"#!/bin/sh\ntouch {marker}\n")
            h.chmod(0o755)
        with (repo / ".git" / "config").open("a") as f:
            f.write(
                f"[core]\n\tfsmonitor = {evil}\n"
                f"\thooksPath = {hooks}\n"
            )

        result = corroborate_finding(
            target_path=repo, file_path="src.c", out_dir=tmp_path / "out",
        )
        assert result.available
        assert result.records
        assert not marker.exists()

    def test_pathspec_after_double_dash(self, tmp_path, sandbox_spy):
        repo = _make_repo(tmp_path)
        corroborate_finding(
            target_path=repo, file_path="src.c", out_dir=tmp_path / "out",
        )
        cmd = sandbox_spy[0]["cmd"]
        assert cmd[-2:] == ["--", "src.c"]


# ---------------------------------------------------------------------------
# Parsing (no git needed)
# ---------------------------------------------------------------------------


class TestParsing:
    def test_parse_log_records(self):
        sha = "a" * 40
        stdout = (
            f"\x1e{sha}\x1f2024-01-02T03:04:05+00:00\x1f"
            "Fix overflow (CVE-2024-1)\x1fbody mentions sanitize\x1f\n\n"
            "src/parse.c\nsrc/util.c\n"
        )
        records = _parse_log_records(stdout)
        assert len(records) == 1
        r = records[0]
        assert r.sha == sha
        assert r.subject == "Fix overflow (CVE-2024-1)"
        assert r.date == "2024-01-02T03:04:05+00:00"
        assert r.files == ("src/parse.c", "src/util.c")
        assert "cve" in r.matched_patterns
        assert "overflow" in r.matched_patterns
        assert "sanitize" in r.matched_patterns

    def test_parse_rejects_malformed_sha(self):
        stdout = "\x1enot-a-sha\x1fd\x1fs\x1fb\x1f\nfile.c\n"
        assert _parse_log_records(stdout) == []

    def test_parse_rejects_short_records(self):
        assert _parse_log_records("\x1eabc\x1fonly-two") == []
        assert _parse_log_records("") == []

    def test_parse_sha_lines_ignores_diff_noise(self):
        sha = "b" * 40
        stdout = f"{sha}\ndiff --git a/x b/x\n@@ -1 +1 @@\n-old\n+new\n"
        assert _parse_sha_lines(stdout) == {sha}

    def test_match_labels(self):
        labels = _match_labels(
            "Sanitize header length", "prevents a heap overflow",
        )
        assert "sanitize" in labels
        assert "overflow" in labels
        assert "cve" not in labels

    def test_use_after_free_variants(self):
        assert "use_after_free" in _match_labels("fix use-after-free", "")
        assert "use_after_free" in _match_labels("Use after free in x", "")
