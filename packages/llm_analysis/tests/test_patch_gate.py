"""Robustness tests for the mechanical patch-validation gate.

Covers the gate's whole surface as behaviours an adversarial patch
could probe:

  * strict unified-diff parse — accept well-formed, reject free-form /
    truncated / miscounted responses
  * scope matrix — in-span hunk, hunk in a different file, distant hunk
    in the same file, slack configurability
  * detector round-trip with a REAL semgrep rule on a tiny C fixture —
    the patched copy silences the rule while the unpatched copy still
    fires (and a cosmetic patch stays ``still-firing``)
  * negative-control failure — a detector that never fires on the
    unpatched copy annotates ``control: FAILED`` and marks the result
    unreliable
  * fail-closed sandbox degradation — no ``core.sandbox`` means no
    execution, only pure-Python annotations
  * end-to-end through the agent's ``generate_patch`` path with a stub
    LLM — the saved artifact gains the gate header, the finding gains
    ``patch_gate``

Sandbox-dependent tests skip when the host cannot run the sandbox or
semgrep is not installed — the pure-Python layers are always exercised.
"""

from __future__ import annotations

import difflib
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

# packages/llm_analysis/tests/test_patch_gate.py — parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from packages.llm_analysis import patch_gate  # noqa: E402
from packages.llm_analysis.patch_gate import (  # noqa: E402
    GateResult,
    extract_unified_diff,
    render_gate_block,
    run_patch_gate,
)

# ---------------------------------------------------------------------------
# Fixture material — a tiny compilable C file with a strcpy at line 6
# ---------------------------------------------------------------------------

VULN_C = """\
#include <stdio.h>
#include <string.h>

void greet(char *name) {
    char buf[16];
    strcpy(buf, name);
    printf("hi %s\\n", buf);
}
"""
FINDING_LINE = 6

FIXED_C = VULN_C.replace(
    "    strcpy(buf, name);\n",
    "    strncpy(buf, name, sizeof(buf) - 1);\n"
    "    buf[sizeof(buf) - 1] = '\\0';\n",
)

# Cosmetic edit: touches the finding's neighbourhood but keeps strcpy.
COSMETIC_C = VULN_C.replace(
    '    printf("hi %s\\n", buf);\n',
    '    printf("hello %s\\n", buf);\n',
)

STRCPY_RULE = """\
rules:
  - id: test-strcpy-fixed-buf
    message: strcpy into fixed buffer
    severity: ERROR
    languages: [c]
    pattern: strcpy($DST, $SRC)
"""

# A rule that matches nothing in the fixture — negative-control probe.
NEVER_FIRES_RULE = """\
rules:
  - id: test-strcpy-fixed-buf
    message: never present in the fixture
    severity: ERROR
    languages: [c]
    pattern: gets($X)
"""


def _make_diff(orig: str, fixed: str, path: str = "vuln.c") -> str:
    return "".join(difflib.unified_diff(
        orig.splitlines(keepends=True),
        fixed.splitlines(keepends=True),
        fromfile=f"a/{path}",
        tofile=f"b/{path}",
    ))


def _fenced_response(diff: str) -> str:
    return f"Here is the fix.\n\n```diff\n{diff}```\n\nBounded copy now.\n"


def _sandbox_available() -> bool:
    run = patch_gate._import_sandbox_run()
    if run is None:
        return False
    try:
        return run(["true"], capture_output=True, timeout=30).returncode == 0
    except Exception:  # noqa: BLE001 — any sandbox failure means "not usable here"
        return False


def _semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


needs_sandbox = pytest.mark.skipif(
    not _sandbox_available(), reason="core.sandbox not runnable on this host",
)
needs_semgrep = pytest.mark.skipif(
    not _semgrep_available(), reason="semgrep not installed",
)


@pytest.fixture
def fixture_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "vuln.c").write_text(VULN_C, encoding="utf-8")
    return repo


@pytest.fixture
def checkers_dir(tmp_path: Path) -> Path:
    d = tmp_path / "checkers"
    d.mkdir()
    (d / "test-strcpy-fixed-buf.yml").write_text(STRCPY_RULE, encoding="utf-8")
    return d


# ---------------------------------------------------------------------------
# 1. Diff parse accept / reject
# ---------------------------------------------------------------------------


class TestDiffParse:

    def test_fenced_diff_accepted(self):
        parsed = extract_unified_diff(_fenced_response(_make_diff(VULN_C, FIXED_C)))
        assert parsed is not None
        assert len(parsed.files) == 1
        assert parsed.files[0].new_path == "b/vuln.c"
        assert parsed.files[0].hunks

    def test_raw_unfenced_diff_accepted(self):
        parsed = extract_unified_diff(
            "Apply this:\n" + _make_diff(VULN_C, FIXED_C) + "\nThat's all.\n"
        )
        assert parsed is not None
        assert parsed.files[0].hunks

    def test_free_form_code_rejected(self):
        resp = (
            "Here is the complete fixed code:\n\n"
            "```c\n" + FIXED_C + "```\n\nUse strncpy.\n"
        )
        assert extract_unified_diff(resp) is None

    def test_prose_only_rejected(self):
        assert extract_unified_diff("Just use strncpy instead of strcpy.") is None
        assert extract_unified_diff("") is None

    def test_miscounted_hunk_rejected(self):
        bad = (
            "```diff\n"
            "--- a/vuln.c\n"
            "+++ b/vuln.c\n"
            "@@ -5,3 +5,3 @@\n"
            "     char buf[16];\n"
            "-    strcpy(buf, name);\n"
            "```\n"
        )
        assert extract_unified_diff(bad) is None

    def test_truncated_hunk_rejected(self):
        # Header promises three old lines; body ends after one.
        bad = (
            "--- a/vuln.c\n"
            "+++ b/vuln.c\n"
            "@@ -5,3 +5,3 @@\n"
            "     char buf[16];\n"
        )
        assert extract_unified_diff(bad) is None

    def test_multi_file_diff_parses_both_sections(self):
        diff = (
            _make_diff(VULN_C, FIXED_C)
            + _make_diff("int x = 1;\n", "int x = 2;\n", path="other.c")
        )
        parsed = extract_unified_diff(_fenced_response(diff))
        assert parsed is not None
        assert len(parsed.files) == 2

    def test_git_header_noise_tolerated(self):
        diff = (
            "diff --git a/vuln.c b/vuln.c\n"
            "index 1234567..89abcde 100644\n"
            + _make_diff(VULN_C, FIXED_C)
        )
        parsed = extract_unified_diff(_fenced_response(diff))
        assert parsed is not None

    def test_not_a_diff_annotates_and_skips_rest(self, fixture_repo):
        result = run_patch_gate(
            "```c\n" + FIXED_C + "```",
            repo_path=fixture_repo, file_path="vuln.c",
            start_line=FINDING_LINE, end_line=FINDING_LINE,
        )
        assert result.format == "not-a-unified-diff"
        assert result.scope is None
        assert result.detector is None
        assert result.control is None

    def test_mid_string_file_scheme_not_corrupted(
        self, tmp_path, monkeypatch,
    ):
        """A literal ``file://`` mid-path must survive normalisation.

        The pre-fix substring-``replace`` deleted the marker anywhere
        in the string, rewriting ``src/file://vuln.c`` (the directory
        ``src/file:`` — doubled separators collapse) to ``src/vuln.c``
        and skipping the gate on "source file not found".
        """
        monkeypatch.setattr(patch_gate, "_import_sandbox_run",
                            lambda: None)
        repo = tmp_path / "repo"
        weird_dir = repo / "src" / "file:"
        weird_dir.mkdir(parents=True)
        (weird_dir / "vuln.c").write_text(VULN_C, encoding="utf-8")
        result = run_patch_gate(
            _fenced_response(_make_diff(VULN_C, FIXED_C,
                                        path="src/file://vuln.c")),
            repo_path=repo, file_path="src/file://vuln.c",
            start_line=FINDING_LINE, end_line=FINDING_LINE,
        )
        assert not any("source file not found" in n
                       for n in result.notes)


# ---------------------------------------------------------------------------
# 2. Scope check matrix
# ---------------------------------------------------------------------------


class TestScopeCheck:

    def _gate(self, response: str, fixture_repo: Path, **kwargs) -> GateResult:
        return run_patch_gate(
            response,
            repo_path=fixture_repo, file_path="vuln.c",
            start_line=FINDING_LINE, end_line=FINDING_LINE,
            **kwargs,
        )

    def test_in_span_hunk_in_bounds(self, fixture_repo, monkeypatch):
        # Scope is pure Python — no sandbox needed for this assertion.
        monkeypatch.setattr(patch_gate, "_import_sandbox_run", lambda: None)
        result = self._gate(
            _fenced_response(_make_diff(VULN_C, FIXED_C)), fixture_repo,
        )
        assert result.scope == "in-bounds"
        assert result.out_of_scope_hunks == []

    def test_adjacent_file_hunk_flagged(self, fixture_repo, monkeypatch):
        monkeypatch.setattr(patch_gate, "_import_sandbox_run", lambda: None)
        diff = (
            _make_diff(VULN_C, FIXED_C)
            + _make_diff(
                "def check(u):\n    return True\n",
                "def check(u):\n    return u.admin\n",
                path="auth.py",
            )
        )
        result = self._gate(_fenced_response(diff), fixture_repo)
        assert result.scope == "OUT-OF-SCOPE HUNKS"
        assert any("auth.py" in h for h in result.out_of_scope_hunks)

    def test_distant_hunk_same_file_flagged(self, fixture_repo, monkeypatch):
        monkeypatch.setattr(patch_gate, "_import_sandbox_run", lambda: None)
        # A hunk 200 lines below the finding span, same file.
        diff = (
            "--- a/vuln.c\n"
            "+++ b/vuln.c\n"
            "@@ -200,3 +200,4 @@\n"
            " int deep(void) {\n"
            "-    return 1;\n"
            "+    setuid(0);\n"
            "+    return 1;\n"
            " }\n"
        )
        result = self._gate(_fenced_response(diff), fixture_repo)
        assert result.scope == "OUT-OF-SCOPE HUNKS"
        assert any("-200,3" in h for h in result.out_of_scope_hunks)

    def test_slack_is_configurable(self, fixture_repo, monkeypatch):
        monkeypatch.setattr(patch_gate, "_import_sandbox_run", lambda: None)
        response = _fenced_response(_make_diff(VULN_C, FIXED_C))
        # The generated hunk starts around line 3 — a zero slack makes
        # even the legitimate fix out-of-scope; the default keeps it in.
        tight = self._gate(response, fixture_repo, scope_slack=0)
        loose = self._gate(response, fixture_repo, scope_slack=40)
        assert tight.scope == "OUT-OF-SCOPE HUNKS"
        assert loose.scope == "in-bounds"

    def test_env_var_slack_override(self, fixture_repo, monkeypatch):
        monkeypatch.setattr(patch_gate, "_import_sandbox_run", lambda: None)
        monkeypatch.setenv("RAPTOR_PATCH_GATE_SCOPE_SLACK", "0")
        result = self._gate(
            _fenced_response(_make_diff(VULN_C, FIXED_C)), fixture_repo,
        )
        assert result.scope == "OUT-OF-SCOPE HUNKS"

    def test_garbage_env_slack_falls_back_to_default(self, fixture_repo, monkeypatch):
        monkeypatch.setattr(patch_gate, "_import_sandbox_run", lambda: None)
        monkeypatch.setenv("RAPTOR_PATCH_GATE_SCOPE_SLACK", "banana")
        result = self._gate(
            _fenced_response(_make_diff(VULN_C, FIXED_C)), fixture_repo,
        )
        assert result.scope == "in-bounds"

    def test_garbage_env_slack_warns(self, monkeypatch, caplog):
        """Malformed / negative overrides warn — same posture as the
        scan-threshold sibling — instead of silently using 40."""
        import logging

        monkeypatch.setenv("RAPTOR_PATCH_GATE_SCOPE_SLACK", "banana")
        with caplog.at_level(logging.WARNING):
            assert patch_gate._env_scope_slack() == 40
        assert any("RAPTOR_PATCH_GATE_SCOPE_SLACK" in r.getMessage()
                   and "not an int" in r.getMessage()
                   for r in caplog.records)

        caplog.clear()
        monkeypatch.setenv("RAPTOR_PATCH_GATE_SCOPE_SLACK", "-3")
        with caplog.at_level(logging.WARNING):
            assert patch_gate._env_scope_slack() == 40
        assert any("must be >= 0" in r.getMessage() for r in caplog.records)

    def test_valid_and_unset_env_slack_do_not_warn(self, monkeypatch, caplog):
        import logging

        monkeypatch.delenv("RAPTOR_PATCH_GATE_SCOPE_SLACK", raising=False)
        with caplog.at_level(logging.WARNING):
            assert patch_gate._env_scope_slack() == 40
            monkeypatch.setenv("RAPTOR_PATCH_GATE_SCOPE_SLACK", "7")
            assert patch_gate._env_scope_slack() == 7
        assert not [r for r in caplog.records
                    if "RAPTOR_PATCH_GATE_SCOPE_SLACK" in r.getMessage()]


# ---------------------------------------------------------------------------
# 3. Detector round-trip (real semgrep, real sandbox)
# ---------------------------------------------------------------------------


# Real semgrep replays (two sandboxed scans per gate run) are
# genuinely heavy — nightly tier, per the pytest.ini slow convention.
@pytest.mark.slow
@needs_sandbox
@needs_semgrep
class TestDetectorRoundTrip:

    def test_fix_silences_detector_and_control_holds(
        self, fixture_repo, checkers_dir,
    ):
        result = run_patch_gate(
            _fenced_response(_make_diff(VULN_C, FIXED_C)),
            repo_path=fixture_repo, file_path="vuln.c",
            start_line=FINDING_LINE, end_line=FINDING_LINE,
            rule_id="test-strcpy-fixed-buf", tool="semgrep",
            checkers_dir=checkers_dir, timeout=120,
        )
        assert result.format == "unified-diff"
        assert result.scope == "in-bounds"
        assert result.apply == "ok"
        assert result.detector == "silenced"
        assert result.control == "ok"
        assert result.reliable is True
        # Fixture is standalone-compilable C — differential check runs.
        assert result.compile == "ok"

    def test_cosmetic_patch_still_firing(self, fixture_repo, checkers_dir):
        result = run_patch_gate(
            _fenced_response(_make_diff(VULN_C, COSMETIC_C)),
            repo_path=fixture_repo, file_path="vuln.c",
            start_line=FINDING_LINE, end_line=FINDING_LINE,
            rule_id="test-strcpy-fixed-buf", tool="semgrep",
            checkers_dir=checkers_dir, timeout=120,
        )
        assert result.apply == "ok"
        assert result.detector == "still-firing"
        assert result.control == "ok"


# ---------------------------------------------------------------------------
# 4. Negative-control failure
# ---------------------------------------------------------------------------


@pytest.mark.slow
@needs_sandbox
@needs_semgrep
class TestNegativeControl:

    def test_detector_that_never_fires_fails_control(self, fixture_repo, tmp_path):
        checkers = tmp_path / "silent-checkers"
        checkers.mkdir()
        (checkers / "test-strcpy-fixed-buf.yml").write_text(
            NEVER_FIRES_RULE, encoding="utf-8",
        )
        result = run_patch_gate(
            _fenced_response(_make_diff(VULN_C, FIXED_C)),
            repo_path=fixture_repo, file_path="vuln.c",
            start_line=FINDING_LINE, end_line=FINDING_LINE,
            rule_id="test-strcpy-fixed-buf", tool="semgrep",
            checkers_dir=checkers, timeout=120,
        )
        assert result.control == "FAILED"
        assert result.reliable is False
        assert any("negative control FAILED" in n for n in result.notes)


# ---------------------------------------------------------------------------
# 5. Honest unsupported / degraded annotations
# ---------------------------------------------------------------------------


class TestDegradation:

    def test_sandbox_unavailable_fails_closed(self, fixture_repo, monkeypatch):
        monkeypatch.setattr(patch_gate, "_import_sandbox_run", lambda: None)
        result = run_patch_gate(
            _fenced_response(_make_diff(VULN_C, FIXED_C)),
            repo_path=fixture_repo, file_path="vuln.c",
            start_line=FINDING_LINE, end_line=FINDING_LINE,
            rule_id="test-strcpy-fixed-buf", tool="semgrep",
        )
        assert result.gate == "unavailable"
        # Pure-Python annotations still computed...
        assert result.format == "unified-diff"
        assert result.scope == "in-bounds"
        # ...but nothing executed.
        assert result.apply is None
        assert result.detector == "skipped"
        assert result.control == "skipped"
        assert result.compile == "skipped"
        assert any("sandbox unavailable" in n for n in result.notes)

    @needs_sandbox
    def test_unappliable_diff_annotates_apply_failed(self, fixture_repo):
        # Context lines that don't exist in the file — git apply rejects.
        diff = (
            "--- a/vuln.c\n"
            "+++ b/vuln.c\n"
            "@@ -5,3 +5,3 @@\n"
            "     char nothing_like_this[99];\n"
            "-    memcpy(buf, name, 999);\n"
            "+    memcpy(buf, name, 1);\n"
            "     return;\n"
        )
        result = run_patch_gate(
            _fenced_response(diff),
            repo_path=fixture_repo, file_path="vuln.c",
            start_line=FINDING_LINE, end_line=FINDING_LINE,
            rule_id="test-strcpy-fixed-buf", tool="semgrep", timeout=120,
        )
        assert result.format == "unified-diff"
        assert result.apply == "failed"
        assert result.detector == "skipped (patch did not apply)"
        assert result.control == "skipped"

    @needs_sandbox
    def test_codeql_recheck_honestly_unsupported(self, fixture_repo):
        result = run_patch_gate(
            _fenced_response(_make_diff(VULN_C, FIXED_C)),
            repo_path=fixture_repo, file_path="vuln.c",
            start_line=FINDING_LINE, end_line=FINDING_LINE,
            rule_id="cpp/unbounded-write", tool="codeql", timeout=120,
        )
        assert result.apply == "ok"
        assert result.detector == "recheck-unsupported (codeql)"
        assert result.control == "skipped"

    @needs_sandbox
    def test_unknown_tool_annotated_not_faked(self, fixture_repo):
        result = run_patch_gate(
            _fenced_response(_make_diff(VULN_C, FIXED_C)),
            repo_path=fixture_repo, file_path="vuln.c",
            start_line=FINDING_LINE, end_line=FINDING_LINE,
            rule_id="some-rule", tool="mystery-scanner", timeout=120,
        )
        assert result.detector == "recheck-unsupported (mystery-scanner)"

    def test_missing_source_file_skips_gate(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        result = run_patch_gate(
            _fenced_response(_make_diff(VULN_C, FIXED_C)),
            repo_path=repo, file_path="vuln.c",
            start_line=FINDING_LINE, end_line=FINDING_LINE,
        )
        assert result.gate == "skipped"

    def test_escaping_finding_path_skips_gate(self, fixture_repo):
        result = run_patch_gate(
            _fenced_response(_make_diff(VULN_C, FIXED_C)),
            repo_path=fixture_repo, file_path="../../etc/passwd",
            start_line=FINDING_LINE, end_line=FINDING_LINE,
        )
        assert result.gate == "skipped"
        assert any("escapes the repo" in n for n in result.notes)


# ---------------------------------------------------------------------------
# 6. Rendering
# ---------------------------------------------------------------------------


class TestRendering:

    def test_gate_block_lines_present(self):
        result = GateResult(
            format="unified-diff", scope="OUT-OF-SCOPE HUNKS",
            out_of_scope_hunks=["auth.py:@@ -1,2 (different file than the finding)"],
            apply="ok", detector="still-firing", control="ok",
            compile="skipped", reliable=True,
        )
        block = render_gate_block(result)
        assert "- format: unified-diff" in block
        assert "- scope: OUT-OF-SCOPE HUNKS" in block
        assert "- detector: still-firing" in block
        assert "- control: ok" in block
        assert "- compile: skipped" in block
        assert "auth.py" in block

    def test_llm_derived_markup_defanged(self):
        # Diff paths and stderr are LLM/tool-derived — autofetch markup
        # must not survive into the rendered block.
        result = GateResult(
            format="unified-diff", scope="OUT-OF-SCOPE HUNKS",
            out_of_scope_hunks=["![x](http://evil/exfil):@@ -1,1"],
            notes=["apply: <img src=http://evil/1.png>"],
        )
        block = render_gate_block(result)
        assert "![x](http://evil/exfil)" not in block
        assert "<img src=http://evil/1.png>" not in block

    def test_unreliable_flag_rendered(self):
        result = GateResult(
            format="unified-diff", control="FAILED", reliable=False,
        )
        assert "UNRELIABLE" in render_gate_block(result)


# ---------------------------------------------------------------------------
# 7. End-to-end through the agent's patch path with a stub LLM
# ---------------------------------------------------------------------------


class _StubLLM:
    def __init__(self, content: str):
        self._content = content
        self.calls = 0

    def generate(self, **kwargs):
        self.calls += 1
        return SimpleNamespace(content=self._content)


def _stub_agent(out_dir: Path, llm: _StubLLM):
    """Minimal agent shell — real ``generate_patch`` bound onto a stub."""
    from packages.llm_analysis.agent import AutonomousSecurityAgentV2
    agent = SimpleNamespace(out_dir=out_dir, llm=llm)
    agent.generate_patch = AutonomousSecurityAgentV2.generate_patch.__get__(
        agent, type(agent),
    )
    return agent


def _make_vuln(repo: Path, tool: str = "codeql"):
    from packages.llm_analysis.agent import VulnerabilityContext
    finding = {
        "finding_id": "FIND-0001",
        "rule_id": "cpp/unbounded-write",
        "file": "vuln.c",
        "startLine": FINDING_LINE,
        "endLine": FINDING_LINE,
        "message": "strcpy into fixed buffer",
        "level": "error",
        "tool": tool,
    }
    vuln = VulnerabilityContext(finding, repo)
    vuln.analysis = {"reasoning": "unbounded strcpy"}
    return vuln


class TestAgentPatchPathE2E:

    def test_patch_artifact_gains_gate_block(self, fixture_repo, tmp_path):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        llm = _StubLLM(_fenced_response(_make_diff(VULN_C, FIXED_C)))
        agent = _stub_agent(out_dir, llm)
        vuln = _make_vuln(fixture_repo)

        assert agent.generate_patch(vuln) is True
        assert llm.calls == 1

        patch_files = list((out_dir / "patches").glob("*_patch.md"))
        assert len(patch_files) == 1
        text = patch_files[0].read_text(encoding="utf-8")
        assert "## Patch Gate" in text
        assert "- format: unified-diff" in text
        assert "```diff" in text  # the patch itself is still saved

        assert vuln.patch_gate is not None
        assert vuln.patch_gate["format"] == "unified-diff"
        assert vuln.patch_gate["scope"] == "in-bounds"
        assert "patch_gate" in vuln.to_dict()

    def test_free_form_response_still_saved_with_format_annotation(
        self, fixture_repo, tmp_path,
    ):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        llm = _StubLLM("Fixed code:\n```c\n" + FIXED_C + "```\n")
        agent = _stub_agent(out_dir, llm)
        vuln = _make_vuln(fixture_repo)

        # The gate never blocks: generation still succeeds and saves.
        assert agent.generate_patch(vuln) is True
        patch_files = list((out_dir / "patches").glob("*_patch.md"))
        assert len(patch_files) == 1
        text = patch_files[0].read_text(encoding="utf-8")
        assert "- format: not-a-unified-diff" in text
        assert vuln.patch_gate["format"] == "not-a-unified-diff"

    def test_gate_crash_never_blocks_patch_save(
        self, fixture_repo, tmp_path, monkeypatch,
    ):
        out_dir = tmp_path / "out"
        out_dir.mkdir()

        def _boom(*args, **kwargs):
            raise RuntimeError("gate exploded")

        monkeypatch.setattr(patch_gate, "run_patch_gate", _boom)
        llm = _StubLLM(_fenced_response(_make_diff(VULN_C, FIXED_C)))
        agent = _stub_agent(out_dir, llm)
        vuln = _make_vuln(fixture_repo)

        assert agent.generate_patch(vuln) is True
        assert vuln.patch_gate is None
        assert list((out_dir / "patches").glob("*_patch.md"))


# ---------------------------------------------------------------------------
# 8. Report surface (core/reporting/findings.py)
# ---------------------------------------------------------------------------


class TestReportSurface:

    def test_patch_gate_line_rendered_and_sanitised(self):
        from core.reporting.findings import build_finding_detail
        finding = {
            "rule_id": "cpp/unbounded-write",
            "file_path": "vuln.c",
            "patch_code": "--- a/vuln.c\n+++ b/vuln.c\n",
            "patch_gate": {
                "format": "unified-diff",
                "scope": "in-bounds",
                "detector": "silenced",
                "control": "ok",
                "compile": "ok",
                "reliable": True,
            },
        }
        section = build_finding_detail(finding, 1)
        assert "Patch gate:" in section.content
        assert "detector: silenced" in section.content

    def test_unreliable_gate_flagged_in_report(self):
        from core.reporting.findings import build_finding_detail
        finding = {
            "rule_id": "r",
            "file_path": "vuln.c",
            "patch_code": "--- a/x\n+++ b/x\n",
            "patch_gate": {
                "format": "unified-diff",
                "detector": "silenced",
                "control": "FAILED",
                "reliable": False,
            },
        }
        section = build_finding_detail(finding, 1)
        assert "unreliable" in section.content


# ---------------------------------------------------------------------------
# 9. Multi-model orchestrator path (PatchTask.finalize)
# ---------------------------------------------------------------------------


def _finding_dict(repo: Path | None, **overrides) -> dict:
    finding = {
        "finding_id": "FIND-0001",
        "rule_id": "cpp/unbounded-write",
        "file_path": "vuln.c",
        "start_line": FINDING_LINE,
        "end_line": FINDING_LINE,
        "tool": "codeql",
    }
    if repo is not None:
        finding["repo_path"] = str(repo)
    finding.update(overrides)
    return finding


def _run_patch_task(findings: list[dict], content: str, **task_kwargs):
    """Drive PatchTask the way the dispatcher does, with a stub result.

    select_items → (stub LLM emits ``content``) → finalize. Returns
    ``(results, prior_results)`` for assertions on both record shapes.
    """
    from packages.llm_analysis.tasks import PatchTask
    task = PatchTask(**task_kwargs)
    prior_results = {
        f["finding_id"]: {"is_exploitable": True} for f in findings
    }
    selected = task.select_items(findings, prior_results)
    assert selected, "fixture findings must be patch-eligible"
    results = [
        {"finding_id": f["finding_id"], "content": content}
        for f in selected
    ]
    task.finalize(results, prior_results)
    return results, prior_results


class TestPatchTaskPathE2E:

    def test_gate_annotations_stored_on_both_record_shapes(
        self, fixture_repo, monkeypatch,
    ):
        # Hermetic: sandbox refused → pure-Python annotations only.
        monkeypatch.setattr(patch_gate, "_import_sandbox_run", lambda: None)
        results, prior = _run_patch_task(
            [_finding_dict(fixture_repo)],
            _fenced_response(_make_diff(VULN_C, FIXED_C)),
        )
        record = prior["FIND-0001"]
        assert record["patch_code"]
        assert record["has_patch"] is True
        gate = record["patch_gate"]
        assert gate["format"] == "unified-diff"
        assert gate["scope"] == "in-bounds"
        assert gate["gate"] == "unavailable"
        # The per-task result record carries the same annotations.
        assert results[0]["patch_gate"] == gate

    def test_missing_span_annotated_honestly(self, fixture_repo, monkeypatch):
        monkeypatch.setattr(patch_gate, "_import_sandbox_run", lambda: None)
        _, prior = _run_patch_task(
            [_finding_dict(fixture_repo, start_line=0, end_line=0)],
            _fenced_response(_make_diff(VULN_C, FIXED_C)),
        )
        gate = prior["FIND-0001"]["patch_gate"]
        assert gate["format"] == "unified-diff"
        assert gate["scope"] == "skipped (no finding span)"
        assert gate["out_of_scope_hunks"] == []

    def test_missing_repo_context_skips_mechanical_checks(self, monkeypatch):
        monkeypatch.setattr(patch_gate, "_import_sandbox_run", lambda: None)
        _, prior = _run_patch_task(
            [_finding_dict(None)],
            _fenced_response(_make_diff(VULN_C, FIXED_C)),
        )
        gate = prior["FIND-0001"]["patch_gate"]
        assert gate["format"] == "unified-diff"
        assert gate["gate"] == "skipped"
        assert any("no file context" in n for n in gate["notes"])

    def test_gate_crash_never_blocks_patch_save(self, fixture_repo, monkeypatch):
        def _boom(*args, **kwargs):
            raise RuntimeError("gate exploded")

        monkeypatch.setattr(patch_gate, "run_patch_gate", _boom)
        _, prior = _run_patch_task(
            [_finding_dict(fixture_repo)],
            _fenced_response(_make_diff(VULN_C, FIXED_C)),
        )
        record = prior["FIND-0001"]
        assert record["patch_code"]
        assert record["has_patch"] is True
        assert "patch_gate" not in record

    def test_free_form_response_annotated_not_dropped(
        self, fixture_repo, monkeypatch,
    ):
        monkeypatch.setattr(patch_gate, "_import_sandbox_run", lambda: None)
        _, prior = _run_patch_task(
            [_finding_dict(fixture_repo)],
            "Fixed code:\n```c\n" + FIXED_C + "```\n",
        )
        record = prior["FIND-0001"]
        assert record["patch_code"]  # gate never blocks the save
        assert record["patch_gate"]["format"] == "not-a-unified-diff"

    @needs_sandbox
    def test_full_gate_through_task_path(self, fixture_repo):
        # Mirrors the agent-path E2E depth: real sandbox apply, honest
        # codeql recheck-unsupported annotation.
        _, prior = _run_patch_task(
            [_finding_dict(fixture_repo)],
            _fenced_response(_make_diff(VULN_C, FIXED_C)),
        )
        gate = prior["FIND-0001"]["patch_gate"]
        assert gate["gate"] == "ran"
        assert gate["apply"] == "ok"
        assert gate["scope"] == "in-bounds"
        assert gate["detector"] == "recheck-unsupported (codeql)"

    @needs_sandbox
    def test_checkers_dir_threads_through_task(
        self, fixture_repo, checkers_dir, monkeypatch,
    ):
        # Detector resolution sees the task-level checkers_dir: with a
        # stubbed replay (no real semgrep cost) the synthesized-checker
        # rule resolves instead of falling back to recheck-unsupported.
        calls = []

        def _fake_run_detector(spec, target, runner, rule_id, timeout):
            calls.append(str(spec.config))
            return [FINDING_LINE], []

        monkeypatch.setattr(patch_gate, "_run_detector", _fake_run_detector)
        _, prior = _run_patch_task(
            [_finding_dict(
                fixture_repo, rule_id="test-strcpy-fixed-buf", tool="semgrep",
            )],
            _fenced_response(_make_diff(VULN_C, FIXED_C)),
            checkers_dir=checkers_dir,
        )
        gate = prior["FIND-0001"]["patch_gate"]
        assert gate["detector"] in ("silenced", "still-firing")
        assert calls and all("test-strcpy-fixed-buf.yml" in c for c in calls)
