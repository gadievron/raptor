"""Adversarial tests for ``synthesise_and_run``.

Inputs that a malicious upstream (compromised LLM, poisoned seed
data from a prior /agentic run, hostile repository layout) could
plausibly hand the synthesis loop. Each must reject cleanly without
filesystem damage or pipeline crash.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from packages.checker_synthesis import (
    Match,
    SeedBug,
    synthesise_and_run,
)
from packages.checker_synthesis import synthesise as synth_mod


def _stub_llm(responses):
    queue = list(responses)

    def llm(prompt, schema, system_prompt):
        if not queue:
            raise AssertionError("stub LLM out of responses")
        item = queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item
    return llm


def _stub_engines(monkeypatch, *, seed_matches, repo_matches):
    calls = {"n": 0}

    def fake_run(rule, rule_path, target):
        n = calls["n"]
        calls["n"] += 1
        if n == 0:
            return list(seed_matches), []
        return list(repo_matches), []

    monkeypatch.setattr(synth_mod, "_run_engine", fake_run)
    return calls


# ---------------------------------------------------------------------------
# Path-traversal defence on seed.file
# ---------------------------------------------------------------------------


class TestSeedPathDefence:
    @pytest.mark.parametrize("bad_path", [
        "../etc/passwd",
        "../../../../etc/shadow",
        "ok/../etc/passwd",
        "/etc/passwd",
        "/absolute/path.py",
    ])
    def test_traversal_or_absolute_rejected(self, tmp_path, bad_path):
        seed = SeedBug(
            file=bad_path, function="evil",
            line_start=1, line_end=2,
            cwe="CWE-?", reasoning="r",
        )
        # Stub LLM should never get called.
        llm = _stub_llm([])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        assert result.rule is None
        assert any(
            "..'" in e or "must not contain" in e or "must be relative" in e
            for e in result.errors
        ), f"expected rejection error, got: {result.errors}"

    def test_newline_in_path_rejected(self, tmp_path):
        seed = SeedBug(
            file="src/foo\n.py", function="f",
            line_start=1, line_end=2,
            cwe="CWE-?", reasoning="r",
        )
        llm = _stub_llm([])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        assert result.rule is None
        assert any("newline" in e for e in result.errors)

    def test_null_in_path_rejected(self, tmp_path):
        seed = SeedBug(
            file="src/foo\x00.py", function="f",
            line_start=1, line_end=2,
            cwe="CWE-?", reasoning="r",
        )
        llm = _stub_llm([])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        assert result.rule is None

    def test_empty_path_rejected(self, tmp_path):
        seed = SeedBug(
            file="", function="f",
            line_start=1, line_end=2,
            cwe="CWE-?", reasoning="r",
        )
        llm = _stub_llm([])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        assert result.rule is None
        assert any("non-empty" in e for e in result.errors)


# ---------------------------------------------------------------------------
# Rule-body validation
# ---------------------------------------------------------------------------


def _seed(tmp_path: Path) -> SeedBug:
    src_dir = tmp_path / "src"
    src_dir.mkdir(exist_ok=True)
    (src_dir / "auth.py").write_text(
        "def login(req):\n    return cursor.execute(f'x={req.q}')\n"
    )
    return SeedBug(
        file="src/auth.py", function="login",
        line_start=1, line_end=2,
        cwe="CWE-89", reasoning="tainted f-string into execute",
    )


class TestRuleBodyValidation:
    def test_null_byte_in_rule_body_rejected(self, tmp_path, monkeypatch):
        seed = _seed(tmp_path)
        _stub_engines(monkeypatch, seed_matches=[], repo_matches=[])
        llm = _stub_llm([
            {"rule_body": "rules:\n  - id: x\x00", "rationale": "ok"},
            {"rule_body": "rules:\n  - id: y\x00", "rationale": "ok"},
        ])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        assert result.rule is None
        assert any("null byte" in e for e in result.errors)

    def test_oversized_line_rejected(self, tmp_path, monkeypatch):
        """Single huge line slips under the byte cap but should
        still be rejected — engines parse line-by-line."""
        seed = _seed(tmp_path)
        _stub_engines(monkeypatch, seed_matches=[], repo_matches=[])
        # 5000-char single line, total still under 32KB.
        big_line = "rules:\n  - id: " + ("a" * 5000)
        llm = _stub_llm([
            {"rule_body": big_line, "rationale": "ok"},
            {"rule_body": big_line, "rationale": "ok"},
        ])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        assert result.rule is None
        assert any("exceeds" in e for e in result.errors)

    def test_lots_of_short_lines_accepted(self, tmp_path, monkeypatch):
        """1000 lines × 50 chars = 50KB total but under the per-line
        cap. Total-byte cap should bite first."""
        seed = _seed(tmp_path)
        _stub_engines(
            monkeypatch,
            seed_matches=[Match(file="src/auth.py", line=1)],
            repo_matches=[Match(file="src/auth.py", line=1)],
        )
        body = "\n".join(["x" * 50 for _ in range(1000)])  # 50KB
        llm = _stub_llm([
            {"rule_body": body, "rationale": "ok"},
            {"rule_body": body, "rationale": "ok"},
        ])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        # Total-byte cap fires first.
        assert result.rule is None
        assert any("too large" in e for e in result.errors)


# ---------------------------------------------------------------------------
# Real-engine integration (only when semgrep is on PATH)
# ---------------------------------------------------------------------------


_SEMGREP = shutil.which("semgrep")


# ---------------------------------------------------------------------------
# Atomic rule write
# ---------------------------------------------------------------------------


class TestAtomicRuleWrite:
    def test_no_tempfile_left_behind(self, tmp_path, monkeypatch):
        seed = _seed(tmp_path)
        seed_match = Match(file="src/auth.py", line=2)
        _stub_engines(
            monkeypatch,
            seed_matches=[seed_match],
            repo_matches=[seed_match],
        )
        llm = _stub_llm([
            {"rule_body": "rules: ...", "rationale": "x"},
        ])
        synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        # Tempfile pattern: ``.rule-*.tmp`` in checkers/.
        leftovers = list((tmp_path / "out" / "checkers").glob(".rule-*.tmp"))
        assert leftovers == []

    def test_concurrent_writes_no_partial_content(self, tmp_path, monkeypatch):
        """Two synthesise_and_run calls back-to-back with the same
        seed produce the same rule_id (attempt 0). The atomic
        rename means the final on-disk content is one of the two
        rule bodies, not a partial mix."""
        seed = _seed(tmp_path)
        seed_match = Match(file="src/auth.py", line=2)
        _stub_engines(
            monkeypatch,
            seed_matches=[seed_match],
            repo_matches=[seed_match],
        )
        # First write.
        llm = _stub_llm([
            {"rule_body": "rules: A_VERSION", "rationale": "first"},
        ])
        synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        # Reset engine call count — second write also runs probe.
        # Plant fresh stub.
        _stub_engines(
            monkeypatch,
            seed_matches=[seed_match],
            repo_matches=[seed_match],
        )
        llm2 = _stub_llm([
            {"rule_body": "rules: B_VERSION", "rationale": "second"},
        ])
        r2 = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm2)
        text = r2.rule_path.read_text()
        # Final content is the second write — exactly, no mixing.
        assert text == "rules: B_VERSION"


# ---------------------------------------------------------------------------
# Snippet truncation
# ---------------------------------------------------------------------------


class TestSnippetTruncation:
    def test_huge_snippet_truncated_in_prompt(self, tmp_path, monkeypatch):
        from packages.checker_synthesis.prompts import build_synthesis_prompt
        seed = SeedBug(
            file="src/foo.py", function="f",
            line_start=1, line_end=2,
            cwe="CWE-?", reasoning="r",
            snippet="x " * 100_000,  # ~200KB
        )
        prompt = build_synthesis_prompt(seed, "semgrep")
        # Prompt body should be much smaller than the raw snippet.
        assert len(prompt.encode("utf-8")) < 50_000
        assert "(snippet truncated)" in prompt

    def test_short_snippet_passes_through(self, tmp_path):
        from packages.checker_synthesis.prompts import build_synthesis_prompt
        seed = SeedBug(
            file="src/foo.py", function="f",
            line_start=1, line_end=2,
            cwe="CWE-?", reasoning="r",
            snippet="def f():\n    pass\n",
        )
        prompt = build_synthesis_prompt(seed, "semgrep")
        assert "def f():" in prompt
        assert "(snippet truncated)" not in prompt


# ---------------------------------------------------------------------------
# Engine exception swallowing
# ---------------------------------------------------------------------------


class TestEngineExceptionSwallow:
    def test_engine_import_error_logged(self, tmp_path, monkeypatch):
        """If the underlying scanner package raises (e.g. binary
        missing, transport error), synthesise_and_run must swallow
        and log to ``errors`` rather than crash the caller."""
        seed = _seed(tmp_path)
        # Patch _run_semgrep at the module level to simulate an
        # adapter exception path.
        from packages.checker_synthesis import synthesise as synth_mod

        def boom(rule_path, target):
            raise ImportError("semgrep package not installed")

        monkeypatch.setattr(synth_mod, "_run_semgrep", boom)

        llm = _stub_llm([
            {"rule_body": "rules: ...", "rationale": "x"},
            {"rule_body": "rules: ...", "rationale": "y"},
        ])
        # Should not raise. Returns a result with errors logged.
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        assert result.rule is None
        assert any("semgrep adapter error" in e for e in result.errors)

    def test_engine_runtime_error_logged(self, tmp_path, monkeypatch):
        seed = _seed(tmp_path)
        from packages.checker_synthesis import synthesise as synth_mod

        def boom(rule_path, target):
            raise RuntimeError("transport failure")

        monkeypatch.setattr(synth_mod, "_run_semgrep", boom)
        llm = _stub_llm([
            {"rule_body": "rules: ...", "rationale": "x"},
            {"rule_body": "rules: ...", "rationale": "y"},
        ])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        assert result.rule is None
        assert any("transport failure" in e for e in result.errors)


# ---------------------------------------------------------------------------
# Rule-too-loose warning
# ---------------------------------------------------------------------------


class TestRuleTooLooseWarning:
    def test_warning_at_threshold(self, tmp_path, monkeypatch):
        seed = _seed(tmp_path)
        seed_match = Match(file="src/auth.py", line=2)
        # 250 variants — past the 200 threshold.
        variants = [
            Match(file=f"src/v{i:03d}.py", line=1)
            for i in range(250)
        ]
        _stub_engines(
            monkeypatch,
            seed_matches=[seed_match],
            repo_matches=[seed_match, *variants],
        )
        llm = _stub_llm([
            {"rule_body": "rules: ...", "rationale": "loose"},
        ])
        result = synthesise_and_run(
            seed, tmp_path, tmp_path / "out", llm,
            max_matches=50,
        )
        # Match cap kicked in.
        assert result.capped is True
        assert len(result.matches) == 50
        # Warning emitted.
        assert any("too loose" in e for e in result.errors)

    def test_no_warning_under_threshold(self, tmp_path, monkeypatch):
        seed = _seed(tmp_path)
        seed_match = Match(file="src/auth.py", line=2)
        # Only 10 variants — well under the threshold and the cap.
        variants = [
            Match(file=f"src/v{i}.py", line=1) for i in range(10)
        ]
        _stub_engines(
            monkeypatch,
            seed_matches=[seed_match],
            repo_matches=[seed_match, *variants],
        )
        llm = _stub_llm([
            {"rule_body": "rules: ...", "rationale": "tight"},
        ])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        assert result.capped is False
        assert not any("too loose" in e for e in result.errors)


@pytest.mark.skipif(_SEMGREP is None, reason="semgrep not on PATH")
class TestRealSemgrepIntegration:
    """Drive the actual semgrep adapter end-to-end. Catches shape
    drift between our adapter (``_run_semgrep``) and what
    ``packages.semgrep.runner.run_rule`` actually returns."""

    def test_real_semgrep_finds_planted_match(self, tmp_path):
        # Plant a target with a clear pattern.
        src = tmp_path / "src"
        src.mkdir()
        (src / "vuln.py").write_text(
            "import subprocess\n"
            "def run_cmd(user_input):\n"
            "    subprocess.call(user_input, shell=True)\n"
            "\n"
            "def run_other(user_input):\n"
            "    subprocess.call(user_input, shell=True)\n"
        )
        seed = SeedBug(
            file="src/vuln.py", function="run_cmd",
            line_start=2, line_end=3,
            cwe="CWE-78",
            reasoning="subprocess.call with shell=True and user input",
        )

        # LLM emits a real, valid Semgrep rule that matches both calls.
        rule_yaml = (
            "rules:\n"
            "  - id: subprocess-shell-true\n"
            "    pattern: subprocess.call(..., shell=True)\n"
            "    message: subprocess shell=True\n"
            "    severity: WARNING\n"
            "    languages: [python]\n"
        )
        llm = _stub_llm([
            {"rule_body": rule_yaml, "rationale": "shell=True is unsafe"},
        ])

        result = synthesise_and_run(
            seed, tmp_path, tmp_path / "out", llm,
        )
        # Positive control passes — the real semgrep matched the seed.
        assert result.positive_control is True, (
            f"positive control failed; errors: {result.errors}"
        )
        # The other ``run_other`` call shows up as a variant.
        variant_files = [m.file for m in result.matches]
        assert any("vuln.py" in f for f in variant_files), (
            f"no variant match found; matches: {result.matches}, "
            f"errors: {result.errors}"
        )
        # Rule file written and on disk.
        assert result.rule_path.exists()
        assert "subprocess-shell-true" in result.rule_path.read_text()

    def test_real_semgrep_invalid_rule_records_error(self, tmp_path):
        """A syntactically-broken YAML rule should fail positive
        control without exploding."""
        src = tmp_path / "src"
        src.mkdir()
        (src / "f.py").write_text(
            "def f(x):\n    eval(x)\n"
        )
        seed = SeedBug(
            file="src/f.py", function="f",
            line_start=1, line_end=2,
            cwe="CWE-94", reasoning="eval of user input",
        )
        bad_yaml = "rules: [this is not valid"
        llm = _stub_llm([
            {"rule_body": bad_yaml, "rationale": "broken"},
            {"rule_body": bad_yaml, "rationale": "still broken"},
        ])
        result = synthesise_and_run(
            seed, tmp_path, tmp_path / "out", llm,
        )
        # Positive control failed; rule is None.
        assert result.rule is None
        assert result.positive_control is False
        # At least one attempt-error logged (semgrep would emit a
        # parse error or simply fail to match).
        assert len(result.errors) >= 1
