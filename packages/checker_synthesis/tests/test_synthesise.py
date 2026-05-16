"""Tests for the ``synthesise_and_run`` orchestration.

The LLM is stubbed (a callable returning canned dicts). The engine
runners are stubbed via ``monkeypatch`` so tests don't require
semgrep / coccinelle binaries on the test runner.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from packages.checker_synthesis import (
    Match,
    SeedBug,
    SynthesisedRule,
    synthesise_and_run,
)
from packages.checker_synthesis import synthesise as synth_mod


def _seed(tmp_path: Path) -> SeedBug:
    """Build a seed bug + plant the source file in tmp_path."""
    src_dir = tmp_path / "src"
    src_dir.mkdir(exist_ok=True)
    (src_dir / "auth.py").write_text(
        "def login(req):\n"
        "    q = req.get('q')\n"
        "    return cursor.execute(f'SELECT * FROM t WHERE x={q}')\n"
    )
    return SeedBug(
        file="src/auth.py",
        function="login",
        line_start=1, line_end=3,
        cwe="CWE-89",
        reasoning="Tainted query string reaches cursor.execute via f-string",
        snippet="def login(req): ...",
    )


def _stub_llm(responses):
    """Return a callable that pops responses in order. Each entry
    is either a dict (returned) or an Exception subclass instance
    (raised) or None (returned as None)."""
    queue = list(responses)

    def llm(prompt, schema, system_prompt):
        if not queue:
            raise AssertionError("stub LLM out of responses")
        item = queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item
    llm._queue = queue  # noqa: SLF001 — for assertions
    return llm


def _stub_engines(monkeypatch, *, seed_matches, repo_matches, errors=None):
    """Patch the semgrep + coccinelle adapters to return canned matches.

    The first call (positive control on seed file) returns ``seed_matches``;
    subsequent calls (codebase scan) return ``repo_matches``.
    """
    calls = {"n": 0}

    def fake_run(rule, rule_path, target):
        n = calls["n"]
        calls["n"] += 1
        if n == 0:
            return list(seed_matches), list(errors or [])
        return list(repo_matches), list(errors or [])

    monkeypatch.setattr(synth_mod, "_run_engine", fake_run)
    return calls


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_first_attempt_succeeds_with_one_variant(self, tmp_path, monkeypatch):
        seed = _seed(tmp_path)
        out = tmp_path / "out"
        # Seed match at line 3 (inside seed range), one variant elsewhere,
        # plus the seed itself in the codebase scan (must be filtered out).
        seed_match = Match(file="src/auth.py", line=3,
                           snippet="cursor.execute(f'...')")
        variant = Match(file="src/admin.py", line=42,
                        snippet="db.exec(f'DROP {tbl}')")
        _stub_engines(
            monkeypatch,
            seed_matches=[seed_match],
            repo_matches=[seed_match, variant],
        )

        llm = _stub_llm([
            {"rule_body": "rules:\n  - id: x\n    pattern: ...\n",
             "rationale": "f-string into execute"},
        ])
        result = synthesise_and_run(seed, tmp_path, out, llm)

        assert result.rule is not None
        assert result.positive_control is True
        # Seed itself filtered; only the variant remains.
        assert len(result.matches) == 1
        assert result.matches[0].file == "src/admin.py"
        assert result.capped is False
        # Rule was written to disk.
        assert result.rule_path is not None
        assert result.rule_path.exists()
        assert result.rule_path.suffix == ".yml"
        assert result.rule_path.read_text().startswith("rules:")

    def test_coccinelle_engine_for_c_seed(self, tmp_path, monkeypatch):
        # Plant a C source file as the seed.
        src = tmp_path / "src"
        src.mkdir()
        (src / "drv.c").write_text(
            "void f(struct s *p) {\n"
            "    if (!p) return;\n"
            "    p->x = 1;\n"
            "}\n"
        )
        seed = SeedBug(
            file="src/drv.c", function="f",
            line_start=1, line_end=4,
            cwe="CWE-476",
            reasoning="missing null check before deref",
        )
        _stub_engines(
            monkeypatch,
            seed_matches=[Match(file="src/drv.c", line=2)],
            repo_matches=[Match(file="src/drv.c", line=2)],
        )
        llm = _stub_llm([
            {"rule_body": "@@ struct s *p; @@\n p->x", "rationale": "deref"},
        ])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        assert result.rule.engine == "coccinelle"
        assert result.rule_path.suffix == ".cocci"


# ---------------------------------------------------------------------------
# Retry / failure paths
# ---------------------------------------------------------------------------


class TestRetry:
    def test_retry_on_positive_control_miss(self, tmp_path, monkeypatch):
        """First rule misses the seed; second matches. Retries once,
        then succeeds."""
        seed = _seed(tmp_path)
        # Custom engine stub: first probe misses, third probe (after retry)
        # hits, fourth call (codebase scan) returns one variant.
        calls = {"n": 0}
        seed_match = Match(file="src/auth.py", line=3)
        variant = Match(file="src/admin.py", line=99)

        def fake_run(rule, rule_path, target):
            n = calls["n"]
            calls["n"] += 1
            # n=0: probe attempt 0 → no match (positive control fails)
            # n=1: probe attempt 1 → match (positive control passes)
            # n=2: codebase scan → seed + variant
            if n == 0:
                return [], []
            if n == 1:
                return [seed_match], []
            return [seed_match, variant], []

        monkeypatch.setattr(synth_mod, "_run_engine", fake_run)
        llm = _stub_llm([
            {"rule_body": "rules:\n  - id: bad", "rationale": "miss"},
            {"rule_body": "rules:\n  - id: good", "rationale": "hit"},
        ])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        assert result.positive_control is True
        # Error log records the first failed attempt.
        assert any("attempt 0" in e for e in result.errors)
        assert len(result.matches) == 1

    def test_give_up_after_retry_budget(self, tmp_path, monkeypatch):
        """Both attempts miss positive control → no rule, no matches."""
        seed = _seed(tmp_path)
        _stub_engines(
            monkeypatch,
            seed_matches=[],   # always miss
            repo_matches=[],
        )
        llm = _stub_llm([
            {"rule_body": "rules: []", "rationale": "first"},
            {"rule_body": "rules: []", "rationale": "second"},
        ])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm,
                                    max_retries=1)
        assert result.rule is None
        assert result.positive_control is False
        # Two failure messages logged (attempt 0, attempt 1).
        miss_errors = [e for e in result.errors if "did not match seed" in e]
        assert len(miss_errors) == 2


class TestLLMFailures:
    def test_llm_returns_non_dict(self, tmp_path, monkeypatch):
        seed = _seed(tmp_path)
        _stub_engines(monkeypatch, seed_matches=[], repo_matches=[])
        llm = _stub_llm(["not a dict", "also not a dict"])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        assert result.rule is None
        assert any("non-dict" in e for e in result.errors)

    def test_llm_missing_rule_body(self, tmp_path, monkeypatch):
        seed = _seed(tmp_path)
        _stub_engines(monkeypatch, seed_matches=[], repo_matches=[])
        llm = _stub_llm([
            {"rationale": "no rule_body field"},
            {"rationale": "still none"},
        ])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        assert result.rule is None
        assert any("missing 'rule_body'" in e for e in result.errors)

    def test_llm_raises_propagates_as_error(self, tmp_path, monkeypatch):
        seed = _seed(tmp_path)
        _stub_engines(monkeypatch, seed_matches=[], repo_matches=[])
        llm = _stub_llm([RuntimeError("transport blew up")] * 2)
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        assert result.rule is None
        assert any("transport blew up" in e for e in result.errors)

    def test_oversized_rule_rejected(self, tmp_path, monkeypatch):
        seed = _seed(tmp_path)
        _stub_engines(monkeypatch, seed_matches=[], repo_matches=[])
        big = "x" * 100_000
        llm = _stub_llm([
            {"rule_body": big, "rationale": "huge"},
            {"rule_body": big, "rationale": "still huge"},
        ])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        assert result.rule is None
        assert any("too large" in e for e in result.errors)


# ---------------------------------------------------------------------------
# Engine selection
# ---------------------------------------------------------------------------


class TestEngineDetection:
    def test_unsupported_extension_returns_early(self, tmp_path):
        seed = SeedBug(
            file="data/blob.bin", function="?",
            line_start=1, line_end=10,
            cwe="CWE-?", reasoning="r",
        )
        # No LLM call should be made; supply an empty stub.
        llm = _stub_llm([])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        assert result.rule is None
        assert any("no engine" in e for e in result.errors)


# ---------------------------------------------------------------------------
# Match cap
# ---------------------------------------------------------------------------


class TestMatchCap:
    def test_caps_at_max_matches(self, tmp_path, monkeypatch):
        seed = _seed(tmp_path)
        seed_match = Match(file="src/auth.py", line=3)
        variants = [
            Match(file=f"src/v{i:03d}.py", line=10)
            for i in range(100)
        ]
        _stub_engines(
            monkeypatch,
            seed_matches=[seed_match],
            repo_matches=[seed_match, *variants],
        )
        llm = _stub_llm([
            {"rule_body": "rules: [...]", "rationale": "x"},
        ])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm,
                                    max_matches=10)
        assert result.capped is True
        assert len(result.matches) == 10


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------


class TestTriage:
    def test_triage_each_match(self, tmp_path, monkeypatch):
        seed = _seed(tmp_path)
        seed_match = Match(file="src/auth.py", line=3)
        v1 = Match(file="src/a.py", line=10, snippet="db.exec(...)")
        v2 = Match(file="src/b.py", line=20, snippet="db.exec(...)")
        _stub_engines(
            monkeypatch,
            seed_matches=[seed_match],
            repo_matches=[seed_match, v1, v2],
        )
        llm = _stub_llm([
            {"rule_body": "rules: ...", "rationale": "x"},
            {"status": "variant", "reasoning": "same shape"},
            {"status": "false_positive", "reasoning": "different sink"},
        ])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm,
                                    triage_each=True)
        assert len(result.triage) == 2
        assert result.triage[0].status == "variant"
        assert result.triage[1].status == "false_positive"

    def test_triage_budget_marks_remainder_skipped(self, tmp_path, monkeypatch):
        seed = _seed(tmp_path)
        seed_match = Match(file="src/auth.py", line=3)
        variants = [Match(file=f"src/v{i}.py", line=1) for i in range(5)]
        _stub_engines(
            monkeypatch,
            seed_matches=[seed_match],
            repo_matches=[seed_match, *variants],
        )
        llm = _stub_llm([
            {"rule_body": "rules: ...", "rationale": "x"},
            # Only 2 triage budget — remaining 3 should be skipped.
            {"status": "variant", "reasoning": "1"},
            {"status": "variant", "reasoning": "2"},
        ])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm,
                                    triage_each=True, max_triage_calls=2)
        assert len(result.triage) == 5
        statuses = [t.status for t in result.triage]
        assert statuses.count("variant") == 2
        assert statuses.count("skipped") == 3

    def test_triage_invalid_status_falls_back_uncertain(self, tmp_path, monkeypatch):
        seed = _seed(tmp_path)
        seed_match = Match(file="src/auth.py", line=3)
        v1 = Match(file="src/a.py", line=10)
        _stub_engines(
            monkeypatch,
            seed_matches=[seed_match],
            repo_matches=[seed_match, v1],
        )
        llm = _stub_llm([
            {"rule_body": "rules: ...", "rationale": "x"},
            {"status": "frobnicated", "reasoning": "garbage"},
        ])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm,
                                    triage_each=True)
        assert result.triage[0].status == "uncertain"

    def test_triage_llm_raises_marks_uncertain(self, tmp_path, monkeypatch):
        seed = _seed(tmp_path)
        seed_match = Match(file="src/auth.py", line=3)
        v1 = Match(file="src/a.py", line=10)
        _stub_engines(
            monkeypatch,
            seed_matches=[seed_match],
            repo_matches=[seed_match, v1],
        )
        llm = _stub_llm([
            {"rule_body": "rules: ...", "rationale": "x"},
            RuntimeError("triage transport failure"),
        ])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm,
                                    triage_each=True)
        assert result.triage[0].status == "uncertain"
        assert "triage failed" in result.triage[0].reasoning


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


class TestSerialisation:
    def test_to_dict_after_synthesis(self, tmp_path, monkeypatch):
        seed = _seed(tmp_path)
        seed_match = Match(file="src/auth.py", line=3)
        variant = Match(file="src/admin.py", line=42)
        _stub_engines(
            monkeypatch,
            seed_matches=[seed_match],
            repo_matches=[seed_match, variant],
        )
        llm = _stub_llm([
            {"rule_body": "rules: ...", "rationale": "x"},
        ])
        result = synthesise_and_run(seed, tmp_path, tmp_path / "out", llm)
        d = result.to_dict()
        import json
        assert json.dumps(d)
        assert d["rule"]["engine"] == "semgrep"
        assert d["positive_control"] is True
        assert len(d["matches"]) == 1
