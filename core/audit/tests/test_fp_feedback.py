"""Tests for core.audit.fp_feedback."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.fp_feedback import (
    FPPattern,
    format_fp_warnings,
    load_fp_patterns,
    save_fp_patterns,
    scan_fp_patterns,
)


def _write_journal(out_dir: Path, entries: list[dict]) -> None:
    """Write review-journal.jsonl entries to the output directory."""
    out_dir.mkdir(parents=True, exist_ok=True)
    journal = out_dir / "review-journal.jsonl"
    lines = [json.dumps(e, separators=(",", ":")) for e in entries]
    journal.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestScanFpPatterns:
    def test_detects_human_override_with_journal_finding(self, tmp_path: Path):
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        md = ann_dir / "src" / "auth.py.md"
        md.parent.mkdir(parents=True)
        md.write_text(
            "## check_pw\n"
            "<!-- meta: source=human status=clean -->\n"
            "Constant-time compare, no SQL here.\n",
        )
        journal_dir = tmp_path / "run"
        _write_journal(journal_dir, [{
            "ts": "2026-01-01T00:00:00Z",
            "run_id": "r1",
            "file": "src/auth.py",
            "function": "check_pw",
            "verdict": "finding",
            "source_hash": "",
            "cwe": "CWE-89",
            "body": "SQL injection via user input",
        }])
        patterns = scan_fp_patterns(ann_dir, journal_dir=journal_dir)
        assert len(patterns) == 1
        p = patterns[0]
        assert p.function == "check_pw"
        assert p.cwe == "CWE-89"
        assert "Constant-time" in p.human_note

    def test_detects_human_override_with_cwe_metadata(self, tmp_path: Path):
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        md = ann_dir / "src" / "auth.py.md"
        md.parent.mkdir(parents=True)
        md.write_text(
            "## check_pw\n"
            "<!-- meta: source=human status=clean cwe=CWE-89 "
            'hypothesis="SQL injection via user input" -->\n'
            "Constant-time compare, no SQL here.\n",
        )
        patterns = scan_fp_patterns(ann_dir)
        assert len(patterns) == 1
        p = patterns[0]
        assert p.function == "check_pw"
        assert p.cwe == "CWE-89"
        assert "Constant-time" in p.human_note

    def test_detects_eq_format_metadata(self, tmp_path: Path):
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        md = ann_dir / "lib.c.md"
        md.write_text(
            "## do_parse\n"
            "<!-- meta: source=human status=clean cwe=CWE-120 -->\n"
            "Bounds checked.\n",
        )
        patterns = scan_fp_patterns(ann_dir)
        assert len(patterns) == 1
        assert patterns[0].cwe == "CWE-120"

    def test_journal_lesson_triggers_detection(self, tmp_path: Path):
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        md = ann_dir / "src" / "db.py.md"
        md.parent.mkdir(parents=True)
        md.write_text(
            "## query\n"
            "<!-- meta: source=human status=clean -->\n"
            "Uses parameterised queries.\n",
        )
        journal_dir = tmp_path / "run"
        _write_journal(journal_dir, [{
            "ts": "2026-01-01T00:00:00Z",
            "run_id": "r1",
            "file": "src/db.py",
            "function": "query",
            "verdict": "clean",
            "source_hash": "",
            "lesson": "Parameterised queries prevent injection here",
        }])
        patterns = scan_fp_patterns(ann_dir, journal_dir=journal_dir)
        assert len(patterns) == 1
        assert "Parameterised" in patterns[0].hypothesis_snippet

    def test_no_override_returns_empty(self, tmp_path: Path):
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        md = ann_dir / "lib.c.md"
        md.write_text(
            "## do_parse\n"
            "<!-- meta: source=llm status=finding -->\n"
            "Buffer overflow.\n",
        )
        assert scan_fp_patterns(ann_dir) == []

    def test_missing_dir_returns_empty(self, tmp_path: Path):
        assert scan_fp_patterns(tmp_path / "nope") == []

    def test_no_journal_still_works(self, tmp_path: Path):
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        md = ann_dir / "src" / "auth.py.md"
        md.parent.mkdir(parents=True)
        md.write_text(
            "## check_pw\n"
            "<!-- meta: source=human status=clean cwe=CWE-79 -->\n"
            "Not vulnerable.\n",
        )
        patterns = scan_fp_patterns(ann_dir, journal_dir=None)
        assert len(patterns) == 1
        assert patterns[0].cwe == "CWE-79"

    def test_journal_suspicious_detected(self, tmp_path: Path):
        ann_dir = tmp_path / "annotations"
        ann_dir.mkdir()
        md = ann_dir / "x.py.md"
        md.write_text(
            "## func\n"
            "<!-- meta: source=human status=clean -->\n"
            "Safe.\n",
        )
        journal_dir = tmp_path / "run"
        _write_journal(journal_dir, [{
            "ts": "2026-01-01T00:00:00Z",
            "run_id": "r1",
            "file": "x.py",
            "function": "func",
            "verdict": "suspicious",
            "source_hash": "",
            "body": "Possible XSS",
        }])
        patterns = scan_fp_patterns(ann_dir, journal_dir=journal_dir)
        assert len(patterns) == 1


class TestFormatFpWarnings:
    def test_matching_extension(self):
        patterns = [
            FPPattern(
                file_pattern="*.py",
                function="check_pw",
                cwe="CWE-89",
                hypothesis_snippet="SQL injection via user input",
                human_note="Constant-time compare",
            ),
        ]
        result = format_fp_warnings(patterns, "src/auth.py")
        assert result is not None
        assert "CWE-89" in result
        assert "overridden" in result

    def test_non_matching_extension(self):
        patterns = [
            FPPattern(
                file_pattern="*.py",
                function="check_pw",
                cwe="CWE-89",
                hypothesis_snippet="SQL injection",
                human_note="no SQL",
            ),
        ]
        result = format_fp_warnings(patterns, "src/auth.c")
        assert result is None

    def test_cwe_filter(self):
        patterns = [
            FPPattern(
                file_pattern="*.py",
                function="f",
                cwe="CWE-89",
                hypothesis_snippet="sqli",
                human_note="no",
            ),
        ]
        assert format_fp_warnings(patterns, "a.py", cwe="CWE-89") is not None
        assert format_fp_warnings(patterns, "a.py", cwe="CWE-79") is None


class TestPersistence:
    def test_save_and_load_roundtrip(self, tmp_path: Path):
        patterns = [
            FPPattern(
                file_pattern="*.py",
                function="check_pw",
                cwe="CWE-89",
                hypothesis_snippet="SQL injection",
                human_note="Not SQL",
            ),
        ]
        save_fp_patterns(patterns, tmp_path)
        loaded = load_fp_patterns(tmp_path)
        assert len(loaded) == 1
        assert loaded[0].function == "check_pw"
        assert loaded[0].cwe == "CWE-89"

    def test_load_missing_returns_empty(self, tmp_path: Path):
        assert load_fp_patterns(tmp_path) == []

    def test_load_malformed_returns_empty(self, tmp_path: Path):
        (tmp_path / "fp-patterns.json").write_text("not json")
        assert load_fp_patterns(tmp_path) == []
