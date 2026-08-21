"""Tests for the audit corpus label schema."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit.corpus.label import (
    FunctionLabel,
    SPAN_SHA_LEN,
    SourcePin,
    VALID_BUG_CLASSES,
    VALID_EXPECTED_STATUSES,
    VALID_REVIEW_MODES,
    compute_span_sha,
    load_all_labels,
    load_label,
)


def _make_label(**overrides):
    defaults = {
        "function_id": "src/net/session.c:session_recv",
        "bug_class": "aliasing",
        "expected_status": "finding",
        "rationale": "In-place transform aliases shared buffer pages.",
        "source": SourcePin(
            repo="demo-repo",
            sha="abc123",
            file="src/net/session.c",
            line_start=142,
            line_end=280,
        ),
        "labeler": "johnc",
        "labeled_at": "2026-07-28",
    }
    defaults.update(overrides)
    return FunctionLabel(**defaults)


class TestFunctionLabel:
    def test_valid_label(self):
        label = _make_label()
        assert label.function_id == "src/net/session.c:session_recv"
        assert label.bug_class == "aliasing"
        assert label.expected_status == "finding"

    def test_invalid_bug_class(self):
        with pytest.raises(ValueError, match="Invalid bug_class"):
            _make_label(bug_class="nosuchclass")

    def test_invalid_expected_status(self):
        with pytest.raises(ValueError, match="Invalid expected_status"):
            _make_label(expected_status="suspicious")

    def test_error_not_valid_expected_status(self):
        with pytest.raises(ValueError, match="Invalid expected_status"):
            _make_label(expected_status="error")

    def test_all_bug_classes_accepted(self):
        for cls in VALID_BUG_CLASSES:
            label = _make_label(bug_class=cls)
            assert label.bug_class == cls

    def test_all_expected_statuses_accepted(self):
        for status in VALID_EXPECTED_STATUSES:
            label = _make_label(expected_status=status)
            assert label.expected_status == status

    def test_to_dict_roundtrip(self):
        label = _make_label(cwe="CWE-787", cve="CVE-2026-31431")
        d = label.to_dict()
        assert d["function_id"] == label.function_id
        assert d["source"]["repo"] == "demo-repo"
        assert d["cwe"] == "CWE-787"

    def test_optional_fields_default_empty(self):
        label = _make_label()
        assert label.cwe == ""
        assert label.cve == ""
        assert label.expected_mechanism == ""
        assert label.expected_mode_results == {}

    def test_expected_mode_results_valid(self):
        label = _make_label(expected_mode_results={
            "security": "finding", "bug_first": "finding",
            "quality": "clean",
        })
        assert label.expected_mode_results["security"] == "finding"

    def test_all_review_modes_accepted(self):
        for mode in VALID_REVIEW_MODES:
            label = _make_label(expected_mode_results={mode: "clean"})
            assert label.expected_mode_results == {mode: "clean"}

    def test_expected_mode_results_invalid_mode(self):
        with pytest.raises(ValueError, match="Invalid expected_mode_results mode"):
            _make_label(expected_mode_results={"paranoid": "finding"})

    def test_expected_mode_results_invalid_status(self):
        with pytest.raises(
            ValueError, match="Invalid expected_mode_results status",
        ):
            _make_label(expected_mode_results={"security": "suspicious"})

    def test_expected_rule_hits_default_empty(self):
        assert _make_label().expected_rule_hits == {}

    def test_expected_rule_hits_valid(self):
        label = _make_label(expected_rule_hits={
            "coccinelle": ["use_after_free"],
            "semgrep": ["raptor.injection.sql.taint.go"],
        })
        assert label.expected_rule_hits["coccinelle"] == [
            "use_after_free",
        ]

    def test_expected_rule_hits_lenient_on_unknown_engine(self):
        # Shape-only validation: unshipped engines/rule sets are fine.
        label = _make_label(expected_rule_hits={"frobnicator": ["r1"]})
        assert label.expected_rule_hits == {"frobnicator": ["r1"]}

    def test_expected_rule_hits_empty_pin_list_allowed(self):
        # An explicit empty pin means "no rule from this engine should
        # ever hit" — a valid, testable expectation.
        label = _make_label(expected_rule_hits={"semgrep": []})
        assert label.expected_rule_hits == {"semgrep": []}

    def test_expected_rule_hits_rejects_non_list(self):
        with pytest.raises(ValueError, match="expected_rule_hits"):
            _make_label(expected_rule_hits={"semgrep": "not-a-list"})

    def test_expected_rule_hits_rejects_empty_engine(self):
        with pytest.raises(ValueError, match="expected_rule_hits"):
            _make_label(expected_rule_hits={"": ["r1"]})

    def test_expected_rule_hits_rejects_non_string_ids(self):
        with pytest.raises(ValueError, match="expected_rule_hits"):
            _make_label(expected_rule_hits={"semgrep": [42]})


class TestLoadLabel:
    def test_load_from_file(self, tmp_path):
        label_data = {
            "schema_version": 1,
            "function_id": "src/auth.py:check_pw",
            "bug_class": "auth",
            "expected_status": "finding",
            "rationale": "Timing side channel in comparison.",
            "source": {
                "repo": "test-app",
                "sha": "deadbeef",
                "file": "src/auth.py",
                "line_start": 10,
                "line_end": 25,
            },
            "labeler": "test",
            "labeled_at": "2026-07-28",
            "cwe": "CWE-208",
        }
        p = tmp_path / "test.label.json"
        p.write_text(json.dumps(label_data))

        label = load_label(p)
        assert label.function_id == "src/auth.py:check_pw"
        assert label.bug_class == "auth"
        assert label.cwe == "CWE-208"
        assert label.source.repo == "test-app"

    def test_expected_mode_results_not_dropped(self, tmp_path):
        """Regression: expected_mode_results was silently discarded."""
        label_data = {
            "schema_version": 1,
            "function_id": "src/auth.py:check_pw",
            "bug_class": "auth",
            "expected_status": "finding",
            "rationale": "Test.",
            "source": {
                "repo": "test-app", "sha": "deadbeef",
                "file": "src/auth.py", "line_start": 10, "line_end": 25,
            },
            "labeler": "test",
            "labeled_at": "2026-07-28",
            "expected_mode_results": {
                "security": "finding", "bug_first": "finding",
            },
        }
        p = tmp_path / "test.label.json"
        p.write_text(json.dumps(label_data))
        label = load_label(p)
        assert label.expected_mode_results == {
            "security": "finding", "bug_first": "finding",
        }

    def test_expected_rule_hits_not_dropped(self, tmp_path):
        label_data = {
            "schema_version": 1,
            "function_id": "src/auth.py:check_pw",
            "bug_class": "auth",
            "expected_status": "finding",
            "rationale": "Test.",
            "source": {
                "repo": "test-app", "sha": "deadbeef",
                "file": "src/auth.py", "line_start": 10, "line_end": 25,
            },
            "labeler": "test",
            "labeled_at": "2026-07-28",
            "expected_rule_hits": {"semgrep": ["raptor.test.rule"]},
        }
        p = tmp_path / "test.label.json"
        p.write_text(json.dumps(label_data))
        label = load_label(p)
        assert label.expected_rule_hits == {
            "semgrep": ["raptor.test.rule"],
        }

    def test_bad_mode_key_rejected_at_load(self, tmp_path):
        label_data = {
            "schema_version": 1,
            "function_id": "src/auth.py:check_pw",
            "bug_class": "auth",
            "expected_status": "finding",
            "rationale": "Test.",
            "source": {
                "repo": "test-app", "sha": "deadbeef",
                "file": "src/auth.py", "line_start": 10, "line_end": 25,
            },
            "labeler": "test",
            "labeled_at": "2026-07-28",
            "expected_mode_results": {"nosuchmode": "finding"},
        }
        p = tmp_path / "test.label.json"
        p.write_text(json.dumps(label_data))
        with pytest.raises(ValueError, match="Invalid expected_mode_results"):
            load_label(p)

    def test_load_all_labels(self, tmp_path):
        for i, cls in enumerate(["aliasing", "auth"]):
            d = tmp_path / cls
            d.mkdir()
            label_data = {
                "schema_version": 1,
                "function_id": f"file{i}.c:func{i}",
                "bug_class": cls,
                "expected_status": "clean",
                "rationale": "Test.",
                "source": {
                    "repo": "test",
                    "sha": "abc",
                    "file": f"file{i}.c",
                    "line_start": 1,
                    "line_end": 10,
                },
                "labeler": "test",
                "labeled_at": "2026-07-28",
            }
            (d / f"func{i}.label.json").write_text(json.dumps(label_data))

        labels = load_all_labels(corpus_dir=tmp_path)
        assert len(labels) == 2

        labels_filtered = load_all_labels(corpus_dir=tmp_path, bug_class="auth")
        assert len(labels_filtered) == 1
        assert labels_filtered[0].bug_class == "auth"

    def _write_label(self, path, fid, bug_class="auth"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "schema_version": 1,
            "function_id": fid,
            "bug_class": bug_class,
            "expected_status": "clean",
            "rationale": "Test.",
            "source": {
                "repo": "test", "sha": "abc",
                "file": "a.c", "line_start": 1, "line_end": 10,
            },
            "labeler": "test",
            "labeled_at": "2026-07-28",
        }))

    def test_duplicate_function_id_rejected(self, tmp_path):
        self._write_label(tmp_path / "auth" / "one.label.json", "a.c:f")
        self._write_label(tmp_path / "lifecycle" / "two.label.json",
                          "a.c:f", bug_class="lifecycle")
        with pytest.raises(ValueError, match="duplicate function_id"):
            load_all_labels(corpus_dir=tmp_path)

    def test_duplicate_error_names_both_files(self, tmp_path):
        self._write_label(tmp_path / "auth" / "one.label.json", "a.c:f")
        self._write_label(tmp_path / "auth" / "two.label.json", "a.c:f")
        with pytest.raises(ValueError) as exc:
            load_all_labels(corpus_dir=tmp_path)
        assert "one.label.json" in str(exc.value)
        assert "two.label.json" in str(exc.value)

    def test_duplicate_detected_even_when_class_filtered_out(self, tmp_path):
        # A duplicate hidden by --class filtering must still fail —
        # the corpus itself is broken, not just this selection.
        self._write_label(tmp_path / "auth" / "one.label.json", "a.c:f")
        self._write_label(tmp_path / "lifecycle" / "two.label.json",
                          "a.c:f", bug_class="lifecycle")
        with pytest.raises(ValueError, match="duplicate function_id"):
            load_all_labels(corpus_dir=tmp_path, bug_class="auth")

    def test_distinct_ids_pass(self, tmp_path):
        self._write_label(tmp_path / "auth" / "one.label.json", "a.c:f")
        self._write_label(tmp_path / "auth" / "two.label.json", "a.c:g")
        assert len(load_all_labels(corpus_dir=tmp_path)) == 2


class TestCommittedLabels:
    """Validate that all committed label files parse correctly."""

    def test_all_committed_labels_valid(self):
        labels_dir = Path(__file__).parent.parent / "labels"
        if not labels_dir.is_dir():
            pytest.skip("No labels directory")
        label_files = list(labels_dir.rglob("*.label.json"))
        if not label_files:
            pytest.skip("No label files committed yet")
        for p in label_files:
            label = load_label(p)
            assert label.bug_class in VALID_BUG_CLASSES
            assert label.expected_status in VALID_EXPECTED_STATUSES
            assert label.function_id
            assert label.rationale
            assert label.source.repo
            assert label.source.sha


class TestSpanSha:
    """Content-addressed pins: optional span_sha on SourcePin."""

    def _pin(self, **overrides):
        defaults = {
            "repo": "demo-repo",
            "sha": "abc123",
            "file": "src/net/session.c",
            "line_start": 142,
            "line_end": 280,
        }
        defaults.update(overrides)
        return SourcePin(**defaults)

    def test_absent_defaults_empty(self):
        assert self._pin().span_sha == ""

    def test_valid_span_sha_accepted(self):
        pin = self._pin(span_sha="0123456789ab")
        assert pin.span_sha == "0123456789ab"

    def test_wrong_length_rejected(self):
        with pytest.raises(ValueError, match="Invalid span_sha"):
            self._pin(span_sha="0123456789abcdef")

    def test_non_hex_rejected(self):
        with pytest.raises(ValueError, match="Invalid span_sha"):
            self._pin(span_sha="0123456789zz")

    def test_uppercase_rejected(self):
        with pytest.raises(ValueError, match="Invalid span_sha"):
            self._pin(span_sha="0123456789AB")

    def test_compute_matches_staleness_convention(self, tmp_path):
        from core.staleness import hash_span

        src = tmp_path / "a.c"
        text = "int a;\nint b;\nint c;\nint d;\n"
        src.write_text(text)
        got = compute_span_sha(text, 2, 3)
        assert got == hash_span(src, 2, 3)
        assert len(got) == SPAN_SHA_LEN

    def test_compute_invalid_range_empty(self):
        assert compute_span_sha("int a;\n", 5, 9) == ""

    def test_to_dict_and_load_roundtrip(self, tmp_path):
        label = _make_label(source=SourcePin(
            repo="test-app", sha="deadbeef", file="src/auth.py",
            line_start=10, line_end=25, span_sha="0123456789ab",
        ))
        p = tmp_path / "test.label.json"
        p.write_text(json.dumps(label.to_dict()))
        loaded = load_label(p)
        assert loaded.source.span_sha == "0123456789ab"

    def test_older_label_without_span_sha_loads(self, tmp_path):
        label = _make_label()
        d = label.to_dict()
        del d["source"]["span_sha"]
        p = tmp_path / "test.label.json"
        p.write_text(json.dumps(d))
        assert load_label(p).source.span_sha == ""
