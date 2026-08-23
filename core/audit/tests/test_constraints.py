"""Tests for core.audit.constraints — constraint data model and storage."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.constraints import (
    Constraint,
    extract_constraints_from_review,
    load_constraints,
    merge_constraint,
    open_constraints,
    refresh_constraint_statuses,
    save_constraints,
)


def _constraint(**kwargs):
    defaults = {
        "function": "parse_header",
        "file": "src/packet.c",
        "kind": "parameter",
        "target": "len",
        "rule": "len must be <= 1024",
        "violation": "stack buffer overflow",
    }
    defaults.update(kwargs)
    return Constraint(**defaults)


class TestConstraintIdentity:
    def test_identity_key(self):
        c = _constraint()
        assert c.identity == "src/packet.c:parse_header:parameter:len"

    def test_same_identity(self):
        c1 = _constraint(rule="must be <= 1024")
        c2 = _constraint(rule="must be <= 2048")
        assert c1.identity == c2.identity

    def test_different_target(self):
        c1 = _constraint(target="len")
        c2 = _constraint(target="buf")
        assert c1.identity != c2.identity

    def test_different_kind(self):
        c1 = _constraint(kind="parameter")
        c2 = _constraint(kind="precondition")
        assert c1.identity != c2.identity


class TestConstraintSerialization:
    def test_round_trip(self):
        c = _constraint(cwe="CWE-121", source_hash="abc123")
        d = c.to_dict()
        c2 = Constraint.from_dict(d)
        assert c2.function == c.function
        assert c2.cwe == "CWE-121"
        assert c2.source_hash == "abc123"

    def test_from_dict_ignores_unknown_keys(self):
        d = _constraint().to_dict()
        d["unknown_field"] = "should be ignored"
        c = Constraint.from_dict(d)
        assert c.function == "parse_header"

    def test_is_taint_expressible(self):
        assert _constraint(kind="parameter").is_taint_expressible()
        assert not _constraint(kind="precondition").is_taint_expressible()
        assert not _constraint(kind="state").is_taint_expressible()


class TestSaveLoadConstraints:
    def test_save_and_load(self, tmp_path: Path):
        constraints = [
            _constraint(target="len"),
            _constraint(target="buf", kind="parameter"),
        ]
        save_constraints(constraints, tmp_path)
        loaded = load_constraints(tmp_path)
        assert len(loaded) == 2
        assert loaded[0].target == "len"
        assert loaded[1].target == "buf"

    def test_load_empty_dir(self, tmp_path: Path):
        assert load_constraints(tmp_path) == []

    def test_load_corrupt_json(self, tmp_path: Path):
        (tmp_path / "constraints.json").write_text("{not valid")
        assert load_constraints(tmp_path) == []

    def test_load_non_list(self, tmp_path: Path):
        (tmp_path / "constraints.json").write_text('{"key": "value"}')
        assert load_constraints(tmp_path) == []

    def test_atomic_write(self, tmp_path: Path):
        save_constraints([_constraint()], tmp_path)
        path = tmp_path / "constraints.json"
        assert path.exists()
        data = json.loads(path.read_text())
        assert len(data) == 1
        assert data[0]["function"] == "parse_header"

    def test_creates_dir(self, tmp_path: Path):
        out = tmp_path / "sub" / "dir"
        save_constraints([_constraint()], out)
        assert (out / "constraints.json").exists()


class TestMergeConstraint:
    def test_append_new(self):
        existing = [_constraint(target="len")]
        new = _constraint(target="buf")
        result = merge_constraint(existing, new)
        assert len(result) == 2

    def test_replace_existing(self):
        existing = [_constraint(rule="old rule")]
        new = _constraint(rule="new rule")
        result = merge_constraint(existing, new)
        assert len(result) == 1
        assert result[0].rule == "new rule"

    def test_preserves_other_constraints(self):
        existing = [
            _constraint(target="len"),
            _constraint(target="buf"),
            _constraint(target="flags"),
        ]
        new = _constraint(target="buf", rule="updated")
        result = merge_constraint(existing, new)
        assert len(result) == 3
        assert result[1].rule == "updated"
        assert result[0].target == "len"
        assert result[2].target == "flags"


class TestOpenConstraints:
    def test_filters_to_open(self):
        constraints = [
            _constraint(status="open"),
            _constraint(status="refuted", target="a"),
            _constraint(status="depth_limited", target="b"),
            _constraint(status="verified", target="c"),
            _constraint(status="stale", target="d"),
        ]
        result = open_constraints(constraints)
        assert len(result) == 2
        targets = {c.target for c in result}
        assert targets == {"len", "b"}


class TestRefreshStatuses:
    def test_marks_stale_on_hash_change(self, tmp_path: Path):
        from core.annotations.storage import compute_function_hash

        (tmp_path / "src").mkdir()
        src = tmp_path / "src" / "packet.c"
        src.write_text("int parse_header() { return 0; }\n")
        old_hash = compute_function_hash(src, 1, 1)

        src.write_text("int parse_header() { return validate(); }\n")

        checklist = {
            "files": [
                {"path": "src/packet.c", "items": [
                    {"name": "parse_header", "line_start": 1, "line_end": 1},
                ]},
            ],
        }
        constraints = [_constraint(source_hash=old_hash, status="open")]
        result = refresh_constraint_statuses(
            constraints, tmp_path, checklist,
        )
        assert result[0].status == "stale"

    def test_keeps_fresh_on_same_hash(self, tmp_path: Path):
        from core.annotations.storage import compute_function_hash

        (tmp_path / "src").mkdir()
        src = tmp_path / "src" / "packet.c"
        src.write_text("int parse_header() { return 0; }\n")
        current_hash = compute_function_hash(src, 1, 1)

        checklist = {
            "files": [
                {"path": "src/packet.c", "items": [
                    {"name": "parse_header", "line_start": 1, "line_end": 1},
                ]},
            ],
        }
        constraints = [_constraint(source_hash=current_hash, status="open")]
        result = refresh_constraint_statuses(
            constraints, tmp_path, checklist,
        )
        assert result[0].status == "open"

    def test_skips_terminal_statuses(self, tmp_path: Path):
        constraints = [
            _constraint(status="refuted", source_hash="abc"),
            _constraint(status="verified", source_hash="def", target="a"),
            _constraint(status="mechanised", source_hash="ghi", target="b"),
        ]
        result = refresh_constraint_statuses(constraints, tmp_path, {})
        assert [c.status for c in result] == [
            "refuted", "verified", "mechanised",
        ]

    def test_no_checklist(self, tmp_path: Path):
        constraints = [_constraint(source_hash="abc")]
        result = refresh_constraint_statuses(constraints, tmp_path, None)
        assert result[0].status == "open"

    def test_deleted_file_marked_stale(self, tmp_path: Path):
        checklist = {
            "files": [
                {"path": "src/packet.c", "items": [
                    {"name": "parse_header", "line_start": 1, "line_end": 1},
                ]},
            ],
        }
        constraints = [_constraint(source_hash="abc")]
        result = refresh_constraint_statuses(
            constraints, tmp_path, checklist,
        )
        assert result[0].status == "stale"


class TestExtractConstraints:
    def test_extracts_valid_constraint(self):
        review = {
            "constraints": [
                {
                    "kind": "parameter",
                    "target": "len",
                    "rule": "must be <= 1024",
                    "violation": "stack overflow",
                    "cwe": "CWE-121",
                    "direction": "callers",
                },
            ],
        }
        result = extract_constraints_from_review(
            review, "src/packet.c", "parse_header",
            source_hash="abc", source_review="run_001",
        )
        assert len(result) == 1
        c = result[0]
        assert c.function == "parse_header"
        assert c.file == "src/packet.c"
        assert c.kind == "parameter"
        assert c.target == "len"
        assert c.source_hash == "abc"
        assert c.source_review == "run_001"

    def test_skips_invalid_kind(self):
        review = {
            "constraints": [
                {"kind": "bogus", "target": "x", "rule": "y"},
            ],
        }
        assert extract_constraints_from_review(review, "a.c", "f") == []

    def test_skips_missing_target(self):
        review = {
            "constraints": [
                {"kind": "parameter", "target": "", "rule": "x"},
            ],
        }
        assert extract_constraints_from_review(review, "a.c", "f") == []

    def test_skips_missing_rule(self):
        review = {
            "constraints": [
                {"kind": "parameter", "target": "x", "rule": ""},
            ],
        }
        assert extract_constraints_from_review(review, "a.c", "f") == []

    def test_no_constraints_key(self):
        assert extract_constraints_from_review({}, "a.c", "f") == []

    def test_constraints_not_list(self):
        assert extract_constraints_from_review(
            {"constraints": "not a list"}, "a.c", "f",
        ) == []

    def test_invalid_direction_defaults_to_callers(self):
        review = {
            "constraints": [
                {
                    "kind": "parameter",
                    "target": "x",
                    "rule": "y",
                    "direction": "sideways",
                },
            ],
        }
        result = extract_constraints_from_review(review, "a.c", "f")
        assert result[0].direction == "callers"

    def test_multiple_constraints(self):
        review = {
            "constraints": [
                {"kind": "parameter", "target": "len", "rule": "bounded"},
                {"kind": "precondition", "target": "lock", "rule": "held"},
            ],
        }
        result = extract_constraints_from_review(review, "a.c", "f")
        assert len(result) == 2
