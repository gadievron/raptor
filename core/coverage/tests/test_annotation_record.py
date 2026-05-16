"""Tests for ``core.coverage.record.build_from_annotations``.

The builder converts an annotation tree into a coverage record
that the existing summary computation can ingest. Annotated
functions count as "examined" for coverage purposes.
"""

from __future__ import annotations



from core.annotations import Annotation, write_annotation
from core.coverage.record import build_from_annotations, load_records


class TestBuildFromAnnotations:
    def test_returns_none_for_missing_dir(self, tmp_path):
        assert build_from_annotations(tmp_path / "nope") is None

    def test_returns_none_for_empty_dir(self, tmp_path):
        # Directory exists but has no annotations.
        assert build_from_annotations(tmp_path) is None

    def test_basic_record_fields(self, tmp_path):
        write_annotation(tmp_path, Annotation(
            file="src/auth.py", function="check_pw",
            body="ok", metadata={"status": "clean", "source": "human"},
        ))
        record = build_from_annotations(tmp_path)
        assert record is not None
        assert record["tool"] == "annotations"
        assert record["files_examined"] == ["src/auth.py"]
        # The function entry has at minimum file + function. Status
        # and hash are populated when the annotation metadata carries
        # them — pinned in the per-function-metadata test below.
        assert len(record["functions_analysed"]) == 1
        entry = record["functions_analysed"][0]
        assert entry["file"] == "src/auth.py"
        assert entry["function"] == "check_pw"
        assert "timestamp" in record

    def test_per_function_status_and_hash_inlined(self, tmp_path):
        """Annotation metadata's ``status`` and ``hash`` flow into
        each function entry — /audit's coverage-audit.json schema
        wants these inline so consumers see verdict + freshness
        without re-reading annotations."""
        write_annotation(tmp_path, Annotation(
            file="src/x.py", function="suspicious_fn",
            metadata={
                "status": "suspicious",
                "hash": "abc123def456",
                "source": "llm",
            },
        ))
        record = build_from_annotations(tmp_path)
        entry = record["functions_analysed"][0]
        assert entry["status"] == "suspicious"
        assert entry["hash"] == "abc123def456"

    def test_status_and_hash_omitted_when_absent(self, tmp_path):
        write_annotation(tmp_path, Annotation(
            file="src/x.py", function="bare_fn",
            metadata={"source": "human"},  # no status, no hash
        ))
        record = build_from_annotations(tmp_path)
        entry = record["functions_analysed"][0]
        assert "status" not in entry
        assert "hash" not in entry

    def test_tool_name_override(self, tmp_path):
        """``/audit`` passes ``tool_name="audit"`` so its records
        land as ``coverage-audit.json``, distinct from /agentic and
        /understand's annotation-derived ``coverage-annotations.json``."""
        write_annotation(tmp_path, Annotation(
            file="src/x.py", function="f",
            metadata={"status": "clean"},
        ))
        record = build_from_annotations(tmp_path, tool_name="audit")
        assert record["tool"] == "audit"

    def test_default_tool_name_is_annotations(self, tmp_path):
        write_annotation(tmp_path, Annotation(
            file="src/x.py", function="f",
            metadata={"status": "clean"},
        ))
        record = build_from_annotations(tmp_path)
        assert record["tool"] == "annotations"

    def test_aggregates_status_and_source_counts(self, tmp_path):
        for fn, status, source in [
            ("a", "clean", "human"),
            ("b", "clean", "llm"),
            ("c", "finding", "llm"),
            ("d", "suspicious", "llm"),
        ]:
            write_annotation(tmp_path, Annotation(
                file="src/foo.py", function=fn, body="x",
                metadata={"status": status, "source": source},
            ))
        record = build_from_annotations(tmp_path)
        assert record["annotation_statuses"] == {
            "clean": 2, "finding": 1, "suspicious": 1,
        }
        assert record["annotation_sources"] == {"human": 1, "llm": 3}

    def test_dedupes_function_records(self, tmp_path):
        """Multiple annotations on the same (file, function) pair —
        the builder records the function once."""
        # Write twice — second overwrites first in-place.
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="login",
            body="first", metadata={"source": "human"},
        ))
        write_annotation(tmp_path, Annotation(
            file="src/foo.py", function="login",
            body="second", metadata={"source": "llm"},
        ))
        record = build_from_annotations(tmp_path)
        # Only one entry — same (file, function) collapses on disk.
        assert len(record["functions_analysed"]) == 1

    def test_walks_nested_tree(self, tmp_path):
        write_annotation(tmp_path, Annotation(
            file="src/a.py", function="f1", body="x",
        ))
        write_annotation(tmp_path, Annotation(
            file="lib/util.py", function="f2", body="y",
        ))
        write_annotation(tmp_path, Annotation(
            file="deep/nested/c.py", function="f3", body="z",
        ))
        record = build_from_annotations(tmp_path)
        assert set(record["files_examined"]) == {
            "src/a.py", "lib/util.py", "deep/nested/c.py",
        }
        assert len(record["functions_analysed"]) == 3


class TestRoundTripWithLoadRecords:
    """Once the record is written via ``write_record``, the standard
    ``load_records`` reader must pick it up."""

    def test_round_trip(self, tmp_path):
        from core.coverage.record import write_record
        ann_dir = tmp_path / "annotations"
        write_annotation(ann_dir, Annotation(
            file="src/foo.py", function="login",
            body="x", metadata={"status": "clean", "source": "human"},
        ))
        record = build_from_annotations(ann_dir)
        assert record is not None
        write_record(tmp_path, record, tool_name="annotations")
        # Now load_records picks it up alongside any other coverage
        # records (none in this test).
        records = load_records(tmp_path)
        assert any(r.get("tool") == "annotations" for r in records)
