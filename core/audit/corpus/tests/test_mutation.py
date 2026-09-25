"""Tests for the synthetic-mutant label kind and mutation mechanics."""

from __future__ import annotations

import json

import pytest

from core.audit.corpus.label import (
    FunctionLabel,
    SourcePin,
    VALID_BUG_CLASSES,
    compute_span_sha,
    load_label,
)
from core.audit.corpus.lint import provenance_check
from core.audit.corpus.mutation import (
    KIND_REAL,
    MAX_MUTATION_SPEC_BYTES,
    MUTATION_OPERATORS,
    OPERATOR_INFO,
    PROVENANCE_SYNTHETIC_MUTANT,
    MutationError,
    apply_labels_to_tree,
    apply_mutation_to_text,
    build_mutation_spec,
    label_kind,
    mutated_span,
    validate_mutation_spec,
)


CLEAN_TEXT = """\
#include <stdlib.h>

int use_buf(char *p)
{
    if (!p)
        return -1;
    p[0] = 1;
    return 0;
}
"""

# The pinned function span of use_buf in CLEAN_TEXT.
SPAN = (3, 9)
# Dropping the two guard lines (5-6).
GUARD_EDIT = (5, 6, [])


def _spec(**overrides):
    spec = build_mutation_spec(
        CLEAN_TEXT,
        line_start=SPAN[0],
        line_end=SPAN[1],
        operator="drop-guard",
        site_line=5,
        edits=[GUARD_EDIT],
    )
    spec.update(overrides)
    return spec


def _label(**overrides):
    defaults = {
        "function_id": "src/buf.c:use_buf",
        "bug_class": "consistency",
        "expected_status": "finding",
        "rationale": "Synthetic drop-guard mutant of a clean family.",
        "source": SourcePin(
            repo="demo-repo",
            sha="abc123",
            file="src/buf.c",
            line_start=SPAN[0],
            line_end=SPAN[1],
            span_sha=compute_span_sha(CLEAN_TEXT, *SPAN),
        ),
        "labeler": "mutation-generator",
        "labeled_at": "2026-09-23",
        "provenance_kind": "synthetic_mutant",
        "mutation": _spec(),
        "expected_mechanism": "consistency",
        "excerpt_scope": "peer_set",
    }
    defaults.update(overrides)
    return FunctionLabel(**defaults)


class TestKind:
    def test_consistency_bug_class_valid(self):
        assert "consistency" in VALID_BUG_CLASSES

    def test_real_label_kind(self):
        label = _label(
            provenance_kind="", mutation={}, bug_class="auth",
        )
        assert label_kind(label) == KIND_REAL

    def test_synthetic_label_kind(self):
        assert label_kind(_label()) == PROVENANCE_SYNTHETIC_MUTANT

    def test_operator_info_covers_every_operator(self):
        assert set(OPERATOR_INFO) == set(MUTATION_OPERATORS)


class TestSchema:
    def test_valid_synthetic_label(self):
        label = _label()
        assert label.mutation["operator"] == "drop-guard"

    def test_invalid_provenance_kind(self):
        with pytest.raises(ValueError, match="Invalid provenance_kind"):
            _label(provenance_kind="mutant")

    def test_mutation_without_kind_rejected(self):
        with pytest.raises(ValueError, match="must declare its kind"):
            _label(provenance_kind="")

    def test_synthetic_with_cve_rejected(self):
        with pytest.raises(ValueError, match="never dressed"):
            _label(cve="CVE-2026-1234")

    def test_synthetic_with_fix_commit_rejected(self):
        with pytest.raises(ValueError, match="never dressed"):
            _label(fix_commit="deadbeef")

    def test_synthetic_without_parent_span_sha_rejected(self):
        pin = SourcePin(
            repo="demo-repo", sha="abc123", file="src/buf.c",
            line_start=SPAN[0], line_end=SPAN[1],
        )
        with pytest.raises(ValueError, match="content-addressed"):
            _label(source=pin)

    def test_synthetic_without_spec_rejected(self):
        with pytest.raises(ValueError, match="non-empty object"):
            _label(mutation={})

    def test_load_roundtrip(self, tmp_path):
        label = _label()
        p = tmp_path / "mutant.label.json"
        p.write_text(json.dumps(label.to_dict()))
        loaded = load_label(p)
        assert loaded.provenance_kind == "synthetic_mutant"
        assert loaded.mutation == label.mutation

    def test_real_label_defaults(self, tmp_path):
        label = _label(
            provenance_kind="", mutation={}, bug_class="auth",
        )
        d = label.to_dict()
        del d["provenance_kind"]
        del d["mutation"]
        p = tmp_path / "real.label.json"
        p.write_text(json.dumps(d))
        loaded = load_label(p)
        assert loaded.provenance_kind == ""
        assert loaded.mutation == {}


class TestValidateSpec:
    def test_valid(self):
        assert validate_mutation_spec(_spec(), span=SPAN) == []

    def test_unknown_operator(self):
        errors = validate_mutation_spec(
            _spec(operator="explode"), span=SPAN,
        )
        assert any("operator" in e for e in errors)

    def test_edit_outside_span(self):
        errors = validate_mutation_spec(
            _spec(edits=[{
                "line_start": 1, "line_end": 1, "replacement": [],
            }], mutated_line_end=8),
            span=SPAN,
        )
        assert any("outside the pinned span" in e for e in errors)

    def test_inconsistent_mutated_line_end(self):
        errors = validate_mutation_spec(
            _spec(mutated_line_end=9), span=SPAN,
        )
        assert any("inconsistent" in e for e in errors)

    def test_bad_span_sha(self):
        errors = validate_mutation_spec(
            _spec(mutated_span_sha="XYZ"), span=SPAN,
        )
        assert any("mutated_span_sha" in e for e in errors)

    def test_overlapping_edits(self):
        errors = validate_mutation_spec(
            _spec(edits=[
                {"line_start": 5, "line_end": 6, "replacement": []},
                {"line_start": 6, "line_end": 6, "replacement": []},
            ]),
            span=SPAN,
        )
        assert any("non-overlapping" in e for e in errors)

    def test_size_cap(self):
        big = "x" * 300
        spec = _spec(note="".join(big for _ in range(80)))
        assert len(json.dumps(spec)) > MAX_MUTATION_SPEC_BYTES
        errors = validate_mutation_spec(spec, span=SPAN)
        assert any("bytes" in e for e in errors)

    def test_not_a_dict(self):
        assert validate_mutation_spec([], span=SPAN)
        assert validate_mutation_spec(None, span=SPAN)

    def test_bool_line_numbers_rejected(self):
        errors = validate_mutation_spec(
            _spec(edits=[{
                "line_start": True, "line_end": 6, "replacement": [],
            }]),
            span=SPAN,
        )
        assert any("line_start" in e for e in errors)


class TestNoOpRefusal:
    """Laundering tripwire: a spec whose applied result hashes
    identical to the parent pin changed nothing — a no-op label could
    declare pristine upstream code carrying a REAL bug as synthetic.
    Refused at all three chokepoints: generation, schema, apply."""

    def _noop_spec(self):
        # Shape-valid, delta 0, replacement identical to the original
        # guard lines — mutated span == parent span byte-for-byte.
        lines = CLEAN_TEXT.split("\n")
        return {
            "operator": "drop-guard",
            "site_line": 5,
            "edits": [{
                "line_start": 5, "line_end": 6,
                "replacement": [lines[4], lines[5]],
            }],
            "mutated_line_end": SPAN[1],
            "mutated_span_sha": compute_span_sha(CLEAN_TEXT, *SPAN),
        }

    def test_builder_refuses_noop(self):
        lines = CLEAN_TEXT.split("\n")
        with pytest.raises(MutationError, match="no-op mutation"):
            build_mutation_spec(
                CLEAN_TEXT,
                line_start=SPAN[0], line_end=SPAN[1],
                operator="drop-guard", site_line=5,
                edits=[(5, 6, [lines[4], lines[5]])],
            )

    def test_schema_refuses_noop(self):
        with pytest.raises(ValueError, match="no-op mutation"):
            _label(mutation=self._noop_spec())

    def test_apply_refuses_noop(self):
        # Apply-level belt-and-braces: a label-shaped object that
        # bypassed schema validation still refuses at application.
        from types import SimpleNamespace

        label = SimpleNamespace(
            function_id="src/buf.c:use_buf",
            source=SourcePin(
                repo="demo-repo", sha="abc123", file="src/buf.c",
                line_start=SPAN[0], line_end=SPAN[1],
                span_sha=compute_span_sha(CLEAN_TEXT, *SPAN),
            ),
            mutation=self._noop_spec(),
        )
        with pytest.raises(MutationError, match="no-op mutation"):
            apply_mutation_to_text(CLEAN_TEXT, label)


class TestApply:
    def test_apply_matches_spec(self):
        mutated = apply_mutation_to_text(CLEAN_TEXT, _label())
        assert "if (!p)" not in mutated
        assert "p[0] = 1;" in mutated
        start, end = SPAN[0], _label().mutation["mutated_line_end"]
        assert compute_span_sha(mutated, start, end) == \
            _label().mutation["mutated_span_sha"]

    def test_parent_drift_refused(self):
        drifted = CLEAN_TEXT.replace("p[0] = 1;", "p[1] = 2;")
        with pytest.raises(MutationError, match="parent span"):
            apply_mutation_to_text(drifted, _label())

    def test_wrong_mutated_sha_refused(self):
        label = _label(mutation=_spec(mutated_span_sha="0" * 12))
        with pytest.raises(MutationError, match="mutated span"):
            apply_mutation_to_text(CLEAN_TEXT, label)

    def test_mutated_span_semantics(self):
        label = _label()
        assert mutated_span(label) == (
            SPAN[0], label.mutation["mutated_line_end"],
        )
        real = _label(
            provenance_kind="", mutation={}, bug_class="auth",
        )
        assert mutated_span(real) == SPAN

    def test_build_spec_refuses_edit_past_eof(self):
        with pytest.raises(MutationError, match="beyond end"):
            build_mutation_spec(
                CLEAN_TEXT,
                line_start=SPAN[0], line_end=SPAN[1],
                operator="drop-guard", site_line=5,
                edits=[(5, 500, [])],
            )


class TestApplyToTree:
    def test_applies_and_verifies(self, tmp_path):
        tree = tmp_path / "demo-repo"
        (tree / "src").mkdir(parents=True)
        (tree / "src" / "buf.c").write_text(CLEAN_TEXT)
        errors = apply_labels_to_tree([_label()], {"demo-repo": tree})
        assert errors == []
        mutated = (tree / "src" / "buf.c").read_text()
        assert "if (!p)" not in mutated

    def test_missing_file_reported(self, tmp_path):
        tree = tmp_path / "demo-repo"
        tree.mkdir()
        errors = apply_labels_to_tree([_label()], {"demo-repo": tree})
        assert errors and "missing" in errors[0]

    def test_missing_tree_reported(self, tmp_path):
        errors = apply_labels_to_tree([_label()], {})
        assert errors and "no tree" in errors[0]

    def test_real_labels_ignored(self, tmp_path):
        real = _label(
            provenance_kind="", mutation={}, bug_class="auth",
        )
        assert apply_labels_to_tree([real], {}) == []


class TestLintCarveOut:
    def test_synthetic_finding_not_warned(self):
        warnings = provenance_check([(None, _label())])
        assert warnings == []

    def test_real_finding_still_warned(self):
        real = _label(
            provenance_kind="", mutation={}, bug_class="auth",
        )
        warnings = provenance_check([(None, real)])
        assert len(warnings) == 1
        assert "no public provenance" in warnings[0]
