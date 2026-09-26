"""Tier gating of structural broken-link refutations.

The cross-file taint engine serializes per-step ``properties`` (tier,
tags) into its dataflow paths. A hop the engine itself derived
heuristically (dispatch table, assumed propagation, binding guess) is
one tree-sitter cannot be expected to re-derive — the absence of a
call edge there is not evidence the chain is broken. Broken links
whose endpoint steps carry sub-``resolved_static`` properties demote
the would-be ``refuted`` to ``inconclusive``; everything without step
properties (every other producer) keeps byte-identical verdicts.
"""

from __future__ import annotations

import pytest

from core.dataflow.structural_validator import (
    _step_sub_static,
    validate_structurally,
)


@pytest.fixture(autouse=True)
def _need_js_grammar():
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_javascript")


HELPER_TAIL = "function helper(y) {\n  sink(y);\n}\n"

#: run() calls other(), never helper() — the run→helper link is
#: genuinely absent, the shape the pre-gate validator refutes with
#: high confidence (pinned by the sibling attribution-divergence
#: tests).
BROKEN_HEAD = "function run(x) {\n  other(x);\n}\n"


def _step(file: str, line: int, properties: dict | None = None) -> dict:
    step = {"file": file, "line": line, "label": "", "snippet": ""}
    if properties is not None:
        step["properties"] = properties
    return step


def _path(source: dict, sink: dict, steps: list | None = None) -> dict:
    return {
        "source": source,
        "sink": sink,
        "steps": steps or [],
        "total_steps": 2 + len(steps or []),
    }


def _write_broken(tmp_path) -> None:
    (tmp_path / "broken.js").write_text(BROKEN_HEAD + HELPER_TAIL)


class TestSubStaticDemotesRefutation:
    def test_heuristic_tier_on_source_step_demotes(self, tmp_path):
        _write_broken(tmp_path)
        path = _path(
            _step("broken.js", 2, {"tier": "heuristic_dynamic"}),
            _step("broken.js", 5),
        )
        result = validate_structurally(path, tmp_path)
        assert result.verdict == "inconclusive"
        assert "demoted" in result.reasoning
        assert any(e.get("link_tier_gated") for e in result.evidence)

    def test_heuristic_tier_on_next_step_demotes(self, tmp_path):
        # The gate reads BOTH endpoints of the broken link — the hop
        # tier may be recorded on the step the edge lands on.
        _write_broken(tmp_path)
        path = _path(
            _step("broken.js", 2),
            _step("broken.js", 5, {"tier": "unresolved"}),
        )
        result = validate_structurally(path, tmp_path)
        assert result.verdict == "inconclusive"

    @pytest.mark.parametrize("tag", ["assumed_propagation", "binding_approx"])
    def test_approximation_tag_demotes_even_on_static_tier(
            self, tmp_path, tag):
        _write_broken(tmp_path)
        path = _path(
            _step("broken.js", 2,
                  {"tier": "resolved_static", "tags": [tag]}),
            _step("broken.js", 5),
        )
        result = validate_structurally(path, tmp_path)
        assert result.verdict == "inconclusive"

    def test_unknown_future_tier_demotes_conservatively(self, tmp_path):
        # An unknown tier value is not evidence-grade resolution;
        # demotion (abstain) is the safe direction.
        _write_broken(tmp_path)
        path = _path(
            _step("broken.js", 2, {"tier": "tier_from_the_future"}),
            _step("broken.js", 5),
        )
        result = validate_structurally(path, tmp_path)
        assert result.verdict == "inconclusive"


class TestRefutationLaneStaysLive:
    def test_resolved_static_steps_still_refute(self, tmp_path):
        # Two-direction: a fully source-static path with a genuinely
        # missing edge keeps the high-confidence refutation.
        _write_broken(tmp_path)
        path = _path(
            _step("broken.js", 2, {"tier": "resolved_static", "tags": []}),
            _step("broken.js", 5, {"tier": "resolved_static", "tags": []}),
        )
        result = validate_structurally(path, tmp_path)
        assert result.verdict == "refuted"

    def test_no_properties_still_refutes_byte_identical(self, tmp_path):
        # The producer-scoping differential: paths without step
        # properties (every non-taint producer) keep the pre-gate
        # verdict AND evidence shape — no link_tier_gated key appears.
        _write_broken(tmp_path)
        path = _path(_step("broken.js", 2), _step("broken.js", 5))
        result = validate_structurally(path, tmp_path)
        assert result.verdict == "refuted"
        assert result.confidence == "high"
        assert all("link_tier_gated" not in e for e in result.evidence)

    def test_ungated_broken_link_still_refutes_alongside_gated(
            self, tmp_path):
        # Mixed path: one broken link is tier-gated, another is fully
        # static — the static one is real refutation evidence and the
        # verdict stands.
        (tmp_path / "multi.js").write_text(
            "function run(x) {\n  other(x);\n}\n"
            "function mid(z) {\n  neither(z);\n}\n"
            + HELPER_TAIL
        )
        path = _path(
            _step("multi.js", 2, {"tier": "heuristic_dynamic"}),
            _step("multi.js", 8),
            steps=[_step("multi.js", 5)],
        )
        result = validate_structurally(path, tmp_path)
        assert result.verdict == "refuted"


class TestConfirmationsUnchanged:
    def test_found_edge_with_sub_static_step_stays_confirmed(
            self, tmp_path):
        # The gate applies to BROKEN links only: a found edge is a
        # found edge, whatever the step tier says.
        (tmp_path / "plain.js").write_text(
            "function run(x) {\n  helper(x);\n}\n" + HELPER_TAIL,
        )
        path = _path(
            _step("plain.js", 2, {"tier": "heuristic_dynamic"}),
            _step("plain.js", 5),
        )
        result = validate_structurally(path, tmp_path)
        assert result.verdict == "confirmed"
        assert result.confidence == "high"


class TestStepSubStaticHelper:
    def test_no_properties_false(self):
        assert _step_sub_static({"file": "a.js", "line": 1}) is False

    def test_non_dict_properties_false(self):
        assert _step_sub_static({"properties": "junk"}) is False

    def test_resolved_static_false(self):
        assert _step_sub_static(
            {"properties": {"tier": "resolved_static"}}) is False

    def test_non_string_tier_ignored(self):
        assert _step_sub_static({"properties": {"tier": 3}}) is False

    def test_empty_tier_ignored(self):
        assert _step_sub_static({"properties": {"tier": ""}}) is False

    def test_sub_static_tier_true(self):
        assert _step_sub_static(
            {"properties": {"tier": "resolved_convention"}}) is True

    def test_tag_true(self):
        assert _step_sub_static(
            {"properties": {"tags": ["assumed_propagation"]}}) is True

    def test_unrelated_tags_false(self):
        assert _step_sub_static(
            {"properties": {"tags": ["excerpt_truncated"]}}) is False

    def test_non_list_tags_false(self):
        assert _step_sub_static(
            {"properties": {"tags": "assumed_propagation"}}) is False

    def test_non_string_tag_entries_ignored(self):
        assert _step_sub_static(
            {"properties": {"tags": [None, 7]}}) is False
