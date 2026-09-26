"""Policy layer of the classifier's bounded retrieval tool loop.

Unit tests for ``packages.llm_analysis.context_toolloop``: the closed
vocabulary (unknown tools refused, never executed), mechanical
argument validation on hostile model output, resolved path containment
(traversal / absolute / symlink escapes), the span/turn/byte rails
with parsed-count revert probes in both directions, the per-finding
file cache, the bounded record shapes, and hostile target bytes
staying escaped at the prompt-bundle egress. Loop-driver behaviour
(turn sequencing, budgets shared with expansion, joins) lives in
test_context_toolloop_agent.py.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import packages.llm_analysis.context_toolloop as toolloop  # noqa: E402
from packages.llm_analysis.context_toolloop import (  # noqa: E402
    CONTEXT_REQUESTS_FIELD,
    MAX_REQUESTS_PER_TURN,
    MAX_TOOLLOOP_TURNS,
    READ_SPAN_MAX_LINES,
    RENDERED_LINE_WIDTH,
    TOOL_RESULT_MAX_BYTES,
    TOOL_VOCABULARY,
    TOOLLOOP_MAX_TOTAL_BYTES,
    ToolLoopState,
    augment_schema,
    build_toolloop_record,
    has_requests,
    run_turn_requests,
)

_N_LINES = 300


def _write_repo(repo: Path) -> None:
    repo.mkdir(exist_ok=True)
    lines = [f"int marker_line_{i:04d};" for i in range(1, _N_LINES + 1)]
    (repo / "vuln.c").write_text("\n".join(lines) + "\n")


def _state(repo: Path, **kwargs) -> ToolLoopState:
    return ToolLoopState.for_repo(repo, **kwargs)


def _span(file: str, start: int, end: int) -> dict:
    return {"tool": "read_span", "file": file, "start": start, "end": end}


def _one(state: ToolLoopState, request: dict) -> dict:
    """Run one request through the turn executor; return its record."""
    _block, records = run_turn_requests([request], state)
    assert len(records) == 1
    return records[0]


class TestSchemaAugmentation:
    def test_augmented_field_is_nullable_array_and_copy(self):
        base = {"is_true_positive": "bool. verdict", "confidence": "string"}
        out = augment_schema(base)
        assert CONTEXT_REQUESTS_FIELD in out
        assert CONTEXT_REQUESTS_FIELD not in base  # input never mutated
        spec = out[CONTEXT_REQUESTS_FIELD]
        # Simple-schema contract: first token types the field, "null"
        # marks it nullable — so a verdict response may omit it.
        assert spec.split()[0] == "list"
        assert "null" in spec
        # The spec advertises the real vocabulary and the real caps.
        for tool in sorted(TOOL_VOCABULARY):
            assert tool in spec
        assert str(READ_SPAN_MAX_LINES) in spec
        assert str(MAX_REQUESTS_PER_TURN) in spec

    def test_verdict_without_requests_field_is_not_incomplete(self):
        # A model that answers with a plain verdict (no
        # context_requests key) must not be scored as incomplete —
        # otherwise every verdict turn drags toward the quality-retry
        # threshold.
        from core.llm.response_validation import (
            validate_structured_response,
        )
        schema = augment_schema({
            "is_true_positive": "bool. verdict",
            "reasoning": "string. why",
        })
        validated = validate_structured_response(
            {"is_true_positive": True, "reasoning": "solid"}, schema,
        )
        assert validated.data[CONTEXT_REQUESTS_FIELD] is None
        assert CONTEXT_REQUESTS_FIELD not in validated.incomplete

    def test_request_list_passes_validation_as_array(self):
        from core.llm.response_validation import (
            validate_structured_response,
        )
        schema = augment_schema({"reasoning": "string. why"})
        requests = [_span("vuln.c", 1, 10)]
        validated = validate_structured_response(
            {"reasoning": "need more", CONTEXT_REQUESTS_FIELD: requests},
            schema,
        )
        assert validated.data[CONTEXT_REQUESTS_FIELD] == requests

    def test_has_requests(self):
        assert has_requests([{"tool": "read_span"}]) is True
        assert has_requests([]) is False
        assert has_requests(None) is False
        assert has_requests("read_span") is False


class TestClosedVocabulary:
    def test_unknown_tool_is_refused_never_executed(self, tmp_path):
        _write_repo(tmp_path)
        state = _state(tmp_path)
        with patch.object(
            toolloop, "read_bytes_capped",
            side_effect=AssertionError("disk touched for unknown tool"),
        ):
            record = _one(state, {
                "tool": "shell", "file": "vuln.c", "start": 1, "end": 2,
            })
        assert record["status"] == "refused"
        assert record["reason"] == "unknown_tool"
        # The hostile tool name is never echoed into the record.
        assert "shell" not in str(record)
        assert state.refused == 1 and state.served == 0

    def test_non_dict_request_is_malformed(self, tmp_path):
        _write_repo(tmp_path)
        state = _state(tmp_path)
        record = _one(state, "read vuln.c")
        assert record["reason"] == "malformed_request"

    def test_vocabulary_is_exactly_the_three_read_tools(self):
        assert TOOL_VOCABULARY == {
            "read_span", "list_callers", "list_callees",
        }

    def test_no_requests_means_no_block(self, tmp_path):
        _write_repo(tmp_path)
        for raw in (None, [], "x", {}):
            block, records = run_turn_requests(raw, _state(tmp_path))
            assert block is None and records == []


class TestArgumentValidation:
    @pytest.mark.parametrize("file_arg", [
        None, 7, "", "a" * 513, "vuln\x00.c", "vuln\x1b.c", "vu\nln.c",
        # C1 controls and Unicode format chars (bidi overrides /
        # isolates, zero-width) are charset-refused too — a served
        # target echoes into the analysis record and must never carry
        # display-reordering bytes.
        "vuln\x85.c", "vu‮ln.c", "vuln​.c",
    ])
    def test_bad_file_args_are_malformed(self, tmp_path, file_arg):
        _write_repo(tmp_path)
        record = _one(_state(tmp_path), _span(file_arg, 1, 2))
        assert record["reason"] == "malformed_request"

    @pytest.mark.parametrize("start,end", [
        (0, 2), (-1, 2), (1, 0), ("1", 2), (1, "2"), (True, 2), (1, True),
        (1.5, 2), (None, 2), (10_000_001, 10_000_002),
    ])
    def test_bad_line_args_are_malformed(self, tmp_path, start, end):
        _write_repo(tmp_path)
        record = _one(_state(tmp_path), _span("vuln.c", start, end))
        assert record["reason"] == "malformed_request"

    def test_start_after_end_is_invalid_range(self, tmp_path):
        _write_repo(tmp_path)
        record = _one(_state(tmp_path), _span("vuln.c", 10, 5))
        assert record["reason"] == "invalid_range"

    @pytest.mark.parametrize("function", [
        None, 7, "", "   ", "f" * 201, "fn\x1b]0;x\x07",
        # C1 / bidi / zero-width function names refused at validation
        # — never looked up, never echoed into a served record.
        "f\x85n", "ma‮in", "pro⁦cess⁩", "ma​in",
    ])
    def test_bad_function_args_are_malformed(self, tmp_path, function):
        _write_repo(tmp_path)
        record = _one(_state(tmp_path), {
            "tool": "list_callers", "function": function,
        })
        assert record["reason"] == "malformed_request"

    def test_bidi_function_name_never_reaches_record_target(
        self, tmp_path,
    ):
        """SHOULD-3 pin: the served-record ``target`` echo is genuinely
        charset-checked — a bidi-override-carrying function name is a
        counted refusal whose record carries no format character (the
        refusal note is an operator-authored constant)."""
        _write_repo(tmp_path)
        state = _state(tmp_path)
        record = _one(state, {
            "tool": "list_callers", "function": "‮evil",
        })
        assert record["status"] == "refused"
        assert record["reason"] == "malformed_request"
        assert "‮" not in str(record)
        assert state.refused == 1 and state.served == 0


class TestContainment:
    def test_traversal_is_path_escape(self, tmp_path):
        repo = tmp_path / "repo"
        _write_repo(repo)
        (tmp_path / "outside.c").write_text("secret\n")
        state = _state(repo)
        record = _one(state, _span("../outside.c", 1, 1))
        assert record["reason"] == "path_escape"
        assert state.refused == 1

    def test_absolute_outside_path_is_path_escape(self, tmp_path):
        repo = tmp_path / "repo"
        _write_repo(repo)
        (tmp_path / "outside.c").write_text("secret\n")
        record = _one(
            _state(repo), _span(str(tmp_path / "outside.c"), 1, 1),
        )
        assert record["reason"] == "path_escape"

    def test_symlink_escape_is_path_escape(self, tmp_path):
        # The check is RESOLVED containment, not lexical: a repo-
        # relative name whose symlink target leaves the repo is
        # refused even though the argument looks contained.
        repo = tmp_path / "repo"
        _write_repo(repo)
        (tmp_path / "outside.c").write_text("secret\n")
        os.symlink(tmp_path / "outside.c", repo / "link.c")
        record = _one(_state(repo), _span("link.c", 1, 1))
        assert record["reason"] == "path_escape"

    def test_symlink_within_repo_is_served(self, tmp_path):
        repo = tmp_path / "repo"
        _write_repo(repo)
        os.symlink(repo / "vuln.c", repo / "alias.c")
        record = _one(_state(repo), _span("alias.c", 1, 1))
        assert record["status"] == "served"

    def test_missing_file_is_not_a_file(self, tmp_path):
        _write_repo(tmp_path)
        record = _one(_state(tmp_path), _span("nope.c", 1, 1))
        assert record["reason"] == "not_a_file"

    def test_directory_is_not_a_file(self, tmp_path):
        _write_repo(tmp_path)
        (tmp_path / "subdir").mkdir()
        record = _one(_state(tmp_path), _span("subdir", 1, 1))
        assert record["reason"] == "not_a_file"

    def test_call_graph_file_arg_is_confined_too(self, tmp_path):
        repo = tmp_path / "repo"
        _write_repo(repo)
        record = _one(_state(repo), {
            "tool": "list_callers", "function": "target_fn",
            "file": "../other.c",
        })
        assert record["reason"] == "path_escape"


class TestReadSpan:
    def test_serves_numbered_lines_within_span(self, tmp_path):
        _write_repo(tmp_path)
        state = _state(tmp_path)
        block, records = run_turn_requests(
            [_span("vuln.c", 130, 132)], state,
        )
        record = records[0]
        assert record["status"] == "served"
        assert record["target"] == "vuln.c:130-132"
        assert record["result_bytes"] > 0
        assert "130: int marker_line_0130;" in block.content
        assert "132: int marker_line_0132;" in block.content
        assert "129:" not in block.content
        assert "133:" not in block.content
        assert state.served == 1
        assert state.total_result_bytes == record["result_bytes"]

    def test_span_at_cap_serves_one_above_refuses(self, tmp_path):
        # Revert probe in both directions: the rail is live.
        _write_repo(tmp_path)
        at_cap = _one(
            _state(tmp_path), _span("vuln.c", 1, READ_SPAN_MAX_LINES),
        )
        assert at_cap["status"] == "served"
        over = _one(
            _state(tmp_path), _span("vuln.c", 1, READ_SPAN_MAX_LINES + 1),
        )
        assert over["reason"] == "span_too_large"

    def test_full_width_full_height_span_is_not_truncated(self, tmp_path):
        # Pins the TOOL_RESULT_MAX_BYTES derivation: the largest
        # legitimate span (max lines, max rendered width, numbered)
        # fits under the per-call byte cap without tripping the
        # defensive truncation.
        repo = tmp_path / "wide"
        repo.mkdir()
        wide = "w" * RENDERED_LINE_WIDTH
        (repo / "wide.c").write_text(
            "\n".join([wide] * READ_SPAN_MAX_LINES) + "\n",
        )
        state = _state(repo)
        block, records = run_turn_requests(
            [_span("wide.c", 1, READ_SPAN_MAX_LINES)], state,
        )
        assert records[0]["status"] == "served"
        assert "[truncated]" not in block.content
        assert records[0]["result_bytes"] <= TOOL_RESULT_MAX_BYTES

    def test_overlong_lines_are_width_clipped(self, tmp_path):
        repo = tmp_path / "long"
        repo.mkdir()
        (repo / "min.c").write_text("x" * 5000 + "\n")
        block, records = run_turn_requests(
            [_span("min.c", 1, 1)], _state(repo),
        )
        assert records[0]["status"] == "served"
        line = block.content.splitlines()[-1]
        assert line.startswith("1: ")
        assert len(line) <= len("1: ") + RENDERED_LINE_WIDTH
        assert line.endswith("...")

    def test_beyond_eof_is_refused(self, tmp_path):
        _write_repo(tmp_path)
        record = _one(
            _state(tmp_path), _span("vuln.c", _N_LINES + 10, _N_LINES + 12),
        )
        assert record["reason"] == "beyond_eof"

    def test_span_past_eof_serves_existing_lines(self, tmp_path):
        # start within the file, end past it: serve what exists.
        _write_repo(tmp_path)
        block, records = run_turn_requests(
            [_span("vuln.c", _N_LINES - 1, _N_LINES + 50)], _state(tmp_path),
        )
        assert records[0]["status"] == "served"
        assert f"{_N_LINES}: int marker_line_{_N_LINES:04d};" \
            in block.content

    def test_duplicate_span_is_refused(self, tmp_path):
        _write_repo(tmp_path)
        state = _state(tmp_path)
        first = _one(state, _span("vuln.c", 1, 5))
        second = _one(state, _span("vuln.c", 1, 5))
        assert first["status"] == "served"
        assert second["reason"] == "duplicate_request"
        # A different span of the same file is fine.
        third = _one(state, _span("vuln.c", 6, 10))
        assert third["status"] == "served"

    def test_file_split_cached_one_disk_read_per_file(self, tmp_path):
        _write_repo(tmp_path)
        state = _state(tmp_path)
        real = toolloop.read_bytes_capped
        calls: list[Path] = []

        def _counting(path, max_bytes):
            calls.append(path)
            return real(path, max_bytes)

        with patch.object(toolloop, "read_bytes_capped", _counting):
            for start in (1, 50, 100):
                record = _one(state, _span("vuln.c", start, start + 4))
                assert record["status"] == "served"
        assert len(calls) == 1

    def test_unreadable_file_is_counted(self, tmp_path):
        _write_repo(tmp_path)
        with patch.object(toolloop, "read_bytes_capped", return_value=None):
            record = _one(_state(tmp_path), _span("vuln.c", 1, 2))
        assert record["reason"] == "file_unreadable"


class TestByteBudget:
    def test_at_threshold_refuses_one_below_serves(self, tmp_path):
        # Revert probe in both directions on the retained-bytes rail.
        _write_repo(tmp_path)
        state = _state(tmp_path)
        state.total_result_bytes = TOOLLOOP_MAX_TOTAL_BYTES - 1
        served = _one(state, _span("vuln.c", 1, 2))
        assert served["status"] == "served"
        assert state.total_result_bytes >= TOOLLOOP_MAX_TOTAL_BYTES
        refused = _one(state, _span("vuln.c", 10, 12))
        assert refused["reason"] == "byte_budget_exhausted"

    def test_budget_applies_to_call_graph_tools_too(self, tmp_path):
        _write_repo(tmp_path)
        state = _state(tmp_path)
        state.total_result_bytes = TOOLLOOP_MAX_TOTAL_BYTES
        record = _one(state, {
            "tool": "list_callers", "function": "target_fn",
            "file": "vuln.c",
        })
        assert record["reason"] == "byte_budget_exhausted"

    def test_oversize_result_is_truncated_with_marker(self, tmp_path):
        _write_repo(tmp_path)
        state = _state(tmp_path)
        with patch.object(toolloop, "TOOL_RESULT_MAX_BYTES", 64):
            block, records = run_turn_requests(
                [_span("vuln.c", 1, 10)], state,
            )
        assert records[0]["status"] == "served"
        assert records[0]["result_bytes"] <= 64 + len("... [truncated]")
        assert "... [truncated]" in block.content
        assert state.total_result_bytes == records[0]["result_bytes"]


class TestPerTurnCap:
    def test_over_cap_requests_collapse_to_one_counted_refusal(
        self, tmp_path,
    ):
        _write_repo(tmp_path)
        state = _state(tmp_path)
        requests = [
            _span("vuln.c", 10 * i + 1, 10 * i + 3)
            for i in range(MAX_REQUESTS_PER_TURN + 2)
        ]
        block, records = run_turn_requests(requests, state)
        assert len(records) == MAX_REQUESTS_PER_TURN + 1
        assert all(
            r["status"] == "served" for r in records[:MAX_REQUESTS_PER_TURN]
        )
        tail = records[-1]
        assert tail["reason"] == "requests_per_turn_cap"
        assert tail["count"] == 2
        assert state.served == MAX_REQUESTS_PER_TURN
        assert state.refused == 2
        assert "additional request(s) refused" in block.content

    def test_at_cap_all_served_no_refusal(self, tmp_path):
        # Revert probe: exactly at the cap nothing is refused.
        _write_repo(tmp_path)
        state = _state(tmp_path)
        requests = [
            _span("vuln.c", 10 * i + 1, 10 * i + 3)
            for i in range(MAX_REQUESTS_PER_TURN)
        ]
        _block, records = run_turn_requests(requests, state)
        assert len(records) == MAX_REQUESTS_PER_TURN
        assert state.refused == 0


class TestCallGraphTools:
    def _repo(self, tmp_path: Path) -> tuple[Path, dict]:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "vuln.c").write_text(
            "void entry(void) { target_fn(s); }\n"
            "void target_fn(char *s) { helper_0(s); }\n",
        )
        (repo / "callee.c").write_text(
            "int helper_0(char *s) { return strlen(s); }\n",
        )
        context_map = {
            "call_edges": [
                {
                    "caller": "entry", "caller_file": "vuln.c",
                    "callee": "target_fn", "callee_file": "vuln.c",
                },
                {
                    "caller": "target_fn", "caller_file": "vuln.c",
                    "callee": "helper_0", "callee_file": "callee.c",
                },
            ],
        }
        return repo, context_map

    def test_list_callers_serves_call_sites(self, tmp_path):
        repo, context_map = self._repo(tmp_path)
        state = _state(repo, context_map=context_map, finding_file="vuln.c")
        block, records = run_turn_requests(
            [{"tool": "list_callers", "function": "target_fn"}], state,
        )
        assert records[0]["status"] == "served"
        assert records[0]["target"] == "target_fn"
        assert "Known callers of target_fn" in block.content
        assert "entry" in block.content

    def test_list_callees_serves_bodies(self, tmp_path):
        repo, context_map = self._repo(tmp_path)
        state = _state(repo, context_map=context_map, finding_file="vuln.c")
        block, records = run_turn_requests(
            [{"tool": "list_callees", "function": "target_fn"}], state,
        )
        assert records[0]["status"] == "served"
        assert "helper_0" in block.content

    def test_explicit_file_arg_overrides_finding_file(self, tmp_path):
        repo, context_map = self._repo(tmp_path)
        state = _state(repo, context_map=context_map, finding_file="other.c")
        block, records = run_turn_requests(
            [{
                "tool": "list_callers", "function": "target_fn",
                "file": "vuln.c",
            }], state,
        )
        assert records[0]["status"] == "served"
        assert "entry" in block.content

    def test_no_callers_serves_explicit_empty_note(self, tmp_path):
        repo, context_map = self._repo(tmp_path)
        state = _state(repo, context_map=context_map, finding_file="vuln.c")
        block, records = run_turn_requests(
            [{"tool": "list_callers", "function": "entry"}], state,
        )
        assert records[0]["status"] == "served"
        assert "(no callers found for entry)" in block.content

    def test_duplicate_call_graph_request_is_refused(self, tmp_path):
        repo, context_map = self._repo(tmp_path)
        state = _state(repo, context_map=context_map, finding_file="vuln.c")
        req = {"tool": "list_callers", "function": "target_fn"}
        assert _one(state, dict(req))["status"] == "served"
        assert _one(state, dict(req))["reason"] == "duplicate_request"

    def test_seam_failure_is_counted_never_raised(self, tmp_path):
        repo, context_map = self._repo(tmp_path)
        state = _state(repo, context_map=context_map, finding_file="vuln.c")
        with patch(
            "packages.llm_analysis.flow_context_inject."
            "caller_call_sites_block",
            side_effect=RuntimeError("seam down"),
        ):
            record = _one(state, {
                "tool": "list_callers", "function": "target_fn",
            })
        assert record["reason"] == "seam_error"
        assert state.refused == 1


class TestRecordBounds:
    def _verdict(self, confidence: str) -> dict:
        return {
            "is_true_positive": True,
            "is_exploitable": False,
            "exploitability_score": 0.2,
            "confidence": confidence,
        }

    def test_record_shape_and_verdict_summaries(self):
        turns = [{
            "turn": 1,
            "requests": [{"tool": "read_span", "status": "served",
                          "target": "vuln.c:1-5", "result_bytes": 100}],
        }]
        record = build_toolloop_record(
            reason="low_confidence",
            first=self._verdict("low"),
            final=self._verdict("high"),
            replaced=True,
            turns=turns,
            end_reason="verdict",
            total_result_bytes=100,
            window_lines=READ_SPAN_MAX_LINES,
            caller_context_attached=True,
            callee_context_attached=False,
        )
        assert record["triggered"] is True
        assert record["end_reason"] == "verdict"
        assert record["first_verdict"]["confidence"] == "low"
        assert record["final_verdict"]["confidence"] == "high"
        assert record["turns"][0]["requests"][0]["target"] == "vuln.c:1-5"
        # Bounded summaries only — never full analysis dicts.
        assert "reasoning" not in str(record)

    def test_record_clamps_turn_and_request_lists(self):
        req = {"tool": "read_span", "status": "served",
               "target": "vuln.c:1-5", "result_bytes": 1}
        turns = [
            {"turn": i + 1, "requests": [dict(req)] * 50}
            for i in range(MAX_TOOLLOOP_TURNS + 5)
        ]
        record = build_toolloop_record(
            reason="verdict_abstained",
            first={}, final=self._verdict("high"), replaced=True,
            turns=turns, end_reason="turn_cap", total_result_bytes=1,
            window_lines=READ_SPAN_MAX_LINES,
            caller_context_attached=False, callee_context_attached=False,
        )
        assert len(record["turns"]) == MAX_TOOLLOOP_TURNS
        assert all(
            len(t["requests"]) <= MAX_REQUESTS_PER_TURN + 1
            for t in record["turns"]
        )


class TestConstantsDerived:
    def test_span_cap_derives_from_expanded_window(self):
        from packages.llm_analysis.context_expansion import (
            EXPANDED_FINDING_CONTEXT_LINES,
        )
        assert READ_SPAN_MAX_LINES == EXPANDED_FINDING_CONTEXT_LINES

    def test_byte_caps_derive_from_span_geometry(self):
        assert TOOL_RESULT_MAX_BYTES == READ_SPAN_MAX_LINES * (
            RENDERED_LINE_WIDTH + toolloop._LINE_RENDER_OVERHEAD
        )
        assert TOOLLOOP_MAX_TOTAL_BYTES == 4 * TOOL_RESULT_MAX_BYTES


class TestHostileBytesAtPromptEgress:
    def test_span_content_is_escaped_in_the_bundle(self, tmp_path):
        # Tool results are raw target text; they must pass the
        # existing envelope chokepoint like every other untrusted
        # block — raw ESC / BEL / C1 / bidi bytes never reach the
        # prompt.
        from packages.llm_analysis.prompts import (
            build_analysis_prompt_bundle,
        )
        repo = tmp_path / "repo"
        repo.mkdir()
        hostile = "\x1b]0;pwned\x07 ‮evil‬ \x9b31m"
        (repo / "vuln.c").write_text(
            f"int x; /* {hostile} */\nint y;\n",
        )
        state = _state(repo)
        block, records = run_turn_requests(
            [_span("vuln.c", 1, 2)], state,
        )
        assert records[0]["status"] == "served"
        assert "\x1b" in block.content  # raw at the block layer
        assert block.kind == "toolloop-results"
        assert block.origin == "classifier-tool-loop"

        bundle = build_analysis_prompt_bundle(
            rule_id="cpp/unbounded-write",
            level="error",
            file_path="vuln.c",
            start_line=1,
            end_line=1,
            message="probe",
            code="int x;",
            surrounding_context="int x;",
            extra_blocks=(block,),
        )
        user = next(m.content for m in bundle.messages if m.role == "user")
        for raw in ("\x1b", "\x07", "\x9b", "‮", "‬"):
            assert raw not in user
        assert "\\x1b" in user

    def test_refusal_notes_carry_no_model_bytes(self, tmp_path):
        # Refusal lines are operator-authored constants: a hostile
        # tool name / path never rides the results block.
        _write_repo(tmp_path)
        hostile = "evil\x1b]0;pwned\x07"
        block, records = run_turn_requests(
            [
                {"tool": hostile, "file": "vuln.c", "start": 1, "end": 1},
                _span("vuln.c", 1, 1),
            ],
            _state(tmp_path),
        )
        assert records[0]["reason"] == "unknown_tool"
        assert hostile not in block.content
        assert "\x07" not in block.content.replace(
            block.content.splitlines()[-1], "",
        )
