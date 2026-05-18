"""Tests for the ``ast_view`` integration in
``packages.llm_analysis.prompts.analysis``.

Covers the renderer (``_render_ast_view_block``) and the bundle
threading (``build_analysis_prompt_bundle_from_finding`` lifting
``finding["ast_view"]`` into an untrusted-block in the user message).

The agent-side enrichment (``packages/llm_analysis/agent.py`` walking
findings and computing ``view()``) is exercised separately by
``test_agent_ast_view_enrichment``.
"""

from __future__ import annotations

from packages.llm_analysis.prompts.analysis import (
    _render_ast_view_block,
    build_analysis_prompt_bundle,
    build_analysis_prompt_bundle_from_finding,
)


def _av(**overrides):
    """Helper: build a default ast_view dict matching
    ``FunctionView.to_dict()`` shape, with field overrides."""
    base = {
        "function": "handle_query",
        "file": "src/routes.py",
        "language": "python",
        "lines": [34, 58],
        "signature": "handle_query(req: Request) -> Response",
        "calls_made": [
            {"line": 36, "chain": ["validate"], "caller": "handle_query", "receiver_class": None},
            {"line": 40, "chain": ["execute_query"], "caller": "handle_query", "receiver_class": None},
            {"line": 50, "chain": ["render_template"], "caller": "handle_query", "receiver_class": None},
        ],
        "returns": [
            {"line": 47, "value_text": "Response(400)"},
            {"line": 57, "value_text": "response"},
        ],
        "has_inline_asm": False,
        "schema_version": 1,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Renderer
# ---------------------------------------------------------------------------


class TestRenderer:
    def test_renders_signature_calls_returns_asm(self):
        text = _render_ast_view_block(_av())
        assert "handle_query(req: Request) -> Response" in text
        assert "src/routes.py:34-58" in text
        assert "inline asm: no" in text
        assert "validate" in text
        assert "execute_query" in text
        assert "render_template" in text
        # Two returns surfaced with lines.
        assert "47" in text and "57" in text

    def test_dedup_calls_with_hit_count(self):
        # Same call name on multiple lines collapses to "name(xN)".
        av = _av(calls_made=[
            {"line": 36, "chain": ["execute"], "caller": "f", "receiver_class": None},
            {"line": 40, "chain": ["execute"], "caller": "f", "receiver_class": None},
            {"line": 50, "chain": ["execute"], "caller": "f", "receiver_class": None},
        ])
        text = _render_ast_view_block(av)
        assert "execute(x3)" in text, text

    def test_dotted_chains_for_method_calls(self):
        av = _av(calls_made=[
            {"line": 36, "chain": ["obj", "method"], "caller": "f", "receiver_class": None},
        ])
        text = _render_ast_view_block(av)
        assert "obj.method" in text

    def test_truncation_marker_on_large_call_list(self):
        # Many distinct callees → truncated with "..."
        many = [
            {"line": 10 + i, "chain": [f"f{i}"], "caller": "h", "receiver_class": None}
            for i in range(30)
        ]
        text = _render_ast_view_block(_av(calls_made=many))
        assert "..." in text
        # Counts are preserved even with truncation.
        assert "(30)" in text

    def test_asm_flag_surfaced(self):
        text = _render_ast_view_block(_av(has_inline_asm=True))
        assert "inline asm: yes" in text

    def test_empty_calls_renders_none_marker(self):
        text = _render_ast_view_block(_av(calls_made=[]))
        assert "calls inside body: (none)" in text

    def test_empty_returns_renders_none_marker(self):
        text = _render_ast_view_block(_av(returns=[]))
        assert "explicit returns: (none)" in text

    def test_signature_fallback_to_function_name(self):
        # Signature empty → fall back to bare function name in header.
        text = _render_ast_view_block(_av(signature=""))
        assert "host function: handle_query" in text

    def test_file_path_override_displaces_ast_view_file(self):
        """``file_path_override`` kwarg substitutes the display path
        for ``ast_view["file"]``. Used by the prompt builder so the
        rendered block body matches the block's ``origin`` (the
        finding's repo-relative path) rather than the absolute path
        ``core.ast.view`` resolved internally."""
        av = _av(file="/tmp/scan-tmpdir/src/routes.py")
        text = _render_ast_view_block(
            av, file_path_override="src/routes.py",
        )
        assert "src/routes.py:" in text
        assert "/tmp/scan-tmpdir" not in text

    def test_file_path_override_default_is_ast_view_file(self):
        """No override → use ``ast_view["file"]`` (backwards-compat
        for any caller that doesn't supply the override)."""
        av = _av(file="some/path.py")
        text = _render_ast_view_block(av)  # no override
        assert "some/path.py:" in text

    def test_compactness_under_100_tokens(self):
        # Rough proxy for token cost: lines and chars.
        text = _render_ast_view_block(_av())
        # 4 lines: header + asm + calls + returns
        assert text.count("\n") == 3
        # Under 400 chars for a typical function.
        assert len(text) < 400, len(text)


# ---------------------------------------------------------------------------
# Bundle threading
# ---------------------------------------------------------------------------


class TestBundleThreading:
    def test_finding_with_ast_view_emits_untrusted_block(self):
        finding = {
            "rule_id": "sql-injection",
            "file_path": "src/routes.py",
            "start_line": 36,
            "end_line": 36,
            "message": "potential SQLi",
            "ast_view": _av(),
        }
        bundle = build_analysis_prompt_bundle_from_finding(finding)
        user = bundle.messages[1].content  # [0]=system, [1]=user
        assert "ast-view" in user
        assert "handle_query" in user
        assert "validate" in user

    def test_finding_without_ast_view_omits_block(self):
        finding = {
            "rule_id": "sql-injection",
            "file_path": "src/routes.py",
            "start_line": 36,
            "end_line": 36,
            "message": "potential SQLi",
            # No ast_view field
        }
        bundle = build_analysis_prompt_bundle_from_finding(finding)
        user = bundle.messages[1].content
        assert "ast-view" not in user

    def test_finding_with_empty_ast_view_dict_still_emits(self):
        # Empty-ish dict (no signature, no calls, no returns, asm=False)
        # — the renderer falls back to bare function + (none) markers,
        # which is still informative ("we know the function exists").
        finding = {
            "rule_id": "sql-injection",
            "file_path": "src/routes.py",
            "start_line": 1,
            "ast_view": {
                "function": "f", "file": "x.py", "language": "python",
                "lines": [1, 1], "signature": "", "calls_made": [],
                "returns": [], "has_inline_asm": False, "schema_version": 1,
            },
        }
        bundle = build_analysis_prompt_bundle_from_finding(finding)
        user = bundle.messages[1].content
        assert "ast-view" in user
        assert "host function: f" in user

    def test_direct_bundle_call_with_ast_view_kwarg(self):
        # Direct ``build_analysis_prompt_bundle`` call (not the
        # finding wrapper) also accepts the kwarg.
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="src/x.py", start_line=1, end_line=1,
            message="test", ast_view=_av(),
        )
        user = bundle.messages[1].content
        assert "ast-view" in user

    def test_bundle_without_ast_view_kwarg_works(self):
        # Backwards-compat: omitting the kwarg works (default None).
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="src/x.py", start_line=1, end_line=1,
            message="test",
        )
        user = bundle.messages[1].content
        assert "ast-view" not in user

    def test_ast_view_block_envelope_origin_includes_function(self):
        # The untrusted-block envelope carries an origin field for
        # debug/audit; ours sets it to
        # ``<finding's file_path>:<function-from-ast_view>`` — file
        # comes from the finding (matches every other block's
        # origin convention), function comes from the ast_view
        # (machine-derived from the parser).
        finding = {
            "rule_id": "x", "file_path": "src/x.py", "start_line": 1,
            "ast_view": _av(),  # ast_view.function = "handle_query"
        }
        bundle = build_analysis_prompt_bundle_from_finding(finding)
        user = bundle.messages[1].content
        assert 'origin="src/x.py:handle_query"' in user


# ---------------------------------------------------------------------------
# Robustness — malformed ast_view dicts
# ---------------------------------------------------------------------------


class TestRobustness:
    def test_missing_function_field(self):
        text = _render_ast_view_block({"calls_made": [], "returns": []})
        assert text  # non-empty
        assert "host function:" in text

    def test_missing_lines_field(self):
        text = _render_ast_view_block({"function": "f", "calls_made": [], "returns": []})
        assert "0-0" in text

    def test_call_with_no_chain(self):
        # A CallSite with chain=[] (theoretically possible from a
        # buggy walker) renders as "?".
        av = _av(calls_made=[
            {"line": 10, "chain": [], "caller": "f", "receiver_class": None},
        ])
        text = _render_ast_view_block(av)
        assert "?" in text

    def test_return_without_line(self):
        av = _av(returns=[{"value_text": "x"}])
        text = _render_ast_view_block(av)
        # Doesn't crash; renders "?" for the missing line.
        assert "?" in text or "explicit returns: 1" in text

    def test_calls_made_not_a_list_silently_dropped(self):
        """Malformed input: ``calls_made`` is a string (e.g. via a
        corrupted JSON round-trip). The renderer must not crash —
        treat as empty list. Pinned because the iterator-over-string
        pattern is a common Python footgun."""
        text = _render_ast_view_block({
            "function": "f", "lines": [1, 1], "signature": "",
            "calls_made": "not_a_list", "returns": [],
            "has_inline_asm": False,
        })
        assert "calls inside body: (none)" in text

    def test_returns_not_a_list_silently_dropped(self):
        text = _render_ast_view_block({
            "function": "f", "lines": [1, 1], "signature": "",
            "calls_made": [], "returns": "not_a_list",
            "has_inline_asm": False,
        })
        assert "explicit returns: (none)" in text

    def test_non_dict_entries_in_calls_dropped(self):
        text = _render_ast_view_block({
            "function": "f", "lines": [1, 1], "signature": "",
            "calls_made": ["bare-string", None, 42, {"chain": ["valid"]}],
            "returns": [], "has_inline_asm": False,
        })
        # Only the dict entry survives.
        assert "calls inside body (1)" in text
        assert "valid" in text

    def test_chain_not_a_list_silently_treated_as_empty(self):
        text = _render_ast_view_block({
            "function": "f", "lines": [1, 1], "signature": "",
            "calls_made": [{"chain": "should_be_a_list"}],
            "returns": [], "has_inline_asm": False,
        })
        # Bad chain → "?" placeholder.
        assert "calls inside body (1)" in text
        assert "?" in text
