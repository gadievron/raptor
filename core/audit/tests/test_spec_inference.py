"""Tests for core.audit.spec_inference."""

from __future__ import annotations

from core.audit.spec_inference import (
    InferredSpec,
    SpecSource,
    _checks_return_value,
    _extract_base_name,
    _is_peer,
    find_peer_functions,
    format_spec_for_context,
    infer_spec_mechanical,
    should_infer_with_llm,
)


class TestInferSpecMechanical:
    def test_name_intent_validate(self):
        gap = {"name": "validate_token", "file": "auth.c"}
        spec = infer_spec_mechanical(gap)
        assert "validates" in spec.intent
        assert "token" in spec.intent
        assert any(s.signal == "function_name" for s in spec.sources)

    def test_name_intent_free(self):
        gap = {"name": "free_buffer", "file": "mem.c"}
        spec = infer_spec_mechanical(gap)
        assert "releases" in spec.intent or "frees" in spec.intent

    def test_name_intent_sanitize(self):
        gap = {"name": "sanitize_input", "file": "web.c"}
        spec = infer_spec_mechanical(gap)
        assert "sanitizes" in spec.intent

    def test_param_preconditions_user_ptr(self):
        gap = {
            "name": "do_read",
            "file": "fs.c",
            "signature": "ssize_t do_read(char __user *buf, size_t len)",
        }
        spec = infer_spec_mechanical(gap)
        assert any("user-space" in p for p in spec.preconditions)

    def test_param_preconditions_size_len(self):
        gap = {
            "name": "read_data",
            "file": "io.c",
            "signature": "int read_data(void *buf, size_t len)",
        }
        spec = infer_spec_mechanical(gap)
        assert any("bounds" in p.lower() or "buffer" in p.lower()
                    for p in spec.preconditions)

    def test_attributes_must_check(self):
        gap = {
            "name": "get_ctx",
            "file": "core.c",
            "attributes": ["__must_check"],
        }
        spec = infer_spec_mechanical(gap)
        assert any("return value must be checked" in inv for inv in spec.invariants)

    def test_attributes_login_required(self):
        gap = {
            "name": "admin_panel",
            "file": "views.py",
            "attributes": ["@login_required"],
        }
        spec = infer_spec_mechanical(gap)
        assert any("authenticated" in inv for inv in spec.invariants)

    def test_docstring_extraction(self):
        gap = {
            "name": "parse_input",
            "file": "parser.c",
            "docstring": "Parse user input and validate it.\n\nRaises ValueError on malformed input.\nReturns the parsed structure.",
        }
        spec = infer_spec_mechanical(gap)
        assert spec.intent
        assert len(spec.postconditions) >= 1

    def test_docstring_from_source(self):
        gap = {
            "name": "compute",
            "file": "math.py",
            "source": '    def compute(x):\n        """Computes the result of x.\n\n        Returns int always.\n        Raises OverflowError if too large.\n        """\n        pass',
        }
        spec = infer_spec_mechanical(gap)
        assert len(spec.postconditions) >= 1

    def test_negative_spec_password(self):
        gap = {
            "name": "verify_password",
            "file": "auth.c",
            "source": "int verify_password(const char *password, const char *hash) {",
        }
        spec = infer_spec_mechanical(gap)
        assert any("password" in ns for ns in spec.negative_specs)

    def test_negative_spec_token(self):
        gap = {
            "name": "check_api_token",
            "file": "api.py",
            "source": "def check_api_token(token): ...",
        }
        spec = infer_spec_mechanical(gap)
        assert any("token" in ns for ns in spec.negative_specs)

    def test_tests_inject_postconditions(self):
        from core.analysis.test_discovery import TestCase
        tests = {
            "validate_email": [
                TestCase(
                    test_file="test_email.py",
                    test_function="test_validate_email",
                    target_function="validate_email",
                    assertions=["assert validate_email('a@b') is True"],
                ),
            ],
        }
        gap = {"name": "validate_email", "file": "email.py"}
        spec = infer_spec_mechanical(gap, tests=tests)
        assert any("[test]" in p for p in spec.postconditions)
        assert any(s.signal == "test_assertions" for s in spec.sources)

    def test_caller_return_check_rate(self):
        checklist = {
            "items": [
                {
                    "name": "caller1", "file": "a.c",
                    "callees": [{"name": "alloc_buf", "file": "buf.c"}],
                    "source": "ret = alloc_buf(sz);\nif (ret == NULL)",
                },
                {
                    "name": "caller2", "file": "b.c",
                    "callees": [{"name": "alloc_buf", "file": "buf.c"}],
                    "source": "ret = alloc_buf(sz);\nif (!ret)",
                },
                {
                    "name": "caller3", "file": "c.c",
                    "callees": [{"name": "alloc_buf", "file": "buf.c"}],
                    "source": "ret = alloc_buf(sz);\nif (ret < 0)",
                },
            ],
        }
        gap = {"name": "alloc_buf", "file": "buf.c"}
        spec = infer_spec_mechanical(gap, checklist=checklist)
        assert any("return value must be checked" in inv for inv in spec.invariants)

    def test_no_name_match(self):
        gap = {"name": "x", "file": "a.c"}
        spec = infer_spec_mechanical(gap)
        assert spec.intent == ""

    def test_empty_gap(self):
        spec = infer_spec_mechanical({})
        assert spec.function == ""
        assert spec.preconditions == []


class TestShouldInferWithLlm:
    def test_deep_dive(self):
        assert should_infer_with_llm({}, "deep_dive") is True

    def test_entry_point(self):
        assert should_infer_with_llm({}, "investigate", is_entry_point=True) is True

    def test_sink(self):
        assert should_infer_with_llm({}, "investigate", is_sink=True) is True

    def test_auth_strategy(self):
        assert should_infer_with_llm({"strategy": "auth"}, "investigate") is True

    def test_glance_no_flags(self):
        assert should_infer_with_llm({}, "glance") is False

    def test_skip_no_flags(self):
        assert should_infer_with_llm({}, "skip") is False


class TestFormatSpecForContext:
    def test_full_spec(self):
        spec = InferredSpec(
            function="validate_jwt",
            file="auth.c",
            intent="validates JWT and returns claims",
            preconditions=["token must be non-NULL"],
            postconditions=["returns valid Claims or raises"],
            invariants=["constant-time comparison"],
            negative_specs=["must NOT log the raw token"],
            sources=[
                SpecSource("function_name", "high", "validates pattern"),
                SpecSource("test_assertions", "high", "2 tests"),
            ],
        )
        text = format_spec_for_context(spec)
        assert "validates JWT" in text
        assert "non-NULL" in text
        assert "Claims" in text
        assert "constant-time" in text
        assert "must NOT" in text
        assert "deviation IS the bug" in text
        assert "function_name [high]" in text

    def test_empty_spec(self):
        spec = InferredSpec(function="x", file="a.c")
        assert format_spec_for_context(spec) == ""

    def test_intent_only(self):
        spec = InferredSpec(function="x", file="a.c", intent="does something")
        text = format_spec_for_context(spec)
        assert "does something" in text


class TestChecksReturnValue:
    def test_if_check(self):
        source = "if (!validate_token(tok)) { return -1; }"
        assert _checks_return_value(source, "validate_token") is True

    def test_ret_assignment(self):
        source = "ret = validate_token(tok);\nif (ret < 0) return;"
        assert _checks_return_value(source, "validate_token") is True

    def test_no_check(self):
        source = "validate_token(tok);\ndo_stuff();"
        assert _checks_return_value(source, "validate_token") is False

    def test_empty_source(self):
        assert _checks_return_value("", "fn") is False


class TestExtractBaseName:
    def test_strips_version_suffix(self):
        assert _extract_base_name("parse_v2") == "parse"
        assert _extract_base_name("handle_request_v1") == "handle_request"

    def test_strips_variant_suffix(self):
        assert _extract_base_name("parse_new") == "parse"
        assert _extract_base_name("validate_safe") == "validate"

    def test_strips_trailing_digits(self):
        assert _extract_base_name("handler3") == "handler"

    def test_leaves_short_names_alone(self):
        assert _extract_base_name("fn") == "fn"


class TestIsPeer:
    def test_versioned_pair(self):
        assert _is_peer("parse", "parse_v1", "parse_v2") is True

    def test_common_prefix(self):
        assert _is_peer("validate", "validate_email", "validate_phone") is True

    def test_unrelated(self):
        assert _is_peer("parse", "parse_v1", "handle_request") is False

    def test_same_function(self):
        assert _is_peer("parse", "parse_v1", "parse_v1") is False


class TestFindPeerFunctions:
    def test_finds_versioned_peers(self):
        checklist = {"files": [{
            "path": "src/auth.c",
            "items": [
                {"name": "validate_token_v1", "line_start": 10},
                {"name": "validate_token_v2", "line_start": 50},
                {"name": "unrelated_func", "line_start": 100},
            ],
        }]}
        peers = find_peer_functions("validate_token_v1", checklist)
        assert len(peers) == 1
        assert peers[0]["name"] == "validate_token_v2"

    def test_empty_on_no_match(self):
        checklist = {"files": [{
            "path": "src/x.c",
            "items": [{"name": "completely_different", "line_start": 1}],
        }]}
        peers = find_peer_functions("parse_input", checklist)
        assert peers == []

    def test_limits_to_five(self):
        items = [{"name": f"handle_v{i}", "line_start": i * 10} for i in range(10)]
        checklist = {"files": [{"path": "x.c", "items": items}]}
        peers = find_peer_functions("handle_v0", checklist)
        assert len(peers) <= 5
