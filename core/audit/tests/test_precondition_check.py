"""Tests for the precondition mechanical verifier."""

from __future__ import annotations

import pytest

from core.audit.precondition_check import (
    CheckResult,
    PreconditionVerdict,
    verify_preconditions,
    _extract_c_function,
    _check_null_termination,
    _check_bounds,
    _check_sanitization,
    _check_attacker_control,
    _check_reaches_sink,
)


# ── Fixtures ────────────────────────────────────────────────────────

REQPARSE_C = """\
#include <string.h>
#include <stdio.h>

#define MAX_METHOD_LEN 16

int is_valid_method(const char *method) {
    if (strcmp(method, "GET") == 0) return 1;
    if (strcmp(method, "POST") == 0) return 1;
    return 0;
}

int parse_request(const char *raw, struct request *req) {
    size_t method_len = strcspn(raw, " ");
    if (method_len >= MAX_METHOD_LEN) return -1;
    memcpy(req->method, raw, method_len);
    req->method[method_len] = '\\0';
    if (!is_valid_method(req->method)) return -1;

    const char *path_start = raw + method_len + 1;
    size_t path_len = strcspn(path_start, " ");
    memcpy(req->path, path_start, path_len);
    req->path[path_len] = '\\0';

    return 0;
}

void handle_connection(int fd) {
    char buf[4096];
    int n = read(fd, buf, sizeof(buf));
    struct request req;
    parse_request(buf, &req);
}
"""


@pytest.fixture
def target_dir(tmp_path):
    """Create a target directory with reqparse.c."""
    (tmp_path / "reqparse.c").write_text(REQPARSE_C)
    return tmp_path


# ── Unit tests for check functions ──────────────────────────────────

class TestCheckNullTermination:
    """Bare call tokens (strncpy/strdup anywhere in the function) are weak
    whole-function evidence and cap at 'inconclusive' under expect_absent,
    matching _check_bounds/_check_sanitization. Only an explicit terminator
    store — parameter-bound when a parameter is named — contradicts."""

    def test_finds_explicit_null_termination(self):
        source = "req->method[method_len] = '\\0';\nreq->path[path_len] = '\\0';"
        result = _check_null_termination(source, "f.c", "fn", "", expect_absent=True)
        assert result.verdict == "contradicted"

    def test_no_null_termination(self):
        source = "memcpy(buf, src, len);\nreturn buf;"
        result = _check_null_termination(source, "f.c", "fn", "", expect_absent=True)
        assert result.verdict == "supported"

    def test_bare_strncpy_is_inconclusive(self):
        source = "strncpy(dst, src, n);"
        result = _check_null_termination(
            source, "f.c", "fn", "", expect_absent=True,
        )
        assert result.verdict == "inconclusive"
        assert "cannot confirm" in result.evidence

    def test_bare_strdup_is_inconclusive(self):
        source = "char *copy = strdup(input);"
        result = _check_null_termination(
            source, "f.c", "fn", "", expect_absent=True,
        )
        assert result.verdict == "inconclusive"

    def test_bare_snprintf_is_inconclusive(self):
        source = "snprintf(tmp, sizeof(tmp), \"%d\", x);"
        result = _check_null_termination(
            source, "f.c", "fn", "", expect_absent=True,
        )
        assert result.verdict == "inconclusive"

    def test_token_with_parameter_named_is_inconclusive(self):
        # strncpy present, parameter named but never explicitly
        # terminated — the token alone must not contradict.
        source = "strncpy(other, src, n);"
        result = _check_null_termination(
            source, "f.c", "fn", "buf", expect_absent=True,
        )
        assert result.verdict == "inconclusive"

    def test_param_bound_store_contradicts(self):
        source = "memcpy(buf, src, n);\nbuf[n] = '\\0';"
        result = _check_null_termination(
            source, "f.c", "fn", "buf", expect_absent=True,
        )
        assert result.verdict == "contradicted"
        assert "buf" in result.evidence

    def test_store_on_other_buffer_does_not_bind_parameter(self):
        source = "scratch[i] = '\\0';"
        result = _check_null_termination(
            source, "f.c", "fn", "buf", expect_absent=True,
        )
        assert result.verdict == "inconclusive"

    def test_unqualified_claim_store_contradicts(self):
        # No parameter named: an explicit terminator store directly
        # contradicts a generic "does not null-terminate" claim.
        source = "out[len] = '\\0';"
        result = _check_null_termination(
            source, "f.c", "fn", "", expect_absent=True,
        )
        assert result.verdict == "contradicted"

    def test_expect_present_and_found(self):
        source = "buf[len] = '\\0';"
        result = _check_null_termination(source, "f.c", "fn", "", expect_absent=False)
        assert result.verdict == "supported"

    def test_expect_present_token_still_supports(self):
        source = "strncpy(dst, src, n);"
        result = _check_null_termination(
            source, "f.c", "fn", "", expect_absent=False,
        )
        assert result.verdict == "supported"

    def test_expect_present_nothing_found_inconclusive(self):
        source = "memcpy(buf, src, len);"
        result = _check_null_termination(
            source, "f.c", "fn", "", expect_absent=False,
        )
        assert result.verdict == "inconclusive"


class TestCheckBounds:
    def test_finds_length_check_inconclusive(self):
        source = "if (method_len >= MAX_METHOD_LEN) return -1;"
        result = _check_bounds(source, "f.c", "fn", "", expect_absent=True)
        assert result.verdict == "inconclusive"

    def test_no_bounds(self):
        source = "char *p = src; return p;"
        result = _check_bounds(source, "f.c", "fn", "", expect_absent=True)
        assert result.verdict == "supported"


class TestCheckSanitization:
    def test_finds_validation_call_inconclusive(self):
        source = "if (!is_valid_method(req->method)) return -1;"
        result = _check_sanitization(source, "f.c", "fn", "", expect_absent=True)
        assert result.verdict == "inconclusive"

    def test_no_sanitization(self):
        source = "int x = a + b;\nreturn x;"
        result = _check_sanitization(source, "f.c", "fn", "", expect_absent=True)
        assert result.verdict == "supported"


class TestCheckAttackerControl:
    def test_function_is_entry_point(self):
        ctx = {"entry_points": ["handle_connection"], "call_edges": []}
        result = _check_attacker_control(
            "", "f.c", "handle_connection", "", expect_absent=False, context_map=ctx,
        )
        assert result.verdict == "supported"

    def test_function_not_reachable(self):
        ctx = {"entry_points": ["main"], "call_edges": []}
        result = _check_attacker_control(
            "", "f.c", "helper", "", expect_absent=False, context_map=ctx,
        )
        assert result.verdict == "contradicted"

    def test_no_context_map(self):
        result = _check_attacker_control("", "f.c", "fn", "", True, None)
        assert result.verdict == "inconclusive"

    def test_no_entry_points_is_inconclusive(self):
        ctx = {"entry_points": [], "call_edges": [
            {"caller": "main", "callee": "helper"},
        ]}
        result = _check_attacker_control(
            "", "f.c", "helper", "", expect_absent=False, context_map=ctx,
        )
        assert result.verdict == "inconclusive"


class TestCheckReachesSink:
    def test_finds_strcpy(self):
        source = "strcpy(dst, src);"
        result = _check_reaches_sink(source, "f.c", "fn", "", expect_absent=False)
        assert result.verdict == "supported"

    def test_no_sinks_inconclusive(self):
        source = "int x = 1;\nreturn x;"
        result = _check_reaches_sink(source, "f.c", "fn", "", expect_absent=False)
        assert result.verdict == "inconclusive"


# ── Integration: verify_preconditions with real files ───────────────

class TestVerifyPreconditions:
    def test_contradicts_false_assumption(self, target_dir):
        """The model claims parse_request does NOT null-terminate method.
        The code clearly does (line: req->method[method_len] = '\\0').
        The verifier should contradict this."""
        preconditions = [{
            "assumption": "parse_request does not null-terminate method",
            "check_type": "caller_null_terminates",
            "location": {"file": "reqparse.c", "function": "parse_request"},
            "expect_absent": True,
            "parameter": "method",
        }]
        verdict = verify_preconditions(preconditions, target_dir)
        assert verdict.any_contradicted
        assert "null-terminate" in verdict.contradiction_summary.lower()

    def test_supports_true_assumption(self, target_dir):
        """The model claims handle_connection does NOT sanitize input.
        handle_connection just reads and passes buf — no sanitization.
        The verifier should support this."""
        preconditions = [{
            "assumption": "handle_connection does not sanitize the raw input",
            "check_type": "caller_sanitizes",
            "location": {"file": "reqparse.c", "function": "handle_connection"},
            "expect_absent": True,
        }]
        verdict = verify_preconditions(preconditions, target_dir)
        assert not verdict.any_contradicted

    def test_inconclusive_on_missing_file(self, target_dir):
        preconditions = [{
            "assumption": "no bounds check",
            "check_type": "caller_bounds_checks",
            "location": {"file": "nonexistent.c", "function": "foo"},
            "expect_absent": True,
        }]
        verdict = verify_preconditions(preconditions, target_dir)
        assert not verdict.any_contradicted
        assert verdict.checks[0].verdict == "inconclusive"

    def test_inconclusive_on_missing_function(self, target_dir):
        preconditions = [{
            "assumption": "no bounds check",
            "check_type": "caller_bounds_checks",
            "location": {"file": "reqparse.c", "function": "nonexistent_fn"},
            "expect_absent": True,
        }]
        verdict = verify_preconditions(preconditions, target_dir)
        assert not verdict.any_contradicted
        assert verdict.checks[0].verdict == "inconclusive"

    def test_multiple_preconditions_one_contradicted(self, target_dir):
        """If any precondition is contradicted, any_contradicted is True."""
        preconditions = [
            {
                "assumption": "handle_connection does not sanitize",
                "check_type": "caller_sanitizes",
                "location": {"file": "reqparse.c", "function": "handle_connection"},
                "expect_absent": True,
            },
            {
                "assumption": "parse_request does not null-terminate",
                "check_type": "caller_null_terminates",
                "location": {"file": "reqparse.c", "function": "parse_request"},
                "expect_absent": True,
            },
        ]
        verdict = verify_preconditions(preconditions, target_dir)
        assert verdict.any_contradicted
        assert len(verdict.checks) == 2
        contradicted = [c for c in verdict.checks if c.verdict == "contradicted"]
        assert len(contradicted) == 1

    def test_empty_preconditions(self, target_dir):
        verdict = verify_preconditions([], target_dir)
        assert not verdict.any_contradicted
        assert len(verdict.checks) == 0


# ── C function extraction ───────────────────────────────────────────

class TestExtractCFunction:
    def test_extracts_simple_function(self):
        source = "int foo(int x) {\n    return x + 1;\n}\n"
        result = _extract_c_function(source, "foo")
        assert result is not None
        assert "return x + 1" in result

    def test_extracts_nested_braces(self):
        source = "void bar() {\n    if (1) {\n        x();\n    }\n}\n"
        result = _extract_c_function(source, "bar")
        assert result is not None
        assert result.endswith("}")

    def test_nonexistent_function(self):
        source = "void baz() { }"
        result = _extract_c_function(source, "nonexistent")
        assert result is None


# ── PreconditionVerdict ─────────────────────────────────────────────

class TestPreconditionVerdict:
    def test_no_checks_is_not_contradicted(self):
        v = PreconditionVerdict()
        assert not v.any_contradicted
        assert v.contradiction_summary == ""

    def test_all_supported_is_not_contradicted(self):
        v = PreconditionVerdict(checks=[
            CheckResult("test", "assumption", "supported"),
        ])
        assert not v.any_contradicted

    def test_one_contradicted(self):
        v = PreconditionVerdict(checks=[
            CheckResult("test", "assumption", "supported"),
            CheckResult("null_check", "no null term", "contradicted", "found \\0"),
        ])
        assert v.any_contradicted
        assert "null_check" in v.contradiction_summary
