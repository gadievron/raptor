"""Tests for cross_function_verify.py — cross-function mechanical verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from core.audit.cross_function_verify import (
    _extract_callee_from_hypothesis,
    _extract_guard_from_hypothesis,
    _extract_leaked_field_from_hypothesis,
    _extract_sinks_from_hypothesis,
    _verify_caller_constraint,
    _verify_incomplete_cleanup,
    _verify_taint_source_sink,
    _verify_taint_to_arithmetic,
    _verify_unchecked_return,
    cross_function_verify,
)


# ── Mock Joern server ───────────────────────────────────────────────


@dataclass
class MockJoernResult:
    ok: bool = True
    raw_output: str = ""


class MockJoernServer:
    """Programmable mock that returns canned results for specific query patterns.

    Patterns are matched in order; the LAST matching pattern wins,
    allowing more specific patterns to override earlier broader ones.
    """

    def __init__(self):
        self._responses: List[tuple[str, MockJoernResult]] = []

    def add_response(self, pattern: str, raw_output: str, ok: bool = True):
        self._responses.append((pattern, MockJoernResult(ok=ok, raw_output=raw_output)))

    def query(self, cpgql: str, **kwargs) -> MockJoernResult:
        match = None
        for pattern, result in self._responses:
            if pattern in cpgql:
                match = result
        return match or MockJoernResult(ok=True, raw_output="List()")


# ── Hypothesis extraction tests ──────────────────────────────────────


class TestExtractCalleeFromHypothesis:
    def test_ignores_return_value(self):
        h = "Ignoring the return value of `inc_rlimit_ucounts` enables a TOCTOU race"
        assert _extract_callee_from_hypothesis(h) == "inc_rlimit_ucounts"

    def test_failure_of(self):
        h = "the failure of `validate_input` is silently discarded"
        assert _extract_callee_from_hypothesis(h) == "validate_input"

    def test_return_value_of(self):
        h = "the return value of `check_auth` is not checked"
        assert _extract_callee_from_hypothesis(h) == "check_auth"

    def test_no_callee(self):
        h = "a buffer overflow occurs when memcpy is called"
        assert _extract_callee_from_hypothesis(h) is None or isinstance(
            _extract_callee_from_hypothesis(h), str
        )


class TestExtractGuardFromHypothesis:
    def test_after_releasing(self):
        h = "accesses tty->link->count without holding the necessary lock after sleeping and releasing `termios_rwsem`"
        result = _extract_guard_from_hypothesis(h)
        assert result == "termios_rwsem"

    def test_callers_must_hold(self):
        h = "callers must call `skb_cow_data` before this function"
        assert _extract_guard_from_hypothesis(h) == "skb_cow_data"

    def test_no_guard(self):
        h = "a buffer overflow when copying user data"
        assert _extract_guard_from_hypothesis(h) is None


class TestExtractLeakedField:
    def test_explicit_list(self):
        h = "fails to clean up requests on the `fpq->io` list"
        assert _extract_leaked_field_from_hypothesis(h) == "io"

    def test_not_freed(self):
        h = "`pending` is not freed during teardown"
        assert _extract_leaked_field_from_hypothesis(h) == "pending"


class TestExtractSinks:
    def test_backtick_names(self):
        h = "interpolating `Host` header directly into `format` call"
        sinks = _extract_sinks_from_hypothesis(h)
        assert "Host" in sinks or "format" in sinks

    def test_keyword_sinks(self):
        h = "user input is concatenated into a query string"
        sinks = _extract_sinks_from_hypothesis(h)
        assert any("concat" in s.lower() for s in sinks)


# ── Verifier unit tests ─────────────────────────────────────────────


class TestUncheckedReturn:
    def test_confirmed(self):
        server = MockJoernServer()
        server.add_response(
            "filterNot",
            'List((42, "inc_rlimit_ucounts(current)"))',
        )
        result = _verify_unchecked_return(
            "commit_creds",
            "Ignoring the return value of `inc_rlimit_ucounts` enables a TOCTOU",
            server,
        )
        assert result is not None
        assert result.verified is True
        assert result.verifier_name == "unchecked_return"
        assert "inc_rlimit_ucounts" in result.evidence

    def test_refuted(self):
        server = MockJoernServer()
        server.add_response("filterNot", "List()")
        result = _verify_unchecked_return(
            "commit_creds",
            "Ignoring the return value of `inc_rlimit_ucounts`",
            server,
        )
        assert result is not None
        assert result.verified is False


class TestTaintSourceSink:
    def test_confirmed(self):
        server = MockJoernServer()
        server.add_response(
            "reachableByFlows",
            'List("scope[\\"headers\\"] -> host_header -> url_string")',
        )
        result = _verify_taint_source_sink(
            "URL.__init__",
            "unsanitized Host header value directly interpolated into URL",
            server,
        )
        assert result is not None
        assert result.verified is True
        assert result.verifier_name == "taint_source_sink"

    def test_no_sinks_extracted(self):
        server = MockJoernServer()
        result = _verify_taint_source_sink(
            "foo",
            "the code is clean and safe",
            server,
        )
        assert result is None


class TestCallerConstraint:
    def test_unguarded_callers(self):
        server = MockJoernServer()
        server.add_response(
            ".caller",
            'List((caller_a, file.c, 10), (caller_b, file.c, 20))',
        )
        server.add_response("lock", "List()")

        result = _verify_caller_constraint(
            "esp_input",
            "callers must call `skb_cow_data` before this function",
            server,
        )
        assert result is not None
        assert result.verified is True
        assert result.verifier_name == "caller_constraint"

    def test_all_guarded(self):
        server = MockJoernServer()
        server.add_response(
            ".caller",
            'List((caller_a, file.c, 10))',
        )
        server.add_response("skb_cow_data", 'List(true)')

        result = _verify_caller_constraint(
            "esp_input",
            "callers must call `skb_cow_data` before this function",
            server,
        )
        assert result is not None
        assert result.verified is False


class TestTaintToArithmetic:
    def test_confirmed(self):
        server = MockJoernServer()
        server.add_response(
            "reachableByFlows",
            'List("param -> size * count@15 -> kmalloc(size)@20")',
        )
        result = _verify_taint_to_arithmetic(
            "_aead_recvmsg",
            "integer overflow in callee bypasses a length check",
            server,
        )
        assert result is not None
        assert result.verified is True
        assert result.verifier_name == "taint_to_arithmetic"

    def test_no_arithmetic_on_path(self):
        server = MockJoernServer()
        server.add_response(
            "reachableByFlows",
            'List("param -> kmalloc(param)@20")',
        )
        result = _verify_taint_to_arithmetic(
            "foo",
            "integer overflow in size calculation",
            server,
        )
        assert result is not None
        assert result.verified is False


class TestIncompleteCleanup:
    def test_confirmed_with_hypothesis_field(self):
        server = MockJoernServer()
        server.add_response(
            ".ast.isFieldIdentifier.map",
            'List((processing, 10), (io, 15), (connected, 5))',
        )
        server.add_response(
            ".argument.isFieldIdentifier",
            'List((processing, 30))',
        )
        result = _verify_incomplete_cleanup(
            "fuse_dev_release",
            "fails to clean up requests on the `fpq->io` list",
            server,
        )
        assert result is not None
        assert result.verified is True
        assert result.verifier_name == "incomplete_cleanup"
        assert "io" in result.evidence

    def test_all_cleaned(self):
        server = MockJoernServer()
        server.add_response(
            ".ast.isFieldIdentifier.map",
            'List((processing, 10), (io, 15))',
        )
        server.add_response(
            ".argument.isFieldIdentifier",
            'List((processing, 30), (io, 35))',
        )
        result = _verify_incomplete_cleanup(
            "fuse_dev_release",
            "fails to clean up requests on the `fpq->io` list",
            server,
        )
        assert result is not None
        assert result.verified is False


# ── Dispatcher tests ─────────────────────────────────────────────────


class TestDispatcher:
    def test_dispatches_unchecked_return(self):
        server = MockJoernServer()
        server.add_response(
            "filterNot",
            'List((42, "inc_rlimit_ucounts()"))',
        )
        result = cross_function_verify(
            function_name="commit_creds",
            file_path="kernel/cred.c",
            hypothesis="Ignoring the failure of `inc_rlimit_ucounts` enables a TOCTOU",
            server=server,
        )
        assert result is not None
        assert result.verified is True
        assert result.verifier_name == "unchecked_return"

    def test_dispatches_caller_constraint(self):
        server = MockJoernServer()
        server.add_response(".caller", 'List((caller_a, file.c, 10))')
        server.add_response("lock", "List()")
        result = cross_function_verify(
            function_name="n_tty_write",
            hypothesis=(
                "accesses tty->link->count without holding the necessary "
                "lock after sleeping and releasing `termios_rwsem`"
            ),
            file_path="drivers/tty/n_tty.c",
            server=server,
        )
        assert result is not None
        assert result.verified is True
        assert result.verifier_name == "caller_constraint"

    def test_no_match_returns_none(self):
        server = MockJoernServer()
        result = cross_function_verify(
            function_name="foo",
            file_path="foo.c",
            hypothesis="the code looks correct",
            server=server,
        )
        assert result is None

    def test_dispatches_taint_to_arithmetic(self):
        server = MockJoernServer()
        server.add_response(
            "reachableByFlows",
            'List("param -> x * 4@12 -> kmalloc@20")',
        )
        result = cross_function_verify(
            function_name="__arm_lpae_unmap",
            file_path="drivers/iommu/io-pgtable-arm.c",
            hypothesis="Integer truncation of the size_t page count to int",
            server=server,
        )
        assert result is not None
        assert result.verified is True
        assert result.verifier_name == "taint_to_arithmetic"

    def test_dispatches_incomplete_cleanup(self):
        server = MockJoernServer()
        server.add_response(
            ".ast.isFieldIdentifier.map",
            'List((processing, 10), (io, 15))',
        )
        server.add_response(".argument.isFieldIdentifier", 'List((processing, 30))')
        result = cross_function_verify(
            function_name="fuse_dev_release",
            file_path="fs/fuse/dev.c",
            hypothesis="resource leak: fails to clean up the `fpq->io` list",
            server=server,
        )
        assert result is not None
        assert result.verified is True
        assert result.verifier_name == "incomplete_cleanup"

    def test_uaf_hypothesis_does_not_trigger_incomplete_cleanup(self):
        server = MockJoernServer()
        server.add_response(
            ".ast.isFieldIdentifier.map",
            'List((count, 5))',
        )
        server.add_response(".argument.isFieldIdentifier", 'List()')
        result = cross_function_verify(
            function_name="fuse_conn_get",
            file_path="fs/fuse/fuse_i.h",
            hypothesis="use-after-free window: concurrent access to fc->count",
            server=server,
        )
        assert result is None

    def test_broad_heuristic_requires_two_cleaned_fields(self):
        server = MockJoernServer()
        server.add_response(
            ".ast.isFieldIdentifier.map",
            'List((count, 5), (flags, 10), (state, 15))',
        )
        server.add_response(".argument.isFieldIdentifier", 'List((flags, 30))')
        result = _verify_incomplete_cleanup(
            "some_helper",
            "resource leak in some_helper",
            server,
        )
        assert result is None


class TestGateHelper:
    def test_no_evidence(self):
        from core.audit.orchestrator import _is_verification_evidence_for_gate, ReviewOutcome
        outcome = ReviewOutcome(
            file="test.c", function="foo", status="suspicious", body="",
        )
        assert _is_verification_evidence_for_gate(outcome) is False

    def test_joern_xf_evidence(self):
        from core.audit.orchestrator import _is_verification_evidence_for_gate, ReviewOutcome
        outcome = ReviewOutcome(
            file="test.c", function="foo", status="suspicious", body="",
            evidence_tool="joern:xf:unchecked_return",
        )
        assert _is_verification_evidence_for_gate(outcome) is True

    def test_detection_only_evidence(self):
        from core.audit.orchestrator import _is_verification_evidence_for_gate, ReviewOutcome
        outcome = ReviewOutcome(
            file="test.c", function="foo", status="suspicious", body="",
            evidence_tool="smt:check-lock-domain",
        )
        assert _is_verification_evidence_for_gate(outcome) is False
