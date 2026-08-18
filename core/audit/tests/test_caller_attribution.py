"""Tests for caller-attribution annotation in core.audit.orchestrator."""

from __future__ import annotations

from core.audit.orchestrator import ReviewOutcome, _apply_caller_attribution


def _outcome(status="suspicious", hypothesis="", body=""):
    return ReviewOutcome(
        file="src/go/scanner/scanner.go",
        function="trailingDigits",
        status=status,
        body=body,
        hypothesis=hypothesis,
    )


def _callers(*names):
    return [
        {"file": "scanner.go", "name": n, "line_start": 1}
        for n in names
    ]


class TestCallerAttribution:
    def test_hypothesis_mentions_caller(self):
        o = _outcome(
            hypothesis="scanNumber passes unvalidated input",
            body="The digits are not bounds-checked.",
        )
        result = _apply_caller_attribution(o, _callers("scanNumber", "Init"))
        assert result.caller_attributed is True
        assert result.attributed_caller == "scanNumber"

    def test_body_mentions_caller(self):
        o = _outcome(
            hypothesis="potential overflow",
            body="The caller scanNumber does not validate the base parameter.",
        )
        result = _apply_caller_attribution(o, _callers("scanNumber"))
        assert result.caller_attributed is True

    def test_no_caller_mention(self):
        o = _outcome(
            hypothesis="potential buffer overflow in digit parsing",
            body="The loop does not check array bounds.",
        )
        result = _apply_caller_attribution(o, _callers("scanNumber"))
        assert result.caller_attributed is False
        assert result.attributed_caller == ""

    def test_no_callers_available(self):
        o = _outcome(
            hypothesis="scanNumber overflow",
        )
        result = _apply_caller_attribution(o, [])
        assert result.caller_attributed is False

    def test_clean_status_skipped(self):
        o = _outcome(status="clean", hypothesis="scanNumber overflow")
        result = _apply_caller_attribution(o, _callers("scanNumber"))
        assert result.caller_attributed is False

    def test_dormant_status_skipped(self):
        o = _outcome(status="dormant", hypothesis="scanNumber overflow")
        result = _apply_caller_attribution(o, _callers("scanNumber"))
        assert result.caller_attributed is False

    def test_finding_status_tagged(self):
        o = _outcome(
            status="finding",
            hypothesis="scanNumber passes tainted data",
        )
        result = _apply_caller_attribution(o, _callers("scanNumber"))
        assert result.caller_attributed is True

    def test_short_name_ignored(self):
        """Caller names < 3 chars would cause false positives."""
        o = _outcome(
            hypothesis="the Go parser handles 'go' keyword",
            body="go routines are concurrent",
        )
        result = _apply_caller_attribution(o, _callers("go"))
        assert result.caller_attributed is False

    def test_case_insensitive(self):
        o = _outcome(
            hypothesis="SCANNUMBER may overflow",
        )
        result = _apply_caller_attribution(o, _callers("scanNumber"))
        assert result.caller_attributed is True

    def test_first_matching_caller_wins(self):
        o = _outcome(
            hypothesis="Init calls scanNumber which overflows",
        )
        result = _apply_caller_attribution(
            o, _callers("Init", "scanNumber"),
        )
        assert result.caller_attributed is True
        assert result.attributed_caller == "Init"

    def test_empty_hypothesis_and_body(self):
        o = _outcome(hypothesis="", body="")
        result = _apply_caller_attribution(o, _callers("scanNumber"))
        assert result.caller_attributed is False
