"""The ``observed_status`` seam on witness results.

``DarkVerifyResult.observed_status`` reports what the harness protocol
itself said (``returned`` / ``exception`` / ``import_error`` /
``binding_error`` / ``arg_binding_error``) independent of the
expectation-relative verdict.
The contract under test has two directions:

- STAMPED: every classification branch that consumed an authenticated
  protocol status carries that status verbatim.
- BLANK: every path that never saw a trustworthy protocol line —
  empty output, unparseable output, token mismatch, duplicate-key
  tampering, unknown status — leaves the default ``""`` so a consumer
  can never mistake a derived verdict for a raw observation.
"""

from __future__ import annotations

import json

import pytest

from core.audit.dark_verify import (
    DarkVerifyResult,
    DarkWitnessSpec,
    _classify_output,
)


def _spec(**kw):
    base = dict(
        finding_key="f1", file="pkg/mod.py", function="check",
        language="python", module_path="pkg.mod",
    )
    base.update(kw)
    return DarkWitnessSpec(**base)


def _line(**fields) -> str:
    return json.dumps(fields)


# -- stamped: the five protocol statuses --------------------------------------


class TestStampedReturned:
    def test_returned_no_expectation_is_inconclusive_but_observed(self):
        r = _classify_output(
            _spec(), _line(status="returned", value="7"), "python")
        assert r.verdict == "inconclusive"
        assert r.observed_status == "returned"
        assert r.actual_return == "7"

    def test_returned_matching_expectation(self):
        r = _classify_output(
            _spec(expected_return=7),
            _line(status="returned", value="7"), "python")
        assert r.verdict == "confirmed"
        assert r.observed_status == "returned"

    def test_returned_mismatching_expectation(self):
        r = _classify_output(
            _spec(expected_return=7),
            _line(status="returned", value="9"), "python")
        assert r.verdict == "refuted"
        assert r.observed_status == "returned"

    def test_returned_when_exception_expected(self):
        r = _classify_output(
            _spec(expected_exception="ValueError"),
            _line(status="returned", value="7"), "python")
        assert r.verdict == "refuted"
        assert r.observed_status == "returned"

    def test_returned_when_crash_expected(self):
        r = _classify_output(
            _spec(language="c", file="src/a.c", module_path="",
                  expected_crash=True),
            _line(status="returned", value="0"), "c")
        assert r.verdict == "refuted"
        assert r.observed_status == "returned"

    def test_returned_when_crash_expected_without_sanitizers(self):
        r = _classify_output(
            _spec(language="rust", file="src/a.rs", module_path="",
                  expected_crash=True),
            _line(status="returned", value="0"), "rust",
            sanitizers_active=False)
        assert r.verdict == "inconclusive"
        assert r.observed_status == "returned"

    def test_pointer_return_inconclusive_still_observed(self):
        r = _classify_output(
            _spec(language="c", file="src/a.c", module_path="",
                  expected_return="0x0",
                  lang_config={"return_type": "char *"}),
            _line(status="returned", value="0x55aa"), "c")
        assert r.verdict == "inconclusive"
        assert r.observed_status == "returned"


class TestStampedException:
    def test_expected_exception_match(self):
        r = _classify_output(
            _spec(expected_exception="ValueError"),
            _line(status="exception", type="ValueError", message="bad"),
            "python")
        assert r.verdict == "confirmed"
        assert r.observed_status == "exception"

    def test_expected_exception_mismatch(self):
        r = _classify_output(
            _spec(expected_exception="ValueError"),
            _line(status="exception", type="TypeError", message="bad"),
            "python")
        assert r.verdict == "refuted"
        assert r.observed_status == "exception"

    def test_unexpected_exception_is_error_but_observed(self):
        r = _classify_output(
            _spec(expected_return=7),
            _line(status="exception", type="TypeError", message="bad"),
            "python")
        assert r.verdict == "error"
        assert r.observed_status == "exception"

    @pytest.mark.parametrize("msg,verdict", [
        ("attempt to index a nil value", "confirmed"),
        ("something else entirely", "refuted"),
    ])
    def test_message_match_language_both_directions(self, msg, verdict):
        r = _classify_output(
            _spec(language="lua", file="src/a.lua", module_path="",
                  expected_exception="nil value"),
            _line(status="exception", type="", message=msg), "lua")
        assert r.verdict == verdict
        assert r.observed_status == "exception"


class TestStampedLoadFailures:
    def test_import_error(self):
        r = _classify_output(
            _spec(), _line(status="import_error", message="no module"),
            "python")
        assert r.verdict == "error"
        assert r.observed_status == "import_error"

    def test_binding_error(self):
        r = _classify_output(
            _spec(), _line(status="binding_error", message="shadowed"),
            "python")
        assert r.verdict == "error"
        assert r.observed_status == "binding_error"

    def test_arg_binding_error(self):
        r = _classify_output(
            _spec(),
            _line(status="arg_binding_error",
                  message="missing a required argument: 'limit'"),
            "python")
        assert r.verdict == "error"
        assert r.observed_status == "arg_binding_error"
        assert "do not bind" in r.match_detail

    def test_arg_binding_error_never_confirms_expected_typeerror(self):
        # The sharpest direction of the contract: a witness that
        # PREDICTED a TypeError must not have that prediction
        # "confirmed" by its own mis-shaped vector failing to bind —
        # the target body never ran.
        r = _classify_output(
            _spec(expected_exception="TypeError"),
            _line(status="arg_binding_error",
                  message="too many positional arguments"),
            "python")
        assert r.verdict == "error"
        assert r.observed_status == "arg_binding_error"


# -- blank: no trustworthy protocol line ever seen ----------------------------


class TestBlankWithoutAuthenticatedObservation:
    def test_empty_output(self):
        r = _classify_output(_spec(), "", "python")
        assert r.verdict == "inconclusive"
        assert r.observed_status == ""

    def test_unparseable_output(self):
        r = _classify_output(_spec(), "Traceback (most recent...", "python")
        assert r.verdict == "inconclusive"
        assert r.observed_status == ""

    def test_token_mismatch(self):
        out = _line(status="returned", value="7", token="forged")
        r = _classify_output(_spec(), out, "python", expected_token="ab12")
        assert r.verdict == "inconclusive"
        assert r.observed_status == ""

    def test_missing_token(self):
        out = _line(status="returned", value="7")
        r = _classify_output(_spec(), out, "python", expected_token="ab12")
        assert r.verdict == "inconclusive"
        assert r.observed_status == ""

    def test_duplicate_key_tampering(self):
        out = ('{"status": "exception", "status": "returned", '
               '"value": "7"}')
        r = _classify_output(_spec(), out, "python")
        assert r.verdict == "inconclusive"
        assert r.observed_status == ""

    def test_unknown_status(self):
        r = _classify_output(
            _spec(), _line(status="segv", value=""), "python")
        assert r.verdict == "inconclusive"
        assert r.observed_status == ""

    def test_authenticated_token_still_stamps(self):
        out = _line(status="returned", value="7", token="ab12")
        r = _classify_output(_spec(), out, "python", expected_token="ab12")
        assert r.observed_status == "returned"


# -- serialization -------------------------------------------------------------


class TestSerialization:
    def test_default_is_blank(self):
        r = DarkVerifyResult(finding_key="f1", verdict="error")
        assert r.observed_status == ""

    def test_to_dict_carries_observed_status(self):
        r = DarkVerifyResult(
            finding_key="f1", verdict="confirmed",
            observed_status="returned")
        d = r.to_dict()
        assert d["observed_status"] == "returned"
        assert json.loads(json.dumps(d))["observed_status"] == "returned"
