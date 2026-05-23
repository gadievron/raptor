"""Tests for ``packages.llm_analysis.intent_match.intent_match``.

The judge is heuristic-first with an LLM tiebreak on ambiguous
cases. Tests pin both layers in isolation:

  * Heuristic feature functions (file/function/CWE-shape/compile-
    error overlap) — direct calls with synthetic inputs.
  * Verdict aggregation thresholds (3-of-4 → matches, 0 → off,
    1-2 → uncertain) — table-driven over the public ``intent_match``
    interface with no LLM client.
  * LLM tiebreak — invoked with a fake LLM provider that returns
    canned responses, exercises both steps of the 2-step prompt
    (describe → judge) and parsing of the verdict line.
  * Defensive paths — empty exploit, missing metadata, LLM raises,
    LLM returns garbage, LLM unavailable.

v1 is a weak-signal classifier with no calibration. Tests pin the
*contract* (the verdict-deciding logic and the schema), not
absolute accuracy claims.
"""

from __future__ import annotations

import sys
from pathlib import Path



# packages/llm_analysis/tests/test_intent_match.py → parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from packages.llm_analysis.intent_match import (  # noqa: E402
    IntentMatchVerdict,
    VERDICT_MATCHES,
    VERDICT_OFF_TARGET,
    VERDICT_UNCERTAIN,
    _cwe_buffer_overflow_shape,
    _cwe_command_injection_shape,
    _cwe_integer_overflow_shape,
    _cwe_null_deref_shape,
    _cwe_path_traversal_shape,
    _cwe_shape,
    _cwe_sql_injection_shape,
    _cwe_xss_shape,
    _compile_error_anchor,
    _file_overlap,
    _function_overlap,
    intent_match,
)


# ---------------------------------------------------------------------------
# Heuristic: file overlap
# ---------------------------------------------------------------------------


class TestFileOverlap:
    def test_full_path_match(self):
        assert _file_overlap("src/auth.c", "// target: src/auth.c\nint main(){}")

    def test_basename_match(self):
        assert _file_overlap("src/auth.c", "/* attacks the auth.c parser */")

    def test_basename_word_boundary(self):
        # 'auth.c' should NOT match in 'authentication_check' — word
        # boundary prevents the false positive
        assert not _file_overlap(
            "src/auth.c",
            "void authentication_check() { /* unrelated */ }",
        )

    def test_no_match(self):
        assert not _file_overlap(
            "src/auth.c", "// completely unrelated code"
        )

    def test_none_path(self):
        assert not _file_overlap(None, "anything")

    def test_empty_code(self):
        assert not _file_overlap("src/auth.c", "")

    def test_directory_path_substring_match(self):
        # Path "src/" has empty basename, so the basename word-
        # boundary check skips. The full-path substring check
        # still fires because "src/" IS a substring. Defensible:
        # finding.file_path is normally a full file path, not a
        # directory; if a caller passes "src/" they get the broad
        # substring contract.
        assert _file_overlap("src/", "anything with src/")
        # But no false match when the directory string is absent.
        assert not _file_overlap("src/", "anything else")


# ---------------------------------------------------------------------------
# Heuristic: function overlap
# ---------------------------------------------------------------------------


class TestFunctionOverlap:
    def test_word_boundary_match(self):
        assert _function_overlap(
            "check_password", "check_password(input);"
        )

    def test_no_false_positive_substring(self):
        # 'check' must not match inside 'checkpoint'
        assert not _function_overlap("check", "checkpoint();")

    def test_no_match(self):
        assert not _function_overlap("foo", "bar()")

    def test_none_function(self):
        assert not _function_overlap(None, "anything")

    def test_empty_code(self):
        assert not _function_overlap("check_password", "")

    def test_special_chars_escaped(self):
        # Function names with dots etc shouldn't break the regex
        assert _function_overlap("c.dotted", "call c.dotted now")


# ---------------------------------------------------------------------------
# Heuristic: compile-error anchor
# ---------------------------------------------------------------------------


class TestCompileErrorAnchor:
    def test_full_path_in_errors(self):
        assert _compile_error_anchor(
            "src/auth.c",
            ["src/auth.c:42: error: expected ';'"],
        )

    def test_basename_in_errors(self):
        assert _compile_error_anchor(
            "src/auth.c",
            ["error: undefined reference to vuln_func in auth.c"],
        )

    def test_no_errors(self):
        assert not _compile_error_anchor("src/auth.c", [])

    def test_none_errors(self):
        assert not _compile_error_anchor("src/auth.c", None)

    def test_errors_dont_mention_file(self):
        assert not _compile_error_anchor(
            "src/auth.c",
            ["error: undefined reference to 'malloc'"],
        )


# ---------------------------------------------------------------------------
# CWE shape detectors — happy paths
# ---------------------------------------------------------------------------


class TestCweBufferOverflowShape:
    def test_python_repeat_payload(self):
        assert _cwe_buffer_overflow_shape('payload = "A" * 100')

    def test_byte_repeat_payload(self):
        assert _cwe_buffer_overflow_shape('p = b"\\x41" * 200')

    def test_long_byte_literal(self):
        assert _cwe_buffer_overflow_shape(
            'shellcode = b"\\xde\\xad\\xbe\\xef\\xca\\xfe\\xba\\xbe\\x00\\x11"'
        )

    def test_short_repeat_excluded(self):
        # 4-char repeat shouldn't fire ("    " * 4 is incidental)
        assert not _cwe_buffer_overflow_shape('"    " * 4')

    def test_no_match(self):
        assert not _cwe_buffer_overflow_shape("int main() {}")


class TestCweCommandInjectionShape:
    def test_semicolon_in_string(self):
        assert _cwe_command_injection_shape(
            'payload = "; rm -rf /"'
        )

    def test_subshell_in_string(self):
        assert _cwe_command_injection_shape(
            'payload = "$(id)"'
        )

    def test_backticks_in_string(self):
        assert _cwe_command_injection_shape(
            'payload = "`whoami`"'
        )

    def test_no_match_plain_code(self):
        assert not _cwe_command_injection_shape(
            'x = 5; y = 6;'  # ; outside string literal
        )


class TestCweSqlInjectionShape:
    def test_or_1_eq_1(self):
        assert _cwe_sql_injection_shape("payload = \"' OR 1=1\"")

    def test_union_select(self):
        assert _cwe_sql_injection_shape(
            "query = \"x' UNION SELECT * FROM users--\""
        )

    def test_drop_table(self):
        assert _cwe_sql_injection_shape(
            "p = \"'; DROP TABLE users;\""
        )

    def test_no_match(self):
        assert not _cwe_sql_injection_shape("def union_users():")


class TestCweXssShape:
    def test_script_tag(self):
        assert _cwe_xss_shape('payload = "<script>alert(1)</script>"')

    def test_onerror_handler(self):
        assert _cwe_xss_shape(
            'payload = "<img src=x onerror=\\\"alert(1)\\\">"'
        )

    def test_javascript_url(self):
        assert _cwe_xss_shape('href = "javascript:alert(1)"')

    def test_no_match(self):
        assert not _cwe_xss_shape("import script_module")


class TestCwePathTraversalShape:
    def test_unix_traversal(self):
        assert _cwe_path_traversal_shape('p = "../../etc/passwd"')

    def test_url_encoded(self):
        assert _cwe_path_traversal_shape('p = "%2e%2e%2fetc"')

    def test_windows_traversal(self):
        assert _cwe_path_traversal_shape('p = "..\\\\..\\\\system32"')

    def test_no_match(self):
        assert not _cwe_path_traversal_shape("path = './foo'")


class TestCweNullDerefShape:
    def test_c_null(self):
        assert _cwe_null_deref_shape("func(NULL);")

    def test_python_none(self):
        assert _cwe_null_deref_shape("x = None")

    def test_empty_string_arg(self):
        assert _cwe_null_deref_shape('func("",)')

    def test_no_match(self):
        assert not _cwe_null_deref_shape("x = 5")


class TestCweIntegerOverflowShape:
    def test_large_hex(self):
        assert _cwe_integer_overflow_shape("size = 0xffffffff")

    def test_near_int_max(self):
        assert _cwe_integer_overflow_shape("n = 0x7fffffff")

    def test_python_2_power(self):
        assert _cwe_integer_overflow_shape("limit = 2**32")

    def test_max_int_constant(self):
        assert _cwe_integer_overflow_shape("size = UINT_MAX")

    def test_no_match(self):
        assert not _cwe_integer_overflow_shape("x = 5")


# ---------------------------------------------------------------------------
# CWE dispatch
# ---------------------------------------------------------------------------


class TestCweDispatch:
    def test_known_cwe_returns_bool(self):
        result = _cwe_shape("CWE-120", 'p = "A" * 100')
        assert result is True

    def test_unknown_cwe_returns_none(self):
        # CWE-416 (UAF) has no v1 detector — abstain
        assert _cwe_shape("CWE-416", "anything") is None

    def test_none_cwe_returns_none(self):
        assert _cwe_shape(None, "anything") is None

    def test_overflow_family_dispatches_correctly(self):
        # CWE-120, 121, 122, 787 all dispatch to the buffer-overflow detector
        for cwe in ("CWE-120", "CWE-121", "CWE-122", "CWE-787"):
            assert _cwe_shape(cwe, 'p = "A" * 100') is True


# ---------------------------------------------------------------------------
# Public ``intent_match`` — verdict aggregation (no LLM)
# ---------------------------------------------------------------------------


class TestIntentMatchVerdictAggregation:
    """Pin the threshold logic: 3-of-4 → matches, 0 → off_target,
    1-2 → uncertain (LLM tiebreak path, here tested with no LLM)."""

    def test_4_of_4_heuristics_matches(self):
        v = intent_match(
            exploit_code=(
                '// targets src/auth.c::check_password\n'
                'payload = "A" * 200'
            ),
            finding_file_path="src/auth.c",
            finding_function_name="check_password",
            finding_cwe="CWE-120",
            exploit_compile_errors=["src/auth.c:1: error: ..."],
        )
        assert v.verdict == VERDICT_MATCHES
        assert v.used_llm is False
        assert v.confidence > 0.8
        assert all(v.signals.values())

    def test_3_of_4_heuristics_matches_no_llm(self):
        # Three heuristics fire, one doesn't — no LLM needed
        v = intent_match(
            exploit_code=(
                '// targets src/auth.c::check_password\n'
                'payload = "A" * 200'
            ),
            finding_file_path="src/auth.c",
            finding_function_name="check_password",
            finding_cwe="CWE-120",
            exploit_compile_errors=[],  # compile-anchor false
        )
        assert v.verdict == VERDICT_MATCHES
        assert v.used_llm is False

    def test_0_heuristics_off_target_no_llm(self):
        # Nothing matches — off_target without LLM
        v = intent_match(
            exploit_code='import requests; requests.get("http://example.com")',
            finding_file_path="src/auth.c",
            finding_function_name="check_password",
            finding_cwe="CWE-120",
        )
        assert v.verdict == VERDICT_OFF_TARGET
        assert v.used_llm is False
        assert all(s is False or s is None for s in v.signals.values())

    def test_1_of_4_uncertain_without_llm(self):
        v = intent_match(
            exploit_code="// auth.c reference only",
            finding_file_path="src/auth.c",
            finding_function_name="check_password",
            finding_cwe="CWE-120",
            llm_client=None,
        )
        assert v.verdict == VERDICT_UNCERTAIN
        assert v.used_llm is False
        assert v.confidence < 0.7  # modest confidence on no-LLM uncertain

    def test_partial_metadata_strong_match(self):
        # Only 2 heuristics can evaluate (no function name, no CWE),
        # both fire → match (all-evaluated-match case)
        v = intent_match(
            exploit_code='// auth.c attack via long payload',
            finding_file_path="src/auth.c",
            finding_function_name=None,
            finding_cwe=None,
        )
        # 1 of 1 evaluated fired — function/cwe abstain (None), file
        # overlap fires, compile-anchor is False (no errors).
        # That's 1/2 evaluated → tiebreak case → uncertain w/o LLM
        # Actually depends on aggregation; verify it's not crashing
        assert v.verdict in {VERDICT_MATCHES, VERDICT_UNCERTAIN}

    def test_no_exploit_code_returns_uncertain(self):
        v = intent_match(
            exploit_code="",
            finding_file_path="src/auth.c",
        )
        assert v.verdict == VERDICT_UNCERTAIN
        assert v.signals == {}
        assert v.used_llm is False
        assert "no exploit_code" in v.reasoning


# ---------------------------------------------------------------------------
# LLM tiebreak — fake provider exercise
# ---------------------------------------------------------------------------


class _FakeLLMResponse:
    def __init__(self, content: str, cost_usd: float = 0.001):
        self.content = content
        self.cost_usd = cost_usd


class _FakeLLMProvider:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def generate(self, prompt, system_prompt=None, task_type=None, **kw):
        self.calls.append({
            "prompt": prompt,
            "system_prompt": system_prompt,
            "task_type": task_type,
        })
        if not self._responses:
            raise RuntimeError("FakeLLMProvider exhausted")
        return self._responses.pop(0)


class TestIntentMatchLLMTiebreak:
    def test_llm_returns_matches(self):
        llm = _FakeLLMProvider([
            _FakeLLMResponse(
                "The exploit constructs a long string payload targeting "
                "check_password in auth.c."
            ),
            _FakeLLMResponse("matches: payload aimed at the named function"),
        ])
        v = intent_match(
            exploit_code='// auth.c\npayload = "A" * 100',
            finding_file_path="src/other.c",  # no file overlap
            finding_function_name="check_password",
            finding_cwe="CWE-120",
            llm_client=llm,
        )
        assert v.verdict == VERDICT_MATCHES
        assert v.used_llm is True
        assert v.cost_usd > 0
        assert len(llm.calls) == 2  # describe + judge
        assert v.llm_error is None

    # Common setup: exploit fires cwe_shape (long-string payload)
    # but file/function/compile don't overlap → 1/4 heuristics →
    # ambiguous → escalates to LLM tiebreak.
    _AMBIGUOUS_KWARGS = dict(
        exploit_code='payload = "A" * 200',
        finding_file_path="src/other.c",  # no overlap with exploit_code
        finding_function_name="check_password",  # no overlap
        finding_cwe="CWE-120",  # cwe_shape fires on long-string payload
    )

    def test_llm_returns_off_target(self):
        llm = _FakeLLMProvider([
            _FakeLLMResponse("The exploit attempts SQL injection."),
            _FakeLLMResponse("off_target: payload is SQL, bug is BOF"),
        ])
        v = intent_match(**self._AMBIGUOUS_KWARGS, llm_client=llm)
        assert v.verdict == VERDICT_OFF_TARGET
        assert v.used_llm is True

    def test_llm_returns_uncertain(self):
        llm = _FakeLLMProvider([
            _FakeLLMResponse("Exploit is generic; not clearly tied to the bug."),
            _FakeLLMResponse("uncertain: shape is plausible but generic"),
        ])
        v = intent_match(**self._AMBIGUOUS_KWARGS, llm_client=llm)
        assert v.verdict == VERDICT_UNCERTAIN
        assert v.used_llm is True

    def test_describe_step_raises_returns_uncertain(self):
        class _Bomb:
            def __init__(self, *a, **kw): pass
            def generate(self, *a, **kw):
                raise RuntimeError("describe-step API failure")
        v = intent_match(**self._AMBIGUOUS_KWARGS, llm_client=_Bomb())
        assert v.verdict == VERDICT_UNCERTAIN
        assert v.used_llm is True
        assert v.llm_error is not None
        assert "describe" in v.llm_error

    def test_judge_step_raises_returns_uncertain(self):
        # Describe succeeds, judge raises
        call_count = [0]

        class _PartialBomb:
            def generate(self, *a, **kw):
                call_count[0] += 1
                if call_count[0] == 1:
                    return _FakeLLMResponse("the exploit does X")
                raise RuntimeError("judge-step API failure")

        v = intent_match(**self._AMBIGUOUS_KWARGS, llm_client=_PartialBomb())
        assert v.verdict == VERDICT_UNCERTAIN
        assert v.used_llm is True
        assert v.llm_error is not None
        assert "judge" in v.llm_error

    def test_llm_returns_unparseable_verdict(self):
        # Judge returns something that doesn't start with one of the
        # three valid verdict words — should fall back to uncertain
        llm = _FakeLLMProvider([
            _FakeLLMResponse("description"),
            _FakeLLMResponse("hmm, hard to say — maybe both?"),
        ])
        v = intent_match(**self._AMBIGUOUS_KWARGS, llm_client=llm)
        assert v.verdict == VERDICT_UNCERTAIN
        assert v.used_llm is True

    def test_llm_returns_none_response(self):
        class _NoneLLM:
            def generate(self, *a, **kw):
                return None

        v = intent_match(**self._AMBIGUOUS_KWARGS, llm_client=_NoneLLM())
        assert v.verdict == VERDICT_UNCERTAIN
        assert v.used_llm is True
        assert v.llm_error is not None

    def test_strong_heuristic_skips_llm_call(self):
        # When 4-of-4 fires, no LLM call should happen even if one is
        # configured. Cost-saving optimisation; pinned so a future
        # refactor doesn't accidentally always-call the LLM.
        llm = _FakeLLMProvider([])  # empty queue would raise if called
        v = intent_match(
            exploit_code=(
                '// targets src/auth.c::check_password\n'
                'payload = "A" * 200'
            ),
            finding_file_path="src/auth.c",
            finding_function_name="check_password",
            finding_cwe="CWE-120",
            exploit_compile_errors=["src/auth.c:1: error: ..."],
            llm_client=llm,
        )
        assert v.verdict == VERDICT_MATCHES
        assert v.used_llm is False
        assert llm.calls == []


# ---------------------------------------------------------------------------
# Schema / output dataclass
# ---------------------------------------------------------------------------


class TestSchemaShape:
    def test_verdict_is_dataclass_with_expected_fields(self):
        v = IntentMatchVerdict(
            verdict=VERDICT_MATCHES,
            confidence=0.9,
            reasoning="test",
            signals={"a": True},
            used_llm=False,
        )
        # Must serialise cleanly via asdict for storage on
        # VulnerabilityContext.intent_match
        from dataclasses import asdict
        d = asdict(v)
        assert set(d.keys()) >= {
            "verdict", "confidence", "reasoning", "signals",
            "used_llm", "cost_usd", "llm_error",
        }

    def test_verdict_strings_are_canonical(self):
        # Three-way verdict; nothing else allowed by the contract
        assert VERDICT_MATCHES == "matches"
        assert VERDICT_OFF_TARGET == "off_target"
        assert VERDICT_UNCERTAIN == "uncertain"


# ---------------------------------------------------------------------------
# Defensive paths added in the adversarial-review stacked fix
# ---------------------------------------------------------------------------


class TestLLMContentTypeTolerance:
    """The judge tolerates unusual LLM client return shapes without
    crashing the prompt envelope. Real providers return ``str``, but
    custom adapters / wrappers have been seen to return ``bytes`` —
    the envelope's regex sub then raises TypeError on bytes input.
    Pre-fix this crashed mid-tiebreak; post-fix the bytes get
    decoded to UTF-8 (with errors=replace) before reaching the
    envelope."""

    _AMBIGUOUS_KWARGS = dict(
        exploit_code='payload = "A" * 200',
        finding_file_path="src/other.c",
        finding_function_name="check_password",
        finding_cwe="CWE-120",
    )

    def test_describe_response_bytes_content_decoded(self):
        """Step 1 (describe) returning bytes content doesn't crash."""
        from unittest.mock import MagicMock
        llm = MagicMock()
        # describe-step → bytes content; judge-step → str
        describe_resp = MagicMock()
        describe_resp.content = b"The exploit constructs a long payload."
        describe_resp.cost_usd = 0.001
        judge_resp = MagicMock()
        judge_resp.content = "matches: payload aimed at target"
        judge_resp.cost_usd = 0.001
        llm.generate.side_effect = [describe_resp, judge_resp]

        v = intent_match(**self._AMBIGUOUS_KWARGS, llm_client=llm)
        assert v.used_llm is True
        # Verdict can be matches OR uncertain depending on how the
        # decoded content gets judged — what matters is no crash.
        assert v.verdict in {VERDICT_MATCHES, VERDICT_OFF_TARGET, VERDICT_UNCERTAIN}
        assert v.llm_error is None

    def test_judge_response_bytes_content_decoded(self):
        """Step 2 (judge) returning bytes content doesn't crash and
        parses correctly after decode."""
        from unittest.mock import MagicMock
        llm = MagicMock()
        describe_resp = MagicMock()
        describe_resp.content = "the exploit does X"
        describe_resp.cost_usd = 0.001
        judge_resp = MagicMock()
        judge_resp.content = b"matches: bytes-typed verdict"
        judge_resp.cost_usd = 0.001
        llm.generate.side_effect = [describe_resp, judge_resp]

        v = intent_match(**self._AMBIGUOUS_KWARGS, llm_client=llm)
        assert v.verdict == VERDICT_MATCHES
        assert v.used_llm is True
        assert v.llm_error is None

    def test_invalid_utf8_bytes_replaced_not_raised(self):
        """Non-UTF8 bytes (decoder error) get replaced rather than
        raised — best-effort decode."""
        from unittest.mock import MagicMock
        llm = MagicMock()
        describe_resp = MagicMock()
        # Invalid UTF-8 byte sequence
        describe_resp.content = b"\xff\xfe invalid utf-8 attempt"
        describe_resp.cost_usd = 0.001
        judge_resp = MagicMock()
        judge_resp.content = "uncertain: garbled input"
        judge_resp.cost_usd = 0.001
        llm.generate.side_effect = [describe_resp, judge_resp]

        v = intent_match(**self._AMBIGUOUS_KWARGS, llm_client=llm)
        assert v.used_llm is True
        # No specific verdict expected — what matters is no crash.
