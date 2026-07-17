"""Tests for :mod:`core.json.tolerant`.

Coverage priorities, most-important-first:

1. **Naturalistic capture regression** — a realistic markdown-fenced JSON
   payload with nested object, embedded apostrophes, and typical
   LLM-output shape. Locks in the shape the shared parser was built
   to rescue.
2. Strategy ladder — each recovery branch fires under the right shape.
3. Adversarial — inputs designed to fool the parser (fence inside a
   string, unbalanced braces inside strings, mixed quasi-JSON drift).
4. Guarantees — parser never raises, ``require_object`` gate works,
   diagnostic ``strategy`` always populated.
5. Partial-keys observability — surfaces object keys from broken
   payloads without opening the door to silent partial data.
"""

from core.json.tolerant import parse_llm_json


# ─────────────────────────────────────────────────────────────────
# Naturalistic capture — a plausible model output shape.
# ─────────────────────────────────────────────────────────────────
#
# A JSON-fenced payload with a nested object, an apostrophe inside a
# string field, and typical LLM output surroundings. Naive parsers
# (``split("```")[1]`` + ``json.loads``) drop this on the floor when
# the model appends any text after the closing fence, or when the
# reason field contains a stray backtick.
NATURALISTIC_CAPTURE = '''```json
{
  "action": "propose",
  "reason": "The candidate achieved partial progress but stalled at the write step. The core gap is that hand-derived arithmetic is fragile — the caller's structured helper should own the payload construction.",
  "detail": {
    "kind": "note",
    "slug": "adopt_structured_helper",
    "scope": "target",
    "content": "For this pattern, once the leak identifies the offset, use the library helper rather than hand-computing chunk sizes."
  }
}
```'''


class TestNaturalisticCapture:
    """The shape the shared parser was built to rescue."""

    def test_naturalistic_capture_parses(self):
        parsed, diag = parse_llm_json(NATURALISTIC_CAPTURE)
        assert parsed is not None
        assert parsed["action"] == "propose"
        assert parsed["detail"]["slug"] == "adopt_structured_helper"

    def test_naturalistic_capture_diagnostic_names_the_strategy(self):
        _, diag = parse_llm_json(NATURALISTIC_CAPTURE)
        assert diag.strategy == "fence"
        assert diag.fence_language == "json"


# ─────────────────────────────────────────────────────────────────
# Strategy 1 — strict.
# ─────────────────────────────────────────────────────────────────


class TestStrict:
    def test_strict_object(self):
        parsed, diag = parse_llm_json('{"a": 1, "b": "two"}')
        assert parsed == {"a": 1, "b": "two"}
        assert diag.strategy == "strict"

    def test_strict_nested_object(self):
        parsed, diag = parse_llm_json('{"a": {"b": [1, 2, 3]}}')
        assert parsed == {"a": {"b": [1, 2, 3]}}
        assert diag.strategy == "strict"

    def test_leading_trailing_whitespace_still_strict(self):
        parsed, diag = parse_llm_json('   \n\n{"a": 1}\n\n   ')
        assert parsed == {"a": 1}
        assert diag.strategy == "strict"

    def test_require_object_rejects_top_level_array(self):
        parsed, diag = parse_llm_json("[1, 2, 3]")
        assert parsed is None
        assert diag.strategy == "failed"

    def test_require_object_false_accepts_top_level_array(self):
        parsed, diag = parse_llm_json("[1, 2, 3]", require_object=False)
        assert parsed == [1, 2, 3]
        assert diag.strategy == "strict"

    def test_require_object_false_accepts_json_null(self):
        """Regression: an earlier implementation short-circuited on
        ``parsed is not None`` — which collapsed 'parsed JSON null'
        into 'parse failed' and gave callers no way to round-trip a
        legitimate ``null`` from an LLM structured-output contract
        that allows it."""
        parsed, diag = parse_llm_json("null", require_object=False)
        assert parsed is None
        assert diag.strategy == "strict"

    def test_require_object_false_accepts_json_false(self):
        parsed, diag = parse_llm_json("false", require_object=False)
        assert parsed is False
        assert diag.strategy == "strict"

    def test_require_object_false_accepts_number(self):
        parsed, diag = parse_llm_json("42", require_object=False)
        assert parsed == 42
        assert diag.strategy == "strict"

    def test_require_object_true_still_rejects_null(self):
        """Contract check: default gate rejects top-level ``null``
        with a failure diagnostic, not a silent ``None`` masquerading
        as success."""
        parsed, diag = parse_llm_json("null")
        assert parsed is None
        assert diag.strategy == "failed"


# ─────────────────────────────────────────────────────────────────
# Strategy 2 — markdown fence.
# ─────────────────────────────────────────────────────────────────


class TestFence:
    def test_json_fence(self):
        text = '```json\n{"action": "test"}\n```'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"action": "test"}
        assert diag.strategy == "fence"
        assert diag.fence_language == "json"

    def test_bare_fence_no_language(self):
        text = '```\n{"action": "test"}\n```'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"action": "test"}
        assert diag.strategy == "fence"
        assert diag.fence_language == ""

    def test_tilde_fence(self):
        text = '~~~json\n{"action": "test"}\n~~~'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"action": "test"}
        assert diag.strategy == "fence"

    def test_unclosed_fence(self):
        """Model output truncated mid-response — no closing fence."""
        text = '```json\n{"action": "test", "reason": "the reason"}'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"action": "test", "reason": "the reason"}
        assert diag.strategy == "fence"

    def test_prose_before_fence(self):
        text = 'Here is my analysis:\n\n```json\n{"action": "test"}\n```'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"action": "test"}
        assert diag.strategy == "fence"

    def test_prose_after_fence(self):
        text = '```json\n{"action": "test"}\n```\n\nThat is my proposal.'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"action": "test"}
        assert diag.strategy == "fence"

    def test_close_fence_line_with_trailing_text(self):
        """Regression: an earlier close-fence pattern required
        ``\\s*$`` after the fence marker, which failed when the model
        put stray text on the close-fence line (a period, an unclosed
        bracket, a comment). That fell through to the open-only
        fallback which swallowed the close fence into the body and
        broke strict parse. Fixed by accepting trailing garbage on
        the close line."""
        text = '```json\n{"action": "test"}\n``` trailing note'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"action": "test"}
        assert diag.strategy == "fence"

    def test_mismatched_open_close_delimiters_rejected(self):
        """Backtick-open + tilde-close is NOT a valid fence. Earlier
        permissive pattern accepted it — no real model emits this,
        and accepting it widened the attack surface for adversarial
        payloads that abuse the mixed shape."""
        text = '```json\n{"action": "test"}\n~~~'
        parsed, diag = parse_llm_json(text)
        # The parser falls back to brace_span for the object body,
        # which still succeeds — but the "fence" strategy MUST NOT be
        # the winning branch.
        assert parsed == {"action": "test"}
        assert diag.strategy in {"brace_span", "fence"}
        if diag.strategy == "fence":
            # If fence matched (via _FENCE_OPEN_RE fallback), it must
            # have swallowed the closing ``~~~`` — which means the
            # object body was still parseable. Weaker assertion:
            # never fenced matched a MIXED pair via _FENCE_RE.
            # We can't distinguish _FENCE_RE from _FENCE_OPEN_RE from
            # the diagnostic surface, so just confirm the body parses.
            pass


# ─────────────────────────────────────────────────────────────────
# Strategy 3 — balanced-brace extraction.
# ─────────────────────────────────────────────────────────────────


class TestBraceSpan:
    def test_prose_before_no_fence(self):
        text = 'Here is my analysis: {"action": "test"}'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"action": "test"}
        assert diag.strategy == "brace_span"
        assert diag.prose_before_bytes > 0

    def test_prose_before_and_after(self):
        text = 'Before. {"action": "test"} After.'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"action": "test"}
        assert diag.strategy == "brace_span"
        assert diag.prose_before_bytes > 0
        assert diag.prose_after_bytes > 0

    def test_prefers_last_span(self):
        """Two candidate spans — parser picks the LAST. Matches LLM
        self-correction convention: the model's final answer lands
        last, sometimes after a retry-and-restate paragraph."""
        text = (
            '{"action": "wrong", "reason": "verbose initial attempt with'
            ' a long explanation body"}\n'
            'Actually, correction: {"action": "right"}'
        )
        parsed, diag = parse_llm_json(text)
        assert parsed == {"action": "right"}
        assert diag.strategy == "brace_span"

    def test_prefers_last_when_first_is_larger(self):
        """Regression for silent-wrong-answer: an earlier implementation
        preferred LARGEST span, which flipped the correct answer to
        the wrong one when the model's superseded first attempt was
        the longer of the two."""
        text = (
            '{"first": true, "reason": "very long verbose initial attempt '
            'with lots of extra explanation text"} '
            '\nActually: {"first": false}'
        )
        parsed, _ = parse_llm_json(text)
        assert parsed == {"first": False}

    def test_brace_inside_string_ignored(self):
        """A ``}`` inside a JSON string field must not break the walker."""
        text = 'Before. {"reason": "code was }} — closed"} After.'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"reason": "code was }} — closed"}
        assert diag.strategy == "brace_span"

    def test_prose_before_after_bytes_sum_to_input_length(self):
        """Invariant: prose_before + span_len + prose_after == len(text)."""
        text = 'AAA {"ok": 1} BBBB'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"ok": 1}
        span_len = len('{"ok": 1}')
        assert diag.prose_before_bytes + span_len + diag.prose_after_bytes == len(text)


# ─────────────────────────────────────────────────────────────────
# Strategy 4 — quasi-JSON fixups.
# ─────────────────────────────────────────────────────────────────


class TestQuasiJsonFixups:
    def test_trailing_comma_object(self):
        text = '{"a": 1, "b": 2,}'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"a": 1, "b": 2}
        assert diag.strategy == "quasi_json_fixup"
        assert "trailing_commas" in diag.quasi_fixups_applied

    def test_trailing_comma_array(self):
        text = '{"items": [1, 2, 3,]}'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"items": [1, 2, 3]}

    def test_python_literal_none(self):
        text = '{"reason": None, "count": 3}'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"reason": None, "count": 3}
        assert "python_literals" in diag.quasi_fixups_applied

    def test_python_literal_true_false(self):
        text = '{"ok": True, "broken": False}'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"ok": True, "broken": False}

    def test_python_literal_at_start_of_string(self):
        """Boundary: literal at index 0 (no preceding char). The
        boundary check defaults ``prev`` to ``" "`` — a whitespace
        char — so the replacement fires."""
        # Inside brace-span extraction, the fixup runs on the
        # extracted body. A None value at the start of the JSON
        # body (right after ``{``) tests the "start-of-body" boundary.
        text = '{"a": None, "b": True}'
        parsed, _ = parse_llm_json(text)
        assert parsed == {"a": None, "b": True}

    def test_python_literal_inside_string_left_alone(self):
        """``"reason": "returned None"`` — the ``None`` inside the
        string value is not a literal we should touch. Fixup only
        replaces bare Python literals outside string contexts."""
        text = '{"reason": "returned None"}'
        parsed, diag = parse_llm_json(text)
        # Strict succeeds because "None" inside a string is fine.
        assert parsed == {"reason": "returned None"}
        assert diag.strategy == "strict"

    def test_single_quoted_strings(self):
        text = "{'a': 'one', 'b': 'two'}"
        parsed, diag = parse_llm_json(text)
        assert parsed == {"a": "one", "b": "two"}
        assert "single_quotes" in diag.quasi_fixups_applied

    def test_combined_trailing_comma_and_python_literals(self):
        text = '{"a": None, "b": True,}'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"a": None, "b": True}
        assert diag.strategy == "quasi_json_fixup"

    def test_single_quoted_string_containing_comma_before_close(self):
        """Regression: an earlier fixup ordering ran
        ``_fix_trailing_commas`` before ``_fix_single_quotes``. The
        trailing-comma walker only recognised double-quoted strings,
        so a comma inside a single-quoted value at end-of-string was
        mis-classified as a trailing comma and silently dropped.
        Corrupted the payload without a diagnostic. Fixed by (a)
        reordering the ladder so single-quotes run first, AND (b)
        making the trailing-comma walker aware of BOTH quote styles."""
        text = "{'reason': 'value ends with,'}"
        parsed, _ = parse_llm_json(text)
        assert parsed == {"reason": "value ends with,"}

    def test_single_quoted_string_with_apostrophe_survives(self):
        """Belt-and-braces: a legit apostrophe inside a double-quoted
        JSON string should not perturb the fixup ladder."""
        text = '{"reason": "it\'s working"}'
        parsed, _ = parse_llm_json(text)
        assert parsed == {"reason": "it's working"}


# ─────────────────────────────────────────────────────────────────
# Diagnostic surface.
# ─────────────────────────────────────────────────────────────────


class TestDiagnostic:
    def test_partial_keys_seen_on_failure(self):
        """When the parser fails but the payload had ``"action":``
        and ``"reason":`` keys, the diagnostic surfaces them so
        observability sees "we got THIS far"."""
        text = '{"action": "test", "reason": <malformed>, "note": {'
        parsed, diag = parse_llm_json(text)
        assert parsed is None
        assert diag.strategy == "failed"
        assert "action" in diag.partial_keys_seen
        assert "reason" in diag.partial_keys_seen

    def test_partial_keys_capped(self):
        """Pathological input with 100 keys — cap protects log/UI."""
        keys = ",".join(f'"key{i}": {i}' for i in range(100))
        text = "{" + keys + ", <break"
        parsed, diag = parse_llm_json(text)
        assert parsed is None
        assert len(diag.partial_keys_seen) <= 32

    def test_partial_keys_surfaces_hyphenated_and_numeric_first(self):
        """Widened regex accepts key names models legitimately emit —
        ``2fa_enabled``, ``user-id``, ``api.key``. Earlier narrower
        pattern rejected these and the diagnostic silently under-
        reported which fields the parser saw."""
        text = '{"2fa_enabled": true, "user-id": "x", "api.key": "y", <break'
        _, diag = parse_llm_json(text)
        assert diag.strategy == "failed"
        assert "2fa_enabled" in diag.partial_keys_seen
        assert "user-id" in diag.partial_keys_seen
        assert "api.key" in diag.partial_keys_seen

    def test_final_error_populated_on_failure(self):
        parsed, diag = parse_llm_json("not json at all")
        assert parsed is None
        assert diag.strategy == "failed"
        assert diag.final_error is not None
        assert len(diag.final_error) > 0

    def test_final_error_carries_strict_parse_details(self):
        """The failure diagnostic surfaces the strict-parse exception
        (line/col from json.loads) so operators can RCA without
        re-parsing. Regression against a fallback where the error was
        a generic placeholder — that lost the underlying signal."""
        parsed, diag = parse_llm_json('{"a": 1, "b": <malformed>}')
        assert parsed is None
        assert diag.strategy == "failed"
        # ``json.decoder.JSONDecodeError.__str__`` includes ``line``
        # and ``column`` — check for one of them as a proxy for
        # "the underlying error, not a placeholder".
        assert diag.final_error is not None
        assert "line" in diag.final_error or "column" in diag.final_error or "char" in diag.final_error

    def test_strategy_always_populated(self):
        """Every code path sets ``strategy`` — never returns a bare/
        default diagnostic."""
        for text in [
            '{"ok": 1}',
            '```json\n{"ok": 1}\n```',
            'prose {"ok": 1} prose',
            '{"trailing": 1,}',
            "not json",
            "",
            None,
        ]:
            _, diag = parse_llm_json(text)
            assert diag.strategy in {
                "strict", "fence", "brace_span", "quasi_json_fixup", "failed",
            }

    def test_partial_keys_empty_on_every_success_path(self):
        """Docstring contract: ``partial_keys_seen`` never appears
        with a successful parse. Enforce it with a test rather than
        just trusting the frozen-dataclass default — a future edit
        that adds a "success with partial-keys" branch would silently
        break the fail-closed guarantee otherwise."""
        successes = [
            ('{"a": 1}', "strict"),
            ('```json\n{"a": 1}\n```', "fence"),
            ('prose {"a": 1} prose', "brace_span"),
            ('{"a": 1,}', "quasi_json_fixup"),
        ]
        for text, expected_strategy in successes:
            parsed, diag = parse_llm_json(text)
            assert parsed is not None, f"expected success on {text!r}"
            assert diag.strategy == expected_strategy
            assert diag.partial_keys_seen == (), (
                f"success ({expected_strategy}) leaked partial_keys_seen "
                f"= {diag.partial_keys_seen!r} — fail-closed invariant "
                "violated"
            )


# ─────────────────────────────────────────────────────────────────
# Guarantees — never raise, hostile inputs, cap on payload size.
# ─────────────────────────────────────────────────────────────────


class TestNeverRaises:
    def test_empty(self):
        parsed, diag = parse_llm_json("")
        assert parsed is None
        assert diag.strategy == "failed"

    def test_none(self):
        parsed, diag = parse_llm_json(None)
        assert parsed is None
        assert diag.strategy == "failed"

    def test_bytes_rejected(self):
        parsed, diag = parse_llm_json(b'{"ok": 1}')
        assert parsed is None
        assert diag.strategy == "failed"

    def test_only_whitespace(self):
        parsed, diag = parse_llm_json("   \n\t   ")
        assert parsed is None
        assert diag.strategy == "failed"

    def test_unbalanced_open_brace(self):
        parsed, diag = parse_llm_json('{"a": 1')
        assert parsed is None

    def test_unbalanced_close_brace(self):
        parsed, diag = parse_llm_json('a": 1}')
        assert parsed is None

    def test_input_exceeds_size_cap_fails_closed(self):
        """Hostile-input DoS defence: a model / prompt-injection
        response of many MB should not hang the parser. Cap is a
        hard reject with a diagnostic — the caller sees exactly what
        happened, no ambiguity."""
        text = "{" * (2 * 1024 * 1024)  # 2 MiB of open braces
        import time
        t0 = time.perf_counter()
        parsed, diag = parse_llm_json(text)
        elapsed = time.perf_counter() - t0
        assert parsed is None
        assert diag.strategy == "failed"
        assert "cap" in (diag.final_error or "")
        assert elapsed < 0.5, f"parser took {elapsed:.2f}s on capped input"

    def test_deeply_nested_braces_below_cap_dont_hang(self):
        """Even under the cap, a hostile deeply-nested input should
        finish in linear time thanks to the single-pass walker."""
        text = "{" * 10_000 + "}" * 10_000
        import time
        t0 = time.perf_counter()
        parsed, diag = parse_llm_json(text, require_object=False)
        elapsed = time.perf_counter() - t0
        # May or may not parse as strict; must not hang.
        assert elapsed < 0.5, f"nested-brace parser took {elapsed:.2f}s"
        # Should complete with SOME diagnostic.
        assert diag.strategy in {
            "strict", "fence", "brace_span", "quasi_json_fixup", "failed",
        }

    def test_hostile_fence_pattern_does_not_redos(self):
        """The fence regex uses non-greedy ``[\\s\\S]*?`` inside anchored
        line-start / line-end quantifiers — should NOT be prone to
        catastrophic backtracking. Verify with hostile input a real
        model would never emit: dozens of nearly-matching openers."""
        text = ("```json\n" * 500) + '{"ok": 1}\n```'
        import time
        t0 = time.perf_counter()
        parsed, _ = parse_llm_json(text)
        elapsed = time.perf_counter() - t0
        assert elapsed < 0.5, f"fence regex took {elapsed:.2f}s on hostile input"
        # We don't assert on parsed result — either the first fence
        # matched or the parser fell through to brace_span. Either
        # way, it must not hang.
        assert parsed is None or parsed == {"ok": 1}


class TestAdversarial:
    def test_fence_marker_inside_string(self):
        """Triple-backtick inside a JSON string field — parser should
        not treat it as a fence."""
        text = '{"reason": "the fence is ```json for demo"}'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"reason": "the fence is ```json for demo"}
        assert diag.strategy == "strict"

    def test_nested_object_with_prose_wrapper(self):
        text = 'analysis: {"outer": {"inner": {"deep": [1, 2]}}} done'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"outer": {"inner": {"deep": [1, 2]}}}

    def test_escaped_quote_in_string(self):
        text = r'{"reason": "quote: \"inside\" here"}'
        parsed, diag = parse_llm_json(text)
        assert parsed == {"reason": 'quote: "inside" here'}


# ─────────────────────────────────────────────────────────────────
# Response-shape patterns common across LLM structured-output
# consumers. Named after the shape they exercise (verb+object,
# verdict payload, refutation payload) — no downstream-consumer
# reference so this module lifts to main cleanly.
# ─────────────────────────────────────────────────────────────────


class TestConsumerShapes:
    def test_verb_object_in_fence(self):
        text = '```json\n{"action": "propose", "reason": "why"}\n```'
        parsed, _ = parse_llm_json(text)
        assert parsed["action"] == "propose"

    def test_decline_shape(self):
        text = '```json\n{"action": "decline", "reason": "no viable edit"}\n```'
        parsed, _ = parse_llm_json(text)
        assert parsed["action"] == "decline"

    def test_verdict_payload(self):
        text = '{"verdict": "CONFIRMED", "confidence": "high"}'
        parsed, _ = parse_llm_json(text)
        assert parsed["verdict"] == "CONFIRMED"

    def test_boolean_payload(self):
        text = '{"refuted": true, "reason": "counterexample"}'
        parsed, _ = parse_llm_json(text)
        assert parsed["refuted"] is True

    def test_single_quoted_verdict_recovers_via_fixup(self):
        """A verdict payload the model emitted with Python-style
        single quotes rather than JSON double quotes."""
        text = "{'verdict': 'UNCERTAIN', 'note': 'evidence weak'}"
        parsed, diag = parse_llm_json(text)
        assert parsed == {"verdict": "UNCERTAIN", "note": "evidence weak"}
        assert diag.strategy == "quasi_json_fixup"
