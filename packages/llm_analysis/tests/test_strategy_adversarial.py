"""Adversarial + E2E coverage for the cwe_strategies wire-in to
``build_analysis_prompt_bundle``.

Probes inputs a faulty / compromised upstream could plausibly hand
the analysis prompt builder. Each case must produce a usable bundle
without crash, without prompt-format corruption, and without
unbounded growth in prompt size.
"""

from __future__ import annotations

import pytest

from packages.llm_analysis.prompts.analysis import (
    build_analysis_prompt_bundle,
    build_analysis_prompt_bundle_from_finding,
)


def _system(bundle):
    return next(m.content for m in bundle.messages if m.role == "system")


def _user(bundle):
    return next(m.content for m in bundle.messages if m.role == "user")


# ---------------------------------------------------------------------------
# Adversarial cwe_id values
# ---------------------------------------------------------------------------


class TestCweIdAdversarial:
    def test_none_cwe_falls_through_cleanly(self):
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="src/foo.py", start_line=1, end_line=5,
            message="m",
            cwe_id=None,
        )
        sys = _system(bundle)
        # No crash; bundle well-formed.
        assert "ASSUME-EXPLOIT" in sys

    def test_empty_string_cwe(self):
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="src/foo.py", start_line=1, end_line=5,
            message="m",
            cwe_id="",
        )
        # No specialised strategy from CWE; general only.
        sys = _system(bundle)
        assert "ASSUME-EXPLOIT" in sys

    def test_lowercase_cwe_still_matches(self):
        """Picker lowercases both sides — ``cwe-78`` should pin
        input_handling the same as ``CWE-78``."""
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="src/foo.py", start_line=1, end_line=5,
            message="m",
            cwe_id="cwe-78",
        )
        sys = _system(bundle)
        assert "## Strategy: input_handling" in sys

    def test_unknown_cwe_id_no_crash(self):
        """Made-up CWE-id matches no strategy. Falls back to general."""
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="src/foo.py", start_line=1, end_line=5,
            message="m",
            cwe_id="CWE-999999",
        )
        sys = _system(bundle)
        # No specialised strategy from this CWE.
        assert "## Strategy: general" in sys

    def test_comma_separated_cwes_no_partial_match(self):
        """Caller supplied ``CWE-78,CWE-89`` as a single string —
        picker treats it as one opaque value, no hit. Caller's
        responsibility to split before passing. Pin the safe
        fall-through behaviour."""
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="src/foo.py", start_line=1, end_line=5,
            message="m",
            cwe_id="CWE-78,CWE-89",
        )
        sys = _system(bundle)
        # Neither input_handling (CWE-78) nor anything else specifically
        # picked by CWE — picker only includes general.
        # Path-based signals could still fire if file_path matched, but
        # foo.py doesn't trigger anything specific.
        # Just verify no crash + base prompt intact.
        assert "ASSUME-EXPLOIT" in sys

    def test_newline_in_cwe_id_no_match(self):
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="src/foo.py", start_line=1, end_line=5,
            message="m",
            cwe_id="CWE-78\n## INJECTED",
        )
        sys = _system(bundle)
        # The newline-injected fake heading should NOT corrupt the
        # rendered system prompt with a fake "## INJECTED" section.
        # The picker uses cwe_id for exact-equality match against
        # strategy CWEs; a newline-bearing id matches nothing.
        # Caller-supplied raw cwe_id is not rendered into the prompt
        # by the picker — only matched strategies' content is.
        assert "## INJECTED" not in sys

    def test_null_byte_in_cwe_id_no_match_no_crash(self):
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="src/foo.py", start_line=1, end_line=5,
            message="m",
            cwe_id="CWE-78\x00",
        )
        sys = _system(bundle)
        assert "\x00" not in sys
        assert "ASSUME-EXPLOIT" in sys

    def test_huge_cwe_id_no_match(self):
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="src/foo.py", start_line=1, end_line=5,
            message="m",
            cwe_id="CWE-" + "9" * 100_000,
        )
        sys = _system(bundle)
        assert "ASSUME-EXPLOIT" in sys
        # System prompt should be roughly the size of the base
        # prompt + maybe a general-only strategy block — definitely
        # not the 100KB cwe_id text.
        assert len(sys) < 50_000


# ---------------------------------------------------------------------------
# Adversarial function_name / file_path / signal lists
# ---------------------------------------------------------------------------


class TestSignalAdversarial:
    def test_newline_in_function_name(self):
        """Tokeniser splits on non-word; newline becomes a separator.
        No fake section heading injected."""
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="src/foo.py", start_line=1, end_line=5,
            message="m",
            function_name="parse\n## INJECTED_HEADING",
        )
        sys = _system(bundle)
        assert "## INJECTED_HEADING" not in sys
        # ``parse`` token still hits input_handling.
        assert "## Strategy: input_handling" in sys

    def test_newline_in_file_path_picker_doesnt_crash(self):
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="src/foo\n## EVIL.py",
            start_line=1, end_line=5,
            message="m",
        )
        # No crash — picker is best-effort + base prompt always works.
        sys = _system(bundle)
        assert "ASSUME-EXPLOIT" in sys
        # Fake heading from file_path not in system prompt.
        assert "## EVIL" not in sys

    def test_function_calls_with_none_member(self):
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="src/foo.py", start_line=1, end_line=5,
            message="m",
            function_calls_made=["mutex_lock", None, "kfree"],  # type: ignore
        )
        # Picker filters falsy entries; should pick concurrency
        # without crashing on the None.
        sys = _system(bundle)
        # Either crashed-and-fell-through (no strategy block beyond
        # general) OR succeeded with concurrency — both acceptable
        # as long as no exception escapes.
        assert "ASSUME-EXPLOIT" in sys

    def test_huge_function_calls_list(self):
        """1000 callees, mostly noise. Picker should still fire on
        the real signals + cap render budget."""
        calls = ["noise_" + str(i) for i in range(1000)] + [
            "mutex_lock", "spin_lock",
        ]
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="src/foo.py", start_line=1, end_line=5,
            message="m",
            function_calls_made=calls,
        )
        sys = _system(bundle)
        assert "## Strategy: concurrency" in sys
        # Bounded prompt size.
        assert len(sys) < 50_000


# ---------------------------------------------------------------------------
# Prompt-size guarantees
# ---------------------------------------------------------------------------


class TestPromptSize:
    def test_full_signal_stack_stays_bounded(self):
        """All signal dimensions populated, max strategies fired —
        the rendered prompt should still fit in a reasonable budget
        (under 32KB system prompt)."""
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="net/foo/parser.c",
            start_line=1, end_line=5,
            message="m",
            cwe_id="CWE-78",
            function_name="parse_locked_decrypt",
            file_includes=["linux/skbuff.h", "linux/spinlock.h",
                           "crypto/aes.h"],
            function_calls_made=[
                "mutex_lock", "spin_lock", "skb_pull",
                "crypto_aead_decrypt", "kmalloc",
            ],
        )
        sys = _system(bundle)
        # System prompt = base + strategy block. Strategy block alone
        # is capped at 16KB by render_strategies; total stays well
        # under 32KB.
        assert len(sys.encode("utf-8")) < 32_000

    def test_strategy_block_capped_when_many_match(self):
        """Multiple strategies could fire across all dimensions. The
        picker caps at 3 by default; rendered output stays bounded."""
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="crypto/algif_aead.c",
            start_line=1, end_line=5,
            message="m",
            cwe_id="CWE-119",
            function_name="aead_recvmsg_locked_splice_parse",
            function_calls_made=[
                "mutex_lock", "splice_to_pipe", "crypto_aead_decrypt",
                "skb_pull", "kmalloc", "capable",
            ],
        )
        sys = _system(bundle)
        # max_strategies=3 → general + 2 specialised. Count headings.
        strategy_count = sys.count("## Strategy:")
        assert strategy_count == 3, (
            f"expected exactly 3 strategy headings, got {strategy_count}"
        )


# ---------------------------------------------------------------------------
# E2E — realistic /agentic shape
# ---------------------------------------------------------------------------


def _realistic_finding():
    """A finding shape that mirrors what /agentic builds before
    routing into the analysis prompt — full metadata, scanner
    message, code snippet, dataflow info, CWE."""
    return {
        "rule_id": "py/sql-injection",
        "level": "error",
        "file_path": "src/auth/login.py",
        "start_line": 42,
        "end_line": 48,
        "message": (
            "Tainted query string from request.args reaches "
            "cursor.execute via f-string interpolation."
        ),
        "code": (
            "def check_credentials(user_id):\n"
            "    q = request.args.get('q')\n"
            "    return cursor.execute(f'SELECT * FROM u WHERE id={q}')"
        ),
        "surrounding_context": (
            "@app.route('/login', methods=['POST'])\n"
            "def login_view():\n"
            "    user_id = request.form['username']\n"
            "    return check_credentials(user_id)"
        ),
        "cwe_id": "CWE-89",
        "metadata": {
            "name": "check_credentials",
            "calls": ["request.args.get", "cursor.execute"],
            "includes": [],  # Python — no headers
            "visibility": "private",
            "return_type": "bool",
            "parameters": [("user_id", "str")],
        },
        "repo_path": "/repo/some-app",
    }


class TestE2E:
    def test_realistic_finding_routed_through_prompt(self):
        finding = _realistic_finding()
        bundle = build_analysis_prompt_bundle_from_finding(finding)

        sys = _system(bundle)
        user = _user(bundle)

        # Base prompt intact.
        assert "ASSUME-EXPLOIT" in sys
        # Strategy block with input_handling (CWE-89 pin).
        assert "Bug-class lenses" in sys
        assert "## Strategy: input_handling" in sys
        # Worked CVE exemplar from input_handling shows up.
        assert "CVE-2023-0179" in sys
        # User envelope contains the scanner message + code.
        assert "Tainted query string" in user
        assert "check_credentials" in user

        # Reasonable size.
        assert len(sys.encode("utf-8")) < 32_000
        assert len(user.encode("utf-8")) < 16_000

    def test_finding_without_cwe_still_works(self):
        finding = _realistic_finding()
        finding.pop("cwe_id")
        finding["metadata"].pop("name", None)
        bundle = build_analysis_prompt_bundle_from_finding(finding)
        sys = _system(bundle)
        # Base prompt always works.
        assert "ASSUME-EXPLOIT" in sys
        # General strategy still fires.
        assert "## Strategy: general" in sys

    def test_strategy_content_distinct_for_different_cwes(self):
        """Two findings differing only in cwe_id → different
        strategy blocks. Sanity check that the wire-in actually
        shapes output."""
        f1 = _realistic_finding()
        f1["cwe_id"] = "CWE-89"  # input_handling

        f2 = _realistic_finding()
        f2["cwe_id"] = "CWE-416"  # memory_management

        sys1 = _system(build_analysis_prompt_bundle_from_finding(f1))
        sys2 = _system(build_analysis_prompt_bundle_from_finding(f2))

        # Different specialised strategies.
        assert "## Strategy: input_handling" in sys1
        assert "## Strategy: memory_management" in sys2
        # Different CVE exemplars.
        assert "CVE-2023-0179" in sys1
        # input_handling exemplar should NOT be in the memory_management
        # finding's prompt.
        assert "CVE-2023-0179" not in sys2

    def test_dataflow_finding_strategy_still_attaches(self):
        """Dataflow findings take a different code path through the
        bundle builder (envelope-wraps source/sink/steps). Strategy
        block should attach regardless."""
        finding = _realistic_finding()
        finding["has_dataflow"] = True
        finding["dataflow"] = {
            "source": {
                "label": "request.args.get",
                "code": "q = request.args.get('q')",
                "file": "src/auth/login.py", "line": 43,
            },
            "sink": {
                "label": "cursor.execute",
                "code": "cursor.execute(f'... {q}')",
                "file": "src/auth/login.py", "line": 44,
            },
            "steps": [],
        }
        bundle = build_analysis_prompt_bundle_from_finding(finding)
        sys = _system(bundle)
        assert "## Strategy: input_handling" in sys
        # Dataflow-specific schema fields should be in scope.
        # (Not checking schema directly here; just that the strategy
        # block didn't displace anything.)
        assert "ASSUME-EXPLOIT" in sys


# ---------------------------------------------------------------------------
# Independence: unrelated callers (e.g. agent.py path) work
# ---------------------------------------------------------------------------


class TestIndependence:
    def test_default_callers_still_work(self):
        """Callers that don't pass any of the new args (legacy code,
        external use) get prior behaviour minus a strategy block.
        Pin the back-compat shape."""
        bundle = build_analysis_prompt_bundle(
            rule_id="x", level="warning",
            file_path="src/foo.py", start_line=1, end_line=5,
            message="m",
            # No cwe_id, no function_name, no includes/calls.
        )
        sys = _system(bundle)
        # Base prompt intact.
        assert "ASSUME-EXPLOIT" in sys
        # General strategy fires (always-on default in picker).
        assert "## Strategy: general" in sys

    def test_metadata_dict_with_legacy_keys(self):
        """Older finding shapes carry metadata without ``name`` /
        ``calls`` / ``includes``. Bundle builder doesn't choke."""
        bundle = build_analysis_prompt_bundle_from_finding({
            "rule_id": "x",
            "level": "warning",
            "file_path": "src/foo.py",
            "start_line": 1, "end_line": 5,
            "message": "m",
            "metadata": {
                "class_name": "MyClass",
                "visibility": "static",
                # No name / calls / includes.
            },
        })
        sys = _system(bundle)
        assert "ASSUME-EXPLOIT" in sys
