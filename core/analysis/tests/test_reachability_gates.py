"""Tests for core.analysis.reachability_gates — generic finding gates."""

import json
import sys
from pathlib import Path
from typing import ClassVar

# core/inventory/tests/ → repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

import core.analysis.reachability_gates as rg
from core.analysis.reachability_gates import (
    _prose_only,
    build_sink_reachable_set,
    compute_demotion_verdict,
    has_safety_self_contradiction,
    is_conduit_candidate,
    is_entry_unreachable,
    query_sink_arg_index,
    query_unguarded_sinks,
)

# ─── build_sink_reachable_set ────────────────────────────────────────────────


class TestBuildSinkReachableSet:
    def test_none_context_map(self):
        assert build_sink_reachable_set(None) is None

    def test_no_call_edges(self):
        assert build_sink_reachable_set({"sinks": [{"function": "f"}]}) is None

    def test_transitive_reach(self):
        cm = {
            "sinks": [{"function": "dangerous_handler"}],
            "call_edges": [
                {"caller": "main", "callee": "parse"},
                {"caller": "parse", "callee": "dangerous_handler"},
            ],
        }
        reachable = build_sink_reachable_set(cm)
        assert "main" in reachable
        assert "parse" in reachable
        assert "dangerous_handler" in reachable

    def test_libc_sinks_auto_seeded(self):
        cm = {
            "sinks": [],
            "call_edges": [
                {"caller": "copy_data", "callee": "memcpy"},
                {"caller": "main", "callee": "copy_data"},
            ],
        }
        reachable = build_sink_reachable_set(cm)
        assert "memcpy" in reachable
        assert "copy_data" in reachable
        assert "main" in reachable

    def test_unreachable_function(self):
        cm = {
            "sinks": [{"function": "sink"}],
            "call_edges": [
                {"caller": "caller_a", "callee": "sink"},
                {"caller": "isolated", "callee": "helper"},
            ],
        }
        reachable = build_sink_reachable_set(cm)
        assert "caller_a" in reachable
        assert "isolated" not in reachable


# ─── is_entry_unreachable ────────────────────────────────────────────────────


class TestIsEntryUnreachable:
    def test_no_context_map(self):
        assert is_entry_unreachable("f", None) is False

    def test_no_call_edges(self):
        assert is_entry_unreachable("f", {"entry_points": []}) is False

    def test_entry_point_not_unreachable(self):
        cm = {
            "entry_points": [{"name": "main"}],
            "call_edges": [{"caller": "main", "callee": "parse"}],
        }
        assert is_entry_unreachable("main", cm) is False

    def test_called_function_not_unreachable(self):
        cm = {
            "entry_points": [{"name": "main"}],
            "call_edges": [{"caller": "main", "callee": "parse"}],
        }
        assert is_entry_unreachable("parse", cm) is False

    def test_orphan_function_is_unreachable(self):
        cm = {
            "entry_points": [{"name": "main"}],
            "call_edges": [{"caller": "main", "callee": "parse"}],
        }
        assert is_entry_unreachable("orphan_fn", cm) is True

    def test_no_entry_points_never_unreachable(self):
        cm = {
            "entry_points": [],
            "call_edges": [{"caller": "a", "callee": "b"}],
        }
        assert is_entry_unreachable("orphan_fn", cm) is False


# ─── is_conduit_candidate ────────────────────────────────────────────────────


class TestIsConduitCandidate:
    def test_mentions_dangerous_call(self):
        assert is_conduit_candidate("passes input to strcpy( dest, src)") is True

    def test_mentions_memcpy_call(self):
        assert is_conduit_candidate("calls memcpy(dst, src, n) without bounds") is True

    def test_conduit_phrase(self):
        assert is_conduit_candidate("forwards data to the downstream handler") is True

    def test_local_logic_bug(self):
        assert is_conduit_candidate(
            "off-by-one in null terminator write at dst[di]"
        ) is False

    def test_word_execution_not_matched(self):
        assert is_conduit_candidate(
            "leads to arbitrary code execution via buffer overflow"
        ) is False

    def test_word_query_not_matched(self):
        assert is_conduit_candidate(
            "decodes URL-encoded query string characters"
        ) is False


# ─── compute_demotion_verdict ────────────────────────────────────────────────


class TestComputeDemotionVerdict:
    def test_entry_unreachable_fires_first(self):
        cm = {
            "entry_points": [{"name": "main"}],
            "call_edges": [{"caller": "main", "callee": "parse"}],
        }
        verdict = compute_demotion_verdict("orphan", "calls strcpy(", cm)
        assert verdict is not None
        assert "entry-unreachability" in verdict

    def test_no_demotion_for_reachable_function(self):
        cm = {
            "entry_points": [{"name": "main"}],
            "call_edges": [
                {"caller": "main", "callee": "parse"},
                {"caller": "parse", "callee": "memcpy"},
            ],
            "sinks": [{"function": "memcpy"}],
        }
        verdict = compute_demotion_verdict("parse", "local logic bug", cm)
        assert verdict is None

    def test_self_contradiction_fires(self):
        cm = {
            "entry_points": [{"name": "banner"}],
            "call_edges": [
                {"caller": "banner", "callee": "memcpy"},
            ],
            "sinks": [{"function": "memcpy"}],
        }
        verdict = compute_demotion_verdict(
            "banner",
            "copies a fixed-size static string into a caller-provided buffer",
            cm,
        )
        assert verdict is not None
        assert "self-contradiction" in verdict

    def test_guarded_sink_evidence_names_tested_sinks(self):
        """The demotion string must record WHICH sinks the guarded
        verdict covered — it tests a curated subset, not all of
        DANGEROUS_LIBC_SINKS, and the suppression must be auditable
        against that list."""
        cm = {
            "entry_points": [{"name": "main"}],
            "call_edges": [
                {"caller": "main", "callee": "parse"},
                {"caller": "parse", "callee": "memcpy"},
            ],
            "sinks": [{"function": "memcpy"}],
        }
        server = _FakeJoernServer(raw_output="2/2")
        verdict = compute_demotion_verdict(
            "parse", "copies input with memcpy(", cm, joern_server=server,
        )
        assert verdict is not None
        assert "guarded-sink" in verdict
        assert "tested sinks:" in verdict
        for name in rg.guard_tested_sinks():
            assert name in verdict
        # Names the verdict does NOT cover must not be claimed.
        assert "sqlite3_exec" not in verdict

    def test_sink_unreachable_conduit(self):
        cm = {
            "entry_points": [{"name": "main"}],
            "call_edges": [
                {"caller": "main", "callee": "wrapper"},
                {"caller": "handler", "callee": "memcpy"},
            ],
            "sinks": [{"function": "memcpy"}],
        }
        verdict = compute_demotion_verdict(
            "wrapper", "passes input to strcpy( dest, src)", cm,
        )
        assert verdict is not None
        assert "sink-unreachability" in verdict


# ─── has_safety_self_contradiction ──────────────────────────────────────────


class TestHasSafetySelfContradiction:
    def test_fixed_size_static_string(self):
        body = "copies a fixed-size static string kBanner into a caller buffer"
        assert has_safety_self_contradiction(body) is True

    def test_saturating_arithmetic(self):
        body = "implements saturating subtraction, correctly returning zero"
        assert has_safety_self_contradiction(body) is True

    def test_correctly_bounded(self):
        body = "the function correctly bounded the output to MAX_LEN bytes"
        assert has_safety_self_contradiction(body) is True

    def test_cannot_overflow(self):
        body = "the copy size is capped so it cannot overflow the destination"
        assert has_safety_self_contradiction(body) is True

    def test_hypothetical_caller_violation(self):
        body = "if a caller violates this contract and provides a smaller buffer"
        assert has_safety_self_contradiction(body) is True

    def test_hypothetical_caller_provides(self):
        body = "if a caller provides a buffer smaller than N, overflow occurs"
        assert has_safety_self_contradiction(body) is True

    def test_real_bug_no_bounds(self):
        body = "does not check output bounds, allowing overflow"
        assert has_safety_self_contradiction(body) is False

    def test_real_bug_format_string(self):
        body = "attacker-controlled path in format string passed to snprintf"
        assert has_safety_self_contradiction(body) is False

    def test_real_bug_fixed_size_buffer(self):
        body = "strcpy overflows the fixed-size stack buffer"
        assert has_safety_self_contradiction(body) is False

    def test_negation_not_correctly(self):
        body = "the function does not correctly implement bounds checking"
        assert has_safety_self_contradiction(body) is False

    def test_negation_however_before(self):
        body = "However, the function correctly handles input validation"
        assert has_safety_self_contradiction(body) is False

    def test_negation_fails_to(self):
        body = "The function fails to correctly validate the input length"
        assert has_safety_self_contradiction(body) is False

    def test_negation_without_bounded(self):
        body = "without correctly bounded checks on the size parameter"
        assert has_safety_self_contradiction(body) is False

    def test_specific_caller_not_hypothetical(self):
        body = "The caller handle_connection provides untrusted data directly"
        assert has_safety_self_contradiction(body) is False

    def test_correctly_handles_is_not_safety_assertion(self):
        body = "The function correctly handles content-type but path is not normalized before fopen"
        assert has_safety_self_contradiction(body) is False

    def test_properly_validates_is_not_safety_assertion(self):
        body = "The function properly validates using normalize_path but this happens after fopen"
        assert has_safety_self_contradiction(body) is False

    def test_correctly_implements_is_not_safety_assertion(self):
        body = "The function correctly implements response formatting but the path is attacker-controlled"
        assert has_safety_self_contradiction(body) is False


# ─── Prose-only scoping of the text-based gates ──────────────────────────────


class TestProseOnlyScoping:
    """Quoted target content cannot plant demotion triggers — only
    prose is scanned by the text-based gates."""

    def test_prose_assertion_still_fires(self):
        assert has_safety_self_contradiction(
            "The copy is correctly bounded by the length check."
        )

    def test_negated_prose_still_suppressed(self):
        assert not has_safety_self_contradiction(
            "The copy is not correctly bounded."
        )

    def test_fenced_code_does_not_fire(self):
        body = (
            "Overflow when len exceeds the buffer.\n"
            "```c\n"
            "/* this buffer is correctly bounded */\n"
            "memcpy(dst, src, len);\n"
            "```\n"
        )
        assert not has_safety_self_contradiction(body)

    def test_unterminated_fence_stripped_to_end(self):
        body = "Overflow here.\n```\ncorrectly bounded forever"
        assert not has_safety_self_contradiction(body)

    def test_inline_code_does_not_fire(self):
        body = (
            "The comment `// correctly bounded` is wrong: "
            "len is attacker-controlled."
        )
        assert not has_safety_self_contradiction(body)

    def test_quote_line_does_not_fire(self):
        body = (
            "Overflow when len exceeds the buffer.\n"
            "> the code claims the value cannot overflow\n"
        )
        assert not has_safety_self_contradiction(body)

    def test_conduit_prose_still_fires(self):
        assert is_conduit_candidate(
            "The wrapper passes user input to memcpy(dst, src, n)."
        )

    def test_conduit_code_block_does_not_fire(self):
        body = (
            "Local off-by-one in the loop bound.\n"
            "```c\nmemcpy(dst, src, n);\n```\n"
        )
        assert not is_conduit_candidate(body)

    def test_prose_only_keeps_surrounding_prose(self):
        stripped = _prose_only("before `code` after")
        assert "before" in stripped
        assert "after" in stripped
        assert "code" not in stripped


# ─── Joern caller override for entry-unreachability ─────────────────────────


class _FakeJoernServer:
    """Minimal stub for JoernServer that returns controlled query results."""

    def __init__(self, raw_output="", errors=None, alive=True):
        self._raw_output = raw_output
        self._errors = errors or []
        self._alive = alive

    def is_alive(self):
        return self._alive

    def query(self, cpgql, *, timeout=30, validate=False):
        class _Result:
            pass
        r = _Result()
        r.raw_output = self._raw_output
        r.errors = self._errors
        return r


class TestEntryUnreachableJoernOverride:
    """Joern caller query prevents false entry-unreachability demotions."""

    _cm: ClassVar[dict] = {
        "entry_points": [{"name": "main"}],
        "call_edges": [{"caller": "main", "callee": "parse"}],
    }

    def test_unreachable_without_joern(self):
        assert is_entry_unreachable("orphan", self._cm) is True

    def test_joern_callers_override_unreachability(self):
        stdout = 'JOERN_CALLER:{"caller":"dispatch","file":"src/dispatch.c","line":42,"code":"orphan(buf)"}'
        server = _FakeJoernServer(raw_output=stdout)
        assert is_entry_unreachable("orphan", self._cm, joern_server=server) is False

    def test_joern_no_callers_stays_unreachable(self):
        server = _FakeJoernServer(raw_output="")
        assert is_entry_unreachable("orphan", self._cm, joern_server=server) is True

    def test_joern_error_stays_unreachable(self):
        server = _FakeJoernServer(raw_output="", errors=["timeout"])
        assert is_entry_unreachable("orphan", self._cm, joern_server=server) is True

    def test_joern_dead_server_stays_unreachable(self):
        server = _FakeJoernServer(alive=False)
        assert is_entry_unreachable("orphan", self._cm, joern_server=server) is True


# ─── query_unguarded_sinks ──────────────────────────────────────────────────


class TestQueryUnguardedSinks:
    def test_none_server(self):
        assert query_unguarded_sinks("fn", None) == []

    def test_dead_server(self):
        server = _FakeJoernServer(alive=False)
        assert query_unguarded_sinks("fn", server) == []

    def test_invalid_function_name(self):
        server = _FakeJoernServer()
        assert query_unguarded_sinks("fn; rm -rf", server) == []


class TestQuerySinkArgIndex:
    def test_none_server(self):
        assert query_sink_arg_index("fn", "memcpy", None) == []

    def test_dead_server(self):
        server = _FakeJoernServer(alive=False)
        assert query_sink_arg_index("fn", "memcpy", server) == []

    def test_invalid_sink_name(self):
        server = _FakeJoernServer()
        assert query_sink_arg_index("fn", "sink; bad", server) == []


# ─── _joern_find_callers reads its query from _QUERIES_DIR ───────────────────


class _RecordingJoernServer:
    """Joern server stub that records every query it receives."""

    def __init__(self):
        self.queries: list[str] = []

    def is_alive(self) -> bool:
        return True

    def query(self, query: str, timeout: int = 0, validate: bool = False):
        self.queries.append(query)

        class _Result:
            errors = None
            raw_output = (
                "JOERN_CALLER:" + json.dumps({"caller": "main"}) + "\n"
            )

        return _Result()


class TestJoernCallersQueriesDir:
    def test_reads_query_from_queries_dir(self, tmp_path, monkeypatch):
        # The module constant is the single authority for the query
        # path; redirecting it redirects the lookup.
        (tmp_path / "callers.sc").write_text(
            "cpg.method.name(\"__FUNCTION__\")", encoding="utf-8",
        )
        monkeypatch.setattr(rg, "_QUERIES_DIR", tmp_path)
        server = _RecordingJoernServer()
        callers = rg._joern_find_callers("target_fn", server)
        assert callers == [{"caller": "main"}]
        assert server.queries == ['cpg.method.name("target_fn")']

    def test_missing_query_file_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rg, "_QUERIES_DIR", tmp_path / "absent")
        server = _RecordingJoernServer()
        assert rg._joern_find_callers("target_fn", server) == []
        assert server.queries == []


# ─── Single-sourced sink vocabulary (drift guards) ───────────────────────────


class TestSinkVocabularySingleSource:
    """The regex and both Joern query sink lists derive from one authority."""

    def test_conduit_regex_matches_every_authority_name(self):
        from core.analysis import reachability_gates as rg

        for name in rg.DANGEROUS_LIBC_SINKS:
            assert rg._CONDUIT_CALL_RE.search(f"calls {name}(buf, n)"), name

    def test_conduit_regex_preserves_pre_derivation_coverage(self):
        # The hand-written regex covered exec-family variants the set
        # lacked; the set was expanded to the union so the derived
        # regex loses nothing.
        from core.analysis import reachability_gates as rg

        for name in ("fgets", "gets", "execl", "execle", "execv",
                     "execve", "execvp", "execvpe", "execlp", "execlpe"):
            assert rg._CONDUIT_CALL_RE.search(f"{name}(x)"), name
        assert not rg._CONDUIT_CALL_RE.search("my_memcpy_wrapper(x)")
        assert not rg._CONDUIT_CALL_RE.search("memcpy_s(x)")

    def test_query_sink_lists_are_authority_subsets(self):
        from core.analysis import reachability_gates as rg

        assert set(rg._CORE_QUERY_SINKS) <= rg.DANGEROUS_LIBC_SINKS
        # fopen/open are the documented unguarded-query extras.
        assert set(rg._UNGUARDED_QUERY_SINKS) - rg.DANGEROUS_LIBC_SINKS == {
            "fopen", "open",
        }
        # The public evidence accessor exposes exactly the tested list.
        assert rg.guard_tested_sinks() == rg._CORE_QUERY_SINKS

    def test_guard_query_renders_pre_split_literal(self):
        from core.analysis import reachability_gates as rg

        rendered = rg._GUARD_QUERY_TEMPLATE.replace(
            "__SINK_NAMES__", rg._scala_string_list(rg._CORE_QUERY_SINKS),
        )
        assert (
            'val sinkNames = List("memcpy", "memmove", "strcpy", "strcat", '
            '"sprintf", "gets", "strncpy", "strncat", "snprintf", "system", '
            '"popen", "execve", "execvp")'
        ) in rendered

    def test_unguarded_sc_renders_pre_split_literal(self):
        from core.analysis import reachability_gates as rg

        sc = (rg._QUERIES_DIR / "unguarded_sinks.sc").read_text()
        assert "__SINK_NAMES__" in sc
        # No leftover hardcoded sink names in the template file.
        assert '"memcpy"' not in sc
        rendered = sc.replace(
            "__SINK_NAMES__",
            rg._scala_string_list(rg._UNGUARDED_QUERY_SINKS),
        )
        assert (
            'val sinkNames = List("memcpy", "memmove", "strcpy", "strcat", '
            '"sprintf", "gets", "strncpy", "strncat", "snprintf", "system", '
            '"popen", "execve", "execvp", "fopen", "open")'
        ) in rendered
