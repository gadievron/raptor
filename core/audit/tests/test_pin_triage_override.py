"""Pin-vs-triage-skip precedence + indirect-call triage awareness.

Replays the v4 head-to-head shape: ``ssl/ssl_sess.c:remove_session_lock``
was operator-pinned (``--pin``) yet the triage classifier skipped it
("no sink path, no dangerous callees, small"). Two defects:

1. A pin is an explicit review order — the review loop's triage-skip
   gate must not drop pinned gaps.
2. The function invokes ``ctx->remove_session_cb(ctx, c)`` — a call
   through a function-pointer field. In C that callee set is
   statically unknowable, so "no sink path / no dangerous callees" was
   never trustworthy evidence for it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.audit.gaps import hoist_pins
from core.audit.triage import TriageBucket, classify_all, classify_function

# The v4 shape, trimmed: an indirect call through a function-pointer
# struct field plus ordinary direct calls, none of them catalog sinks.
_SSL_SESS_SNIPPET = """
static int remove_session_lock(SSL_CTX *ctx, SSL_SESSION *c, int lck)
{
    SSL_SESSION *r;
    int ret = 0;

    if ((c != NULL) && (c->session_id_length != 0)) {
        if ((r = lh_SSL_SESSION_retrieve(ctx->sessions, c)) != NULL) {
            ret = 1;
            r = lh_SSL_SESSION_delete(ctx->sessions, r);
            SSL_SESSION_list_remove(ctx, r);
        }
        c->not_resumable = 1;

        if (ctx->remove_session_cb != NULL)
            ctx->remove_session_cb(ctx, c);

        if (ret)
            SSL_SESSION_free(r);
    }
    return ret;
}

static int plain_helper(int x)
{
    return local_transform(x);
}
"""


class TestPinnedGapNeverTriageSkipped:
    def _gaps(self):
        return [
            {"file": "a.c", "name": "high", "priority": 0, "sloc": 50},
            {"file": "ssl/ssl_sess.c", "name": "remove_session_lock",
             "priority": 3, "sloc": 27},
        ]

    def test_hoist_pins_marks_pinned(self):
        out = hoist_pins(self._gaps(), ["ssl/ssl_sess.c:remove_session_lock"])
        assert out[0]["name"] == "remove_session_lock"
        assert out[0].get("pinned") is True
        assert not out[1].get("pinned")

    def test_unpinned_gaps_not_marked(self):
        gaps = self._gaps()
        out = hoist_pins(gaps, None)
        assert all(not g.get("pinned") for g in out)

    def test_review_loop_wiring_pin_overrides_skip(self):
        """The triage-skip gate in review_one_function bypasses pinned
        gaps with a loud warning (source-level wiring check — the
        heavy review_one_function scaffolding is exercised in
        integration tests, mirroring TestReviewOneFunctionTimeoutPath)."""
        src = (Path(__file__).resolve().parents[1]
               / "orchestrator.py").read_text()
        idx = src.find("def review_one_function")
        assert idx != -1
        end = src.find("\ndef ", idx)
        window = src[idx:end if end != -1 else len(src)]
        # The pin-override branch precedes the skip gate and neuters it.
        override = window.find('gap.get("pinned")')
        skip_gate = window.find('triage.bucket == TriageBucket.SKIP '
                                'and not gap.get("force_review")')
        assert override != -1, "pin override branch missing"
        assert skip_gate != -1, "triage skip gate missing"
        assert override < skip_gate
        assert "--pin override" in window  # the loud note


class TestIndirectCallTriageAwareness:
    def test_v4_shape_callback_target_never_skipped(self):
        # Exact v4 signal shape: small, sink-unreachable, no dangerous
        # callees — but registered as a callback / invoked indirectly.
        r = classify_function(
            file="ssl/ssl_sess.c", function="remove_session_lock",
            sloc=27, sink_unreachable=True,
            has_dangerous_callees=False, is_callback_target=True,
        )
        assert r.bucket != TriageBucket.SKIP

    def test_same_shape_without_callback_signal_still_skips(self):
        # Documents what the exemption protects against: without the
        # callback signal the mechanical skip fires.
        r = classify_function(
            file="ssl/ssl_sess.c", function="remove_session_lock",
            sloc=27, sink_unreachable=True,
            has_dangerous_callees=False, is_callback_target=False,
        )
        assert r.bucket == TriageBucket.SKIP

    def test_classify_all_matches_callback_names_bare(self):
        gaps = [{
            "file": "ssl/ssl_sess.c", "name": "remove_session_lock",
            "line_start": 839, "line_end": 866,
        }]
        results = classify_all(
            gaps,
            sink_unreachable_keys=frozenset(
                {"ssl/ssl_sess.c:remove_session_lock"}),
            callback_target_names=frozenset({"remove_session_lock"}),
        )
        r = results["ssl/ssl_sess.c:remove_session_lock:839"]
        assert r.bucket != TriageBucket.SKIP


class TestV4ShapeEndToEnd:
    """Full mechanical-pipeline replay: C source → call graph →
    sink discovery → evidence index → triage. Before the fix the
    chain ended in TriageBucket.SKIP for the callback-invoking
    function."""

    def test_indirect_caller_not_sink_unreachable_not_skipped(self):
        pytest.importorskip("tree_sitter_c")
        from core.evidence import build_evidence_index
        from core.inventory.call_graph import extract_call_graph_c
        from core.inventory.sink_discovery import discover_sinks

        graph = extract_call_graph_c(_SSL_SESS_SNIPPET)
        assert graph.calls, "C extractor produced no calls"

        sink_results = discover_sinks({"ssl/ssl_sess.c": graph})
        verdict = sink_results.unreachable_eligible[
            ("ssl/ssl_sess.c", "remove_session_lock")]
        assert verdict.eligible is False
        assert "function-pointer" in verdict.reason
        # The sibling without indirect calls keeps its verdict.
        plain = sink_results.unreachable_eligible[
            ("ssl/ssl_sess.c", "plain_helper")]
        assert plain.eligible is True

        checklist = {"files": [{
            "path": "ssl/ssl_sess.c",
            "items": [
                {"name": "remove_session_lock",
                 "line_start": 839, "line_end": 866},
                {"name": "plain_helper",
                 "line_start": 868, "line_end": 871},
            ],
        }]}
        index = build_evidence_index(
            checklist=checklist, sink_results=sink_results,
        )
        rec = index["ssl/ssl_sess.c:remove_session_lock"]
        assert rec.sink_unreachable is False

        sink_unreachable_keys = frozenset(
            k for k, r in index.items() if r.sink_unreachable)
        gaps = [
            {"file": "ssl/ssl_sess.c", "name": "remove_session_lock",
             "line_start": 839, "line_end": 866},
        ]
        results = classify_all(
            gaps, sink_unreachable_keys=sink_unreachable_keys,
        )
        r = results["ssl/ssl_sess.c:remove_session_lock:839"]
        assert r.bucket != TriageBucket.SKIP
