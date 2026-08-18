"""Tests for the incremental study consumer (StudyQueue + helpers)."""

import asyncio
import threading
import time

from core.audit.orchestrator import (
    ConceptIndex,
    StudyQueue,
    StudyRequest,
    _dedup_batch,
    _extract_concept_from_question,
)

# ── StudyRequest ────────────────────────────────────────────────────


class TestStudyRequest:
    def test_defaults(self):
        r = StudyRequest(
            question="what is sk_buff?",
            source_file="net/core/skbuff.c",
            source_function="alloc_skb",
        )
        assert r.priority == "normal"
        assert r.resolution == "identifier"
        assert r.context == ""


# ── StudyQueue ──────────────────────────────────────────────────────


class TestStudyQueue:
    def test_enqueue_dequeue(self):
        q = StudyQueue()
        q.enqueue(StudyRequest("what is A?", "a.c", "fn_a"))
        q.enqueue(StudyRequest("what is B?", "b.c", "fn_b"))
        batch = q.dequeue_batch(max_items=10, timeout=0.1)
        assert len(batch) == 2
        assert batch[0].question == "what is A?"

    def test_dequeue_max_items(self):
        q = StudyQueue()
        for i in range(20):
            q.enqueue(StudyRequest(f"q{i}?", "f.c", "fn"))
        batch = q.dequeue_batch(max_items=5, timeout=0.1)
        assert len(batch) == 5
        # Remainder still queued
        batch2 = q.dequeue_batch(max_items=100, timeout=0.1)
        assert len(batch2) == 15

    def test_dequeue_blocks_then_returns(self):
        q = StudyQueue()

        def _producer():
            time.sleep(0.05)
            q.enqueue(StudyRequest("q?", "f.c", "fn"))

        t = threading.Thread(target=_producer)
        t.start()
        batch = q.dequeue_batch(max_items=10, timeout=2.0)
        t.join()
        assert len(batch) == 1

    def test_dequeue_timeout_empty(self):
        q = StudyQueue()
        t0 = time.monotonic()
        batch = q.dequeue_batch(max_items=10, timeout=0.1)
        elapsed = time.monotonic() - t0
        assert batch == []
        assert elapsed < 1.0

    def test_signal_producer_done_wakes_waiter(self):
        q = StudyQueue()

        def _signal():
            time.sleep(0.05)
            q.signal_producer_done()

        t = threading.Thread(target=_signal)
        t.start()
        batch = q.dequeue_batch(max_items=10, timeout=5.0)
        t.join()
        assert batch == []
        assert q.is_done()

    def test_is_done_when_drained(self):
        q = StudyQueue()
        q.enqueue(StudyRequest("q?", "f.c", "fn"))
        q.signal_producer_done()
        assert not q.is_done()  # still has items
        q.dequeue_batch(max_items=10, timeout=0.1)
        assert q.is_done()

    def test_thread_safety(self):
        q = StudyQueue()
        n = 100
        barrier = threading.Barrier(4)

        def _producer(start):
            barrier.wait()
            for i in range(start, start + n):
                q.enqueue(StudyRequest(f"q{i}?", "f.c", "fn"))

        threads = [
            threading.Thread(target=_producer, args=(i * n,))
            for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        total = 0
        while True:
            batch = q.dequeue_batch(max_items=50, timeout=0.05)
            if not batch:
                break
            total += len(batch)
        assert total == 4 * n


# ── _extract_concept_from_question ──────────────────────────────────


class TestExtractConcept:
    def test_what_is(self):
        assert _extract_concept_from_question("what is sk_buff?") == "sk_buff"

    def test_how_does(self):
        assert _extract_concept_from_question(
            "how does skb_put work?"
        ) == "skb_put"

    def test_does_validate(self):
        assert _extract_concept_from_question(
            "Does process_heartbeat validate payload_len?"
        ) == "process_heartbeat"

    def test_backtick(self):
        assert _extract_concept_from_question(
            "what is `mbuf`?"
        ) == "mbuf"

    def test_no_match(self):
        assert _extract_concept_from_question("random sentence") is None


# ── _dedup_batch ────────────────────────────────────────────────────


class TestDedupBatch:
    def _req(self, q, sf="f.c", sfn="fn"):
        return StudyRequest(question=q, source_file=sf, source_function=sfn)

    def test_removes_already_seen(self):
        batch = [
            self._req("what is sk_buff?"),
            self._req("what is skb_put?"),
        ]
        seen = {"sk_buff"}
        fresh = _dedup_batch(batch, seen, None)
        assert len(fresh) == 1
        assert fresh[0].question == "what is skb_put?"

    def test_removes_from_domain_model(self):
        dm = {"concepts": [{"name": "sk_buff"}], "invariants": []}
        batch = [self._req("what is sk_buff?")]
        fresh = _dedup_batch(batch, set(), dm)
        assert fresh == []

    def test_keeps_questions_without_extractable_concept(self):
        batch = [self._req("is there a race condition?")]
        fresh = _dedup_batch(batch, set(), None)
        assert len(fresh) == 1

    def test_case_insensitive(self):
        batch = [self._req("what is SK_BUFF?")]
        seen = {"sk_buff"}
        fresh = _dedup_batch(batch, seen, None)
        assert fresh == []


# ── ConceptIndex ───────────────────────────────────────────────────


class TestConceptIndex:
    def _checklist(self, items):
        return {"items": items}

    def _item(self, file, name, source=""):
        return {"file": file, "name": name, "source": source}

    def test_empty_when_no_items(self):
        ci = ConceptIndex.build({"items": []}, {"sk_buff"})
        assert ci.concepts_for("a.c", "fn") == frozenset()
        assert ci.functions_for("sk_buff") == frozenset()

    def test_empty_when_no_types(self):
        cl = self._checklist([self._item("a.c", "fn", "sk_buff x;")])
        ci = ConceptIndex.build(cl, None)
        assert ci.concepts_for("a.c", "fn") == frozenset()

    def test_basic_intersection(self):
        cl = self._checklist([
            self._item("net/core.c", "alloc_skb", "struct sk_buff *skb;"),
            self._item("net/core.c", "free_skb", "kfree(sk_buff);"),
            self._item("fs/inode.c", "get_inode", "struct inode *ip;"),
        ])
        types = {"sk_buff", "inode"}
        ci = ConceptIndex.build(
            cl, types, cardinality_cap_pct=1.0, cardinality_cap_abs=100,
        )

        assert "sk_buff" in ci.concepts_for("net/core.c", "alloc_skb")
        assert "sk_buff" in ci.concepts_for("net/core.c", "free_skb")
        assert "inode" in ci.concepts_for("fs/inode.c", "get_inode")
        assert ci.concepts_for("nonexistent.c", "fn") == frozenset()

        assert "net/core.c:alloc_skb" in ci.functions_for("sk_buff")
        assert "net/core.c:free_skb" in ci.functions_for("sk_buff")

    def test_cardinality_cap_drops_common_concepts(self):
        items = [
            self._item(f"f{i}.c", f"fn{i}", "buf ctx list thing;")
            for i in range(100)
        ]
        types = {"buf", "ctx", "list", "thing", "rare_type"}
        items.append(self._item("z.c", "fn_rare", "rare_type x;"))
        cl = self._checklist(items)
        ci = ConceptIndex.build(cl, types, cardinality_cap_abs=10)
        assert ci.concepts_for("f0.c", "fn0") == frozenset()
        assert "rare_type" in ci.concepts_for("z.c", "fn_rare")

    def test_empty_classmethod(self):
        ci = ConceptIndex.empty()
        assert ci.concepts_for("a.c", "fn") == frozenset()
        assert ci.functions_for("any") == frozenset()

    def test_case_insensitive_lookup(self):
        cl = self._checklist([
            self._item("a.c", "fn", "SK_BUFF usage here"),
        ])
        types = {"sk_buff"}
        ci = ConceptIndex.build(cl, types)
        assert "sk_buff" in ci.concepts_for("a.c", "fn")
        assert "a.c:fn" in ci.functions_for("SK_BUFF")


# ── StudyQueue concept tracking ────────────────────────────────────


class TestStudyQueueConcepts:
    def test_pending_concepts_tracks_enqueue(self):
        q = StudyQueue()
        q.enqueue(StudyRequest("what is sk_buff?", "a.c", "fn"))
        assert "sk_buff" in q.pending_concepts()

    def test_mark_studied_clears_pending(self):
        q = StudyQueue()
        q.enqueue(StudyRequest("what is sk_buff?", "a.c", "fn"))
        q.mark_studied({"sk_buff"})
        assert "sk_buff" not in q.pending_concepts()

    def test_signal_consumer_done_clears_all(self):
        q = StudyQueue()
        q.enqueue(StudyRequest("what is sk_buff?", "a.c", "fn"))
        q.enqueue(StudyRequest("what is mbuf?", "b.c", "fn"))
        q.signal_consumer_done()
        assert q.pending_concepts() == frozenset()
        assert q.consumer_done is True

    def test_set_event_loop_and_notify(self):
        loop = asyncio.new_event_loop()
        event = asyncio.Event()
        q = StudyQueue()
        q.set_event_loop(loop, event)
        q.enqueue(StudyRequest("what is sk_buff?", "a.c", "fn"))

        def _mark():
            time.sleep(0.02)
            q.mark_studied({"sk_buff"})

        t = threading.Thread(target=_mark)
        t.start()

        async def _wait():
            await asyncio.wait_for(event.wait(), timeout=2.0)

        loop.run_until_complete(_wait())
        t.join()
        loop.close()
        assert "sk_buff" not in q.pending_concepts()

    def test_notify_noop_before_set_event_loop(self):
        q = StudyQueue()
        q.enqueue(StudyRequest("what is sk_buff?", "a.c", "fn"))
        q.mark_studied({"sk_buff"})

    def test_non_extractable_concept_not_tracked(self):
        q = StudyQueue()
        q.enqueue(StudyRequest("is there a race?", "a.c", "fn"))
        assert q.pending_concepts() == frozenset()


# ── Suppression gate helpers (executor) ────────────────────────────


class TestSuppressionGate:
    """Test the suppression check logic extracted from the executor."""

    def test_suppression_blocks_leaf_with_pending(self):
        from core.audit.task_graph import TaskGraph

        # fn_caller calls fn_callee.  fn_caller has no dependents (leaf).
        # fn_callee has a dependent (fn_caller depends on its summary).
        gaps = [
            {"file": "a.c", "name": "fn_callee", "line_start": 10,
             "priority_score": 1.0},
            {"file": "a.c", "name": "fn_caller", "line_start": 50,
             "priority_score": 1.0},
        ]
        edges = [{"caller_file": "a.c", "caller": "fn_caller",
                   "callee_file": "a.c", "callee": "fn_callee"}]
        graph = TaskGraph.from_workqueue(gaps, edges)

        ci = ConceptIndex(
            {"sk_buff": {"a.c:fn_caller"}},
            {"a.c:fn_caller": {"sk_buff"}},
        )
        q = StudyQueue()
        q.enqueue(StudyRequest("what is sk_buff?", "a.c", "fn_caller"))

        caller_key = "a.c:fn_caller:50"
        # fn_caller is a leaf — nobody depends on its taint summary
        assert not graph.has_dependents(caller_key)

        concepts = ci.concepts_for("a.c", "fn_caller")
        pending = q.pending_concepts()
        blocked = concepts & pending
        assert blocked

    def test_no_suppression_with_dependents(self):
        from core.audit.task_graph import TaskGraph

        # fn_callee is a callee — fn_caller depends on its summary
        gaps = [
            {"file": "a.c", "name": "fn_callee", "line_start": 10,
             "priority_score": 1.0},
            {"file": "a.c", "name": "fn_caller", "line_start": 50,
             "priority_score": 1.0},
        ]
        edges = [{"caller_file": "a.c", "caller": "fn_caller",
                   "callee_file": "a.c", "callee": "fn_callee"}]
        graph = TaskGraph.from_workqueue(gaps, edges)

        # fn_callee has dependents — must NOT be suppressed (leaf-only rule)
        assert graph.has_dependents("a.c:fn_callee:10")

    def test_no_suppression_without_concept_match(self):
        ci = ConceptIndex(
            {"sk_buff": {"a.c:fn_other"}},
            {"a.c:fn_other": {"sk_buff"}},
        )
        q = StudyQueue()
        q.enqueue(StudyRequest("what is sk_buff?", "a.c", "fn"))

        concepts = ci.concepts_for("b.c", "fn_unrelated")
        pending = q.pending_concepts()
        assert not (concepts & pending)

    def test_release_after_mark_studied(self):
        q = StudyQueue()
        q.enqueue(StudyRequest("what is sk_buff?", "a.c", "fn"))
        hold_set = {"a.c:fn:10": {"sk_buff"}}

        q.mark_studied({"sk_buff"})
        pending = q.pending_concepts()
        released = [
            k for k in list(hold_set)
            if not (hold_set[k] & pending)
        ]
        assert released == ["a.c:fn:10"]

    def test_force_release_on_consumer_done(self):
        q = StudyQueue()
        q.enqueue(StudyRequest("what is sk_buff?", "a.c", "fn"))
        q.enqueue(StudyRequest("what is mbuf?", "b.c", "fn"))
        hold_set = {
            "a.c:fn:10": {"sk_buff"},
            "b.c:fn:20": {"mbuf"},
        }
        q.signal_consumer_done()
        assert q.consumer_done
        assert len(hold_set) == 2
