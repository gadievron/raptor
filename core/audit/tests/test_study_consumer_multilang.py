"""Study-consumer language dispatch (P37 — study loop beyond C/C++).

Pins: per-batch routing (C corpus / in-process multilang / unsupported),
re-review parity for non-C languages, and the reading-list marking
semantics — resolved requires domain-model evidence, unresolvable
carries a reason and is never resolved-clean, attempted-but-unverified
stays pending.  All hermetic: subprocess and run_study stubbed.
"""

from __future__ import annotations

import json
import time
import types

import pytest

from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    StudyQueue,
    StudyRequest,
    _extract_concept_from_question,
    _LockedOutcomes,
    _mark_batch_reading_list,
    _partition_study_batch,
    _study_consumer_loop,
)

# ------------------------------------------------------------------
# Question concept extraction (dotted / qualified shapes)
# ------------------------------------------------------------------

class TestExtractConceptDotted:
    def test_c_shape_unchanged(self) -> None:
        assert _extract_concept_from_question("what is sk_buff?") == "sk_buff"
        assert (
            _extract_concept_from_question("how does skb_put work?")
            == "skb_put"
        )

    def test_dotted_python(self) -> None:
        assert (
            _extract_concept_from_question("Does json.loads reject NaN?")
            == "json.loads"
        )

    def test_double_colon_rust(self) -> None:
        assert (
            _extract_concept_from_question(
                "Does Vec::with_capacity zero the memory?",
            )
            == "Vec::with_capacity"
        )

    def test_backticked(self) -> None:
        assert (
            _extract_concept_from_question("Does `http.Client.Do` retry?")
            == "http.Client.Do"
        )

    def test_trailing_period_stripped(self) -> None:
        assert (
            _extract_concept_from_question("does parse_config. work")
            == "parse_config"
        )


# ------------------------------------------------------------------
# Batch partitioning
# ------------------------------------------------------------------

def _req(source_file: str, question: str = "does thing work?", **kw):
    return StudyRequest(
        question=question,
        source_file=source_file,
        source_function=kw.pop("source_function", "fn"),
        **kw,
    )


class TestPartitionStudyBatch:
    def test_c_files_route_to_c(self) -> None:
        c, ml, un = _partition_study_batch(
            [_req("a.c"), _req("b.cpp"), _req("h.hpp")],
        )
        assert len(c) == 3 and not ml and not un

    def test_multilang_files_route_in_process(self) -> None:
        c, ml, un = _partition_study_batch([
            _req("a.py"), _req("b.go"), _req("C.java"),
            _req("d.ts"), _req("e.rs"), _req("f.js"),
        ])
        assert not c and len(ml) == 6 and not un

    def test_unsupported_language_partitioned_out(self) -> None:
        c, ml, un = _partition_study_batch([_req("a.rb"), _req("b.lua")])
        assert not c and not ml and len(un) == 2

    def test_missing_source_file_stays_on_c_path(self) -> None:
        c, ml, un = _partition_study_batch([_req("")])
        assert len(c) == 1 and not ml and not un

    def test_mixed_batch(self) -> None:
        c, ml, un = _partition_study_batch(
            [_req("a.c"), _req("b.py"), _req("c.rb")],
        )
        assert len(c) == 1 and len(ml) == 1 and len(un) == 1


# ------------------------------------------------------------------
# Reading-list marking semantics (pinned)
# ------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _scorecard_events(monkeypatch):
    """Capture scorecard events; never write the real sidecar."""
    events: list[tuple] = []
    monkeypatch.setattr(
        "core.audit.orchestrator._record_study_scorecard",
        lambda model, agreed, reason: events.append(
            (model, agreed, reason),
        ),
    )
    return events


def _seed_reading_list(out_dir, entries):
    from core.concepts.audit_bridge import queue_reading_list_item

    for e in entries:
        queue_reading_list_item(out_dir, **e)


def _load_rl(out_dir):
    return json.loads((out_dir / "reading-list.json").read_text())


class TestMarkBatchReadingList:
    def test_mechanical_tier_resolves(self, tmp_path) -> None:
        q = "Does `parse_config` validate its input?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "pkg/config.py",
            "source_function": "handler",
        }])
        dm = {"concepts": [{"id": "parse_config_contract",
                            "provenance": "mechanical"}],
              "invariants": [], "contracts": []}
        eligible = _mark_batch_reading_list(
            tmp_path,
            [_req("pkg/config.py", q, source_function="handler")],
            dm,
            {},
        )
        item = _load_rl(tmp_path)["items"][0]
        assert item["resolved"]
        assert item["resolved_concept_id"] == "parse_config_contract"
        assert "pkg/config.py:handler" in eligible

    def test_verbatim_tier_resolves_after_agreement(
        self, tmp_path, monkeypatch,
    ) -> None:
        import core.concepts.answer_gate as _gate
        monkeypatch.setattr(
            _gate, "verify_flip_answer",
            lambda *a, **kw: {"agreed": True, "reason": "agreed"},
        )
        q = "Does `parse_config` validate its input?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "pkg/config.py",
            "source_function": "handler",
        }])
        dm = {"concepts": [{
            "id": "parse_config_contract", "provenance": "verbatim",
            "receipt": {"file": "pkg/config.py", "line": 1,
                        "quote": "def parse_config(path):",
                        "verified": True},
        }], "invariants": [], "contracts": []}
        eligible = _mark_batch_reading_list(
            tmp_path,
            [_req("pkg/config.py", q, source_function="handler")],
            dm, {},
            study_client=object(), source_root=tmp_path,
        )
        assert _load_rl(tmp_path)["items"][0]["resolved"]
        assert "pkg/config.py:handler" in eligible

    def test_verbatim_gate_disagreement_is_inconclusive(
        self, tmp_path, monkeypatch,
    ) -> None:
        import core.concepts.answer_gate as _gate
        monkeypatch.setattr(
            _gate, "verify_flip_answer",
            lambda *a, **kw: {"agreed": False,
                              "reason": "independent resolution cited "
                                        "different source"},
        )
        q = "Does `parse_config` validate its input?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "pkg/config.py",
        }])
        dm = {"concepts": [{
            "id": "parse_config_contract", "provenance": "verbatim",
            "receipt": {"verified": True, "file": "f", "line": 1,
                        "quote": "q" * 20},
        }], "invariants": [], "contracts": []}
        eligible = _mark_batch_reading_list(
            tmp_path, [_req("pkg/config.py", q)], dm, {},
            study_client=object(), source_root=tmp_path,
        )
        item = _load_rl(tmp_path)["items"][0]
        assert not item["resolved"]
        assert not item["unresolvable"], (
            "inconclusive is not terminal unresolvable"
        )
        assert eligible == set(), "quarantined answer must not re-review"
        answers = json.loads(
            (tmp_path / "study-answers.json").read_text())["answers"]
        assert answers[0]["status"] == "inconclusive"
        assert not answers[0]["agreement"]["agreed"]

    def test_verbatim_without_client_fails_closed(self, tmp_path) -> None:
        q = "Does `parse_config` validate its input?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "pkg/config.py",
        }])
        dm = {"concepts": [{
            "id": "parse_config_contract", "provenance": "verbatim",
            "receipt": {"verified": True},
        }], "invariants": [], "contracts": []}
        eligible = _mark_batch_reading_list(
            tmp_path, [_req("pkg/config.py", q)], dm, {},
        )
        assert eligible == set()
        assert not _load_rl(tmp_path)["items"][0]["resolved"]

    def test_unverified_tier_is_hint_only(self, tmp_path) -> None:
        """An answer without a verified receipt (legacy or
        no-quote) never resolves and never re-reviews."""
        q = "Does `parse_config` validate its input?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "pkg/config.py",
        }])
        dm = {"concepts": [{"id": "parse_config_contract"}],
              "invariants": [], "contracts": []}
        eligible = _mark_batch_reading_list(
            tmp_path, [_req("pkg/config.py", q)], dm, {},
        )
        item = _load_rl(tmp_path)["items"][0]
        assert not item["resolved"]
        assert not item["unresolvable"]
        assert eligible == set()
        answers = json.loads(
            (tmp_path / "study-answers.json").read_text())["answers"]
        assert answers[0]["status"] == "pending"
        assert "unverified hint" in answers[0]["reason"]

    def _corpus(self, tmp_path, items):
        sl = tmp_path / "study-list.json"
        sl.write_text(json.dumps({
            "target": str(tmp_path), "source_root": str(tmp_path),
            "items": items,
        }))
        return sl

    def test_spot_check_resolves_and_overrides(self, tmp_path) -> None:
        sl = self._corpus(tmp_path, [{
            "name": "MAX_FRAME", "kind": "macro", "file": "lib.rs",
            "line": 2,
            "definition": "pub const MAX_FRAME: usize = 4096;",
        }])
        q = "Is MAX_FRAME 4096?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "lib.rs",
            "source_function": "decode",
        }])
        # An unverified LLM summary exists for the same identifier —
        # the mechanical spot-check must displace it.
        dm = {"concepts": [{"id": "max_frame_limit"}],
              "invariants": [], "contracts": []}
        eligible = _mark_batch_reading_list(
            tmp_path,
            [_req("lib.rs", q, source_function="decode")],
            dm, {}, study_list_path=sl,
        )
        item = _load_rl(tmp_path)["items"][0]
        assert item["resolved"]
        assert item["resolved_concept_id"] == "spotcheck:MAX_FRAME"
        assert "lib.rs:decode" in eligible
        answers = json.loads(
            (tmp_path / "study-answers.json").read_text())["answers"]
        assert answers[0]["tier"] == "mechanical"
        assert answers[0]["spot_check_override"] is True
        assert answers[0]["receipt"]["verified"]

    def test_spot_check_mismatch_still_mechanical_answer(
        self, tmp_path,
    ) -> None:
        sl = self._corpus(tmp_path, [{
            "name": "MAX_FRAME", "kind": "macro", "file": "lib.rs",
            "line": 2,
            "definition": "pub const MAX_FRAME: usize = 4096;",
        }])
        q = "Is MAX_FRAME equal to 8192?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "lib.rs",
        }])
        _mark_batch_reading_list(
            tmp_path, [_req("lib.rs", q)], None, {},
            study_list_path=sl,
        )
        answers = json.loads(
            (tmp_path / "study-answers.json").read_text())["answers"]
        assert "DOES NOT match" in answers[0]["answer"]

    def test_contradicting_spot_check_is_gated_not_trusted(
        self, tmp_path,
    ) -> None:
        """A spot-check that CONTRADICTS the question's asserted value
        is flip-causing: without a verification client for the
        agreement gate it must quarantine (fail closed), not resolve
        on unconditional mechanical trust."""
        sl = self._corpus(tmp_path, [{
            "name": "MAX_FRAME", "kind": "macro", "file": "lib.rs",
            "line": 2,
            "definition": "pub const MAX_FRAME: usize = 4096;",
        }])
        q = "Is MAX_FRAME equal to 8192?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "lib.rs",
        }])
        _mark_batch_reading_list(
            tmp_path, [_req("lib.rs", q)], None, {},
            study_list_path=sl,
        )
        item = _load_rl(tmp_path)["items"][0]
        assert not item.get("resolved")
        answers = json.loads(
            (tmp_path / "study-answers.json").read_text())["answers"]
        assert answers[0]["status"] == "inconclusive"
        assert answers[0]["agreement"]["agreed"] is False

    def test_agreeing_spot_check_keeps_mechanical_trust(
        self, tmp_path,
    ) -> None:
        sl = self._corpus(tmp_path, [{
            "name": "MAX_FRAME", "kind": "macro", "file": "lib.rs",
            "line": 2,
            "definition": "pub const MAX_FRAME: usize = 4096;",
        }])
        q = "Is MAX_FRAME 4096?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "lib.rs",
        }])
        _mark_batch_reading_list(
            tmp_path, [_req("lib.rs", q)], None, {},
            study_list_path=sl,
        )
        item = _load_rl(tmp_path)["items"][0]
        assert item["resolved"]
        answers = json.loads(
            (tmp_path / "study-answers.json").read_text())["answers"]
        assert answers[0]["status"] == "resolved"

    def test_no_extracted_snippet_is_unresolvable(self, tmp_path) -> None:
        """Extract-then-answer enforcement: when extraction produced
        nothing for the identifier, the LLM is never allowed to
        answer from prior knowledge — terminal unresolvable."""
        sl = self._corpus(tmp_path, [{
            "name": "unrelated_fn", "kind": "function",
            "file": "a.c", "line": 1,
            "definition": "int unrelated_fn(void) { return 0; }",
        }])
        q = "Does `ghost_helper` retry on failure?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "a.c",
        }])
        dm = {"concepts": [{"id": "ghost_helper_retries",
                            "provenance": "verbatim",
                            "receipt": {"verified": True}}],
              "invariants": [], "contracts": []}
        eligible = _mark_batch_reading_list(
            tmp_path, [_req("a.c", q)], dm, {}, study_list_path=sl,
        )
        item = _load_rl(tmp_path)["items"][0]
        assert item["unresolvable"]
        assert "no extracted source snippet" in item["unresolvable_reason"]
        assert eligible == set()

    def test_receipt_discard_marks_unresolvable(self, tmp_path) -> None:
        (tmp_path / "study-discards.json").write_text(json.dumps({
            "discarded": [{
                "kind": "concept", "id": "parse_config_contract",
                "reason": "receipt verification failed",
                "names": ["parse_config_contract", "parse_config"],
            }],
        }))
        q = "Does `parse_config` validate its input?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "pkg/config.py",
        }])
        _mark_batch_reading_list(
            tmp_path, [_req("pkg/config.py", q)], None, {},
        )
        item = _load_rl(tmp_path)["items"][0]
        assert item["unresolvable"]
        assert item["unresolvable_reason"] == "receipt verification failed"

    def test_scorecard_records_gate_outcomes(
        self, tmp_path, monkeypatch, _scorecard_events,
    ) -> None:
        import core.concepts.answer_gate as _gate
        monkeypatch.setattr(
            _gate, "verify_flip_answer",
            lambda *a, **kw: {"agreed": False, "reason": "disagreed"},
        )
        q = "Does `parse_config` validate its input?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "pkg/config.py",
        }])
        dm = {"concepts": [{
            "id": "parse_config_contract", "provenance": "verbatim",
            "receipt": {"verified": True},
        }], "invariants": [], "contracts": []}
        _mark_batch_reading_list(
            tmp_path, [_req("pkg/config.py", q)], dm, {},
            study_client=object(), source_root=tmp_path,
            scorecard_model="modelX",
        )
        assert ("modelX", False, "disagreed") in _scorecard_events

    def test_attempted_but_unverified_stays_pending(self, tmp_path) -> None:
        q = "Does `parse_config` validate its input?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "pkg/config.py",
        }])
        dm = {"concepts": [{"id": "unrelated_concept",
                            "provenance": "verbatim"}],
              "invariants": [], "contracts": []}
        _mark_batch_reading_list(
            tmp_path, [_req("pkg/config.py", q)], dm, {},
        )
        item = _load_rl(tmp_path)["items"][0]
        assert not item["resolved"]
        assert not item["unresolvable"]

    def test_failure_marks_unresolvable_never_resolved(self, tmp_path) -> None:
        q = "Does `ghost_fn` retry?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "pkg/config.py",
        }])
        dm = {"concepts": [{"id": "ghost_fn_contract"}],
              "invariants": [], "contracts": []}
        # Even though a concept would match, the resolver verdict wins:
        # the identifier has no static definition.
        _mark_batch_reading_list(
            tmp_path, [_req("pkg/config.py", q)], dm,
            {q: "not found in the scanned source tree"},
        )
        item = _load_rl(tmp_path)["items"][0]
        assert item["unresolvable"]
        assert "not found" in item["unresolvable_reason"]
        assert not item["resolved"]

    def test_critical_failure_is_loud(self, tmp_path, monkeypatch) -> None:
        import core.audit.orchestrator as _orch

        lines = []
        monkeypatch.setattr(
            _orch.logger, "warning",
            lambda msg, *a, **kw: lines.append(msg % a if a else msg),
        )
        q = "Does `ghost_fn` retry?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "pkg/config.py",
            "priority": "critical",
        }])
        _mark_batch_reading_list(
            tmp_path,
            [_req("pkg/config.py", q, priority="critical")],
            None,
            {q: "not found"},
        )
        assert any("CRITICAL assumption unresolvable" in ln for ln in lines)

    def test_actionable_invariant_counts_as_evidence(self, tmp_path) -> None:
        q = "Does MaxHeaderLen bound the buffer?"
        _seed_reading_list(tmp_path, [{
            "question": q, "source_file": "server/header.go",
        }])
        dm = {"concepts": [],
              "invariants": [{"id": "maxheaderlen_bound",
                              "provenance": "mechanical",
                              "statement": "len <= MaxHeaderLen"}],
              "contracts": []}
        _mark_batch_reading_list(
            tmp_path, [_req("server/header.go", q)], dm, {},
        )
        assert _load_rl(tmp_path)["items"][0]["resolved"]


# ------------------------------------------------------------------
# Full consumer loop (hermetic)
# ------------------------------------------------------------------

def _fixture_tree(tmp_path):
    target = tmp_path / "src"
    pkg = target / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "config.py").write_text(
        'def parse_config(path):\n'
        '    """Parse the config file. Raises ValueError on bad input."""\n'
        '    return path\n',
    )
    return target


def _stub_prep(monkeypatch, out_dir, calls=None):
    """Stub the study-prep subprocess: records calls, writes study-list."""
    import core.audit.orchestrator as _orch

    recorded = calls if calls is not None else []

    def fake_run(cmd, **kwargs):
        recorded.append(cmd)
        (out_dir / "study-list.json").write_text(json.dumps({
            "target": str(out_dir), "source_root": str(out_dir),
            "items": [],
        }))
        return types.SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(_orch.subprocess, "run", fake_run)
    return recorded


def _stub_llm(monkeypatch):
    import core.llm.client as _client_mod

    monkeypatch.setattr(
        _client_mod, "LLMClient",
        lambda *a, **kw: types.SimpleNamespace(total_cost=0.0),
    )


def _stub_run_study(monkeypatch, out_dir, concepts, *, tier="mechanical"):
    import core.concepts.study as _study_mod

    tiered = []
    for c in concepts:
        c = dict(c)
        c.setdefault("provenance", tier)
        tiered.append(c)

    def fake_run_study(study_list_path, output_dir, client, **kw):
        (out_dir / "domain-model.json").write_text(json.dumps({
            "version": "1", "target": "", "source_root": "",
            "concepts": tiered, "invariants": [], "contracts": [],
            "bug_patterns": [],
        }))

    monkeypatch.setattr(_study_mod, "run_study", fake_run_study)


def _run_loop(config, queue, *, reviewed=None):
    shared = types.SimpleNamespace(domain_model=None)
    _study_consumer_loop(
        queue, config, shared, lambda ctx, cfg: None,
        reviewed if reviewed is not None else _LockedOutcomes(),
        OrchestratorResult(),
        checklist={"files": []},
        context_map=None,
        evidence_index={},
        sarif_cache=None,
        entry_points=set(),
        start_time=time.monotonic(),
        on_progress=None,
    )
    return shared


def _queue(*reqs):
    q = StudyQueue()
    for r in reqs:
        q.enqueue(r)
    q.signal_producer_done()
    return q


class TestConsumerMultilangDispatch:
    def test_python_question_resolves_and_merges(
        self, monkeypatch, tmp_path,
    ) -> None:
        target = _fixture_tree(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        _stub_prep(monkeypatch, out)
        _stub_llm(monkeypatch)
        _stub_run_study(
            monkeypatch, out, [{"id": "parse_config_contract"}],
        )

        q = "Does `parse_config` validate its input?"
        _run_loop(config, _queue(StudyRequest(
            question=q, source_file="pkg/config.py",
            source_function="handler",
        )))

        # Resolved definition merged into the study corpus
        study_list = json.loads((out / "study-list.json").read_text())
        names = {i["name"] for i in study_list["items"]}
        assert "parse_config" in names
        # Reading-list item resolved against the domain model
        rl = _load_rl(out)
        assert rl["items"][0]["resolved"]

    def test_unresolvable_python_question_marked_with_reason(
        self, monkeypatch, tmp_path,
    ) -> None:
        target = _fixture_tree(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        _stub_prep(monkeypatch, out)
        _stub_llm(monkeypatch)
        _stub_run_study(monkeypatch, out, [{"id": "ghost_fn_contract"}])

        q = "Does `ghost_fn` retry on failure?"
        _run_loop(config, _queue(StudyRequest(
            question=q, source_file="pkg/config.py",
            source_function="handler",
        )))

        item = _load_rl(out)["items"][0]
        assert item["unresolvable"]
        assert item["unresolvable_reason"]
        assert not item["resolved"]
        # Honest record also lands in the study corpus
        study_list = json.loads((out / "study-list.json").read_text())
        assert any(
            u["name"] == "ghost_fn"
            for u in study_list.get("unresolved_identifiers", [])
        )

    def test_unsupported_language_skips_study_entirely(
        self, monkeypatch, tmp_path,
    ) -> None:
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=tmp_path, out_dir=out)
        calls = _stub_prep(monkeypatch, out)

        q = "Does `method_missing` proxy to the client?"
        queue = _queue(StudyRequest(
            question=q, source_file="lib/client.rb",
            source_function="call",
        ))
        _run_loop(config, queue)

        assert calls == [], "study-prep must not run for unsupported batch"
        item = _load_rl(out)["items"][0]
        assert item["unresolvable"]
        assert ".rb" in item["unresolvable_reason"]
        assert not item["resolved"]
        # Suppression gate released
        assert queue.pending_concepts() == frozenset()

    def test_re_review_parity_for_python(
        self, monkeypatch, tmp_path,
    ) -> None:
        """A resolved non-C assumption re-enters the review queue for
        its originating function exactly as for C."""
        import core.audit.orchestrator as _orch

        target = _fixture_tree(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        _stub_prep(monkeypatch, out)
        _stub_llm(monkeypatch)
        _stub_run_study(
            monkeypatch, out, [{"id": "parse_config_contract"}],
        )

        re_reviewed: list[set] = []

        def fake_re_review(result, *a, **kw):
            # reading_list_functions is positional arg 8 (a[7])
            re_reviewed.append(set(a[7]))
            return result

        monkeypatch.setattr(
            _orch, "_re_review_study_enriched", fake_re_review,
        )

        reviewed = _LockedOutcomes()
        reviewed["pkg/config.py:handler"] = types.SimpleNamespace(
            status="suspicious",
        )

        q = "Does `parse_config` validate its input?"
        _run_loop(config, _queue(StudyRequest(
            question=q, source_file="pkg/config.py",
            source_function="handler",
        )), reviewed=reviewed)

        assert re_reviewed, "re-review must fire for non-C languages"
        assert "pkg/config.py:handler" in re_reviewed[0]

    def test_unresolvable_function_not_re_reviewed(
        self, monkeypatch, tmp_path,
    ) -> None:
        """No knowledge was gained — the originating function must not
        burn a re-review slot."""
        import core.audit.orchestrator as _orch

        target = _fixture_tree(tmp_path)
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        _stub_prep(monkeypatch, out)
        _stub_llm(monkeypatch)
        _stub_run_study(monkeypatch, out, [{"id": "anything"}])

        re_reviewed: list[set] = []
        monkeypatch.setattr(
            _orch, "_re_review_study_enriched",
            lambda result, *a, **kw: (re_reviewed.append(set(a[7])), result)[1],
        )

        reviewed = _LockedOutcomes()
        reviewed["pkg/config.py:handler"] = types.SimpleNamespace(
            status="suspicious",
        )

        _run_loop(config, _queue(StudyRequest(
            question="Does `ghost_fn` retry?",
            source_file="pkg/config.py", source_function="handler",
        )), reviewed=reviewed)

        for keys in re_reviewed:
            assert "pkg/config.py:handler" not in keys


# ------------------------------------------------------------------
# Gate: non-C workqueues start the consumer
# ------------------------------------------------------------------

class TestStudyGateSuffixes:
    @pytest.mark.parametrize("path,expected", [
        ("a.c", True), ("b.cpp", True),
        ("pkg/app.py", True), ("srv/main.go", True),
        ("App.java", True), ("web/app.ts", True), ("lib.rs", True),
        ("script.rb", False), ("conf.lua", False), ("style.css", False),
    ])
    def test_supported_path(self, path, expected) -> None:
        from core.concepts.lang_resolve import is_study_supported_path
        assert is_study_supported_path(path) is expected


# ------------------------------------------------------------------
# C per-batch definition splice (one-shot prep gains no later corpus)
# ------------------------------------------------------------------

class TestCPerBatchSplice:
    def _tree(self, tmp_path):
        target = tmp_path / "target"
        (target / "net" / "proto").mkdir(parents=True)
        (target / "net" / "proto" / "sock.c").write_text(
            "/* proto_set_level rejects levels above PROTO_LEVEL_MAX. */\n"
            "int proto_set_level(struct proto_sock *ps, unsigned int lv)\n"
            "{\n"
            "\tif (lv > PROTO_LEVEL_MAX)\n"
            "\t\treturn -EINVAL;\n"
            "\tps->level = lv;\n"
            "\treturn 0;\n"
            "}\n",
        )
        out = tmp_path / "out"
        out.mkdir()
        return target, out

    def test_c_question_splices_definition(self, tmp_path) -> None:
        from core.audit.orchestrator import _resolve_multilang_requests

        target, out = self._tree(tmp_path)
        config = OrchestratorConfig(target_path=target, out_dir=out)
        study_list = out / "study-list.json"
        req = StudyRequest(
            question=(
                "Does this hold: proto_set_level validates the level "
                "before this function runs?"
            ),
            source_file="net/proto/rx.c",
            source_function="rx_init",
        )
        _resolve_multilang_requests(
            config, [req], study_list, include_c=True,
        )
        data = json.loads(study_list.read_text())
        names = {i["name"] for i in data["items"]}
        assert "proto_set_level" in names
        item = next(
            i for i in data["items"] if i["name"] == "proto_set_level"
        )
        assert "PROTO_LEVEL_MAX" in item["definition"]

    def test_default_path_still_excludes_c(self, tmp_path) -> None:
        from core.audit.orchestrator import _resolve_multilang_requests

        target, out = self._tree(tmp_path)
        config = OrchestratorConfig(target_path=target, out_dir=out)
        study_list = out / "study-list.json"
        req = StudyRequest(
            question="Does `proto_set_level` validate the level?",
            source_file="net/proto/rx.c",
            source_function="rx_init",
        )
        failures = _resolve_multilang_requests(config, [req], study_list)
        assert failures  # C identifier is unresolvable on the ml path
        if study_list.is_file():
            data = json.loads(study_list.read_text())
            names = {i["name"] for i in data.get("items", [])}
            assert "proto_set_level" not in names

    def test_scoped_before_root(self, tmp_path) -> None:
        # A same-named decoy outside the request's subsystem must not
        # shadow the subsystem definition.
        from core.audit.orchestrator import (
            _resolve_scoped,
        )
        from core.concepts.lang_resolve import resolve_identifiers

        target, _out = self._tree(tmp_path)
        (target / "vendorpkg").mkdir()
        (target / "vendorpkg" / "decoy.c").write_text(
            "int proto_set_level(int x) { return x; }\n",
        )
        req = StudyRequest(
            question="Does proto_set_level validate?",
            source_file="net/proto/rx.c",
            source_function="rx_init",
        )
        res = _resolve_scoped(
            target, ["proto_set_level"], [req], resolve_identifiers,
            include_c=True,
        )
        files = [i.file for i in res.items]
        assert "net/proto/sock.c" in files

    def test_scoped_resolution_for_multilang(self, tmp_path) -> None:
        # The scoped-first strategy applies to non-C study languages
        # too: a Go identifier in the request's subsystem resolves
        # even when the tree is larger than a flat scan would cover.
        from core.audit.orchestrator import _resolve_scoped
        from core.concepts.lang_resolve import resolve_identifiers

        target = tmp_path / "t"
        (target / "pkg" / "wire").mkdir(parents=True)
        (target / "pkg" / "wire" / "frame.go").write_text(
            "package wire\n\n"
            "// advanceFrame records a frame boundary.\n"
            "func advanceFrame(n int) int {\n"
            "\treturn n + 1\n"
            "}\n",
        )
        req = StudyRequest(
            question="Does advanceFrame validate the parsed number?",
            source_file="pkg/wire/decode.go",
            source_function="decodeHeader",
        )
        res = _resolve_scoped(
            target, ["advanceFrame"], [req], resolve_identifiers,
        )
        assert [i.name for i in res.items] == ["advanceFrame"]


class TestIncludeChasePass:
    """_resolve_scoped: identifiers the subsystem passes miss resolve
    through the request source file's #include graph before the run
    falls back to (and gives up at) the capped root scan."""

    def _tree(self, tmp_path):
        target = tmp_path / "tree"
        (target / "drivers" / "widget").mkdir(parents=True)
        (target / "include" / "linux" / "widget").mkdir(parents=True)
        (target / "drivers" / "widget" / "main.c").write_text(
            '#include <linux/widget.h>\n\n'
            "int widget_prepare(void) { return widget_ref_get(); }\n",
        )
        (target / "include" / "linux" / "widget.h").write_text(
            "/* umbrella */\n",
        )
        (target / "include" / "linux" / "widget" / "core.h").write_text(
            "/* widget_ref_get grabs a runtime PM reference. */\n"
            "static inline int widget_ref_get(void) { return 0; }\n",
        )
        return target

    def test_chase_rescues_shared_header_definition(self, tmp_path) -> None:
        from core.audit.orchestrator import _resolve_scoped
        from core.concepts.lang_resolve import resolve_identifiers

        target = self._tree(tmp_path)

        calls = []

        def capped(root, idents, scope=None, files=None, include_c=False):
            # A kernel-sized tree: any pass without an explicit scope
            # or file set stops at the flat cap before reaching
            # include/ (simulated as an empty scan).
            calls.append({"scope": scope, "files": files})
            if scope is None and files is None:
                return resolve_identifiers(
                    root, idents, scope=root / "drivers",
                    include_c=include_c,
                )
            return resolve_identifiers(
                root, idents, scope=scope, files=files,
                include_c=include_c,
            )

        req = StudyRequest(
            question="Does widget_ref_get leave the count incremented on error?",
            source_file="drivers/widget/main.c",
            source_function="widget_prepare",
        )
        res = _resolve_scoped(
            target, ["widget_ref_get"], [req], capped, include_c=True,
        )
        assert [i.name for i in res.items] == ["widget_ref_get"]
        item = next(i for i in res.items if i.name == "widget_ref_get")
        assert item.file == "include/linux/widget/core.h"
        # The rescue came from the include-chase file set, not a
        # lucky scope/root pass.
        chase = [c for c in calls if c["files"] is not None]
        assert chase and any(
            "core.h" in str(p) for p in chase[0]["files"]
        )

    def test_no_chase_when_subsystem_pass_resolves(self, tmp_path) -> None:
        from core.audit.orchestrator import _resolve_scoped
        from core.concepts.lang_resolve import resolve_identifiers

        target = self._tree(tmp_path)
        (target / "drivers" / "widget" / "local.h").write_text(
            "static inline int widget_ref_get(void) { return 1; }\n",
        )

        calls = []

        def spy(root, idents, scope=None, files=None, include_c=False):
            calls.append({"files": files})
            return resolve_identifiers(
                root, idents, scope=scope, files=files,
                include_c=include_c,
            )

        req = StudyRequest(
            question="Does widget_ref_get leave the count incremented on error?",
            source_file="drivers/widget/main.c",
            source_function="widget_prepare",
        )
        res = _resolve_scoped(
            target, ["widget_ref_get"], [req], spy, include_c=True,
        )
        assert [i.name for i in res.items] == ["widget_ref_get"]
        assert all(c["files"] is None for c in calls), (
            "include chase must only run for leftovers"
        )
