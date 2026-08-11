"""Tests for core.audit.live_classifications — intra-run learning."""

from __future__ import annotations

from core.audit.live_classifications import (
    LiveClassifications,
    expand_wrapper_sinks,
    extract_from_outcome,
    find_sanitizer_re_review_targets,
    load_from_project_context,
)


class TestLiveClassifications:
    def test_add_sink_new(self):
        live = LiveClassifications()
        assert live.add_sink("run_query", discovered_by="db.py:handle_request")
        assert "run_query" in live.sinks
        assert live._sink_sources["run_query"] == "db.py:handle_request"

    def test_add_sink_duplicate(self):
        live = LiveClassifications()
        live.add_sink("run_query")
        assert not live.add_sink("run_query")

    def test_add_sanitizer(self):
        live = LiveClassifications()
        assert live.add_sanitizer("escape_html", discovered_by="render.py:show")
        assert "escape_html" in live.sanitizers

    def test_add_entry_point(self):
        live = LiveClassifications()
        assert live.add_entry_point("api.py:handle_post")
        assert not live.add_entry_point("api.py:handle_post")

    def test_should_upgrade_triage_match(self):
        live = LiveClassifications()
        live.add_sink("run_query")
        reason = live.should_upgrade_triage("handler.py:process", ["run_query", "log"])
        assert reason is not None
        assert "run_query" in reason

    def test_should_upgrade_triage_no_match(self):
        live = LiveClassifications()
        live.add_sink("run_query")
        assert live.should_upgrade_triage("handler.py:process", ["log", "print"]) is None

    def test_as_persistable(self):
        live = LiveClassifications()
        live.add_sink("exec_cmd", discovered_by="shell.py:run")
        live.add_sanitizer("validate_input", discovered_by="api.py:post")
        data = live.as_persistable()
        assert len(data["sinks"]) == 1
        assert data["sinks"][0]["name"] == "exec_cmd"
        assert len(data["sanitizers"]) == 1
        assert data["sanitizers"][0]["name"] == "validate_input"

    def test_as_persistable_empty(self):
        live = LiveClassifications()
        assert live.as_persistable() == {}

    def test_stats(self):
        live = LiveClassifications()
        assert live.stats() == "no live discoveries"
        live.add_sink("f")
        assert "1 sinks" in live.stats()
        live.add_sanitizer("g")
        assert "1 sanitizers" in live.stats()


class TestExtractFromOutcome:
    def _make_outcome(self, review_result=None, status="clean"):
        class FakeOutcome:
            pass
        o = FakeOutcome()
        o.review_result = review_result
        o.status = status
        return o

    def test_no_review_result(self):
        live = LiveClassifications()
        o = self._make_outcome(review_result=None)
        assert extract_from_outcome(o, {"file": "a.py", "name": "f"}, live) == 0

    def test_dangerous_callees(self):
        live = LiveClassifications()
        o = self._make_outcome(review_result={
            "dangerous_callees": ["exec_cmd", "run_shell"],
        })
        added = extract_from_outcome(o, {"file": "a.py", "name": "handler"}, live)
        assert added == 2
        assert "exec_cmd" in live.sinks
        assert "run_shell" in live.sinks

    def test_sanitizer_callees(self):
        live = LiveClassifications()
        o = self._make_outcome(review_result={
            "sanitizer_callees": ["escape_html"],
        })
        added = extract_from_outcome(o, {"file": "a.py", "name": "render"}, live)
        assert added == 1
        assert "escape_html" in live.sanitizers

    def test_precondition_sink(self):
        live = LiveClassifications()
        o = self._make_outcome(review_result={
            "preconditions": [{
                "check_type": "function_reaches_sink",
                "location": {"function": "custom_exec"},
            }],
        })
        added = extract_from_outcome(o, {"file": "a.py", "name": "caller"}, live)
        assert added == 1
        assert "custom_exec" in live.sinks

    def test_precondition_same_function_skipped(self):
        live = LiveClassifications()
        o = self._make_outcome(review_result={
            "preconditions": [{
                "check_type": "function_reaches_sink",
                "location": {"function": "caller"},
            }],
        })
        added = extract_from_outcome(o, {"file": "a.py", "name": "caller"}, live)
        assert added == 0

    def test_empty_callees_skipped(self):
        live = LiveClassifications()
        o = self._make_outcome(review_result={
            "dangerous_callees": ["", "  ", "valid_sink"],
        })
        added = extract_from_outcome(o, {"file": "a.py", "name": "f"}, live)
        assert added == 1
        assert "valid_sink" in live.sinks

    def test_hypothesis_extraction(self):
        live = LiveClassifications()
        o = self._make_outcome(
            review_result={
                "hypothesis": "passes unsanitized input to custom_exec()",
            },
            status="finding",
        )
        extract_from_outcome(o, {"file": "a.py", "name": "handler"}, live)
        assert "custom_exec" in live.sinks

    def test_hypothesis_only_on_findings(self):
        live = LiveClassifications()
        o = self._make_outcome(
            review_result={
                "hypothesis": "passes unsanitized input to custom_exec()",
            },
            status="clean",
        )
        extract_from_outcome(o, {"file": "a.py", "name": "handler"}, live)
        assert "custom_exec" not in live.sinks

    def test_deduplication(self):
        live = LiveClassifications()
        o = self._make_outcome(review_result={
            "dangerous_callees": ["exec_cmd", "exec_cmd"],
        })
        added = extract_from_outcome(o, {"file": "a.py", "name": "f"}, live)
        assert added == 1


class TestLoadFromProjectContext:
    def test_empty(self):
        live = load_from_project_context(None)
        assert not live.sinks
        assert not live.sanitizers

    def test_sinks_loaded(self):
        learnings = [
            {"text": "custom_exec", "category": "sink"},
            {"text": "run_query", "category": "sink"},
        ]
        live = load_from_project_context(learnings)
        assert live.sinks == {"custom_exec", "run_query"}

    def test_sanitizers_loaded(self):
        learnings = [
            {"text": "escape_html", "category": "sanitizer"},
        ]
        live = load_from_project_context(learnings)
        assert live.sanitizers == {"escape_html"}

    def test_other_categories_ignored(self):
        learnings = [
            {"text": "some pattern", "category": "pattern"},
            {"text": "exec_cmd", "category": "sink"},
        ]
        live = load_from_project_context(learnings)
        assert live.sinks == {"exec_cmd"}
        assert not live.sanitizers

    def test_empty_text_skipped(self):
        learnings = [
            {"text": "", "category": "sink"},
        ]
        live = load_from_project_context(learnings)
        assert not live.sinks

    def test_entry_points_loaded(self):
        learnings = [
            {"text": "api.py:handle_post", "category": "entry_point"},
        ]
        live = load_from_project_context(learnings)
        assert "api.py:handle_post" in live.entry_points

    def test_checklist_filters_sinks(self):
        learnings = [
            {"text": "_joern_live_query", "category": "sink"},
            {"text": "_aead_recvmsg", "category": "sink"},
        ]
        checklist = {
            "files": [{"path": "aead.c", "items": [
                {"name": "_aead_recvmsg"},
            ]}],
        }
        live = load_from_project_context(learnings, checklist=checklist)
        assert "_aead_recvmsg" in live.sinks
        assert "_joern_live_query" not in live.sinks

    def test_no_checklist_loads_all(self):
        learnings = [
            {"text": "_joern_live_query", "category": "sink"},
            {"text": "_aead_recvmsg", "category": "sink"},
        ]
        live = load_from_project_context(learnings)
        assert "_joern_live_query" in live.sinks
        assert "_aead_recvmsg" in live.sinks


class TestExpandWrapperSinks:
    def test_wrapper_detected(self):
        live = LiveClassifications()
        live.add_sink("dangerous_api")
        edges = [
            {"caller_file": "a.py", "caller": "wrapper_fn", "callee": "dangerous_api"},
            {"caller_file": "b.py", "caller": "user1", "callee": "wrapper_fn"},
            {"caller_file": "c.py", "caller": "user2", "callee": "wrapper_fn"},
        ]
        added = expand_wrapper_sinks(live, edges)
        assert added == 1
        assert "wrapper_fn" in live.sinks

    def test_single_caller_skipped(self):
        live = LiveClassifications()
        live.add_sink("dangerous_api")
        edges = [
            {"caller_file": "a.py", "caller": "wrapper_fn", "callee": "dangerous_api"},
            {"caller_file": "b.py", "caller": "user1", "callee": "wrapper_fn"},
        ]
        added = expand_wrapper_sinks(live, edges, min_callers=2)
        assert added == 0

    def test_no_edges(self):
        live = LiveClassifications()
        live.add_sink("dangerous_api")
        assert expand_wrapper_sinks(live, []) == 0

    def test_no_sinks(self):
        live = LiveClassifications()
        edges = [
            {"caller_file": "a.py", "caller": "f", "callee": "g"},
        ]
        assert expand_wrapper_sinks(live, edges) == 0

    def test_already_known_sink_skipped(self):
        live = LiveClassifications()
        live.add_sink("dangerous_api")
        live.add_sink("wrapper_fn")
        edges = [
            {"caller_file": "a.py", "caller": "wrapper_fn", "callee": "dangerous_api"},
            {"caller_file": "b.py", "caller": "u1", "callee": "wrapper_fn"},
            {"caller_file": "c.py", "caller": "u2", "callee": "wrapper_fn"},
        ]
        added = expand_wrapper_sinks(live, edges)
        assert added == 0


class TestFindSanitizerReReviewTargets:
    def _make_outcome(self, file, func, status, review_result=None, body=""):
        class FakeOutcome:
            pass
        o = FakeOutcome()
        o.file = file
        o.function = func
        o.status = status
        o.review_result = review_result
        o.body = body
        return o

    def test_finding_with_sanitizer_callee(self):
        live = LiveClassifications()
        live.add_sanitizer("validate_input")
        o = self._make_outcome("a.py", "handler", "finding", review_result={
            "preconditions": [{
                "check_type": "some_check",
                "location": {"function": "validate_input"},
            }],
        })
        targets = find_sanitizer_re_review_targets(live, [o])
        assert len(targets) == 1
        assert "validate_input" in targets[0][1]

    def test_clean_skipped(self):
        live = LiveClassifications()
        live.add_sanitizer("validate_input")
        o = self._make_outcome("a.py", "handler", "clean", review_result={
            "preconditions": [{
                "location": {"function": "validate_input"},
            }],
        })
        assert find_sanitizer_re_review_targets(live, [o]) == []

    def test_sanitizer_in_body(self):
        live = LiveClassifications()
        live.add_sanitizer("escape_html")
        o = self._make_outcome(
            "a.py", "render", "suspicious",
            review_result={"preconditions": []},
            body="calls escape_html but may bypass it",
        )
        targets = find_sanitizer_re_review_targets(live, [o])
        assert len(targets) == 1

    def test_no_sanitizers(self):
        live = LiveClassifications()
        o = self._make_outcome("a.py", "f", "finding")
        assert find_sanitizer_re_review_targets(live, [o]) == []

    def test_no_match(self):
        live = LiveClassifications()
        live.add_sanitizer("validate_input")
        o = self._make_outcome("a.py", "f", "finding", review_result={
            "preconditions": [{"location": {"function": "other_fn"}}],
        })
        assert find_sanitizer_re_review_targets(live, [o]) == []
