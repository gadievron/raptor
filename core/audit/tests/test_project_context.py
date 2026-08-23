"""Tests for core.audit.project_context — persistent project-level learnings."""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.project_context import (
    VALID_CATEGORIES,
    Learning,
    ProjectContext,
    add_learning,
    load_project_context,
    save_project_context,
)


class TestLearning:
    def test_auto_id(self):
        lrn = Learning(text="test learning")
        assert lrn.id
        assert len(lrn.id) == 12

    def test_deterministic_id(self):
        lrn1 = Learning(text="same text")
        lrn2 = Learning(text="same text")
        assert lrn1.id == lrn2.id

    def test_different_text_different_id(self):
        lrn1 = Learning(text="text one")
        lrn2 = Learning(text="text two")
        assert lrn1.id != lrn2.id

    def test_auto_created(self):
        lrn = Learning(text="test")
        assert lrn.created

    def test_explicit_id(self):
        lrn = Learning(text="test", id="custom-id")
        assert lrn.id == "custom-id"

    def test_defaults(self):
        lrn = Learning(text="test")
        assert lrn.category == "note"
        assert lrn.source == "human"
        assert lrn.file == ""
        assert lrn.function == ""
        assert lrn.strategy == ""


class TestProjectContext:
    def test_add_new(self):
        ctx = ProjectContext()
        lrn = Learning(text="new learning")
        assert ctx.add(lrn) is True
        assert len(ctx.learnings) == 1

    def test_add_duplicate(self):
        ctx = ProjectContext()
        lrn = Learning(text="same")
        ctx.add(lrn)
        assert ctx.add(Learning(text="same")) is False
        assert len(ctx.learnings) == 1

    def test_remove(self):
        ctx = ProjectContext()
        lrn = Learning(text="to remove")
        ctx.add(lrn)
        assert ctx.remove(lrn.id) is True
        assert len(ctx.learnings) == 0

    def test_remove_nonexistent(self):
        ctx = ProjectContext()
        assert ctx.remove("nonexistent") is False

    def test_query_unscoped(self):
        ctx = ProjectContext()
        ctx.add(Learning(text="global note"))
        ctx.add(Learning(text="file-scoped", file="a.c"))
        results = ctx.query()
        assert len(results) == 2

    def test_query_by_file(self):
        ctx = ProjectContext()
        ctx.add(Learning(text="a note", file="a.c"))
        ctx.add(Learning(text="b note", file="b.c"))
        ctx.add(Learning(text="global note"))
        results = ctx.query(file="a.c")
        assert len(results) == 2
        texts = {r.text for r in results}
        assert "a note" in texts
        assert "global note" in texts

    def test_query_by_category(self):
        ctx = ProjectContext()
        ctx.add(Learning(text="arch note", category="architecture"))
        ctx.add(Learning(text="plain note", category="note"))
        results = ctx.query(category="architecture")
        assert len(results) == 1
        assert results[0].text == "arch note"

    def test_query_by_strategy(self):
        ctx = ProjectContext()
        ctx.add(Learning(text="crypto note", strategy="crypto"))
        ctx.add(Learning(text="other"))
        results = ctx.query(strategy="crypto")
        assert len(results) == 2
        texts = {r.text for r in results}
        assert "crypto note" in texts
        assert "other" in texts

    def test_to_dict(self):
        ctx = ProjectContext()
        ctx.add(Learning(text="test", category="pattern", id="abc123"))
        d = ctx.to_dict()
        assert d["version"] == 1
        assert len(d["learnings"]) == 1
        assert d["learnings"][0]["id"] == "abc123"
        assert d["learnings"][0]["category"] == "pattern"


class TestSaveLoad:
    def test_roundtrip(self, tmp_path: Path):
        run_dir = tmp_path / "run-001"
        run_dir.mkdir()

        ctx = ProjectContext()
        ctx.add(Learning(
            text="project uses OpenSSL 1.1.1",
            category="architecture",
            source="llm",
            file="src/crypto.c",
        ))
        ctx.add(Learning(
            text="false positive: CWE-78 in safe_exec is a wrapper",
            category="suppression",
        ))

        saved_path = save_project_context(ctx, run_dir)
        assert saved_path.exists()
        assert saved_path.parent == run_dir

        loaded = load_project_context(run_dir)
        assert len(loaded.learnings) == 2
        assert loaded.learnings[0].text == "project uses OpenSSL 1.1.1"
        assert loaded.learnings[0].category == "architecture"
        assert loaded.learnings[1].category == "suppression"

    def test_load_from_parent(self, tmp_path: Path, monkeypatch):
        (tmp_path / "project-context.json").write_text(json.dumps({
            "version": 1,
            "learnings": [{"text": "from parent", "id": "p1"}],
        }))

        run_dir = tmp_path / "run-001"
        run_dir.mkdir()

        import core.audit.project_context as _mod
        monkeypatch.setattr(_mod, "_is_project_dir", lambda d: True)

        loaded = load_project_context(run_dir)
        assert len(loaded.learnings) == 1
        assert loaded.learnings[0].text == "from parent"

    def test_load_from_run_dir(self, tmp_path: Path):
        (tmp_path / "project-context.json").write_text(json.dumps({
            "version": 1,
            "learnings": [{"text": "in run dir", "id": "r1"}],
        }))

        loaded = load_project_context(tmp_path)
        assert len(loaded.learnings) == 1

    def test_load_missing(self, tmp_path: Path):
        loaded = load_project_context(tmp_path)
        assert loaded.learnings == []

    def test_load_corrupt(self, tmp_path: Path):
        (tmp_path / "project-context.json").write_text("not json{")
        loaded = load_project_context(tmp_path)
        assert loaded.learnings == []


class TestAddLearning:
    def test_adds_and_persists(self, tmp_path: Path):
        run_dir = tmp_path / "run-001"
        run_dir.mkdir()

        result = add_learning(
            run_dir,
            "this project uses constant-time comparisons",
            category="pattern",
            source="llm",
        )
        assert result is not None
        assert result.text == "this project uses constant-time comparisons"

        loaded = load_project_context(run_dir)
        assert len(loaded.learnings) == 1

    def test_dedup(self, tmp_path: Path):
        run_dir = tmp_path / "run-001"
        run_dir.mkdir()

        add_learning(run_dir, "same text")
        result = add_learning(run_dir, "same text")
        assert result is None

        loaded = load_project_context(run_dir)
        assert len(loaded.learnings) == 1

    def test_invalid_category_raises(self, tmp_path: Path):
        run_dir = tmp_path / "run-001"
        run_dir.mkdir()

        try:
            add_learning(run_dir, "test", category="invalid")
            assert False, "should raise ValueError"
        except ValueError as exc:
            assert "invalid" in str(exc)

    def test_all_valid_categories(self, tmp_path: Path):
        run_dir = tmp_path / "run-001"
        run_dir.mkdir()

        for cat in VALID_CATEGORIES:
            result = add_learning(run_dir, f"test {cat}", category=cat)
            assert result is not None

    def test_with_scope(self, tmp_path: Path):
        run_dir = tmp_path / "run-001"
        run_dir.mkdir()

        result = add_learning(
            run_dir,
            "encrypt_block uses AES-128-CBC",
            file="src/crypto.c",
            function="encrypt_block",
            strategy="crypto",
        )
        assert result.file == "src/crypto.c"
        assert result.function == "encrypt_block"
        assert result.strategy == "crypto"


class TestPersistProjectLearnings:
    def test_saves_tool_confirmed_observations(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorResult,
            _persist_project_learnings,
        )
        run_dir = tmp_path / "project" / "run1"
        run_dir.mkdir(parents=True)
        session_obs = [
            {"text": "memcpy often called without bounds", "source": "a.c:copy_buf", "kind": "tool_confirmation"},
            {"text": "unconfirmed guess", "source": "b.c:fn"},
        ]
        result = OrchestratorResult()
        _persist_project_learnings(run_dir, session_obs, result)

        ctx = load_project_context(run_dir)
        texts = [lrn.text for lrn in ctx.learnings]
        assert "memcpy often called without bounds" in texts
        assert "unconfirmed guess" not in texts

    def test_saves_gate_demoted_suspicious(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorResult,
            ReviewOutcome,
            _persist_project_learnings,
        )
        run_dir = tmp_path / "project" / "run2"
        run_dir.mkdir(parents=True)
        result = OrchestratorResult()
        result.outcomes = [
            ReviewOutcome(
                file="x.c", function="safe_fn", status="suspicious",
                body="[self-contradiction: asserts bounded] the copy is bounded",
            ),
            ReviewOutcome(
                file="y.c", function="real_fn", status="finding",
                body="real bug here",
            ),
        ]
        _persist_project_learnings(run_dir, [], result)

        ctx = load_project_context(run_dir)
        assert len(ctx.learnings) == 1
        assert "self-contradiction" in ctx.learnings[0].text
        assert ctx.learnings[0].category == "suppression"

    def test_dedup_avoids_duplicates(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorResult,
            _persist_project_learnings,
        )
        run_dir = tmp_path / "project" / "run3"
        run_dir.mkdir(parents=True)
        session_obs = [
            {"text": "pattern X", "source": "a.c:f", "kind": "tool_confirmation"},
        ]
        result = OrchestratorResult()
        _persist_project_learnings(run_dir, session_obs, result)
        _persist_project_learnings(run_dir, session_obs, result)

        ctx = load_project_context(run_dir)
        texts = [lrn.text for lrn in ctx.learnings]
        assert texts.count("pattern X") == 1


class TestObservationRoundTrip:
    """The observation shape _accumulate_observations produces must be
    the shape _persist_project_learnings consumes."""

    def test_tool_confirmation_persists_as_pattern_learning(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorResult,
            ReviewOutcome,
            _accumulate_observations,
            _persist_project_learnings,
        )

        run_dir = tmp_path / "project" / "run-rt"
        run_dir.mkdir(parents=True)

        outcome = ReviewOutcome(
            file="a.c", function="copy_buf", status="finding",
            body="overflow", hypothesis="memcpy without bounds check",
            evidence_tool="semgrep:unbounded-memcpy",
        )
        session_obs: list = []
        _accumulate_observations(
            session_obs, outcome, {"file": "a.c", "name": "copy_buf"},
            sweep_pre_status="suspicious",
        )
        assert session_obs, "producer should emit a tool confirmation"

        _persist_project_learnings(run_dir, session_obs, OrchestratorResult())
        ctx = load_project_context(run_dir)
        assert any(
            lrn.category == "pattern" and "memcpy" in lrn.text
            for lrn in ctx.learnings
        )
