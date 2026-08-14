"""Tests for libexec/raptor-study-loop orchestrator."""

import importlib.machinery
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

RAPTOR_DIR = Path(__file__).resolve().parents[3]
STUDY_LOOP = str(RAPTOR_DIR / "libexec" / "raptor-study-loop")


def _load_loop_module() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("raptor_study_loop", STUDY_LOOP)
    spec = importlib.util.spec_from_file_location(
        "raptor_study_loop", STUDY_LOOP, loader=loader,
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_loop = _load_loop_module()


def _run_loop(args: list[str], env_extra: dict | None = None) -> subprocess.CompletedProcess:
    """Run study-loop with trust marker set."""
    import os
    env = os.environ.copy()
    env["_RAPTOR_TRUSTED"] = "1"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, STUDY_LOOP] + args,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestStudyLoopCLI:
    def test_help(self):
        result = _run_loop(["--help"])
        assert result.returncode == 0
        assert "drain" in result.stdout.lower() or "study" in result.stdout.lower()

    def test_missing_target_produces_no_items(self, tmp_path):
        result = _run_loop([
            "/nonexistent/target", str(tmp_path),
            "--identifier", "some_func",
        ])
        assert "no study items" in result.stderr.lower() or result.returncode == 0

    def test_path_only_runs_overview(self, tmp_path):
        """Path-only invocation triggers overview mode."""
        result = _run_loop(["/nonexistent/target", str(tmp_path)])
        assert "running overview" in result.stderr.lower()

    def test_creates_output_dir(self, tmp_path):
        out = tmp_path / "loop-out"
        target = tmp_path / "src"
        target.mkdir()
        _run_loop([str(target), str(out), "--identifier", "some_func"])
        assert out.is_dir()


class TestStudyLoopConvergence:
    """Test that the loop terminates correctly."""

    def test_empty_target_terminates(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        out = tmp_path / "out"
        result = _run_loop([
            str(target), str(out), "--identifier", "some_func",
        ])
        assert "no study items" in result.stderr.lower() or result.returncode == 0


class TestReadingListDrain:
    """Test reading-list integration in the loop."""

    def test_reading_list_items_extracted(self):
        """Verify the helper that extracts identifiers from reading list."""
        import importlib.util
        import os
        os.environ["_RAPTOR_TRUSTED"] = "1"
        sys.path.insert(0, str(RAPTOR_DIR))

        spec = importlib.util.spec_from_file_location(
            "study_loop", STUDY_LOOP,
            submodule_search_locations=[],
        )
        if spec is None or spec.loader is None:
            # Fallback: exec the file directly and grab the function
            import types
            mod = types.ModuleType("study_loop")
            mod.__file__ = STUDY_LOOP
            exec(
                compile(
                    Path(STUDY_LOOP).read_text(encoding="utf-8"),
                    STUDY_LOOP, "exec",
                ),
                mod.__dict__,
            )
        else:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

        pending = [
            {"question": "struct page ownership", "resolution": "identifier",
             "context": "Need to understand `page` lifecycle"},
            {"question": "memory aliasing semantics", "resolution": "concept",
             "context": ""},
        ]
        idents, concepts = mod._extract_rl_identifiers(pending)
        assert "page" in idents
        assert "memory aliasing semantics" in concepts


class TestMarkItemsResolved:
    def _write_rl(self, out_dir, items):
        rl_path = out_dir / "reading-list.json"
        rl_path.write_text(json.dumps({"items": items}), encoding="utf-8")

    def test_marks_backtick_ident_in_question(self, tmp_path):
        self._write_rl(tmp_path, [
            {"question": "What is `crypto_type`?", "resolved": False},
            {"question": "What is `crypto_alg`?", "resolved": False},
        ])
        count = _loop._mark_items_resolved(
            tmp_path, ["crypto_type"], [])
        assert count == 1
        data = json.loads((tmp_path / "reading-list.json").read_text())
        assert data["items"][0]["resolved"] is True
        assert data["items"][0]["resolved_concept_id"] == "studied"
        assert not data["items"][1].get("resolved")

    def test_marks_backtick_ident_in_context(self, tmp_path):
        self._write_rl(tmp_path, [
            {"question": "What role does this play?",
             "context": "See `crypto_chain` in algapi.c",
             "resolved": False},
        ])
        count = _loop._mark_items_resolved(
            tmp_path, ["crypto_chain"], [])
        assert count == 1

    def test_marks_struct_pattern(self, tmp_path):
        self._write_rl(tmp_path, [
            {"question": "What is struct crypto_type?", "resolved": False},
        ])
        count = _loop._mark_items_resolved(
            tmp_path, ["struct crypto_type"], [])
        assert count == 1

    def test_marks_concept_by_question_text(self, tmp_path):
        self._write_rl(tmp_path, [
            {"question": "How does algorithm chaining work?",
             "resolution": "concept", "resolved": False},
        ])
        count = _loop._mark_items_resolved(
            tmp_path, [], ["How does algorithm chaining work?"])
        assert count == 1

    def test_skips_already_resolved(self, tmp_path):
        self._write_rl(tmp_path, [
            {"question": "What is `crypto_type`?", "resolved": True},
        ])
        count = _loop._mark_items_resolved(
            tmp_path, ["crypto_type"], [])
        assert count == 0

    def test_no_file_returns_zero(self, tmp_path):
        count = _loop._mark_items_resolved(
            tmp_path, ["crypto_type"], [])
        assert count == 0


class TestDetectConceptsDir:
    def test_existing_concepts_dir(self, tmp_path):
        project_root = tmp_path / "projects" / "myproj"
        run_dir = project_root / "run_001"
        run_dir.mkdir(parents=True)
        (project_root / "concepts").mkdir()
        result = _loop._detect_concepts_dir(run_dir)
        assert result == project_root / "concepts"

    def test_creates_concepts_dir_for_project(self, tmp_path):
        project_root = tmp_path / "projects" / "myproj"
        run_dir = project_root / "run_001"
        run_dir.mkdir(parents=True)
        result = _loop._detect_concepts_dir(run_dir)
        assert result == project_root / "concepts"
        assert result.is_dir()

    def test_returns_none_for_standalone_run(self, tmp_path):
        run_dir = tmp_path / "out" / "understand_20260731"
        run_dir.mkdir(parents=True)
        result = _loop._detect_concepts_dir(run_dir)
        assert result is None


class TestLoadPriorKnowledge:
    def test_loads_existing_domain_model(self, tmp_path):
        concepts_dir = tmp_path / "concepts"
        concepts_dir.mkdir()
        dm = {"concepts": [{"id": "c1", "description": "test"}]}
        (concepts_dir / "domain-model.json").write_text(
            json.dumps(dm), encoding="utf-8")

        run_dir = tmp_path / "run_001"
        run_dir.mkdir()
        _loop._load_prior_knowledge(run_dir, concepts_dir)

        loaded = json.loads((run_dir / "domain-model.json").read_text())
        assert loaded["concepts"][0]["id"] == "c1"

    def test_does_not_overwrite_existing(self, tmp_path):
        concepts_dir = tmp_path / "concepts"
        concepts_dir.mkdir()
        (concepts_dir / "domain-model.json").write_text(
            '{"concepts": []}', encoding="utf-8")

        run_dir = tmp_path / "run_001"
        run_dir.mkdir()
        (run_dir / "domain-model.json").write_text(
            '{"concepts": [{"id": "local"}]}', encoding="utf-8")

        _loop._load_prior_knowledge(run_dir, concepts_dir)
        loaded = json.loads((run_dir / "domain-model.json").read_text())
        assert loaded["concepts"][0]["id"] == "local"

    def test_none_concepts_dir_is_noop(self, tmp_path):
        run_dir = tmp_path / "run_001"
        run_dir.mkdir()
        _loop._load_prior_knowledge(run_dir, None)
        assert not (run_dir / "domain-model.json").exists()


class TestPromoteToProject:
    def test_promotes_domain_model(self, tmp_path):
        concepts_dir = tmp_path / "concepts"
        concepts_dir.mkdir()
        run_dir = tmp_path / "run_001"
        run_dir.mkdir()
        dm = {"concepts": [{"id": "c1"}], "invariants": [], "contracts": []}
        (run_dir / "domain-model.json").write_text(
            json.dumps(dm), encoding="utf-8")

        _loop._promote_to_project(run_dir, concepts_dir)

        promoted = json.loads(
            (concepts_dir / "domain-model.json").read_text())
        assert promoted["concepts"][0]["id"] == "c1"

    def test_promotes_reading_list(self, tmp_path):
        concepts_dir = tmp_path / "concepts"
        concepts_dir.mkdir()
        run_dir = tmp_path / "run_001"
        run_dir.mkdir()
        rl = {"items": [{"question": "q1", "resolved": True}]}
        (run_dir / "reading-list.json").write_text(
            json.dumps(rl), encoding="utf-8")

        _loop._promote_to_project(run_dir, concepts_dir)

        promoted = json.loads(
            (concepts_dir / "reading-list.json").read_text())
        assert promoted["items"][0]["resolved"] is True

    def test_none_concepts_dir_is_noop(self, tmp_path):
        run_dir = tmp_path / "run_001"
        run_dir.mkdir()
        (run_dir / "domain-model.json").write_text("{}", encoding="utf-8")
        _loop._promote_to_project(run_dir, None)

    def test_atomic_write(self, tmp_path):
        concepts_dir = tmp_path / "concepts"
        concepts_dir.mkdir()
        run_dir = tmp_path / "run_001"
        run_dir.mkdir()
        dm = {"version": "1"}
        (run_dir / "domain-model.json").write_text(
            json.dumps(dm), encoding="utf-8")
        (concepts_dir / "domain-model.json").write_text(
            '{"version": "old"}', encoding="utf-8")

        _loop._promote_to_project(run_dir, concepts_dir)

        promoted = json.loads(
            (concepts_dir / "domain-model.json").read_text())
        assert promoted["version"] == "1"
        # No .tmp files left behind
        tmps = list(concepts_dir.glob(".domain-model.json.*.tmp"))
        assert len(tmps) == 0


class TestStoreInSage:
    def test_no_domain_model_file(self, tmp_path):
        _loop._store_in_sage(tmp_path, "/repos/myproj")

    def test_sage_import_fails_gracefully(self, tmp_path):
        dm = {"version": "1", "concepts": [], "invariants": [], "contracts": []}
        (tmp_path / "domain-model.json").write_text(
            json.dumps(dm), encoding="utf-8")
        with patch.dict("sys.modules", {"core.sage.hooks": None}):
            _loop._store_in_sage(tmp_path, "/repos/myproj")
