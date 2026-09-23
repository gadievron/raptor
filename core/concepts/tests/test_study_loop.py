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
    return subprocess.run(  # noqa: PLW1510 - callers assert on returncode
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

    @staticmethod
    def _rl_item(item_id: str, **overrides) -> dict:
        item = {
            "id": item_id,
            "question": f"question {item_id}",
            "source_command": "audit",
            "resolved": False,
        }
        item.update(overrides)
        return item

    def test_promotes_reading_list(self, tmp_path):
        concepts_dir = tmp_path / "concepts"
        concepts_dir.mkdir()
        run_dir = tmp_path / "run_001"
        run_dir.mkdir()
        rl = {"items": [self._rl_item("rl-1", resolved=True)]}
        (run_dir / "reading-list.json").write_text(
            json.dumps(rl), encoding="utf-8")

        _loop._promote_to_project(run_dir, concepts_dir)

        promoted = json.loads(
            (concepts_dir / "reading-list.json").read_text())
        assert promoted["items"][0]["resolved"] is True

    def test_reading_list_promotion_merges(self, tmp_path):
        """Promotion folds the run's items into the canonical list —
        a byte-copy would erase items a concurrent run queued after
        this run seeded (lost update)."""
        concepts_dir = tmp_path / "concepts"
        concepts_dir.mkdir()
        run_dir = tmp_path / "run_001"
        run_dir.mkdir()
        # Canonical has an item this run never saw (concurrent writer)
        # plus one the run resolves.
        canonical = {"items": [
            self._rl_item("rl-concurrent"),
            self._rl_item("rl-shared"),
        ]}
        (concepts_dir / "reading-list.json").write_text(
            json.dumps(canonical), encoding="utf-8")
        run = {"items": [self._rl_item("rl-shared", resolved=True)]}
        (run_dir / "reading-list.json").write_text(
            json.dumps(run), encoding="utf-8")

        _loop._promote_to_project(run_dir, concepts_dir)

        promoted = json.loads(
            (concepts_dir / "reading-list.json").read_text())
        by_id = {i["id"]: i for i in promoted["items"]}
        assert set(by_id) == {"rl-concurrent", "rl-shared"}
        assert by_id["rl-shared"]["resolved"] is True

    def test_domain_model_promotion_merges(self, tmp_path):
        """The domain model merges into the canonical copy (run wins
        per id, everything else accumulates) and dict-level extras
        like subject_title survive."""
        concepts_dir = tmp_path / "concepts"
        concepts_dir.mkdir()
        run_dir = tmp_path / "run_001"
        run_dir.mkdir()
        canonical = {
            "concepts": [
                {"id": "other-run", "name": "B", "description": "d"},
            ],
            "invariants": [], "contracts": [],
            "architecture": {"style": "pipeline"},
        }
        (concepts_dir / "domain-model.json").write_text(
            json.dumps(canonical), encoding="utf-8")
        run = {
            "concepts": [
                {"id": "this-run", "name": "A", "description": "d"},
            ],
            "invariants": [], "contracts": [],
            "subject_title": "My Target",
        }
        (run_dir / "domain-model.json").write_text(
            json.dumps(run), encoding="utf-8")

        _loop._promote_to_project(run_dir, concepts_dir)

        promoted = json.loads(
            (concepts_dir / "domain-model.json").read_text())
        ids = {c["id"] for c in promoted["concepts"]}
        assert ids == {"other-run", "this-run"}
        assert promoted["subject_title"] == "My Target"
        assert promoted["architecture"] == {"style": "pipeline"}

    def test_patterns_promotion_merges(self, tmp_path):
        """A narrowly scoped run's patterns.json must never replace
        the whole-tree accumulation — merge keyed by pattern name."""
        concepts_dir = tmp_path / "concepts"
        concepts_dir.mkdir()
        run_dir = tmp_path / "run_001"
        run_dir.mkdir()
        (concepts_dir / "patterns.json").write_text(json.dumps({
            "patterns": {"old_fn": {"role": "allocator"}},
        }), encoding="utf-8")
        (run_dir / "patterns.json").write_text(json.dumps({
            "patterns": {"new_fn": {"role": "validator"}},
        }), encoding="utf-8")

        _loop._promote_to_project(run_dir, concepts_dir)

        promoted = json.loads(
            (concepts_dir / "patterns.json").read_text())
        assert set(promoted["patterns"]) == {"old_fn", "new_fn"}

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


class TestUnresolvableExcludedFromDrain:
    """The standalone study-loop driver must not drain or resolve
    items the consumer marked unresolvable — they were attempted and
    cannot be answered from the source."""

    def _write_rl(self, tmp_path):
        rl = {"items": [
            {"id": "rl-1", "question": "Does `alive_fn` check bounds?",
             "resolved": False, "resolution": "identifier"},
            {"id": "rl-2", "question": "Does `dead_fn` retry?",
             "resolved": False, "unresolvable": True,
             "unresolvable_reason": "monkey-patched",
             "resolution": "identifier"},
        ]}
        (tmp_path / "reading-list.json").write_text(json.dumps(rl))

    def test_pending_excludes_unresolvable(self, tmp_path):
        self._write_rl(tmp_path)
        pending = _loop._load_pending_reading_list(tmp_path)
        assert [i["id"] for i in pending] == ["rl-1"]


class TestCompileInvariantsExitCode:
    """A compile-invariants failure must propagate into the loop's exit
    code like the prep and study-run legs do — not exit 0 with zero
    compiled rules."""

    def _run_main(self, tmp_path, compile_rc: int) -> int:
        target = tmp_path / "src"
        target.mkdir()
        out = tmp_path / "out"
        out.mkdir()
        # Prep artefacts pre-seeded: the patched _run is a no-op, so
        # the files the real subcommands would write must exist.
        (out / "study-list.json").write_text(
            json.dumps({"items": []}), encoding="utf-8",
        )
        (out / "domain-model.json").write_text(
            json.dumps({"invariants": [{
                "statement": "refcount never drops below zero",
                "negation": "refcount drops below zero",
            }]}),
            encoding="utf-8",
        )

        def fake_run(cmd, *, verbose=False):
            if "raptor-compile-invariants" in cmd[1]:
                return compile_rc
            return 0

        argv = ["raptor-study-loop", str(target), str(out),
                "--identifier", "some_func"]
        with patch.object(_loop, "_run", side_effect=fake_run), \
                patch.object(sys, "argv", argv):
            return _loop.main()

    def test_compile_failure_sets_exit_code(self, tmp_path):
        assert self._run_main(tmp_path, compile_rc=3) == 3

    def test_compile_success_exits_zero(self, tmp_path):
        assert self._run_main(tmp_path, compile_rc=0) == 0


class TestFailedRunDoesNotPromote:
    """A failed run must not promote its domain model (possibly the
    PRIOR canonical copied in by _load_prior_knowledge) over the
    project store, nor store it in SAGE, nor pay the attach/synthesis
    pass."""

    def _run_main(self, tmp_path, prep_rc: int) -> tuple[int, Path]:
        target = tmp_path / "src"
        target.mkdir()
        project = tmp_path / "proj"
        out = project / "run_001"
        out.mkdir(parents=True)
        concepts = project / "concepts"
        concepts.mkdir()
        # Prior canonical model — _load_prior_knowledge copies it into
        # the run dir, so a failed run HAS a domain-model.json.
        (concepts / "domain-model.json").write_text(
            json.dumps({"concepts": [{"id": "prior"}],
                        "invariants": [], "contracts": []}),
            encoding="utf-8",
        )
        (out / "study-list.json").write_text(
            json.dumps({"items": []}), encoding="utf-8",
        )

        def fake_run(cmd, *, verbose=False):
            if "raptor-study-prep" in cmd[1]:
                return prep_rc
            return 0

        argv = ["raptor-study-loop", str(target), str(out),
                "--identifier", "some_func"]
        with patch.object(_loop, "_run", side_effect=fake_run), \
                patch.object(_loop, "_store_in_sage") as sage, \
                patch.object(_loop, "_promote_to_project") as promote, \
                patch.object(sys, "argv", argv):
            rc = _loop.main()
        self._sage_called = sage.called
        self._promote_called = promote.called
        return rc, concepts

    def test_failed_run_skips_promotion_and_sage(self, tmp_path):
        rc, _concepts = self._run_main(tmp_path, prep_rc=7)
        assert rc == 7
        assert not self._promote_called
        assert not self._sage_called

    def test_successful_run_still_promotes(self, tmp_path):
        rc, _concepts = self._run_main(tmp_path, prep_rc=0)
        assert rc == 0
        assert self._promote_called
        assert self._sage_called


class TestPriorKnowledgeAtomicity:
    def test_prior_copy_routes_through_atomic_writer(self, tmp_path,
                                                     monkeypatch):
        """A torn prior copy (crash mid-write) leaves a malformed
        reading-list that silently de-scopes the next prep to a
        full-tree scan — the copy must go through the shared atomic
        writer."""
        import core.atomic_fs as atomic_fs
        calls = []
        real = atomic_fs.write_text_atomically

        def recording(path, content, **kw):
            calls.append(Path(path))
            return real(path, content, **kw)

        monkeypatch.setattr(atomic_fs, "write_text_atomically", recording)
        concepts = tmp_path / "concepts"
        concepts.mkdir()
        (concepts / "reading-list.json").write_text(
            json.dumps({"items": []}), encoding="utf-8")
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        _loop._load_prior_knowledge(run_dir, concepts)
        assert run_dir / "reading-list.json" in calls
        assert json.loads(
            (run_dir / "reading-list.json").read_text()) == {"items": []}


class TestOverviewSymlinkExclusion:
    def test_symlinked_sources_not_inventoried(self, tmp_path):
        """A hostile tree's out-pointing symlink must not feed host
        file content into the overview prompt (the prep scan already
        excludes symlinks)."""
        outside = tmp_path / "outside.c"
        outside.write_text("int secret(void){return 0;}\n",
                           encoding="utf-8")
        target = tmp_path / "tree"
        target.mkdir()
        (target / "linked.c").symlink_to(outside)
        idents, concepts, summary, title = (
            _loop._overview_from_directory(target)
        )
        # Only a symlink in the tree → nothing inventoried, no LLM
        # call attempted.
        assert (idents, concepts, summary, title) == ([], [], "", "")


class TestRunEnvCuration:
    """_run hands children the curated LLM env, not a full environ copy."""

    def test_env_scrubbed_keys_forwarded_marker_set(self, monkeypatch):
        mod = _loop
        captured = {}

        def fake_run(cmd, **kwargs):
            captured.update(kwargs)

            class R:
                returncode = 0

            return R()

        monkeypatch.setattr(mod.subprocess, "run", fake_run)
        monkeypatch.setenv("EDITOR", "evil-editor")
        monkeypatch.setenv("SOME_RANDOM_SHELL_VAR", "leak-me")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")
        monkeypatch.setenv("RAPTOR_STUDY_MAX_OUTPUT_TOKENS", "9000")
        rc = mod._run([sys.executable, "-c", "pass"])
        assert rc == 0
        env = captured["env"]
        # Ambient shell state no longer flows to children...
        assert "EDITOR" not in env
        assert "SOME_RANDOM_SHELL_VAR" not in env
        # ...but what the LLM children consume does.
        assert env.get("ANTHROPIC_API_KEY") == "test-key-123"
        assert env.get("RAPTOR_STUDY_MAX_OUTPUT_TOKENS") == "9000"
        assert env.get("_RAPTOR_TRUSTED") == "1"

    def test_study_knob_absent_stays_absent(self, monkeypatch):
        mod = _loop
        captured = {}

        def fake_run(cmd, **kwargs):
            captured.update(kwargs)

            class R:
                returncode = 0

            return R()

        monkeypatch.setattr(mod.subprocess, "run", fake_run)
        monkeypatch.delenv("RAPTOR_STUDY_MAX_OUTPUT_TOKENS", raising=False)
        mod._run([sys.executable, "-c", "pass"])
        assert "RAPTOR_STUDY_MAX_OUTPUT_TOKENS" not in captured["env"]


class TestStudyReportSanitised:
    """domain-model.json fields are LLM-authored plus target-source
    bytes — study-report.md must carry no live markdown structure,
    fence escapes, or control bytes."""

    HOSTILE = "\x1b]0;pwned\x07\x9b2J‮evil"

    def test_hostile_domain_model_rendered_inert(self, tmp_path):
        dm = {
            "target": "/t",
            "subject_title": f"lib{self.HOSTILE}",
            "overview_summary": (
                f"# forged heading\n{self.HOSTILE}\n"
                "![exfil](//evil.example/x)"
            ),
            "key_files": [{"file": f"src/{self.HOSTILE}.c",
                           "role": "header",
                           "description": f"desc {self.HOSTILE}"}],
            "concepts": [],
            "struct_definitions": [{
                "name": f"s{self.HOSTILE}",
                "definition": "struct s {\n int x;\n};\n```\n# spilled",
                "doc_comment": f"doc {self.HOSTILE}",
            }],
            "struct_annotations": [],
            "contracts": [{"function": f"fn{self.HOSTILE}", "file": "a.h",
                           "when": f"when {self.HOSTILE}",
                           "security_note": f"sec {self.HOSTILE}"}],
            "invariants": [{"id": "INV-1",
                            "statement": f"stmt {self.HOSTILE}",
                            "negation": f"neg {self.HOSTILE}",
                            "relevant_cwes": ["CWE-787"]}],
            "bug_patterns": [{"description": f"bug {self.HOSTILE}. More."}],
            "state_machines": [{"name": f"sm{self.HOSTILE}",
                                "description": f"d {self.HOSTILE}",
                                "states": [{"name": "S|0",
                                            "description": f"x {self.HOSTILE}"}]}],
            "security_context": {"privilege_level": f"root {self.HOSTILE}",
                                 "trust_summary": f"t {self.HOSTILE}"},
        }
        (tmp_path / "domain-model.json").write_text(json.dumps(dm))
        _loop._render_study_report(tmp_path)
        report = (tmp_path / "study-report.md").read_text()
        for raw in ("\x1b", "\x07", "\x9b", "‮"):
            assert raw not in report
        # No forged heading from LLM prose (line-leading # defanged).
        assert "\n# forged heading" not in report
        # The struct definition's embedded fence cannot terminate the
        # wrapping ```c block: no bare ``` line between the wrappers.
        body = report.split("```c", 1)[1]
        inner = body.split("\n```\n", 1)[0]
        assert "# spilled" in inner  # stayed INSIDE the fence
        # Autofetch markup is stripped from prose.
        assert "//evil.example" not in report


class TestStructDefinitionsTolerateMalformedItems:
    """Report attachment of struct definitions runs AFTER the paid
    study completed; a malformed study-list item (LLM-adjacent
    artifact) must be skipped, never raise past the block's
    (OSError, ValueError) handlers and throw away the report,
    project promotion, and SAGE storage."""

    def test_nameless_item_is_skipped_not_keyerror(self) -> None:
        sl = {"items": [
            {"kind": "struct", "relevance_tier": 1},          # no name
            {"kind": "struct", "name": "", "relevance_tier": 1},
            {"kind": "struct", "name": "good", "relevance_tier": 2,
             "file": "a.h"},
        ]}
        defs = _loop._struct_definitions(sl)
        assert [d["name"] for d in defs] == ["good"]

    def test_junk_tier_keeps_item(self) -> None:
        # Fail toward review: an unparseable tier must neither crash
        # (TypeError on the > comparison) nor silently drop the item.
        sl = {"items": [
            {"kind": "struct", "name": "s1", "relevance_tier": "3"},
            {"kind": "struct", "name": "s2", "relevance_tier": None},
            {"kind": "struct", "name": "deep", "relevance_tier": 3},
            {"kind": "other", "name": "not-a-struct"},
            "not-a-dict",
        ]}
        defs = _loop._struct_definitions(sl)
        assert [d["name"] for d in defs] == ["s1", "s2"]
