"""Attach lifecycle: project bindings, CLI, and finding sync."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from packages.ghidra.model import REDatabase, REFunction


@pytest.fixture
def gpr_project(tmp_path):
    gpr = tmp_path / "gpr-home" / "firmware.gpr"
    gpr.parent.mkdir()
    gpr.write_text("")
    (gpr.parent / "firmware.rep").mkdir()
    return gpr


@pytest.fixture
def project_env(tmp_path, gpr_project, monkeypatch):
    """An active project whose manager resolves from attach's code."""
    from core.project.project import ProjectManager

    projects_dir = tmp_path / "projects"
    mgr = ProjectManager(projects_dir=projects_dir)
    project = mgr.create(
        "attach-proj", str(tmp_path / "target-code"),
        description="attach tests",
        output_dir=str(tmp_path / "project-out"),
    )

    import packages.ghidra.attach as attach_mod
    monkeypatch.setattr(
        attach_mod, "_load_project",
        lambda project_name=None: (mgr, mgr.load("attach-proj")),
    )
    return mgr, project


def _test_db():
    return REDatabase(
        source_tool="ghidra",
        binary_path="/test/firmware",
        functions=[
            REFunction(name="parse_input", address=0x4000, size=200,
                       source_tool="ghidra"),
            REFunction(name="handle_auth", address=0x5000, size=150,
                       source_tool="ghidra"),
            REFunction(name="process_cmd", address=0x6000, size=300,
                       source_tool="ghidra"),
        ],
    )


class TestProjectModel:
    def test_round_trip_with_ghidra_projects(self, tmp_path, gpr_project):
        from core.project.project import Project
        p = Project(
            name="t", target="/some/path",
            output_dir=str(tmp_path / "out"),
            ghidra_projects=[str(gpr_project), "/another/project.gpr"],
        )
        d = p.to_dict()
        assert len(d["ghidra_projects"]) == 2
        p2 = Project.from_dict(d)
        assert p2.ghidra_projects == p.ghidra_projects

    def test_back_compat_pre_ghidra_files(self):
        from core.project.project import Project
        for version in (1, 3, 4):
            p = Project.from_dict({
                "version": version, "name": "old",
                "target": "/old/path", "output_dir": "/old/out",
            })
            assert p.ghidra_projects == []

    def test_schema_version_covers_ghidra(self):
        from core.project.project import _PROJECT_SCHEMA_VERSION, Project
        assert _PROJECT_SCHEMA_VERSION >= 5
        assert Project(name="x", target="t", output_dir="o").version \
            == _PROJECT_SCHEMA_VERSION

    def test_malformed_field_dropped(self):
        from core.project.project import Project
        p = Project.from_dict({
            "name": "x", "target": "t", "output_dir": "o",
            "ghidra_projects": {"not": "a list"},
        })
        assert p.ghidra_projects == []
        p2 = Project.from_dict({
            "name": "x", "target": "t", "output_dir": "o",
            "ghidra_projects": ["/ok.gpr", 42, None],
        })
        assert p2.ghidra_projects == ["/ok.gpr"]


class TestAttachLifecycle:
    def test_attach_registers_and_returns_cache_dir(
        self, project_env, gpr_project,
    ):
        from packages.ghidra.attach import attach, get_attached_projects
        cache = attach(gpr_project, import_now=False)
        assert cache.is_dir()
        # NOT dot-prefixed (Ghidra refuses hidden path elements for
        # the in-cache headless working copy); run management skips
        # it by name instead.
        assert cache.parent.name == "ghidra-attach"
        assert cache.name.startswith(f"{gpr_project.stem}-")
        assert get_attached_projects() == [str(gpr_project.resolve())]

    def test_same_stem_attachments_get_distinct_caches(
        self, project_env, tmp_path,
    ):
        """Cross-version layouts (v1/fw.gpr, v2/fw.gpr) — and hostile
        bundles reusing a common stem — must never share a cache dir:
        a shared slot let one attachment's database masquerade as
        another's, misdirecting name→address enrichment placement."""
        from packages.ghidra.attach import attach
        caches = set()
        for ver in ("v1", "v2"):
            g = tmp_path / ver / "fw.gpr"
            g.parent.mkdir()
            g.write_text("")
            caches.add(attach(g, import_now=False))
        assert len(caches) == 2

    def test_attach_rejects_control_characters(self, project_env, tmp_path):
        from packages.ghidra.attach import attach
        with pytest.raises(ValueError, match="control characters"):
            attach(str(tmp_path / "evil\x1b]0;x\x07.gpr"),
                   import_now=False)

    def test_attach_idempotent(self, project_env, gpr_project):
        from packages.ghidra.attach import attach, get_attached_projects
        attach(gpr_project, import_now=False)
        attach(gpr_project, import_now=False)
        assert len(get_attached_projects()) == 1

    def test_attach_rejects_non_gpr(self, project_env, tmp_path):
        from packages.ghidra.attach import attach
        not_gpr = tmp_path / "binary.elf"
        not_gpr.write_bytes(b"\x7fELF")
        with pytest.raises(ValueError, match="not a Ghidra project"):
            attach(not_gpr, import_now=False)
        with pytest.raises(ValueError, match="not a Ghidra project"):
            attach(tmp_path / "missing.gpr", import_now=False)

    def test_attach_without_project_fails_loud(
        self, gpr_project, monkeypatch,
    ):
        import packages.ghidra.attach as attach_mod
        monkeypatch.setattr(
            attach_mod, "_load_project",
            lambda project_name=None: (None, None),
        )
        with pytest.raises(ValueError, match="no active RAPTOR project"):
            attach_mod.attach(gpr_project, import_now=False)

    def test_detach_specific_and_all(self, project_env, tmp_path):
        from packages.ghidra.attach import (
            attach,
            detach,
            get_attached_projects,
        )
        gprs = []
        for i in range(3):
            g = tmp_path / f"p{i}" / f"proj{i}.gpr"
            g.parent.mkdir()
            g.write_text("")
            gprs.append(g)
            attach(g, import_now=False)
        assert detach(gprs[1]) == 1
        assert len(get_attached_projects()) == 2
        assert detach() == 2
        assert get_attached_projects() == []
        assert detach() == 0

    def test_import_now_runs_bridge(self, project_env, gpr_project):
        calls = {}

        class FakeBridge:
            def __init__(self, gpr, program_name=None):
                calls["gpr"] = Path(gpr)

            def import_project(self, out_dir, **kw):
                calls["out_dir"] = Path(out_dir)
                return _test_db()

            def close(self):
                calls["closed"] = True

        with patch("packages.ghidra.bridge.GhidraBridge", FakeBridge):
            from packages.ghidra.attach import attach
            cache = attach(gpr_project)
        assert calls["gpr"] == gpr_project.resolve()
        assert calls["out_dir"] == cache
        assert calls["closed"] is True


class TestResolver:
    def test_context_inject_resolver_reads_attachments(
        self, project_env, gpr_project,
    ):
        from packages.ghidra.attach import attach
        from packages.ghidra.context_inject import _resolve_ghidra_projects
        attach(gpr_project, import_now=False)
        with patch("packages.ghidra.attach.get_attached_projects",
                   return_value=[str(gpr_project)]) as gap:
            assert _resolve_ghidra_projects(Path("/x")) == [
                str(gpr_project)]
            gap.assert_called_once()

    def test_resolver_degrades_to_empty(self):
        from packages.ghidra.context_inject import _resolve_ghidra_projects
        with patch("packages.ghidra.attach.get_attached_projects",
                   side_effect=RuntimeError("boom")):
            assert _resolve_ghidra_projects(Path("/x")) == []


class TestSyncFindingsToAttached:
    @pytest.fixture
    def sync_env(self, project_env, gpr_project, tmp_path):
        mgr, project = project_env
        # cached redb in the RAPTOR-owned attach location
        from packages.ghidra.attach import attach_dir
        ghidra_dir = attach_dir(project, gpr_project)
        ghidra_dir.mkdir(parents=True)
        (ghidra_dir / "re-database.json").write_text(
            json.dumps(_test_db().to_dict()))
        out_dir = tmp_path / "run-output"
        out_dir.mkdir()
        return project, out_dir, str(gpr_project.resolve())

    def _populate_agentic(self, out_dir):
        (out_dir / "analysed_results.json").write_text(json.dumps([{
            "repo_path": "/test/target-code",
            "is_true_positive": True,
            "is_exploitable": True,
            "message": "heap overflow in parse_input",
            "level": "error",
            "metadata": {"name": "parse_input"},
            "analysis": {
                "reasoning": "Heap buffer overflow via unchecked memcpy",
            },
        }]))

    def _populate_journal(self, out_dir):
        (out_dir / "review-journal.jsonl").write_text(json.dumps({
            "ts": "2026-08-24T00:00:00Z", "run_id": "test-run-001",
            "file": "src/auth.c", "function": "handle_auth",
            "verdict": "finding", "source_hash": "abc123",
            "body": "Authentication bypass via integer overflow",
            "cwe": "CWE-190",
        }) + "\n")

    def _populate_annotations(self, out_dir):
        ann = out_dir / "annotations" / "src"
        ann.mkdir(parents=True)
        (ann / "cmd.c.md").write_text(
            "# src/cmd.c\n\n"
            "## process_cmd\n"
            "<!-- meta: status=suspicious cwe=CWE-78 -->\n\n"
            "Command injection via unsanitised user input\n",
        )

    def _run_sync(self, out_dir, gpr_resolved, export_calls):
        class FakeBridge:
            def __init__(self, gpr, **kw):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.close()

            def export_enrichments(self, db, output_gpr, *,
                                   findings=None):
                export_calls.append({
                    "output_gpr": str(output_gpr),
                    "findings": list(findings or []),
                })
                return output_gpr

            def close(self):
                pass

        with patch("packages.ghidra.attach.get_attached_projects",
                   return_value=[gpr_resolved]), \
             patch("packages.ghidra.bridge.GhidraBridge", FakeBridge):
            from packages.ghidra.attach import sync_findings_to_attached
            return sync_findings_to_attached(
                out_dir, target_path=Path("/test/target-code"),
            )

    def test_all_data_types_synced_one_pass(self, sync_env):
        """All three sources export in ONE apply pass per attachment
        (multiple passes each re-copy the project and clobber the
        previous pass), with names resolved to binary addresses."""
        _project, out_dir, gpr_resolved = sync_env
        self._populate_agentic(out_dir)
        self._populate_journal(out_dir)
        self._populate_annotations(out_dir)

        export_calls = []
        total = self._run_sync(out_dir, gpr_resolved, export_calls)

        assert total == 3
        assert len(export_calls) == 1, (
            "one combined apply pass per attachment — per-source "
            "passes clobber each other"
        )
        by_addr = {f.get("address"): f
                   for f in export_calls[0]["findings"]}
        assert 0x4000 in by_addr
        assert "Heap buffer overflow" in by_addr[0x4000]["summary"]
        assert 0x5000 in by_addr
        assert "Authentication bypass" in by_addr[0x5000]["summary"]
        assert 0x6000 in by_addr
        assert "Suspicious" in by_addr[0x6000]["summary"]
        assert by_addr[0x6000]["severity"] == "Medium"

    def test_agentic_address_mapping(self, sync_env):
        _project, out_dir, gpr_resolved = sync_env
        self._populate_agentic(out_dir)
        export_calls = []
        self._run_sync(out_dir, gpr_resolved, export_calls)
        findings = export_calls[0]["findings"]
        assert len(findings) == 1
        assert findings[0]["address"] == 0x4000

    def test_no_data_produces_zero(self, sync_env):
        _project, out_dir, gpr_resolved = sync_env
        with patch("packages.ghidra.attach.get_attached_projects",
                   return_value=[gpr_resolved]):
            from packages.ghidra.attach import sync_findings_to_attached
            assert sync_findings_to_attached(out_dir) == 0

    def test_no_attachments_zero_without_collect(self, tmp_path):
        with patch("packages.ghidra.attach.get_attached_projects",
                   return_value=[]):
            from packages.ghidra.attach import sync_findings_to_attached
            assert sync_findings_to_attached(tmp_path) == 0

    def test_missing_gpr_skipped(self, sync_env):
        _project, out_dir, _ = sync_env
        self._populate_agentic(out_dir)
        with patch("packages.ghidra.attach.get_attached_projects",
                   return_value=["/nonexistent/gone.gpr"]):
            from packages.ghidra.attach import sync_findings_to_attached
            assert sync_findings_to_attached(out_dir) == 0

    def test_unresolved_names_stay_name_keyed(self, sync_env):
        """A function absent from the cached db keeps its name key —
        Ghidra-side resolution handles (or skips) it there."""
        _project, out_dir, gpr_resolved = sync_env
        (out_dir / "analysed_results.json").write_text(json.dumps([{
            "is_true_positive": True, "is_exploitable": True,
            "message": "x", "level": "error",
            "metadata": {"name": "not_in_db"},
            "analysis": {"reasoning": "y"},
        }]))
        export_calls = []
        self._run_sync(out_dir, gpr_resolved, export_calls)
        f = export_calls[0]["findings"][0]
        assert f.get("address") is None
        assert f["function"] == "not_in_db"


class TestProjectGhidraCLI:
    def _cli(self, argv, monkeypatch, mgr):
        import core.project.cli as cli_mod
        monkeypatch.setattr(cli_mod, "ProjectManager", lambda: mgr)
        monkeypatch.setattr(cli_mod, "_get_active_project",
                            lambda: "cli-proj")
        monkeypatch.setattr(
            cli_mod, "_acquire_mutation_lock", lambda m, a: None,
        )
        monkeypatch.setattr("sys.argv", ["raptor-project-manager"] + argv)
        try:
            cli_mod.main()
        except SystemExit:
            pass

    @pytest.fixture
    def cli_env(self, tmp_path):
        from core.project.project import ProjectManager
        mgr = ProjectManager(projects_dir=tmp_path / "projects")
        mgr.create("cli-proj", str(tmp_path / "target"),
                   description="cli",
                   output_dir=str(tmp_path / "out"))
        return mgr

    def test_add_list_remove_clear(self, cli_env, gpr_project,
                                   monkeypatch, capsys):
        mgr = cli_env
        self._cli(["ghidra", "add", str(gpr_project)], monkeypatch, mgr)
        assert "Attached" in capsys.readouterr().out
        assert mgr.load("cli-proj").ghidra_projects == [
            str(gpr_project.resolve())]

        self._cli(["ghidra", "list"], monkeypatch, mgr)
        assert str(gpr_project.resolve()) in capsys.readouterr().out

        self._cli(["ghidra", "remove", str(gpr_project)],
                  monkeypatch, mgr)
        capsys.readouterr()
        assert mgr.load("cli-proj").ghidra_projects == []

        self._cli(["ghidra", "add", str(gpr_project)], monkeypatch, mgr)
        capsys.readouterr()
        self._cli(["ghidra", "clear"], monkeypatch, mgr)
        capsys.readouterr()
        assert mgr.load("cli-proj").ghidra_projects == []

    def test_add_rejects_non_gpr(self, cli_env, tmp_path,
                                 monkeypatch, capsys):
        mgr = cli_env
        bogus = tmp_path / "not-a-project.txt"
        bogus.write_text("")
        self._cli(["ghidra", "add", str(bogus)], monkeypatch, mgr)
        assert "not an existing .gpr" in capsys.readouterr().out
        assert mgr.load("cli-proj").ghidra_projects == []


class TestSyncHonesty:
    def test_failed_attachment_reported(self, tmp_path, monkeypatch):
        import packages.ghidra.attach as attach_mod
        monkeypatch.setattr(
            attach_mod, "_load_project",
            lambda project_name=None: (None, None),
        )
        (tmp_path / "analysed_results.json").write_text(json.dumps([{
            "is_true_positive": True, "is_exploitable": True,
            "message": "x", "level": "error",
            "metadata": {"name": "f"}, "analysis": {"reasoning": "y"},
        }]))
        with patch("packages.ghidra.attach.get_attached_projects",
                   return_value=["/gone/missing.gpr"]):
            result = attach_mod.sync_findings_to_attached(tmp_path)
        assert int(result) == 0
        assert result.failed == ["/gone/missing.gpr"]
        assert result.attachments == 1

    def test_per_attachment_export_subdirs(self, tmp_path, monkeypatch):
        """Two same-stem attachments must not share a working-copy
        slot — the second apply would delete the first's enriched
        copy."""
        import packages.ghidra.attach as attach_mod
        from core.project.project import ProjectManager
        mgr = ProjectManager(projects_dir=tmp_path / "projects")
        mgr.create("sync-proj", str(tmp_path / "t"),
                   output_dir=str(tmp_path / "out"))
        monkeypatch.setattr(
            attach_mod, "_load_project",
            lambda project_name=None: (mgr, mgr.load("sync-proj")),
        )
        gprs = []
        for ver in ("v1", "v2"):
            g = tmp_path / ver / "fw.gpr"
            g.parent.mkdir()
            g.write_text("")
            gprs.append(str(g.resolve()))
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / "analysed_results.json").write_text(json.dumps([{
            "is_true_positive": True, "is_exploitable": True,
            "message": "x", "level": "error",
            "metadata": {"name": "f"}, "analysis": {"reasoning": "y"},
        }]))
        seen_dirs = []

        class FakeBridge:
            def __init__(self, gpr, **kw):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.close()

            def export_enrichments(self, db, output_gpr, *,
                                   findings=None):
                seen_dirs.append(Path(output_gpr).parent)
                return output_gpr

            def close(self):
                pass

        with patch("packages.ghidra.attach.get_attached_projects",
                   return_value=gprs), \
             patch("packages.ghidra.bridge.GhidraBridge", FakeBridge):
            result = attach_mod.sync_findings_to_attached(run_dir)
        assert int(result) == 2 and not result.failed
        assert len(set(seen_dirs)) == 2, (
            "same-stem attachments shared a working-copy slot"
        )


class TestCacheOnlyAutoInjection:
    def test_auto_path_never_live_imports(self, tmp_path, monkeypatch):
        from packages.ghidra import context_inject
        gpr = tmp_path / "bundle.gpr"
        gpr.write_text("")
        called = {}
        monkeypatch.setattr(
            context_inject, "_resolve_ghidra_projects",
            lambda repo: [str(gpr)],
        )
        monkeypatch.setattr(
            context_inject, "_load_cached_redb", lambda p: None,
        )
        monkeypatch.setattr(
            context_inject, "_live_import",
            lambda p: (called.setdefault("live", True), None)[1],
        )
        context_inject.prepare_ghidra_context(tmp_path / "repo-auto")
        assert "live" not in called, (
            "auto-resolved attachments must be cache-only — a live "
            "import would parse the hostile bundle unprompted"
        )
        # explicit list keeps the live-import fallback
        context_inject.prepare_ghidra_context(
            tmp_path / "repo-explicit", ghidra_projects=[str(gpr)],
        )
        assert called.get("live") is True


class TestCleanNeverTouchesCaches:
    def test_attach_cache_invisible_to_run_scan(self, project_env,
                                                gpr_project, tmp_path):
        """/project clean's run scanner must never see attach caches —
        it would stamp them with adopted run metadata and delete them
        under the keep quota."""
        from packages.ghidra.attach import attach
        mgr, project = project_env
        cache = attach(gpr_project, import_now=False)
        (cache / "re-database.json").write_text("{}")
        # a real run dir alongside, so the scan has something to see
        (Path(project.output_dir) / "scan_20260825_000000").mkdir()
        fresh = mgr.load("attach-proj")
        run_dirs = [d.name for d in fresh._list_run_dirs()]
        assert run_dirs == ["scan_20260825_000000"]
        assert not (cache / ".raptor-run.json").exists()


class TestOrchestratedPromptInjection:
    def test_prime_reaches_dispatch_prompt_builder(self, tmp_path,
                                                   monkeypatch):
        """The orchestrated dispatch path builds prompts via
        build_analysis_prompt_bundle_from_finding — the parent-process
        prime must be consumed THERE, or the feature is dead code in
        the default /agentic mode — prime and injection previously
        lived in paths that never met."""
        import json as _json

        from packages.ghidra import context_inject

        repo = tmp_path / "repo"
        repo.mkdir()
        gpr = tmp_path / "fw.gpr"
        gpr.write_text("")
        cache = tmp_path / "cache"
        cache.mkdir()
        db = _test_db()
        for f in db.functions:
            if f.name == "parse_input":
                f.decompilation = "int parse_input(char *b){ /* d */ }"
        (cache / "re-database.json").write_text(_json.dumps(db.to_dict()))

        monkeypatch.setattr(
            context_inject, "_resolve_ghidra_projects",
            lambda rp: [str(gpr)],
        )
        # candidates come from roundtrip inside _load_cached_redb
        import packages.ghidra.roundtrip as rt
        monkeypatch.setattr(
            rt, "redb_cache_candidates",
            lambda gp: [cache / "re-database.json"],
        )
        context_inject.clear_ghidra_cache()
        context_inject.prepare_ghidra_context(repo)

        from packages.llm_analysis.prompts.analysis import (
            build_analysis_prompt_bundle_from_finding,
        )
        finding = {
            "rule_id": "c-buffer-overflow",
            "level": "error",
            "message": "overflow",
            "file_path": "src/x.c",
            "region": {"startLine": 1},
            "snippet": "int x;",
            "repo_path": str(repo),
            "metadata": {"name": "parse_input"},
        }
        bundle = build_analysis_prompt_bundle_from_finding(finding)
        rendered = bundle.user_prompt if hasattr(bundle, "user_prompt") \
            else str(bundle)
        assert "parse_input(char *b)" in rendered, (
            "primed Ghidra context did not reach the dispatch-path "
            "prompt"
        )
        context_inject.clear_ghidra_cache()


class TestCacheShapeHardening:
    def test_decompilation_clip_bounds_bytes_and_lines(self):
        """200 retained lines of unbounded length must not bypass the
        char budget (the elif made the byte cap unreachable for any
        function over the line cap)."""
        from packages.ghidra.context_inject import (
            _MAX_DECOMP_CHARS,
            _render_function_context,
        )
        from packages.ghidra.model import REDatabase, REFunction
        fat = REFunction(
            name="fat", address=0x1000, size=4, source_tool="ghidra",
            decompilation="\n".join("A" * 10_000 for _ in range(250)),
        )
        db = REDatabase(source_tool="ghidra", binary_path="/t/fw",
                        functions=[fat])
        parts = _render_function_context(fat, db)
        decomp_part = next(p for p in parts if "Decompilation" in p)
        assert len(decomp_part) < _MAX_DECOMP_CHARS + 1024
        assert "truncated" in decomp_part

    def test_wrong_shape_cache_degrades_not_crashes(self, project_env,
                                                    gpr_project):
        """Valid-JSON-wrong-shape caches (AttributeError territory)
        must degrade to name-keyed findings, never crash status or
        abort the sync loop before healthy attachments."""

        from packages.ghidra.attach import _load_attached_db, attach_dir
        _mgr, project = project_env
        cache = attach_dir(project, gpr_project)
        cache.mkdir(parents=True)
        for hostile in ('[]', '[{"a":1}]', '{"functions": "notalist"}',
                        '{"functions": [42]}'):
            (cache / "re-database.json").write_text(hostile)
            assert _load_attached_db(gpr_project, project) is None

    def test_corrupt_cache_does_not_abort_multi_attachment_sync(
        self, project_env, tmp_path,
    ):
        import json as _json

        from packages.ghidra.attach import attach_dir
        import packages.ghidra.attach as attach_mod
        _mgr, project = project_env
        good = tmp_path / "good" / "fw.gpr"
        bad = tmp_path / "bad" / "fw.gpr"
        for g in (good, bad):
            g.parent.mkdir()
            g.write_text("")
        bad_cache = attach_dir(project, bad)
        bad_cache.mkdir(parents=True)
        (bad_cache / "re-database.json").write_text("[]")  # wrong shape
        run = tmp_path / "run"
        run.mkdir()
        (run / "analysed_results.json").write_text(_json.dumps([{
            "is_true_positive": True, "is_exploitable": True,
            "message": "x", "level": "error",
            "metadata": {"name": "f"}, "analysis": {"reasoning": "y"},
        }]))
        calls = []

        class FakeBridge:
            def __init__(self, gpr, **kw):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                pass

            def export_enrichments(self, db, output_gpr, *,
                                   findings=None):
                calls.append(str(output_gpr))
                return output_gpr

        with __import__("unittest.mock", fromlist=["patch"]).patch(
                "packages.ghidra.attach.get_attached_projects",
                return_value=[str(bad.resolve()), str(good.resolve())]), \
             __import__("unittest.mock", fromlist=["patch"]).patch(
                "packages.ghidra.bridge.GhidraBridge", FakeBridge):
            result = attach_mod.sync_findings_to_attached(run)
        # both attachments export (the corrupt cache only degrades
        # address resolution); nothing crashed
        assert int(result) == 2 and not result.failed
        assert len(calls) == 2

    def test_orchestrated_report_shape_syncs(self, project_env,
                                             gpr_project, tmp_path):
        """The run-written report shape (not just the explicit-input
        list) must flow through sync."""
        import json as _json

        import packages.ghidra.attach as attach_mod
        run = tmp_path / "run-orch"
        run.mkdir()
        (run / "orchestrated_report.json").write_text(_json.dumps({
            "results": [{
                "is_true_positive": True, "is_exploitable": True,
                "message": "scanner says overflow", "level": "error",
                "reasoning": "LLM-grade reasoning text",
                "analysis": None,
                "metadata": {"name": "parse_input"},
            }],
        }))
        got = []

        class FakeBridge:
            def __init__(self, gpr, **kw):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                pass

            def export_enrichments(self, db, output_gpr, *,
                                   findings=None):
                got.extend(findings or [])
                return output_gpr

        with __import__("unittest.mock", fromlist=["patch"]).patch(
                "packages.ghidra.attach.get_attached_projects",
                return_value=[str(gpr_project.resolve())]), \
             __import__("unittest.mock", fromlist=["patch"]).patch(
                "packages.ghidra.bridge.GhidraBridge", FakeBridge):
            result = attach_mod.sync_findings_to_attached(run)
        assert int(result) == 1
        assert "LLM-grade reasoning" in got[0]["summary"]

    def test_sync_result_pickle_and_truthiness(self):
        import copy
        import pickle

        from packages.ghidra.attach import SyncResult
        r = SyncResult(0, ["/gone.gpr"], 1)
        assert bool(r) is False and r.failed  # the documented trap
        r2 = pickle.loads(pickle.dumps(r))
        assert r2.failed == ["/gone.gpr"] and r2.attachments == 1
        r3 = copy.copy(r)
        assert r3.failed == ["/gone.gpr"]

    def test_explicit_to_export_dedups_journal(self, tmp_path):
        """Parity: the --to form must not double-submit orchestrated
        findings that were also journaled."""
        import json as _json

        from packages.ghidra.roundtrip import export_all_to_ghidra
        out = tmp_path / "run"
        out.mkdir()
        gpr = tmp_path / "t.gpr"
        gpr.write_text("")
        (out / "review-journal.jsonl").write_text(_json.dumps({
            "ts": "t", "run_id": "r", "file": "a.c",
            "function": "handle_auth", "verdict": "finding",
            "source_hash": "h", "body": "journal copy",
        }) + "\n")
        results = [{
            "is_true_positive": True, "is_exploitable": True,
            "message": "agentic copy", "level": "error",
            "metadata": {"name": "handle_auth"},
            "analysis": {"reasoning": "agentic reasoning"},
        }]
        from unittest.mock import MagicMock, patch
        mock_bridge = MagicMock()
        mock_bridge.__enter__.return_value = mock_bridge
        mock_bridge.export_enrichments.return_value = tmp_path / "e.gpr"
        with patch("packages.ghidra.bridge.GhidraBridge",
                   return_value=mock_bridge):
            counts = export_all_to_ghidra(out, gpr, results)
        assert counts["total"] == 1, "journal row not deduped vs agentic"


def _load_ghidra_cli(monkeypatch):
    """Import libexec/raptor-ghidra as a module (loader test pattern,
    see packages/cve_diff's libexec tests)."""
    import importlib.util
    from importlib.machinery import SourceFileLoader
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    repo_root = Path(__file__).resolve().parents[3]
    loader = SourceFileLoader(
        "raptor_ghidra_cli_under_test",
        str(repo_root / "libexec" / "raptor-ghidra"),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class TestCacheLayoutAndCollectorHardening:
    def test_headless_refuses_hidden_path_elements(self, tmp_path):
        """Ghidra rejects project paths with dot-prefixed elements
        ("Path element starting with '.' is not permitted") only
        after a full JVM launch — the guard must fail first with an
        actionable message, before the tool lookup (hermetic on
        Ghidra-less hosts)."""
        from packages.ghidra.headless import (
            GhidraError,
            _refuse_hidden_path_elements,
            export_project,
        )
        hidden_out = (tmp_path / ".cache" / "slot"
                      / "re-database.json")
        with pytest.raises(GhidraError, match="hidden"):
            export_project(tmp_path / "fw.gpr", hidden_out)
        # clean paths pass the guard silently
        _refuse_hidden_path_elements(
            tmp_path / "clean" / "slot", "working copy")

    def test_attach_cache_candidate_ordered_before_legacy_global(
        self, tmp_path,
    ):
        """Readers take the first existing candidate: a stale
        cwd-relative one-shot-import cache (stem-only key, any prior
        `raptor-ghidra import` of ANY same-stem project) listed
        first shadowed every same-stem attachment's path-hashed
        cache — the exact masquerade the hash was built to stop."""
        from packages.ghidra.attach import attach_dir
        from packages.ghidra.roundtrip import redb_cache_candidates

        proj = type("P", (), {"output_dir": str(tmp_path / "out")})()

        class FakeMgr:
            def get_active(self):
                return "p"

            def load(self, name):
                return proj

        gpr = tmp_path / "v1" / "fw.gpr"
        with patch("core.project.project.ProjectManager", FakeMgr):
            cands = redb_cache_candidates(gpr)
        assert cands[0] == attach_dir(proj, gpr) / "re-database.json"
        # Legacy global candidate stays LAST — resolved against the
        # configured out base, not the process CWD.
        from core.config import RaptorConfig
        assert cands[-1] == (
            RaptorConfig.get_out_dir() / "ghidra-import-fw"
            / "re-database.json")

    def test_sequential_shape_records_export(self):
        """Sequential runs (vuln.to_dict() in the autonomous report)
        carry is_true_positive only inside `analysis` — the top-level
        filter alone dropped every sequential record, so the LLM's
        reasoning never reached Ghidra."""
        from packages.ghidra.roundtrip import collect_agentic_findings
        rec = {
            "finding_id": "f1", "message": "overflow", "level": "error",
            "exploitable": True, "exploitability_score": 9,
            "analysis": {"is_true_positive": True,
                         "reasoning": "seq reasoning"},
            "metadata": {"name": "parse_input"},
        }
        got = collect_agentic_findings([rec])
        assert len(got) == 1
        assert got[0]["summary"] == "seq reasoning"
        assert got[0]["function"] == "parse_input"

    def test_top_level_false_tp_not_overridden_by_analysis(self):
        """An explicit top-level is_true_positive=False (orchestrated
        merge verdict) must win over a stale analysis-dict True."""
        from packages.ghidra.roundtrip import collect_agentic_findings
        rec = {
            "exploitable": True, "is_true_positive": False,
            "analysis": {"is_true_positive": True},
        }
        assert collect_agentic_findings([rec]) == []

    def test_duplicate_name_stays_name_keyed(self):
        """A name defined twice in ONE database must not be anchored
        to the first match's address — sync would place the comment
        on the wrong function with no ambiguity marker."""
        from packages.ghidra.attach import _resolve_addresses
        db = REDatabase(
            source_tool="ghidra", binary_path="/fw/one.bin",
            functions=[
                REFunction(name="dup", address=0x1000, size=10,
                           source_tool="ghidra"),
                REFunction(name="dup", address=0x2000, size=10,
                           source_tool="ghidra"),
                REFunction(name="uniq", address=0x3000, size=10,
                           source_tool="ghidra"),
            ],
        )
        out = _resolve_addresses(
            [{"function": "dup", "address": None},
             {"function": "uniq", "address": None}], db)
        assert out[0]["address"] is None
        assert out[1]["address"] == 0x3000

    def test_same_db_duplicate_note_names_no_phantom_database(
        self, tmp_path,
    ):
        """For duplicates inside ONE database the old note claimed
        the function was "ALSO defined in 1 other attached
        database(s) (<this same binary>)" — self-contradicting the
        header line above it."""
        from packages.ghidra import context_inject
        db = REDatabase(
            source_tool="ghidra", binary_path="/fw/one.bin",
            functions=[
                REFunction(name="dup", address=0x1000, size=10,
                           source_tool="ghidra",
                           signature="int dup(void)"),
                REFunction(name="dup", address=0x2000, size=10,
                           source_tool="ghidra",
                           signature="int dup(int)"),
            ],
        )
        key = str((tmp_path / "repo").resolve())
        idx = context_inject._build_func_index([db])
        with context_inject._GHIDRA_LOCK:
            context_inject._GHIDRA_CACHE[key] = [db]
            context_inject._GHIDRA_FUNC_INDEX[key] = idx
        try:
            blocks = context_inject.ghidra_blocks_for_finding({
                "repo_path": str(tmp_path / "repo"),
                "metadata": {"name": "dup"},
            })
            assert blocks
            body = blocks[0].content
            assert "in this same database" in body
            assert "other attached database" not in body
            # the binary is named once, in the header — not again as
            # if it were a different database
            assert body.count("/fw/one.bin") == 1
        finally:
            context_inject.clear_ghidra_cache()

    def test_cross_db_duplicate_note_still_names_other_binary(
        self, tmp_path,
    ):
        from packages.ghidra import context_inject
        db1 = REDatabase(
            source_tool="ghidra", binary_path="/fw/v1.bin",
            functions=[REFunction(name="dup", address=0x1000, size=10,
                                  source_tool="ghidra",
                                  signature="int dup(void)")],
        )
        db2 = REDatabase(
            source_tool="ghidra", binary_path="/fw/v2.bin",
            functions=[REFunction(name="dup", address=0x1000, size=10,
                                  source_tool="ghidra",
                                  signature="int dup(void)")],
        )
        key = str((tmp_path / "repo").resolve())
        idx = context_inject._build_func_index([db1, db2])
        with context_inject._GHIDRA_LOCK:
            context_inject._GHIDRA_CACHE[key] = [db1, db2]
            context_inject._GHIDRA_FUNC_INDEX[key] = idx
        try:
            blocks = context_inject.ghidra_blocks_for_finding({
                "repo_path": str(tmp_path / "repo"),
                "metadata": {"name": "dup"},
            })
            assert blocks
            body = blocks[0].content
            assert "other attached database" in body
            assert "/fw/v2.bin" in body
        finally:
            context_inject.clear_ghidra_cache()

    def test_prepare_accepts_str_repo_path(self, tmp_path, monkeypatch):
        """The orchestrator holds repo_path as str; the un-coerced
        `repo_path.resolve()` raised AttributeError, which callers'
        blanket except swallowed into silently-disabled injection."""
        from packages.ghidra import context_inject
        gpr = tmp_path / "s.gpr"
        gpr.write_text("")
        monkeypatch.setattr(context_inject, "_resolve_ghidra_projects",
                            lambda r: [str(gpr)])
        monkeypatch.setattr(context_inject, "_load_cached_redb",
                            lambda p: _test_db())
        try:
            context_inject.prepare_ghidra_context(
                str(tmp_path / "repo"))
            key = str((tmp_path / "repo").resolve())
            with context_inject._GHIDRA_LOCK:
                assert context_inject._GHIDRA_CACHE.get(key)
        finally:
            context_inject.clear_ghidra_cache()

    def test_refresh_evicts_stale_cache_entry(self, tmp_path,
                                              monkeypatch):
        """refresh=True must repopulate a pre-existing (stale, empty)
        entry instead of short-circuiting on the cache hit."""
        from packages.ghidra import context_inject
        repo = tmp_path / "repo"
        key = str(repo.resolve())
        with context_inject._GHIDRA_LOCK:
            context_inject._GHIDRA_CACHE[key] = []
            context_inject._GHIDRA_FUNC_INDEX[key] = {}
        gpr = tmp_path / "a.gpr"
        gpr.write_text("")
        monkeypatch.setattr(context_inject, "_resolve_ghidra_projects",
                            lambda r: [str(gpr)])
        monkeypatch.setattr(context_inject, "_load_cached_redb",
                            lambda p: _test_db())
        try:
            context_inject.prepare_ghidra_context(repo, refresh=True)
            with context_inject._GHIDRA_LOCK:
                assert context_inject._GHIDRA_CACHE[key], (
                    "stale empty entry survived refresh=True")
        finally:
            context_inject.clear_ghidra_cache()

    def test_attach_threads_wait_to_op_lock(self, project_env,
                                            gpr_project, monkeypatch):
        import core.project.oplock as oplock_mod
        from contextlib import contextmanager
        seen = {}
        real = oplock_mod.project_op_lock

        @contextmanager
        def spy(project_dir, operation, grace=None, wait=False):
            seen["wait"] = wait
            with real(project_dir, operation, grace=grace, wait=wait):
                yield

        monkeypatch.setattr(oplock_mod, "project_op_lock", spy)
        from packages.ghidra.attach import attach
        attach(gpr_project, import_now=False, wait=True)
        assert seen["wait"] is True


class TestGhidraCliStatusAndWarnings:
    def test_attach_and_detach_parsers_accept_wait(self, monkeypatch):
        mod = _load_ghidra_cli(monkeypatch)
        p = mod._build_parser()
        assert p.parse_args(["attach", "x.gpr", "--wait"]).wait is True
        assert p.parse_args(["detach", "--wait"]).wait is True
        assert p.parse_args(["attach", "x.gpr"]).wait is False

    def test_status_honest_when_gpr_missing_but_cache_present(
        self, monkeypatch, capsys,
    ):
        """The old line said "no cached db (run attach to import)"
        with a populated cache on disk and a .gpr that attach can
        only reject — two false claims in one line."""
        import argparse as _ap

        import packages.ghidra.attach as attach_mod
        mod = _load_ghidra_cli(monkeypatch)
        monkeypatch.setattr(attach_mod, "get_attached_projects",
                            lambda project_name=None: ["/gone/fw.gpr"])
        monkeypatch.setattr(attach_mod, "_load_attached_db",
                            lambda p, project=None: _test_db())
        rc = mod._cmd_status(_ap.Namespace())
        out = capsys.readouterr().out
        assert rc == 0
        assert "[MISSING]" in out
        assert "3 functions" in out
        assert "restore it or detach" in out
        assert "run attach to import" not in out

    def test_status_missing_gpr_without_cache(self, monkeypatch,
                                              capsys):
        import argparse as _ap

        import packages.ghidra.attach as attach_mod
        mod = _load_ghidra_cli(monkeypatch)
        monkeypatch.setattr(attach_mod, "get_attached_projects",
                            lambda project_name=None: ["/gone/fw.gpr"])
        monkeypatch.setattr(attach_mod, "_load_attached_db",
                            lambda p, project=None: None)
        rc = mod._cmd_status(_ap.Namespace())
        out = capsys.readouterr().out
        assert rc == 0
        assert "restore the .gpr, then run attach" in out

    def test_reattach_warns_on_decompilation_downgrade(
        self, project_env, gpr_project, monkeypatch, capsys,
    ):
        """A plain re-attach over a --decompile-all cache silently
        discarded the decompilation /agentic prompts inject — the
        refresh must say what it is about to drop."""
        import argparse as _ap

        from packages.ghidra.attach import attach_dir
        mod = _load_ghidra_cli(monkeypatch)
        mgr, project = project_env
        cache = attach_dir(project, gpr_project)
        cache.mkdir(parents=True)
        db = _test_db()
        db.functions[0].decompilation = "int parse_input(void) {}"
        (cache / "re-database.json").write_text(
            json.dumps(db.to_dict()))

        class FakeBridge:
            def __init__(self, gpr, **kw):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                pass

            def import_project(self, out_dir, decompile=False,
                               timeout=None):
                return _test_db()

        args = _ap.Namespace(gpr=gpr_project, enrich=False,
                             decompile_all=False, program=None,
                             binary=None, wait=False, timeout=None)
        with patch("packages.ghidra.bridge.GhidraBridge", FakeBridge):
            rc = mod._cmd_attach(args)
        err = capsys.readouterr().err
        assert rc == 0
        assert "decompilation for 1 function(s)" in err
        assert "--decompile-all" in err

    def test_oversize_cache_warns_at_attach(self, tmp_path,
                                            monkeypatch, capsys):
        """Readers reject caches over the size ceiling; without an
        attach-time warning the operator loops on "run attach to
        import" advice that re-writes the same oversize file."""
        from packages.ghidra import context_inject
        mod = _load_ghidra_cli(monkeypatch)
        cache = tmp_path / "slot"
        cache.mkdir()
        (cache / "re-database.json").write_text("x" * 128)
        monkeypatch.setattr(context_inject, "_MAX_CACHE_BYTES", 64)
        mod._warn_oversize_cache(cache)
        err = capsys.readouterr().err
        assert "read ceiling" in err


class TestArchiveAndInputHardening:
    def test_collector_tolerates_non_dict_analysis_and_records(self):
        """analysed_results.json is arbitrary operator JSON — a
        prose-string analysis (or junk list items) crashed the
        collector's eager `analysis.get` for EVERY record, aborting
        the sync to all attachments before healthy records were
        gathered."""
        from packages.ghidra.roundtrip import collect_agentic_findings
        records = [
            {"analysis": "the model replied in prose", "message": "m"},
            {"analysis": [{"is_true_positive": True}]},
            "junk-item",
            {"analysis": "prose again", "is_true_positive": True,
             "exploitable": True, "message": "kept",
             "metadata": {"name": "parse_input"}},
        ]
        got = collect_agentic_findings(records)
        assert len(got) == 1
        assert got[0]["summary"] == "kept"

    def test_hidden_guard_uses_textual_path_not_resolved(
        self, tmp_path,
    ):
        """The JVM receives the UNRESOLVED textual path: a visible
        symlink into a hidden real dir must PASS (Ghidra opens it
        fine), and a textual .hidden element must be REFUSED even
        when its final component symlinks to a visible dir."""
        from packages.ghidra.headless import (
            GhidraError,
            _refuse_hidden_path_elements,
        )
        real_hidden = tmp_path / ".cache" / "gstore"
        real_hidden.mkdir(parents=True)
        visible_link = tmp_path / "outdir"
        visible_link.symlink_to(real_hidden)
        # visible textual path → passes even though it resolves hidden
        _refuse_hidden_path_elements(visible_link, "working copy")

        visible_real = tmp_path / "visible-store"
        visible_real.mkdir()
        hidden_parent = tmp_path / ".hidden"
        hidden_parent.mkdir()
        (hidden_parent / "lnk").symlink_to(visible_real)
        with pytest.raises(GhidraError, match="hidden"):
            _refuse_hidden_path_elements(
                hidden_parent / "lnk", "working copy")

    def test_attach_refuses_bidi_override_paths(
        self, project_env, tmp_path,
    ):
        """Bidi overrides/isolates visually reverse the echoed path —
        which .gpr is attached can be disguised. Refused at
        registration like C0 controls."""
        from packages.ghidra.attach import attach
        evil = tmp_path / "fw\u202egpj.evil" / "fw.gpr"
        with pytest.raises(ValueError, match="control characters"):
            attach(str(evil), import_now=False)

    def test_cross_db_same_binary_note_names_other_database(
        self, tmp_path,
    ):
        """Two attachments importing the SAME binary: the note keyed
        on binary_path equality claimed the duplicate was "in this
        same database" — literally false; it must name the other
        database (labelled same binary)."""
        from packages.ghidra import context_inject
        mk = lambda: REDatabase(  # noqa: E731
            source_tool="ghidra", binary_path="/fw/one.bin",
            functions=[REFunction(name="dup", address=0x1000, size=10,
                                  source_tool="ghidra",
                                  signature="int dup(void)")],
        )
        db1, db2 = mk(), mk()
        key = str((tmp_path / "repo").resolve())
        idx = context_inject._build_func_index([db1, db2])
        with context_inject._GHIDRA_LOCK:
            context_inject._GHIDRA_CACHE[key] = [db1, db2]
            context_inject._GHIDRA_FUNC_INDEX[key] = idx
        try:
            blocks = context_inject.ghidra_blocks_for_finding({
                "repo_path": str(tmp_path / "repo"),
                "metadata": {"name": "dup"},
            })
            assert blocks
            body = blocks[0].content
            assert "in this same database" not in body
            assert "1 other attached database(s)" in body
            assert "(same binary)" in body
        finally:
            context_inject.clear_ghidra_cache()

    def test_doctor_advisory_skips_generated_dirs(
        self, tmp_path, monkeypatch,
    ):
        """`ghidra-attach` sorts ahead of run names and consumed one
        of the doctor advisory's bounded scan slots, evicting a real
        run from the human-grade-note count."""
        import core.annotations.storage as storage_mod
        from core.startup import doctor
        out = tmp_path / "out"
        (out / "ghidra-attach" / "annotations").mkdir(parents=True)
        run_ann = out / "scan_1" / "annotations"
        run_ann.mkdir(parents=True)
        monkeypatch.setattr(doctor, "_ADVISORY_MAX_RUN_DIRS", 1)
        scanned = []
        monkeypatch.setattr(
            storage_mod, "iter_all_annotations",
            lambda base: (scanned.append(Path(base)), [])[1],
        )
        doctor._human_grade_note_count(out)
        assert run_ann in scanned
        assert (out / "ghidra-attach" / "annotations") not in scanned


class TestGhidraCliScrubbedOutput:
    def test_cli_forwards_wait_to_library(self, monkeypatch):
        """The parser test alone would not fail if the handlers
        stopped passing wait= through."""
        import argparse as _ap

        import packages.ghidra.attach as attach_mod
        mod = _load_ghidra_cli(monkeypatch)
        seen = {}

        def fake_attach(gpr, *, program_name=None, import_fn=None,
                        wait=False):
            seen["attach_wait"] = wait
            return Path("/tmp/x"), _test_db()

        def fake_detach(gpr, wait=False):
            seen["detach_wait"] = wait
            return 1

        monkeypatch.setattr(attach_mod, "attach", fake_attach)
        monkeypatch.setattr(attach_mod, "detach", fake_detach)
        args = _ap.Namespace(gpr=Path("/tmp/x.gpr"), enrich=False,
                             decompile_all=False, program=None,
                             binary=None, wait=True, timeout=None)
        mod._cmd_attach(args)
        mod._cmd_detach(_ap.Namespace(gpr=None, wait=True))
        assert seen == {"attach_wait": True, "detach_wait": True}

    def test_decompile_scrubs_cached_output(self, monkeypatch,
                                            capsys, tmp_path):
        """The cached database derives from an attacker-controlled
        bundle — decompilation echoed to the TTY must pass the
        control-character scrub like every other print."""
        import argparse as _ap

        from packages.ghidra import context_inject
        mod = _load_ghidra_cli(monkeypatch)
        db = _test_db()
        db.functions[0].decompilation = (
            "\x1b]0;PWNED\x07int parse_input(void) {}"
        )
        monkeypatch.setattr(context_inject, "_load_cached_redb",
                            lambda p: db)
        gpr = tmp_path / "p.gpr"
        gpr.write_text("")
        rc = mod._cmd_decompile(_ap.Namespace(
            gpr=gpr, function="parse_input", program=None, timeout=5))
        out = capsys.readouterr().out
        assert rc == 0
        assert "\x1b" not in out and "\x07" not in out
        assert "int parse_input" in out

    def test_project_ghidra_list_strips_bidi(self):
        """/project ghidra list previously echoed U+202E raw while
        raptor-ghidra status stripped it — the printed path could be
        visually reversed."""
        import re as _re
        pat = ("[\x00-\x1f\x7f\x9b"
               "\u202a-\u202e\u2066-\u2069]")
        # the exact class now used by cli.py's _strip_ctrl
        assert _re.sub(pat, "", "/tmp/fw\u202egpj.evil/fw.gpr") == \
            "/tmp/fwgpj.evil/fw.gpr"
        import inspect

        import core.project.cli as cli_mod
        src = inspect.getsource(cli_mod)
        assert "\\u202a-\\u202e" in src, (
            "cli.py _strip_ctrl lost the bidi range")


class TestCollectorShapeHardening:
    def test_non_dict_metadata_and_level_degrade(self):
        """metadata and level are as operator-controlled as analysis:
        a prose metadata crashed the collector's .get, and a dict
        level failed the attachment's apply late, inside the JVM,
        as a non-string bookmark category."""
        from packages.ghidra.roundtrip import collect_agentic_findings
        got = collect_agentic_findings([
            {"is_true_positive": True, "is_exploitable": True,
             "metadata": "prose, not a dict", "message": "m1"},
            {"is_true_positive": True, "is_exploitable": True,
             "level": {"sev": "high"}, "message": "m2",
             "metadata": {"name": "fn2"}},
        ])
        assert len(got) == 2
        assert got[0]["function"] == ""
        assert isinstance(got[1]["severity"], str)

    def test_non_string_function_names_stay_hashable(self):
        """A list-valued metadata.name flowed into the journal-dedup
        sets and raised TypeError: unhashable — aborting the whole
        gather outside any per-attachment guard."""
        from packages.ghidra.roundtrip import collect_agentic_findings
        got = collect_agentic_findings([
            {"is_true_positive": True, "is_exploitable": True,
             "metadata": {"name": ["libfoo", "bar"]},
             "message": "m"},
        ])
        assert got[0]["function"] == ""
        # the dedup set construction the value flows into
        assert {f.get("function") for f in got} == {""}

    def test_model_coerces_planted_cache_text_fields(self):
        """A wrong-typed decompilation/signature in a planted cache
        tripped the renderers' AttributeError, silently disabling
        injection for the function via blanket excepts."""
        from packages.ghidra.model import REFunction
        f = REFunction.from_dict({
            "name": "x", "address": 1, "size": 2,
            "decompilation": {"j": 1}, "signature": 123,
        })
        assert isinstance(f.decompilation, str)
        assert isinstance(f.signature, str)
        f2 = REFunction.from_dict({"name": "y", "address": 1, "size": 2})
        assert f2.decompilation is None and f2.signature is None

    def test_ambiguity_note_counts_identical_snapshots_separately(
        self, tmp_path,
    ):
        """Dataclass value-equality collapsed two identical snapshot
        attachments into "1 other attached database(s)" — dedup must
        be by identity."""
        from packages.ghidra import context_inject
        mk = lambda: REDatabase(  # noqa: E731
            source_tool="ghidra", binary_path="/fw/one.bin",
            functions=[REFunction(name="dup", address=0x1000, size=10,
                                  source_tool="ghidra",
                                  signature="int dup(void)")],
        )
        dbs = [mk(), mk(), mk()]
        key = str((tmp_path / "repo").resolve())
        idx = context_inject._build_func_index(dbs)
        with context_inject._GHIDRA_LOCK:
            context_inject._GHIDRA_CACHE[key] = dbs
            context_inject._GHIDRA_FUNC_INDEX[key] = idx
        try:
            blocks = context_inject.ghidra_blocks_for_finding({
                "repo_path": str(tmp_path / "repo"),
                "metadata": {"name": "dup"},
            })
            assert blocks
            assert "2 other attached database(s)" in blocks[0].content
        finally:
            context_inject.clear_ghidra_cache()


class TestApplyPayloadHardening:
    def test_addresses_coerced_at_collection_and_chokepoint(self):
        """A hex-STRING address (plausible scanner shape) passed the
        collector raw and failed the WHOLE attachment late — inside
        the pyghidra range check / the import script's getAsLong —
        on both engines."""
        from packages.ghidra.roundtrip import (
            _exportable,
            collect_agentic_findings,
        )
        got = collect_agentic_findings([{
            "is_true_positive": True, "is_exploitable": True,
            "message": "m", "metadata": {"name": "parse"},
            "address": "0x400123",
        }, {
            "is_true_positive": True, "is_exploitable": True,
            "message": "m2", "metadata": {"name": "other"},
            "address": {"weird": 1},
        }])
        assert got[0]["address"] == 0x400123
        assert got[1]["address"] is None  # degrades to name-keyed
        # chokepoint normalizes findings from OTHER sources too
        out = _exportable([
            {"function": "f", "address": "1234"},
            {"function": "g", "address": True},
        ])
        assert out[0]["address"] == 1234
        assert out[1]["address"] is None

    def test_cached_decompilation_count_tolerates_wrong_shapes(
        self, monkeypatch, tmp_path,
    ):
        """{"functions": 5} raised TypeError out of the op-locked
        import — the helper's docstring promises reader-grade
        degradation."""
        mod = _load_ghidra_cli(monkeypatch)
        cache = tmp_path / "slot"
        cache.mkdir()
        (cache / "re-database.json").write_text('{"functions": 5}')
        assert mod._cached_decompilation_count(cache) == 0
        (cache / "re-database.json").write_text('{"functions": true}')
        assert mod._cached_decompilation_count(cache) == 0

    def test_safe_line_flattens_and_bounds(self, monkeypatch):
        """A hand-edited registry path with a newline injected a fake
        status line; a multi-MB one emitted a multi-MB echo."""
        mod = _load_ghidra_cli(monkeypatch)
        out = mod._safe_line("a\nb\tc")
        assert "\n" not in out and "\t" not in out
        assert len(mod._safe_line("x" * 10_000)) <= 501


class TestRendererBudgetHardening:
    def _db_with(self, **func_kw):
        kw = dict(name="target_fn", address=0x1000, size=32,
                  source_tool="ghidra")
        kw.update(func_kw)
        return REDatabase(source_tool="ghidra",
                          binary_path="/fw/bin",
                          functions=[REFunction(**kw)])

    def _block_for(self, db, tmp_path, name="target_fn"):
        from packages.ghidra import context_inject
        key = str((tmp_path / "repo").resolve())
        idx = context_inject._build_func_index([db])
        with context_inject._GHIDRA_LOCK:
            context_inject._GHIDRA_CACHE[key] = [db]
            context_inject._GHIDRA_FUNC_INDEX[key] = idx
        try:
            blocks = context_inject.ghidra_blocks_for_finding({
                "repo_path": str(tmp_path / "repo"),
                "metadata": {"name": name},
            })
            return blocks[0].content if blocks else ""
        finally:
            context_inject.clear_ghidra_cache()

    def test_signature_and_name_clipped(self, tmp_path):
        """Only decompilation was capped: a multi-MB signature (or
        function name) inflated the block to megabytes — the exact
        route the in-module caps exist to close."""
        body = self._block_for(
            self._db_with(signature="s" * 4_000_000,
                          name="n" * 1_000_000), tmp_path,
            name="n" * 1_000_000)
        assert body
        assert len(body) < 64 * 1024

    def test_type_fields_capped(self, tmp_path):
        from packages.ghidra.model import REType
        db = self._db_with(signature="struct BIG *fn(void)")
        db.types = [REType(
            name="BIG", kind="struct", size=8,
            fields=[{"name": f"f{i}", "type": "int", "offset": i}
                    for i in range(100_000)],
            source_tool="ghidra")]
        body = self._block_for(db, tmp_path)
        assert "more field(s)" in body
        assert len(body) < 64 * 1024

    def test_retype_from_dict_coerces_wrong_shapes(self):
        from packages.ghidra.model import REType
        t = REType.from_dict({"name": "T", "kind": "struct",
                              "size": "huge", "fields": "prose"})
        assert t.size is None and t.fields is None
        t2 = REType.from_dict({"name": "T", "kind": "struct",
                               "fields": [{"name": "a"}, "junk"]})
        assert t2.fields == [{"name": "a"}]

    def test_wrong_typed_finding_fields_degrade_to_empty(
        self, tmp_path,
    ):
        """Wrong-typed finding fields raised past the guards into the
        callers' blanket excepts — silently-disabled injection, the
        failure mode the str-repo_path fix already closed once."""
        from packages.ghidra import context_inject
        db = self._db_with(signature="int f(void)")
        key = str((tmp_path / "repo").resolve())
        idx = context_inject._build_func_index([db])
        with context_inject._GHIDRA_LOCK:
            context_inject._GHIDRA_CACHE[key] = [db]
            context_inject._GHIDRA_FUNC_INDEX[key] = idx
        try:
            for finding in (
                {"repo_path": 123},
                {"repo_path": ["x"]},
                {"repo_path": str(tmp_path / "repo"),
                 "metadata": "prose"},
                {"repo_path": str(tmp_path / "repo"),
                 "metadata": {"name": ["list"]}},
            ):
                assert context_inject.ghidra_blocks_for_finding(
                    finding) == ()
        finally:
            context_inject.clear_ghidra_cache()

    def test_same_binary_label_requires_known_paths(self, tmp_path):
        """unknown == unknown must not read as "(same binary)"."""
        from packages.ghidra import context_inject
        mk = lambda: REDatabase(  # noqa: E731
            source_tool="ghidra", binary_path=None,
            functions=[REFunction(name="dup", address=0x1000, size=10,
                                  source_tool="ghidra",
                                  signature="int dup(void)")],
        )
        dbs = [mk(), mk()]
        key = str((tmp_path / "repo").resolve())
        idx = context_inject._build_func_index(dbs)
        with context_inject._GHIDRA_LOCK:
            context_inject._GHIDRA_CACHE[key] = dbs
            context_inject._GHIDRA_FUNC_INDEX[key] = idx
        try:
            blocks = context_inject.ghidra_blocks_for_finding({
                "repo_path": str(tmp_path / "repo"),
                "metadata": {"name": "dup"},
            })
            assert blocks
            assert "(same binary)" not in blocks[0].content
        finally:
            context_inject.clear_ghidra_cache()


class TestAddressIndex:
    def test_indexed_lookups_match_linear_semantics(self):
        db = _test_db()
        assert db.function_by_address(0x4000).name == "parse_input"
        assert db.function_by_address(0x9999) is None
        # containment: parse_input spans 0x4000..0x40c8
        assert db.function_containing_address(0x4010).name == \
            "parse_input"
        assert db.function_containing_address(0x3fff) is None
        # junk addresses degrade
        assert db.function_containing_address("junk") is None
        assert db.function_by_address("junk") is None

    def test_index_invalidated_on_function_append(self):
        db = _test_db()
        assert db.function_containing_address(0x7000) is None
        db.functions.append(
            REFunction(name="late", address=0x7000, size=16,
                       source_tool="ghidra"))
        assert db.function_containing_address(0x7008).name == "late"

    def test_bulk_resolution_is_not_quadratic(self):
        """The pre-index linear scan resolved ALL 10k addresses in
        ~1.8s (quadratic, early-exit helps only the front of the
        list); the indexed path must clear the same full workload
        with an order of magnitude to spare — querying only a
        front-of-list prefix here let the linear scan pass on
        early-exit and made the pin vacuous."""
        import time
        funcs = [REFunction(name="dup", address=0x1000 + 32 * i,
                            size=32, source_tool="ghidra",
                            signature="int dup(void)")
                 for i in range(10_000)]
        db = REDatabase(source_tool="ghidra", binary_path="/fw/b",
                        functions=funcs)
        # CPU time, not wall clock: lookups are pure computation, so
        # the quadratic regression burns CPU while an oversubscribed
        # runner only adds scheduling delay — process_time keeps the
        # signal without load-induced flakes. Bound trade-off: high
        # enough for slow CI CPUs (~10x over the indexed path), low
        # enough that the ~1.8s-CPU linear rescan still trips it.
        t0 = time.process_time()
        for addr in range(0x1000, 0x1000 + 32 * 10_000, 32):
            db.function_containing_address(addr + 3)
        elapsed = time.process_time() - t0
        assert elapsed < 1.0, f"indexed lookups took {elapsed:.2f}s CPU"

    def test_zero_size_symbols_do_not_break_containment(self):
        """nm-fallback databases carry size-0 symbols (asm without
        .size, ARM mapping symbols) INSIDE sized functions' ranges —
        they consumed the bounded walk-back budget and turned real
        containment hits into silent misses."""
        funcs = [REFunction(name="big_fn", address=0x1000,
                            size=0x10000, source_tool="nm")]
        funcs += [REFunction(name=f"$d{i}", address=0x1100 + 8 * i,
                             size=0, source_tool="nm")
                  for i in range(100)]
        db = REDatabase(source_tool="nm", functions=funcs)
        hit = db.function_containing_address(0x8000)
        assert hit is not None and hit.name == "big_fn"
        # exact-match on a zero-size symbol still resolves
        assert db.function_by_address(0x1100).name == "$d0"


class TestAnnotationPayloadClip:
    def test_annotation_function_field_clipped(self, tmp_path):
        """The heading regex accepts any non-newline run and the
        write-time name validator does not bind hand-written files —
        the function field was the one payload field left unbounded."""
        from packages.ghidra.roundtrip import collect_annotation_findings
        ann = tmp_path / "annotations" / "src"
        ann.mkdir(parents=True)
        big = "f" * 5000
        (ann / "x.c.md").write_text(
            f"# src/x.c\n\n## {big}\n"
            "<!-- meta: status=finding cwe=CWE-787 -->\n\n"
            "note body\n",
        )
        got = collect_annotation_findings(tmp_path)
        assert got
        assert len(got[0]["function"]) <= 300


class TestRelativeOutputDirAbsolutized:
    def test_attach_dir_absolutizes_relative_output_dir(self):
        """A registered RELATIVE output_dir (the CLI archive-import
        minted them) flowed into JVM-facing paths that the sandboxed
        analyzeHeadless resolved against its private scratch cwd —
        the import "succeeded" but the export JSON never landed
        where the readers look."""
        import os

        from packages.ghidra.attach import attach_dir
        proj = type("P", (), {"output_dir": "out/projects/rel"})()
        cache = attach_dir(proj, Path("/tmp/x/fw.gpr"))
        assert cache.is_absolute()
        assert str(cache).startswith(
            os.path.abspath("out/projects/rel"))
