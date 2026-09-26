"""Basic smoke tests for the project CLI."""

import contextlib
import io
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.project.cli import (
    _get_active_project,
    _get_output_summary,
    _print_findings,
    _print_sca_findings_section,
    _sca_finding_escalations,
    _sca_finding_kind,
    _sca_finding_package,
    main,
)


class _FakeProject:
    """Minimal stand-in: _print_findings only calls get_run_dirs()."""

    def __init__(self, run_dirs):
        self._run_dirs = run_dirs

    def get_run_dirs(self, sweep=False):
        return self._run_dirs


def _sca_finding(name, *, severity="high", escalation_reasons=None):
    sca = {"kind": "slopsquat_suspect", "ecosystem": "npm", "name": name}
    if escalation_reasons is not None:
        sca["evidence"] = {"escalation_reasons": escalation_reasons}
    return {
        "id": f"SCA-{name}", "finding_id": f"SCA-{name}",
        "vuln_type": "sca:supply_chain:slopsquat_suspect", "tool": "sca",
        "file": "package.json", "function": name, "line": 0,
        "severity": severity, "title": f"Slopsquat suspect: {name}",
        "description": "looks like an LLM-hallucinated package name",
        "sca": sca,
    }


def _write_sca(run_dir: Path, rows):
    (run_dir / "sca").mkdir(parents=True, exist_ok=True)
    (run_dir / "sca" / "findings.json").write_text(json.dumps(rows), encoding="utf-8")


class TestCountSarifResultsInDir(unittest.TestCase):
    """The run-dir SARIF counter must survive malformed files.

    These files are tool-emitted and operator-editable; pre-fix a
    non-dict run entry raised AttributeError and took the whole
    /project status rendering down with one bad file."""

    def test_malformed_run_entry_does_not_abort_count(self):
        from core.project.cli import _count_sarif_results_in_dir
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            (run_dir / "bad.sarif").write_text(json.dumps(
                {"runs": ["corrupt-entry",
                          {"results": [{"ruleId": "x"}]}]}))
            (run_dir / "good.sarif").write_text(json.dumps(
                {"runs": [{"results": [{"ruleId": "a"},
                                       {"ruleId": "b"}]}]}))
            self.assertEqual(_count_sarif_results_in_dir(run_dir), 3)


class TestRunSummarySca(unittest.TestCase):
    """The per-run summary count (run list) includes SCA findings, so it
    matches what /project findings shows."""

    def test_sca_only_run_counted(self):
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            _write_sca(run_dir, [_sca_finding("lodash-pro")])
            # meta with no status → computed, not cached/written back.
            self.assertEqual(_get_output_summary(run_dir, {}), "1 findings")

    def test_code_plus_sca_combined(self):
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            (run_dir / "findings.json").write_text(json.dumps([
                {"id": "F-1", "file": "a.c", "function": "main", "line": 5,
                 "vuln_type": "buffer_overflow"},
            ]), encoding="utf-8")
            _write_sca(run_dir, [_sca_finding("expresss")])
            self.assertEqual(_get_output_summary(run_dir, {}), "2 findings")

    def test_stale_v1_cache_recomputed(self):
        """A pre-SCA cached summary (no version, or version != current)
        must NOT short-circuit — else SCA-containing runs completed before
        this change under-count forever."""
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            _write_sca(run_dir, [_sca_finding("lodash-pro")])
            # Stale v1 cache: count present, no version stamp.
            stale_meta = {"output_summary": "0 findings"}
            self.assertEqual(
                _get_output_summary(run_dir, stale_meta), "1 findings")

    def test_current_version_cache_used(self):
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            _write_sca(run_dir, [_sca_finding("lodash-pro")])
            # Current-version cache short-circuits (returns cached, no recompute).
            fresh_meta = {"output_summary": "99 findings", "output_summary_v": 2}
            self.assertEqual(
                _get_output_summary(run_dir, fresh_meta), "99 findings")

    def test_cache_write_back_holds_metadata_lock(self):
        """The cache write-back is an RMW on .raptor-run.json and must
        take the same cross-process lock as every other marker writer."""
        from core.run import metadata as run_metadata
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            _write_sca(run_dir, [_sca_finding("lodash-pro")])
            meta = {"status": "completed"}
            meta_path = run_dir / run_metadata.RUN_METADATA_FILE
            meta_path.write_text(json.dumps(meta), encoding="utf-8")
            locked = []
            real_lock = run_metadata._metadata_lock

            @contextlib.contextmanager
            def spy_lock(path):
                locked.append(Path(path))
                with real_lock(path):
                    yield

            with patch.object(run_metadata, "_metadata_lock", spy_lock):
                _get_output_summary(run_dir, meta)
            self.assertEqual(locked, [meta_path])

    def test_cache_write_back_preserves_concurrent_update(self):
        """A marker rewrite that landed between our load and the cache
        write-back (e.g. write_run_pin) must survive: the write-back
        re-loads under the lock and adds only the cache keys."""
        from core.run.metadata import RUN_METADATA_FILE
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            _write_sca(run_dir, [_sca_finding("lodash-pro")])
            meta_path = run_dir / RUN_METADATA_FILE
            # Our (stale) snapshot, loaded before the concurrent writer.
            stale = {"status": "completed"}
            # The concurrent writer's version, already on disk.
            meta_path.write_text(json.dumps({
                "status": "completed", "project": "just-pinned",
            }), encoding="utf-8")
            _get_output_summary(run_dir, stale)
            on_disk = json.loads(meta_path.read_text(encoding="utf-8"))
            self.assertEqual(on_disk.get("project"), "just-pinned")
            self.assertEqual(on_disk.get("output_summary"), "1 findings")


class TestPrintFindingsSca(unittest.TestCase):

    def test_sca_helpers(self):
        f = _sca_finding("lodahs")
        self.assertEqual(_sca_finding_package(f), "npm:lodahs")
        self.assertEqual(_sca_finding_kind(f), "Supply Chain · Slopsquat Suspect")

    def test_escalation_helper_extracts_reasons(self):
        f = _sca_finding("react-helper", escalation_reasons=["co-occurs with X"])
        self.assertEqual(_sca_finding_escalations(f), ["co-occurs with X"])
        # Absent / malformed evidence yields an empty list, never raises.
        self.assertEqual(_sca_finding_escalations(_sca_finding("lodahs")), [])
        self.assertEqual(_sca_finding_escalations({}), [])

    def test_escalation_reasons_printed_in_detailed_mode(self):
        rows = [_sca_finding("react-helper", severity="critical",
                             escalation_reasons=["co-occurs with recent_publish"])]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print_sca_findings_section(rows, detailed=True)
        self.assertIn("escalated: co-occurs with recent_publish", buf.getvalue())

    def test_escalation_reasons_absent_from_summary_mode(self):
        rows = [_sca_finding("react-helper", severity="critical",
                             escalation_reasons=["co-occurs with recent_publish"])]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print_sca_findings_section(rows, detailed=False)
        # Summary table shows the (bumped) severity but not the prose reasons.
        self.assertNotIn("escalated:", buf.getvalue())
        self.assertIn("Critical", buf.getvalue())

    def test_sca_section_renders(self):
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            _write_sca(run_dir, [_sca_finding("lodahs")])
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _print_findings(_FakeProject([run_dir]))
            out = buf.getvalue()
            self.assertIn("Supply chain / dependencies (SCA)", out)
            self.assertIn("npm:lodahs", out)

    def test_sca_only_run_not_reported_as_no_findings(self):
        """Regression: a run with ONLY sca/findings.json (no top-level
        findings.json) must still surface the SCA section, not print
        'No findings.' and bail."""
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            _write_sca(run_dir, [_sca_finding("expresss")])
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _print_findings(_FakeProject([run_dir]))
            out = buf.getvalue()
            self.assertNotIn("No findings.", out)
            self.assertIn("npm:expresss", out)

    def test_truly_empty_reports_no_findings(self):
        with TemporaryDirectory() as d:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _print_findings(_FakeProject([Path(d)]))
            self.assertIn("No findings.", buf.getvalue())


class TestProjectFindingsScaE2E(unittest.TestCase):
    """End-to-end across the package boundary: a slopsquat detected by
    the REAL SCA detector + serialised by the REAL write_findings_json
    must surface in /project findings.

    Guards the contract — SCA's on-disk findings.json shape vs the
    project view's loader/renderer. A future SCA serializer change that
    drifts the row shape breaks this test rather than silently dropping
    dependency findings from the project view. Skipped if the optional
    SCA package isn't importable.
    """

    def test_real_slopsquat_surfaces_in_project_findings(self):
        try:
            from packages.sca.parsers.package_json import parse as parse_pkg
            from packages.sca.supply_chain import _slopsquat_to_finding
            from packages.sca.supply_chain.slopsquat import check_dep
            from packages.sca.findings import write_findings_json
        except ImportError:
            self.skipTest("optional SCA package not importable")

        with TemporaryDirectory() as d:
            target = Path(d) / "target"
            target.mkdir()
            # 'lodash-pro' = popular prefix 'lodash' + generic suffix
            # 'pro' → the detector's popular_prefix_generic_suffix rule.
            (target / "package.json").write_text(json.dumps({
                "name": "victim-app",
                "dependencies": {"lodash-pro": "^1.0.0", "express": "^4.0.0"},
            }), encoding="utf-8")

            deps = parse_pkg(target / "package.json")
            ss = [f for f in (check_dep(dep) for dep in deps) if f]
            self.assertTrue(ss, "real detector found no slopsquat in 'lodash-pro'")
            sc_findings = [_slopsquat_to_finding(f) for f in ss]

            run_dir = Path(d) / "run"
            write_findings_json(
                run_dir / "sca" / "findings.json",
                supply_chain_findings=sc_findings,
            )

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _print_findings(_FakeProject([run_dir]))
            out = buf.getvalue()
            self.assertIn("Supply chain / dependencies (SCA)", out)
            self.assertIn("lodash-pro", out)
            self.assertIn("Slopsquat", out)


class TestDoMergeLabel(unittest.TestCase):
    """The merge summary line follows merge.py's documented
    "N findings (M vulns)" convention — the physical-finding count is
    always the one labelled "findings"."""

    def _run(self, tmp: Path, name: str, findings) -> Path:
        d = tmp / name
        d.mkdir(parents=True)
        (d / ".raptor-run.json").write_text(json.dumps({
            "version": 2, "command": "scan", "status": "completed",
            "project": None, "project_source": "none",
        }), encoding="utf-8")
        (d / "findings.json").write_text(
            json.dumps({"findings": findings}), encoding="utf-8")
        return d

    def test_vuln_count_never_labelled_findings(self):
        from core.project.project import Project
        with TemporaryDirectory() as td:
            tmp = Path(td)
            out = tmp / "proj-out"
            out.mkdir()
            # Same logical vuln (file, function, type) at two lines:
            # 2 physical findings, 1 vuln.
            self._run(out, "scan-1", [{
                "file": "a.py", "function": "f",
                "vuln_type": "sql_injection", "line": 5,
            }])
            self._run(out, "scan-2", [{
                "file": "a.py", "function": "f",
                "vuln_type": "sql_injection", "line": 9,
            }])
            project = Project(name="mergeme", target=str(tmp / "code"),
                              output_dir=str(out))
            from core.project.cli import _do_merge as do_merge
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                do_merge(project, "scan", yes=True)
            output = buf.getvalue()
            self.assertIn("2 findings (1 vulns)", output)
            self.assertNotIn("(1 findings)", output)


class TestConfirmPrompt(unittest.TestCase):
    """Destructive confirms treat a closed/non-tty stdin as "no"
    instead of crashing with an unhandled EOFError."""

    def test_eof_means_no(self):
        from core.project.cli import _confirm
        with patch("builtins.input", side_effect=EOFError):
            self.assertFalse(_confirm("Proceed? [y/N] "))

    def test_yes_and_no_answers(self):
        from core.project.cli import _confirm
        with patch("builtins.input", return_value="y"):
            self.assertTrue(_confirm("Proceed? [y/N] "))
        with patch("builtins.input", return_value="n"):
            self.assertFalse(_confirm("Proceed? [y/N] "))

    def test_merge_without_yes_cancels_on_closed_stdin(self):
        from core.project.cli import _do_merge
        from core.project.project import Project
        with TemporaryDirectory() as td:
            tmp = Path(td)
            out = tmp / "proj-out"
            out.mkdir()
            for name in ("scan-1", "scan-2"):
                d = out / name
                d.mkdir()
                (d / ".raptor-run.json").write_text(json.dumps({
                    "version": 2, "command": "scan",
                    "status": "completed",
                    "project": None, "project_source": "none",
                }), encoding="utf-8")
                (d / "findings.json").write_text("[]", encoding="utf-8")
            project = Project(name="p", target=str(tmp / "code"),
                              output_dir=str(out))
            buf = io.StringIO()
            with patch("builtins.input", side_effect=EOFError), \
                    contextlib.redirect_stdout(buf):
                _do_merge(project, "scan", yes=False)
            self.assertIn("Cancelled", buf.getvalue())
            # Nothing merged, nothing deleted.
            self.assertTrue((out / "scan-1").exists())
            self.assertTrue((out / "scan-2").exists())


class TestCLI(unittest.TestCase):

    def test_help(self):
        """main() with no args prints help without crashing."""
        with patch("sys.argv", ["raptor-project"]):
            # Should not raise
            main()

    def test_create(self):
        """Create subcommand creates a project file."""
        with TemporaryDirectory() as d:
            output_dir = Path(d) / "output"
            with patch("core.project.cli.ProjectManager") as MockMgr:
                instance = MockMgr.return_value
                instance.create.return_value = type("P", (), {
                    "name": "test", "output_dir": str(output_dir)
                })()
                # The ProjectManager is mocked, so the target is
                # opaque to this CLI parsing test — value just needs
                # to be a string the argparse layer accepts.
                target = str(Path(d) / "code")
                with patch("sys.argv", ["raptor-project", "create", "test",
                                        "--target", target]):
                    main()
                instance.create.assert_called_once()

    def test_list_empty(self):
        """List subcommand with no projects doesn't crash."""
        with patch("core.project.cli.ProjectManager") as MockMgr:
            instance = MockMgr.return_value
            instance.list_projects.return_value = []
            with patch("sys.argv", ["raptor-project", "list"]):
                main()
            instance.list_projects.assert_called_once()


class TestEditorGuard(unittest.TestCase):
    """$EDITOR argv validation on `notes --edit`: the basename
    allowlist alone still executed EDITOR='vim -c ":!cmd"' — vim runs
    the -c argument as a command."""

    def _run_notes_edit(self, editor):
        buf = io.StringIO()
        with patch("core.project.cli.ProjectManager") as MockMgr, \
                patch.object(os, "isatty", lambda fd: True), \
                patch.dict(os.environ, {"EDITOR": editor}), \
                patch("subprocess.run") as run_mock, \
                contextlib.redirect_stdout(buf), \
                contextlib.redirect_stderr(buf):
            instance = MockMgr.return_value
            instance.load.return_value = type("P", (), {"notes": ""})()
            with patch("sys.argv",
                       ["raptor-project", "notes", "test", "--edit"]):
                main()
        return buf.getvalue(), run_mock

    def test_editor_command_argument_refused(self):
        out, run_mock = self._run_notes_edit('vim -c ":!touch pwned"')
        self.assertIn("Refusing to launch editor", out)
        run_mock.assert_not_called()

    def test_bare_editor_and_wait_flag_still_launch(self):
        # Two-direction guard: the bare name and the blocking-wait
        # flag remain usable.
        _out, run_mock = self._run_notes_edit("vim")
        run_mock.assert_called_once()
        _out, run_mock = self._run_notes_edit("code --wait")
        run_mock.assert_called_once()


class TestGetActiveProject(unittest.TestCase):
    """Tests for _get_active_project symlink resolution."""

    def test_symlink_resolves(self):
        with TemporaryDirectory() as d:
            projects_dir = Path(d)
            (projects_dir / "myapp.json").write_text('{"name":"myapp"}')
            active = projects_dir / ".active"
            active.symlink_to("myapp.json")

            with patch("core.project.project.PROJECTS_DIR", projects_dir):
                with patch.dict(os.environ, {}, clear=True):
                    result = _get_active_project()
            self.assertEqual(result, "myapp")

    def test_dangling_symlink_cleaned(self):
        with TemporaryDirectory() as d:
            projects_dir = Path(d)
            active = projects_dir / ".active"
            active.symlink_to("gone.json")

            with patch("core.project.project.PROJECTS_DIR", projects_dir):
                with patch.dict(os.environ, {}, clear=True):
                    result = _get_active_project()
            self.assertIsNone(result)
            self.assertFalse(active.exists() or active.is_symlink())

    def test_no_symlink_returns_none(self):
        with TemporaryDirectory() as d:
            with patch("core.project.project.PROJECTS_DIR", Path(d)):
                with patch.dict(os.environ, {}, clear=True):
                    result = _get_active_project()
            self.assertIsNone(result)



if __name__ == "__main__":
    unittest.main()


class TestMergeHostileCommandType(unittest.TestCase):
    """`command` is child-writable run metadata restored verbatim —
    the merge join must treat it as a direct-child NAME (the same
    contract remove/move enforce), and the plan line must not relay
    raw bytes to the terminal."""

    def _run(self, out: Path, name: str, command) -> Path:
        d = out / name
        d.mkdir(parents=True)
        (d / ".raptor-run.json").write_text(json.dumps({
            "version": 2, "command": command, "status": "completed",
            "project": None, "project_source": "none",
        }), encoding="utf-8")
        (d / "findings.json").write_text("[]", encoding="utf-8")
        return d

    def _project(self, tmp: Path):
        from core.project.project import Project
        out = tmp / "proj-out"
        out.mkdir(exist_ok=True)
        return Project(name="p", target=str(tmp / "code"),
                       output_dir=str(out)), out

    def test_absolute_command_never_escapes(self):
        from core.project.cli import _do_merge
        with TemporaryDirectory() as td:
            tmp = Path(td)
            project, out = self._project(tmp)
            victim = tmp / "victim"
            hostile = str(victim / "cfg")
            self._run(out, "scan-1", hostile)
            self._run(out, "scan-2", hostile)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _do_merge(project, "all", yes=True)
            # Nothing may be created outside the project output dir.
            self.assertFalse(victim.exists())
            # Source runs preserved (the hostile group is refused, not
            # merged-and-deleted).
            self.assertTrue((out / "scan-1").exists())
            self.assertTrue((out / "scan-2").exists())
            self.assertIn("refus", buf.getvalue().lower())

    def test_traversal_command_never_escapes(self):
        from core.project.cli import _do_merge
        with TemporaryDirectory() as td:
            tmp = Path(td)
            project, out = self._project(tmp)
            (tmp / "victim").mkdir()
            self._run(out, "scan-1", "../victim/x")
            self._run(out, "scan-2", "../victim/x")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _do_merge(project, "all", yes=True)
            self.assertFalse(list((tmp / "victim").iterdir()))
            self.assertTrue((out / "scan-1").exists())
            self.assertTrue((out / "scan-2").exists())

    def test_plan_line_sanitises_command(self):
        from core.project.cli import _do_merge
        with TemporaryDirectory() as td:
            tmp = Path(td)
            project, out = self._project(tmp)
            hostile = "scan\x1b]0;evil\x07"
            self._run(out, "scan-1", hostile)
            self._run(out, "scan-2", hostile)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _do_merge(project, "all", yes=True)
            self.assertNotIn("\x1b", buf.getvalue())
            self.assertNotIn("\x07", buf.getvalue())

    def test_benign_merge_control(self):
        from core.project.cli import _do_merge
        with TemporaryDirectory() as td:
            tmp = Path(td)
            project, out = self._project(tmp)
            self._run(out, "scan-1", "scan")
            self._run(out, "scan-2", "scan")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _do_merge(project, "all", yes=True)
            merged = [p for p in out.iterdir()
                      if p.is_dir() and p.name.startswith("scan-")]
            self.assertEqual(len(merged), 1)
            self.assertFalse((out / "scan-1").exists())


class TestMergeDeleteTimeLivenessRecheck(unittest.TestCase):
    """The plan-time live split is arbitrarily stale by delete time —
    an unbounded operator confirm sits between them, and a planned
    run can be RESUMED in the gap. /project clean re-checks per dir
    immediately before its rmtree; merge deleted on the stale plan
    and rmtree'd an in-flight run."""

    def _run(self, out: Path, name: str) -> Path:
        d = out / name
        d.mkdir(parents=True)
        (d / ".raptor-run.json").write_text(json.dumps({
            "version": 2, "command": "scan", "status": "completed",
            "project": None, "project_source": "none",
        }), encoding="utf-8")
        (d / "findings.json").write_text("[]", encoding="utf-8")
        return d

    def test_run_resumed_during_confirm_is_not_deleted(self):
        from core.project.cli import _do_merge
        from core.project.project import Project
        with TemporaryDirectory() as td:
            tmp = Path(td)
            out = tmp / "proj-out"
            out.mkdir()
            project = Project(name="p", target=str(tmp / "code"),
                              output_dir=str(out))
            d1 = self._run(out, "scan-1")
            self._run(out, "scan-2")

            resumed = {"flag": False}

            def confirm_resumes(prompt):
                # Operator sits on the prompt; scan-1 resumes.
                resumed["flag"] = True
                return True

            def live_after_resume(d):
                return resumed["flag"] and Path(d).name == "scan-1"

            buf = io.StringIO()
            with patch("core.project.cli._confirm", confirm_resumes), \
                    patch("core.project.clean.run_is_live",
                          live_after_resume), \
                    contextlib.redirect_stdout(buf):
                _do_merge(project, "all", yes=False)
            self.assertTrue(d1.exists(),
                            "run resumed during the confirm gap was "
                            "rmtree'd in flight")
            self.assertIn("skipped delete", buf.getvalue())
            # The non-live sibling still merged and got deleted.
            self.assertFalse((out / "scan-2").exists())


class TestMergeDotPrefixAndLengthGate(unittest.TestCase):
    """Boundary of the merge name gate: a forged command of ".x"
    passed and produced a merged dir _list_run_dirs skips forever —
    while the source runs were deleted on success (merged data
    invisible to every project view). Over-NAME_MAX / NUL command
    types escaped as uncaught OSError from the mkdir."""

    def _run(self, out: Path, name: str, command) -> Path:
        d = out / name
        d.mkdir(parents=True)
        (d / ".raptor-run.json").write_text(json.dumps({
            "version": 2, "command": command, "status": "completed",
            "project": None, "project_source": "none",
        }), encoding="utf-8")
        (d / "findings.json").write_text("[]", encoding="utf-8")
        return d

    def _merge(self, command):
        from core.project.cli import _do_merge
        from core.project.project import Project
        with TemporaryDirectory() as td:
            tmp = Path(td)
            out = tmp / "proj-out"
            out.mkdir()
            project = Project(name="p", target=str(tmp / "code"),
                              output_dir=str(out))
            self._run(out, "scan-1", command)
            self._run(out, "scan-2", command)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _do_merge(project, "all", yes=True)
            return (buf.getvalue(), (out / "scan-1").exists(),
                    (out / "scan-2").exists())

    def test_dot_prefixed_command_refused(self):
        text, s1, s2 = self._merge(".x")
        self.assertIn("refus", text.lower())
        self.assertTrue(s1)
        self.assertTrue(s2)

    def test_underscore_prefixed_command_refused(self):
        text, s1, _s2 = self._merge("_gen")
        self.assertIn("refus", text.lower())
        self.assertTrue(s1)

    def test_over_length_command_refused_not_oserror(self):
        text, s1, _s2 = self._merge("s" * 300)
        self.assertIn("refus", text.lower())
        self.assertTrue(s1)


class TestFindingsReadjudicationNotice(unittest.TestCase):
    """/project findings surfaces the re-adjudication signal broken
    down by shape — counts only, nothing overturned in the view."""

    @staticmethod
    def _run(base: Path, name: str, findings, status="completed") -> Path:
        run_dir = base / name
        run_dir.mkdir(parents=True)
        (run_dir / "findings.json").write_text(
            json.dumps({"findings": findings}), encoding="utf-8")
        (run_dir / ".raptor-run.json").write_text(
            json.dumps({"status": status, "command": "validate"}),
            encoding="utf-8")
        return run_dir

    def test_overturn_and_split_counts_in_notice(self):
        site = {"file": "a.php", "function": "handler", "line": 4,
                "vuln_type": "xss", "cwe_id": "CWE-79"}
        with TemporaryDirectory() as d:
            old = self._run(Path(d), "run_a",
                            [dict(site, id="A-1", status="confirmed")])
            new = self._run(Path(d), "run_b", [
                dict(site, id="B-1", status="confirmed"),
                dict(site, id="B-2", status="ruled_out"),
            ])
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                # get_run_dirs contract is NEWEST-first.
                _print_findings(_FakeProject([new, old]))
            out = buf.getvalue()
            self.assertIn("1 confirmed verdict(s) disproven by a later run",
                          out)
            self.assertIn("1 intra-run final-verdict split(s)", out)
            self.assertIn("Nothing is auto-overturned.", out)

    def test_no_contradiction_no_notice(self):
        with TemporaryDirectory() as d:
            run = self._run(Path(d), "run_a", [{
                "id": "A-1", "file": "a.php", "function": "handler",
                "line": 4, "status": "confirmed",
            }])
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                _print_findings(_FakeProject([run]))
            self.assertNotIn("re-adjudication", buf.getvalue())
