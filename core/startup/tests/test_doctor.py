"""Tests for ``core.startup.doctor``.

Exercises the renderer + main entry point with mocked ``init.check_*``
returns. The check functions themselves have their own tests
(``test_check_env_macos.py``, etc.); doctor's surface is the
mapping from check-function output → failure/warning/pass
classification + exit code.
"""

from __future__ import annotations

import typing

from core.startup import doctor
from core.startup.doctor import _render, main


def _gather_stub(
    *,
    tool_results=(),
    tool_warnings=(),
    llm_lines=(),
    llm_warnings=(),
    env_parts=(),
    env_warnings=(),
    lang_line=None,
    project_line=None,
    advisories=(),
):
    """Build a _gather()-shaped tuple for tests."""
    return (
        list(tool_results), list(tool_warnings),
        list(llm_lines), list(llm_warnings),
        list(env_parts), list(env_warnings),
        lang_line, project_line,
        list(advisories),
    )


# ---------------------------------------------------------------------------
# Classification — what's a failure, what's a warning, what's a pass
# ---------------------------------------------------------------------------


class TestRenderClassification:
    def test_env_cross_glyph_is_failure(self):
        text, n_fail, n_warn = _render(
            *_gather_stub(env_parts=["out/ ✗", "disk 16 GB free"]),
            verbose=False,
        )
        assert n_fail == 1
        assert n_warn == 0
        assert "FAILURES:" in text
        assert "✗ out/ ✗" in text
        # The fact line is a pass.
        assert "disk 16 GB free" not in text.split("FAILURES:")[1].split("\n\n")[0]

    def test_tool_warnings_are_warnings(self):
        text, n_fail, n_warn = _render(
            *_gather_stub(
                tool_results=[("semgrep", True), ("rr", False)],
                tool_warnings=["/crash-analysis limited — rr not found"],
            ),
            verbose=False,
        )
        assert n_fail == 0
        assert n_warn == 1
        assert "WARNINGS:" in text
        assert "rr not found" in text

    def test_llm_warnings_are_warnings(self):
        _text, _n_fail, n_warn = _render(
            *_gather_stub(llm_warnings=["No API keys configured"]),
            verbose=False,
        )
        assert n_warn == 1

    def test_env_warnings_are_warnings(self):
        _text, _n_fail, n_warn = _render(
            *_gather_stub(env_warnings=["RAPTOR_DIR not set"]),
            verbose=False,
        )
        assert n_warn == 1

    def test_pass_lines_default_summarised(self):
        text, n_fail, n_warn = _render(
            *_gather_stub(
                tool_results=[("semgrep", True), ("codeql", True)],
                env_parts=["out/ ✓"],
                lang_line="tree-sitter ✓ (python)",
            ),
            verbose=False,
        )
        assert n_fail == 0
        assert n_warn == 0
        # All-good path emits the compact summary line.
        assert "All " in text and "check(s) passed" in text
        # Individual pass lines NOT in default output.
        assert "PASSED:" not in text

    def test_pass_lines_shown_with_verbose(self):
        text, _n_fail, _n_warn = _render(
            *_gather_stub(
                tool_results=[("semgrep", True)],
                env_parts=["out/ ✓"],
            ),
            verbose=True,
        )
        assert "PASSED:" in text
        assert "tools present: semgrep" in text
        assert "out/ ✓" in text

    def test_summary_line_always_present(self):
        text, _, _ = _render(*_gather_stub(), verbose=False)
        assert "Summary:" in text
        assert "0 failure(s)" in text

    def test_lang_cross_line_not_listed_as_pass(self):
        """A ✗ tree-sitter line must not appear under PASSED — the
        degradation warning check_lang emits covers the signal."""
        text, n_fail, n_warn = _render(
            *_gather_stub(
                lang_line="  lang: tree-sitter ✗",
                env_warnings=[
                    ("no tree-sitter grammars installed — inventory "
                     "degrades to regex extraction"),
                ],
            ),
            verbose=True,
        )
        assert n_fail == 0
        assert n_warn == 1
        passed_section = text.split("PASSED:")[1] if "PASSED:" in text else ""
        assert "tree-sitter ✗" not in passed_section

    def test_lang_check_line_still_listed_as_pass(self):
        text, _, _ = _render(
            *_gather_stub(lang_line="  lang: tree-sitter ✓ (python, c)"),
            verbose=True,
        )
        assert "tree-sitter ✓ (python, c)" in text


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


class TestMainExitCodes:
    def test_clean_run_returns_zero(self, capsys, monkeypatch):
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(tool_results=[("semgrep", True)]),
        )
        rc = main([])
        assert rc == 0

    def test_any_failure_returns_one(self, capsys, monkeypatch):
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(env_parts=["out/ ✗"]),
        )
        rc = main([])
        assert rc == 1

    def test_warnings_alone_do_not_fail(self, capsys, monkeypatch):
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(env_warnings=["RAPTOR_DIR not set"]),
        )
        rc = main([])
        assert rc == 0

    def test_strict_fails_on_warnings(self, capsys, monkeypatch):
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(env_warnings=["RAPTOR_DIR not set"]),
        )
        rc = main(["--strict"])
        assert rc == 1

    def test_strict_passes_on_clean(self, capsys, monkeypatch):
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(tool_results=[("semgrep", True)]),
        )
        rc = main(["--strict"])
        assert rc == 0

    def test_verbose_does_not_change_exit_code(self, capsys, monkeypatch):
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(env_parts=["out/ ✗"]),
        )
        rc = main(["--verbose"])
        assert rc == 1


# ---------------------------------------------------------------------------
# Usage / argument handling
# ---------------------------------------------------------------------------


class TestUsage:
    def test_unknown_flag_returns_two(self, capsys):
        rc = main(["--json"])
        captured = capsys.readouterr()
        assert rc == 2
        assert "usage: raptor doctor" in captured.err

    def test_help_flag_returns_zero_on_stdout(self, capsys):
        """`--help` is a help request: usage to stdout, exit 0.

        Distinct from an unknown flag (stderr, exit 2). Guards against the
        regression where --help fell into the unknown-arg branch.
        """
        rc = main(["--help"])
        captured = capsys.readouterr()
        assert rc == 0
        assert "usage: raptor doctor" in captured.out
        assert captured.err == ""

    def test_short_help_flag_returns_zero_on_stdout(self, capsys):
        """`-h` behaves identically to `--help`."""
        rc = main(["-h"])
        captured = capsys.readouterr()
        assert rc == 0
        assert "usage: raptor doctor" in captured.out
        assert captured.err == ""

    def test_strict_and_verbose_combinable(self, capsys, monkeypatch):
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(env_warnings=["x"]),
        )
        rc = main(["--strict", "--verbose"])
        assert rc == 1

    def test_short_verbose_flag(self, capsys, monkeypatch):
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(tool_results=[("x", True)]),
        )
        rc = main(["-v"])
        assert rc == 0
        # Short flag triggers verbose rendering.
        out = capsys.readouterr().out
        assert "PASSED:" in out


# ---------------------------------------------------------------------------
# Module-dep import verification (doctor-only depth)
# ---------------------------------------------------------------------------


class TestModuleDepVerification:
    """The banner's find_spec probe deliberately never imports; doctor
    spends a subprocess to catch the present-but-broken-wheel state
    (Python upgraded under the venv, half-completed install)."""

    _DEPS: typing.ClassVar[dict] = {
        "z3": {
            "module": "z3", "pip": "z3-solver",
            "severity": "degrades", "affects": "/audit (SMT)",
        },
        "semgrep": {"binary": "semgrep", "affects": "/scan"},
    }

    def _run(self, monkeypatch, *, spec_found=True, returncode=0,
             run_side_effect=None):
        from unittest import mock

        from core.config import RaptorConfig

        proc = mock.Mock(returncode=returncode, stdout="", stderr="boom")
        run_mock = mock.Mock(
            return_value=proc, side_effect=run_side_effect,
        )
        with mock.patch.object(RaptorConfig, "TOOL_DEPS", self._DEPS), \
             mock.patch(
                 "importlib.util.find_spec",
                 return_value=object() if spec_found else None,
             ), mock.patch("subprocess.run", run_mock):
            warnings = doctor._module_dep_warnings()
        return warnings, run_mock

    def test_broken_module_warns_with_reinstall_hint(self, monkeypatch):
        warnings, _ = self._run(monkeypatch, returncode=1)
        assert len(warnings) == 1
        assert "z3 is installed but failed to import" in warnings[0]
        assert "z3-solver" in warnings[0]

    def test_healthy_module_stays_quiet(self, monkeypatch):
        warnings, _ = self._run(monkeypatch, returncode=0)
        assert warnings == []

    def test_absent_module_skipped_without_subprocess(self, monkeypatch):
        # Absent is check_tools' territory — no duplicate warning,
        # and no subprocess spent.
        warnings, run_mock = self._run(monkeypatch, spec_found=False)
        assert warnings == []
        run_mock.assert_not_called()

    def test_binary_deps_never_probed(self, monkeypatch):
        # Only module deps are import-verified; one subprocess for z3,
        # none for semgrep.
        _, run_mock = self._run(monkeypatch, returncode=0)
        assert run_mock.call_count == 1

    def test_probe_failure_never_raises(self, monkeypatch):
        warnings, _ = self._run(
            monkeypatch, run_side_effect=OSError("spawn failed"),
        )
        assert warnings == []


# ---------------------------------------------------------------------------
# Module-dep probe isolation
# ---------------------------------------------------------------------------


class TestModuleProbeIsolation:
    """``python -c`` puts the invocation cwd at ``sys.path[0]`` — a
    planted module in whatever directory doctor runs from must never
    execute in the probe subprocess."""

    def test_planted_module_in_cwd_not_executed(
        self, monkeypatch, tmp_path,
    ):
        from unittest import mock

        from core.config import RaptorConfig

        attack = tmp_path / "attack"
        attack.mkdir()
        canary = tmp_path / "canary"
        (attack / "raptor_probe_target_mod.py").write_text(
            "import pathlib\n"
            f"pathlib.Path({str(canary)!r}).touch()\n",
        )
        deps = {
            "probe-target": {
                "module": "raptor_probe_target_mod",
                "pip": "probe-target", "affects": "/nothing",
            },
        }
        monkeypatch.chdir(attack)
        with mock.patch.object(RaptorConfig, "TOOL_DEPS", deps), \
             mock.patch(
                 "importlib.util.find_spec", return_value=object(),
             ):
            doctor._module_dep_warnings()
        assert not canary.exists(), (
            "module-dep probe imported a module planted in the "
            "invocation cwd"
        )


# ---------------------------------------------------------------------------
# Internal-error safety
# ---------------------------------------------------------------------------


class TestInternalSafety:
    def test_gather_exception_renders_as_failure(
        self, capsys, monkeypatch,
    ):
        def boom():
            raise RuntimeError("simulated check explosion")
        monkeypatch.setattr(doctor, "_gather", boom)
        rc = main([])
        assert rc == 1
        out = capsys.readouterr().out
        assert "doctor internal error" in out
        assert "simulated check explosion" in out


# ---------------------------------------------------------------------------
# Output shape — failures-first, no banner content
# ---------------------------------------------------------------------------


class TestOutputShape:
    def test_no_logo_no_quote(self, capsys, monkeypatch):
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(tool_results=[("semgrep", True)]),
        )
        main([])
        out = capsys.readouterr().out
        # Banner artifacts should be absent.
        assert "raptor:~$" not in out  # no quote prompt
        assert "╔═" not in out  # no logo box
        assert "Get them bugs" not in out

    def test_failures_appear_before_warnings(
        self, capsys, monkeypatch,
    ):
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(
                env_parts=["out/ ✗"],
                env_warnings=["disk getting low"],
            ),
        )
        main([])
        out = capsys.readouterr().out
        fail_idx = out.index("FAILURES:")
        warn_idx = out.index("WARNINGS:")
        assert fail_idx < warn_idx

    def test_install_hint_attached_to_missing_tool_warning(
        self, capsys, monkeypatch,
    ):
        # Missing rr → warning carries the PM-aware install hint
        # on a continuation line. Shared substrate with /describe.
        from packages.describe.package_manager import (
            detect_package_manager,
        )
        detect_package_manager.cache_clear()
        monkeypatch.setattr(
            "shutil.which",
            lambda cmd: "/usr/bin/apt" if cmd == "apt" else None,
        )
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(
                tool_results=[("rr", False), ("gdb", True)],
                tool_warnings=[
                    "/crash-analysis limited — rr not found",
                ],
            ),
        )
        main([])
        out = capsys.readouterr().out
        # Warning + install hint on its own continuation line.
        assert "rr not found" in out
        assert "hint: sudo apt install rr" in out
        # Summary count uses real-warning count (1), not 1+hint=2.
        assert "1 warning(s)" in out

    def test_install_hint_for_codeql_uses_static_url(
        self, capsys, monkeypatch,
    ):
        # codeql isn't in any distro repo → install_advice
        # dispatches to a static GH-Releases URL instead of a
        # bogus ``apt install codeql``.
        from packages.describe.package_manager import (
            detect_package_manager,
        )
        detect_package_manager.cache_clear()
        monkeypatch.setattr(
            "shutil.which",
            lambda cmd: "/usr/bin/apt" if cmd == "apt" else None,
        )
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(
                tool_results=[("codeql", False)],
                tool_warnings=[
                    "/codeql, /agentic limited — codeql not found",
                ],
            ),
        )
        main([])
        out = capsys.readouterr().out
        # Static-URL kind: NO "apt install codeql" (would be
        # wrong — package doesn't exist in distro repos).
        assert "apt install codeql" not in out
        assert "github.com/github/codeql-cli-binaries" in out

    def test_specific_paths_present_in_env_warnings(
        self, capsys, monkeypatch,
    ):
        """Doctor output names the specific path / value when the check
        knows it — operator saves a lookup. Pin that the warning text
        flows through to stdout unchanged."""
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(
                env_warnings=[
                    ("RAPTOR_DIR not set in this process; "
                     "expected /home/op/raptor based on checkout "
                     "location."),
                ],
            ),
        )
        main([])
        out = capsys.readouterr().out
        assert "/home/op/raptor" in out


# ---------------------------------------------------------------------------
# ANSI / control-byte defence
# ---------------------------------------------------------------------------


class TestNonprintableEscaping:
    """Every operator-visible string from upstream checks must pass
    through ``escape_nonprintable`` before reaching stdout. No current
    producer of doctor input emits ANSI, but defence in depth keeps a
    future change (e.g. tool warning sourced from subprocess stderr,
    project name read from disk) from delivering a terminal-escape
    injection."""

    _EVIL = "\x1b[31mEVIL\x1b[0m"
    _EVIL_ESCAPED = "\\x1b[31mEVIL\\x1b[0m"

    def test_ansi_in_tool_warning_is_escaped(
        self, capsys, monkeypatch,
    ):
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(
                tool_warnings=[f"/agentic limited — {self._EVIL} fake-tool"],
            ),
        )
        main([])
        out = capsys.readouterr().out
        assert "\x1b" not in out
        assert self._EVIL_ESCAPED in out

    def test_ansi_in_llm_warning_is_escaped(
        self, capsys, monkeypatch,
    ):
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(
                llm_warnings=[f"provider error: {self._EVIL}"],
            ),
        )
        main([])
        out = capsys.readouterr().out
        assert "\x1b" not in out

    def test_ansi_in_env_failure_is_escaped(
        self, capsys, monkeypatch,
    ):
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(
                env_parts=[f"out/ ✗ {self._EVIL}"],
            ),
        )
        main([])
        out = capsys.readouterr().out
        assert "\x1b" not in out
        # The ✗ glyph (a printable Unicode codepoint) survives;
        # only the ESC bytes get rewritten.
        assert "✗" in out

    def test_ansi_in_pass_lines_is_escaped_under_verbose(
        self, capsys, monkeypatch,
    ):
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(
                env_parts=[f"out/ ✓ {self._EVIL}"],
            ),
        )
        main(["--verbose"])
        out = capsys.readouterr().out
        assert "\x1b" not in out

    def test_ansi_in_internal_error_is_escaped(
        self, capsys, monkeypatch,
    ):
        def boom():
            raise RuntimeError(f"taint {self._EVIL} in message")
        monkeypatch.setattr(doctor, "_gather", boom)
        rc = main([])
        assert rc == 1
        out = capsys.readouterr().out
        assert "\x1b" not in out
        assert "doctor internal error" in out

    def test_printable_glyphs_survive(self, capsys, monkeypatch):
        """The escaping pass keeps ✗ ✓ ! and Unicode letters — only
        non-printable bytes get rewritten. Pin so a tightening of
        ``escape_nonprintable`` doesn't accidentally mangle the
        doctor's status glyphs."""
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(
                env_parts=["out/ ✗"],
                tool_warnings=["rr not found — /crash-analysis limited"],
            ),
        )
        main([])
        out = capsys.readouterr().out
        assert "✗" in out
        assert "!" in out
        # Em-dash (a printable Unicode codepoint) must survive.
        assert "—" in out


# ---------------------------------------------------------------------------
# Imported-annotation advisory sweep
# ---------------------------------------------------------------------------


def _write_note(base, source_file, function, metadata):
    from core.annotations.models import Annotation
    from core.annotations.storage import write_annotation

    write_annotation(base, Annotation(
        file=source_file, function=function,
        body="reviewed", metadata=metadata,
    ))


_HUMAN_GRADE_META = {
    "status": "clean", "source": "human",
    "tty": "stdin", "provenance": "interactive-tty",
}


def _make_project(tmp_path, name, *, target="/src/app"):
    """Fabricate a registered project with an output dir under tmp_path."""
    from core.project.project import ProjectManager

    mgr = ProjectManager(projects_dir=tmp_path / "registry")
    out_dir = tmp_path / "out" / name
    mgr.create(name, target, output_dir=str(out_dir), resolve_target=False)
    return out_dir


class TestImportedAnnotationAdvisories:
    def test_no_projects_is_skipped(self, tmp_path):
        assert doctor._imported_annotation_advisories(
            projects_dir=tmp_path / "registry",
        ) == []

    def test_human_grade_notes_get_generic_advisory(self, tmp_path):
        out_dir = _make_project(tmp_path, "proj1")
        _write_note(out_dir / "annotations", "src/a.py", "f",
                    _HUMAN_GRADE_META)
        lines = doctor._imported_annotation_advisories(
            projects_dir=tmp_path / "registry",
        )
        assert len(lines) == 1
        assert "'proj1'" in lines[0]
        assert "cannot be machine-attributed" in lines[0]
        assert "/annotate ls" in lines[0]

    def test_imported_target_breadcrumb_gets_targeted_advisory(
        self, tmp_path,
    ):
        """The one pre-marker registry breadcrumb: import registers
        target='(imported)' when the archive metadata omitted a target.
        Such projects get a targeted line, not the generic one."""
        out_dir = _make_project(tmp_path, "oldimport", target="(imported)")
        run = out_dir / "scan_20260101-000000"
        run.mkdir(parents=True)
        _write_note(run / "annotations", "src/b.py", "g",
                    _HUMAN_GRADE_META)
        lines = doctor._imported_annotation_advisories(
            projects_dir=tmp_path / "registry",
        )
        assert len(lines) == 1
        assert "'oldimport'" in lines[0]
        assert "(imported)" in lines[0]
        assert "1 human-grade annotation(s)" in lines[0]

    def test_marker_covered_trees_are_skipped(self, tmp_path):
        """Runs (and whole projects) carrying the persisted import
        marker were demoted at import time — never advised on."""
        import json

        out_marked_run = _make_project(tmp_path, "postfix-run")
        run = out_marked_run / "scan_20260101-000000"
        run.mkdir(parents=True)
        (run / ".raptor-imported.json").write_text(
            json.dumps({"imported": True}))
        _write_note(run / "annotations", "src/c.py", "h",
                    _HUMAN_GRADE_META)

        out_marked_root = _make_project(tmp_path, "postfix-root")
        (out_marked_root / ".raptor-imported.json").write_text(
            json.dumps({"imported": True}))
        _write_note(out_marked_root / "annotations", "src/d.py", "i",
                    _HUMAN_GRADE_META)

        assert doctor._imported_annotation_advisories(
            projects_dir=tmp_path / "registry",
        ) == []

    def test_hint_tier_notes_not_flagged(self, tmp_path):
        """Demoted (provenance=imported) and non-tty notes are hint
        tier — no operator authority, nothing to advise about."""
        out_dir = _make_project(tmp_path, "hints")
        _write_note(out_dir / "annotations", "src/e.py", "j", {
            "status": "clean", "source": "human",
            "provenance": "imported",
        })
        _write_note(out_dir / "annotations", "src/e.py", "k", {
            "status": "clean", "source": "human",
            "tty": "none", "provenance": "non-tty",
        })
        _write_note(out_dir / "annotations", "src/e.py", "l", {
            "status": "clean", "source": "agent",
            "tty": "stdin", "provenance": "interactive-tty",
        })
        assert doctor._imported_annotation_advisories(
            projects_dir=tmp_path / "registry",
        ) == []

    def test_advisories_render_without_affecting_counts(self, capsys):
        text, n_fail, n_warn = _render(
            *_gather_stub(
                tool_results=[("semgrep", True)],
                advisories=["human-grade annotations found in 'p'"],
            ),
            verbose=False,
        )
        assert n_fail == 0
        assert n_warn == 0
        assert "ADVISORIES:" in text
        assert "i human-grade annotations found in 'p'" in text

    def test_advisories_do_not_fail_strict(self, capsys, monkeypatch):
        monkeypatch.setattr(
            doctor, "_gather",
            lambda: _gather_stub(
                tool_results=[("semgrep", True)],
                advisories=["human-grade annotations found in 'p'"],
            ),
        )
        rc = main(["--strict"])
        assert rc == 0
        assert "ADVISORIES:" in capsys.readouterr().out
