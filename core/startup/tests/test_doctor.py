"""Tests for ``core.startup.doctor``.

Exercises the renderer + main entry point with mocked ``init.check_*``
returns. The check functions themselves have their own tests
(``test_check_env_macos.py``, etc.); doctor's surface is the
mapping from check-function output → failure/warning/pass
classification + exit code.
"""

from __future__ import annotations



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
):
    """Build a _gather()-shaped tuple for tests."""
    return (
        list(tool_results), list(tool_warnings),
        list(llm_lines), list(llm_warnings),
        list(env_parts), list(env_warnings),
        lang_line, project_line,
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
        text, n_fail, n_warn = _render(
            *_gather_stub(llm_warnings=["No API keys configured"]),
            verbose=False,
        )
        assert n_warn == 1

    def test_env_warnings_are_warnings(self):
        text, n_fail, n_warn = _render(
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
        text, n_fail, n_warn = _render(
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
                    "RAPTOR_DIR not set in this process; "
                    "expected /home/op/raptor based on checkout "
                    "location.",
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
