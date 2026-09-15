"""The console handler is the chokepoint for logger-routed foreign
text: any log call interpolating scanned-repo names, subprocess
stderr, or LLM excerpts must reach the operator's TTY with control
bytes escaped — per-site wraps have failed member-by-member."""

from __future__ import annotations

import logging

import pytest

from core.logging import EscapingConsoleFormatter, RaptorLogger

HOSTILE = "\x1b]0;pwned\x07\x9b2J‮evil"
RAW = ("\x1b", "\x07", "\x9b", "‮")


def _record(msg: str, *args: object) -> logging.LogRecord:
    return logging.LogRecord(
        name="pkg.mod", level=logging.INFO, pathname="x.py", lineno=1,
        msg=msg, args=args or None, exc_info=None,
    )


class TestEscapingConsoleFormatter:
    def test_hostile_message_escaped(self):
        fmt = EscapingConsoleFormatter("[%(levelname)s] %(message)s")
        out = fmt.format(_record(f"scanning {HOSTILE} done"))
        for raw in RAW:
            assert raw not in out
        assert out.startswith("[INFO] scanning ")
        assert "done" in out

    def test_hostile_percent_args_escaped(self):
        # The common injection site: clean format string, foreign %s arg.
        fmt = EscapingConsoleFormatter("[%(levelname)s] %(message)s")
        out = fmt.format(_record("file: %s", HOSTILE))
        for raw in RAW:
            assert raw not in out

    def test_newlines_and_tabs_survive(self):
        fmt = EscapingConsoleFormatter("%(message)s")
        out = fmt.format(_record("line1\n\tline2"))
        assert out == "line1\n\tline2"

    def test_traceback_structure_survives(self):
        fmt = EscapingConsoleFormatter("%(message)s")
        try:
            raise ValueError(f"boom {HOSTILE}")
        except ValueError:
            import sys
            rec = logging.LogRecord(
                name="pkg.mod", level=logging.ERROR, pathname="x.py",
                lineno=1, msg="failed", args=None, exc_info=sys.exc_info(),
            )
        out = fmt.format(rec)
        assert "Traceback" in out and "\n" in out
        for raw in RAW:
            assert raw not in out


class TestConsoleHandlersUseEscapingFormatter:
    def test_raptor_and_root_console_handlers_escaping(self):
        RaptorLogger()  # singleton — idempotent init
        import sys
        checked = 0
        for logger in (logging.getLogger("raptor"), logging.getLogger()):
            for handler in logger.handlers:
                if (isinstance(handler, logging.StreamHandler)
                        and getattr(handler, "stream", None) is sys.stderr):
                    assert isinstance(
                        handler.formatter, EscapingConsoleFormatter,
                    ), (
                        f"console handler on {logger.name or 'root'!r} "
                        "not using the escaping formatter — foreign "
                        "bytes in log lines reach the TTY raw"
                    )
                    checked += 1
        assert checked >= 1


_BASICCONFIG_CALL_RE = None  # compiled lazily below


def _bare_basicconfig_offences(text: str) -> list[int]:
    """Line numbers of bare-basicConfig usage in ``text``.

    Two spellings: an attribute call on any module alias
    (``logging.basicConfig(`` / ``_logging.basicConfig(``) and the
    imported-name form (``from logging import basicConfig [as x]`` —
    the import itself is the marker; importing it has no purpose but
    calling it, and flagging at the import keeps the scan alias-proof).
    """
    import re
    offences = []
    for m in re.finditer(r"^[^\n#]*?\b\w+\.basicConfig\(", text, re.M):
        offences.append(text.count("\n", 0, m.start()) + 1)
    for m in re.finditer(
            r"^\s*from\s+logging\s+import\s+[^\n]*\bbasicConfig\b",
            text, re.M):
        offences.append(text.count("\n", 0, m.start()) + 1)
    return sorted(set(offences))


class TestConfigureCliLogging:
    """Standalone CLIs must not leave a plain-formatter console
    handler on the root logger — a broad-handler relay like
    ``logger.error("...: %s", exc)`` would deliver raw control bytes
    from foreign-derived exception text to the operator TTY."""

    def _fresh_root(self):
        root = logging.getLogger()
        saved = root.handlers[:]
        root.handlers = []
        return root, saved

    def test_console_handler_gets_escaping_formatter(self):
        import io

        from core.logging import configure_cli_logging
        root, saved = self._fresh_root()
        try:
            configure_cli_logging(logging.INFO,
                                  fmt="%(levelname)s: %(message)s")
            console = [h for h in root.handlers
                       if isinstance(h, logging.StreamHandler)
                       and not isinstance(h, logging.FileHandler)]
            assert console, "basicConfig should have added a console handler"
            for h in console:
                assert isinstance(h.formatter, EscapingConsoleFormatter)
            # End-to-end: a relayed hostile exception renders escaped.
            buf = io.StringIO()
            console[0].stream = buf
            logger = logging.getLogger("cli.test.escaping")
            try:
                raise ValueError("boom \x1b[2J\x1b[Hforged \x9bx")
            except ValueError as exc:
                logger.error("SBOM import failed: %s", exc)
            out = buf.getvalue()
            assert "\x1b" not in out
            assert "\x9b" not in out
            assert "boom" in out and "forged" in out
        finally:
            root.handlers = saved

    def test_preconfigured_root_handlers_untouched(self):
        """When the process already has console handlers (a CLI module
        loaded in-process inside a RAPTOR run), basicConfig no-ops and
        configure_cli_logging must not clobber the bootstrap's
        formatters/formats either."""
        from core.logging import configure_cli_logging
        root, saved = self._fresh_root()
        try:
            pre = logging.StreamHandler()
            pre.setFormatter(
                logging.Formatter("[%(levelname)s] %(message)s"))
            root.addHandler(pre)
            configure_cli_logging(logging.WARNING, fmt="%(message)s")
            assert pre.formatter._fmt == "[%(levelname)s] %(message)s"
            assert not isinstance(pre.formatter, EscapingConsoleFormatter)
        finally:
            root.handlers = saved

    def test_runtime_sources_never_call_bare_basicconfig(self):
        """Closure oracle for the logging-sink exclusion of the
        exception-relay arm: the exclusion is sound only while every
        runtime console config routes through configure_cli_logging
        (or the run-logging setup in core/logging itself). Enumerate
        the real ``logging.basicConfig`` call sites mechanically —
        a bare one in runtime source fails here.

        Exempt: test files, subsystem scripts/ dirs (outside the
        launcher), core/logging itself (the chokepoint's home), and
        buffer-capture harness strings (raptor-self-test's child
        harness logs into an in-memory buffer, never a TTY).
        """
        import subprocess
        from pathlib import Path

        repo = Path(__file__).resolve().parents[3]
        try:
            proc = subprocess.run(
                ["git", "-C", str(repo), "ls-files",
                 "core", "packages", "libexec", "raptor*.py"],
                capture_output=True, text=True, check=True,
            )
        except (OSError, subprocess.CalledProcessError):
            pytest.skip("git ls-files unavailable (no git / not a "
                        "checkout) — closure scan needs the tracked "
                        "file list")
        rels = proc.stdout.splitlines()
        offenders = []
        for rel in rels:
            parts = rel.split("/")
            if ("tests" in parts or "scripts" in parts
                    or parts[-1].startswith("test_")
                    or parts[-1] == "conftest.py"):
                continue
            if rel.startswith("core/logging/"):
                continue
            if rel == "libexec/raptor-self-test":
                # basicConfig(stream=<StringIO buffer>) inside a child
                # harness heredoc — captured, never a TTY.
                continue
            if not (rel.endswith(".py") or rel.startswith("libexec/")):
                continue
            try:
                text = (repo / rel).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for line in _bare_basicconfig_offences(text):
                offenders.append(f"{rel}:{line}")
        assert not offenders, (
            "bare logging.basicConfig in runtime source — use "
            f"core.logging.configure_cli_logging: {offenders}"
        )


def test_bare_basicconfig_predicate_catches_both_spellings():
    """The closure scan's predicate must see the attribute form on any
    module alias AND the imported-name spelling (empirically evaded
    the first module-attribute-only regex)."""
    attr = "import logging\nlogging.basicConfig(level=10)\n"
    aliased_mod = "import logging as _log\n_log.basicConfig(level=10)\n"
    imported = "from logging import basicConfig\nbasicConfig(level=10)\n"
    imported_as = "from logging import basicConfig as bc\nbc(level=10)\n"
    for planted in (attr, aliased_mod, imported, imported_as):
        assert _bare_basicconfig_offences(planted), planted
    safe = (
        "from core.logging import configure_cli_logging\n"
        "configure_cli_logging(10)\n"
        "# logging.basicConfig( in a comment does not count\n"
    )
    assert _bare_basicconfig_offences(safe) == []
