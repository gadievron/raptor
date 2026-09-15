"""The console handler is the chokepoint for logger-routed foreign
text: any log call interpolating scanned-repo names, subprocess
stderr, or LLM excerpts must reach the operator's TTY with control
bytes escaped — per-site wraps have failed member-by-member."""

from __future__ import annotations

import logging

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
