"""TTY-conditional display lanes in libexec/raptor-run-sandboxed.

The wrapper's mandated use is arbitrary untrusted build systems, and it
passes the child's stdout/stderr through to the caller. Before the
display lane existed, that pass-through was verbatim: a hostile build
could emit terminal escape sequences (OSC window-title spoofs, CSI
erase-line, carriage-return overwrites, C1 controls, bidi overrides)
straight at the operator's terminal and forge "all-clear" output.

The lane is TTY-conditional: a live terminal gets the
``core.security.log_sanitisation`` escaping contract with newlines and
tabs preserved (build output is structurally multi-line); a pipe or
file gets byte-for-byte pass-through so programmatic consumers keep
fidelity. Unknown TTY-ness fails toward escaping. The TimeoutExpired
partial-output leg rides the same lane.

Hermetic: the script is exec'd in-process with a stubbed core.sandbox
module and test-owned stdout/stderr stream objects — no namespaces,
Landlock, or real children.
"""

from __future__ import annotations

import contextlib
import importlib.machinery
import importlib.util
import io
import logging
import subprocess
import sys
import types
from pathlib import Path
from typing import TextIO
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-run-sandboxed"

# One payload exercising every escape class the sanitisation contract
# names: ESC/OSC (window-title spoof), CSI (erase line), CR (line
# overwrite), BEL, a C1 control, and a bidi override — interleaved
# with legitimate multi-line build prose.
HOSTILE = (
    "checking compiler... ok\n"
    "\x1b]0;pwned-title\x07"
    "\x1b[2K\rall 97 tests passed\n"
    "\x9bodd C1\n"
    "path‮gnp.cod\n"
    "\tindented detail\n"
)


class _TtyStream(io.StringIO):
    def isatty(self) -> bool:
        return True


class _PipeStream(io.StringIO):
    def isatty(self) -> bool:
        return False


class _BrokenIsattyStream(io.StringIO):
    def isatty(self) -> bool:
        raise ValueError("stream state unknowable")


def _run_script(monkeypatch, tmp_path, *, child_stdout: str = "",
                child_stderr: str = "", timeout_exc: BaseException | None = None,
                raw_child_output: "tuple[bytes, bytes] | None" = None,
                sandbox_info: "dict | None" = None,
                out_stream: TextIO, err_stream: TextIO) -> int:
    """Exec the wrapper against a stubbed sandbox whose run() returns
    the given child output (or raises *timeout_exc*); the given stream
    objects ARE the wrapper's stdout/stderr, so each test owns its
    display lanes. Returns the exit code.

    *raw_child_output* supplies the child's (stdout, stderr) as raw
    BYTES and makes the stub honour subprocess's capture-decode
    semantics: text mode decodes with the wrapper's own encoding/errors
    kwargs — strict by default, exactly where an invalid byte raised
    UnicodeDecodeError before the errors="replace" fix."""
    fake = types.ModuleType("core.sandbox")

    class SandboxSetupError(Exception):
        pass

    @contextlib.contextmanager
    def sandbox(**kwargs):
        def run_fn(cmd, **run_kwargs):
            if timeout_exc is not None:
                raise timeout_exc
            stdout: "str | bytes" = child_stdout
            stderr: "str | bytes" = child_stderr
            if raw_child_output is not None:
                if run_kwargs.get("text"):
                    enc = run_kwargs.get("encoding") or "utf-8"
                    errs = run_kwargs.get("errors") or "strict"
                    stdout = raw_child_output[0].decode(enc, errs)
                    stderr = raw_child_output[1].decode(enc, errs)
                else:
                    stdout, stderr = raw_child_output
            return types.SimpleNamespace(
                returncode=0, stdout=stdout, stderr=stderr,
                sandbox_info=dict(sandbox_info or {}))

        yield run_fn

    fake.SandboxSetupError = SandboxSetupError
    fake.SANDBOX_ENGAGE_EXIT_CODE = 3
    fake.sandbox = sandbox
    monkeypatch.setitem(sys.modules, "core.sandbox", fake)

    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    monkeypatch.delenv("OUTPUT_DIR", raising=False)
    monkeypatch.setattr(sys, "argv", [
        "raptor-run-sandboxed", "--output-dir", str(tmp_path / "out"),
        "/bin/true"])
    monkeypatch.setattr(sys, "stdout", out_stream)
    monkeypatch.setattr(sys, "stderr", err_stream)

    loader = importlib.machinery.SourceFileLoader(
        "raptor_run_sandboxed_display_under_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    # The script calls configure_cli_logging, which may attach a root
    # handler bound to the swapped stderr; restore root logging state
    # so a test-owned StringIO never leaks into later tests' logs.
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        with pytest.raises(SystemExit) as exc, \
                patch.object(sys, "path", sys.path.copy()):
            loader.exec_module(mod)
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)
    return exc.value.code


class TestTtyLaneEscapes:
    def test_stdout_tty_escapes_every_control_class(
            self, monkeypatch, tmp_path):
        out, err = _TtyStream(), _TtyStream()
        code = _run_script(monkeypatch, tmp_path, child_stdout=HOSTILE,
                           out_stream=out, err_stream=err)
        assert code == 0
        shown = out.getvalue()
        # No raw control byte reaches the terminal...
        assert "\x1b" not in shown
        assert "\x07" not in shown
        assert "\r" not in shown
        assert "\x9b" not in shown
        assert "‮" not in shown
        # ...each arrives as its inert escape instead...
        assert "\\x1b]0;pwned-title\\x07" in shown
        assert "\\x1b[2K\\x0dall 97 tests passed" in shown
        assert "\\x9bodd C1" in shown
        assert "\\u202egnp.cod" in shown
        # ...and the structural whitespace plus prose are untouched.
        assert "checking compiler... ok\n" in shown
        assert "\tindented detail\n" in shown
        assert shown.count("\n") == HOSTILE.count("\n")

    def test_stderr_tty_lane_gets_the_same_treatment(
            self, monkeypatch, tmp_path):
        out, err = _TtyStream(), _TtyStream()
        code = _run_script(monkeypatch, tmp_path, child_stderr=HOSTILE,
                           out_stream=out, err_stream=err)
        assert code == 0
        shown = err.getvalue()
        assert "\x1b" not in shown
        assert "\\x1b]0;pwned-title" in shown

    def test_unknown_ttyness_fails_toward_escaping(
            self, monkeypatch, tmp_path):
        # A mangled progress bar is recoverable; an injected terminal
        # sequence is not — when isatty itself errors, escape.
        out, err = _BrokenIsattyStream(), _TtyStream()
        code = _run_script(monkeypatch, tmp_path, child_stdout=HOSTILE,
                           out_stream=out, err_stream=err)
        assert code == 0
        assert "\x1b" not in out.getvalue()
        assert "\\x1b]0;pwned-title" in out.getvalue()


class TestPipeLaneIsVerbatim:
    def test_piped_stdout_keeps_byte_fidelity(self, monkeypatch, tmp_path):
        out, err = _PipeStream(), _PipeStream()
        code = _run_script(monkeypatch, tmp_path, child_stdout=HOSTILE,
                           out_stream=out, err_stream=err)
        assert code == 0
        assert out.getvalue() == HOSTILE

    def test_piped_stderr_keeps_byte_fidelity(self, monkeypatch, tmp_path):
        out, err = _PipeStream(), _PipeStream()
        code = _run_script(monkeypatch, tmp_path, child_stderr=HOSTILE,
                           out_stream=out, err_stream=err)
        assert code == 0
        assert err.getvalue() == HOSTILE


class TestInvalidUtf8NeverAbortsTheRun:
    """One invalid UTF-8 byte from the untrusted child must not abort
    the wrapper. Under the default strict decode it raised
    UnicodeDecodeError (a ValueError), which the generic handler turned
    into exit 2 — with ALL child output and every ``[sandbox]``
    blocked/crash diagnostic suppressed: a hostile build could silence
    the sandbox's own evidence with a single byte. The wrapper now
    requests ``errors="replace"``, matching the TimeoutExpired
    partial-output leg."""

    RAW = (b"compiling\xff\x1b[2Kok\n", b"warn\xfe\n")

    def test_output_and_diagnostics_survive_invalid_bytes(
            self, monkeypatch, tmp_path):
        out, err = _PipeStream(), _PipeStream()
        code = _run_script(
            monkeypatch, tmp_path, raw_child_output=self.RAW,
            sandbox_info={"blocked": ["network connect denied"]},
            out_stream=out, err_stream=err)
        # The child's exit code, not the wrapper's failure code 2.
        assert code == 0
        # Undecodable bytes become U+FFFD; everything else survives.
        assert out.getvalue() == "compiling�\x1b[2Kok\n"
        assert err.getvalue().startswith("warn�\n")
        # The sandbox's own evidence still reaches the caller.
        assert "[sandbox] network connect denied" in err.getvalue()

    def test_tty_lane_still_escapes_after_replacement(
            self, monkeypatch, tmp_path):
        out, err = _TtyStream(), _TtyStream()
        code = _run_script(monkeypatch, tmp_path,
                           raw_child_output=self.RAW,
                           out_stream=out, err_stream=err)
        assert code == 0
        shown = out.getvalue()
        assert "\x1b" not in shown
        assert "\\x1b[2K" in shown
        assert "�" in shown


class TestTimeoutPartialOutputRidesTheLane:
    def _timeout(self) -> subprocess.TimeoutExpired:
        return subprocess.TimeoutExpired(
            cmd=["/bin/true"], timeout=5,
            output=b"partial\x1b[8mhidden\xff\n",
            stderr=b"late\x1b]0;spoof\x07line\n")

    def test_tty_lane_escapes_partial_output(self, monkeypatch, tmp_path):
        out, err = _TtyStream(), _TtyStream()
        code = _run_script(monkeypatch, tmp_path,
                           timeout_exc=self._timeout(),
                           out_stream=out, err_stream=err)
        assert code == 2
        shown_out, shown_err = out.getvalue(), err.getvalue()
        assert "\x1b" not in shown_out
        assert "\\x1b[8mhidden" in shown_out
        # Undecodable bytes become U+FFFD (printable — passes through).
        assert "�" in shown_out
        assert "\x1b" not in shown_err
        assert "late\\x1b]0;spoof\\x07line" in shown_err
        # The wrapper's own failure banner still lands on stderr.
        assert "sandbox invocation failed: TimeoutExpired" in shown_err

    def test_pipe_lane_passes_partial_output_through(
            self, monkeypatch, tmp_path):
        out, err = _PipeStream(), _PipeStream()
        code = _run_script(monkeypatch, tmp_path,
                           timeout_exc=self._timeout(),
                           out_stream=out, err_stream=err)
        assert code == 2
        assert out.getvalue() == "partial\x1b[8mhidden�\n"
        assert err.getvalue().startswith("late\x1b]0;spoof\x07line\n")
