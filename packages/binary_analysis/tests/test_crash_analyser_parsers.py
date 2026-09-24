"""Tests for debugger-output parsing in the crash analyser.

All tests are hermetic: parsers are exercised on captured output
fixtures, and command construction is intercepted at the script-write
seam — no gdb/lldb/target binary is ever executed.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from packages.binary_analysis.crash_analyser import CrashAnalyser, CrashContext


def _bare_analyser() -> CrashAnalyser:
    """CrashAnalyser without __init__ side effects (tool probes, nm).

    The parser methods under test consume only their arguments, so an
    uninitialised instance is sufficient and keeps the tests hermetic.
    """
    return CrashAnalyser.__new__(CrashAnalyser)


def _context() -> CrashContext:
    return CrashContext(
        crash_id="c1",
        binary_path=Path("/nonexistent/bin"),
        input_file=Path("/nonexistent/input"),
        signal="",
    )


# gdb -batch -x <script> output: script commands are NOT echoed, so the
# register block appears with no `info registers` marker line above it.
GDB_BATCH_OUTPUT = """\
Program received signal SIGSEGV, Segmentation fault.
0x0000555555555131 in main ()
rax            0x0                 0
rbx            0x7fffffffe5e8      140737488349160
rcx            0x555555557dc0      93824992247232
rip            0x555555555131      0x555555555131 <main+8>
eflags         0x10246             [ IF ZF PF AF ]
#0  0x0000555555555131 in main ()
#1  0x00007ffff7db1d90 in __libc_start_call_main ()
=> 0x555555555131 <main+8>:\tmov    (%rax),%eax
   0x555555555133 <main+10>:\tret
0x7fffffffe5c0:\t0x00000000\t0x00000000\t0xffffe5e8\t0x00007fff
"""


class TestParseGdbOutput(unittest.TestCase):
    def test_registers_extracted_without_command_echo(self):
        """Register values must parse from batch output that carries no
        echoed `info registers` line."""
        analyser = _bare_analyser()
        ctx = _context()
        analyser._parse_gdb_output(ctx, GDB_BATCH_OUTPUT)
        self.assertEqual(ctx.registers.get("rax"), "0x0")
        self.assertEqual(ctx.registers.get("rbx"), "0x7fffffffe5e8")
        self.assertEqual(ctx.registers.get("rip"), "0x555555555131")

    def test_non_register_lines_not_misparsed(self):
        """Backtrace frames, disassembly, memory dumps and bare-address
        lines must not produce fake register entries."""
        analyser = _bare_analyser()
        ctx = _context()
        analyser._parse_gdb_output(ctx, GDB_BATCH_OUTPUT)
        # Register names never contain '#', '=>' or start with 0x.
        for name in ctx.registers:
            self.assertNotIn("#", name)
            self.assertFalse(name.startswith("0x"), name)
        # `bt full` locals use `name = 0x...` and must not match.
        ctx2 = _context()
        analyser._parse_gdb_output(ctx2, "        buf = 0x7fffffffe5e8\n")
        self.assertEqual(ctx2.registers, {})

    def test_pc_fallback_uses_parsed_rip(self):
        """With registers parsed, the crash-address fallback fires when
        no crash instruction was found."""
        analyser = _bare_analyser()
        ctx = _context()
        analyser._parse_gdb_output(
            ctx,
            "rip            0x401234            0x401234 <main+20>\n",
        )
        self.assertEqual(ctx.crash_address, "0x401234")


# lldb -s <script> output: each script command IS echoed with the
# `(lldb) ` prompt prefix.
LLDB_SESSION_OUTPUT = """\
(lldb) process launch -o "/tmp/o" -e "/tmp/e"
Process 123 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = signal SIGSEGV
(lldb) register read
General Purpose Registers:
        x0 = 0x0000000000000000
        x1 = 0x000000016fdff2c8
        pc = 0x0000000100003f5c
(lldb) thread backtrace --extended true
  frame #0: 0x0000000100003f5c crashme`main + 12
(lldb) disassemble --count 10 --start-address $pc
    0x100003f5c <+12>: ldr    w8, [x8]
"""


class TestParseLldbOutput(unittest.TestCase):
    def test_registers_extracted_despite_prompt_echo(self):
        """The echoed `(lldb) register read` line opens the section; it
        must not immediately close it via the `(lldb)` terminator."""
        analyser = _bare_analyser()
        ctx = _context()
        analyser._parse_lldb_output(ctx, LLDB_SESSION_OUTPUT)
        self.assertEqual(ctx.registers.get("x0"), "0x0000000000000000")
        self.assertEqual(ctx.registers.get("x1"), "0x000000016fdff2c8")
        self.assertEqual(ctx.registers.get("pc"), "0x0000000100003f5c")

    def test_next_command_echo_terminates_section(self):
        """A later `(lldb) <cmd>` echo must close the register section
        so disassembly `= 0x` content is not misread as registers."""
        analyser = _bare_analyser()
        ctx = _context()
        analyser._parse_lldb_output(ctx, LLDB_SESSION_OUTPUT)
        self.assertNotIn("w8,", ctx.registers)
        # Only the three real registers were captured.
        self.assertEqual(set(ctx.registers), {"x0", "x1", "pc"})

    def test_pc_fallback_uses_parsed_registers(self):
        analyser = _bare_analyser()
        ctx = _context()
        analyser._parse_lldb_output(ctx, LLDB_SESSION_OUTPUT)
        self.assertEqual(ctx.crash_address, "0x0000000100003f5c")


class TestLldbLaunchQuoting(unittest.TestCase):
    def test_redirect_paths_quoted_in_launch_command(self):
        """`process launch -o/-e` paths must be quoted so directories
        containing spaces survive LLDB's shell-style tokenisation."""
        import tempfile

        with tempfile.TemporaryDirectory(prefix="dir with space ") as td:
            binary = Path(td) / "bin"
            binary.write_bytes(b"\x7fELF" + b"\x00" * 12)
            input_file = Path(td) / "input"
            input_file.write_bytes(b"A")

            analyser = _bare_analyser()
            analyser.binary = binary

            captured: dict = {}

            def fake_write_script(commands: list, prefix: str = "") -> Path:
                captured["commands"] = list(commands)
                script = Path(td) / "script"
                script.write_text("\n".join(commands))
                return script

            fake_result = MagicMock(stdout="ok", stderr="", returncode=0)
            with patch.object(
                CrashAnalyser, "_write_debugger_script",
                side_effect=fake_write_script,
            ), patch(
                "packages.binary_analysis.crash_analyser._sandbox_run",
                return_value=fake_result,
            ):
                analyser._run_lldb_analysis(input_file)

            launch = next(
                c for c in captured["commands"] if c.startswith("process launch")
            )
            # Both redirect paths are inside quotes.
            self.assertIn('-o "', launch)
            self.assertIn('-e "', launch)
            # The space-bearing directory sits inside a quoted region.
            self.assertIn(f'"{td}', launch)


class TestAslrEnabledStringConvention(unittest.TestCase):
    """binary_info is dict[str, str]: aslr_enabled must be the
    'true'/'false' string convention, never a Python bool."""

    def _layout_info(self, aslr_stdout: str) -> dict:
        import tempfile

        analyser = _bare_analyser()
        analyser.binary = Path("/nonexistent/bin")

        # The ASLR level is read straight from the procfs pseudo-file
        # (module-level seam) — point it at a fixture.
        td = tempfile.mkdtemp(prefix="aslr-fixture-")
        self.addCleanup(
            lambda: __import__("shutil").rmtree(td, ignore_errors=True))
        aslr_file = Path(td) / "randomize_va_space"
        aslr_file.write_text(aslr_stdout)

        def fake_run_trusted(argv: list, **kwargs) -> MagicMock:
            # otool NX probe — irrelevant here
            return MagicMock(returncode=1, stdout="")

        nm_result = MagicMock(returncode=1, stdout="")
        readelf_result = MagicMock(returncode=1, stdout="")
        with patch(
            "packages.binary_analysis.crash_analyser.platform.system",
            return_value="Linux",
        ), patch(
            "packages.binary_analysis.crash_analyser._PROC_ASLR_PATH",
            aslr_file,
        ), patch(
            "packages.binary_analysis.crash_analyser._run_trusted",
            side_effect=fake_run_trusted,
        ), patch(
            "packages.binary_analysis.crash_analyser._nm",
            return_value=nm_result,
        ), patch(
            "packages.binary_analysis.crash_analyser._readelf",
            return_value=readelf_result,
        ):
            return analyser._get_memory_layout_info()

    def test_enabled_is_true_string(self):
        info = self._layout_info("2\n")
        self.assertEqual(info["aslr_enabled"], "true")
        self.assertIsInstance(info["aslr_enabled"], str)

    def test_disabled_is_false_string(self):
        info = self._layout_info("0\n")
        self.assertEqual(info["aslr_enabled"], "false")
        self.assertIsInstance(info["aslr_enabled"], str)


ASAN_REPORT = """\
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000018
READ of size 4 at 0x602000000018 thread T0
    #0 0x1004013a4 in parse_record main.c:42
    #1 0x1004010f0 in main main.c:80
==12345==ABORTING
"""


class TestInferiorAsanCapture(unittest.TestCase):
    """`process launch -o/-e` redirects the crashing inferior's
    stdout/stderr to stub files; on macOS the ASan report lands on the
    INFERIOR's stderr. Pre-fix both stubs were deleted unread and the
    diagnostics silently discarded."""

    def _run_lldb_with_inferior_stderr(self, stderr_text: str) -> tuple:
        import re
        import tempfile

        with tempfile.TemporaryDirectory(prefix="lldb-inferior-") as td:
            binary = Path(td) / "bin"
            binary.write_bytes(b"\x7fELF" + b"\x00" * 12)
            input_file = Path(td) / "input"
            input_file.write_bytes(b"A")

            analyser = _bare_analyser()
            analyser.binary = binary

            captured: dict = {}

            def fake_write_script(commands: list, prefix: str = "") -> Path:
                captured["commands"] = list(commands)
                script = Path(td) / "script"
                script.write_text("\n".join(commands))
                return script

            def fake_sandbox_run(argv: list, **kwargs) -> MagicMock:
                launch = next(
                    c for c in captured["commands"]
                    if c.startswith("process launch")
                )
                m = re.search(r'-o "([^"]+)" -e "([^"]+)"', launch)
                out_path, err_path = m.group(1), m.group(2)
                # The inferior writes to the redirect stubs; LLDB's
                # own transcript is result.stdout.
                Path(out_path).write_text("inferior said hello\n")
                Path(err_path).write_text(stderr_text)
                captured["stubs"] = (Path(out_path), Path(err_path))
                return MagicMock(
                    stdout="(lldb) process launch\nProcess 1 stopped\n",
                    stderr="", returncode=0,
                )

            with patch.object(
                CrashAnalyser, "_write_debugger_script",
                side_effect=fake_write_script,
            ), patch(
                "packages.binary_analysis.crash_analyser._sandbox_run",
                side_effect=fake_sandbox_run,
            ):
                output = analyser._run_lldb_analysis(input_file)
            return output, captured["stubs"]

    def test_inferior_stderr_read_into_analysis_output(self):
        output, (out_stub, err_stub) = (
            self._run_lldb_with_inferior_stderr(ASAN_REPORT))
        # LLDB's own transcript is still there...
        self.assertIn("Process 1 stopped", output)
        # ...and the inferior's streams now ride along, labelled.
        self.assertIn("=== inferior stdout ===", output)
        self.assertIn("inferior said hello", output)
        self.assertIn("=== inferior stderr ===", output)
        self.assertIn("AddressSanitizer: heap-buffer-overflow", output)
        # Cleanup contract unchanged: the stubs are still removed.
        self.assertFalse(out_stub.exists())
        self.assertFalse(err_stub.exists())

    def test_inferior_read_is_size_capped(self):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            stub = Path(td) / "stub"
            stub.write_text("x" * (CrashAnalyser._INFERIOR_OUTPUT_CAP + 500))
            fd = os.open(str(stub), os.O_RDONLY)
            try:
                text = CrashAnalyser._read_inferior_capped(
                    fd, CrashAnalyser._INFERIOR_OUTPUT_CAP)
            finally:
                os.close(fd)
            self.assertEqual(len(text), CrashAnalyser._INFERIOR_OUTPUT_CAP)
        # Unset stub fd degrades to empty, never raises.
        self.assertEqual(CrashAnalyser._read_inferior_capped(None, 10), "")

    def test_inferior_read_ignores_swapped_stub_path(self):
        """The attacker binary runs between stub creation and the
        read-back: a symlink swapped in at the stub name must never
        route the read — the kept fd stays bound to the original
        inode, so a swap yields the original (empty) content."""
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            stub = Path(td) / "stub"
            stub.write_text("")
            fd = os.open(str(stub), os.O_RDONLY)
            try:
                secret = Path(td) / "host-secret"
                secret.write_text("root:hash:0:0\n")
                stub.unlink()
                stub.symlink_to(secret)
                text = CrashAnalyser._read_inferior_capped(fd, 4096)
            finally:
                os.close(fd)
            self.assertEqual(text, "")

    def _wired_analyser(self, debugger_output: str) -> CrashAnalyser:
        analyser = _bare_analyser()
        analyser.binary = Path("/nonexistent/bin")
        analyser._debugger = "gdb"
        analyser._get_binary_info = lambda: {}
        analyser._detect_asan_binary = lambda: False
        analyser._run_gdb_analysis = lambda input_file: debugger_output
        analyser._get_disassembly = lambda addr: ""
        analyser._get_memory_layout_info = lambda: {}
        analyser._detect_environmental_crash = lambda ctx: {}
        analyser._analyze_memory_regions = lambda ctx: {}
        return analyser

    def test_analyse_crash_parses_asan_from_debugger_output(self):
        """ASan text arriving via the debugger path must reach the
        analysis record (binary_info.asan_output + crash_type)."""
        analyser = self._wired_analyser("(gdb) run\n" + ASAN_REPORT)
        context = analyser.analyse_crash(
            "c1", Path("/nonexistent/input"), "06")
        self.assertIn("AddressSanitizer", context.binary_info["asan_output"])
        self.assertEqual(context.crash_type, "heap_buffer_overflow")
        self.assertIn("parse_record", context.stack_trace)

    def test_direct_asan_run_takes_precedence(self):
        """When the dedicated ASan re-run already captured a report,
        the debugger-path text must not overwrite it."""
        analyser = self._wired_analyser("(gdb) run\n" + ASAN_REPORT)
        analyser._detect_asan_binary = lambda: True
        direct_report = ASAN_REPORT.replace(
            "heap-buffer-overflow", "use-after-free")
        analyser._run_asan_analysis = lambda input_file: direct_report
        context = analyser.analyse_crash(
            "c1", Path("/nonexistent/input"), "06")
        self.assertEqual(context.crash_type, "use_after_free")
        self.assertIn(
            "use-after-free", context.binary_info["asan_output"])


if __name__ == "__main__":
    unittest.main()
