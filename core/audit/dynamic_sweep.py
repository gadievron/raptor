"""Dynamic validation during audit review.

When the review loop identifies a finding without tool confirmation,
compile a test harness and run it with sanitisers. The result (crash,
sanitiser report, clean exit) becomes evidence in the same review
cycle (Cap 6).

Gate: only triggered for status=finding with evidence_tool not already
"dynamic". Expected cost: <5% of reviewed functions produce findings,
so <5% trigger dynamic validation.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.run.workdir import exec_workdir

logger = logging.getLogger(__name__)

_HARNESS_TIMEOUT_S = 10
_COMPILE_TIMEOUT_S = 15
_SANITIZER_FLAGS = "-fsanitize=address,undefined -fno-omit-frame-pointer -g"


@dataclass
class DynamicSweepResult:
    """Result of running a dynamic test harness.

    ``evidence_strength`` vocabulary (verdict-integrity contract):

    * ``"sanitizer"`` — a sanitizer report on STDERR anchored by a
      signal-grade death (``abort_on_error=1`` + ``handle_segv=0``
      make a genuine report terminate in a force-delivered fault even
      though the harness runs as the sandbox pid-namespace init, where
      ``raise(SIGABRT)`` self-signals are discarded — see
      ``_get_safe_env``). Confirms.
    * ``"crash"`` — the harness died by a REAL signal: the parent's own
      waitpid saw WIFSIGNALED (``signal_provenance == "waitstatus"``,
      see core/sandbox/observe.py). Confirms.
    * ``"exception"`` — the harness observed an in-process exception or
      a plain nonzero exit. Idiomatic target code raises RuntimeError
      on garbage input, and hostile target code (the harness IMPORTS
      AND CALLS the target's own function) mints this shape at will —
      it is a review hint, never mechanical confirmation.
    * ``"inconclusive"`` — nothing ran / nothing observed.

    Known residual (documented judgment): the harness executes target
    code in-process, so a deliberately hostile function can still
    self-deliver a genuine crash signal (``kill(getpid(), SIGSEGV)``).
    The signal-grade bar removes the exception-grade FP-amplifier and
    the exit-code/stdout forgery lanes; in-process self-signaling is
    inherent to this harness shape.
    """

    compiled: bool
    ran: bool
    crashed: bool
    sanitizer_output: str | None
    exit_code: int
    evidence_strength: str
    duration_s: float


def should_run_dynamic(
    outcome: Any,
    config: Any,
) -> bool:
    """Gate: should we run dynamic validation for this finding?"""
    if not getattr(config, "dynamic_validation", False):
        return False

    status = getattr(outcome, "status", "")
    if status != "finding":
        return False

    evidence_tool = getattr(outcome, "evidence_tool", "")
    if evidence_tool and evidence_tool.startswith("dynamic"):
        return False

    file_path = getattr(outcome, "file", "")
    if not file_path:
        return False

    return _is_compilable_language(file_path)


def run_dynamic_sweep(
    outcome: Any,
    ctx: dict[str, Any],
    config: Any,
) -> DynamicSweepResult | None:
    """Run a dynamic test for a finding.

    Generates a harness, compiles with sanitisers, runs in sandbox,
    and returns the result.
    """
    start = time.monotonic()
    file_path = getattr(outcome, "file", "")
    source = ctx.get("source", "")

    if not source or not file_path:
        return None

    target_path = getattr(config, "target_path", None)
    if target_path is None:
        return None

    if file_path.endswith((".c", ".h", ".cpp", ".cc", ".cxx")):
        return _run_c_harness(outcome, ctx, config, start)
    if file_path.endswith(".py"):
        return _run_python_harness(outcome, ctx, config, start)

    return None


def generate_c_harness(
    outcome: Any,
    ctx: dict[str, Any],
) -> str:
    """Generate a C test harness for a finding."""
    function_name = getattr(outcome, "function", "unknown")
    hypothesis = getattr(outcome, "hypothesis", "")
    source = ctx.get("source", "")
    file_path = getattr(outcome, "file", "")

    if not _is_valid_identifier(function_name):
        return ""

    review = getattr(outcome, "review_result", None) or {}
    cwe = review.get("cwe_class", "") or review.get("cwe", "")

    if _is_buffer_overflow(cwe, hypothesis):
        return _harness_buffer_overflow(function_name, source, file_path)
    if _is_format_string(cwe, hypothesis):
        return _harness_format_string(function_name, source, file_path)
    if _is_use_after_free(cwe, hypothesis):
        return _harness_use_after_free(function_name, source, file_path)
    if _is_null_deref(cwe, hypothesis):
        return _harness_null_deref(function_name, source, file_path)

    return _harness_generic(function_name, source, file_path)


def generate_python_harness(
    outcome: Any,
    ctx: dict[str, Any],
) -> str:
    """Generate a Python test script for a finding."""
    function_name = getattr(outcome, "function", "unknown")
    hypothesis = getattr(outcome, "hypothesis", "")
    file_path = getattr(outcome, "file", "")

    if not _is_valid_identifier(function_name):
        return ""

    module = file_path.removesuffix(".py").replace("/", ".")
    if not all(_is_valid_identifier(part) for part in module.split(".")):
        return ""

    return (
        f"import sys\n"
        f"import traceback\n"
        f"\n"
        f"try:\n"
        f"    from {module} import {function_name}\n"
        f"except ImportError:\n"
        f"    print('IMPORT_FAILED')\n"
        f"    sys.exit(2)\n"
        f"\n"
        f"# Hypothesis: {hypothesis[:100]}\n"
        f"test_inputs = [\n"
        f"    None,\n"
        f"    '',\n"
        f"    'A' * 10000,\n"
        f"    b'\\x00' * 256,\n"
        f"    -1,\n"
        f"    0,\n"
        f"    2**31,\n"
        f"    {{'__class__': 'exploit'}},\n"
        f"]\n"
        f"\n"
        f"for inp in test_inputs:\n"
        f"    try:\n"
        f"        {function_name}(inp)\n"
        f"    except (TypeError, ValueError, AttributeError):\n"
        f"        pass\n"
        f"    except Exception as e:\n"
        f"        print(f'UNEXPECTED_EXCEPTION: {{type(e).__name__}}: {{e}}')\n"
        f"        traceback.print_exc()\n"
        f"\n"
        f"print('HARNESS_COMPLETE')\n"
    )


def _sandbox_unavailable_result(
    exc: BaseException, *, compiled: bool, start: float,
) -> DynamicSweepResult:
    """The harness (or its compile) could not run because sandbox
    isolation failed to engage. LLM-derived code must never execute
    unsandboxed, so the dynamic channel is skipped: the finding keeps
    whatever static evidence it had, the operator sees why in the log,
    and the result reads as inconclusive rather than as tested.
    """
    logger.warning(
        "dynamic_sweep: sandbox isolation could not engage — skipping "
        "dynamic validation for this finding (never runs LLM-generated "
        "harness code unsandboxed): %s", exc,
    )
    return DynamicSweepResult(
        compiled=compiled, ran=False, crashed=False,
        sanitizer_output=f"sandbox unavailable: {exc}"[:500],
        exit_code=-1,
        evidence_strength="inconclusive",
        duration_s=time.monotonic() - start,
    )


def _detect_compiler(target_path: Path, file_path: str) -> str:
    """Detect the C/C++ compiler for the target project.

    Uses BuildDetector to scan the target for C++ source files and
    select g++ when needed.  Falls back to choosing by file extension,
    then to plain gcc.
    """
    try:
        from core.build.build_detector import BuildDetector
        detector = BuildDetector(target_path)
        _, compiler, _, _ = detector._detect_build_params("cpp")
        if compiler:
            return compiler
    except (OSError, ValueError):
        # Best-effort detection: tree walk / build-file parse failures
        # fall back to extension-based compiler choice below.
        pass
    # Fallback: choose compiler based on the file being compiled.
    if file_path.endswith((".cpp", ".cc", ".cxx")):
        return "g++"
    return "gcc"


def _run_c_harness(
    outcome: Any,
    ctx: dict[str, Any],
    config: Any,
    start: float,
) -> DynamicSweepResult | None:
    """Compile and run a C test harness."""
    harness_code = generate_c_harness(outcome, ctx)
    if not harness_code:
        return None

    raw_target = getattr(config, "target_path", None)
    if not raw_target:
        logger.warning("dynamic_sweep: target_path not set, skipping C harness")
        return None
    target_path = Path(raw_target)
    file_path = getattr(outcome, "file", "")
    compiler = _detect_compiler(target_path, file_path)

    safe_env = _get_safe_env()

    # Harness code (and the harness binary compiled from it) is
    # LLM-derived — run_untrusted() for both steps: restrict_reads +
    # fake home + strict env + namespace network block, with target
    # readable (compile needs -I{target}) and the scratch dir writable.
    # There is deliberately NO unsandboxed fallback: when isolation
    # cannot engage, the dynamic channel is skipped with a loud
    # warning (SandboxSetupError caught BY NAME below — the documented
    # exception to its except-Exception-proof design) rather than
    # executing LLM-generated code on the bare host.
    from core.sandbox import SandboxSetupError, run_untrusted

    with tempfile.TemporaryDirectory(
            prefix="raptor_dyn_", dir=exec_workdir()) as tmpdir:
        harness_path = Path(tmpdir) / "harness.c"
        binary_path = Path(tmpdir) / "harness"
        harness_path.write_text(harness_code)

        compile_cmd = [
            compiler, str(harness_path),
            "-o", str(binary_path),
            f"-I{target_path}",
        ] + _SANITIZER_FLAGS.split()

        try:
            compile_result = run_untrusted(
                compile_cmd,
                target=str(target_path),
                output=tmpdir,
                cwd=tmpdir,
                env=safe_env,
                caller_label="dynamic_sweep_compile",
                capture_output=True, text=True,
                timeout=_COMPILE_TIMEOUT_S,
            )
        except SandboxSetupError as e:
            return _sandbox_unavailable_result(e, compiled=False, start=start)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return DynamicSweepResult(
                compiled=False, ran=False, crashed=False,
                sanitizer_output=None, exit_code=-1,
                evidence_strength="inconclusive",
                duration_s=time.monotonic() - start,
            )

        if compile_result.returncode != 0:
            return DynamicSweepResult(
                compiled=False, ran=False, crashed=False,
                sanitizer_output=compile_result.stderr[:500],
                exit_code=compile_result.returncode,
                evidence_strength="inconclusive",
                duration_s=time.monotonic() - start,
            )

        try:
            try:
                run_result = run_untrusted(
                    [str(binary_path)],
                    target=str(target_path),
                    output=tmpdir,
                    cwd=tmpdir,
                    env=safe_env,
                    caller_label="dynamic_sweep_harness",
                    capture_output=True, text=True,
                    timeout=_HARNESS_TIMEOUT_S,
                )
            except SandboxSetupError as e:
                return _sandbox_unavailable_result(
                    e, compiled=True, start=start)
        except subprocess.TimeoutExpired:
            return DynamicSweepResult(
                compiled=True, ran=True, crashed=False,
                sanitizer_output="timeout",
                exit_code=-1,
                evidence_strength="inconclusive",
                duration_s=time.monotonic() - start,
            )

        spawn_failure = _spawn_failure_reason(run_result)
        if spawn_failure is not None:
            return _spawn_failure_result(spawn_failure, run_result, start)

        combined_output = run_result.stdout + run_result.stderr
        crashed = run_result.returncode != 0
        # Sanitizer scan reads STDERR ONLY: sanitizers write their
        # reports to stderr, while target stdout is fully attacker-
        # controlled prose (a puts("...use-after-free...") used to mint
        # sanitizer-grade evidence).
        sanitizer_hit = _has_sanitizer_output(run_result.stderr)
        signal_grade = _signal_grade_death(run_result)

        # Confirming strengths require a signal-grade death: the env
        # sets abort_on_error=1 + handle_segv=0 for BOTH sanitizer
        # families (see _get_safe_env — halt_on_error alone merely
        # exits 1), so a GENUINE report is followed by a force-
        # delivered fatal signal; a printed fake from a cleanly-
        # exiting (or exit(1)-ing) process is not. Bare nonzero
        # exits — previously "crash" — are exception-grade.
        if sanitizer_hit and signal_grade:
            strength = "sanitizer"
        elif signal_grade:
            strength = "crash"
        elif crashed or sanitizer_hit:
            strength = "exception"
        else:
            strength = "inconclusive"

        return DynamicSweepResult(
            compiled=True,
            ran=True,
            crashed=crashed,
            sanitizer_output=(
                combined_output[:2000] if sanitizer_hit or crashed else None
            ),
            exit_code=run_result.returncode,
            evidence_strength=strength,
            duration_s=time.monotonic() - start,
        )


def _run_python_harness(
    outcome: Any,
    ctx: dict[str, Any],
    config: Any,
    start: float,
) -> DynamicSweepResult | None:
    """Run a Python test harness."""
    harness_code = generate_python_harness(outcome, ctx)
    if not harness_code:
        return None
    raw_target = getattr(config, "target_path", None)
    if not raw_target:
        logger.warning("dynamic_sweep: target_path not set, skipping Python harness")
        return None
    target_path = Path(raw_target)

    safe_env = _get_safe_env()

    # Same containment rationale as the C harness (see _run_c_harness).
    # The target path rides in a sys.path prelude rather than
    # PYTHONPATH: run_untrusted()'s strict_env strips PYTHONPATH (it's
    # in DANGEROUS_ENV_VARS), and the prelude gives identical import
    # behaviour without weakening that contract.
    from core.sandbox import SandboxSetupError, run_untrusted

    with tempfile.TemporaryDirectory(
            prefix="raptor_dyn_", dir=exec_workdir()) as tmpdir:
        harness_path = Path(tmpdir) / "harness.py"
        harness_path.write_text(
            f"import sys\nsys.path.insert(0, {str(target_path)!r})\n"
            + harness_code
        )

        try:
            try:
                run_result = run_untrusted(
                    ["python3", str(harness_path)],
                    target=str(target_path),
                    output=tmpdir,
                    cwd=tmpdir,
                    env=safe_env,
                    caller_label="dynamic_sweep_python_harness",
                    capture_output=True, text=True,
                    timeout=_HARNESS_TIMEOUT_S,
                )
            except SandboxSetupError as e:
                return _sandbox_unavailable_result(
                    e, compiled=True, start=start)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return DynamicSweepResult(
                compiled=True, ran=False, crashed=False,
                sanitizer_output=None, exit_code=-1,
                evidence_strength="inconclusive",
                duration_s=time.monotonic() - start,
            )

        spawn_failure = _spawn_failure_reason(run_result)
        if spawn_failure is not None:
            return _spawn_failure_result(spawn_failure, run_result, start)

        combined_output = run_result.stdout + run_result.stderr
        crashed = run_result.returncode != 0

        if "IMPORT_FAILED" in combined_output:
            return DynamicSweepResult(
                compiled=True, ran=False, crashed=False,
                sanitizer_output=None, exit_code=2,
                evidence_strength="inconclusive",
                duration_s=time.monotonic() - start,
            )

        has_unexpected = "UNEXPECTED_EXCEPTION" in combined_output

        # Python lane, verdict-integrity contract: only an interpreter-
        # fatal termination — a real signal the parent's waitpid saw
        # (SIGSEGV in a C extension, faulthandler-visible aborts) — is
        # crash evidence. An in-harness Python exception is what
        # idiomatic code does on garbage input AND what a hostile
        # target function (the harness imports and calls it) raises at
        # will; both used to mint "crash" → dynamic:crash → CONFIRMED.
        if _signal_grade_death(run_result):
            strength = "crash"
        elif has_unexpected or crashed:
            strength = "exception"
        else:
            strength = "inconclusive"

        return DynamicSweepResult(
            compiled=True,
            ran=True,
            crashed=crashed,
            sanitizer_output=(
                combined_output[:2000] if crashed or has_unexpected else None
            ),
            exit_code=run_result.returncode,
            evidence_strength=strength,
            duration_s=time.monotonic() - start,
        )


# Exit codes the spawn layers re-encode a failed exec of the target as
# (shell/util-linux convention, shared by the in-sandbox exec lane
# and the Landlock-only retry): 127 file not found, 126 found but not
# executable, 125 catch-all exec errno.
_EXEC_FAILURE_RETURNCODES = frozenset({125, 126, 127})


def _stderr_is_sandbox_diagnostic_only(stderr: object) -> bool:
    """True iff *stderr* is empty or carries only the sandbox layer's
    own pre-exec diagnostics: lines prefixed ``sandbox:`` or the spawn
    child's ``sandbox child failure:`` block — both written before the
    target's first instruction."""
    if not stderr:
        return True
    text = (stderr.decode("utf-8", errors="replace")
            if isinstance(stderr, bytes) else str(stderr))
    lines = [line for line in text.splitlines() if line.strip()]
    if lines and lines[0].startswith("sandbox child failure:"):
        return True
    return all(line.startswith("sandbox:") for line in lines)


def _spawn_failure_reason(run_result: Any) -> str | None:
    """Classify a harness run as a spawn failure — the child never
    successfully exec'd the harness — or ``None`` (genuine outcome).

    A spawn failure is not a dynamic observation: the call sites route
    it to ``"inconclusive"``, never ``"exception"`` — the exception
    stamp demotes a finding to suspicious, and a harness that never
    executed must carry no evidence weight in either direction.

    Precise signal first: a ``_setup_status`` category tuple from the
    exec-status pipe means setup or exec failed before the target ran.
    Otherwise the bounded heuristic: the spawn lanes re-encode a
    failed exec as a bare 125/126/127 exit, which is ambiguous with
    target code choosing those codes, so reclassification is limited
    to the pre-first-output window — any signal/sanitizer evidence or
    any output beyond the sandbox layer's own diagnostics disqualifies
    it (a failed exec happens before the target's first instruction).
    ``_setup_status is None`` (pipe EOF) does not veto the heuristic:
    the pipe reports failure best-effort only. Residual: a hostile
    target exiting 125-127 with no output reads inconclusive — no new
    forgery power (it can already exit 0) and no demotion power.
    """
    status = getattr(run_result, "_setup_status", None)
    if status is not None:
        try:
            cat, why = status[0], status[1]
        except (TypeError, IndexError, KeyError):
            cat, why = "?", str(status)
        return f"sandbox setup/exec failure ({cat}: {why})"
    rc = getattr(run_result, "returncode", None)
    if rc not in _EXEC_FAILURE_RETURNCODES:
        return None
    info = getattr(run_result, "sandbox_info", None) or {}
    if info.get("signal") or info.get("sanitizer") or info.get("crashed"):
        return None  # it demonstrably ran/died — a genuine outcome
    if getattr(run_result, "stdout", None):
        return None  # produced output — it ran
    if not _stderr_is_sandbox_diagnostic_only(
            getattr(run_result, "stderr", None)):
        return None
    return (
        f"exit code {rc} with no output and no signal — exec-failure "
        f"shape (spawn layers re-encode a failed exec as 125/126/127)"
    )


def _spawn_failure_result(
    reason: str, run_result: Any, start: float,
) -> DynamicSweepResult:
    """Inconclusive result for a harness whose exec never happened."""
    logger.warning(
        "dynamic_sweep: harness did not execute — dynamic validation "
        "is inconclusive for this finding: %s", reason,
    )
    rc = run_result.returncode
    return DynamicSweepResult(
        compiled=True, ran=False, crashed=False,
        sanitizer_output=f"harness did not execute: {reason}"[:500],
        # Keep the int contract: on the precise _setup_status branch
        # the returncode is not load-bearing and may in principle be
        # unset.
        exit_code=rc if isinstance(rc, int) else -1,
        evidence_strength="inconclusive",
        duration_s=time.monotonic() - start,
    )


_IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def _is_valid_identifier(name: str) -> bool:
    """Return True when *name* is a safe C/Python identifier."""
    return bool(_IDENT_RE.match(name))


def _is_compilable_language(file_path: str) -> bool:
    """Check if the file is in a language we can compile/run."""
    return file_path.endswith((".c", ".h", ".cpp", ".cc", ".cxx", ".py"))


def _signal_grade_death(run_result: Any) -> bool:
    """True when the harness died by a REAL signal.

    Reads the sandbox layer's evidence tiering
    (``sandbox_info["signal_provenance"] == "waitstatus"`` — the
    parent's own waitpid saw WIFSIGNALED; see
    core/sandbox/observe.py). Exit-code shapes (128+sig) are
    deliberately NOT accepted: target code forges them with a single
    ``exit(139)`` / ``sys.exit(139)``. Falls back to the raw
    ``returncode < 0`` check when sandbox_info is absent (same kernel
    truth, unwrapped runners).

    Tier visibility, so operators are not surprised: spawn tiers that
    LAUNDER the target's signal into a 128+sig exit code before the
    parent's waitpid — the in-namespace pid-1 waiter on mount-ns runs
    and the no-namespace trampoline — can never satisfy this check,
    so the dynamic ``crash``/``sanitizer`` confirmed lanes are dark
    on those tiers (everything routes to exception-grade →
    suspicious). That is the fail-safe direction by design: an
    exit-code shape is exactly what a hostile target can mint, and
    the launder point sits where forged and genuine shapes are
    indistinguishable. Signal-grade evidence flows on tiers where the
    kernel's WIFSIGNALED reaches the parent unre-encoded.
    """
    info = getattr(run_result, "sandbox_info", None) or {}
    if info.get("signal_provenance") == "waitstatus" and info.get("crashed"):
        return True
    if info:
        return False
    try:
        return int(run_result.returncode) < 0
    except (TypeError, ValueError):
        return False


def _has_sanitizer_output(output: str) -> bool:
    """Check for ASan/UBSan/MSan markers in output."""
    markers = (
        "ERROR: AddressSanitizer",
        "ERROR: LeakSanitizer",
        "ERROR: MemorySanitizer",
        "runtime error:",
        "SUMMARY: AddressSanitizer",
        "SUMMARY: UndefinedBehaviorSanitizer",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "use-after-free",
        "double-free",
        "heap-use-after-free",
    )
    return any(m in output for m in markers)


_CWE_SPLIT_RE = re.compile(r'[\s,;/|]+')


def _cwe_tokens(cwe: str) -> set[str]:
    """Split a CWE string into exact tokens for membership tests."""
    return set(_CWE_SPLIT_RE.split(cwe.upper())) if cwe else set()


def _is_buffer_overflow(cwe: str, hypothesis: str) -> bool:
    tokens = _cwe_tokens(cwe)
    return (
        bool(tokens & {"CWE-120", "CWE-121", "CWE-122", "CWE-787"})
        or "buffer overflow" in hypothesis.lower()
        or "out of bounds" in hypothesis.lower()
    )


def _is_format_string(cwe: str, hypothesis: str) -> bool:
    return (
        "CWE-134" in _cwe_tokens(cwe)
        or "format string" in hypothesis.lower()
    )


def _is_use_after_free(cwe: str, hypothesis: str) -> bool:
    tokens = _cwe_tokens(cwe)
    return (
        bool(tokens & {"CWE-416", "CWE-415"})
        or "use after free" in hypothesis.lower()
        or "use-after-free" in hypothesis.lower()
        or "double free" in hypothesis.lower()
    )


def _is_null_deref(cwe: str, hypothesis: str) -> bool:
    return (
        "CWE-476" in _cwe_tokens(cwe)
        or "null" in hypothesis.lower()
    )


def _harness_buffer_overflow(func: str, _source: str, _file_path: str) -> str:
    # Syntactic probe only — does not link the target; compiled=False is the
    # expected result when the target's symbols are not self-contained.
    return (
        f'#include <string.h>\n'
        f'#include <stdlib.h>\n'
        f'#include <stdio.h>\n'
        f'\n'
        f'// Syntactic probe — does not link the target\n'
        f'// Hypothesis: buffer overflow in {func}\n'
        f'\n'
        f'int main(void) {{\n'
        f'    char small_buf[16];\n'
        f'    char large_input[4096];\n'
        f'    memset(large_input, \'A\', sizeof(large_input) - 1);\n'
        f'    large_input[sizeof(large_input) - 1] = \'\\0\';\n'
        f'\n'
        f'    // Attempt to trigger overflow\n'
        f'    {func}(small_buf, large_input);\n'
        f'    printf("HARNESS_COMPLETE\\n");\n'
        f'    return 0;\n'
        f'}}\n'
    )


def _harness_format_string(func: str, _source: str, _file_path: str) -> str:
    return (
        f'#include <stdio.h>\n'
        f'#include <stdlib.h>\n'
        f'\n'
        f'int main(void) {{\n'
        f'    const char *fmt = "%s%s%s%s%s%s%s%s%s%s";\n'
        f'    {func}(fmt);\n'
        f'    printf("HARNESS_COMPLETE\\n");\n'
        f'    return 0;\n'
        f'}}\n'
    )


def _harness_use_after_free(func: str, _source: str, _file_path: str) -> str:
    return (
        f'#include <stdlib.h>\n'
        f'#include <stdio.h>\n'
        f'#include <string.h>\n'
        f'\n'
        f'int main(void) {{\n'
        f'    char *p = malloc(64);\n'
        f'    if (!p) return 1;\n'
        f'    memset(p, \'A\', 64);\n'
        f'    free(p);\n'
        f'    // Use after free trigger point\n'
        f'    {func}(p);\n'
        f'    printf("HARNESS_COMPLETE\\n");\n'
        f'    return 0;\n'
        f'}}\n'
    )


def _harness_null_deref(func: str, _source: str, _file_path: str) -> str:
    return (
        f'#include <stdio.h>\n'
        f'#include <stdlib.h>\n'
        f'\n'
        f'int main(void) {{\n'
        f'    {func}(NULL);\n'
        f'    printf("HARNESS_COMPLETE\\n");\n'
        f'    return 0;\n'
        f'}}\n'
    )


def _harness_generic(_func: str, _source: str, _file_path: str) -> str:
    return (
        '#include <stdio.h>\n'
        '#include <stdlib.h>\n'
        '#include <string.h>\n'
        '\n'
        'int main(void) {\n'
        '    printf("HARNESS_COMPLETE\\n");\n'
        '    return 0;\n'
        '}\n'
    )


def _get_safe_env() -> dict[str, str]:
    """Get a sanitised environment for subprocess execution."""
    try:
        from core.config import RaptorConfig
        env = RaptorConfig.get_safe_env()
    except (ImportError, AttributeError):
        env = dict(os.environ)
        for key in ("TERMINAL", "EDITOR", "VISUAL", "BROWSER", "PAGER"):
            env.pop(key, None)
        # Degraded-fallback belt: this branch hands the child a
        # full-environ copy, so at minimum drop the credential-env
        # family (the canonical vocabulary is stdlib-only and imports
        # even where core.config cannot; guard anyway — this fallback
        # exists precisely for broken-install conditions).
        try:
            from core.security.credential_env import (
                CREDENTIAL_ENV_FAMILY,
                is_credential_env_pattern_member,
            )
        except ImportError:
            pass
        else:
            for key in CREDENTIAL_ENV_FAMILY:
                env.pop(key, None)
            # Pattern members (CARGO_TARGET_<triple>_RUNNER-shaped
            # names) have no enumerable spelling — exact-name pops
            # cannot reach them, so sweep the survivors by predicate.
            for key in [k for k in env if is_credential_env_pattern_member(k)]:
                env.pop(key)
    env["ASAN_OPTIONS"] = "detect_leaks=1:abort_on_error=1:handle_segv=0"
    # abort_on_error=1 is load-bearing for the signal-grade sanitizer
    # classification: halt_on_error alone makes UBSan STOP (exit 1,
    # unsignaled) — abort_on_error makes a genuine report die trying
    # to deliver a signal.
    #
    # handle_segv=0 is load-bearing for HOW that death reaches the
    # parent's waitpid. The harness runs as the init process of the
    # sandbox's pid namespace, and the kernel discards default-action
    # self-signals sent to a namespace init — abort()'s raise(SIGABRT)
    # never delivers. glibc's abort() then escalates to its trap
    # instruction, a hardware fault the kernel force-delivers even to
    # pid 1: SIGSEGV, waitstatus-visible, signal-grade. With ASan's
    # default handle_segv=1 that escalation fault is INTERCEPTED
    # in-process instead: ASan prints a "SEGV" report, its own die
    # path re-enters abort(), and glibc's staged abort falls through
    # to its terminal _exit(127) — an exit-code death the signal-grade
    # bar rightly refuses (observed: genuine UBSan CWE-190 hits
    # classifying "exception" with exit 127 on glibc 2.39, where the
    # trap stage runs with signals deliverable; glibc >= 2.40 blocks
    # all signals before the trap, so the same interception never
    # happens and the fault force-kills either way). Disabling the
    # sanitizer's SEGV interception makes the escalation fault the
    # deterministic terminator on every glibc: report on stderr +
    # WIFSIGNALED at the parent = "sanitizer". Cost: a wild SIGSEGV
    # in target code loses ASan's decoded SEGV report and classifies
    # signal-only "crash" — the stronger, still-confirming stamp.
    env["UBSAN_OPTIONS"] = (
        "print_stacktrace=1:halt_on_error=1:abort_on_error=1:handle_segv=0"
    )
    return env
