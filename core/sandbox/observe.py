"""Post-run result interpretation and enforcement detection.

Two functions:
- `_interpret_result()`: reads the subprocess result (signal, stderr) and
  attaches a structured `sandbox_info` dict with crash / resource-exceeded /
  sanitizer state.
- `_check_blocked()`: scans stderr for patterns that indicate a sandbox
  layer fired, enriches `sandbox_info["blocked"]` accordingly. Each
  category is only reported when its layer is actually engaged for the
  call, so we don't claim enforcement on an unsandboxed run.

Nothing here is on the hot path of subprocess execution; both functions
run in the parent after the child has exited.
"""

import logging
import re
import signal
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Truncate the command in single-line log messages so scan-loop output
# doesn't get flooded with long argv lists; full argv is still visible
# to the subprocess itself and to post-mortem tools that see the real
# arguments on the process.
_CMD_DISPLAY_MAX_ARGS = 3

# Patterns in stderr that signal sandbox enforcement — the process tried
# something that was blocked
_BLOCKED_PATTERNS = [
    # Network blocked (namespace or Landlock)
    ("network", "Network is unreachable"),
    ("network", "Connection refused"),
    ("network", "Could not resolve host"),
    ("network", "curl: (7)"),
    ("network", "curl: (6)"),
    ("network", "fatal: unable to access"),
    ("network", "ConnectionError"),
    ("network", "urlopen error"),
    # Landlock filesystem restriction — each pattern is a pre-filter; the
    # real gating happens via landlock_engaged + path-within-writable checks
    # in _check_blocked. Landlock returns EACCES ("Permission denied"), not
    # EPERM — don't add "Operation not permitted" here or we'll fire on
    # unrelated capability checks (ptrace, mount, etc.).
    ("write", "Read-only file system"),
    ("write", "cannot create"),      # sh/bash: "cannot create /path: Permission denied"
    ("write", "PermissionError"),    # Python:  "PermissionError: [Errno 13] Permission denied: '/path'"
    # Seccomp returns EPERM ("Operation not permitted") for blocked syscalls.
    # This is inherently ambiguous — EPERM also comes from legitimate capability
    # checks. The _check_blocked function fires the seccomp hint only when
    # seccomp is actually engaged for the call AND the returncode is non-zero.
    ("seccomp", "Operation not permitted"),
]


def _interpret_result(result: subprocess.CompletedProcess, cmd_display: str) -> None:
    """Interpret process termination and attach sandbox_info to the result.

    Adds result.sandbox_info dict with:
    - signal: signal name if killed by signal (SIGSEGV, SIGABRT, etc.)
    - signal_num: signal number
    - crashed: True iff the process did not exit normally (killed by a
      crash signal, OR died with non-zero exit while a sanitizer fired).
      Sanitizer reports with rc==0 (halt_on_error=0) set `sanitizer` but
      leave `crashed` unset.
    - sanitizer: "asan"|"ubsan"|"msan"|"tsan" when stderr contains a
      sanitizer report (independent of `crashed`).
    - resource_exceeded: True if killed by resource limit (SIGXCPU, SIGXFSZ)
    - evidence: factual summary for /validate (joined string)
    - evidence_items: list of individual evidence items (only when >1)
    - blocked: list of sandbox-enforcement events (added by _check_blocked
      after _interpret_result runs; present only when sandbox layers fired)
    """
    info = {"crashed": False, "resource_exceeded": False}
    evidence_items = []

    try:
        rc = int(result.returncode)
    except (TypeError, ValueError):
        result.sandbox_info = info  # type: ignore[attr-defined]
        return

    # Two routes to "died by signal":
    #   1. subprocess.run convention: rc < 0, where sig = -rc.
    #      Happens when the direct child of Popen dies by signal and
    #      the parent's waitpid sees WIFSIGNALED.
    #   2. 128+sig convention: rc in [129, 128 + NSIG). Used when
    #      something between Popen and the target (e.g. the pid-1
    #      shim at libexec/raptor-pid1-shim) caught the signal via
    #      waitpid + WIFSIGNALED and exited with 128+WTERMSIG because
    #      it couldn't re-raise the signal on itself (the pid-ns
    #      filter blocks pid-1 from raise()ing signals without an
    #      installed handler — the very filter the shim exists to
    #      keep AWAY from the target). Standard unix shell
    #      convention; bash's $? uses it too. Decode identically.
    # SIGKILL (9) via 128+9=137 is a genuine ambiguity vs. a program
    # that legitimately exits 137 — accepted as a negligible risk,
    # the 128+sig range is almost never an honest exit code.
    sig_num = 0
    if rc < 0:
        sig_num = -rc
    elif 128 < rc < 128 + signal.NSIG:
        sig_num = rc - 128

    if sig_num:
        try:
            sig_name = signal.Signals(sig_num).name
        except (ValueError, AttributeError):
            sig_name = f"SIG{sig_num}"

        info["signal"] = sig_name
        info["signal_num"] = sig_num

        crash_signals = {
            signal.SIGSEGV, signal.SIGABRT, signal.SIGBUS,
            signal.SIGFPE, signal.SIGILL,
        }
        resource_signals = set()
        if hasattr(signal, "SIGXCPU"):
            resource_signals.add(signal.SIGXCPU)
        if hasattr(signal, "SIGXFSZ"):
            resource_signals.add(signal.SIGXFSZ)

        # SIGSYS is the seccomp kill signal. The kernel sends it when a
        # seccomp filter uses SCMP_ACT_KILL / KILL_PROCESS — for us this
        # means an unregistered-architecture syscall (our BADARCH filter)
        # or an explicit KILL rule. Flag it so operators can distinguish
        # "sandbox did its job" from "kernel did something weird".
        seccomp_signals = set()
        if hasattr(signal, "SIGSYS"):
            seccomp_signals.add(signal.SIGSYS)

        if sig_num in {s.value for s in crash_signals}:
            info["crashed"] = True
            evidence_items.append(f"Process crashed with {sig_name}")
            logger.info(f"Sandbox: {cmd_display} killed by {sig_name} (crash)")
        elif sig_num in {s.value for s in resource_signals}:
            info["resource_exceeded"] = True
            if hasattr(signal, "SIGXCPU") and sig_num == signal.SIGXCPU:
                evidence_items.append(f"Process killed by {sig_name} — CPU time exhausted")
            elif hasattr(signal, "SIGXFSZ") and sig_num == signal.SIGXFSZ:
                evidence_items.append(f"Process killed by {sig_name} — file size limit exceeded")
            else:
                evidence_items.append(f"Process killed by {sig_name} — resource limit exceeded")
            logger.warning(f"Sandbox: {cmd_display} killed by {sig_name} (resource limit)")
        elif sig_num in {s.value for s in seccomp_signals}:
            info["seccomp_killed"] = True
            evidence_items.append(
                "Process killed by SIGSYS — seccomp blocked a syscall "
                "(likely 32-bit-compat int 0x80 or an explicit KILL rule)"
            )
            logger.info(f"Sandbox: {cmd_display} killed by SIGSYS (seccomp)")
        else:
            evidence_items.append(f"Process killed by {sig_name}")
            logger.debug(f"Sandbox: {cmd_display} killed by {sig_name}")

    # Check stderr for sanitizer reports (ASAN, UBSAN, MSAN, TSAN).
    # `crashed` strictly means "process did not exit normally" — we only set
    # it here when rc indicates abnormal termination. ASAN with
    # halt_on_error=0 reports and continues; such runs set `sanitizer` but
    # leave `crashed` unchanged. Consumers wanting "bug detected" should
    # read info.get("sanitizer") OR info.get("crashed").
    # Handle both text-mode (str) and binary-mode (bytes) stderr — the
    # latter when callers pass text=False. Decode defensively so sanitizer
    # detection isn't silently skipped for binary callers.
    raw_stderr = result.stderr
    if isinstance(raw_stderr, bytes):
        stderr_text = raw_stderr.decode("utf-8", errors="replace")
    elif isinstance(raw_stderr, str):
        stderr_text = raw_stderr
    else:
        stderr_text = ""
    died_abnormally = rc != 0
    if stderr_text:
        if "AddressSanitizer" in stderr_text:
            info["sanitizer"] = "asan"
            asan_match = re.search(r"ERROR: AddressSanitizer: (\S+)", stderr_text)
            # bug_type comes from an ASAN error line in stderr, which a
            # malicious binary can forge (ASAN prints attacker-influenced
            # symbols / addresses and nothing stops the target binary
            # printing a fake `ERROR: AddressSanitizer: \x1b[31m…` to
            # stderr directly). `(\S+)` captures any non-whitespace run,
            # including ESC sequences. Without sanitisation, the
            # logger.info below would inject terminal escapes into any
            # operator watching live output.
            from core.security.log_sanitisation import escape_nonprintable
            bug_type = escape_nonprintable(
                asan_match.group(1) if asan_match else "unknown"
            )
            evidence_items.append(f"AddressSanitizer: {bug_type}")
            if died_abnormally:
                info["crashed"] = True
            logger.info(f"Sandbox: {cmd_display} — ASAN detected {bug_type}")
        elif "UndefinedBehaviorSanitizer" in stderr_text:
            info["sanitizer"] = "ubsan"
            evidence_items.append("UndefinedBehaviorSanitizer triggered")
            logger.info(f"Sandbox: {cmd_display} — UBSAN triggered")
        elif "MemorySanitizer" in stderr_text:
            info["sanitizer"] = "msan"
            evidence_items.append("MemorySanitizer: use of uninitialised memory")
            if died_abnormally:
                info["crashed"] = True
            logger.info(f"Sandbox: {cmd_display} — MSAN triggered")
        elif "ThreadSanitizer" in stderr_text:
            info["sanitizer"] = "tsan"
            evidence_items.append("ThreadSanitizer: data race detected")
            logger.info(f"Sandbox: {cmd_display} — TSAN triggered")

    # Build evidence: flat string for simple consumers, list for structured access
    if evidence_items:
        info["evidence"] = " — ".join(evidence_items)
        if len(evidence_items) > 1:
            info["evidence_items"] = evidence_items

    # Attach to result for consumers to read
    result.sandbox_info = info  # type: ignore[attr-defined]


def _path_within(path: str, allowed: list) -> bool:
    """Return True if `path` is inside any of the `allowed` directories.

    Conservative: returns False on relative paths or any parsing failure so
    callers can treat the result as "definitely within an allowed dir".
    """
    if not path or not allowed:
        return False
    try:
        p = Path(path).resolve(strict=False)
    except (OSError, ValueError):
        return False
    if not p.is_absolute():
        return False
    for a in allowed:
        try:
            ap = Path(a).resolve(strict=False)
            if p == ap or ap in p.parents:
                return True
        except (OSError, ValueError):
            continue
    return False


def _check_blocked(stderr: str, cmd_display: str, returncode: int = 0,
                   sandbox_info: dict = None,
                   network_engaged: bool = False,
                   landlock_engaged: bool = False,
                   writable_paths: list = None,
                   seccomp_engaged: bool = False,
                   seccomp_profile: str = None) -> None:
    """Enrich sandbox_info when stderr shows evidence of sandbox enforcement.

    Only fires for an enforcement layer that is actually engaged this call:
    network patterns require `network_engaged`, write patterns require
    `landlock_engaged`. Writes inside `writable_paths` are always normal
    filesystem permission errors, never Landlock.

    Wording is factual: we log what was observed, not a verdict on intent.
    A single stderr cannot distinguish Landlock EACCES from ordinary EACCES,
    so we do not claim maliciousness.
    """
    if not stderr:
        return
    reported = set()
    blocked_evidence = []
    for category, pattern in _BLOCKED_PATTERNS:
        if pattern not in stderr or category in reported:
            continue
        if category == "network" and not network_engaged:
            continue
        if category == "write":
            # Write blocks need "Permission denied" alongside the pattern to
            # filter noise like "cannot create output file: No space left".
            if "Permission denied" not in stderr:
                continue
            if not landlock_engaged:
                continue
        if category == "seccomp":
            # Seccomp returns EPERM ("Operation not permitted"). The pattern
            # is inherently noisy — EPERM also comes from legitimate
            # capability checks (ptrace on protected process, mount without
            # privs, etc.). Fire only when seccomp is engaged AND the
            # process actually failed (rc != 0) AND the text looks like a
            # syscall-level message (not a higher-level "Not permitted" from
            # a CLI tool's own error).
            if not seccomp_engaged or returncode == 0:
                continue

        # For write blocks, try to isolate the offending path. If it falls
        # inside writable_paths it cannot be Landlock — skip.
        attempted_path = None
        if category == "write":
            # Exclude whitespace control chars (\r, \n, \t) from the capture
            # — CRLF line endings, tab-separated error formats, etc. would
            # otherwise embed control bytes in sandbox_info["blocked"] and
            # log lines, a control-char injection surface.
            m = re.search(r"(?:cannot create|Permission denied:?|open:)\s+'?([^':\r\n\t]+)", stderr)
            if m:
                # Strip any remaining control chars defensively. Paths
                # should not contain them; stderr from untrusted tools may.
                raw = m.group(1).strip().rstrip("'")
                attempted_path = "".join(c for c in raw if c.isprintable())
                if _path_within(attempted_path, writable_paths or []):
                    continue  # Writable per policy → not Landlock, not our alert

        # Factual, non-accusatory log. Downstream tools still see the evidence
        # in sandbox_info["blocked"]; the human-facing log just notes what
        # happened without speculating about intent.
        if category == "network":
            logger.info(
                f"Sandbox: outbound network blocked during: {cmd_display} "
                f"(rc={returncode})"
            )
            blocked_evidence.append("Attempted outbound network connection (blocked by sandbox)")
        elif category == "write":
            path_note = f" to {attempted_path}" if attempted_path else ""
            logger.info(
                f"Sandbox: write outside allowed paths denied{path_note} "
                f"during: {cmd_display} (rc={returncode})"
            )
            if attempted_path:
                blocked_evidence.append(f"Attempted write to {attempted_path} (blocked by sandbox)")
            else:
                blocked_evidence.append("Attempted write outside allowed paths (blocked by sandbox)")
        elif category == "seccomp":
            # Actionable diagnostic — name the knob users can turn. Debug
            # unblocks ptrace; network-only turns off Landlock AND seccomp
            # (keeps namespace net block). Which to suggest depends on
            # the active profile.
            suggestion = "--sandbox network-only"
            if seccomp_profile == "full":
                suggestion = "--sandbox debug (if gdb/rr) or " + suggestion
            logger.info(
                f"Sandbox: 'Operation not permitted' seen in stderr during "
                f"{cmd_display} (rc={returncode}) — this may be seccomp "
                f"blocking a syscall (profile={seccomp_profile!r}). If the "
                f"tool genuinely needs the syscall, try {suggestion}."
            )
            blocked_evidence.append(
                f"Syscall denied by seccomp (profile={seccomp_profile!r}) — "
                f"caller may need to relax sandbox"
            )

        reported.add(category)

    if sandbox_info is not None and blocked_evidence:
        sandbox_info["blocked"] = blocked_evidence
