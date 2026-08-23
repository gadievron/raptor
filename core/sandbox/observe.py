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
from typing import Any

from core.sandbox.summary import record_denial

logger = logging.getLogger(__name__)

# Truncate the command in single-line log messages so scan-loop output
# doesn't get flooded with long argv lists; full argv is still visible
# to the subprocess itself and to post-mortem tools that see the real
# arguments on the process.
_CMD_DISPLAY_MAX_ARGS = 3

# Cap on distinct ASAN bug types extracted from one stderr stream — a
# hostile target spamming forged `ERROR: AddressSanitizer: <type>` lines
# must not balloon the evidence string.
_MAX_ASAN_BUG_TYPES = 8

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
    # UDP-at-startup casualties of network policies that deny UDP /
    # loopback socket use: the Linux egress-proxy FALLBACK tier
    # (netns-incapable hosts — seccomp denies AF_INET SOCK_DGRAM
    # creation) and macOS seatbelt's `(deny network*)` (denies UDP and
    # loopback wholesale). JVM build tooling opens a loopback UDP
    # socket before doing anything (gradle's FileLockContentionHandler
    # / local-IP detection). Precise tool strings; the real gating is
    # udp_block_engaged + rc != 0 in _check_blocked.
    ("udp", "Could not determine a usable local IP"),
    ("udp", "java.net.SocketException: Operation not permitted"),
    # Daemon-IPC casualty of the degraded-mode Landlock TCP-connect deny:
    # the daemon binds fine (bind is never restricted) but the client's
    # loopback connect gets EACCES. Precise tool string, not a generic
    # "could not connect", to keep the pre-filter noise-free.
    ("network", "Could not connect to the Gradle daemon"),
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
    info: dict[str, Any] = {"crashed": False, "resource_exceeded": False}
    evidence_items: list[str] = []

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
        # Evidence tiering (verdict-integrity): rc < 0 is the parent's
        # own waitpid() seeing WIFSIGNALED — kernel truth that target
        # code cannot mint through exit(2). rc in (128, 128+NSIG) is an
        # exit-CODE convention: trusted intermediates (pid-1 shim,
        # preexec trampoline) re-encode real signal deaths this way,
        # but a hostile target calling exit(128+n) produces the
        # IDENTICAL shape. Stamp the distinction so downstream verdict
        # makers (core/witness/sandbox_outcome.py, exploit oracles) can
        # grade waitstatus-provenance signals as mechanical evidence
        # and exit-code-decoded ones as heuristic. New field only —
        # existing consumers that ignore it keep their behaviour.
        info["signal_provenance"] = "waitstatus" if rc < 0 else "exitcode"

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
            logger.info("Sandbox: %s killed by %s (crash)", cmd_display, sig_name)
        elif sig_num in {s.value for s in resource_signals}:
            info["resource_exceeded"] = True
            if hasattr(signal, "SIGXCPU") and sig_num == signal.SIGXCPU:
                evidence_items.append(f"Process killed by {sig_name} — CPU time exhausted")
            elif hasattr(signal, "SIGXFSZ") and sig_num == signal.SIGXFSZ:
                evidence_items.append(f"Process killed by {sig_name} — file size limit exceeded")
            else:
                evidence_items.append(f"Process killed by {sig_name} — resource limit exceeded")
            logger.warning("Sandbox: %s killed by %s (resource limit)", cmd_display, sig_name)
        elif sig_num in {s.value for s in seccomp_signals}:
            info["seccomp_killed"] = True
            evidence_items.append(
                "Process killed by SIGSYS — seccomp blocked a syscall "
                "(likely 32-bit-compat int 0x80 or an explicit KILL rule)"
            )
            logger.info("Sandbox: %s killed by SIGSYS (seccomp)", cmd_display)
        else:
            evidence_items.append(f"Process killed by {sig_name}")
            logger.debug("Sandbox: %s killed by %s", cmd_display, sig_name)

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
            # Bug types come from ASAN error lines in stderr, which a
            # malicious binary can forge (ASAN prints attacker-influenced
            # symbols / addresses and nothing stops the target binary
            # printing a fake `ERROR: AddressSanitizer: \x1b[31m…` to
            # stderr directly). `(\S+)` captures any non-whitespace run,
            # including ESC sequences. Without sanitisation, the
            # logger.info below would inject terminal escapes into any
            # operator watching live output.
            #
            # EVERY reported type is kept (deduplicated, bounded), not
            # just the first match: first-match extraction let one
            # decoy `ERROR: AddressSanitizer: <wrong-type>` line
            # printed by the target before the real report rename the
            # bug type of a genuine, fully-retained crash — consumers
            # that compare the extracted type against a prediction
            # then read the mismatch as "not the predicted bug". The
            # bound keeps a type-spamming target from ballooning the
            # evidence string.
            from core.security.log_sanitisation import escape_nonprintable
            reported_types: list[str] = []
            for m in re.finditer(r"ERROR: AddressSanitizer: (\S+)", stderr_text):
                t = escape_nonprintable(m.group(1))
                if t not in reported_types:
                    reported_types.append(t)
                    if len(reported_types) >= _MAX_ASAN_BUG_TYPES:
                        break
            bug_type = ", ".join(reported_types) if reported_types else "unknown"
            evidence_items.append(f"AddressSanitizer: {bug_type}")
            if died_abnormally:
                info["crashed"] = True
            logger.info("Sandbox: %s — ASAN detected %s", cmd_display, bug_type)
        elif "UndefinedBehaviorSanitizer" in stderr_text:
            info["sanitizer"] = "ubsan"
            evidence_items.append("UndefinedBehaviorSanitizer triggered")
            if died_abnormally:
                info["crashed"] = True
            logger.info("Sandbox: %s — UBSAN triggered", cmd_display)
        elif "MemorySanitizer" in stderr_text:
            info["sanitizer"] = "msan"
            evidence_items.append("MemorySanitizer: use of uninitialised memory")
            if died_abnormally:
                info["crashed"] = True
            logger.info("Sandbox: %s — MSAN triggered", cmd_display)
        elif "ThreadSanitizer" in stderr_text:
            info["sanitizer"] = "tsan"
            evidence_items.append("ThreadSanitizer: data race detected")
            if died_abnormally:
                info["crashed"] = True
            logger.info("Sandbox: %s — TSAN triggered", cmd_display)

    # Evidence tiering: every sanitizer detection above is a bare
    # stderr substring match — target code (or anything that shares the
    # child's stderr, e.g. a hostile binary spawned by an honest
    # exploit) can print a byte-identical fake report. Stamp the
    # provenance so verdict makers never grade this as mechanical
    # evidence on its own; consumers with a stronger oracle (dark_verify
    # sentinel ordering, the exploit_verify waitstatus wrapper) upgrade
    # explicitly.
    if info.get("sanitizer"):
        info["sanitizer_provenance"] = "stderr_match"

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

    Relative paths must be rejected BEFORE `Path.resolve()` — `resolve()`
    silently turns a relative path into an absolute one rooted at the
    parent process's cwd, so the post-resolve `is_absolute()` check below
    can never be False. Without this gate, a relative path coming through
    sandbox stderr enrichment was matched against the allowlist via cwd
    semantics that the sandboxed child's cwd may not even share.
    """
    if not path or not allowed:
        return False
    if not Path(path).is_absolute():
        return False
    try:
        p = Path(path).resolve(strict=False)
    except (OSError, ValueError):
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
                   sandbox_info: dict | None = None,
                   network_engaged: bool = False,
                   landlock_engaged: bool = False,
                   writable_paths: list | None = None,
                   seccomp_engaged: bool = False,
                   seccomp_profile: str | None = None,
                   degraded_net_deny: bool = False,
                   udp_block_engaged: bool = False) -> None:
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
            if "Permission denied" not in stderr and "Read-only file system" not in stderr:
                continue
            if not landlock_engaged:
                continue
        # UDP-block patterns only fire when the seccomp SOCK_DGRAM
        # block is actually engaged for this call (egress-proxy
        # fallback tier) AND the process failed — the JVM
        # SocketException string is otherwise too generic.
        if category == "udp" and (not udp_block_engaged or returncode == 0):
            continue

        # Seccomp returns EPERM ("Operation not permitted"). The pattern
        # is inherently noisy — EPERM also comes from legitimate
        # capability checks (ptrace on protected process, mount without
        # privs, etc.). Fire only when seccomp is engaged AND the
        # process actually failed (rc != 0) AND the text looks like a
        # syscall-level message (not a higher-level "Not permitted" from
        # a CLI tool's own error).
        if category == "seccomp" and (not seccomp_engaged or returncode == 0):
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
        # Each denial also records to the per-run sandbox-summary if a run
        # is active (see core/sandbox/summary.py) — gives operators a
        # post-run aggregate of what the sandbox blocked, with suggested
        # fixes, instead of forcing them to grep log lines.
        if category == "network":
            if degraded_net_deny:
                # Degraded-mode Landlock TCP-connect deny is stricter
                # than the netns it substitutes for: loopback connects
                # are denied too, so daemon-IPC tools (gradle daemon,
                # language servers, self-spawned test servers) fail to
                # reach their own listener. Name the exact knob.
                logger.info(
                    "Sandbox: TCP connect denied during: %s (rc=%s) — degraded-mode Landlock deny is active (no namespace backend on this host) and it covers loopback as well. Daemon-IPC tools are auto-nudged to no-daemon mode where possible; if this workload genuinely needs loopback TCP, pass degraded_net_deny=False (accepts open egress on this host).", cmd_display, returncode
                )
            else:
                logger.info(
                    "Sandbox: outbound network blocked during: %s (rc=%s)", cmd_display, returncode
                )
            blocked_evidence.append("Attempted outbound network connection (blocked by sandbox)")
            record_denial(cmd_display, returncode, "network")
        elif category == "write":
            path_note = f" to {attempted_path}" if attempted_path else ""
            logger.info(
                "Sandbox: write outside allowed paths denied%s during: %s (rc=%s)", path_note, cmd_display, returncode
            )
            if attempted_path:
                blocked_evidence.append(f"Attempted write to {attempted_path} (blocked by sandbox)")
                record_denial(cmd_display, returncode, "write", path=attempted_path)
            else:
                blocked_evidence.append("Attempted write outside allowed paths (blocked by sandbox)")
                record_denial(cmd_display, returncode, "write")
        elif category == "udp":
            logger.info(
                "Sandbox: UDP/loopback socket use denied during: %s (rc=%s) — the active network policy denies it (Linux: the egress-proxy fallback tier's seccomp SOCK_DGRAM block on netns-incapable hosts; macOS: seatbelt's blanket network deny). JVM build tools (gradle) need a loopback UDP socket at startup and cannot run under this policy. On Linux netns-capable hosts the default proxy tier contains UDP topologically and they work; on macOS, JVM builds must run outside block_network.", cmd_display, returncode
            )
            blocked_evidence.append(
                "UDP/loopback socket use denied by the sandbox network "
                "policy (JVM-startup casualty)"
            )
            record_denial(cmd_display, returncode, "udp")
        elif category == "seccomp":
            # Actionable diagnostic — name the knob users can turn. Debug
            # unblocks ptrace; network-only turns off Landlock AND seccomp
            # (keeps namespace net block). Which to suggest depends on
            # the active profile.
            suggestion = "--sandbox network-only"
            if seccomp_profile == "full":
                suggestion = "--sandbox debug (if gdb/rr) or " + suggestion
            logger.info(
                "Sandbox: 'Operation not permitted' seen in stderr during %s (rc=%s) — this may be seccomp blocking a syscall (profile=%r). If the tool genuinely needs the syscall, try %s.", cmd_display, returncode, seccomp_profile, suggestion
            )
            blocked_evidence.append(
                f"Syscall denied by seccomp (profile={seccomp_profile!r}) — "
                f"caller may need to relax sandbox"
            )
            record_denial(cmd_display, returncode, "seccomp",
                          profile=seccomp_profile)

        reported.add(category)

    if sandbox_info is not None and blocked_evidence:
        sandbox_info["blocked"] = blocked_evidence
