"""Shared skill-dispatch runner for lifecycle-managed ``claude -p`` passes.

Both /agentic's enrichment passes (``core/orchestration/agentic_passes``)
and /audit's post-audit validation handoff (``core/audit/validate``)
dispatch a Claude Code subprocess with a skill loaded, wrapped in the
same run-lifecycle bookkeeping. The audit copy was written second and
had already drifted behind the agentic one (head-truncation instead of
signal-sorted truncation, no ``OSError`` launch handling, and — the
security-relevant one — no cc-trust ``block_cc_dispatch`` gate). This
module is the single implementation of the MECHANICS:

- the gate chain: cc-trust block → rule-of-two → claude on PATH →
  caller preflight;
- lifecycle start/complete/fail via ``libexec/raptor-run-lifecycle``
  (with ``get_safe_env()`` so an untrusted target's ambient env never
  reaches the helpers);
- the sandboxed ``run_untrusted_networked`` dispatch with
  ``TimeoutExpired``/``OSError`` handling and the
  KeyboardInterrupt-aware "settled" pattern so an interrupted run dir
  never lingers in "running" state;
- signal-sorted truncation for over-cap finding selections.

Everything POLICY-shaped stays caller-side: which findings qualify,
what the prompt says, and what happens with the artefacts afterwards
(checklist enrichment, audit's auto-feedback hook).
"""

from __future__ import annotations

import logging
import math
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from core.llm.cc_proxy_hosts import (
    proxy_hosts_for_cc_dispatch as _proxy_hosts_for_cc_dispatch,
)
from core.llm.cc_proxy_hosts import (
    readable_paths_for_cc_dispatch as _readable_paths_for_cc_dispatch,
)
from core.sandbox import run_untrusted_networked
from core.sandbox.errors import SandboxSetupError as _SandboxSetupError
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

logger = logging.getLogger(__name__)

# Credential posture for the CC skill-pass child. "env" (default) is
# the current behaviour — backend credentials overlay into the child
# env (with AWS minting for sandboxed Bedrock children). "proxy" flips
# the child to the credential-proxy posture: ZERO provider credentials
# in env; the child authenticates to the local LLM dispatcher with a
# scoped minted token (budget = this pass's budget, TTL sized to the
# pass timeout, models pinned from the install's model env) and the
# dispatcher — which holds the credentials and SigV4-signs — fronts
# the provider. Documented in docs/environment.md.
_CC_CREDENTIAL_MODE_ENV = "RAPTOR_CC_CREDENTIAL_MODE"

# In-netns loopback port the sandbox bridges to the dispatcher UDS for
# proxy-mode children. The child's ANTHROPIC_BASE_URL is baked with
# this number before spawn; the sandbox shifts its own forwarder off
# it on the (rare) collision.
_CC_PROXY_BRIDGE_PORT = 61781


def _cc_credential_mode() -> str:
    raw = (os.environ.get(_CC_CREDENTIAL_MODE_ENV) or "env").strip().lower()
    if raw in ("env", "proxy"):
        return raw
    logger.warning(
        "%s=%r is not 'env' or 'proxy' — using 'env'",
        _CC_CREDENTIAL_MODE_ENV, raw,
    )
    return "env"


@dataclass
class _CCProxyCredentials:
    """Everything one proxy-mode CC dispatch needs, minted per-pass."""
    token: str
    token_id: str
    base_url: str
    bridges: dict          # {in-netns port: dispatcher UDS path}
    budget_usd: float


def _setup_cc_proxy_credentials(
    budget_usd: str, timeout_s: int, caller_label: str,
) -> _CCProxyCredentials:
    """Mint a scoped child token and derive the child's dispatcher route.

    Fail-fast contract: any missing precondition raises RuntimeError
    with an operator-actionable message — a proxy-mode child without a
    working dispatcher route must never fall back to env credentials
    (that would silently defeat the posture the operator asked for).
    """
    socket_path = os.environ.get("RAPTOR_LLM_SOCKET")
    if not socket_path:
        msg = (
            f"{_CC_CREDENTIAL_MODE_ENV}=proxy requires the LLM "
            "dispatcher route (RAPTOR_LLM_SOCKET) — run through the "
            "RAPTOR launcher, or unset the mode for env-credential "
            "dispatch"
        )
        raise RuntimeError(msg)
    from core.sandbox import check_mount_available, check_net_available
    if not check_net_available():
        msg = (
            f"{_CC_CREDENTIAL_MODE_ENV}=proxy requires the netns "
            "sandbox tier (unshare --user --net unavailable on this "
            "host) — the dispatcher bridge cannot engage"
        )
        raise RuntimeError(msg)
    if not check_mount_available():
        msg = (
            f"{_CC_CREDENTIAL_MODE_ENV}=proxy requires the fork spawn "
            "backend (mount-ns unavailable on this host) — only that "
            "backend runs the dispatcher bridge inside the child netns"
        )
        raise RuntimeError(msg)
    try:
        budget = float(budget_usd)
    except (TypeError, ValueError):
        msg = f"invalid pass budget {budget_usd!r} for proxy-mode mint"
        raise RuntimeError(msg) from None
    # The bridge terminates INSIDE the sandbox as the host UID, so it
    # must target the dispatcher's child-plane socket (scoped child
    # tokens only — no worker tokens, no /_child/* management, no
    # /_token/renew), never the full-capability worker socket. The
    # child plane lives next to the worker socket under a fixed name
    # (LLMDispatcher.child_socket_path); fail fast when absent rather
    # than falling back to the worker socket — a fallback would
    # silently hand the sandbox the admin plane.
    child_socket = Path(socket_path).with_name("llm-child.sock")
    if not child_socket.exists():
        raise RuntimeError(
            f"{_CC_CREDENTIAL_MODE_ENV}=proxy requires the dispatcher's "
            "child-plane socket (llm-child.sock next to the worker "
            "socket) — the running dispatcher predates the child plane; "
            "restart the run through the current launcher"
        )
    # Model pins the child will actually request — the CLI resolves
    # its model from these envs; unpinned installs mint an
    # any-model token (the USD budget stays the effective cap).
    models = [
        m for m in (
            os.environ.get("ANTHROPIC_MODEL"),
            os.environ.get("ANTHROPIC_SMALL_FAST_MODEL"),
            os.environ.get("RAPTOR_CC_MODEL"),
            os.environ.get("RAPTOR_CC_FALLBACK_MODEL"),
        ) if m
    ]
    if not models:
        logger.info(
            "proxy-mode mint: no model pins in env — minting without "
            "a model allowlist (budget/TTL still enforced)",
        )
    from core.llm.dispatcher.client import mint_child_token
    minted = mint_child_token(
        budget_usd=budget,
        models=models or None,
        # TTL covers the pass timeout plus slack for spawn/teardown.
        ttl_s=timeout_s + 600,
        label=caller_label,
    )
    # base_url is the gateway ORIGIN; cc_subprocess_env derives the
    # per-install route family (API vs Bedrock gateway vars) from it.
    return _CCProxyCredentials(
        token=minted["token"],
        token_id=minted["token_id"],
        base_url=f"http://127.0.0.1:{_CC_PROXY_BRIDGE_PORT}",
        bridges={_CC_PROXY_BRIDGE_PORT: str(child_socket)},
        budget_usd=budget,
    )


def _settle_cc_proxy_credentials(
    creds: _CCProxyCredentials, run_dir: Path | None, log_label: str,
) -> None:
    """Post-run spend reconciliation + revocation for one dispatch.

    Best-effort: the dispatch outcome is already decided; this only
    settles the ledger. Reads the token's dispatcher-booked spend,
    reconciles max-of-ledgers (the skill pass captures no child exit
    report, so the child-reported side is 0 and the dispatcher ledger
    is authoritative), writes the record into the run dir for the
    operator, and revokes the token so it cannot be replayed.
    """
    from core.llm.dispatcher.client import (
        child_token_spend,
        reconcile_child_spend,
        revoke_child_token,
    )
    spend: dict = {}
    try:
        spend = child_token_spend(creds.token_id)
    except (RuntimeError, OSError) as e:
        logger.warning("%s: child-token spend read failed: %s",
                       log_label, e)
    try:
        revoke_child_token(creds.token_id)
    except (RuntimeError, OSError) as e:
        logger.warning("%s: child-token revoke failed: %s", log_label, e)
    reconciled = reconcile_child_spend(
        spend.get("spent_usd") or 0.0, 0.0,
    )
    logger.info(
        "%s: credential-proxy spend $%.4f of $%.2f budget "
        "(%s requests, token %s)",
        log_label, reconciled, creds.budget_usd,
        spend.get("requests_made", "?"), creds.token_id,
    )
    if run_dir is not None:
        try:
            from core.json import save_json
            save_json(run_dir / "cc-proxy-spend.json", {
                "token_id": creds.token_id,
                "budget_usd": creds.budget_usd,
                "dispatcher_spent_usd": spend.get("spent_usd", 0.0),
                "reconciled_usd": reconciled,
                "requests_made": spend.get("requests_made", 0),
                "unpriced_requests": spend.get("unpriced_requests", 0),
                "last_model": spend.get("last_model"),
                "status": spend.get("status"),
            })
        except OSError as e:
            logger.warning("%s: cc-proxy-spend.json write failed: %s",
                           log_label, e)

# core/orchestration/skill_dispatch.py -> repo root (parents[2])
_RAPTOR_DIR = Path(__file__).resolve().parents[2]
_LIFECYCLE = _RAPTOR_DIR / "libexec" / "raptor-run-lifecycle"
_BUILD_CHECKLIST = _RAPTOR_DIR / "libexec" / "raptor-build-checklist"

# Sanity cap: even a pathological report shouldn't push more than this
# through a single post-pass subprocess. Above the cap callers truncate
# (signal-sorted — see truncate_findings_by_signal) and log a warning.
MAX_VALIDATE_FINDINGS = 50

_LIFECYCLE_TIMEOUT_S = 30   # lifecycle helpers are mechanical; should be instant


# Reason prefix stamped on SkillDispatchResult.skipped_reason when the
# sandbox refused to set up (the child never launched). Callers use
# is_sandbox_setup_skip to classify — never their own string matching.
_SANDBOX_SETUP_REASON_PREFIX = "sandbox setup failed: "


def is_sandbox_setup_skip(reason: str | None) -> bool:
    """True when a dispatch skip records a sandbox SETUP failure.

    Setup failures happen before any billed work (the child process
    never launched), so a bounded caller-side retry is safe: it can
    never double-run a skill pass, only re-attempt the launch.
    """
    return bool(reason) and str(reason).startswith(
        _SANDBOX_SETUP_REASON_PREFIX)


#: Bytes of each child stream kept in the on-disk failure artifact.
_CHILD_TAIL_PERSIST_CHARS = 65536

#: Writer-authored disclosure for a dispatch result whose streams were
#: never captured (stdout/stderr both None — the runner was invoked
#: without capture, so the child's narrative went to the parent's
#: inherited stdio and is gone). Distinct from a captured-but-silent
#: child: rendering the two identically made a plumbing regression
#: look like a quiet child, and the empty tail was undiagnosable.
_CAPTURE_MISSING_NOTE = (
    "child streams were not captured (dispatch ran without "
    "capture_output — the child's output went to the parent's "
    "inherited stdio and was not persisted)"
)


def _streams_captured(proc: subprocess.CompletedProcess) -> bool:
    """True when the dispatch result carries captured streams.

    ``subprocess`` semantics: an uncaptured stream is ``None``; a
    captured-but-silent stream is ``""``/``b""``. Both streams share
    one ``capture_output`` switch, so either being non-None means
    capture was on.
    """
    return proc.stdout is not None or proc.stderr is not None


def _child_failure_tail(proc: subprocess.CompletedProcess) -> str:
    """Bounded diagnostic line for a failed dispatch child.

    The CC child multiplexes its own errors onto stdout — stderr is
    routinely EMPTY on a nonzero exit, so a stderr-only excerpt goes
    blank exactly when the operator needs it. Prefer stderr, fall back
    to the stdout TAIL (a crash narrative ends the stream). Both
    streams quote hostile-target bytes, so the excerpt is escaped and
    bounded for the operator's terminal.
    """
    from core.security.log_sanitisation import sanitise_for_terminal

    if not _streams_captured(proc):
        return f"({_CAPTURE_MISSING_NOTE})"
    err = (proc.stderr or "").strip()
    if err:
        return sanitise_for_terminal(err, max_len=500)
    out = (proc.stdout or "").strip()
    if out:
        return ("(stderr empty; stdout tail) "
                + sanitise_for_terminal(out[-500:], max_len=500))
    return ("(capture active — the child produced no output on "
            "stdout or stderr)")


def _timeout_partial_capture(
    exc: subprocess.TimeoutExpired,
) -> subprocess.CompletedProcess:
    """CompletedProcess-shaped view of a timeout kill's partial capture.

    ``TimeoutExpired`` surfaces whatever the runner captured before
    the kill — the only account of what the child was doing when the
    clock ran out. Streams may arrive as bytes on this path (the kill
    can precede decoding); decode with replacement so hostile bytes
    cannot fail the forensics. ``returncode`` is a placeholder — the
    caller labels the artifact's exit line ``timeout``.
    """
    def _decoded_stream(stream: object) -> str:
        if isinstance(stream, bytes):
            return stream.decode("utf-8", errors="replace")
        return stream if isinstance(stream, str) else ""

    return subprocess.CompletedProcess(
        args=exc.cmd, returncode=-1,
        stdout=_decoded_stream(exc.stdout),
        stderr=_decoded_stream(exc.stderr))


def _persist_child_tail(
    run_dir: Path | None, proc: subprocess.CompletedProcess,
    exit_label: str | None = None,
    duration_s: float | None = None,
) -> None:
    """Write bounded child-stream tails beside the failed pass.

    The artifact must never be SILENTLY empty: a child that produced
    no bytes gets an explicit writer-authored ``streams=empty`` line
    (with the exit label and ``duration=`` above it), and a result
    whose streams were never captured gets ``capture=missing`` —
    "the child said nothing" and "nobody listened" are different
    failures and must read differently on disk.

    The WARNING line carries 500 chars; the artifact keeps enough of
    both streams to root-cause without re-running a multi-minute
    child. Stream content quotes hostile-target bytes — escaped
    (newlines kept: it is a multi-line narrative) before landing in an
    operator-readable file, and every body line carries the ``| ``
    quote prefix so writer-authored lines (the ``exit=`` authority
    label, the section markers) are the only lines at column 0.
    Escaping alone is not splice resistance here: with newlines
    preserved, an entirely-printable child stdout could end with a
    forged ``exit=0`` line plus duplicate section markers that read
    exactly like parent-authored text (and a windowed excerpt of the
    artifact then LED with the forgery once the genuine line 1 fell
    out of the window). Best-effort — never let forensics fail the
    failure path. ``exit_label`` replaces the numeric exit on paths
    with no real exit status (the timeout kill).
    """
    if run_dir is None:
        return
    exit_text: str = (exit_label if exit_label is not None
                      else str(proc.returncode))
    # Writer-authored header lines (column 0, like the exit label —
    # child body lines are always ``| ``-quoted so these cannot be
    # forged). Empty tails must never render silently: an artifact
    # that reads identically for "capture was off", "the child said
    # nothing", and "the child crashed pre-logging" is undiagnosable
    # exactly when it is needed.
    notes: str = ""
    if duration_s is not None:
        notes += f"duration={duration_s:.1f}s\n"
    captured = _streams_captured(proc)
    if not captured:
        notes += f"capture=missing ({_CAPTURE_MISSING_NOTE})\n"
    elif not (proc.stderr or "").strip() and not (proc.stdout or "").strip():
        notes += ("streams=empty (capture was active — the child "
                  "produced no output on stdout or stderr; it likely "
                  "died before logging anything)\n")
    content = (
        f"exit={exit_text}\n"
        + notes
        + "--- stderr tail ---\n"
        + _quote_body((proc.stderr or "")[-_CHILD_TAIL_PERSIST_CHARS:])
        + "\n--- stdout tail ---\n"
        + _quote_body((proc.stdout or "")[-_CHILD_TAIL_PERSIST_CHARS:])
        + "\n"
    )
    try:
        from core.atomic_fs import write_text_atomically

        # run_dir is child-writable by design (output=, cwd) and the
        # child holds MAKE_SYM: a plain open("w") here follows a
        # child-planted symlink at this name and hands the UNSANDBOXED
        # parent an arbitrary-file write. The atomic primitive stages
        # in an O_EXCL tempfile and renames over the name — a rename
        # replaces a symlink, never follows it. 0600 for stream-at-
        # rest parity with the prompt tempfile hygiene.
        write_text_atomically(
            Path(run_dir) / "dispatch-child-tail.log", content, mode=0o600,
        )
    except OSError:
        logger.debug("child tail persist failed", exc_info=True)


def _esc(s: str) -> str:
    """Control-byte escape for the tail artifact.

    Length is bounded by the caller's slice; newlines are kept — the
    tail is a multi-line narrative, and flattening it would destroy
    exactly the tracebacks it exists to preserve.
    """
    from core.security.log_sanitisation import escape_nonprintable

    return escape_nonprintable(s, preserve_newlines=True)


def _quote_body(s: str) -> str:
    """Escape a child stream tail and quote every line with ``| ``.

    The prefix makes the artifact's in-band markers forgery-evident:
    untrusted body lines can never sit at column 0, so a column-0
    ``exit=`` or ``--- … tail ---`` line is writer-authored by
    construction (a child-emitted ``| exit=0`` renders as
    ``| | exit=0`` — visibly quoted). See the label-preserving
    excerpting contract in :mod:`core.security.log_sanitisation`.
    """
    return "\n".join("| " + line for line in _esc(s).split("\n"))  # line-model: escape_nonprintable above renders any \r inert


def missing_validation_report(run_dir: Path) -> str | None:
    """``validate_outputs`` probe for /validate skill passes.

    The validation pipeline's terminal artifact is
    ``validation-report.md`` — Stage 1 writes it only after the stage
    verdicts are merged. A CC child can exit 0 while the pipeline
    inside it crashed (a stage helper failing mid-run leaves the child
    free to narrate the failure and exit cleanly), so the child's exit
    status alone cannot stand for "verdicts were produced": a pass
    recorded as completed on exit status alone leaves every selected
    finding silently pending. Absent or empty report ⇒ the pass
    failed, with the reason surfaced through the dispatch result.
    """
    report = Path(run_dir) / "validation-report.md"
    try:
        if report.is_file() and report.stat().st_size > 0:
            return None
    except OSError:
        pass
    return (
        "validate pipeline produced no verdicts: validation-report.md "
        "missing or empty in the run dir (in-child stage crash or "
        "pipeline abort; the child process itself exited 0)"
    )


@dataclass
class SkillDispatchResult:
    """Outcome of :func:`run_skill_dispatch`.

    ``run_dir`` is set as soon as the lifecycle started, including on
    failure paths, so callers can surface the partially-populated run
    directory to the operator.

    ``child_exit`` is the parent-observed exit of the child process
    (numeric exit status, or the timeout label) — ``None`` when no
    child ever produced one (launch/sandbox-setup failures). It is
    the OUT-OF-BAND copy of the tail artifact's line-1 authority
    label: consumers that excerpt ``dispatch-child-tail.log`` must
    re-emit exit authority from this field, never recover it from
    artifact bytes (the artifact lives in a child-writable directory).
    """
    ran: bool
    skipped_reason: str | None = None
    run_dir: Path | None = None
    duration_s: float = 0.0
    child_exit: str | None = None


class StageError(Exception):
    """Raised by a caller's ``stage`` callback to abort the dispatch
    with a specific reason (the lifecycle is marked failed with it)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------------------
# Lifecycle helpers — wrap libexec/raptor-run-lifecycle and raptor-build-checklist.
# ---------------------------------------------------------------------------


class LifecycleStart(NamedTuple):
    """Outcome of :func:`start_lifecycle`.

    ``run_dir`` — the started run dir, or None when the helper failed.
    ``error`` — on failure, a one-line sanitised detail for the
    caller's skip record (helper stderr quotes project names and
    target paths, so it is escaped and bounded before it travels);
    None when there is nothing to say.
    """

    run_dir: Path | None
    error: str | None = None


def _vet_threaded_pin(pinned: str, target: Path, command: str) -> str:
    """Return the project pin to thread for a CHILD run — a three-way
    vet of *pinned* against the CHILD's target:

    * **Match** — the child target lies inside the project's
      registered target: thread *pinned* unchanged.
    * **Mismatch** — the project loaded and the target-match
      predicate answers False: thread ``ARGV_NONE`` (start the child
      standalone), loudly. Threading the pin would deterministically
      refuse the child's start — the lifecycle helper's target-match
      gate errors with "target ... is outside project ...". That
      poisoned-pin shape is real: a parent started with ``--out``
      records its AMBIENT pin even when the ambient project does not
      match the parent's own target (``get_output_dir``'s ``--out``
      arm warns and proceeds), so the parent marker carries a project
      the target was never inside, and threading it verbatim killed
      every child pass (the /validate post-pass of an exhaustive
      audit run skipped with "lifecycle start failed"). Mirror the
      ``--out`` doctrine: outside the project's target, project
      placement and trust markers do not apply.
    * **Unknown** — the project cannot be loaded
      (``ProjectManager.load`` funnels every file-level failure —
      missing entry, unreadable file or dir, corrupt JSON — to
      ``None``) or the vet itself raises: KEEP the pin and let the
      helper's own gate adjudicate moments later. Its refusal rides
      back as the recorded skip detail, so deferring loses nothing,
      while demoting on a non-verdict would silently strip project
      placement from a healthy pinned run on a transient registry
      read error.

    The demotion warning interpolates the child target and the
    project's registered target — attacker-influenceable strings
    (checkout directory names) — so both are escaped and bounded per
    the log-sanitisation contract before they reach the log stream.
    """
    from core.security.log_sanitisation import sanitise_for_terminal
    try:
        from core.project.project import ProjectManager
        project = ProjectManager().load(pinned)
        if project is None:
            logger.warning(
                "lifecycle start %s: project '%s' could not be loaded "
                "for vetting (missing, unreadable, or corrupt registry "
                "entry); keeping the pin — the lifecycle helper will "
                "adjudicate", command,
                sanitise_for_terminal(pinned, max_len=120))
            return pinned
        from core.run.output import target_matches_project
        if target_matches_project(str(target), pinned,
                                  project.target, command=command):
            return pinned
        project_target: str = project.target
    except Exception:  # noqa: BLE001 — vet unavailable: not a verdict
        logger.warning(
            "lifecycle start %s: project '%s' could not be vetted; "
            "keeping the pin — the lifecycle helper will adjudicate",
            command, sanitise_for_terminal(pinned, max_len=120))
        logger.debug("lifecycle start %s: pin vet failed for %r",
                     command, pinned, exc_info=True)
        return pinned
    from core.run.pin import ARGV_NONE
    logger.warning(
        "lifecycle start %s: not threading project pin %r — child "
        "target %s is outside the project's target (%s); starting the "
        "child standalone (projectless). Project placement and trust "
        "markers do not apply to a target outside the project.",
        command, pinned,
        sanitise_for_terminal(str(target), max_len=300),
        sanitise_for_terminal(project_target, max_len=300))
    return ARGV_NONE


def _start_failure_detail(proc: subprocess.CompletedProcess) -> str:
    """One-line, sanitised failure detail from a nonzero helper exit.

    The helper's contract is a single ``ERROR: ...`` stderr line;
    prefer it, fall back to the last non-empty stderr line, then to
    the bare exit code. Helper stderr interpolates target paths and
    project names (attacker-influenceable on hostile checkouts), so
    the line is escaped and bounded per the log-sanitisation contract
    before it reaches a report field.
    """
    from core.security.log_sanitisation import sanitise_for_terminal

    lines = [ln.strip() for ln in (proc.stderr or "").splitlines()
             if ln.strip()]
    detail = next((ln for ln in lines if ln.startswith("ERROR:")),
                  lines[-1] if lines else "")
    if not detail:
        return f"helper exited {proc.returncode} with no stderr"
    return sanitise_for_terminal(detail, max_len=300)


def start_lifecycle(command: str, target: Path,
                    parent_run_dir: Path | None = None) -> LifecycleStart:
    """Start a new lifecycle-managed run dir.

    Returns a :class:`LifecycleStart`: ``run_dir`` holds the
    OUTPUT_DIR path on success and None if the helper failed or its
    output couldn't be parsed; on failure ``error`` carries the
    sanitised one-line detail so callers can record WHY (the bare
    "lifecycle start failed" constant hid a deterministic
    target-match refusal from the operator and the run report).

    ``parent_run_dir`` names the lifecycle run dir of the PARENT phase
    (the /audit or /agentic run this dispatch is a child pass of). The
    child run must land in the parent RUN's pinned project: the
    process-scoped ``--project`` override threads as before, but
    without one the parent run's own pin (freeze-cache first, session-
    ledger witness checked) is threaded instead of letting the child
    re-resolve ambiently — a mid-run project switch (another session
    bumping the machine-wide last-activated default) otherwise
    re-points the child at a DIFFERENT project, whose target-match
    gate refuses the start ("target ... is outside project ...") or,
    on a matching target, silently splits one command's artifacts
    across two projects. Only AUTHORITATIVE parent pins thread (a real
    ``project`` key, including the explicit-none pin); the legacy
    containment fallback authorizes reads only and must not become an
    argv pin.

    The helpers run with `RaptorConfig.get_safe_env()` (strict allowlist)
    rather than the inherited environment. When the pipeline runs against
    an untrusted target — operator points RAPTOR at a freshly cloned OSS
    repo — the parent env may carry attacker-relevant vars (LD_PRELOAD,
    PYTHONSTARTUP, BASH_ENV from a poisoned dotfile, GIT_CONFIG_GLOBAL
    pointing at a malicious config). Inheriting them into the lifecycle
    subprocesses (which themselves invoke raptor-managed bash + python)
    widens the trust boundary unnecessarily. The helpers don't depend on
    operator env beyond PATH/HOME/USER, which get_safe_env preserves.
    """
    from core.config import RaptorConfig
    safe_env = RaptorConfig.get_safe_env()
    # The libexec trust guard requires _RAPTOR_TRUSTED or CLAUDECODE in the
    # child env. get_safe_env() only COPIES those if already in os.environ —
    # under bin/raptor (or a Claude Code session) they are, but on the direct
    # `python3 raptor.py agentic` path they are not, so the /understand
    # pre-pass's lifecycle call hit the guard and exited 2 ("Pre-pass
    # skipped"). This is RAPTOR dispatching its OWN lifecycle helper, so
    # asserting the trust marker is correct. setdefault so a real parent
    # value (bin/raptor / CC) is never overwritten; _RAPTOR_TRUSTED (not a
    # fabricated CLAUDECODE) is the honest marker for a non-CC transport.
    safe_env.setdefault("_RAPTOR_TRUSTED", "1")
    argv = [str(_LIFECYCLE), "start", command, "--target", str(target)]
    # Thread the parent's project explicitly: a sibling lifecycle run
    # (the /understand pre-pass, the /validate post-pass, the gap-audit
    # chain) must land in the SAME project as the run that spawned it —
    # re-resolving ambiently in the child raced mid-run project
    # switches and split one command's artifacts across two projects.
    try:
        from core.run.pin import ARGV_NONE, get_process_project
        pinned = get_process_project()
        if pinned is None and parent_run_dir is not None:
            from core.run.pin import resolve_witnessed_run_pin
            pin, witnessed = resolve_witnessed_run_pin(parent_run_dir)
            if pin.authoritative:
                if not witnessed:
                    # The pin still threads — the sessionless/detached
                    # orchestrator (no env credential, no claude-shaped
                    # ancestor) has no ledger record by construction,
                    # and a witnessed-only gate would strand exactly
                    # that child back on the ambient layers. But the
                    # unwitnessed marker is child-writable, so say so
                    # loudly. pin.project is registry-vetted here
                    # (resolution drops pins naming unregistered
                    # projects, and registered names are
                    # charset-validated at creation).
                    logger.warning(
                        "lifecycle start %s: threading parent run pin "
                        "%r from %s with NO session-ledger witness "
                        "(sessionless/detached parent) — the pin comes "
                        "from the child-writable run marker only",
                        command, pin.project, parent_run_dir)
                pinned = pin.project if pin.project is not None \
                    else ARGV_NONE
        if pinned is not None and pinned != ARGV_NONE:
            # Vet the pin against the CHILD's target before threading:
            # a project whose registered target does not contain the
            # child target deterministically refuses the start (the
            # helper's target-match gate), which killed the post-pass
            # outright. See _vet_threaded_pin for the doctrine.
            pinned = _vet_threaded_pin(pinned, target, command)
        if pinned is not None:
            argv += ["--project", pinned if pinned else ARGV_NONE]
            # The flag is harness-synthesized, not operator-typed: the
            # marker makes the child record pin provenance "threaded"
            # instead of "argv" (core.run.pin.PIN_SOURCES).
            from core.run.pin import PIN_THREADED_ENV
            safe_env[PIN_THREADED_ENV] = "1"
    except Exception:  # noqa: BLE001 — child falls back to its own layers
        logger.debug(
            "lifecycle start %s: parent pin threading failed — the "
            "child resolves its project from its own layers", command,
            exc_info=True)
    try:
        proc = subprocess.run(
            argv,
            capture_output=True, text=True, timeout=_LIFECYCLE_TIMEOUT_S,
            env=safe_env, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        from core.security.log_sanitisation import sanitise_for_terminal
        logger.warning("lifecycle start %s failed: %s", command, e)
        return LifecycleStart(
            None,
            "helper spawn failed: "
            + sanitise_for_terminal(str(e), max_len=300))
    if proc.returncode != 0:
        detail = _start_failure_detail(proc)
        logger.warning("lifecycle start %s returned %d: %s",
                       command, proc.returncode, detail)
        return LifecycleStart(None, detail)
    for line in reversed(proc.stdout.splitlines()):
        line = line.strip()
        if line.startswith("OUTPUT_DIR="):
            return LifecycleStart(Path(line[len("OUTPUT_DIR="):]).resolve())
    logger.warning("lifecycle start %s did not emit OUTPUT_DIR=", command)
    return LifecycleStart(None, "helper did not emit OUTPUT_DIR=")


def complete_lifecycle(output_dir: Path) -> None:
    """Mark a lifecycle run as completed. Best-effort; swallows errors.

    See `start_lifecycle` for the env=safe_env rationale.
    """
    from core.config import RaptorConfig
    safe_env = RaptorConfig.get_safe_env()
    try:
        proc = subprocess.run(
            [str(_LIFECYCLE), "complete", str(output_dir)],
            capture_output=True, text=True, timeout=_LIFECYCLE_TIMEOUT_S,
            env=safe_env, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("lifecycle complete failed: %s", e)
        return
    if proc.returncode != 0:
        logger.warning("lifecycle complete returned %d: %s",
                       proc.returncode, (proc.stderr or "")[:300])


def fail_lifecycle(output_dir: Path | None, message: str) -> None:
    """Mark a lifecycle run as failed. Best-effort; swallows errors.

    See `start_lifecycle` for the env=safe_env rationale.
    """
    if output_dir is None:
        return
    from core.config import RaptorConfig
    safe_env = RaptorConfig.get_safe_env()
    try:
        proc = subprocess.run(
            [str(_LIFECYCLE), "fail", str(output_dir), message],
            capture_output=True, text=True, timeout=_LIFECYCLE_TIMEOUT_S,
            env=safe_env, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("lifecycle fail failed: %s", e)
        return
    if proc.returncode != 0:
        logger.warning("lifecycle fail returned %d: %s",
                       proc.returncode, (proc.stderr or "")[:300])


def build_checklist(target: Path, output_dir: Path) -> bool:
    """Run libexec/raptor-build-checklist. Returns True on success.

    The child runs under the shared work-scaled bound
    (``core.audit.checklist_timeout`` — the same sizing rule and
    RAPTOR_CHECKLIST_BUILD_TIMEOUT_S override as the raptor-audit
    call sites; a flat 300s here live-failed on large binary
    targets on the audit surface). This surface degrades instead of
    refusing on an invalid override — a pre-pass builder failure is
    already a warn-and-continue path, so a malformed env value logs
    a warning and the computed scaled bound applies.

    See `start_lifecycle` for the env=safe_env rationale.
    """
    from core.audit.checklist_timeout import (
        checklist_build_timeout_s,
        scaled_checklist_build_timeout_s,
    )
    from core.config import RaptorConfig
    safe_env = RaptorConfig.get_safe_env()
    try:
        timeout_s = checklist_build_timeout_s(target, output_dir)
    except ValueError as e:
        logger.warning(
            "build_checklist: %s — using the work-scaled bound", e)
        timeout_s = scaled_checklist_build_timeout_s(target, output_dir)
    try:
        proc = subprocess.run(
            [str(_BUILD_CHECKLIST), str(target), str(output_dir)],
            capture_output=True, text=True, timeout=timeout_s,
            env=safe_env, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("build_checklist failed: %s", e)
        return False
    if proc.returncode != 0:
        logger.warning("build_checklist returned %d: %s",
                       proc.returncode, (proc.stderr or "")[:300])
        return False
    return True


# ---------------------------------------------------------------------------
# Signal-sorted truncation.
# ---------------------------------------------------------------------------


def _safe_score(f: dict) -> float:
    """Coerce ``exploitability_score`` for sorting.

    The schema says exploitability_score is a number, but malformed LLM
    output (e.g. "high" instead of 0.9) shouldn't crash sort
    mid-truncation. Coerce non-numeric to 0. Also guard against NaN/Inf
    — Python sort with NaN keys produces undefined order because NaN
    compares False to everything; we'd get non-deterministic truncation.
    """
    raw = f.get("exploitability_score")
    try:
        v = float(raw) if raw is not None else 0.0
    except (TypeError, ValueError):
        return 0.0
    if math.isnan(v) or math.isinf(v):
        return 0.0
    return v


def _signal_key(f: dict) -> tuple:
    return (
        0 if f.get("is_exploitable") is True else 1,  # exploitable first
        -_safe_score(f),                                # score descending
        _tree_class_rank(f),                            # production first
        _sarif_level_rank(f),                           # error > warning
    )


# SARIF severity levels, strongest first. Raw SARIF results carry no
# is_exploitable / exploitability_score / tree_class, so without this
# component they all tie and truncation degrades to head order for
# SARIF-shaped callers; unknown or absent levels rank as "warning"
# (the SARIF default), so findings without the field are unaffected.
_SARIF_LEVEL_RANK = {"error": 0, "warning": 1, "none": 2, "note": 3}


def _sarif_level_rank(f: dict) -> int:
    level = f.get("level")
    return _SARIF_LEVEL_RANK.get(level, 1) if isinstance(level, str) else 1


def _tree_class_rank(f: dict) -> int:
    """Tie-break rank below the signal fields: findings tagged with a
    non-production ``tree_class`` (core.audit.tree_class vocabulary —
    audit emissions stamp it) yield to production findings ONLY when
    the exploitability signals tie. Untagged findings (other emitters)
    rank as production, so their ordering is unchanged."""
    from core.audit.tree_class import NON_PRODUCTION_TREE_CLASSES

    return 1 if f.get("tree_class") in NON_PRODUCTION_TREE_CLASSES else 0


def truncate_findings_by_signal(
    findings: list,
    cap: int = MAX_VALIDATE_FINDINGS,
    *,
    log_label: str = "post-pass",
) -> list:
    """Cap *findings* at *cap*, dropping the weakest qualifiers.

    Sorts by signal strength so truncation drops the weakest, not
    whoever happened to be last in report order. Priority:

    1. ``is_exploitable=True`` wins over confidence-only
    2. higher ``exploitability_score`` wins (when present)
    3. ties broken by input order (Python sort is stable)

    Entries missing both signal fields all tie, so a caller whose
    findings carry neither (e.g. audit emissions) keeps its input
    order for the survivors — never worse than head-truncation, and
    strictly better as soon as any entry carries a signal field.
    Returns the input list unchanged when it's within the cap.
    """
    if len(findings) <= cap:
        return findings
    ranked = sorted(findings, key=_signal_key)
    logger.warning(
        "%s: %d findings selected; truncating to %d "
        "(keeping highest-signal: is_exploitable then exploitability_score)",
        log_label, len(findings), cap,
    )
    return ranked[:cap]


# ---------------------------------------------------------------------------
# The generic gated dispatch runner.
# ---------------------------------------------------------------------------


def run_skill_dispatch(
    *,
    command: str,
    target: Path,
    tools: str,
    budget_usd: str,
    timeout_s: int,
    caller_label: str,
    log_label: str,
    build_prompt: Callable[[Path], str],
    block_cc_dispatch: bool = False,
    claude_bin: str | None = None,
    context_dirs: Sequence[Path] = (),
    preflight: Callable[[], str | None] | None = None,
    stage: Callable[[Path], None] | None = None,
    validate_outputs: Callable[[Path], str | None] | None = None,
    parent_run_dir: Path | None = None,
) -> SkillDispatchResult:
    """Run one lifecycle-managed, sandboxed ``claude -p`` skill pass.

    Gate chain (first hit wins, mirrors the /agentic post-pass order):

    1. ``block_cc_dispatch`` — cc-trust verdict for the target repo
       (compute via ``core.security.cc_trust.check_repo_claude_trust``);
    2. rule-of-two: human terminal or effective sandbox (per
       ``require_human_or_sandbox_for_agentic_pass(command)``);
    3. ``claude`` binary on PATH (or explicit ``claude_bin``);
    4. caller ``preflight()`` — cheap caller-side checks (report
       exists, selection non-empty); return a skip reason or None.

    Then: lifecycle start → ``stage(run_dir)`` (write selection files /
    pointers into the run dir; raise :class:`StageError` to abort with
    a reason) → ``build_prompt(run_dir)`` → sandboxed dispatch →
    ``validate_outputs(run_dir)`` (return an error string to fail the
    run) → lifecycle complete.

    ``context_dirs`` are prior-phase artefact dirs the CC child must
    read (e.g. the parent pipeline's out_dir): they are appended to the
    sandbox ``add_dirs`` and ``readable_paths``. ``target`` and the run
    dir are always included.

    ``parent_run_dir`` is the parent phase's lifecycle run dir: its
    project pin is threaded into this pass's lifecycle start so the
    child run lands in the SAME project as the run that spawned it
    (see :func:`start_lifecycle`).

    May raise: unexpected exceptions propagate AFTER the lifecycle is
    marked failed — callers keep their own never-raise wrapper so the
    base pipeline survives (both existing callers already do).
    KeyboardInterrupt / SystemExit also mark the lifecycle failed
    ("interrupted") before propagating.
    """
    if block_cc_dispatch:
        return SkillDispatchResult(
            ran=False,
            skipped_reason="cc_trust blocked dispatch (untrusted target)")

    from core.security.rule_of_two import (
        NonInteractiveError,
        require_human_or_sandbox_for_agentic_pass,
    )
    try:
        require_human_or_sandbox_for_agentic_pass(command)
    except NonInteractiveError as e:
        return SkillDispatchResult(ran=False, skipped_reason=str(e))

    # Administrative transport kill switch — this lane is a billed
    # `claude -p` spawn that does not pass run_cc_streaming, so it
    # honours the switch itself, joining the gate chain with the same
    # skip shape as the other gates.
    from core.llm.cc_adapter import cc_transport_disabled, resolve_claude_cli
    if cc_transport_disabled():
        return SkillDispatchResult(
            ran=False,
            skipped_reason="claude CLI transport disabled "
            "(RAPTOR_CC_TRANSPORT_DISABLED is set)")

    # Operator-forced local-only posture: these skill passes are
    # claude-bound (agentic tool-using investigations; there is no
    # Ollama agent loop), so under RAPTOR_NO_CLAUDE skip them cleanly
    # rather than spawning claude. Same skip shape as the other gates.
    if os.environ.get("RAPTOR_NO_CLAUDE"):
        return SkillDispatchResult(
            ran=False,
            skipped_reason="claude CLI skipped (RAPTOR_NO_CLAUDE is set); "
            "this pass requires the Claude Code agent")

    # Realpath at the resolution seam: symlinked installs otherwise
    # fail the mount-ns visibility check and silently downgrade the
    # dispatch to Landlock-only (see resolve_claude_cli).
    claude_bin = resolve_claude_cli(claude_bin)
    if not claude_bin:
        return SkillDispatchResult(ran=False, skipped_reason="claude not on PATH")

    if preflight is not None:
        reason = preflight()
        if reason is not None:
            return SkillDispatchResult(ran=False, skipped_reason=reason)

    # Present-but-unusable claude (installed, NOT logged in) must skip
    # like "not on PATH" — otherwise start_lifecycle creates a run dir,
    # the dispatch spawns `claude -p` which exits with "Not logged in",
    # and the run surfaces a noisy failure. The cc-probe (cache-first;
    # a real call only on cold cache) returns None when the transport
    # is not trustworthy, including the unauthenticated case.
    from core.llm.cc_probe import probe_cc_session_model
    if probe_cc_session_model(claude_bin) is None:
        return SkillDispatchResult(
            ran=False,
            skipped_reason="claude CLI present but not usable "
            "(not logged in, or transport probe failed) — "
            "run `claude /login`")

    target = Path(target).resolve()
    context_dirs = [Path(d).resolve() for d in context_dirs]

    t0 = time.monotonic()

    started = start_lifecycle(command, target,
                              parent_run_dir=parent_run_dir)
    run_dir = started.run_dir
    if run_dir is None:
        # Carry the helper's one-line detail (already sanitised at the
        # start_lifecycle seam): the bare constant left the operator
        # with no lead on WHY the child pass never started.
        reason = "lifecycle start failed"
        if started.error:
            reason = f"{reason}: {started.error}"
        return SkillDispatchResult(ran=False,
                                   skipped_reason=reason,
                                   duration_s=time.monotonic() - t0)

    # Track whether the run reached a definitive end-state. If we exit
    # via KeyboardInterrupt or another BaseException (which Exception
    # doesn't catch), the finally clause still marks the lifecycle
    # failed so the run dir doesn't linger in "running" state forever.
    lifecycle_settled = False
    cc_proxy_creds: _CCProxyCredentials | None = None
    try:
        if stage is not None:
            try:
                stage(run_dir)
            except StageError as e:
                # Mark settled BEFORE the call so that if fail_lifecycle
                # itself raises, the `finally` block's "interrupted"
                # fallback doesn't overwrite the real failure reason.
                # Same pattern at every other fail_lifecycle call site
                # in this function.
                lifecycle_settled = True
                fail_lifecycle(run_dir, e.reason)
                return SkillDispatchResult(
                    ran=False, skipped_reason=e.reason, run_dir=run_dir,
                    duration_s=time.monotonic() - t0)

        prompt = build_prompt(run_dir)

        # Credential posture (see _CC_CREDENTIAL_MODE_ENV). Proxy-mode
        # setup failures FAIL the pass with a clear reason — never a
        # silent fallback to env credentials.
        credential_mode = _cc_credential_mode()
        if credential_mode == "proxy":
            try:
                cc_proxy_creds = _setup_cc_proxy_credentials(
                    budget_usd, timeout_s, caller_label,
                )
            except (RuntimeError, OSError) as e:
                lifecycle_settled = True
                fail_lifecycle(run_dir, f"credential-proxy setup: {e}")
                logger.warning("%s: credential-proxy setup failed: %s",
                               log_label, e)
                return SkillDispatchResult(
                    ran=False,
                    skipped_reason=f"credential-proxy setup failed: {e}",
                    run_dir=run_dir, duration_s=time.monotonic() - t0)

        from core.llm.cc_adapter import (
            CCDispatchConfig,
            build_cc_command,
            cc_subprocess_env,
            system_prompt_file_for,
        )
        dispatch_config = CCDispatchConfig(
            claude_bin=claude_bin,
            tools=tools,
            add_dirs=(str(_RAPTOR_DIR), str(target),
                      *(str(d) for d in context_dirs), str(run_dir)),
            budget_usd=budget_usd,
            timeout_s=timeout_s,
            capture_json_envelope=False,
        )
        # env: proxy mode hands the child a credential-FREE env whose
        # only auth is the scoped dispatcher token; env mode keeps the
        # backend overlay (CLAUDE_CODE_*/ANTHROPIC_*/AWS_*) so a
        # Bedrock/Vertex-backed CLI child can authenticate itself. The
        # sandbox's proxy env still overrides HTTPS_PROXY either way.
        if cc_proxy_creds is not None:
            child_env = cc_subprocess_env(
                credential_mode="proxy",
                proxy_base_url=cc_proxy_creds.base_url,
                proxy_auth_token=cc_proxy_creds.token,
            )
        else:
            child_env = cc_subprocess_env(mint_aws_credentials=True)
        # Prompt transport differs by credential posture. Proxy mode
        # MUST use ``stdin=<file>``: only the fork spawn backend runs
        # the dispatcher bridge inside the child's netns, and that
        # backend cannot plumb ``input=`` — passing it silently routes
        # the dispatch down the unshare-CLI fallback whose empty netns
        # has no forwarder (the child would have no network at all).
        # The prompt can embed operator context and excerpts of the
        # scanned source, so it must not persist on disk: it goes into
        # a 0600 tempfile (mkstemp) that is unlinked before the child
        # is spawned — the only remaining reference is the open fd the
        # spawn backend dup2s onto the child's stdin, and the inode
        # dies when both sides close it.
        stdin_kwargs: dict
        prompt_fh = None
        if cc_proxy_creds is not None:
            fd, tmp_prompt_path = tempfile.mkstemp(prefix="cc-prompt-")
            try:
                os.unlink(tmp_prompt_path)
                prompt_fh = os.fdopen(fd, "w+b")
            except OSError:
                os.close(fd)
                raise
            prompt_fh.write(prompt.encode("utf-8"))
            prompt_fh.flush()
            prompt_fh.seek(0)
            stdin_kwargs = {"stdin": prompt_fh}
        else:
            stdin_kwargs = {"input": prompt}
        try:
            # Sandboxed Claude Code dispatch with restrict_reads=True.
            # See cc_dispatch.py for rationale; this site adds
            # str(_RAPTOR_DIR) on top of the calibrated/default
            # readable_paths so the LLM-directed Bash tool can invoke
            # libexec helpers (which live under RAPTOR_DIR), plus the
            # caller's context_dirs holding prior phases' artefacts.
            # target + run_dir are auto-allowlisted via the
            # target=/output= positional args; $HOME secrets stay
            # denied.
            #
            # System prompt (when the config carries one) rides a 0600
            # tempfile + --system-prompt-file — never in the child's
            # world-readable /proc/<pid>/cmdline (see
            # build_cc_command's hygiene contract). Spawn AND wait stay
            # inside the CM; the file path joins readable_paths because
            # TMPDIR is outside the sandbox's read allowlist.
            with system_prompt_file_for(dispatch_config) as _sys_prompt_path:
                proc = run_untrusted_networked(
                    build_cc_command(
                        dispatch_config,
                        system_prompt_file=_sys_prompt_path,
                    ),
                    text=True,
                    # The sandbox runner's capture defaults to FALSE:
                    # without this kwarg the CompletedProcess carries
                    # stdout=None/stderr=None and every failure-path
                    # consumer below (_child_failure_tail,
                    # _persist_child_tail, the timeout partial
                    # capture) persisted EMPTY tails — a multi-minute
                    # billed child exited nonzero and the run dir held
                    # nothing diagnosable. The CC child in -p mode
                    # emits its result/error narrative at exit (no
                    # live progress stream is lost), and the fork
                    # spawn backend drains the pipes under its own
                    # per-stream byte cap, so capture is bounded.
                    capture_output=True,
                    # The captured streams can quote hostile-target
                    # bytes; the subprocess-backed lanes otherwise
                    # decode strict and a single bad byte raises
                    # UnicodeDecodeError in the parent — losing the
                    # very narrative capture exists to keep. (The
                    # fork spawn backend already decodes with
                    # replacement; this aligns the other lanes.)
                    errors="replace",
                    **stdin_kwargs,
                    timeout=timeout_s,
                    target=str(target), output=str(run_dir),
                    # Explicit cwd: the claude CLI treats its working
                    # directory as a project root (CLAUDE.md, .claude
                    # settings, workspace-trust posture). Inheriting the
                    # parent's cwd handed the child whatever project the
                    # OPERATOR happened to be sitting in — an untrusted
                    # workspace whose permission rules the CLI loudly
                    # ignores. The run dir is RAPTOR-owned, carries no
                    # project config, and is already writable via
                    # output=; tool grants come from --allowed-tools.
                    cwd=str(run_dir),
                    # env-mode children get mint_aws_credentials=True:
                    # sandboxed — Landlock denies ~/.aws and the egress
                    # allowlist has no IMDS route, so on IAM-role Bedrock
                    # hosts their own AWS credential chain is dead ("Could
                    # not load credentials from any providers", rc=1); the
                    # parent resolves the chain and attaches frozen session
                    # credentials at its trust boundary. Proxy-mode
                    # children carry no credentials at all (see above).
                    env=child_env,
                    # Trust-marker propagation: this child is RAPTOR's own
                    # claude binary running a skill pass on the same
                    # operator-approved run (gated above by cc-trust +
                    # rule-of-two). Its job is to drive libexec/ helpers
                    # (raptor-validation-helper, raptor-run-lifecycle)
                    # whose preamble refuses callers without CLAUDECODE /
                    # _RAPTOR_TRUSTED — the default marker strip left the
                    # validate post-pass child looking untrusted (rc=1,
                    # A4). A parent that holds no marker propagates
                    # nothing: an untrusted parent stays refused.
                    keep_trust_markers=True,
                    readable_paths=(
                        [str(_RAPTOR_DIR)]
                        + [str(d) for d in context_dirs]
                        + _readable_paths_for_cc_dispatch(claude_bin)
                        + ([str(_sys_prompt_path)]
                           if _sys_prompt_path is not None else [])
                    ),
                    # Proxy mode: loopback-only allowlist (deny-all remote —
                    # the child talks solely to the bridged dispatcher).
                    proxy_hosts=_proxy_hosts_for_cc_dispatch(
                        claude_bin, credential_mode=credential_mode,
                    ),
                    # Proxy mode: relay in-netns 127.0.0.1:<port> to the
                    # dispatcher UDS so the CLI's ANTHROPIC_BASE_URL works
                    # inside the empty network namespace.
                    loopback_unix_bridges=(
                        cc_proxy_creds.bridges if cc_proxy_creds else None
                    ),
                    caller_label=caller_label,
                    # run_dir is a run-dir root by construction (the
                    # lifecycle starts it above) and that is this
                    # lane's contract: the skill pass writes the run's
                    # own artifacts there.
                    output_run_root_ok=True,
                )
        except subprocess.TimeoutExpired as e:
            lifecycle_settled = True
            fail_lifecycle(run_dir, f"timeout after {timeout_s}s")
            # The exception carries the kill's partial capture — the
            # only account of what the multi-minute child was doing
            # when the clock ran out. Persist it like the rc!=0 and
            # validate-failure legs (previously discarded: the arm
            # returned without writing, and the operator got a bare
            # timeout line).
            _persist_child_tail(
                run_dir, _timeout_partial_capture(e),
                exit_label=f"timeout after {timeout_s}s",
                duration_s=time.monotonic() - t0)
            logger.warning("%s timed out after %ds", log_label, timeout_s)
            return SkillDispatchResult(
                ran=False, skipped_reason=f"timeout after {timeout_s}s",
                run_dir=run_dir, duration_s=time.monotonic() - t0,
                child_exit=f"timeout after {timeout_s}s")
        except OSError as e:
            lifecycle_settled = True
            fail_lifecycle(run_dir, f"launch failed: {e}")
            logger.warning("%s failed to launch: %s", log_label, e)
            return SkillDispatchResult(
                ran=False, skipped_reason=f"launch failed: {e}",
                run_dir=run_dir, duration_s=time.monotonic() - t0)
        except _SandboxSetupError as e:
            # BaseException by design ("fail loud") — convert to a
            # clean pass failure here because the callers' never-raise
            # backstops only catch Exception, and a credential-proxy
            # bridge that cannot engage must fail THIS pass, not crash
            # the whole pipeline.
            lifecycle_settled = True
            reason = f"{_SANDBOX_SETUP_REASON_PREFIX}{e}"
            fail_lifecycle(run_dir, reason)
            logger.warning("%s sandbox setup failed: %s", log_label, e)
            return SkillDispatchResult(
                ran=False, skipped_reason=reason,
                run_dir=run_dir, duration_s=time.monotonic() - t0)
        finally:
            if prompt_fh is not None:
                prompt_fh.close()

        if proc.returncode != 0:
            lifecycle_settled = True
            # Safety net for the cc-probe gate above: auth can expire
            # between the probe and the dispatch, so detect the CLI's
            # own "Not logged in" on a non-zero exit and skip cleanly.
            _child_out = ((proc.stdout or "") + (proc.stderr or "")).lower()
            if ("not logged in" in _child_out
                    or "please run /login" in _child_out
                    or "please run `claude /login`" in _child_out):
                reason = ("claude CLI present but not logged in — run "
                          "`claude /login` (skill pass skipped)")
                fail_lifecycle(run_dir, reason)
                logger.warning("%s skipped: %s", log_label, reason)
                return SkillDispatchResult(
                    ran=False, skipped_reason=reason,
                    run_dir=run_dir, duration_s=time.monotonic() - t0,
                    child_exit=str(proc.returncode))
            fail_lifecycle(run_dir, f"subprocess returned {proc.returncode}")
            _persist_child_tail(run_dir, proc,
                                duration_s=time.monotonic() - t0)
            logger.warning("%s returned %d: %s", log_label, proc.returncode,
                           _child_failure_tail(proc))
            return SkillDispatchResult(
                ran=False,
                skipped_reason=f"subprocess returned {proc.returncode}",
                run_dir=run_dir, duration_s=time.monotonic() - t0,
                child_exit=str(proc.returncode))

        if validate_outputs is not None:
            error = validate_outputs(run_dir)
            if error is not None:
                lifecycle_settled = True
                fail_lifecycle(run_dir, error)
                # The child exited 0 but the pass produced no terminal
                # artifact — its narrative is the only account of what
                # went wrong inside.
                _persist_child_tail(run_dir, proc,
                                    duration_s=time.monotonic() - t0)
                logger.warning("%s: %s", log_label, error)
                return SkillDispatchResult(
                    ran=False, skipped_reason=error, run_dir=run_dir,
                    duration_s=time.monotonic() - t0,
                    child_exit=str(proc.returncode))

        complete_lifecycle(run_dir)
        lifecycle_settled = True

        return SkillDispatchResult(ran=True, run_dir=run_dir,
                                   duration_s=time.monotonic() - t0,
                                   child_exit=str(proc.returncode))

    except Exception:
        # Make sure the lifecycle is marked failed before propagating.
        lifecycle_settled = True
        fail_lifecycle(run_dir, "unexpected exception")
        raise
    finally:
        # Settle the credential-proxy ledger (spend read + reconcile +
        # revoke) whether the dispatch succeeded, failed, or was
        # interrupted — a minted token must never outlive its pass.
        if cc_proxy_creds is not None:
            try:
                _settle_cc_proxy_credentials(
                    cc_proxy_creds, run_dir, log_label,
                )
            except Exception:  # settlement is best-effort
                logger.warning(
                    "%s: credential-proxy settlement failed", log_label,
                    exc_info=True,
                )
        # KeyboardInterrupt / SystemExit / any other BaseException
        # bypasses the except-Exception clause above. Make sure the run
        # dir is marked failed so downstream consumers (the bridge)
        # don't keep finding it as "in progress".
        if not lifecycle_settled:
            fail_lifecycle(run_dir, "interrupted")


__all__ = [
    "MAX_VALIDATE_FINDINGS",
    "LifecycleStart",
    "SkillDispatchResult",
    "StageError",
    "build_checklist",
    "complete_lifecycle",
    "fail_lifecycle",
    "missing_validation_report",
    "run_skill_dispatch",
    "start_lifecycle",
    "truncate_findings_by_signal",
]
