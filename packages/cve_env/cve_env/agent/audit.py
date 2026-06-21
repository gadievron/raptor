"""Per-CVE agent audit-log writer.

Split from event telemetry: stuffing full prompts + responses into a
bounded event stream balloons the event file to GB scale and operators
``rm -rf output/`` -- losing the run-level summary alongside the LLM
transcripts. Split the two:

* ``output/agentic/<run_id>/<cve_id>.jsonl`` -- one file per CVE; owner
  of the full agentic payload (each turn's tool call, tool result, cost,
  token usage). Append-only. Deleting one CVE's trace is cheap and does
  not lose the run summary.
* (Optional future) ``output/monitor/events.jsonl`` -- bounded event
  stream for dashboards. Not implemented in v0.1.

Design choices:

* One :class:`AuditWriter` per run. ``run_id`` is baked in at
  construction so every turn writes under the same run directory.
* Append-only. Each ``write`` serializes to a single JSON line. We never
  rewrite or truncate -- forensic value depends on full history.
* Fail-loud on I/O errors. If the agent runs and we cannot trace it, the
  attribution join downstream is corrupt. Let the exception propagate.

The stage Literal is an open string (tool names vary per run) and the
status Literal is restricted to agent-loop outcomes.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

# Security: redact obvious secrets before persisting tool I/O to the audit
# JSONL. The agent has a built-in host Bash, so a command line could carry a
# token (e.g. ``curl -H "Authorization: Bearer ghp_..."``); the log is
# append-only and may be shared for debugging, so secrets must not land in it.
# Patterns are tight known-prefix / fixed-shape tokens, so legitimate build
# text (image tags, paths, reasons) is never matched.
_SECRET_TOKEN_RE = re.compile(
    r"gh[opusr]_[A-Za-z0-9]{36,}"  # GitHub PAT (classic) / oauth / server / refresh
    r"|github_pat_[A-Za-z0-9_]{20,}"  # GitHub fine-grained PAT
    r"|sk-ant-[A-Za-z0-9_-]{20,}"  # Anthropic API key
    r"|AKIA[0-9A-Z]{16}"  # AWS access key id
    r"|[Bb]earer\s+[A-Za-z0-9._-]{12,}"  # Authorization: Bearer <token>
    r"|dckr_pat_[A-Za-z0-9_-]{20,}"  # Docker Hub PAT
    r"|glpat-[A-Za-z0-9_-]{20,}"  # GitLab PAT
    r"|apiKey\s*[:=]\s*[A-Za-z0-9_-]{8,}"  # NVD API key header value
    r"|ya29\.[A-Za-z0-9_-]{20,}"  # GCP OAuth access token
)
# Credentials embedded in a URL userinfo (``https://user:pass@host``), e.g. a
# git-over-https token URL — drop the userinfo, keep scheme + host.
_URL_CRED_RE = re.compile(r"((?:https?|git|ssh)://)[^/\s:@]+:[^/\s@]+@")

_REDACTED = "[REDACTED]"


def _redact_secrets(obj: Any) -> Any:
    """Recursively replace secret-shaped substrings in strings within ``obj``.

    Dicts/lists/tuples are walked; all other types pass through unchanged.
    Keys and structure are preserved so downstream readers (which consume
    typed sub-keys, never raw secret substrings) are unaffected.
    """
    if isinstance(obj, str):
        return _URL_CRED_RE.sub(
            rf"\1{_REDACTED}@", _SECRET_TOKEN_RE.sub(_REDACTED, obj)
        )
    if isinstance(obj, dict):
        return {k: _redact_secrets(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_secrets(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_redact_secrets(v) for v in obj)
    return obj


AuditStatus = Literal[
    "tool_ok",
    "tool_rejected",
    "tool_error",
    "llm_turn",
    "budget_exhausted",
    "final_success",
    "final_give_up",
    "final_turn_cap",
    "final_no_verify",
    "recovery",
    "post_build_refusal",
    "fix8_continuation",
    "force_resolve_continuation",
    "benign_verify_continuation",
    "proprietary_verify_continuation",
]
"""Agent-visible outcomes of a single audit entry.

One ``tool_ok`` per successful tool call, one ``llm_turn`` per LLM
request, terminal ``final_*`` exactly once per CVE.

``final_no_verify`` is emitted when the SDK ends with
``stop_reason='end_turn'`` AND verify wasn't passed AND no give_up was
issued — labeling silent end_turns distinctly rather than mislabeling
them ``final_turn_cap`` (no turn cap fired in that case).

``recovery`` is emitted alongside the ordinary ``tool_ok`` when a
build-path tool succeeds within ``RECOVERY_GAP_TURNS`` turns of a
same-tool failure. Lets post-bench analysis count recovery events without
scripted forensic over raw tool_ok / tool_error pairs.

``post_build_refusal`` is emitted when the SDK throws a refusal-class
exception AFTER ``state.launched_ok`` is True, i.e., the agent reached
docker_run/compose_up success but the verify-plan composition (or a
downstream tool input) tripped Anthropic's safety classifier. Distinct
from research-phase refusals (NVD-description trigger handled by the
sanitizer). Paired with the prompts.py open-clause verify-plan
composition rule.

``force_resolve_continuation`` is emitted by the build-engagement gate.
``benign_verify_continuation`` is emitted when a post-launch refusal
blocked verify and the env-gated benign-verify continuation resumes the
session with a benign-only verify prompt.

``proprietary_verify_continuation`` is emitted when the env-gated
proprietary-verify continuation resumes the session because the agent gave
up ``proprietary`` WITHOUT an image_resolve probe — verify-the-negative
against the open-source-by-proprietary-vendor false-positive class. Locked
by ``test_proprietary_verify_continuation`` +
``test_audit_status_registers_all_emitted_continuations``.
"""


def _sanitize_cve_id(cve_id: str) -> str:
    """Collapse a CVE ID into a filesystem-safe name.

    Restrict to ``[A-Za-z0-9_.-]``; replace everything else with ``_``.
    Prevents free-form debugging strings from escaping the audit root
    via path separators or ``..``.
    """
    return (
        "".join(c if c.isalnum() or c in {"-", "_", "."} else "_" for c in cve_id)
        or "UNKNOWN"
    )


@dataclass(frozen=True)
class AuditEntry:
    """One event in the agent loop's trace for a given CVE.

    Fields are strings / primitives where possible so downstream jq / pandas
    consumers do not need Python context to decode. ``tool_input`` /
    ``tool_result`` / ``llm_message`` are whatever JSON-serializable shape
    the caller chose; the writer only promises round-trippable
    persistence.
    """

    turn: int
    status: AuditStatus
    tool_name: str = ""
    tool_input: dict[str, Any] = field(default_factory=dict)
    tool_result: Any = None
    llm_message: dict[str, Any] = field(default_factory=dict)
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    reason: str = ""


class AuditWriter:
    """Per-run-scoped audit-log writer.

    Usage (from the agent loop):

        writer = AuditWriter(run_id=run_id, root=Path("output/agentic"))
        writer.write(cve_id="CVE-2018-7600", entry=AuditEntry(...))

    Thread-safety: one process, one writer per run. The append is a
    single ``write`` call on an opened-and-closed file handle each time,
    which is atomic for lines under 4 KB on POSIX. Multi-KB prompts
    exceed that cap, so if multi-writer semantics become a concern swap
    to ``os.O_APPEND`` directly -- the contract is the path, not the
    impl.
    """

    def __init__(self, *, run_id: str, root: Path) -> None:
        self._run_id = run_id
        self._root = root

    @property
    def run_root(self) -> Path:
        """Directory for this run's traces (``root/run_id/``)."""
        return self._root / self._run_id

    def write(self, *, cve_id: str, entry: AuditEntry) -> Path:
        """Append one :class:`AuditEntry` to the CVE's trace.

        Returns the path written so tests can assert on it directly
        without reconstructing the convention.

        Atomicity: the JSON line + ``\\n`` are written in a SINGLE
        ``fh.write`` call so a crash never leaves a partial line on disk.
        ``flush()`` is called immediately so the line is visible to a
        concurrent reader without waiting on Python's I/O buffer.
        """
        path = self._path_for(cve_id=cve_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Security: restrict the run dir to the owner (0700) — it holds the full
        # agentic transcript. Best-effort: chmod can fail on exotic filesystems
        # and must not abort the run (the fail-loud contract is about writing the
        # trace, not its mode).
        with contextlib.suppress(OSError):
            os.chmod(path.parent, 0o700)
        payload: dict[str, object] = {
            "run_id": self._run_id,
            "cve_id": cve_id,
            "turn": entry.turn,
            "status": entry.status,
            "tool_name": entry.tool_name,
            "tool_input": _redact_secrets(entry.tool_input),
            "tool_result": _redact_secrets(entry.tool_result),
            "llm_message": _redact_secrets(entry.llm_message),
            "input_tokens": entry.input_tokens,
            "output_tokens": entry.output_tokens,
            "cost_usd": entry.cost_usd,
            "reason": entry.reason,
        }
        line = json.dumps(payload, sort_keys=True, default=str) + "\n"
        # Boundary repair: if the file already has content and does not end
        # in a newline (partial line from a prior crash), prepend ``\n`` so
        # the partial is bounded and skipped on read. Single ``a+b`` open
        # eliminates the TOCTOU of the original two-handle approach.
        raw = line.encode("utf-8")
        with path.open("a+b") as fh:
            fh.seek(0, 2)
            pos = fh.tell()
            if pos > 0:
                fh.seek(pos - 1)
                if fh.read(1) != b"\n":
                    fh.write(b"\n")
            fh.write(raw)
            fh.flush()
        # Security: restrict the audit file to the owner (0600). Idempotent.
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)
        return path

    def _path_for(self, *, cve_id: str) -> Path:
        return self.run_root / f"{_sanitize_cve_id(cve_id)}.jsonl"

    def read(self, *, cve_id: str) -> tuple[dict[str, object], ...]:
        """Stream back entries for one CVE -- test/debug aid.

        Returns an empty tuple if the file does not exist; a caller
        asking about a CVE that hasn't run yet shouldn't eat a
        ``FileNotFoundError``.

        Partial-line recovery: a malformed line is SKIPPED rather than
        crashing the reader. An interrupted write could leave a partial
        line that ``json.loads`` would raise on. The atomic single-write in
        ``write()`` prevents new partial lines, but legacy traces may still
        contain them, so the reader must be tolerant.
        """
        path = self._path_for(cve_id=cve_id)
        if not path.exists():
            return ()
        out: list[dict[str, object]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                # Forensic-recovery: skip malformed lines silently. If
                # this is hot-path enough to need observability, callers
                # can compare line count vs returned entry count.
                continue
            out.append(parsed)
        return tuple(out)
