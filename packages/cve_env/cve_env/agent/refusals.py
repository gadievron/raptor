"""Detect + log LLM refusals to the project-level refusals-log.md.

Every refusal is logged with full context for reproduction AND with what
happened after -- so future research can answer: when do models refuse, what
preamble/retry/tool-swap helped, and how often did the overall build still
succeed? A refusal is any
assistant TextBlock (or ResultMessage body) that matches the refusal
patterns below. Deterministic tool failures, validator rejections, and
docker subprocess errors do NOT count (they are handled separately).

Per refusal we capture:

* **Preceding context** -- the last ``_HISTORY_WINDOW`` turn-events
  before the refusal (tool calls, tool results, assistant text). This
  lets a researcher see what prompt / tool output / framing elicited
  the refusal.
* **Subsequent turns** -- the next ``_RECOVERY_WINDOW`` turn-events
  after the refusal, filled in post-hoc by the loop. Captures the
  agent's retry / pivot / give-up shape verbatim.
* **retry_pattern** -- classification: ``retry_same_tool``,
  ``pivot_tool``, ``text_reframe``, ``give_up``, ``ended``,
  ``no_followup``.
* **recovery_worked** -- did the overall run eventually reach
  ``verify.passed``? Paired with ``time_to_recovery_turns`` and
  ``final_outcome_status`` so the log can be grouped by "successful
  recoveries" vs "refusals that killed the run".

The writer appends to ``<env-builder-again>/refusals-log.md``. File is
never truncated -- forensic value requires full history.
"""

from __future__ import annotations

import datetime as _dt
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_HISTORY_WINDOW: int = 4
"""Turn-events of preceding context stored per refusal."""

_RECOVERY_WINDOW: int = 4
"""Turn-events of subsequent context captured after a refusal."""

# Patterns deliberately cover both first-person refusals and policy-adjacent
# framing. Matches are case-insensitive. Keep the list narrow: a pattern that
# fires on benign text ("I can't tell you which is faster without measuring")
# would drown the log in false positives.
_REFUSAL_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\bI\s+(can'?t|cannot|will\s+not|won'?t)\s+(help|assist|do|provide|comply)",
        re.I,
    ),
    re.compile(r"\bI\s+(must|have\s+to)\s+decline\b", re.I),
    re.compile(r"\b(unable|not\s+able)\s+to\s+(help|assist|provide|comply)\b", re.I),
    re.compile(r"\bI\s+(shouldn'?t|should\s+not)\s+(help|do|assist)\b", re.I),
    re.compile(
        r"\b(against|violates?)\s+(my|the|Anthropic[']?s?)\s+"
        r"(guidelines|policy|policies|usage\s+policy)\b",
        re.I,
    ),
    re.compile(
        r"\b(as\s+an\s+AI|as\s+a\s+language\s+model)\b.*?\b(cannot|can'?t|won'?t)\b",
        re.I,
    ),
    re.compile(r"\bI\s+don'?t\s+feel\s+comfortable\b", re.I),
    # This apology pattern requires a refusal-class keyword
    # (cannot/won't/unable/refuse/decline/must not/shouldn't) within ~100
    # non-period chars after the trigger — the natural window for "I apologize,
    # but I cannot proceed." A bare apology+pronoun shape would otherwise fire
    # on benign apologies like "I apologize, but I had a typo", so the keyword
    # requirement filters out simple apology+correction patterns.
    re.compile(
        r"\bI\s+apologize[,.]?\s+but\s+(?:I|this|that)\b"
        r"[^.]{0,100}?\b"
        r"(?:cannot|can'?t|won'?t|unable|refuse|refus|decline|must\s+not|shouldn'?t)\b",
        re.I,
    ),
    re.compile(r"\brefus(?:e|ing|ed)\s+to\s+(help|assist|do|provide)\b", re.I),
    # claude-agent-sdk's bundled `claude` CLI wraps AUP-class refusals in an
    # "API Error" prefix. The wrapper text uses "unable to respond" (not
    # "unable to help|assist") and "violate our Usage Policy" (not "violate
    # the/my/Anthropic's policy"), so the patterns above don't match. These two
    # patterns close that gap.
    re.compile(r"\bAPI\s+Error:.*?\bunable\s+to\s+respond\b", re.I),
    re.compile(r"\bviolat(?:e|es)\s+(?:our|the)\s+Usage\s+Policy\b", re.I),
)


@dataclass
class RefusalEvent:
    """One refusal observation + context to reproduce AND study recovery.

    Not frozen -- ``subsequent_turns`` / ``retry_pattern`` /
    ``recovery_worked`` / ``final_outcome_status`` /
    ``time_to_recovery_turns`` are filled in post-hoc by the loop
    once the run finishes.
    """

    timestamp_utc: str
    project: str
    cve_id: str
    run_id: str
    turn: int
    audit_path: str
    refusal_text: str
    matched_pattern: str
    preceding_turns: list[dict[str, Any]] = field(default_factory=list)
    subsequent_turns: list[dict[str, Any]] = field(default_factory=list)
    retry_pattern: str = ""
    recovery_worked: bool | None = None
    time_to_recovery_turns: int = -1
    final_outcome_status: str = ""
    system_prompt_ref: str = ""
    user_prompt: str = ""
    tool_call: dict[str, Any] | None = None
    model: str = ""
    host_arch: str = ""
    notes: str = ""


@dataclass
class RefusalScanner:
    """Incremental scanner for one build run. Accumulates events + history."""

    project: str
    cve_id: str
    run_id: str
    audit_path: Path
    model: str = ""
    host_arch: str = ""
    events: list[RefusalEvent] = field(default_factory=list)
    _history: deque[dict[str, Any]] = field(
        default_factory=lambda: deque(maxlen=_HISTORY_WINDOW)
    )
    _full_trail: list[dict[str, Any]] = field(default_factory=list)

    def observe(self, event_record: dict[str, Any]) -> None:
        """Record one turn-event (tool_use / tool_result / text) in the trail.

        Loop should call this for EVERY event it sees, even non-text ones,
        so the preceding_turns context is complete.
        """
        self._history.append(event_record)
        self._full_trail.append(event_record)

    def scan_text(
        self,
        *,
        turn: int,
        text: str,
        tool_call: dict[str, Any] | None = None,
    ) -> RefusalEvent | None:
        """Return a :class:`RefusalEvent` if ``text`` matches any pattern.

        The current text is NOT included in ``preceding_turns`` -- those
        are the events that led up to the refusal (not the refusal itself).
        """
        if not text:
            return None
        for pat in _REFUSAL_PATTERNS:
            m = pat.search(text)
            if m is not None:
                preceding = [dict(e) for e in self._history]
                event = RefusalEvent(
                    timestamp_utc=_dt.datetime.now(_dt.UTC).isoformat(
                        timespec="seconds"
                    ),
                    project=self.project,
                    cve_id=self.cve_id,
                    run_id=self.run_id,
                    turn=turn,
                    audit_path=str(self.audit_path),
                    refusal_text=text[:2000],
                    matched_pattern=pat.pattern,
                    preceding_turns=preceding,
                    model=self.model,
                    host_arch=self.host_arch,
                    tool_call=tool_call,
                )
                self.events.append(event)
                return event
        return None

    def finalize(self, *, final_outcome_status: str, verify_passed: bool) -> None:
        """Fill subsequent_turns / retry_pattern / recovery_worked on each event.

        Called once the run finishes. Uses the full turn trail to look
        forward from each refusal's turn.
        """
        for event in self.events:
            followups: list[dict[str, Any]] = []
            refusal_idx: int | None = None
            for i, rec in enumerate(self._full_trail):
                if (
                    rec.get("turn") == event.turn
                    and rec.get("kind") == "assistant_text"
                ):
                    refusal_idx = i
                    break
            if refusal_idx is not None:
                followups = [
                    dict(r)
                    for r in self._full_trail[
                        refusal_idx + 1 : refusal_idx + 1 + _RECOVERY_WINDOW
                    ]
                ]
            event.subsequent_turns = followups
            event.retry_pattern = _classify_retry(event, followups)
            event.recovery_worked = verify_passed
            event.final_outcome_status = final_outcome_status
            if verify_passed and followups:
                for off, rec in enumerate(followups, start=1):
                    if (
                        rec.get("kind") == "tool_result"
                        and rec.get("tool_name") == "verify"
                    ):
                        # This is an approximation -- turn offset to the first
                        # verify result after the refusal.
                        event.time_to_recovery_turns = off
                        break


def _classify_retry(event: RefusalEvent, followups: list[dict[str, Any]]) -> str:
    """Coarse classification of how the agent followed a refusal.

    Categories:
    * ``no_followup`` -- nothing after the refusal (end of trail).
    * ``ended`` -- only a terminal event followed.
    * ``give_up`` -- the agent called ``give_up`` immediately after.
    * ``retry_same_tool`` -- same tool name as the tool_call in the
      refusal context.
    * ``pivot_tool`` -- different tool than the one in scope.
    * ``text_reframe`` -- another assistant text (often "let me try a
      different approach") with no tool call.
    """
    if not followups:
        return "no_followup"
    first = followups[0]
    kind = first.get("kind")
    if kind == "assistant_tool_use":
        followed_tool = first.get("tool_name", "")
        if followed_tool == "give_up":
            return "give_up"
        prior_tool = (event.tool_call or {}).get("name", "")
        if prior_tool and followed_tool == prior_tool:
            return "retry_same_tool"
        return "pivot_tool"
    if kind == "assistant_text":
        return "text_reframe"
    if kind == "result":
        return "ended"
    return "no_followup"


def _render_turn_line(rec: dict[str, Any]) -> str:
    """One compact line summarizing a turn event for the markdown log."""
    kind = rec.get("kind", "?")
    turn = rec.get("turn", "?")
    if kind == "assistant_tool_use":
        tn = rec.get("tool_name", "?")
        inp = rec.get("input")
        return f"  - turn {turn}: assistant tool_use `{tn}` input={inp!r}"
    if kind == "tool_result":
        tn = rec.get("tool_name", "?")
        preview = str(rec.get("result_preview", ""))[:240]
        return f"  - turn {turn}: tool_result `{tn}` -> {preview!r}"
    if kind == "assistant_text":
        text = str(rec.get("text", ""))[:240]
        return f"  - turn {turn}: assistant_text {text!r}"
    if kind == "result":
        stop = rec.get("stop_reason", "")
        cost = rec.get("total_cost_usd", 0.0)
        return f"  - turn {turn}: RESULT stop={stop!r} cost_usd={cost}"
    return f"  - turn {turn}: {kind} {rec!r}"


def _escape_terminal_codes(s: str) -> str:
    """Escape ANSI ESC, BEL, NUL, etc. to ``\\xHH`` form for markdown-safe
    rendering. ``refusal_text`` is LLM-controlled and reaches
    refusals-log.md inside a ``\\`\\`\\`code block\\`\\`\\``` interpolated raw
    (no ``!r``). An attacker who induces ANSI ESC sequences (e.g.
    ``\\x1b[2J\\x1b[H pwned``) in the model output triggers terminal
    injection when an operator runs ``cat refusals-log.md``.

    Preserves printable Unicode + newlines + tabs (markdown-friendly).
    Other ``event.*`` string fields use ``!r`` (Python ``repr()`` already
    escapes); only ``refusal_text`` needs explicit treatment.
    """
    out: list[str] = []
    for ch in s:
        if ch in ("\n", "\t"):
            out.append(ch)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(ch)
    return "".join(out)


def _render_event(event: RefusalEvent, recovery: str | None = None) -> str:
    """Render one event as a markdown section for refusals-log.md."""
    safe_refusal_text = _escape_terminal_codes(event.refusal_text)
    label = f"{event.cve_id}@{event.run_id}:turn{event.turn}"
    tool_block = (
        f"\n**Tool call in scope:** `{event.tool_call['name']}` "
        f"input={event.tool_call.get('input')!r}\n"
        if event.tool_call
        else "\n"
    )
    context_line = (
        f"project={event.project} cve={event.cve_id} "
        f"run={event.run_id} turn={event.turn}"
    )
    preceding_block = (
        "\n".join(_render_turn_line(r) for r in event.preceding_turns)
        or "  _(no preceding turns captured)_"
    )
    subsequent_block = (
        "\n".join(_render_turn_line(r) for r in event.subsequent_turns)
        or "  _(no subsequent turns -- refusal was last event)_"
    )
    recovery_summary = recovery or (
        f"run final={event.final_outcome_status} "
        f"verify_passed={event.recovery_worked} "
        f"retry_pattern={event.retry_pattern!r} "
        f"turns_to_verify={event.time_to_recovery_turns}"
    )
    return (
        f"\n## {event.timestamp_utc} — {label}\n"
        f"\n**Context:** {context_line}\n"
        f"\n**Audit path:** `{event.audit_path}`\n"
        f"\n**Matched pattern:** `{event.matched_pattern}`\n"
        f"{tool_block}"
        f"\n**Refusal text:**\n```\n{safe_refusal_text}\n```\n"
        f"\n**Preceding turns (most recent last):**\n{preceding_block}\n"
        f"\n**Subsequent turns (recovery window):**\n{subsequent_block}\n"
        f"\n**Retry classification:** `{event.retry_pattern or '(pending)'}`\n"
        f"\n**Reproduction:** model={event.model} host_arch={event.host_arch}\n"
        f"\n**Recovery:** {recovery_summary}\n"
        f"\n**Notes:** {event.notes or '_(pending triage)_'}\n"
        "\n---\n"
    )


def append_events(
    events: list[RefusalEvent],
    *,
    log_path: Path,
    recovery_per_event: dict[int, str] | None = None,
) -> None:
    """Append ``events`` to ``log_path`` as markdown sections.

    ``recovery_per_event`` maps ``turn`` -> recovery description and is
    filled in after the run finishes. Missing entries fall back to the
    placeholder.
    """
    if not events:
        return
    log_path.parent.mkdir(parents=True, exist_ok=True)
    recovery_per_event = recovery_per_event or {}
    with log_path.open("a", encoding="utf-8") as fh:
        for event in events:
            fh.write(_render_event(event, recovery=recovery_per_event.get(event.turn)))


def default_log_path() -> Path:
    """Resolve the canonical ``refusals-log.md`` location.

    Lands under the configured output root (``CVE_ENV_OUTPUT_ROOT`` when
    set, else ``REPO_ROOT/output``) so the refusals log sits with the
    run's other artifacts. raptor points the output root at ``out/``.
    Previously this was a depth-hardcoded ``parents[3].parent`` walk that
    broke when the package was re-homed under ``packages/cve_env/``.
    """
    from cve_env.config import OUTPUT_ROOT

    return OUTPUT_ROOT / "refusals-log.md"
