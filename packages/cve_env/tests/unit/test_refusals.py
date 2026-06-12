"""Tests for :mod:`cve_env.agent.refusals`."""

from __future__ import annotations

from pathlib import Path

import pytest

from cve_env.agent.refusals import (
    _REFUSAL_PATTERNS,
    RefusalScanner,
    append_events,
    default_log_path,
)


@pytest.fixture
def scanner(tmp_path: Path) -> RefusalScanner:
    return RefusalScanner(
        project="cve-env-test",
        cve_id="CVE-TEST-0001",
        run_id="run-x",
        audit_path=tmp_path / "audit.jsonl",
        model="claude-opus-4-7",
        host_arch="arm64",
    )


@pytest.mark.parametrize(
    "text",
    [
        "I can't help with that request.",
        "I cannot assist with this task.",
        "I won't help build that.",
        "I'm unable to comply with this.",
        "This violates Anthropic's usage policy.",
        "As an AI, I cannot do that.",
        "I must decline this request.",
        "I don't feel comfortable providing that.",
        "I shouldn't help with this.",
        "I apologize, but I cannot proceed.",
        "I refuse to assist with something that could cause harm.",
    ],
)
def test_detects_canonical_refusals(scanner: RefusalScanner, text: str) -> None:
    event = scanner.scan_text(turn=1, text=text)
    assert event is not None
    assert event.refusal_text == text[:2000]


@pytest.mark.parametrize(
    "text",
    [
        "The agent couldn't find a matching image on arm64.",
        "Docker reports: Unable to find image 'nginx:latest' locally.",
        "verify.passed = False; reason: container exited with code 1.",
        "The build failed because openssl/ssl.h was not found.",
        "I'll check whether the container is running.",
    ],
)
def test_does_not_match_tool_errors(scanner: RefusalScanner, text: str) -> None:
    # These are legit tool failures; not refusals.
    assert scanner.scan_text(turn=1, text=text) is None


def test_empty_and_none_safe(scanner: RefusalScanner) -> None:
    assert scanner.scan_text(turn=1, text="") is None


def test_event_carries_tool_call(scanner: RefusalScanner) -> None:
    event = scanner.scan_text(
        turn=3,
        text="I cannot assist with that operation.",
        tool_call={"name": "docker_run", "input": {"image": "foo"}},
    )
    assert event is not None
    assert event.tool_call == {"name": "docker_run", "input": {"image": "foo"}}


def test_append_events_writes_markdown(tmp_path: Path, scanner: RefusalScanner) -> None:
    scanner.scan_text(turn=5, text="I cannot assist with this kind of request.")
    log = tmp_path / "refusals-log.md"
    append_events(scanner.events, log_path=log, recovery_per_event={5: "Retried with tool X"})
    content = log.read_text(encoding="utf-8")
    assert "CVE-TEST-0001" in content
    assert "turn5" in content
    assert "Retried with tool X" in content


def test_append_noop_on_empty_list(tmp_path: Path) -> None:
    log = tmp_path / "refusals-log.md"
    append_events([], log_path=log)
    # Path should NOT be created if there's nothing to write.
    assert not log.exists()


def test_default_log_path_points_at_project_root() -> None:
    p = default_log_path()
    # Lands under the configured output root (config.OUTPUT_ROOT) with the
    # canonical filename. The directory is deployment-dependent
    # (CVE_ENV_OUTPUT_ROOT override → raptor's out/), so assert against
    # config rather than a hardcoded directory name.
    from cve_env.config import OUTPUT_ROOT

    assert p.name == "refusals-log.md"
    assert p.parent == OUTPUT_ROOT


def test_pattern_coverage_is_nonempty() -> None:
    assert len(_REFUSAL_PATTERNS) >= 8


# -- enrichment: preceding_turns, subsequent_turns, retry_pattern -------


_REFUSAL_SAMPLE = "I cannot assist with that operation."


def _tool_use(turn: int, name: str, **input_: object) -> dict[str, object]:
    return {"turn": turn, "kind": "assistant_tool_use", "tool_name": name, "input": input_}


def _tool_result(turn: int, name: str, preview: str = "ok") -> dict[str, object]:
    return {"turn": turn, "kind": "tool_result", "tool_name": name, "result_preview": preview}


def _text(turn: int, text: str) -> dict[str, object]:
    return {"turn": turn, "kind": "assistant_text", "text": text}


def test_preceding_turns_captured_from_observed_trail(scanner: RefusalScanner) -> None:
    scanner.observe(_tool_use(1, "vulhub_lookup", cve_id="X"))
    scanner.observe(_tool_result(2, "vulhub_lookup", "miss"))
    scanner.observe(_tool_use(3, "image_resolve"))
    event = scanner.scan_text(turn=4, text=_REFUSAL_SAMPLE)
    assert event is not None
    assert len(event.preceding_turns) == 3
    assert event.preceding_turns[0]["tool_name"] == "vulhub_lookup"
    assert event.preceding_turns[-1]["tool_name"] == "image_resolve"


def test_preceding_turns_truncated_to_window(scanner: RefusalScanner) -> None:
    from cve_env.agent.refusals import _HISTORY_WINDOW

    for i in range(_HISTORY_WINDOW + 3):
        scanner.observe(_text(i + 1, f"t{i}"))
    event = scanner.scan_text(turn=100, text="I cannot assist.")
    assert event is not None
    assert len(event.preceding_turns) == _HISTORY_WINDOW


def test_finalize_populates_subsequent_turns_and_pattern(scanner: RefusalScanner) -> None:
    # Refusal at turn 5 after a docker_run; then agent pivots to source_build.
    scanner.observe(_text(5, _REFUSAL_SAMPLE))
    scanner.scan_text(
        turn=5,
        text=_REFUSAL_SAMPLE,
        tool_call={"name": "docker_run", "input": {}},
    )
    scanner.observe(_tool_use(6, "source_build"))
    scanner.observe(_tool_result(7, "source_build", "ok"))
    scanner.observe(_tool_use(8, "verify"))
    scanner.observe(_tool_result(9, "verify", "passed"))

    scanner.finalize(final_outcome_status="success", verify_passed=True)

    event = scanner.events[0]
    assert event.retry_pattern == "pivot_tool"
    assert len(event.subsequent_turns) >= 1
    assert event.recovery_worked is True
    assert event.final_outcome_status == "success"
    assert event.time_to_recovery_turns >= 1


def test_classify_retry_same_tool(scanner: RefusalScanner) -> None:
    scanner.observe(_text(1, "I cannot assist with that."))
    scanner.scan_text(
        turn=1,
        text="I cannot assist with that.",
        tool_call={"name": "dockerfile_gen", "input": {}},
    )
    scanner.observe(_tool_use(2, "dockerfile_gen"))
    scanner.finalize(final_outcome_status="verify_failed", verify_passed=False)
    assert scanner.events[0].retry_pattern == "retry_same_tool"


def test_classify_retry_give_up(scanner: RefusalScanner) -> None:
    scanner.observe(_text(1, _REFUSAL_SAMPLE))
    scanner.scan_text(turn=1, text=_REFUSAL_SAMPLE)
    scanner.observe(_tool_use(2, "give_up", reason="proprietary"))
    scanner.finalize(final_outcome_status="unresolvable", verify_passed=False)
    assert scanner.events[0].retry_pattern == "give_up"
    assert scanner.events[0].recovery_worked is False


def test_classify_retry_no_followup(scanner: RefusalScanner) -> None:
    scanner.observe(_text(1, "I cannot assist with that."))
    scanner.scan_text(turn=1, text="I cannot assist with that.")
    scanner.finalize(final_outcome_status="turn_cap", verify_passed=False)
    assert scanner.events[0].retry_pattern == "no_followup"


def test_classify_retry_text_reframe(scanner: RefusalScanner) -> None:
    scanner.observe(_text(1, _REFUSAL_SAMPLE))
    scanner.scan_text(turn=1, text=_REFUSAL_SAMPLE)
    scanner.observe(_text(2, "Let me try a different approach."))
    scanner.finalize(final_outcome_status="verify_failed", verify_passed=False)
    assert scanner.events[0].retry_pattern == "text_reframe"


def test_render_event_escapes_terminal_codes_in_refusal_text(
    tmp_path: Path, scanner: RefusalScanner
) -> None:
    """BUG-004c (port from bafb): refusal_text is LLM-controlled and reaches
    refusals-log.md inside a ```code block``` (interpolated raw, no !r). An
    attacker who induces ANSI ESC + screen-clear + cursor-home sequences in
    the model's refusal text triggers terminal injection when an operator
    runs ``cat refusals-log.md``. Other event.* string fields use !r which
    Python's repr() already escapes; only refusal_text is at risk.

    Regression: refusal_text containing \\x1b (ESC), \\x07 (BEL), \\x00 (NUL)
    must be escaped to \\xHH form in the rendered output. Printable Unicode
    + newlines + tabs must be preserved (markdown-friendly).
    """
    # Inject a malicious refusal_text simulating what an LLM-controlled
    # response could carry. \x1b[2J\x1b[H clears terminal; \x07 is BEL.
    malicious = "Sorry, I cannot.\x1b[2J\x1b[H pwned\x07\x00"
    scanner.observe(_text(1, "Refusal: cannot help"))
    # Force a refusal event to exist
    scanner.scan_text(turn=1, text=_REFUSAL_SAMPLE)
    scanner.finalize(final_outcome_status="incomplete", verify_passed=False)
    # Replace the captured refusal_text with our malicious payload to
    # exercise the rendering path.
    scanner.events[0].refusal_text = malicious

    log = tmp_path / "refusals-log.md"
    append_events(scanner.events, log_path=log)
    content = log.read_text(encoding="utf-8")
    # Raw control codes MUST NOT appear (terminal-injection guard).
    assert "\x1b" not in content, "raw ESC byte present — terminal injection"
    assert "\x07" not in content, "raw BEL byte present"
    assert "\x00" not in content, "raw NUL byte present"
    # Escaped form should be present so log is informative.
    assert "\\x1b" in content or "\\x1B" in content, "ESC not escaped"
    # Printable Unicode preserved.
    # (No specific Unicode test here; the printable subset is a separate concern.)


def test_render_includes_preceding_and_subsequent(tmp_path: Path, scanner: RefusalScanner) -> None:
    scanner.observe(_tool_use(1, "vulhub_lookup"))
    scanner.observe(_text(2, "I cannot assist with that."))
    scanner.scan_text(turn=2, text="I cannot assist with that.")
    scanner.observe(_tool_use(3, "give_up"))
    scanner.finalize(final_outcome_status="unresolvable", verify_passed=False)

    log = tmp_path / "refusals-log.md"
    append_events(scanner.events, log_path=log)
    content = log.read_text(encoding="utf-8")
    assert "Preceding turns" in content
    assert "Subsequent turns" in content
    assert "Retry classification" in content
    assert "vulhub_lookup" in content
    assert "give_up" in content


# -- Phase 67.0 TDD safety net ------------------------------------------------
# Phase 67 audit findings:
#  * issue #8 (severity 6): Pattern 8 ``r"\bI\s+apologize[,.]?\s+but\s+(I|this|that)\b"``
#    matches BENIGN apology+correction text (e.g. "I apologize, but I had a
#    typo in my last response — let me try again"). 67.1 will tighten the
#    regex to require a refusal keyword (cannot/won't/unable/decline) within
#    a short window after the trigger.
#  * issue #9 (severity 7): refusals-log.md is append-only with no rotation.
#    A long-running bench can grow it past 50 MB; 67.2 will rotate at 5 MB
#    boundary to refusals-log.md.1 (max 3 rotations kept).


def test_phase67_refusal_pattern8_no_falsepos_on_benign_explanations(
    scanner: RefusalScanner,
) -> None:
    """Phase 67.1 contract: 'I apologize, but I had a typo' is benign and
    must NOT be classified as a refusal.

    Pattern 8 today matches the structural shape ``I apologize, but I/this/that``
    without checking whether a refusal keyword (cannot/won't/unable/refuse)
    appears nearby. That produces false positives when the agent simply
    apologizes for an error and proceeds to fix it. The fix narrows
    Pattern 8's match to require a refusal keyword within a short window
    after the trigger.
    """
    benign_correction_texts = [
        "I apologize, but I had a typo in my previous response. Let me retry.",
        "I apologize, but that command needs a different argument; running again.",
        "I apologize, but this output is from the wrong file. Re-reading the right one.",
    ]
    for text in benign_correction_texts:
        event = scanner.scan_text(turn=1, text=text)
        assert event is None, (
            f"Pattern 8 false-positive on benign apology+correction: {text!r}"
        )
