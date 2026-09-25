"""Replay-determinism eval harness: frozen-transcript case runner.

Runs the /analyze classification loop hermetically from a recorded
LLM transcript (``core.llm.transcript`` replay mode — no LLM
dispatch, no credentials, no spend by construction; the transport
availability probe client construction otherwise issues is suppressed
by the harness) and compares the verdicts that come back against the
case's pinned expectations.

Case bundle contract (one directory per case)::

    <case>/
      llm-transcript.jsonl     recorded trail (RAPTOR_LLM_TRANSCRIPT=
                               record:<path> during a live run)
      findings.json            list of finding dicts in the parsed-
                               SARIF shape process_findings consumes
      expected-verdicts.json   {finding_id: {field: value, ...}} —
                               every listed field must match the
                               replayed record's analysis verbatim
      repo/                    optional target source snapshot; when
                               absent the loop runs against an empty
                               directory (subject-layer transcript
                               matching tolerates the prompt drift)

The private case corpus lives under ``core/audit/corpus/replay-cases``
— machinery ships in-tree, case content is supplied locally and never
committed (same convention as the corpus ``labels/`` and per-channel
micro-corpora). Runners without that content skip with notice; the
CI lane records the skip against its skip-count budget.

Failure contract: every drift class raises :class:`ReplayEvalFailure`
with a bounded report — verdict drift (a listed expectation field
mismatches), a replay miss (the loop issued a call the transcript
cannot serve; ``TranscriptReplayer.misses`` is checked even though
per-finding error handling swallows the raised miss into an
error-status record), and leftover entries (the loop issued FEWER
calls than the recorded run — a stage silently skipped). Case text
quoted into failure reports is escaped and bounded: transcripts and
findings derive from scanned-target material.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import unittest.mock as mock
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

#: Local-only case corpus home (content never committed).
CASES_DIR = REPO / "core" / "audit" / "corpus" / "replay-cases"

_TRANSCRIPT_NAME = "llm-transcript.jsonl"
_FINDINGS_NAME = "findings.json"
_EXPECTED_NAME = "expected-verdicts.json"

#: Bound on any case-derived text quoted into a failure report.
_REPORT_VALUE_CHARS = 200


class ReplayEvalFailure(AssertionError):
    """A replay-eval case failed (drift, miss, or leftover)."""


def discover_cases(cases_dir: Path = CASES_DIR) -> list[Path]:
    """Case directories under *cases_dir*: any directory carrying a
    transcript file. Sorted for deterministic parametrisation."""
    if not cases_dir.is_dir():
        return []
    return sorted(
        p.parent for p in cases_dir.rglob(_TRANSCRIPT_NAME)
        if p.is_file()
    )


def _bounded(value: Any) -> str:
    from core.security.log_sanitisation import escape_nonprintable

    text = escape_nonprintable(str(value))
    if len(text) > _REPORT_VALUE_CHARS:
        text = text[:_REPORT_VALUE_CHARS] + "…[elided]"
    return text


def _load_json(path: Path) -> Any:
    if not path.is_file():
        raise ReplayEvalFailure(
            f"case file missing: {path} — a replay case needs "
            f"{_TRANSCRIPT_NAME}, {_FINDINGS_NAME} and {_EXPECTED_NAME}"
        )
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ReplayEvalFailure(f"case file unreadable: {path}: {exc}") from exc


@dataclass
class CaseResult:
    """What one replayed case produced (for determinism assertions)."""

    verdicts: dict[str, dict[str, Any]]
    misses: int
    leftover: int


@contextlib.contextmanager
def _hermetic_loop_env(tmp_dir: Path, transcript: Path) -> Iterator[None]:
    """Ambient-state isolation for one loop run: replay-mode
    transcript session, LLM cache off (HMAC key confined to a tmp
    XDG_DATA_HOME), no scorecard sidecar writes — the conventions of
    the transcript acceptance test, packaged for the case runner.

    Also pre-satisfies the transport-detection cache: client
    construction otherwise issues a live availability probe (an HTTP
    GET to the configured local-model host) that, while never a
    dispatch and never a spend, would make the run network-dependent.
    """
    import core.llm.detection as detection
    from core.llm.client import LLMClient
    from core.llm.transcript import reset_active_transcript

    env = {
        "RAPTOR_LLM_TRANSCRIPT": f"replay:{transcript}",
        "RAPTOR_LLM_CACHE": "off",
        "XDG_DATA_HOME": str(tmp_dir / "xdg-data"),
    }
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.dict(os.environ, env))
        stack.enter_context(mock.patch.object(
            LLMClient, "flush_usage_to_scorecard",
            lambda self, **kwargs: None,
        ))
        stack.enter_context(mock.patch.object(
            detection, "_ollama_checked", True,
        ))
        stack.enter_context(mock.patch.object(
            detection, "_cached_ollama_models", [],
        ))
        reset_active_transcript()
        try:
            yield
        finally:
            reset_active_transcript()


def run_analysis_loop(
    repo_path: Path,
    out_dir: Path,
    findings: list[dict[str, Any]],
    make_client: Callable[[Any], Any],
) -> dict[str, dict[str, Any]]:
    """Drive ``process_findings`` hermetically over *findings*.

    ``make_client`` receives the agent module's ``LLMConfig`` class's
    module namespace indirectly — it is called with no arguments and
    must return the LLM client the loop should use (a replay client
    from ``build_llm_client``, or a recording client in the synthetic
    fixtures). Collaborators with side effects outside the loop
    (source-intel priming subprocesses, SAGE store hooks, SARIF
    parsing) are stubbed exactly like the transcript acceptance test.
    Returns finding_id -> its full result record.
    """
    import core.sage.hooks as hooks
    import packages.llm_analysis.agent as agent_mod
    import packages.llm_analysis.source_intel_inject as sii

    availability = mock.MagicMock()
    availability.external_llm = False
    availability.claude_code = True
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch(
            "packages.llm_analysis.agent.detect_llm_availability",
            return_value=availability,
        ))
        stack.enter_context(mock.patch.object(
            sii, "prepare_source_intel", lambda *a, **k: None,
        ))
        stack.enter_context(mock.patch.object(
            hooks, "recall_prior_finding_verdict", lambda *a, **k: None,
        ))
        stack.enter_context(mock.patch.object(
            hooks, "store_finding_verdict", lambda *a, **k: False,
        ))
        stack.enter_context(mock.patch.object(
            agent_mod, "parse_sarif_findings", lambda _p: list(findings),
        ))
        stack.enter_context(mock.patch.object(
            agent_mod, "deduplicate_findings", lambda fs: fs,
        ))
        agent = agent_mod.AutonomousSecurityAgentV2(
            repo_path=repo_path,
            out_dir=out_dir,
            prep_only=True,
            synthesise_checkers=False,
            generate_exploits=False,
            generate_patches=False,
            verify_exploits=False,
            use_verified_exemplars=False,
        )
        client = make_client()
        agent.llm = client
        agent.llm_config = client.config
        report = agent.process_findings(
            sarif_paths=["replay-case.sarif"], checklist=None,
            emit_journal=False,
        )
    return {rec["finding_id"]: rec for rec in report["results"]}


def run_replay_case(case_dir: Path, tmp_dir: Path) -> CaseResult:
    """Replay one case bundle and enforce its expectations.

    Raises :class:`ReplayEvalFailure` on verdict drift, any replay
    miss, or leftover transcript entries. *tmp_dir* hosts the run's
    scratch output (and the empty stand-in repo when the case ships
    no ``repo/`` snapshot).
    """
    from core.llm.config import LLMConfig
    from core.llm.transcript import TranscriptLLMClient, build_llm_client

    transcript = case_dir / _TRANSCRIPT_NAME
    if not transcript.is_file():
        raise ReplayEvalFailure(f"case file missing: {transcript}")
    findings = _load_json(case_dir / _FINDINGS_NAME)
    expected = _load_json(case_dir / _EXPECTED_NAME)
    if not isinstance(findings, list) or not isinstance(expected, dict):
        raise ReplayEvalFailure(
            f"case {case_dir.name}: {_FINDINGS_NAME} must be a list and "
            f"{_EXPECTED_NAME} an object"
        )

    repo_path = case_dir / "repo"
    if not repo_path.is_dir():
        repo_path = tmp_dir / "empty-repo"
        repo_path.mkdir(parents=True, exist_ok=True)

    client_box: list[TranscriptLLMClient] = []

    def make_client() -> TranscriptLLMClient:
        client = build_llm_client(
            LLMConfig(primary_model=None, fallback_models=[]),
        )
        if not isinstance(client, TranscriptLLMClient):
            raise ReplayEvalFailure(
                "replay session did not activate — build_llm_client "
                "returned a plain client despite RAPTOR_LLM_TRANSCRIPT"
            )
        client_box.append(client)
        return client

    with _hermetic_loop_env(tmp_dir, transcript):
        records = run_analysis_loop(
            repo_path, tmp_dir / "out", findings, make_client,
        )

    if not client_box:
        # The loop died before reaching client construction — red
        # either way, but name the actual failure instead of an
        # IndexError from the harness itself.
        raise ReplayEvalFailure(
            f"replay case {_bounded(case_dir.name)}: the analysis loop "
            f"failed before constructing the replay client"
        )
    client = client_box[0]
    session = client.transcript_session
    failures: list[str] = []

    for finding_id, fields in sorted(expected.items()):
        record = records.get(finding_id)
        if record is None:
            failures.append(
                f"expected finding {_bounded(finding_id)} produced no "
                f"result record"
            )
            continue
        if record.get("status") == "error":
            failures.append(
                f"finding {_bounded(finding_id)} errored: "
                f"{_bounded(record.get('error'))}"
            )
            continue
        analysis = record.get("analysis") or {}
        for field, want in fields.items():
            got = analysis.get(field)
            if got != want:
                failures.append(
                    f"verdict drift on {_bounded(finding_id)}."
                    f"{_bounded(field)}: expected {_bounded(want)}, "
                    f"replayed {_bounded(got)}"
                )

    if session.misses:
        failures.append(
            f"{len(session.misses)} transcript replay miss(es) — the "
            f"loop issued calls the recorded trail cannot serve"
        )
    leftover = session.leftover_report()["leftover"]
    if leftover:
        failures.append(
            f"{leftover} transcript entr(ies) never replayed — the "
            f"loop issued fewer calls than the recorded run"
        )
    # Replay is incapable of dispatch by construction; pin it anyway.
    if client.providers or client.total_cost:
        failures.append("replay run constructed a provider or spent money")

    if failures:
        raise ReplayEvalFailure(
            f"replay case {_bounded(case_dir.name)} failed:\n  "
            + "\n  ".join(failures)
        )
    return CaseResult(
        verdicts={
            fid: dict(rec.get("analysis") or {})
            for fid, rec in records.items()
        },
        misses=len(session.misses),
        leftover=leftover,
    )
