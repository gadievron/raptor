"""LLM-driven taint spec and safety-assumption synthesis.

Replaces the heuristic-only ``_iris_candidate_to_spec()`` in the audit
orchestrator.  The LLM reads candidate function source and classifies
each as source / sink / sanitiser / propagator / none, with taint
classes and parameter positions.

The second synthesis pass (``synthesise_assumptions``) reads sink and
sanitiser functions and extracts compositional safety assumptions —
preconditions that must hold for a function to be used safely.

The heuristic path remains as a fallback when the LLM is unavailable
or synthesis is disabled via ``RaptorConfig.IRIS_SYNTHESIS_ENABLED``.
"""

from __future__ import annotations

import logging
import re
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.evidence import EvidenceTier

from .assumptions import (
    AssumptionCategory,
    BypassFinding,
    SafetyAssumption,
    assumption_from_dict,
)
from .specs import CandidateFunction, TaintSpec, parse_spec_response

logger = logging.getLogger(__name__)

_SOURCE_MAX_LINES = 200
_MAX_BATCH = 20

_SYSTEM_PROMPT = """\
You are a taint-analysis expert classifying functions for dataflow tools.

For each function below, determine its taint role:
- **source**: introduces attacker-controlled data (user input, network, \
environment, file read from untrusted path)
- **sink**: dangerous operation that must not receive tainted data \
(command execution, SQL query, file write, deserialization)
- **sanitiser**: validates, escapes, or encodes tainted data, removing \
the taint for specific classes
- **propagator**: passes taint through without checking (wrappers, \
adapters, formatters)
- **none**: no taint relevance

Output a JSON array of objects.  One object per function.  Skip \
functions with role "none".

Each object:
```json
{
  "function": "<name>",
  "file": "<path>",
  "role": "source|sink|sanitiser|propagator",
  "taint_classes": ["sql", "xss", "cmd", "path", "deserialize", ...],
  "params_affected": [0, 1],
  "return_tainted": true,
  "confidence": 0.85
}
```

- ``taint_classes``: which vulnerability classes this function is \
relevant to.  Use short labels: sql, xss, cmd, path, deserialize, \
ssrf, ldap, xpath, ssti, header, redirect, crypto, log.
- ``params_affected``: zero-indexed parameter positions that carry \
taint (for sinks: which params are dangerous; for sources: which \
params receive tainted data; for sanitisers: which params are cleaned).
- ``return_tainted``: whether the return value carries taint.
- ``confidence``: 0.0–1.0, your confidence in the classification.

Be conservative: if uncertain, set confidence < 0.5 or omit the \
function.  False positives waste expensive tool re-runs.\
"""


@dataclass
class _Batch:
    candidates: list[CandidateFunction]
    sources: list[str]


class _BudgetExhaustedSkip(Exception):
    """Internal marker: batch skipped without an LLM call because the
    run budget is already exhausted (terminal — see
    ``core.llm.client.LLMBudgetExceededError``)."""


def _run_batches(
    batches: list[_Batch],
    do_batch: Any,
    llm_client: Any,
    *,
    label: str,
    on_error: Any | None = None,
) -> list[Any]:
    """Fan out *do_batch* over *batches* with budget-terminal semantics.

    ``LLMBudgetExceededError`` is a terminal contract for the run
    (see ``core.llm.client``): once one batch hits it, every further
    call is a guaranteed refusal.  On the first budget-exceeded error
    the loop stops submitting — the remaining batches skip their LLM
    call and go straight to *on_error* — and ONE warning reports the
    drop count, instead of each batch independently re-discovering
    the exhausted budget.  Other LLM errors keep per-batch drop
    semantics: transient failures legitimately differ per batch.

    When *llm_client* exposes ``is_budget_exhausted()`` it is polled
    before each batch, so a budget already spent by earlier pipeline
    stages (or an earlier synthesis leg) stops the loop before the
    first call.
    """
    from core.llm.client import is_budget_exceeded_error
    from core.llm.concurrency import run_parallel

    exhausted = threading.Event()
    lock = threading.Lock()
    skipped = [0]
    probe = getattr(llm_client, "is_budget_exhausted", None)

    def _fn(batch: _Batch) -> Any:
        if not exhausted.is_set() and callable(probe):
            try:
                if probe():
                    exhausted.set()
            except Exception:  # noqa: BLE001 — probe is best-effort
                pass
        if exhausted.is_set():
            raise _BudgetExhaustedSkip()
        return do_batch(batch)

    def _handle_error(batch: _Batch, exc: Exception) -> Any:
        if isinstance(exc, _BudgetExhaustedSkip):
            with lock:
                skipped[0] += 1
        elif is_budget_exceeded_error(exc):
            exhausted.set()
        return on_error(batch, exc) if on_error else None

    mw = getattr(llm_client, "recommended_max_workers", 1)
    results = run_parallel(
        batches, _fn,
        max_workers=mw,
        label=label,
        on_error=_handle_error,
    )
    if skipped[0]:
        logger.warning(
            "iris.synthesise: %s: budget exhausted, dropping remaining "
            "%d batch(es)", label, skipped[0],
        )
    return results


def synthesise_specs(
    candidates: list[CandidateFunction],
    llm_client: Any,
    *,
    target_path: Path | None = None,
    prior_specs: Sequence[TaintSpec] = (),
    feedback: dict[str, Any] | None = None,
    max_batch: int = _MAX_BATCH,
    source_max_lines: int = _SOURCE_MAX_LINES,
) -> list[TaintSpec]:
    """Synthesise taint specs by having the LLM read candidate source.

    Parameters
    ----------
    candidates:
        Functions identified as potential taint-relevant by
        ``identify_candidates()``.
    llm_client:
        An LLM client with a ``.chat()`` or compatible method.
        Expected to accept ``(system, user)`` message pairs and
        return a response string.
    target_path:
        Root of the target codebase for reading source files.
    prior_specs:
        Specs from a previous round or persistent store, included
        in the prompt as context.
    feedback:
        Refinement feedback from a previous round (see ``refine.py``).
    max_batch:
        Maximum candidates per LLM call.
    source_max_lines:
        Truncate each candidate's source to this many lines.

    Returns
    -------
    List of ``TaintSpec`` with ``evidence_tier=HEURISTIC`` and
    ``source="llm"``.
    """
    if not candidates:
        return []

    batches = _build_batches(
        candidates,
        target_path=target_path,
        max_batch=max_batch,
        source_max_lines=source_max_lines,
    )

    def _do_batch(batch: _Batch) -> list[TaintSpec]:
        user_prompt = _build_user_prompt(
            batch, prior_specs=prior_specs, feedback=feedback,
        )
        response = _call_llm(llm_client, _SYSTEM_PROMPT, user_prompt)
        specs = parse_spec_response(response)
        for spec in specs:
            spec.source = "llm"
            spec.evidence_tier = EvidenceTier.HEURISTIC
        return specs

    def _on_error(batch: _Batch, _exc: Exception) -> list[TaintSpec]:
        return list(_heuristic_fallback(batch.candidates))

    results = _run_batches(
        batches, _do_batch, llm_client,
        label="iris-synth",
        on_error=_on_error,
    )

    all_specs: list[TaintSpec] = []
    for specs in results:
        if specs:
            all_specs.extend(specs)

    logger.info(
        "iris.synthesise: %d specs from %d candidates (%d batches)",
        len(all_specs), len(candidates), len(batches),
    )
    return all_specs


def synthesise_specs_heuristic(
    candidates: list[CandidateFunction],
) -> list[TaintSpec]:
    """Name-heuristic fallback (no LLM).

    Moved from ``_iris_candidate_to_spec()`` in the audit orchestrator.
    """
    return _heuristic_fallback(candidates)


def _build_batches(
    candidates: list[CandidateFunction],
    *,
    target_path: Path | None,
    max_batch: int,
    source_max_lines: int,
) -> list[_Batch]:
    batches: list[_Batch] = []
    current_cands: list[CandidateFunction] = []
    current_srcs: list[str] = []

    for cand in candidates:
        source = _read_candidate_source(cand, target_path, source_max_lines)
        current_cands.append(cand)
        current_srcs.append(source)

        if len(current_cands) >= max_batch:
            batches.append(_Batch(current_cands, current_srcs))
            current_cands = []
            current_srcs = []

    if current_cands:
        batches.append(_Batch(current_cands, current_srcs))

    return batches


def _read_candidate_source(
    cand: CandidateFunction,
    target_path: Path | None,
    max_lines: int,
) -> str:
    """Read the candidate's source file, truncated."""
    if cand.source:
        lines = cand.source.splitlines()[:max_lines]
        return "\n".join(lines)

    if target_path is None:
        return f"# source unavailable for {cand.function} in {cand.file}"

    full_path = (target_path / cand.file).resolve()
    if not full_path.is_relative_to(target_path.resolve()):
        return f"# path outside target: {cand.file}"
    if not full_path.is_file():
        return f"# file not found: {cand.file}"

    try:
        text = full_path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        if (cand.line_start or 0) > 0 and (cand.line_end or 0) > 0:
            start = max(0, cand.line_start - 1)
            end = min(len(lines), cand.line_end)
            lines = lines[start:end]
        lines = lines[:max_lines]
        return "\n".join(lines)
    except OSError:
        return f"# read error: {cand.file}"


def _build_user_prompt(
    batch: _Batch,
    *,
    prior_specs: Sequence[TaintSpec],
    feedback: dict[str, Any] | None,
) -> str:
    parts: list[str] = []

    if prior_specs:
        prior_lines = [
            f"  {s.function} ({s.file}): {s.role} "
            f"[{', '.join(s.taint_classes)}]"
            for s in prior_specs
        ]
        parts.append(
            "Already-known project specs (for context, do not repeat):\n"
            + "\n".join(prior_lines)
        )

    if feedback:
        fb_lines = []
        confirmed = feedback.get("confirmed_keys", [])
        if confirmed:
            fb_lines.append(
                f"Previous round: {len(confirmed)} specs confirmed by tool."
            )
        refuted = feedback.get("refuted_keys", [])
        if refuted:
            fb_lines.append(
                f"Previous round: {len(refuted)} specs produced only "
                f"false positives — reconsider or drop these."
            )
        errors = feedback.get("tool_errors", [])
        if errors:
            fb_lines.append(
                f"Previous round: {len(errors)} specs caused tool "
                f"compilation errors."
            )
        cwe_gaps = feedback.get("cwe_gaps", [])
        if cwe_gaps:
            fb_lines.append(
                f"Low-quality CWE coverage (TP rate < 70%): "
                f"{', '.join(cwe_gaps)}.  Prioritise higher-confidence "
                f"specs for these classes or drop marginal candidates."
            )
        if fb_lines:
            parts.append("Refinement feedback:\n" + "\n".join(fb_lines))

    parts.append("Classify these functions:\n")
    # Function source (and inventory-derived names/reasons) come from
    # the target repo — neutralise envelope/role forgery before
    # interpolation.
    from core.security.prompt_envelope import neutralize_tag_forgery
    for cand, source in zip(batch.candidates, batch.sources, strict=False):
        parts.append(
            f"### {neutralize_tag_forgery(cand.function)} "
            f"({neutralize_tag_forgery(cand.file)})")
        if cand.reason:
            parts.append(
                f"Candidate reason: {neutralize_tag_forgery(cand.reason)}")
        parts.append(f"```\n{neutralize_tag_forgery(source)}\n```\n")

    return "\n\n".join(parts)


def _call_llm(client: Any, system: str, user: str) -> str:
    """Call the LLM client, adapting to available API shapes.

    Supports: ``generate(prompt, system_prompt)`` (core.llm.client),
    ``chat(system, user)``, ``complete(prompt)``, or bare callable.
    """
    if hasattr(client, "generate"):
        resp = client.generate(prompt=user, system_prompt=system,
                               task_type="iris")
        return resp.content
    if hasattr(client, "chat"):
        return client.chat(system=system, user=user)
    if hasattr(client, "complete"):
        return client.complete(f"{system}\n\n{user}")
    if callable(client):
        return client(system, user)
    raise TypeError(f"unsupported LLM client type: {type(client)}")


_SANITISER_KW = (
    "sanitize", "sanitise", "escape", "encode",
    "filter", "clean", "purify",
)
_SOURCE_KW = (
    "read", "recv", "fetch", "load",
    "input", "get_user", "getenv",
)
_SINK_KW = (
    "write", "send", "execute", "exec", "eval",
    "query", "system", "render", "emit",
)


def _heuristic_fallback(
    candidates: list[CandidateFunction],
) -> list[TaintSpec]:
    """Name-based role classification (no LLM)."""
    specs = []
    for cand in candidates:
        name = cand.function.lower()
        role = "propagator"
        if any(p in name for p in _SANITISER_KW):
            role = "sanitiser"
        elif any(p in name for p in _SOURCE_KW):
            role = "source"
        elif any(p in name for p in _SINK_KW):
            role = "sink"
        specs.append(TaintSpec(
            function=cand.function,
            file=cand.file,
            role=role,
            confidence=0.6 if cand.has_security_name else 0.4,
            evidence_tier=EvidenceTier.HEURISTIC,
            source="heuristic",
        ))
    return specs


# ── Assumption synthesis ──────────────────────────────────────────────

_ASSUMPTION_CATEGORIES = {c.value for c in AssumptionCategory}

_ASSUMPTION_SYSTEM_PROMPT = """\
You are a security analyst extracting safety assumptions from code.

For each function below, identify what must be true about its inputs \
or calling context for safe operation. Focus on assumptions that, if \
violated, produce a security vulnerability.

Categories (use exactly these values):
- sanitisation: data must be cleaned/escaped before use
- validation: data must satisfy bounds/format/type checks
- ordering: a function must have been called first (lock, auth, init)
- state: a runtime state precondition must hold
- type_constraint: data must not have been narrowed/widened unsafely
- provenance: data must come from a trusted source

Output a JSON array. One object per assumption. Skip functions with \
no security-relevant assumptions.

Each object:
```json
{
  "target": "<function name>",
  "file": "<file path>",
  "assumption": "<human-readable assumption>",
  "category": "sanitisation|validation|ordering|state|type_constraint|provenance",
  "enforced_by": ["<function(s) that enforce this assumption>"],
  "bug_class": "<CWE ID or short label>",
  "params_affected": [0],
  "confidence": 0.8,
  "underminer": "<function that defeats the enforcer, or null>"
}
```

Be conservative: only include assumptions where violation leads to a \
concrete security bug. Omit speculative or low-confidence entries.\
"""


def synthesise_assumptions(
    specs: list[TaintSpec],
    llm_client: Any,
    *,
    target_path: Path | None = None,
    bypass_findings: Sequence[BypassFinding] = (),
    source_max_lines: int = _SOURCE_MAX_LINES,
) -> list[SafetyAssumption]:
    """Extract safety assumptions from sink/sanitiser functions.

    This is the second synthesis pass — runs after taint spec
    synthesis.  Only functions with role ``sink`` or ``sanitiser``
    are analysed (they're the ones with exploitable preconditions).
    """
    sink_specs = [s for s in specs if s.role in ("sink", "sanitiser")]
    if not sink_specs:
        return []

    cands = [
        CandidateFunction(
            function=s.function,
            file=s.file,
            reason=f"taint role: {s.role}",
        )
        for s in sink_specs
    ]

    batches = _build_batches(
        cands,
        target_path=target_path,
        max_batch=_MAX_BATCH,
        source_max_lines=source_max_lines,
    )

    def _do_batch(batch: _Batch) -> list[SafetyAssumption]:
        user_prompt = _build_assumption_prompt(
            batch, bypass_findings=bypass_findings,
        )
        response = _call_llm(
            llm_client, _ASSUMPTION_SYSTEM_PROMPT, user_prompt,
        )
        return _parse_assumption_response(response)

    def _on_error(
        batch: _Batch, exc: Exception,
    ) -> list[SafetyAssumption]:
        # Unlike spec synthesis there is no heuristic fallback here —
        # the name heuristics produce TaintSpecs, not SafetyAssumptions
        # — so a failed batch degrades to no assumptions.  Log loudly:
        # run_parallel's default only records the failure at DEBUG.
        logger.warning(
            "iris.synthesise: assumption batch of %d function(s) "
            "dropped after LLM error: %s", len(batch.candidates), exc,
        )
        return []

    results = _run_batches(
        batches, _do_batch, llm_client,
        label="iris-assumptions",
        on_error=_on_error,
    )

    all_assumptions: list[SafetyAssumption] = []
    for assumptions in results:
        if assumptions:
            all_assumptions.extend(assumptions)

    logger.info(
        "iris.synthesise: %d assumptions from %d sink/sanitiser specs",
        len(all_assumptions), len(sink_specs),
    )
    return all_assumptions


def _build_assumption_prompt(
    batch: _Batch,
    *,
    bypass_findings: Sequence[BypassFinding] = (),
) -> str:
    parts: list[str] = []

    if bypass_findings:
        bp_lines = []
        for bf in bypass_findings[:20]:
            via = f" via {bf.via_intermediate}" if bf.via_intermediate else ""
            label = "ordering violation" if bf.ordering_violation else "missing enforcer"
            bp_lines.append(
                f"  {bf.caller_function} ({bf.caller_file}): "
                f"{label} for {bf.assumption.target}{via}"
            )
        parts.append(
            "Previous round found these bypass paths (refine or add "
            "assumptions to cover them):\n" + "\n".join(bp_lines)
        )

    parts.append(
        "Extract safety assumptions for these functions:\n"
    )
    from core.security.prompt_envelope import neutralize_tag_forgery
    for cand, source in zip(batch.candidates, batch.sources, strict=False):
        parts.append(
            f"### {neutralize_tag_forgery(cand.function)} "
            f"({neutralize_tag_forgery(cand.file)})")
        if cand.reason:
            parts.append(f"Context: {neutralize_tag_forgery(cand.reason)}")
        parts.append(f"```\n{neutralize_tag_forgery(source)}\n```\n")

    return "\n\n".join(parts)


def _parse_assumption_response(response: str) -> list[SafetyAssumption]:
    """Parse LLM response into SafetyAssumption objects."""
    from core.json.tolerant import parse_llm_json

    data, _diag = parse_llm_json(response)
    if data is None:
        logger.debug("iris.synthesise: assumption response not valid JSON")
        return []

    if not isinstance(data, list):
        data = [data]

    result: list[SafetyAssumption] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        if not item.get("target") or not item.get("assumption"):
            continue
        entry = dict(item)
        cat = entry.get("category", "")
        if cat not in _ASSUMPTION_CATEGORIES:
            cat = "sanitisation"
        entry["category"] = cat
        entry["evidence_tier"] = "heuristic"
        entry["source"] = "llm"
        try:
            result.append(assumption_from_dict(entry))
        except Exception:  # noqa: BLE001 — LLM-shaped item; skip, don't crash
            logger.debug("iris.synthesise: skipping malformed assumption item")
    return result


# ── Heuristic assumption generators (Phase D) ───────────────────────

_DB_WRITE_KW = re.compile(
    r"\b(insert|update|save|put|store|write|set|create|add)\b", re.IGNORECASE,
)
_DB_READ_KW = re.compile(
    r"\b(select|find|get|load|read|fetch|query|retrieve)\b", re.IGNORECASE,
)
_RENDER_KW = re.compile(
    r"\b(render|display|print|template|html|response\.write|inner_html|"
    r"dangerouslySetInnerHTML|v-html|mark_safe|Markup|format_html)\b",
    re.IGNORECASE,
)
_SANITISE_KW = re.compile(
    r"\b(escape|sanitize|sanitise|encode|bleach|clean|purify|strip_tags|"
    r"html_escape|markupsafe|cgi\.escape|html\.escape)\b",
    re.IGNORECASE,
)
_CONFIG_READ_KW = re.compile(
    r"\b(getenv|environ|config\[|config\.get|settings\.|"
    r"os\.environ|dotenv|cfg\[|cfg\.get|\.env)\b",
    re.IGNORECASE,
)
_SECURITY_DECISION_KW = re.compile(
    r"\b(auth|allow|deny|permit|grant|restrict|privilege|role|"
    r"admin|secret|key|token|password|csrf|cors|ssl|tls|verify)\b",
    re.IGNORECASE,
)


def _extract_storage_names(source: str) -> set[str]:
    """Pull table/model/cache names from source for writer/reader matching."""
    names: set[str] = set()
    for m in re.finditer(r"""['"]([A-Za-z_]\w{2,})['"]""", source):
        names.add(m.group(1).lower())
    return names


def stored_taint_assumptions(
    gaps: Sequence[dict[str, Any]],
) -> list[SafetyAssumption]:
    """Generate assumptions for persistence-layer stored-XSS patterns.

    For each gap that writes to persistence AND has a corresponding
    reader that renders without sanitisation, creates a SafetyAssumption
    with category=sanitisation, bug_class=CWE-79.
    """
    writers: list[dict[str, Any]] = []
    readers: list[dict[str, Any]] = []
    writer_storage: dict[str, set[str]] = {}
    reader_storage: dict[str, set[str]] = {}

    for gap in gaps:
        source = gap.get("source", "")
        if not source:
            continue
        key = f"{gap.get('file', '')}:{gap.get('name', '')}"
        if _DB_WRITE_KW.search(source):
            writers.append(gap)
            writer_storage[key] = _extract_storage_names(source)
        if _DB_READ_KW.search(source):
            readers.append(gap)
            reader_storage[key] = _extract_storage_names(source)

    if not writers or not readers:
        return []

    assumptions: list[SafetyAssumption] = []
    for reader in readers:
        rsource = reader.get("source", "")
        if not _RENDER_KW.search(rsource):
            continue
        rkey = f"{reader.get('file', '')}:{reader.get('name', '')}"
        rnames = reader_storage.get(rkey, set())
        if not rnames:
            continue

        for writer in writers:
            wkey = f"{writer.get('file', '')}:{writer.get('name', '')}"
            wnames = writer_storage.get(wkey, set())
            if not (wnames & rnames):
                continue

            sanitisers = [
                m.group(0) for m in _SANITISE_KW.finditer(rsource)
            ]
            if sanitisers:
                continue

            assumptions.append(SafetyAssumption(
                target=reader.get("name", ""),
                file=reader.get("file", ""),
                assumption=(
                    f"Data stored by {writer.get('name', '?')} must be "
                    f"sanitised before rendering"
                ),
                category=AssumptionCategory.SANITISATION,
                enforced_by=["escape", "sanitize", "sanitise", "html_escape"],
                bug_class="CWE-79",
                confidence=0.6,
                source="heuristic",
            ))
    return assumptions


def config_provenance_assumptions(
    gaps: Sequence[dict[str, Any]],
) -> list[SafetyAssumption]:
    """Generate assumptions for config-dependent security decisions.

    For each gap that reads configuration AND makes a security decision,
    creates a SafetyAssumption with category=provenance, bug_class=CWE-15.
    """
    assumptions: list[SafetyAssumption] = []
    for gap in gaps:
        source = gap.get("source", "")
        if not source:
            continue
        if not _CONFIG_READ_KW.search(source):
            continue
        if not _SECURITY_DECISION_KW.search(source):
            continue
        assumptions.append(SafetyAssumption(
            target=gap.get("name", ""),
            file=gap.get("file", ""),
            assumption=(
                f"{gap.get('name', '?')} reads external configuration "
                f"to make a security decision"
            ),
            category=AssumptionCategory.PROVENANCE,
            enforced_by=[],
            bug_class="CWE-15",
            confidence=0.5,
            source="heuristic",
        ))
    return assumptions
