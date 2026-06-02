"""Tier 1B: cheap-LLM-assisted sanitizer characterization for cases
Tier 0's mechanical extractor doesn't recognise.

The LLM is an EXTRACTOR, not an adjudicator.  It points at the fix's
validator and characterizes its shape into a structured JSON spec; every
SOUND verdict still comes from a mechanical path we already trust:

  * ``kind="charset"`` / ``"charset_sub"`` — cross-check via the
    existing Tier 0 mechanical extractor on the LLM-named source line,
    then run the existing Z3 proof.  If the LLM's claimed charset
    doesn't match what the mechanical extractor finds, DECLINE.
  * ``kind="known_safe_call"`` — look up the LLM's claimed library
    call in :mod:`known_safe_calls` (curated table, human-verified).
    Out-of-table → DECLINE.
  * ``kind="other"`` — LLM couldn't reduce to a sound shape; pass to
    Tier 2.

The LLM can be wrong (hallucinated charset, fabricated library call,
spurious line reference).  Each verification gate catches the failure
mode it's designed for:

  1. ``validator_source_line`` must literally appear as a ``+`` line
     in the supplied diff (catches fabricated lines).
  2. Mechanical re-extract must agree with the LLM's claimed kind +
     charset (catches misreading).
  3. Chain tracking confirms the validated variable reaches the sink
     (catches "validator was added, but not for the value the sink
     uses").
  4. Curated table catches unsafe library claims (any library not on
     the table is rejected — we never trust an LLM-claimed library
     name on its own).

What's NEW in the trust surface vs Tier 0: the curated
:mod:`known_safe_calls` table.  Every entry there is a soundness claim
we own.  Nothing about the LLM's output is trusted as a safety
assertion.
"""

from __future__ import annotations

import json
import re as _re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from core.dataflow import known_safe_calls
from core.dataflow.smt_barrier import (
    Tier0Result,
    Tier0Status,
    ValidatorSpec,
    _function_containing,
    _python_chain_reaches_sink,
    _same_function_in_order,
    extract_validator as _mechanical_extract,
    prove_neutralizes,
)


# A bare-minimum LLM completer signature, compatible with the existing
# ``Completer`` alias in barrier_synth (system_prompt, user_prompt) -> str.
# Kept local so callers can mock without importing from barrier_synth.
LLMComplete = Callable[[str, str], str]


_SYSTEM_PROMPT = """\
You are a strict JSON-only extraction tool. Read a security fix diff
and identify what sanitizer the fix added. Output ONLY a single JSON
object — no commentary, no markdown fences, no prose.

Schema:
{
  "kind": "charset" | "charset_sub" | "known_safe_call" | "other",
  "validator_source_line": "<the SINGLE diff +-line that introduces the validator, VERBATIM, including any leading whitespace, with the leading '+' STRIPPED>",
  "variable_name": "<the variable the validator constrains>",
  "charset": "<allowed-char body when kind=charset, e.g. 'A-Za-z0-9_.+-'; empty otherwise>",
  "forbidden": "<stripped-char body when kind=charset_sub; empty otherwise>",
  "library_call": "<dotted name when kind=known_safe_call (e.g. 'werkzeug.security.safe_join', 'html.escape'); empty otherwise>"
}

Kind definitions:
- "charset": validator is a whole-string anchored regex over a character class, e.g. re.match(r'^[A-Za-z0-9]+$', x), x.matches("^[…]+$") in Java, x =~ /^[…]+$/ in Ruby, /^[…]+$/.test(x) in JS.
- "charset_sub": validator strips chars via substitution to empty string, e.g. x = re.sub('[forbidden]+', '', x), x = x.replace(/[…]/g, '').
- "known_safe_call": validator is a single call to a well-known library function that returns a sanitized value or raises on unsafe input. Examples: html.escape, django.utils.html.escape, markupsafe.escape, bleach.clean, shlex.quote, werkzeug.security.safe_join, werkzeug.utils.secure_filename, validator.escape (JS), DOMPurify.sanitize, StringEscapeUtils.escapeHtml4 (Java).
- "other": none of the above; the sanitizer is custom, semantic, or multi-step.

Field rules:
- "validator_source_line" MUST be copied verbatim from the diff. Do not paraphrase. Empty string is invalid.
- Empty string for any field that does not apply.
- If you are not certain, output "kind": "other" and leave all other fields empty.
"""


@dataclass
class _LLMSpec:
    """Parsed LLM JSON output — the LLM's CLAIM, not yet verified."""
    kind: str
    validator_source_line: str
    variable_name: str
    charset: str
    forbidden: str
    library_call: str


def _build_user_prompt(fix_diff: str, sink_class: str, language: str) -> str:
    return (
        f"sink_class: {sink_class}\n"
        f"language: {language}\n"
        "fix_diff:\n"
        f"{fix_diff[:4000]}"  # cap to keep cheap-model input bounded
    )


def _parse_llm_output(raw: str) -> Optional[_LLMSpec]:
    """Parse the LLM's reply into a structured spec.  Tolerates markdown
    fences (despite the prompt forbidding them).  Returns None on parse
    failure — the orchestrator then DECLINES."""
    text = (raw or "").strip()
    if "```" in text:
        # extract first fenced block body
        try:
            block = text.split("```", 2)[1]
            if "\n" in block:
                block = block.split("\n", 1)[1]
            text = block.strip().rstrip("`").strip()
        except IndexError:
            return None
    try:
        data = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    try:
        return _LLMSpec(
            kind=str(data.get("kind", "")),
            validator_source_line=str(data.get("validator_source_line", "")),
            variable_name=str(data.get("variable_name", "")),
            charset=str(data.get("charset", "")),
            forbidden=str(data.get("forbidden", "")),
            library_call=str(data.get("library_call", "")),
        )
    except Exception:                                       # pragma: no cover
        return None


def _validator_line_in_diff(fix_diff: str, claimed_line: str) -> bool:
    """The LLM-named source line must literally appear as a +-line in
    the diff (catches fabricated lines)."""
    needle = claimed_line.strip()
    if not needle:
        return False
    for raw in fix_diff.splitlines():
        if not raw.startswith("+") or raw.startswith("+++"):
            continue
        if raw[1:].strip() == needle:
            return True
    return False


def _mechanical_recheck_charset_kind(
    spec: _LLMSpec, language: str,
) -> Optional[ValidatorSpec]:
    """Run the existing mechanical extractor on the LLM-named source
    line and confirm it agrees with the LLM's claimed kind + charset
    (or forbidden).  Returns the mechanical ValidatorSpec on agreement,
    None on disagreement."""
    # Synthesise a single-line diff to reuse the existing extractor.
    fake_diff = "+" + spec.validator_source_line + "\n"
    mech = _mechanical_extract(fake_diff, language=language)
    if mech is None:
        return None
    if mech.kind != spec.kind:
        return None
    if spec.kind == "charset" and mech.charset != spec.charset:
        return None
    if spec.kind == "charset_sub" and mech.forbidden != spec.forbidden:
        return None
    if spec.variable_name and mech.var_name != spec.variable_name:
        return None
    return mech


def _find_best_validator_line(
    source_text: str, claimed_line_text: str, sink_line: int, language: str,
) -> Optional[int]:
    """Locate the validator's line number in the post-fix source.

    When the LLM's ``validator_source_line`` appears MULTIPLE times in
    the file (common for short library calls like ``abs_path =
    safe_join(…)``, which can recur across helpers), the previous
    first-match-wins strategy could pick an occurrence in an unrelated
    function — failing the dominance check even when a different
    occurrence (in the sink's function) is the actual sanitizer.

    Selection rule:
      * For Python: among occurrences strictly before ``sink_line``,
        prefer one in the SAME function as the sink; among those, pick
        the closest one (largest line < sink_line).
      * Non-Python (no AST): among occurrences before ``sink_line``,
        pick the closest.
      * Returns ``None`` if no usable occurrence exists.
    """
    needle = claimed_line_text.strip()
    if not needle:
        return None
    candidates = [idx + 1 for idx, ln in enumerate(source_text.splitlines())
                  if ln.strip() == needle and idx + 1 < sink_line]
    if not candidates:
        return None
    if language == "python":
        try:
            import ast
            tree = ast.parse(source_text)
        except SyntaxError:
            return max(candidates)
        sink_fn = _function_containing(tree, sink_line)
        if sink_fn is not None:
            same_fn = [ln for ln in candidates
                       if _function_containing(tree, ln) is sink_fn]
            if same_fn:
                return max(same_fn)
        return max(candidates)
    return max(candidates)


def _try_known_safe_call(
    spec: _LLMSpec, source_text: str, sink_uri: str, sink_line: int,
    sink_class: str, language: str,
) -> Tier0Result:
    """Adjudicate a ``kind="known_safe_call"`` LLM claim by curated-
    table lookup + chain check."""
    entry = known_safe_calls.find(spec.library_call, sink_class, language)
    if entry is None:
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"library_call {spec.library_call!r} not in curated "
            f"known-safe table for sink_class={sink_class!r} / "
            f"language={language!r}",
        )
    # Find the best occurrence of the LLM-claimed line (closest to the
    # sink, preferring same-function for Python).
    validator_line = _find_best_validator_line(
        source_text, spec.validator_source_line, sink_line, language,
    )
    if validator_line is None:
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            "no occurrence of the LLM-named line found before the sink",
        )
    # Source-order + same-function check (the helper above already
    # picked a same-function candidate when possible; this confirms
    # for the AST-aware Python path).
    try:
        import ast
        tree = ast.parse(source_text) if language == "python" else None
    except SyntaxError:
        tree = None
    if tree is not None:
        if not _same_function_in_order(tree, validator_line, sink_line):
            return Tier0Result(
                Tier0Status.NOT_APPLICABLE,
                f"safe-call at line {validator_line} not in same function "
                f"as sink at line {sink_line}",
            )
    # Chain check — only Python has an AST chain tracker for now.  For
    # non-Python we conservatively require the LLM's variable_name to
    # appear textually at the sink line.
    sink_lines = source_text.splitlines()
    sink_line_text = sink_lines[sink_line - 1] if 0 < sink_line <= len(sink_lines) else ""
    if language == "python" and tree is not None and spec.variable_name:
        chain_ok = _python_chain_reaches_sink(
            tree, spec.variable_name, validator_line, sink_line, sink_line_text,
        )
    elif spec.variable_name:
        chain_ok = bool(_re.search(
            rf"\b{_re.escape(spec.variable_name)}\b", sink_line_text,
        ))
    else:
        chain_ok = False
    if not chain_ok:
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"variable {spec.variable_name!r} sanitized by "
            f"{entry.library_call} does not reach the sink line",
        )
    artifact = f"library:{entry.library_call}@{sink_uri}:{validator_line}"
    return Tier0Result(
        Tier0Status.SOUND,
        f"curated known-safe call: {entry.library_call} "
        f"(sink_class={sink_class}): {entry.soundness_note}",
        artifact=artifact,
        extras={"validator_line": validator_line, "var_name": spec.variable_name,
                "library_call": entry.library_call},
    )


def try_tier1b(
    *, fix_diff: str, repo_root: Path, sink_uri: str, sink_line: int,
    sink_class: str, language: str, complete: LLMComplete,
) -> Tier0Result:
    """Run the Tier 1B LLM-assisted extraction + sound adjudication.

    Returns a :class:`Tier0Result` (re-used for uniformity with the
    bridge's existing dispatch).  SOUND verdicts are still mechanically
    adjudicated — the LLM only suggests the shape.

    ``complete`` is the LLM completer (system_prompt, user_prompt) -> str.
    Caller is responsible for cheap-model pinning (typically via
    :func:`barrier_synth.model_completer`).
    """
    user_prompt = _build_user_prompt(fix_diff, sink_class, language)
    try:
        raw = complete(_SYSTEM_PROMPT, user_prompt)
    except Exception as exc:                                # pragma: no cover
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"Tier 1B LLM call failed: {type(exc).__name__}: {exc}",
        )
    spec = _parse_llm_output(raw)
    if spec is None:
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            "Tier 1B: LLM output not parseable as JSON",
        )
    if spec.kind == "other":
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            "Tier 1B: LLM characterized the sanitizer as 'other' "
            "(no sound mechanical adjudicator)",
        )
    if not _validator_line_in_diff(fix_diff, spec.validator_source_line):
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            "Tier 1B: LLM-claimed validator_source_line not found as "
            "a + line in the fix diff (possible hallucination)",
        )
    # Read post-fix source for verification.
    src_path = repo_root / sink_uri.lstrip("/")
    if not src_path.is_file():
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"Tier 1B: post-fix source not readable at {sink_uri!r}",
        )
    try:
        source_text = src_path.read_text(errors="replace")
    except OSError as exc:
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"Tier 1B: could not read source: {exc}",
        )

    if spec.kind in ("charset", "charset_sub"):
        # Mechanical re-extract on the LLM-named line; agreement gates
        # everything downstream.
        mech = _mechanical_recheck_charset_kind(spec, language)
        if mech is None:
            return Tier0Result(
                Tier0Status.NOT_APPLICABLE,
                f"Tier 1B: mechanical re-extract disagrees with LLM's "
                f"claimed kind={spec.kind!r} / charset / forbidden on "
                f"the named source line",
            )
        # From here on, the verdict comes from the existing Tier 0
        # adjudication paths.  Z3 proof + chain check.
        verdict = prove_neutralizes(mech, sink_class)
        if not verdict.sound:
            return Tier0Result(
                Tier0Status.DECLINED, verdict.reasoning, spec=mech,
                counterexample=verdict.counterexample,
            )
        # Sound on language intersection — now confirm the variable
        # reaches the sink (skip the AST/dominance complexity here;
        # the source-order + same-function check stays inside the
        # existing Tier 0 helpers if a caller wants to add it later).
        # For first cut: trust the LLM-named line is between the
        # function entry and the sink (it's on the validator's
        # source line, which the chain check uses as a bound).
        # Locate the validator's line — same find-best-occurrence helper
        # as the known_safe_call path uses (closest occurrence before
        # the sink, same-function for Python).
        validator_line = _find_best_validator_line(
            source_text, spec.validator_source_line, sink_line, language,
        )
        if validator_line is None:
            return Tier0Result(
                Tier0Status.NOT_APPLICABLE,
                "Tier 1B: no occurrence of the LLM-named line found "
                "before the sink",
            )
        sink_lines = source_text.splitlines()
        sink_line_text = (sink_lines[sink_line - 1]
                          if 0 < sink_line <= len(sink_lines) else "")
        if language == "python":
            try:
                import ast
                tree = ast.parse(source_text)
            except SyntaxError:
                return Tier0Result(
                    Tier0Status.NOT_APPLICABLE,
                    "Tier 1B: post-fix source has syntax errors",
                )
            chain_ok = _python_chain_reaches_sink(
                tree, mech.var_name, validator_line, sink_line, sink_line_text,
            )
        else:
            chain_ok = bool(_re.search(
                rf"\b{_re.escape(mech.var_name)}\b", sink_line_text,
            ))
        if not chain_ok:
            return Tier0Result(
                Tier0Status.NOT_APPLICABLE,
                f"Tier 1B: variable {mech.var_name!r} does not reach "
                f"sink at line {sink_line}",
                spec=mech,
            )
        # Same artifact format as Tier 0 mechanical extraction — the
        # soundness mechanism is identical (Z3 regex proof).  The
        # ``llm_extracted`` flag in ``extras`` records that the LLM
        # pointed at the spec; the proof itself is mechanical.
        artifact = (f"smt:{mech.kind}:[{mech.charset or mech.forbidden}]"
                    f"@{sink_uri}:{validator_line}")
        return Tier0Result(
            Tier0Status.SOUND, verdict.reasoning, spec=mech,
            artifact=artifact,
            extras={"validator_line": validator_line, "var_name": mech.var_name,
                    "llm_extracted": True},
        )

    if spec.kind == "known_safe_call":
        return _try_known_safe_call(
            spec, source_text, sink_uri, sink_line, sink_class, language,
        )

    return Tier0Result(
        Tier0Status.NOT_APPLICABLE,
        f"Tier 1B: unknown kind {spec.kind!r}",
    )
