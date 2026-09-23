"""Tier 1B: cheap-LLM-assisted sanitizer characterization for cases
Tier 0's mechanical extractor doesn't recognise.

The LLM is an EXTRACTOR, not an adjudicator.  It points at the fix's
validator and characterizes its shape into a structured JSON spec; every
SOUND verdict still comes from a mechanical path we already trust:

  * ``kind="charset"`` / ``"charset_sub"`` — cross-check via the
    existing Tier 0 mechanical extractor on the LLM-named source line,
    then run the existing Z3 proof.  If the LLM's claimed charset
    doesn't match what the mechanical extractor finds, the claim is
    rejected with ``NOT_APPLICABLE`` (``DECLINED`` is reserved for a
    completed-but-unsound Z3 proof).
  * ``kind="known_safe_call"`` — look up the LLM's claimed library
    call in :mod:`known_safe_calls` (curated table, human-verified).
    Out-of-table → rejected with ``NOT_APPLICABLE``.
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
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from core.dataflow import known_safe_calls
from core.dataflow.smt_barrier import (
    Tier0Result,
    Tier0Status,
    ValidatorSpec,
    _crosses_function_boundary,
    _function_containing,
    code_view_lines,
    _lexical_validator_in_branch,
    _python_chain_reaches_sink,
    _lexical_var_reaches_sink,
    _sanitizer_tails_for_spec_kind,
    _same_function_in_order,
    _validator_in_branch,
    prove_neutralizes,
    split_source_lines,
    substitution_dominates_sink,
    validator_dominates_sink,
)
from core.dataflow.smt_barrier import (
    extract_validator as _mechanical_extract,
)
from core.paths import confine
from core.llm.coerce import extract_fenced_code

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


def _parse_llm_output(raw: str) -> _LLMSpec | None:
    """Parse the LLM's reply into a structured spec.  Tolerates markdown
    fences (despite the prompt forbidding them).  Returns None on parse
    failure — the orchestrator then DECLINES."""
    text = extract_fenced_code(raw)
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
    except Exception:  # noqa: BLE001 — hostile JSON values; never raise here
        return None


def _validator_line_in_diff(fix_diff: str, claimed_line: str) -> bool:
    """The LLM-named source line must literally appear as a +-line in
    the diff (catches fabricated lines)."""
    needle = claimed_line.strip()
    if not needle:
        return False
    for raw in split_source_lines(fix_diff):
        if not raw.startswith("+") or raw.startswith("+++"):
            continue
        if raw[1:].strip() == needle:
            return True
    return False


def _mechanical_recheck_charset_kind(
    spec: _LLMSpec, language: str,
) -> ValidatorSpec | None:
    """Run the existing mechanical extractor on the LLM-named source
    line and confirm it agrees with the LLM's claimed kind + charset
    (or forbidden).  Returns the mechanical ValidatorSpec on agreement,
    None on disagreement."""
    # Synthesise a single-line diff to reuse the existing extractor.
    # Stripped to match _validator_line_in_diff's whitespace-insensitive
    # comparison — the anti-fabrication check and the re-extract must
    # see the same rendering of the LLM's claimed line.
    fake_diff = "+" + spec.validator_source_line.strip() + "\n"
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
) -> int | None:
    """Locate the validator's line number in the post-fix source.

    When the LLM's ``validator_source_line`` appears MULTIPLE times in
    the file (common for short library calls like ``abs_path =
    safe_join(…)``, which can recur across helpers), the previous
    first-match-wins strategy could pick an occurrence in an unrelated
    function — failing the dominance check even when a different
    occurrence (in the sink's function) is the actual sanitizer.

    Selection rule:
      * Occurrences are anchored against the comment/string-blanked
        view of the file (same rule as ``find_validator_line``): a
        line whose text lives inside a block comment or a multi-line
        string is prose — binding to it would hand the dominance and
        chain gates a decoy location (CVE fix diffs routinely carry
        commented-out old sanitizer lines as ``+`` lines, and the
        cheap LLM is pointed at the diff). Unlike Tier 0's per-line
        re-extraction this lane's needles (e.g. curated safe calls)
        have no extractor, so the anchor is positional: the
        candidate's first code character must survive in the view.
        Fails CLOSED — a missing or short view line reads as prose.
      * For Python: among code occurrences strictly before
        ``sink_line``, prefer one in the SAME function as the sink;
        among those, pick the closest one (largest line < sink_line).
      * Non-Python (no AST): among code occurrences before
        ``sink_line``, pick the closest.
      * Returns ``None`` if no usable occurrence exists.
    """
    needle = claimed_line_text.strip()
    if not needle:
        return None
    view = code_view_lines(source_text, language)
    candidates = []
    for idx, ln in enumerate(split_source_lines(source_text)):
        if ln.strip() != needle or idx + 1 >= sink_line:
            continue
        first = len(ln) - len(ln.lstrip())
        view_ln = view[idx] if idx < len(view) else None
        if (view_ln is None or first >= len(view_ln)
                or view_ln[first] == " "):
            continue
        candidates.append(idx + 1)
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


def _line_invokes_library_call(
    line: str, library_call: str, variable: str,
    *, require_variable_in_args: bool = False,
) -> bool:
    """Verify the LLM-claimed ``library_call`` actually appears on the
    claimed line as a call, applied to (or assigned from) the claimed
    variable.

    Gate 1 only proves the line EXISTS in the diff — an LLM can point
    at any real added line (a log statement, a comment-adjacent
    assignment) and claim it is ``shlex.quote``.  Without this check
    the curated-table lookup adjudicates a call that never happens.

    ``require_variable_in_args=True`` (validate-kind entries) drops
    the assigned-from fallback: a validate-kind chain starts DIRECTLY
    from the claimed variable, so accepting ``safe = raw; ok =
    ipcheck(z)`` for variable ``safe`` — bound on the line but never
    an argument of (nor bound from) the call — would certify SOUND
    for a value the validator never constrained.  Transform-kind
    callers keep the fallback: their chain start is re-derived from
    the actual binding targets, so a mis-attributed variable here is
    harmless.
    """
    tail = library_call.rsplit(".", maxsplit=1)[-1]
    lib_parts = library_call.split(".")
    # \b pin: unanchored, every position inside a long dotted-name
    # run starts a fresh scan of the line tail — quadratic; a
    # mid-word start is never a real callee name.
    for m in _re.finditer(r"\b([A-Za-z_][\w.]*)\s*\(", line):
        name_parts = m.group(1).split(".")
        if name_parts[-1] != tail:
            continue
        # The dotted name on the line must be a suffix of the claimed
        # library call (``quote(``, ``shlex.quote(`` both match
        # ``shlex.quote``; ``os.quote(`` does not).
        if name_parts != lib_parts[-len(name_parts):]:
            continue
        # Argument span of this call.
        depth = 0
        arg_start = m.end() - 1
        arg_end = len(line)
        for k in range(arg_start, len(line)):
            if line[k] == "(":
                depth += 1
            elif line[k] == ")":
                depth -= 1
                if depth == 0:
                    arg_end = k
                    break
        args = line[arg_start + 1:arg_end]
        if not variable:
            # No variable claim to bind — the later chain check
            # rejects the empty variable anyway; call presence is all
            # this gate can verify.
            return True
        if _re.search(rf"\b{_re.escape(variable)}\b", args):
            return True
        if (not require_variable_in_args
                and _re.match(rf"\s*{_re.escape(variable)}\s*=", line)):
            return True
    return False


def _value_calls_tail(value, tail: str) -> bool:
    """True iff ``value``'s subtree contains a call whose callee name
    (bare or attribute) is ``tail``.  Pre-filter only — binding
    decisions use :func:`_value_is_call_result` (the value must BE the
    call, not merely contain it)."""
    import ast
    return any(
        isinstance(c, ast.Call)
        and isinstance(c.func, (ast.Name, ast.Attribute))
        and (c.func.id if isinstance(c.func, ast.Name)
             else c.func.attr) == tail
        for c in ast.walk(value)
    )


def _value_is_call_result(value, tail: str) -> bool:
    """True iff ``value`` IS a call to ``tail`` — not merely contains
    one.  The subtree form credited containers and selects that mix
    the raw input around the sanitized element
    (``p = [escape(x), x]``, ``p = q, r = escape(x), x``,
    ``{...: escape(x), ...: x}[flag]``) with a fully-sanitized
    binding (false SOUND).  Parentheses/annotations are transparent at
    the AST level; anything else refuses — refusing costs yield,
    never soundness."""
    import ast
    if not isinstance(value, ast.Call):
        return False
    func = value.func
    if isinstance(func, ast.Name):
        return func.id == tail
    if isinstance(func, ast.Attribute):
        return func.attr == tail
    return False


def _paired_transform_targets(target, value, tail: str) -> set[str]:
    """Names whose paired value IS the transform call, matched
    element-wise through tuple/list structure.

    A tuple co-assignment binds each target element to its
    corresponding VALUE element — ``escaped, raw = html.escape(x), x``
    binds ``raw`` to the RAW input, so collecting every target name of
    the statement handed the chain a variable the transform never
    touched (false SOUND).  Only the element whose paired value IS the
    call joins (a value that merely CONTAINS the call — a container
    literal, a chained-target tuple, a subscript select — mixes raw
    input around the sanitized element); when the pairing cannot be
    established (starred targets, non-tuple RHS for a tuple target,
    length mismatch) the whole target contributes nothing — refusing
    costs yield, never soundness."""
    import ast
    if isinstance(target, ast.Name):
        return {target.id} if _value_is_call_result(value, tail) else set()
    if isinstance(target, (ast.Tuple, ast.List)):
        if (
            isinstance(value, (ast.Tuple, ast.List))
            and len(value.elts) == len(target.elts)
            and not any(isinstance(t, ast.Starred) for t in target.elts)
        ):
            out: set[str] = set()
            for t_elt, v_elt in zip(target.elts, value.elts):
                out |= _paired_transform_targets(t_elt, v_elt, tail)
            return out
        return set()
    # Starred / Attribute / Subscript: nothing the chain can follow.
    return set()


def _lexical_binding_segments(line: str) -> list[str]:
    """Split a lexical-language source line into per-binding segments:
    on ``;`` (statement joins) and on top-level ``,`` (declarator
    lists).  Commas nested inside brackets or string literals never
    split.  Over-splitting only narrows a segment — the capture and
    the call must co-reside in one segment — so the crude split errs
    toward refusal, never toward crediting."""
    segments: list[str] = []
    buf: list[str] = []
    depth = 0
    quote: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote is not None:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(line):
                buf.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
            buf.append(ch)
        elif ch in "([{":
            depth += 1
            buf.append(ch)
        elif ch in ")]}":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch in ";," and depth == 0:
            segments.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    segments.append("".join(buf))
    return segments


def _transform_binding_targets(
    tree, source_text: str, validator_line: int, library_call: str,
) -> set[str]:
    """Plain-Name targets the transform call's result is bound to on
    the claimed line — empty when the result is discarded or bound to
    nothing the chain tracker can follow (attribute/subscript)."""
    import ast
    tail = library_call.rsplit(".", maxsplit=1)[-1]
    targets: set[str] = set()
    if tree is not None:
        for node in ast.walk(tree):
            if getattr(node, "lineno", None) != validator_line:
                continue
            if not isinstance(
                node, (ast.Assign, ast.AnnAssign, ast.NamedExpr),
            ):
                continue
            value = getattr(node, "value", None)
            if value is None:
                continue
            if not _value_calls_tail(value, tail):
                continue
            node_targets = (list(node.targets)
                            if isinstance(node, ast.Assign)
                            else [node.target])
            for t in node_targets:
                targets |= _paired_transform_targets(t, value, tail)
        return targets
    # Lexical languages: accept ``x = ...call(...)`` (with optional
    # const/let/var/final or a type before the name).  Statement
    # segments are split on ``;`` AND on top-level ``,`` and the
    # capture + call-presence test applied PER SEGMENT: on a
    # semicolon-joined line (``var safe = x; var y = sanitize(x);``)
    # or a multi-declarator list (``var safe = x, y = sanitize(x);``)
    # the call must sit in the SAME binding as the captured target,
    # otherwise the FIRST target (bound to the raw value) was credited
    # with a transform that belongs to a later binding.  Commas inside
    # brackets (call arguments, literals) and string literals do not
    # split; a delimiter inside a string literal only narrows a
    # segment further — it can never join two statements — so the
    # crude split errs toward refusal.
    lines = split_source_lines(source_text)
    if not (0 < validator_line <= len(lines)):
        return set()
    line = lines[validator_line - 1]
    out: set[str] = set()
    for segment in _lexical_binding_segments(line):
        m = _re.match(
            r"\s*(?:(?:const|let|var|final)\s+)?"
            r"(?:[A-Za-z_$][\w$<>\[\].]*\s+)?"
            r"([A-Za-z_$][\w$]*)\s*=[^=]",
            segment,
        )
        if m and _re.search(rf"\b{_re.escape(tail)}\s*\(", segment[m.end():]):
            out.add(m.group(1))
    return out


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
    if not _line_invokes_library_call(
            spec.validator_source_line, spec.library_call,
            spec.variable_name,
            require_variable_in_args=(entry.input_arg_kind == "validate")):
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"Tier 1B: claimed library call {spec.library_call!r} does "
            f"not appear on the claimed source line applied to "
            f"{spec.variable_name!r} (possible hallucination)",
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
    tree = None
    if language == "python":
        try:
            import ast
            tree = ast.parse(source_text)
        except SyntaxError:
            # Refuse, never degrade: every dominance gate below
            # (same-function, binding-target, branch) is conditioned
            # on `tree is not None` for Python, so carrying on with
            # tree=None silently certified with ALL gates skipped —
            # one syntax error anywhere in the file (common in py2 /
            # newer-syntax corpora, and plantable in a scanned repo)
            # disabled dominance for every known-safe-call
            # certification in it. Same behaviour as the tier1b
            # extraction lane's parse refusal below.
            return Tier0Result(
                Tier0Status.NOT_APPLICABLE,
                "post-fix source has syntax errors — Python dominance "
                "gates unavailable for a known-safe-call certification",
            )
    if tree is not None and not _same_function_in_order(
            tree, validator_line, sink_line):
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"safe-call at line {validator_line} not in same function "
            f"as sink at line {sink_line}",
        )
    if language != "python" and _crosses_function_boundary(
            source_text, validator_line, sink_line, language):
        # Same gate try_tier0 applies: without a per-language AST a
        # source-order check alone would let a safe-call in helper A
        # "dominate" a sink in helper B.
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"safe-call at line {validator_line} is separated from the "
            f"sink at line {sink_line} by a function boundary",
        )
    # Transform-kind entries return the sanitized VALUE: the chain
    # must start from what the call's result is BOUND to, never from
    # the input argument — ``safe = html.escape(name); render(name)``
    # (mis-bound) and a bare ``html.escape(name)`` (discarded) both
    # leave raw ``name`` at the sink, the exact incomplete-fix class
    # this gate exists to catch (the curated-table contract says "the
    # return value (or a name assigned from it)"). Validate-kind
    # entries constrain the input itself, so the LLM's variable stays
    # the chain start there — sound ONLY because the table contract
    # requires validate-kind calls to RAISE on bad input (a
    # sentinel-returning validator leaves the raw input live and must
    # be classed transform; see the KnownSafeCall docstring and the
    # werkzeug.security.safe_join precedent).
    chain_vars: set[str] = (
        {spec.variable_name} if spec.variable_name else set()
    )
    if entry.input_arg_kind == "transform":
        chain_vars = _transform_binding_targets(
            tree, source_text, validator_line, spec.library_call,
        )
        if not chain_vars:
            return Tier0Result(
                Tier0Status.NOT_APPLICABLE,
                f"Tier 1B: {entry.library_call} result at line "
                f"{validator_line} is not bound to a variable the "
                f"chain can follow — a discarded transform sanitizes "
                f"nothing",
            )
    # Chain check — only Python has an AST chain tracker for now.  For
    # non-Python we conservatively require the chain variable to
    # appear textually at the sink line.
    sink_lines = split_source_lines(source_text)
    sink_line_text = sink_lines[sink_line - 1] if 0 < sink_line <= len(sink_lines) else ""
    if language == "python" and tree is not None:
        # The sanitizing binding on the validator line is exactly the
        # curated call — name it so the chain walker exempts ONLY that
        # binding node, never the whole line.
        tail_set = frozenset({entry.library_call.rsplit(".", 1)[-1]})
        chain_ok = any(
            _python_chain_reaches_sink(
                tree, var, validator_line, sink_line, sink_line_text,
                sanitizer_call_tails=tail_set,
            )
            for var in chain_vars
        )
    else:
        chain_ok = any(
            _lexical_var_reaches_sink(
                var, source_text, validator_line, sink_line,
                sink_line_text,
            )
            for var in chain_vars
        )
    if not chain_ok:
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"variable {sorted(chain_vars) or [spec.variable_name]!r} "
            f"sanitized by "
            f"{entry.library_call} does not reach the sink line",
        )
    if (language == "python" and tree is not None and chain_vars
            and _validator_in_branch(tree, validator_line, sink_line)):
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"safe-call at line {validator_line} does not dominate "
            f"sink (conditional branch)",
        )
    # Conditional-execution gate for the non-Python languages: without
    # it a branch-wrapped sanitizer (``if (opts.clean) { name =
    # validator.escape(name); } res.send(name)``) certified SOUND while
    # the flow is live whenever the branch is skipped — breaking the
    # sound tier's zero-false-suppression guarantee.
    if language != "python" and _lexical_validator_in_branch(
            source_text, validator_line, sink_line, language=language):
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"safe-call at line {validator_line} not proven to execute "
            f"unconditionally before the sink (branch-wrapped or "
            f"tracker-inconclusive)",
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
    except Exception as exc:  # noqa: BLE001 — any LLM failure = DECLINE
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
    # Read post-fix source for verification.  Containment-checked via
    # the shared chokepoint: ``sink_uri`` arrives verbatim from
    # finding/corpus records (cvefix_bridge threads it from the
    # diff/finding shape), so a crafted ``..`` segment would walk the
    # read outside ``repo_root`` and adjudicate a barrier against an
    # arbitrary host file.  Same defence as the rest of the arc
    # (``finding_resolver._read_finding_source``,
    # ``injection_prescreen._read_source``).
    src_path = confine(repo_root, sink_uri.lstrip("/"))
    if src_path is None:
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"Tier 1B: sink path {sink_uri!r} resolves outside the "
            f"repo root — refusing to read it",
        )
    if not src_path.is_file():
        return Tier0Result(
            Tier0Status.NOT_APPLICABLE,
            f"Tier 1B: post-fix source not readable at {sink_uri!r}",
        )
    try:
        source_text = src_path.read_text(encoding="utf-8", errors="replace")
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
        # reaches the sink (chain check below), and for Python also
        # that the validator dominates the sink via the Tier 0
        # AST helpers (validator_dominates_sink /
        # substitution_dominates_sink), bailing to NOT_APPLICABLE
        # when the validator is advisory or the variable reassigned.
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
        if language != "python" and _crosses_function_boundary(
                source_text, validator_line, sink_line, language):
            # Same gate try_tier0 applies to its non-Python path: the
            # source-order check alone would let a validator in helper
            # A "dominate" a sink in helper B when both live in the
            # same file — the validator's exit-on-fail returns from A,
            # not B.
            return Tier0Result(
                Tier0Status.NOT_APPLICABLE,
                f"Tier 1B: validator at line {validator_line} is "
                f"separated from the sink at line {sink_line} by a "
                f"function boundary",
                spec=mech,
            )
        if language != "python" and _lexical_validator_in_branch(
                source_text, validator_line, sink_line,
                guard_shaped=(mech.kind == "charset"), language=language):
            # Same conditional-execution gate the known_safe_call path
            # applies: a branch-wrapped sanitizer certifies SOUND while
            # the flow is live whenever the branch is skipped. For the
            # guard form the guard's own exit-on-fail block is exempt.
            return Tier0Result(
                Tier0Status.NOT_APPLICABLE,
                f"Tier 1B: validator at line {validator_line} not "
                f"proven to execute unconditionally before the sink "
                f"(branch-wrapped or tracker-inconclusive)",
                spec=mech,
            )
        sink_lines = split_source_lines(source_text)
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
                sanitizer_call_tails=_sanitizer_tails_for_spec_kind(
                    mech.kind),
            )
        else:
            chain_ok = _lexical_var_reaches_sink(
                mech.var_name, source_text, validator_line, sink_line,
                sink_line_text,
            )
        if not chain_ok:
            return Tier0Result(
                Tier0Status.NOT_APPLICABLE,
                f"Tier 1B: variable {mech.var_name!r} does not reach "
                f"sink at line {sink_line}",
                spec=mech,
            )
        if language == "python" and source_text:
            if mech.kind == "charset_sub":
                dominates = substitution_dominates_sink(
                    source_text, validator_line, sink_line, mech.var_name,
                )
            else:
                dominates = validator_dominates_sink(
                    source_text, validator_line, sink_line,
                )
            if not dominates:
                return Tier0Result(
                    Tier0Status.NOT_APPLICABLE,
                    f"Tier 1B: validator at line {validator_line} does "
                    f"not dominate sink (advisory or reassigned)",
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
