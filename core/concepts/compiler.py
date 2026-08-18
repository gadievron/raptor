"""Concept compiler — turn semantic invariants into mechanical rules.

Takes Invariant objects from the domain model and compiles them into
Semgrep/Coccinelle rules via the checker_synthesis substrate.  The LLM
is prompted to detect VIOLATIONS of an invariant (its negation) rather
than variants of a specific bug.

Three-phase study pipeline:
  Phase 1: mechanical prep (raptor-study-prep)
  Phase 2: LLM concept extraction (study.py)
  Phase 3: rule compilation — THIS MODULE

Reuses checker_synthesis's grammar grounding, engine selection, and
dual control validation.  Only the prompt framing differs.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.concepts.model import CONFIDENCE_GRADES, DomainModel, Invariant

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Result
# ------------------------------------------------------------------

@dataclass
class CompilationResult:
    """Output of compiling one invariant into a mechanical rule."""

    invariant_id: str
    engine: str | None = None
    rule_id: str | None = None
    rule_body: str = ""
    rule_path: Path | None = None
    rationale: str = ""
    dual_control: bool = False
    matches: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return bool(self.rule_body) and self.dual_control

    def to_dict(self) -> dict[str, Any]:
        return {
            "invariant_id": self.invariant_id,
            "engine": self.engine,
            "rule_id": self.rule_id,
            "rule_body": self.rule_body,
            "rule_path": str(self.rule_path) if self.rule_path else None,
            "rationale": self.rationale,
            "dual_control": self.dual_control,
            "matches": self.matches,
            "errors": self.errors,
        }


# ------------------------------------------------------------------
# Prompt construction
# ------------------------------------------------------------------

_INVARIANT_SYSTEM_BASE = (
    "You are a security analyst compiling a semantic invariant into a "
    "static analysis rule.  The invariant describes a property that must "
    "hold throughout a codebase.  Your rule must detect VIOLATIONS — code "
    "where the invariant does NOT hold.\n\n"
    "The rule must:\n"
    "  1. Be tight enough to match real violations, not every call to "
    "the relevant API.\n"
    "  2. Focus on the NEGATION — what the violation looks like "
    "structurally.\n"
    "  3. Be syntactically valid for the chosen engine.\n"
    "  4. Come with test fixtures — a minimal violating snippet that "
    "MUST match (test_positive) and a minimal conforming snippet that "
    "must NOT match (test_negative).\n\n"
    "Static analysis rules can only capture structural patterns, not "
    "full semantic properties.  Focus on the most common structural "
    "shape of the violation.  If the invariant is too abstract to "
    "express as a structural pattern, say so in the rationale and "
    "produce the closest approximation."
)


def _invariant_system_for_engine(engine: str) -> str:
    from packages.checker_synthesis.grammars import (
        COCCINELLE_GRAMMAR,
        SEMGREP_GRAMMAR,
    )
    grammars = {"coccinelle": COCCINELLE_GRAMMAR, "semgrep": SEMGREP_GRAMMAR}
    grammar = grammars.get(engine)
    if grammar:
        return _INVARIANT_SYSTEM_BASE + "\n\n" + grammar
    return _INVARIANT_SYSTEM_BASE


def build_invariant_prompt(
    inv: Invariant,
    engine: str,
    retry_feedback: str = "",
    source_snippets: list[str] | None = None,
    *,
    model_id: str = "",
) -> tuple[str, str]:
    """Build the enveloped synthesis prompt for an invariant violation
    rule.  Returns ``(user, system)``.

    The invariant's statement / negation / description / evidence are
    LLM-derived from target code and the source snippets are target
    code — all travel in untrusted envelope blocks; the invariant id
    and CWE list ride in slots; task instructions stay in the system
    text.

    *source_snippets*: optional list of code excerpts showing known
    violation sites.  Giving the LLM real code dramatically improves
    the structural accuracy of the generated rule.
    """
    from core.security.prompt_defense_profiles import (
        CONSERVATIVE,
        get_profile_for,
    )
    from core.security.prompt_envelope import (
        TaintedString,
        UntrustedBlock,
        build_prompt,
    )

    parts = [
        _invariant_system_for_engine(engine),
        "",
        f"INVARIANT TO COMPILE ({engine})",
        "",
        ("The invariant's statement, violation (negation), context, and "
         "evidence arrive as untrusted blocks; its id and relevant CWEs "
         "are in the slots."),
    ]
    if source_snippets:
        parts += [
            "",
            ("Source code showing known violation(s) arrives in the "
             "untrusted violation-source blocks."),
        ]
    parts += [
        "",
        "TASK:",
        f"Output a {engine} rule that detects VIOLATIONS of this invariant.",
        ("The rule should match code where the invariant is broken — the "
         "negation pattern described in the invariant-negation block."),
        "",
        "Focus on the structural shape of the violation.",
        "",
        "RULE DESIGN PRINCIPLES:",
        "  1. Your rule's first pattern should match a SINGLE STATEMENT",
        "     — the API call or operation.  Use pattern-not-inside to",
        "     exclude properly guarded instances.",
        "  2. Do NOT write multi-line patterns that match both a call",
        "     AND a subsequent use/dereference.  Sub-expressions like",
        "     *$PTR or $PTR[$IDX] are NOT statements and silently fail",
        "     to match in statement position.",
        "  3. For 'missing guard' (CWE-476, CWE-252): match the call",
        "     site, exclude with pattern-not-inside for the guard.",
        "  4. For 'repeated operation' (CWE-415): match two consecutive",
        "     occurrences with ellipsis between them.",
        "  5. For 'wrong argument': match the call with the wrong form,",
        "     exclude with pattern-not for the correct form.",
    ]
    if engine == "semgrep":
        parts += [
            "",
            "SEMGREP — use pattern mode (patterns: / pattern:), NOT taint",
            "mode (mode: taint).  Missing checks, double free, format",
            "string — these are all local structural patterns.  Taint",
            "mode is ONLY for cross-function source-to-sink data flow.",
            "For C/C++: ALWAYS include trailing semicolons in multi-line",
            "patterns.  `$PTR = malloc(...)` without a semicolon in",
            "pattern-not-inside causes mis-parsing and false suppression.",
        ]
    # The fixture language must match the extension the dual-control
    # oracle executes the fixtures under (_fixture_ext) — a C fixture
    # run as .py parses as the wrong language and rejects valid rules.
    fixture_ext = _fixture_ext(inv, engine)
    fixture_lang = _fixture_language(fixture_ext)
    if fixture_lang:
        fixture_desc = f"parseable {fixture_lang} code"
    else:
        fixture_desc = f"parseable code for a {fixture_ext} source file"
    header_note = (
        " — no #include headers" if fixture_lang in ("C", "C++") else ""
    )
    parts += [
        "",
        (f"Provide two test fixtures (each 5-20 lines of complete, "
         f"{fixture_desc}{header_note}):"),
        ("  - test_positive: minimal snippet VIOLATING the invariant "
         "(rule MUST match).  Must contain exactly the structural shape "
         "the rule detects."),
        ("  - test_negative: minimal snippet CONFORMING to the invariant "
         "(rule must NOT match).  Must differ from test_positive in "
         "exactly the way the rule checks — e.g. adds the missing guard, "
         "removes the duplicate call, uses a literal instead of a variable."),
        "",
        ('Respond with JSON: {"rule_body": "...", "rationale": "...", '
         '"test_positive": "...", "test_negative": "..."}.'),
    ]
    if retry_feedback:
        parts += [
            "",
            ("RETRY — the previous attempt failed; the failure detail "
             "arrives as an untrusted retry-feedback block. Refine the "
             "rule, don't regenerate from scratch."),
        ]

    blocks = [
        UntrustedBlock(
            content=inv.statement or "",
            kind="invariant-statement",
            origin=inv.id,
        ),
        UntrustedBlock(
            content=inv.negation or "",
            kind="invariant-negation",
            origin=inv.id,
        ),
    ]
    if inv.description:
        blocks.append(UntrustedBlock(
            content=inv.description,
            kind="invariant-context",
            origin=inv.id,
        ))
    if inv.evidence:
        ev_lines = [f"  - {e}" for e in inv.evidence[:5]]
        if len(inv.evidence) > 5:
            ev_lines.append(f"  ... ({len(inv.evidence) - 5} more)")
        blocks.append(UntrustedBlock(
            content="Evidence (sites where the invariant holds):\n"
                    + "\n".join(ev_lines),
            kind="invariant-evidence",
            origin=inv.id,
        ))
    for snip in (source_snippets or [])[:3]:
        blocks.append(UntrustedBlock(
            content=snip[:4096].rstrip(),
            kind="violation-source",
            origin=inv.id,
        ))
    if retry_feedback:
        blocks.append(UntrustedBlock(
            content=retry_feedback,
            kind="retry-feedback",
            origin="synthesis-harness",
        ))

    slots = {
        "invariant_id": TaintedString(value=inv.id or "", trust="untrusted"),
    }
    if inv.relevant_cwes:
        slots["relevant_cwes"] = TaintedString(
            value=", ".join(inv.relevant_cwes), trust="untrusted",
        )

    profile = get_profile_for(model_id) if model_id else CONSERVATIVE
    bundle = build_prompt(
        system="\n".join(parts),
        profile=profile,
        untrusted_blocks=tuple(blocks),
        slots=slots,
    )
    user = "\n\n".join(
        m.content for m in bundle.messages if m.role == "user"
    )
    system_text = next(
        (m.content for m in bundle.messages if m.role == "system"), "",
    )
    return user, system_text


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _slugify(value: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_.")
    return s[:60] or "x"


def _make_rule_id(inv: Invariant, engine: str, attempt: int) -> str:
    return f"inv.{_slugify(inv.id)}.{engine}.{attempt}"


def _fixture_ext(inv: Invariant, engine: str) -> str:
    """File extension for dual-control test fixtures."""
    if engine == "coccinelle":
        return ".c"
    for ev in inv.evidence:
        ev_file = ev.split(":")[0].strip() if ":" in ev else ""
        if ev_file:
            suffix = Path(ev_file).suffix.lower()
            if suffix:
                return suffix
    return ".py"


# Prompt-facing language name per fixture extension.  Keyed to what
# _fixture_ext can return; kept aligned with the engine extension sets
# in packages.checker_synthesis.languages.
_EXT_LANGUAGE: dict[str, str] = {
    ".c": "C", ".h": "C",
    ".cpp": "C++", ".cc": "C++", ".cxx": "C++", ".c++": "C++",
    ".hpp": "C++", ".hh": "C++", ".hxx": "C++",
    ".py": "Python", ".pyi": "Python",
    ".java": "Java",
    ".go": "Go",
    ".js": "JavaScript", ".jsx": "JavaScript",
    ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".php": "PHP",
    ".cs": "C#",
    ".kt": "Kotlin", ".kts": "Kotlin",
    ".scala": "Scala",
    ".swift": "Swift",
    ".lua": "Lua",
    ".ex": "Elixir", ".exs": "Elixir",
}


def _fixture_language(ext: str) -> str | None:
    """Language name for a fixture extension, or None if unknown."""
    return _EXT_LANGUAGE.get(ext.lower())


def _infer_engine(inv: Invariant) -> str:
    """Pick engine from invariant evidence file extensions."""
    from packages.checker_synthesis.languages import detect_engine
    for ev in inv.evidence:
        ev_file = ev.split(":")[0].strip() if ":" in ev else ""
        detected = detect_engine(ev_file) if ev_file else None
        if detected:
            return detected
    return "semgrep"


# ------------------------------------------------------------------
# Driver adapters (proposer + oracle for the generate-and-verify loop)
# ------------------------------------------------------------------

class _InvariantProposer:
    """Wraps the LLM call as a Proposer for the driver."""

    def __init__(self, llm, inv, engine, source_snippets):
        self._llm = llm
        self._inv = inv
        self._engine = engine
        self._source_snippets = source_snippets

    def propose(self, context, feedback, *, prior_verdict=None):
        from packages.checker_synthesis.prompts import SYNTHESIS_SCHEMA

        # The builder folds the engine-specific system base into the
        # returned system text (with envelope priming).
        prompt, system = build_invariant_prompt(
            self._inv, self._engine, retry_feedback=feedback,
            source_snippets=self._source_snippets,
        )
        try:
            return self._llm(prompt, SYNTHESIS_SCHEMA, system)
        except Exception as exc:
            raise ValueError(f"LLM error: {exc}") from exc


class _DualControlOracle:
    """Validates, builds, and dual-control tests a proposed rule."""

    reliability_class = "decisive"

    def __init__(self, inv, engine, out_dir):
        self._inv = inv
        self._engine = engine
        self._out_dir = out_dir
        self._call_count = 0

    def judge(self, candidate, context):
        from core.orchestration.driver import Verdict
        from packages.checker_synthesis.models import SynthesisedRule
        from packages.checker_synthesis.synthesise import (
            _dual_control,
            _fixup_cocci_body,
            _validate_rule_body,
            _write_rule,
        )

        self._call_count += 1

        if not isinstance(candidate, dict):
            return Verdict(passed=False, feedback="LLM returned non-dict")

        body = candidate.get("rule_body", "")
        if not isinstance(body, str) or not body.strip():
            return Verdict(passed=False, feedback="missing rule_body")

        body_err = _validate_rule_body(body)
        if body_err:
            return Verdict(passed=False, feedback=body_err)

        if self._engine == "coccinelle":
            body = _fixup_cocci_body(body)

        rule_id = _make_rule_id(self._inv, self._engine, self._call_count - 1)
        test_pos = str(candidate.get("test_positive", "") or "")
        test_neg = str(candidate.get("test_negative", "") or "")
        rationale = str(candidate.get("rationale", "") or "")

        rule = SynthesisedRule(
            engine=self._engine, rule_id=rule_id, body=body,
            rationale=rationale, test_positive=test_pos,
            test_negative=test_neg,
        )
        rule_path = _write_rule(self._out_dir, rule)

        evidence = {
            "rule_id": rule_id, "body": body,
            "rule_path": rule_path, "rationale": rationale,
        }

        ext = _fixture_ext(self._inv, self._engine)
        if not test_pos or not test_neg:
            return Verdict(
                passed=False,
                feedback="no test fixtures for dual control",
                evidence=evidence,
            )

        dc_ok, dc_errors = _dual_control(rule, rule_path, self._engine, ext)
        if dc_ok:
            return Verdict(passed=True, evidence=evidence)

        dc_feedback = "; ".join(e for e in dc_errors if "dual control:" in e)
        return Verdict(
            passed=False, feedback=dc_feedback,
            evidence={**evidence, "dc_errors": dc_errors},
        )


# ------------------------------------------------------------------
# Core compilation
# ------------------------------------------------------------------

def compile_invariant(
    inv: Invariant,
    engine: str,
    llm: Any,
    out_dir: Path,
    *,
    repo_root: Path | None = None,
    max_retries: int = 1,
    max_sweep_matches: int = 50,
    source_snippets: list[str] | None = None,
) -> CompilationResult:
    """Compile a single invariant into a mechanical rule.

    If *repo_root* is given, sweeps the codebase for matches after
    dual control passes.  *source_snippets*: code excerpts of known
    violation sites — dramatically improves rule quality.
    """
    from core.orchestration.driver import DriverConfig
    from core.orchestration.driver import run as driver_run

    result = CompilationResult(invariant_id=inv.id, engine=engine)

    if not inv.statement or not inv.negation:
        result.errors.append("invariant needs both statement and negation")
        return result

    proposer = _InvariantProposer(llm, inv, engine, source_snippets)
    oracle = _DualControlOracle(inv, engine, out_dir)

    dr = driver_run(
        proposer, oracle, {},
        config=DriverConfig(max_attempts=max_retries + 1),
    )

    result.errors.extend(dr.errors)

    if dr.verdict and dr.verdict.evidence:
        ev = dr.verdict.evidence
        result.rule_id = ev.get("rule_id")
        result.rule_body = ev.get("body", "")
        result.rule_path = ev.get("rule_path")
        result.rationale = ev.get("rationale", "")
        result.dual_control = dr.verdict.passed
        if "dc_errors" in ev:
            result.errors.extend(ev["dc_errors"])

    # Sweep only after dual control passes — rule_body is also
    # populated on dual-control failure (the last attempt's evidence),
    # and an unvalidated rule must not produce codebase matches.
    if result.dual_control and result.rule_body and repo_root and repo_root.is_dir():
        from packages.checker_synthesis.models import SynthesisedRule
        from packages.checker_synthesis.synthesise import _run_engine

        rule = SynthesisedRule(
            engine=engine,
            rule_id=result.rule_id or "sweep",
            body=result.rule_body,
        )
        matches, errors = _run_engine(rule, result.rule_path, repo_root)
        result.errors.extend(errors)
        for m in matches[:max_sweep_matches]:
            result.matches.append({
                "file": m.file,
                "line": m.line,
                "snippet": m.snippet or "",
            })
        if len(matches) > max_sweep_matches:
            result.errors.append(
                f"sweep capped at {max_sweep_matches} "
                f"(total: {len(matches)})"
            )

    return result


# ------------------------------------------------------------------
# Batch entry
# ------------------------------------------------------------------

def compile_model(
    model: DomainModel,
    out_dir: Path,
    llm: Any,
    *,
    repo_root: Path | None = None,
    engine: str | None = None,
    min_confidence: str = "traced",
    max_compilations: int = 10,
) -> list[CompilationResult]:
    """Compile all qualified invariants from a domain model.

    Filters to invariants at or above *min_confidence* that have
    both statement and negation.  Skips already-compiled invariants
    (those with ``mechanical_rule`` set).
    """
    try:
        min_idx = CONFIDENCE_GRADES.index(min_confidence)
    except ValueError:
        min_idx = 0

    candidates = []
    for inv in model.invariants:
        if inv.confidence not in CONFIDENCE_GRADES:
            continue
        if CONFIDENCE_GRADES.index(inv.confidence) < min_idx:
            continue
        if not inv.statement or not inv.negation:
            continue
        if inv.mechanical_rule:
            continue
        candidates.append(inv)

    from packages.checker_synthesis.languages import fallback_engine

    results: list[CompilationResult] = []
    for inv in candidates[:max_compilations]:
        inv_engine = engine or _infer_engine(inv)

        cr = compile_invariant(
            inv, inv_engine, llm, out_dir,
            repo_root=repo_root,
        )

        if not cr.success and not engine:
            ev_file = ""
            for ev in inv.evidence:
                if ":" in ev:
                    ev_file = ev.split(":")[0].strip()
                    break
            alt = fallback_engine(inv_engine, ev_file)
            if alt:
                logger.info(
                    "invariant %s: %s failed, trying %s",
                    inv.id, inv_engine, alt,
                )
                cr = compile_invariant(
                    inv, alt, llm, out_dir,
                    repo_root=repo_root,
                )

        results.append(cr)

        if cr.success:
            inv.mechanical_rule = cr.rule_id
            logger.info(
                "compiled invariant %s -> %s (%s)",
                inv.id, cr.rule_id, cr.engine,
            )

    manifest_path = out_dir / "compiled-invariants.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps([r.to_dict() for r in results], indent=2) + "\n",
        encoding="utf-8",
    )

    return results
