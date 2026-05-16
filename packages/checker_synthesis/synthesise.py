"""Orchestration for KNighter checker synthesis.

Public API: ``synthesise_and_run(seed, repo_root, out_dir, llm,
**opts)`` returns a ``CheckerSynthesisResult`` documenting every
stage of the pipeline.

The LLM dependency is injected as a Protocol so tests can stub
without mocking the ``core.llm`` machinery. Production callers
pass an adapter around ``LLMClient.generate_structured``.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Tuple

from .languages import detect_engine
from .models import (
    CheckerSynthesisResult,
    Match,
    MatchTriage,
    SeedBug,
    SynthesisedRule,
)
from .prompts import (
    SYNTHESIS_SCHEMA,
    SYNTHESIS_SYSTEM,
    TRIAGE_SCHEMA,
    TRIAGE_SYSTEM,
    build_synthesis_prompt,
    build_triage_prompt,
)

logger = logging.getLogger(__name__)


# Hard upper bound on rule body size. An LLM that emits a 100KB
# YAML "rule" is misbehaving; refuse rather than feed it to the
# scanner. KNighter's published rules sit in the 0.5–4KB range.
_RULE_BODY_MAX_BYTES = 32_768

# Per-line ceiling on the rule body. A single multi-megabyte line
# can hang downstream YAML / spatch parsers without tripping the
# byte cap immediately. Real rule lines are short.
_RULE_BODY_MAX_LINE = 4_096

# Maximum size for ``seed.snippet`` plumbed into the LLM prompt.
# A 1MB snippet doesn't help synthesis — the LLM only needs the
# function's structural shape — and bloats prompt cost / context.
_SEED_SNIPPET_MAX_BYTES = 8_192

# Threshold above which the codebase scan triggers a "rule too
# loose" warning. The match cap still applies after this; the
# warning just tells operators (and /audit) the synthesised rule
# may need refinement before downstream triage.
_RULE_TOO_LOOSE_THRESHOLD = 200


def _validate_seed_path(file_path: str) -> Optional[str]:
    """Reject seed file paths that could escape ``repo_root`` or
    that would refer to an absolute location. Mirrors the defence
    in ``core.annotations`` — caller-supplied path that we then
    join with ``repo_root`` to read source.

    Returns an error string on rejection, or None if OK.
    """
    if not file_path:
        return "seed.file must be non-empty"
    if any(c in file_path for c in "\n\r\x00"):
        return "seed.file must not contain newline / null characters"
    p = Path(file_path)
    if p.is_absolute():
        return f"seed.file must be relative: {file_path!r}"
    if any(part == ".." for part in p.parts):
        return f"seed.file may not contain '..' segments: {file_path!r}"
    return None


def _validate_rule_body(body: str) -> Optional[str]:
    """Reject rule bodies with control chars or oversized lines.
    Returns an error string on rejection, or None if OK."""
    if "\x00" in body:
        return "rule body contains null byte"
    for i, line in enumerate(body.split("\n"), 1):
        if len(line) > _RULE_BODY_MAX_LINE:
            return (
                f"rule body line {i} exceeds {_RULE_BODY_MAX_LINE} chars "
                f"({len(line)})"
            )
    return None


class LLMCallable(Protocol):
    """Minimal LLM interface for the synthesis loop.

    Production: wraps ``LLMClient.generate_structured``. Tests:
    a stub that returns canned dicts.

    Returns the parsed structured response, or None when the LLM
    cannot satisfy the schema. Raises on transport / auth failure.
    """

    def __call__(
        self, prompt: str, schema: Dict[str, Any], system_prompt: str,
    ) -> Optional[Dict[str, Any]]:
        ...


def _slugify(value: str) -> str:
    """File-safe slug for rule_id construction."""
    s = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_.")
    return s or "x"


def _make_rule_id(seed: SeedBug, attempt: int) -> str:
    """Stable rule_id used for filenames + log lines."""
    return (
        f"{_slugify(seed.file)}.{_slugify(seed.function)}."
        f"{_slugify(seed.cwe)}.{attempt}"
    )


def _rule_extension(engine: str) -> str:
    return ".yml" if engine == "semgrep" else ".cocci"


def _write_rule(
    out_dir: Path, rule: SynthesisedRule,
) -> Path:
    """Atomic rule write — mirrors the annotations pattern.

    Concurrent synthesises on the same seed (e.g. an /audit driver
    parallel-fanning hypothesis tests) could each write the same
    ``rule_id`` filename. Without atomicity, a reader between the
    two writes sees partial content; with it, they see one or the
    other intact.
    """
    rules_dir = out_dir / "checkers"
    rules_dir.mkdir(parents=True, exist_ok=True)
    path = rules_dir / f"{rule.rule_id}{_rule_extension(rule.engine)}"
    tmp = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8",
        dir=rules_dir, prefix=".rule-", suffix=".tmp",
        delete=False,
    )
    try:
        tmp.write(rule.body)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp.close()
        os.replace(tmp.name, path)
    except Exception:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise
    return path


# ---------------------------------------------------------------------------
# Engine adapters — kept thin so tests can stub them.
# ---------------------------------------------------------------------------


def _run_semgrep(
    rule_path: Path, target: Path,
) -> Tuple[List[Match], List[str]]:
    """Run a Semgrep rule against ``target`` (file or directory).
    Returns ``(matches, errors)``.

    The runner returns ``SemgrepFinding`` dataclasses (not dicts) —
    access via attributes. ``file`` is normalised to a path relative
    to ``target`` when it's under it, otherwise kept as-is.
    """
    from packages.semgrep.runner import run_rule
    result = run_rule(target, str(rule_path))
    matches: List[Match] = []
    target_resolved = target.resolve()
    for f in result.findings or []:
        # SemgrepFinding has attribute access — file, line, etc.
        path = getattr(f, "file", "") or ""
        line = int(getattr(f, "line", 0) or 0)
        message = getattr(f, "message", "") or ""
        # Normalise to repo-relative when possible.
        rel = path
        try:
            p = Path(path)
            if p.is_absolute():
                rel = str(p.relative_to(target_resolved))
        except (ValueError, OSError):
            rel = path
        matches.append(Match(file=rel, line=line,
                             snippet=str(message)[:500]))
    errors: List[str] = list(result.errors or [])
    return matches, errors


def _run_coccinelle(
    rule_path: Path, target: Path,
) -> Tuple[List[Match], List[str]]:
    from packages.coccinelle.runner import run_rule
    result = run_rule(target, rule_path)
    matches: List[Match] = []
    for m in getattr(result, "matches", []) or []:
        # SpatchMatch shape — access defensively.
        path = getattr(m, "file", "") or getattr(m, "path", "") or ""
        line = getattr(m, "line", 0) or 0
        snippet = getattr(m, "snippet", "") or ""
        try:
            rel = str(Path(path).relative_to(target.resolve())) \
                if Path(path).is_absolute() else path
        except ValueError:
            rel = path
        matches.append(Match(file=rel, line=int(line),
                             snippet=str(snippet)[:500]))
    errors = list(getattr(result, "errors", []) or [])
    return matches, errors


def _run_engine(
    rule: SynthesisedRule, rule_path: Path, target: Path,
) -> Tuple[List[Match], List[str]]:
    """Dispatch to engine adapter, swallowing any unexpected
    exception (ImportError if scanner package not installed,
    runtime errors from the runner) into the returned ``errors``
    list. Synthesis failures must never crash the caller."""
    try:
        if rule.engine == "semgrep":
            return _run_semgrep(rule_path, target)
        if rule.engine == "coccinelle":
            return _run_coccinelle(rule_path, target)
        return [], [f"unsupported engine: {rule.engine!r}"]
    except Exception as e:
        return [], [f"{rule.engine} adapter error: {e}"]


# ---------------------------------------------------------------------------
# Synthesis steps
# ---------------------------------------------------------------------------


def _propose_rule(
    seed: SeedBug, engine: str, attempt: int, llm: LLMCallable,
    retry_feedback: str = "",
    prior_fps: Tuple[Match, ...] = (),
) -> Tuple[Optional[SynthesisedRule], Optional[str]]:
    """Single LLM round-trip producing one candidate rule.
    Returns ``(rule, error)``; exactly one is set."""
    prompt = build_synthesis_prompt(
        seed, engine,
        retry_feedback=retry_feedback,
        prior_fps=prior_fps,
    )
    try:
        data = llm(prompt, SYNTHESIS_SCHEMA, SYNTHESIS_SYSTEM)
    except Exception as e:
        return None, f"llm error: {e}"
    if not isinstance(data, dict):
        return None, "llm returned non-dict response"
    body = data.get("rule_body")
    rationale = data.get("rationale", "") or ""
    if not isinstance(body, str) or not body.strip():
        return None, "llm response missing 'rule_body'"
    if len(body.encode("utf-8")) > _RULE_BODY_MAX_BYTES:
        return None, (
            f"rule body too large "
            f"({len(body)} chars > {_RULE_BODY_MAX_BYTES})"
        )
    body_err = _validate_rule_body(body)
    if body_err:
        return None, body_err
    return SynthesisedRule(
        engine=engine,
        rule_id=_make_rule_id(seed, attempt),
        body=body,
        rationale=rationale,
    ), None


def _positive_control(
    seed: SeedBug, rule_path: Path, repo_root: Path, engine: str,
) -> Tuple[bool, List[str]]:
    """Run rule on the seed's source file alone; require at least
    one match within the seed's line range."""
    seed_file = repo_root / seed.file
    if not seed_file.exists():
        return False, [f"seed file not found: {seed_file}"]
    rule = SynthesisedRule(engine=engine, rule_id="probe", body="")
    matches, errors = _run_engine(rule, rule_path, seed_file)
    for m in matches:
        if seed.line_start <= m.line <= seed.line_end:
            return True, errors
    return False, errors


def _is_seed_match(seed: SeedBug, m: Match) -> bool:
    """Identify a match that IS the seed bug (so we can drop it
    from the variant list)."""
    if Path(m.file).name != Path(seed.file).name:
        return False
    return seed.line_start <= m.line <= seed.line_end


def _triage(
    seed: SeedBug, rule: SynthesisedRule, matches: List[Match],
    llm: LLMCallable, max_calls: int,
) -> Tuple[List[MatchTriage], List[str]]:
    """LLM-classify each match. Bounded by ``max_calls`` to cap cost.
    Matches beyond the budget are recorded with ``status='skipped'``.
    """
    out: List[MatchTriage] = []
    errors: List[str] = []
    for i, m in enumerate(matches):
        if i >= max_calls:
            out.append(MatchTriage(
                match=m, status="skipped",
                reasoning=f"triage budget exhausted after {max_calls} calls",
            ))
            continue
        prompt = build_triage_prompt(seed, rule, m)
        try:
            data = llm(prompt, TRIAGE_SCHEMA, TRIAGE_SYSTEM)
        except Exception as e:
            errors.append(f"triage llm error for {m.file}:{m.line}: {e}")
            out.append(MatchTriage(
                match=m, status="uncertain",
                reasoning=f"triage failed: {e}",
            ))
            continue
        if not isinstance(data, dict):
            out.append(MatchTriage(
                match=m, status="uncertain",
                reasoning="triage response was not a dict",
            ))
            continue
        status = str(data.get("status", "uncertain"))
        if status not in ("variant", "false_positive", "uncertain"):
            status = "uncertain"
        reasoning = str(data.get("reasoning", "") or "")
        out.append(MatchTriage(match=m, status=status, reasoning=reasoning))
    return out, errors


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def synthesise_and_run(
    seed: SeedBug,
    repo_root: Path,
    out_dir: Path,
    llm: LLMCallable,
    *,
    max_retries: int = 1,
    max_matches: int = 50,
    triage_each: bool = False,
    max_triage_calls: int = 50,
    prior_fps: Tuple[Match, ...] = (),
) -> CheckerSynthesisResult:
    """End-to-end: propose → validate → run → optionally triage.

    Args:
        seed: confirmed bug to synthesise around.
        repo_root: root the rule is run against (codebase scan).
        out_dir: where ``checkers/<rule_id>.{yml,cocci}`` is written.
        llm: callable matching ``LLMCallable`` Protocol.
        max_retries: how many times to refine if positive control
            fails (1 = one refinement attempt). Reasonable default;
            higher rarely helps.
        max_matches: variant matches beyond this are dropped and
            ``capped=True`` is set. Protects against rules so loose
            they swamp downstream consumers.
        triage_each: when True, every match gets an LLM verdict.
            Off by default — costs N×LLM calls per synthesis.
        max_triage_calls: hard ceiling on triage LLM calls.
        prior_fps: matches from earlier iterations of an FP-elimination
            loop, classified as false positives by triage. The
            synthesis prompt appends them as negative examples. Empty
            for single-shot synthesis; populated by
            ``synthesise_with_refinement``.
    """
    repo_root = Path(repo_root).resolve()
    out_dir = Path(out_dir)

    # Defence-in-depth: reject seed paths that could escape repo_root
    # before any filesystem touch.
    path_err = _validate_seed_path(seed.file)
    if path_err:
        return CheckerSynthesisResult(seed=seed, errors=[path_err])

    engine = detect_engine(seed.file)
    if engine is None:
        return CheckerSynthesisResult(
            seed=seed,
            errors=[f"no engine for file extension of {seed.file!r}"],
        )

    result = CheckerSynthesisResult(seed=seed)
    feedback = ""
    rule: Optional[SynthesisedRule] = None
    rule_path: Optional[Path] = None

    for attempt in range(max_retries + 1):
        rule, err = _propose_rule(
            seed, engine, attempt, llm, feedback,
            prior_fps=tuple(prior_fps),
        )
        if err:
            result.errors.append(f"attempt {attempt}: {err}")
            rule = None
            if attempt >= max_retries:
                return result
            feedback = err
            continue

        rule_path = _write_rule(out_dir, rule)
        ok, run_errors = _positive_control(seed, rule_path, repo_root, engine)
        result.errors.extend(f"attempt {attempt}: {e}" for e in run_errors)
        if ok:
            break
        # Positive control failed — retry if we still have budget.
        result.errors.append(
            f"attempt {attempt}: rule did not match seed at "
            f"{seed.file}:{seed.line_start}-{seed.line_end}"
        )
        feedback = (
            f"Previous rule did not match the seed bug at lines "
            f"{seed.line_start}-{seed.line_end} of {seed.file}. "
            f"Refine the pattern so it captures the original."
        )
        rule = None
        rule_path = None

    if rule is None or rule_path is None:
        return result

    result.rule = rule
    result.rule_path = rule_path
    result.positive_control = True

    # Codebase scan.
    matches, run_errors = _run_engine(rule, rule_path, repo_root)
    result.errors.extend(run_errors)
    # Drop the seed itself from the variant list.
    variants = [m for m in matches if not _is_seed_match(seed, m)]
    pre_cap = len(variants)
    if pre_cap > max_matches:
        variants = variants[:max_matches]
        result.capped = True
    if pre_cap >= _RULE_TOO_LOOSE_THRESHOLD:
        # Way more matches than a typical bug class produces — the
        # synthesised rule is almost certainly too loose. Surface
        # this so /audit can decide whether to refine, retry with
        # a different prompt, or surface to the operator.
        result.errors.append(
            f"rule appears too loose: {pre_cap} variant matches "
            f"(threshold {_RULE_TOO_LOOSE_THRESHOLD}); refine "
            f"the synthesis prompt before triaging"
        )
    result.matches = variants

    if triage_each and variants:
        triage, t_errors = _triage(seed, rule, variants, llm, max_triage_calls)
        result.triage = triage
        result.errors.extend(t_errors)

    return result


# ---------------------------------------------------------------------------
# Iterative FP-elimination wrapper (Phase A Mode 2)
# ---------------------------------------------------------------------------


def _fp_rate(result: CheckerSynthesisResult) -> Optional[float]:
    """Fraction of triaged matches classified as false positive.

    Returns None when the rate can't be computed (no triage,
    everything skipped). Excludes ``skipped`` from the denominator
    — those are budget-truncated, not classified.
    """
    triaged = [t for t in result.triage if t.status != "skipped"]
    if not triaged:
        return None
    fps = [t for t in triaged if t.status == "false_positive"]
    return len(fps) / len(triaged)


def synthesise_with_refinement(
    seed: SeedBug,
    repo_root: Path,
    out_dir: Path,
    llm: LLMCallable,
    *,
    max_iterations: int = 5,
    max_acceptable_fp_rate: float = 0.2,
    max_matches: int = 50,
    max_triage_calls: int = 50,
) -> CheckerSynthesisResult:
    """Iterative checker synthesis with FP-elimination.

    The KNighter pipeline that ``synthesise_and_run`` implements has
    a single shot at the rule. The /audit design (2026-05-08) and
    KNighter's own paper observe that 5–10 iterations of FP-driven
    refinement typically converge a noisy rule to a tight one. This
    wrapper provides that loop.

    Each iteration:

      1. Run ``synthesise_and_run`` with ``triage_each=True``,
         passing the accumulated FPs from prior iterations as
         negative examples.
      2. Compute FP rate from the triage verdicts.
      3. If FP rate ≤ ``max_acceptable_fp_rate``: converged, return
         the current result.
      4. Otherwise, append this iteration's FPs to the running list
         and try again.

    Convergence rules:
      * Always returns the iteration with the LOWEST FP rate. If
        no iteration beat the threshold, the best-so-far still
        wins over the worst.
      * If positive control fails on an iteration (no rule produced),
        it doesn't count toward the best-so-far — just bumps to the
        next iteration with the existing FP context.
      * If we exhaust ``max_iterations`` without improvement, the
        best-so-far is returned with an error log entry naming
        the situation.
      * If triage couldn't run at all (e.g. zero matches), there's
        nothing to learn from; return immediately after iteration 1.

    The first iteration is identical to a vanilla
    ``synthesise_and_run(triage_each=True)`` call. Operators who
    don't want refinement should call ``synthesise_and_run`` directly.
    """
    if max_iterations <= 0:
        return CheckerSynthesisResult(
            seed=seed,
            errors=["max_iterations must be > 0"],
        )

    prior_fps: List[Match] = []
    best: Optional[CheckerSynthesisResult] = None
    best_rate: Optional[float] = None

    for iteration in range(max_iterations):
        result = synthesise_and_run(
            seed, repo_root, out_dir, llm,
            max_matches=max_matches,
            triage_each=True,
            max_triage_calls=max_triage_calls,
            prior_fps=tuple(prior_fps),
        )

        # If synthesis failed entirely, bump to next iteration.
        # The accumulated FP context from prior rounds carries
        # forward — maybe a different rule will land this round.
        if result.rule is None:
            result.errors.append(
                f"iteration {iteration}: no rule produced"
            )
            if best is None:
                best = result  # at least surface SOMETHING
            continue

        rate = _fp_rate(result)
        if rate is None:
            # Triage didn't run — no signal to refine on. Take this
            # result and stop; refinement can't help without verdicts.
            result.errors.append(
                f"iteration {iteration}: no triage verdicts; "
                f"refinement loop has nothing to learn"
            )
            return result

        # Track best-so-far by rate (lower is better).
        if best_rate is None or rate < best_rate:
            best = result
            best_rate = rate

        if rate <= max_acceptable_fp_rate:
            # Converged.
            return result

        # Accumulate FPs for the next prompt. Cap to keep prompt
        # size bounded across iterations — the prompt builder also
        # caps to 8 in the prompt itself.
        new_fps = [t.match for t in result.triage
                   if t.status == "false_positive"]
        # Avoid duplicate locations (dedup by file:line).
        seen = {(m.file, m.line) for m in prior_fps}
        for m in new_fps:
            key = (m.file, m.line)
            if key in seen:
                continue
            prior_fps.append(m)
            seen.add(key)

    # Exhausted without converging — return best-so-far with a note.
    if best is None:
        return CheckerSynthesisResult(
            seed=seed,
            errors=["refinement: no result across all iterations"],
        )
    if best_rate is None:
        # No iteration ever produced a triageable rule.
        best.errors.append(
            f"refinement: did not converge in {max_iterations} "
            f"iterations (no rule reached triage)"
        )
    else:
        best.errors.append(
            f"refinement: did not converge in {max_iterations} "
            f"iterations (best fp_rate={best_rate:.2f} > threshold "
            f"{max_acceptable_fp_rate:.2f})"
        )
    return best
