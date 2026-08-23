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
import re
import tempfile
from pathlib import Path
from typing import Any, Protocol

from core.atomic_fs import write_text_atomically
from packages.coccinelle.runner import contains_script_block

from .languages import detect_engine, fallback_engine
from .models import (
    CheckerSynthesisResult,
    Match,
    MatchTriage,
    SeedBug,
    SynthesisedRule,
)
from .prompts import (
    SYNTHESIS_SCHEMA,
    TRIAGE_SCHEMA,
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


def _validate_seed_path(file_path: str) -> str | None:
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


def _validate_rule_body(body: str) -> str | None:
    """Reject rule bodies containing null bytes or oversized lines.
    Syntax problems are handled by ``_fixup_cocci_body``, not here.
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


# Matches both layouts LLMs emit: the clause on its own line, and the
# same-line ``... when != if (E)`` form. The optional dots group is
# preserved on substitution so the ellipsis (valid SmPL on its own)
# survives the strip.
_INVALID_WHEN_RE = re.compile(
    r"^(?P<dots>\s*\.\.\.)?[ \t]*when\s*!=\s*(?:if|assert|while|for|switch)"
    r"\s*\(.*$",
    re.MULTILINE,
)


def _fixup_cocci_body(body: str) -> str:
    """Strip known-invalid ``when`` clauses that LLMs persistently generate.

    ``when != if (...)`` and similar compound-statement negations are
    invalid SmPL — Coccinelle ``when`` can only negate expressions.
    Rather than rejecting the whole rule (which the LLM regenerates
    identically on retry), strip the offending clauses (keeping a
    same-line leading ``...``) so the remaining rule gets a chance at
    dual control.
    """
    return _INVALID_WHEN_RE.sub(
        lambda m: m.group("dots") or "", body)


def _reject_cocci_scripting(body: str) -> str | None:
    """Refuse Coccinelle rule bodies that declare scripting blocks.

    ``@script:`` / ``@initialize:`` / ``@finalize:`` blocks execute
    code inside spatch — an LLM-synthesised rule carrying one is a
    code-execution vector and must never be persisted to the checkers
    library. Shares the runner's matcher (contains_script_block) so
    the gate here and the runner's refusal agree on what counts as a
    scripting block. RAPTOR injects its own COCCIRESULT reporting
    harness at run time; rules need only declarative SmPL.

    Returns an error string on rejection, or None if OK.
    """
    if contains_script_block(body):
        return (
            "rule body declares a scripting block (@script:/"
            "@initialize:/@finalize:) — LLM-synthesised rules must be "
            "declarative SmPL only; RAPTOR injects the reporting "
            "harness itself"
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
        self, prompt: str, schema: dict[str, Any], system_prompt: str,
    ) -> dict[str, Any] | None:
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
    path = rules_dir / f"{rule.rule_id}{_rule_extension(rule.engine)}"
    # Atomic write: concurrent synthesises on the same seed (an
    # /audit driver parallel-fanning hypothesis tests) can each write
    # the same rule_id filename. Primitive's random-suffix tempfile
    # keeps their writes isolated; readers see one or the other
    # intact, never partial content.
    write_text_atomically(path, rule.body, tmp_prefix=".rule-")
    return path


# ---------------------------------------------------------------------------
# Engine adapters — kept thin so tests can stub them.
# ---------------------------------------------------------------------------


def _run_semgrep(
    rule_path: Path, target: Path,
) -> tuple[list[Match], list[str]]:
    """Run a Semgrep rule against ``target`` (file or directory).
    Returns ``(matches, errors)``.

    The runner returns ``SemgrepFinding`` dataclasses (not dicts) —
    access via attributes. ``file`` is normalised to a path relative
    to ``target`` when it's under it, otherwise kept as-is.
    """
    from packages.semgrep.runner import run_rule
    result = run_rule(target, str(rule_path))
    matches: list[Match] = []
    target_resolved = target.resolve()
    for f in result.findings or []:
        # SemgrepFinding has attribute access — file, line, etc.
        path = getattr(f, "file", "") or ""
        line = int(getattr(f, "line", 0) or 0)
        # Normalise to repo-relative when possible.
        rel = path
        try:
            p = Path(path)
            if p.is_absolute():
                rel = str(p.relative_to(target_resolved))
        except (ValueError, OSError):
            rel = path
        matches.append(Match(file=rel, line=line, snippet=""))
    errors: list[str] = list(result.errors or [])
    # Belt-and-braces returncode consult: the runner populates errors
    # for every rc outside {0, 1} since the U14-F3 fix, but the
    # mechanical-control evidence chain (dual control, ground truth,
    # fix-mutant) must never depend on a single layer to distinguish
    # engine failure from verified silence.
    if result.returncode not in (0, 1) and not errors:
        errors.append(
            f"semgrep exited with returncode {result.returncode}"
        )
    # A fixture the engine could not examine proves nothing about it.
    errors.extend("semgrep failed to scan "
                f"{ff.get('path', '?')}: {ff.get('reason', 'error')}" for ff in (result.files_failed or [])[:5] if isinstance(ff, dict))
    return matches, errors


def _run_coccinelle(
    rule_path: Path, target: Path,
) -> tuple[list[Match], list[str]]:
    from packages.coccinelle.runner import run_rule
    result = run_rule(target, rule_path)
    matches: list[Match] = []
    for m in getattr(result, "matches", []) or []:
        # SpatchMatch shape — access defensively.
        path = getattr(m, "file", "") or getattr(m, "path", "") or ""
        line = getattr(m, "line", 0) or 0
        snippet = getattr(m, "snippet", "") or ""
        try:
            rel = str(Path(path).relative_to(target.resolve())) \
                if Path(path).is_absolute() else path
        except (ValueError, OSError):
            rel = path
        matches.append(Match(file=rel, line=int(line),
                             snippet=str(snippet)[:500]))
    errors = list(getattr(result, "errors", []) or [])
    # spatch's keyword-based _parse_errors misses failures that don't
    # print a known error string — consult the returncode so a crashed
    # or refused spatch run never reads as verified silence in the
    # mechanical-control chain.
    returncode = getattr(result, "returncode", 0)
    if returncode != 0 and not errors:
        errors.append(f"spatch exited with returncode {returncode}")
    return matches, errors


def _run_engine(
    rule: SynthesisedRule, rule_path: Path, target: Path,
) -> tuple[list[Match], list[str]]:
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
    except Exception as e:  # noqa: BLE001
        return [], [f"{rule.engine} adapter error: {e}"]


# ---------------------------------------------------------------------------
# Synthesis steps
# ---------------------------------------------------------------------------


def _propose_rule(
    seed: SeedBug, engine: str, attempt: int, llm: LLMCallable,
    retry_feedback: str = "",
    prior_fps: tuple[Match, ...] = (),
    model_id: str = "",
) -> tuple[SynthesisedRule | None, str | None]:
    """Single LLM round-trip producing one candidate rule.
    Returns ``(rule, error)``; exactly one is set."""
    prompt, system = build_synthesis_prompt(
        seed, engine,
        retry_feedback=retry_feedback,
        prior_fps=prior_fps,
        model_id=model_id,
    )
    try:
        data = llm(prompt, SYNTHESIS_SCHEMA, system)
    except Exception as e:  # noqa: BLE001
        return None, f"llm error: {e}"
    if not isinstance(data, dict):
        return None, "llm returned non-dict response"
    body = data.get("rule_body")
    rationale = data.get("rationale", "") or ""
    test_positive = data.get("test_positive", "") or ""
    test_negative = data.get("test_negative", "") or ""
    fix_patch = data.get("fix_patch", "") or ""
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
    if engine == "coccinelle":
        body = _fixup_cocci_body(body)
        script_err = _reject_cocci_scripting(body)
        if script_err:
            # Rejected before _write_rule — a scripted rule never
            # reaches the library on disk.
            return None, script_err
    return SynthesisedRule(
        engine=engine,
        rule_id=_make_rule_id(seed, attempt),
        body=body,
        rationale=rationale,
        test_positive=str(test_positive),
        test_negative=str(test_negative),
        fix_patch=str(fix_patch),
    ), None


def _positive_control(
    seed: SeedBug, rule_path: Path, repo_root: Path, engine: str,
) -> tuple[bool, list[str]]:
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


def _fixture_ext(seed: SeedBug, engine: str) -> str:
    """File extension for dual-control test fixtures."""
    if engine == "coccinelle":
        return ".c"
    return Path(seed.file).suffix or ".c"


def _dual_control(
    rule: SynthesisedRule, rule_path: Path, engine: str, ext: str,
) -> tuple[bool, list[str]]:
    """Run the rule against LLM-generated positive and negative test
    fixtures. Both must be present; the rule must match the positive
    and must NOT match the negative."""
    if not rule.test_positive or not rule.test_negative:
        return False, ["dual control: LLM did not emit test fixtures"]

    errors: list[str] = []
    dummy = SynthesisedRule(engine=engine, rule_id="probe", body="")

    with tempfile.TemporaryDirectory(prefix="raptor_dc_") as tmp:
        tmp_path = Path(tmp)
        pos_file = tmp_path / f"test_positive{ext}"
        neg_file = tmp_path / f"test_negative{ext}"
        pos_file.write_text(rule.test_positive, encoding="utf-8")
        neg_file.write_text(rule.test_negative, encoding="utf-8")

        pos_matches, pos_errors = _run_engine(dummy, rule_path, pos_file)
        errors.extend(pos_errors)
        if not pos_matches:
            if pos_errors:
                # Same fail-closed policy as the negative side: an
                # engine error means the fixture may not even have
                # parsed — reporting it as "did not match" sends the
                # retry loop chasing the wrong defect.
                errors.append(
                    "dual control: engine errored on positive fixture "
                    "— no-match proves nothing (fixture may not parse)"
                )
            else:
                errors.append(
                    "dual control: rule did not match positive test fixture"
                )
            return False, errors

        neg_matches, neg_errors = _run_engine(dummy, rule_path, neg_file)
        errors.extend(neg_errors)
        if neg_matches:
            errors.append(
                f"dual control: rule matched negative test fixture "
                f"({len(neg_matches)} hit(s) — rule is too broad)"
            )
            return False, errors
        if neg_errors:
            # Engine error on the negative run: zero matches proves
            # nothing (the fixture may not even have parsed). Fail
            # closed — same policy as _fix_mutant_control's
            # engine-errored-on-patched-copy verdict.
            errors.append(
                "dual control: engine errored on negative fixture — "
                "silence is not a pass (control not verifiable)"
            )
            return False, errors

    return True, errors


def _run_on_fixture_text(
    rule_path: Path, engine: str, text: str, ext: str,
) -> tuple[list, list[str]]:
    """Run the rule against fixture text materialised in a temp file."""
    dummy = SynthesisedRule(engine=engine, rule_id="probe", body="")
    with tempfile.TemporaryDirectory(prefix="raptor_gt_") as tmp:
        fixture = Path(tmp) / f"fixture{ext}"
        fixture.write_text(text, encoding="utf-8")
        return _run_engine(dummy, rule_path, fixture)


def _ground_truth_control(
    seed: SeedBug,
    rule_path: Path,
    engine: str,
    positive_text: str,
    negative_text: str | None,
) -> tuple[bool, bool | None, list[str]]:
    """External ground-truth control for seeds not present in the repo.

    ``positive_text`` is known-vulnerable code (e.g. a CVE fix commit's
    pre-fix hunk); ``negative_text`` is the fixed form. The rule must
    match the positive; when a negative is supplied it must stay
    silent on it. Returns ``(positive_ok, negative_ok, errors)`` where
    ``negative_ok`` is None when no negative fixture was supplied.
    """
    ext = _fixture_ext(seed, engine)
    errors: list[str] = []
    pos_matches, pos_errors = _run_on_fixture_text(
        rule_path, engine, positive_text, ext,
    )
    errors.extend(pos_errors)
    if not pos_matches:
        errors.append(
            "ground-truth control: rule did not match the known-"
            "vulnerable fixture"
        )
        return False, None, errors
    if negative_text is None:
        return True, None, errors
    neg_matches, neg_errors = _run_on_fixture_text(
        rule_path, engine, negative_text, ext,
    )
    errors.extend(neg_errors)
    if neg_matches:
        errors.append(
            f"ground-truth control: rule matched the FIXED fixture "
            f"({len(neg_matches)} hit(s) — pattern does not "
            "distinguish the fix)"
        )
        return True, False, errors
    if neg_errors:
        # Engine error on the fixed fixture: zero matches proves
        # nothing. Fail closed — an unverifiable negative must not
        # cascade into fix_mutant_control=True + rule_tier="library".
        errors.append(
            "ground-truth control: engine errored on the FIXED "
            "fixture — silence is not a pass (negative control "
            "not verifiable)"
        )
        return True, False, errors
    return True, True, errors


def _fix_mutant_control(
    seed: SeedBug,
    rule: SynthesisedRule,
    rule_path: Path,
    repo_root: Path,
    engine: str,
) -> tuple[bool | None, list[str]]:
    """Mechanical fix-mutant control.

    Applies the LLM-supplied guard-insertion patch (``rule.fix_patch``
    — a drop-in replacement for the seed's line range) to a COPY of
    the seed file, then re-runs the rule against the patched copy.  A
    rule that still matches inside the patched region cannot
    distinguish fixed from unfixed code — it keys on guard-insensitive
    syntax, not on the missing check.

    Unlike dual control, the fixtures here are anchored to the REAL
    seed file: the LLM only authors the guard insertion, and the
    apply + re-run steps are mechanical, so the rule is not grading
    its own homework end-to-end.

    Returns ``(verdict, errors)``:

      * ``True``  — patch applied and the rule no longer matches the
        patched region (control passed).
      * ``False`` — the rule still matches the patched region
        (control failed).
      * ``None``  — patch missing / failed to apply / result not
        verifiable.  Callers treat this fail-closed for library
        acceptance.
    """
    errors: list[str] = []
    if not rule.fix_patch.strip():
        return None, ["fix-mutant: LLM did not emit fix_patch"]

    seed_file = repo_root / seed.file
    try:
        original = seed_file.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return None, [f"fix-mutant: cannot read seed file: {e}"]

    lines = original.split("\n")
    line_start, line_end = seed.line_start, seed.line_end
    if not (1 <= line_start <= line_end <= len(lines)):
        return None, [
            (f"fix-mutant: seed line range {line_start}-{line_end} "
             f"outside file ({len(lines)} lines) — patch not applicable"),
        ]

    patch_lines = rule.fix_patch.split("\n")
    # Trim one trailing empty line from the patch — LLMs habitually
    # end strings with "\n", which would otherwise insert a blank.
    if patch_lines and patch_lines[-1] == "":
        patch_lines = patch_lines[:-1]
    if not patch_lines:
        return None, ["fix-mutant: fix_patch is empty after trimming"]

    original_region = lines[line_start - 1:line_end]
    if [ln.strip() for ln in patch_lines] == \
            [ln.strip() for ln in original_region]:
        return None, [
            ("fix-mutant: fix_patch is identical to the seed lines "
             "(no guard inserted) — patch failed to apply"),
        ]

    patched = "\n".join(
        lines[:line_start - 1] + patch_lines + lines[line_end:],
    )

    ext = Path(seed.file).suffix or _fixture_ext(seed, engine)
    dummy = SynthesisedRule(engine=engine, rule_id="probe", body="")
    with tempfile.TemporaryDirectory(prefix="raptor_fm_") as tmp:
        patched_file = Path(tmp) / f"fix_mutant{ext}"
        patched_file.write_text(patched, encoding="utf-8")
        matches, run_errors = _run_engine(dummy, rule_path, patched_file)
        errors.extend(run_errors)

    # The patched region now spans [line_start, line_start+len-1].
    # Matches with line 0 (engine gave no location) are counted as
    # in-region — fail-closed rather than silently passing.
    region_end = line_start + len(patch_lines) - 1
    in_region = [
        m for m in matches
        if m.line == 0 or line_start <= m.line <= region_end
    ]
    if in_region:
        errors.append(
            f"fix-mutant: rule still matches the patched seed region "
            f"({len(in_region)} hit(s)) — rule cannot distinguish "
            f"fixed from unfixed code"
        )
        return False, errors

    if run_errors and not matches:
        # Engine failed on the patched copy (e.g. the patch broke
        # parsing) — the control ran but proved nothing.
        errors.append(
            "fix-mutant: engine errored on patched copy — "
            "control not verifiable"
        )
        return None, errors

    return True, errors


def _is_seed_match(seed: SeedBug, m: Match) -> bool:
    """Identify a match that IS the seed bug (so we can drop it
    from the variant list)."""
    if m.file != seed.file:
        return False
    return seed.line_start <= m.line <= seed.line_end


def _triage(
    seed: SeedBug, rule: SynthesisedRule, matches: list[Match],
    llm: LLMCallable, max_calls: int,
    model_id: str = "",
) -> tuple[list[MatchTriage], list[str]]:
    """LLM-classify each match. Bounded by ``max_calls`` to cap cost.
    Matches beyond the budget are recorded with ``status='skipped'``.
    """
    out: list[MatchTriage] = []
    errors: list[str] = []
    for i, m in enumerate(matches):
        if i >= max_calls:
            out.append(MatchTriage(
                match=m, status="skipped",
                reasoning=f"triage budget exhausted after {max_calls} calls",
            ))
            continue
        prompt, system = build_triage_prompt(seed, rule, m, model_id=model_id)
        try:
            data = llm(prompt, TRIAGE_SCHEMA, system)
        except Exception as e:  # noqa: BLE001
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
    prior_fps: tuple[Match, ...] = (),
    model_id: str = "",
    ground_truth_fixtures: tuple[str, str | None] | None = None,
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
        model_id: model identifier threaded into prompt building
            (proposal and triage) to select the per-model envelope
            profile via ``get_profile_for``; empty string falls back
            to the CONSERVATIVE profile.
        ground_truth_fixtures: ``(positive_text, negative_text)`` for
            EXTERNAL seeds whose file is not present in ``repo_root``
            (e.g. a CVE fix commit's pre-fix hunk / fixed form). The
            positive control runs against the positive fixture instead
            of ``repo_root / seed.file``; when the negative fixture is
            supplied the rule must stay silent on it (ground-truth
            analogue of the fix-mutant control). The codebase sweep
            still runs over ``repo_root``.
    """
    repo_root = Path(repo_root).resolve()
    out_dir = Path(out_dir)

    # Defence-in-depth: reject seed paths that could escape repo_root
    # before any filesystem touch.
    path_err = _validate_seed_path(seed.file)
    if path_err:
        return CheckerSynthesisResult(seed=seed, errors=[path_err])

    primary_engine = detect_engine(seed.file)
    if primary_engine is None:
        return CheckerSynthesisResult(
            seed=seed,
            errors=[f"no engine for file extension of {seed.file!r}"],
        )

    engines_to_try = [primary_engine]
    alt = fallback_engine(primary_engine, seed.file)
    if alt:
        engines_to_try.append(alt)

    result = CheckerSynthesisResult(seed=seed)
    rule: SynthesisedRule | None = None
    rule_path: Path | None = None

    for engine in engines_to_try:
        if rule is not None:
            break
        feedback = ""
        for attempt in range(max_retries + 1):
            tag = f"{engine} attempt {attempt}"
            rule, err = _propose_rule(
                seed, engine, attempt, llm, feedback,
                prior_fps=tuple(prior_fps),
                model_id=model_id,
            )
            if err:
                result.errors.append(f"{tag}: {err}")
                rule = None
                feedback = err
                continue

            rule_path = _write_rule(out_dir, rule)
            gt_negative_ok: bool | None = None
            if ground_truth_fixtures is not None:
                ok, gt_negative_ok, run_errors = _ground_truth_control(
                    seed, rule_path, engine,
                    ground_truth_fixtures[0], ground_truth_fixtures[1],
                )
                if ok and gt_negative_ok is False:
                    result.errors.extend(f"{tag}: {e}" for e in run_errors)
                    if any("not verifiable" in e for e in run_errors):
                        feedback = (
                            "The engine errored while running the rule "
                            "against the fixed form of the code — the "
                            "rule (or fixture) may not parse. Produce a "
                            "simpler, syntactically valid pattern."
                        )
                    else:
                        feedback = (
                            "The rule matched the known-vulnerable "
                            "fixture but ALSO matched the fixed form. "
                            "Refine the pattern so the patched code "
                            "does not match."
                        )
                    rule = None
                    rule_path = None
                    continue
            else:
                ok, run_errors = _positive_control(
                    seed, rule_path, repo_root, engine,
                )
            result.errors.extend(f"{tag}: {e}" for e in run_errors)
            if ok:
                ext = _fixture_ext(seed, engine)
                if rule.test_positive and rule.test_negative:
                    dc_ok, dc_errors = _dual_control(
                        rule, rule_path, engine, ext,
                    )
                    result.errors.extend(
                        f"{tag}: {e}" for e in dc_errors
                    )
                    if dc_ok:
                        result.dual_control = True
                        logger.debug(
                            "dual control passed for %s (%s)",
                            seed.file, engine,
                        )
                        break
                    dc_reason = " ".join(
                        e for e in dc_errors
                        if e.startswith("dual control:")
                    )
                    logger.debug(
                        "dual control failed for %s %s: %s",
                        seed.file, tag, dc_reason,
                    )
                    feedback = (
                        "The rule matched the seed bug (positive "
                        "control passed) but failed the dual "
                        "control gate. " + dc_reason
                    )
                    rule = None
                    rule_path = None
                    continue
                # Fail-closed: without fixtures the rule was never
                # exercised against known-good/known-bad code, so
                # it may not enter the persistent library
                # (rule_tier stays "sweep_once").  The rule is
                # still used for this run's codebase sweep.
                result.errors.append(
                    f"{tag}: dual control skipped — LLM did not "
                    "emit test fixtures; rule excluded from "
                    "library (rule_tier=sweep_once)"
                )
                logger.warning(
                    "dual control skipped: LLM did not emit "
                    "test fixtures for %s — rule excluded from "
                    "library",
                    seed.file,
                )
                break
            result.errors.append(
                f"{tag}: rule did not match seed at "
                f"{seed.file}:{seed.line_start}-{seed.line_end}"
            )
            feedback = (
                f"Previous rule did not match the seed bug at "
                f"lines {seed.line_start}-{seed.line_end} of "
                f"{seed.file}. Refine the pattern so it captures "
                f"the original."
            )
            rule = None
            rule_path = None

    if rule is None or rule_path is None:
        return result

    result.rule = rule
    result.rule_path = rule_path
    result.positive_control = True

    # Fix-mutant control (library gate, not a sweep gate): only rules
    # that passed dual control are candidates for the library, so only
    # those pay for the extra engine run.  Verdict semantics and the
    # fail-closed policy are documented on _fix_mutant_control.
    if ground_truth_fixtures is not None:
        # External seed: the repo-anchored fix-mutant control cannot
        # run (seed file absent). The ground-truth negative fixture is
        # its analogue — the grant requires the negative control to
        # have VERIFIED silence on the fixed form (gt_negative_ok is
        # True), not merely that a negative fixture was supplied: an
        # engine error on the negative run reads as False now, and a
        # missing fixture as None — neither may grant the library tier.
        if result.dual_control and gt_negative_ok is True:
            result.fix_mutant_control = True
            result.rule_tier = "library"
    elif result.dual_control:
        fm_ok, fm_errors = _fix_mutant_control(
            seed, rule, rule_path, repo_root, rule.engine,
        )
        result.fix_mutant_control = fm_ok
        result.errors.extend(fm_errors)
        if fm_ok is True:
            result.rule_tier = "library"
        else:
            reason = (
                "patch missing or failed to apply" if fm_ok is None
                else "rule matched the patched seed"
            )
            result.errors.append(
                f"fix-mutant control did not pass ({reason}); rule "
                "excluded from library (rule_tier=sweep_once)"
            )
            logger.info(
                "fix-mutant control %s for %s (%s) — library excluded",
                "not applicable" if fm_ok is None else "failed",
                seed.file, rule.engine,
            )

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
        triage, t_errors = _triage(seed, rule, variants, llm,
                                   max_triage_calls, model_id=model_id)
        result.triage = triage
        result.errors.extend(t_errors)

    return result


# ---------------------------------------------------------------------------
# Iterative FP-elimination wrapper (Phase A Mode 2)
# ---------------------------------------------------------------------------


def _fp_rate(result: CheckerSynthesisResult) -> float | None:
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
    model_id: str = "",
    ground_truth_fixtures: tuple[str, str | None] | None = None,
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

    ``ground_truth_fixtures`` rides through unchanged to every
    iteration's ``synthesise_and_run`` call — external seeds (e.g.
    CVE fix commits, see :mod:`.cve_bridge`) refine against the same
    known-vulnerable / known-fixed pair each round.
    """
    if max_iterations <= 0:
        return CheckerSynthesisResult(
            seed=seed,
            errors=["max_iterations must be > 0"],
        )

    prior_fps: list[Match] = []
    best: CheckerSynthesisResult | None = None
    best_rate: float | None = None

    for iteration in range(max_iterations):
        result = synthesise_and_run(
            seed, repo_root, out_dir, llm,
            max_matches=max_matches,
            triage_each=True,
            max_triage_calls=max_triage_calls,
            prior_fps=tuple(prior_fps),
            model_id=model_id,
            ground_truth_fixtures=ground_truth_fixtures,
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
