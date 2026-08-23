"""Bridge a /cve-diff run into validated checker synthesis.

``/cve-diff`` acquires the public fix commit for a CVE and writes a
self-describing output directory (``<CVE>.osv.json`` with the fix
pointer and per-file before/after source). This module turns that
artifact into checker-synthesis seeds mechanically — pre-fix hunks as
the known-vulnerable fixture, post-fix source as the fixed form — and
feeds the EXISTING control machinery (positive / dual / ground-truth
negative). No gating is re-implemented here: a rule enters the
persistent library only when ``synthesise_and_run`` stamped
``rule_tier="library"`` and ``RuleLibrary.promote`` accepts it.

Provenance doctrine (no-undisclosed-vulns): every seed and library
entry records the CVE id and fix-commit SHA
(``cvefix:<CVE-ID>@<sha12>``), and a run REFUSES inputs whose OSV
record lacks a well-formed CVE id or fix SHA — a diff without public
provenance must not become a shipped rule.
"""

from __future__ import annotations

import difflib
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.json import dumps_display

from .languages import detect_engine
from .library import RuleLibrary
from .models import CheckerSynthesisResult, SeedBug
from .synthesise import (
    _SEED_SNIPPET_MAX_BYTES,
    LLMCallable,
    synthesise_with_refinement,
)

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")

# Lines of pre-fix context kept around the changed region in the seed
# snippet (the prompt's view of the bug; fixtures use the full file).
_SNIPPET_CONTEXT_LINES = 5


class ProvenanceError(ValueError):
    """The cve-diff artifact lacks verifiable public provenance."""


@dataclass(frozen=True)
class CveFixFile:
    """One changed file from the fix commit, with full pre/post text."""

    path: str
    before_source: str
    after_source: str
    is_test: bool = False


@dataclass(frozen=True)
class CveFixRecord:
    """Provenance-validated view of one /cve-diff output directory."""

    cve_id: str
    repository_url: str
    fix_commit: str
    files: tuple[CveFixFile, ...]
    cwe: str = ""          # root_cause.cwe_id when --with-root-cause ran
    summary: str = ""      # root_cause.summary when present
    # database_specific.diff_against — the pre-fix parent commit. Empty
    # when the record predates the field or carries a malformed SHA;
    # consumers that need a before/after pair (core.dataflow's cvefix
    # walk) must skip such records rather than guess.
    parent_commit: str = ""

    @property
    def provenance(self) -> str:
        return f"cvefix:{self.cve_id}@{self.fix_commit[:12]}"


@dataclass(frozen=True)
class CveSeedBundle:
    """A synthesis seed plus its ground-truth fixture pair."""

    seed: SeedBug
    positive_text: str        # pre-fix file (known vulnerable)
    negative_text: str | None  # post-fix file (known fixed)


@dataclass
class CveBridgeReport:
    """Outcome of one bridge run, JSON-serialisable via to_dict()."""

    cve_id: str = ""
    fix_commit: str = ""
    seeds_derived: int = 0
    results: list[CheckerSynthesisResult] = field(default_factory=list)
    promoted_rule_ids: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "fix_commit": self.fix_commit,
            "seeds_derived": self.seeds_derived,
            "results": [r.to_dict() for r in self.results],
            "promoted_rule_ids": list(self.promoted_rule_ids),
            "errors": list(self.errors),
        }


def load_cve_run(output_dir: Path | str) -> CveFixRecord:
    """Parse a /cve-diff output directory into a provenance-checked record.

    Raises ProvenanceError when the OSV artifact is missing, ambiguous,
    or lacks a well-formed CVE id / fix-commit SHA. The refusal is the
    public-provenance gate — do not weaken it to "best effort".
    """
    output_dir = Path(output_dir)
    osv_files = sorted(output_dir.glob("*.osv.json"))
    if not osv_files:
        msg = f"no *.osv.json in {output_dir} — run /cve-diff first"
        raise ProvenanceError(msg)
    if len(osv_files) > 1:
        msg = (
            f"multiple OSV records in {output_dir} "
            f"({', '.join(p.name for p in osv_files)}); "
            "pass a directory holding exactly one CVE"
        )
        raise ProvenanceError(msg)
    osv_path = osv_files[0]
    try:
        osv = json.loads(osv_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        msg = f"unreadable OSV record {osv_path}: {exc}"
        raise ProvenanceError(msg) from exc

    cve_id = str(osv.get("id", ""))
    if not _CVE_RE.match(cve_id):
        msg = (
            f"OSV id {cve_id!r} is not a CVE identifier — "
            "public provenance required for library rules"
        )
        raise ProvenanceError(msg)

    fix_commit = ""
    repository_url = ""
    for affected in osv.get("affected", []) or []:
        for rng in affected.get("ranges", []) or []:
            repository_url = repository_url or str(rng.get("repo", ""))
            for event in rng.get("events", []) or []:
                if "fixed" in event:
                    fix_commit = str(event["fixed"])
    if not _SHA_RE.match(fix_commit):
        msg = (
            f"OSV record for {cve_id} carries no well-formed fix-commit "
            f"SHA (got {fix_commit!r}) — public provenance required"
        )
        raise ProvenanceError(msg)

    db = osv.get("database_specific", {}) or {}
    files: list[CveFixFile] = [CveFixFile(
            path=str(f.get("path", "")),
            before_source=str(f.get("before_source") or ""),
            after_source=str(f.get("after_source") or ""),
            is_test=bool(f.get("is_test", False)),
        ) for f in db.get("files", []) or []]

    parent_commit = str(db.get("diff_against", "") or "")
    if not _SHA_RE.match(parent_commit):
        parent_commit = ""

    root_cause = db.get("root_cause", {}) or {}
    return CveFixRecord(
        cve_id=cve_id,
        repository_url=repository_url,
        fix_commit=fix_commit,
        files=tuple(files),
        cwe=str(root_cause.get("cwe_id", "") or ""),
        summary=str(root_cause.get("summary", "") or ""),
        parent_commit=parent_commit,
    )


def _changed_pre_lines(before: str, after: str) -> tuple[int, int, int]:
    """(first, last, count) of pre-image lines the fix touched (1-based).

    Counts lines in `replace`/`delete` opcodes — the code the fix
    removed or rewrote, i.e. the vulnerable form.
    """
    before_lines = before.splitlines()
    after_lines = after.splitlines()
    sm = difflib.SequenceMatcher(a=before_lines, b=after_lines, autojunk=False)
    first = last = 0
    count = 0
    for tag, i1, i2, _j1, _j2 in sm.get_opcodes():
        if tag in ("replace", "delete") and i2 > i1:
            if first == 0:
                first = i1 + 1
            last = i2
            count += i2 - i1
    return first, last, count


def derive_seeds(
    record: CveFixRecord,
    *,
    cwe: str = "",
    max_seeds: int = 1,
) -> list[CveSeedBundle]:
    """Mechanically derive synthesis seeds from the fix record.

    Candidates are non-test files with both pre- and post-fix source,
    a supported engine for their extension, and at least one changed
    pre-image line. Ranked by changed-line count (the file the fix
    rewrote most is the likeliest vulnerable site); the top
    ``max_seeds`` become seeds. The full pre/post file text rides as
    the ground-truth fixture pair; the seed snippet is the changed
    region plus context, capped at the synthesis snippet limit.
    """
    scored: list[tuple[int, int, int, CveFixFile]] = []
    for f in record.files:
        if f.is_test or not f.before_source or not f.after_source:
            continue
        if f.before_source == f.after_source:
            continue
        if detect_engine(f.path) is None:
            continue
        first, last, count = _changed_pre_lines(f.before_source, f.after_source)
        if count == 0:
            continue
        scored.append((count, first, last, f))
    scored.sort(key=lambda t: (-t[0], t[3].path))

    effective_cwe = cwe or record.cwe
    reasoning = (
        f"Pre-fix code changed by the public fix commit "
        f"{record.fix_commit[:12]} for {record.cve_id}."
    )
    if record.summary:
        reasoning += f" Root cause: {record.summary}"

    bundles: list[CveSeedBundle] = []
    for count, first, last, f in scored[:max_seeds]:
        lines = f.before_source.splitlines()
        lo = max(0, first - 1 - _SNIPPET_CONTEXT_LINES)
        hi = min(len(lines), last + _SNIPPET_CONTEXT_LINES)
        snippet = "\n".join(lines[lo:hi])
        if len(snippet.encode("utf-8")) > _SEED_SNIPPET_MAX_BYTES:
            snippet = snippet.encode("utf-8")[:_SEED_SNIPPET_MAX_BYTES] \
                .decode("utf-8", errors="ignore")
        seed = SeedBug(
            file=f.path,
            function="",
            line_start=first,
            line_end=last,
            cwe=effective_cwe,
            reasoning=reasoning,
            snippet=snippet,
            provenance=record.provenance,
        )
        bundles.append(CveSeedBundle(
            seed=seed,
            positive_text=f.before_source,
            negative_text=f.after_source,
        ))
        logger.debug(
            "cve seed: %s lines %d-%d (%d changed)", f.path, first, last, count,
        )
    return bundles


def synthesise_checker_from_cve(
    output_dir: Path | str,
    repo_root: Path | str,
    out_dir: Path | str,
    llm: LLMCallable,
    *,
    cwe: str = "",
    max_seeds: int = 1,
    max_iterations: int = 5,
    library_dir: Path | None = None,
    promote: bool = True,
) -> CveBridgeReport:
    """End-to-end: /cve-diff output → validated rule → RuleLibrary.

    ``repo_root`` is the codebase the synthesised rule is swept over
    (variant discovery + triage — the library's promotion gate needs
    triage verdicts, so an empty or unrelated repo yields a rule that
    passes controls but is reported as not promoted).

    Raises ProvenanceError for artifacts without public provenance.
    """
    record = load_cve_run(output_dir)
    report = CveBridgeReport(cve_id=record.cve_id, fix_commit=record.fix_commit)

    bundles = derive_seeds(record, cwe=cwe, max_seeds=max_seeds)
    report.seeds_derived = len(bundles)
    if not bundles:
        report.errors.append(
            "no synthesis seeds derivable: no non-test source file with "
            "a supported engine changed in the fix commit"
        )
        return report

    library = RuleLibrary(library_dir) if promote else None
    for bundle in bundles:
        result = synthesise_with_refinement(
            bundle.seed, Path(repo_root), Path(out_dir), llm,
            max_iterations=max_iterations,
            ground_truth_fixtures=(bundle.positive_text, bundle.negative_text),
        )
        report.results.append(result)
        if library is None or result.rule is None:
            continue
        entry = library.promote(result, source=bundle.seed.provenance)
        if entry is not None:
            report.promoted_rule_ids.append(entry.rule_id)
        elif result.rule_tier == "library":
            report.errors.append(
                f"{result.rule.rule_id}: library-tier rule not promoted "
                "(promotion needs triaged sweep matches — sweep the rule "
                "against a repo where variants exist)"
            )
    return report


# ---------------------------------------------------------------------------
# CLI (called by libexec/raptor-cve-checker; kept here for testability)
# ---------------------------------------------------------------------------


def _build_llm() -> LLMCallable | None:
    """Production LLM callable, or None when no LLM is configured."""
    try:
        from core.llm.client import LLMClient
        from core.llm.task_types import TaskType
    except ImportError:
        return None
    client = LLMClient()
    if not hasattr(client, "generate_structured"):
        return None

    def _call(prompt: str, schema: dict, system_prompt: str):
        try:
            data, _full = client.generate_structured(
                prompt=prompt,
                schema=schema,
                system_prompt=system_prompt,
                task_type=TaskType.ANALYSE,
            )
            return data
        except Exception as exc:  # noqa: BLE001 — transport failure degrades to no-rule
            logger.debug("cve-checker LLM call failed: %s", exc)
            return None

    return _call


def cli_main(argv: list[str] | None = None) -> int:
    """Entry point for ``libexec/raptor-cve-checker``.

    Exit codes: 0 = bridge ran (report on stdout, including failed
    synthesis — outcomes live in the report), 2 = usage or provenance
    error, 3 = no LLM configured.
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="raptor-cve-checker",
        description=(
            "Synthesise a validated checker rule from a /cve-diff run"
        ),
    )
    parser.add_argument(
        "output_dir",
        help="/cve-diff output directory (holds <CVE>.osv.json)",
    )
    parser.add_argument(
        "--repo", required=True,
        help="Repository root to sweep the synthesised rule over",
    )
    parser.add_argument(
        "--out", default=None,
        help="Where checkers/<rule>.{yml,cocci} land "
             "(default: <output_dir>/checkers-bridge)",
    )
    parser.add_argument("--cwe", default="",
                        help="CWE override (else root_cause.cwe_id from OSV)")
    parser.add_argument("--max-seeds", type=int, default=1)
    parser.add_argument("--max-iterations", type=int, default=5)
    parser.add_argument("--library-dir", default=None,
                        help="RuleLibrary directory (default: out/rule-library)")
    parser.add_argument("--no-promote", action="store_true",
                        help="Synthesise and report only; skip library promotion")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    repo_root = Path(args.repo).resolve()
    if not repo_root.is_dir():
        print(f"error: repo not found: {repo_root}", file=sys.stderr)
        return 2
    out_dir = Path(args.out) if args.out else output_dir / "checkers-bridge"

    # Provenance gate runs before the LLM is built: a refusal must not
    # depend on LLM availability.
    try:
        load_cve_run(output_dir)
    except ProvenanceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    llm = _build_llm()
    if llm is None:
        print(
            "error: no LLM configured — checker synthesis proposes rules "
            "via the LLM (validation is mechanical). Configure a model "
            "and retry.",
            file=sys.stderr,
        )
        return 3

    report = synthesise_checker_from_cve(
        output_dir, repo_root, out_dir, llm,
        cwe=args.cwe,
        max_seeds=args.max_seeds,
        max_iterations=args.max_iterations,
        library_dir=Path(args.library_dir) if args.library_dir else None,
        promote=not args.no_promote,
    )
    print(dumps_display(report.to_dict(), indent=2))
    return 0
