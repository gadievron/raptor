"""External ground-truth seed sources for checker synthesis.

Synthesis historically seeded only from the current run's own review
outcomes — RAPTOR could synthesize checkers only from bugs it had just
found itself. This module adds bounded external seed sources, each
carrying provenance:

* **Journal findings** (current + prior runs): confirmed ``finding``
  verdicts from the review journal / project index become repo-anchored
  seeds.
* **Crash RCAs**: /agentic fuzz crash triage (``crash_analysis/
  crash-contexts.json``) resolves crash sites to source seeds.
* **cvefix corpus**: TP-labeled entries from the cvefix corpus
  machinery become external seeds with ground-truth fixture pairs
  (pre-fix snippet = positive, post-fix form = negative) — the dual
  control the synthesiser requires, anchored to a known CVE instead of
  an LLM guess.

Every source is bounded (:data:`MAX_SEEDS_PER_SOURCE`); the overall
synthesis spend stays under the run's ``MAX_SYNTHESIS_PER_RUN`` cap at
the call site.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Per-source seed budget. The synthesis lane cap
# (checker_synthesis.MAX_SYNTHESIS_PER_RUN) still bounds total spend.
MAX_SEEDS_PER_SOURCE = 2

# Crash-type → CWE hints for crash-context seeds.
_CRASH_TYPE_CWE = {
    "heap_overflow": "CWE-122",
    "heap-buffer-overflow": "CWE-122",
    "stack_overflow": "CWE-121",
    "stack-buffer-overflow": "CWE-121",
    "buffer_overflow": "CWE-120",
    "use_after_free": "CWE-416",
    "heap-use-after-free": "CWE-416",
    "double_free": "CWE-415",
    "null_deref": "CWE-476",
    "null_dereference": "CWE-476",
    "format_string": "CWE-134",
    "integer_overflow": "CWE-190",
    "uninitialized": "CWE-457",
    "out_of_bounds": "CWE-125",
}


@dataclass(frozen=True)
class ExternalSeed:
    """A seed plus optional ground-truth fixture pair.

    ``positive_fixture`` / ``negative_fixture`` are set only for seeds
    whose file is NOT present in the audit target (cvefix): the
    substrate's ground-truth control uses them instead of the
    repo-anchored positive control.
    """

    seed: Any  # packages.checker_synthesis.SeedBug
    positive_fixture: str | None = None
    negative_fixture: str | None = None


def _snippet_for(
    target_path: Path, file_path: str, line_start: int, line_end: int,
) -> str:
    """Bounded source snippet under path containment; "" on any miss."""
    if not file_path or line_start <= 0:
        return ""
    try:
        target = Path(target_path).resolve()
        full = (target / file_path).resolve()
        full.relative_to(target)
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
    except (ValueError, OSError):
        return ""
    end = min(line_end or line_start, line_start + 120, len(lines))
    return "\n".join(lines[line_start - 1: end])[:8000]


def _entry_reasoning(entry: Any) -> str:
    """Best hypothesis text from a journal entry."""
    hyps = getattr(entry, "hypotheses", None) or []
    for h in hyps:
        if isinstance(h, dict) and (h.get("mechanism") or "").strip():
            return str(h["mechanism"]).strip()[:500]
    body = getattr(entry, "body", "") or ""
    return str(body).strip()[:500]


def seeds_from_journal(
    out_dir: Path | None,
    project_dir: Path | None,
    target_path: Path,
    *,
    exclude_keys: set[tuple[str, str]] | frozenset = frozenset(),
    max_seeds: int = MAX_SEEDS_PER_SOURCE,
) -> list[ExternalSeed]:
    """Confirmed findings from the current run's journal + prior runs.

    Prior runs come through the project index (latest verdict per
    function). Entries need a CWE and a hypothesis to seed synthesis.
    """
    try:
        from core.coverage.journal import load_entries, load_index
        from packages.checker_synthesis import SeedBug
    except ImportError:
        logger.debug("journal seed source unavailable", exc_info=True)
        return []

    entries: list[tuple[str, Any]] = []
    if out_dir is not None:
        try:
            for e in load_entries(Path(out_dir)):
                entries.append(("journal:current", e))
        except Exception:
            logger.debug("journal load failed", exc_info=True)
    if project_dir is not None:
        try:
            for e in load_index(Path(project_dir)).values():
                run_id = getattr(e, "run_id", "") or "prior"
                entries.append((f"journal:{run_id}", e))
        except Exception:
            logger.debug("journal index load failed", exc_info=True)

    seeds: list[ExternalSeed] = []
    seen: set[tuple[str, str]] = set(exclude_keys)
    for provenance, entry in entries:
        if len(seeds) >= max_seeds:
            break
        if getattr(entry, "verdict", "") != "finding":
            continue
        file_path = getattr(entry, "file", "") or ""
        function = getattr(entry, "function", "") or ""
        cwe = getattr(entry, "cwe", "") or ""
        if not file_path or not function or not cwe:
            continue
        key = (file_path, function)
        if key in seen:
            continue
        reasoning = _entry_reasoning(entry)
        if not reasoning:
            continue
        seen.add(key)
        line_start = int(getattr(entry, "line_start", 0) or 0)
        line_end = int(getattr(entry, "line_end", 0) or line_start)
        seeds.append(
            ExternalSeed(
                seed=SeedBug(
                    file=file_path,
                    function=function,
                    line_start=line_start,
                    line_end=line_end,
                    cwe=cwe,
                    reasoning=reasoning,
                    snippet=_snippet_for(
                        target_path, file_path, line_start, line_end,
                    ),
                    provenance=provenance,
                )
            )
        )
    return seeds


def seeds_from_crash_contexts(
    run_dirs: list[Path],
    target_path: Path,
    *,
    checklist: dict[str, Any] | None = None,
    max_seeds: int = MAX_SEEDS_PER_SOURCE,
) -> list[ExternalSeed]:
    """Seeds from fuzz crash triage artifacts (crash RCAs).

    Reads ``crash_analysis/crash-contexts.json`` from each run dir.
    A context needs a resolvable ``source_location`` (``file:line``
    inside the target); the function span comes from the checklist
    when available.
    """
    try:
        from packages.checker_synthesis import SeedBug
    except ImportError:
        return []

    target = Path(target_path).resolve()
    seeds: list[ExternalSeed] = []
    seen: set[tuple[str, int]] = set()

    for run_dir in run_dirs:
        if len(seeds) >= max_seeds:
            break
        path = Path(run_dir) / "crash_analysis" / "crash-contexts.json"
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for ctx in data.get("contexts", []):
            if len(seeds) >= max_seeds:
                break
            if not isinstance(ctx, dict):
                continue
            loc = str(ctx.get("source_location") or "")
            file_part, _, line_part = loc.rpartition(":")
            try:
                line = int(line_part)
            except ValueError:
                continue
            if not file_part or line <= 0:
                continue
            rel = _relativize(file_part, target)
            if rel is None:
                continue
            if (rel, line) in seen:
                continue
            seen.add((rel, line))

            function = str(ctx.get("function_name") or "") or "unknown"
            line_start, line_end = line, line
            if checklist:
                try:
                    from core.inventory.lookup import lookup_function

                    func = lookup_function(
                        checklist, rel, line, repo_root=str(target),
                    )
                    if func and func.get("name"):
                        function = func["name"]
                        line_start = int(func.get("line_start") or line)
                        line_end = int(func.get("line_end") or line)
                except (ValueError, TypeError, OSError):
                    pass

            crash_type = str(ctx.get("crash_type") or "").lower()
            cwe = _CRASH_TYPE_CWE.get(crash_type, "")
            analysis = ctx.get("analysis") or {}
            extra = ""
            if isinstance(analysis, dict):
                extra = str(analysis.get("reasoning") or "")[:300]
            reasoning = (
                f"Fuzzing crash {ctx.get('crash_id', '?')}: "
                f"{crash_type or 'crash'} at {rel}:{line} "
                f"(signal {ctx.get('signal', '?')}, "
                f"exploitability {ctx.get('exploitability', '?')})."
            )
            if extra:
                reasoning = f"{reasoning} {extra}"
            seeds.append(
                ExternalSeed(
                    seed=SeedBug(
                        file=rel,
                        function=function,
                        line_start=line_start,
                        line_end=line_end,
                        cwe=cwe,
                        reasoning=reasoning[:500],
                        snippet=_snippet_for(
                            target, rel, line_start, line_end,
                        ),
                        provenance=f"crash:{ctx.get('crash_id', '?')}",
                    )
                )
            )
    return seeds


def _relativize(file_part: str, target: Path) -> str | None:
    """Make a crash-report path target-relative; None when it escapes."""
    try:
        p = Path(file_part)
        if p.is_absolute():
            return str(p.resolve().relative_to(target))
        (target / p).resolve().relative_to(target)
        return str(p)
    except (ValueError, OSError):
        return None


def seeds_from_cvefix_corpus(
    corpus_dir: Path,
    *,
    max_seeds: int = MAX_SEEDS_PER_SOURCE,
) -> list[ExternalSeed]:
    """Seeds from a cvefix-mined corpus (``write_corpus`` layout).

    TP-labeled findings (pre-fix, the vulnerable form) become external
    seeds whose positive fixture is the finding's sink snippet; when an
    FP-labeled sibling for the same file exists (post-fix, still
    flagged) its snippet becomes the ground-truth negative fixture.
    """
    corpus_dir = Path(corpus_dir)
    if not corpus_dir.is_dir():
        return []
    try:
        from packages.checker_synthesis import SeedBug
    except ImportError:
        return []

    tps: list[dict[str, Any]] = []
    fp_snippets: dict[str, str] = {}

    for label_path in sorted(corpus_dir.glob("*.label.json")):
        finding_path = corpus_dir / label_path.name.replace(
            ".label.json", ".json",
        )
        if not finding_path.is_file():
            continue
        try:
            label = json.loads(label_path.read_text(encoding="utf-8"))
            finding = json.loads(finding_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        sink = finding.get("sink") or {}
        file_path = str(sink.get("file_path") or "")
        snippet = str(sink.get("snippet") or "")
        if not file_path or not snippet.strip():
            continue
        verdict = str(label.get("verdict") or "")
        if verdict == "true_positive":
            tps.append({"finding": finding, "label": label})
        elif verdict == "false_positive":
            fp_snippets.setdefault(file_path, snippet)

    seeds: list[ExternalSeed] = []
    seen_files: set[str] = set()
    for item in tps:
        if len(seeds) >= max_seeds:
            break
        finding = item["finding"]
        sink = finding.get("sink") or {}
        file_path = str(sink.get("file_path") or "")
        if file_path in seen_files:
            continue
        seen_files.add(file_path)
        snippet = str(sink.get("snippet") or "")
        line = int(sink.get("line") or 1)
        rule_id = str(finding.get("rule_id") or "")
        message = str(finding.get("message") or "")
        cwe = _cwe_for_rule(rule_id, message)
        finding_id = str(finding.get("finding_id") or "cve")
        seeds.append(
            ExternalSeed(
                seed=SeedBug(
                    file=file_path,
                    function="",
                    line_start=line,
                    line_end=line,
                    cwe=cwe,
                    reasoning=(
                        f"Known-CVE vulnerable pattern ({finding_id}, "
                        f"rule {rule_id}): {message}"
                    )[:500],
                    snippet=snippet[:8000],
                    provenance=f"cvefix:{finding_id}",
                ),
                positive_fixture=snippet,
                negative_fixture=fp_snippets.get(file_path),
            )
        )
    return seeds


def _cwe_for_rule(rule_id: str, message: str) -> str:
    try:
        from core.sarif.import_normalizer import _infer_cwe

        return _infer_cwe(rule_id, message) or ""
    except Exception:
        logger.debug("cvefix cwe inference failed", exc_info=True)
        return ""


def collect_external_seeds(
    config: Any,
    *,
    checklist: dict[str, Any] | None = None,
    exclude_keys: set[tuple[str, str]] | frozenset = frozenset(),
    max_per_source: int = MAX_SEEDS_PER_SOURCE,
) -> list[ExternalSeed]:
    """Gather bounded seeds from every available external source.

    Sources: journal (current run + project index), crash contexts
    (own run + project siblings), cvefix corpus
    (``<out_dir>/cvefix/corpus`` or ``config.cvefix_corpus_dir``).
    """
    out_dir = getattr(config, "out_dir", None)
    target_path = getattr(config, "target_path", None)
    if not target_path:
        return []

    project_dir = None
    run_dirs: list[Path] = []
    if out_dir:
        run_dirs.append(Path(out_dir))
        try:
            if (Path(out_dir) / ".raptor-run.json").exists():
                project_dir = Path(out_dir).parent
            from .joern_backend import sibling_run_dirs

            run_dirs.extend(
                sibling_run_dirs(out_dir, target_path=target_path)
            )
        except Exception:
            logger.debug("sibling discovery failed", exc_info=True)

    seeds: list[ExternalSeed] = []
    try:
        seeds.extend(
            seeds_from_journal(
                out_dir,
                project_dir,
                target_path,
                exclude_keys=exclude_keys,
                max_seeds=max_per_source,
            )
        )
    except Exception:
        logger.debug("journal seed source failed", exc_info=True)
    try:
        seeds.extend(
            seeds_from_crash_contexts(
                run_dirs,
                target_path,
                checklist=checklist,
                max_seeds=max_per_source,
            )
        )
    except Exception:
        logger.debug("crash seed source failed", exc_info=True)
    try:
        corpus_dir = getattr(config, "cvefix_corpus_dir", None)
        if corpus_dir is None and out_dir:
            corpus_dir = Path(out_dir) / "cvefix" / "corpus"
        if corpus_dir is not None:
            seeds.extend(
                seeds_from_cvefix_corpus(
                    Path(corpus_dir), max_seeds=max_per_source,
                )
            )
    except Exception:
        logger.debug("cvefix seed source failed", exc_info=True)

    return seeds
