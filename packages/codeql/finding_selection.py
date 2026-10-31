"""Select CodeQL analysis candidates across all SARIF producers."""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from core.hash import sha256_string
from core.logging import get_logger
from core.sarif.parser import get_result_rule, load_sarif, rule_default_level

logger = get_logger()


@dataclass(frozen=True)
class AnalysisCandidate:
    sarif_file: Path
    run: dict
    result: dict


def all_run_results(sarif: dict) -> list[tuple[dict, dict]]:
    """Keep every result paired with its owning run, in document order."""
    runs = sarif.get("runs")
    if not isinstance(runs, list):
        return []
    return [
        (run, result)
        for run in runs if isinstance(run, dict)
        if isinstance(run.get("results"), list)
        for result in run["results"] if isinstance(result, dict)
    ]


def _content_key(value: dict) -> str:
    # Keep sort keys small even when results contain large dataflow traces.
    return sha256_string(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ))


def select_findings_for_analysis(
    sarif_files: Iterable[str | Path], cap: int,
) -> tuple[list[AnalysisCandidate], int]:
    """Apply one global cap using shared signals and stable SARIF tie-breaks.

    Scoring uses copies, including inherited rule severity when needed.
    The analyzer receives the original result and its original run. No
    cross-tool deduplication or synthetic exploitability signals are added.
    """
    from core.orchestration.skill_dispatch import rank_findings_by_signal

    records = []
    seen_paths: set[Path] = set()
    candidate_count = 0
    for sarif_file in sarif_files:
        path = Path(sarif_file)
        try:
            path = path.resolve()
        except (OSError, RuntimeError):
            logger.warning("Could not resolve SARIF path: %s", path)
            continue
        if path in seen_paths:
            continue
        seen_paths.add(path)
        sarif = load_sarif(path)
        if not sarif:
            continue
        run_contexts: dict[int, str] = {}
        for run, result in all_run_results(sarif):
            candidate_count += 1
            if cap <= 0:
                continue
            if id(run) not in run_contexts:
                run_contexts[id(run)] = _content_key(
                    {k: v for k, v in run.items() if k != "results"},
                )
            run_key = run_contexts[id(run)]
            signal = dict(result)
            if signal.get("level") is None:
                rule = get_result_rule(run, result)
                signal["level"] = rule_default_level(rule) or "warning"
            candidate = AnalysisCandidate(path, run, result)
            records.append(((_content_key(result), run_key, str(path)), signal, candidate))

    # Stable sort before the shared ranker makes ties independent of file,
    # run, and result enumeration. Run metadata disambiguates equal results
    # without letting other results in that run influence the tie-break.
    records.sort(key=lambda record: record[0])
    by_signal = {id(signal): candidate for _key, signal, candidate in records}
    ranked = rank_findings_by_signal([signal for _key, signal, _candidate in records])
    selected = [by_signal[id(signal)] for signal in ranked[:max(0, cap)]]
    logger.info(
        "CodeQL analysis selection: %d of %d candidates selected globally; %d deferred",
        len(selected), candidate_count, candidate_count - len(selected),
    )
    return selected, candidate_count
