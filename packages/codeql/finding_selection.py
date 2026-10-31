"""Select CodeQL analysis candidates across all SARIF producers."""

from __future__ import annotations

import heapq
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


def _duplicate_key(
    run: dict, result: dict, rule: dict, owner: dict | None,
    context_keys: dict[tuple[str, int], str],
) -> str | None:
    """Merge only reports with matching rule, source context, and evidence.

    Keep all locations, flows, fingerprints, messages, and result properties
    in the identity. Missing usable rule/location metadata disables merging.
    Only ranking fields and run-local descriptor references are excluded.
    """
    tool = run.get("tool")
    if not isinstance(tool, dict):
        return None
    driver = tool.get("driver")
    if not isinstance(driver, dict) or not isinstance(driver.get("name"), str):
        return None
    if not isinstance(rule.get("id"), str) or not rule["id"]:
        return None
    if not isinstance(owner, dict) or not isinstance(owner.get("name"), str):
        return None
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations or not isinstance(locations[0], dict):
        return None
    physical = locations[0].get("physicalLocation")
    if not isinstance(physical, dict):
        return None
    artifact = physical.get("artifactLocation")
    region = physical.get("region")
    if not isinstance(artifact, dict) or not isinstance(artifact.get("uri"), str) or not artifact["uri"]:
        return None
    if not isinstance(region, dict) or type(region.get("startLine")) is not int or region["startLine"] <= 0:
        return None
    message = result.get("message")
    if not isinstance(message, dict) or not any(
        isinstance(message.get(key), str) and message[key] for key in ("text", "markdown")
    ):
        return None

    def namespace(component):
        key = ("component", id(component))
        if key not in context_keys:
            context_keys[key] = _content_key({
                key: value for key, value in component.items() if key != "rules"
            })
        return context_keys[key]

    descriptor_key = ("rule", id(rule))
    if descriptor_key not in context_keys:
        descriptor = dict(rule)
        config = descriptor.get("defaultConfiguration")
        if isinstance(config, dict):
            config = {key: value for key, value in config.items() if key != "level"}
            if config:
                descriptor["defaultConfiguration"] = config
            else:
                descriptor.pop("defaultConfiguration")
        context_keys[descriptor_key] = _content_key(descriptor)
    source_key = ("run", id(run))
    if source_key not in context_keys:
        # Hash shared tables once per run, never once per finding: large
        # artifact tables otherwise multiply serialization work by results.
        context_keys[source_key] = _content_key({
            "tables": {key: run[key] for key in (
                "originalUriBaseIds", "artifacts", "logicalLocations",
                "addresses", "specialLocations", "taxonomies", "graphs",
                "threadFlowLocations", "webRequests", "webResponses",
                "externalPropertyFileReferences", "versionControlProvenance",
            ) if key in run},
            "working_directories": [invocation.get("workingDirectory")
                                    for invocation in run.get("invocations", [])
                                    if isinstance(invocation, dict) and "workingDirectory" in invocation]
            if isinstance(run.get("invocations"), list) else [],
        })
    evidence = {key: value for key, value in result.items() if key not in {
        "ruleId", "ruleIndex", "rule", "level", "is_exploitable",
        "exploitability_score", "tree_class",
    }}
    return _content_key({
        "driver": namespace(driver), "component": namespace(owner),
        "descriptor": context_keys[descriptor_key], "evidence": evidence,
        "source_context": context_keys[source_key],
    })



@dataclass(eq=False)
class _HeapEntry:
    rank: tuple
    duplicate_key: str | None
    candidate: AnalysisCandidate

    def __lt__(self, other: _HeapEntry) -> bool:
        # heapq exposes the worst retained candidate at the root.
        return self.rank > other.rank


def _scan_file(
    path: Path, cap: int, heap: list[_HeapEntry],
    selected_groups: dict[str, _HeapEntry], seen_duplicates: set[str],
    ordinal: int,
) -> tuple[int, int]:
    """Load one document; retain payloads only for its current winners."""
    # Reuse the batch sorter's existing key; keep the policy in one place.
    from core.orchestration.skill_dispatch import _signal_key

    sarif = load_sarif(path)
    if not sarif or not isinstance(sarif.get("runs"), list):
        return 0, 0
    candidate_count = duplicate_count = 0
    for run in sarif["runs"]:
        if not isinstance(run, dict) or not isinstance(run.get("results"), list):
            continue
        run_key = _content_key({k: v for k, v in run.items() if k != "results"})
        rule_owners: dict[int, dict] = {}
        context_keys: dict[tuple[str, int], str] = {}
        resolved_rules: dict[str, dict] = {}
        tool = run.get("tool")
        if isinstance(tool, dict):
            extensions = tool.get("extensions")
            components = [tool.get("driver"), *(extensions if isinstance(extensions, list) else [])]
            for component in components:
                if isinstance(component, dict) and isinstance(component.get("rules"), list):
                    rule_owners.update({id(rule): component for rule in component["rules"]
                                        if isinstance(rule, dict)})
        analysis_run = None
        for result in run["results"]:
            if not isinstance(result, dict):
                continue
            candidate_count += 1
            reference_key = _content_key({
                key: result[key] for key in ("ruleId", "ruleIndex", "rule") if key in result
            })
            if reference_key not in resolved_rules:
                resolved_rules[reference_key] = get_result_rule(run, result)
            rule = resolved_rules[reference_key]
            duplicate_key = _duplicate_key(run, result, rule, rule_owners.get(id(rule)), context_keys)
            if duplicate_key is not None:
                if duplicate_key in seen_duplicates:
                    duplicate_count += 1
                else:
                    seen_duplicates.add(duplicate_key)
            if cap <= 0:
                continue
            signal = dict(result)
            if signal.get("level") is None:
                signal["level"] = rule_default_level(rule) or "warning"
            # Matches stable content-sort followed by stable signal-sort.
            # Ordinal preserves the old encounter order for exact ties.
            rank = (_signal_key(signal), _content_key(result), run_key,
                    str(path), ordinal + candidate_count)
            previous = selected_groups.get(duplicate_key) if duplicate_key is not None else None
            if previous is not None:
                if rank >= previous.rank:
                    continue
                heap.remove(previous)
                heapq.heapify(heap)
            elif len(heap) >= cap and rank >= heap[0].rank:
                continue
            if analysis_run is None:
                # The analyzer reads the selected result plus run metadata.
                # Keeping run.results here would retain every sibling payload.
                analysis_run = {key: value for key, value in run.items() if key != "results"}
            entry = _HeapEntry(rank, duplicate_key, AnalysisCandidate(path, analysis_run, result))
            if len(heap) < cap:
                heapq.heappush(heap, entry)
            else:
                evicted = heapq.heapreplace(heap, entry)
                if evicted.duplicate_key is not None:
                    del selected_groups[evicted.duplicate_key]
            if duplicate_key is not None:
                selected_groups[duplicate_key] = entry
    return candidate_count, duplicate_count


def select_findings_for_analysis(
    sarif_files: Iterable[str | Path], cap: int,
) -> tuple[list[AnalysisCandidate], int, int]:
    """Select the exact global top unique reports without retaining all payloads.

    Keep at most cap candidate payloads across files, one document while it is
    scanned, and compact identities for exact duplicate counts. Run metadata
    is preserved; each returned run.results contains only its selected reports.
    """
    heap: list[_HeapEntry] = []
    selected_groups: dict[str, _HeapEntry] = {}
    seen_paths: set[Path] = set()
    seen_duplicates: set[str] = set()
    candidate_count = duplicate_count = 0
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
        count, duplicates = _scan_file(
            path, cap, heap, selected_groups, seen_duplicates, candidate_count,
        )
        candidate_count += count
        duplicate_count += duplicates
    selected = [entry.candidate for entry in sorted(heap, key=lambda entry: entry.rank)]
    for candidate in selected:
        candidate.run.setdefault("results", []).append(candidate.result)
    logger.info(
        "CodeQL analysis selection: %d of %d reports selected globally; "
        "%d duplicates removed; %d unique candidates deferred",
        len(selected), candidate_count, duplicate_count,
        candidate_count - duplicate_count - len(selected),
    )
    return selected, candidate_count, duplicate_count
