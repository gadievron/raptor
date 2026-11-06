"""
RAPTOR SARIF Utilities

Utilities for working with SARIF (Static Analysis Results Interchange Format) files,
including validation, deduplication, and merging.
"""

import hashlib
import json
import math
import os
import re
import stat as stat_mod
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit, quote

from core.detectors.compiler_families import compiler_diagnostic_is_candidate
from core.detectors.compiler_paths import PathBudget, PATH_KIND, attach_paths
from core.config import RaptorConfig
from core.json import dumps_canonical, iterencode_canonical, load_json, loads
from core.logging import get_logger
from core.security.log_sanitisation import escape_nonprintable

logger = get_logger()

# One SARIF read cap for every consumer that loads a whole SARIF
# document into memory (this parser plus the core/dataflow corpus /
# bridge / diff loaders alias it). Trade-off, both directions:
# raising it admits bigger artifacts at proportional memory cost
# (documents are parsed whole, so the cap is effectively a per-load
# RSS budget); lowering it starts refusing legitimate large
# combined.sarif files from full CodeQL+semgrep runs on big targets.
# 100 MiB has held for real combined runs — move it only against a
# corpus of observed artifact sizes.
SARIF_MAX_BYTES = 100 * 1024 * 1024


def _as_dict(value: Any) -> dict[str, Any]:
    """Untrusted-shape guard: return *value* if it is a dict, else {}.

    SARIF nesting (`tool.driver`, `physicalLocation.region`, ...) is
    attacker-controlled — a crafted file can put a string or null where
    the spec says object, and a bare `.get()` chain then raises
    AttributeError and aborts the whole import."""
    return value if isinstance(value, dict) else {}


def _text_value(value: Any) -> str | None:
    """Read optional SARIF text without coercing malformed display metadata."""
    text = _as_dict(value).get("text")
    return text if isinstance(text, str) else None


def _snippet_text(physical_location: Any) -> str:
    """Prefer a region's snippet, then a usable context-region snippet."""
    physical = _as_dict(physical_location)
    region = _as_dict(physical.get("region"))
    context = _as_dict(physical.get("contextRegion"))
    return _text_value(region.get("snippet")) or _text_value(context.get("snippet")) or ""


def _coerce_line(value: Any) -> int | None:
    """Coerce an untrusted SARIF line/column value to int, or None.

    CPython's json.loads accepts strings, floats, and Infinity/NaN
    where SARIF says integer. Non-integer values that flow into line
    arithmetic or list slicing raise TypeError far from the parse
    boundary, so anything that is not a genuine integer (or an
    integral finite float) becomes None — downstream gates then treat
    the field as absent instead of crashing."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and math.isfinite(value) and value.is_integer():
        return int(value)
    return None


# Per-step ``properties`` sanitisation bounds. SARIF threadFlow
# location properties are producer-supplied (the cross-file taint
# engine serializes per-hop tier/kind/tags there) but arrive from an
# UNTRUSTED file, so the carry is allowlisted-by-type and bounded.
# Raising the caps admits more attacker-shaped bytes into every
# downstream consumer of dataflow_path (prompts, reports); lowering
# them truncates legitimate producer vocabulary (tag lists, sanitizer
# name lists) and consumers lose tier evidence.
_STEP_PROPS_MAX_KEYS = 16
_STEP_PROPS_MAX_STRING = 256
_STEP_PROPS_MAX_LIST = 16


def _sanitize_step_properties(props: Any) -> dict[str, Any]:
    """Bounded, display-inert copy of a threadFlow location's
    ``properties`` bag.

    Keeps only value shapes the step contract uses — strings
    (escaped + capped), bools, ints, and lists of strings (each
    escaped + capped, list capped) — under capped, escaped string
    keys. Everything else is dropped: an unexpected nested object or
    float in an untrusted SARIF earns no ride into ``dataflow_path``.
    Returns ``{}`` (caller omits the key) for non-dict input.
    """
    if not isinstance(props, dict):
        return {}
    out: dict[str, Any] = {}
    for key, value in props.items():
        if len(out) >= _STEP_PROPS_MAX_KEYS:
            break
        if not isinstance(key, str):
            continue
        safe_key = escape_nonprintable(key)[:_STEP_PROPS_MAX_STRING]
        if isinstance(value, bool):
            out[safe_key] = value
        elif isinstance(value, int):
            out[safe_key] = value
        elif isinstance(value, str):
            out[safe_key] = escape_nonprintable(
                value)[:_STEP_PROPS_MAX_STRING]
        elif isinstance(value, list):
            out[safe_key] = [
                escape_nonprintable(item)[:_STEP_PROPS_MAX_STRING]
                for item in value[:_STEP_PROPS_MAX_LIST]
                if isinstance(item, str)
            ]
    return out


def _thread_flow_location(wrapper: Any, cached_locations: Any) -> dict[str, Any] | None:
    """Resolve one run-owned cached hop; reject conflicting or chained references.

    SARIF 2.1.0 section 3.38.2 requires inline properties to agree with
    the cached object. Only direct array indexing is used, with no traversal.
    """
    if not isinstance(wrapper, dict):
        return None
    index = wrapper.get("index", -1)
    if type(index) is not int or index < -1:
        return None
    if index == -1:
        return wrapper
    if not isinstance(cached_locations, list) or index >= len(cached_locations):
        return None
    cached = cached_locations[index]
    if not isinstance(cached, dict):
        return None
    if "index" in cached and (type(cached["index"]) is not int or cached["index"] != index):
        return None
    if any(key != "index" and value != cached.get(key) for key, value in wrapper.items()):
        return None
    return cached


def _path_from_locations(
    locations: list[dict[str, Any]],
    *, resolve_uri: Callable[[dict[str, Any]], str | None] | None = None,
    thread_flow_locations: Any = None,
) -> dict[str, Any] | None:
    """Build a {source, sink, steps, total_steps} dict from one
    SARIF threadFlow's locations array. Returns None if there are
    fewer than 2 locations (no source-to-sink path).

    Each step carries a sanitized copy of the threadFlow location's
    ``properties`` bag when one is present (the cross-file taint
    engine's per-hop tier/kind/tags surface); locations without
    properties produce the exact pre-existing step shape."""
    if len(locations) < 2:
        return None
    path: dict[str, Any] = {
        "source": None,
        "sink": None,
        "steps": [],
        "total_steps": len(locations),
    }
    for idx, raw_wrapper in enumerate(locations):
        loc_wrapper = _thread_flow_location(raw_wrapper, thread_flow_locations)
        if loc_wrapper is None:
            return None
        location = loc_wrapper.get("location", {})
        physical_loc = location.get("physicalLocation") or {}
        artifact = physical_loc.get("artifactLocation", {})
        region = physical_loc.get("region") or {}
        # Untrusted scanner-supplied text — escape control / format
        # bytes before surfacing into the operator-facing dataflow
        # path. A scanner producing `message.text = "evil\x1b[2J"`
        # (clear-screen ANSI escape, terminal hijack on stdout
        # render) or a code snippet containing C1 controls / bidi
        # overrides could otherwise smuggle terminal-rendering
        # behaviour through the dataflow display layer.
        message = escape_nonprintable(_text_value(location.get("message")) or "")
        snippet = escape_nonprintable(_snippet_text(physical_loc))
        file_uri = resolve_uri(artifact) if resolve_uri is not None else artifact.get("uri", "")
        if resolve_uri is not None and file_uri is None:
            return None
        step_info = {
            "file": file_uri,
            "line": _coerce_line(region.get("startLine")) or 0,
            "column": _coerce_line(region.get("startColumn")) or 0,
            "label": message,
            "snippet": snippet,
        }
        step_props = _sanitize_step_properties(loc_wrapper.get("properties"))
        if step_props:
            step_info["properties"] = step_props
        if idx == 0:
            path["source"] = step_info
        elif idx == len(locations) - 1:
            path["sink"] = step_info
        else:
            path["steps"].append(step_info)
    return path


def extract_dataflow_path(
    code_flows: list[dict[str, Any]], *,
    resolve_uri: Callable[[dict[str, Any]], str | None] | None = None,
    thread_flow_locations: Any = None,
) -> dict[str, Any] | None:
    """
    Extract dataflow path information from SARIF codeFlows.

    Pre-fix only `codeFlows[0].threadFlows[0]` was returned. SARIF
    results commonly carry multiple code flows (one per source-to-sink
    path the analyser identified) and multiple thread flows (one per
    relevant thread). Picking only the first hid genuinely-different
    paths from the operator — the second sink for the same source, the
    second source feeding the same sink, etc.

    An optional run-owned URI resolver applies to every hop. Returning
    None rejects that path while leaving sibling thread flows available.
    Without a resolver, explicit URI behavior is unchanged. The optional
    ``thread_flow_locations`` table belongs to the same run; unresolved or
    conflicting indexed hops reject their whole path, never bridge over it.

    Returns:
        Dict with `source`/`sink`/`steps`/`total_steps` for the first
        usable path (back-compat for existing callers), plus an
        `alternative_paths` list of the same dict-shape for every
        OTHER (codeFlow, threadFlow) combination that produced a
        valid 2+ location path. Empty list when the first is the
        only path.
    """
    if not code_flows:
        return None

    all_paths: list[dict[str, Any]] = []
    for flow in code_flows:
        try:
            thread_flows = flow.get("threadFlows") or []
            if not isinstance(thread_flows, list):
                raise TypeError("threadFlows must be an array")
            malformed_thread_reported = False
            for tflow in thread_flows:
                try:
                    locations = tflow.get("locations") or []
                    p = _path_from_locations(
                        locations, resolve_uri=resolve_uri,
                        thread_flow_locations=thread_flow_locations,
                    )
                    if p is not None:
                        all_paths.append(p)
                except Exception as e:  # noqa: BLE001
                    if not malformed_thread_reported:
                        logger.warning("SARIF parser: skipping malformed threadFlow(s): %s", e)
                        malformed_thread_reported = True
        except Exception as e:  # noqa: BLE001
            logger.warning("SARIF parser: skipping malformed codeFlow: %s", e)
            continue

    if not all_paths:
        return None

    primary = all_paths[0]
    primary["alternative_paths"] = all_paths[1:]
    return primary


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Retain distinct tool evidence and collapse repeated reports.

    Identity includes the normalized tool, validated rule scope, location,
    rule and finding ID. When distinct retained records reuse a finding ID,
    qualify only those colliding IDs so downstream artifact files and
    ID-keyed maps remain distinct.
    The original ID is retained as source_finding_id. Input rows are not
    mutated; ordinary IDs and legacy same-tool deduplication are unchanged.
    """
    scopes: dict[tuple[str, str], str] = {}

    def finding_scope(finding):
        name = finding.get("tool")
        name = name if isinstance(name, str) else ""
        origin = finding.get("rule_scope")
        origin = origin if isinstance(origin, str) else ""
        key = (name, origin)
        if key not in scopes:
            tool = _normalise_tool_name(name)
            scopes[key] = dumps_canonical([tool, origin]) if origin else tool
        return scopes[key]

    def column_identity(finding):
        start = _coerce_line(finding.get("startColumn")) or 0
        end = _coerce_line(finding.get("endColumn")) or 0
        start, end = max(start, 0), max(end, 0)
        return ("columns", start, end) if start or end else ()

    owners: dict[str, tuple] = {}
    collisions: set[str] = set()
    seen: set[tuple] = set()
    unique: list[dict[str, Any]] = []
    for finding in findings:
        scope = finding_scope(finding)
        fid = finding.get("finding_id")
        fp = (
            scope,
            finding.get("file"),
            finding.get("startLine"),
            finding.get("endLine"),
            finding.get("rule_id"),
            fid,
            *column_identity(finding),
        )
        if isinstance(fid, str) and fid:
            if owners.setdefault(fid, fp) != fp:
                collisions.add(fid)
        if fp not in seen:
            seen.add(fp)
            unique.append(finding)

    if not collisions:
        return unique

    def source_key(finding):
        return (finding["finding_id"], finding_scope(finding), finding.get("file"),
                finding.get("startLine"), finding.get("endLine"), finding.get("rule_id"),
                *column_identity(finding))

    sources = {source_key(finding) for finding in unique
               if isinstance(finding.get("finding_id"), str)
               and finding["finding_id"] in collisions}
    scope_counts: dict[tuple, int] = {}
    for source in sources:
        scope_counts[source[:2]] = scope_counts.get(source[:2], 0) + 1
    qualified: dict[tuple, str] = {}
    reserved = set(owners)
    # Deterministic order also makes collision avoidance independent of
    # report ordering. Reserve original IDs, not just generated ones.
    for source in sorted(sources, key=lambda value: (value[0], value[1], dumps_canonical(value[2:]))):
        fid, scope = source[:2]
        # Keep existing cross-scope IDs byte-for-byte. Add location/rule
        # material only when a single scope itself reuses the source ID.
        if scope_counts[source[:2]] > 1:
            scope = dumps_canonical([scope, *source[2:]])
        for salt in range(len(reserved) + 1):
            payload = dumps_canonical(["raptor:tool-finding-id:v1", fid, scope, salt])
            candidate = hashlib.sha256(payload.encode("ascii")).hexdigest()
            if candidate not in reserved:
                qualified[source] = candidate
                reserved.add(candidate)
                break
        else:
            raise ValueError("Unable to allocate distinct qualified finding IDs")
    for index, finding in enumerate(unique):
        fid = finding.get("finding_id")
        if isinstance(fid, str) and fid in collisions:
            source_id = finding.get("source_finding_id")
            if not isinstance(source_id, str) or not source_id:
                source_id = fid
            unique[index] = dict(finding, finding_id=qualified[source_key(finding)],
                                 source_finding_id=source_id)
    return unique


def _result_key(
    result: dict[str, Any],
) -> tuple[Any, ...]:
    """Dedup key for a SARIF result.

    Pre-fix the key was just (ruleId, uri, startLine). That collapsed
    distinct findings on the same line:

      * Two SQL-injection findings at the same line but different
        column offsets — the second arrival overwrote the first
        and the operator only saw one.
      * Two findings at different `endLine`s sharing a startLine
        (multi-line span vs single-line span on the same start) —
        same collapse.
      * Two scanner runs returning the same shape under different
        SARIF `partialFingerprints` — these are the tool's own
        identity for the finding and should disambiguate even when
        line/column match.

    Extended key: (ruleId, uri, startLine, endLine, startColumn,
    fingerprint). Missing fields default to 0 / "" so keys remain
    hashable and the (legacy) "no column / no fingerprint" case
    keeps deduping like before. Valid end columns and native match IDs append
    tagged identity material; absent or malformed values leave legacy key bytes
    unchanged. Native IDs equal to the rule ID retain the existing legacy guard.
    """
    rule_id = result.get("ruleId", "")
    if not isinstance(rule_id, str):
        rule_id = repr(rule_id)
    locs = result.get("locations")
    first_loc = _as_dict(locs[0]) if isinstance(locs, list) and locs else {}
    phys = _as_dict(first_loc.get("physicalLocation"))
    uri = _as_dict(phys.get("artifactLocation")).get("uri", "")
    if not isinstance(uri, str):
        uri = repr(uri)
    region = _as_dict(phys.get("region"))
    line = _coerce_line(region.get("startLine")) or 0
    end_line = _coerce_line(region.get("endLine"))  # multi-line spans differ
    if end_line is None:
        end_line = line
    start_col = _coerce_line(region.get("startColumn")) or 0
    # `partialFingerprints` is a tool-supplied dict; serialise the
    # primary `primaryLocationLineHash` if present, else collapse the
    # whole dict to a stable string. SARIF spec recommends
    # `primaryLocationLineHash` as the dedup-quality fingerprint.
    fp = _as_dict(result.get("partialFingerprints"))
    fingerprint = fp.get("primaryLocationLineHash")
    if not isinstance(fingerprint, str):
        fingerprint = ""
    if not fingerprint and fp:
        # Fall back to a stable serialisation of the whole dict —
        # different fingerprint sets mean different findings.
        fingerprint = repr(sorted(fp.items()))
    key: tuple[Any, ...] = (rule_id, uri, line, end_line, start_col, fingerprint)
    end_col = _coerce_line(region.get("endColumn"))
    if end_col is not None and end_col > 0:
        key += ("endColumn", end_col)
    native_id = _as_dict(result.get("fingerprints")).get("matchBasedId/v1")
    if isinstance(native_id, str) and native_id and native_id != rule_id:
        key += ("matchBasedId/v1", native_id)
    return key


def _uses_artifact_table(result: dict[str, Any]) -> bool:
    """Detect indexed standard locations without traversing property bags.

    Bound the walk to 20,000 steps / 64 iterator frames. On exhaustion,
    retain the run context so unseen references cannot be rebound by merge.
    Strings and wide arrays are never copied into a pending-work list.
    """
    stack: list[Iterator[Any]] = [iter((result,))]
    for _ in range(20_000):
        if not stack:
            return False
        try:
            node = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        if isinstance(node, dict):
            for name in ("artifactLocation", "analysisTarget"):
                artifact = node.get(name)
                if isinstance(artifact, dict) and "index" in artifact:
                    return True
            if len(stack) >= 64:
                return True
            stack.append(value for key, value in node.items() if key != "properties")
        elif isinstance(node, list):
            if len(stack) >= 64:
                return True
            stack.append(iter(node))
    return True


def _sarif_content_identity(value, *, stream=False):
    # Result records are usually small; retain the C encoder's fast
    # path there. Run metadata can contain an entire rule/artifact table.
    if not stream:
        return hashlib.sha256(dumps_canonical(value).encode("ascii")).hexdigest()
    digest = hashlib.sha256()
    try:
        for chunk in iterencode_canonical(value):
            digest.update(chunk)
    except RecursionError:
        # The Python iterator can reach its depth limit before the C
        # encoder. Discard the partial hash and preserve legacy support.
        return hashlib.sha256(dumps_canonical(value).encode("ascii")).hexdigest()
    return digest.hexdigest()


# Searching more incompatible groups may improve compaction, never correctness.
_MERGE_COMPATIBILITY_CHECKS = 16


def scope_conflicting_driver_rules(runs: list[Any]) -> list[Any]:
    """Namespace conflicting driver bindings across runs without changing inputs.

    Only live same-tool runs need comparison. Ordinary single-run reports and
    nonconflicting definitions retain legacy namespaces. Existing well-formed
    scopes are retained; scopes never grant evidence authority.
    """
    grouped: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, run in enumerate(runs):
        if not isinstance(run, dict):
            continue
        results = run.get("results")
        if isinstance(results, list) and any(isinstance(result, dict) for result in results):
            grouped.setdefault(get_tool_name(run), []).append((index, run))
    output = runs
    for tool_runs in grouped.values():
        if len(tool_runs) < 2:
            continue
        variants: dict[str, tuple[dict, dict] | None] = {}
        conflicts: set[str] = set()
        records = []
        for index, run in tool_runs:
            tool = _as_dict(run.get("tool"))
            driver = _as_dict(tool.get("driver"))
            header = {key: value for key, value in driver.items() if key != "rules"}
            rules = driver.get("rules")
            unique: dict[str, dict | None] = {}
            for rule in rules if isinstance(rules, list) else []:
                rid = _as_dict(rule).get("id")
                if isinstance(rid, str) and rid:
                    unique[rid] = None if rid in unique else rule
            for rid, rule in unique.items():
                if rule is None:
                    if rid in variants and variants[rid] is not None:
                        conflicts.add(rid)
                    variants.setdefault(rid, None)
                    continue
                if _scope_fingerprint(_as_dict(rule.get("properties")).get("raptor_rule_scope")) is not None:
                    continue  # Already distinct from the default namespace.
                variant = (header, rule)
                if rid in variants and variants[rid] != variant:
                    conflicts.add(rid)
                variants.setdefault(rid, variant)
            # Extension fallback already has its own component namespace.
            if not tool.get("extensions"):
                for result in run["results"]:
                    if not isinstance(result, dict):
                        continue
                    rid = result.get("ruleId")
                    if (isinstance(rid, str) and rid and rid not in unique
                            and "rule" not in result and result.get("ruleIndex", -1) == -1):
                        if rid in variants and variants[rid] is not None:
                            conflicts.add(rid)
                        variants.setdefault(rid, None)
            records.append((index, header, unique))
        if not conflicts:
            continue
        for index, header, unique in records:
            run = runs[index]
            tool = _as_dict(run.get("tool"))
            driver = _as_dict(tool.get("driver"))
            rules = driver.get("rules")
            if not isinstance(rules, list):
                continue
            replacement = None
            for position, descriptor in enumerate(rules):
                if not isinstance(descriptor, dict):
                    continue
                rid = descriptor.get("id")
                if not isinstance(rid, str) or rid not in conflicts or unique.get(rid) is not descriptor:
                    continue
                properties = _as_dict(descriptor.get("properties"))
                if _scope_fingerprint(properties.get("raptor_rule_scope")) is not None:
                    continue
                scope = _sarif_content_identity(
                    ["raptor:driver-rule-context:v1", header, descriptor], stream=True,
                )
                if replacement is None:
                    replacement = list(rules)
                replacement[position] = {**descriptor, "properties": {**properties, "raptor_rule_scope": scope}}
            if replacement is not None:
                if output is runs:
                    output = list(runs)
                output[index] = {**run, "tool": {**tool, "driver": {**driver, "rules": replacement}}}
    return output


def merge_sarif(sarif_paths: list[str]) -> dict[str, Any]:
    """
    Merge multiple SARIF files into a single SARIF dict.

    ID-only runs with compatible tool headers and rule bindings are grouped
    and deduplicated by ``_result_key`` (latest occurrence wins). Runs carrying
    URI-base tables, referenced artifacts, cached logical/dataflow locations or
    qualified rules retain their metadata;
    only identical contexts and exact reports are coalesced.

    Args:
        sarif_paths: List of paths to SARIF files

    Returns:
        Merged SARIF dict with deduplicated results per compatible context
    """
    # Group runs by tool name so same-tool runs get their results merged
    tool_runs: dict[str | tuple[str, str], dict[str, Any]] = {}
    legacy_groups: dict[str, list[dict[str, Any]]] = {}

    def accumulate_file(sarif_path: str) -> None:
        sarif_data = load_sarif(Path(sarif_path))
        if not sarif_data:
            return
        for run in (sarif_data.get("runs") or []):
            if not isinstance(run, dict):
                logger.warning(
                    "SARIF merge: skipping non-object run in %s", sarif_path
                )
                continue
            tool_name = get_tool_name(run)
            results = run.get("results") or []
            artifacts = run.get("artifacts")
            tool = _as_dict(run.get("tool"))
            driver = _as_dict(tool.get("driver"))
            context_owned = bool(
                _as_dict(run.get("originalUriBaseIds")) or tool.get("extensions")
                or any(name in run for name in ("logicalLocations", "threadFlowLocations"))
                or any(isinstance(result, dict) and ("ruleIndex" in result or "rule" in result)
                       for result in results)
                or (isinstance(artifacts, list) and artifacts
                    and any(_uses_artifact_table(result) for result in results if isinstance(result, dict)))
            )
            rules: dict[str, dict[str, Any]] = {}
            ambiguous_rules = False
            if not context_owned:
                driver_rules = driver.get("rules")
                for descriptor in driver_rules if isinstance(driver_rules, list) else []:
                    rule_id = _as_dict(descriptor).get("id")
                    if isinstance(rule_id, str) and rule_id:
                        if rule_id in rules:
                            ambiguous_rules = True
                            break
                        rules[rule_id] = descriptor
            if context_owned or ambiguous_rules:
                # Rules, URI bases and cached locations belong to this run.
                # Combining tables can rebind rules, functions or evidence hops.
                metadata = {key: value for key, value in run.items() if key != "results"}
                context_key = (tool_name, _sarif_content_identity(metadata, stream=True))
                if context_key not in tool_runs:
                    tool_runs[context_key] = {"original": metadata, "results": {}}
                for result in results:
                    if isinstance(result, dict):
                        tool_runs[context_key]["results"][_sarif_content_identity(result)] = result
                continue
            header = {**tool, "driver": {key: value for key, value in driver.items() if key != "rules"}}
            referenced = {result["ruleId"] for result in results
                          if isinstance(result, dict) and isinstance(result.get("ruleId"), str)}
            unresolved = referenced - rules.keys()
            group = None
            groups = legacy_groups.setdefault(tool_name, [])
            for candidate in groups[:_MERGE_COMPATIBILITY_CHECKS]:
                if candidate["header"] != header:
                    continue
                old_rules = candidate["rules_by_id"]
                if (unresolved & old_rules.keys()
                        or rules.keys() & candidate["unresolved_ids"]):
                    continue  # A missing descriptor cannot borrow a neighbor's.
                if any(rule_id in old_rules and old_rules[rule_id] != descriptor
                       for rule_id, descriptor in rules.items()):
                    continue
                group = candidate
                break
            if group is None:
                group = {
                    "tool": tool, "header": header,
                    "rules_by_id": {}, "unresolved_ids": set(),
                    "results": {}, "invocations": [],
                }
                tool_runs[(tool_name, f"id-only:{len(groups)}")] = group
                groups.append(group)
            # Equal descriptors and disjoint bindings can share a table. Keep
            # latest equal objects so superseded input descriptors are released.
            group["rules_by_id"].update(rules)
            group["unresolved_ids"].update(unresolved)
            # The final driver table comes from rules_by_id. Keep a private
            # header without the original table so replaced equivalent descriptors die.
            header = group["tool"]
            header_driver = _as_dict(header.get("driver"))
            if group["rules_by_id"] and "rules" in header_driver:
                group["tool"] = {
                    **header, "driver": {key: value for key, value in header_driver.items() if key != "rules"},
                }
            # Append invocations — each input run is its own
            # invocation record; multiple legitimately coexist.
            for inv in run.get("invocations") or []:
                if isinstance(inv, dict):
                    group["invocations"].append(inv)
            for result in run.get("results") or []:
                if not isinstance(result, dict):
                    continue
                key = _result_key(result)
                group["results"][key] = result

    # Release each input's temporary document/run/result references before
    # loading the next. Only the metadata and findings selected above survive.
    for sarif_path in sarif_paths:
        accumulate_file(sarif_path)

    # Preserve qualified namespaces; rebuild only ID-based merged runs.
    merged_runs = []
    for run_data in tool_runs.values():
        if "original" in run_data:
            qualified_run = dict(run_data["original"])
            qualified_run["results"] = list(run_data["results"].values())
            merged_runs.append(qualified_run)
            continue
        # Re-inject the unioned rule list into tool.driver.rules.
        tool_block = dict(run_data["tool"]) if run_data["tool"] else {}
        driver = dict(tool_block.get("driver") or {})
        if run_data["rules_by_id"]:
            driver["rules"] = list(run_data["rules_by_id"].values())
        tool_block["driver"] = driver
        run_out: dict[str, Any] = {
            "tool": tool_block,
        }
        if run_data["invocations"]:
            run_out["invocations"] = run_data["invocations"]
        run_out["results"] = list(run_data["results"].values())
        merged_runs.append(run_out)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": scope_conflicting_driver_rules(merged_runs),
    }


_CWE_TAG_RE = re.compile(r"cwe[-_]?(\d+)", re.IGNORECASE)


def _extract_cwe_from_rule(rule: dict[str, Any]) -> str | None:
    """Extract CWE ID from a SARIF rule.

    SARIF tools emit CWE metadata in several places — pre-fix this
    only checked two:

      * `properties.cwe` as a string ("CWE-89")
      * `properties.tags` as a list of strings ("external/cwe/cwe-89")

    Now also covers:
      * `properties.cwe` as a LIST (some tools emit
        `["CWE-89", "CWE-564"]`) — pre-fix the `isinstance(str)`
        branch silently fell through to None for these.
      * `relationships[].target.id` — SARIF spec's canonical way to
        link a rule to a CWE-taxonomy entry. CodeQL's SARIF output
        uses this exclusively (no properties.cwe), so pre-fix every
        CodeQL CWE was missed.
      * `properties.cwe_id` (alternate name several tools use).

    Returns the FIRST CWE-ID found in inspection order. Multi-CWE
    findings still surface only one CWE — promoting to a list would
    break downstream consumers expecting a single string.
    """
    from core.cve.cwe import format_cwe
    props = _as_dict(rule.get("properties"))

    # `properties.cwe` — string OR list.
    raw_cwe = props.get("cwe") or props.get("cwe_id")
    if isinstance(raw_cwe, str):
        m = _CWE_TAG_RE.search(raw_cwe)
        if m:
            return format_cwe(m.group(1))
    elif isinstance(raw_cwe, list):
        for entry in raw_cwe:
            if isinstance(entry, str):
                m = _CWE_TAG_RE.search(entry)
                if m:
                    return format_cwe(m.group(1))

    # `properties.tags` — list of strings, may contain external/cwe/cwe-N.
    tags = props.get("tags")
    for tag in (tags if isinstance(tags, list) else []):
        if isinstance(tag, str):
            m = _CWE_TAG_RE.search(tag)
            if m:
                return format_cwe(m.group(1))

    # `relationships[]` — SARIF spec's canonical mechanism. Each
    # relationship has a `target` reference (`{"id": "CWE-89", ...}`
    # or `{"toolComponent": {"name": "CWE"}, "id": "89"}`).
    relationships = rule.get("relationships")
    for rel in relationships if isinstance(relationships, list) else []:
        if not isinstance(rel, dict):
            continue
        target = rel.get("target") or {}
        if not isinstance(target, dict):
            continue
        target_id = target.get("id")
        if isinstance(target_id, str):
            m = _CWE_TAG_RE.search(target_id)
            if m:
                return format_cwe(m.group(1))
        # CodeQL emits the bare numeric id with the toolComponent
        # naming the CWE catalog separately.
        tc = target.get("toolComponent") or {}
        if (
            isinstance(tc, dict)
            and isinstance(tc.get("name"), str)
            and tc["name"].upper() == "CWE"
            and isinstance(target_id, (str, int))
        ):
            canon = format_cwe(target_id)
            if canon is not None:
                return canon

    return None


def count_results(sarif_data: Any) -> int:
    """Total number of results across all runs of a parsed SARIF dict.

    Shape-tolerant by contract: this is a provenance/summary signal,
    not a validator, and its inputs include SARIF files found on disk
    in run directories (operator-editable, tool-emitted, or hostile).
    A non-dict document, a non-list ``runs``, a non-dict run entry, or
    a non-list ``results`` each count as zero instead of raising —
    per-module copies of this loop drifted exactly on that tolerance
    (one raised ``AttributeError`` on a non-dict run entry and took
    the whole rendering path down with it).
    """
    if not isinstance(sarif_data, dict):
        return 0
    runs = sarif_data.get("runs")
    if not isinstance(runs, list):
        return 0
    total = 0
    for run_obj in runs:
        if not isinstance(run_obj, dict):
            continue
        results = run_obj.get("results")
        if isinstance(results, list):
            total += len(results)
    return total


def load_sarif(sarif_path: Path) -> dict[str, Any] | None:
    """
    Load a SARIF file with safety guards.

    Handles existence check, regular-file gate (a planted FIFO or
    device node is refused instead of blocking the reader), size
    guard (100 MiB, enforced on the fd actually read), and JSON
    decode errors. All SARIF file I/O should go through this function.

    Args:
        sarif_path: Path to SARIF file

    Returns:
        Parsed SARIF dict, or None on error
    """
    if not sarif_path.exists():
        logger.error("SARIF: file does not exist: %s", sarif_path)
        return None

    max_size = SARIF_MAX_BYTES  # trade-off comment at the constant

    # Gated read on the OPEN fd. Pre-fix the function used
    # `sarif_path.read_text()` followed by `if len(content) > max_size`
    # — the WHOLE file was loaded into memory BEFORE the size check,
    # so a 10 GB malformed/hostile SARIF file OOM-killed the process
    # instead of being rejected. A later revision stat'ed BY NAME and
    # opened BY NAME with a bounded read — but the size gate never
    # checked the file TYPE, so a FIFO planted at the SARIF path
    # (stats as 0 bytes, passing any cap) blocked the reader forever
    # at the open; no swap race needed. SARIF paths include run-dir
    # artifacts producible under another principal's write grant —
    # the exact plantable-hang class core.json's gated read closes,
    # so the same fd discipline applies here: O_NONBLOCK makes a
    # FIFO/device open return instead of blocking (no effect on
    # regular-file reads), fstat the fd actually being read, require
    # a regular file, and bound the read at `max_size + 1` bytes (the
    # standard one-extra-byte "did we hit the limit" sentinel) with a
    # post-read re-check so growth during the read is refused too.
    # Symlink-to-regular still resolves; symlink-to-FIFO is refused
    # with the FIFO.
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        fd = os.open(str(sarif_path), flags)
    except OSError as e:
        logger.warning("SARIF: could not read %s: %s", sarif_path, e)
        return None
    try:
        st = os.fstat(fd)
        if not stat_mod.S_ISREG(st.st_mode):
            logger.error(
                "SARIF: not a regular file: %s", sarif_path,
            )
            return None
        if st.st_size > max_size:
            logger.error(
                "SARIF: file too large (%.0f MiB): %s",
                st.st_size / 1024 / 1024, sarif_path,
            )
            return None
        with os.fdopen(fd, "rb") as f:
            fd = -1  # fdopen owns it now
            raw = f.read(max_size + 1)
        if len(raw) > max_size:
            # Race: file grew between fstat and read.
            logger.error(
                "SARIF: file grew past %.0f MiB during read: %s",
                max_size / 1024 / 1024, sarif_path,
            )
            return None
        content = raw.decode("utf-8", errors="replace")
    except OSError as e:
        logger.warning("SARIF: could not read %s: %s", sarif_path, e)
        return None
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass

    try:
        # core.json.loads: shared backend (orjson when installed) —
        # SARIF documents are the hottest single parse in the repo.
        data = loads(content or "{}")
    except (ValueError, RecursionError):
        try:
            # Tolerant retry, stdlib-only: a document rejected solely
            # for a bare NaN/Infinity literal (json.dumps with the
            # default allow_nan=True emits them; _coerce_line handles
            # them per-field downstream) must keep importing — that
            # tolerance is pinned by the crafted-SARIF tests. The
            # retry costs one extra parse on the rare non-finite or
            # malformed document; the well-formed common case stays
            # on the fast path above.
            data = loads(content or "{}", allow_non_finite=True)
        except (ValueError, RecursionError) as e:
            # RecursionError: json parsing recurses per nesting
            # level, so a deeply-nested (~>1000 levels) hostile SARIF
            # blows the Python recursion limit. That must land on the
            # same reject-with-None path as malformed JSON —
            # load_sarif is the safe-load boundary; letting
            # RecursionError escape crashed the caller.
            logger.error("SARIF: invalid JSON in %s: %s", sarif_path, e)
            return None

    if not isinstance(data, dict):
        logger.error("SARIF: root must be an object in %s", sarif_path)
        return None

    return data


def get_tool_name(run: dict[str, Any]) -> str:
    """Extract tool name from a SARIF run."""
    driver = _as_dict(_as_dict(run.get("tool")).get("driver"))
    name = driver.get("name")
    return name if isinstance(name, str) and name else "unknown"


def get_rules(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Extract rules from a SARIF run, keyed by rule ID.

    Rules are collected from ``tool.driver.rules`` AND every
    ``tool.extensions[*].rules`` array: SARIF places pack-/plugin-
    provided rules on extension toolComponents (CodeQL's pack-based
    runs emit that layout), and a driver-only read silently dropped
    their severity defaults and CWE tags — every such result flattened
    to "warning" with no CWE mapping. On an id collision the driver's
    definition wins (extensions are secondary components). Results
    that reference extension rules by ``ruleIndex``/
    ``rule.toolComponent.index`` WITHOUT a ``ruleId`` string still
    don't join (the result-side lookup is keyed on ruleId only).

    Non-object rules and non-string rule ids (spec violations in
    untrusted SARIF) are dropped rather than crashing the parse."""
    tool = _as_dict(run.get("tool"))

    def _component_rules(component: Any) -> dict[str, dict[str, Any]]:
        rules = _as_dict(component).get("rules")
        if not isinstance(rules, list):
            return {}
        return {
            r["id"]: r
            for r in rules
            if isinstance(r, dict) and isinstance(r.get("id"), str) and r["id"]
        }

    out: dict[str, dict[str, Any]] = {}
    extensions = tool.get("extensions")
    if isinstance(extensions, list):
        for ext in extensions:
            out.update(_component_rules(ext))
    out.update(_component_rules(tool.get("driver")))
    return out


def get_result_rule(run: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Resolve a result's descriptor within its referenced tool component.

    An explicit extension reference must never borrow a same-ID driver rule.
    Indexed references select directly and must agree with readable IDs/GUIDs.
    Support descriptor IDs/GUIDs and indexes, rejecting ambiguous matches and
    malformed component references. Legacy ID-only results prefer the driver
    and may use a uniquely matching extension when the driver has no match.
    """
    tool = _as_dict(run.get("tool"))
    driver = _as_dict(tool.get("driver"))
    extensions = tool.get("extensions")
    extensions = extensions if isinstance(extensions, list) else []
    reference = _as_dict(result.get("rule"))
    result_id = result.get("ruleId")
    reference_id = reference.get("id")
    result_id = result_id if isinstance(result_id, str) and result_id else None
    reference_id = reference_id if isinstance(reference_id, str) and reference_id else None
    if result_id and reference_id and result_id != reference_id:
        return {}
    rule_id = reference_id or result_id
    guid = reference.get("guid")
    guid = guid if isinstance(guid, str) and guid else None
    for mapping, name in ((reference, "index"), (result, "ruleIndex")):
        if name in mapping and (type(mapping[name]) is not int or mapping[name] < -1):
            return {}
    if "index" in reference and "ruleIndex" in result and reference["index"] != result["ruleIndex"]:
        return {}
    rule_index = reference.get("index", result.get("ruleIndex", -1))

    def resolve(component):
        rules = _as_dict(component).get("rules")
        if not isinstance(rules, list):
            return {}
        if rule_index >= 0:
            if rule_index >= len(rules) or not isinstance(rules[rule_index], dict):
                return None
            descriptor = rules[rule_index]
            if rule_id:
                descriptor_id = descriptor.get("id")
                compatible = descriptor_id == rule_id
                # SARIF permits one sub-rule component in a readable ID.
                if not compatible and isinstance(descriptor_id, str) and descriptor_id:
                    suffix = rule_id[len(descriptor_id) + 1:]
                    compatible = (rule_id.startswith(descriptor_id + "/")
                                  and bool(suffix) and "/" not in suffix)
                if not compatible:
                    return None
            if guid and descriptor.get("guid") != guid:
                return None
            return descriptor
        if rule_id or guid:
            matches = [r for r in rules if isinstance(r, dict)
                       and (not rule_id or r.get("id") == rule_id)
                       and (not guid or r.get("guid") == guid)]
            return matches[0] if len(matches) == 1 else (None if matches else {})
        return {}

    if "toolComponent" in reference:
        component_ref = reference["toolComponent"]
        if not isinstance(component_ref, dict):
            return {}
        index = component_ref.get("index", -1)
        if type(index) is not int or index < -1:
            return {}
        names = {key: component_ref[key] for key in ("name", "guid")
                 if key in component_ref}
        if any(not isinstance(value, str) or not value for value in names.values()):
            return {}
        if index >= 0:
            if index >= len(extensions):
                return {}
            component = _as_dict(extensions[index])
            if any(component.get(key) != value for key, value in names.items()):
                return {}
        elif names:
            matches = [c for c in [driver, *extensions] if isinstance(c, dict)
                       and all(c.get(key) == value for key, value in names.items())]
            if len(matches) != 1:
                return {}
            component = matches[0]
        else:
            component = driver
        return resolve(component) or {}

    rule = resolve(driver)
    if rule_index >= 0 or rule is None or rule or not (rule_id or guid):
        return rule or {}
    resolved = [resolve(component) for component in extensions]
    if any(rule is None for rule in resolved):
        return {}
    matches = [rule for rule in resolved if rule]
    return matches[0] if len(matches) == 1 else {}


def _scope_fingerprint(value: Any) -> str | None:
    """Recognize normalized namespace bookkeeping, never an authority stamp."""
    if (isinstance(value, str) and len(value) == 64
            and all(char in "0123456789abcdef" for char in value)):
        return value
    return None


class ResultRuleResolver:
    """Run-owned descriptor lookup with an unambiguous legacy-ID index.

    Indexed and component-qualified references use the shared validator,
    caching repeated references within a bounded per-run working set.
    Ordinary ID-only reports avoid scanning every rule for every result.
    Run metadata is treated as immutable; no result payloads or cross-run
    lookup state are retained.
    """

    def __init__(self, run: dict[str, Any]):
        tool = _as_dict(run.get("tool"))
        self._run = {"tool": tool}
        self._by_id: dict[str, dict[str, Any] | None] = {}
        self._owners: dict[int, tuple[str, str]] = {}
        self._scopes: dict[int, str] = {}
        self._metadata: dict[int, tuple[str | None, str | None, str | None]] = {}
        self._references: dict[tuple, dict[str, Any] | None] = {}
        extensions = tool.get("extensions")
        for component in extensions if isinstance(extensions, list) else []:
            for rule in self._rules(component, "extension"):
                rid = rule["id"]
                self._by_id[rid] = None if rid in self._by_id else rule
        driver_ids: set[str] = set()
        for rule in self._rules(tool.get("driver"), "driver"):
            rid = rule["id"]
            self._by_id[rid] = None if rid in driver_ids else rule
            driver_ids.add(rid)

    def _rules(self, component, kind):
        component = _as_dict(component)
        rules = component.get("rules")
        guid, name = component.get("guid"), component.get("name")
        owner = (kind, guid if isinstance(guid, str) and guid else
                 name if isinstance(name, str) else "")
        if isinstance(rules, list):
            for rule in rules:
                if isinstance(rule, dict) and isinstance(rule.get("id"), str) and rule["id"]:
                    self._owners[id(rule)] = owner
                    yield rule

    def scope(
        self, rule: dict[str, Any], *, cwe: str | None, level: str | None,
    ) -> str | None:
        """Stable provenance for an already validated descriptor, never an index."""
        key = id(rule)
        owner = self._owners.get(key)
        if owner is None:
            return None
        # Normalized exports retain an already derived namespace on the
        # descriptor. Read it only after reference validation selected this
        # owned rule; result property bags cannot supply a scope.
        normalized_scope = _scope_fingerprint(_as_dict(rule.get("properties")).get("raptor_rule_scope"))
        if normalized_scope is not None:
            return normalized_scope
        # A unique driver ID already has the default namespace. Keep its
        # legacy shape and identity; only extensions and ambiguous driver
        # descriptors require additional provenance.
        if owner[0] == "driver" and self._by_id.get(rule["id"]) is rule:
            return None
        if key not in self._scopes:
            guid, name = rule.get("guid"), rule.get("name")
            identity = (["guid", guid] if isinstance(guid, str) and guid else
                        ["id", rule["id"], "name", name if isinstance(name, str) else "", cwe, level])
            payload = dumps_canonical([owner, identity])
            self._scopes[key] = hashlib.sha256(payload.encode("ascii")).hexdigest()
        return self._scopes[key]

    def metadata(self, rule: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
        """Return cached CWE, default severity and scope for a resolved descriptor."""
        if not rule:
            return None, None, None
        key = id(rule)
        if key not in self._metadata:
            cwe = _extract_cwe_from_rule(rule)
            level = rule_default_level(rule)
            self._metadata[key] = (cwe, level, self.scope(rule, cwe=cwe, level=level))
        return self._metadata[key]

    def resolve(self, result: dict[str, Any]) -> dict[str, Any]:
        index = result.get("ruleIndex", -1)
        if not _as_dict(result.get("rule")) and type(index) is int and index == -1:
            rid = result.get("ruleId")
            return (self._by_id.get(rid) or {}) if isinstance(rid, str) else {}
        reference = _as_dict(result.get("rule"))
        descriptor_index = reference.get("index", index)
        component = reference.get("toolComponent", {})
        if (type(descriptor_index) is int and descriptor_index >= 0
                and isinstance(component, dict)
                and (not component or (type(component.get("index")) is int and component["index"] >= 0))):
            # Fully indexed references already validate in constant time;
            # building a cache key would cost more than the lookup itself.
            return get_result_rule(self._run, result)
        key = self._reference_key(result)
        if key is not None and key in self._references:
            return self._references[key] or {}
        rule = get_result_rule(self._run, result)
        # Admission limits bound bookkeeping on untrusted, all-distinct
        # references. Oversized/unsupported keys still use full validation.
        if key is not None and len(self._references) < 256:
            self._references[key] = rule or None
        return rule

    @staticmethod
    def _reference_key(result: dict[str, Any]) -> tuple | None:
        reference = _as_dict(result.get("rule"))
        component = reference.get("toolComponent", {})
        if not isinstance(component, dict):
            return None
        parts = []
        for mapping, names in (
            (result, ("ruleId", "ruleIndex")),
            (reference, ("id", "guid", "index")),
            (component, ("name", "guid", "index")),
        ):
            fields = []
            for name in names:
                if name not in mapping:
                    continue
                value = mapping[name]
                if type(value) not in (str, int, type(None)):
                    return None
                if isinstance(value, str) and len(value) > 1024:
                    return None
                fields.append((name, type(value), value))
            parts.append(tuple(fields))
        # Presence matters: an explicit empty toolComponent selects the
        # driver, whereas its absence permits legacy extension fallback.
        return ("toolComponent" in reference, *parts)


def _result_rule_id(result: dict[str, Any], rule: dict[str, Any]) -> str | None:
    """Readable result identity, with fallback only from a validated descriptor."""
    rule_id = result.get("ruleId")
    if isinstance(rule_id, str) and rule_id:
        return rule_id
    if rule:
        reference_id = _as_dict(result.get("rule")).get("id")
        resolved_id = (reference_id if isinstance(reference_id, str) and reference_id
                       else rule.get("id"))
        if isinstance(resolved_id, str) and resolved_id:
            return resolved_id
    return rule_id if isinstance(rule_id, str) else None


def rule_default_level(rule: dict[str, Any]) -> str | None:
    """The rule's ``defaultConfiguration.level``, or None.

    Per the SARIF spec, a result without an explicit ``level`` inherits
    it from its rule's defaultConfiguration. Semgrep's SARIF emitter
    relies on this — results never carry ``level`` (verified against
    semgrep 1.172.0) — so a parser that defaults straight to "warning"
    flattens every rule-declared severity, including error-severity
    rules, to warning.
    """
    cfg = rule.get("defaultConfiguration")
    level = cfg.get("level") if isinstance(cfg, dict) else None
    if isinstance(level, str) and level:
        return level
    return None


def logical_location_function(location: Any, logical_locations: Any = None) -> str | None:
    """Read inline or run-indexed function identity without scanning the run table.

    SARIF 2.1.0 section 3.33.3 requires inline identity fields to agree
    with the indexed object. A bad reference loses only its optional function
    metadata. Cached objects may identify their own index, but are not chains.
    No parent traversal or name reconstruction is needed for display names.
    """
    entries = _as_dict(location).get("logicalLocations")
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        index = entry.get("index", -1)
        if type(index) is not int or index < -1:
            continue
        logical = entry
        if index >= 0:
            if not isinstance(logical_locations, list) or index >= len(logical_locations):
                continue
            logical = logical_locations[index]
            if not isinstance(logical, dict):
                continue
            if "index" in logical and (type(logical["index"]) is not int
                                       or logical["index"] != index):
                continue
            if any(key in entry and entry[key] != logical.get(key)
                   for key in ("name", "fullyQualifiedName", "kind", "decoratedName", "parentIndex")):
                continue
        if logical.get("kind") not in ("function", "method", "member"):
            continue
        name = logical.get("name")
        if not isinstance(name, str) or not name:
            name = logical.get("fullyQualifiedName")
        if isinstance(name, str) and name:
            return name
    return None


# URI expansion must stay useful for local source files, not amplify a short
# artifact table into unbounded strings. 64 KiB exceeds ordinary native paths
# (including percent-encoded POSIX paths). Memo admission is separately smaller.
_MAX_RESOLVED_URI_CHARS = 64 * 1024
_URI_CACHE_ENTRIES = 256
_URI_CACHE_VALUE_CHARS = 4096
_URI_CACHE_KEY_CHARS = 1024


def _normalize_artifact_uri(uri: str) -> str | None:
    """Canonicalize local file authorities without decoding path bytes."""
    if (len(uri) > _MAX_RESOLVED_URI_CHARS or uri.startswith(" ")
            or any(ord(char) < 32 or ord(char) == 127 for char in uri)):
        return None
    try:
        parts = urlsplit(uri)
    except ValueError:
        return None
    if parts.scheme == "file" and parts.netloc.lower() in ("", "localhost"):
        return urlunsplit(parts._replace(netloc=""))
    return uri


def _join_artifact_uri(base: str, relative: str) -> str | None:
    """Join complete URI bases; preserve unresolved relative prefixes literally."""
    try:
        parts = urlsplit(base)
        if relative.startswith("//"):
            size = (len(parts.scheme) + 1 if parts.scheme else 0) + len(relative)
        elif relative.startswith("/"):
            size = len(urlunsplit(parts._replace(path="", query="", fragment=""))) + len(relative)
        else:
            size = len(base) + len(relative)
        if size > _MAX_RESOLVED_URI_CHARS:
            return None
        if parts.scheme:
            joined = urljoin(base, relative)
            # urllib does not resolve arbitrary schemes. Never lose an
            # absolute non-file origin and reinterpret the child as local.
            if not urlsplit(joined).scheme:
                return None
        elif parts.netloc:
            # Supply a scheme for authority/path joining, then retain the
            # original network-relative form instead of inventing a protocol.
            network = urljoin("file:" + base, relative)
            joined = urlunsplit(urlsplit(network)._replace(scheme=""))
        else:
            # A redacted/missing root is conventionally supplied by the target
            # directory. urljoin would erase leading '..' from relative bases.
            joined = relative if relative.startswith("/") else base + relative
    except ValueError:
        return None
    return _normalize_artifact_uri(joined)


def sarif_uri_path(uri: Any) -> str | None:
    """Interpret a local SARIF file reference without stripping remote authority.

    Percent decoding and target-root containment remain boundary-specific;
    this helper never fetches anything or treats a remote origin as a filename.
    """
    if not isinstance(uri, str):
        return None
    uri = _normalize_artifact_uri(uri)
    if uri is None:
        return None
    try:
        parts = urlsplit(uri)
    except ValueError:
        return None
    if parts.netloc or (parts.scheme and parts.scheme != "file"):
        return None
    from core.paths import strip_file_uri
    return strip_file_uri(uri)


def sarif_flow_uri(artifact: Any, resolved_uri: str | None) -> str | None:
    """Blank files are for unspecified locations, not failed explicit references."""
    if not isinstance(artifact, dict):
        return None
    if resolved_uri is None and not any(key in artifact for key in ("uri", "index", "uriBaseId")):
        return ""
    return resolved_uri


class ArtifactUriResolver:
    """Run-owned URI resolution with bounded artifact and base memoization.

    Only metadata is retained, never result payloads. Filesystem containment
    remains the caller's responsibility. Missing/redacted roots retain relative
    hints; cyclic, over-deep or oversized expansions do not invent local paths.
    """

    def __init__(self, run: dict[str, Any]):
        self._uri_bases = _as_dict(run.get("originalUriBaseIds"))
        artifacts = run.get("artifacts")
        self._artifacts = artifacts if isinstance(artifacts, list) else []
        self._artifact_uris: dict[int, str | None] = {}
        self._base_uris: dict[str, str | None] = {}

    @staticmethod
    def _remember(cache, key, uri):
        if len(cache) < _URI_CACHE_ENTRIES and (uri is None or len(uri) <= _URI_CACHE_VALUE_CHARS):
            cache[key] = uri

    def _base_uri(self, base_id: str) -> str | None:
        memoize = len(base_id) <= _URI_CACHE_KEY_CHARS
        if memoize and base_id in self._base_uris:
            return self._base_uris[base_id]
        seen: set[str] = set()
        chain: list[str] = []
        current = base_id
        resolved: str | None = ""
        for _ in range(16):
            if current in seen:
                resolved = None
                break
            seen.add(current)
            base = _as_dict(self._uri_bases.get(current))
            uri = base.get("uri")
            if not isinstance(uri, str):
                break  # Missing/redacted roots keep the established relative hint.
            uri = _normalize_artifact_uri(uri)
            if uri is None:
                resolved = None
                break
            try:
                parts = urlsplit(uri)
                # Keep an empty relative base empty; it is not filesystem '/'.
                path = parts.path + "/" if parts.path and not parts.path.endswith("/") else parts.path
                directory = urlunsplit(parts._replace(path=path, query="", fragment=""))
            except ValueError:
                resolved = None
                break
            if parts.scheme:
                resolved = directory
                break  # Absolute bases never inherit another parent.
            chain.append(directory)
            parent = base.get("uriBaseId")
            if not isinstance(parent, str):
                break
            current = parent
        else:
            resolved = None
        for directory in reversed(chain):
            if resolved is None:
                break
            resolved = _join_artifact_uri(resolved, directory)
        # Cache only this requested root: intermediate failures at the depth
        # limit need not be failures when requested with their own full budget.
        if memoize:
            self._remember(self._base_uris, base_id, resolved)
        return resolved

    def resolve(self, artifact: dict[str, Any]) -> str | None:
        """Prefer explicit URIs; otherwise look up an exact integer index."""
        art = _as_dict(artifact)
        uri = art.get("uri")
        index = None
        if not isinstance(uri, str):
            index = art.get("index")
            if type(index) is not int or not 0 <= index < len(self._artifacts):
                return None
            if index in self._artifact_uris:
                return self._artifact_uris[index]
            art = _as_dict(_as_dict(self._artifacts[index]).get("location"))
            uri = art.get("uri")
        uri = _normalize_artifact_uri(uri) if isinstance(uri, str) else None
        if uri is not None and not urlsplit(uri).scheme:
            base_id = art.get("uriBaseId")
            if isinstance(base_id, str):
                base = self._base_uri(base_id)
                uri = _join_artifact_uri(base, uri) if base is not None else None
        if index is not None:
            self._remember(self._artifact_uris, index, uri)
        return uri


def _uri_escapes_root(uri: str, source_root: Path) -> bool:
    """Containment check for a resolved artifact URI against a known
    source root — same defence as ``import_normalizer._is_under_root``,
    applied at the parse boundary so parser safety doesn't depend on
    every caller running the normalizer afterwards.

    SARIF is untrusted input: a crafted URI (``../../etc/passwd``, an
    absolute path, or a percent-encoded traversal) must not flow
    downstream as an in-tree file path. Returns True when the URI
    resolves OUTSIDE *source_root*. Purely lexical + symlink
    resolution — the file is not required to exist, so in-root URIs
    keep parsing exactly as before.
    """
    # file:///abs/path → /abs/path (kept absolute; the join below
    # then yields the absolute path itself, which must still land
    # under the root to survive).
    try:
        parts = urlsplit(uri)
        if (parts.netloc and (parts.scheme != "file" or parts.netloc.lower() != "localhost")) or (
            parts.scheme and parts.scheme != "file"
        ):
            return True
        clean = unquote(parts.path if parts.scheme == "file" else uri)
        root = source_root.resolve()
        resolved = (root / clean).resolve()
    except (OSError, ValueError):
        return True
    return resolved != root and not str(resolved).startswith(str(root) + "/")


def parse_sarif_findings(
    sarif_path: Path, source_root: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Parse findings from a SARIF file.

    Args:
        sarif_path: Path to SARIF file
        source_root: Optional root of the analysed source tree. When
            given, findings whose (base-joined) artifact URI resolves
            outside this root are skipped with a warning — mirroring
            how ``import_normalizer`` drops unmappable URIs. When
            None (default), behaviour is unchanged: all findings are
            returned and containment is the caller's responsibility.

    Returns:
        List of finding dictionaries with normalized structure
    """
    data = load_sarif(sarif_path)
    if not data:
        return []

    findings: list[dict[str, Any]] = []
    compiler_path_budget = PathBudget()

    runs = data.get("runs") or []
    # Debug: parsing internals — this fires for every SARIF file every
    # pipeline stage touches, so at INFO it was per-finding chatter in
    # the audit trail. Malformed-input warnings above stay WARNING.
    logger.debug("SARIF parser: found %d run(s) in SARIF file", len(runs))

    runs = scope_conflicting_driver_rules(runs)
    for run_idx, run in enumerate(runs):
        if not isinstance(run, dict):
            logger.warning(
                "SARIF parser: skipping non-object run %d", run_idx + 1
            )
            continue
        results = run.get("results") or []
        if not isinstance(results, list):
            logger.warning(
                "SARIF parser: run %d has non-array results; skipping",
                run_idx + 1,
            )
            continue
        logger.debug("SARIF parser: run %d: %d result(s)", run_idx + 1, len(results))

        tool_name = get_tool_name(run)

        rule_resolver = ResultRuleResolver(run)

        uri_resolver = ArtifactUriResolver(run)

        flow_root_warning_reported = False

        def _resolve_flow_uri(artifact: dict[str, Any]) -> str | None:
            nonlocal flow_root_warning_reported
            uri = sarif_flow_uri(artifact, uri_resolver.resolve(artifact))
            if uri and source_root is not None and _uri_escapes_root(uri, source_root):
                if not flow_root_warning_reported:
                    logger.warning("SARIF parser: skipping dataflow paths with out-of-root URIs; first: %s",
                                   escape_nonprintable(uri)[:1024])
                    flow_root_warning_reported = True
                return None
            return uri

        for result in results:
            if not isinstance(result, dict):
                logger.warning(
                    "SARIF parser: skipping non-object result in run %d",
                    run_idx + 1,
                )
                continue
            rule = rule_resolver.resolve(result)
            if (compiler_diagnostic_is_candidate(result.get("ruleId", ""))
                    or compiler_diagnostic_is_candidate(rule.get("id", ""))):
                continue

            locs = result.get("locations")
            first_loc = _as_dict(locs[0]) if isinstance(locs, list) and locs else {}
            loc = _as_dict(first_loc.get("physicalLocation"))
            artifact = _as_dict(loc.get("artifactLocation"))
            file_uri = uri_resolver.resolve(artifact)

            # finding_id resolution:
            #   1. SARIF tool-supplied fingerprint (best — survives
            #      reformatting / line-shifts that the tool tracked).
            #      Semgrep emits `fingerprints["matchBasedId/v1"]`, so
            #      semgrep finding_ids are unchanged by this logic.
            #   2. Deterministic hash of the logical rule ID, resolved
            #      primary URI, span, column and partialFingerprints —
            #      stable across equivalent references and distinct files.
            #   3. Deterministic hash of the canonicalised result.
            #
            # NEVER bare ruleId. Pre-fix the chain was
            # `fingerprint or ruleId or sha` — CodeQL results carry no
            # `fingerprints` member (they use `partialFingerprints`),
            # so EVERY CodeQL finding of one rule fell back to the
            # ruleId and shared a single finding_id. Downstream that
            # collided per-finding artifact files (later findings
            # overwrote earlier ones), misrouted dispatch keyed on
            # finding_id, and dropped findings from by_id maps.
            #
            # The content-sha fallback uses
            # `hashlib.sha256(json.dumps(..., sort_keys=True))`:
            # `hash()` is randomised per-process (PYTHONHASHSEED) and
            # unsorted dumps depend on dict insertion order, so
            # neither is stable across invocations.
            rule_id = _result_rule_id(result, rule)
            fingerprint = _as_dict(result.get("fingerprints")).get("matchBasedId/v1")
            if isinstance(fingerprint, str) and fingerprint:
                finding_id = fingerprint
            else:
                key = _result_key(result)
                # A relative URI can name different files under different
                # bases. Use the same resolved file as the imported finding.
                key = (rule_id or key[0], file_uri if file_uri is not None else key[1], *key[2:])
                # Use the key-derived hash only when it carries
                # distinguishing material beyond the ruleId (a
                # location or a partialFingerprint). A bare
                # rule-only key would re-introduce the collision,
                # so fall through to the content sha instead.
                if any(key[1:]):
                    finding_id = hashlib.sha256(
                        "\x1f".join(str(part) for part in key).encode("utf-8")
                    ).hexdigest()
                else:
                    # Full result serialization is needed only for the
                    # locationless, fingerprintless fallback. Tool-specific
                    # payloads can dwarf the identity material above.
                    try:
                        canonical = json.dumps(result, sort_keys=True, default=str)
                    except (TypeError, ValueError):
                        canonical = repr(sorted(result.items()))
                    finding_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

            function_name = logical_location_function(first_loc, run.get("logicalLocations"))
            region = _as_dict(loc.get("region"))
            snippet = _snippet_text(loc)

            # Extract dataflow path if present
            code_flows = result.get("codeFlows") or []
            properties = _as_dict(result.get("properties"))
            is_compiler_path = properties.get("code_flow_kind") == PATH_KIND or (tool_name == "compiler" and bool(code_flows))
            compiler_evidence: dict[str, Any] = {}
            if is_compiler_path:
                bounded: dict[str, Any] = {}
                locate = (lambda uri: None if _uri_escapes_root(quote(uri, safe="/"), source_root) else uri) if source_root is not None else None
                attach_paths(bounded, {"code_flows": code_flows,
                                      "compiler_path_notes": properties.get("compiler_path_notes")}, locate)
                compiler_evidence = bounded
                dataflow_path = None  # Control-flow assumptions are not taint source/sink evidence.
            else:
                dataflow_path = extract_dataflow_path(
                    code_flows, resolve_uri=_resolve_flow_uri,
                    thread_flow_locations=run.get("threadFlowLocations"),
                ) if code_flows else None

            rule_cwe, default_level, rule_scope = rule_resolver.metadata(rule)

            # Containment gate at the parse boundary (opt-in via
            # source_root). Out-of-root URIs degrade the same way the
            # import normalizer treats unmappable URIs: skip + warn.
            if (
                source_root is not None
                and file_uri
                and _uri_escapes_root(file_uri, source_root)
            ):
                logger.warning(
                    "SARIF parser: skipping finding with out-of-root "
                    "URI: %s (rule_id=%s)",
                    escape_nonprintable(file_uri),
                    escape_nonprintable(str(rule_id)),
                )
                continue

            if is_compiler_path:
                retained: dict[str, Any] = {}
                compiler_path_budget.retain(retained, compiler_evidence.get("code_flows", []),
                                             compiler_evidence.get("compiler_path_notes", []))
                compiler_evidence = retained

            message_text = _text_value(result.get("message"))
            level = result.get("level")
            if not isinstance(level, str) or not level:
                # SARIF severity inheritance: absent result.level means
                # the rule's defaultConfiguration.level (semgrep never
                # emits result.level).
                level = default_level or "warning"

            columns = {}
            for field in ("startColumn", "endColumn"):
                column = _coerce_line(region.get(field))
                if column is not None and column > 0:
                    columns[field] = column

            findings.append(
                {
                    "finding_id": finding_id,
                    **({"rule_scope": rule_scope} if rule_scope else {}),
                    "rule_id": rule_id,
                    "message": message_text,
                    "file": file_uri,
                    **({"function": function_name} if function_name else {}),
                    # Untrusted numeric fields: coerced to int-or-None at
                    # the parse boundary so downstream arithmetic and
                    # slicing (snippet synthesis in the import
                    # normalizer) never see a string / Infinity / NaN.
                    "startLine": _coerce_line(region.get("startLine")),
                    "endLine": _coerce_line(region.get("endLine")),
                    **columns,
                    "snippet": snippet,
                    "level": level,
                    "cwe_id": _extract_cwe_from_rule(result) or rule_cwe,
                    "tool": tool_name,
                    # Dataflow information
                    "has_dataflow": dataflow_path is not None,
                    "dataflow_path": dataflow_path,
                    **({"compiler_evidence": compiler_evidence} if is_compiler_path else {}),
                }
            )

    logger.info("SARIF parser: parsed %d total findings", len(findings))
    return findings


def validate_sarif(
    sarif_path: Path, schema_path: Path | None = None,
) -> bool | None:
    """
    Validate SARIF file against schema.

    Args:
        sarif_path: Path to SARIF file
        schema_path: Optional path to SARIF schema (auto-detected if None)

    Returns:
        Tri-state — pre-fix returned plain bool, which conflated
        "passed full validation" with "couldn't run full validation
        but the basic shape was OK" (jsonschema not installed, schema
        file missing, schema file unreadable). Callers couldn't
        distinguish "trust this SARIF" from "couldn't fully verify
        it" — the latter often warrants a warning to the operator.

          * True   — passed full schema validation.
          * False  — failed validation (load failed, version
                     unsupported, missing 'runs' field, OR
                     jsonschema reported a schema violation).
          * None   — basic structural checks passed, but full
                     schema validation could not run (jsonschema
                     not installed, schema file missing /
                     unreadable). Caller decides whether to treat
                     as trust-with-warning or as failure.
    """
    sarif_data = load_sarif(sarif_path)
    if not sarif_data:
        return False

    if sarif_data.get("version") not in ["2.1.0", "2.0.0"]:
        logger.warning(
            "SARIF validation: unsupported version: %s", sarif_data.get('version')
        )
        return False

    if "runs" not in sarif_data:
        logger.warning("SARIF validation: missing required 'runs' field")
        return False

    runs = sarif_data["runs"]
    if not isinstance(runs, list) or any(
        not isinstance(run, dict)
        or ("results" in run and (
            not isinstance(run["results"], list)
            or any(not isinstance(result, dict) for result in run["results"])
        ))
        for run in runs
    ):
        logger.warning("SARIF validation: runs and results must be arrays of objects")
        return False

    # Track whether full schema validation actually ran. If it didn't,
    # we return None (the tri-state "couldn't verify") rather than
    # True (the false-positive "fully verified").
    full_validation_ran = False
    try:
        import jsonschema

        if schema_path is None:
            schema_path = RaptorConfig.SCHEMAS_DIR / "sarif-2.1.0.json"

        if schema_path.exists():
            schema = load_json(schema_path)
            if schema is not None:
                jsonschema.validate(instance=sarif_data, schema=schema)
                full_validation_ran = True
            else:
                logger.warning(
                    "SARIF validation: schema file unreadable: %s", schema_path
                )
        else:
            logger.debug(
                "SARIF validation: schema file not found at %s; skipping full validation", schema_path
            )
    except ImportError:
        logger.debug(
            "SARIF validation: jsonschema not installed; "
            "skipping full validation"
        )
    except jsonschema.SchemaError as e:
        # The bundled schema itself is invalid — that is a local
        # deployment problem, not evidence about the SARIF file, so
        # report "couldn't verify" rather than pass/fail.
        logger.warning("SARIF validation: schema file invalid: %s", e.message)
    except jsonschema.ValidationError as e:
        logger.warning("SARIF validation: schema validation failed: %s", e.message)
        return False

    return True if full_validation_ran else None


_TOOL_NAME_MAP = {
    "semgrep oss": "semgrep",
    "semgrep": "semgrep",
    "codeql": "codeql",
    "coccinelle": "coccinelle",
}


def _normalise_tool_name(driver_name: str) -> str:
    """Map a SARIF ``tool.driver.name`` to the canonical key used by
    ``scan_coverage.py`` (``semgrep``, ``codeql``, ``coccinelle``).
    Falls back to a lowercased version of the driver name."""
    return _TOOL_NAME_MAP.get(driver_name.lower(), driver_name.lower())


def generate_scan_metrics(
    sarif_paths: list[str], *, file_count_paths: list[str] | None = None,
) -> dict[str, Any]:
    """
    Generate metrics from scan results.

    Args:
        sarif_paths: Reports whose findings are counted.
        file_count_paths: Optional original reports for artifact-based file
            counts and execution diagnostics when merging has discarded or
            changed metadata. Their findings do not enter finding metrics.

    Returns:
        Dictionary containing scan metrics
    """
    metrics: dict[str, Any] = {
        "total_files_scanned": 0,
        "total_findings": 0,
        "nosemgrep_suppressed_count": 0,
        "findings_by_severity": {
            "error": 0,
            "warning": 0,
            "note": 0,
            "none": 0,
        },
        "findings_by_rule": {},
        "findings_by_tool": {},
        "tools_used": [],
        "tool_execution_failures": {},
        "tool_coverage_limitations": {},
        "sarif_input_errors": 0,
    }

    # A report used for both findings and provenance is decoded only once.
    inputs = {path: (True, file_count_paths is None) for path in sarif_paths}
    if file_count_paths is not None:
        for path in file_count_paths:
            inputs[path] = (inputs.get(path, (False, False))[0], True)

    def execution_metrics(run: dict, tool_key: str) -> None:
        invocations = run.get("invocations", [])
        if not isinstance(invocations, list):
            metrics["sarif_input_errors"] += 1
            return
        for invocation in invocations:
            if not isinstance(invocation, dict):
                metrics["sarif_input_errors"] += 1
                continue
            failed = invocation.get("executionSuccessful") is False
            if "executionSuccessful" in invocation and type(invocation["executionSuccessful"]) is not bool:
                metrics["sarif_input_errors"] += 1
            notifications = invocation.get("toolExecutionNotifications", [])
            if not isinstance(notifications, list):
                metrics["sarif_input_errors"] += 1
                notifications = []
            for note in notifications:
                if not isinstance(note, dict):
                    metrics["sarif_input_errors"] += 1
                    continue
                failed |= note.get("level") == "error"
                limitation = _as_dict(note.get("properties")).get("coverage_limitation")
                # Older compiler reports used this marker for informational
                # review candidates, which do not imply incomplete analysis.
                if isinstance(limitation, str) and limitation and limitation != "review_candidates":
                    counts = metrics["tool_coverage_limitations"]
                    counts[tool_key] = counts.get(tool_key, 0) + 1
            if failed:
                counts = metrics["tool_execution_failures"]
                counts[tool_key] = counts.get(tool_key, 0) + 1

    def accumulate_file(sarif_path: str, count_findings: bool, count_files: bool) -> None:
        sarif_data = load_sarif(Path(sarif_path))
        if not sarif_data or not isinstance(sarif_data.get("runs"), list):
            metrics["sarif_input_errors"] += 1
            return

        for run in sarif_data["runs"]:
            if not isinstance(run, dict):
                metrics["sarif_input_errors"] += 1
                continue
            if count_files or not file_count_paths:
                execution_metrics(run, _normalise_tool_name(get_tool_name(run)))
            if count_files:
                artifacts = run.get("artifacts", [])
                if isinstance(artifacts, list):
                    metrics["total_files_scanned"] += len(artifacts)
                elif artifacts is not None:
                    metrics["sarif_input_errors"] += 1
            results = run.get("results", [])
            if not isinstance(results, list):
                metrics["sarif_input_errors"] += 1
                results = []
            else:
                metrics["sarif_input_errors"] += sum(not isinstance(row, dict) for row in results)
            if not count_findings:
                continue
            tool_name = get_tool_name(run)
            if tool_name not in metrics["tools_used"]:
                metrics["tools_used"].append(tool_name)

            # Preserve finding-count semantics; malformed rows are separately
            # recorded so counts cannot imply successful analysis.
            metrics["total_findings"] += len(results)

            tool_key = _normalise_tool_name(tool_name)
            metrics["findings_by_tool"][tool_key] = (
                metrics["findings_by_tool"].get(tool_key, 0) + len(results)
            )

            rule_resolver: ResultRuleResolver | None = None

            for result in results:
                if not isinstance(result, dict):
                    continue
                suppression = _as_dict(_as_dict(result.get("properties")).get("nosemgrep"))
                if suppression.get("suppressed") is True:
                    metrics["nosemgrep_suppressed_count"] += 1
                # Resolve at most once, and only when an inherited field
                # needs it. Fully explicit results need no descriptor lookup.
                level = result.get("level")
                raw_rule_id = result.get("ruleId")
                needs_level = not isinstance(level, str) or not level
                needs_id = not isinstance(raw_rule_id, str) or not raw_rule_id
                rule = {}
                if needs_level or needs_id:
                    if rule_resolver is None:
                        rule_resolver = ResultRuleResolver(run)
                    rule = rule_resolver.resolve(result)
                # Count by severity
                if needs_level:
                    level = rule_default_level(rule) or "warning"
                if level in metrics["findings_by_severity"]:
                    metrics["findings_by_severity"][level] += 1

                # Count by rule
                rule_id = _result_rule_id(result, rule) or "unknown"
                metrics["findings_by_rule"][rule_id] = (
                    metrics["findings_by_rule"].get(rule_id, 0) + 1
                )

    # Metrics retain only counts and names, never the decoded input or resolver.
    for sarif_path, (count_findings, count_files) in inputs.items():
        accumulate_file(sarif_path, count_findings, count_files)

    return metrics


def sanitize_finding_for_display(finding: dict[str, Any]) -> dict[str, Any]:
    """
    Sanitize a finding for safe display, truncating long fields.

    Args:
        finding: Finding dictionary

    Returns:
        Sanitized finding dictionary
    """
    sanitized = finding.copy()

    # Truncate long snippets.
    #
    # Pre-fix the gates were `if "X" in sanitized and len(...)`,
    # treating "key present" as "value is a string" — but a SARIF
    # finding can carry `{"snippet": null}` or `{"message": null}`
    # explicitly (some tools serialise unset fields as null
    # rather than omitting them). `len(None)` then crashed with
    # TypeError, dropping the whole finding from the sanitised
    # output and leaving the operator's report short by one
    # entry per finding-with-null-message. Add isinstance
    # guards so the truncation only fires when the value
    # actually IS a string.
    snippet = sanitized.get("snippet")
    if isinstance(snippet, str) and len(snippet) > 500:
        sanitized["snippet"] = snippet[:497] + "..."

    message = sanitized.get("message")
    if isinstance(message, str) and len(message) > 200:
        sanitized["message"] = message[:197] + "..."

    return sanitized
