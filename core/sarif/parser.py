#!/usr/bin/env python3
"""
RAPTOR SARIF Utilities

Utilities for working with SARIF (Static Analysis Results Interchange Format) files,
including validation, deduplication, and merging.
"""

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core.config import RaptorConfig
from core.json import load_json
from core.logging import get_logger
from core.security.log_sanitisation import escape_nonprintable

logger = get_logger()


def _path_from_locations(
    locations: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Build a {source, sink, steps, total_steps} dict from one
    SARIF threadFlow's locations array. Returns None if there are
    fewer than 2 locations (no source-to-sink path)."""
    if len(locations) < 2:
        return None
    path: Dict[str, Any] = {
        "source": None,
        "sink": None,
        "steps": [],
        "total_steps": len(locations),
    }
    for idx, loc_wrapper in enumerate(locations):
        location = loc_wrapper.get("location", {})
        physical_loc = location.get("physicalLocation", {})
        artifact = physical_loc.get("artifactLocation", {})
        region = physical_loc.get("region", {})
        # Untrusted scanner-supplied text — escape control / format
        # bytes before surfacing into the operator-facing dataflow
        # path. A scanner producing `message.text = "evil\x1b[2J"`
        # (clear-screen ANSI escape, terminal hijack on stdout
        # render) or a code snippet containing C1 controls / bidi
        # overrides could otherwise smuggle terminal-rendering
        # behaviour through the dataflow display layer.
        message = escape_nonprintable(
            location.get("message", {}).get("text", "") or ""
        )
        snippet = escape_nonprintable(
            region.get("snippet", {}).get("text", "") or ""
        )
        step_info = {
            "file": artifact.get("uri", ""),
            "line": region.get("startLine", 0),
            "column": region.get("startColumn", 0),
            "label": message,
            "snippet": snippet,
        }
        if idx == 0:
            path["source"] = step_info
        elif idx == len(locations) - 1:
            path["sink"] = step_info
        else:
            path["steps"].append(step_info)
    return path


def extract_dataflow_path(code_flows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Extract dataflow path information from SARIF codeFlows.

    Pre-fix only `codeFlows[0].threadFlows[0]` was returned. SARIF
    results commonly carry multiple code flows (one per source-to-sink
    path the analyser identified) and multiple thread flows (one per
    relevant thread). Picking only the first hid genuinely-different
    paths from the operator — the second sink for the same source, the
    second source feeding the same sink, etc.

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

    try:
        # `.get(k, default)` returns the value (None) when the key is
        # present-but-null. SARIF emitters legitimately produce
        # `"threadFlows": null` when no flow is available — guard with
        # `or []` so iteration doesn't TypeError on None.
        all_paths: List[Dict[str, Any]] = []
        for flow in code_flows:
            for tflow in (flow.get("threadFlows") or []):
                locations = tflow.get("locations") or []
                p = _path_from_locations(locations)
                if p is not None:
                    all_paths.append(p)

        if not all_paths:
            return None

        primary = all_paths[0]
        primary["alternative_paths"] = all_paths[1:]
        return primary

    except Exception as e:
        logger.warning(f"SARIF parser: failed to extract dataflow path: {e}")
        return None


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove duplicate findings based on fingerprints.

    Args:
        findings: List of finding dictionaries

    Returns:
        List of unique findings
    """
    seen: Set[Tuple] = set()
    unique: List[Dict[str, Any]] = []

    for finding in findings:
        # Create fingerprint from location + rule
        fp = (
            finding.get("file"),
            finding.get("startLine"),
            finding.get("endLine"),
            finding.get("rule_id"),
        )

        if fp not in seen:
            seen.add(fp)
            unique.append(finding)

    return unique


def _result_key(
    result: Dict[str, Any],
) -> Tuple[str, str, int, int, int, str]:
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
    keeps deduping like before.
    """
    rule_id = result.get("ruleId", "")
    locs = result.get("locations") or [{}]
    phys = locs[0].get("physicalLocation", {}) if locs else {}
    uri = phys.get("artifactLocation", {}).get("uri", "")
    region = phys.get("region", {}) or {}
    line = region.get("startLine", 0)
    end_line = region.get("endLine", line)  # multi-line spans differ
    start_col = region.get("startColumn", 0)
    # `partialFingerprints` is a tool-supplied dict; serialise the
    # primary `primaryLocationLineHash` if present, else collapse the
    # whole dict to a stable string. SARIF spec recommends
    # `primaryLocationLineHash` as the dedup-quality fingerprint.
    fp = result.get("partialFingerprints") or {}
    fingerprint = fp.get("primaryLocationLineHash") or ""
    if not fingerprint and fp:
        # Fall back to a stable serialisation of the whole dict —
        # different fingerprint sets mean different findings.
        fingerprint = repr(sorted(fp.items()))
    return (rule_id, uri, line, end_line, start_col, fingerprint)


def merge_sarif(sarif_paths: List[str]) -> Dict[str, Any]:
    """
    Merge multiple SARIF files into a single SARIF dict.

    Groups runs by tool name, deduplicates results within each tool by
    (ruleId, uri, startLine). Latest occurrence wins on collision.

    Args:
        sarif_paths: List of paths to SARIF files

    Returns:
        Merged SARIF dict with deduplicated results per tool
    """
    # Group runs by tool name so same-tool runs get their results merged
    tool_runs: Dict[str, Dict[str, Any]] = {}  # tool_name -> merged run

    for sarif_path in sarif_paths:
        sarif_data = load_sarif(Path(sarif_path))
        if not sarif_data:
            continue
        for run in (sarif_data.get("runs") or []):
            tool_name = run.get("tool", {}).get("driver", {}).get("name", "unknown")
            if tool_name not in tool_runs:
                tool_runs[tool_name] = {
                    "tool": run.get("tool", {}),
                    # Track rules by id so we union the rule list across
                    # same-tool runs without duplicates. Pre-fix the
                    # `tool` block was set once (first run wins) and any
                    # rules emitted in subsequent runs' tool.driver.rules
                    # were silently dropped — downstream consumers
                    # looking up `result.ruleId` against the merged
                    # rule index missed those rules entirely (CWE
                    # lookup, severity inheritance, etc. all returned
                    # None for the dropped rules).
                    "rules_by_id": {},
                    "results": {},  # keyed by _result_key for dedup
                    # Preserve `originalUriBaseIds` and `invocations`
                    # across same-tool runs. Pre-fix these were
                    # silently dropped — `parse_sarif_findings`
                    # downstream cannot resolve relative URIs in the
                    # results without `originalUriBaseIds`, and
                    # consumers reasoning about run timing /
                    # exitCode (CI gates, run-aborted detection) need
                    # `invocations` intact. Per-id merge for the
                    # bases (later wins on key collision); list
                    # extend for invocations (each run is its own
                    # logical invocation).
                    "uri_bases": {},
                    "invocations": [],
                }
            # Union this run's rules into the per-tool index. Same-id
            # rules from later runs win on collision (matches the
            # latest-occurrence-wins semantic the result dedup uses).
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
                if isinstance(rule, dict):
                    rule_id = rule.get("id")
                    if rule_id:
                        tool_runs[tool_name]["rules_by_id"][rule_id] = rule
            # Merge originalUriBaseIds — keyed dict, later wins.
            for base_id, base in (run.get("originalUriBaseIds") or {}).items():
                if isinstance(base, dict):
                    tool_runs[tool_name]["uri_bases"][base_id] = base
            # Append invocations — each input run is its own
            # invocation record; multiple legitimately coexist.
            for inv in run.get("invocations") or []:
                if isinstance(inv, dict):
                    tool_runs[tool_name]["invocations"].append(inv)
            for result in run.get("results", []):
                key = _result_key(result)
                tool_runs[tool_name]["results"][key] = result

    # Build final SARIF with one run per tool
    merged_runs = []
    for tool_name, run_data in tool_runs.items():
        # Re-inject the unioned rule list into tool.driver.rules.
        tool_block = dict(run_data["tool"]) if run_data["tool"] else {}
        driver = dict(tool_block.get("driver") or {})
        if run_data["rules_by_id"]:
            driver["rules"] = list(run_data["rules_by_id"].values())
        tool_block["driver"] = driver
        run_out: Dict[str, Any] = {
            "tool": tool_block,
        }
        if run_data["uri_bases"]:
            run_out["originalUriBaseIds"] = run_data["uri_bases"]
        if run_data["invocations"]:
            run_out["invocations"] = run_data["invocations"]
        run_out["results"] = list(run_data["results"].values())
        merged_runs.append(run_out)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": merged_runs,
    }


_CWE_TAG_RE = re.compile(r"cwe[-_]?(\d+)", re.IGNORECASE)


def _extract_cwe_from_rule(rule: Dict[str, Any]) -> Optional[str]:
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
    props = rule.get("properties") or {}

    # `properties.cwe` — string OR list.
    raw_cwe = props.get("cwe") or props.get("cwe_id")
    if isinstance(raw_cwe, str):
        m = _CWE_TAG_RE.search(raw_cwe)
        if m:
            return f"CWE-{m.group(1)}"
    elif isinstance(raw_cwe, list):
        for entry in raw_cwe:
            if isinstance(entry, str):
                m = _CWE_TAG_RE.search(entry)
                if m:
                    return f"CWE-{m.group(1)}"

    # `properties.tags` — list of strings, may contain external/cwe/cwe-N.
    for tag in props.get("tags", []) or []:
        if isinstance(tag, str):
            m = _CWE_TAG_RE.search(tag)
            if m:
                return f"CWE-{m.group(1)}"

    # `relationships[]` — SARIF spec's canonical mechanism. Each
    # relationship has a `target` reference (`{"id": "CWE-89", ...}`
    # or `{"toolComponent": {"name": "CWE"}, "id": "89"}`).
    for rel in rule.get("relationships") or []:
        if not isinstance(rel, dict):
            continue
        target = rel.get("target") or {}
        if not isinstance(target, dict):
            continue
        target_id = target.get("id")
        if isinstance(target_id, str):
            m = _CWE_TAG_RE.search(target_id)
            if m:
                return f"CWE-{m.group(1)}"
        # CodeQL emits the bare numeric id with the toolComponent
        # naming the CWE catalog separately.
        tc = target.get("toolComponent") or {}
        if (
            isinstance(tc, dict)
            and isinstance(tc.get("name"), str)
            and tc["name"].upper() == "CWE"
            and isinstance(target_id, (str, int))
        ):
            try:
                return f"CWE-{int(str(target_id))}"
            except ValueError:
                pass

    return None


def load_sarif(sarif_path: Path) -> Optional[Dict[str, Any]]:
    """
    Load a SARIF file with safety guards.

    Handles existence check, size guard (100 MiB), and JSON decode errors.
    All SARIF file I/O should go through this function.

    Args:
        sarif_path: Path to SARIF file

    Returns:
        Parsed SARIF dict, or None on error
    """
    if not sarif_path.exists():
        logger.error(f"SARIF: file does not exist: {sarif_path}")
        return None

    max_size = 100 * 1024 * 1024  # 100 MiB

    # Stat-then-bounded-read. Pre-fix the function used
    # `sarif_path.read_text()` followed by `if len(content) > max_size`
    # — the WHOLE file was loaded into memory BEFORE the size check,
    # so a 10 GB malformed/hostile SARIF file OOM-killed the process
    # instead of being rejected. The "avoids TOCTOU" comment was
    # technically true but irrelevant: the real risk here is memory
    # exhaustion, not stat/read size-skew (a few KB drift between
    # stat and read doesn't matter for the cap decision).
    #
    # Bounded read of `max_size + 1` bytes lets us detect "too large"
    # without ever loading more than the cap into memory. Reading
    # one extra byte is the standard "did we hit the limit" sentinel.
    try:
        st = sarif_path.stat()
        if st.st_size > max_size:
            logger.error(
                f"SARIF: file too large ({st.st_size / 1024 / 1024:.0f} MiB): "
                f"{sarif_path}"
            )
            return None
        with sarif_path.open("rb") as f:
            raw = f.read(max_size + 1)
        if len(raw) > max_size:
            # Race: file grew between stat and read.
            logger.error(
                f"SARIF: file grew past {max_size / 1024 / 1024:.0f} MiB "
                f"during read: {sarif_path}"
            )
            return None
        content = raw.decode("utf-8", errors="replace")
    except OSError as e:
        logger.warning(f"SARIF: could not read {sarif_path}: {e}")
        return None

    try:
        data = json.loads(content or "{}")
    except json.JSONDecodeError as e:
        logger.error(f"SARIF: invalid JSON in {sarif_path}: {e}")
        return None
    except OSError as e:
        logger.error(f"SARIF: could not read {sarif_path}: {e}")
        return None

    if not isinstance(data, dict):
        logger.error(f"SARIF: root must be an object in {sarif_path}")
        return None

    return data


def get_tool_name(run: Dict[str, Any]) -> str:
    """Extract tool name from a SARIF run."""
    return run.get("tool", {}).get("driver", {}).get("name") or "unknown"


def get_rules(run: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Extract rules from a SARIF run, keyed by rule ID."""
    return {
        r.get("id", ""): r
        for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        if r.get("id")
    }


def parse_sarif_findings(sarif_path: Path) -> List[Dict[str, Any]]:
    """
    Parse findings from a SARIF file.

    Args:
        sarif_path: Path to SARIF file

    Returns:
        List of finding dictionaries with normalized structure
    """
    data = load_sarif(sarif_path)
    if not data:
        return []

    findings: List[Dict[str, Any]] = []

    runs = data.get("runs") or []
    logger.info(f"SARIF parser: found {len(runs)} run(s) in SARIF file")
    
    for run_idx, run in enumerate(runs):
        results = run.get("results", [])
        logger.info(f"SARIF parser: run {run_idx + 1}: {len(results)} result(s)")

        tool_name = get_tool_name(run)

        # Build rule_id → CWE lookup
        rules_by_id = {}
        for rid, rule in get_rules(run).items():
            cwe_id = _extract_cwe_from_rule(rule)
            if rid:
                rules_by_id[rid] = {"cwe_id": cwe_id}

        # Per-run originalUriBaseIds for relative-URI resolution.
        # SARIF emitters commonly emit `result.locations[*].artifactLocation
        # = {"uri": "src/foo.c", "uriBaseId": "%SRCROOT%"}` rather than
        # an absolute URI. Pre-fix the parser took `artifact.get("uri")`
        # verbatim — `findings[i].file` came out as `"src/foo.c"`,
        # which subsequent consumers (vulnerability-rendering,
        # editor-jump links, dedup keyed on file path) treated as a
        # path relative to wherever they happened to be running.
        # Resolve via the run's `originalUriBaseIds` table.
        uri_bases = run.get("originalUriBaseIds") or {}

        def _resolve_uri(art: Dict[str, Any]) -> Optional[str]:
            """Resolve `art.uri` against the run's `originalUriBaseIds`,
            following nested `uriBaseId` references up to a small depth
            cap. Returns the final URI string, or None if the input
            has no `uri`."""
            uri = art.get("uri")
            if uri is None:
                return None
            base_id = art.get("uriBaseId")
            seen: Set[str] = set()
            depth = 0
            while base_id and base_id not in seen and depth < 16:
                seen.add(base_id)
                depth += 1
                base = uri_bases.get(base_id)
                if not isinstance(base, dict):
                    break
                base_uri = base.get("uri")
                if not isinstance(base_uri, str):
                    break
                # SARIF spec: base URIs end in '/'. Tolerate missing
                # separator without doubling.
                if not base_uri.endswith("/"):
                    base_uri = base_uri + "/"
                # Don't double-slash if the inner URI happens to be
                # absolute on its own.
                uri = base_uri + uri.lstrip("/")
                base_id = base.get("uriBaseId")
            return uri

        for result in results:
            # finding_id resolution:
            #   1. SARIF tool-supplied fingerprint (best — survives
            #      reformatting / line-shifts that the tool tracked).
            #   2. ruleId (cheap, but collides across multiple findings
            #      of the same rule type — only useful when the run has
            #      one finding per rule).
            #   3. Deterministic hash of the canonicalised result.
            #
            # Pre-fix the fallback was `str(hash(json.dumps(result)))`.
            # Two problems:
            #   * Python's `hash()` is randomised per-process by default
            #     (PYTHONHASHSEED) for security against hash-flooding,
            #     so the SAME finding produced a DIFFERENT finding_id
            #     on every invocation. Downstream consumers tracking
            #     findings across runs (deduplication, regression
            #     detection, fix verification) couldn't correlate.
            #   * `json.dumps` without `sort_keys=True` is also non-
            #     deterministic across dict insertion orders.
            # `hashlib.sha256(json.dumps(..., sort_keys=True))` fixes
            # both: identical input always yields the same hex digest.
            try:
                canonical = json.dumps(result, sort_keys=True, default=str)
            except (TypeError, ValueError):
                canonical = repr(sorted(result.items()))
            sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            finding_id = (
                (result.get("fingerprints") or {}).get("matchBasedId/v1")
                or result.get("ruleId")
                or sha
            )

            loc = (result.get("locations") or [{}])[0].get("physicalLocation", {})
            artifact = loc.get("artifactLocation", {})
            region = loc.get("region", {})
            snippet = region.get("snippet", {}).get("text", "")

            # Extract dataflow path if present
            code_flows = result.get("codeFlows") or []
            dataflow_path = extract_dataflow_path(code_flows) if code_flows else None

            rule_id = result.get("ruleId")
            rule_meta = rules_by_id.get(rule_id, {})

            findings.append(
                {
                    "finding_id": finding_id,
                    "rule_id": rule_id,
                    "message": result.get("message", {}).get("text"),
                    "file": _resolve_uri(artifact),
                    "startLine": region.get("startLine"),
                    "endLine": region.get("endLine"),
                    "snippet": snippet,
                    "level": result.get("level", "warning"),
                    "cwe_id": rule_meta.get("cwe_id"),
                    "tool": tool_name,
                    # Dataflow information
                    "has_dataflow": dataflow_path is not None,
                    "dataflow_path": dataflow_path,
                }
            )

    logger.info(f"SARIF parser: parsed {len(findings)} total findings")
    return findings


def validate_sarif(
    sarif_path: Path, schema_path: Optional[Path] = None,
) -> Optional[bool]:
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
            f"SARIF validation: unsupported version: {sarif_data.get('version')}"
        )
        return False

    if "runs" not in sarif_data:
        logger.warning("SARIF validation: missing required 'runs' field")
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
                    f"SARIF validation: schema file unreadable: {schema_path}"
                )
        else:
            logger.debug(
                f"SARIF validation: schema file not found at {schema_path}; "
                "skipping full validation"
            )
    except ImportError:
        logger.debug(
            "SARIF validation: jsonschema not installed; "
            "skipping full validation"
        )
    except jsonschema.ValidationError as e:
        logger.warning(f"SARIF validation: schema validation failed: {e.message}")
        return False

    return True if full_validation_ran else None


def generate_scan_metrics(sarif_paths: List[str]) -> Dict[str, Any]:
    """
    Generate metrics from scan results.

    Args:
        sarif_paths: List of paths to SARIF files

    Returns:
        Dictionary containing scan metrics
    """
    metrics: Dict[str, Any] = {
        "total_files_scanned": 0,
        "total_findings": 0,
        "findings_by_severity": {
            "error": 0,
            "warning": 0,
            "note": 0,
            "none": 0,
        },
        "findings_by_rule": {},
        "tools_used": [],
    }

    for sarif_path in sarif_paths:
        sarif_data = load_sarif(Path(sarif_path))
        if not sarif_data:
            continue

        for run in (sarif_data.get("runs") or []):
            tool_name = get_tool_name(run)
            if tool_name not in metrics["tools_used"]:
                metrics["tools_used"].append(tool_name)

            # Count artifacts (files)
            artifacts = run.get("artifacts", [])
            metrics["total_files_scanned"] += len(artifacts)

            # Count findings
            results = run.get("results", [])
            metrics["total_findings"] += len(results)

            for result in results:
                # Count by severity
                level = result.get("level", "warning")
                if level in metrics["findings_by_severity"]:
                    metrics["findings_by_severity"][level] += 1

                # Count by rule
                rule_id = result.get("ruleId", "unknown")
                metrics["findings_by_rule"][rule_id] = (
                    metrics["findings_by_rule"].get(rule_id, 0) + 1
                )

    return metrics


def sanitize_finding_for_display(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize a finding for safe display, truncating long fields.

    Args:
        finding: Finding dictionary

    Returns:
        Sanitized finding dictionary
    """
    sanitized = finding.copy()

    # Truncate long snippets
    if "snippet" in sanitized and len(sanitized["snippet"]) > 500:
        sanitized["snippet"] = sanitized["snippet"][:497] + "..."

    # Truncate long messages
    if "message" in sanitized and len(sanitized["message"]) > 200:
        sanitized["message"] = sanitized["message"][:197] + "..."

    return sanitized
