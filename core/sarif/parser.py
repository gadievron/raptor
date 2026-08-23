"""
RAPTOR SARIF Utilities

Utilities for working with SARIF (Static Analysis Results Interchange Format) files,
including validation, deduplication, and merging.
"""

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from core.config import RaptorConfig
from core.json import load_json, loads
from core.logging import get_logger
from core.security.log_sanitisation import escape_nonprintable

logger = get_logger()


def _as_dict(value: Any) -> dict[str, Any]:
    """Untrusted-shape guard: return *value* if it is a dict, else {}.

    SARIF nesting (`tool.driver`, `physicalLocation.region`, ...) is
    attacker-controlled — a crafted file can put a string or null where
    the spec says object, and a bare `.get()` chain then raises
    AttributeError and aborts the whole import."""
    return value if isinstance(value, dict) else {}


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


def _path_from_locations(
    locations: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Build a {source, sink, steps, total_steps} dict from one
    SARIF threadFlow's locations array. Returns None if there are
    fewer than 2 locations (no source-to-sink path)."""
    if len(locations) < 2:
        return None
    path: dict[str, Any] = {
        "source": None,
        "sink": None,
        "steps": [],
        "total_steps": len(locations),
    }
    for idx, loc_wrapper in enumerate(locations):
        location = loc_wrapper.get("location", {})
        physical_loc = location.get("physicalLocation") or {}
        artifact = physical_loc.get("artifactLocation") or {}
        region = physical_loc.get("region") or {}
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
            (region.get("snippet") or {}).get("text", "") or ""
        )
        step_info = {
            "file": artifact.get("uri", ""),
            "line": _coerce_line(region.get("startLine")) or 0,
            "column": _coerce_line(region.get("startColumn")) or 0,
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


def extract_dataflow_path(code_flows: list[dict[str, Any]]) -> dict[str, Any] | None:
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

    all_paths: list[dict[str, Any]] = []
    for flow in code_flows:
        try:
            for tflow in (flow.get("threadFlows") or []):
                locations = tflow.get("locations") or []
                p = _path_from_locations(locations)
                if p is not None:
                    all_paths.append(p)
        except Exception as e:  # noqa: BLE001
            logger.warning("SARIF parser: skipping malformed codeFlow: %s", e)
            continue

    if not all_paths:
        return None

    primary = all_paths[0]
    primary["alternative_paths"] = all_paths[1:]
    return primary


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Remove duplicate findings by (file, startLine, endLine, rule_id)
    identity.

    Operates on parsed finding dicts and does not consult SARIF
    ``partialFingerprints`` — that lives in :func:`_result_key`, the
    raw-result dedup used by :func:`merge_sarif`.

    Identity key: (file, startLine, endLine, rule_id, finding_id).
    Pre-fix the key stopped at rule_id, which was COARSER than the
    raw-result discipline in :func:`_result_key` — two distinct
    same-line findings (different column, different tool
    fingerprint) survived ``merge_sarif`` only to be collapsed here.
    ``finding_id`` (parse-time identity: tool fingerprint or the
    location/fingerprint hash) carries exactly the column +
    fingerprint distinction, so including it aligns the two dedup
    layers. Findings from producers that set no finding_id key
    degrade to the legacy behaviour (None in that slot).

    Args:
        findings: List of finding dictionaries

    Returns:
        List of unique findings
    """
    seen: set[tuple] = set()
    unique: list[dict[str, Any]] = []

    for finding in findings:
        # Create fingerprint from location + rule + parse identity
        fp = (
            finding.get("file"),
            finding.get("startLine"),
            finding.get("endLine"),
            finding.get("rule_id"),
            finding.get("finding_id"),
        )

        if fp not in seen:
            seen.add(fp)
            unique.append(finding)

    return unique


def _result_key(
    result: dict[str, Any],
) -> tuple[str, str, int, int, int, str]:
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
    return (rule_id, uri, line, end_line, start_col, fingerprint)


def merge_sarif(sarif_paths: list[str]) -> dict[str, Any]:
    """
    Merge multiple SARIF files into a single SARIF dict.

    Groups runs by tool name, deduplicates results within each tool by
    ``_result_key`` (ruleId, uri, startLine, endLine, startColumn,
    fingerprint). Latest occurrence wins on collision.

    Args:
        sarif_paths: List of paths to SARIF files

    Returns:
        Merged SARIF dict with deduplicated results per tool
    """
    # Group runs by tool name so same-tool runs get their results merged
    tool_runs: dict[str, dict[str, Any]] = {}  # tool_name -> merged run

    for sarif_path in sarif_paths:
        sarif_data = load_sarif(Path(sarif_path))
        if not sarif_data:
            continue
        for run in (sarif_data.get("runs") or []):
            if not isinstance(run, dict):
                logger.warning(
                    "SARIF merge: skipping non-object run in %s", sarif_path
                )
                continue
            tool_name = get_tool_name(run)
            if tool_name not in tool_runs:
                tool_runs[tool_name] = {
                    "tool": _as_dict(run.get("tool")),
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
            tool_runs[tool_name]["rules_by_id"].update(get_rules(run))
            # Merge originalUriBaseIds — keyed dict, later wins.
            # Same-tool runs from different working trees can define
            # the SAME base id (e.g. %SRCROOT%) with DIFFERENT uris;
            # the merged run keeps only one, so relative URIs from the
            # other run(s) resolve against the wrong root. SARIF has
            # no per-result base table, so keeping per-run bases would
            # mean keeping the runs separate — not worth breaking the
            # one-run-per-tool merge shape. Detect the conflict and
            # warn the operator instead of silently mis-resolving.
            for base_id, base in _as_dict(run.get("originalUriBaseIds")).items():
                if isinstance(base, dict):
                    existing = tool_runs[tool_name]["uri_bases"].get(base_id)
                    if existing is not None and existing != base:
                        logger.warning(
                            "SARIF merge: conflicting originalUriBaseIds "
                            "definition for %r while merging %s "
                            "(%r vs %r); later definition wins — "
                            "relative URIs from earlier runs of tool "
                            "%r may resolve against the wrong root",
                            base_id, sarif_path,
                            existing.get("uri"), base.get("uri"),
                            tool_name,
                        )
                    tool_runs[tool_name]["uri_bases"][base_id] = base
            # Append invocations — each input run is its own
            # invocation record; multiple legitimately coexist.
            for inv in run.get("invocations") or []:
                if isinstance(inv, dict):
                    tool_runs[tool_name]["invocations"].append(inv)
            for result in run.get("results") or []:
                if not isinstance(result, dict):
                    continue
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
        run_out: dict[str, Any] = {
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


def load_sarif(sarif_path: Path) -> dict[str, Any] | None:
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
        logger.error("SARIF: file does not exist: %s", sarif_path)
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
                "SARIF: file too large (%.0f MiB): %s",
                st.st_size / 1024 / 1024, sarif_path,
            )
            return None
        with sarif_path.open("rb") as f:
            raw = f.read(max_size + 1)
        if len(raw) > max_size:
            # Race: file grew between stat and read.
            logger.error(
                "SARIF: file grew past %.0f MiB during read: %s",
                max_size / 1024 / 1024, sarif_path,
            )
            return None
        content = raw.decode("utf-8", errors="replace")
    except OSError as e:
        logger.warning("SARIF: could not read %s: %s", sarif_path, e)
        return None

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

    Non-object rules and non-string rule ids (spec violations in
    untrusted SARIF) are dropped rather than crashing the parse."""
    driver = _as_dict(_as_dict(run.get("tool")).get("driver"))
    rules = driver.get("rules")
    if not isinstance(rules, list):
        return {}
    return {
        r["id"]: r
        for r in rules
        if isinstance(r, dict) and isinstance(r.get("id"), str) and r["id"]
    }


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
    clean = unquote(uri).removeprefix("file://")
    try:
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

    runs = data.get("runs") or []
    # Debug: parsing internals — this fires for every SARIF file every
    # pipeline stage touches, so at INFO it was per-finding chatter in
    # the audit trail. Malformed-input warnings above stay WARNING.
    logger.debug("SARIF parser: found %d run(s) in SARIF file", len(runs))

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
        uri_bases = _as_dict(run.get("originalUriBaseIds"))

        def _resolve_uri(
            art: dict[str, Any], _uri_bases=uri_bases,
        ) -> str | None:
            """Resolve `art.uri` against the run's `originalUriBaseIds`,
            following nested `uriBaseId` references up to a small depth
            cap. Returns the final URI string, or None if the input
            has no `uri`."""
            uri = art.get("uri")
            if not isinstance(uri, str):
                return None
            base_id = art.get("uriBaseId")
            seen: set[str] = set()
            depth = 0
            while isinstance(base_id, str) and base_id not in seen and depth < 16:
                seen.add(base_id)
                depth += 1
                base = _uri_bases.get(base_id)
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
            if not isinstance(result, dict):
                logger.warning(
                    "SARIF parser: skipping non-object result in run %d",
                    run_idx + 1,
                )
                continue
            # finding_id resolution:
            #   1. SARIF tool-supplied fingerprint (best — survives
            #      reformatting / line-shifts that the tool tracked).
            #      Semgrep emits `fingerprints["matchBasedId/v1"]`, so
            #      semgrep finding_ids are unchanged by this logic.
            #   2. Deterministic hash of the same identity material
            #      `_result_key` uses (ruleId, uri, startLine, endLine,
            #      startColumn, partialFingerprints) — stable across
            #      runs, distinct per location.
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
            try:
                canonical = json.dumps(result, sort_keys=True, default=str)
            except (TypeError, ValueError):
                canonical = repr(sorted(result.items()))
            sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            rule_id = result.get("ruleId")
            if not isinstance(rule_id, str):
                rule_id = None
            fingerprint = _as_dict(result.get("fingerprints")).get("matchBasedId/v1")
            if isinstance(fingerprint, str) and fingerprint:
                finding_id = fingerprint
            else:
                key = _result_key(result)
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
                    finding_id = sha

            locs = result.get("locations")
            first_loc = _as_dict(locs[0]) if isinstance(locs, list) and locs else {}
            loc = _as_dict(first_loc.get("physicalLocation"))
            artifact = _as_dict(loc.get("artifactLocation"))
            region = _as_dict(loc.get("region"))
            snippet = _as_dict(region.get("snippet")).get("text", "")
            if not isinstance(snippet, str):
                snippet = ""

            # Extract dataflow path if present
            code_flows = result.get("codeFlows") or []
            dataflow_path = extract_dataflow_path(code_flows) if code_flows else None

            rule_meta = rules_by_id.get(rule_id, {})

            file_uri = _resolve_uri(artifact)
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

            message_text = _as_dict(result.get("message")).get("text")
            if not isinstance(message_text, str):
                message_text = None
            level = result.get("level", "warning")
            if not isinstance(level, str):
                level = "warning"

            findings.append(
                {
                    "finding_id": finding_id,
                    "rule_id": rule_id,
                    "message": message_text,
                    "file": file_uri,
                    # Untrusted numeric fields: coerced to int-or-None at
                    # the parse boundary so downstream arithmetic and
                    # slicing (snippet synthesis in the import
                    # normalizer) never see a string / Infinity / NaN.
                    "startLine": _coerce_line(region.get("startLine")),
                    "endLine": _coerce_line(region.get("endLine")),
                    "snippet": snippet,
                    "level": level,
                    "cwe_id": rule_meta.get("cwe_id"),
                    "tool": tool_name,
                    # Dataflow information
                    "has_dataflow": dataflow_path is not None,
                    "dataflow_path": dataflow_path,
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


def generate_scan_metrics(sarif_paths: list[str]) -> dict[str, Any]:
    """
    Generate metrics from scan results.

    Args:
        sarif_paths: List of paths to SARIF files

    Returns:
        Dictionary containing scan metrics
    """
    metrics: dict[str, Any] = {
        "total_files_scanned": 0,
        "total_findings": 0,
        "findings_by_severity": {
            "error": 0,
            "warning": 0,
            "note": 0,
            "none": 0,
        },
        "findings_by_rule": {},
        "findings_by_tool": {},
        "tools_used": [],
    }

    for sarif_path in sarif_paths:
        sarif_data = load_sarif(Path(sarif_path))
        if not sarif_data:
            continue

        for run in (sarif_data.get("runs") or []):
            if not isinstance(run, dict):
                continue
            tool_name = get_tool_name(run)
            if tool_name not in metrics["tools_used"]:
                metrics["tools_used"].append(tool_name)

            # Count artifacts (files)
            artifacts = run.get("artifacts") or []
            metrics["total_files_scanned"] += len(artifacts)

            # Count findings
            results = run.get("results") or []
            if not isinstance(results, list):
                results = []
            metrics["total_findings"] += len(results)

            tool_key = _normalise_tool_name(tool_name)
            metrics["findings_by_tool"][tool_key] = (
                metrics["findings_by_tool"].get(tool_key, 0) + len(results)
            )

            for result in results:
                if not isinstance(result, dict):
                    continue
                # Count by severity
                level = result.get("level", "warning")
                if isinstance(level, str) and level in metrics["findings_by_severity"]:
                    metrics["findings_by_severity"][level] += 1

                # Count by rule
                rule_id = result.get("ruleId", "unknown")
                if not isinstance(rule_id, str):
                    rule_id = "unknown"
                metrics["findings_by_rule"][rule_id] = (
                    metrics["findings_by_rule"].get(rule_id, 0) + 1
                )

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
