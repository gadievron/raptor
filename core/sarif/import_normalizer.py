"""Normalize externally-produced SARIF findings for the RAPTOR pipeline.

Imported SARIF may be missing fields that RAPTOR's own scanners always
populate (snippet, CWE, well-resolved file paths).  This module
synthesizes what it can from the source tree and warns about the rest,
producing findings in the same internal dict shape that
:func:`core.sarif.parser.parse_sarif_findings` returns.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from core.logging import get_logger
from core.sarif.parser import _coerce_line

logger = get_logger()


# ---------------------------------------------------------------------------
# CWE inference from rule_id / message text
# ---------------------------------------------------------------------------

_CWE_MESSAGE_PATTERNS: list[tuple] = [
    (re.compile(r"sql.?inject", re.IGNORECASE), "CWE-89"),
    (re.compile(r"command.?inject|os.?command|shell.?inject", re.IGNORECASE), "CWE-78"),
    (re.compile(r"cross.?site.?script|xss", re.IGNORECASE), "CWE-79"),
    (re.compile(r"path.?travers|directory.?travers", re.IGNORECASE), "CWE-22"),
    (re.compile(r"buffer.?over(?:flow|run)|stack.?overflow", re.IGNORECASE), "CWE-120"),
    (re.compile(r"heap.?over(?:flow|run)", re.IGNORECASE), "CWE-122"),
    (re.compile(r"format.?string", re.IGNORECASE), "CWE-134"),
    (re.compile(r"integer.?over(?:flow|wrap)", re.IGNORECASE), "CWE-190"),
    (re.compile(r"double.?free", re.IGNORECASE), "CWE-415"),
    (re.compile(r"use.?after.?free|uaf", re.IGNORECASE), "CWE-416"),
    (re.compile(r"null.?(?:pointer|deref|dereference)", re.IGNORECASE), "CWE-476"),
    (re.compile(r"out.?of.?bounds.?write", re.IGNORECASE), "CWE-787"),
    (re.compile(r"out.?of.?bounds.?read", re.IGNORECASE), "CWE-125"),
    (re.compile(r"uninitiali[sz]ed", re.IGNORECASE), "CWE-908"),
    (re.compile(r"deseriali[sz]ation", re.IGNORECASE), "CWE-502"),
    (re.compile(r"(?:server.?side|ssrf).?request.?forg", re.IGNORECASE), "CWE-918"),
    (re.compile(r"race.?condition|toctou|time.?of.?check", re.IGNORECASE), "CWE-367"),
    (re.compile(r"type.?confusion", re.IGNORECASE), "CWE-843"),
    (re.compile(r"hardcoded.?(?:secret|password|credential|key)", re.IGNORECASE), "CWE-798"),
]

_CWE_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def _infer_cwe(rule_id: str, message: str) -> str | None:
    """Infer CWE from rule_id keywords or finding message text.

    Returns ``"CWE-NNN"`` or None.  Tries the vuln-type reverse map
    first (covers Semgrep/CodeQL-style rule IDs), then falls back to
    message-text regex patterns.
    """
    try:
        from packages.exploit_feasibility import get_vuln_type_for_rule
        from core.schema_constants import VULN_TYPE_TO_CWE
        vt = get_vuln_type_for_rule(rule_id)
        if vt and vt in VULN_TYPE_TO_CWE:
            return VULN_TYPE_TO_CWE[vt]
    except ImportError:
        pass

    combined = f"{rule_id} {message}"

    m = _CWE_RE.search(combined)
    if m:
        from core.cve.cwe import format_cwe
        return format_cwe(m.group(1))

    for pattern, cwe in _CWE_MESSAGE_PATTERNS:
        if pattern.search(combined):
            return cwe

    return None


# ---------------------------------------------------------------------------
# URI rebasing — map scanner paths to the extracted source tree
# ---------------------------------------------------------------------------

def _strip_file_scheme(uri: str) -> str:
    if uri.startswith("file:///"):
        return uri[len("file:///"):]
    if uri.startswith("file://"):
        return uri[len("file://"):]
    return uri


_SCA_TOOL_KEYWORDS = (
    "snyk", "grype", "trivy", "dependency-check", "npm audit",
    "yarn audit", "pip-audit", "safety", "osv-scanner",
    "renovate", "dependabot",
)

_SAST_TOOL_KEYWORDS = (
    "codeql", "semgrep", "coverity", "bandit", "pylint", "flawfinder",
    "checkmarx", "fortify", "sonarqube", "sonar", "spotbugs", "findbugs",
    "clang-tidy", "cppcheck", "infer",
)

_DEPENDENCY_MANIFEST_NAMES = frozenset({
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "Pipfile.lock", "poetry.lock", "setup.cfg",
    "setup.py", "pyproject.toml", "Cargo.lock", "Cargo.toml",
    "go.sum", "go.mod", "Gemfile.lock", "Gemfile",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "composer.lock", "composer.json", "Podfile.lock",
    "packages.config", "Directory.Build.props",
})


def _is_sca_finding(finding: dict[str, Any]) -> bool:
    tool = (finding.get("tool") or "").lower().strip()
    if any(kw in tool for kw in _SCA_TOOL_KEYWORDS):
        return True
    if any(kw in tool for kw in _SAST_TOOL_KEYWORDS):
        return False
    uri = finding.get("file") or ""
    basename = Path(uri).name
    return basename in _DEPENDENCY_MANIFEST_NAMES


_SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".tox", ".venv",
    "venv", ".mypy_cache", ".pytest_cache",
})


def _build_file_index(source_root: Path) -> dict[str, list[Path]]:
    """Map basename → list of relative paths under *source_root*.

    Skips well-known non-source directories to keep the index small
    and the walk fast on large repos.
    """
    index: dict[str, list[Path]] = {}

    # Iterative walk (explicit stack). The tree being indexed is the
    # UNTRUSTED scanned repo — a recursive walk hits Python's
    # recursion limit around ~1000 directory levels and a hostile
    # deep tree would abort the whole import with RecursionError.
    stack: list[Path] = [source_root]
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(directory.iterdir())
        except (OSError, PermissionError):
            continue
        for entry in entries:
            if entry.is_dir() and not entry.is_symlink():
                if entry.name not in _SKIP_DIRS:
                    stack.append(entry)
            elif entry.is_file():
                rel = entry.relative_to(source_root)
                index.setdefault(entry.name, []).append(rel)

    return index


def _is_under_root(source_root: Path, candidate: str) -> bool:
    """Verify *candidate* resolves to a path under *source_root*.

    Defends against path-traversal in attacker-controlled SARIF URIs
    (``../../etc/passwd``).
    """
    try:
        resolved = (source_root / candidate).resolve()
        return resolved.is_file() and str(resolved).startswith(
            str(source_root.resolve()) + "/"
        )
    except (OSError, ValueError):
        return False


def _resolve_uri(
    uri: str,
    source_root: Path,
    file_index: dict[str, list[Path]],
    depth_cache: list[int | None],
) -> str | None:
    """Resolve a SARIF URI to a relative path under *source_root*.

    Tries progressively shorter prefixes until a match is found.
    Caches the successful strip-depth so subsequent findings from the
    same scanner resolve in O(1).

    Rejects any resolved path that escapes *source_root* (traversal
    defence for untrusted SARIF).

    Returns a POSIX-style relative path string, or None.
    """
    clean = unquote(_strip_file_scheme(uri))
    if clean.startswith("/"):
        clean = clean.lstrip("/")

    parts = Path(clean).parts
    if not parts:
        return None

    if depth_cache[0] is not None:
        candidate = str(Path(*parts[depth_cache[0]:])) if depth_cache[0] < len(parts) else None
        if candidate and _is_under_root(source_root, candidate):
            return candidate

    for depth in range(len(parts)):
        candidate = str(Path(*parts[depth:]))
        if _is_under_root(source_root, candidate):
            depth_cache[0] = depth
            return candidate

    basename = parts[-1]
    matches = file_index.get(basename, [])
    if len(matches) == 1:
        resolved = str(matches[0])
        if _is_under_root(source_root, resolved):
            logger.debug("URI %s: basename-only match → %s", uri, resolved)
            return resolved

    return None


# ---------------------------------------------------------------------------
# Snippet synthesis
# ---------------------------------------------------------------------------

_SNIPPET_CONTEXT_LINES = 3

# Per-finding source reads are bounded: the referenced file lives in
# the UNTRUSTED scanned tree and the SARIF (also untrusted) picks
# which file gets read — an unbounded read_text on a multi-GB blob
# would be repeated once per snippet-less finding. 10 MiB comfortably
# covers real source files (the sibling SARIF-document cap in
# parser.load_sarif is 100 MiB for whole result files).
_SNIPPET_SOURCE_MAX_BYTES = 10 * 1024 * 1024


def _synthesize_snippet(
    source_root: Path, rel_path: str,
    start_line: int, end_line: int | None,
) -> str:
    """Read the finding's source lines plus trailing context.

    The snippet starts at ``start_line`` (no leading context) and
    extends ``_SNIPPET_CONTEXT_LINES`` lines past the finding's end.
    Files larger than ``_SNIPPET_SOURCE_MAX_BYTES`` are skipped (the
    finding keeps flowing, just without a synthesized snippet).
    """
    try:
        full = source_root / rel_path
        if full.stat().st_size > _SNIPPET_SOURCE_MAX_BYTES:
            logger.warning(
                "SARIF import: skipping snippet synthesis for oversized "
                "file (>%d MiB): %s",
                _SNIPPET_SOURCE_MAX_BYTES // (1024 * 1024), rel_path,
            )
            return ""
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
        s = max(0, start_line - 1)
        e = min(len(lines), (end_line or start_line) + _SNIPPET_CONTEXT_LINES)
        return "\n".join(lines[s:e])
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Import result
# ---------------------------------------------------------------------------

@dataclass
class ImportWarning:
    finding_index: int
    field: str
    message: str


@dataclass
class ImportStats:
    total_imported: int = 0
    findings_skipped: int = 0
    cwe_inferred: int = 0
    snippet_synthesized: int = 0
    uri_rebased: int = 0
    uri_unresolved: int = 0
    sca_tagged: int = 0


@dataclass
class ImportResult:
    findings: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[ImportWarning] = field(default_factory=list)
    stats: ImportStats = field(default_factory=ImportStats)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def normalize_imported_findings(
    findings: list[dict[str, Any]],
    source_root: Path,
    original_tool: str = "external",
) -> ImportResult:
    """Normalize and enrich imported SARIF findings.

    Operates on the finding dicts produced by
    :func:`core.sarif.parser.parse_sarif_findings`.  Synthesizes
    missing fields from the source tree, rebases URIs, and infers CWE
    from rule IDs / message text.

    Findings that cannot be mapped to a source file are dropped (with
    a warning).
    """
    result = ImportResult()
    source_root = source_root.resolve()

    file_index = _build_file_index(source_root)
    depth_cache: list[int | None] = [None]

    for idx, finding in enumerate(findings):
        uri = finding.get("file") or ""
        if not isinstance(uri, str):
            uri = ""
        # Untrusted numeric fields: findings may arrive from external
        # SARIF where startLine is a JSON string or Infinity/NaN —
        # values that pass a truthiness gate but raise TypeError in
        # the snippet arithmetic below. Coerce to int-or-None and
        # require a positive line so only usable locations proceed.
        start_line = _coerce_line(finding.get("startLine"))
        if start_line is not None and start_line < 1:
            start_line = None
        if not uri or start_line is None:
            result.warnings.append(ImportWarning(
                idx, "file/startLine",
                f"Skipped: missing or invalid file/startLine "
                f"(rule_id={finding.get('rule_id')})",
            ))
            result.stats.findings_skipped += 1
            continue
        finding["startLine"] = start_line

        # --- URI rebasing ---
        resolved = _resolve_uri(uri, source_root, file_index, depth_cache)
        if resolved is None:
            result.warnings.append(ImportWarning(
                idx, "file",
                f"Skipped: cannot map URI to source: {uri}",
            ))
            result.stats.findings_skipped += 1
            result.stats.uri_unresolved += 1
            continue

        rebased = resolved != uri
        if rebased:
            result.stats.uri_rebased += 1
        finding["file"] = resolved

        # --- endLine default ---
        # Same coercion as startLine; a missing, non-integer, or
        # before-start endLine falls back to startLine.
        end_line = _coerce_line(finding.get("endLine"))
        if not end_line or end_line < start_line:
            end_line = start_line
        finding["endLine"] = end_line

        # --- snippet synthesis ---
        if not finding.get("snippet"):
            snippet = _synthesize_snippet(
                source_root, resolved,
                start_line, finding.get("endLine"),
            )
            if snippet:
                finding["snippet"] = snippet
                result.stats.snippet_synthesized += 1

        # --- CWE inference ---
        if not finding.get("cwe_id"):
            inferred = _infer_cwe(
                finding.get("rule_id") or "",
                finding.get("message") or "",
            )
            if inferred:
                finding["cwe_id"] = inferred
                finding["_cwe_inferred"] = True
                result.stats.cwe_inferred += 1

        # --- message fallback ---
        if not finding.get("message"):
            rule_id = finding.get("rule_id") or "unknown"
            finding["message"] = f"{rule_id} at {resolved}:{start_line}"

        # --- level default ---
        if not finding.get("level"):
            finding["level"] = "warning"

        # --- tool preservation ---
        if not finding.get("tool") or finding["tool"] == "unknown":
            finding["tool"] = original_tool

        # --- SCA detection ---
        if _is_sca_finding(finding):
            finding["source_type"] = "dependency"
            result.stats.sca_tagged += 1

        result.findings.append(finding)

    result.stats.total_imported = len(result.findings)
    return result


def format_import_summary(result: ImportResult, sarif_files: list[str]) -> str:
    """Format a human-readable import summary for the operator."""
    s = result.stats
    lines = [
        f"Importing SARIF: {', '.join(sarif_files)}",
        f"  → {s.total_imported} findings imported",
    ]
    if s.findings_skipped:
        unmapped = [w for w in result.warnings if w.field == "file"]
        if unmapped:
            examples = "; ".join(w.message.split(": ", 1)[-1] for w in unmapped[:3])
            lines.append(f"  → {s.findings_skipped} findings skipped ({examples})")
        else:
            lines.append(f"  → {s.findings_skipped} findings skipped")
        if s.uri_unresolved:
            lines.append(
                f"  → {s.uri_unresolved} skipped because their URIs "
                f"could not be mapped to the source tree"
            )
    if s.cwe_inferred:
        lines.append(f"  → {s.cwe_inferred} CWEs inferred from rule_id/message")
    if s.snippet_synthesized:
        lines.append(f"  → {s.snippet_synthesized} snippets synthesized from source")
    if s.uri_rebased:
        lines.append(f"  → {s.uri_rebased} URIs rebased to source tree")

    if s.sca_tagged:
        lines.append(
            f"  ⚠️  {s.sca_tagged} findings tagged as dependency (SCA) "
            f"— consider --also-scan for richer dependency analysis"
        )

    no_dataflow = sum(
        1 for f in result.findings if not f.get("has_dataflow")
    )
    if no_dataflow == len(result.findings) and result.findings:
        lines.append("  → 0 dataflow paths (SARIF did not include codeFlows)")
    return "\n".join(lines)


def _step_to_threadflow_location(step: dict[str, Any]) -> dict[str, Any]:
    """Convert one internal dataflow step ({file, line, column, label,
    snippet}) back to a SARIF threadFlow location object."""
    region: dict[str, Any] = {}
    line = step.get("line")
    if isinstance(line, int) and line > 0:
        region["startLine"] = line
    column = step.get("column")
    if isinstance(column, int) and column > 0:
        region["startColumn"] = column
    snippet = step.get("snippet")
    if isinstance(snippet, str) and snippet:
        region["snippet"] = {"text": snippet}
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": step.get("file") or ""},
            "region": region,
        }
    }
    label = step.get("label")
    if isinstance(label, str) and label:
        location["message"] = {"text": label}
    return {"location": location}


def _path_to_codeflow(path: dict[str, Any]) -> dict[str, Any] | None:
    """Convert one internal {source, sink, steps, ...} path dict to a
    SARIF codeFlow object, or None when the path has fewer than the
    two locations the parser requires to round-trip."""
    ordered = [path.get("source"), *(path.get("steps") or []), path.get("sink")]
    steps = [s for s in ordered if isinstance(s, dict)]
    if len(steps) < 2:
        return None
    return {
        "threadFlows": [
            {"locations": [_step_to_threadflow_location(s) for s in steps]}
        ]
    }


def _dataflow_to_codeflows(dataflow_path: Any) -> list[dict[str, Any]]:
    """Convert a finding's ``dataflow_path`` to a SARIF ``codeFlows`` array.

    ``parse_sarif_findings`` stores dataflow as an INTERNAL dict
    ({source, sink, steps, total_steps, alternative_paths}) — emitting
    that dict verbatim as ``result.codeFlows`` produced schema-invalid
    SARIF, and ``extract_dataflow_path`` on re-parse iterated its
    string keys and returned None, silently losing every imported
    finding's dataflow after the disk hop. Convert the dict back to
    the spec's array-of-codeFlow shape (one codeFlow for the primary
    path plus one per alternative path).

    A list value is already SARIF-shaped (hand-built findings that
    never went through the parser) and passes through unchanged.
    """
    if isinstance(dataflow_path, list):
        return [cf for cf in dataflow_path if isinstance(cf, dict)]
    if not isinstance(dataflow_path, dict):
        return []
    flows: list[dict[str, Any]] = []
    primary = _path_to_codeflow(dataflow_path)
    if primary is not None:
        flows.append(primary)
    for alt in dataflow_path.get("alternative_paths") or []:
        if isinstance(alt, dict):
            cf = _path_to_codeflow(alt)
            if cf is not None:
                flows.append(cf)
    return flows


def findings_to_sarif(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Convert normalized finding dicts back to a valid SARIF 2.1.0 structure.

    Groups findings by tool name and produces one run per tool.
    The output preserves normalizer patches (rebased URIs, inferred CWEs,
    synthesized snippets) so downstream consumers that re-parse from disk
    see the same data the in-memory pipeline does.
    """
    runs_by_tool: dict[str, list] = {}
    rules_by_tool: dict[str, dict[str, dict]] = {}

    for f in findings:
        tool = f.get("tool") or "external"
        runs_by_tool.setdefault(tool, [])
        rules_by_tool.setdefault(tool, {})

        rule_id = f.get("rule_id") or "unknown"

        region: dict[str, Any] = {}
        if f.get("startLine"):
            region["startLine"] = f["startLine"]
        if f.get("endLine"):
            region["endLine"] = f["endLine"]
        if f.get("snippet"):
            region["snippet"] = {"text": f["snippet"]}

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": f.get("level") or "warning",
            "message": {"text": f.get("message") or ""},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("file") or ""},
                    "region": region,
                }
            }],
        }

        if f.get("has_dataflow") and f.get("dataflow_path"):
            code_flows = _dataflow_to_codeflows(f["dataflow_path"])
            if code_flows:
                result["codeFlows"] = code_flows

        # Same guard as enriched_writer._build_result: a legacy
        # finding whose finding_id is the bare rule_id (the pre-fix
        # collided form) must not be stamped out as a tool
        # fingerprint — every same-rule finding would share a
        # matchBasedId/v1 on re-parse.
        fid = f.get("finding_id")
        if fid and fid != rule_id:
            result["fingerprints"] = {"matchBasedId/v1": fid}

        runs_by_tool[tool].append(result)

        if rule_id not in rules_by_tool[tool]:
            rule_entry: dict[str, Any] = {"id": rule_id}
            cwe = f.get("cwe_id")
            if cwe:
                rule_entry["properties"] = {"cwe": [cwe]}
            rules_by_tool[tool][rule_id] = rule_entry

    sarif: dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [],
    }
    for tool_name, results in runs_by_tool.items():
        sarif["runs"].append({
            "tool": {
                "driver": {
                    "name": tool_name,
                    "rules": list(rules_by_tool[tool_name].values()),
                }
            },
            "results": results,
        })

    return sarif


def import_provenance_block(
    result: ImportResult,
    sarif_files: list[str],
    tools: list[str],
    source_type: str = "directory",
    archive_sha256: str | None = None,
) -> dict[str, Any]:
    """Build the provenance block for the run manifest."""
    s = result.stats
    block: dict[str, Any] = {
        "sarif_files": sarif_files,
        "tools": tools,
        "total_imported": s.total_imported,
        "synthesized_fields": {
            "cwe_inferred": s.cwe_inferred,
            "snippet_synthesized": s.snippet_synthesized,
            "uri_rebased": s.uri_rebased,
            "findings_skipped": s.findings_skipped,
            "uri_unresolved": s.uri_unresolved,
        },
        "source": source_type,
    }
    if archive_sha256:
        block["archive_sha256"] = archive_sha256
    return block
