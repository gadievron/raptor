"""Normalize externally-produced SARIF findings for the RAPTOR pipeline.

Imported SARIF may be missing fields that RAPTOR's own scanners always
populate (snippet, CWE, well-resolved file paths).  This module
synthesizes what it can from the source tree and warns about the rest,
producing findings in the same internal dict shape that
:func:`core.sarif.parser.parse_sarif_findings` returns.
"""

import os
import re
import stat as _stat_mod
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from core.logging import get_logger
from core.sarif import emit
from core.sarif.parser import _coerce_line
from core.security.log_sanitisation import escape_nonprintable

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


#: See the rejection comment in _resolve_uri.
_MAX_URI_COMPONENTS = 256

#: Aggregate budget for FAILED full depth-loop scans per import. The
#: per-URI component cap bounds one resolution at sub-second cost, but
#: the document cap admits ~147k cap-sized findings, so per-URI
#: soundness still summed to hours across the import loop — the
#: aggregate axis of the same wedge. Legitimate imports do not carry
#: thousands of unmappable URIs (a real path mismatch resolves via the
#: strip-depth cache after the first success), so after this many
#: full scans that found nothing, unknown URIs stop paying for the
#: depth loop and resolve only through the cheap cached-depth path.
#: Trade-off, both directions: too low turns a genuinely mixed-root
#: import into silent unresolved skips after few failures; too high
#: re-opens the hours-scale aggregate wedge (64 × ~60 ms cap-sized
#: scans ≈ 4 s worst case).
_MAX_FAILED_URI_SCANS = 64

#: Negative-memo ceiling: entries are attacker-chosen URI strings, so
#: the memo itself must not become the memory wedge (~147k cap-sized
#: URIs ≈ 100 MB). Past the cap, repeats of NEW failed URIs fall back
#: to the scan budget above.
_MAX_FAILED_URI_MEMO = 4096

#: Positive-memo ceiling — same attacker-chosen-string reasoning as
#: the negative memo (values are bounded resolved paths, keys are the
#: URIs). Past the cap, repeats of NEW successful URIs re-resolve via
#: the depth cache / basename index (cheap paths).
_MAX_RESOLVED_URI_MEMO = 4096

#: Aggregate wall budget for FULL depth-loop scans per import —
#: successes included. The failed-scan count budget above cannot see
#: a wedge built from RESOLVING URIs: alternating deep URIs whose
#: strip depths differ (~253 junk components ending in a real in-repo
#: filename) each succeed, so nothing was memoised or charged and the
#: quadratic loop ran per finding (~66 ms × 147k admitted findings ≈
#: hours). Once spent, unknown URIs resolve only through the cached
#: depths and the O(1) basename index. Trade-off, both directions:
#: too low degrades genuinely many-rooted imports to basename-only
#: resolution (ambiguous basenames then skip, loudly); too high
#: re-opens the hours-scale wedge (20 s ≈ 300 cap-sized scans —
#: two orders of magnitude above the handful of distinct scanner
#: roots real imports carry).
_MAX_FULL_SCAN_SECONDS = 20.0


#: Ceiling on remembered strip depths. The cached-depth loop runs
#: BEFORE every budget gate and pays one ``_is_under_root`` resolve
#: per entry per unresolved URI, so the cache length is a per-URI
#: cost multiplier the DOCUMENT controls: a handful of cheap resolving
#: URIs (each caching one distinct depth) used to grow it to the
#: component cap (256), making every later unmappable URI pay 256
#: unbudgeted resolves — the same hours-scale wedge the scan budgets
#: close, re-opened through the one unbudgeted lane. Capping the
#: cache (LRU eviction, most-recent-first order) makes the lane's
#: worst case a small input-independent constant. Trade-off, both
#: directions: too low thrashes genuinely multi-shape imports (each
#: shape re-pays a budgeted full scan when its depth is evicted —
#: real imports carry a handful of scanner shapes, mixed-root CI
#: aggregates maybe a few more); too high re-opens the seeded wedge
#: (cost scales linearly with the cap). 8 covers every observed
#: legitimate shape count with headroom.
_MAX_DEPTH_CACHE = 8


def _remember_depth(depth_cache: list, depth: int) -> None:
    """Record a successful strip depth, most-recent-first, capped at
    ``_MAX_DEPTH_CACHE`` entries (LRU eviction — see the constant's
    trade-off note). A single-slot cache thrashed when two scanner
    shapes alternated, re-paying the full scan per finding; an
    unbounded cache let the document itself inflate the per-URI cost
    of the pre-budget cached-depth loop."""
    if depth in depth_cache:
        depth_cache.remove(depth)
    depth_cache.insert(0, depth)
    while None in depth_cache:
        depth_cache.remove(None)
    del depth_cache[_MAX_DEPTH_CACHE:]


def _resolve_uri(
    uri: str,
    source_root: Path,
    file_index: dict[str, list[Path]],
    depth_cache: list[int | None],
    *,
    failed_memo: set[str] | None = None,
    scan_budget: list[int] | None = None,
    resolved_memo: dict[str, str] | None = None,
    scan_clock: list[float] | None = None,
) -> str | None:
    """Resolve a SARIF URI to a relative path under *source_root*.

    Tries progressively shorter prefixes until a match is found.
    Caches successful strip-depths (``depth_cache``, most-recent-first,
    capped at ``_MAX_DEPTH_CACHE``) so subsequent findings from the
    same scanner shape(s) resolve in O(1) — a single-slot cache
    thrashed on two alternating shapes and re-paid the quadratic scan
    per finding; an uncapped cache let the document seed one entry per
    depth and multiply every unresolved URI's pre-budget cost by 256.

    Rejects any resolved path that escapes *source_root* (traversal
    defence for untrusted SARIF).

    Per-import state, all optional:

    - ``failed_memo`` short-circuits URIs that already failed — the
      depth loop memoised only SUCCESSFUL strip depths, so 147k
      findings carrying the SAME unresolvable URI each re-paid the
      full quadratic scan.
    - ``scan_budget`` (mutable cell) bounds the number of FAILED full
      scans (see ``_MAX_FAILED_URI_SCANS``).
    - ``resolved_memo`` short-circuits repeat SUCCESSFUL URIs.
    - ``scan_clock`` (mutable cell, accumulated seconds) bounds the
      aggregate wall time of full scans, successes included (see
      ``_MAX_FULL_SCAN_SECONDS``) — resolving-URI wedges never touch
      the failure budget.

    Once either budget is spent, unknown URIs resolve only through
    the cached-depth fast path and the O(1) basename index — the
    basename match is NOT part of the quadratic wedge and is never
    budgeted (skipping it dropped every legitimate finding whose
    unmappable siblings arrived first).

    Returns a POSIX-style relative path string, or None.
    """
    if resolved_memo is not None and uri in resolved_memo:
        return resolved_memo[uri]
    if failed_memo is not None and uri in failed_memo:
        return None

    def _fail() -> None:
        if (failed_memo is not None
                and len(failed_memo) < _MAX_FAILED_URI_MEMO):
            failed_memo.add(uri)
        return None

    def _ok(resolved: str) -> str:
        if (resolved_memo is not None
                and len(resolved_memo) < _MAX_RESOLVED_URI_MEMO):
            resolved_memo[uri] = resolved
        return resolved

    clean = unquote(_strip_file_scheme(uri))
    if clean.startswith("/"):
        clean = clean.lstrip("/")

    parts = Path(clean).parts
    if not parts:
        return _fail()
    # Component cap before the depth loop: each iteration resolves a
    # path of O(N) components, so an N-component URI costs O(N²) —
    # measured 62s at 8000 components (~16 KB of SARIF text), and the
    # 100 MiB document cap admits URIs thousands of times larger. No
    # legitimate source tree approaches this depth; a hostile imported
    # SARIF must not wedge /agentic --sarif for hours. Trade-off, both
    # directions: too low rejects deep-but-real vendored trees (Linux
    # peaks around depth ~20); too high re-opens the quadratic wedge.
    # 256 sits an order of magnitude above real trees while bounding
    # the loop at sub-second cost.
    if len(parts) > _MAX_URI_COMPONENTS:
        logger.debug(
            "URI rejected: %d path components exceeds the %d cap",
            len(parts), _MAX_URI_COMPONENTS,
        )
        return _fail()

    for i, cached_depth in enumerate(depth_cache):
        if cached_depth is None or cached_depth >= len(parts):
            continue
        candidate = str(Path(*parts[cached_depth:]))
        if _is_under_root(source_root, candidate):
            if i != 0:
                # Most-recent-first so alternating shapes stay O(1).
                depth_cache.insert(0, depth_cache.pop(i))
            return _ok(candidate)

    scans_allowed = not (
        (scan_budget is not None and scan_budget[0] <= 0)
        or (scan_clock is not None
            and scan_clock[0] >= _MAX_FULL_SCAN_SECONDS)
    )
    if scans_allowed:
        scan_start = time.monotonic()
        try:
            for depth in range(len(parts)):
                candidate = str(Path(*parts[depth:]))
                if _is_under_root(source_root, candidate):
                    _remember_depth(depth_cache, depth)
                    return _ok(candidate)
        finally:
            if scan_clock is not None:
                before = scan_clock[0]
                scan_clock[0] += time.monotonic() - scan_start
                if (before < _MAX_FULL_SCAN_SECONDS
                        <= scan_clock[0]):
                    logger.warning(
                        "SARIF import: full URI scans exceeded the "
                        "%.0f s aggregate wall budget — further "
                        "unknown URIs resolve only via cached depths "
                        "and unique basenames (hostile or deeply "
                        "prefixed SARIF)",
                        _MAX_FULL_SCAN_SECONDS,
                    )

    # Basename index: O(1), NOT part of the quadratic wedge — always
    # consulted, budgets or not (budget exhaustion used to skip it and
    # dropped every legitimate finding whose unmappable siblings came
    # first in the document).
    basename = parts[-1]
    matches = file_index.get(basename, [])
    if len(matches) == 1:
        resolved = str(matches[0])
        if _is_under_root(source_root, resolved):
            logger.debug(
                "URI %s: basename-only match → %s",
                escape_nonprintable(uri), resolved,
            )
            return _ok(resolved)

    if scans_allowed and scan_budget is not None:
        scan_budget[0] -= 1
        if scan_budget[0] == 0:
            logger.warning(
                "SARIF import: %d full URI scans found nothing — "
                "further unknown URIs skip full-scan resolution "
                "(hostile or wrong-root SARIF; resolved shapes keep "
                "the cached-depth fast path, unique basenames keep "
                "the index match)",
                _MAX_FAILED_URI_SCANS,
            )
    return _fail()


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
    # Gated read on the OPEN fd: the file lives in the UNTRUSTED
    # scanned tree and the (also untrusted) SARIF picks which path is
    # read, so both the size gate and the file-type gate must hold on
    # the fd actually read — a stat-by-name gate misses a FIFO
    # planted in the tree (stats 0 bytes, then blocks the import
    # stage forever at the open) and a swap-after-stat grow.
    full = source_root / rel_path
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        fd = os.open(str(full), flags)
    except OSError:
        return ""
    try:
        st = os.fstat(fd)
        if not _stat_mod.S_ISREG(st.st_mode):
            # rel_path is a filename from the UNTRUSTED scanned tree
            # (archives/git admit control bytes in names) and these
            # WARNINGs reach the operator terminal raw through the
            # console handler — escape at creation, like the module's
            # ImportWarning messages and parser.py's out-of-root twin.
            logger.warning(
                "SARIF import: skipping snippet synthesis for "
                "non-regular file: %s",
                escape_nonprintable(rel_path),
            )
            return ""
        if st.st_size > _SNIPPET_SOURCE_MAX_BYTES:
            logger.warning(
                "SARIF import: skipping snippet synthesis for oversized "
                "file (>%d MiB): %s",
                _SNIPPET_SOURCE_MAX_BYTES // (1024 * 1024),
                escape_nonprintable(rel_path),
            )
            return ""
        with os.fdopen(fd, "rb") as fh:
            fd = -1  # fdopen owns it now
            raw = fh.read(_SNIPPET_SOURCE_MAX_BYTES + 1)
        if len(raw) > _SNIPPET_SOURCE_MAX_BYTES:
            return ""  # grew past the cap during the read
        lines = raw.decode("utf-8", errors="replace").splitlines()
        s = max(0, start_line - 1)
        e = min(len(lines), (end_line or start_line) + _SNIPPET_CONTEXT_LINES)
        return "\n".join(lines[s:e])
    except OSError:
        return ""
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


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
    failed_memo: set[str] = set()
    scan_budget: list[int] = [_MAX_FAILED_URI_SCANS]
    resolved_memo: dict[str, str] = {}
    scan_clock: list[float] = [0.0]

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
                f"(rule_id={escape_nonprintable(str(finding.get('rule_id')))})",
            ))
            result.stats.findings_skipped += 1
            continue
        finding["startLine"] = start_line

        # --- URI rebasing ---
        resolved = _resolve_uri(
            uri, source_root, file_index, depth_cache,
            failed_memo=failed_memo, scan_budget=scan_budget,
            resolved_memo=resolved_memo, scan_clock=scan_clock,
        )
        if resolved is None:
            result.warnings.append(ImportWarning(
                idx, "file",
                # Imported SARIF is untrusted; the message is printed
                # to the operator terminal by the /agentic import
                # summary, so hostile URI bytes are escaped at
                # creation (sibling parser.py escapes the identical
                # warning).
                f"Skipped: cannot map URI to source: "
                f"{escape_nonprintable(uri)}",
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
            # Belt for records built before message-side escaping.
            examples = "; ".join(
                escape_nonprintable(w.message.split(": ", 1)[-1])
                for w in unmapped[:3]
            )
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

        result: dict[str, Any] = emit.result(
            rule_id,
            f.get("message") or "",
            [emit.location(f.get("file") or "", region)],
            level=f.get("level") or "warning",
        )

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

    return emit.document(
        [
            emit.run(
                tool_name, list(rules_by_tool[tool_name].values()), results,
            )
            for tool_name, results in runs_by_tool.items()
        ],
        schema_uri=emit.SCHEMA_URI_SCHEMASTORE,
        version_first=True,
    )


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
