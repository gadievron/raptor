"""Findings emission in standard RAPTOR format.

Findings from /audit are emitted in the same JSON format as /scan
and /agentic, so they flow unchanged into /validate.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any, TYPE_CHECKING
from pathlib import Path

from core.json import load_json, save_json

from .tree_class import classify_tree_class

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# findings.json is RAPTOR-written run output — the findings-class
# budget used across the audit/validate bridges.
_MAX_FINDINGS_BYTES = 64 * 1024 * 1024

# Source-fallback read cap for enclosing-function re-derivation —
# target-repo files are untrusted; a planted multi-GB file must not
# balloon the emit path.
_MAX_ATTRIBUTION_SOURCE_BYTES = 16 * 1024 * 1024

# Languages whose named functions never nest inside another function
# body. For these, a checklist item whose span sits STRICTLY inside
# another item's span is an extraction artifact (the regex C extractor
# mints phantom items from multi-line call continuations like
# `strcmp(a, b))) {`), so the OUTER item is the true enclosing
# function. Nesting languages (Python, JS, ...) keep the inner item —
# a named nested def is a real, more specific attribution.
# Membership criterion (both directions): BELONGS — C-family suffixes
# whose standard grammar has no named nested functions; NEVER —
# suffixes of languages with named inner functions/closures that the
# inventory itemises (.py, .js, .ts, .go method literals, .lua).
_NON_NESTING_SUFFIXES = frozenset({
    ".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx",
    ".h++",
})

# Checklist kinds that can be an ENCLOSING-function candidate.
# Missing/empty kind kept for legacy checklists. Other kinds (macro,
# interstitial, declaration, ...) never become the resolved enclosing
# name — but a claim naming one still validates by name (a finding
# recorded against a macro item is a legitimate attribution).
_ATTRIBUTION_KINDS = frozenset({"", "function", "method"})


def _attribution_items(
    checklist: dict[str, Any],
    file_path: str,
) -> list[dict[str, Any]] | None:
    """Normalised function items for *file_path*, or None when the
    file has no checklist entry (no basis to validate against).

    Only the first entry matching *file_path* is consulted (checklist
    paths are unique by construction — the ``find_checklist_item``
    precedent). Legacy checklists keep per-file items under
    ``functions``.
    """
    for file_entry in checklist.get("files", []) or []:
        if not isinstance(file_entry, dict):
            continue
        if file_entry.get("path") != file_path:
            continue
        raw = file_entry.get("items")
        if raw is None:
            raw = file_entry.get("functions") or []
        items: list[dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "")
            if not name:
                continue
            try:
                line_start = int(item.get("line_start") or 0)
                line_end = int(item.get("line_end") or 0)
            except (TypeError, ValueError):
                line_start = line_end = 0
            items.append({
                "name": name,
                "kind": str(item.get("kind") or ""),
                "line_start": line_start,
                "line_end": line_end,
            })
        return items
    return None


def _innermost(items: list[dict[str, Any]]) -> dict[str, Any]:
    """The most specific (latest-starting, then shortest) span."""
    return max(
        items,
        key=lambda it: (it["line_start"], -it["line_end"]),
    )


def _enclosing_from_source(
    target_path: Path,
    file_path: str,
    line: int,
) -> str:
    """Best-effort enclosing-function name read from the source file.

    Delegates to :func:`core.audit._util.find_enclosing_function`,
    whose backwards ``def`` walk only resolves Python-style sources —
    its ``"<module>"`` miss (and any C-family file) maps to ``""``
    here. The open is the contained reader (``open_regular_beneath``):
    *file_path* is finding-derived (ultimately scanned-repo data), so
    escapes, symlinks and FIFO/device plants all refuse to ``None``.
    The read is capped (``_MAX_ATTRIBUTION_SOURCE_BYTES``); a claimed
    line beyond the cap resolves to ``""`` rather than clamping to the
    last pre-cap definition.
    """
    from core.source import open_regular_beneath

    from ._util import find_enclosing_function

    try:
        fh = open_regular_beneath(
            target_path, file_path, "r",
            encoding="utf-8", errors="replace",
        )
        if fh is None:
            return ""
        with fh:
            content = fh.read(_MAX_ATTRIBUTION_SOURCE_BYTES)
    except (OSError, ValueError):
        return ""
    lines = content.split("\n")
    if line > len(lines) and len(content) >= _MAX_ATTRIBUTION_SOURCE_BYTES:
        # The claimed line lies BEYOND the capped read: clamping to the
        # last pre-cap line would stamp a confident wrong name from
        # whatever ``def`` happens to precede the cap. No basis is the
        # honest answer — the caller lands on "unverified".
        return ""
    idx = min(line - 1, len(lines) - 1)
    if idx < 0:
        return ""
    name = find_enclosing_function(lines, idx)
    return name if name and name != "<module>" else ""


def resolve_function_attribution(
    checklist: dict[str, Any] | None,
    file_path: str,
    claimed: str,
    line: int,
    *,
    target_path: Path | None = None,
) -> tuple[str, str]:
    """Validate a finding's claimed function name against the run's
    checklist and return ``(resolved_name, disposition)``.

    An exhaustive audit run of a large C codebase shipped findings
    whose ``function`` was the CALLEE at the finding line (``strcmp``,
    ``strlen``): the regex C extractor had minted phantom checklist
    items from multi-line call continuations, the review loop reviewed
    them under the callee name, and every findings emitter copied that
    name unvalidated. ``(file, function)`` is an identity key in the
    report join, cross-run dedup and project claim matching, so the
    misattribution corrupts joins — not just presentation.

    Dispositions:

    - ``"validated"`` — the claimed name is a checklist item for the
      file and nothing contradicts it; use as-is.
    - ``"corrected"`` — the checklist line ranges (preferred) or the
      source fallback identify a different enclosing function; the
      caller should surface the resolved name and preserve the claim.
    - ``"unverified"`` — the file is itemised but neither the claim
      nor the line resolves; keep the claim, disclose.
    - ``"no_basis"`` — no checklist / no entry for the file; nothing
      to validate against, pass through silently.

    Junk-shaped VALUES never raise (``line`` is nominally an int but
    non-int junk fished out of a finding dict coerces to "no usable
    line"; malformed items are skipped), but wrong-typed CONTAINERS
    (``files``/``items`` of a non-list type) do raise — the
    never-raise guarantee lives at :func:`stamp_function_attribution`,
    which guards this resolver, and all production writers go through
    the stamp. Never signals "drop": the fail-safe direction is keep
    the finding, best-effort attribution.
    """
    claimed = str(claimed or "")
    if not file_path or not isinstance(checklist, dict):
        return claimed, "no_basis"
    items = _attribution_items(checklist, file_path)
    if items is None:
        return claimed, "no_basis"
    try:
        line_n = int(line)
    except (TypeError, ValueError):
        line_n = 0
    containing = [
        it for it in items
        if it["kind"] in _ATTRIBUTION_KINDS
        and 0 < it["line_start"] <= line_n
        and line_n <= it["line_end"]
    ] if line_n > 0 else []

    claimed_hits = [it for it in containing if it["name"] == claimed]
    if claimed_hits:
        # Exact match containing the line: passthrough — UNLESS the
        # claimed item is strictly nested inside another item in a
        # non-nesting language, where the inner item can only be an
        # extraction artifact and the outer one is the true function.
        suffix = Path(file_path).suffix.lower()
        if suffix in _NON_NESTING_SUFFIXES:
            hit = _innermost(claimed_hits)
            outers = [
                it for it in containing
                if it["name"] != claimed
                and it["line_start"] <= hit["line_start"]
                and it["line_end"] >= hit["line_end"]
                and (it["line_start"] < hit["line_start"]
                     or it["line_end"] > hit["line_end"])
            ]
            if outers:
                return _innermost(outers)["name"], "corrected"
        return claimed, "validated"

    if containing:
        # Claim absent (or elsewhere) but the line sits inside known
        # function span(s): re-derive from the inventory — innermost
        # span is the most specific enclosing definition.
        return _innermost(containing)["name"], "corrected"

    if claimed and any(it["name"] == claimed for it in items):
        # Name is a real item for the file; only the line disagrees
        # (drift, or the finding line points at a related site).
        # The name itself validates — never second-guess it here.
        return claimed, "validated"

    if line_n > 0 and target_path is not None:
        name = _enclosing_from_source(target_path, file_path, line_n)
        if name and name != claimed:
            return name, "corrected"
        if name:
            return claimed, "validated"
    return claimed, "unverified"


def stamp_function_attribution(
    finding: dict[str, Any],
    checklist: dict[str, Any] | None,
    *,
    target_path: Path | None = None,
) -> dict[str, Any]:
    """Validate/correct ``finding["function"]`` in place (chokepoint
    for every findings.json writer).

    On correction the original claim is preserved in
    ``claimed_function`` — the journal/coverage layers key on the
    AS-REVIEWED checklist-item name, so readers joining findings back
    to journal rows must prefer ``claimed_function`` when present.
    An unresolvable claim is disclosed via
    ``function_attribution="unverified"``. Never raises, never drops:
    attribution failure must not cost the finding.
    """
    try:
        claimed = str(finding.get("function") or "")
        resolved, disposition = resolve_function_attribution(
            checklist,
            str(finding.get("file") or ""),
            claimed,
            finding.get("line") or 0,
            target_path=target_path,
        )
        if disposition == "corrected" and resolved and resolved != claimed:
            finding["function"] = resolved
            if claimed:
                finding["claimed_function"] = claimed
        elif disposition == "unverified" and claimed:
            finding["function_attribution"] = "unverified"
    except Exception:  # noqa: BLE001 — best-effort stamp, never costs the finding
        logger.debug("function attribution stamp failed", exc_info=True)
    return finding


@contextlib.contextmanager
def _findings_lock(out_dir: Path):
    """Advisory cross-process lock for the findings.json
    read-modify-write.

    Parallel emitters (``raptor-audit record`` sub-agents sharing one
    out_dir) both read N findings and both wrote N+1 — one finding was
    lost and the len-derived ids collided. ``save_json``'s atomic
    rename prevents torn files but not lost updates. Best-effort:
    platforms without ``fcntl`` proceed unlocked (the previous
    behaviour), never fail the emit.

    The ``.lock`` file is deliberately left behind (the
    ``core.project`` locking precedent): unlinking after unlock races
    — a locker that opened the old inode holds a lock nobody else
    sees. The empty leftover is cosmetic.
    """
    lock_path = out_dir / "findings.json.lock"
    fh = None
    try:
        import fcntl
        fh = open(lock_path, "a+")  # noqa: SIM115 — held across yield  # raw-open: run-dir lock file created by this module; append handle
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    except Exception:
        logger.debug("findings lock unavailable", exc_info=True)
        if fh is not None:
            with contextlib.suppress(OSError):
                fh.close()
            fh = None
    try:
        yield
    finally:
        if fh is not None:
            with contextlib.suppress(OSError):
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                fh.close()


def _next_finding_id(existing: list[dict[str, Any]]) -> str:
    """AUDIT-NNN above every existing numeric suffix — ``len()+1``
    collided after any external deletion."""
    top = 0
    for f in existing:
        fid = str(f.get("id", "") or "")
        head, _, tail = fid.rpartition("-")
        if head == "AUDIT" and tail.isdigit():
            top = max(top, int(tail))
    return f"AUDIT-{top + 1:03d}"


def emit_finding(
    *,
    out_dir: Path,
    file_path: str,
    function_name: str,
    line: int,
    title: str,
    description: str,
    cwe: str | None = None,
    severity: str = "medium",
    tool_evidence: list[dict[str, Any]] | None = None,
    hypothesis: str | None = None,
    tree_class: str | None = None,
    target_path: Path | None = None,
) -> dict[str, Any]:
    """Emit a finding and append to findings.json.

    Args:
        out_dir: Run output directory.
        file_path: Relative path to the source file.
        function_name: Name of the function where the finding is.
            Validated against the run's checklist at the row seam
            (:func:`stamp_function_attribution`) — a callee-named or
            otherwise misattributed claim is corrected to the
            enclosing function with the claim preserved in
            ``claimed_function``.
        line: Line number of the vulnerable code.
        title: Short title for the finding.
        description: Detailed description with evidence.
        cwe: CWE identifier (e.g. "CWE-78").
        severity: low/medium/high/critical.
        tool_evidence: List of dicts with tool name, rule, output.
        hypothesis: The hypothesis that was confirmed.
        tree_class: Pre-computed tree class (core.audit.tree_class
            vocabulary) — callers holding prep-time vendored verdicts
            pass a refined value; absent, the path-only classifier
            stamps it. A tag for ordering/weighting, never a filter.
        target_path: Target repo root, enabling the source-based
            enclosing-function fallback when the checklist cannot
            resolve the claim.

    Returns:
        The finding dict.
    """
    try:
        from core.inventory import read_checklist
        checklist: dict[str, Any] | None = read_checklist(out_dir)
    except Exception:  # noqa: BLE001 — attribution is best-effort, never costs the emit
        logger.debug("checklist read for attribution failed", exc_info=True)
        checklist = None
    # One locked read-modify-write: id derivation and the append must
    # see the same snapshot, or two parallel emitters mint the same id
    # and one finding is lost.
    with _findings_lock(out_dir):
        existing = load_findings(out_dir)
        finding = {
            "id": _next_finding_id(existing),
            "file": file_path,
            "function": function_name,
            "line": line,
            "title": title,
            "description": description,
            "severity": severity,
            "origin": "audit",
            "tree_class": tree_class or classify_tree_class(file_path),
        }
        if cwe:
            finding["cwe"] = cwe
            finding["vuln_type"] = cwe
        else:
            finding["vuln_type"] = "novel"

        if tool_evidence:
            finding["tool_evidence"] = tool_evidence
        if hypothesis:
            finding["hypothesis"] = hypothesis

        stamp_function_attribution(
            finding, checklist, target_path=target_path,
        )
        existing.append(finding)
        write_findings(existing, out_dir)
    return finding


def load_findings(out_dir: Path) -> list[dict[str, Any]]:
    """Load findings.json from the output directory.

    Corrupt/oversize content degrades to ``[]`` with a warning;
    an UNREADABLE file (EACCES, EIO) still raises ``OSError`` —
    findings.json is where "no findings" and "could not read the
    findings" must stay distinguishable.
    """
    path = out_dir / "findings.json"
    try:
        data = load_json(path, strict=True, max_bytes=_MAX_FINDINGS_BYTES)
    except ValueError:
        logger.warning("corrupt findings.json at %s", path)
        return []
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        found = data.get("findings", [])
        return found if isinstance(found, list) else []
    # Valid-JSON scalar (int/str/bool): wrong shape degrades to []
    # like corrupt content — the docstring's contract.
    logger.warning("wrong-shaped findings.json at %s", path)
    return []


def write_findings(findings: list[dict[str, Any]], out_dir: Path) -> Path:
    """Write findings.json to the output directory."""
    path = out_dir / "findings.json"
    save_json(path, findings)
    return path
