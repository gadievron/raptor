"""Caller-contract call-site digest for the review context.

Targets the caller-proof false-positive family: teardown / NULL-contract
hypotheses ("double free if called twice", "NULL deref if a caller
passes NULL") formed against a function reviewed in isolation, where
every actual call site upholds the assumed precondition.  The review
context's caller section shows only the first call line per caller with
one line of context — no guard windows, no post-call reuse, no
all-sites coverage — so the reviewer cannot weigh the hypothesis
against how the function is actually used.

This module builds a mechanical digest of ALL in-repo call sites for
contract-risk functions (teardown-named helpers and pointer-parameter
deallocation wrappers): per-site excerpts covering the guard window
above each call and the reuse window after it, plus an enumeration
honesty header derived from what actually executed — the method the
enumeration used (call graph vs bounded tree scan), whether the scan
hit its file cap, how many unresolved callers the graph reported, and
how many test-file sites were set aside.

Epistemics: "all N current callers uphold the precondition" is a
statement about the current tree, not the function — the contract stays
violated-in-waiting.  The digest therefore feeds the review prompt as
context the model weighs (report the concern at low confidence as an
API-robustness note when every enumerated site is clean); it never
stamps ``evidence_tool``, never promotes, and never refutes.  Static
enumeration misses indirect calls (function pointers, macros), and the
rendered digest says so.  No LLM calls.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: Render at most this many call sites in full.
MAX_SITES_RENDERED = 20
#: Above this many sites the digest declines to enumerate (ubiquitous
#: APIs like logging helpers: per-site evidence is noise at that scale
#: and the prompt cost is unbounded).
DECLINE_OVER_SITES = 25
#: Excerpt window around each call site.
_BEFORE_LINES = 6
_AFTER_LINES = 4
#: Per-line render cap — call-site lines come from the scanned repo.
_MAX_LINE_CHARS = 200
#: Brace-matching bound for inferring a definition's closing line.
_MAX_DEF_SCAN_LINES = 2000

# Teardown-shaped names: the stem vocabulary the ptr-lifecycle channel
# already uses for release events, plus init-inverse stems.
_TEARDOWN_NAME_RE = re.compile(
    r"(?:^|_)(?:free|destroy|release|put|teardown|cleanup|clear|"
    r"close|stop|fini|deinit|uninit)(?:_|$)",
    re.IGNORECASE,
)

# A deallocation-looking call.  The argument-binding check below keeps
# this from firing on every function that frees a local on an error
# path: only frees of a *parameter* (or a field of one) mark the
# function as a teardown wrapper.
_DEALLOC_NAME = r"(?:\w*free\w*|\w+_(?:destroy|release|put|teardown))"


def _param_names(metadata: dict[str, Any]) -> list[str]:
    """Parameter names from checklist metadata (dicts or pairs)."""
    names: list[str] = []
    for p in metadata.get("parameters", []) or []:
        name = ""
        if isinstance(p, dict):
            name = str(p.get("name", ""))
        elif isinstance(p, (list, tuple)) and p:
            name = str(p[0] or "")
        if name and re.fullmatch(r"[A-Za-z_]\w*", name):
            names.append(name)
    return names


def is_contract_risk_function(
    function_name: str,
    metadata: dict[str, Any],
    source: str,
) -> bool:
    """Should this function get a caller-contract digest?

    True for teardown-named functions and for functions that pass one
    of their own parameters (or a field of one) to a
    deallocation-looking call — the wrapper shape behind
    "double free if called twice" / "NULL deref if caller passes NULL"
    hypotheses.  Deliberately narrow: the digest costs prompt tokens
    on every triggered review.
    """
    if _TEARDOWN_NAME_RE.search(function_name or ""):
        return True
    if not source:
        return False
    params = _param_names(metadata)
    if not params:
        return False
    param_alt = "|".join(re.escape(p) for p in params)
    dealloc_on_param = re.compile(
        rf"\b{_DEALLOC_NAME}\s*\(\s*&?\s*(?:{param_alt})\b",
        re.IGNORECASE,
    )
    return bool(dealloc_on_param.search(source))


def _is_test_file(rel_path: str) -> bool:
    """The same conventional test-file predicate the inventory
    call-graph path applies (``callers_of(exclude_test_files=True)``)
    — reused so the tree-scan fallback and the graph path exclude the
    same files instead of rendering a test-only caller as ordinary
    evidence.  False (keep the site) when the predicate is
    unavailable, matching a graph path that could not exclude either.
    """
    try:
        from core.analysis.reachability import _is_test_file as pred

        return pred(rel_path)
    except Exception:
        return False


def _enumeration_uncertainty(
    inventory: dict[str, Any] | None,
    file_path: str,
    function_name: str,
) -> int | None:
    """Callers the graph could not resolve definitively, or None when
    the call graph cannot answer at all."""
    if not inventory:
        return None
    try:
        from core.analysis.reachability import InternalFunction, callers_of

        result = callers_of(
            inventory,
            InternalFunction(file_path=file_path, name=function_name, line=0),
            exclude_test_files=True,
        )
        return (
            len(result.uncertain)
            + len(result.method_match_overinclusive)
        )
    except Exception:
        logger.debug(
            "caller_contract: callers_of failed for %s:%s",
            file_path, function_name, exc_info=True,
        )
        return None


def _infer_def_end(
    target_path: Path,
    rel_file: str,
    line_start: int,
) -> int:
    """Closing-brace line of the definition starting at ``line_start``,
    or ``line_start`` when it cannot be determined.

    C-family brace matching without string/comment parsing — good
    enough to keep a self-recursive call inside the body from counting
    as a call site when the caller did not supply ``line_end``; the
    fallback (span collapses to the signature line) only ever
    under-excludes, never hides a real external caller.
    """
    try:
        resolved = (target_path / rel_file).resolve()
        if not resolved.is_relative_to(target_path.resolve()):
            return line_start
        lines = resolved.read_text(errors="replace").splitlines()
    except OSError:
        return line_start
    depth = 0
    opened = False
    end = min(len(lines), line_start - 1 + _MAX_DEF_SCAN_LINES)
    for i in range(max(0, line_start - 1), end):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                opened = True
            elif ch == "}":
                depth -= 1
                if opened and depth <= 0:
                    return i + 1
    return line_start


def _site_excerpt(
    target_path: Path,
    rel_file: str,
    line: int,
    file_cache: dict[str, list[str] | None],
) -> str:
    """Numbered excerpt around one call site (guard window above,
    reuse window below)."""
    if rel_file not in file_cache:
        try:
            resolved = (target_path / rel_file).resolve()
            if not resolved.is_relative_to(target_path.resolve()):
                file_cache[rel_file] = None
            else:
                file_cache[rel_file] = resolved.read_text(
                    errors="replace",
                ).splitlines()
        except OSError:
            file_cache[rel_file] = None
    lines = file_cache[rel_file]
    if not lines or line < 1 or line > len(lines):
        return ""
    start = max(0, line - 1 - _BEFORE_LINES)
    end = min(len(lines), line + _AFTER_LINES)
    return "\n".join(
        f"{i + 1:5d}{'>' if i + 1 == line else ' '} "
        f"{lines[i][:_MAX_LINE_CHARS]}"
        for i in range(start, end)
    )


def build_caller_contract_digest(
    target_path: Path,
    file_path: str,
    function_name: str,
    *,
    line_start: int = 0,
    line_end: int | None = None,
    inventory: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """All-in-repo-call-sites digest for one function, or None when
    nothing useful can be said (enumeration failed outright).

    Returns a dict:
        function, file: identity
        total_sites: int (all discovered, before any cap)
        sites: [{file, caller, line, excerpt}] (capped)
        declined: bool — too many sites to enumerate usefully
        enumeration: "call-graph" | "tree-scan" — the path that
            actually produced the sites (a present-but-unresolving
            inventory reports "tree-scan")
        scan_capped: bool — the bounded tree scan hit its file cap
        scanned_files: int — files the tree scan covered (0 for the
            call-graph path)
        uncertain_callers: int | None — graph edges it could not
            resolve definitively (None = the graph did not drive
            this enumeration)
        test_sites_excluded: int — test-file call sites set aside,
            mirroring the graph path's test exclusion
    """
    try:
        from .api_boundary import enumerate_call_sites_with_report

        def_end = line_end
        if line_start and not def_end:
            def_end = _infer_def_end(
                Path(target_path), file_path, line_start,
            )
        def_span = (line_start, def_end or line_start) if line_start else None
        sites, report = enumerate_call_sites_with_report(
            Path(target_path),
            function_name,
            def_file=file_path,
            def_span=def_span,
            inventory=inventory,
        )
    except Exception:
        logger.debug(
            "caller_contract: enumeration failed for %s:%s",
            file_path, function_name, exc_info=True,
        )
        return None

    kept = [s for s in sites if not _is_test_file(s.get("file", ""))]
    test_excluded = len(sites) - len(kept)
    method = report.get("method", "tree-scan")
    uncertain = (
        _enumeration_uncertainty(inventory, file_path, function_name)
        if method == "call-graph" else None
    )
    digest: dict[str, Any] = {
        "function": function_name,
        "file": file_path,
        "total_sites": len(kept),
        "sites": [],
        "declined": False,
        "enumeration": method,
        "scan_capped": bool(report.get("scan_capped")),
        "scanned_files": int(report.get("scanned_files", 0)),
        "uncertain_callers": uncertain,
        "test_sites_excluded": test_excluded,
    }
    if len(kept) > DECLINE_OVER_SITES:
        digest["declined"] = True
        return digest

    file_cache: dict[str, list[str] | None] = {}
    tp = Path(target_path)
    for site in kept[:MAX_SITES_RENDERED]:
        excerpt = _site_excerpt(
            tp, site.get("file", ""), int(site.get("line", 0)), file_cache,
        )
        digest["sites"].append({
            "file": site.get("file", ""),
            "caller": site.get("caller", ""),
            "line": site.get("line", 0),
            "excerpt": excerpt,
        })
    return digest
