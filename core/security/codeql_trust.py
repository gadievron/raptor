"""
core/security/codeql_trust.py

Trust check for target-repo CodeQL pack files.

Called before invoking ``codeql database create`` against an untrusted
repo. Returns True if the caller should refuse to dispatch.

**Distinct from cc_trust.** Claude Code config files
(``.claude/settings.json``, ``.mcp.json``) go through ``cc_trust``;
CodeQL pack files are loaded by the ``codeql`` binary itself during
``codeql database create``, bypassing the CC trust path entirely.
This module is the parallel check for the codeql side.

Files inspected:
    codeql-pack.yml         (recursive walk, capped)
    qlpack.yml              (recursive walk, capped)
    .github/codeql/codeql-config.yml

Blocking fields in ``codeql-pack.yml`` / ``qlpack.yml``:
    extractor:                     ANY value (codeql may exec this)
    dependencies.<name>            non-canonical (not ``codeql/...``)
    buildCommand                   subprocess invocation
    setup / preCompileScript /
    postCompileScript              subprocess invocation
    structural: symlink, oversized, malformed → block

Blocking fields in ``codeql-config.yml``:
    packs.<lang>[]                 non-canonical pack reference
    queries[].uses                 external repo / URL reference
    manualBuildSteps / setup       subprocess invocation
    structural: symlink, oversized, malformed → block

Trust override: same module-flag pattern as cc_trust. ``--trust-repo``
sets it once at entry-point argparse time; this module reads it via
``check_repo_codeql_trust(trust_override=None)``. Deliberately NOT
driven by an env var (target repos can inject env via the build
system; trust must come from explicit operator intent).
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover — yaml is a hard dep elsewhere
    yaml = None


# ---------------------------------------------------------------------------
# Process-wide trust override
# ---------------------------------------------------------------------------

_trust_override_set = False


def set_trust_override(val: bool) -> None:
    """Set process-wide trust override. Call once from each entry point
    that parses ``--trust-repo``. Idempotent."""
    global _trust_override_set
    _trust_override_set = bool(val)


# ---------------------------------------------------------------------------
# Finding / FileScan dataclasses (parallel to cc_trust)
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """One labelled row in the per-file findings table."""
    label: str
    value: str
    blocking: bool


@dataclass
class FileScan:
    """Findings for one inspected file."""
    path: Path
    findings: List[Finding] = field(default_factory=list)

    def has_blocking(self) -> bool:
        return any(f.blocking for f in self.findings)


# ---------------------------------------------------------------------------
# Constants + helpers
# ---------------------------------------------------------------------------

# packages/codeql/.. — three levels up from this file.
_RAPTOR_DIR = Path(__file__).resolve().parents[2]

# 1 MiB cap on pack files. Real codeql-pack.yml files are <10 KiB; the
# cap exists to bound the YAML parser's memory exposure.
_MAX_CONFIG_BYTES = 1_048_576

# Bound the recursive walk on pathological repos (vendored monorepos
# with thousands of nested pack files). 200 hits + early break is
# enough to catch any realistic pack layout while keeping the walk
# bounded.
_MAX_PACK_FILES = 200

# U+2028/U+2029 line-separators slip past Cc/Cf categories but
# render as newlines in terminals — strip them so output can't be
# split by an attacker-supplied label.
_EXTRA_STRIP = frozenset({" ", " "})

# CodeQL's canonical (Microsoft-authored) pack namespace. Anything
# outside this namespace is third-party and may carry custom
# extractors / queries.
_CANONICAL_PACK_PREFIX = "codeql/"


def _safe(s: str) -> str:
    """Strip Unicode control/format chars and line/paragraph separators.
    Same defence as cc_trust._safe — see that docstring for the threat
    model (ANSI escapes, Trojan Source bidi, zero-width chars)."""
    return "".join(
        c if c == "\t" or (
            c not in _EXTRA_STRIP
            and unicodedata.category(c) not in ("Cc", "Cf")
        ) else "?"
        for c in s
    )


def _truncate(s: str, limit: int = 80) -> str:
    safe = _safe(s)
    return safe[:limit] + "..." if len(safe) > limit else safe


def _path_present(p: Path) -> bool:
    try:
        return p.is_symlink() or p.exists()
    except OSError:
        return False


def _read_capped(path: Path) -> Optional[bytes]:
    """Read up to ``_MAX_CONFIG_BYTES`` bytes. Returns None on
    oversized, non-regular, or unreadable."""
    try:
        if not path.is_file():
            return None
        size = path.stat().st_size
        if size > _MAX_CONFIG_BYTES:
            return None
        with open(path, "rb") as f:
            return f.read(_MAX_CONFIG_BYTES + 1)
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Per-file scanners
# ---------------------------------------------------------------------------


def _scan_pack_file(path: Path) -> FileScan:
    """Scan a ``codeql-pack.yml`` or ``qlpack.yml``."""
    fs = FileScan(path=path)
    raw = _read_capped(path)
    if raw is None:
        fs.findings.append(
            Finding("oversized/unreadable", _truncate(str(path), 120), True)
        )
        return fs
    if yaml is None:                                    # pragma: no cover
        fs.findings.append(
            Finding("yaml unavailable", "cannot inspect", True)
        )
        return fs
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        fs.findings.append(
            Finding("malformed YAML", _truncate(str(e), 120), True)
        )
        return fs
    if not isinstance(doc, dict):
        fs.findings.append(
            Finding("non-dict YAML", _truncate(str(type(doc).__name__), 60), True)
        )
        return fs

    # extractor: ANY value flags for review — codeql may exec this
    # binary/script during DB build. The path is relative to the pack;
    # an attacker-supplied repo could point it anywhere inside the
    # source root.
    if doc.get("extractor"):
        fs.findings.append(
            Finding("extractor", _truncate(str(doc["extractor"]), 120), True)
        )

    # dependencies: only the canonical ``codeql/`` namespace is allowed
    # without manual review. Third-party packs may bring their own
    # extractors / queries.
    #
    # Codeql's schema names a dict[name->version] but YAML is permissive
    # and we've seen real packs in the wild use a flat list form
    # (``dependencies: ['name@version', ...]``). Handle both — if the
    # ``dependencies`` key is present at all and isn't an empty value,
    # walk every entry. An attacker who can write the pack chooses the
    # form, so we have to inspect both.
    deps = doc.get("dependencies")
    if isinstance(deps, dict):
        dep_specs = [(str(n), str(v)) for n, v in deps.items()]
    elif isinstance(deps, list):
        dep_specs = [(str(item), "") for item in deps]
    else:
        dep_specs = []
    for n, v in dep_specs:
        if not n.startswith(_CANONICAL_PACK_PREFIX):
            label = f"{n}: {v}" if v else n
            fs.findings.append(
                Finding("non-canonical dep", _truncate(label, 120), True)
            )

    # defaultSuiteFile: relative path to a query suite that codeql will
    # compile + run by default. An attacker-controlled suite can pull
    # in arbitrary queries (which then compile arbitrary QL — extension
    # functions, file I/O via standard library, etc.). Path traversal
    # via ``../`` could also reference suites outside the pack.
    suite = doc.get("defaultSuiteFile")
    if suite:
        s = str(suite)
        if ".." in s or s.startswith("/"):
            fs.findings.append(
                Finding("defaultSuiteFile (escapes pack)",
                        _truncate(s, 120), True)
            )

    # buildCommand / setup hooks — pack-level subprocess invocation.
    # These keys aren't part of the formal codeql-pack schema today,
    # but conservative blocking guards against future schema growth
    # AND against custom/forked codeql distributions.
    for key in ("buildCommand", "setup",
                "preCompileScript", "postCompileScript"):
        if doc.get(key):
            fs.findings.append(
                Finding(key, _truncate(str(doc[key]), 120), True)
            )

    return fs


def _scan_codeql_config(path: Path) -> FileScan:
    """Scan a ``.github/codeql/codeql-config.yml``."""
    fs = FileScan(path=path)
    raw = _read_capped(path)
    if raw is None:
        fs.findings.append(
            Finding("oversized/unreadable", _truncate(str(path), 120), True)
        )
        return fs
    if yaml is None:                                    # pragma: no cover
        fs.findings.append(
            Finding("yaml unavailable", "cannot inspect", True)
        )
        return fs
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        fs.findings.append(
            Finding("malformed YAML", _truncate(str(e), 120), True)
        )
        return fs
    if not isinstance(doc, dict):
        fs.findings.append(
            Finding("non-dict YAML", _truncate(str(type(doc).__name__), 60), True)
        )
        return fs

    # packs: dict-by-language OR flat list of pack-spec strings.
    # Canonical = ``codeql/<name>``; anything else is third-party.
    packs = doc.get("packs")
    if packs:
        flat: List[str] = []
        if isinstance(packs, dict):
            for refs in packs.values():
                if isinstance(refs, list):
                    flat.extend(str(r) for r in refs if isinstance(r, str))
        elif isinstance(packs, list):
            flat = [str(r) for r in packs if isinstance(r, str)]
        for ref in flat:
            if not ref.startswith(_CANONICAL_PACK_PREFIX):
                fs.findings.append(
                    Finding("non-canonical pack", _truncate(ref, 120), True)
                )

    # queries: list of {uses: ...} OR string entries. External repo
    # references (``owner/repo`` or URL) bring in arbitrary queries
    # that can abuse extension functions during analysis.
    queries = doc.get("queries")
    if queries:
        entries = queries if isinstance(queries, list) else [queries]
        for e in entries:
            if isinstance(e, dict):
                uses = str(e.get("uses", ""))
            else:
                uses = str(e)
            # External: any path containing ``/`` that isn't a relative
            # local reference (``./`` or ``../``).
            if "/" in uses and not uses.startswith(("./", "../")):
                fs.findings.append(
                    Finding("external queries", _truncate(uses, 120), True)
                )

    # manualBuildSteps / setup — subprocess invocation directives.
    for key in ("manualBuildSteps", "setup"):
        if doc.get(key):
            fs.findings.append(
                Finding(key, _truncate(str(doc[key]), 120), True)
            )

    # pack-cache: redirects codeql's pack download cache to a custom
    # location. Used legitimately for offline / air-gapped builds, but
    # an attacker-supplied repo could point it at a writable in-repo
    # path pre-stocked with malicious pack content; codeql then
    # "downloads" (i.e. reads) packs from there. Block any value —
    # operator must opt in via --trust-repo if they need it.
    if doc.get("pack-cache"):
        fs.findings.append(
            Finding("pack-cache", _truncate(str(doc["pack-cache"]), 120), True)
        )

    return fs


# ---------------------------------------------------------------------------
# Top-level scan + cache
# ---------------------------------------------------------------------------


@lru_cache(maxsize=64)
def _scan_cached(resolved_path: str) -> Tuple[Tuple[FileScan, ...], bool]:
    """Pure scan: returns (scans, any_blocking). Cached because
    filesystem state for a given resolved path doesn't change within a
    session. Side-effect-free so cache hits don't suppress operator-
    visible warnings (rendered in the caller)."""
    target = Path(resolved_path)
    # Skip RAPTOR's own repo — RAPTOR ships codeql packs under
    # packages/llm_analysis/codeql_packs/ that would always flag
    # if scanned. Operator running RAPTOR against itself is
    # implicitly trusted.
    if target == _RAPTOR_DIR:
        return ((), False)

    # Walk for pack files. Skip dotted dirs (e.g. ``.git``,
    # ``.claude/worktrees``) except ``.github`` which holds
    # codeql-config.yml legitimately.
    pack_files: List[Path] = []
    try:
        for name in ("codeql-pack.yml", "qlpack.yml"):
            for p in target.rglob(name):
                if len(pack_files) >= _MAX_PACK_FILES:
                    break
                rel_parts = p.relative_to(target).parts
                if any(
                    part.startswith(".") and part != ".github"
                    for part in rel_parts[:-1]
                ):
                    continue
                pack_files.append(p)
            if len(pack_files) >= _MAX_PACK_FILES:
                break
    except OSError:
        pass

    config_path = target / ".github" / "codeql" / "codeql-config.yml"
    if _path_present(config_path):
        pack_files.append(config_path)

    if not pack_files:
        return ((), False)

    scans: List[FileScan] = []
    for path in pack_files:
        if path.is_symlink():
            fs = FileScan(path=path)
            try:
                tgt = str(path.readlink())
            except OSError:
                tgt = "<unreadable>"
            fs.findings.append(Finding("symlink", _truncate(tgt, 120), True))
            scans.append(fs)
            continue
        if path.name == "codeql-config.yml":
            scanned = _scan_codeql_config(path)
        else:
            scanned = _scan_pack_file(path)
        if scanned.findings:
            scans.append(scanned)

    any_blocking = any(s.has_blocking() for s in scans)
    return (tuple(scans), any_blocking)


def check_repo_codeql_trust(
    repo_path: str,
    trust_override: Optional[bool] = None,
) -> bool:
    """Check target repo for unsafe CodeQL pack config. Returns True if
    DB creation should be refused.

    ``trust_override``:
        None   → read the module-level flag (set by ``set_trust_override``).
                 Production default.
        True   → force trust (warn but never block). Tests, callers with
                 context the module flag doesn't capture.
        False  → force strict. Tests, hard-enforcement code paths.
    """
    if not repo_path:
        return False
    try:
        resolved = str(Path(repo_path).resolve())
    except (ValueError, OSError):
        return False
    if trust_override is None:
        trust_override = _trust_override_set
    scans, any_blocking = _scan_cached(resolved)
    if scans:
        target = Path(resolved)
        _render_scan_report(target, scans, any_blocking, trust_override)
    return any_blocking and not trust_override


def _render_scan_report(
    target: Path,
    scans: Tuple[FileScan, ...],
    any_blocking: bool,
    trust_override: bool,
) -> None:
    """Pure rendering — separated from ``_scan_cached`` so the cache
    doesn't suppress operator warnings on re-invocation."""
    safe_target = _safe(str(target))
    if any_blocking:
        if trust_override:
            print(f"raptor: {safe_target} has dangerous CodeQL pack config "
                  f"(trust override active):")
        else:
            print(f"raptor: {safe_target} has dangerous CodeQL pack config:")
    else:
        print(f"raptor: {safe_target} has CodeQL pack config:")

    for fs in scans:
        try:
            rel = fs.path.relative_to(target)
        except ValueError:
            rel = fs.path
        print(f"  {_safe(str(rel))}")
        if not fs.findings:
            continue
        label_w = max(len(f.label) for f in fs.findings) + 2
        for f in fs.findings:
            print(f"    {f.label:<{label_w}}{f.value}")


__all__ = [
    "Finding",
    "FileScan",
    "check_repo_codeql_trust",
    "set_trust_override",
]
