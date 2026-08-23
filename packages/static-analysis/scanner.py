#!/usr/bin/env python3
"""Automated Code Security Agent (Enhanced)
- Accepts a repo path or Git URL
- Supports --policy-groups (comma-separated list) to select rule categories
- Runs Semgrep across selected local rule directories IN PARALLEL
- Optionally runs CodeQL when --codeql is provided; requires codeql CLI and query packs
- Produces SARIF outputs and optional merged SARIF with deduplication
- Includes progress reporting and comprehensive metrics
- The output of this could be consumed by RAPTOR or other tools for further analysis for finding bugs/security issues
"""
import argparse
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Add parent directory to path for imports
# packages/static-analysis/scanner.py -> repo root
sys.path.insert(0, str(Path(__file__).parents[2]))

from core.json import dumps_display
from core.config import RaptorConfig
from core.git import clone_repository
from core.hash import sha256_bytes, sha256_tree
from core.json import load_json, save_json
from core.logging import get_logger
from core.run.output import unique_run_suffix
from core.run.safe_io import safe_run_mkdir
from core.sandbox import SANDBOX_ENGAGE_EXIT_CODE, SandboxSetupError
from core.sarif.parser import generate_scan_metrics, merge_sarif, validate_sarif
from packages import semgrep as semgrep_pkg

logger = get_logger()

# Byte budgets: semgrep registry pack caches are capped at download
# time (32 MiB socket cap in cache-packs) — 64 MiB leaves headroom;
# per-pack tool JSON / SARIF outputs over a hostile target use the
# SARIF budget class.
_MAX_PACK_CACHE_BYTES = 64 * 1024 * 1024
_MAX_TOOL_JSON_BYTES = 100 * 1024 * 1024


def _sarif_result_uri(result: dict) -> str:
    """Extract the file URI from a SARIF result, or empty string when
    the structure is missing the expected nesting."""
    locs = result.get("locations") or []
    if not locs:
        return ""
    phys = locs[0].get("physicalLocation") or {}
    return (phys.get("artifactLocation") or {}).get("uri") or ""


def filter_sarif_by_exclude_globs(
    sarif: dict, exclude_globs: list[str] | None,
) -> tuple[dict, int]:
    """Return ``(filtered_sarif, dropped_count)`` — a copy of ``sarif``
    with every result whose file URI matches any of ``exclude_globs``
    removed from ``runs[*].results``. Order-preserving. No-op when
    ``exclude_globs`` is None/empty.

    Operator escape hatch for vendored / test / generated paths the
    structural filters can't cover. Applied at the combined-SARIF
    layer in /scan so the downstream metrics + /agentic consumption
    see the filtered set; individual per-tool SARIFs stay unfiltered
    as a forensic record of what each tool actually emitted.

    Results without a usable URI (malformed location block) are kept
    defensively — operator excludes shouldn't accidentally drop
    findings whose metadata is broken.
    """
    if not exclude_globs:
        return sarif, 0
    import copy
    import fnmatch as _fnmatch
    out = copy.deepcopy(sarif)
    dropped = 0
    for run in out.get("runs", []):
        kept: list = []
        for r in run.get("results", []):
            uri = _sarif_result_uri(r)
            if uri and any(_fnmatch.fnmatch(uri, g) for g in exclude_globs):
                dropped += 1
                continue
            kept.append(r)
        run["results"] = kept
    return out, dropped


def _pack_tuple_for_id(pack_id: str) -> tuple[str, str]:
    """Resolve a pack-id-suffix (``"security-audit"``,
    ``"command-injection"``) to the full
    ``(display_name, full_pack_id)`` tuple ``BASELINE_SEMGREP_PACKS``
    uses. The display names aren't a clean derivation from the
    pack-id (``command-injection`` → ``semgrep_injection``,
    ``owasp-top-ten`` → ``semgrep_owasp_top_10`` — both reflect
    historical naming conventions in
    ``RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK``), so consult
    those mappings first; fall back to a synthesised name for
    unknown ids.

    Used by ``_resolve_baseline_packs`` to convert the
    target-type catalog's ``semgrep_packs.default`` (a list of
    pack-id suffixes) to the tuple shape scanner internals expect.
    """
    full_id = f"p/{pack_id}"
    # Baseline packs are listed by full tuple already.
    for name, fid in RaptorConfig.BASELINE_SEMGREP_PACKS:
        if fid == full_id:
            return (name, fid)
    # POLICY_GROUP_TO_SEMGREP_PACK values cover the rest of the
    # canonical (name, pack-id) pairs.
    for name, fid in RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK.values():
        if fid == full_id:
            return (name, fid)
    # Unknown pack-id (catalog author added something we don't
    # have a name convention for) — synthesise a safe name.
    safe = pack_id.replace("-", "_").replace("/", "_")
    return (f"semgrep_{safe}", full_id)


# Registry packs dropped by the reachability probe this run.
# Accumulated across dispatcher calls (parallel/sequential dispatch and
# the expanded-semgrep stage all probe independently) so main() can
# record the full loss in scan_metrics.json.
_dropped_registry_packs: list[str] = []


def _drop_unreachable_registry_packs(
    configs: list[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Drop uncached registry packs when semgrep.dev is unreachable.

    A 3-second TCP probe distinguishes "airgapped" from "slow link".
    Cached packs (resolved to local paths by ``get_semgrep_config``)
    and local rule directories pass through unchanged.

    Dropping is loud: with an unpopulated local registry cache an
    offline run loses EVERY baseline pack, which pre-fix read as a
    clean-but-quiet scan. Each drop prints an operator banner and is
    accumulated in ``_dropped_registry_packs`` for scan_metrics.json.
    """
    needs_network = [
        (n, c) for n, c in configs
        if c.startswith(("p/", "category/"))
    ]
    if not needs_network:
        return configs
    import os
    import socket
    from urllib.parse import urlsplit
    # Probe the FIRST HOP semgrep will actually use. On
    # mandatory-egress-proxy hosts a direct TCP connect to
    # semgrep.dev:443 always fails even though semgrep (which honours
    # proxy env) can fetch registry packs fine — pre-fix that
    # misclassified every proxied host as airgapped and silently
    # dropped all registry packs. When a proxy is configured for
    # https (and semgrep.dev isn't no_proxy'd), reachability of the
    # proxy itself is the meaningful signal.
    probe_host, probe_port = "semgrep.dev", 443
    proxy_url = (
        os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
        or os.environ.get("all_proxy") or os.environ.get("ALL_PROXY")
    )
    if proxy_url:
        from core.http.urllib_backend import _host_in_no_proxy
        raw_no = os.environ.get("no_proxy") or os.environ.get("NO_PROXY") or ""
        no_proxy = tuple(e.strip() for e in raw_no.split(",") if e.strip())
        if not _host_in_no_proxy("semgrep.dev", no_proxy):
            parsed = urlsplit(
                proxy_url if "://" in proxy_url else f"http://{proxy_url}"
            )
            if parsed.hostname:
                probe_host = parsed.hostname
                probe_port = parsed.port or (
                    443 if parsed.scheme == "https" else 80
                )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((probe_host, probe_port))
        return configs
    except (TimeoutError, OSError):
        dropped = [n for n, _ in needs_network]
        logger.warning(
            "semgrep.dev unreachable (3 s probe failed) — "
            "dropping %d uncached registry pack(s): %s",
            len(dropped), ", ".join(dropped),
        )
        for name in dropped:
            if name not in _dropped_registry_packs:
                _dropped_registry_packs.append(name)
        print(
            f"⚠️  semgrep: {len(dropped)} registry pack(s) dropped "
            f"({', '.join(dropped)}) — semgrep.dev unreachable and no "
            "local cache for them. Coverage is reduced for this run; "
            "populate engine/semgrep/rules/registry-cache/ with "
            "engine/semgrep/tools/cache-packs.py to scan offline.",
            file=sys.stderr,
        )
        drop_set = {c for _, c in needs_network}
        return [(n, c) for n, c in configs if c not in drop_set]
    finally:
        sock.close()


def _resolve_baseline_packs(
    repo_path: Path | None,
) -> list[tuple[str, str]]:
    """Resolve the baseline semgrep pack set for ``repo_path``.

    When the target-type catalog matches and ships
    ``semgrep_packs.default``, use the catalog's list — that's
    the per-target-type tuning #7-7b ships. When no catalog match
    (or the matched entry has no default packs, like the
    ``generic`` fallback), use the hardcoded
    ``RaptorConfig.BASELINE_SEMGREP_PACKS``.

    Operator override via ``--policy-groups`` happens elsewhere
    (in main's rules_dirs construction) and remains authoritative
    — this resolver only governs the baseline (what runs when
    the operator hasn't narrowed the rule set explicitly).
    """
    if repo_path is None:
        return list(RaptorConfig.BASELINE_SEMGREP_PACKS)
    try:
        from core.run.target_types import load as load_target_type
        entry = load_target_type(Path(repo_path))
    except Exception:  # noqa: BLE001
        # Catalog substrate is best-effort; never break the scan
        # on a catalog load issue.
        return list(RaptorConfig.BASELINE_SEMGREP_PACKS)
    if entry is None or not entry.semgrep_packs_default:
        return list(RaptorConfig.BASELINE_SEMGREP_PACKS)
    return [_pack_tuple_for_id(pid) for pid in entry.semgrep_packs_default]


# File-extension → semgrep-language mapping. Covers the common
# cases; missing extensions silently produce no language hit
# (operator sees an empty applicability count rather than a wrong
# one). Lowercased keys; matches the lowercased extensions
# catalog YAMLs ship.
_EXT_TO_SEMGREP_LANG: dict[str, str] = {
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
    ".hpp": "cpp", ".hh": "cpp",
    ".py": "python",
    ".go": "go",
    ".rs": "rust",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".kt": "kotlin", ".kts": "kotlin",
    ".swift": "swift",
    ".scala": "scala",
    ".cs": "csharp",
    ".sol": "solidity",
    ".sh": "bash", ".bash": "bash",
    ".yaml": "yaml", ".yml": "yaml",
    ".json": "json",
    ".html": "html", ".htm": "html",
    ".lua": "lua",
}


# Semgrep ships rules using BOTH names for the same language —
# e.g. ``p/owasp-top-ten`` carries 67 rules at ``languages: [ts]``
# AND 4 at ``languages: [typescript]``. A naïve extension →
# canonical-name mapping misses the alias rules, undercounting
# applicability. Expand the target set with the known aliases
# before intersecting against each rule's ``languages`` field.
# Symmetric: every key/value is rewritten the same direction
# in both classes (operator's catalog might declare either form).
_SEMGREP_LANG_ALIASES: dict[str, set] = {
    "typescript": {"typescript", "ts"},
    "ts": {"typescript", "ts"},
    "kotlin": {"kotlin", "kt"},
    "kt": {"kotlin", "kt"},
    "javascript": {"javascript", "js"},
    "js": {"javascript", "js"},
    "csharp": {"csharp", "cs", "C#"},
    "cs": {"csharp", "cs", "C#"},
    "bash": {"bash", "sh"},
    "sh": {"bash", "sh"},
    "yaml": {"yaml", "yml"},
}


# Operator-facing display names live in
# ``core.inventory.languages`` so /prepare and any future
# renderer share the single source of truth. Re-exported with
# underscore prefix here for back-compat with internal callers
# (e.g. tests) that imported from this module.
from core.inventory.languages import (  # noqa: E402, F401
    LANG_DISPLAY as _LANG_DISPLAY,  # tests reference via _scanner._LANG_DISPLAY
)
from core.inventory.languages import (  # noqa: E402
    display_lang as _display_lang,  # noqa: F401 — tests reference via _scanner._display_lang
)
from core.inventory.languages import (  # noqa: E402  (after the constants it displays)
    display_langs as _display_langs,  # used by call sites below
)


def _expand_language_aliases(langs: list[str]) -> set:
    """Expand ``langs`` to include semgrep's alias names so the
    intersection check below catches rules registered under
    either form."""
    out: set = set()
    for lang in langs:
        out.add(lang)
        out.update(_SEMGREP_LANG_ALIASES.get(lang, set()))
    return out


def _target_semgrep_languages(repo_path: Path | None) -> list[str]:
    """Best-effort set of semgrep language ids for ``repo_path``.

    Sourced from the matched target-type catalog entry's
    ``file_extensions`` — cheap (no tree walk) and accurate for
    the common case. Returns ``[]`` when no catalog match,
    extension list empty, or no extension maps to a known
    semgrep language. Caller treats ``[]`` as ''don't show
    applicability'' (better than guessing wrong).
    """
    if repo_path is None:
        return []
    try:
        from core.run.target_types import load as _load_tt
        entry = _load_tt(repo_path)
    except Exception:  # noqa: BLE001
        return []
    if entry is None:
        return []
    langs: set = set()
    for ext in entry.file_extensions:
        lang = _EXT_TO_SEMGREP_LANG.get(ext.lower())
        if lang:
            langs.add(lang)
    return sorted(langs)


def _pack_rules_applicable_count(
    pack_id: str, target_langs: list[str],
) -> tuple[int, int] | None:
    """Read the cached pack JSON for ``pack_id`` and return
    ``(applicable_rule_count, total_rule_count)`` for rules
    whose ``languages`` list intersects the alias-expanded
    ``target_langs`` set.

    None when the pack isn't cached locally — the operator's
    semgrep invocation would fetch the pack from the registry
    at scan time and we'd be measuring stale numbers. The
    visibility line then omits this pack rather than printing
    a misleading zero.
    """
    cache_file = RaptorConfig.SEMGREP_REGISTRY_CACHE_DIR / (
        "c." + pack_id.replace("/", ".") + ".json"
    )
    if not cache_file.is_file():
        return None
    data = load_json(cache_file, max_bytes=_MAX_PACK_CACHE_BYTES)
    if not isinstance(data, dict):
        return None
    rules = data.get("rules") or []
    # Defensive: a future / corrupted cache file with ``rules`` as
    # a non-list (e.g. dict, scalar) would crash the iteration
    # below. Treat as no data — caller skips the pack.
    if not isinstance(rules, list):
        return None
    target_set = _expand_language_aliases(target_langs)
    applicable = 0
    total = 0
    for r in rules:
        if not isinstance(r, dict):
            continue
        total += 1
        rule_langs = r.get("languages") or []
        if not isinstance(rule_langs, list):
            continue
        if set(rule_langs) & target_set:
            applicable += 1
    return (applicable, total)


def _pack_applicable_rule_ids(
    pack_id: str, target_langs: list[str],
) -> set | None:
    """Return the SET of rule ids in ``pack_id`` whose
    ``languages`` field intersects the alias-expanded
    ``target_langs``. Used by ``_is_coverage_thin`` to dedupe
    across packs that ship overlapping rules — e.g. ``p/default``
    and ``p/security-audit`` share many entries; counting each
    twice would inflate the threshold check.

    None when the pack isn't cached locally (same contract as
    ``_pack_rules_applicable_count``).
    """
    cache_file = RaptorConfig.SEMGREP_REGISTRY_CACHE_DIR / (
        "c." + pack_id.replace("/", ".") + ".json"
    )
    if not cache_file.is_file():
        return None
    data = load_json(cache_file, max_bytes=_MAX_PACK_CACHE_BYTES)
    if not isinstance(data, dict):
        return None
    rules = data.get("rules") or []
    if not isinstance(rules, list):
        return None
    target_set = _expand_language_aliases(target_langs)
    ids: set = set()
    for r in rules:
        if not isinstance(r, dict):
            continue
        rule_langs = r.get("languages") or []
        if not isinstance(rule_langs, list):
            continue
        if set(rule_langs) & target_set:
            rule_id = r.get("id")
            if isinstance(rule_id, str) and rule_id:
                ids.add(rule_id)
    return ids


# Default threshold for unique applicable rules across baseline
# packs. Calibration point: a C / userspace-daemon scan with the
# c.userspace-daemon catalog nets ~9 unique applicable C rules; a
# Python web-app scan with its catalog nets ~200+. 25 sits
# comfortably between the two — picks up genuinely thin language
# coverage without false-positive-ing on healthy coverage.
# Operator-tunable via ``RAPTOR_SCAN_THIN_COVERAGE_THRESHOLD``
# env var so future catalog entries with different rule densities
# can be accommodated without a code change.
_DEFAULT_THIN_COVERAGE_RULE_THRESHOLD = 25


def _thin_coverage_threshold() -> int:
    """Read the threshold from the env var, fall back to the
    default. Malformed values (non-integer / negative) warn-once
    and fall back to the default so a typo doesn't silently
    disable the hint forever."""
    import os
    raw = os.environ.get("RAPTOR_SCAN_THIN_COVERAGE_THRESHOLD")
    if not raw:
        return _DEFAULT_THIN_COVERAGE_RULE_THRESHOLD
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "RAPTOR_SCAN_THIN_COVERAGE_THRESHOLD=%r is not an int; "
            "using default %d",
            raw, _DEFAULT_THIN_COVERAGE_RULE_THRESHOLD,
        )
        return _DEFAULT_THIN_COVERAGE_RULE_THRESHOLD
    if value < 0:
        logger.warning(
            "RAPTOR_SCAN_THIN_COVERAGE_THRESHOLD=%d must be >= 0; "
            "using default %d",
            value, _DEFAULT_THIN_COVERAGE_RULE_THRESHOLD,
        )
        return _DEFAULT_THIN_COVERAGE_RULE_THRESHOLD
    return value


def _is_coverage_thin(
    resolved_baseline: list[tuple[str, str]],
    target_langs: list[str],
) -> bool:
    """True iff the count of UNIQUE applicable rule ids across
    all baseline packs falls below the configured threshold
    (``RAPTOR_SCAN_THIN_COVERAGE_THRESHOLD`` env var, default
    25). Uncached packs are skipped — we don't know what they'd
    contribute, so the hint doesn't fire on uncertainty.
    Deduplication is essential because packs share rules
    (``p/default`` and ``p/security-audit`` overlap heavily);
    naively summing per-pack counts would inflate the figure
    past the threshold for genuinely thin coverage."""
    if not target_langs:
        return False
    unique_ids: set = set()
    have_any_cached = False
    for _, pack_id in resolved_baseline:
        ids = _pack_applicable_rule_ids(pack_id, target_langs)
        if ids is None:
            continue
        have_any_cached = True
        unique_ids.update(ids)
    return (
        have_any_cached
        and len(unique_ids) < _thin_coverage_threshold()
    )


def _llm_configured() -> bool:
    """True when RAPTOR can dispatch an LLM call. Best-effort —
    used to decide whether to suggest ``/agentic`` in the
    thin-coverage hint (no point suggesting an LLM-driven path
    when no LLM provider is available).

    Defaults to True on any import / instantiation failure so a
    transient config bug doesn't silently strip an option the
    operator might be able to use."""
    try:
        from core.llm.config import LLMConfig
        return LLMConfig().primary_model is not None
    except Exception:  # noqa: BLE001
        return True


def _format_thin_coverage_hint(
    target_langs: list[str],
    codeql_already_running: bool,
    llm_configured: bool = True,
) -> str:
    """One-line operator-facing escalation hint when pack
    applicability is thin. CodeQL clause omitted when the
    operator already passed ``--codeql``; /agentic clause
    omitted when no LLM is configured (suggesting it would be
    hollow guidance).
    """
    lang_label = _display_langs(target_langs)
    options: list[str] = []
    if not codeql_already_running:
        options.append("rerun with --codeql for richer queries")
    if llm_configured:
        options.append("use /agentic for LLM-driven hunting")
    if not options:
        # Pathological: both alternatives unavailable. Honest
        # about it — operator at least knows the gap is real.
        return f"  Coverage thin for {lang_label}."
    return (
        f"  Coverage thin for {lang_label} — "
        f"{'; '.join(options)}."
    )


def _format_pack_applicability(
    resolved_baseline: list[tuple[str, str]],
    target_langs: list[str],
) -> str | None:
    """Render the operator-facing visibility line, or None when
    no useful signal (no target langs, no cached pack data).

    Example::

        Pack rules applicable to c: security-audit 9/225, command-injection 0/30, owasp-top-ten 0/544

    Pre-#16a the operator saw only ``6 rule-group(s)`` with no
    way to know how many of the ~2k rules across those packs
    actually target their language — masked the upstream
    coverage gap that surfaced on the c.userspace-daemon scan.
    """
    if not target_langs:
        return None
    parts: list[str] = []
    for _, pack_id in resolved_baseline:
        counts = _pack_rules_applicable_count(pack_id, target_langs)
        if counts is None:
            continue
        applicable, total = counts
        # Strip the ``p/`` prefix for readability — the operator
        # cares about the pack name, not the registry path
        # convention.
        short = pack_id.removeprefix("p/")
        parts.append(f"{short} {applicable}/{total}")
    if not parts:
        return None
    return (
        f"Pack rules applicable to "
        f"{_display_langs(target_langs)}: {', '.join(parts)}"
    )


def _resolve_rules_applied(
    groups: list[str],
    resolved_baseline: list[tuple[str, str]],
    rules_dirs: list[str],
) -> list[str]:
    """Compute the ``rules_applied`` list stored on the semgrep
    coverage record.

    Captures every policy group whose registry pack actually ran,
    so the coverage report's "policy group(s) not used" check
    (``POLICY_GROUP_TO_SEMGREP_PACK.keys() - rules_applied``)
    doesn't falsely flag groups whose pack was added via the
    catalog, via a rule-dir-name match, or as a shared pack id
    across multiple policy groups.

    Pre-fix: ``rules_applied=['all']`` (literal) or local rule
    directory names; both lacked the canonical policy-group keys,
    so EVERY policy group showed as ''not used'' — the
    operator-facing inconsistency the c.userspace-daemon scan
    surfaced.

    Honest semantic: pack-id-driven. A policy group is ''applied''
    iff its registry pack id is in the set of pack ids semgrep
    actually ran. That set is the union of:

    * Catalog-resolved baseline packs (``resolved_baseline``).
    * Pack ids that ``semgrep_scan_parallel`` adds because a
      rule dir's name matched a key in ``POLICY_GROUP_TO_SEMGREP_PACK``
      (see scanner.py:``Add corresponding standard pack if available``).

    Operator-passed specific policy groups (``--policy-groups
    auth,injection``) drive ``rules_dirs`` membership, which feeds
    back through the same rule-dir → pack-id mapping — so the
    set inclusion is automatic; no special branch needed.

    Two correctness wins over the pre-fix design:

    1. Shared pack ids — ``flows`` and ``best-practices`` both
       map to ``p/default``; running ``flows/`` exercises both,
       and both correctly land in ``applied`` here.
    2. No-local-rule-dir groups — ``best-practices`` has no
       local rule dir; ``--policy-groups all`` doesn't trigger
       its registry pack via the rule-dir loop, so it's NOT in
       ``applied`` unless something else added ``p/default``
       (which ``flows/`` does in practice).

    * ``groups`` — accepted for API symmetry / future extension;
      currently unused (rule-dir membership is the actual signal).
    * ``resolved_baseline`` — the catalog-resolved baseline pack
      set (``[(display_name, pack_id), ...]``).
    * ``rules_dirs`` — local rule directory paths the scanner
      passed to semgrep_scan_parallel. Used to derive which
      registry packs got auto-added via the rule-dir → pack-id
      mapping, AND as the fallback identity when nothing else
      populated the applied set.
    """
    # Compute the set of pack ids semgrep ACTUALLY ran — the
    # union of catalog baseline + auto-added registry packs (via
    # rule-dir name match).
    ran_pack_ids: set = {pid for _, pid in resolved_baseline}
    for rd in rules_dirs:
        dir_name = Path(rd).name
        mapping = RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK.get(dir_name)
        if mapping is not None:
            ran_pack_ids.add(mapping[1])

    # Reverse-map every policy group whose pack id ran.
    applied = {
        group
        for group, (_name, pack_id)
        in RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK.items()
        if pack_id in ran_pack_ids
    }
    if applied:
        return sorted(applied)
    # Fallback: no policy groups exercised → record rule-dir
    # names so the coverage record still has SOME identity
    # (preserves pre-fix shape for the genuinely-empty case).
    _ = groups  # accepted for API symmetry; unused — see docstring.
    # Single-file groups record by stem ("ssrf"), dirs by name.
    return [
        Path(r).stem if Path(r).is_file() else Path(r).name
        for r in rules_dirs
    ]


def _sanitize_pack_name(name: str) -> str:
    r"""Strict allowlist: alphanumeric + dash + underscore + dot.

    ``name`` is the policy-pack name from
    ``RaptorConfig.BASELINE_SEMGREP_PACKS`` /
    ``POLICY_GROUP_TO_SEMGREP_PACK`` (operator can extend via
    ``--policy-groups``), and the sanitised result becomes part of an
    output FILE PATH. Any other shell / filesystem-special character
    (``*``, ``?``, ``[``, ``]``, ``\``, space, NUL, newline, control
    bytes) would otherwise flow straight into
    ``out_dir / f"semgrep_{suffix}.sarif"``. Concrete failure: a
    custom policy pack named with a space produced an output path with
    embedded whitespace that subsequent ``find`` / ``glob`` calls
    mishandled. Preserves the legacy ``/`` → ``_`` and ``:`` → ``_``
    mapping (both in the disallowed set, so they get replaced anyway).
    """
    return re.sub(r'[^A-Za-z0-9._-]', '_', name)


def run(cmd, cwd=None, timeout=RaptorConfig.DEFAULT_TIMEOUT, env=None,
        target=None, output=None, proxy_hosts=None, caller_label=None,
        fake_home: bool=False, readable_paths=None):
    """Execute a command in a network-isolated sandbox and return results.

    When `target` and `output` are supplied, Landlock is engaged — the
    child may read anywhere (Landlock default) but may only write to
    `output` and `/tmp`.

    Network policy:
      - Default (proxy_hosts=None): block_network=True at the user-ns
        layer. Child sees no interfaces at all.
      - proxy_hosts=[...] set: route outbound via the RAPTOR egress
        proxy with a hostname allowlist. Caller specifies which hosts
        are needed (`semgrep.dev` for registry pack fetches,
        `github.com`/`gitlab.com` for git clone, etc.). UDP blocked,
        DNS resolution delegated to the proxy. Net surface is strictly
        narrower than plain block_network=False and strictly wider
        than block_network=True.
    """
    from core.sandbox import run as sandbox_run
    net_kwargs = (
        {"use_egress_proxy": True, "proxy_hosts": list(proxy_hosts),
         "caller_label": caller_label or "scanner"}
        if proxy_hosts else
        {"block_network": True}
    )
    # tool_paths: speculative best-guess bind set so mount-ns isolation
    # can engage. For Python tools we need (a) the script's bin dir
    # and (b) the interpreter's stdlib dir at sys.prefix/lib/pythonX.Y.
    #
    # Outcome depends on the operator's install layout:
    #
    #   /usr/bin/semgrep (system install): cmd[0] already in mount
    #     tree, helper returns []; mount-ns engages cleanly, full
    #     isolation, silent.
    #
    #   ~/.local/bin/semgrep (pip --user) or /opt/homebrew/bin
    #     (brew): helper returns [bin_dir, stdlib_dir]; mount-ns
    #     tries with these. If semgrep then exec's native deps not
    #     in the bind set (semgrep-core, etc.), context.py's
    #     speculative-C retry catches the 126/empty-stderr and
    #     falls back to Landlock-only. Workflow proceeds; debug-
    #     level diagnostic only.
    # Exec via the binary's REAL path: pip-style installs land a
    # symlink in a user bin dir while the actual script, interpreter
    # and native deps live under the venv the tool-path helper binds.
    # The mount-ns visibility check (correctly) refuses a cmd[0] whose
    # own path isn't in the bind tree, so invoking via the symlink
    # dropped every such tool to the Landlock-only fallback — where
    # netns proxy connectivity is deliberately not re-plumbed, which
    # is why registry pack fetches (p/...) always failed on pip-
    # installed semgrep.
    _resolved0 = shutil.which(cmd[0]) or cmd[0]
    _real0 = os.path.realpath(_resolved0)
    if _real0 != cmd[0] and os.path.isfile(_real0):
        cmd = [_real0, *cmd[1:]]
    tool_paths = _compute_python_tool_paths(cmd)
    from core.sandbox.python_paths import python_runtime_tool_paths
    for p in python_runtime_tool_paths():
        if p not in tool_paths:
            tool_paths.append(p)
    sandbox_kwargs = {}
    if fake_home:
        sandbox_kwargs["fake_home"] = True
    if readable_paths:
        sandbox_kwargs["readable_paths"] = list(readable_paths)
        # readable_paths only reaches Landlock under restrict_reads;
        # the channel that makes a path VISIBLE inside the mount-ns
        # bind tree is tool_paths. The standard tree carries system
        # dirs + target/output only — no /home — so local rule
        # configs and --extra-config files were unreadable whenever
        # mount-ns engaged, and the pack failed. Name them on both
        # channels: bind now, read-allow if reads ever restrict.
        for _rp in readable_paths:
            if _rp not in tool_paths:
                tool_paths.append(_rp)
    # ``strict_env=True`` acknowledges that this caller deliberately
    # supplies env= (a ``get_safe_env()``-derived dict with HOME / XDG
    # overrides from the semgrep-specific path). Without it, the sandbox
    # logs a one-line WARNING per invocation telling us to do exactly
    # this. Operator on PR #777 surfaced the warning firing ~12× per
    # scan run. The strip is a no-op for us (``get_safe_env`` already
    # excludes DANGEROUS_ENV_VARS) but the flag is also the documented
    # "I'm aware of the bypass" marker.
    p = sandbox_run(
        cmd,
        target=target,
        output=output,
        cwd=cwd,
        env=env or RaptorConfig.get_safe_env(),
        strict_env=True,
        text=True,
        capture_output=True,
        timeout=timeout,
        tool_paths=tool_paths or None,
        **sandbox_kwargs,
        **net_kwargs,
    )
    return p.returncode, p.stdout, p.stderr


def _compute_python_tool_paths(cmd) -> list:
    """Best-guess bind dirs for a Python-tool sandbox call.

    Reads cmd[0]'s shebang to find the interpreter, then computes:
      - script's bin dir (so cmd[0] resolves)
      - interpreter's bin dir (often same dir)
      - interpreter's stdlib dir, derived from interpreter path +
        version (e.g. /home/USER/bin/python3.13 →
        /home/USER/lib/python3.13)

    All paths are absolute. Skips dirs that already lie under a
    standard mount-ns bind prefix (/usr, /lib, etc.) — no point
    asking for a bind that's already there.

    Returns [] when cmd is empty, the shebang can't be read, or
    the layout doesn't match a recognisable Python install.
    Speculative: a wrong guess is caught by context.py's
    speculative-C retry (re-runs without tool_paths if the call
    exits 126/127 with empty stderr).
    """
    import re
    from pathlib import Path
    if not cmd:
        return []
    cmd0 = cmd[0]
    # Prefix-skip set — paths already in the mount-ns bind tree.
    _SYS_PREFIXES = ("/usr/", "/lib/", "/lib64/", "/etc/", "/bin/", "/sbin/")
    def _interesting(p: str) -> bool:
        return p and not any(p == s.rstrip("/") or p.startswith(s)
                             for s in _SYS_PREFIXES)
    paths = set()
    # 1. Script's bin dir.
    if Path(cmd0).is_absolute():
        bin_dir = str(Path(cmd0).resolve().parent)
        if _interesting(bin_dir):
            paths.add(bin_dir)
    # 2. Read shebang to find the interpreter.
    #
    # Pre-fix `f.readline()` was unbounded — `readline` reads
    # until newline OR EOF. A file at `cmd0` with no newline
    # (a binary, a corrupted script, an attacker-planted file
    # at the resolved path) would read the WHOLE file into RSS
    # before we noticed it wasn't a shebang. For multi-MB
    # binaries that happen to live at `cmd[0]` (semgrep itself
    # is a Python wrapper but some installs ship a compiled
    # bin), the readline allocated the binary's full contents.
    #
    # Cap at 4 KB. POSIX shebangs are limited to 127 chars on
    # Linux + 512 on most BSDs anyway; 4 KB is well above any
    # legitimate shebang line.
    _SHEBANG_READ_CAP = 4096
    interp = None
    try:
        with open(cmd0, "rb") as f:
            first_line = f.readline(_SHEBANG_READ_CAP).decode(
                "utf-8", errors="ignore"
            ).strip()
        if first_line.startswith("#!"):
            interp = first_line[2:].split()[0]
    except (OSError, IndexError, UnicodeDecodeError):
        pass
    # 3. Interpreter's bin dir + stdlib dir.
    # CRITICAL: use the UNRESOLVED interp path for stdlib computation,
    # NOT Path.resolve(). Python's sys.prefix is computed from the path
    # used to invoke the interpreter (i.e. sys.executable, which equals
    # the unresolved shebang path). For an interpreter at
    # /home/U/bin/python3.13 that's a symlink to /usr/bin/python3.13,
    # Python sets sys.prefix=/home/U and looks for stdlib at
    # /home/U/lib/python3.13. If we bind-mount the resolved location
    # (/usr/lib/python3.13 — already in mount tree) Python won't find
    # its stdlib because it's looking at sys.prefix-relative path.
    # The bin dir IS still added via Path.resolve() (so symlink targets
    # outside the mount tree get added too), but stdlib derivation
    # MUST follow the unresolved path.
    if interp and Path(interp).is_absolute() and Path(interp).is_file():
        # Bin dir for the interpreter. Add both the resolved AND
        # unresolved bin dirs so we cover the full symlink chain.
        for p in {str(Path(interp).parent), str(Path(interp).resolve().parent)}:
            if _interesting(p):
                paths.add(p)
        # Extract version from interpreter name. Try the SHEBANG name
        # first (typically `python3.13` — version-stamped); fall back
        # to the resolved name if the shebang name lacks a version.
        candidate_names = [Path(interp).name, Path(interp).resolve().name]
        ver = None
        for name in candidate_names:
            m = re.match(r"python(\d+\.\d+)", name)
            if m:
                ver = m.group(1)
                break
        if ver:
            # Stdlib at sys.prefix/lib/pythonX.Y where sys.prefix is
            # derived from the UNRESOLVED interp path (Python's view).
            stdlib = Path(interp).parent.parent / "lib" / f"python{ver}"
            if stdlib.is_dir() and _interesting(str(stdlib)):
                paths.add(str(stdlib))
    return sorted(paths)


def _semgrep_jobs_per_worker(
    n_configs: int,
    max_workers: int,
    cpu_count: int,
) -> int:
    """Per-process ``--jobs`` so concurrent packs share the host.

    Unpinned, each semgrep process defaults to every core; N parallel
    packs would oversubscribe the machine N-fold (and semgrep's
    rule interpreter is memory-hungry per job). Divide the cores by
    the number of packs actually running at once, floor 1.
    """
    active = max(1, min(max_workers, n_configs))
    return max(1, cpu_count // active)


# Semgrep error types that mean a FILE was dropped for resource
# reasons — the scan "succeeded" while silently not analysing it.
_SEMGREP_RESOURCE_DROP_TYPES = frozenset({
    "Timeout", "OutOfMemory", "FixpointTimeout", "TimeoutDuringInterfile",
})


def _semgrep_dropped_files(json_paths: list) -> dict:
    """Files dropped by per-rule timeouts / memory caps, across packs.

    Returns ``{path: sorted list of error types}``. Errors are
    per-pack, so every pack's JSON must be swept — a file dropped
    under one pack's rules is invisible in the others'. Unreadable
    JSONs are skipped (that pack already failed loudly elsewhere).
    """
    dropped: dict = {}
    for jp in json_paths:
        data = load_json(jp, max_bytes=_MAX_TOOL_JSON_BYTES)
        for e in data.get("errors", []) if isinstance(data, dict) else []:
            etype = str(e.get("type", ""))
            if etype in _SEMGREP_RESOURCE_DROP_TYPES and e.get("path"):
                dropped.setdefault(e["path"], set()).add(etype)
    return {p: sorted(t) for p, t in sorted(dropped.items())}


def _semgrep_max_memory_mb(
    n_configs: int,
    max_workers: int,
    total_ram_mb: int,
) -> int:
    """Per-pack ``--max-memory`` backstop (MiB).

    Local scans default to unlimited; with many packs running at once
    that is OOM-killer roulette — the kernel picks a victim and the
    pack dies with no attributable error. A generous share (75% of
    RAM divided by the packs actually running, floor 4 GiB) converts
    that into semgrep's own clean per-pack termination, surfaced
    through the normal failed-pack path.
    """
    active = max(1, min(max_workers, n_configs))
    return max(4096, (total_ram_mb * 3 // 4) // active)


def run_single_semgrep(
    name: str,
    config: str,
    repo_path: Path,
    out_dir: Path,
    timeout: int,
    progress_callback: Callable | None = None,
    extra_config_readable_paths: list[str] | None = None,
    jobs: int | None = None,
    max_memory_mb: int | None = None,
) -> tuple[str, bool]:
    """
    Run a single Semgrep scan.

    Returns:
        Tuple of (sarif_path, success)
    """
    suffix = _sanitize_pack_name(name)
    sarif = out_dir / f"semgrep_{suffix}.sarif"
    json_out = out_dir / f"semgrep_{suffix}.json"
    stderr_log = out_dir / f"semgrep_{suffix}.stderr.log"
    exit_file = out_dir / f"semgrep_{suffix}.exit"

    logger.debug("Starting Semgrep scan: %s", name)

    if progress_callback:
        progress_callback(f"Scanning with {name}")

    # Build the semgrep argv via packages/semgrep/. Sandbox engagement,
    # HOME redirect, and registry-pack proxy hosts remain scanner concerns
    # below — packages/semgrep/ is pure invocation logic.
    # Resolve binary explicitly to avoid broken-venv installations.
    semgrep_cmd = shutil.which("semgrep") or "/opt/homebrew/bin/semgrep"
    cmd = semgrep_pkg.build_cmd(
        repo_path,
        config,
        json_output_path=json_out,
        rule_timeout=RaptorConfig.SEMGREP_RULE_TIMEOUT,
        semgrep_bin=semgrep_cmd,
        extra_args=(
            (["--jobs", str(jobs)] if jobs else [])
            + (["--max-memory", str(max_memory_mb)] if max_memory_mb else [])
            or None
        ),
    )

    # Create clean environment without venv contamination or dangerous vars.
    # `VIRTUAL_ENV` and `PYTHONPATH` are now stripped by
    # `get_safe_env()` itself (DANGEROUS_ENV_VARS); the local
    # strips were redundant.
    clean_env = RaptorConfig.get_safe_env()
    # Remove venv from PATH
    if 'PATH' in clean_env:
        path_parts = clean_env['PATH'].split(':')
        path_parts = [p for p in path_parts if 'venv' not in p.lower() and '/bin/pysemgrep' not in p]
        clean_env['PATH'] = ':'.join(path_parts)

    # HOME + XDG basedirs are redirected via the sandbox layer's
    # ``fake_home=True`` primitive (passed below to ``run()``). The
    # sandbox itself owns the override semantics: it pre-creates
    # ``HOME`` + all four ``XDG_*_HOME`` subdirs (CONFIG/DATA/CACHE/STATE)
    # with mode 0o700 inside ``output``, refuses to materialise if any
    # target path is a symlink (TOCTOU defence against a prior sandboxed
    # child substituting a redirect target), and merges the override
    # into the subprocess env with ``fake_home_env`` winning over any
    # caller-supplied ``env=`` (see ``core/sandbox/context.py``).
    #
    # Without the XDG override, ``SAFE_ENV_ALLOWLIST`` preserves the
    # operator's ``XDG_CONFIG_HOME`` and newer semgrep follows it to the
    # real ``~/.config/semgrep`` — outside the Landlock writable policy.
    # Under full sandbox the path is invisible inside the mount-ns;
    # under the rootless-podman / distrobox Landlock-only path Landlock
    # denies the write and semgrep crashes. ``fake_home=True`` is the
    # profile-agnostic fix and means the policy lives in ONE place
    # (sandbox context) instead of hand-rolled per-tool.
    #
    # semgrep 1.79.0 does NOT persistently cache registry packs on disk
    # — every invocation fetches the pack YAML from semgrep.dev
    # regardless of HOME / cache dir — so the redirect costs us nothing
    # (there's no cache to lose across scans). PR #196 ships pack YAMLs
    # under engine/semgrep/rules/registry-cache/ and rewrites
    # ``p/security-audit`` → local path BEFORE semgrep's registry client
    # runs — post-#196 the fetch path is cold.

    # Registry packs ("p/xxx", "category/xxx") fetch YAML from semgrep.dev
    # on every invocation — semgrep has no persistent on-disk cache. A slow
    # or stalled registry fetch otherwise consumes the full SEMGREP_TIMEOUT
    # (15 min) per pack, and at MAX_SEMGREP_WORKERS=4 can eat the whole
    # 30-min agentic budget for one bad network moment. Bound the per-pack
    # cost with a tighter ceiling so a stuck fetch drops that pack and the
    # remaining packs still run. Local rule directories keep the longer
    # timeout because they do real scan work without network.
    is_registry_pack = config.startswith(("p/", "category/"))
    effective_timeout = min(timeout, RaptorConfig.SEMGREP_PACK_TIMEOUT) if is_registry_pack else timeout

    try:
        # Engage Landlock via target + output. Writes pinned to out_dir
        # and /tmp. Reads Landlock-default-wide (semgrep is a
        # RAPTOR-chosen trusted tool, not attacker-controlled code).
        # Network: route via the egress proxy with the resolved
        # allowlist — UDP blocked, hostname-allowlisted,
        # resolved-IP-screened by the proxy's is_global check.
        # Allowlist pulled from ._proxy_hosts (override → calibrate
        # → static default) so operators on Semgrep self-hosted /
        # corporate registry mirrors can override without source
        # edits. See packages/static-analysis/_proxy_hosts.py.
        #
        # ``static-analysis`` is hyphenated → not importable as a
        # Python package; scanner.py runs as ``__main__`` via
        # subprocess. Load the helper via importlib at call time
        # to match the existing convention (see tests under
        # packages/static-analysis/tests/ for the same pattern).
        import importlib.util as _importlib_util
        _ph_path = Path(__file__).parent / "_proxy_hosts.py"
        _ph_spec = _importlib_util.spec_from_file_location(
            "static_analysis_proxy_hosts", _ph_path,
        )
        _ph = _importlib_util.module_from_spec(_ph_spec)
        _ph_spec.loader.exec_module(_ph)
        # ``fake_home=True``: sandbox layer materialises HOME + four
        # XDG_*_HOME dirs inside ``output``, with symlink-TOCTOU defence,
        # and merges its override into the subprocess env (winning over
        # ``clean_env``'s ``HOME`` if anything else set it). Profile-
        # agnostic — fires even under ``--sandbox none``.
        #
        # ``readable_paths``: the caller's ``--extra-config`` rule paths
        # are passed here as well as in the semgrep argv. Today the
        # scanner's Landlock policy is read-wide (``restrict_reads=False``
        # — semgrep is a RAPTOR-chosen trusted tool) so this is a no-op,
        # but future-proofs against a flip to read-restricted: an operator
        # ``--extra-config /home/me/rules.yml`` would otherwise be denied
        # at sandbox-read time.
        # Local rule-directory packs reference a filesystem config
        # (engine/semgrep/rules/<category>). Under mount-ns the child
        # only sees the standard bind tree plus target/output — an
        # install root under a masked path (/tmp checkouts, private
        # prefixes) would leave the config unreadable and fail the
        # pack. Naming it in readable_paths bind-mounts it explicitly
        # instead of relying on where the install root happens to live.
        _pack_readable = list(extra_config_readable_paths or [])
        if (not is_registry_pack and Path(config).exists()
                and str(config) not in _pack_readable):
            _pack_readable.append(str(config))
        rc, so, se = run(
            cmd, timeout=effective_timeout, env=clean_env,
            target=str(repo_path), output=str(out_dir),
            proxy_hosts=_ph.proxy_hosts_for_semgrep(),
            caller_label="scanner-semgrep",
            fake_home=True,
            readable_paths=_pack_readable or None,
        )

        # Validate output
        if not so or not so.strip():
            logger.warning("Semgrep scan '%s' produced empty output", name)
            so = '{"runs": []}'

        # Explicit `encoding="utf-8"` on all three writes. Pre-fix
        # bare `write_text(...)` used `locale.getpreferredencoding()`
        # which returns cp1252/latin-1 on some hosts. Semgrep's SARIF
        # output is UTF-8 by spec; writing it back in cp1252 would
        # mojibake non-ASCII rule descriptions and snippet text. The
        # downstream SARIF parser then either failed schema validation
        # OR silently fed mojibake into LLM analysis prompts.
        # `errors="replace"` belt-and-braces against a stray non-UTF-8
        # byte sequence in the semgrep stdout (shouldn't happen but
        # we don't want a single bad byte to crash the write).
        sarif.write_text(so, encoding="utf-8", errors="replace")
        stderr_log.write_text(se or "", encoding="utf-8", errors="replace")
        exit_file.write_text(str(rc), encoding="utf-8")

        # Validate SARIF — tri-state result:
        #   True  → full schema validation passed
        #   False → load failed or schema rejected the structure
        #   None  → basic shape OK but full schema check couldn't run
        #           (jsonschema not installed, schema file missing)
        # Treat None as trust-with-warning rather than rejection;
        # the basic-shape check (load + version + runs field) is
        # already strict enough to catch malformed semgrep output.
        is_valid = validate_sarif(sarif)
        if is_valid is False:
            logger.warning("Semgrep scan '%s' produced invalid SARIF", name)
        elif is_valid is None:
            logger.debug(
                "Semgrep scan '%s': SARIF basic shape OK but full "
                "schema validation skipped (jsonschema or schema file unavailable)",
                name
            )

        success = rc in (0, 1) and is_valid is not False
        logger.debug("Completed Semgrep scan: %s (exit=%s, valid=%s)", name, rc, is_valid)

        return str(sarif), success

    except SandboxSetupError:
        # Sandbox isolation could not engage on this host. Do NOT mask it
        # as an empty SARIF — that is the exact "0 findings in 0 files"
        # silent-failure this exception exists to prevent. Propagate so
        # the scan fails loud; the operator picks an explicit profile
        # (`--sandbox network-only`). Every pack would hit the same host
        # condition, so failing on the first is correct.
        raise
    except Exception as e:  # noqa: BLE001
        logger.error("Semgrep scan '%s' failed: %s", name, e)
        # Write empty SARIF on error. Same encoding posture as the
        # success path above — explicit UTF-8 so the downstream
        # parser sees a consistent byte shape regardless of host
        # locale.
        sarif.write_text('{"runs": []}', encoding="utf-8")
        stderr_log.write_text(str(e), encoding="utf-8", errors="replace")
        exit_file.write_text("-1", encoding="utf-8")
        return str(sarif), False


def semgrep_scan_parallel(
    repo_path: Path,
    rules_dirs: list[str],
    out_dir: Path,
    timeout: int = RaptorConfig.SEMGREP_TIMEOUT,
    progress_callback: Callable | None = None,
    baseline_packs: list[tuple[str, str]] | None = None,
    extra_configs: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    """
    Run Semgrep scans in parallel for improved performance.

    Args:
        repo_path: Path to repository to scan
        rules_dirs: List of rule directory paths
        out_dir: Output directory for results
        timeout: Timeout per scan
        progress_callback: Optional callback for progress updates
        baseline_packs: Override for the always-run baseline pack
            set (``[(display_name, pack_id), ...]``). When None,
            falls back to ``RaptorConfig.BASELINE_SEMGREP_PACKS`` —
            preserves pre-#17 behaviour for callers that don't
            consult the target-type catalog. Callers integrated
            with the catalog (scanner.py main) resolve via
            ``_resolve_baseline_packs`` and pass the result.
        extra_configs: Operator-supplied custom rule sources
            (``--extra-config``). Each value becomes its own peer
            pack named ``extra_<basename>`` with its own SARIF;
            duplicate paths are dropped with a warning and basename
            collisions get a positional suffix. None/empty ⇒ no
            extra packs.

    Returns:
        (sarif_paths, failed_pack_names). Callers MUST surface the
        failed list — silent-failure on parallel pack dispatch (a
        submitted pack producing no SARIF on disk while
        ``failed_scans`` records nothing) had no operator-visible
        signal pre-fix: the survivor's SARIF was the only artifact
        and the coverage record read like a complete run. Returning
        the failed list from the dispatcher closes that gap; the
        caller renders the summary line and writes it into the
        coverage record.
    """
    if baseline_packs is None:
        baseline_packs = list(RaptorConfig.BASELINE_SEMGREP_PACKS)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build config list with BOTH local rules AND standard packs for each category
    configs: list[tuple[str, str]] = []
    added_packs = set()  # Track which standard packs we've added to avoid duplicates

    # Add local rules + corresponding standard packs for each specified category
    for rd in rules_dirs:
        rd_path = Path(rd)
        if rd_path.exists():
            # Files (single-file policy groups like ssrf) name the
            # category by stem so the pack name is 'category_ssrf',
            # not 'category_ssrf.yaml'.
            category_name = rd_path.stem if rd_path.is_file() else rd_path.name

            # Add local rules for this category
            configs.append((f"category_{category_name}", str(rd_path)))

            # Add corresponding standard pack if available
            if category_name in RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK:
                pack_name, pack_id = RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK[category_name]
                if pack_id not in added_packs:
                    resolved = RaptorConfig.get_semgrep_config(pack_id)
                    configs.append((pack_name, resolved))
                    added_packs.add(pack_id)
                    logger.debug("Added standard pack for %s: %s", category_name, resolved)
        else:
            logger.warning("Rule directory not found: %s", rd_path)

    # Add baseline packs (unless already added). ``baseline_packs``
    # was resolved by the caller (target-type catalog → tuned
    # default per #7-7b; otherwise hardcoded BASELINE).
    for pack_name, pack_identifier in baseline_packs:
        if pack_identifier not in added_packs:
            configs.append((pack_name, RaptorConfig.get_semgrep_config(pack_identifier)))
            added_packs.add(pack_identifier)

    # Operator-supplied custom rule sources via ``--extra-config``. Each
    # value becomes a peer pack (its own SARIF, merged into combined
    # results). Names are derived from the path so the operator can spot
    # which extra-config produced which finding. Paths are deduped by
    # resolved value (the validation pass at the CLI already resolves
    # paths, but a defensive dedup here guards against future callers
    # that don't go through main()). Basename collisions across distinct
    # paths get a positional suffix so the per-pack SARIF filename
    # ``semgrep_extra_<name>.sarif`` is unique — without this, two paths
    # like ``/a/rules.yml`` + ``/b/rules.yml`` would both write to
    # ``semgrep_extra_rules.sarif`` and the silent-drop detector would
    # NOT fire (the file exists, just from the other pack's worker).
    _seen_extra: set = set()
    _used_names: set = {n for n, _ in configs}
    for _idx, extra in enumerate(extra_configs or []):
        if extra in _seen_extra:
            logger.warning("--extra-config: duplicate path dropped: %s", extra)
            continue
        _seen_extra.add(extra)
        base = f"extra_{_sanitize_pack_name(Path(extra).name)}"
        unique = base
        _i = 0
        while unique in _used_names:
            _i += 1
            unique = f"{base}_{_i}"
        _used_names.add(unique)
        configs.append((unique, extra))

    configs = _drop_unreachable_registry_packs(configs)

    logger.info(
        "Starting %d Semgrep scans in parallel (max %s workers)",
        len(configs),
        RaptorConfig.MAX_SEMGREP_WORKERS
    )
    logger.info(
        "  - Local rule directories: %d", len([c for c in configs if c[0].startswith('category_')])
    )
    logger.info(
        "  - Standard/baseline packs: %d",
        len([c for c in configs if not c[0].startswith('category_')])
    )

    # Run scans in parallel
    sarif_paths: list[str] = []
    failed_scans: list[str] = []

    _jobs = _semgrep_jobs_per_worker(
        len(configs), RaptorConfig.MAX_SEMGREP_WORKERS,
        os.cpu_count() or 4,
    )
    from core.tuning import _detect_total_ram_mb
    _max_mem = _semgrep_max_memory_mb(
        len(configs), RaptorConfig.MAX_SEMGREP_WORKERS,
        _detect_total_ram_mb(),
    )
    with ThreadPoolExecutor(max_workers=RaptorConfig.MAX_SEMGREP_WORKERS) as executor:
        future_to_config = {
            executor.submit(
                run_single_semgrep,
                name,
                config,
                repo_path,
                out_dir,
                timeout,
                progress_callback,
                extra_config_readable_paths=list(extra_configs or []),
                jobs=_jobs,
                max_memory_mb=_max_mem,
            ): (name, config)
            for name, config in configs
        }

        total = len(future_to_config)

        for completed, future in enumerate(
                as_completed(future_to_config), start=1):
            name, _config = future_to_config[future]

            try:
                sarif_path, success = future.result()
                sarif_paths.append(sarif_path)

                if not success:
                    failed_scans.append(name)

                if progress_callback:
                    progress_callback(f"Completed {completed}/{total} scans")

            except SandboxSetupError:
                # Isolation could not engage — every pack hits the same
                # host condition, so don't demote it to a per-pack failure
                # (which would still emit a "scanned, found nothing" run).
                # Propagate so the whole scan fails loud.
                raise
            except Exception as exc:  # noqa: BLE001
                logger.error("Semgrep scan '%s' raised exception: %s", name, exc)
                failed_scans.append(name)

    # Detect the missing-SARIF case (worker returned success + a
    # SARIF path, but no file actually exists on disk). Pre-fix,
    # silently-dropped packs left no ``failed_scans`` entry —
    # ``failure_count`` was 0, operators saw a clean run, the missing
    # SARIFs went unnoticed. Check actual file presence (not the
    # returned-path string) so any drop between worker-return and
    # file-landing — filesystem error, sandbox teardown, race —
    # registers as a failure.
    submitted_names = {name for name, _ in configs}
    silently_dropped = []
    for name in submitted_names:
        suffix = _sanitize_pack_name(name)
        sarif_expected = out_dir / f"semgrep_{suffix}.sarif"
        if not sarif_expected.is_file():  # noqa: SIM102
            if name not in failed_scans:
                silently_dropped.append(name)
                failed_scans.append(name)
    if silently_dropped:
        logger.warning(
            "Silently-dropped packs (submitted, no SARIF on disk): %s", ', '.join(silently_dropped)
        )

    if failed_scans:
        logger.warning("Failed scans: %s", ', '.join(failed_scans))

    logger.info("Completed %d scans (%d failed)", len(sarif_paths), len(failed_scans))
    return sarif_paths, failed_scans


def semgrep_scan_sequential(
    repo_path: Path,
    rules_dirs: list[str],
    out_dir: Path,
    timeout: int = RaptorConfig.SEMGREP_TIMEOUT,
    baseline_packs: list[tuple[str, str]] | None = None,
    extra_configs: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Sequential scanning fallback for debugging.

    Returns ``(sarif_paths, failed_pack_names)`` — same contract as
    ``semgrep_scan_parallel``. The sequential path is the
    ``--sequential`` debug fallback; parallelism isn't the source of
    the silent-drop class but the worker can still claim success
    while no SARIF lands (filesystem error, sandbox teardown), so
    the same cross-check + reporting apply.

    ``baseline_packs``: same contract as the parallel sibling —
    override for the always-run baseline pack set; None falls back
    to ``RaptorConfig.BASELINE_SEMGREP_PACKS``.
    """
    if baseline_packs is None:
        baseline_packs = list(RaptorConfig.BASELINE_SEMGREP_PACKS)
    out_dir.mkdir(parents=True, exist_ok=True)
    sarif_paths: list[str] = []
    failed_scans: list[str] = []

    # Build config list with BOTH local rules AND standard packs for each category
    configs: list[tuple[str, str]] = []
    added_packs = set()  # Track which standard packs we've added to avoid duplicates

    # Add local rules + corresponding standard packs for each specified category
    for rd in rules_dirs:
        rd_path = Path(rd)
        if rd_path.exists():
            # Files (single-file policy groups like ssrf) name the
            # category by stem so the pack name is 'category_ssrf',
            # not 'category_ssrf.yaml'.
            category_name = rd_path.stem if rd_path.is_file() else rd_path.name

            # Add local rules for this category
            configs.append((f"category_{category_name}", str(rd_path)))

            # Add corresponding standard pack if available
            if category_name in RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK:
                pack_name, pack_id = RaptorConfig.POLICY_GROUP_TO_SEMGREP_PACK[category_name]
                if pack_id not in added_packs:
                    resolved = RaptorConfig.get_semgrep_config(pack_id)
                    configs.append((pack_name, resolved))
                    added_packs.add(pack_id)

    # Add baseline packs (unless already added) — see parallel sibling
    # for the catalog-aware resolution rationale.
    for pack_name, pack_identifier in baseline_packs:
        if pack_identifier not in added_packs:
            configs.append((pack_name, RaptorConfig.get_semgrep_config(pack_identifier)))
            added_packs.add(pack_identifier)

    # Operator --extra-config — see parallel sibling for dedup +
    # basename-collision-rename rationale.
    _seen_extra: set = set()
    _used_names: set = {n for n, _ in configs}
    for extra in (extra_configs or []):
        if extra in _seen_extra:
            logger.warning("--extra-config: duplicate path dropped: %s", extra)
            continue
        _seen_extra.add(extra)
        base = f"extra_{_sanitize_pack_name(Path(extra).name)}"
        unique = base
        _i = 0
        while unique in _used_names:
            _i += 1
            unique = f"{base}_{_i}"
        _used_names.add(unique)
        configs.append((unique, extra))

    configs = _drop_unreachable_registry_packs(configs)

    for idx, (name, config) in enumerate(configs, 1):
        logger.info("Running scan %s/%d: %s", idx, len(configs), name)
        sarif_path, success = run_single_semgrep(
            name, config, repo_path, out_dir, timeout,
            extra_config_readable_paths=list(extra_configs or []),
        )
        sarif_paths.append(sarif_path)
        if not success:
            failed_scans.append(name)

    # Detect silent drops the same way semgrep_scan_parallel does —
    # worker may report success while no SARIF actually exists on
    # disk. Cross-check submitted names against on-disk files.
    submitted_names = {name for name, _ in configs}
    silently_dropped = []
    for name in submitted_names:
        suffix = _sanitize_pack_name(name)
        sarif_expected = out_dir / f"semgrep_{suffix}.sarif"
        if not sarif_expected.is_file():  # noqa: SIM102
            if name not in failed_scans:
                silently_dropped.append(name)
                failed_scans.append(name)
    if silently_dropped:
        logger.warning(
            "Silently-dropped packs (submitted, no SARIF on disk): %s", ', '.join(silently_dropped)
        )

    return sarif_paths, failed_scans


class _CodeQLStageTag(logging.Filter):
    """Prefix log lines emitted from the concurrent CodeQL stage thread.

    When the CodeQL stage overlaps the Semgrep stage their progress
    lines interleave on the operator's console; the tag keeps the
    stream legible without re-plumbing either stage's logging. The
    prefix carries no format specifiers, so records with %-args still
    format correctly.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if threading.current_thread().name.startswith("codeql-stage"):
            record.msg = "[codeql] " + str(record.msg)
        return True


def run_codeql(
    repo_path: Path,
    out_dir: Path,
    languages: list[str] | None = None,
    build_command: str | None = None,
    traced_build: bool = False,
) -> list[str]:
    """Delegate CodeQL analysis to packages/codeql/agent.py.

    Pre-unification this module shipped its own ~80-LOC WIP CodeQL
    runner alongside the proper one in `packages/codeql/`. The two
    diverged: the in-tree runner had no auto-detection (operator
    had to hard-code the language list), no build-system detection
    or synthesis (compiled C/C++ projects without a Makefile got
    silent extraction failures), no content-addressed DB cache, no
    target-repo trust check, no language alias normalisation
    (PR #448), and a hard-coded query-dir path that broke if the
    operator wasn't standing in repo root. The packages/codeql/
    runner has all of those.

    The two paths converge here: scanner.py invokes the proper
    agent as a subprocess (mirroring how raptor_agentic.py runs it
    at line 743). Output naming is identical — the agent writes
    `codeql_<lang>.sarif` per detected language under `out_dir`,
    matching the previous in-tree runner's convention so downstream
    consumers (SARIF merge, coverage records) are unchanged.

    Args:
        repo_path: Repository to scan.
        out_dir: Directory for SARIF + report outputs.
        languages: Explicit language list. None ⇒ auto-detect
            (recommended; the agent picks up everything in the
            repo and skips empty languages, vs the pre-unification
            "always create cpp/java/python/go DBs whether the repo
            has those files or not" approach).
        build_command: Optional CodeQL build command override
            (e.g. for compiled languages with non-standard layouts).
        traced_build: When True, forward ``--traced-build`` to the
            agent (traced-build CodeQL extraction for compiled
            languages). Default False adds no flag.

    Returns:
        List of absolute SARIF paths the agent wrote. Empty on any
        failure (logged); never raises.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    if shutil.which("codeql") is None:
        logger.warning("codeql CLI not on PATH; skipping CodeQL stage")
        return []

    # repo root → packages/codeql/agent.py. scanner.py lives at
    # packages/static-analysis/scanner.py so parents[2] is repo root.
    script_root = Path(__file__).resolve().parents[2]
    agent_script = script_root / "packages" / "codeql" / "agent.py"
    if not agent_script.exists():
        logger.warning("codeql agent script missing at %s; skipping CodeQL stage", agent_script)
        return []

    cmd = [
        sys.executable,
        str(agent_script),
        "--repo", str(repo_path),
        "--out", str(out_dir),
    ]
    if languages:
        cmd.extend(["--languages", ",".join(languages)])
    if build_command:
        cmd.extend(["--build-command", build_command])
    if traced_build:
        cmd.append("--traced-build")

    logger.info("Delegating CodeQL stage to %s", agent_script.name)
    # subprocess.run + timeout SIGKILLs the immediate child only,
    # leaving the agent's codeql grandchildren as orphans holding
    # cache locks + gigabytes of memory until they finish. This
    # path is NOT sandboxed (the agent does its own sandboxing of
    # the codeql calls), so namespace teardown isn't doing the
    # cleanup for us. Use Popen with start_new_session so the
    # agent becomes its own process group leader, then killpg on
    # timeout to flatten the whole tree. Sandboxed call sites
    # (adapters/codeql.py via make_sandbox_runner) don't need
    # this — their immediate child IS the namespace, and killing
    # the namespace kills everything inside.
    proc = None
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,
            env=RaptorConfig.get_safe_env(),
        )
        try:
            stdout, stderr = proc.communicate(timeout=3600)
            returncode = proc.returncode
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            logger.warning("codeql agent timed out after 3600s; skipping")
            return []
    except OSError as e:
        logger.warning("failed to invoke codeql agent: %s", e)
        return []

    if returncode == SANDBOX_ENGAGE_EXIT_CODE:
        # The codeql agent subprocess reported the sandbox could not engage.
        # Propagate as a hard failure rather than silently returning [] — the
        # /scan __main__ handler turns this into a fail-loud exit-3 abort.
        msg = (
            "the codeql agent subprocess reported the sandbox could not "
            f"engage (exit {SANDBOX_ENGAGE_EXIT_CODE})"
        )
        raise SandboxSetupError(
            msg,
            "re-run with --sandbox network-only (or --sandbox none). "
            "RAPTOR will not silently downgrade.",
        )

    if returncode != 0:
        # Surface the agent's stderr tail so the operator can see
        # WHY the run failed — language detection miscount, build
        # synthesis failure, trust-check rejection. Same truncation
        # rationale as before — codeql error output can run
        # thousands of lines.
        stderr_tail = (stderr or stdout or "").strip()
        if len(stderr_tail) > 2000:
            stderr_tail = "..." + stderr_tail[-2000:]
        logger.warning(
            "codeql agent exited rc=%s. Last stderr: %s", returncode, stderr_tail or '<empty>'
        )
        # Don't return early — the agent may have produced partial
        # SARIFs (one language succeeded, another failed). Glob and
        # return whatever's there.

    # Glob for the agent's SARIF outputs. Naming matches the old
    # in-tree runner so downstream code (SARIF merge, coverage
    # records, _classify_artifact) needs no changes.
    return sorted(str(p) for p in out_dir.glob("codeql_*.sarif"))


# ---------------------------------------------------------------------------
# Coccinelle (spatch) — C/C++ structural patterns
# ---------------------------------------------------------------------------


# Repo-language heuristic: same set of extensions as the
# /understand --hunt cocci backend (#457). Bounded so giant non-C
# repos don't pay an unbounded rglob.
_COCCI_C_EXTS: tuple = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh")


def _repo_has_c_cpp_source(repo_path: Path,
                           max_files_to_check: int = 200) -> bool:
    """Quick heuristic: does the target have C/C++ source? Used by
    the auto-skip for non-C/C++ targets (cocci is C-family only)."""
    if not repo_path.is_dir():
        return False
    seen = 0
    for entry in repo_path.rglob("*"):
        if not entry.is_file():
            continue
        seen += 1
        if entry.suffix.lower() in _COCCI_C_EXTS:
            return True
        if seen >= max_files_to_check:
            return False
    return False


def _shipped_cocci_rules_dir() -> Path | None:
    """Return the in-tree shipped-rules directory or None if it
    isn't present (minimal install / stripped tarball). The rules
    live at ``engine/coccinelle/rules/`` — distributed with RAPTOR,
    not generated."""
    here = Path(__file__).resolve()
    # packages/static-analysis/scanner.py → repo root → engine/...
    candidate = here.parents[2] / "engine" / "coccinelle" / "rules"
    if candidate.is_dir():
        return candidate
    return None


def run_cocci(
    repo_path: Path,
    out_dir: Path,
    rules_dir: Path | None = None,
    timeout: int = 300,
) -> list[str]:
    """Run Coccinelle's shipped rule set against ``repo_path`` and
    emit SARIF.

    Auto-skipped when:
      * spatch isn't on PATH (degrades silently — operators without
        cocci installed shouldn't see noise).
      * the target has no C/C++ source (cocci is C-family-only).
      * no shipped rules directory exists (defensive — minimal
        install / packaging strip).

    Returns the list of SARIF paths emitted (currently exactly one,
    ``cocci.sarif``, when the run produced any output). Empty list
    when skipped — same shape as ``run_codeql`` so the caller's
    ``sarif_inputs = semgrep_sarifs + codeql_sarifs + cocci_sarifs``
    union works without special-cases.

    Errors during individual rule runs are captured into the SARIF
    ``invocations[].toolExecutionNotifications`` so operators see
    them in the combined report rather than silently lost.
    """
    from packages.coccinelle.runner import (
        is_available as spatch_available,
    )
    from packages.coccinelle.runner import (
        run_rules as spatch_run_rules,
    )
    from packages.coccinelle.sarif import results_to_sarif

    if not spatch_available():
        logger.debug("cocci: spatch not on PATH; skipping")
        return []
    if not _repo_has_c_cpp_source(repo_path):
        logger.debug("cocci: target has no C/C++ source; skipping")
        return []

    effective_rules_dir = rules_dir or _shipped_cocci_rules_dir()
    if effective_rules_dir is None:
        logger.debug(
            "cocci: shipped rules dir not found "
            "(engine/coccinelle/rules/); skipping",
        )
        return []

    logger.info(
        "cocci: running %s against %s (timeout %ss/rule)", effective_rules_dir, repo_path, timeout
    )
    results = spatch_run_rules(
        target=repo_path,
        rules_dir=effective_rules_dir,
        timeout_per_rule=timeout,
        no_includes=True,  # operator targets are untrusted
        # In-repo shipped engine/coccinelle rules (code trust) — their
        # @script:python reporting blocks are trusted.
        allow_scripting=True,
    )

    sarif_doc = results_to_sarif(results, repo_path)
    sarif_path = out_dir / "cocci.sarif"
    save_json(sarif_path, sarif_doc)

    # Coverage record — the SARIF translation drops files_examined, so build it
    # from the spatch results (the true examined-set). Best-effort: a coverage
    # write must never fail the scan. Previously cocci's examined-set was
    # recorded nowhere, in any context.
    try:
        from core.coverage.record import build_from_cocci, write_record
        from packages.coccinelle.runner import version as _spatch_version
        cov = build_from_cocci(results, spatch_version=_spatch_version())
        if cov:
            write_record(out_dir, cov, tool_name="coccinelle")
    except Exception:
        logger.debug("cocci: coverage record write failed", exc_info=True)

    n_results = sum(len(r.matches) for r in results)
    n_errors = sum(len(r.errors or []) for r in results)
    logger.info(
        "cocci: %s matches across %d rules (%s rule-level errors); SARIF at %s",
        n_results,
        len(results),
        n_errors,
        sarif_path
    )
    return [str(sarif_path)]


# ---------------------------------------------------------------------------
# Compiler-analyzer scan (gcc -fanalyzer / clang --analyze) — opt-in
# ---------------------------------------------------------------------------


def _load_compiler_scan():
    """Load the compiler_scan sibling module via importlib.

    ``static-analysis`` is hyphenated → not importable as a Python
    package; same call-time importlib convention as ``_proxy_hosts``.
    Registered in ``sys.modules`` (dataclass processing resolves the
    defining module there) and memoised across calls.
    """
    import importlib.util as _importlib_util
    name = "static_analysis_compiler_scan"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).parent / "compiler_scan.py"
    spec = _importlib_util.spec_from_file_location(name, path)
    mod = _importlib_util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def run_compiler_scan_stage(
    repo_path: Path,
    out_dir: Path,
    max_tus: int | None = None,
) -> list[str]:
    """Run the compiler-analyzer scan channel and emit ``compiler.sarif``.

    Same channel as core.audit.compiler_sweep, opposite direction: the
    compiler's static analyzers run per-TU across the whole target and
    their diagnostics become scan findings for the dedup/analysis
    pipeline. Sandboxed, network-blocked, no build system — no repo
    code executes (see packages/static-analysis/compiler_scan.py).

    Auto-skipped (with a debug log) when the target has no C/C++
    source. A refused run (sandbox unavailable, no analyzer toolchain)
    is reported LOUDLY on stderr — never a silent empty result.

    Returns the list of SARIF paths emitted — same shape as
    ``run_codeql`` / ``run_cocci`` so the caller's ``sarif_inputs``
    union works without special cases.
    """
    if not _repo_has_c_cpp_source(repo_path):
        logger.debug("compiler-scan: target has no C/C++ source; skipping")
        return []

    cs = _load_compiler_scan()
    kwargs = {} if max_tus is None else {"max_tus": max_tus}
    result = cs.scan_target(repo_path, out_dir=out_dir, **kwargs)

    if not result.ok:
        print(
            f"⚠️  compiler-scan did not run: {result.reason}",
            file=sys.stderr,
        )
        return []

    sarif_path = out_dir / "compiler.sarif"
    save_json(sarif_path, cs.to_sarif(result))

    summary = result.summary_line()
    logger.info("%s; SARIF at %s", summary, sarif_path)
    if result.tus_skipped_cap or result.tus_failed:
        # Cap skips and failed TUs must reach the operator without
        # log-level spelunking — same posture as the failed-pack line.
        print(f"⚠️  {summary}", file=sys.stderr)
    return [str(sarif_path)]


# ---------------------------------------------------------------------------
# Expanded-view semgrep (fidelity-3 macro-hidden sink coverage) — opt-in
# ---------------------------------------------------------------------------


def run_expanded_semgrep_stage(
    repo_path: Path,
    out_dir: Path,
    rules_dirs: list[str],
    baseline_packs: list[tuple[str, str]],
    extra_configs: list[str] | None = None,
    max_tus: int | None = None,
) -> list[str]:
    """Re-run the loaded semgrep ruleset over fidelity-3 expanded views.

    Pattern rules miss anything hidden behind macros (LIST_FOREACH
    wrappers, lock macros, allocator wrappers). This stage expands
    macro-heavy C/C++ TUs through the real preprocessor
    (core.audit.preprocessor_view — sandboxed, no repo code executes),
    runs the same rule configs the plain stage ran over the expanded
    scratch tree, translates match lines back to ORIGINAL coordinates,
    and emits ``expanded_semgrep.sarif`` under a distinct tool name
    (``semgrep-expanded``) with an ``expanded_view`` marker on every
    result. Matches mapping into system headers or other files are
    dropped (noise by policy).

    Bounded by preprocessor_view's per-run expansion budget; skipped
    TUs are reported loudly. Best-effort per config — a failing pack
    never kills the stage.

    Returns the list of SARIF paths emitted (same shape as the other
    stage runners).
    """
    if not _repo_has_c_cpp_source(repo_path):
        logger.debug("expanded-semgrep: target has no C/C++ source; skipping")
        return []

    from core.audit import expanded_semgrep as es
    from packages.semgrep.runner import is_available as semgrep_available
    from packages.semgrep.runner import run_rule as semgrep_run_rule

    if not semgrep_available():
        print(
            "⚠️  expanded-semgrep did not run: semgrep not installed",
            file=sys.stderr,
        )
        return []

    scratch = Path(tempfile.mkdtemp(prefix="expanded_semgrep_", dir=str(out_dir)))
    try:
        kwargs = {} if max_tus is None else {"max_tus": max_tus}
        corpus = es.build_expanded_corpus(
            repo_path, scratch, out_dir=out_dir, **kwargs,
        )
        summary = corpus.summary_line()
        logger.info(summary)
        if corpus.skipped_budget:
            print(f"⚠️  {summary}", file=sys.stderr)
        if corpus.expanded == 0:
            return []

        # Same config set the plain stage ran: local rule dirs +
        # baseline packs + operator --extra-config, minus unreachable
        # registry packs.
        configs: list[tuple[str, str]] = []
        added_packs: set = set()
        for rd in rules_dirs:
            rd_path = Path(rd)
            if rd_path.exists():
                _cat = rd_path.stem if rd_path.is_file() else rd_path.name
                configs.append((f"category_{_cat}", str(rd_path)))
        for pack_name, pack_id in baseline_packs:
            if pack_id not in added_packs:
                configs.append(
                    (pack_name, RaptorConfig.get_semgrep_config(pack_id)),
                )
                added_packs.add(pack_id)
        configs.extend((f"extra_{_sanitize_pack_name(Path(extra).name)}", extra) for extra in extra_configs or [])
        configs = _drop_unreachable_registry_packs(configs)

        all_findings: list[dict] = []
        seen: set = set()
        total_dropped = 0
        failed_packs = 0
        for name, config in configs:
            try:
                res = semgrep_run_rule(
                    corpus.root, config, name=name,
                    timeout=RaptorConfig.SEMGREP_PACK_TIMEOUT,
                    env=RaptorConfig.get_safe_env(preserve_proxy=True),
                )
            except Exception as exc:  # noqa: BLE001 — one pack must not kill the stage
                logger.warning("expanded-semgrep: pack %s failed: %s", name, exc)
                failed_packs += 1
                continue
            if res.errors and not res.findings:
                logger.debug(
                    "expanded-semgrep: pack %s errors: %s", name, res.errors[:3],
                )
                failed_packs += 1
                continue
            translated, dropped = es.translate_corpus_findings(
                corpus, res.findings,
            )
            total_dropped += dropped
            for f in translated:
                key = (f["rule_id"], f["file"], f["line"])
                if key in seen:
                    continue
                seen.add(key)
                all_findings.append(f)

        if configs and failed_packs == len(configs):
            # Every pack failed: writing a zero-finding SARIF here
            # would read downstream as a clean expanded-semgrep run.
            # Surface the failure and emit nothing (mirrors the
            # graduated-rules stage's stderr failure tally).
            print(
                f"⚠️  expanded-semgrep stage FAILED: all "
                f"{len(configs)} pack(s) failed to run — no SARIF "
                f"emitted (a zero-finding result would be "
                f"indistinguishable from a clean scan)",
                file=sys.stderr,
            )
            logger.error(
                "expanded-semgrep: all %d packs failed; no SARIF emitted",
                len(configs),
            )
            return []
        if failed_packs:
            print(
                f"⚠️  expanded-semgrep: {failed_packs}/{len(configs)} "
                f"pack(s) failed to run",
                file=sys.stderr,
            )

        sarif_path = out_dir / "expanded_semgrep.sarif"
        save_json(sarif_path, es.findings_to_sarif(all_findings))
        logger.info(
            "expanded-semgrep: %d finding(s) at original coordinates "
            "(%d expanded-region matches dropped as noise); SARIF at %s",
            len(all_findings), total_dropped, sarif_path,
        )
        return [str(sarif_path)]
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# ---------------------------------------------------------------------------
# Graduated synthesized rules (P7) — default-on, opt-out
# ---------------------------------------------------------------------------

_GRADUATED_TOOL_NAME = "raptor-graduated"


def find_engine_rules_dir(out_dir: Path, repo_path: Path) -> Path | None:
    """Locate the project's graduated semgrep rules directory.

    Graduation (RuleLibrary.graduate / core.audit graduation) writes to
    ``<project_dir>/engine-rules/semgrep/rules/*.yaml``. Candidate
    resolution mirrors the run-directory layouts:

      * /scan with a project: ``out_dir`` is the run dir → sibling
        ``engine-rules`` under the project dir (``out_dir.parent``).
      * /agentic: the scanner child writes to ``<run_dir>/scan`` →
        two levels up.
      * the active project's ``output_dir`` (authoritative when set).

    SECURITY: only RAPTOR-graduated rules may load — a candidate that
    resolves inside the scanned repo is rejected, so a hostile target
    cannot plant YAML that runs as trusted scanner config.
    """
    repo_resolved = Path(repo_path).resolve()
    candidates = []
    out_resolved = Path(out_dir).resolve()
    candidates.append(out_resolved.parent / "engine-rules")
    candidates.append(out_resolved.parent.parent / "engine-rules")
    try:
        from core.project.project import ProjectManager
        mgr = ProjectManager()
        active = mgr.get_active()
        if active:
            proj = mgr.load(active)
            if proj is not None and getattr(proj, "output_dir", ""):
                candidates.append(Path(proj.output_dir) / "engine-rules")
    except Exception:
        logger.debug(
            "graduated-rules: active-project lookup failed", exc_info=True,
        )

    for candidate in candidates:
        rules_dir = candidate / "semgrep" / "rules"
        try:
            resolved = rules_dir.resolve()
        except OSError:
            continue
        if resolved == repo_resolved or repo_resolved in resolved.parents:
            logger.warning(
                "graduated-rules: refusing rules dir inside the scanned "
                "repo (%s) — repo-supplied YAML never loads", resolved,
            )
            # Security-event stream (restored: the scanner emitted
            # security events on suspicious-input rejection until the
            # a2f0255b restructure; the clone-URL emitter moved to
            # core/git, this is the scanner's own rejection path now).
            # Observability only — the `continue` above/below is the
            # behaviour; the emitter never raises.
            logger.log_security_event(
                "untrusted_rules_dir_rejected",
                "graduated-rules candidate resolves inside the scanned "
                "repo; repo-supplied YAML never loads as scanner config",
                rules_dir=str(resolved),
                repo=str(repo_resolved),
            )
            continue
        if rules_dir.is_dir() and any(rules_dir.glob("*.yaml")):
            return rules_dir
    return None


def run_graduated_rules_stage(
    repo_path: Path,
    out_dir: Path,
    rules_dir: Path | None = None,
) -> list[str]:
    """Run the project's graduated synthesized rules as a scan stage.

    Each graduated rule encodes a confirmed real-bug pattern
    (precision-gated at graduation: >=2 TPs, >=3 matches, >=80%).
    Runs every ``*.yaml`` under the engine-rules semgrep dir
    individually (one bad rule never kills the stage), and emits
    ``graduated.sarif`` under the distinct ``raptor-graduated`` tool
    name with ``properties.provenance = "synthesized:<rule_id>"`` on
    every result — so downstream analysis can key precision feedback
    (``RuleLibrary.record_match``) back to the originating rule.

    Auto-skips silently when no graduated rules exist. Returns the
    list of SARIF paths emitted (same shape as the other stage
    runners).
    """
    if rules_dir is None:
        rules_dir = find_engine_rules_dir(out_dir, repo_path)
    if rules_dir is None:
        logger.debug("graduated-rules: no engine-rules dir found; skipping")
        return []

    # Containment check also for operator-supplied dirs: rules that
    # live inside the scanned repo never load as scanner config.
    try:
        rules_resolved = Path(rules_dir).resolve()
        repo_resolved = Path(repo_path).resolve()
    except OSError:
        return []
    if rules_resolved == repo_resolved or repo_resolved in rules_resolved.parents:
        print(
            f"⚠️  graduated-rules: refusing rules dir inside the scanned "
            f"repo: {rules_resolved}",
            file=sys.stderr,
        )
        return []

    rule_files = sorted(Path(rules_dir).glob("*.yaml"))
    if not rule_files:
        return []

    try:
        from packages.semgrep.runner import is_available as semgrep_available
        from packages.semgrep.runner import run_rule as semgrep_run_rule
    except ImportError:
        return []
    if not semgrep_available():
        print(
            "⚠️  graduated-rules stage did not run: semgrep not installed",
            file=sys.stderr,
        )
        return []

    all_findings: list[tuple[str, dict]] = []
    failed = 0
    for rule_file in rule_files:
        rule_id = rule_file.stem
        try:
            res = semgrep_run_rule(
                Path(repo_path), str(rule_file),
                name=f"graduated_{rule_id}",
                timeout=RaptorConfig.SEMGREP_PACK_TIMEOUT,
                env=RaptorConfig.get_safe_env(preserve_proxy=True),
            )
        except Exception as exc:  # noqa: BLE001 — one rule must not kill the stage
            logger.warning("graduated-rules: %s failed: %s", rule_id, exc)
            failed += 1
            continue
        if res.errors and not res.findings:
            logger.debug(
                "graduated-rules: %s errors: %s", rule_id, res.errors[:3],
            )
            failed += 1
            continue
        all_findings.extend((rule_id, f.to_dict()) for f in res.findings)

    sarif_path = Path(out_dir) / "graduated.sarif"
    save_json(sarif_path, _graduated_findings_to_sarif(all_findings))
    logger.info(
        "graduated-rules: %d rule(s) ran (%d failed), %d finding(s); "
        "SARIF at %s",
        len(rule_files), failed, len(all_findings), sarif_path,
    )
    if failed:
        print(
            f"⚠️  graduated-rules: {failed}/{len(rule_files)} graduated "
            "rule(s) failed to run",
            file=sys.stderr,
        )
    return [str(sarif_path)]


def run_source_wrapper_stage(
    repo_path: Path,
    out_dir: Path,
) -> tuple[list[str], list[str]]:
    """Project mechanically-derived Java source-wrapper summaries into
    additional taint-source rules and run them as a scan stage.

    Sources are proofs from ``core.analysis.java_source_summaries``
    (a helper method whose return provably carries servlet-request
    data); sinks/sanitizers mirror the in-repo java rules. The
    generated YAML lives under the run output directory — never in
    the rules tree. Additive findings only, emitted as
    ``source-wrappers.sarif`` under the ``raptor-source-wrappers``
    tool name with rule ids prefixed ``source-wrapper:``. Auto-skips
    silently when the tree yields no summaries or tree-sitter java
    is unavailable.
    """
    try:
        from core.analysis.java_source_summaries import scan_tree
        from packages.semgrep.source_wrapper_rules import generate_rules_yaml
    except ImportError:
        return [], []
    try:
        summaries, refusals, scanned = scan_tree(Path(repo_path))
    except Exception as exc:  # noqa: BLE001 — stage must not kill the scan
        logger.warning("source-wrappers: scan failed: %s", exc)
        return [], []
    if not summaries:
        logger.debug(
            "source-wrappers: no qualifying wrappers "
            "(%d files scanned)", scanned)
        return [], []
    yaml_text = generate_rules_yaml(summaries)
    if not yaml_text:
        return [], []
    stage_dir = Path(out_dir) / "source-wrappers"
    stage_dir.mkdir(parents=True, exist_ok=True)
    rules_file = stage_dir / "rules.yaml"
    rules_file.write_text(yaml_text, encoding="utf-8")

    try:
        from packages.semgrep.runner import is_available as semgrep_available
        from packages.semgrep.runner import run_rule as semgrep_run_rule
    except ImportError:
        return [], []
    if not semgrep_available():
        print(
            "⚠️  source-wrapper stage did not run: semgrep not installed",
            file=sys.stderr,
        )
        return [], []
    try:
        res = semgrep_run_rule(
            Path(repo_path), str(rules_file),
            name="source_wrappers",
            timeout=RaptorConfig.SEMGREP_PACK_TIMEOUT,
            env=RaptorConfig.get_safe_env(preserve_proxy=True),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("source-wrappers: run failed: %s", exc)
        return [], []

    findings = [("wrapper", f.to_dict()) for f in res.findings]
    sarif_path = Path(out_dir) / "source-wrappers.sarif"
    doc = _stage_findings_to_sarif(
        findings,
        tool_name="raptor-source-wrappers",
        rule_prefix="source-wrapper",
        # CWE rides the SARIF rule properties — the recall matcher
        # never credits CWE-less findings (by doctrine), and the
        # downstream CWE dispatch keys off it too.
        cwe_by_suffix={
            ".xss": "CWE-79",
            ".trust-boundary": "CWE-501",
            ".sqli": "CWE-89",
            ".xpath": "CWE-643",
        },
    )
    save_json(sarif_path, doc)
    # The qualified wrapper names are run-scoped learned vocabulary:
    # the sanitizer-cut post-pass's source locator only knows the
    # direct servlet getters, so a finding whose taint enters via
    # scr.getTheParameter(...) has no locatable source without them.
    wrapper_names = sorted({s.name for s in summaries})
    save_json(stage_dir / "wrappers.json", {
        "wrapper_methods": wrapper_names,
        "provenance": "mechanical-summary",
    })
    logger.info(
        "source-wrappers: %d wrapper(s) projected, %d finding(s); "
        "SARIF at %s (refusal top: %s)",
        len(summaries), len(findings), sarif_path,
        sorted(refusals.items(), key=lambda kv: -kv[1])[:3],
    )
    return [str(sarif_path)], wrapper_names


def _stage_findings_to_sarif(
    findings: list[tuple[str, dict]],
    *,
    tool_name: str,
    rule_prefix: str,
    cwe_by_suffix: dict[str, str] | None = None,
) -> dict:
    """SARIF doc for a generated-rule stage; same shape discipline as
    the graduated stage (distinct tool name, provenance in ruleId)."""
    rule_defs: list[dict] = []
    seen_rules: set = set()
    results: list[dict] = []
    for rule_id, f in findings:
        sarif_rule_id = (
            f.get("rule_id") or f"{rule_prefix}:{rule_id}"
        )
        if not str(sarif_rule_id).startswith(rule_prefix):
            sarif_rule_id = f"{rule_prefix}:{sarif_rule_id}"
        if sarif_rule_id not in seen_rules:
            rule_def = {
                "id": sarif_rule_id,
                "name": sarif_rule_id,
                "shortDescription": {"text": sarif_rule_id},
                "defaultConfiguration": {"level": "warning"},
            }
            for suffix, cwe in (cwe_by_suffix or {}).items():
                if str(sarif_rule_id).endswith(suffix):
                    rule_def["properties"] = {"cwe": cwe}
                    break
            rule_defs.append(rule_def)
            seen_rules.add(sarif_rule_id)
        results.append({
            "ruleId": sarif_rule_id,
            "level": f.get("level") or "warning",
            "message": {
                "text": f.get("message") or f"{rule_prefix} rule matched",
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.get("file") or f.get("path") or "",
                    },
                    "region": {
                        "startLine": f.get("line")
                                     or f.get("start_line") or 1,
                        "endLine": f.get("line_end")
                                   or f.get("end_line")
                                   or f.get("line")
                                   or f.get("start_line") or 1,
                    },
                },
            }],
            "properties": {"provenance": "mechanical-source-summary"},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": tool_name,
                "informationUri": "https://github.com/anthropics",
                "rules": rule_defs,
            }},
            "results": results,
        }],
    }


def _graduated_findings_to_sarif(
    findings: list[tuple[str, dict]],
) -> dict:
    """SARIF 2.1.0 document for graduated-rule findings.

    Distinct ``tool.driver.name`` keeps these a separate run in
    combined.sarif. Provenance rides the ``ruleId`` itself
    (``synthesized:<library_rule_id>``) because the downstream SARIF
    parser (core/sarif/parser.py) keeps rule_id but drops result
    properties — the precision-feedback loop keys
    ``RuleLibrary.record_match`` off this prefix. The semgrep-internal
    rule id (LLM-chosen kebab-case) is preserved in properties for
    forensics.
    """
    rule_defs: list[dict] = []
    seen_rules: set = set()
    results: list[dict] = []
    for rule_id, f in findings:
        sarif_rule_id = f"synthesized:{rule_id}"
        if sarif_rule_id not in seen_rules:
            rule_defs.append({
                "id": sarif_rule_id,
                "name": sarif_rule_id,
                "shortDescription": {"text": sarif_rule_id},
                "defaultConfiguration": {"level": "warning"},
            })
            seen_rules.add(sarif_rule_id)
        results.append({
            "ruleId": sarif_rule_id,
            "level": f.get("level") or "warning",
            "message": {
                "text": f.get("message")
                        or f"graduated rule {rule_id} matched",
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("file", "")},
                    "region": {"startLine": f.get("line", 0)},
                },
            }],
            "properties": {
                "provenance": sarif_rule_id,
                "semgrep_rule_id": f.get("rule_id", ""),
            },
        })
    return {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": _GRADUATED_TOOL_NAME,
                    "informationUri": "https://github.com/anthropics/raptor",
                    "rules": rule_defs,
                },
            },
            "results": results,
        }],
    }


def _sarif_has_findings(sarif_path: Path) -> bool:
    """Return True iff the SARIF file contains at least one result.

    Failures (missing file, unparseable JSON) return False — callers treat
    "unknown" the same as "empty" because the goal is opportunistic cleanup.
    """
    data = load_json(sarif_path, max_bytes=_MAX_TOOL_JSON_BYTES)
    if not isinstance(data, dict):
        return False
    return any(run_obj.get("results") for run_obj in data.get("runs", []) or [])


def cleanup_per_pack_artifacts(out_dir: Path) -> int:
    """Remove redundant per-pack semgrep files after combined.sarif is written.

    Per-pack files (semgrep_<suffix>.{exit,json,sarif,stderr.log}) are
    intermediate: combined.sarif is the canonical post-merge artefact, and
    scan_metrics.json captures the per-run accounting. Keep the minimum
    needed for post-mortem of failed packs.

    Cleanup rules (per pack):
      - Always remove: .exit, .json, empty .stderr.log
      - On exit in (0, 1): also remove .sarif (semgrep returns 1 on findings)
      - On exit>=2: keep .exit, keep non-empty .stderr.log, keep .sarif if
        it has findings; delete the .sarif if it is empty/zero-results
        (still redundant — combined.sarif holds those results too)

    Strict glob (semgrep_*.{exit,json,sarif,stderr.log}) and os.unlink
    only — never follow symlinks or recurse.

    Returns the number of files removed.
    """
    removed = 0
    # Group by suffix using a strict glob set.
    suffixes: set = set()
    for ext in (".exit", ".json", ".sarif", ".stderr.log"):
        for p in out_dir.glob(f"semgrep_*{ext}"):
            # glob does not follow symlinks for matching, but the resolved
            # entry might still be one — defend with is_symlink check.
            if p.is_symlink() or not p.is_file():
                continue
            name = p.name[len("semgrep_"):-len(ext)]
            if name:
                suffixes.add(name)

    for suffix in suffixes:
        exit_file = out_dir / f"semgrep_{suffix}.exit"
        json_file = out_dir / f"semgrep_{suffix}.json"
        sarif_file = out_dir / f"semgrep_{suffix}.sarif"
        stderr_file = out_dir / f"semgrep_{suffix}.stderr.log"

        # Read exit code BEFORE any deletion.
        exit_code: int | None
        try:
            exit_code = int(exit_file.read_text(encoding="utf-8").strip())
        except Exception:  # noqa: BLE001
            exit_code = None

        success = exit_code in (0, 1)

        # Always delete: .json (intermediate machine output)
        for victim in (json_file,):
            try:
                if victim.is_file() and not victim.is_symlink():
                    os.unlink(victim)
                    removed += 1
            except FileNotFoundError:
                pass
            except OSError as e:
                logger.debug("cleanup: could not remove %s: %s", victim, e)

        # Empty stderr — always delete
        try:
            if (stderr_file.is_file() and not stderr_file.is_symlink()
                    and stderr_file.stat().st_size == 0):
                os.unlink(stderr_file)
                removed += 1
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.debug("cleanup: could not stat/remove %s: %s", stderr_file, e)

        if success:
            # On success, .exit and .sarif are both redundant (combined.sarif
            # is canonical and metrics record the success).
            for victim in (exit_file, sarif_file):
                try:
                    if victim.is_file() and not victim.is_symlink():
                        os.unlink(victim)
                        removed += 1
                except FileNotFoundError:
                    pass
                except OSError as e:
                    logger.debug("cleanup: could not remove %s: %s", victim, e)
        # Failed pack: keep .exit. Keep .sarif only if it has findings;
        # otherwise it is redundant noise (an empty {"runs":[]} stub).
        elif sarif_file.is_file() and not sarif_file.is_symlink():  # noqa: SIM102
            if not _sarif_has_findings(sarif_file):
                try:
                    os.unlink(sarif_file)
                    removed += 1
                except OSError as e:
                    logger.debug("cleanup: could not remove %s: %s", sarif_file, e)

    if removed:
        logger.info("Cleaned up %s redundant per-pack scan files in %s", removed, out_dir)
    return removed


def _count_sarif_results(sarif_data) -> int:
    """Return the total number of results across runs in a parsed SARIF dict.

    Tolerates malformed shapes — non-dict / non-list members count as zero
    rather than raising. This is a provenance signal, not a validator.
    """
    if not isinstance(sarif_data, dict):
        return 0
    total = 0
    for run_obj in sarif_data.get("runs", []) or []:
        if not isinstance(run_obj, dict):
            continue
        results = run_obj.get("results") or []
        if isinstance(results, list):
            total += len(results)
    return total


def _pack_provenance_from_sarif(sarif_path: Path, out_dir: Path) -> dict:
    """Compute provenance for one per-pack SARIF.

    MUST be called before cleanup_per_pack_artifacts() runs, because
    cleanup deletes the per-pack SARIF / .exit / .stderr.log it depends on.

    Returns a dict with keys:
        tool, name, exit, findings, sarif_sha256, stderr_size_bytes
    Missing-file and parse failures degrade to safe defaults rather
    than raising — provenance is best-effort.
    """
    p = Path(sarif_path)
    stem = p.stem  # e.g. "semgrep_category_auth" or "codeql_cpp"
    if stem.startswith("semgrep_"):
        tool = "semgrep"
        name = stem[len("semgrep_"):]
    elif stem.startswith("codeql_"):
        tool = "codeql"
        name = stem[len("codeql_"):]
    else:
        tool = "unknown"
        name = stem

    # Hash + size + findings — read bytes once.
    # Size cap (128 MiB) — a hostile rule-pack producing arbitrarily
    # large SARIF would otherwise OOM the post-scan analysis.
    _SARIF_MAX_BYTES = 128 * 1024 * 1024
    try:
        if p.stat().st_size > _SARIF_MAX_BYTES:
            # Treat oversize SARIF as unreadable — the enclosing
            # OSError branch handles the messaging.
            msg = f"SARIF exceeds {_SARIF_MAX_BYTES}-byte cap"
            raise OSError(msg)
        raw = p.read_bytes()
        sarif_sha256 = sha256_bytes(raw)
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except Exception:  # noqa: BLE001
            data = None
        findings = _count_sarif_results(data) if data is not None else 0
    except OSError:
        # Missing (FileNotFoundError) or unreadable (EACCES, EIO, …)
        # — best-effort provenance, leave hash empty.
        sarif_sha256 = ""
        findings = 0

    # Exit code: only semgrep packs write a .exit file. CodeQL only emits
    # a SARIF on rc==0 (run_codeql appends only on success), so 0 is
    # accurate when we can see the SARIF.
    if tool == "semgrep":
        exit_file = out_dir / f"{stem}.exit"
        try:
            exit_code = int(exit_file.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            exit_code = -1
    else:
        exit_code = 0

    # Stderr size: again, semgrep-specific. CodeQL doesn't emit one in
    # the per-pack pattern; report 0.
    stderr_log = out_dir / f"{stem}.stderr.log"
    try:
        stderr_size = stderr_log.stat().st_size
    except (OSError, FileNotFoundError):
        stderr_size = 0

    return {
        "tool": tool,
        "name": name,
        "exit": exit_code,
        "findings": findings,
        "sarif_sha256": sarif_sha256,
        "stderr_size_bytes": stderr_size,
    }


def _compose_verification_manifest(
    sarif_inputs, combined_sarif: Path, out_dir: Path,
) -> dict:
    """Build the verification.json provenance manifest.

    Computes per-pack hashes from the per-pack SARIFs while they're still
    on disk — caller MUST invoke this before cleanup_per_pack_artifacts().
    """
    packs = [_pack_provenance_from_sarif(Path(p), out_dir) for p in sarif_inputs]

    combined: dict = {"path": combined_sarif.name}
    try:
        raw = combined_sarif.read_bytes()
        combined["sha256"] = sha256_bytes(raw)
        combined["size_bytes"] = len(raw)
    except FileNotFoundError:
        combined["sha256"] = ""
        combined["size_bytes"] = 0

    return {
        "schema_version": 1,
        "combined_sarif": combined,
        "packs": packs,
    }


def _validate_policy_groups(
    ap: argparse.ArgumentParser, policy_groups: str,
) -> None:
    """Hard-fail (argparse exit 2) on unknown or reserved policy
    groups, naming the valid ones. ``all`` is always accepted."""
    groups = [g.strip() for g in policy_groups.split(",") if g.strip()]
    excluded = {"registry-cache"}
    try:
        valid = sorted(
            p.name for p in RaptorConfig.SEMGREP_RULES_DIR.iterdir()
            if p.is_dir() and p.name not in excluded
        )
    except OSError:
        # Rules dir unreadable — the scan itself will surface that;
        # don't turn every invocation into a usage error here.
        return
    bad = [g for g in groups if g != "all" and g not in valid]
    if bad:
        ap.error(
            f"unknown policy group(s): {', '.join(sorted(set(bad)))}. "
            f"Valid groups: all, {', '.join(valid)}"
        )


def main() -> None:
    ap = argparse.ArgumentParser(description="RAPTOR Automated Code Security Agent with parallel scanning")
    ap.add_argument("--repo", required=True, help="Path or Git URL")
    # Argparse accepts BOTH the hyphenated (`--policy-version`,
    # `--policy-groups`) and underscore (`--policy_version`,
    # `--policy_groups`) forms. The hyphenated form is canonical
    # — matches the rest of the CLI surface (`--no-sandbox`,
    # `--audit-verbose`) and POSIX convention. Underscore form
    # retained as alias because docs/scripts in the wild used
    # the underscore variant before this PR; removing them
    # would break operator workflows that hard-coded the old
    # spelling.
    ap.add_argument(
        "--policy-version", "--policy_version",
        default=RaptorConfig.DEFAULT_POLICY_VERSION,
        dest="policy_version",
    )
    ap.add_argument(
        "--policy-groups", "--policy_groups",
        default=RaptorConfig.DEFAULT_POLICY_GROUPS,
        dest="policy_groups",
        help="Comma-separated list of rule group names (e.g. crypto,secrets,injection,auth,all)",
    )
    ap.add_argument(
        "--codeql", action="store_true",
        help="Run CodeQL stage. Delegates to packages/codeql/agent.py — the "
             "same engine /codeql uses (auto-language-detection, build "
             "synthesis, content-addressed DB cache, trust check). Off by "
             "default to keep /scan fast; use --no-codeql to assert opt-out.",
    )
    ap.add_argument(
        "--no-codeql", action="store_true",
        help="Explicitly disable the CodeQL stage. Takes precedence over "
             "--codeql. Useful in scripts that want a guaranteed Semgrep-only "
             "scan regardless of what defaults change in future.",
    )
    ap.add_argument(
        "--no-cocci", action="store_true",
        help="Disable the Coccinelle (spatch) stage. By default cocci runs "
             "automatically when (a) spatch is on PATH and (b) the target has "
             "C/C++ source. Catches structural patterns (missing NULL checks, "
             "lock imbalance, unchecked returns) Semgrep doesn't model "
             "AST-level. Auto-skips silently when the prerequisites aren't "
             "met; this flag is for the explicit-opt-out case in scripts.",
    )
    ap.add_argument(
        "--compiler-scan", action="store_true",
        dest="compiler_scan",
        help="Run the compiler-analyzer scan channel: gcc -fanalyzer / "
             "clang --analyze per C/C++ translation unit, diagnostics become "
             "scan findings alongside Semgrep/CodeQL. Sandboxed, network "
             "blocked, no build system — no repo code executes. Off by "
             "default (operator opt-in).",
    )
    ap.add_argument(
        "--no-compiler-scan", action="store_true",
        dest="no_compiler_scan",
        help="Explicitly disable the compiler-analyzer scan stage. Takes "
             "precedence over --compiler-scan; script-friendly opt-out if "
             "defaults change in future.",
    )
    ap.add_argument(
        "--compiler-scan-max-tus", type=int, default=None, metavar="N",
        dest="compiler_scan_max_tus",
        help="Cap the number of translation units the compiler-analyzer "
             "scan compiles (default 2000). Skipped TUs are reported "
             "loudly, never silently truncated.",
    )
    ap.add_argument(
        "--expanded-semgrep", action="store_true",
        dest="expanded_semgrep",
        help="Re-run the loaded Semgrep ruleset over fidelity-3 "
             "preprocessor-expanded views of macro-heavy C/C++ TUs, with "
             "matches line-mapped back to original coordinates — catches "
             "sinks hidden behind macros (LIST_FOREACH wrappers, allocator "
             "macros). Budget-bounded; preprocessing is sandboxed and no "
             "repo code executes. Off by default (operator opt-in).",
    )
    ap.add_argument(
        "--no-sanitizer-cut-postpass", action="store_true",
        dest="no_sanitizer_cut_postpass",
        help="Disable the record-only sanitizer-cut post-pass. By "
             "default eligible findings (CWE with catalog sanitizers, "
             "supported language) are evaluated by the value-bound "
             "gate and suppress/candidate verdicts are recorded to "
             "suppressions.jsonl as evidence (dropped: false). The "
             "post-pass never drops or demotes a finding in any mode; "
             "this flag skips it entirely.",
    )
    ap.add_argument(
        "--no-sanitizer-cut-enforce", action="store_true",
        dest="no_sanitizer_cut_enforce",
        help="Run the sanitizer-cut post-pass in record-only mode: "
             "full-proof suppress verdicts are written as evidence "
             "(dropped: false) but no finding is removed from the "
             "combined SARIF. Default is enforcement (corpus-earned, "
             "operator-approved 2026-08-19; per-tool SARIFs are never "
             "filtered in any mode).",
    )
    ap.add_argument(
        "--no-config-resolved", action="store_true",
        dest="no_config_resolved",
        help="Disable the config-resolved additive findings stage. By "
             "default Java getInstance-family selector calls whose "
             "argument resolves through the strict .properties-file "
             "resolver to a known-weak algorithm emit an additional "
             "finding (provenance=config-resolved). Detection only — "
             "the stage never suppresses anything.",
    )
    ap.add_argument(
        "--no-source-wrappers", action="store_true",
        dest="no_source_wrappers",
        help="Skip the source-wrapper projection stage (mechanically "
             "derived Java taint-source rules for helper classes whose "
             "methods return servlet-request data).",
    )
    ap.add_argument(
        "--no-graduated-rules", action="store_true",
        dest="no_graduated_rules",
        help="Disable the graduated synthesized-rules stage. By default "
             "every scan runs the active project's precision-gated "
             "graduated rules (engine-rules/semgrep/rules/) as a "
             "standard stage — each encodes a previously confirmed "
             "real-bug pattern. Auto-skips silently when no graduated "
             "rules exist; this flag is the explicit opt-out.",
    )
    ap.add_argument(
        "--graduated-rules-dir", default=None, metavar="DIR",
        dest="graduated_rules_dir",
        help="Explicit graduated-rules directory (the semgrep/rules "
             "subdir of an engine-rules tree). Overrides project-based "
             "auto-resolution. Path-validated: a directory inside the "
             "scanned repo is refused.",
    )
    ap.add_argument(
        "--languages",
        help="Comma-separated language list for CodeQL (e.g. cpp,java). "
             "Operator-friendly aliases (c, c++, js, ts, c#, kt, py) are "
             "normalised. Default: auto-detect, which only creates DBs for "
             "languages actually present in the repo.",
    )
    ap.add_argument(
        "--build-command",
        help="Override CodeQL's build command for compiled languages. "
             "Forwarded to packages/codeql/agent.py --build-command.",
    )
    ap.add_argument(
        "--traced-build", action="store_true",
        help="Opt into traced-build C/C++ CodeQL extraction (executes the "
             "repo's build system — asserts trust in the repo). Default is "
             "buildless: no repo code runs during database creation. "
             "Forwarded to packages/codeql/agent.py --traced-build.",
    )
    ap.add_argument(
        "--no-traced-build", action="store_true",
        help="Force buildless CodeQL extraction for this run, overriding "
             "--traced-build. Per-run escape hatch.",
    )
    ap.add_argument("--keep", action="store_true", help="Keep temp working directory")
    ap.add_argument("--sequential", action="store_true", help="Fully serial run: semgrep packs one at a time AND stages in order (no semgrep/codeql overlap). Debugging knob.")
    ap.add_argument("--out", default=None, help="Output directory (from lifecycle). Overrides auto-generated path.")
    ap.add_argument(
        "--exclude-dir", action="append", default=None, metavar="GLOB",
        dest="exclude_dir",
        help=(
            "Drop SARIF results whose file URI matches GLOB. Repeatable "
            "(OR semantics). Applied post-merge to the combined.sarif + "
            "scan_metrics; individual per-tool SARIFs stay unfiltered as "
            "forensic record of what each tool actually emitted. Operator "
            "escape hatch for vendored / test / generated paths. Example: "
            "``--exclude-dir 'vendor/*' --exclude-dir '**/tests/*'``"
        ),
    )
    ap.add_argument(
        "--extra-config", action="append", default=None, metavar="PATH",
        dest="extra_config",
        help=(
            "Additional semgrep rule source — a YAML rule file or a directory "
            "of rules. Each value becomes a peer scan alongside the registry "
            "packs (its own SARIF, merged into combined results). Repeatable. "
            "Path must exist at parse time. RAPTOR never picks up ambient "
            "``~/.semgrep/rules`` from the operator's HOME (sandbox stays "
            "hermetic + reproducible across machines); this flag is the "
            "explicit opt-in channel for custom rules. Example: "
            "``--extra-config ./my-rules.yml --extra-config /etc/sec/policy/``"
        ),
    )

    ap.add_argument(
        "--show-suppressed", action="store_true",
        dest="show_suppressed",
        help="Include nosemgrep-suppressed findings in the output summary. "
             "The SARIF always contains all findings regardless of this flag; "
             "it only controls the presentation layer.",
    )

    from core.sandbox import add_cli_args, apply_cli_args
    add_cli_args(ap)
    args = ap.parse_args()
    apply_cli_args(args, parser=ap)

    # Unknown policy groups are an argparse-level HARD error. Pre-fix
    # they only logged a warning mid-scan — an operator copying a bad
    # example (`--policy-groups injction`) got a scan that silently
    # ran without the intended rules and never found out. Fail fast,
    # before any clone / output-dir work, listing the valid groups.
    _validate_policy_groups(ap, args.policy_groups)

    # Explicit negative beats positive (per-run escape hatch; project
    # trust-marker consumption lives in the /agentic and /codeql entry
    # points which resolve markers before forwarding --traced-build).
    if getattr(args, "no_traced_build", False):
        args.traced_build = False

    # Validate --extra-config paths upfront. Fail-loud on bad input so the
    # operator finds out before a 30-minute scan has burnt its budget. The
    # resolved absolute path replaces the operator-supplied string so the
    # downstream semgrep invocation gets a stable, ambient-CWD-free
    # reference. Dedup by resolved path — passing the same rule file twice
    # (often a copy-paste mistake on the command line) silently doubled
    # the pack count + double-counted findings in pre-dedup runs.
    if args.extra_config:
        _resolved_extra: list[str] = []
        _seen: set = set()
        for raw in args.extra_config:
            p = Path(raw).expanduser()
            if not p.exists():
                ap.error(f"--extra-config: path does not exist: {raw}")
            resolved = str(p.resolve())
            if resolved in _seen:
                logger.warning(
                    "--extra-config: duplicate path on CLI dropped: %s",
                    raw,
                )
                continue
            _seen.add(resolved)
            _resolved_extra.append(resolved)
        args.extra_config = _resolved_extra

    start_time = time.time()
    tmp = Path(tempfile.mkdtemp(prefix="raptor_auto_"))
    repo_path = None

    logger.info("Starting automated code security scan")
    logger.info("Repository: %s", args.repo)
    logger.info("Policy version: %s", args.policy_version)
    logger.info("Policy groups: %s", args.policy_groups)

    try:
        # Acquire repository
        if args.repo.startswith(("http://", "https://", "git@")):
            repo_path = tmp / "repo"
            clone_repository(args.repo, repo_path)
        else:
            repo_path = Path(args.repo).resolve()
            if not repo_path.exists():
                msg = f"repository path does not exist: {repo_path}"
                raise RuntimeError(msg)

        # Determine local rule directories
        groups = [g.strip() for g in args.policy_groups.split(",") if g.strip()]
        rules_base = RaptorConfig.SEMGREP_RULES_DIR
        _EXCLUDED_RULE_DIRS = {"registry-cache"}
        if "all" in groups:
            rules_dirs = [
                str(p) for p in sorted(rules_base.iterdir())
                if p.is_dir() and p.name not in _EXCLUDED_RULE_DIRS
            ]
        else:
            valid, unknown = [], []
            for g in groups:
                p = rules_base / g
                rule_file = RaptorConfig.POLICY_GROUP_RULE_FILES.get(g)
                if g in _EXCLUDED_RULE_DIRS:
                    logger.warning("Policy group '%s' is reserved and cannot be used directly", g)
                elif p.is_dir():
                    valid.append(str(p))
                elif rule_file is not None and rule_file.is_file():
                    # Single-file group (e.g. ssrf → sinks/ssrf.yaml) —
                    # the rules live inside another group's directory.
                    valid.append(str(rule_file))
                else:
                    unknown.append(g)
            if unknown:
                logger.warning(
                    "Unknown policy groups (no rule directory found): %s", ', '.join(unknown)
                )
            rules_dirs = valid

        logger.info("Using %d rule directories", len(rules_dirs))

        # Output directory: use --out if provided (lifecycle), otherwise generate
        if args.out:
            out_dir = Path(args.out)
        else:
            repo_name = repo_path.name
            # Collision-prevention via unique_run_suffix — see core/run/output.py.
            out_dir = RaptorConfig.get_out_dir() / f"scan_{repo_name}_{unique_run_suffix('_')}"
        out_dir.parent.mkdir(parents=True, exist_ok=True)
        safe_run_mkdir(out_dir)

        # Make record_denial calls (proxy events, generic Landlock
        # denials) write to THIS subprocess's out_dir. Without this,
        # active_run_dir is None → record_denial is no-op → events
        # silently dropped. The lifecycle hook in raptor.py wires
        # this for top-level invocations; for the agentic flow,
        # scanner.py runs as a subprocess and must wire it itself.
        # summarize_and_write at end-of-main converts the JSONL to
        # sandbox-summary.json.
        from core.sandbox.summary import set_active_run_dir
        set_active_run_dir(out_dir)

        # Manifest
        logger.info("Computing repository hash...")
        repo_hash = sha256_tree(repo_path)

        manifest = {
            "agent": "auto_codesec",
            "version": "2.0.0",  # Updated version with parallel scanning
            "repo_path": str(repo_path),
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "input_hash": repo_hash,
            "policy_version": args.policy_version,
            "policy_groups": groups,
            "parallel_scanning": not args.sequential,
        }
        save_json(out_dir / "scan-manifest.json", manifest)

        # Semgrep stage - Use parallel scanning by default. Resolve
        # the baseline pack set via the target-type catalog (QoL
        # #7-7b: per-target tuning) — catalog entry for the matched
        # target type provides ``semgrep_packs.default``; falls back
        # to the hardcoded RaptorConfig.BASELINE_SEMGREP_PACKS when
        # no catalog match. Surface the resolved set + source so the
        # operator sees WHY a particular pack list ran.
        resolved_baseline = _resolve_baseline_packs(repo_path)
        if list(resolved_baseline) != list(RaptorConfig.BASELINE_SEMGREP_PACKS):
            try:
                from core.run.target_types import load as _load_tt
                _tt = _load_tt(repo_path)
                _tt_name = _tt.name if _tt else "unknown"
            except Exception:  # noqa: BLE001
                _tt_name = "unknown"
            _names = [n for n, _ in resolved_baseline]
            logger.info("Semgrep baseline packs for target type '%s': %s", _tt_name, _names)
        # Per-pack language applicability (QoL #16a). Tells the
        # operator how many rules in each baseline pack actually
        # match the target's language(s) — without this they read
        # ``6 rule-group(s)`` and assume thousands of rules
        # apply, when the upstream registry coverage for their
        # language may be much thinner. Silent on no-target-lang
        # or no-cached-pack-data (we won't fabricate a count).
        _target_langs = _target_semgrep_languages(repo_path)
        _applicability = _format_pack_applicability(
            list(resolved_baseline), _target_langs,
        )
        if _applicability:
            logger.info(_applicability)
            # Escalation hint when applicability is thin —
            # surface the alternative paths now so the operator
            # doesn't think the framework's silent under-scan IS
            # the verdict on the target. Omit when --codeql is
            # already running (would suggest something happening).
            if _is_coverage_thin(
                list(resolved_baseline), _target_langs,
            ):
                _codeql_running = (
                    args.codeql and not args.no_codeql
                )
                logger.info(_format_thin_coverage_hint(
                    _target_langs, _codeql_running,
                    llm_configured=_llm_configured(),
                ))
        logger.info("Starting Semgrep scans...")
        # CodeQL stage overlap: the two heavyweight stages are
        # independent SARIF producers, and the CodeQL DB build is
        # usually the critical path — start it before the Semgrep
        # packs so both run concurrently. --sequential keeps the
        # fully serial order (debugging knob for both kinds of
        # parallelism). Each stage's internal parallelism already
        # shares the host (per-pack --jobs / per-build -j division);
        # the transient 2:1 overlap is deliberate — the DB build's
        # extractor phases are I/O-heavy while Semgrep is CPU-bound,
        # and a hard split would idle cores for whichever stage
        # finishes first.
        run_codeql_stage = args.codeql and not args.no_codeql
        _codeql_future = None
        _codeql_pool = None
        _codeql_t0 = 0.0
        _stage_tag = _CodeQLStageTag()
        if run_codeql_stage and not args.sequential:
            _langs_arg = (
                [x.strip() for x in args.languages.split(",") if x.strip()]
                if args.languages else None  # None ⇒ agent auto-detects
            )
            print("⏱  Semgrep and CodeQL stages running concurrently "
                  "(CodeQL lines tagged [codeql])", flush=True)
            logging.getLogger().addFilter(_stage_tag)
            _codeql_pool = ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="codeql-stage")
            _codeql_t0 = time.time()
            _codeql_future = _codeql_pool.submit(
                run_codeql, repo_path, out_dir,
                languages=_langs_arg,
                build_command=args.build_command,
                traced_build=args.traced_build,
            )

        if args.sequential:
            # Fallback to sequential for debugging
            logger.warning("Sequential scanning enabled (slower)")
            semgrep_sarifs, semgrep_failed = semgrep_scan_sequential(
                repo_path, rules_dirs, out_dir,
                baseline_packs=resolved_baseline,
                extra_configs=args.extra_config,
            )
        else:
            semgrep_sarifs, semgrep_failed = semgrep_scan_parallel(
                repo_path, rules_dirs, out_dir,
                baseline_packs=resolved_baseline,
                extra_configs=args.extra_config,
            )

        # Surface failed-pack count on stderr — at scan-level so the
        # operator sees it without trawling the run's log file. The
        # logger.warning inside semgrep_scan_parallel writes to the
        # configured log handler (DEBUG/INFO level depending on -v);
        # the stderr line below is unconditional and operator-facing.
        if semgrep_failed:
            print(
                f"⚠️  semgrep: {len(semgrep_failed)} pack(s) failed or "
                f"produced no SARIF: {', '.join(semgrep_failed)}",
                file=sys.stderr,
            )

        # CI-gate signal — "every dispatched semgrep pack failed" means
        # the scan produced no useful output. Pre-fix this exited 0
        # regardless: an operator running ``raptor scan`` as a pre-merge
        # gate on a broken sandbox would silently false-pass with "0
        # findings". Detect at the dispatch boundary (sarif_paths has
        # one entry per dispatched pack — success or fail; failed_scans
        # is the failure subset). When the two lengths match and packs
        # were attempted, surface as a distinct exit code at the final
        # sys.exit below. The reserved SANDBOX_ENGAGE_EXIT_CODE stays
        # for the actual sandbox-engagement-failure path (raised as
        # SandboxSetupError); ``4`` is the all-packs-failed signal.
        all_semgrep_failed = (
            len(semgrep_sarifs) > 0
            and len(semgrep_failed) == len(semgrep_sarifs)
        )
        if all_semgrep_failed:
            print(
                f"\nRAPTOR: scan produced no useful semgrep output — "
                f"all {len(semgrep_sarifs)} dispatched pack(s) failed. "
                f"Exiting 4 (CI-gate signal — distinct from "
                f"sandbox-engagement-failure exit "
                f"{SANDBOX_ENGAGE_EXIT_CODE}).",
                file=sys.stderr,
            )

        # CodeQL stage (optional). --no-codeql takes precedence —
        # script-friendly so a default-flip from "off" to "on" can
        # be opted out of without code changes. When the stage was
        # started concurrently above, join it here; the merge below
        # needs its SARIFs either way.
        codeql_sarifs = []
        if _codeql_future is not None:
            try:
                codeql_sarifs = _codeql_future.result()
            except Exception as e:  # noqa: BLE001 — stage isolation: semgrep results must survive
                logger.error("CodeQL stage raised: %s", e)
                print(f"⚠️  CodeQL stage failed: {e}", file=sys.stderr)
            finally:
                _codeql_pool.shutdown(wait=False)
                logging.getLogger().removeFilter(_stage_tag)
            print(f"⏱  CodeQL stage finished "
                  f"({time.time() - _codeql_t0:.0f}s, "
                  f"{len(codeql_sarifs)} SARIF file(s))", flush=True)
        elif run_codeql_stage:
            languages = (
                [s.strip() for s in args.languages.split(",") if s.strip()]
                if args.languages else None  # None ⇒ agent auto-detects
            )
            codeql_sarifs = run_codeql(
                repo_path, out_dir,
                languages=languages,
                build_command=args.build_command,
                traced_build=args.traced_build,
            )

        # Coccinelle stage. Default-on for C/C++ targets; auto-skips
        # silently when spatch is absent or the repo has no C/C++
        # source. ``--no-cocci`` is the explicit opt-out (e.g.
        # operator wants only semgrep/codeql signal). Cheap to run —
        # the shipped rule set is small and AST-level matching is
        # fast — but the opt-out exists for unattended pipelines
        # where any extra signal is noise.
        cocci_sarifs = []
        if not args.no_cocci:
            cocci_sarifs = run_cocci(repo_path, out_dir)

        # Compiler-analyzer stage (opt-in). Same channel as /audit's
        # compiler_sweep, opposite direction — per-TU gcc -fanalyzer /
        # clang --analyze diagnostics become scan findings. --no wins
        # over --on, mirroring the codeql flag pair.
        compiler_sarifs = []
        if args.compiler_scan and not args.no_compiler_scan:
            compiler_sarifs = run_compiler_scan_stage(
                repo_path, out_dir, max_tus=args.compiler_scan_max_tus,
            )

        # Expanded-view semgrep stage (opt-in). Re-runs the resolved
        # ruleset over fidelity-3 expanded views of macro-heavy TUs;
        # findings land at original coordinates with an expanded_view
        # marker under the distinct semgrep-expanded tool name.
        expanded_sarifs = []
        if args.expanded_semgrep:
            expanded_sarifs = run_expanded_semgrep_stage(
                repo_path, out_dir, rules_dirs, list(resolved_baseline),
                extra_configs=args.extra_config,
            )

        # Graduated synthesized rules (default-on, opt-out). Every
        # past confirmed bug pattern that graduated from the rule
        # library re-fires as a standing zero-LLM-cost detector, with
        # provenance synthesized:<id> per result. Auto-skips silently
        # when the project has no graduated rules.
        graduated_sarifs = []
        if not args.no_graduated_rules:
            graduated_sarifs = run_graduated_rules_stage(
                repo_path, out_dir,
                rules_dir=(
                    Path(args.graduated_rules_dir)
                    if args.graduated_rules_dir else None
                ),
            )

        # Source-wrapper projection (default-on, opt-out): helper
        # methods that provably return servlet-request data become
        # additional taint sources for the in-repo java sink profiles.
        source_wrapper_sarifs = []
        source_wrapper_names: list[str] = []
        if not args.no_source_wrappers:
            source_wrapper_sarifs, source_wrapper_names = (
                run_source_wrapper_stage(repo_path, out_dir)
            )

        # Config-resolved additive findings (default-on, opt-out):
        # weak algorithms selected via bundled .properties files are
        # invisible to pattern detectors — the strict resolver proves
        # the file value and emits provenance=config-resolved findings
        # as a separate SARIF run. Detection only; never suppresses.
        config_resolved_sarifs = []
        config_resolved_stats = None
        if (
            RaptorConfig.CONFIG_RESOLVED_ENABLED
            and not args.no_config_resolved
        ):
            try:
                from core.analysis.config_resolved_findings import (
                    run_config_resolved_stage,
                )
                _cr_sarif, config_resolved_stats = (
                    run_config_resolved_stage(repo_path, out_dir)
                )
                if _cr_sarif is not None:
                    config_resolved_sarifs = [_cr_sarif]
            except Exception as e:  # noqa: BLE001
                logger.warning("config-resolved stage failed: %s", e)

        # Merge SARIFs if more than one
        sarif_inputs = (
            semgrep_sarifs + codeql_sarifs + cocci_sarifs
            + compiler_sarifs + expanded_sarifs + graduated_sarifs
            + config_resolved_sarifs + source_wrapper_sarifs
        )
        merged = out_dir / "combined.sarif"
        exclude_globs = args.exclude_dir
        excluded_count = 0
        nosemgrep_count = 0
        if sarif_inputs:
            logger.info("Merging %d SARIF files...", len(sarif_inputs))
            try:
                merged_data = merge_sarif([str(p) for p in sarif_inputs])
                # Operator --exclude-dir: post-merge filter so
                # combined.sarif + downstream metrics see only the
                # non-excluded set. Per-tool SARIFs stay unfiltered
                # (forensic record of what each tool emitted).
                merged_data, excluded_count = filter_sarif_by_exclude_globs(
                    merged_data, exclude_globs,
                )
                if excluded_count:
                    logger.info(
                        "--exclude-dir dropped %s results from combined.sarif (%s)",
                        excluded_count,
                        exclude_globs
                    )
                # Annotate SARIF results whose source lines carry
                # nosemgrep inline-suppression comments.  The annotation
                # lives in result.properties.nosemgrep so any downstream
                # consumer (/validate, external SARIF viewers) can see
                # that a finding was developer-suppressed.
                nosemgrep_count = semgrep_pkg.annotate_sarif(
                    merged_data, str(repo_path),
                )
                save_json(merged, merged_data)
                logger.info("Merged SARIF created: %s", merged)
            except Exception as e:  # noqa: BLE001
                logger.warning("SARIF merge failed, using individual files: %s", e)
                (out_dir / "sarif_merge.stderr.log").write_text(str(e), encoding="utf-8")

        # Sanitizer-cut post-pass: value-bound gate verdicts land in
        # suppressions.jsonl. Candidate verdicts are always evidence
        # (dropped: false); full-proof suppress verdicts ENFORCE by
        # default (corpus-earned, operator-approved 2026-08-19) — their
        # findings are filtered from the combined SARIF below, while
        # per-tool SARIFs stay unfiltered as the forensic record.
        # Enforcement only runs when the combined SARIF exists (the
        # per-tool fallback has no drop surface, so it stays
        # record-only). Reads the filtered combined SARIF when it
        # exists so --exclude-dir is honored. Failure degrades to a
        # warning — the post-pass can never fail a scan.
        sanitizer_cut_postpass_stats = None
        if (
            RaptorConfig.SANITIZER_CUT_POSTPASS_ENABLED
            and not args.no_sanitizer_cut_postpass
            and sarif_inputs
        ):
            try:
                from core.analysis.sanitizer_cut_postpass import (
                    filter_enforced_from_sarif,
                    run_postpass,
                )
                merged_exists = merged.exists()
                postpass_inputs = (
                    [merged] if merged_exists else list(sarif_inputs)
                )
                enforce_on = (
                    RaptorConfig.SANITIZER_CUT_ENFORCE_ENABLED
                    and not args.no_sanitizer_cut_enforce
                    and merged_exists
                )
                sanitizer_cut_postpass_stats = run_postpass(
                    postpass_inputs, repo_path, out_dir,
                    extra_source_patterns=source_wrapper_names,
                    enforce=enforce_on,
                )
                enforced = (
                    (sanitizer_cut_postpass_stats or {})
                    .get("enforced_findings") or []
                )
                if enforce_on and enforced:
                    removed = filter_enforced_from_sarif(merged, enforced)
                    sanitizer_cut_postpass_stats["enforced_removed"] = removed
                    if removed != len(enforced):
                        logger.warning(
                            "sanitizer-cut enforcement: %d verdicts enforced "
                            "but %d results removed from the combined SARIF "
                            "— identities that matched no result stayed "
                            "recorded (dropped: true) without a drop; "
                            "investigate before trusting this run's counts",
                            len(enforced), removed,
                        )
                    else:
                        logger.info(
                            "sanitizer-cut enforcement: %d proven-safe "
                            "finding(s) removed from the combined SARIF "
                            "(per-tool SARIFs unfiltered; records in "
                            "suppressions.jsonl)", removed,
                        )
            except Exception as e:  # noqa: BLE001
                logger.warning("sanitizer-cut post-pass failed: %s", e)

        # Generate metrics. When --exclude-dir filtered the combined
        # SARIF, metrics should reflect the filtered set — read from
        # the just-written combined.sarif rather than the unfiltered
        # individual inputs.
        logger.info("Generating scan metrics...")
        _enforced_removed = int(
            (sanitizer_cut_postpass_stats or {}).get("enforced_removed") or 0
        )
        if (excluded_count or _enforced_removed) and merged.exists():
            # The combined SARIF reflects --exclude-dir filtering and/or
            # sanitizer-cut enforcement drops; metrics must read it, not
            # the unfiltered per-tool forensic SARIFs.
            metrics = generate_scan_metrics([str(merged)])
        else:
            metrics = generate_scan_metrics(sarif_inputs)
        # Record per-engine failure surfaces so downstream readers
        # can distinguish a clean run from one where N packs silently
        # dropped. Empty list is intentional (positive marker — "we
        # tracked this, nothing failed") rather than absent-key
        # (couldn't-be-bothered).
        metrics["semgrep_failed_packs"] = semgrep_failed
        # Registry packs the reachability probe dropped before dispatch
        # (see _drop_unreachable_registry_packs) — distinct from
        # semgrep_failed_packs, which records packs that DISPATCHED and
        # then failed. Empty list means every requested pack ran.
        metrics["dropped_registry_packs"] = sorted(_dropped_registry_packs)
        metrics["nosemgrep_suppressed_count"] = nosemgrep_count
        # Record-only post-pass stats (None when disabled or no SARIFs)
        # — verdict counts, refusal reasons, budget skips. The verdicts
        # themselves live in suppressions.jsonl.
        metrics["sanitizer_cut_postpass"] = sanitizer_cut_postpass_stats
        # Additive config-resolved stage stats (None when disabled) —
        # files scanned, emissions, per-refusal resolver counts.
        metrics["config_resolved"] = config_resolved_stats
        metrics["show_suppressed"] = getattr(args, "show_suppressed", False)
        save_json(out_dir / "scan_metrics.json", metrics)

        # Write coverage records and derive total_files_scanned from them
        try:
            from core.coverage.record import (
                build_from_codeql,
                build_from_semgrep,
                load_records,
                write_record,
            )
            # Semgrep coverage — find JSON outputs alongside SARIFs.
            # See ``_resolve_rules_applied`` for why this isn't just
            # ``groups`` or rule-dir names.
            _rules_applied = _resolve_rules_applied(
                groups, resolved_baseline, rules_dirs,
            )
            _all_semgrep_jsons = [
                Path(sp).with_suffix(".json") for sp in semgrep_sarifs
                if Path(sp).with_suffix(".json").exists()
            ]
            # Degradation visibility: a file dropped by rule timeouts /
            # memory caps was NOT analysed even though the pack
            # "succeeded" — silent coverage loss unless said out loud.
            _dropped = _semgrep_dropped_files(_all_semgrep_jsons)
            if _dropped:
                _preview = ", ".join(list(_dropped)[:5])
                _more = len(_dropped) - min(5, len(_dropped))
                print(
                    f"⚠️  semgrep: {len(_dropped)} file(s) dropped by "
                    f"rule timeouts/memory caps — NOT analysed: "
                    f"{_preview}"
                    + (f" (+{_more} more)" if _more else "")
                    + ". Full list in coverage-record files_failed.",
                    file=sys.stderr,
                )
            for json_path in _all_semgrep_jsons:
                record = build_from_semgrep(
                    out_dir, json_path,
                    rules_applied=_rules_applied,
                    extra_error_json_paths=_all_semgrep_jsons,
                )
                if record:
                    write_record(out_dir, record, tool_name="semgrep")
                    break  # one record covers all (paths.scanned is cumulative; errors merged above)

            # CodeQL coverage — from SARIF artifacts
            for sarif_path in codeql_sarifs:
                record = build_from_codeql(Path(sarif_path))
                if record:
                    write_record(out_dir, record, tool_name="codeql")
                    break  # one record per run

            # Derive total_files_scanned from coverage records — these are
            # the canonical source of what was examined (not SARIF artifacts,
            # which Semgrep doesn't populate).
            all_covered = set()
            for rec in load_records(out_dir):
                all_covered.update(rec.get("files_examined", []))
            if all_covered:
                metrics["total_files_scanned"] = len(all_covered)
                save_json(out_dir / "scan_metrics.json", metrics)
        except Exception as e:  # noqa: BLE001
            logger.debug("Coverage record write failed (non-fatal): %s", e)

        if nosemgrep_count:
            _active = metrics['total_findings'] - nosemgrep_count
            logger.info(
                "Scan complete: %s findings + %s developer-suppressed in %s files",
                _active,
                nosemgrep_count,
                metrics['total_files_scanned']
            )
        else:
            logger.info(
                "Scan complete: %s findings in %s files",
                metrics['total_findings'],
                metrics['total_files_scanned']
            )

        # Provenance manifest. MUST be composed BEFORE cleanup runs,
        # because cleanup deletes most of the per-pack SARIFs we hash.
        try:
            verification = _compose_verification_manifest(
                sarif_inputs, merged, out_dir,
            )
        except Exception as e:  # noqa: BLE001
            logger.debug("verification manifest compose failed (non-fatal): %s", e)
            verification = {
                "schema_version": 1,
                "combined_sarif": {"path": merged.name, "sha256": "", "size_bytes": 0},
                "packs": [],
            }

        # Per-pack file cleanup. Runs AFTER combined.sarif and
        # scan_metrics.json are finalised. The merged SARIF is canonical;
        # per-pack semgrep_*.{exit,json,sarif,stderr.log} files are
        # intermediate. Keep only what's useful for post-mortem of failed
        # packs (exit code + non-empty stderr + sarif-with-findings).
        try:
            cleanup_per_pack_artifacts(out_dir)
        except Exception as e:  # noqa: BLE001
            logger.debug("Per-pack cleanup failed (non-fatal): %s", e)

        save_json(out_dir / "verification.json", verification)

        duration = time.time() - start_time
        logger.info("Total scan duration: %.2fs", duration)

        # Tool-execution coverage block — reads coverage-<tool>.json
        # records the scanners emit; renders an aligned per-tool
        # summary (findings count, rule groups, silent-drop
        # warnings) so the operator sees what RAN with what RESULT
        # before the function-level coverage block below.
        # Distinct from store_summary which answers ''what code did
        # any tool examine?''; this one answers ''what did we look
        # at it WITH?''.
        try:
            from core.reporting.scan_coverage import render_scan_coverage
            tool_cov = render_scan_coverage(out_dir)
            if tool_cov:
                print()
                print(tool_cov)
        except Exception as e:  # noqa: BLE001
            logger.debug("Tool-coverage render failed (non-fatal): %s", e)

        # Print coverage summary (unified store-backed report; file-level tier
        # when there's no function inventory, e.g. a bare /scan).
        try:
            from core.coverage.store_summary import render_run_coverage
            cov = render_run_coverage(out_dir)
            if cov:
                print()
                print(cov)
                print()
        except (ImportError, FileNotFoundError) as exc:
            # Narrowed: ImportError if the optional summary module
            # isn't installed; FileNotFoundError if checklist hasn't
            # been created yet. Other errors propagate so they
            # surface instead of silently dropping the summary.
            logger.debug("scanner: coverage summary unavailable: %s", exc)

        result = {
            "status": "ok",
            "manifest": manifest,
            "metrics": metrics,
            "duration": duration,
        }
        print(dumps_display(result, indent=2))
        # Aggregate any tracer-emitted .sandbox-denials.jsonl into
        # sandbox-summary.json. The lifecycle hook lives in raptor.py
        # / raptor_agentic.py for top-level invocations — neither
        # covers THIS subprocess's out_dir when scanner.py is invoked
        # as a child of agentic. Without this call, audit JSONL
        # produced inside scanner subprocess (when mount-ns + tracer
        # actually engage for some Semgrep call) would orphan in
        # out_dir/.sandbox-denials.jsonl. No-op if no JSONL was
        # written (the common case today, since Semgrep hits B
        # fallback via Landlock-only).
        try:
            from core.sandbox.summary import summarize_and_write
            summarize_and_write(out_dir)
        except Exception as _e:
            logger.debug("summarize_and_write at end of scanner.py: "
                         "%s", _e, exc_info=True)
        # ``all_semgrep_failed`` set above when every dispatched
        # semgrep pack failed (CI-gate signal — exit 4 distinct from
        # the sandbox-engagement-failure exit code which is reserved
        # for the SandboxSetupError path at __main__).
        sys.exit(4 if all_semgrep_failed else 0)
    finally:
        if not args.keep:
            try:
                shutil.rmtree(tmp)
            except OSError as exc:
                # rmtree failure on the scratch dir — log at WARNING
                # so the operator can spot the leak. Pre-fix this
                # was completely silent.
                logger.warning(
                    "scanner: failed to clean up scratch dir %s: %s",
                    tmp, exc,
                )


if __name__ == "__main__":
    try:
        main()
    except SandboxSetupError as e:
        # Fail loud with the actionable message, not a traceback. The scan
        # did NOT run — never let this look like a clean "0 findings".
        print(
            f"\nRAPTOR: scan aborted — sandbox isolation could not engage.\n{e}",
            file=sys.stderr,
        )
        sys.exit(SANDBOX_ENGAGE_EXIT_CODE)
