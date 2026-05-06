"""Mechanical CodeQL query construction for IRIS dataflow validation.

Three tiers, ordered by reliability:

  Tier 1 — `discover_prebuilt_query` + adapter.run_prebuilt_query:
    discovers existing CodeQL queries indexed by `external/cwe/cwe-NNN`
    tags under each installed `*-queries` pack. Invokes them by absolute
    path. The LLM is not involved in QL generation; we just run the
    professionally-written, pack-maintained `.ql` files. Handles 70-80%
    of real Semgrep findings (CWE-78 / 79 / 89 / 22 etc.) for whatever
    languages have packs installed.

  Tier 2 — `build_template_query`: for CWEs with no prebuilt query, or
    languages that lack a `*-queries` pack on the host, assembles a full
    query from a per-language template with placeholders. The LLM fills
    only the `isSource` and `isSink` predicate bodies — small surface,
    much smaller compile-error risk than full-query generation.

  Tier 3 (in dataflow_validation.py): compile-error retry feeding the
    error back to the LLM. Last resort when Tier 2's template fill-in
    still doesn't compile (e.g. wrong AST node names).

The mechanical layers (1+2) reduce the LLM's QL surface from "write a
complete CodeQL query, including imports / metadata / module structure
/ PathGraph / select clause / source / sink" down to "write the body of
two predicates" or, when a CWE is known, nothing at all.

Empirical motivation: real-LLM E2E runs showed Gemini-2.5-pro hallucinated
import paths (`semmle.python.security.dataflow.*` no longer exists),
used the legacy `Configuration` class API, and got AST class names wrong
(`IndexExpr` instead of `Subscript`). Constraining the LLM to predicate
bodies — for which CodeQL's standard library exposes high-level helpers
like `RemoteFlowSource` — sidesteps most of these failure modes.

Discovery vs hardcoded map: an earlier draft maintained a hand-edited
(language, CWE) → (import_path, flow_module) dict. Discovery replaces
that — the CodeQL packs already organise queries by CWE under
`Security/CWE-NNN/` and tag them with `@tags external/cwe/cwe-NNN`.
The packs are the source of truth; hardcoding goes stale on every pack
update. Discovery picks up new queries (and user-installed custom
packs) automatically.
"""

import functools
import json
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# Tier 1 — discovery ---------------------------------------------------------

# Default pack search root. Mirrors the pack location CodeQL itself uses
# for its bundled stdlib packs. The directory contains `<lang>-queries`
# packs directly. Tests monkeypatch this constant to point at a fixture
# tree.
_DEFAULT_PACK_ROOT = Path.home() / ".codeql" / "packages" / "codeql"

# Match `@tags external/cwe/cwe-NNN` (case-insensitive). The tag may sit on
# its own line (continuation of a multi-line @tags block) or follow @tags
# directly. Captures the numeric portion.
_CWE_TAG_RE = re.compile(
    r"\bexternal/cwe/cwe-(\d+)\b",
    re.IGNORECASE,
)

# Match `@kind path-problem` to filter out non-dataflow queries.
# Standalone `@kind problem` queries are useful for static checks
# (e.g. "missing httpOnly flag") but don't track paths from source to
# sink — they're not what IRIS is validating.
_KIND_PATH_PROBLEM_RE = re.compile(
    r"@kind\s+path-problem\b",
    re.IGNORECASE,
)

# Match `@id <ns>/<rest>` — used for stable identification of which
# discovered query handled a particular finding (audit trail).
_ID_RE = re.compile(r"@id\s+([\w.\-/]+)")

# Bound how much of each .ql file we read when checking metadata. Real
# headers fit in ~1 KB; reading more wastes IO on large dataflow query
# bodies. 4 KB gives slack for queries with long descriptions.
_METADATA_READ_BYTES = 4096


def _pack_roots() -> List[Path]:
    """Resolve all CodeQL pack roots in priority order.

    Returns extras (from RaptorConfig.EXTRA_CODEQL_PACK_ROOTS) first,
    then the default. First-seen-wins semantics in the walk mean
    extras override the default on (lang, CWE) collisions — RAPTOR-
    shipped packs (e.g. raptor-python-queries with LocalFlowSource
    coverage) take precedence over the bundled stdlib queries.

    Config import is deferred so this module stays import-safe in
    contexts (tests, scripts) where core.config may not be fully
    initialised. Tests can also monkeypatch _DEFAULT_PACK_ROOT
    directly to point at fixtures.
    """
    extras: List[Path] = []
    try:
        from core.config import RaptorConfig
        extras = list(RaptorConfig.EXTRA_CODEQL_PACK_ROOTS or [])
    except ImportError:
        pass
    return extras + [_DEFAULT_PACK_ROOT]


_RESOLVE_TIMEOUT_SECS = 30
# Match `codeql/<lang>-queries` (canonical published-pack naming).
# `<lang>` covers letters, digits, hyphens — no slashes.
_QUERIES_PACK_NAME_RE = re.compile(r"^codeql/([A-Za-z0-9-]+)-queries$")


def _resolved_pack_pointers() -> Dict[str, Path]:
    """Ask the `codeql` CLI for the canonical install paths of all
    published query packs. Returns {language: pack_path} for the
    `codeql/<lang>-queries` namespace; non-queries packs (libs,
    examples, tests) are filtered out.

    Used as a secondary discovery source so operators who installed
    CodeQL via the upstream queries-checkout (for example
    `~/.local/codeql-queries/`) get IRIS Tier 1 coverage too — the
    layout there does not match `<DEFAULT_PACK_ROOT>/<lang>-queries/`,
    so the original walk would otherwise miss it.

    Failure modes handled silently: codeql not on PATH, CLI errors,
    parse errors, or timeout. The hardcoded `_DEFAULT_PACK_ROOT` walk
    runs regardless of this helper's success.

    Sandbox-safe: `codeql resolve qlpacks` is a metadata read against
    the binary's own pack-cache. No target-repo or network access.
    """
    binary = shutil.which("codeql")
    if not binary:
        return {}
    try:
        proc = subprocess.run(
            [binary, "resolve", "qlpacks", "--format=json"],
            capture_output=True, text=True,
            timeout=_RESOLVE_TIMEOUT_SECS,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.debug("codeql resolve qlpacks failed: %s", e)
        return {}
    if proc.returncode != 0:
        logger.debug(
            "codeql resolve qlpacks returned %d: %s",
            proc.returncode, (proc.stderr or "").strip()[:200],
        )
        return {}
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        logger.debug("codeql resolve qlpacks JSON parse failed: %s", e)
        return {}

    out: Dict[str, Path] = {}
    for pack_name, paths in (data or {}).items():
        m = _QUERIES_PACK_NAME_RE.match(pack_name)
        if not m or not paths:
            continue
        lang = m.group(1).lower()
        # `paths` is a list — published packs typically have one entry.
        # Take the first that exists on disk.
        for p in paths:
            path = Path(p)
            if path.is_dir():
                out[lang] = path
                break
    return out


def _read_metadata(ql_path: Path) -> Optional[str]:
    """Return the first ~4KB of a .ql file as text, or None on read failure.

    Comment-block parsing is naive on purpose: we just look for tag
    matches anywhere in the head of the file. CodeQL's QLDoc format puts
    metadata in the leading `/** ... */` block, so substring matches are
    safe — there's no executable QL syntax in the comment block that would
    spoof our patterns.
    """
    try:
        with ql_path.open("rb") as f:
            data = f.read(_METADATA_READ_BYTES)
        return data.decode("utf-8", errors="replace")
    except OSError:
        return None


def _extract_cwes(metadata: str) -> List[str]:
    """All CWE-NNN tags found in the metadata block (canonical form).

    CodeQL packs zero-pad to three digits (`cwe-022`); the canonical
    MITRE form has no leading zeros (`CWE-22`). Strip leading zeros so
    the discovery dict uses the same key shape that callers pass in.
    """
    return [
        f"CWE-{int(m.group(1))}"
        for m in _CWE_TAG_RE.finditer(metadata)
    ]


def _is_path_problem(metadata: str) -> bool:
    return bool(_KIND_PATH_PROBLEM_RE.search(metadata))


def _query_id(metadata: str) -> Optional[str]:
    m = _ID_RE.search(metadata)
    return m.group(1) if m else None


def _language_from_pack_dir(pack_dir: Path) -> Optional[str]:
    """Extract language tag from a `<lang>-queries` directory name.

    Examples: `python-queries` → "python", `cpp-queries` → "cpp".
    Returns None for directories that don't fit the convention (library
    packs like `python-all`, `dataflow`, etc.).
    """
    name = pack_dir.name
    if not name.endswith("-queries"):
        return None
    return name[: -len("-queries")].lower()


@functools.lru_cache(maxsize=1)
def discover_prebuilt_queries() -> Dict[Tuple[str, str], Path]:
    """Walk installed CodeQL query packs to build the (lang, CWE) → path map.

    Scans `<pack_root>/<lang>-queries/<version>/Security/CWE-*/*.ql` and
    reads each file's QLDoc header for `@kind path-problem` and
    `external/cwe/cwe-NNN` tags. Returns a dict keyed by (language tag,
    CWE-NNN string) with the absolute path of the .ql file.

    Result is cached for the process lifetime via lru_cache. The scan
    is cheap (~100ms for ~500 files) but still wasteful to repeat per
    finding. Tests that need to bust the cache call
    `discover_prebuilt_queries.cache_clear()`.

    Multiple .ql files can share a (lang, CWE) key — e.g. both
    `Security/CWE-078/CommandInjection.ql` and an extension query, or
    a RAPTOR override and the stdlib version. First-seen wins, with
    extras (RaptorConfig.EXTRA_CODEQL_PACK_ROOTS) walked before the
    default root so RAPTOR-shipped packs win on collisions. Within a
    single root, iteration is alphabetical for determinism.
    """
    out: Dict[Tuple[str, str], Path] = {}

    # Build the priority-ordered list of (language, pack_dir) pairs:
    #   1. Extras roots (RaptorConfig.EXTRA_CODEQL_PACK_ROOTS) — RAPTOR-
    #      shipped packs win on collisions.
    #   2. `codeql resolve qlpacks` — direct pointers from the operator's
    #      installed packs, including non-default install layouts like
    #      the upstream codeql-queries checkout.
    #   3. _DEFAULT_PACK_ROOT iter — the canonical
    #      `~/.codeql/packages/codeql/` install. May overlap with (2);
    #      `seen_dirs` dedupes by resolved absolute path.
    seen_dirs: set = set()
    pack_dirs: List[Tuple[str, Path]] = []

    def _add_pack_dir(language: str, pack_dir: Path) -> None:
        try:
            resolved = pack_dir.resolve()
        except (OSError, RuntimeError):
            return
        if resolved in seen_dirs:
            return
        seen_dirs.add(resolved)
        pack_dirs.append((language, pack_dir))

    # (1) Extras roots — iterate children
    for root in _pack_roots()[:-1]:  # all but the default (handled in (3))
        if not root.is_dir():
            logger.debug("CodeQL pack root not found: %s", root)
            continue
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            lang = _language_from_pack_dir(child)
            if lang:
                _add_pack_dir(lang, child)

    # (2) `codeql resolve qlpacks` — direct language→path pointers
    for lang, path in _resolved_pack_pointers().items():
        _add_pack_dir(lang, path)

    # (3) _DEFAULT_PACK_ROOT — canonical install layout
    default_root = _pack_roots()[-1]
    if default_root.is_dir():
        for child in sorted(default_root.iterdir()):
            if not child.is_dir():
                continue
            lang = _language_from_pack_dir(child)
            if lang:
                _add_pack_dir(lang, child)
    else:
        logger.debug("CodeQL default pack root not found: %s", default_root)

    # Walk each pack dir. Layout variants supported:
    #   Flat:        <pack>/Security/...                 (in-repo packs)
    #   Versioned:   <pack>/<version>/Security/...       (canonical install)
    #   Nested-CWE:  <pack>/Security/CWE/CWE-NNN/*.ql    (upstream queries
    #                                                    checkout — handled
    #                                                    by rglob below)
    for language, pack_dir in pack_dirs:
        search_dirs: List[Path] = []
        flat_security = pack_dir / "Security"
        if flat_security.is_dir():
            search_dirs.append(flat_security)
        else:
            for version_dir in sorted(pack_dir.iterdir()):
                if not version_dir.is_dir():
                    continue
                security_dir = version_dir / "Security"
                if security_dir.is_dir():
                    search_dirs.append(security_dir)

        for security_dir in search_dirs:
            for ql_path in sorted(security_dir.rglob("*.ql")):
                metadata = _read_metadata(ql_path)
                if metadata is None or not _is_path_problem(metadata):
                    continue
                for cwe in _extract_cwes(metadata):
                    key = (language, cwe)
                    out.setdefault(key, ql_path)

    if out:
        logger.debug(
            "discovered %d prebuilt CodeQL queries across %d languages",
            len(out), len({k[0] for k in out}),
        )
    return out


def discover_prebuilt_query(language: str, cwe: str) -> Optional[Path]:
    """Look up a prebuilt path-problem query for (language, CWE).

    Both args are normalised before lookup. Returns the absolute .ql
    path, or None when no such query exists in the installed packs.
    """
    if not language or not cwe:
        return None
    key = (language.lower().strip(), cwe.upper().strip())
    return discover_prebuilt_queries().get(key)


# Tier 2 — language templates ------------------------------------------------

# Per-language taint-tracking templates. The LLM fills in two strings:
# `source_predicate_body` and `sink_predicate_body`. Everything else
# (imports, module structure, PathGraph wiring, select clause) is
# mechanical.
#
# These match the modern ConfigSig + TaintTracking::Global<> API found
# in current python-all / java-all / cpp-all / javascript-all packs.
_TAINT_TEMPLATES: Dict[str, str] = {
    "python": """\
/**
 * @name IRIS validation: {query_id}
 * @kind path-problem
 * @id {query_id}
 * @problem.severity error
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources

module IrisConfig implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node n) {{
    {source_predicate_body}
  }}
  predicate isSink(DataFlow::Node n) {{
    {sink_predicate_body}
  }}
}}

module IrisFlow = TaintTracking::Global<IrisConfig>;
import IrisFlow::PathGraph

from IrisFlow::PathNode source, IrisFlow::PathNode sink
where IrisFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "IRIS dataflow path"
""",
    "java": """\
/**
 * @name IRIS validation: {query_id}
 * @kind path-problem
 * @id {query_id}
 * @problem.severity error
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources

module IrisConfig implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node n) {{
    {source_predicate_body}
  }}
  predicate isSink(DataFlow::Node n) {{
    {sink_predicate_body}
  }}
}}

module IrisFlow = TaintTracking::Global<IrisConfig>;
import IrisFlow::PathGraph

from IrisFlow::PathNode source, IrisFlow::PathNode sink
where IrisFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "IRIS dataflow path"
""",
    "cpp": """\
/**
 * @name IRIS validation: {query_id}
 * @kind path-problem
 * @id {query_id}
 * @problem.severity error
 */
import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.security.FlowSources

module IrisConfig implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node n) {{
    {source_predicate_body}
  }}
  predicate isSink(DataFlow::Node n) {{
    {sink_predicate_body}
  }}
}}

module IrisFlow = TaintTracking::Global<IrisConfig>;
import IrisFlow::PathGraph

from IrisFlow::PathNode source, IrisFlow::PathNode sink
where IrisFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "IRIS dataflow path"
""",
    "javascript": """\
/**
 * @name IRIS validation: {query_id}
 * @kind path-problem
 * @id {query_id}
 * @problem.severity error
 */
import javascript
import DataFlow::PathGraph

module IrisConfig implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node n) {{
    {source_predicate_body}
  }}
  predicate isSink(DataFlow::Node n) {{
    {sink_predicate_body}
  }}
}}

module IrisFlow = TaintTracking::Global<IrisConfig>;

from IrisFlow::PathNode source, IrisFlow::PathNode sink
where IrisFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "IRIS dataflow path"
""",
    "go": """\
/**
 * @name IRIS validation: {query_id}
 * @kind path-problem
 * @id {query_id}
 * @problem.severity error
 */
import go
import semmle.go.dataflow.DataFlow
import semmle.go.dataflow.TaintTracking

module IrisConfig implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node n) {{
    {source_predicate_body}
  }}
  predicate isSink(DataFlow::Node n) {{
    {sink_predicate_body}
  }}
}}

module IrisFlow = TaintTracking::Global<IrisConfig>;
import IrisFlow::PathGraph

from IrisFlow::PathNode source, IrisFlow::PathNode sink
where IrisFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "IRIS dataflow path"
""",
}


def supported_languages_for_template() -> set:
    """Languages with a Tier 2 template available."""
    return set(_TAINT_TEMPLATES.keys())


def build_template_query(
    *,
    language: str,
    source_predicate_body: str,
    sink_predicate_body: str,
    query_id: str = "raptor/iris-validation",
) -> Optional[str]:
    """Assemble a Tier 2 query from the template + LLM-supplied predicates.

    Args:
        language: Normalised language tag ("python", "java", etc.).
        source_predicate_body: QL fragment forming the body of
            `predicate isSource(DataFlow::Node n) { ... }`. Trailing
            semicolons / surrounding braces are NOT included.
        sink_predicate_body: same shape, for `isSink`.
        query_id: Stable identifier embedded in the query metadata.

    Returns:
        Full .ql text, or None when the language has no template.
    """
    template = _TAINT_TEMPLATES.get(language.lower())
    if template is None:
        return None
    if not source_predicate_body or not source_predicate_body.strip():
        return None
    if not sink_predicate_body or not sink_predicate_body.strip():
        return None

    return template.format(
        source_predicate_body=source_predicate_body.strip(),
        sink_predicate_body=sink_predicate_body.strip(),
        query_id=query_id,
    )


# Schema for the structured response when we ask the LLM for predicates only.
# Used by the dataflow_validation runner when Tier 1 doesn't apply and we
# fall through to Tier 2.
TEMPLATE_PREDICATE_SCHEMA = {
    "source_predicate_body": (
        "string — body of the isSource(DataFlow::Node n) predicate. "
        "Just the body content (without surrounding braces or the "
        "predicate signature). Example: "
        "'n instanceof RemoteFlowSource' for a remote source."
    ),
    "sink_predicate_body": (
        "string — body of the isSink(DataFlow::Node n) predicate. "
        "Same shape: just the body. Example: "
        "'exists(Call c | c.getFunc().(...) ... and n.asExpr() = c.getArg(0))'."
    ),
    "expected_evidence": (
        "string — what kind of match would confirm the hypothesis."
    ),
    "reasoning": (
        "string — why these predicates test the dataflow_summary's claim."
    ),
}


# CWE inference --------------------------------------------------------------

# Maps regex patterns over Semgrep rule IDs to CWE numbers. Used when the
# finding's `cwe_id` field is empty — many Semgrep rules don't tag CWE
# explicitly but their rule names are descriptive. Without inference we
# lose the CWE → prebuilt query mapping for these findings.
#
# Order matters: more specific patterns first. The first match wins.
_RULE_ID_TO_CWE: list = [
    # Command injection — variants seen in real rule sets:
    # "command-injection", "os-command-injection", "command_injection",
    # "subprocess-shell-true", "shell-true", "subprocess.shell",
    # "command-shell" (raptor's variant), "exec-shell", etc.
    (re.compile(
        r"command[-_]?injection"
        r"|os[-_]?command"
        r"|subprocess[-_.].*shell"
        r"|shell[-_]?true"
        r"|command[-_]shell"
        r"|exec[-_]?shell",
        re.IGNORECASE,
    ), "CWE-78"),
    # SQL injection
    (re.compile(r"sql[-_]?injection|sqli\b", re.IGNORECASE), "CWE-89"),
    # NoSQL injection
    (re.compile(r"nosql[-_]?injection|mongo[-_].*injection", re.IGNORECASE), "CWE-943"),
    # Path traversal
    (re.compile(r"path[-_]?traversal|tainted[-_]?path|directory[-_]?traversal",
                re.IGNORECASE), "CWE-22"),
    # XSS — DOM-based and reflected both map to CWE-79
    (re.compile(r"\bxss\b|cross[-_]?site[-_]?scripting", re.IGNORECASE), "CWE-79"),
    # Code injection / eval
    (re.compile(r"code[-_]?injection|\beval\b.*injection", re.IGNORECASE), "CWE-94"),
    # XXE / XML external entity
    (re.compile(r"\bxxe\b|xml[-_]?external[-_]?entit", re.IGNORECASE), "CWE-611"),
    # SSRF
    (re.compile(r"\bssrf\b|server[-_]?side[-_]?request[-_]?forger",
                re.IGNORECASE), "CWE-918"),
    # LDAP injection
    (re.compile(r"ldap[-_]?injection", re.IGNORECASE), "CWE-90"),
    # XPath injection
    (re.compile(r"xpath[-_]?injection", re.IGNORECASE), "CWE-643"),
    # Open redirect
    (re.compile(r"open[-_]?redirect|url[-_]?redirect", re.IGNORECASE), "CWE-601"),
    # Template injection / SSTI
    (re.compile(r"template[-_]?injection|\bssti\b", re.IGNORECASE), "CWE-1336"),
    # Deserialization
    (re.compile(r"deserialization|insecure[-_]?deserial|unsafe[-_]?deserial",
                re.IGNORECASE), "CWE-502"),
    # Log injection
    (re.compile(r"log[-_]?injection|log[-_]?forging", re.IGNORECASE), "CWE-117"),
    # Hardcoded credentials
    (re.compile(r"hardcoded[-_]?(?:credential|secret|password|key|token)",
                re.IGNORECASE), "CWE-798"),
    # Weak crypto / hash
    (re.compile(r"weak[-_]?(?:hash|crypto|cipher|digest)|broken[-_]?(?:hash|crypto)",
                re.IGNORECASE), "CWE-327"),
    # ReDoS
    (re.compile(r"\bredos\b|catastrophic[-_]?backtrack|polynomial[-_]?redos",
                re.IGNORECASE), "CWE-1333"),
    # Cleartext logging
    (re.compile(r"cleartext[-_]?(?:log|stor)|sensitive[-_]?in[-_]?log",
                re.IGNORECASE), "CWE-312"),
    # Stack trace exposure
    (re.compile(r"stack[-_]?trace|exception[-_]?message[-_]?disclos",
                re.IGNORECASE), "CWE-209"),
]


def infer_cwe_from_rule_id(rule_id: str) -> Optional[str]:
    """Infer a CWE tag from a Semgrep rule_id when the finding lacks one.

    Many Semgrep rules don't set the `cwe_id` field explicitly but have
    descriptive rule names like "raptor.injection.command-shell" or
    "python.lang.security.deserialization.pickle". Inferring from the
    rule_id lets Tier 1's CWE → prebuilt-query map kick in for findings
    that would otherwise fall through to Tier 2.

    Returns the first matching CWE-NNN string, or None when no pattern
    matches. Patterns are ordered from most specific to most general
    so e.g. "subprocess-shell-true" hits the command-injection pattern
    rather than a hypothetical generic "subprocess" one.
    """
    if not rule_id:
        return None
    for pattern, cwe in _RULE_ID_TO_CWE:
        if pattern.search(rule_id):
            return cwe
    return None


__all__ = [
    "discover_prebuilt_queries",
    "discover_prebuilt_query",
    "build_template_query",
    "supported_languages_for_template",
    "TEMPLATE_PREDICATE_SCHEMA",
    "infer_cwe_from_rule_id",
]
