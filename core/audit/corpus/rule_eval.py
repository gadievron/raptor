"""Mechanical rule-verification runner for the /audit calibration corpus.

Runs RAPTOR's deterministic rule inventories over the corpus's pinned
sources and scores the hits against the ground-truth labels.  No LLM
is involved anywhere — this measures what the custom rules alone can
see.  Two rule populations, scored separately (``--provenance``):
the shipped in-repo inventories, and the project's *graduated* rules —
synthesized checkers that ``RuleLibrary.graduate`` promoted into
``<project_dir>/engine-rules/`` as first-class scanner rules.

Engines:
- ``semgrep`` — the shipped category dirs under
  ``engine/semgrep/rules/`` (same enumeration as the production
  scanner; upstream registry packs are deliberately excluded — only
  our own rules are under calibration).
- ``coccinelle`` — the shipped ``engine/coccinelle/rules/*.cocci``
  set (same directory the production scanner's cocci stage runs).
- ``codeql`` — opt-in via ``--engine codeql``; see
  ``run_codeql_engine`` for the per-repo feasibility gate.

Scope: file-scoped.  Labels are grouped per pinned repo, the labelled
files are copied into a minimal excerpt tree (reusing ``run_corpus``'s
splice/excerpt machinery), and each engine runs over that tree through
the same sandboxed runners the production scanners use.

Join semantics: a hit counts for a label when it lands in the label's
pinned file within ``[line_start - slop, line_end + slop]`` (``--slop``,
default 2).  A rule *targets* a label when the label pins it explicitly
(optional ``expected_rule_hits``), or — fallback — when the rule's CWE
metadata intersects the label's CWE (or its bug class's CWE family) and
the rule's language applies to the pinned file.

Scoring: per-rule true positives (targeted hit on a ``finding`` label),
false positives (any hit on a ``clean`` label), misses (targeted
``finding`` label with no hit), plus untargeted hits (serendipitous
detections).  The actionable output for rule authoring is the
RULE-COVERAGE GAP list: ``finding`` labels no evaluated rule even
targets.

Skips are never failures: missing fixtures, absent engines, and
per-repo infeasibility are reported in the skip taxonomy (mirroring
``run_corpus``'s missing-source handling) and excluded from scoring.

Usage:
    python3 -m core.audit.corpus.rule_eval [--class C] [--label ID]...
        [--engine semgrep --engine coccinelle] [--slop N]
        [--spatch-timeout N] [--provenance all|shipped|graduated]
        [--engine-rules-dir DIR] [--fetch] [--out DIR] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

ENGINES = ("semgrep", "coccinelle", "codeql")
DEFAULT_ENGINES = ("semgrep", "coccinelle")
DEFAULT_SLOP = 2
# Matches packages.coccinelle.runner.run_rules' own default — the
# production cocci stage's per-rule bound.
DEFAULT_SPATCH_TIMEOUT = 300

# Fallback CWE families per corpus bug class, used only when a label
# carries no explicit ``cwe``.  A seed mapping, not an ontology — a
# label whose class is missing here simply never matches by class and
# shows up in the coverage-gap list, which is the honest failure mode.
# Keep it small: ``expected_rule_hits`` on the label is the preferred
# precision mechanism (exact rule pins beat any family guess); this
# map only exists so unpinned labels get a sane targeting default.
# Deliberately unmapped: ``clean`` (no finding labels — targeting is
# moot) and ``trap`` (heterogeneous by design; its labels carry
# explicit ``cwe`` fields where one applies).
BUG_CLASS_CWES: Dict[str, FrozenSet[str]] = {
    "aliasing": frozenset({"CWE-415", "CWE-416", "CWE-825"}),
    "auth": frozenset({"CWE-285", "CWE-287", "CWE-306", "CWE-862",
                       "CWE-863"}),
    "concurrency": frozenset({"CWE-362", "CWE-366", "CWE-367", "CWE-413",
                              "CWE-667", "CWE-833"}),
    "fail_open": frozenset({"CWE-636", "CWE-703"}),
    "integer": frozenset({"CWE-190", "CWE-191", "CWE-192", "CWE-197",
                          "CWE-681"}),
    "lifecycle": frozenset({"CWE-401", "CWE-415", "CWE-416", "CWE-459",
                            "CWE-590", "CWE-772"}),
    "uninitialised": frozenset({"CWE-457", "CWE-908", "CWE-909"}),
    "variant": frozenset({"CWE-119", "CWE-125", "CWE-787"}),
}

_EXT_LANG = {
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".go": "go",
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".rb": "ruby",
    ".rs": "rust",
}

# Semgrep rule ``languages`` entries normalised to the _EXT_LANG space.
_SEMGREP_LANG_ALIASES = {
    "py": "python",
    "golang": "go",
    "js": "javascript",
    "ts": "typescript",
    "c++": "cpp",
}

# Semgrep languages that apply to any file.
_WILDCARD_LANGS = frozenset({"generic", "regex"})

_CWE_RE = re.compile(r"\bCWE[-_ ]?0*(\d+)\b", re.IGNORECASE)
_QL_ID_RE = re.compile(r"@id\s+(\S+)")


def _normalise_cwe(raw: str) -> str:
    """``cwe-089`` / ``CWE_89`` / ``CWE-89: SQL injection`` -> ``CWE-89``."""
    m = _CWE_RE.search(raw or "")
    return f"CWE-{int(m.group(1))}" if m else ""


@dataclass(frozen=True)
class RuleInfo:
    """One rule from a shipped or graduated inventory."""

    engine: str
    rule_id: str
    path: str
    cwes: FrozenSet[str] = frozenset()
    languages: FrozenSet[str] = frozenset()
    # "shipped" — the in-repo rule inventories; "graduated" — a
    # synthesized checker that RuleLibrary.graduate promoted into the
    # project's engine-rules dir. Scored as separate populations:
    # measuring synthesized-rule quality against corpus ground truth
    # is the point of tagging.
    provenance: str = "shipped"

    @property
    def key(self) -> str:
        return f"{self.engine}:{self.rule_id}"


@dataclass(frozen=True)
class RuleHit:
    """One engine match, in label coordinate space (repo-relative file)."""

    engine: str
    rule_id: str
    file: str
    line: int
    line_end: int = 0
    message: str = ""


@dataclass
class EngineOutcome:
    """Result of running one engine over one repo's excerpt tree."""

    engine: str
    available: bool = True
    skipped_reason: str = ""
    hits: List[RuleHit] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    invocations: int = 0
    elapsed_s: float = 0.0
    # Wall time per engine invocation, keyed at the engine's spend
    # granularity: coccinelle runs one spatch per rule (key = rule
    # id), semgrep runs one scan per shipped category dir (key =
    # ``category_<dir>``), codeql runs one query-suite pass (key =
    # ``custom-queries``). Recorded in the results JSON so slow rules
    # are visible and boundable (--spatch-timeout).
    rule_timings: Dict[str, float] = field(default_factory=dict)

    @property
    def ran(self) -> bool:
        return self.available and not self.skipped_reason


# ---------------------------------------------------------------------------
# Rule discovery — mirrors the production scanners' enumeration.
# ---------------------------------------------------------------------------

_EXCLUDED_SEMGREP_RULE_DIRS = frozenset({"registry-cache"})


def semgrep_config_dirs() -> List[Path]:
    """Shipped semgrep rule dirs, enumerated exactly like the scanner.

    Mirrors ``packages/static-analysis/scanner.py``: every subdirectory
    of ``RaptorConfig.SEMGREP_RULES_DIR`` except the registry cache.
    """
    from core.config import RaptorConfig

    base = RaptorConfig.SEMGREP_RULES_DIR
    if not base.is_dir():
        return []
    return [
        p for p in sorted(base.iterdir())
        if p.is_dir() and p.name not in _EXCLUDED_SEMGREP_RULE_DIRS
    ]


def discover_semgrep_rules(
    config_dirs: Optional[List[Path]] = None,
) -> Tuple[List[RuleInfo], List[str]]:
    """Parse rule id / languages / CWE metadata from the shipped YAMLs.

    Returns ``(rules, errors)`` — a YAML that fails to parse is an
    error entry, never a crash.
    """
    import yaml

    dirs = semgrep_config_dirs() if config_dirs is None else config_dirs
    rules: List[RuleInfo] = []
    errors: List[str] = []
    for d in dirs:
        for yf in sorted(list(d.glob("*.yaml")) + list(d.glob("*.yml"))):
            try:
                doc = yaml.safe_load(yf.read_text(encoding="utf-8"))
            except (yaml.YAMLError, OSError, UnicodeDecodeError) as exc:
                errors.append(f"{yf}: {exc}")
                continue
            if not isinstance(doc, dict):
                continue
            for entry in doc.get("rules") or []:
                if not isinstance(entry, dict) or not entry.get("id"):
                    continue
                raw_langs = entry.get("languages") or []
                if isinstance(raw_langs, str):
                    raw_langs = [raw_langs]
                langs = frozenset(
                    _SEMGREP_LANG_ALIASES.get(str(lang).lower(),
                                              str(lang).lower())
                    for lang in raw_langs
                )
                meta = entry.get("metadata") or {}
                raw_cwes = meta.get("cwe") or []
                if isinstance(raw_cwes, str):
                    raw_cwes = [raw_cwes]
                cwes = frozenset(
                    c for c in (_normalise_cwe(str(x)) for x in raw_cwes)
                    if c
                )
                rules.append(RuleInfo(
                    engine="semgrep",
                    rule_id=str(entry["id"]),
                    path=str(yf),
                    cwes=cwes,
                    languages=langs,
                ))
    return rules, errors


def cocci_rules_dir() -> Optional[Path]:
    """Shipped Coccinelle rules dir — same location the scanner runs."""
    from core.config import RaptorConfig

    candidate = RaptorConfig.ENGINE_DIR / "coccinelle" / "rules"
    return candidate if candidate.is_dir() else None


def discover_cocci_rules(
    rules_dir: Optional[Path] = None,
) -> List[RuleInfo]:
    """Inventory the shipped .cocci rules.

    Rule id is the file stem (matching ``SpatchResult.rule``); CWEs are
    extracted from the leading comment header, where the shipped rules
    document their target defect class.
    """
    if rules_dir is None:
        rules_dir = cocci_rules_dir()
    if rules_dir is None or not rules_dir.is_dir():
        return []
    rules: List[RuleInfo] = []
    for path in sorted(rules_dir.glob("*.cocci")):
        cwes: set = set()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if not (stripped.startswith("//") or stripped.startswith("/*")
                    or stripped.startswith("*")):
                break
            for m in _CWE_RE.finditer(stripped):
                cwes.add(f"CWE-{int(m.group(1))}")
        rules.append(RuleInfo(
            engine="coccinelle",
            rule_id=path.stem,
            path=str(path),
            cwes=frozenset(cwes),
            languages=frozenset({"c", "cpp"}),
        ))
    return rules


# CodeQL query-pack languages RAPTOR ships custom queries for, keyed by
# the _EXT_LANG source language.
_CODEQL_LANG_FOR = {"c": "cpp", "cpp": "cpp", "java": "java"}


def codeql_query_dir(language: str) -> Optional[Path]:
    """Shipped custom-query dir for one CodeQL language, if any."""
    from core.config import RaptorConfig

    candidate = RaptorConfig.CODEQL_QUERIES_DIR / language
    return candidate if candidate.is_dir() else None


def discover_codeql_rules() -> List[RuleInfo]:
    """Inventory the shipped custom CodeQL queries.

    Rule id is the query's ``@id`` metadata (what SARIF ``ruleId``
    carries); CWEs come from the header's ``external/cwe/cwe-N`` tags
    or any CWE mention in the metadata comment.
    """
    from core.config import RaptorConfig

    base = RaptorConfig.CODEQL_QUERIES_DIR
    if not base.is_dir():
        return []
    lang_sources = {"cpp": frozenset({"c", "cpp"}),
                    "java": frozenset({"java"})}
    rules: List[RuleInfo] = []
    for lang_dir in sorted(p for p in base.iterdir() if p.is_dir()):
        languages = lang_sources.get(lang_dir.name,
                                     frozenset({lang_dir.name}))
        for path in sorted(lang_dir.glob("*.ql")):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            header = text.split("*/", 1)[0]
            id_match = _QL_ID_RE.search(header)
            rule_id = id_match.group(1) if id_match else path.stem
            cwes = frozenset(
                f"CWE-{int(m.group(1))}"
                for m in _CWE_RE.finditer(header)
            )
            rules.append(RuleInfo(
                engine="codeql",
                rule_id=rule_id,
                path=str(path),
                cwes=cwes,
                languages=languages,
            ))
    return rules


def discover_rules(engines: List[str]) -> Tuple[List[RuleInfo], List[str]]:
    """Discover the shipped inventories for the requested engines."""
    rules: List[RuleInfo] = []
    errors: List[str] = []
    if "semgrep" in engines:
        sg_rules, sg_errors = discover_semgrep_rules()
        rules.extend(sg_rules)
        errors.extend(sg_errors)
    if "coccinelle" in engines:
        rules.extend(discover_cocci_rules())
    if "codeql" in engines:
        rules.extend(discover_codeql_rules())
    return rules, errors


# ---------------------------------------------------------------------------
# Graduated rules — synthesized checkers promoted by RuleLibrary
# .graduate / core.audit.checker_library.graduate_checkers into
# ``<project_dir>/engine-rules/``.
# ---------------------------------------------------------------------------


def graduated_semgrep_dir(base: Path) -> Optional[Path]:
    """Graduated semgrep rules dir under one engine-rules base."""
    candidate = base / "semgrep" / "rules"
    if candidate.is_dir() and (
        any(candidate.glob("*.yaml")) or any(candidate.glob("*.yml"))
    ):
        return candidate
    return None


def graduated_cocci_dir(base: Path) -> Optional[Path]:
    """Graduated coccinelle rules dir under one engine-rules base."""
    candidate = base / "coccinelle"
    if candidate.is_dir() and any(candidate.glob("*.cocci")):
        return candidate
    return None


def find_engine_rules_base(
    out_dir: Optional[Path],
    fixture_roots: Iterable[Path] = (),
) -> Optional[Path]:
    """Locate the project's graduated engine-rules base directory.

    Mirrors ``packages/static-analysis/scanner.py``'s
    ``find_engine_rules_dir`` candidate walk (the dashed package dir
    is not importable): graduation writes to
    ``<project_dir>/engine-rules/``, so the candidates are the run
    dir's siblings (``out_dir.parent``, ``out_dir.parent.parent``)
    plus the active project's ``output_dir``.

    SECURITY: same property the scanner enforces — only
    RAPTOR-graduated rules may load. A candidate that resolves inside
    a pinned fixture tree is rejected, so third-party corpus source
    can never plant rule files that run as trusted engine config.
    """
    candidates: List[Path] = []
    if out_dir is not None:
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

    roots = []
    for root in fixture_roots:
        try:
            roots.append(Path(root).resolve())
        except OSError:
            continue

    for candidate in candidates:
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if any(
            resolved == root or root in resolved.parents
            for root in roots
        ):
            logger.warning(
                "graduated-rules: refusing engine-rules dir inside a "
                "pinned fixture tree (%s) — fixture-supplied rules "
                "never load", resolved,
            )
            continue
        if graduated_semgrep_dir(candidate) or graduated_cocci_dir(candidate):
            return candidate
    return None


def discover_graduated_rules(
    engines: List[str],
    base: Optional[Path],
) -> Tuple[List[RuleInfo], List[str]]:
    """Inventory graduated rules under one engine-rules base.

    Only semgrep and coccinelle — the two engines checker synthesis
    graduates runnable rules for. The same parsers as the shipped
    inventories apply; rows are re-tagged ``provenance="graduated"``.
    """
    import dataclasses

    rules: List[RuleInfo] = []
    errors: List[str] = []
    if base is None:
        return rules, errors
    if "semgrep" in engines:
        sg_dir = graduated_semgrep_dir(base)
        if sg_dir is not None:
            sg_rules, sg_errors = discover_semgrep_rules([sg_dir])
            rules.extend(sg_rules)
            errors.extend(sg_errors)
    if "coccinelle" in engines:
        cocci_dir = graduated_cocci_dir(base)
        if cocci_dir is not None:
            rules.extend(discover_cocci_rules(cocci_dir))
    return (
        [dataclasses.replace(r, provenance="graduated") for r in rules],
        errors,
    )


def merge_inventories(
    shipped: List[RuleInfo],
    graduated: List[RuleInfo],
) -> Tuple[List[RuleInfo], List[str]]:
    """Concatenate inventories, dropping graduated key collisions.

    Engine hits carry only ``engine:rule_id``, so a graduated rule
    whose key collides with a shipped rule cannot be attributed
    separately — it is dropped from the inventory with a loud note
    (rename the synthesized rule) rather than silently double-counted.
    """
    seen = {r.key for r in shipped}
    merged = list(shipped)
    errors: List[str] = []
    for rule in graduated:
        if rule.key in seen:
            errors.append(
                f"graduated rule {rule.key} collides with a shipped "
                f"rule id and was dropped from scoring — rename it"
            )
            continue
        seen.add(rule.key)
        merged.append(rule)
    return merged, errors


# ---------------------------------------------------------------------------
# Engine execution — one repo excerpt tree at a time, through the same
# sandboxed runners the production scanners use.
# ---------------------------------------------------------------------------


def _relativize(path: str, root: Path) -> str:
    """Map an engine-reported path back into label coordinate space."""
    if not path:
        return path
    try:
        p = Path(path)
        if p.is_absolute():
            return str(p.resolve().relative_to(root.resolve()))
    except (ValueError, OSError):
        pass
    return path


def _strip_semgrep_prefix(rule_id: str, config_dir: Path) -> str:
    """Undo semgrep's local-config rule-id prefixing.

    For local file configs semgrep emits SARIF ruleIds prefixed with
    the dotted config path (``/x/rules`` + ``raptor.foo`` ->
    ``x.rules.raptor.foo``); the inventory carries the bare YAML id.
    """
    try:
        prefix = (
            str(config_dir.resolve()).lstrip("/").replace("/", ".") + "."
        )
    except OSError:
        return rule_id
    if rule_id.startswith(prefix):
        return rule_id[len(prefix):]
    return rule_id


def run_semgrep_engine(
    excerpt: Path,
    *,
    config_dirs: Optional[List[Path]] = None,
    timeout: int = 900,
    label_prefix: str = "category",
) -> EngineOutcome:
    """Run semgrep rule configs over the excerpt tree.

    Default configs are the shipped category dirs; a graduated pass
    passes its own ``config_dirs`` with ``label_prefix="graduated"``
    so invocation names in errors/timings stay distinguishable.
    """
    outcome = EngineOutcome(engine="semgrep")
    from packages.semgrep import runner as semgrep_runner

    if not semgrep_runner.is_available():
        outcome.available = False
        outcome.skipped_reason = "semgrep not installed"
        return outcome

    dirs = semgrep_config_dirs() if config_dirs is None else config_dirs
    if not dirs:
        outcome.skipped_reason = "no shipped semgrep rule dirs found"
        return outcome

    t0 = time.monotonic()
    for d in dirs:
        name = f"{label_prefix}_{d.name}"
        result = semgrep_runner.run_rule(
            excerpt, str(d), name=name, timeout=timeout,
        )
        outcome.invocations += 1
        outcome.rule_timings[name] = round(
            result.elapsed_ms / 1000.0, 3,
        )
        if not result.ok:
            detail = "; ".join(result.errors) or f"rc={result.returncode}"
            outcome.errors.append(f"{name}: {detail}")
        for f in result.findings or []:
            outcome.hits.append(RuleHit(
                engine="semgrep",
                rule_id=_strip_semgrep_prefix(f.rule_id, d),
                file=_relativize(f.file, excerpt),
                line=int(f.line or 0),
                line_end=int(f.line_end or 0),
                message=(f.message or "")[:200],
            ))
    outcome.elapsed_s = time.monotonic() - t0
    return outcome


def _has_c_sources(excerpt: Path) -> bool:
    for suffix in ("c", "h", "cc", "cpp", "cxx", "hpp"):
        try:
            next(excerpt.rglob(f"*.{suffix}"))
            return True
        except StopIteration:
            continue
    return False


def run_cocci_engine(
    excerpt: Path,
    *,
    rules_dir: Optional[Path] = None,
    timeout_per_rule: int = DEFAULT_SPATCH_TIMEOUT,
) -> EngineOutcome:
    """Run the shipped .cocci rules over the excerpt tree.

    Mirrors the production cocci stage: ``--no-includes`` (excerpt
    trees have no headers anyway) and ``allow_scripting=True`` — the
    shipped rules are in-repo, code-trust content.
    """
    outcome = EngineOutcome(engine="coccinelle")
    from packages.coccinelle import runner as cocci_runner

    if not cocci_runner.is_available():
        outcome.available = False
        outcome.skipped_reason = "spatch not installed"
        return outcome

    if rules_dir is None:
        rules_dir = cocci_rules_dir()
    if rules_dir is None or not rules_dir.is_dir():
        outcome.skipped_reason = "no shipped coccinelle rules dir found"
        return outcome
    if not _has_c_sources(excerpt):
        outcome.skipped_reason = "no C/C++ sources among pinned files"
        return outcome

    t0 = time.monotonic()
    results = cocci_runner.run_rules(
        excerpt, rules_dir,
        no_includes=True,
        timeout_per_rule=timeout_per_rule,
        allow_scripting=True,
    )
    for res in results:
        outcome.invocations += 1
        outcome.rule_timings[res.rule] = round(res.elapsed_ms / 1000.0, 3)
        if not res.ok:
            detail = "; ".join(res.errors) or f"rc={res.returncode}"
            outcome.errors.append(f"{res.rule}: {detail}")
        for m in res.matches or []:
            message = m.message or ""
            if m.rule and m.rule != res.rule:
                message = f"[{m.rule}] {message}"
            outcome.hits.append(RuleHit(
                engine="coccinelle",
                rule_id=res.rule,
                file=_relativize(m.file, excerpt),
                line=int(m.line or 0),
                line_end=int(m.line_end or 0),
                message=message[:200],
            ))
    outcome.elapsed_s = time.monotonic() - t0
    return outcome


def merge_engine_outcomes(
    a: EngineOutcome, b: EngineOutcome,
) -> EngineOutcome:
    """Merge two same-engine outcomes over the same excerpt tree
    (shipped pass + graduated pass). A half that did not run
    contributes nothing; when neither ran the first skip wins."""
    if not a.ran:
        return b if b.ran else a
    if not b.ran:
        return a
    a.hits.extend(b.hits)
    a.errors.extend(b.errors)
    a.invocations += b.invocations
    a.elapsed_s += b.elapsed_s
    a.rule_timings.update(b.rule_timings)
    return a


def _label_languages(labels: List[Any]) -> set:
    return {
        lang for lang in (
            _EXT_LANG.get(Path(label.source.file).suffix.lower())
            for label in labels
        )
        if lang
    }


def codeql_feasibility(labels: List[Any]) -> Tuple[str, str]:
    """Decide whether CodeQL can honestly run for one repo's labels.

    Returns ``(codeql_language, "")`` when feasible, or ``("", reason)``
    when not.  CodeQL needs a database extraction pass: buildless
    extraction exists for C/C++ (and is the sandboxed default —
    untrusted build scripts never run), while Java custom queries need
    a traced build of the pinned upstream repo, which excerpt trees
    cannot provide.  Languages RAPTOR ships no custom queries for are
    skipped outright rather than faked with upstream suites.
    """
    if shutil.which("codeql") is None:
        return "", "codeql CLI not on PATH"

    langs = _label_languages(labels)
    if not langs:
        return "", "no recognised source language among pinned files"

    candidates = []
    unsupported = []
    for lang in sorted(langs):
        ql_lang = _CODEQL_LANG_FOR.get(lang)
        if ql_lang and codeql_query_dir(ql_lang) is not None:
            candidates.append(ql_lang)
        else:
            unsupported.append(lang)
    if not candidates:
        return "", (
            "no shipped custom CodeQL queries for language(s): "
            + ", ".join(sorted(unsupported))
        )
    ql_lang = candidates[0]
    if ql_lang == "java":
        return "", (
            "java custom queries need a traced build of the pinned "
            "repo — not feasible on a corpus excerpt tree"
        )
    return ql_lang, ""


def run_codeql_engine(
    excerpt: Path,
    labels: List[Any],
    out_dir: Path,
    *,
    db_root: Optional[Path] = None,
) -> EngineOutcome:
    """Run the shipped custom CodeQL queries where extraction is feasible.

    Buildless C/C++ extraction over an excerpt tree tolerates missing
    headers but is necessarily partial — results measure what the
    custom queries see under those conditions, and a failed database
    build is a skip (with the CLI error preserved), never a fake pass.
    """
    outcome = EngineOutcome(engine="codeql")
    if shutil.which("codeql") is None:
        outcome.available = False
        outcome.skipped_reason = "codeql CLI not on PATH"
        return outcome

    language, reason = codeql_feasibility(labels)
    if not language:
        outcome.skipped_reason = reason
        return outcome

    query_dir = codeql_query_dir(language)
    if query_dir is None:  # feasibility already checked; defensive
        outcome.skipped_reason = f"no custom queries for {language}"
        return outcome

    from packages.codeql.database_manager import DatabaseManager
    from packages.codeql.query_runner import QueryRunner

    t0 = time.monotonic()
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        manager = DatabaseManager(
            db_root=db_root or out_dir / "codeql-db",
        )
        db_result = manager.create_database(excerpt, language)
        if not db_result.success or db_result.database_path is None:
            outcome.skipped_reason = (
                f"{language} database creation failed"
            )
            outcome.errors.extend(db_result.errors or [])
            return outcome

        runner = QueryRunner()
        t_queries = time.monotonic()
        query_result = runner.run_custom_queries(
            db_result.database_path, query_dir, out_dir, language,
        )
        outcome.invocations = query_result.queries_executed or 1
        # Query-suite wall time only — database extraction is a fixed
        # per-repo cost, not attributable to any one rule.
        outcome.rule_timings["custom-queries"] = round(
            time.monotonic() - t_queries, 3,
        )
        if not query_result.success:
            outcome.errors.extend(query_result.errors or [])
        sarif_path = query_result.sarif_path
        if sarif_path and Path(sarif_path).is_file():
            from packages.semgrep.models import parse_sarif

            findings = parse_sarif(Path(sarif_path).read_text(
                encoding="utf-8", errors="replace",
            ))
            for f in findings:
                outcome.hits.append(RuleHit(
                    engine="codeql",
                    rule_id=f.rule_id,
                    file=_relativize(f.file, excerpt),
                    line=int(f.line or 0),
                    line_end=int(f.line_end or 0),
                    message=(f.message or "")[:200],
                ))
    except RuntimeError as exc:  # CLI detection raced away
        outcome.skipped_reason = str(exc)
    finally:
        outcome.elapsed_s = time.monotonic() - t0
    return outcome


# ---------------------------------------------------------------------------
# Join + scoring (pure — no engine, no filesystem).
# ---------------------------------------------------------------------------


def hit_joins_label(hit: RuleHit, label: Any, slop: int = DEFAULT_SLOP) -> bool:
    """A hit joins a label when it lands in the pinned file and range."""
    if hit.file != label.source.file:
        return False
    lo = label.source.line_start - slop
    hi = label.source.line_end + slop
    h_lo = hit.line
    h_hi = hit.line_end or hit.line
    return h_lo <= hi and h_hi >= lo


def _expected_rule_ids(label: Any) -> Dict[str, List[str]]:
    """Optional per-engine exact-rule pins on the label (else empty)."""
    return getattr(label, "expected_rule_hits", None) or {}


def _label_cwes(label: Any) -> FrozenSet[str]:
    explicit = _normalise_cwe(getattr(label, "cwe", "") or "")
    if explicit:
        return frozenset({explicit})
    return BUG_CLASS_CWES.get(label.bug_class, frozenset())


def _language_compatible(rule: RuleInfo, label: Any) -> bool:
    if not rule.languages or rule.languages & _WILDCARD_LANGS:
        return True
    lang = _EXT_LANG.get(Path(label.source.file).suffix.lower())
    return lang is not None and lang in rule.languages


def rule_targets_label(rule: RuleInfo, label: Any) -> bool:
    """Does this rule claim the label's defect class?

    Exact pins win: when the label carries ``expected_rule_hits`` for
    this rule's engine, membership decides.  Otherwise targeting falls
    back to language compatibility plus CWE intersection with the
    label's CWE (or its bug class's CWE family).
    """
    pinned = _expected_rule_ids(label).get(rule.engine)
    if pinned is not None:
        return rule.rule_id in pinned
    if not _language_compatible(rule, label):
        return False
    return bool(_label_cwes(label) & rule.cwes)


def evaluate(
    labels: List[Any],
    repo_outcomes: Dict[str, Dict[str, EngineOutcome]],
    inventory: List[RuleInfo],
    *,
    slop: int = DEFAULT_SLOP,
) -> Dict[str, Any]:
    """Join engine hits to labels and score against ground truth.

    ``repo_outcomes`` maps repo_key -> engine -> EngineOutcome.  A
    label is *exposed* to an engine only when that engine actually ran
    over the label's repo — unexposed (engine, label) pairs never
    count as misses.
    """
    rules_by_key = {r.key: r for r in inventory}

    def exposed(label: Any, engine: str) -> bool:
        outcome = repo_outcomes.get(label.source.repo, {}).get(engine)
        return outcome is not None and outcome.ran

    # Join hits per label.
    label_rows: List[Dict[str, Any]] = []
    joined: Dict[Tuple[str, str], List[RuleHit]] = {}
    for label in labels:
        row_hits: List[RuleHit] = []
        for engine, outcome in repo_outcomes.get(
                label.source.repo, {}).items():
            if not outcome.ran:
                continue
            for hit in outcome.hits:
                if hit_joins_label(hit, label, slop):
                    row_hits.append(hit)
                    joined.setdefault(
                        (label.function_id, f"{hit.engine}:{hit.rule_id}"),
                        [],
                    ).append(hit)
        targeted_by = sorted(
            rule.key for rule in inventory
            if rule_targets_label(rule, label)
        )
        detected_by = sorted({
            f"{h.engine}:{h.rule_id}" for h in row_hits
            if f"{h.engine}:{h.rule_id}" in rules_by_key
            and rule_targets_label(
                rules_by_key[f"{h.engine}:{h.rule_id}"], label)
        })
        label_rows.append({
            "function_id": label.function_id,
            "bug_class": label.bug_class,
            "expected": label.expected_status,
            "cwe": getattr(label, "cwe", ""),
            "status": "evaluated",
            "engines_exposed": sorted(
                e for e in repo_outcomes.get(label.source.repo, {})
                if exposed(label, e)
            ),
            "hits": [
                {"engine": h.engine, "rule_id": h.rule_id,
                 "line": h.line, "message": h.message}
                for h in row_hits
            ],
            "targeted_by": targeted_by,
            "detected_by": detected_by,
        })

    # Per-rule scoring.
    per_rule: List[Dict[str, Any]] = []
    for rule in inventory:
        tp: List[str] = []
        fp: List[str] = []
        misses: List[str] = []
        untargeted: List[str] = []
        dormant_hits: List[str] = []
        for label in labels:
            if not exposed(label, rule.engine):
                continue
            has_hit = bool(joined.get((label.function_id, rule.key)))
            targets = rule_targets_label(rule, label)
            if label.expected_status == "finding":
                if targets and has_hit:
                    tp.append(label.function_id)
                elif targets:
                    misses.append(label.function_id)
                elif has_hit:
                    untargeted.append(label.function_id)
            elif label.expected_status == "clean":
                if has_hit:
                    fp.append(label.function_id)
            elif label.expected_status == "dormant":
                if has_hit:
                    dormant_hits.append(label.function_id)
        if tp or fp or misses or untargeted or dormant_hits:
            denominator = len(tp) + len(fp)
            per_rule.append({
                "rule": rule.key,
                "engine": rule.engine,
                "rule_id": rule.rule_id,
                "provenance": rule.provenance,
                "cwes": sorted(rule.cwes),
                "tp": tp,
                "fp": fp,
                "misses": misses,
                "untargeted_hits": untargeted,
                "dormant_hits": dormant_hits,
                "precision": (
                    len(tp) / denominator if denominator else None
                ),
            })

    # Per-class rollup.
    per_class: Dict[str, Dict[str, int]] = {}
    for label in labels:
        cls = per_class.setdefault(label.bug_class, {
            "finding_total": 0, "finding_detected": 0,
            "finding_untargeted_hit": 0, "finding_uncovered": 0,
            "clean_total": 0, "clean_false_alarmed": 0,
        })
        row = next(
            r for r in label_rows
            if r["function_id"] == label.function_id
        )
        if label.expected_status == "finding":
            cls["finding_total"] += 1
            if row["detected_by"]:
                cls["finding_detected"] += 1
            elif row["hits"]:
                cls["finding_untargeted_hit"] += 1
            if not row["targeted_by"]:
                cls["finding_uncovered"] += 1
        elif label.expected_status == "clean":
            cls["clean_total"] += 1
            if row["hits"]:
                cls["clean_false_alarmed"] += 1

    # Rule-coverage gaps — the actionable list for rule authoring.
    gaps: List[Dict[str, Any]] = []
    for label in labels:
        if label.expected_status != "finding":
            continue
        row = next(
            r for r in label_rows
            if r["function_id"] == label.function_id
        )
        if not row["targeted_by"]:
            gaps.append({
                "function_id": label.function_id,
                "bug_class": label.bug_class,
                "cwe": getattr(label, "cwe", ""),
                "expected_mechanism": getattr(
                    label, "expected_mechanism", ""),
                "file": label.source.file,
            })

    return {
        "labels": label_rows,
        "per_rule": per_rule,
        "per_class": per_class,
        "coverage_gaps": gaps,
    }


# ---------------------------------------------------------------------------
# Reporting.
# ---------------------------------------------------------------------------


# Summary shows at most this many slow invocations, and only those at
# or above the floor — sub-second rules are noise at summary altitude
# (the full per-rule table lives in the results JSON).
_SUMMARY_SLOWEST_N = 5
_SUMMARY_SLOW_FLOOR_S = 5.0


def format_summary(report: Dict[str, Any]) -> str:
    """Human-readable summary block."""
    meta = report.get("meta", {})
    lines: List[str] = []
    lines.append("=" * 70)
    lines.append("Rule verification run complete")
    lines.append(f"  Engines: {', '.join(meta.get('engines', []))}")
    discovered = f"  Rules discovered: {meta.get('rules_discovered', 0)}"
    if "rules_graduated" in meta:
        discovered += (
            f" ({meta.get('rules_shipped', 0)} shipped + "
            f"{meta.get('rules_graduated', 0)} graduated)"
        )
    lines.append(discovered)
    if meta.get("provenance") and meta["provenance"] != "all":
        lines.append(f"  Provenance filter: {meta['provenance']}")
    lines.append(
        f"  Labels: {meta.get('labels_evaluated', 0)} evaluated, "
        f"{meta.get('labels_skipped', 0)} skipped"
    )
    if meta.get("wall_s") is not None:
        lines.append(f"  Wall clock: {meta['wall_s']:.0f}s")

    engine_notes = meta.get("engine_notes", [])
    if engine_notes:
        lines.append("")
        lines.append("Engine status:")
        for note in engine_notes:
            lines.append(f"  {note}")

    per_class = report.get("per_class", {})
    if per_class:
        lines.append("")
        lines.append(
            f"{'Class':<14} {'Find':>5} {'Det':>4} {'Untgt':>6} "
            f"{'Uncov':>6} {'Clean':>6} {'FA':>4}"
        )
        lines.append("-" * 52)
        for cls in sorted(per_class):
            c = per_class[cls]
            lines.append(
                f"{cls:<14} {c['finding_total']:>5} "
                f"{c['finding_detected']:>4} "
                f"{c['finding_untargeted_hit']:>6} "
                f"{c['finding_uncovered']:>6} "
                f"{c['clean_total']:>6} {c['clean_false_alarmed']:>4}"
            )

    per_rule = report.get("per_rule", [])
    # Shipped and graduated rules are separate populations —
    # graduated (synthesized) rule quality against ground truth is
    # what the tagging exists to measure.
    for provenance, heading in (
        ("shipped", "Shipped rules with corpus interaction:"),
        ("graduated", "Graduated rules with corpus interaction:"),
    ):
        rows = [
            r for r in per_rule
            if r.get("provenance", "shipped") == provenance
        ]
        if not rows:
            continue
        lines.append("")
        lines.append(heading)
        for r in rows:
            parts = []
            if r["tp"]:
                parts.append(f"tp={len(r['tp'])}")
            if r["fp"]:
                parts.append(f"fp={len(r['fp'])}")
            if r["misses"]:
                parts.append(f"miss={len(r['misses'])}")
            if r["untargeted_hits"]:
                parts.append(f"untargeted={len(r['untargeted_hits'])}")
            if r["dormant_hits"]:
                parts.append(f"dormant={len(r['dormant_hits'])}")
            lines.append(f"  {r['rule']}: {', '.join(parts)}")
            for fid in r["fp"]:
                lines.append(f"    FP on clean label: {fid}")
            for fid in r["misses"]:
                lines.append(f"    miss: {fid}")

    timings = report.get("rule_timings") or {}
    slowest = sorted(
        (
            (secs, repo, engine, key)
            for repo, engines in timings.items()
            for engine, per_rule in engines.items()
            for key, secs in per_rule.items()
        ),
        reverse=True,
    )[:_SUMMARY_SLOWEST_N]
    slowest = [t for t in slowest if t[0] >= _SUMMARY_SLOW_FLOOR_S]
    if slowest:
        lines.append("")
        lines.append("Slowest rule invocations:")
        for secs, repo, engine, key in slowest:
            lines.append(f"  {secs:>7.1f}s  {repo}/{engine}: {key}")

    gaps = report.get("coverage_gaps", [])
    lines.append("")
    if gaps:
        lines.append(
            f"RULE-COVERAGE GAPS ({len(gaps)} finding label(s) no "
            f"evaluated rule targets):"
        )
        for g in gaps:
            cwe = f" {g['cwe']}" if g["cwe"] else ""
            mech = (
                f" mechanism={g['expected_mechanism']}"
                if g["expected_mechanism"] else ""
            )
            lines.append(
                f"  {g['function_id']} ({g['bug_class']}{cwe}){mech}"
            )
    else:
        lines.append("No rule-coverage gaps among evaluated finding labels.")

    skipped = report.get("skipped", [])
    if skipped:
        lines.append("")
        lines.append(f"Skipped labels ({len(skipped)} — not failures):")
        for s in skipped:
            lines.append(f"  {s['function_id']}: {s['reason']}")

    errors = meta.get("engine_errors", [])
    if errors:
        lines.append("")
        lines.append(f"Engine errors ({len(errors)}):")
        for e in errors:
            lines.append(f"  {e}")

    return "\n".join(lines)


def _write_report(report: Dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    results_path = out_dir / "rule-eval-results.json"
    with open(results_path, "w") as f:
        json.dump(report, f, indent=2)
        f.write("\n")
    summary_path = out_dir / "rule-eval-summary.txt"
    summary_path.write_text(format_summary(report) + "\n")
    return results_path


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the shipped deterministic rules over the "
                    "/audit calibration corpus and score against "
                    "ground truth",
    )
    parser.add_argument(
        "--class", dest="bug_class", default=None,
        help="Run only one bug class (e.g. lifecycle, uninitialised)",
    )
    parser.add_argument(
        "--label", dest="label_ids", action="append", default=[],
        help="Run only these labels by function_id (repeatable)",
    )
    parser.add_argument(
        "--engine", dest="engines", action="append", default=[],
        choices=sorted(ENGINES),
        help="Engine to run (repeatable; default: semgrep + coccinelle."
             " codeql is opt-in — it needs database extraction, see"
             " run_codeql_engine)",
    )
    parser.add_argument(
        "--slop", type=int, default=DEFAULT_SLOP,
        help="Line slop when joining hits to pinned ranges "
             f"(default: {DEFAULT_SLOP})",
    )
    parser.add_argument(
        "--provenance",
        choices=("all", "shipped", "graduated"),
        default="all",
        help="Which rule population to run and score: the shipped "
             "in-repo inventories, the project's graduated synthesized "
             "rules (RuleLibrary.graduate promotions under "
             "<project>/engine-rules/), or both (default). Per-rule "
             "scores carry the provenance tag either way",
    )
    parser.add_argument(
        "--engine-rules-dir", type=Path, default=None,
        help="Explicit graduated engine-rules base directory "
             "(containing semgrep/rules/ and coccinelle/). Default: "
             "the scanner's candidate walk — run-dir siblings, then "
             "the active project's output dir",
    )
    parser.add_argument(
        "--spatch-timeout", type=int, default=DEFAULT_SPATCH_TIMEOUT,
        help="Per-rule timeout in seconds for each spatch invocation "
             f"(default: {DEFAULT_SPATCH_TIMEOUT}, the production cocci "
             "stage's bound). Kernel-sized excerpts push some shipped "
             "rules to the bound; a timed-out rule is an engine error "
             "for that rule, never a run failure",
    )
    parser.add_argument(
        "--fetch", action="store_true",
        help="Fetch/update pinned sources before running",
    )
    parser.add_argument(
        "--out", type=Path, default=None,
        help="Output directory (default: out/rule-eval-<timestamp>)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Discover rules, verify labels, and report coverage gaps "
             "without running any engine",
    )
    args = parser.parse_args(argv)

    from .label import load_all_labels
    from .run_corpus import (
        _build_excerpt_tree,
        _label_source_status,
        _resolve_source_dirs,
    )

    labels = load_all_labels(bug_class=args.bug_class)
    if args.label_ids:
        id_set = set(args.label_ids)
        labels = [lb for lb in labels if lb.function_id in id_set]
    if not labels:
        print("No labels found.", file=sys.stderr)
        return 1

    engines = list(dict.fromkeys(args.engines)) or list(DEFAULT_ENGINES)
    print(f"Loaded {len(labels)} label(s); engines: {', '.join(engines)}")

    # Sources first: the graduated-rules candidate walk needs the
    # fixture roots to enforce its containment check.
    source_dirs = _resolve_source_dirs(labels, do_fetch=args.fetch)

    shipped_rules: List[RuleInfo] = []
    discovery_errors: List[str] = []
    run_shipped = args.provenance in ("all", "shipped")
    if run_shipped:
        shipped_rules, discovery_errors = discover_rules(engines)

    graduated_base: Optional[Path] = None
    graduated_rules: List[RuleInfo] = []
    if args.provenance in ("all", "graduated"):
        # Explicit dir is an operator trust assertion; the candidate
        # walk enforces the fixture-containment check itself.
        graduated_base = args.engine_rules_dir or find_engine_rules_base(
            args.out, fixture_roots=source_dirs.values(),
        )
        if graduated_base is not None:
            graduated_rules, grad_errors = discover_graduated_rules(
                engines, graduated_base,
            )
            discovery_errors.extend(grad_errors)
        elif args.provenance == "graduated":
            print(
                "No graduated engine-rules dir found (no active project"
                " with graduated rules; pass --engine-rules-dir).",
                file=sys.stderr,
            )
            return 1

    inventory, collision_errors = merge_inventories(
        shipped_rules, graduated_rules,
    )
    discovery_errors.extend(collision_errors)
    n_graduated = len(inventory) - len(shipped_rules)
    print(f"Discovered {len(inventory)} rule(s): {len(shipped_rules)} "
          f"shipped + {n_graduated} graduated "
          f"({len(discovery_errors)} discovery error(s))")

    evaluable: List[Any] = []
    skipped_rows: List[Dict[str, str]] = []
    for label in labels:
        status, detail = _label_source_status(label, source_dirs)
        if status == "ok":
            evaluable.append(label)
        elif status == "prefix":
            skipped_rows.append({
                "function_id": label.function_id,
                "reason": f"file found only at {detail} — fix the "
                          f"fixture symlink (see sources.json)",
            })
        else:
            skipped_rows.append({
                "function_id": label.function_id,
                "reason": detail,
            })

    if args.dry_run:
        # Coverage gaps are an inventory-level question — answerable
        # with zero engine cost, over ALL loaded labels.
        report = evaluate(labels, {}, inventory, slop=args.slop)
        report["skipped"] = skipped_rows
        report["meta"] = {
            "engines": engines,
            "provenance": args.provenance,
            "rules_discovered": len(inventory),
            "rules_shipped": len(shipped_rules),
            "rules_graduated": n_graduated,
            "labels_evaluated": 0,
            "labels_skipped": len(skipped_rows),
            "engine_notes": ["dry run — no engine executed"],
            "engine_errors": discovery_errors,
        }
        if graduated_base is not None:
            report["meta"]["engine_rules_dir"] = str(graduated_base)
        print(format_summary(report))
        return 0

    if not evaluable:
        print("All labels skipped (missing fixtures) — nothing to run.",
              file=sys.stderr)
        for s in skipped_rows:
            print(f"  {s['function_id']}: {s['reason']}", file=sys.stderr)
        return 0

    out_dir = args.out or Path(f"out/rule-eval-{int(time.time())}")

    t0 = time.monotonic()
    repo_outcomes: Dict[str, Dict[str, EngineOutcome]] = {}
    grad_semgrep = (
        graduated_semgrep_dir(graduated_base)
        if graduated_base is not None else None
    )
    grad_cocci = (
        graduated_cocci_dir(graduated_base)
        if graduated_base is not None else None
    )
    excerpt_dirs = _build_excerpt_tree(evaluable, source_dirs)
    try:
        for repo_key, excerpt in excerpt_dirs.items():
            repo_labels = [
                lb for lb in evaluable if lb.source.repo == repo_key
            ]
            outcomes: Dict[str, EngineOutcome] = {}
            for engine in engines:
                print(f"  {repo_key}: running {engine}...", flush=True)
                if engine == "semgrep":
                    o: Optional[EngineOutcome] = None
                    if run_shipped:
                        o = run_semgrep_engine(excerpt)
                    if grad_semgrep is not None:
                        grad = run_semgrep_engine(
                            excerpt, config_dirs=[grad_semgrep],
                            label_prefix="graduated",
                        )
                        o = (
                            grad if o is None
                            else merge_engine_outcomes(o, grad)
                        )
                    outcomes[engine] = o if o is not None else (
                        EngineOutcome(
                            engine=engine,
                            skipped_reason="no graduated semgrep rules",
                        )
                    )
                elif engine == "coccinelle":
                    o = None
                    if run_shipped:
                        o = run_cocci_engine(
                            excerpt,
                            timeout_per_rule=args.spatch_timeout,
                        )
                    if grad_cocci is not None:
                        grad = run_cocci_engine(
                            excerpt, rules_dir=grad_cocci,
                            timeout_per_rule=args.spatch_timeout,
                        )
                        o = (
                            grad if o is None
                            else merge_engine_outcomes(o, grad)
                        )
                    outcomes[engine] = o if o is not None else (
                        EngineOutcome(
                            engine=engine,
                            skipped_reason="no graduated coccinelle rules",
                        )
                    )
                elif engine == "codeql":
                    if run_shipped:
                        outcomes[engine] = run_codeql_engine(
                            excerpt, repo_labels,
                            out_dir / "codeql" / repo_key,
                        )
                    else:
                        # Graduation writes codeql/*.ql but the
                        # execution surface runs a single query dir;
                        # never fake a graduated-only codeql pass.
                        outcomes[engine] = EngineOutcome(
                            engine=engine,
                            skipped_reason=(
                                "graduated-only codeql runs are not "
                                "supported"
                            ),
                        )
                o = outcomes[engine]
                if o.skipped_reason:
                    print(f"    {engine}: skipped — {o.skipped_reason}",
                          flush=True)
                else:
                    print(
                        f"    {engine}: {len(o.hits)} hit(s), "
                        f"{o.invocations} invocation(s), "
                        f"{len(o.errors)} error(s), {o.elapsed_s:.0f}s",
                        flush=True,
                    )
            repo_outcomes[repo_key] = outcomes
    finally:
        for d in excerpt_dirs.values():
            shutil.rmtree(str(d), ignore_errors=True)
    wall_s = time.monotonic() - t0

    report = evaluate(evaluable, repo_outcomes, inventory, slop=args.slop)
    report["skipped"] = skipped_rows

    engine_notes: List[str] = []
    engine_errors: List[str] = list(discovery_errors)
    for repo_key in sorted(repo_outcomes):
        for engine, outcome in sorted(repo_outcomes[repo_key].items()):
            if outcome.skipped_reason:
                engine_notes.append(
                    f"{repo_key}/{engine}: skipped — "
                    f"{outcome.skipped_reason}"
                )
            else:
                engine_notes.append(
                    f"{repo_key}/{engine}: {len(outcome.hits)} hit(s) "
                    f"in {outcome.elapsed_s:.0f}s"
                )
            engine_errors.extend(
                f"{repo_key}/{engine}: {e}" for e in outcome.errors
            )

    report["rule_timings"] = {
        repo_key: {
            engine: outcome.rule_timings
            for engine, outcome in repo_outcomes[repo_key].items()
            if outcome.rule_timings
        }
        for repo_key in sorted(repo_outcomes)
    }

    report["meta"] = {
        "engines": engines,
        "provenance": args.provenance,
        "slop": args.slop,
        "spatch_timeout": args.spatch_timeout,
        "rules_discovered": len(inventory),
        "rules_shipped": len(shipped_rules),
        "rules_graduated": n_graduated,
        "labels_evaluated": len(evaluable),
        "labels_skipped": len(skipped_rows),
        "wall_s": round(wall_s, 1),
        "engine_notes": engine_notes,
        "engine_errors": engine_errors,
    }
    if graduated_base is not None:
        report["meta"]["engine_rules_dir"] = str(graduated_base)

    results_path = _write_report(report, out_dir)
    print(f"\nResults written to {results_path}")
    print()
    print(format_summary(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
