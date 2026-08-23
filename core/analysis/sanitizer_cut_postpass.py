"""Sanitizer-cut post-pass over scan SARIF findings.

The value-bound gate (:mod:`core.analysis.sanitizer_cut`) runs inside
the audit / smt_barrier paths, so a plain ``/scan`` run produced no
``suppressions.jsonl`` evidence and the recall harness's warm scorer
had nothing to measure. This post-pass closes that gap: after the
scanner writes its SARIFs, every finding whose CWE has catalog
sanitizers for the file's language is resolved and evaluated through
the production gate. ``candidate_only`` verdicts are always written
as record-only evidence (``dropped: false``). Full-proof ``suppress``
verdicts ENFORCE when — and only when — the ``sanitizer_dominated``
witness is corpus-earned (``earns_suppression`` in
:mod:`core.analysis.reach_witness`, flipped with operator approval
2026-08-19 under the binary-oracle protocol) AND the caller requested
enforcement: their records carry ``dropped: true`` and their finding
identities are returned so the scanner can filter the combined SARIF
(per-tool SARIFs stay unfiltered as the forensic record). Enforcement
can never exceed the spec: a caller passing ``enforce=True`` against
an unearned spec still records evidence only. The post-pass itself
still never mutates a finding — filtering is the scanner's, driven by
the returned identities.

Source-line discovery
---------------------

The gate needs a taint-source line. CodeQL findings carry one in their
SARIF codeFlows. Semgrep OSS 1.172 computes taint traces but withholds
them from machine output (``dataflow_trace`` requires login), so
semgrep findings get a conservative locator instead: the file must
contain exactly ONE source-shaped call before the sink line — zero or
several source-shaped lines refuse the finding (counted, never
guessed). A wrong source guess is the false-suppression direction, so
ambiguity always loses. The per-language source shapes are seed sets
(<= 9 names each); project-specific sources must come from learned
vocabulary, never this table.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.analysis import threat_model_java as _tm

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

logger = logging.getLogger(__name__)

# Languages with a wired resolver leg (python native, java via
# cfg_builder_java, c via the cpp intraproc path). Anything else is
# refused before the resolver is imported.
_SUPPORTED_LANGUAGES = frozenset({"python", "java", "c"})

_EXT_LANGUAGE = {
    ".py": "python",
    ".java": "java",
    ".c": "c",
    ".h": "c",
}

# Source-shaped call patterns per language, grouped by SOURCE KIND —
# the taxonomy mirrors the CodeQL threat-model kinds the programme
# already trusts (remote/servlet, console, environment, file,
# properties, database, socket). Seed sets <= 9 patterns per kind;
# growth must come from learned vocabulary, never this table.
#
# Per-kind keys beyond "patterns":
#   file_evidence — regexes of which at least one must appear ANYWHERE
#       in the file for the kind to activate. Line-level matching
#       cannot see receiver chains declared on earlier lines, so this
#       is how readLine stays a console source only where System.in is
#       actually in play — a StringReader-only file activates nothing.
#   exclude_line — line-level negative guards (System.getProperty is
#       the environment kind, not the properties kind).
#   resolver_composed — the properties kind composes with b22's strict
#       resolver, RESOLVER FIRST: a getProperty read proven to yield
#       only file-constant/literal-default values is a CONSTANT, not a
#       source; only unresolved reads are tainted-file candidates.
#
# Widening this table is safety-positive for the gate: candidates are
# combined all-must-suppress, so extra candidates make suppression
# strictly harder — the hazard of a MISSING pattern (the true source
# unmatched while another line matches) shrinks as coverage grows.
# Source kinds whose reads the taint-free fold tier could itself
# discharge (System.getenv / getProperty / file / console / database /
# socket reads).  When any of THIS finding's surviving candidates
# carries one of these kinds, the suspected source IS such a read —
# treating it as attacker-free would be circular, so the gate call
# bans the TF system-read producer for the finding (b42; measured as
# 17 environment-source ground-truth-bad Juliet files suppressed).
_TF_COLLIDING_KINDS = frozenset({
    "environment", "properties", "file", "console", "database",
    "socket",
})

_SOURCE_KINDS: dict[str, dict[str, dict[str, Any]]] = {
    "java": {
        "servlet": {
            "patterns": (
                r"\.getParameter\s*\(",
                r"\.getParameterValues\s*\(",
                r"\.getParameterMap\s*\(",
                r"\.getHeader\s*\(",
                r"\.getHeaderNames\s*\(",
                r"\.getHeaders\s*\(",
                r"\.getIntHeader\s*\(",
                r"\.getCookies\s*\(",
                r"\.getQueryString\s*\(",
            ),
        },
        "console": {
            "patterns": (
                r"\.readLine\s*\(",
                r"\.nextLine\s*\(",
                r"\.next\s*\(\s*\)",
            ),
            "file_evidence": (r"System\s*\.\s*in\b",),
        },
        "environment": {
            # Derived from the shared threat-model authority: an API
            # classified as an environment source here can NEVER fold
            # taint-free in const_fold_java (both tables read the same
            # module; the b44 stop-ship's contradiction is structurally
            # impossible). See core.analysis.threat_model_java.
            "patterns": _tm.environment_source_patterns(),
        },
        "file": {
            "patterns": (
                r"\.readLine\s*\(",
                r"\.read\s*\(",
            ),
            "file_evidence": (
                r"new\s+FileReader\b",
                r"new\s+FileInputStream\b",
            ),
        },
        "properties": {
            "patterns": (r"\.getProperty\s*\(",),
            "exclude_line": (r"System\s*\.\s*getProperty",),
            "resolver_composed": True,
        },
        "database": {
            "patterns": (
                r"\.getString\s*\(",
                r"\.getNString\s*\(",
                r"\.getObject\s*\(",
            ),
            "file_evidence": (r"\bResultSet\b", r"\bexecuteQuery\b"),
        },
        "socket": {
            "patterns": (r"\.getInputStream\s*\(",),
            "file_evidence": (r"\bSocket\b",),
        },
    },
    "python": {
        "web": {
            "patterns": (
                r"request\.args",
                r"request\.form",
                r"request\.values",
                r"request\.get_json\s*\(",
            ),
        },
    },
    "c": {},
}


@dataclass
class PostpassStats:
    """Counters for the one-line summary and scan_metrics."""

    examined: int = 0
    recorded_suppress: int = 0
    enforced: int = 0
    # Identities of enforced findings (rule_id, file-as-in-SARIF, line)
    # — the scanner's filter input. Empty when enforcement is off.
    enforced_findings: list[dict[str, Any]] = field(default_factory=list)
    recorded_candidate: int = 0
    refused: int = 0
    refused_reasons: dict[str, int] = field(default_factory=dict)
    budget_exhausted_skips: int = 0
    elapsed_seconds: float = 0.0
    # Which optional gate mechanisms fired (CFG build_notes such as
    # switch:constant-resolved, plus table-load-resolved constancy) —
    # the refusal/mechanism telemetry that ranks the next iteration.
    mechanism_counts: dict[str, int] = field(default_factory=dict)
    # Which source KINDS supplied the candidates for examined findings
    # (locator path only; codeFlows findings are counted as "trace").
    source_kind_counts: dict[str, int] = field(default_factory=dict)

    def source_kind(self, kind: str) -> None:
        self.source_kind_counts[kind] = self.source_kind_counts.get(kind, 0) + 1

    def refuse(self, reason: str) -> None:
        self.refused += 1
        self.refused_reasons[reason] = self.refused_reasons.get(reason, 0) + 1

    def mechanism(self, note: str) -> None:
        self.mechanism_counts[note] = self.mechanism_counts.get(note, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "examined": self.examined,
            "recorded_suppress": self.recorded_suppress,
            "enforced": self.enforced,
            "enforced_findings": list(self.enforced_findings),
            "recorded_candidate": self.recorded_candidate,
            "refused": self.refused,
            "refused_reasons": dict(sorted(self.refused_reasons.items())),
            "budget_exhausted_skips": self.budget_exhausted_skips,
            "mechanism_counts": dict(sorted(self.mechanism_counts.items())),
            "source_kind_counts": dict(sorted(self.source_kind_counts.items())),
            "elapsed_seconds": round(self.elapsed_seconds, 3),
        }


def _sink_method_span(
    resolved_path: Path,
    sink_line: int,
    text_cache: dict[Path, str],
):
    """Sink's enclosing-method span for candidate scoping.

    Uses the shared per-file text cache; any failure returns None and
    scoping simply does not apply (candidates behave as before).
    """
    try:
        if resolved_path not in text_cache:
            text_cache[resolved_path] = resolved_path.read_text(
                encoding="utf-8", errors="replace",
            )
        text = text_cache[resolved_path]
        if not text:
            return None
        from core.analysis.cross_method_java import enclosing_method_span
        return enclosing_method_span(text, sink_line)
    except Exception:  # noqa: BLE001 — scoping is an optimisation, never a failure
        return None


def _language_for(file_path: str) -> str | None:
    for ext, lang in _EXT_LANGUAGE.items():
        if file_path.lower().endswith(ext):
            return lang
    return None


def _resolver_grammar_available(language: str) -> bool:
    """True when the resolver leg for *language* has its parser.

    Python needs only stdlib ``ast``; java and c need optional
    tree-sitter grammar wheels. Probes the exact parser plumbing the
    resolver uses so a broken grammar classifies the same way the
    resolver would see it.
    """
    # Alias the imports: the two builders export the same
    # ``_get_parser`` name with different signatures (java takes no
    # argument, cpp takes the language), and importing both bare into
    # one function scope invites exactly the cross-binding mixup that
    # static call checkers flag.
    try:
        if language == "java":
            from core.analysis.cfg_builder_java import (
                _get_parser as _get_java_parser,
            )
            return _get_java_parser() is not None
        if language == "c":
            from core.analysis.cfg_builder_cpp import (
                _get_parser as _get_cpp_parser,
            )
            return _get_cpp_parser("c") is not None
    except Exception:  # noqa: BLE001 — a broken grammar counts as absent
        return False
    return True


def _grammar_ok(language: str, cache: dict[str, bool]) -> bool:
    """Once-per-run grammar probe with the loud degradation signal.

    When the grammar for a supported language is missing, every one
    of its findings degrades to a ``language-unsupported`` refusal
    (the enumerated inconclusive the sibling channels use) instead of
    being silently folded into ``resolver-refused``, and ONE warning
    line names the missing capability — degraded coverage must never
    be indistinguishable from full coverage.
    """
    if language not in cache:
        cache[language] = _resolver_grammar_available(language)
        if not cache[language]:
            logger.warning(
                "sanitizer-cut post-pass: tree-sitter %s grammar not "
                "installed — %s findings degrade to language-unsupported "
                "refusals (no suppression evidence recorded)",
                language, language,
            )
    return cache[language]


# A finding whose file has more source-shaped lines than this before
# the sink is refused outright — evaluating the gate from each
# candidate stays sound at any count, but the cost is per-candidate
# and unbounded fan-out is a DoS surface on hostile input.
_MAX_CANDIDATE_SOURCES = 4


def _scan_file_for_kinds(
    file_path: Path, language: str, extra_patterns: tuple,
) -> list[tuple] | None:
    """Per-file scan: ``[(line, frozenset(kinds)), ...]`` or None.

    Kind activation, exclusion, and the properties/resolver
    composition all happen here so the result is cacheable per file.
    """
    kinds_table = _SOURCE_KINDS.get(language) or {}
    if not kinds_table and not extra_patterns:
        return []
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    active: dict[str, dict[str, Any]] = {}
    for kind, spec in kinds_table.items():
        evidence = spec.get("file_evidence")
        if evidence and not any(re.search(p, text) for p in evidence):
            continue
        active[kind] = {
            "regex": re.compile("|".join(spec["patterns"])),
            "exclude": [re.compile(p) for p in spec.get("exclude_line", ())],
            "resolver": bool(spec.get("resolver_composed")),
        }
    extra_regex = re.compile("|".join(extra_patterns)) if extra_patterns else None

    resolver = None
    resolver_built = False
    out: list[tuple] = []
    for i, line in enumerate(text.splitlines()):
        lineno = i + 1
        kinds = set()
        for kind, spec in active.items():
            if not spec["regex"].search(line):
                continue
            if any(ex.search(line) for ex in spec["exclude"]):
                continue
            if spec["resolver"]:
                # Resolver first: a proven config constant is not a
                # source. Resolver failure (parser missing, ambiguous
                # line, unresolved read) keeps the line a candidate —
                # the conservative direction for a suppressor.
                if not resolver_built:
                    resolver_built = True
                    try:
                        from core.analysis.config_resolve_java import (
                            make_config_resolver,
                        )
                        resolver = make_config_resolver(
                            text, str(file_path))
                    except Exception:  # noqa: BLE001
                        resolver = None
                if resolver is not None:
                    try:
                        from core.analysis.config_resolve_java import (
                            resolve_line,
                        )
                        if resolve_line(resolver, lineno).resolved:
                            continue
                    except Exception:  # noqa: BLE001
                        pass
            kinds.add(kind)
        if extra_regex is not None and extra_regex.search(line):
            kinds.add("learned")
        if kinds:
            out.append((lineno, frozenset(kinds)))
    return out


def _candidate_source_lines_with_kinds(
    file_path: Path, sink_line: int, language: str,
    _cache: dict[Path, list[tuple] | None],
    extra_patterns: tuple = (),
) -> list[tuple]:
    """Source-shaped lines before the sink with their source kinds.

    The soundness argument for multiple candidates: the taint rule's
    withheld trace started at ONE of these lines, so the gate verdict
    may only suppress when the flow from EVERY candidate is cut — the
    caller enforces all-must-suppress. Zero candidates, an unreadable
    file, or more than :data:`_MAX_CANDIDATE_SOURCES` return ``[]``
    (refusal).
    """
    if file_path not in _cache:
        _cache[file_path] = _scan_file_for_kinds(
            file_path, language, extra_patterns)
    entries = _cache[file_path]
    if entries is None:
        return []
    before_sink = [(ln, kinds) for ln, kinds in entries if ln < sink_line]
    if not before_sink or len(before_sink) > _MAX_CANDIDATE_SOURCES:
        return []
    return before_sink


def _candidate_source_lines(
    file_path: Path, sink_line: int, language: str,
    _cache: dict[Path, list[tuple] | None],
    extra_patterns: tuple = (),
) -> list[int]:
    """Back-compat lines-only view of the kinds variant."""
    return [ln for ln, _ in _candidate_source_lines_with_kinds(
        file_path, sink_line, language, _cache, extra_patterns)]


def _locate_unique_source_line(
    file_path: Path, sink_line: int, language: str,
    _cache: dict[Path, list[int] | None],
    extra_patterns: tuple = (),
) -> int | None:
    """Back-compat single-source form: the file's single source-shaped
    call before the sink, or None when zero/ambiguous/unreadable."""
    lines = _candidate_source_lines(
        file_path, sink_line, language, _cache, extra_patterns)
    if len(lines) != 1:
        return None
    return lines[0]


def _dataflow_source_line(finding: Mapping[str, Any]) -> int | None:
    path = finding.get("dataflow_path") or {}
    source = path.get("source") or {}
    line = source.get("line")
    if isinstance(line, int) and line > 0:
        return line
    return None


# Learned source-method names must be plain Java identifiers before
# they become regex alternates — anything else is refused (a learned
# name is derived from parsed source, but the boundary revalidates).
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")


def _compile_extra_source_patterns(names: Iterable[str]) -> tuple:
    r"""Run-scoped learned source patterns (e.g. source-wrapper methods).

    Each valid identifier becomes a ``\.name\s*(`` call pattern —
    the same shape as the seed table. Invalid names are dropped, not
    escaped: the caller passes mechanically-derived method names, so
    anything non-identifier is a contract violation worth losing.
    """
    out = [r"\." + re.escape(name) + r"\s*\(" for name in names or () if isinstance(name, str) and _IDENT_RE.match(name)]
    return tuple(out)


def run_postpass(
    sarif_paths: Iterable[Path],
    repo_root: Path,
    out_dir: Path,
    *,
    budget_seconds: float = 180.0,
    extra_source_patterns: Iterable[str] = (),
    enforce: bool = True,
) -> dict[str, Any]:
    """Run the record-only gate over every eligible SARIF finding.

    Returns the stats dict (also logged as a one-line summary). Any
    unexpected per-finding failure is a refusal, never an exception —
    the post-pass must not be able to fail a scan.
    """
    from core.analysis.finding_resolver import ResolvedFinding, resolve_finding
    from core.analysis.sanitizer_cut import (
        VERDICT_CANDIDATE_ONLY,
        VERDICT_SUPPRESS,
        evaluate_finding,
        record_sanitizer_cut_suppression,
    )
    from core.dataflow.sanitizer_catalog import sanitizer_callables_for_cwe
    from core.sarif.parser import parse_sarif_findings

    # Enforcement is bounded by the earning contract, not the caller:
    # enforce=True only takes effect while the sanitizer_dominated
    # witness kind is corpus-earned (derived set membership tracks
    # VERDICTS[*].earns_suppression). Reverting the one spec field
    # returns every caller to record-only with no further changes.
    from core.analysis.reach_witness import (
        STRUCTURALLY_SUPPRESSIBLE_KINDS,
        VERDICTS,
    )
    _san_spec = VERDICTS["sanitizer_dominated"]
    enforce_live = bool(enforce) and (
        _san_spec.earns_suppression
        and _san_spec.kind in STRUCTURALLY_SUPPRESSIBLE_KINDS
    )

    stats = PostpassStats()
    started = time.monotonic()
    learned_patterns = _compile_extra_source_patterns(extra_source_patterns)
    if learned_patterns:
        stats.mechanism_counts["learned-source-patterns"] = len(learned_patterns)
    source_cache: dict[Path, list[int] | None] = {}
    text_cache: dict[Path, str] = {}
    grammar_cache: dict[str, bool] = {}
    repo_root = Path(repo_root).resolve()

    findings: list[dict[str, Any]] = []
    for sarif in sarif_paths:
        try:
            findings.extend(parse_sarif_findings(Path(sarif)))
        except Exception as exc:  # noqa: BLE001 — hostile/malformed SARIF must not kill the pass
            logger.warning("sanitizer-cut post-pass: unreadable SARIF %s: %s", sarif, exc)

    # Group by file so the resolver's per-finding parse cost clusters;
    # the source-locator cache is per-file already.
    findings.sort(key=lambda f: str(f.get("file") or ""))

    for finding in findings:
        if time.monotonic() - started > budget_seconds:
            stats.budget_exhausted_skips += 1
            continue

        cwe = finding.get("cwe_id") or ""
        file_path = str(finding.get("file") or "")
        sink_line = finding.get("startLine") or 0
        if not (cwe and file_path and sink_line):
            continue  # not an eligible shape; don't count as examined

        language = _language_for(file_path)
        if language not in _SUPPORTED_LANGUAGES:
            continue

        try:
            if not sanitizer_callables_for_cwe(cwe, language) \
                    and language != "java":
                # No catalog coverage for this class/language. Java
                # proceeds regardless: the constant-definers and
                # collection-guard pre-checks suppress without any
                # call-shaped sanitizer, and sqli/cmdi/pathtrav — the
                # classes with EMPTY Java catalogs — are exactly where
                # the allowlist-guard idiom lives.
                continue
        except Exception:  # noqa: BLE001
            continue

        resolved_path = Path(file_path)
        if not resolved_path.is_absolute():
            resolved_path = repo_root / file_path
        try:
            inside = resolved_path.resolve().is_relative_to(repo_root)
        except (OSError, ValueError):
            inside = False
        if not inside or not resolved_path.is_file():
            stats.examined += 1
            stats.refuse("file-outside-target-or-missing")
            continue

        stats.examined += 1

        if not _grammar_ok(language, grammar_cache):
            stats.refuse("language-unsupported")
            continue

        finding_kinds: set = set()
        trace_line = _dataflow_source_line(finding)
        if trace_line is not None:
            source_lines = [trace_line]
            stats.source_kind("trace")
            # Classify the trace's own source line so the circularity
            # ban (below) covers trace-carrying findings too: a
            # CodeQL flow that STARTS at a system read must not have
            # that read discharged as taint-free.
            if language == "java":
                tk = _candidate_source_lines_with_kinds(
                    resolved_path, int(sink_line) + 10**9, language,
                    source_cache,
                    learned_patterns if language == "java" else (),
                )
                for ln, ks in tk:
                    if ln == trace_line:
                        finding_kinds |= set(ks)
        else:
            with_kinds = _candidate_source_lines_with_kinds(
                resolved_path, int(sink_line), language, source_cache,
                learned_patterns if language == "java" else (),
            )
            source_lines = [ln for ln, _ in with_kinds]
            for kind in sorted({k for _, ks in with_kinds for k in ks}):
                stats.source_kind(kind)
            if language == "java" and source_lines:
                # Traceless findings come from intra-procedural taint
                # (trace-capable producers emit traces, which take the
                # branch above), so a candidate outside the sink's
                # enclosing method cannot be the withheld source —
                # scope it out. See core.analysis.cross_method_java.
                span = _sink_method_span(
                    resolved_path, int(sink_line), text_cache,
                )
                if span is not None:
                    _name, span_start, span_end = span
                    in_method = [
                        ln for ln in source_lines
                        if span_start <= ln <= span_end
                    ]
                    scoped_out = len(source_lines) - len(in_method)
                    if scoped_out:
                        for _i in range(scoped_out):
                            stats.mechanism("cross-method:candidate-scoped")
                        source_lines = in_method
            surviving = set(source_lines)
            for ln, ks in with_kinds:
                if ln in surviving:
                    finding_kinds |= set(ks)
                    # Caller-mediated taint needs no extra candidate:
                    # the gate's definer-exclusivity condition is
                    # source-agnostic, so a sink argument reachable
                    # from a method parameter fails condition 3 under
                    # EVERY candidate (pinned by
                    # test_params_entry_redundant_with_condition3).
        if not source_lines:
            stats.refuse("no-source-candidates")
            continue
        if finding_kinds & _TF_COLLIDING_KINDS:
            stats.mechanism("taint-free:banned-system-read-source")

        # Evaluate from EVERY candidate source. Suppress only when
        # all candidates suppress (the withheld taint trace started at
        # one of them, so every one must be cut); candidate_only when
        # nothing worse than candidate_only appears; anything else —
        # a no_suppress verdict, a resolver refusal, or a gate error
        # on any candidate — refuses the whole finding.
        verdicts: list[str] = []
        native = None
        for source_line in source_lines:
            native = {
                "cwe": cwe,
                "file_path": str(resolved_path),
                "source_line": int(source_line),
                "sink_line": int(sink_line),
                # The record writer reads "line": without it every
                # suppression record carried line=None and could
                # never be placed inside a line-scoped ground-truth
                # entry — the damage metric's measured blind spot.
                "line": int(sink_line),
                "language": language,
                "rule_id": finding.get("rule_id") or "",
                "tool": finding.get("tool") or "",
            }
            try:
                resolved = resolve_finding(native)
                if not isinstance(resolved, ResolvedFinding):
                    verdicts = ["resolver-refused"]
                    break
                if language == "java":
                    if resolved_path not in text_cache:
                        try:
                            text_cache[resolved_path] = resolved_path.read_text(
                                encoding="utf-8", errors="replace",
                            )
                        except OSError:
                            text_cache[resolved_path] = ""
                    java_text = text_cache[resolved_path] or None
                else:
                    java_text = None
                result = evaluate_finding(
                    resolved.cfg,
                    [resolved.source_node],
                    resolved.sink_node,
                    cwe=resolved.cwe,
                    language=resolved.language,
                    source_symbols=resolved.source_symbols,
                    sink_arg=resolved.sink_arg,
                    extra_bindings=resolved.inter_proc_bindings,
                    java_source_text=java_text,
                    java_file_path=str(resolved_path),
                    repo_root=str(repo_root),
                    ban_tf_system_reads=bool(
                        finding_kinds & _TF_COLLIDING_KINDS
                    ),
                )
            except Exception:  # noqa: BLE001 — arbitrary scanned source can break parsing
                verdicts = ["gate-error"]
                break
            for note in getattr(resolved.cfg, "build_notes", ()) or ():
                stats.mechanism(note)
            reason_text = getattr(result, "reason", "") or ""
            if "constant-table load" in reason_text:
                stats.mechanism("constant:table-load")
            if reason_text.startswith("collection-membership guard"):
                stats.mechanism("collection:membership-guard")
            if ("conduit helper" in reason_text
                    or reason_text.startswith("conduit-constant")):
                stats.mechanism("conduit:constant")
            if "(conduit transparency)" in reason_text:
                stats.mechanism("conduit:transparency")
            if "constant-key collection round-trip" in reason_text:
                stats.mechanism("collection:constant-roundtrip")
            if "tracked local collection" in reason_text:
                stats.mechanism("collection:sanitizer-elements")
            if "non-agreeing taint-free union" in reason_text:
                stats.mechanism("taint-free:definer-union")
            if "returns-taint-free helper union" in reason_text:
                stats.mechanism("taint-free:helper-summary")
            verdicts.append(result.verdict)

        if verdicts == ["resolver-refused"]:
            stats.refuse("resolver-refused")
            continue
        if verdicts == ["gate-error"]:
            stats.refuse("gate-error")
            continue
        full_proof = all(v == VERDICT_SUPPRESS for v in verdicts)
        if full_proof:
            stats.recorded_suppress += 1
        elif all(v in (VERDICT_SUPPRESS, VERDICT_CANDIDATE_ONLY)
                 for v in verdicts):
            stats.recorded_candidate += 1
            if len(verdicts) > 1:
                # Mixed multi-source candidate: counted, not recorded —
                # a record carrying one candidate source's bindings
                # would misattribute the others' evidence.
                continue
        else:
            stats.refuse("no-suppress-verdict")
            continue
        try:
            # Enforcement is structurally limited to FULL-PROOF suppress
            # verdicts (every source candidate individually proven):
            # the candidate_only path can never reach an enforce=True
            # call — pinned by test_candidate_only_never_enforces.
            if full_proof and enforce_live:
                record_sanitizer_cut_suppression(
                    out_dir, native, result, enforce=True,
                )
                stats.enforced += 1
                stats.enforced_findings.append({
                    "rule_id": finding.get("rule_id") or "",
                    "file": str(finding.get("file") or ""),
                    "line": int(sink_line),
                })
            else:
                record_sanitizer_cut_suppression(out_dir, native, result)
        except Exception as exc:  # noqa: BLE001
            logger.warning("sanitizer-cut post-pass: record failed: %s", exc)

    stats.elapsed_seconds = time.monotonic() - started
    logger.info(
        "sanitizer-cut post-pass: %d examined, %d suppress-verdicts recorded "
        "(%d enforced), %d candidate_only recorded, %d refused, "
        "%d skipped on budget (%.1fs)",
        stats.examined, stats.recorded_suppress, stats.enforced,
        stats.recorded_candidate,
        stats.refused, stats.budget_exhausted_skips, stats.elapsed_seconds,
    )
    return stats.to_dict()


def filter_enforced_from_sarif(
    sarif_path: Path,
    enforced: list[dict[str, Any]],
) -> int:
    """Remove enforced findings from one SARIF file, in place.

    The scanner's drop surface for corpus-earned sanitizer-cut
    enforcement: results matching an enforced identity (exact rule id,
    exact start line, and URI suffix-agreement with the recorded file)
    are removed from the combined SARIF. Per-tool SARIFs are never
    passed here — they stay unfiltered as the forensic record, matching
    the binary-oracle convention. Returns the number of results
    removed. Any parse/shape failure removes nothing (0) — filtering
    can only ever be a no-op, never corrupt a SARIF.
    """
    if not enforced:
        return 0
    import json as _json

    def _norm(s: str) -> str:
        return str(s or "").replace("\\", "/").lstrip("./")

    keys = [
        ((e.get("rule_id") or ""), _norm(e.get("file") or ""),
         int(e.get("line") or 0))
        for e in enforced
    ]
    try:
        data = _json.loads(Path(sarif_path).read_text(encoding="utf-8"))
        removed = 0
        for run in data.get("runs") or []:
            results = run.get("results")
            if not isinstance(results, list):
                continue
            kept = []
            for res in results:
                rule = res.get("ruleId") or ""
                uri, line = "", 0
                try:
                    loc = (res.get("locations") or [{}])[0]
                    phys = loc.get("physicalLocation") or {}
                    uri = _norm(
                        (phys.get("artifactLocation") or {}).get("uri") or "")
                    line = int((phys.get("region") or {}).get("startLine") or 0)
                except Exception:  # noqa: BLE001 — malformed location = keep
                    kept.append(res)
                    continue
                hit = any(
                    rule == k_rule and line == k_line
                    and (uri == k_file or uri.endswith("/" + k_file)
                         or k_file.endswith("/" + uri))
                    for (k_rule, k_file, k_line) in keys
                )
                if hit:
                    removed += 1
                else:
                    kept.append(res)
            run["results"] = kept
        if removed:
            Path(sarif_path).write_text(
                _json.dumps(data, indent=2), encoding="utf-8")
        return removed
    except Exception as exc:  # noqa: BLE001 — never corrupt the SARIF
        logger.warning(
            "sanitizer-cut enforcement: SARIF filter failed on %s: %s "
            "(no findings removed)", sarif_path, exc)
        return 0
