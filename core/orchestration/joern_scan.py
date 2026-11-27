"""Joern CPG scan phase for /agentic — a findings-producing scanner.

Promotes the Joern machinery RAPTOR already ships (resident server,
content-hash CPG cache, tiered taint sweep) from evidence/suppression
duty to a first-class scan phase beside Semgrep/CodeQL/OpenAnt:

* **Taint sweep** — the same tiered taint query the audit pre-sweep
  runs (``packages/joern/queries/tiered_taint.sc``), but its flows are
  emitted as SARIF results with ``codeFlows`` instead of being used
  only as reviewer context.
* **Structural queries** — fourteen C/C++ queries ported from the
  upstream Joern query database
  (``packages/joern/queries/structural_c.sc``): the use-after-free
  trio, TOCTOU file races, malloc/memcpy integer overflow, strlen
  truncation, format-string control, strncpy null-termination,
  the privilege-drop-order pair, fixed-offset array access without a
  length check, unchecked read/recv/malloc returns, and the
  gets/getwd banned-function pair. These are syntactic/structural
  traversals (milliseconds on a warm CPG) that CodeQL only matches
  with a successful database build — Joern's fuzzy c2cpg parser needs
  no build, which is the distinctive value on unbuildable targets.

Output is one SARIF 2.1.0 file (``<run>/joern/joern.sarif``) appended
to the run's SARIF list, so normalisation, cross-scanner dedup and the
validation pipeline apply downstream with no new plumbing.

The phase is opt-in via ``--joern-scan``, opt-out via
``--no-joern-scan``, and auto-enables when the target's dominant
language has an evidence-earned Joern profile and the CodeQL analysis
covering that language did not succeed this run
(:func:`joern_scan_decision` is the single authority). It is never
fatal: any failure degrades to a loud warning and the run continues
on the other scanners' findings.
"""

from __future__ import annotations

import logging
import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.paths import to_repo_relative

logger = logging.getLogger(__name__)

_SCANHIT_MARKER = "JOERN_SCANHIT:"
_SCANERR_MARKER = "JOERN_SCANERR:"
_SCANDONE_MARKER = "JOERN_SCAN_DONE:"

#: Expected query count in structural_c.sc — cross-checked against the
#: completion sentinel so a script edit that drops a query is caught.
_STRUCTURAL_QUERY_COUNT = 14

#: Cap on emitted taint results (mirrors the Scala-side flow cap —
#: a pathological target must not produce an unbounded SARIF file).
_MAX_TAINT_RESULTS = 500

#: Structural rules: query name (as emitted in the records) → SARIF
#: rule metadata. CWE tags ride ``properties.cwe`` — the shape
#: ``core.sarif.parser._extract_cwe_from_rule`` reads first.
STRUCTURAL_RULES: dict[str, dict[str, str]] = {
    "free-follows-value-reuse": {
        "description": "A freed value is reused without reassignment"
                       " (use-after-free)",
        "cwe": "CWE-416",
        "level": "error",
    },
    "free-returned-value": {
        "description": "A value returned through an output parameter"
                       " is freed on a path (caller use-after-free)",
        "cwe": "CWE-416",
        "level": "error",
    },
    "free-field-no-reassign": {
        "description": "A struct field reached through a parameter is"
                       " freed and not reassigned on all paths",
        "cwe": "CWE-416",
        "level": "error",
    },
    "file-operation-race": {
        "description": "Two file operations on the same non-literal"
                       " path can act on different files (TOCTOU)",
        "cwe": "CWE-367",
        "level": "warning",
    },
    "malloc-memcpy-int-overflow": {
        "description": "memcpy into a heap buffer whose malloc size"
                       " was computed arithmetically with a different"
                       " length expression",
        "cwe": "CWE-190",
        "level": "warning",
    },
    "strlen-truncation": {
        "description": "strlen result (size_t) assigned to a plain"
                       " int target (truncation)",
        "cwe": "CWE-197",
        "level": "note",
    },
    "format-controlled-printf": {
        "description": "Non-literal format string reaches a"
                       " printf-family sink",
        "cwe": "CWE-134",
        "level": "warning",
    },
    "strncpy-no-null-term": {
        "description": "strncpy fills the whole malloc'd buffer with"
                       " no explicit null termination",
        "cwe": "CWE-170",
        "level": "warning",
    },
    "setuid-without-setgid": {
        "description": "Process user ID changed without dropping"
                       " group privileges first",
        "cwe": "CWE-696",
        "level": "warning",
    },
    "setgid-without-setgroups": {
        "description": "Process group changed without clearing"
                       " ancillary groups first",
        "cwe": "CWE-271",
        "level": "warning",
    },
    "constant-array-access-no-check": {
        "description": "Fixed-offset array access with no sufficient"
                       " length check found (name-heuristic length"
                       " sibling)",
        "cwe": "CWE-129",
        "level": "note",
    },
    "unchecked-read-recv-malloc": {
        "description": "Return value of read/recv/malloc is never"
                       " checked in the caller",
        "cwe": "CWE-252",
        "level": "note",
    },
    "call-to-gets": {
        "description": "Call to gets() — unbounded read into the"
                       " destination buffer, inherently dangerous",
        "cwe": "CWE-242",
        "level": "error",
    },
    "call-to-getwd": {
        "description": "Call to getwd() — unbounded path write,"
                       " deprecated in favour of getcwd",
        "cwe": "CWE-676",
        "level": "warning",
    },
}

#: Taint-sink categorisation: first matching entry wins. Sink names
#: are drawn from the ``packages.joern.lang_config`` profile sink
#: lists (most, not all, are categorised); names with no category
#: fall through to the generic rule.
_TAINT_CATEGORIES: tuple[tuple[str, str, str | None, frozenset[str]], ...] = (
    ("joern-taint-command-injection",
     "Tainted data reaches a command-execution sink", "CWE-78",
     frozenset({
         "system", "popen", "exec", "execve", "execvp", "execl",
         "execlp", "execle", "fexecve", "posix_spawn", "posix_spawnp",
         "subprocess_call", "subprocess_run", "subprocess_Popen",
         "Command", "CommandContext", "execSync", "spawn", "spawnSync",
         "execFile", "start", "Start", "launch",
     })),
    ("joern-taint-buffer-write",
     "Tainted data reaches an unbounded buffer-write sink", "CWE-120",
     frozenset({
         "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat",
         "strncat", "sprintf", "snprintf", "vsprintf", "vsnprintf",
         "gets", "scanf", "sscanf", "fscanf",
     })),
    ("joern-taint-format-string",
     "Tainted data reaches a format-string sink", "CWE-134",
     frozenset({
         "printf", "fprintf", "syslog", "dprintf", "vprintf",
         "vfprintf",
     })),
    ("joern-taint-sql-injection",
     "Tainted data reaches a query-execution sink", "CWE-89",
     frozenset({
         "execute", "executemany", "raw", "executeQuery",
         "executeUpdate", "prepareStatement", "createQuery",
         "createNativeQuery", "query", "Query", "QueryRow", "Exec",
         "Prepare",
     })),
    ("joern-taint-deserialization",
     "Tainted data reaches a deserialisation sink", "CWE-502",
     frozenset({
         "loads", "load", "unserialize", "readObject", "readResolve",
         "fromJson", "readValue", "Unmarshal", "Decode", "NewDecoder",
         "deserialize",
     })),
    ("joern-taint-code-injection",
     "Tainted data reaches a code-evaluation sink", "CWE-94",
     frozenset({
         "eval", "Function", "evaluate", "createExpression",
         "render_template_string", "from_string", "setTimeout",
         "setInterval",
     })),
    ("joern-taint-path-injection",
     "Tainted data reaches a file-path sink", "CWE-73",
     frozenset({
         "fopen", "freopen", "open", "creat", "Open", "Create",
         "OpenFile", "ReadFile", "WriteFile", "readFile",
         "readFileSync", "writeFile", "writeFileSync",
         "createReadStream", "createWriteStream", "FileInputStream",
         "FileOutputStream", "FileWriter", "FileReader",
     })),
    ("joern-taint-request-forgery",
     "Tainted data reaches an outbound-request sink", "CWE-918",
     frozenset({
         "urlopen", "openConnection", "openStream", "connect", "fetch",
         "request", "Get", "Post", "Do", "NewRequest",
     })),
)

_TAINT_FALLBACK_RULE = "joern-taint-dangerous-sink"
_TAINT_FALLBACK_DESC = "Tainted data reaches a dangerous sink"

_CALL_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")

_ALL_CATEGORISED_SINKS: frozenset[str] = frozenset().union(
    *(names for _, _, _, names in _TAINT_CATEGORIES))


def _taint_rule_for(sink_call: str) -> tuple[str, str, str | None]:
    """(rule_id, description, cwe) for a sink call name."""
    for rule_id, desc, cwe, names in _TAINT_CATEGORIES:
        if sink_call in names:
            return rule_id, desc, cwe
    return _TAINT_FALLBACK_RULE, _TAINT_FALLBACK_DESC, None


#: Byte budget for the sink-line fallback read: scanning stops here
#: even if the sink line was not reached (hostile multi-GB files or
#: single multi-GB lines must not cost memory or time).
_SINK_READ_CAP_BYTES = 8 * 1024 * 1024
_SINK_READ_CHUNK = 64 * 1024
#: Retained bytes of the sink line itself (the call name regex only
#: needs the head of the line).
_SINK_LINE_CAP = 1000


def _read_target_line(target_path: Path, uri: str, line: int) -> str:
    """Bounded read of one line from the scanned (untrusted) tree.

    Hardened for hostile repos: ``confine`` re-checks containment with
    symlinks RESOLVED (``to_repo_relative`` is lexical, and a committed
    symlink inside the target can point anywhere), ``O_NOFOLLOW`` +
    ``O_NONBLOCK`` + an ``S_ISREG`` gate refuse symlinked/special files
    (a FIFO would block forever, a device node reads unboundedly), and
    the chunked scan never materialises more than one chunk — a single
    multi-GB line costs at most ``_SINK_LINE_CAP`` retained bytes and
    ``_SINK_READ_CAP_BYTES`` scanned bytes."""
    from core.paths import confine

    resolved = confine(target_path, uri)
    if resolved is None:
        return ""
    fd = None
    try:
        fd = os.open(resolved,
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                     | os.O_CLOEXEC)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return ""
        remaining_newlines = line - 1
        scanned = 0
        collected = b""
        while scanned < _SINK_READ_CAP_BYTES:
            chunk = os.read(
                fd, min(_SINK_READ_CHUNK,
                        _SINK_READ_CAP_BYTES - scanned))
            if not chunk:
                break
            scanned += len(chunk)
            while remaining_newlines > 0:
                cut = chunk.find(b"\n")
                if cut < 0:
                    chunk = b""
                    break
                chunk = chunk[cut + 1:]
                remaining_newlines -= 1
            if remaining_newlines == 0 and chunk:
                end = chunk.find(b"\n")
                collected += chunk if end < 0 else chunk[:end]
                if end >= 0 or len(collected) >= _SINK_LINE_CAP:
                    break
        return collected[:_SINK_LINE_CAP].decode("utf-8",
                                                 errors="replace")
    except (OSError, ValueError):
        logger.debug("sink line read failed for %s:%s", uri, line,
                     exc_info=True)
        return ""
    finally:
        if fd is not None:
            os.close(fd)


def _resolve_sink_name(
    flow: Any, target_path: Path, uri: str, line: int,
    cache: dict[tuple[str, int], str] | None = None,
) -> str:
    """Best-effort sink call name for a taint flow.

    The flow's terminal node is the sink call's ARGUMENT (the taint
    query sources from ``cpg.call.name(sink).argument``), so
    ``flow.sink_call`` is usually empty. Recovery order: the parsed
    sink_call when present, then a known categorised call name in any
    step's code (scanning from the sink end), then the sink line's own
    text in the target tree (bounded read, cached per conversion).
    Empty string means "unknown" and routes to the generic rule."""
    cand = str(getattr(flow, "sink_call", "") or "").strip()
    if cand:
        return cand
    for step in reversed(list(getattr(flow, "steps", []) or [])):
        for name in _CALL_NAME_RE.findall(str(step.code or "")):
            if name in _ALL_CATEGORISED_SINKS:
                return name
    key = (uri, line)
    if cache is not None and key in cache:
        return cache[key]
    resolved = ""
    for name in _CALL_NAME_RE.findall(
            _read_target_line(target_path, uri, line)):
        if name in _ALL_CATEGORISED_SINKS:
            resolved = name
            break
    if cache is not None:
        cache[key] = resolved
    return resolved


@dataclass(frozen=True)
class JoernScanDecision:
    """Outcome of the enablement decision, with its reason."""

    run: bool
    reason: str
    #: True when the operator explicitly asked (``--joern-scan``) —
    #: a blocked explicit request warrants a louder surface than a
    #: skipped auto-enable.
    requested: bool = False


#: detect_language() name → the CodeQL analysis key whose success
#: covers that language this run. CodeQL's ``java`` analysis compiles
#: Kotlin and its ``javascript`` extractor reads TypeScript, so those
#: map onto the covering analysis rather than themselves.
_CODEQL_LANGUAGE_FOR: dict[str, str] = {
    "c": "cpp", "cpp": "cpp",
    "java": "java", "kotlin": "java",
    "javascript": "javascript", "typescript": "javascript",
    "python": "python",
    "go": "go",
    "csharp": "csharp",
    "swift": "swift",
}

#: Languages the auto rule may enable unforced. Evidence-earned, not
#: aspirational: a name is admitted only after a live end-to-end run
#: on this toolchain — sandboxed CPG build, tiered sweep, SARIF with
#: a code-flowed finding on a vulnerable fixture AND silence on its
#: clean control. A profiled language that has not earned this stays
#: behind --joern-scan (forced runs are allowed for ANY language and
#: fail loudly). detect_language() names, lowercase.
_AUTO_ENABLE_LANGUAGES: frozenset[str] = frozenset({
    "c", "cpp", "python", "java", "javascript", "typescript",
    "go", "kotlin", "csharp", "swift",
})


def joern_scan_decision(
    *,
    requested: bool,
    disabled: bool,
    skip_scan: bool,
    openant_only: bool,
    target_path: Path,
    codeql_covered_languages: frozenset[str] | set[str] = frozenset(),
    joern_available: bool | None = None,
    has_joern_sources: bool | None = None,
    language: str | None = None,
) -> JoernScanDecision:
    """Single authority for whether the Joern scan phase runs.

    Precedence: explicit disable, then the scan-replacing modes
    (imported SARIF, ``--openant-only``), then explicit enable, then
    the auto rule — a target whose dominant language has an
    evidence-earned Joern profile (:data:`_AUTO_ENABLE_LANGUAGES`) and
    whose covering CodeQL analysis (:data:`_CODEQL_LANGUAGE_FOR`) did
    not succeed this run gets the phase by default, because Joern's
    fuzzy frontends are the interprocedural dataflow channel that
    needs no build.

    ``codeql_covered_languages``: CodeQL analysis keys (``cpp``,
    ``java``, …) that COMPLETED successfully this run — mere language
    detection does not count (on a mixed repo whose cpp database
    build fails, the run still exits 0 with cpp detected).

    ``joern_available`` / ``has_joern_sources`` / ``language`` default
    to live probes; tests inject values. The sources gate runs before
    the language census is trusted: ``detect_language`` falls back to
    "python" on trees with NO profiled sources, and that fallback must
    never auto-enable a sweep against an unprofiled tree.
    """
    if disabled:
        return JoernScanDecision(False, "disabled by --no-joern-scan")
    if skip_scan:
        return JoernScanDecision(
            False, "imported SARIF replaces the scan step"
                   " (--sarif without --also-scan)",
            requested=requested)
    if openant_only:
        return JoernScanDecision(
            False, "--openant-only replaces the pattern scanners",
            requested=requested)

    if joern_available is None:
        try:
            from packages.joern.prereqs import is_available
            joern_available = is_available()
        except ImportError:
            joern_available = False

    if requested:
        if not joern_available:
            return JoernScanDecision(
                False, "--joern-scan requested but Joern is not"
                       " installed (see packages/joern/prereqs)",
                requested=True)
        return JoernScanDecision(True, "requested via --joern-scan",
                                 requested=True)

    if not joern_available:
        return JoernScanDecision(False, "Joern is not installed")

    if has_joern_sources is None:
        try:
            from core.audit.joern_backend import (
                target_has_c_sources,
                target_has_joern_sources,
            )
            has_joern_sources = (target_has_c_sources(target_path)
                                 or target_has_joern_sources(target_path))
        except ImportError:
            has_joern_sources = False

    if not has_joern_sources:
        return JoernScanDecision(
            False, "no sources with a curated Joern profile"
                   " (pass --joern-scan to force)")

    if language is None:
        try:
            from packages.joern.lang_config import detect_language
            language = detect_language(str(target_path))
        except ImportError:
            language = ""
    language = (language or "").lower()

    if language not in _AUTO_ENABLE_LANGUAGES:
        return JoernScanDecision(
            False, f"auto-enable not earned for {language or 'unknown'}"
                   " targets (pass --joern-scan to force)")

    codeql_key = _CODEQL_LANGUAGE_FOR.get(language, language)
    if codeql_key in codeql_covered_languages:
        return JoernScanDecision(
            False, f"CodeQL produced {codeql_key} coverage this run"
                   " (pass --joern-scan to run both)")
    return JoernScanDecision(
        True, f"auto-enabled: {language} target without CodeQL"
              f" {codeql_key} coverage this run")


@dataclass
class JoernScanOutcome:
    """What the phase produced, for metrics and the run summary."""

    sarif_path: Path | None = None
    finding_count: int = 0
    taint_flow_count: int = 0
    structural_hit_count: int = 0
    language: str = ""
    semantics_rows: int = 0
    errors: list[str] = field(default_factory=list)
    queries_failed: list[str] = field(default_factory=list)
    degraded: bool = False
    elapsed_s: float = 0.0

    def metrics(self) -> dict[str, Any]:
        """The ``scan_metrics['joern']`` payload."""
        return {
            "total_findings": self.finding_count,
            "taint_flows": self.taint_flow_count,
            "structural_hits": self.structural_hit_count,
            "language": self.language,
            "semantics_rows": self.semantics_rows,
            "queries_failed": list(self.queries_failed),
            "errors": list(self.errors),
            "degraded": self.degraded,
            "elapsed_s": round(self.elapsed_s, 1),
            "sarif": str(self.sarif_path) if self.sarif_path else None,
        }


def _flow_location(uri: str, line: int, label: str) -> dict[str, Any]:
    """One ``threadFlows[].locations[]`` entry."""
    return {
        "location": {
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line},
            },
            "message": {"text": label},
        },
    }


def _taint_results(
    flows: list[Any],
    target_path: Path,
    rules: Any,
    errors: list[str],
) -> list[dict[str, Any]]:
    """Convert TaintFlow objects to SARIF results with codeFlows.

    Flows whose sink cannot be mapped to a line inside the target are
    dropped (CPG filenames are target-relative by construction; an
    out-of-root path is either an external header or hostile)."""
    from core.sarif import emit

    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, str]] = set()
    sink_name_cache: dict[tuple[str, int], str] = {}
    for flow in flows:
        if len(results) >= _MAX_TAINT_RESULTS:
            errors.append(
                f"taint results capped at {_MAX_TAINT_RESULTS};"
                " remainder dropped")
            break
        steps = list(getattr(flow, "steps", []) or [])
        if not steps:
            continue
        sink_step = steps[-1]
        sink_uri = to_repo_relative(
            str(sink_step.file or ""), target_path, outside_root="none")
        sink_line = int(sink_step.line or 0)
        if sink_uri is None or sink_line <= 0:
            continue
        sink_uri = Path(sink_uri).as_posix()
        sink_call = _resolve_sink_name(flow, target_path, sink_uri,
                                       sink_line, cache=sink_name_cache)
        rule_id, desc, cwe = _taint_rule_for(sink_call)
        source_method = (flow.source_method or "")[:120]
        key = (rule_id, sink_uri, sink_line, source_method)
        if key in seen:
            continue
        seen.add(key)

        props: dict[str, Any] = {"tags": ["security"]}
        if cwe:
            props["cwe"] = cwe
        rules.add(emit.minimal_rule(
            rule_id, full_description=desc, level="warning",
            properties=props))

        src = (flow.source_param or "")[:120]
        sink_name = (sink_call or "sink")[:120]
        message = (
            f"{desc}: '{src}' from {source_method or 'unknown'}"
            f" reaches {sink_name} at {sink_uri}:{sink_line}"
        )
        entry = emit.result(
            rule_id, message,
            [emit.location(sink_uri, emit.source_region(sink_line))],
            level="warning",
        )
        flow_locs: list[dict[str, Any]] = []
        for idx, step in enumerate(steps):
            step_uri = to_repo_relative(
                str(step.file or ""), target_path, outside_root="none")
            step_line = int(step.line or 0)
            if step_uri is None or step_line <= 0:
                continue
            label = ("source" if idx == 0
                     else "sink" if idx == len(steps) - 1 else "step")
            flow_locs.append(_flow_location(
                Path(step_uri).as_posix(), step_line, label))
        if len(flow_locs) >= 2:
            entry["codeFlows"] = [
                {"threadFlows": [{"locations": flow_locs}]},
            ]
        results.append(entry)
    return results


def _structural_results(
    raw_output: str,
    target_path: Path,
    rules: Any,
    errors: list[str],
    queries_failed: list[str],
) -> list[dict[str, Any]]:
    """Parse structural_c.sc records into SARIF results.

    Vacuity guard: a transcript without the completion sentinel means
    the script never ran to its end — zero hits then read as "not
    scanned" (degraded), never as "clean"."""
    from core.analysis._joern_lines import parse_marker_records
    from core.sarif import emit

    hits, hit_errors = parse_marker_records(raw_output, _SCANHIT_MARKER)
    query_errs, _ = parse_marker_records(raw_output, _SCANERR_MARKER)
    done, _ = parse_marker_records(raw_output, _SCANDONE_MARKER)
    errors.extend(hit_errors)

    for rec in query_errs:
        if isinstance(rec, dict):
            name = str(rec.get("query", "unknown"))[:80]
            queries_failed.append(name)
            errors.append(
                f"structural query {name} failed:"
                f" {str(rec.get('error', ''))[:200]}")

    done_recs = [d for d in done if isinstance(d, dict)]
    if not done_recs:
        errors.append(
            "structural query script did not complete"
            " (no completion sentinel) — structural coverage for this"
            " run is incomplete, not clean")
    elif done_recs[0].get("queries") != _STRUCTURAL_QUERY_COUNT:
        # Script/table drift: the sentinel's declared query count no
        # longer matches this module's rule table expectation.
        errors.append(
            f"structural query count drift: script declared"
            f" {done_recs[0].get('queries')!r}, expected"
            f" {_STRUCTURAL_QUERY_COUNT}")

    results: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for rec in hits:
        if not isinstance(rec, dict):
            continue
        query = str(rec.get("query", ""))
        meta = STRUCTURAL_RULES.get(query)
        if meta is None:
            # Unknown query name in a hit record — a script/table
            # drift signal, surfaced once per name.
            msg = f"unknown structural query in records: {query[:80]!r}"
            if msg not in errors:
                errors.append(msg)
            continue
        uri = to_repo_relative(
            str(rec.get("file", "")), target_path, outside_root="none")
        try:
            line = int(rec.get("line", 0))
        except (TypeError, ValueError, OverflowError):
            # OverflowError: JSON 1e400 parses to float('inf').
            line = 0
        if uri is None or line <= 0:
            continue
        uri = Path(uri).as_posix()
        key = (query, uri, line)
        if key in seen:
            continue
        seen.add(key)

        rule_id = f"joern-{query}"
        rules.add(emit.minimal_rule(
            rule_id, full_description=meta["description"],
            level=meta["level"],
            properties={"cwe": meta["cwe"], "tags": ["security"]}))
        function = str(rec.get("function", ""))[:120]
        message = f"{meta['description']}"
        if function:
            message += f" (function {function})"
        results.append(emit.result(
            rule_id, message,
            [emit.location(uri, emit.source_region(line))],
            level=meta["level"],
        ))
    return results


def run_joern_scan_phase(
    target_path: Path,
    out_dir: Path,
    *,
    query_timeout_s: int | None = None,
) -> JoernScanOutcome:
    """Run the Joern scan phase and write ``<out_dir>/joern/joern.sarif``.

    Reuses the resident-server machinery end to end: content-hash CPG
    cache keyed at the project directory (``out_dir``'s parent — the
    same slot the audit backend and /validate warm), run-dir exclusion
    so this run's artifacts stay out of the content key, and the
    per-language tuning profile. Never raises for operational
    failures — the outcome carries ``errors``/``degraded`` and the
    caller decides how loudly to surface them.
    """
    outcome = JoernScanOutcome()
    t0 = time.monotonic()
    try:
        from packages.joern import joern_session
        from packages.joern.lang_config import detect_language, profile_for
        from packages.joern.runner import run_output_exclude_dirs
        from packages.joern.tunables import JoernTunables
    except ImportError as error:
        outcome.errors.append(f"joern package unavailable: {error}")
        outcome.degraded = True
        return outcome

    target_path = Path(target_path)
    out_dir = Path(out_dir)
    try:
        tunables = JoernTunables.from_tuning()
    except Exception:  # noqa: BLE001 — tuning read must not cost the phase
        logger.debug("joern tunables from_tuning failed", exc_info=True)
        tunables = JoernTunables()

    # Project-level CPG reuse: the run dir's parent is the project
    # directory (same rule as core.audit.joern_backend.
    # resolve_cpg_cache_dir) — a projectless run still caches there.
    cache_dir: Path | None = out_dir.parent
    if cache_dir == out_dir:
        cache_dir = None
    exclude_dirs = run_output_exclude_dirs(out_dir, target_path)

    language = detect_language(str(target_path))
    profile = profile_for(language)
    outcome.language = language
    timeout = int(query_timeout_s or getattr(tunables, "query_timeout_s", 300) or 300)

    queries_dir = (Path(__file__).resolve().parents[2]
                   / "packages" / "joern" / "queries")
    structural_script = queries_dir / "structural_c.sc"

    from core.sarif import emit
    rules = emit.RuleIndex()
    results: list[dict[str, Any]] = []

    try:
        with joern_session(
            target_path, cache_dir=cache_dir, tunables=tunables,
            exclude_dirs=exclude_dirs,
        ) as srv:
            if srv is None:
                outcome.errors.append(
                    "joern session unavailable (CPG build or server"
                    " start failed)")
                outcome.degraded = True
                return outcome

            # Learned sanitiser kill rows (IRIS, tool-corroborated /
            # operator-promoted only) suppress flows the project has
            # already proven sanitised — the same install the audit
            # backend performs, so scan and audit sweeps agree. Its
            # own failures degrade to 0 rows, never to a lost sweep.
            try:
                from core.audit.joern_backend import (
                    install_flow_semantics,
                )
                outcome.semantics_rows = install_flow_semantics(
                    srv, target_path, out_dir=out_dir)
            except Exception:  # noqa: BLE001 — vocab must not cost a sweep
                logger.debug("flow-semantics install failed",
                             exc_info=True)

            taint = srv.run_tiered_sweep(
                timeout=timeout, lang_profile=profile)
            if taint.errors:
                outcome.errors.extend(
                    str(e)[:300] for e in taint.errors)
                outcome.degraded = True
            flows = list(taint.flows or [])
            outcome.taint_flow_count = len(flows)
            results.extend(_taint_results(
                flows, target_path, rules, outcome.errors))

            if language in ("c", "cpp") and structural_script.exists():
                structural = srv.query_script(
                    structural_script, timeout=timeout)
                if structural.errors:
                    outcome.errors.extend(
                        str(e)[:300] for e in structural.errors)
                    outcome.degraded = True
                structural_entries = _structural_results(
                    structural.raw_output or "", target_path, rules,
                    outcome.errors, outcome.queries_failed)
                outcome.structural_hit_count = len(structural_entries)
                results.extend(structural_entries)
    except Exception as error:  # noqa: BLE001 — phase is never fatal
        logger.warning("joern scan phase failed", exc_info=True)
        outcome.errors.append(f"joern scan phase failed: {error}")
        outcome.degraded = True

    outcome.elapsed_s = time.monotonic() - t0
    # Any recorded error means this run's coverage is incomplete —
    # including the converters' vacuity/drift errors and the taint
    # result cap, which are appended without transport errors.
    if outcome.errors or outcome.queries_failed:
        outcome.degraded = True
    if not results:
        return outcome

    from core.json import save_json
    sarif = emit.document(
        [emit.run("joern", rules.rules(), results,
                  information_uri="https://joern.io")],
        schema_uri=emit.SCHEMA_URI_SCHEMASTORE,
    )
    joern_dir = out_dir / "joern"
    joern_dir.mkdir(parents=True, exist_ok=True)
    sarif_path = joern_dir / "joern.sarif"
    save_json(sarif_path, sarif)
    outcome.sarif_path = sarif_path
    outcome.finding_count = len(results)
    return outcome


#: Fraction of total system RAM the two big JVM budgets (CodeQL ``-M``
#: plus the Joern ``-Xmx``) may jointly claim before an explicitly
#: requested Joern scan keeps the serial post-CodeQL ordering instead
#: of overlapping the CodeQL subprocess. Both directions matter:
#: lower (e.g. 0.5) would re-serialise the shipped auto tuning — each
#: budget derives at ~25% of RAM, so the pair sums to ~50%, and the
#: default install is exactly where the overlap is meant to pay —
#: while higher (e.g. 0.9) would admit the ``raptor-tune max`` profile
#: (each budget at ~50% of RAM, the pair at ~100%) beside the
#: already-running Semgrep scan, the co-residency that OOM-kills on
#: swapless hosts. ``-Xmx``/``-M`` are ceilings, not reservations, so
#: the sum overstates typical concurrent RSS — the margin is the
#: point: the gate must stay safe when both engines genuinely grow
#: into their budgets on a large target.
_CONCURRENT_JVM_RAM_FRACTION = 0.75


def joern_concurrency_gate(
    *,
    codeql_running: bool,
    total_ram_mb: int | None = None,
    codeql_ram_mb: int | None = None,
    joern_heap_mb: int | None = None,
) -> tuple[bool, str]:
    """Whether an explicit Joern scan may overlap the CodeQL phase.

    Consulted only for the ``--joern-scan`` lane (the auto-enable rule
    needs CodeQL's per-language coverage and therefore always runs
    after collection). Budgets default to the resolved central tuning
    (``codeql_ram_mb`` / ``joern_heap_mb``) and live RAM detection;
    tests inject values. Any resolution failure answers ``False`` —
    the serial ordering is always correct, so the gate fails toward
    it.

    Returns ``(allowed, reason)``; the reason is a module-authored
    constant-shaped string suitable for logs.
    """
    try:
        if total_ram_mb is None or codeql_ram_mb is None or joern_heap_mb is None:
            from core.tuning import _detect_total_ram_mb, get_tuning
            tuning = get_tuning()
            if total_ram_mb is None:
                total_ram_mb = _detect_total_ram_mb()
            if codeql_ram_mb is None:
                codeql_ram_mb = tuning.codeql_ram_mb
            if joern_heap_mb is None:
                joern_heap_mb = tuning.joern_heap_mb
    except Exception:  # noqa: BLE001 — tuning failure must not pick the risky ordering
        logger.debug("joern concurrency gate: tuning resolution failed",
                     exc_info=True)
        return False, "tuning resolution failed (serial ordering kept)"
    if total_ram_mb <= 0:
        return False, "total RAM unknown (serial ordering kept)"
    claimed_mb = joern_heap_mb + (codeql_ram_mb if codeql_running else 0)
    budget_mb = int(total_ram_mb * _CONCURRENT_JVM_RAM_FRACTION)
    if claimed_mb > budget_mb:
        return False, (
            f"JVM budgets {claimed_mb} MB exceed {budget_mb} MB"
            f" ({_CONCURRENT_JVM_RAM_FRACTION:.0%} of {total_ram_mb} MB RAM)"
            " — serial ordering kept")
    return True, (
        f"JVM budgets {claimed_mb} MB within {budget_mb} MB"
        f" ({_CONCURRENT_JVM_RAM_FRACTION:.0%} of {total_ram_mb} MB RAM)")
