"""Coverage records — what each tool examined during a run.

Per-tool records written as coverage-<tool>.json in the run output directory.
Built from the reads manifest (populated by the PostToolUse hook),
Semgrep JSON output, CodeQL SARIF, and findings.json.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.json import load_json, save_json

COVERAGE_RECORD_FILE = "coverage-record.json"  # legacy single-file name
READS_MANIFEST = ".reads-manifest"

# Ceiling on how much of the reads manifest a single reader ingests.
# Legitimate /agentic runs produce manifests under 5 MB even on large
# monorepos; 64 MB is a generous ceiling. In adversarial cases (the
# PostToolUse hook fires on every Read, an LLM in a tight loop reads
# thousands of small files) the manifest can reach hundreds of MB —
# better a partial coverage record than an OOM.
_MANIFEST_CAP = 64 * 1024 * 1024


def _read_manifest_lines(manifest_path: Path) -> set[str]:
    """Read reads-manifest paths under a shared flock with a size cap.

    Single reader for the hook-written ``.reads-manifest`` so every
    consumer (``build_from_manifest``, ``build_from_findings``) gets
    the same reader-writer coordination and memory ceiling.

    Hold a shared flock during the read so an in-flight writer (the
    PostToolUse hook in plugins/coverage/) can't interleave a partial
    line into our buffered iteration — the hook side serialises
    appends via flock LOCK_EX on the same path; taking LOCK_SH here
    completes the coordination. fcntl.flock is non-fatal: on platforms
    without flock (Windows; raptor doesn't really support them but the
    import is best-effort) we fall back to an unlocked read.

    Use ``rstrip("\\r\\n")`` not ``strip()`` — the latter also trims
    leading/trailing spaces, but POSIX permits filenames that
    legitimately START or END with a space. ``track_read`` already
    rejects NUL/CR/LF in the path itself, so a manifest line carrying
    a filename with a trailing space made it in legitimately. Only
    newline-style line terminators need removing.

    Best-effort: returns an empty set when the manifest is missing or
    unreadable.
    """
    files: set[str] = set()
    if not manifest_path.exists():
        return files
    try:
        try:
            import fcntl as _fcntl
        except ImportError:
            _fcntl = None
        with open(manifest_path, "r", encoding="utf-8",
                  errors="replace") as f:
            if _fcntl is not None:
                try:
                    _fcntl.flock(f, _fcntl.LOCK_SH)
                except OSError:
                    pass
            bytes_read = 0
            for line in f:
                bytes_read += len(line)
                if bytes_read > _MANIFEST_CAP:
                    # Cap hit — log and stop. The remaining entries
                    # don't make it into the coverage record.
                    import logging
                    logging.getLogger(__name__).warning(
                        "coverage manifest %s exceeded %d-byte cap; "
                        "truncating coverage record (read %d files)",
                        manifest_path, _MANIFEST_CAP, len(files),
                    )
                    break
                line = line.rstrip("\r\n")
                if line:
                    files.add(line)
            # The flock releases when the file is closed.
    except OSError:
        pass
    return files


def build_from_manifest(run_dir: Path, tool: str,
                        rules_applied: list[str] | None = None,
                        extra_files: list[str] | None = None) -> dict[str, Any] | None:
    """Build a coverage record from the reads manifest.

    The manifest is populated by the PostToolUse hook on Read.
    Deduplicates the raw manifest lines; path normalisation against the
    target happens downstream when the record is imported
    (:mod:`core.coverage.importer`).

    Args:
        run_dir: Run output directory containing .reads-manifest.
        tool: Tool identifier (e.g., "llm:validate", "understand").
        rules_applied: Optional list of rules/stages that ran.
        extra_files: Additional files to include (from other sources).

    Returns:
        Coverage record dict, or None if no manifest exists.
    """
    run_dir = Path(run_dir)
    manifest = run_dir / READS_MANIFEST

    # Locked, capped, streaming read — the manifest is appended to by
    # the PostToolUse hook (LOCK_EX side), so this reader needs the
    # same LOCK_SH coordination as ``build_from_findings``.
    files = _read_manifest_lines(manifest)

    # Add extra files from tool-specific sources
    if extra_files:
        files.update(extra_files)

    if not files:
        return None

    record = {
        "tool": tool,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": sorted(files),
    }
    if rules_applied:
        record["rules_applied"] = rules_applied

    return record


def cleanup_manifest(run_dir: Path) -> bool:
    """Remove the consumed ``.reads-manifest`` from *run_dir*.

    Callers that fold the manifest into a coverage record (e.g. the
    validation helper's ``build_from_findings`` + ``write_record``
    sequence) delete it afterwards so the run-completion hook's
    manifest→``coverage-read.json`` conversion doesn't re-count the
    same reads.  Best-effort: returns True when a manifest was
    removed, False when none existed or removal failed.
    """
    manifest = Path(run_dir) / READS_MANIFEST
    try:
        manifest.unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False


def build_from_semgrep(run_dir: Path, semgrep_json_path: Path,
                       rules_applied: list[str] | None = None,
                       extra_error_json_paths: list[Path] | None = None,
                       ) -> dict[str, Any] | None:
    """Build a coverage record from Semgrep JSON output.

    Reads paths.scanned from Semgrep's JSON output for authoritative
    file list, and errors for files_failed.

    ``extra_error_json_paths``: the OTHER packs' JSON outputs.
    ``paths.scanned`` is cumulative across packs (same tree walk), so
    one file suffices for the examined list — but ``errors`` are
    per-pack: a file dropped by rule timeouts under one pack's rules
    is reported only in that pack's JSON. Merging every pack's errors
    keeps files_failed from silently under-reporting coverage loss.
    """
    data = load_json(semgrep_json_path)
    if not data or not isinstance(data, dict):
        return None

    paths = data.get("paths", {})
    scanned = paths.get("scanned", [])
    if not scanned:
        return None

    errors = list(data.get("errors", []))
    for extra in (extra_error_json_paths or []):
        if Path(extra) == Path(semgrep_json_path):
            continue
        extra_data = load_json(extra)
        if isinstance(extra_data, dict):
            errors.extend(extra_data.get("errors", []))
    version = data.get("version", "")

    record = {
        "tool": "semgrep",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": sorted(scanned),
    }
    if version:
        record["version"] = version
    if rules_applied:
        record["rules_applied"] = rules_applied
    seen: set = set()
    failed = []
    for e in errors:
        if not e.get("path"):
            continue
        key = (e.get("path"), e.get("message", "error"))
        if key in seen:
            continue
        seen.add(key)
        failed.append({"path": e["path"], "reason": e.get("message", "error")})
    if failed:
        record["files_failed"] = failed

    return record


def build_from_cocci(spatch_results: list[Any],
                     spatch_version: str | None = None,
                     ) -> dict[str, Any] | None:
    """Build a coverage record from a list of ``SpatchResult``.

    Source of truth is the runner's structured output, NOT the
    SARIF — the SARIF is the operator-facing artefact and re-parsing
    it would lose data (notably ``files_examined``, which spatch
    emits at runtime but the SARIF translation drops). Same trust
    boundary as ``build_from_semgrep`` reading semgrep's JSON.

    Args:
        spatch_results: list of ``packages.coccinelle.models.SpatchResult``
            produced by ``packages.coccinelle.runner.run_rules``. The
            type is ``Any`` here to keep ``core.coverage.record``
            importable without the ``packages/coccinelle`` package
            (e.g. minimal containers, test scaffolds).
        spatch_version: spatch version string (from
            ``packages.coccinelle.runner.version()``). Best-effort —
            tracked so coverage records distinguish runs across
            spatch upgrades.

    Returns the coverage-record dict, or None when no rules ran
    (matches ``build_from_semgrep`` / ``build_from_codeql`` shape;
    callers don't write empty records).
    """
    if not spatch_results:
        return None

    files: set = set()
    rules_applied: list[str] = []
    failures: list[dict[str, str]] = []

    for r in spatch_results:
        # Defensive attribute access — these are SpatchResult fields
        # but we don't import the dataclass to keep this module's
        # dependency footprint at "stdlib + core.json".
        rule_name = getattr(r, "rule", "") or ""
        if rule_name:
            rules_applied.append(rule_name)
        for f in getattr(r, "files_examined", []) or []:
            if f:
                files.add(f)
        # spatch errors → failures with the rule name as ``path``
        # (no per-file binding from spatch errors; the rule itself
        # is what failed).
        for err in getattr(r, "errors", []) or []:
            failures.append({
                "path": rule_name,
                "reason": str(err)[:500],
            })

    if not files and not rules_applied:
        # Skipped run with no signal at all — don't write a record.
        return None

    record: dict[str, Any] = {
        "tool": "coccinelle",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": sorted(files),
    }
    if spatch_version:
        record["version"] = spatch_version
    if rules_applied:
        record["rules_applied"] = sorted(set(rules_applied))
    # Match the sibling builders (semgrep, codeql): drop failures with
    # an empty path — a SpatchResult with errors but no rule name
    # would otherwise emit a phantom empty-path files_failed entry.
    failures = [f for f in failures if f["path"]]
    if failures:
        record["files_failed"] = failures

    return record


def build_from_codeql(sarif_path: Path) -> dict[str, Any] | None:
    """Build a coverage record from CodeQL SARIF output.

    Extracts: files from artifacts, packs from tool.extensions,
    rules from tool.driver.rules, failures from invocations.
    """
    data = load_json(sarif_path)
    if not data or not isinstance(data, dict):
        return None

    files = []
    packs = []
    rules = []
    failures = []
    version = ""

    for run in data.get("runs", []):
        # Files extracted
        for artifact in run.get("artifacts", []):
            uri = artifact.get("location", {}).get("uri", "")
            if uri:
                files.append(uri)

        # Tool info
        tool = run.get("tool", {})
        driver = tool.get("driver", {})
        version = version or driver.get("version") or driver.get("semanticVersion") or ""
        rules.extend(r.get("id", "") for r in driver.get("rules", []))

        # Packs
        for ext in tool.get("extensions", []):
            name = ext.get("name", "")
            ver = ext.get("version", "")
            packs.append(f"{name}@{ver}" if ver else name)

        # Extraction failures
        for inv in run.get("invocations", []):
            for notif in inv.get("toolExecutionNotifications", []):
                if notif.get("level") in ("error", "warning"):
                    loc = notif.get("locations", [{}])[0] if notif.get("locations") else {}
                    path = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                    failures.append({
                        "path": path,
                        "reason": notif.get("message", {}).get("text", "unknown"),
                    })

    if not files:
        return None

    record = {
        "tool": "codeql",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": sorted(set(files)),
    }
    if version:
        record["version"] = version
    if packs:
        record["packs"] = packs
    if rules:
        record["rules_applied"] = sorted(set(rules))
    failures = [f for f in failures if f["path"]]
    if failures:
        record["files_failed"] = failures

    return record


def build_from_findings(findings_path: Path, reads_manifest_path: Path | None = None,
                        tool: str = "llm") -> dict[str, Any] | None:
    """Build a coverage record from findings.json + optional reads manifest.

    Combines two signals:
    - files_examined: files the LLM opened (from reads manifest)
    - functions_analysed: functions the LLM produced findings/rulings for
    """
    findings_data = load_json(findings_path)
    if not findings_data or not isinstance(findings_data, dict):
        return None

    findings = findings_data.get("findings", [])

    # Functions analysed (from findings with rulings)
    functions = []
    finding_files = set()
    for f in findings:
        file_path = f.get("file", "")
        func = f.get("function", "")
        if file_path and func:
            functions.append({"file": file_path, "function": func})
            finding_files.add(file_path)

    # Files examined (from reads manifest) — locked, capped,
    # streaming read shared with ``build_from_manifest``.
    read_files = set()
    if reads_manifest_path:
        read_files = _read_manifest_lines(reads_manifest_path)

    all_files = sorted(read_files | finding_files)

    if not all_files and not functions:
        return None

    record = {
        "tool": tool,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if all_files:
        record["files_examined"] = all_files
    if functions:
        record["functions_analysed"] = functions

    return record


def build_from_annotations(
    annotations_dir: Path,
    *,
    tool_name: str = "annotations",
) -> dict[str, Any] | None:
    """Build a coverage record from a tree of annotation .md files.

    Every annotated function counts as "examined" for coverage purposes:
    operator manual review and LLM analysis both produce a finished
    record about the function. ``status=clean`` annotations are the
    cleanest signal but any annotation is sufficient evidence — the
    function was looked at.

    Args:
        annotations_dir: Directory containing the annotation tree
            (typically ``<run_output_dir>/annotations``).
        tool_name: ``tool`` field for the resulting record. Defaults
            to ``"annotations"`` for back-compat with /agentic and
            /understand consumers; ``/audit`` passes ``"audit"`` so
            its records land as ``coverage-audit.json`` and are
            distinguishable from generic annotation-derived
            coverage.

    Returns:
        Coverage record dict, or None if the directory doesn't exist
        or contains no annotations.

    Per-function entries include ``status`` and ``hash`` when those
    fields are present in the annotation's metadata — ``/audit``
    populates both at write time, so the resulting record carries
    the verdict and source-line hash inline. Readers that don't
    expect these fields ignore unknown keys.
    """
    annotations_dir = Path(annotations_dir)
    if not annotations_dir.exists():
        return None
    # Local import — avoid circular dependency with packages that
    # use coverage records.
    from core.annotations import iter_all_annotations

    files = set()
    functions: list[dict[str, str]] = []
    seen = set()
    statuses: dict[str, int] = {}
    sources: dict[str, int] = {}
    for ann in iter_all_annotations(annotations_dir):
        if ann.file:
            files.add(ann.file)
        key = (ann.file, ann.function)
        if key in seen:
            continue
        seen.add(key)
        entry: dict[str, str] = {"file": ann.file, "function": ann.function}
        # Include verdict + source-line hash inline when the
        # annotation metadata carries them. /audit's status enum
        # (clean / suspicious / finding / error) flows straight
        # through; staleness detection downstream uses the hash.
        st = ann.metadata.get("status")
        if st:
            entry["status"] = st
            statuses[st] = statuses.get(st, 0) + 1
        h = ann.metadata.get("hash")
        if h:
            entry["hash"] = h
        functions.append(entry)
        src = ann.metadata.get("source")
        if src:
            sources[src] = sources.get(src, 0) + 1
    if not files and not functions:
        return None
    return {
        "tool": tool_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files_examined": sorted(files),
        "functions_analysed": functions,
        # Annotation-specific extension (readers ignore unknown keys).
        "annotation_statuses": statuses,
        "annotation_sources": sources,
    }


def build_from_journal(run_dir: Path,
                       tool_name: str = "journal") -> dict[str, Any] | None:
    """Build a coverage record from review-journal.jsonl.

    Replaces ``build_from_annotations`` for runs that emit journal
    entries instead of annotation .md files (post-migration /agentic).

    Args:
        run_dir: Run output directory containing review-journal.jsonl.
        tool_name: ``tool`` field for the resulting record.

    Returns:
        Coverage record dict, or None if no journal entries exist.
    """
    from core.coverage.journal import load_entries

    entries = load_entries(run_dir)
    if not entries:
        return None

    functions: list[dict[str, str]] = []
    seen = set()
    statuses: dict[str, int] = {}

    for entry in entries:
        key = (entry.file, entry.function)
        if key in seen:
            continue
        seen.add(key)
        func_entry: dict[str, str] = {
            "file": entry.file,
            "function": entry.function,
        }
        if entry.verdict:
            func_entry["status"] = entry.verdict
            statuses[entry.verdict] = statuses.get(entry.verdict, 0) + 1
        if entry.source_hash:
            func_entry["hash"] = entry.source_hash
        functions.append(func_entry)

    if not functions:
        return None
    # Deliberately NO files_examined: the record's tool label is
    # review-grade (llm/analysed — see core/coverage/registry.py), and
    # the importer marks files_examined WHOLE-FILE under the record's
    # tool. A journal entry reviews one function, not its whole file;
    # emitting the file list here inflated every containing file to
    # reviewed. functions_analysed carries the exact spans.
    return {
        "tool": tool_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "functions_analysed": functions,
        "journal_statuses": statuses,
    }


def write_record(run_dir: Path, record: dict[str, Any],
                 tool_name: str | None = None) -> Path:
    """Write a coverage record to the run directory.

    Args:
        run_dir: Run output directory.
        record: Coverage record dict.
        tool_name: If provided, writes coverage-<tool_name>.json.
                   Otherwise writes the legacy coverage-record.json.
    """
    if tool_name:
        filename = f"coverage-{tool_name}.json"
    else:
        filename = COVERAGE_RECORD_FILE
    path = Path(run_dir) / filename
    save_json(path, record)
    return path


def load_records(run_dir: Path) -> list[dict[str, Any]]:
    """Load all coverage records from a run directory.

    The per-tool glob `coverage-*.json` overlaps the legacy
    single-file name `coverage-record.json` (`record` matches
    `*`). Pre-fix the legacy file was picked up by the per-tool
    loop AS WELL as the legacy fallback below — and if the
    legacy file happened to have a `"tool"` key (e.g. an old
    single-file write that pre-dated the per-tool split but
    still recorded a tool name), the per-tool loop accepted it,
    `records` became non-empty, and the legacy fallback never
    fired. The same record then appeared twice in the loaded
    list, double-counting in downstream coverage stats.
    Explicitly exclude `COVERAGE_RECORD_FILE` from the glob so
    the legacy file only flows through its dedicated fallback
    path.
    """
    run_dir = Path(run_dir)
    records = []
    seen_tools = set()
    # Per-tool files at the run-dir top level AND in immediate tool subdirs.
    # Producers write coverage records into their own subdir (agentic's scanner
    # -> scan/, codeql -> codeql/), while a standalone /scan writes them at the
    # top level. coverage-*.json only appears in those tool dirs, so the
    # one-level subdir glob picks up nothing unrelated. Top level is listed
    # first so it wins the per-tool de-dup if a tool's record is in both places.
    candidates = (sorted(run_dir.glob("coverage-*.json"))
                  + sorted(run_dir.glob("*/coverage-*.json")))
    for p in candidates:
        if p.name == COVERAGE_RECORD_FILE:
            continue
        data = load_json(p)
        if isinstance(data, dict) and "tool" in data:
            tool = data.get("tool")
            if tool in seen_tools:
                continue
            seen_tools.add(tool)
            records.append(data)
    # Legacy single file (if no per-tool files found)
    if not records:
        legacy = load_json(run_dir / COVERAGE_RECORD_FILE)
        if legacy:
            records.append(legacy)
    return records


def load_record(run_dir: Path) -> dict[str, Any] | None:
    """Load a coverage record from a run directory. Legacy single-file API."""
    return load_json(Path(run_dir) / COVERAGE_RECORD_FILE)
