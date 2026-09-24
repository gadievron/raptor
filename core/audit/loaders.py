"""Data loaders for the /audit orchestrator.

Pure I/O helpers that load optional side-channel data (variants, fuzz
coverage, exploit feedback, taint approximations) from the run
directory.  Separated from orchestrator.py for readability — no
orchestrator state is mutated.
"""

from __future__ import annotations

import contextlib
import logging
import os
from pathlib import Path

from core.paths import confine
from typing import Any

from core.json import load_json

logger = logging.getLogger(__name__)


def load_variants(out_dir: Path) -> set[str]:
    """Load variants.json from /understand --hunt if present.

    Returns a set of "file:function" keys that match known variant
    patterns, used to boost priority.
    """
    path = out_dir / "variants.json"
    if not path.exists():
        return set()
    try:
        data = load_json(path, strict=True, max_bytes=64 * 1024 * 1024)
        # Visibility plumbing (docs/security.md I2-(b)): variants.json
        # is LLM-authored; log its provenance stamp (or its absence —
        # both read as untrusted) so the audit trail records the trust
        # status of the priority-boost source.
        from core.artifacts.provenance import provenance_of
        prov = provenance_of(data)
        logger.info(
            "variants: provenance generator=%s untrusted=%s legacy=%s",
            prov["generator"], prov["untrusted"], prov["legacy"],
        )
        targets: set[str] = set()
        for variant in data if isinstance(data, list) else data.get("variants", []):
            fp = variant.get("file", "")
            fn = variant.get("function", "")
            if fp and fn:
                targets.add(f"{fp}:{fn}")
        if targets:
            logger.info("variants: %d pattern-match targets loaded", len(targets))
        return targets
    except Exception:
        logger.debug("variants.json load failed", exc_info=True)
        return set()


def load_coverage_records(out_dir: Path) -> list[dict[str, Any]]:
    """Load the run's coverage records: per-tool + legacy.

    Modern per-tool records (``coverage-*.json`` via
    ``core.coverage.record.load_records`` — the same loader the
    ``raptor-audit gaps`` CLI uses) feed the gap computation's covered
    set and file-tool priority tiers. Pre-fix only the legacy
    single-file ``coverage-record.json`` was loaded here, so the
    orchestrator path saw an empty list on every modern run — record
    priority tiers and ``--mark`` suppression were silently inert.
    ``load_records`` still serves the legacy single file as a fallback
    for runs that pre-date the per-tool split (list-shaped legacy
    files, which this loader always accepted, are spliced flat).
    """
    records: list[dict[str, Any]] = []
    try:
        from core.coverage.record import load_records
        loaded = load_records(out_dir)
    except Exception:
        logger.debug("coverage record load failed", exc_info=True)
        return records
    for rec in loaded:
        # A list-shaped legacy coverage-record.json comes back as one
        # list element from load_records' fallback; this loader always
        # accepted list-shaped legacy files, so splice it flat.
        if isinstance(rec, list):
            records.extend(r for r in rec if isinstance(r, dict))
        elif isinstance(rec, dict):
            records.append(rec)
    return records


def load_exploit_feedback(out_dir: Path, load_feedback_state, FeedbackState):
    """Load exploit feedback state from the project or run directory."""
    candidates = [
        out_dir / "exploit-feedback.json",
        out_dir.parent / "exploit-feedback.json",
    ]
    for path in candidates:
        if path.is_file():
            state = load_feedback_state(path)
            if state.source_precision or state.checker_precision:
                return state
    return FeedbackState()


def load_fuzz_coverage(out_dir: Path) -> dict[str, Any] | None:
    """Load fuzz coverage data if present.

    Shape-gated: coverage-fuzz.json is a run-dir artifact, so a
    malformed or tampered non-dict root must load as absent — one
    list-shaped file made every review of the run raise at
    per-function context assembly.
    """
    path = out_dir / "coverage-fuzz.json"
    if not path.exists():
        return None
    data = load_json(path, max_bytes=64 * 1024 * 1024)
    if not isinstance(data, dict):
        if data is not None:
            logger.warning(
                "coverage-fuzz.json in %s is %s-shaped, expected object "
                "— ignoring the artifact",
                out_dir, type(data).__name__,
            )
        return None
    return data


def load_fuzz_coverage_any(
    out_dir: Path,
    sibling_dirs: list[Path] | tuple[Path, ...] = (),
) -> dict[str, Any] | None:
    """Per-function fuzz coverage from this run, else newest sibling.

    In project mode /fuzz writes ``coverage-fuzz.json`` into its OWN
    run directory — the per-function consumer only ever read the audit
    run's dir, so the artifact was invisible one directory over. Falls
    back to the newest sibling run (by artifact mtime) that carries a
    per-function ``files`` map.
    """
    own = load_fuzz_coverage(out_dir)
    if own is not None:
        return own
    best: tuple[int, dict[str, Any]] | None = None
    for d in sibling_dirs or ():
        path = Path(d) / "coverage-fuzz.json"
        try:
            if not path.is_file():
                continue
            data = load_fuzz_coverage(Path(d))
            if not data or not data.get("files"):
                continue
            mtime = path.stat().st_mtime_ns
        except OSError:
            continue
        if best is None or mtime > best[0]:
            best = (mtime, data)
    return best[1] if best else None


def fuzz_coverage_for(
    fuzz_data: dict[str, Any],
    file_path: str,
    function_name: str,
) -> dict[str, Any] | None:
    """Extract fuzz coverage for a specific function.

    Tolerates non-dict roots and containers: the artifact may come
    from an older producer or be tampered, and this runs inside every
    review's context assembly.
    """
    if not isinstance(fuzz_data, dict):
        return None
    flat_key = f"{file_path}:{function_name}"
    if flat_key in fuzz_data:
        return fuzz_data[flat_key]
    files = fuzz_data.get("files")
    if not isinstance(files, dict):
        return None
    file_data = files.get(file_path)
    if not isinstance(file_data, dict):
        return None
    functions = file_data.get("functions")
    if not isinstance(functions, dict):
        return None
    func_data = functions.get(function_name)
    if func_data:
        return func_data
    return None


def _coerce_flow_index_keys(flows: Any) -> dict[int, list[Any]]:
    """Coerce one flow map's parameter-index keys to int and validate
    the flow shapes.

    A key is accepted only as a non-negative integer in canonical
    decimal form (``key == str(int(key))``, or an int already) — the
    producer enumerates parameter positions through exactly that
    spelling, so sign prefixes, whitespace, underscores, and non-ASCII
    digits name no real position and are dropped, failing toward
    claiming no flow. Values are filtered to ``(callee, arg_index)``
    pairs of ``(str, int)``: consumers unpack, slice, and render these
    pairs, so a malformed value must not reach them either.
    """
    coerced: dict[int, list[Any]] = {}
    if not isinstance(flows, dict):
        return coerced
    for key, flow_list in flows.items():
        if isinstance(key, int) and not isinstance(key, bool):
            idx = key
        else:
            try:
                idx = int(key)
            except (TypeError, ValueError):
                idx = -1
            if key != str(idx):
                idx = -1
        if idx < 0:
            logger.debug(
                "taint_approx: dropped flow with non-canonical "
                "parameter index %r", key,
            )
            continue
        if not isinstance(flow_list, list):
            logger.debug(
                "taint_approx: dropped non-list flow value for "
                "parameter %d: %r", idx, flow_list,
            )
            continue
        kept = [
            pair for pair in flow_list
            if isinstance(pair, (list, tuple))
            and len(pair) == 2
            and isinstance(pair[0], str)
            and isinstance(pair[1], int)
            and not isinstance(pair[1], bool)
        ]
        if len(kept) != len(flow_list):
            logger.debug(
                "taint_approx: dropped %d malformed flow pair(s) for "
                "parameter %d", len(flow_list) - len(kept), idx,
            )
        coerced[idx] = kept
    return coerced


def _rekey_cached_taint_approx(cached: dict[str, Any]) -> dict[str, Any]:
    """Re-key cached flow maps to integer parameter indices and
    shape-validate the fields consumers operate on.

    The cache round-trips through JSON, whose object keys are always
    strings, so ``direct_flows`` / ``dangerous_flows`` come back
    str-keyed while consumers index ``params`` with the key and
    compare it against ``len(params)`` — int operations. The typing
    is in-band (index and shapes ride inside disk-sourced data), so
    everything is normalised once here, where the cached shape enters
    the run, instead of at every consumer: flow maps through
    :func:`_coerce_flow_index_keys`, and a ``params`` that is not a
    list of str is replaced with ``[]`` (consumers then fall back to
    their legible ``arg<N>`` naming instead of ``len()``/indexing a
    non-list).
    """
    for approx in cached.values():
        if not isinstance(approx, dict):
            continue
        for flow_field in ("direct_flows", "dangerous_flows"):
            if flow_field in approx:
                approx[flow_field] = _coerce_flow_index_keys(
                    approx[flow_field],
                )
        # Keyed on presence, not truthiness/None: an explicit null
        # must be replaced like any other malformed shape (consumers
        # iterate params without a None guard); only an absent key
        # stays absent.
        params = approx.get("params")
        if "params" in approx and not (
            isinstance(params, list)
            and all(isinstance(p, str) for p in params)
        ):
            logger.debug(
                "taint_approx: replaced malformed params with []: %r",
                params,
            )
            approx["params"] = []
    return cached


def load_or_build_taint_approx(
    target_path: Path | None,
    out_dir: Path | None,
    scope: list | None = None,
) -> dict[str, Any] | None:
    """Load cached taint approximations or build and persist them."""
    if out_dir:
        cache_path = out_dir / "taint-approx.json"
        if cache_path.exists():
            # load_json (non-strict) self-handles read/parse errors;
            # only path-level OSErrors can legitimately escape.
            with contextlib.suppress(OSError):
                from core.json import load_json
                cached = load_json(cache_path)
                if isinstance(cached, dict) and cached:
                    logger.info(
                        "taint_approx: loaded %d cached results", len(cached),
                    )
                    return _rekey_cached_taint_approx(cached)
    results = _build_taint_approx(target_path, scope=scope)
    if results and out_dir:
        # Cache write is best-effort: IO failures and non-finite
        # values in the data (allow_nan=False) are the legitimate set.
        with contextlib.suppress(OSError, ValueError):
            from core.json import save_json
            save_json(out_dir / "taint-approx.json", results)
    return results


def _build_taint_approx(
    target_path: Path | None,
    scope: list | None = None,
) -> dict[str, Any] | None:
    """Build tree-sitter taint approximations for all C/C++ files."""
    if not target_path or not target_path.is_dir():
        return None

    try:
        from core.analysis.taint_approx import (
            extract_taint_approx_c,
            extract_taint_approx_cpp,
            function_key,
        )
    except ImportError:
        return None

    scope_prefixes = (
        tuple(str((target_path / s).resolve()) + os.sep for s in scope)
        if scope else None
    )

    # Same per-file size ceiling as the inventory builder — a multi-MB
    # generated/vendored source file costs seconds of parse time for
    # approximations nobody reads.
    from core.inventory.builder import MAX_FILE_BYTES
    from core.source import read_text_capped

    results: dict[str, Any] = {}
    c_exts = {".c", ".h"}
    cpp_exts = {".cc", ".cpp", ".cxx", ".hpp"}
    skipped_large = 0

    for path in target_path.rglob("*"):
        if not path.is_file():
            continue
        if scope_prefixes and not str(path.resolve()).startswith(scope_prefixes):
            continue
        suffix = path.suffix.lower()
        if suffix not in c_exts and suffix not in cpp_exts:
            continue

        # Capped fd read, not stat-then-read (target-writable files
        # race a by-name size gate; FIFO plants block raw reads).
        # Confine-resolve keeps in-tree symlinked sources readable
        # and refuses links escaping the root.
        resolved = confine(target_path, path)
        if resolved is None:
            continue
        got = read_text_capped(resolved, MAX_FILE_BYTES)
        if got is None:
            continue
        content, truncated = got
        if truncated:
            skipped_large += 1
            continue

        rel = str(path.relative_to(target_path))

        # Per-file guard: one pathological file (parser crash, walker
        # bug, RecursionError from an extreme tree) must not sink the
        # taint pass for the whole target — log and move on.
        try:
            if suffix in c_exts:
                approxes = extract_taint_approx_c(content)
            else:
                approxes = extract_taint_approx_cpp(content)
        except Exception as e:  # noqa: BLE001 — skip one file, keep the pass
            logger.warning(
                "taint_approx: extraction failed for %s; skipping file "
                "(%s: %s)", rel, e.__class__.__name__, e)
            continue

        # The shared constructor is the seam contract: the evidence
        # index and compute_transitive_taint join on exactly this
        # spelling.
        for func_name, approx in approxes.items():
            results[function_key(rel, func_name)] = approx

    if skipped_large:
        logger.info(
            "taint_approx: %d file(s) skipped (larger than %d bytes)",
            skipped_large, MAX_FILE_BYTES)
    if results:
        logger.info("taint_approx: %d functions analysed", len(results))
    return results or None


# ``recreate_coverage_from_journal`` was removed. Journal → coverage-
# store synthesis now happens once at run completion via
# ``core.coverage.importer.import_journal`` (called from
# ``core.run.metadata._snapshot_run_coverage``). The store is the
# durable, cross-run record of LLM review existence; per-run
# ``compute_gaps`` reads coverage records that already carry the
# imported journal marks. No in-run resynthesis needed.
