"""Lookahead prewarm for the coccinelle sweep leg.

The orchestrator's coccinelle leg memoizes ONE file sweep per
(rendered-rule content, file content) — see ``run_coccinelle_file_sweep``
— which removes the per-function multiplier but leaves the per-file
floor: every file in the inventory still costs one fork+exec'd
sandboxed spatch, serially, as its first function comes up for audit
(~0.3-0.8 s each; >13 h per rule on a 63k-file tree).

This module is a strictly caller-side consumer of that memo. When the
leg dispatches a (rule, file) pair, ``maybe_prewarm`` is called BEFORE
the memoized step. Once a few distinct files have been dispatched
against the same rendered rule ("rent-to-buy": the rule has proven it
is being swept broadly, so warming ahead will be consumed), it batches
the upcoming inventory files — grouped by parent directory so the
spatch cwd matches single-file mode's include resolution — through
multi-file ``run_rule`` invocations on a bounded worker pool, splits
the combined result per file, and pins each file's sweep result into
the run's ``SweepMemo``. The serial dispatch that follows then hits.

Correctness stance:

* Pinned results are built to be indistinguishable from what
  ``run_coccinelle_file_sweep`` returns for the same inputs: same
  argv path spelling (``target_path / file_path``, so match dicts
  carry identical ``file`` fields), same cwd (the file's parent
  directory), same ``defines={}`` / ``allow_scripting=True`` /
  rule identity (``rule_id`` is always the SOURCE rule path, never a
  rendered tempfile), same confirmed-iff-matches classification.
* Only ``confirmed`` / ``refuted`` verdicts are pinned. A failed or
  timed-out batch pins NOTHING — those files fall back to the plain
  per-file path, which computes (and classifies) them itself. Files
  the substrate gate would skip are never batched, so their skip
  receipts also come from the real sweep.
* Memo keys are built with the same parts the leg uses
  (rule hash / file content hash / path / defines) via
  ``SweepMemo.make_key`` — a key the leg would not construct
  identically is impossible by shape, and any un-hashable input
  degrades to "don't pin".

Failure stance: everything here is advisory. ``maybe_prewarm``
swallows every exception (debug-logged) — the worst outcome of a
prewarm bug is the pre-existing serial behaviour.
"""

import logging
import threading
import weakref
from pathlib import Path
from typing import Any

from ._util import safe_join
from .sweep import SweepResult, file_substrate_coverage
from .sweep_memo import SweepMemo, hash_file

logger = logging.getLogger(__name__)

# Parity anchor: run_coccinelle_file_sweep runs spatch with
# timeout=120 per file; batch timeouts are scaled from the same base
# (see packages.coccinelle.runner.derive_batch_timeout_s).
_SINGLE_FILE_TIMEOUT_S = 120

# Distinct dispatched files (same rendered rule) before the first
# warm burst. Both directions:
#   * Lower and a rule dispatched against a handful of files (a
#     targeted re-check, a deepen probe) pays for a lookahead window
#     it never consumes — the waste bound per rule is roughly one
#     burst, and the trigger is what keeps that bound rare.
#   * Higher and the sweep runs serial for longer before the batch
#     win engages; on an inventory-ordered primary pass the third
#     distinct file is already strong evidence the whole tree is
#     coming.
TRIGGER_DISTINCT_FILES = 3

# Directory-grouped chunks warmed per burst. Both directions:
#   * Higher and one burst pins more entries than the shared sweep
#     memo can safely hold — the memo is a 1024-entry LRU shared with
#     the semgrep/SMT/CodeQL legs, so a burst must stay well inside
#     that window or it evicts entries before the serial cursor
#     consumes them (and evicts OTHER tools' hot entries). It also
#     stretches the synchronous burst latency paid by one dispatch.
#   * Lower and the burst cannot fill the batch worker pool
#     (derive_batch_workers caps at 16 lanes), so the parallel win
#     shrinks and bursts fire more often, each paying pool spin-up.
LOOKAHEAD_CHUNKS = 16


class _RuleState:
    """Per-(memo, rendered-rule) prewarm bookkeeping."""

    __slots__ = ("seen", "warmed", "pinned", "chunks", "chunk_of",
                 "burst_lock")

    def __init__(self) -> None:
        self.seen: set[str] = set()
        self.warmed: set[int] = set()
        self.pinned: set[str] = set()
        self.chunks: list[list[str]] | None = None
        self.chunk_of: dict[str, int] = {}
        self.burst_lock = threading.Lock()


# Prewarm state rides on the RUN's SweepMemo instance (weakly): the
# memo is per-run and already threads through every dispatch, so
# keying on it gives per-run isolation without touching
# OrchestratorConfig, and the state dies with the memo.
_state_lock = threading.Lock()
_states: "weakref.WeakKeyDictionary[SweepMemo, dict[str, _RuleState]]" = (
    weakref.WeakKeyDictionary()
)


def _rule_state(memo: SweepMemo, rule_hash: str) -> _RuleState:
    with _state_lock:
        per_memo = _states.get(memo)
        if per_memo is None:
            per_memo = {}
            _states[memo] = per_memo
        st = per_memo.get(rule_hash)
        if st is None:
            st = _RuleState()
            per_memo[rule_hash] = st
        return st


def _inventory_paths(config: Any) -> list[str]:
    """Ordered relative file paths from the run inventory."""
    inv = getattr(config, "inventory", None)
    if not isinstance(inv, dict):
        return []
    out: list[str] = []
    for entry in inv.get("files") or []:
        if isinstance(entry, dict):
            p = entry.get("path")
            if isinstance(p, str) and p:
                out.append(p)
    return out


def _build_chunks(
    config: Any, root: Path,
) -> tuple[list[list[str]], dict[str, int]]:
    """Group inventory files into parent-directory batches.

    Consecutive inventory entries sharing a parent directory form one
    chunk (capped at BATCH_CHUNK_FILES): a batch's files must share
    the spatch cwd — the file's parent, exactly as single-file mode
    sets it — for relative-#include resolution parity. Eligibility
    (existence, containment, substrate) is deliberately NOT checked
    here: it is deferred to warm time so a 63k-file inventory costs
    nothing until (and unless) its region of the tree is actually
    warmed.
    """
    from packages.coccinelle.runner import BATCH_CHUNK_FILES

    chunks: list[list[str]] = []
    current: list[str] = []
    current_parent: Path | None = None
    for fp in _inventory_paths(config):
        parent = (root / fp).parent
        if current and (
            parent != current_parent or len(current) >= BATCH_CHUNK_FILES
        ):
            chunks.append(current)
            current = []
        current_parent = parent
        current.append(fp)
    if current:
        chunks.append(current)
    chunk_of = {
        fp: i for i, chunk in enumerate(chunks) for fp in chunk
    }
    return chunks, chunk_of


def _eligible(root: Path, fp: str) -> bool:
    """Whether *fp* may be batched (parity with the sweep's own gates).

    Excluded files are simply not batched — the serial sweep computes
    its own containment / missing-file / substrate result for them, so
    prewarm never has to reproduce those receipt shapes.
    """
    # Same containment chokepoint as the serial sweep's gate
    # (_check_path_containment -> safe_join): resolves symlinks, so an
    # in-tree symlink pointing outside the root is excluded here just
    # as the serial path would refuse it. A lexical-only check would
    # let a degraded (bare-run) sandbox tier read the out-of-tree
    # content and pin a verdict the serial gate refuses to compute.
    if safe_join(root, fp) is None:
        return False
    full = root / fp
    try:
        if not full.is_file():
            return False
    except OSError:
        return False
    try:
        cov = file_substrate_coverage(
            "coccinelle", target_path=root, file_path=fp, language=None,
        )
    except Exception:  # noqa: BLE001 — gate parity is best-effort
        return False
    return not (cov is not None and cov.covered is False)


def _run_chunk(
    root: Path, exec_rule: str, members: list[str],
) -> dict[str, Any] | None:
    """One batched spatch invocation; per-file demux, or None on failure."""
    from packages.coccinelle.runner import (
        demux_result_by_file,
        derive_batch_timeout_s,
        run_rule,
    )

    file_set = [root / fp for fp in members]
    # cwd parity: single-file mode runs spatch from the file's parent
    # directory; the batch shares one parent by construction.
    parent = file_set[0].parent
    result = run_rule(
        parent,
        Path(exec_rule),
        file_set=file_set,
        defines={},
        timeout=derive_batch_timeout_s(
            _SINGLE_FILE_TIMEOUT_S, len(file_set),
        ),
        # Same trust stance as run_coccinelle_file_sweep: the leg's
        # rules are in-repo / rendered-from-in-repo (code trust).
        allow_scripting=True,
    )
    if not result.ok:
        # Failed or timed-out batch: pin nothing; every member falls
        # back to the plain per-file path.
        logger.debug(
            "cocci prewarm batch failed (%d files, rc=%s): %s",
            len(file_set), result.returncode, result.errors[:1],
        )
        return None
    return demux_result_by_file(result, file_set, root)


def _pin_chunk(
    memo: SweepMemo,
    st: _RuleState,
    demuxed: dict[str, Any],
    members: list[str],
    root: Path,
    rule_source: str,
    rule_hash: str,
) -> int:
    """Pin per-file verdicts into the memo; count of pinned entries."""
    pinned = 0
    for fp in members:
        per = demuxed.get(fp)
        if per is None:
            # Demux keys fall back to the argv spelling when a path
            # does not resolve under the root (symlinked subtree).
            per = demuxed.get(str(root / fp))
        if per is None or not per.ok:
            continue
        matches = [
            m.to_dict() if hasattr(m, "to_dict") else {"raw": str(m)}
            for m in per.matches
        ]
        sweep_result = SweepResult(
            tool="coccinelle",
            file_path=fp,
            function_name="",
            outcome="confirmed" if matches else "refuted",
            matches=matches,
            # Always the SOURCE rule path — a rendered tempfile path
            # would poison the memoized result once it is unlinked.
            rule_id=rule_source,
        )
        key = SweepMemo.make_key("coccinelle", {
            "rule": rule_hash,
            "file": hash_file(root / fp),
            "path": fp,
            # Parity with the leg's key: this consumer never routes
            # defines, so the dimension is pinned empty.
            "defines": "",
        })
        if key is None:
            continue
        memo.put(key, sweep_result)
        with _state_lock:
            st.pinned.add(fp)
        pinned += 1
    return pinned


def maybe_prewarm(
    config: Any,
    *,
    effective_target: Path,
    file_path: str,
    rule_source: str,
    exec_rule: str,
    rule_hash: str | None,
) -> None:
    """Advisory lookahead prewarm for one coccinelle-leg dispatch.

    Called by the orchestrator's coccinelle leg BEFORE the memoized
    sweep step. Never raises; never blocks a second dispatcher thread
    behind a running burst (non-blocking claim — the skipped thread
    simply proceeds on the serial path).

    Args:
        config: OrchestratorConfig (read: ``sweep_memo``,
            ``inventory``). Absent/None memo disables prewarm.
        effective_target: Root of the audited tree.
        file_path: Repo-relative path of the dispatched file.
        rule_source: The SOURCE .cocci path (memo/rule_id identity).
        exec_rule: The rule file to actually run — the leg's rendered
            tempfile when vocabulary was spliced, else the source
            path. Must outlive this (synchronous) call, which the
            leg's unlink-in-finally ordering guarantees.
        rule_hash: The leg's rendered-bytes hash (memo key part);
            None means the leg is running unmemoized — no prewarm.
    """
    try:
        _maybe_prewarm(
            config,
            effective_target=Path(effective_target),
            file_path=file_path,
            rule_source=rule_source,
            exec_rule=exec_rule,
            rule_hash=rule_hash,
        )
    except Exception:  # noqa: BLE001 — advisory by contract
        logger.debug("cocci prewarm skipped", exc_info=True)


def _maybe_prewarm(
    config: Any,
    *,
    effective_target: Path,
    file_path: str,
    rule_source: str,
    exec_rule: str,
    rule_hash: str | None,
) -> None:
    memo = getattr(config, "sweep_memo", None)
    if memo is None or rule_hash is None:
        return

    st = _rule_state(memo, rule_hash)
    with _state_lock:
        if file_path in st.pinned:
            return
        st.seen.add(file_path)
        if len(st.seen) < TRIGGER_DISTINCT_FILES:
            return

    # One burst at a time per rule: a second dispatcher thread that
    # arrives mid-burst must not stack another 16-lane pool on top —
    # it skips and computes its own file serially (benign duplication,
    # the memo tolerates double-compute).
    if not st.burst_lock.acquire(blocking=False):
        return
    try:
        if st.chunks is None:
            st.chunks, st.chunk_of = _build_chunks(
                config, effective_target,
            )
        start = st.chunk_of.get(file_path)
        if start is None:
            return
        _warm_burst(
            memo, st,
            root=effective_target,
            rule_source=rule_source,
            exec_rule=exec_rule,
            rule_hash=rule_hash,
            start_chunk=start,
        )
    finally:
        st.burst_lock.release()


def _warm_burst(
    memo: SweepMemo,
    st: _RuleState,
    *,
    root: Path,
    rule_source: str,
    exec_rule: str,
    rule_hash: str,
    start_chunk: int,
) -> None:
    from concurrent.futures import ThreadPoolExecutor

    from packages.coccinelle.runner import derive_batch_workers

    assert st.chunks is not None
    jobs: list[list[str]] = []
    with _state_lock:
        end = min(start_chunk + LOOKAHEAD_CHUNKS, len(st.chunks))
        for ci in range(start_chunk, end):
            if ci in st.warmed:
                continue
            st.warmed.add(ci)
            members = [
                fp for fp in st.chunks[ci] if fp not in st.pinned
            ]
            if members:
                jobs.append(members)
    # Eligibility outside the lock (stat + substrate detection).
    jobs = [
        [fp for fp in members if _eligible(root, fp)]
        for members in jobs
    ]
    jobs = [members for members in jobs if members]
    if not jobs:
        return

    workers = min(derive_batch_workers(), len(jobs))
    pinned = 0
    # Synchronous burst: submit-all then wait — no worker thread ever
    # outlives this call, so run teardown never races a stray spatch.
    with ThreadPoolExecutor(
        max_workers=workers, thread_name_prefix="cocci-prewarm",
    ) as pool:
        futures = [
            (members, pool.submit(_run_chunk, root, exec_rule, members))
            for members in jobs
        ]
        for members, fut in futures:
            demuxed = fut.result()
            if demuxed is None:
                continue
            pinned += _pin_chunk(
                memo, st, demuxed, members, root, rule_source, rule_hash,
            )
    logger.debug(
        "cocci prewarm burst: %d chunk(s), %d file verdict(s) pinned",
        len(jobs), pinned,
    )
