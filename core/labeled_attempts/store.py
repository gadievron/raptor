"""Storage layer for LabeledAttempt records.

Three-tier pool:

  Bundled demo corpus      packages/llm_analysis/exploit_engine/eval/bundled_corpus/
                            ships with each RAPTOR release; immutable per release
  Per-project (default)    <project>/labeled_attempts/<finding_id>/<oracle>-<ts>.json
                            operator-owned, per-engagement, default writable
  Cross-project global     ~/.raptor/labeled_attempts/<finding_sig>/...
                            opt-in via ``/project corpus enable``

Reader always pulls from per-project + bundled by default; global is
opt-in via the ``include_global`` flag (which the operator gates via
project config — see ``read_all()`` for the resolution order).

Writes are append-only. Each record gets a unique filename derived from
``(oracle, timestamp)``; no in-place updates. If a duplicate would land
at the same filename (timestamp collision), we append a millisecond
suffix.

Filename layout chosen for grep-ability:

    <project>/labeled_attempts/
        <finding_signature>/                # stable hash, not finding_id
            sandbox-20260603T140532Z.json
            codeql-20260603T140601Z.json
            web-20260603T140645Z.json

Keying by ``finding_signature`` (not ``finding_id``) lets a finding
that's been re-scanned with a new id still group with its prior
attempts. The ``finding_id`` of the most recent record is retrievable
by reading the latest record in the directory.
"""

from __future__ import annotations

import json
import os
import secrets
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from .types import LabeledAttempt

__all__ = [
    "write",
    "read_all",
    "find_by_cwe",
    "find_by_finding_signature",
    "bundled_corpus_path",
    "global_pool_path",
    "project_pool_path",
]


# --------------------------------------------------------------------------
# Path helpers
# --------------------------------------------------------------------------


def bundled_corpus_path() -> Path:
    """Where the RAPTOR-bundled demo corpus lives.

    Relative to RAPTOR's source tree, not the operator's filesystem.
    The bundled corpus is read-only at runtime (ships with each
    release).
    """
    raptor_dir = Path(os.environ["RAPTOR_DIR"])
    return (
        raptor_dir
        / "packages" / "llm_analysis" / "exploit_engine"
        / "eval" / "bundled_corpus"
    )


def global_pool_path() -> Path:
    """Where cross-project shared records live.

    Operator opts in per-project via ``/project corpus enable``.
    """
    return Path.home() / ".raptor" / "labeled_attempts"


def project_pool_path(project_dir: Path) -> Path:
    """Per-project store under the project's output directory."""
    return Path(project_dir) / "labeled_attempts"


# --------------------------------------------------------------------------
# Write
# --------------------------------------------------------------------------


def _record_filename(attempt: LabeledAttempt) -> str:
    """Filename derived from oracle + timestamp + random suffix.

    The random suffix avoids collisions when multiple writers land in
    the same millisecond (concurrent /exploit runs, batched ingest).
    The atomic-create-with-retry loop in ``_write_atomic`` handles
    the rare collision case.

    LabeledAttempt's __post_init__ validates the timestamp is ISO-
    parseable, so the fromisoformat() call below cannot raise here.
    """
    ts = datetime.fromisoformat(attempt.timestamp)
    stamp = ts.strftime("%Y%m%dT%H%M%S") + f".{ts.microsecond // 1000:03d}"
    # 6 hex chars = 24 bits of randomness → 16M-way collision space
    # within the same millisecond. Plenty.
    suffix = secrets.token_hex(3)
    return f"{attempt.oracle}-{stamp}Z-{suffix}.json"


def _write_atomic(path: Path, payload: str, *, max_retries: int = 5) -> Path:
    """Write ``payload`` to ``path`` with O_EXCL semantics so a
    racing writer can't silently clobber us. On collision (same
    filename produced by two writers in the same millisecond with
    the same random suffix — extremely unlikely but possible),
    re-roll the suffix and retry.

    Returns the path actually written (may differ from the input
    ``path`` if a retry happened — caller cares about success, not
    the original name).
    """
    # O_NOFOLLOW: if the target path is a symlink we refuse to follow
    # it — defends against a planted symlink at the filename pointing
    # somewhere outside the pool (e.g. /etc/passwd). With O_NOFOLLOW
    # the open fails with ELOOP rather than silently writing through.
    # O_CREAT | O_EXCL: create new; fail if exists.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    for attempt_n in range(max_retries):
        try:
            fd = os.open(path, flags, 0o644)
            try:
                os.write(fd, payload.encode("utf-8"))
            finally:
                os.close(fd)
            return path
        except FileExistsError:
            # Re-roll the random suffix and try again. Format is
            # "<base>-<suffix>.json" — replace the suffix.
            stem = path.stem  # e.g. "sandbox-20260603T140532.123Z-abc123"
            base = "-".join(stem.split("-")[:-1])
            new_suffix = secrets.token_hex(3)
            path = path.with_name(f"{base}-{new_suffix}.json")
            continue
    raise OSError(
        f"could not create unique filename after {max_retries} retries "
        f"(this should never happen — bug?)"
    )


def write(
    attempt: LabeledAttempt,
    *,
    project_dir: Path,
    also_global: bool = False,
) -> list[Path]:
    """Persist a record to the per-project store and optionally to the
    global pool.

    Returns the list of paths written (1 element if project-only,
    2 if also_global=True).
    """
    paths: list[Path] = []

    # Pre-serialise once so both writes get the same blob.
    payload = json.dumps(attempt.to_dict(), indent=2)

    project_dir_root = project_pool_path(project_dir) / attempt.finding_signature
    project_dir_root.mkdir(parents=True, exist_ok=True)
    project_file = _write_atomic(
        project_dir_root / _record_filename(attempt), payload,
    )
    paths.append(project_file)

    if also_global:
        global_root = global_pool_path() / attempt.finding_signature
        global_root.mkdir(parents=True, exist_ok=True)
        global_file = _write_atomic(
            global_root / _record_filename(attempt), payload,
        )
        paths.append(global_file)

    return paths


# --------------------------------------------------------------------------
# Read
# --------------------------------------------------------------------------


def _iter_records_in_dir(root: Path) -> Iterable[LabeledAttempt]:
    """Yield every readable record under ``root``. Unreadable files
    are skipped silently (an old schema with a missing required
    field shouldn't break retrieval over the rest of the corpus)."""
    if not root.exists():
        return
    for finding_dir in sorted(root.iterdir()):
        if not finding_dir.is_dir():
            continue
        for record_file in sorted(finding_dir.glob("*.json")):
            try:
                data = json.loads(record_file.read_text())
                yield LabeledAttempt.from_dict(data)
            except (json.JSONDecodeError, ValueError, KeyError, TypeError):
                # Skip corrupt / outdated records rather than fail the
                # whole read. Retrieval is best-effort.
                continue


def read_all(
    *,
    project_dir: Optional[Path] = None,
    include_bundled: bool = True,
    include_global: bool = False,
) -> Iterable[LabeledAttempt]:
    """Stream all readable records across the requested pools.

    Pool resolution order:

        L3 pool = current_project
                  ∪ bundled_demo_corpus      (include_bundled, default True)
                  ∪ global_pool              (include_global, opt-in)

    Order is intentional: bundled first (cheapest to read, always-on
    baseline), project second (most relevant to current work),
    global last (richest but only when opted in). Consumers that want
    a stable ordering can sort.
    """
    if include_bundled:
        yield from _iter_records_in_dir(bundled_corpus_path())

    if project_dir is not None:
        yield from _iter_records_in_dir(project_pool_path(project_dir))

    if include_global:
        yield from _iter_records_in_dir(global_pool_path())


def find_by_cwe(
    cwe: str,
    *,
    project_dir: Optional[Path] = None,
    include_bundled: bool = True,
    include_global: bool = False,
) -> Iterable[LabeledAttempt]:
    """Filter ``read_all`` to a specific CWE class.

    For L3 retrieval the common case is "find me the verified
    successes for CWE-X" — this is the convenience wrapper.
    """
    cwe_norm = cwe.strip().upper()
    for attempt in read_all(
        project_dir=project_dir,
        include_bundled=include_bundled,
        include_global=include_global,
    ):
        if attempt.cwe.strip().upper() == cwe_norm:
            yield attempt


def find_by_finding_signature(
    signature: str,
    *,
    project_dir: Optional[Path] = None,
    include_bundled: bool = True,
    include_global: bool = False,
) -> Iterable[LabeledAttempt]:
    """Filter ``read_all`` to all attempts on a specific finding.

    Useful for "show me everything we've tried on this bug" reports.
    Returns records in arbitrary order; caller sorts by timestamp
    if needed.
    """
    for attempt in read_all(
        project_dir=project_dir,
        include_bundled=include_bundled,
        include_global=include_global,
    ):
        if attempt.finding_signature == signature:
            yield attempt
