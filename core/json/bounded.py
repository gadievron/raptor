"""Bounded JSON entry points for attacker-influenced sources.

``core.json.utils.load_json`` serves RAPTOR-owned artifacts, where
the writer is trusted and the failure mode of interest is a corrupt
or half-written file. The helpers here serve the OTHER input class:
JSON another principal can inflate at will — tool output produced
over a hostile target (SARIF, scanner ``--json`` payloads), files
discovered inside a scanned repository, and network responses. For
those, parsing before sizing is a memory-exhaustion primitive: a
multi-gigabyte payload OOM-kills the scan before any content check
runs.

Both helpers gate on size BEFORE the parse (and, for files, BEFORE
the read) and fail closed with a distinct, size-mentioning
:class:`JsonBudgetExceededError`. The error subclasses ``ValueError``
so call sites with an existing ``except ValueError`` /
``except json.JSONDecodeError`` malformed-input path degrade the same
way for over-budget input without new plumbing — while callers that
want to report the refusal distinctly can catch the subclass.

Kept separate from ``core.json.utils`` so the security-bound surface
stays small, explicit, and greppable.
"""

from __future__ import annotations

import json
import logging
import stat as _stat
from pathlib import Path
from typing import Any

from core.json.utils import JsonBudgetExceededError, _reject_non_finite

__all__ = [
    "JsonBudgetExceededError",  # canonical home: core.json.utils
    "load_json_bounded",
    "loads_bounded",
]

logger = logging.getLogger(__name__)


def loads_bounded(data: str | bytes, *, max_bytes: int) -> Any:
    """Parse in-memory JSON with a size gate BEFORE the parse.

    For ``bytes`` the gate is exact; for ``str`` it counts characters
    (a lower bound on the UTF-8 byte length — the string is already
    materialised, so the gate's job is bounding parse cost, which
    scales with length, not re-measuring memory).

    Raises:
        JsonBudgetExceededError: input longer than ``max_bytes``.
        ValueError: malformed JSON, or a non-finite constant
            (``NaN`` / ``Infinity`` — same default hardening as
            ``core.json.utils.load_json``).
    """
    unit = "bytes" if isinstance(data, (bytes, bytearray)) else "characters"
    size = len(data)
    if size > max_bytes:
        msg = (
            f"JSON input is {size} {unit} — exceeds the "
            f"{max_bytes}-byte budget; refusing to parse"
        )
        logger.warning("%s", msg)
        raise JsonBudgetExceededError(msg)
    return json.loads(data, parse_constant=_reject_non_finite)


def load_json_bounded(path: str | Path, *, max_bytes: int) -> Any:
    """Load a JSON file with a ``stat()`` size gate BEFORE any read.

    Strict contract (unlike ``load_json``'s warn-and-``None``): every
    failure raises, so an unreadable or over-budget file can't be
    confused with a parsed ``null``. The read itself is capped at
    ``max_bytes + 1`` so a file that grows between stat and read is
    still refused without buffering past the budget. Decoding is
    ``utf-8-sig`` (BOM-tolerant, matching ``load_json``) with
    ``errors="replace"`` so adversarial byte sequences surface as a
    parse error, not a crash.

    Raises:
        OSError: missing / unreadable file.
        JsonBudgetExceededError: file larger than ``max_bytes``.
        ValueError: non-regular file (FIFO, socket, device — an
            unbounded-read primitive), malformed JSON, or a
            non-finite constant.
    """
    p = Path(path)
    st = p.stat()
    if not _stat.S_ISREG(st.st_mode):
        msg = (
            f"refusing to read {p}: not a regular file "
            f"(mode=0o{st.st_mode:o})"
        )
        logger.warning("%s", msg)
        raise ValueError(msg)
    if st.st_size > max_bytes:
        msg = (
            f"JSON file {p} is {st.st_size} bytes — exceeds the "
            f"{max_bytes}-byte budget; refusing to read"
        )
        logger.warning("%s", msg)
        raise JsonBudgetExceededError(msg)
    with p.open("rb") as fh:
        raw = fh.read(max_bytes + 1)
    if len(raw) > max_bytes:
        msg = (
            f"JSON file {p} grew past the {max_bytes}-byte budget "
            f"during read; refusing to parse"
        )
        logger.warning("%s", msg)
        raise JsonBudgetExceededError(msg)
    return json.loads(
        raw.decode("utf-8-sig", errors="replace"),
        parse_constant=_reject_non_finite,
    )
