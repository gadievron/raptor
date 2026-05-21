"""Bounded file-read helper for SCA parsers.

Every parser in this package reads attacker-controlled target-repo
files. Without an in-process size bound, a hostile manifest can
exhaust the parser's memory before the sandbox-level limit kicks
in — which is the right fail-closed posture for the sandbox, but
leaves the operator-facing tool with a "OOMKilled at line 137"
error message instead of a clean ``treating as unparseable``
verdict.

This helper caps reads at ``_MAX_PARSER_BYTES`` (50 MB by default).
That's:

  * Above the largest legitimate ``package-lock.json`` /
    ``yarn.lock`` / ``Cargo.lock`` seen in the wild (the biggest
    monorepos run ~30-40 MB).
  * Below the magnitude of zip-bomb / DoS payloads, which tend to
    be 100s of MB to GB.

Mirrors ``core.inventory.builder.MAX_FILE_BYTES`` (8 MiB for
source code) — same defensive shape, looser cap because SCA
manifests legitimately run larger than source files.

Other parsers in this package read target files via
``path.read_text(encoding="utf-8")`` without a bound. They should
migrate to this helper; until they do, the OS-level fail (sandbox
memory limit) is the backstop. New parsers added to the package
should use this from the start.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# 50 MB. See module docstring for the bound rationale.
_MAX_PARSER_BYTES = 50 * 1024 * 1024


def read_bounded(
    path: Path, *, max_bytes: int = _MAX_PARSER_BYTES,
) -> Optional[str]:
    """Read ``path`` as UTF-8 text, capped at ``max_bytes``.

    Returns ``None`` and logs at warning level when:

      * the file can't be stat'd (vanished, permission denied)
      * the file exceeds ``max_bytes`` per its stat
      * the file grew past ``max_bytes`` between stat and read
        (racing writer; OS-level TOCTOU defence)
      * any OSError fires during the read

    Mirrors the ``core.inventory.builder._read_source_text``
    pattern: stat first to reject before opening, then read with
    ``+1`` and double-check so a file that grew between stat and
    read still surfaces as unparseable rather than silently
    truncating.

    Decodes with ``errors="replace"`` so adversarial byte sequences
    don't crash the parser — the caller's regex / JSON parse
    handles the resulting U+FFFD replacement chars as gracefully
    as it handles legitimate non-UTF-8 manifests.
    """
    try:
        size = path.stat().st_size
    except OSError as e:
        logger.debug("sca.parsers: cannot stat %s: %s", path, e)
        return None
    if size > max_bytes:
        logger.warning(
            "sca.parsers: refusing to read %s (size=%d > max=%d) "
            "— hostile or unusually large manifest; treating as "
            "unparseable", path, size, max_bytes,
        )
        return None
    try:
        with path.open("rb") as fh:
            raw = fh.read(max_bytes + 1)
    except OSError as e:
        logger.debug("sca.parsers: cannot read %s: %s", path, e)
        return None
    if len(raw) > max_bytes:
        logger.warning(
            "sca.parsers: %s grew past max during read (>%d); "
            "treating as unparseable", path, max_bytes,
        )
        return None
    return raw.decode("utf-8", errors="replace")
