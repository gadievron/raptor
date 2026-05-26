"""Detect transitive deps that have become optional (or removed)
in newer parent versions — surface as a "bump parent, drop CVE"
remediation path.

The canonical bite: raptor's ``requirements.txt`` pins
``instructor==1.14.5``. instructor 1.14.5's PyPI ``requires_dist``
includes ``diskcache>=5.6.3`` unconditionally → cascade-resolver
adds diskcache to the project's dep set → diskcache==5.6.3 has
CVE-2025-69872 → scan emits a vuln finding the operator can't
fix because there's no upstream patch.

But instructor 1.15.1's ``requires_dist`` moves diskcache behind
``; extra == "diskcache"`` — i.e., it's now optional. Bumping
the parent from 1.14.5 to 1.15.1 silently drops diskcache from
the cascade output AND the CVE goes away.

This detector spots that pattern programmatically:

  1. For each cascade-sourced (transitive) dep with a vuln /
     supply-chain / platform-compat finding
  2. Walk its ``source_extra["via"]`` to find parent direct deps
  3. For each parent: fetch the LATEST stable's ``requires_dist``;
     check whether the transitive moved behind ``; extra == ...``
     or disappeared entirely
  4. If so → emit ``sca:supply_chain:transitive_now_optional``
     with the suggested bump

Severity scales with the underlying transitive issue:
  - transitive has a HIGH/CRITICAL vuln → finding is HIGH
    (the bump is a real remediation path, not just hygiene)
  - transitive has only INFO/LOW signals → finding is INFO
"""

from __future__ import annotations

from packages.sca.transitive_drop.detector import (
    detect_droppable_transitives,
)

__all__ = ["detect_droppable_transitives"]
