"""Target license detection and classification.

Walks a scan target's top-level dir for license-named files
(``LICENSE``, ``COPYING``, ``LICENCE``, dual-licensed
``LICENSE-MIT`` / ``LICENSE-APACHE`` variants), reads the first
~50 lines, and returns a :class:`TargetLicense` carrying the SPDX
identifier (when detectable), a coarse OSS / proprietary / unknown
classification, and the source file + confidence tier.

The classification is INFORMATIONAL — RAPTOR surfaces the result
at lifecycle start so the operator sees what their target looks
like before running tools (e.g. CodeQL) whose license terms may
restrict use on non-OSS code. RAPTOR does NOT enforce: operators
may have a CodeQL commercial license RAPTOR can't see, may be
running a bug-bounty engagement on first-party code that lacks a
LICENSE file but is authorized, may be doing security research on
decompiled binaries, etc. The detection is a signal for the
operator's own compliance check, not a gate.

## Relationship with ``packages/sca/license.py``

Distinct concerns:

* ``packages/sca/license.py`` — DEPENDENCY licenses sourced from
  registry metadata (PyPI Trove classifiers, npm package.json,
  crates, maven POMs); runs a policy engine
  (allow/warn/deny per operator config) to emit ``LicenseFinding``
  rows. Inputs are per-dep; output is policy violations.
* this module — the TARGET'S OWN license sourced from a LICENSE
  file at the repo root; coarse OSS / proprietary / unknown
  classification for operator-facing surface at lifecycle start.
  No policy, no findings.

The two share no natural data today (SCA has no
``is_oss_spdx_id``-shaped constant — it's policy-based). If a
third consumer materialises that wants ''is this id OSS?'' as a
question, extract the allowlist here to a shared helper then.
SCA's ``_looks_like_spdx_expression`` regex is the one natural
future bridge — useful when this module gains compound-header
support (``SPDX-License-Identifier: MIT OR Apache-2.0``).
"""

from .detector import (
    TargetLicense,
    detect_target_license,
    format_license_summary,
    log_license_details,
)

__all__ = [
    "TargetLicense",
    "detect_target_license",
    "format_license_summary",
    "log_license_details",
]
