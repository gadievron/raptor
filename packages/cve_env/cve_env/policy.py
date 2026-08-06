"""Version-correctness policy constants."""

from __future__ import annotations

import re

FORBIDDEN_VERSION_TAGS: frozenset[str] = frozenset(
    {"latest", "stable", "lts", "current", "edge", "nightly"}
)

# Shared regex for the trailing ``@sha256:<64-hex>`` suffix.
# Used by P14 invariant enforcement (validators.py + dockerfile_hygiene.py)
# to strip the digest BEFORE checking the tag — closes the
# ``nginx:latest@sha256:...`` bypass. Defined once here to prevent
# semantic drift between the two enforcement sites.
#
# Security hardening: the ``(?:...)+`` form strips ALL stacked trailing
# digests, not just the last one. The single-digest ``...$`` form left a
# ``nginx:latest@sha256:<64>@sha256:<64>`` ref with a residual digest after
# stripping, so ``endswith(":latest")`` still failed and the forbidden tag
# slipped through both enforcement sites.
SHA256_DIGEST_SUFFIX_RE: re.Pattern[str] = re.compile(r"(?:@sha256:[0-9a-f]{64})+$")
# Detect the malformed multi-digest case so callers can reject it outright
# (a legitimate ref carries exactly one digest).
SHA256_MULTI_DIGEST_RE: re.Pattern[str] = re.compile(r"(?:@sha256:[0-9a-f]{64}){2,}$")
