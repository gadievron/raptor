"""Canonical test-path classification.

Single source of truth for "does this file path look like test or fixture
content?" — used by the diff extractors to populate
``FileChange.is_test``. Before this module existed, three separate
``_TEST_PATH_RE`` definitions in ``cve_diff/diffing/`` disagreed on edge
cases like ``fixtures/`` and ``*.test.*``, causing the same file to be
classified differently depending on which extractor handled the CVE
(2026-05-01 bug surfaced by the simplifier-pipeline Stage 2 dry-run).

The pattern below is the **strict union** of the two divergent regexes
that previously coexisted — i.e., a path is "test" if EITHER of the old
patterns already classified it that way. No path that both old patterns
agreed was non-test gets re-classified.
"""

from __future__ import annotations

import re

_TEST_PATH_RE = re.compile(
    # Directory components signaling test / spec / fixture content
    r"(?:^|/)(?:tests?|__tests__|specs?|testing|fixtures?)(?:/|$)"
    # ``test_X`` filename (with or without extension) — leading-test prefix
    r"|(?:^|/)test_[^/]+(?:\.[^/]+)?$"
    # ``X_test.ext`` filename — trailing-test suffix
    r"|(?:^|/)[^/]+_test\.[^/]+$"
    # ``X.test.ext`` or ``X.spec.ext`` filename — JS/TS-style test naming
    r"|(?:^|/)[^/]+\.(?:test|spec)\.[^/]+$",
    re.IGNORECASE,
)


def is_test_path(path: str) -> bool:
    """Heuristic: does this file path look like test or fixture content?

    Returns True for:
      - Files under ``tests/``, ``test/``, ``__tests__/``, ``specs/``,
        ``spec/``, ``testing/``, ``fixtures/``, ``fixture/``
      - Filenames matching ``test_*``, ``*_test.*``, ``*.test.*``,
        ``*.spec.*``

    Used to populate ``FileChange.is_test`` consistently across every
    extractor (clone, GitHub API, GitLab API, patch URL).
    """
    return bool(_TEST_PATH_RE.search(path or ""))
