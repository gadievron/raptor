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

The classifier is deliberately **extension-agnostic**: ``test_*`` and
``*_test.*`` filenames match regardless of suffix because legitimate
test fixtures use ``.txt`` / ``.json`` / ``.bin`` / etc. as often as
``.py`` / ``.go`` / ``.c``. Callers that need source-language filtering
should compose with their own extension check.

Module renamed from ``test_path.py`` to ``path_classifier.py`` (2026-05-02)
to stop pytest's default ``test_*.py`` collection rule from picking up
application code.
"""

from __future__ import annotations

import re

_TEST_PATH_RE = re.compile(
    # Directory components signaling test / spec / fixture content
    r"(?:^|/)(?:tests?|__tests__|specs?|testing|fixtures?)(?:/|$)"
    # ``test_X`` filename (with or without extension) — leading-test prefix.
    # Per-component matches are bounded at NAME_MAX (255) on POSIX
    # filesystems. Pre-fix `[^/]+` was unbounded — the upstream
    # `_PATH_LEN_CAP` truncation at 8 KB already constrained the input,
    # but a defensive in-pattern bound makes the linear-time guarantee
    # explicit at the regex level (no engine-version dependent
    # behaviour) and survives a future caller that bypasses the
    # length cap.
    r"|(?:^|/)test_[^/]{1,255}(?:\.[^/]{1,255})?$"
    # ``X_test.ext`` filename — trailing-test suffix
    r"|(?:^|/)[^/]{1,255}_test\.[^/]{1,255}$"
    # ``X.test.ext`` or ``X.spec.ext`` filename — JS/TS-style test naming
    r"|(?:^|/)[^/]{1,255}\.(?:test|spec)\.[^/]{1,255}$",
    re.IGNORECASE,
)


# File paths are bounded by NAME_MAX (255) per component and PATH_MAX
# (4096) per full path on Linux. A real diff entry above 4 KB is
# essentially never legitimate; cap before regex to avoid handing the
# matcher pathological input. The four alternations each scan
# `[^/]+` greedily — concatenating them across a 1 MB single-
# component string would still complete linearly in CPython's regex
# engine, but the WALL TIME for "is this a test path" was measurable
# (>10 ms) on 100 KB inputs, which is unacceptable for a pure
# classification helper called once per file in a diff. Cap fits
# well above PATH_MAX to leave room for path prefixes added by
# upstream tools (`a/`, `b/`, repo-relative roots).
_PATH_LEN_CAP = 8 * 1024


def is_test_path(path: str) -> bool:
    """Heuristic: does this file path look like test or fixture content?

    Returns True for:
      - Files under ``tests/``, ``test/``, ``__tests__/``, ``specs/``,
        ``spec/``, ``testing/``, ``fixtures/``, ``fixture/``
      - Filenames matching ``test_*``, ``*_test.*``, ``*.test.*``,
        ``*.spec.*``

    Used to populate ``FileChange.is_test`` consistently across every
    extractor (clone, GitHub API, GitLab API, patch URL).

    Returns False for paths longer than ``_PATH_LEN_CAP`` rather than
    spending wallclock matching against pathological input — see the
    cap's docstring for the threat model.
    """
    if not path:
        return False
    if len(path) > _PATH_LEN_CAP:
        return False
    return bool(_TEST_PATH_RE.search(path))
