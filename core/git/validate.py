"""Repository-URL allowlist.

Restricts ``clone_repository`` to known-good hosting. Any URL not
matching one of the patterns is rejected fail-closed; this is a
defence against typosquat hostnames and accidental clones from
attacker-supplied URLs that route through unexpected hosts.

Currently allows:
  - https://github.com/<owner>/<repo>[/]
  - https://gitlab.com/<owner>/<repo>[/]
  - git@github.com:<owner>/<repo>.git
  - git@gitlab.com:<owner>/<repo>.git

Further hosts (self-hosted gitlab, codeberg, etc.) can be added when
a concrete need surfaces — staying narrow until then.
"""

from __future__ import annotations

import re

# `re.ASCII` so ``\w`` can't smuggle Cyrillic / homoglyph chars into the
# allowed owner/repo segment. The first char of each segment must be
# alphanumeric or underscore — refuses leading ``-`` (which OpenSSH
# would parse as an option after argv translation, CVE-2017-1000117).
#
# Repo-name body is `\w(?:[\w\-]|\.(?!\.))*` instead of `\w[\w.\-]*`.
# Pre-fix the looser body accepted repo names ending in `..` (e.g.
# `https://github.com/foo/bar..`) because the `[\w.\-]*` star
# happily matched two consecutive dots. GitHub itself rejects `..`
# in repo names — but our validator accepted them, then downstream
# git operations and filesystem joins (`Path(target_dir) / repo`)
# could be tricked into path-traversal-shaped behaviour. The
# negative lookahead `(?!\.)` after a `.` forbids a SECOND dot
# immediately, blocking `..` runs anywhere in the body while still
# allowing single-dot positions (e.g. `repo.name`, `foo.bar.git`).
_ALLOWED_PATTERNS = [
    r"https://github\.com/\w[\w\-]*/\w(?:[\w\-]|\.(?!\.))*/?",
    r"https://gitlab\.com/\w[\w\-]*/\w(?:[\w\-]|\.(?!\.))*/?",
    r"git@github\.com:\w[\w\-]*/\w(?:[\w\-]|\.(?!\.))*\.git",
    r"git@gitlab\.com:\w[\w\-]*/\w(?:[\w\-]|\.(?!\.))*\.git",
]


def validate_repo_url(url: str) -> bool:
    """Return True if ``url`` matches one of the allowlist patterns.

    Uses ``re.fullmatch`` so a trailing newline (or any other char) is
    rejected — ``re.match`` + ``$`` would accept ``"...repo/\\n"``.
    """
    if len(url) > 2048:
        return False
    return any(re.fullmatch(p, url, re.ASCII) for p in _ALLOWED_PATTERNS)


__all__ = ["validate_repo_url"]
