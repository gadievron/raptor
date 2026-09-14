"""Shared source-file extension set for the URL-scanning walkers.

``typosquat_domain`` and ``exfil_destinations`` scan the same class
of file — anything that can carry a hardcoded URL a payload would
dereference — but each carried its own extension set and they
drifted: the typosquat walker was missing ``.mjs`` / ``.cjs`` /
``.jsx`` / ``.tsx``, the PRIMARY npm hook-payload extensions its
exfil sibling already covered.  One constant, both consumers.

``exfil_destinations`` additionally scans documentation formats
(kept local there — exfil indicators in docs are still indicators,
while typosquat near-miss checks on prose would mostly find typos).
"""

from __future__ import annotations

# Code / script / config files that plausibly carry a payload URL.
SOURCE_CODE_EXTS: frozenset[str] = frozenset({
    ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".sh", ".bash", ".zsh", ".rb", ".go", ".rs", ".php", ".cs",
    ".java", ".kt", ".gradle", ".dockerfile",
    ".yml", ".yaml", ".json", ".toml", ".xml", ".cfg", ".ini",
})

__all__ = ["SOURCE_CODE_EXTS"]
