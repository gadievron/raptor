"""
Shape classification driven by GitHub `/repos/{slug}/languages`.

The static classifier in ``shape.py`` carries a project-by-project list of
packaging/notes filenames. The user's standing directive
(``feedback_dynamic_signals_over_lists.md``) is to derive decisions from
runtime signals where possible.

This module asks GitHub directly: what languages exist in this repo? A
changed file is "source" when its extension corresponds to a language the
repo actually contains. Everything else falls back to two universal
heuristics — release notes and version manifests — that aren't tied to any
single ecosystem.

Behaviour:
- When the fetcher returns ``None`` (no auth / rate-limit / 404), the result
  is identical to the static ``shape.classify`` fall-back so nothing
  regresses on offline benches.
- Extension->language map is intentionally small and *intrinsic to the file
  format* (``.py`` is Python everywhere). It is the conceptual opposite of
  the repo-specific seeded lists the user has flagged.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Callable, Optional

from cve_diff.diffing import shape as static_shape

LanguagesFetcher = Callable[[str], Optional[dict[str, Any]]]

_EXT_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".pyx": "python", ".pyi": "python",
    ".c": "c", ".h": "c",
    ".cc": "c++", ".cpp": "c++", ".cxx": "c++", ".hpp": "c++", ".hh": "c++",
    ".rs": "rust",
    ".go": "go",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".rb": "ruby",
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".swift": "swift",
    ".m": "objective-c", ".mm": "objective-c++",
    ".cs": "c#",
    ".php": "php",
    ".lua": "lua",
    ".pl": "perl", ".pm": "perl",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".scala": "scala",
    ".clj": "clojure", ".cljs": "clojure",
    ".ex": "elixir", ".exs": "elixir",
    ".erl": "erlang",
    ".hs": "haskell",
    ".ml": "ocaml", ".mli": "ocaml",
    ".dart": "dart",
    ".groovy": "groovy",
    ".r": "r",
    ".jl": "julia",
    ".nim": "nim",
    ".zig": "zig",
    ".elm": "elm",
    ".sol": "solidity",
    ".vue": "vue",
    ".asm": "assembly", ".s": "assembly",
    ".ps1": "powershell",
}


def classify(
    files: list[str],
    slug: str | None,
    fetch: LanguagesFetcher,
) -> str:
    """Return ``source`` / ``packaging_only`` / ``notes_only`` for ``files``.

    Strategy:
      1. Empty diff -> ``source`` (parity with static classifier).
      2. If we can fetch ``/languages`` for ``slug`` and any changed file's
         extension matches one of the repo's languages -> ``source``.
      3. Otherwise fall back to the static classifier so nothing regresses
         on offline runs or repos GitHub doesn't enumerate.
    """
    if not files:
        return "source"

    if slug:
        payload = fetch(slug)
        if payload:
            repo_langs = frozenset(str(k).lower() for k in payload.keys())
            for path in files:
                ext = _ext(path)
                lang = _EXT_TO_LANGUAGE.get(ext)
                if lang and lang in repo_langs:
                    return "source"
            return _non_source_breakdown(files)

    return static_shape.classify(files)


def _ext(path: str) -> str:
    name = PurePosixPath(path).name
    # Leading-dot file with no second dot is a dotfile, not an extension.
    stripped = name.lstrip(".")
    if "." not in stripped:
        return ""
    return "." + stripped.rsplit(".", 1)[1].lower()


def _non_source_breakdown(files: list[str]) -> str:
    """Once /languages says no file is source, decide notes vs packaging."""
    cats = {static_shape._classify_one(f) for f in files}
    if cats == {"notes"}:
        return "notes_only"
    return "packaging_only"
