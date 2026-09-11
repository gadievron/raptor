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
from typing import Any
from collections.abc import Callable

from cve_diff.diffing import shape as static_shape

LanguagesFetcher = Callable[[str], dict[str, Any] | None]

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

# Intrinsically ambiguous extensions map to EVERY language they can
# belong to: a header-only fix in a repo GitHub reports as {"C++"}
# (no "C" entry in /languages) is still a source change, and forcing
# it through the single-language map hard-failed genuine upstream
# fixes as "packaging_only" / "likely downstream mirror".
_EXT_TO_LANGUAGES_MULTI: dict[str, frozenset[str]] = {
    ".h": frozenset({"c", "c++", "objective-c"}),
    ".hh": frozenset({"c++", "c"}),
    ".m": frozenset({"objective-c", "matlab"}),
}


def _langs_for_ext(ext: str) -> frozenset[str]:
    multi = _EXT_TO_LANGUAGES_MULTI.get(ext)
    if multi:
        return multi
    lang = _EXT_TO_LANGUAGE.get(ext)
    return frozenset({lang}) if lang else frozenset()


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
        # nosemgrep: sinks.raptor.web.ssrf.dynamic-url
        # ``fetch`` is a typed injected callable (parameter at
        # line 75). The GitHub-API URL it builds is internal to
        # the cve-diff package; ``slug`` is a vetted owner/repo
        # form, not raw user input.
        payload = fetch(slug)
        if payload:
            repo_langs = frozenset(str(k).lower() for k in payload)
            any_mapped = False
            for path in files:
                langs = _langs_for_ext(_ext(path))
                if langs:
                    any_mapped = True
                    if langs & repo_langs:
                        return "source"
            if any_mapped:
                return _non_source_breakdown(files)
            # No changed file's extension is even IN the (deliberately
            # small, intrinsic) map — grammar / SQL / Fortran / template
            # fixes are real source changes this table doesn't cover.
            # The dynamic layer has no signal either way, so it must
            # fall back to the static classifier rather than force a
            # non-source verdict that hard-fails the run.

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
