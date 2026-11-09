"""CodeQL per-language path filters for the CI workflows.

Reads the set of changed files for the current event from
``$CHANGED_FILES_LIST`` (one path per line) and writes
``<filter>=true|false`` lines to ``$GITHUB_OUTPUT``.  If
``$CHANGED_FILES_LIST`` is unset or points at a missing file, every
filter is forced to ``true`` (safe fallback for events without a
meaningful diff base).

Subsystem-level test dispatch (sandbox, sca, llm_analysis, etc.) is
handled by ``test_scope.py`` via import-graph analysis.  This file
retains only the CodeQL per-language gates (codeql_python, codeql_cpp,
codeql_actions) used by ``codeql.yml``. Python source triggers honour the
scanner config's exclusions; unfamiliar config shapes retain broad matching.
Dependency and workflow metadata keep their original triggers.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import sys
from pathlib import Path


FILTERS: dict[str, list[str]] = {
    "codeql_python": [
        "**/*.py",
        "requirements*.txt",
        "pyproject.toml",
        "uv.lock",
        ".github/workflows/codeql.yml",
        ".github/codeql/**",
        ".github/scripts/ci_push_base.py",
    ],
    "codeql_cpp": [
        "**/*.c",
        "**/*.h",
        "**/*.cpp",
        "**/*.hpp",
        "**/*.cc",
        "**/*.hh",
        ".github/workflows/codeql.yml",
        ".github/codeql/**",
        ".github/scripts/ci_push_base.py",
    ],
    "codeql_actions": [
        ".github/workflows/**",
        ".github/actions/**",
        "action.yml",
        "action.yaml",
        ".github/codeql/**",
        ".github/scripts/ci_push_base.py",
    ],
}


def match_glob(path: str, pattern: str) -> bool:
    """Approximate minimatch semantics for the patterns in ``FILTERS``.

    Rules:
      * ``foo/bar.py``  exact match
      * ``foo/**``      recursive prefix (matches ``foo`` and ``foo/...``)
      * ``**/X``        ``X`` at any depth, including top-level
      * ``*.py``        single-segment match (no ``/`` in pattern → top-level)
      * ``foo/*.py``    one segment after ``foo/``
    """
    if path == pattern:
        return True

    # Recursive prefix: ``foo/**`` matches ``foo`` and anything under it.
    if pattern.endswith("/**"):
        prefix = pattern[: -len("/**")]
        return path == prefix or path.startswith(prefix + "/")

    # ``**/X`` — match X at any depth.
    if pattern.startswith("**/"):
        suffix = pattern[len("**/") :]
        # Try every path-suffix (including the full path) against the suffix.
        parts = path.split("/")
        for i in range(len(parts)):
            if fnmatch.fnmatchcase("/".join(parts[i:]), suffix):
                return True
        return False

    # No ``/`` in pattern → restrict to top-level files.
    if "/" not in pattern:
        return "/" not in path and fnmatch.fnmatchcase(path, pattern)

    # Anything else: defer to fnmatch on the full path.
    return fnmatch.fnmatchcase(path, pattern)


CONFIG = Path(__file__).resolve().parents[2] / ".github/codeql/codeql-config.yml"


def _ignored_source_patterns() -> tuple[str, ...]:
    """Recognise the config's scalar list; unfamiliar shapes keep broad scans.

    Restrict this optimisation to the current simple config rather than adding
    a YAML dependency to the selector. Metadata edits always trigger scans.
    """
    patterns = []
    seen_name = seen_list = False
    try:
        for line in CONFIG.read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            if not line.startswith(" "):
                if value.startswith("name: ") and not seen_name and not seen_list:
                    label = value[len("name: "):]
                    if label.startswith('"'):
                        if not isinstance(json.loads(label), str):
                            return ()
                    elif not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_. -]*", label):
                        return ()
                    seen_name = True
                    continue
                if value == "paths-ignore:" and not seen_list:
                    seen_list = True
                    continue
                return ()
            if not seen_list or not line.startswith("  - "):
                return ()
            value = line[4:].strip()
            if not value.startswith('"'):
                return ()  # JSON-quoted scalars are unambiguous YAML strings.
            value = json.loads(value)
            if (not isinstance(value, str)
                    or not re.fullmatch(r"[A-Za-z0-9_./*\-]+", value)
                    or any(part in ("", ".", "..") or "**" in part and part != "**"
                           for part in value.split("/"))):
                return ()
            patterns.append(value)
    except (OSError, ValueError):
        return ()
    return tuple(patterns)


def _ignored_source(path: str, pattern: str) -> bool:
    """Match CodeQL's segment stars and recursive directory prefixes."""
    parts, tokens = path.split("/"), pattern.split("/")

    def expand(positions):
        for j, token in enumerate(tokens):
            if token == "**" and j in positions:
                positions.add(j + 1)
        return positions

    positions = expand({0})
    for part in parts:
        if len(tokens) in positions:
            return True  # A matched directory includes its descendants.
        positions = expand({j if tokens[j] == "**" else j + 1
                            for j in positions
                            if tokens[j] == "**" or fnmatch.fnmatchcase(part, tokens[j])})
    return len(tokens) in positions


def evaluate(changed_files: list[str] | None) -> dict[str, bool]:
    """Return ``{filter_name: matched}`` for every filter in ``FILTERS``.

    ``None`` signals "no diff base available" — every filter is forced
    on so a CI mistake errs toward running tests.
    """
    if changed_files is None:
        return dict.fromkeys(FILTERS, True)
    ignored = _ignored_source_patterns()
    python_sources = [path for path in changed_files
                      if not any(_ignored_source(path, pattern) for pattern in ignored)]
    out: dict[str, bool] = {}
    for name, patterns in FILTERS.items():
        out[name] = any(
            match_glob(f, p) for p in patterns
            for f in (python_sources if name == "codeql_python" and p == "**/*.py"
                      else changed_files)
        )
    return out


def _read_changed_files() -> list[str] | None:
    """Return the list of changed files, or ``None`` if unavailable.

    A real PR always changes at least one file, so an *empty* list file
    means the upstream diff fetch silently produced zero entries (e.g.
    a fork-PR ``gh api .../pulls/N/files`` call that returned an empty
    page on partial auth). Treat that as "diff base unavailable" and
    force every filter on, rather than skipping all jobs.
    """
    list_path = os.environ.get("CHANGED_FILES_LIST")
    if not list_path:
        return None
    p = Path(list_path)
    if not p.is_file():
        return None
    files = [
        line.strip() for line in p.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    if not files:
        return None
    return files


def main() -> int:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        print("ERROR: GITHUB_OUTPUT not set", file=sys.stderr)
        return 1

    changed = _read_changed_files()
    results = evaluate(changed)

    with open(output, "a", encoding="utf-8") as fh:
        fh.writelines(f"{name}={'true' if hit else 'false'}\n" for name, hit in results.items())

    if changed is None:
        list_path = os.environ.get("CHANGED_FILES_LIST")
        if list_path and Path(list_path).is_file():
            print(
                f"Diff base produced empty file list ({list_path}) — "
                "treating as unavailable and forcing all filters to true."
            )
        else:
            print("No diff base available — forcing all filters to true.")
    else:
        print(f"Changed files: {len(changed)}")
        for name, hit in results.items():
            print(f"  {name}: {hit}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
