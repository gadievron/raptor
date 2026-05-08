"""Path-filter computation for the test-suite workflow.

Replaces the third-party ``dorny/paths-filter`` action. Reads the set
of changed files for the current event from ``$CHANGED_FILES_LIST``
(one path per line) and writes ``<filter>=true|false`` lines to
``$GITHUB_OUTPUT``. If ``$CHANGED_FILES_LIST`` is unset or points at a
missing file, every filter is forced to ``true`` (safe fallback for
events without a meaningful diff base).

The ``FILTERS`` dict is the single source of truth for what each
subsystem-scoped CI job depends on. ``.github/tests/test_filter_coverage.py``
imports it directly to verify that every ``core.*`` / ``packages.*``
import made by a subsystem's source is covered by the corresponding
filter's globs.
"""

from __future__ import annotations

import fnmatch
import os
import sys
from pathlib import Path


FILTERS: dict[str, list[str]] = {
    "python": [
        "core/**",
        "packages/**",
        "libexec/tests/**",
        ".github/tests/**",
        "*.py",
        "requirements*.txt",
        "pyproject.toml",
        ".github/workflows/tests.yml",
    ],
    "bash_surface": [
        "raptor.py",
        "libexec/**",
        "core/**",
        "packages/**",
        "plugins/**",
        "test/**",
        "*.sh",
        "**/*.sh",
        "requirements*.txt",
        "pyproject.toml",
        ".github/workflows/tests.yml",
        ".github/workflows/bash-test.yml",
    ],
    # Direct + transitive deps for sandbox (validated by
    # .github/tests/test_filter_coverage.py).
    "sandbox": [
        "core/sandbox/**",
        "core/security/**",
        "core/config.py",
        "core/run/**",
        "libexec/raptor-run-sandboxed",
        "libexec/raptor-pid1-shim",
        "requirements*.txt",
        ".github/workflows/tests.yml",
    ],
    # Direct + transitive deps for exploit_feasibility. Several core/
    # modules are flat .py files (logging.py, config.py) so they are
    # listed by name rather than as ``foo/**`` glob prefixes.
    "exploit_feasibility": [
        "packages/exploit_feasibility/**",
        "packages/binary_analysis/**",
        "packages/codeql/smt_path_validator.py",
        "core/hash/**",
        "core/json/**",
        "core/logging.py",
        "core/logging/**",
        "core/config.py",
        "core/orchestration/**",
        "core/sandbox/**",
        "core/smt_solver/**",
        "requirements*.txt",
        ".github/workflows/tests.yml",
    ],
    # CodeQL per-language scoping. Each matrix entry in codeql.yml
    # gates on the corresponding filter, so a python-only PR skips the
    # c-cpp and actions matrix entries (and vice versa).
    "codeql_python": [
        "**/*.py",
        "requirements*.txt",
        "pyproject.toml",
        ".github/workflows/codeql.yml",
        ".github/codeql/**",
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
    ],
    "codeql_actions": [
        ".github/workflows/**",
        ".github/actions/**",
        "action.yml",
        "action.yaml",
        ".github/codeql/**",
    ],
    # Prompt-envelope audit: AST-based heuristic that scans a registered
    # list of prompt-construction files for untrusted-attribute
    # interpolations bypassing UntrustedBlock / neutralize_tag_forgery.
    # Only re-runs when an audited file, the audit module, or the test
    # itself changes. Hardcoded list mirrors
    # ``_PROMPT_CONSTRUCTION_FILES`` in
    # core/security/prompt_envelope_audit.py — drift caught by the
    # filter-coverage lint in .github/tests/test_filter_coverage.py.
    "prompt_audit": [
        # Audit module + allowlist (same file)
        "core/security/prompt_envelope_audit.py",
        # Audit test file
        "core/security/tests/test_prompt_envelope_audit.py",
        # Registered prompt-builder files
        "packages/llm_analysis/agent.py",
        "packages/llm_analysis/dataflow_validation.py",
        "packages/llm_analysis/orchestrator.py",
        "packages/llm_analysis/prefilter.py",
        "packages/llm_analysis/tasks.py",
        "packages/llm_analysis/crash_agent.py",
        "packages/llm_analysis/prompts/analysis.py",
        "packages/llm_analysis/prompts/exploit.py",
        "packages/llm_analysis/prompts/patch.py",
        "packages/hypothesis_validation/runner.py",
        "packages/codeql/autonomous_analyzer.py",
        "packages/codeql/dataflow_validator.py",
        "packages/codeql/build_detector.py",
        "packages/web/fuzzer.py",
        "packages/autonomous/dialogue.py",
        "core/llm/multi_model/prompt_helpers.py",
        "packages/cve_diff/cve_diff/agent/loop.py",
        "packages/cve_diff/cve_diff/agent/prompt.py",
        "packages/cve_diff/cve_diff/analysis/analyzer.py",
        "requirements*.txt",
        ".github/workflows/tests.yml",
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


def evaluate(changed_files: list[str] | None) -> dict[str, bool]:
    """Return ``{filter_name: matched}`` for every filter in ``FILTERS``.

    ``None`` signals "no diff base available" — every filter is forced
    on so a CI mistake errs toward running tests.
    """
    if changed_files is None:
        return {name: True for name in FILTERS}
    out: dict[str, bool] = {}
    for name, patterns in FILTERS.items():
        out[name] = any(
            match_glob(f, p) for f in changed_files for p in patterns
        )
    return out


def _read_changed_files() -> list[str] | None:
    list_path = os.environ.get("CHANGED_FILES_LIST")
    if not list_path:
        return None
    p = Path(list_path)
    if not p.is_file():
        return None
    return [
        line.strip() for line in p.read_text().splitlines() if line.strip()
    ]


def main() -> int:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        print("ERROR: GITHUB_OUTPUT not set", file=sys.stderr)
        return 1

    changed = _read_changed_files()
    results = evaluate(changed)

    with open(output, "a", encoding="utf-8") as fh:
        for name, hit in results.items():
            fh.write(f"{name}={'true' if hit else 'false'}\n")

    if changed is None:
        print("No diff base available — forcing all filters to true.")
    else:
        print(f"Changed files: {len(changed)}")
        for name, hit in results.items():
            print(f"  {name}: {hit}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
