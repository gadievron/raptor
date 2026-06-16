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
        ".github/tests/**",
        "test/**",
        "*.py",
        "requirements*.txt",
        "pyproject.toml",
        ".github/workflows/tests.yml",
    ],
    # Direct + transitive deps for sandbox (validated by
    # .github/tests/test_filter_coverage.py).
    "sandbox": [
        "core/sandbox/**",
        "core/config/**",
        "core/run/**",
        "core/security/**",
        "libexec/raptor-pid1-shim",
        "libexec/raptor-run-sandboxed",
        "requirements*.txt",
        ".github/workflows/tests.yml",
    ],
    # Direct + transitive deps for exploit_feasibility. Note: pre-#447
    # `core/config.py`, `core/logging.py`, `core/progress.py`,
    # `core/schema_constants.py` were bare .py files; #447 promoted
    # each to a package directory. The bare-form globs have been
    # dropped from every filter below — restore them only if those
    # files are re-added (current main has package directories only).
    "exploit_feasibility": [
        "packages/exploit_feasibility/**",
        "packages/binary_analysis/**",
        "packages/codeql/smt_path_validator.py",
        "core/config/**",
        "core/function_taxonomy/**",
        "core/hash/**",
        "core/json/**",
        "core/logging/**",
        "core/orchestration/**",
        "core/sandbox/**",
        "core/smt_solver/**",
        "core/witness/**",
        "requirements*.txt",
        ".github/workflows/tests.yml",
    ],
    # CI lint / filter-coverage tests. Gated narrowly so a code-only PR
    # doesn't pay for them. Includes the prompt-envelope audit source
    # because the prompt_audit filter-coverage test imports it.
    "ci_lint": [
        ".github/scripts/**",
        ".github/tests/**",
        ".github/workflows/tests.yml",
        "core/security/prompt_envelope_audit.py",
    ],
    # Heavy subsystem tests carved out from the broad ``python`` fast
    # tier. Each subsystem's globs are validated by
    # ``.github/tests/test_filter_coverage.py`` against the actual
    # imports in its source tree. When a code-only PR doesn't touch a
    # subsystem, its tier is skipped — net runtime saving on most PRs.
    "codeql": [
        "packages/codeql/**",
        "packages/autonomous/**",
        "packages/source_intel/**",
        "core/build/**",
        "core/config/**",
        "core/coverage/**",
        "core/dataflow/**",
        "core/git/**",
        "core/hash/**",
        "core/inventory/**",
        "core/json/**",
        "core/llm/**",
        "core/logging/**",
        "core/orchestration/**",
        "core/reporting/**",
        "core/run/**",
        "core/sandbox/**",
        "core/sarif/**",
        "core/security/**",
        "core/smt_solver/**",
        "core/threat_model/**",
        "core/tuning/**",
        "core/zip/**",
        "requirements*.txt",
        ".github/workflows/tests.yml",
    ],
    "llm_analysis": [
        "packages/llm_analysis/**",
        "packages/autonomous/**",
        "packages/binary_analysis/**",
        "packages/checker_synthesis/**",
        "packages/codeql/**",
        "packages/cvss/**",
        "packages/exploit_feasibility/**",
        "packages/exploitability_validation/**",
        "packages/fuzzing/**",
        "packages/hypothesis_validation/**",
        "packages/source_intel/**",
        "core/annotations/**",
        "core/ast/**",
        "core/build/**",
        "core/config/**",
        "core/coverage/**",
        "core/dataflow/structural_validator.py",
        "core/hash/**",
        "core/inventory/**",
        "core/json/**",
        "core/llm/**",
        "core/logging/**",
        "core/orchestration/**",
        "core/progress/**",
        "core/reporting/**",
        "core/run/**",
        "core/sage/**",
        "core/sandbox/**",
        "core/sarif/**",
        "core/schema_constants/**",
        "core/security/**",
        "core/smt_solver/**",
        "core/threat_model/**",
        "core/verified_outcome/**",
        "core/witness/**",
        "core/zip/**",
        "requirements*.txt",
        ".github/workflows/tests.yml",
    ],
    "cve_diff": [
        "packages/cve_diff/**",
        "packages/nvd/**",
        "packages/osv/**",
        "core/config/**",
        "core/git/**",
        "core/http/**",
        "core/json/**",
        "core/llm/**",
        "core/security/**",
        "core/url_patterns.py",
        "core/url_patterns/**",
        "requirements*.txt",
        ".github/workflows/tests.yml",
    ],
    "fuzzing": [
        "packages/fuzzing/**",
        "packages/autonomous/**",
        "packages/binary_analysis/**",
        "core/config/**",
        "core/hash/**",
        "core/json/**",
        "core/logging/**",
        "core/sandbox/**",
        "core/witness/**",
        "requirements*.txt",
        ".github/workflows/tests.yml",
    ],
    "sage": [
        "core/sage/**",
        "packages/autonomous/**",
        "packages/exploit_feasibility/**",
        "packages/llm_analysis/**",
        "core/config/**",
        "core/hash/**",
        "core/llm/**",
        "core/logging/**",
        "core/sandbox/**",
        "core/security/**",
        "requirements*.txt",
        ".github/workflows/tests.yml",
    ],
    # SCA tier — ~3,255 tests as of 2026-05-23, ≈30% of the broad
    # ``python`` fast tier's collected count. Carving into its own
    # gated job removes a 30-percent-of-corpus cluster from the
    # 4-way pytest-split, evening out the fast-tier shards. Globs
    # cover packages/sca + the 16 core/ and 3 packages/ siblings
    # SCA actually imports (validated by test_filter_coverage.py).
    "sca": [
        "packages/sca/**",
        "packages/binary_analysis/**",
        "packages/cvss/**",
        "packages/osv/**",
        "core/binary/**",
        "core/config/**",
        "core/coverage/**",
        "core/cve/**",
        "core/dockerfile/**",
        "core/http/**",
        "core/inventory/**",
        "core/json/**",
        "core/license/**",
        "core/llm/**",
        "core/oci/**",
        "core/progress/**",
        "core/sandbox/**",
        "core/security/**",
        "core/tar/**",
        "core/upstream_latest/**",
        "core/zip/**",
        "requirements*.txt",
        ".github/workflows/tests.yml",
    ],
    "orchestration": [
        "core/orchestration/**",
        "packages/codeql/**",
        "packages/exploitability_validation/**",
        "core/ast/**",
        "core/config/**",
        "core/hash/**",
        "core/inventory/**",
        "core/json/**",
        "core/llm/**",
        "core/run/**",
        "core/sandbox/**",
        "core/schema_constants/**",
        "core/security/**",
        "core/threat_model/**",
        "requirements*.txt",
        ".github/workflows/tests.yml",
    ],
    # source_intel: Coccinelle-driven memory-corruption evidence.
    # Carved into its own tier so the dedicated job can apt-install
    # coccinelle and actually RUN the real-spatch E2E — in the broad
    # ``python`` fast tier those tests skipif(not which("spatch")) and
    # so never executed in CI (spatch isn't installed there). The
    # import-derived globs below are auto-maintained by
    # ``.github/tests/test_filter_coverage.py --update``.
    "source_intel": [
        "packages/source_intel/**",
        "packages/coccinelle/**",
        "packages/codeql/dataflow_validator.py",
        "packages/llm_analysis/**",
        "core/build/**",
        "core/dataflow/**",
        "core/function_taxonomy/**",
        "core/inventory/**",
        "core/llm/**",
        "core/security/**",
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
        line.strip() for line in p.read_text().splitlines() if line.strip()
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
        for name, hit in results.items():
            fh.write(f"{name}={'true' if hit else 'false'}\n")

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
