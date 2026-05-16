"""Static checks confirming each consumer wired in PR2 carries
`sanitise_host_fingerprint=True` at every sandbox.run call site that
executes target-supplied or attacker-influenced code.

Dynamic invocation tests would re-prove what
test_fingerprint_e2e.py already covers (the persona's effect inside
the spawned child). What we need here is a regression guard that
the wiring stays in place across refactors — a static source check
is precisely the right granularity.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]


# (file, minimum number of sites expected, optional descriptor)
PR2_CONSUMERS = [
    ("packages/binary_analysis/debugger.py", 2,
     "GDB under sandbox(profile=debug): two paths (with/without "
     "input file)"),
    ("packages/binary_analysis/crash_analyser.py", 4,
     "GDB analysis + LLDB analysis + LLDB fallback + plain binary "
     "replay against ASAN-built target"),
    ("packages/fuzzing/afl_runner.py", 1,
     "afl-showmap coverage compute on harness + input"),
    ("packages/codeql/database_manager.py", 1,
     "codeql database create — runs target-supplied build commands "
     "during autobuild (paired with cpu_count=HOST_CPU_COUNT to "
     "preserve build parallelism)"),
]


@pytest.mark.parametrize("rel,min_sites,descriptor", PR2_CONSUMERS)
def test_consumer_passes_sanitise_host_fingerprint(rel, min_sites, descriptor):
    """Every site in the file that calls `_sandbox_run(...)` /
    `sandbox_run(...)` / `sandbox.run(...)` AND looks like it
    executes target-derived content must include
    `sanitise_host_fingerprint=True` within the call.

    We use a coarse static check (count kwargs in the file) rather
    than parsing the AST: the source files are stable enough that
    counting occurrences of the literal kwarg is sufficient, and
    the comment hints in each file make the intent clear to a
    human reviewer."""
    f = REPO_ROOT / rel
    assert f.is_file(), f"missing consumer file: {f}"
    text = f.read_text()
    sites = len(re.findall(
        r"sanitise_host_fingerprint\s*=\s*True", text,
    ))
    assert sites >= min_sites, (
        f"{rel}: expected at least {min_sites} "
        f"`sanitise_host_fingerprint=True` site(s) ({descriptor}); "
        f"found {sites}. A refactor likely dropped one."
    )


def test_query_runner_does_NOT_sanitise():
    """packages/codeql/query_runner.py runs `codeql analyze` against
    a pre-built database — it doesn't exec target code, so adding
    sanitisation there would be pure overhead. Assert it stays
    un-sanitised so a well-meaning copy-paste doesn't introduce
    unnecessary mount-ns engagement."""
    f = REPO_ROOT / "packages/codeql/query_runner.py"
    text = f.read_text()
    assert "sanitise_host_fingerprint=True" not in text, (
        "query_runner.py must NOT pass sanitise_host_fingerprint — "
        "it analyses pre-built CodeQL databases, doesn't run target "
        "code, and the mount-ns engagement would be wasted overhead. "
        "If you have a reason to sanitise there, update this test."
    )


def test_build_detector_target_repo_sites_unchanged():
    """packages/codeql/build_detector.py has two sandbox.run sites:
    one runs an LLM-emitted Python script for build-system detection
    (doesn't exec target binaries directly), one runs Claude Code.
    Neither needs sanitisation today. Pinned here so adding
    sanitisation later is a deliberate change, not accidental."""
    f = REPO_ROOT / "packages/codeql/build_detector.py"
    text = f.read_text()
    assert "sanitise_host_fingerprint=True" not in text, (
        "build_detector.py started sanitising — confirm this is "
        "intended and update this test if so"
    )


def test_codeql_database_manager_uses_host_cpu_count():
    """packages/codeql/database_manager.py wires sanitisation PAIRED
    with cpu_count=HOST_CPU_COUNT so the target repo's parallel build
    (make -j$(nproc), mvn -T NC, gradle --parallel) keeps real
    parallelism. Default cpu_count=4 would serialise builds to 4
    threads and push them past CODEQL_TIMEOUT on multi-core hosts."""
    f = REPO_ROOT / "packages/codeql/database_manager.py"
    text = f.read_text()
    assert "sanitise_host_fingerprint=True" in text, (
        "database_manager.py must sanitise — it runs the target "
        "repo's build commands"
    )
    assert "cpu_count=HOST_CPU_COUNT" in text, (
        "database_manager.py must use cpu_count=HOST_CPU_COUNT — "
        "the default cpu_count=4 would serialise parallel builds and "
        "push long codeql builds past CODEQL_TIMEOUT"
    )
