"""Performance baseline on a synthetic 10k-dep monorepo.

Builds a fixture with O(10k) deps across mixed ecosystems, runs
``raptor-sca <target> --offline`` against it, records:

  * Cold wallclock (total)
  * Peak RSS of the scan process itself (via ``os.wait4`` performed
    by a slim relay interpreter — see ``_run_scan`` for why both
    session-cumulative ``getrusage`` readings and a direct
    fork-from-pytest ``wait4`` are wrong here)
  * Per-stage timing (best-effort — extracted from stderr if
    progress logs carry stage transitions)

Pinned to a regression-detection threshold (default `RUNTIME_BUDGET_S`).
When the budget is exceeded the test fails with the full
breakdown so the operator can identify the regressed stage.

Marked ``slow`` so default test runs don't pay the 30-60s cost;
explicit ``pytest -m slow`` opts in. The test is the **baseline**
— the absolute numbers it records are themselves the documented
behaviour, not just the pass/fail gate. Future runs that go 2x
slower trip the assertion.

Why 10k specifically: it's the size operators are most likely
to hit (large monorepo with multi-ecosystem deps + transitive
expansion). The threshold is set generously — only catches
egregious regressions.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


# Regression threshold. Adjust upward only when a substantive +
# documented perf trade was made (e.g. enabling a new checker).
# Catch egregious regressions (10x), not normal variance.
RUNTIME_BUDGET_S = 120.0    # 2 minutes — generous for CI
RSS_BUDGET_MB = 1024        # 1 GiB peak — generous

# Synthetic-fixture targets. Round numbers that make sample-rate
# tests easy to write.
PYTHON_DEPS = 2000
NPM_DEPS = 2000
CARGO_DEPS = 1000
GO_DEPS = 1000
MAVEN_DEPS = 1000
COMPOSER_DEPS = 1000
GEM_DEPS = 1000
DOCKER_IMAGES = 50          # k8s manifests
GHA_ACTIONS = 20            # GHA workflows
# Total ≈ 10070


def _build_large_monorepo(repo: Path) -> None:
    """Generate a synthetic ~10k-dep multi-ecosystem fixture."""
    repo.mkdir(parents=True, exist_ok=True)

    # Python
    lines = [f"req-pkg-{i}=={1+i//100}.0.{i%100}\n" for i in range(PYTHON_DEPS)]
    (repo / "requirements.txt").write_text("".join(lines), encoding="utf-8")

    # Node
    deps = {f"npm-pkg-{i}": f"{1+i//100}.0.{i%100}" for i in range(NPM_DEPS)}
    (repo / "package.json").write_text(json.dumps({
        "name": "monorepo", "version": "1.0.0", "dependencies": deps,
    }), encoding="utf-8")

    # Cargo
    cargo_lines = ['[package]', 'name = "monorepo"', 'version = "0.1.0"',
                   'edition = "2021"', '', '[dependencies]']
    for i in range(CARGO_DEPS):
        cargo_lines.append(f'cargo-pkg-{i} = "{1+i//100}.0.{i%100}"')
    (repo / "Cargo.toml").write_text(
        "\n".join(cargo_lines) + "\n", encoding="utf-8",
    )

    # Go
    go_lines = ['module monorepo', '', 'go 1.21', '', 'require (']
    for i in range(GO_DEPS):
        go_lines.append(
            f'\texample.com/go-pkg-{i} v{1+i//100}.0.{i%100}'
        )
    go_lines.append(')')
    (repo / "go.mod").write_text(
        "\n".join(go_lines) + "\n", encoding="utf-8",
    )

    # Maven
    pom_deps = "\n".join([
        f'    <dependency>\n'
        f'      <groupId>com.example.mvn</groupId>\n'
        f'      <artifactId>mvn-pkg-{i}</artifactId>\n'
        f'      <version>{1+i//100}.0.{i%100}</version>\n'
        f'    </dependency>'
        for i in range(MAVEN_DEPS)
    ])
    (repo / "pom.xml").write_text(f'''<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>monorepo</artifactId>
  <version>1.0</version>
  <dependencies>
{pom_deps}
  </dependencies>
</project>
''', encoding="utf-8")

    # Composer
    composer_deps = {
        f"vendor/composer-pkg-{i}": f"^{1+i//100}.0"
        for i in range(COMPOSER_DEPS)
    }
    (repo / "composer.json").write_text(json.dumps({
        "name": "example/monorepo", "require": composer_deps,
    }), encoding="utf-8")

    # RubyGems
    gemfile_lines = ["source 'https://rubygems.org'", ""]
    for i in range(GEM_DEPS):
        gemfile_lines.append(
            f"gem 'gem-pkg-{i}', '{1+i//100}.0.{i%100}'"
        )
    (repo / "Gemfile").write_text(
        "\n".join(gemfile_lines) + "\n", encoding="utf-8",
    )

    # k8s manifests (Dockerfile FROM resolves these via core.oci)
    (repo / "k8s").mkdir()
    for i in range(DOCKER_IMAGES):
        (repo / "k8s" / f"app-{i}.yaml").write_text(
            f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: app-{i}
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.{i}.0
''', encoding="utf-8",
        )

    # GHA workflows
    (repo / ".github" / "workflows").mkdir(parents=True)
    for i in range(GHA_ACTIONS):
        (repo / ".github" / "workflows" / f"wf-{i}.yml").write_text(
            f"name: wf-{i}\n"
            "on: [push]\n"
            "jobs:\n"
            f"  test:\n"
            f"    runs-on: ubuntu-latest\n"
            f"    steps:\n"
            f"      - uses: actions/checkout@v{3 + i % 2}\n",
            encoding="utf-8",
        )


# Hard cap on one scan invocation. Mirrors the old
# ``subprocess.run(..., timeout=600)`` bound.
_SCAN_TIMEOUT_S = 600.0

# ``os.wait4`` poll interval while the scan child runs.
_WAIT_POLL_S = 0.05


def _rusage_rss_mb(ru_maxrss: int) -> float:
    """Convert a reaped child's ``ru_maxrss`` to MiB.

    Linux: ``ru_maxrss`` is in KiB. macOS: ``ru_maxrss`` is in bytes.
    Sniff via platform.
    """
    if sys.platform == "darwin":
        return ru_maxrss / (1024 * 1024)
    return ru_maxrss / 1024


# Measurement relay: a freshly exec'd interpreter that spawns the
# scan, reaps it via ``os.wait4``, and writes ``{exit, ru_maxrss}``
# as JSON to the path in argv[1]. Runs the reaping from a slim
# (~15 MiB) process instead of the test process — see ``_run_scan``
# for why the fork parent's size matters.
_RELAY_SRC = """\
import json, os, subprocess, sys

result_path = sys.argv[1]
proc = subprocess.Popen(sys.argv[2:])
_, status, rusage = os.wait4(proc.pid, 0)
proc.returncode = os.waitstatus_to_exitcode(status)
with open(result_path, "w", encoding="utf-8") as fh:
    json.dump({
        "exit": proc.returncode,
        "ru_maxrss": rusage.ru_maxrss,
    }, fh)
"""


def _run_scan(target: Path, out: Path) -> tuple[float, float, str]:
    """Run the scan, returning (wallclock_s, peak_child_rss_mb,
    stderr).

    Peak RSS comes from ``os.wait4`` on the scan process, so the
    reading covers exactly that child (plus anything it spawned and
    reaped) and nothing else. Two measurement artifacts shaped this
    implementation — both surfaced as nightly failures where this
    gate blamed the SCA scan for memory it never allocated:

    * ``resource.getrusage(RUSAGE_CHILDREN)`` (the original
      implementation) is the high-water mark across EVERY child the
      test process ever reaped — and the nightly runs all slow tests
      in one shuffled pytest process, so an earlier test's
      heavyweight child (an audit-orchestrator E2E's Joern JVM peaks
      ~1.7 GiB) set the mark. Fixed by per-child ``os.wait4``.

    * A child forked directly from the test process inherits the
      test process's resident set: on Linux the pre-exec
      (COW-shared) address space is accounted to the child, so the
      ``ru_maxrss`` that ``wait4`` reports starts at the fork
      parent's RSS at spawn time, regardless of what the child
      itself allocates (measured: a 1.5 GiB parent produces a
      1.5 GiB ``wait4`` reading for a scan whose true peak is
      ~120 MiB). The nightly's single pytest process accumulates
      >1.7 GiB across the slow suite, so any scan forked from it
      read as ~1.8 GiB. Fixed by exec'ing a slim relay interpreter
      (``_RELAY_SRC``) and letting IT spawn + ``wait4`` the scan:
      the scan then forks from a ~15 MiB parent, and the relay's
      own (still-contaminated) rusage is discarded.

    Scan stdout/stderr go to unnamed temp files rather than pipes
    (inherited through the relay, which touches neither stream):
    the relay's ``os.wait4`` must be the reaper, and files can't
    deadlock on a full pipe buffer while it sits in the wait call.
    """
    cmd = [
        sys.executable, "-m", "packages.sca.cli",
        str(target), "--offline", "--out", str(out),
    ]
    result_fd, result_path = tempfile.mkstemp(suffix=".json")
    os.close(result_fd)
    try:
        start = time.perf_counter()
        with tempfile.TemporaryFile() as out_fh, \
                tempfile.TemporaryFile() as err_fh:
            proc = subprocess.Popen(
                [sys.executable, "-c", _RELAY_SRC, result_path, *cmd],
                stdout=out_fh, stderr=err_fh, cwd=str(REPO_ROOT),
                start_new_session=True,
            )
            deadline = start + _SCAN_TIMEOUT_S
            while True:
                pid, status, _ = os.wait4(proc.pid, os.WNOHANG)
                if pid == proc.pid:
                    break
                if time.perf_counter() > deadline:
                    # Kill the whole session (relay + scan) — killing
                    # just the relay would orphan the scan.
                    os.killpg(proc.pid, signal.SIGKILL)
                    _, status, _ = os.wait4(proc.pid, 0)
                    proc.returncode = os.waitstatus_to_exitcode(status)
                    raise RuntimeError(
                        f"scan timed out after {_SCAN_TIMEOUT_S:.0f}s"
                    )
                time.sleep(_WAIT_POLL_S)
            # The relay was reaped via wait4, behind Popen's back —
            # sync its bookkeeping so __exit__/__del__ don't wait
            # again.
            relay_rc = os.waitstatus_to_exitcode(status)
            proc.returncode = relay_rc
            elapsed = time.perf_counter() - start
            err_fh.seek(0)
            stderr = err_fh.read().decode("utf-8", errors="replace")
        if relay_rc != 0:
            raise RuntimeError(
                f"measurement relay crashed: exit={relay_rc}\n"
                f"stderr (last 2k):\n{stderr[-2000:]}"
            )
        result = json.loads(
            Path(result_path).read_text(encoding="utf-8")
        )
    finally:
        os.unlink(result_path)
    returncode = result["exit"]
    rss_mb = _rusage_rss_mb(result["ru_maxrss"])
    if returncode not in (0, 1):
        raise RuntimeError(
            f"scan crashed: exit={returncode}\n"
            f"stderr (last 2k):\n{stderr[-2000:]}"
        )
    return elapsed, rss_mb, stderr


# ---------------------------------------------------------------------------
# Shared fixture — builds the monorepo once, runs the scan once, shares
# (elapsed, rss_mb, stderr, out_dir, repo_dir) across both tests. Saves
# one full build+scan cycle (~5s) vs the old per-test approach.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def _monorepo_scan_result(tmp_path_factory):
    base = tmp_path_factory.mktemp("sca_perf")
    repo = base / "monorepo"
    _build_large_monorepo(repo)
    out = base / "out"
    elapsed, rss_mb, stderr = _run_scan(repo, out)
    total_files = sum(1 for _ in repo.rglob("*") if _.is_file())
    return elapsed, rss_mb, stderr, out, total_files


# ---------------------------------------------------------------------------
# The actual perf gate
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_10k_dep_monorepo_within_budget(_monorepo_scan_result) -> None:
    """A ~10k-dep multi-ecosystem fixture scans within
    ``RUNTIME_BUDGET_S`` seconds and ``RSS_BUDGET_MB`` MiB.

    Surfaces the full breakdown on failure so a regression
    points at the responsible stage."""
    elapsed, rss_mb, stderr, out, total_files = _monorepo_scan_result

    assert total_files > 50, (
        f"fixture too small: only {total_files} files generated"
    )

    print(
        f"\n[perf-baseline 10k-dep monorepo]\n"
        f"  wallclock:  {elapsed:6.2f}s  (budget {RUNTIME_BUDGET_S:.0f}s)\n"
        f"  peak RSS:   {rss_mb:6.1f}MiB (budget {RSS_BUDGET_MB:.0f}MiB)\n"
        f"  fixture:    {total_files} files / {PYTHON_DEPS+NPM_DEPS+CARGO_DEPS+GO_DEPS+MAVEN_DEPS+COMPOSER_DEPS+GEM_DEPS} declared deps\n"
    )

    assert elapsed < RUNTIME_BUDGET_S, (
        f"scan took {elapsed:.1f}s — over budget {RUNTIME_BUDGET_S:.0f}s.\n"
        f"Peak RSS: {rss_mb:.1f}MiB.\n"
        f"Last stderr lines:\n{stderr[-1500:]}"
    )
    assert rss_mb < RSS_BUDGET_MB, (
        f"peak RSS {rss_mb:.1f}MiB — over budget {RSS_BUDGET_MB:.0f}MiB.\n"
        f"Wallclock: {elapsed:.1f}s.\n"
        f"Last stderr lines:\n{stderr[-1500:]}"
    )

    # Spot-check that the scan didn't silently drop the fixture
    findings = out / "findings.json"
    assert findings.is_file()
    data = json.loads(findings.read_text())
    items = data if isinstance(data, list) else data.get("findings", [])
    assert len(items) > 0, "monorepo scan produced ZERO findings"


@pytest.mark.slow
def test_per_stage_progress_emitted(_monorepo_scan_result) -> None:
    """Progress reporter emits identifiable stage markers; the
    perf baseline depends on these to attribute time to stages
    when a regression hits.
    """
    _, _, stderr, _, _ = _monorepo_scan_result
    stage_markers = ["discovery", "join", "osv"]
    found = [s for s in stage_markers if s in stderr.lower()]
    assert found, (
        f"no stage markers in stderr — perf attribution unavailable.\n"
        f"stderr (last 2k):\n{stderr[-2000:]}"
    )
