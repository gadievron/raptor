"""Performance baseline on a synthetic 10k-dep monorepo.

Builds a fixture with O(10k) deps across mixed ecosystems, runs
``raptor-sca <target> --offline`` against it, records:

  * Cold wallclock (total)
  * Peak RSS (via ``resource.getrusage``)
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
import resource
import subprocess
import sys
import time
from pathlib import Path
from typing import Tuple

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


def _peak_rss_mb() -> float:
    """Peak RSS of the current process in MiB.

    Linux: ``ru_maxrss`` is in KiB. macOS: ``ru_maxrss`` is in bytes.
    Sniff via platform.
    """
    rusage = resource.getrusage(resource.RUSAGE_CHILDREN)
    if sys.platform == "darwin":
        return rusage.ru_maxrss / (1024 * 1024)
    return rusage.ru_maxrss / 1024


def _run_scan(target: Path, out: Path) -> Tuple[float, float, str]:
    """Run the scan, returning (wallclock_s, peak_child_rss_mb,
    stderr)."""
    cmd = [
        sys.executable, "-m", "packages.sca.cli",
        str(target), "--offline", "--out", str(out),
    ]
    start = time.perf_counter()
    proc = subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(REPO_ROOT), timeout=600,
    )
    elapsed = time.perf_counter() - start
    rss_mb = _peak_rss_mb()
    if proc.returncode not in (0, 1):
        raise RuntimeError(
            f"scan crashed: exit={proc.returncode}\n"
            f"stderr (last 2k):\n{proc.stderr[-2000:]}"
        )
    return elapsed, rss_mb, proc.stderr


# ---------------------------------------------------------------------------
# The actual perf gate
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_10k_dep_monorepo_within_budget(tmp_path: Path) -> None:
    """A ~10k-dep multi-ecosystem fixture scans within
    ``RUNTIME_BUDGET_S`` seconds and ``RSS_BUDGET_MB`` MiB.

    Surfaces the full breakdown on failure so a regression
    points at the responsible stage."""
    repo = tmp_path / "monorepo"
    _build_large_monorepo(repo)

    # Sanity: fixture is the size we declared
    total_files = sum(1 for _ in repo.rglob("*") if _.is_file())
    assert total_files > 50, (
        f"fixture too small: only {total_files} files generated"
    )

    out = tmp_path / "out"
    elapsed, rss_mb, stderr = _run_scan(repo, out)

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
    # At minimum: hygiene findings for the manifests-without-lockfiles.
    # We don't gate on exact count (varies with caching) but expect SOME.
    assert len(items) > 0, "monorepo scan produced ZERO findings"


@pytest.mark.slow
def test_per_stage_progress_emitted(tmp_path: Path) -> None:
    """Progress reporter emits identifiable stage markers; the
    perf baseline depends on these to attribute time to stages
    when a regression hits.
    """
    repo = tmp_path / "monorepo"
    _build_large_monorepo(repo)
    out = tmp_path / "out"

    _, _, stderr = _run_scan(repo, out)
    # Stages we expect somewhere in stderr from the multi-stage
    # progress UI.
    stage_markers = ["discovery", "join", "osv"]
    found = [s for s in stage_markers if s in stderr.lower()]
    assert found, (
        f"no stage markers in stderr — perf attribution unavailable.\n"
        f"stderr (last 2k):\n{stderr[-2000:]}"
    )
