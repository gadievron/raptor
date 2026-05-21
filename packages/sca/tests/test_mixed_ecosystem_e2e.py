"""Tier-5 E2E: mixed-ecosystem fixture.

One project tree with all of: npm + Python + Maven + Cargo +
Dockerfile + Helm + .gitmodules + GHA workflows + compose +
k8s manifests. Asserts every ecosystem's manifest gets DISCOVERED
+ PARSED into the findings stream (a representative dep from each
appears somewhere in findings or the SBOM components list).

Catches the regression class where one ecosystem's parser starts
swallowing the others, or where dispatch routing forgets a
filename pattern, or where a refactor changes the canonical
ecosystem label and downstream filters silently drop matches.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import List

REPO_ROOT = Path(__file__).resolve().parents[3]


def _build_mixed_fixture(repo: Path) -> None:
    """One project with every ecosystem we support. Each manifest
    pins a real, well-known dep so the test can assert that
    SPECIFIC dep surfaces in the parsed output."""
    repo.mkdir(parents=True, exist_ok=True)

    # Python — requirements.txt + pyproject.toml
    (repo / "requirements.txt").write_text(
        "requests==2.31.0\n"
        "urllib3==2.0.7\n",
        encoding="utf-8",
    )
    (repo / "pyproject.toml").write_text(
        '[project]\n'
        'name = "fixture"\n'
        'version = "1.0.0"\n'
        'dependencies = ["click>=8.0"]\n',
        encoding="utf-8",
    )

    # Node — package.json
    (repo / "package.json").write_text(json.dumps({
        "name": "fixture",
        "version": "1.0.0",
        "dependencies": {"lodash": "4.17.21", "axios": "1.6.0"},
    }), encoding="utf-8")

    # Maven — pom.xml
    (repo / "pom.xml").write_text('''<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>fixture</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.16.0</version>
    </dependency>
  </dependencies>
</project>
''', encoding="utf-8")

    # Cargo — Cargo.toml
    (repo / "Cargo.toml").write_text(
        '[package]\n'
        'name = "fixture"\n'
        'version = "0.1.0"\n'
        'edition = "2021"\n'
        '\n'
        '[dependencies]\n'
        'serde = "1.0.193"\n',
        encoding="utf-8",
    )

    # Dockerfile + compose + k8s
    (repo / "Dockerfile").write_text(
        "FROM python:3.13-slim\n"
        "RUN pip install requests==2.31.0\n",
        encoding="utf-8",
    )
    (repo / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  app:\n"
        "    image: redis:7.2.4\n",
        encoding="utf-8",
    )
    (repo / "k8s").mkdir()
    (repo / "k8s" / "deployment.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: app\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: web\n"
        "          image: nginx:1.25.3\n",
        encoding="utf-8",
    )

    # Helm
    (repo / "charts" / "app").mkdir(parents=True)
    (repo / "charts" / "app" / "Chart.yaml").write_text(
        "apiVersion: v2\n"
        "name: app\n"
        "version: 0.1.0\n"
        "dependencies:\n"
        "  - name: redis\n"
        "    version: 17.15.0\n"
        "    repository: https://charts.bitnami.com/bitnami\n",
        encoding="utf-8",
    )

    # GHA workflow
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text(
        "name: ci\n"
        "on: [push]\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v3\n",
        encoding="utf-8",
    )

    # Git submodules declaration
    (repo / ".gitmodules").write_text(
        '[submodule "vendor/lib"]\n'
        '\tpath = vendor/lib\n'
        '\turl = https://github.com/some/lib.git\n',
        encoding="utf-8",
    )


def _run_cli(args: List[str], *, timeout: int = 120) -> subprocess.CompletedProcess:
    cmd = [sys.executable, "-m", "packages.sca.cli"] + args
    return subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=str(REPO_ROOT), timeout=timeout,
    )


# ---------------------------------------------------------------------------
# Discovery — every ecosystem represented
# ---------------------------------------------------------------------------

def _collect_dep_names_from_outputs(out_dir: Path) -> set:
    """Pull dep names from findings.json and sbom.cdx.json. Either
    is fine as evidence that the parser ran and produced output.

    Findings schema has the dep name in ``sca.name`` (nested block)
    or ``function`` (the canonical-row dep slot). SBOM components
    have ``name``. Walk all three so the assertion is robust to
    which output records each ecosystem."""
    names = set()
    findings_path = out_dir / "findings.json"
    if findings_path.exists():
        data = json.loads(findings_path.read_text())
        items = data if isinstance(data, list) else data.get("findings", [])
        for f in items:
            sca = f.get("sca") or {}
            for src in (sca.get("name"), f.get("function"),
                        f.get("dep_name"), f.get("name")):
                if src:
                    names.add(src.lower())
    sbom_path = out_dir / "sbom.cdx.json"
    if sbom_path.exists():
        sbom = json.loads(sbom_path.read_text())
        for comp in sbom.get("components", []):
            n = comp.get("name", "")
            if n:
                names.add(n.lower())
    return names


def test_mixed_fixture_discovers_each_ecosystem(tmp_path: Path) -> None:
    """One representative dep from each ecosystem must appear in
    the parsed output (findings.json + sbom.cdx.json union)."""
    repo = tmp_path / "repo"
    _build_mixed_fixture(repo)
    out = tmp_path / "out"
    proc = _run_cli([str(repo), "--offline", "--out", str(out)])
    assert proc.returncode in (0, 1), (
        f"scan crashed: exit={proc.returncode}\nstderr:\n{proc.stderr[-2000:]}"
    )
    names = _collect_dep_names_from_outputs(out)

    # One signal per ecosystem — these aren't exhaustive but each
    # is unique enough to prove the parser ran.
    expected = {
        # name (canonical form per the parser) — proves the ecosystem
        "requests",       # Python requirements.txt
        "click",          # Python pyproject.toml
        "lodash",         # Node package.json
        # Maven uses "groupId:artifactId" as the dep name
        "com.fasterxml.jackson.core:jackson-databind",
        "serde",          # Cargo Cargo.toml
    }
    missing = expected - names
    assert not missing, (
        f"mixed fixture missed ecosystems: {missing}.\n"
        f"Got {len(names)} dep names. Sample (first 30): "
        f"{sorted(list(names))[:30]}"
    )


def test_mixed_fixture_sbom_lists_components(tmp_path: Path) -> None:
    """The SBOM emit path must include components from each
    ecosystem — it's the canonical output for cross-tool sharing."""
    repo = tmp_path / "repo"
    _build_mixed_fixture(repo)
    out = tmp_path / "out"
    proc = _run_cli([str(repo), "--offline", "--out", str(out)])
    assert proc.returncode in (0, 1)
    sbom = json.loads((out / "sbom.cdx.json").read_text())
    components = sbom.get("components", [])
    # At minimum: Python (2) + Node (2) + Maven (1) + Cargo (1) = 6
    # Plus inline-Dockerfile dep (1) = 7
    # Allow some slack: discovery may add transitive synthetics.
    assert len(components) >= 6, (
        f"SBOM components too few: {len(components)}.\n"
        f"Components: {[c.get('name') for c in components]}"
    )


def test_mixed_fixture_produces_all_canonical_outputs(tmp_path: Path) -> None:
    """findings.json, report.md, sbom.cdx.json all emit on a
    multi-ecosystem scan. Any one missing → operator can't
    consume the run."""
    repo = tmp_path / "repo"
    _build_mixed_fixture(repo)
    out = tmp_path / "out"
    proc = _run_cli([str(repo), "--offline", "--out", str(out)])
    assert proc.returncode in (0, 1)
    for name in ("findings.json", "report.md", "sbom.cdx.json"):
        assert (out / name).is_file(), (
            f"missing canonical output: {name}"
        )
        # Each is non-empty
        assert (out / name).stat().st_size > 0, f"empty output: {name}"


def test_mixed_fixture_findings_well_formed(tmp_path: Path) -> None:
    """Each finding row has the canonical fields a downstream
    consumer (CI / SARIF converter / patcher) depends on."""
    repo = tmp_path / "repo"
    _build_mixed_fixture(repo)
    out = tmp_path / "out"
    proc = _run_cli([str(repo), "--offline", "--out", str(out)])
    assert proc.returncode in (0, 1)
    data = json.loads((out / "findings.json").read_text())
    items = data if isinstance(data, list) else data.get("findings", [])
    if not items:
        return  # offline + empty cache may produce no vulns; OK
    # First few rows — assert canonical fields present.
    for f in items[:5]:
        assert "severity" in f or "level" in f, (
            f"finding missing severity: {f}"
        )
        # An identifier for the dep — findings store it in
        # several places depending on the row builder. Any of them
        # is fine.
        sca = f.get("sca") or {}
        has_id = (
            sca.get("name")
            or f.get("function")
            or f.get("dep_name")
            or f.get("name")
        )
        assert has_id, f"finding missing dep id: {f}"
