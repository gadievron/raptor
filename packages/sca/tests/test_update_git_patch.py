"""Tests for ``raptor-sca fix --cve-only --git-patch``: emit a git-apply-compatible
unified diff alongside ``proposed/``."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from packages.sca import update


def _vuln_row(*, manifest: Path, name: str, eco: str,
              version: str, fix: str,
              advisory_id: str = "GHSA-x",
              pin_style: str = "exact") -> dict:
    return {
        "id": f"sca:vuln:{eco}:{name}:{version}:{advisory_id}",
        "vuln_type": "sca:vulnerable_dependency",
        "tool": "sca",
        "file": str(manifest),
        "function": name,
        "line": 0,
        "severity": "high",
        "description": "test",
        "sca": {
            "ecosystem": eco, "name": name, "version": version,
            "purl": f"pkg:{eco.lower()}/{name}@{version}",
            "pin_style": pin_style,
            "fixed_version": fix,
            "advisory": {"id": advisory_id, "aliases": [],
                          "summary": "t", "fixed_versions": [fix],
                          "references": [], "severity": None},
            "all_advisories": [], "in_kev": False, "epss": None,
            "reachability": {"verdict": "imported",
                              "confidence": {"level": "high", "numeric": 0.95,
                                             "reason": "t"},
                              "evidence": []},
            "cvss_score": 7.5, "cvss_vector": None,
            "version_match_confidence": {"level": "high", "numeric": 0.95,
                                          "reason": "t"},
            "parser_confidence": {"level": "high", "numeric": 0.95,
                                   "reason": "t"},
            "exposure_factor": 0.0, "transitive_depth": 0,
            "related_findings": [],
        },
    }


def _findings_file(tmp_path: Path, rows: list) -> Path:
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(rows), encoding="utf-8")
    return p


def test_git_patch_written_alongside_proposed(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    (target / "service").mkdir(parents=True)
    pom = target / "service" / "pom.xml"
    pom.write_text("""\
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies><dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version>
  </dependency></dependencies>
</project>
""", encoding="utf-8")

    findings = _findings_file(tmp_path, [_vuln_row(
        manifest=pom,
        eco="Maven",
        name="org.apache.logging.log4j:log4j-core",
        version="2.14.1", fix="2.17.1",
    )])
    out = tmp_path / "out"
    rc = update.main([
        "--findings", str(findings),
        "--out", str(out),
        "--allow-major",
        "--git-patch",
    ])
    assert rc == 0
    patch = out / "upgrade.patch"
    assert patch.exists(), "upgrade.patch should land alongside proposed/"
    body = patch.read_text()
    # Standard git-apply-friendly headers.
    assert "diff --git " in body
    assert "+++ b/" in body
    # Old version removed, new version added.
    assert "<version>2.14.1</version>" in body
    assert "<version>2.17.1</version>" in body
    # The patch body has the old line as a deletion and the new as
    # an addition.
    assert any(line.startswith("-") and "2.14.1" in line
               for line in body.splitlines())
    assert any(line.startswith("+") and "2.17.1" in line
               for line in body.splitlines())


def test_git_apply_actually_applies(tmp_path: Path) -> None:
    """End-to-end: init a git repo, generate the patch from inside it,
    apply with real `git apply`, verify the file is upgraded."""
    if shutil.which("git") is None:
        import pytest
        pytest.skip("git not on PATH")
    target = tmp_path / "repo"
    (target / "frontend").mkdir(parents=True)
    pkg = target / "frontend" / "package.json"
    pkg.write_text(json.dumps(
        {"name": "demo", "dependencies": {"lodash": "^4.17.4"}},
        indent=2,
    ) + "\n", encoding="utf-8")
    # Init git inside the target so _find_repo_root picks it up.
    subprocess.run(["git", "init", "-q", str(target)], check=True)
    subprocess.run(["git", "-C", str(target), "add", "."], check=True)
    subprocess.run(["git", "-C", str(target), "-c", "user.email=t",
                    "-c", "user.name=t", "commit", "-q", "-m", "base"],
                   check=True)

    findings = _findings_file(tmp_path, [_vuln_row(
        manifest=pkg, eco="npm", name="lodash",
        version="4.17.4", fix="4.17.21", pin_style="caret",
    )])
    out = tmp_path / "out"
    update.main([
        "--findings", str(findings),
        "--out", str(out),
        "--git-patch",
    ])
    patch = out / "upgrade.patch"
    assert patch.exists()
    # Patch path should be repo-rooted: ``frontend/package.json``.
    body = patch.read_text()
    assert "diff --git a/frontend/package.json b/frontend/package.json" in body

    rc = subprocess.run(
        ["git", "-C", str(target), "apply", str(patch)],
        check=False, capture_output=True, text=True,
    )
    assert rc.returncode == 0, (
        f"patch should apply cleanly: {rc.stdout}{rc.stderr}\n"
        f"patch:\n{body}"
    )
    after = json.loads(pkg.read_text())
    assert after["dependencies"]["lodash"] == "^4.17.21"


def test_git_patch_skipped_when_no_changes_applied(tmp_path: Path) -> None:
    """No applied changes (every plan got skipped) → no upgrade.patch."""
    # The dep uses a property reference (Maven case), which the
    # rewriter skips. Use a Maven manifest to force a skipped plan.
    pom = tmp_path / "pom.xml"
    pom.write_text("""\
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties><log4j.version>2.14.1</log4j.version></properties>
  <dependencies><dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>${log4j.version}</version>
  </dependency></dependencies>
</project>
""", encoding="utf-8")
    findings = _findings_file(tmp_path, [_vuln_row(
        manifest=pom,
        eco="Maven",
        name="org.apache.logging.log4j:log4j-core",
        version="2.14.1", fix="2.17.1",
    )])
    out = tmp_path / "out"
    update.main([
        "--findings", str(findings),
        "--out", str(out),
        "--allow-major",
        "--git-patch",
    ])
    assert not (out / "upgrade.patch").exists()


def test_no_git_patch_flag_means_no_patch(tmp_path: Path) -> None:
    pom = tmp_path / "pom.xml"
    pom.write_text("""\
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies><dependency>
    <groupId>g</groupId><artifactId>a</artifactId><version>1.0</version>
  </dependency></dependencies>
</project>
""", encoding="utf-8")
    findings = _findings_file(tmp_path, [_vuln_row(
        manifest=pom, eco="Maven", name="g:a", version="1.0", fix="1.5",
    )])
    out = tmp_path / "out"
    update.main([
        "--findings", str(findings), "--out", str(out),
    ])
    assert not (out / "upgrade.patch").exists()
