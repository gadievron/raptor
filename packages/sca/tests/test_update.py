"""Tests for ``packages.sca.update`` (the ``raptor-sca fix --cve-only`` subcommand)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

import pytest

from packages.sca import update


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _vuln_row(
    *,
    ecosystem: str,
    name: str,
    version: str,
    fixed_version: str | None,
    manifest: Path,
    advisory_id: str = "GHSA-x",
    pin_style: str = "exact",
    aliases: List[str] | None = None,
) -> dict:
    return {
        "id": f"sca:vuln:{ecosystem}:{name}:{version}:{advisory_id}",
        "vuln_type": "sca:vulnerable_dependency",
        "tool": "sca",
        "file": str(manifest),
        "function": name,
        "line": 0,
        "severity": "high",
        "description": f"{name}@{version} test",
        "sca": {
            "ecosystem": ecosystem,
            "name": name,
            "version": version,
            "purl": f"pkg:{ecosystem.lower()}/{name}@{version}",
            "pin_style": pin_style,
            "fixed_version": fixed_version,
            "advisory": {
                "id": advisory_id,
                "aliases": aliases or [],
                "summary": "test",
                "fixed_versions": [fixed_version] if fixed_version else [],
                "references": [],
                "severity": None,
            },
            "all_advisories": [],
            "in_kev": False,
            "epss": None,
            "reachability": {"verdict": "imported",
                             "confidence": {"level": "high",
                                            "numeric": 0.95, "reason": "t"},
                             "evidence": []},
            "cvss_score": 7.5,
            "cvss_vector": None,
            "version_match_confidence": {"level": "high", "numeric": 0.95,
                                         "reason": "t"},
            "parser_confidence": {"level": "high", "numeric": 0.95,
                                  "reason": "t"},
            "exposure_factor": 0.0,
            "transitive_depth": 0,
            "related_findings": [],
        },
    }


def _findings_file(tmp_path: Path, rows: list) -> Path:
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(rows), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# pom.xml rewriter
# ---------------------------------------------------------------------------

def test_pom_xml_rewrite_bumps_version(tmp_path: Path) -> None:
    pom = tmp_path / "pom.xml"
    pom.write_text("""\
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>
""", encoding="utf-8")
    findings = _findings_file(tmp_path, [_vuln_row(
        ecosystem="Maven",
        name="org.apache.logging.log4j:log4j-core",
        version="2.14.1", fixed_version="2.17.1",
        manifest=pom,
    )])
    out = tmp_path / "out"
    rc = update.main([
        "--findings", str(findings), "--out", str(out), "--allow-major",
    ])
    assert rc == 0
    # Find the proposed file by walking the tree (path layout depends on cwd).
    found = list((out / "proposed").rglob("pom.xml"))
    assert len(found) == 1
    body = found[0].read_text()
    assert "<version>2.17.1</version>" in body
    assert "<version>2.14.1</version>" not in body
    changes = json.loads((out / "changes.json").read_text())
    assert changes[0]["new_version"] == "2.17.1"


def test_pom_xml_with_property_reference_skipped(tmp_path: Path) -> None:
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
        ecosystem="Maven",
        name="org.apache.logging.log4j:log4j-core",
        version="2.14.1", fixed_version="2.17.1",
        manifest=pom,
    )])
    out = tmp_path / "out"
    update.main(["--findings", str(findings), "--out", str(out), "--allow-major"])
    changes = json.loads((out / "changes.json").read_text())
    assert changes[0]["skipped_reason"] is not None
    assert "property reference" in changes[0]["skipped_reason"]


# ---------------------------------------------------------------------------
# package.json rewriter
# ---------------------------------------------------------------------------

def test_package_json_caret_preserved(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "demo",
        "dependencies": {"lodash": "^4.17.4"},
    }, indent=2), encoding="utf-8")
    findings = _findings_file(tmp_path, [_vuln_row(
        ecosystem="npm", name="lodash",
        version="4.17.4", fixed_version="4.17.21",
        manifest=pkg, pin_style="caret",
    )])
    out = tmp_path / "out"
    update.main(["--findings", str(findings), "--out", str(out)])
    proposed = list((out / "proposed").rglob("package.json"))[0]
    obj = json.loads(proposed.read_text())
    assert obj["dependencies"]["lodash"] == "^4.17.21"


def test_package_json_exact_pin_replaced(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "demo",
        "dependencies": {"lodash": "4.17.4"},
    }, indent=2), encoding="utf-8")
    findings = _findings_file(tmp_path, [_vuln_row(
        ecosystem="npm", name="lodash",
        version="4.17.4", fixed_version="4.17.21",
        manifest=pkg,
    )])
    out = tmp_path / "out"
    update.main(["--findings", str(findings), "--out", str(out)])
    proposed = list((out / "proposed").rglob("package.json"))[0]
    assert json.loads(proposed.read_text())["dependencies"]["lodash"] == "4.17.21"


def test_package_json_git_url_skipped(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "dependencies": {"lodash": "git+https://github.com/lodash/lodash.git#v4.17.4"},
    }), encoding="utf-8")
    findings = _findings_file(tmp_path, [_vuln_row(
        ecosystem="npm", name="lodash",
        version="4.17.4", fixed_version="4.17.21",
        manifest=pkg,
    )])
    out = tmp_path / "out"
    update.main(["--findings", str(findings), "--out", str(out)])
    changes = json.loads((out / "changes.json").read_text())
    assert changes[0]["skipped_reason"] is not None


# ---------------------------------------------------------------------------
# requirements.txt rewriter
# ---------------------------------------------------------------------------

def test_requirements_txt_rewrite(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("# pinned\ndjango==4.2.7\nrequests>=2.31.0\n", encoding="utf-8")
    findings = _findings_file(tmp_path, [_vuln_row(
        ecosystem="PyPI", name="django",
        version="4.2.7", fixed_version="4.2.10",
        manifest=req,
    )])
    out = tmp_path / "out"
    update.main(["--findings", str(findings), "--out", str(out)])
    proposed = list((out / "proposed").rglob("requirements.txt"))[0]
    body = proposed.read_text()
    assert "django==4.2.10" in body
    # Untouched line preserved.
    assert "requests>=2.31.0" in body
    assert "# pinned" in body


def test_requirements_txt_pep503_normalisation(tmp_path: Path) -> None:
    """``Foo_Bar.Baz`` in the manifest should match the PEP 503 form
    ``foo-bar-baz`` carried in findings."""
    req = tmp_path / "requirements.txt"
    req.write_text("Foo_Bar.Baz==1.0.0\n", encoding="utf-8")
    findings = _findings_file(tmp_path, [_vuln_row(
        ecosystem="PyPI", name="foo-bar-baz",
        version="1.0.0", fixed_version="1.0.1",
        manifest=req,
    )])
    out = tmp_path / "out"
    update.main(["--findings", str(findings), "--out", str(out)])
    proposed = list((out / "proposed").rglob("requirements.txt"))[0]
    assert "==1.0.1" in proposed.read_text()


# ---------------------------------------------------------------------------
# pyproject.toml rewriter
# ---------------------------------------------------------------------------

def test_pyproject_toml_pep621_rewrite(tmp_path: Path) -> None:
    py = tmp_path / "pyproject.toml"
    py.write_text("""\
[project]
dependencies = [
  "django==4.2.7",
  "requests~=2.31.0",
]
""", encoding="utf-8")
    findings = _findings_file(tmp_path, [_vuln_row(
        ecosystem="PyPI", name="django",
        version="4.2.7", fixed_version="4.2.10",
        manifest=py,
    )])
    out = tmp_path / "out"
    update.main(["--findings", str(findings), "--out", str(out)])
    proposed = list((out / "proposed").rglob("pyproject.toml"))[0]
    body = proposed.read_text()
    assert '"django==4.2.10"' in body
    assert '"requests~=2.31.0"' in body


def test_pyproject_toml_poetry_caret_preserved(tmp_path: Path) -> None:
    py = tmp_path / "pyproject.toml"
    py.write_text("""\
[tool.poetry.dependencies]
python = "^3.10"
django = "^4.2.7"
""", encoding="utf-8")
    findings = _findings_file(tmp_path, [_vuln_row(
        ecosystem="PyPI", name="django",
        version="4.2.7", fixed_version="4.2.10",
        manifest=py,
    )])
    out = tmp_path / "out"
    update.main(["--findings", str(findings), "--out", str(out)])
    proposed = list((out / "proposed").rglob("pyproject.toml"))[0]
    body = proposed.read_text()
    assert 'django = "^4.2.10"' in body
    assert 'python = "^3.10"' in body


# ---------------------------------------------------------------------------
# Mode flags
# ---------------------------------------------------------------------------

def test_fix_filter_restricts_to_listed_advisories(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "dependencies": {"a": "1.0.0", "b": "2.0.0"},
    }), encoding="utf-8")
    findings = _findings_file(tmp_path, [
        _vuln_row(ecosystem="npm", name="a", version="1.0.0",
                  fixed_version="1.5.0", manifest=pkg,
                  advisory_id="GHSA-keep"),
        _vuln_row(ecosystem="npm", name="b", version="2.0.0",
                  fixed_version="2.5.0", manifest=pkg,
                  advisory_id="GHSA-skip"),
    ])
    out = tmp_path / "out"
    update.main([
        "--findings", str(findings),
        "--out", str(out),
        "--fix", "GHSA-keep",
    ])
    changes = json.loads((out / "changes.json").read_text())
    names = {c["name"] for c in changes}
    assert names == {"a"}


def test_minimal_picks_max_fix_across_findings(tmp_path: Path) -> None:
    """Two CVEs against the same dep with fixes 1.5 and 1.10 — the
    proposed bump must be 1.10."""
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"dependencies": {"x": "1.0.0"}}),
                   encoding="utf-8")
    findings = _findings_file(tmp_path, [
        _vuln_row(ecosystem="npm", name="x", version="1.0.0",
                  fixed_version="1.5.0", manifest=pkg,
                  advisory_id="GHSA-1"),
        _vuln_row(ecosystem="npm", name="x", version="1.0.0",
                  fixed_version="1.10.0", manifest=pkg,
                  advisory_id="GHSA-2"),
    ])
    out = tmp_path / "out"
    update.main(["--findings", str(findings), "--out", str(out)])
    proposed = list((out / "proposed").rglob("package.json"))[0]
    assert json.loads(proposed.read_text())["dependencies"]["x"] == "1.10.0"


def test_allow_major_gates_cross_major_upgrade(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"dependencies": {"x": "1.0.0"}}),
                   encoding="utf-8")
    findings = _findings_file(tmp_path, [_vuln_row(
        ecosystem="npm", name="x", version="1.0.0",
        fixed_version="2.0.0", manifest=pkg,
    )])
    out_no_major = tmp_path / "out_no_major"
    rc = update.main([
        "--findings", str(findings), "--out", str(out_no_major),
    ])
    # No proposed file because the only fix crosses a major boundary
    # and --allow-major wasn't supplied.
    assert rc == 0
    assert not (out_no_major / "proposed").exists()

    out_allow = tmp_path / "out_allow"
    update.main([
        "--findings", str(findings), "--out", str(out_allow),
        "--allow-major",
    ])
    proposed = list((out_allow / "proposed").rglob("package.json"))[0]
    assert json.loads(proposed.read_text())["dependencies"]["x"] == "2.0.0"


def test_pin_only_skips_loose_pins(tmp_path: Path) -> None:
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "dependencies": {"x": "^1.0.0", "y": "1.0.0"},
    }), encoding="utf-8")
    findings = _findings_file(tmp_path, [
        _vuln_row(ecosystem="npm", name="x", version="1.0.0",
                  fixed_version="1.5.0", manifest=pkg, pin_style="caret"),
        _vuln_row(ecosystem="npm", name="y", version="1.0.0",
                  fixed_version="1.5.0", manifest=pkg, pin_style="exact"),
    ])
    out = tmp_path / "out"
    update.main(["--findings", str(findings), "--out", str(out),
                 "--pin-only"])
    changes = {c["name"]: c for c in json.loads(
        (out / "changes.json").read_text(),
    )}
    assert changes["y"]["skipped_reason"] is None
    assert changes["x"]["skipped_reason"] is not None
    assert "pin-only" in changes["x"]["skipped_reason"]


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

def test_neither_findings_nor_target_returns_2(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        update.main(["--out", str(tmp_path / "out")])
    assert exc.value.code == 2


def test_findings_missing_returns_2(tmp_path: Path) -> None:
    rc = update.main(["--findings", str(tmp_path / "nope.json"),
                      "--out", str(tmp_path / "out")])
    assert rc == 2


# ---------------------------------------------------------------------------
# api-compat risk surfacing
# ---------------------------------------------------------------------------

def test_changes_json_carries_compat_risks_for_major_bump(
    tmp_path: Path,
) -> None:
    """A 3.x → 4.x bump is semver-major; the compat heuristic must fire
    and the JSON output must carry the structured ``compat_risks``
    entries so downstream consumers (LLM review, PR commenter, CI gate)
    can read them."""
    req = tmp_path / "requirements.txt"
    req.write_text("django==3.2.0\n", encoding="utf-8")
    findings = _findings_file(tmp_path, [_vuln_row(
        ecosystem="PyPI", name="django",
        version="3.2.0", fixed_version="4.0.0",
        manifest=req,
    )])
    out = tmp_path / "out"
    # ``--allow-major`` because the upgrade crosses 3 → 4; ``--offline``
    # to keep the test hermetic — semver risk fires from version
    # strings alone, no PyPI roundtrip needed.
    update.main([
        "--findings", str(findings), "--out", str(out),
        "--allow-major", "--offline",
    ])
    changes = json.loads((out / "changes.json").read_text())
    assert len(changes) == 1
    assert "compat_risks" in changes[0]
    risks = changes[0]["compat_risks"]
    assert any(r["kind"] == "semver_major" and r["severity"] == "high"
               for r in risks)
    assert changes[0]["compat_overall_severity"] == "high"


def test_changes_md_compat_column_and_detail_block(
    tmp_path: Path,
) -> None:
    """The markdown rendering must surface a Compat column AND a detail
    block when any change has non-empty risks."""
    req = tmp_path / "requirements.txt"
    req.write_text("django==3.2.0\n", encoding="utf-8")
    findings = _findings_file(tmp_path, [_vuln_row(
        ecosystem="PyPI", name="django",
        version="3.2.0", fixed_version="4.0.0",
        manifest=req,
    )])
    out = tmp_path / "out"
    update.main([
        "--findings", str(findings), "--out", str(out),
        "--allow-major", "--offline",
    ])
    md = (out / "changes.md").read_text()
    assert "| Compat |" in md
    assert "**high**" in md
    assert "Upgrade-compat risk detail" in md
    assert "semver-major" in md


def test_changes_no_compat_column_value_for_clean_minor_bump(
    tmp_path: Path,
) -> None:
    """When a minor-bump upgrade has no risks, the Compat cell is "—"
    and no detail block is emitted."""
    req = tmp_path / "requirements.txt"
    req.write_text("django==4.2.7\n", encoding="utf-8")
    findings = _findings_file(tmp_path, [_vuln_row(
        ecosystem="PyPI", name="django",
        version="4.2.7", fixed_version="4.2.10",
        manifest=req,
    )])
    out = tmp_path / "out"
    update.main([
        "--findings", str(findings), "--out", str(out), "--offline",
    ])
    changes = json.loads((out / "changes.json").read_text())
    # No compat risks → compat_risks key absent.
    assert "compat_risks" not in changes[0]
    md = (out / "changes.md").read_text()
    assert "| — |" in md
    assert "Upgrade-compat risk detail" not in md


def test_offline_and_allow_cascade_are_mutually_exclusive(
    tmp_path: Path, capsys: pytest.CaptureFixture,
) -> None:
    """``--offline --allow-cascade`` is operator confusion: the cascade
    resolver shells out to npm/pip/go which all need network. Reject
    at argparse time so the operator sees a clear message instead of
    a confusing resolver-can't-reach-registry failure deep in the run.
    """
    findings = tmp_path / "findings.json"
    findings.write_text("[]", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        update.main([
            "--findings", str(findings),
            "--out", str(tmp_path / "out"),
            "--offline", "--allow-cascade",
        ])
    assert exc.value.code == 2     # argparse error exit
    err = capsys.readouterr().err
    assert "mutually exclusive" in err
    assert "--offline" in err and "--allow-cascade" in err


# ---------------------------------------------------------------------------
# Cascade validation (parallel per-ecosystem dispatch)
# ---------------------------------------------------------------------------


class _StubResolver:
    """Minimal Resolver stub for cascade tests.

    ``available`` / ``success`` / ``error`` / ``proposed_lockfile``
    drive the verdict. ``barrier`` (when supplied) lets multiple
    threads synchronise so we can verify the resolvers actually run
    concurrently.
    """

    def __init__(
        self, *, available=True, success=True, error=None,
        proposed_lockfile=None, barrier=None,
    ):
        self._available = available
        self._success = success
        self._error = error
        self._lockfile = proposed_lockfile
        self._barrier = barrier
        self.dry_run_calls = []

    def is_available(self):
        return self._available

    def dry_run(self, project_dir, *, timeout=120):
        if self._barrier is not None:
            # Block until all threads reach this point — proves
            # concurrent execution.
            self._barrier.wait(timeout=5)
        self.dry_run_calls.append(project_dir)
        # Build a fake ResolverResult — duck-typed to what
        # _validate_one_ecosystem reads.
        from packages.sca.resolvers import ResolverResult
        return ResolverResult(
            ecosystem="stub",
            success=self._success,
            available=self._available,
            error=self._error,
            proposed_lockfile=self._lockfile,
        )


def _make_proposed(tmp_path: Path, eco_to_files: dict) -> Path:
    """Build a tmp_path/out/proposed/ tree mirroring the CWD-relative
    layout the cascade expects."""
    out = tmp_path / "out"
    proposed = out / "proposed"
    proposed.mkdir(parents=True, exist_ok=True)
    for eco_path, content in eco_to_files.items():
        target = proposed / eco_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return out


def _make_change(
    *, ecosystem: str, name: str = "pkg", manifest: Path,
) -> "update.UpgradeChange":
    return update.UpgradeChange(
        ecosystem=ecosystem, name=name,
        old_version="1.0.0", new_version="1.0.1",
        manifest=manifest,
        advisory_ids=("GHSA-x",),
    )


def test_cascade_parallel_runs_resolver_per_ecosystem(
    tmp_path: Path, monkeypatch,
) -> None:
    """All ecosystems get their resolver invoked. Result count
    matches input ecosystem count."""
    cwd = Path.cwd()
    out = _make_proposed(tmp_path, {})

    npm_resolver = _StubResolver()
    pypi_resolver = _StubResolver()
    go_resolver = _StubResolver()

    def fake_get_resolver(eco, *, project_dir):
        return {
            "npm": npm_resolver,
            "PyPI": pypi_resolver,
            "Go": go_resolver,
        }.get(eco)

    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver", fake_get_resolver,
    )

    applied = [
        _make_change(ecosystem="npm", manifest=cwd / "package.json"),
        _make_change(ecosystem="PyPI", manifest=cwd / "requirements.txt"),
        _make_change(ecosystem="Go", manifest=cwd / "go.mod"),
    ]
    update._run_cascade_validation(applied, out)

    cascade = json.loads((out / "cascade.json").read_text())
    assert len(cascade) == 3
    ecos = {row["ecosystem"] for row in cascade}
    assert ecos == {"npm", "PyPI", "Go"}
    # Each resolver got exactly one dry_run call.
    assert len(npm_resolver.dry_run_calls) == 1
    assert len(pypi_resolver.dry_run_calls) == 1
    assert len(go_resolver.dry_run_calls) == 1


def test_cascade_resolver_crash_isolates_to_one_ecosystem(
    tmp_path: Path, monkeypatch,
) -> None:
    """A resolver subprocess that raises rather than returning a
    result fails just THAT ecosystem with verdict='error'; other
    ecosystems still report cleanly."""
    cwd = Path.cwd()
    out = _make_proposed(tmp_path, {})

    class _CrashingResolver(_StubResolver):
        def dry_run(self, project_dir, *, timeout=120):
            raise RuntimeError("simulated crash")

    crashing = _CrashingResolver()
    healthy = _StubResolver()

    def fake_get_resolver(eco, *, project_dir):
        return {"npm": crashing, "PyPI": healthy}.get(eco)

    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver", fake_get_resolver,
    )

    applied = [
        _make_change(ecosystem="npm", manifest=cwd / "package.json"),
        _make_change(ecosystem="PyPI", manifest=cwd / "requirements.txt"),
    ]
    update._run_cascade_validation(applied, out)
    cascade = json.loads((out / "cascade.json").read_text())
    rows = {r["ecosystem"]: r for r in cascade}
    assert rows["npm"]["verdict"] == "error"
    assert "simulated crash" in rows["npm"]["reason"]
    assert rows["PyPI"]["verdict"] == "ok"


def test_cascade_unsupported_and_skipped_verdicts(
    tmp_path: Path, monkeypatch,
) -> None:
    """No resolver registered → unsupported. Resolver present but
    tool not in PATH → skipped."""
    cwd = Path.cwd()
    out = _make_proposed(tmp_path, {})

    unavailable_resolver = _StubResolver(available=False)

    def fake_get_resolver(eco, *, project_dir):
        if eco == "Maven":
            return None       # unsupported
        if eco == "PyPI":
            return unavailable_resolver
        return None

    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver", fake_get_resolver,
    )

    applied = [
        _make_change(ecosystem="Maven", manifest=cwd / "pom.xml"),
        _make_change(ecosystem="PyPI", manifest=cwd / "requirements.txt"),
    ]
    update._run_cascade_validation(applied, out)
    cascade = json.loads((out / "cascade.json").read_text())
    rows = {r["ecosystem"]: r for r in cascade}
    assert rows["Maven"]["verdict"] == "unsupported"
    assert rows["PyPI"]["verdict"] == "skipped"
    assert "PATH" in rows["PyPI"]["reason"]


def test_cascade_lockfile_capture(
    tmp_path: Path, monkeypatch,
) -> None:
    """When a resolver returns a proposed_lockfile, it gets written
    under cascade-<eco>.lock with the right contents."""
    cwd = Path.cwd()
    out = _make_proposed(tmp_path, {})

    resolver = _StubResolver(proposed_lockfile=b"lockfile-bytes")

    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver",
        lambda eco, *, project_dir: resolver,
    )

    applied = [
        _make_change(ecosystem="npm", manifest=cwd / "package.json"),
    ]
    update._run_cascade_validation(applied, out)
    lockfile_path = out / "cascade-npm.lock"
    assert lockfile_path.exists()
    assert lockfile_path.read_bytes() == b"lockfile-bytes"


def test_cascade_preserves_input_order_in_summary(
    tmp_path: Path, monkeypatch,
) -> None:
    """cascade.json rows come back in the same ecosystem order as
    by_eco's keys (which preserve insertion order from ``applied``).
    Important so diffs against the previous sequential implementation
    are deterministic."""
    cwd = Path.cwd()
    out = _make_proposed(tmp_path, {})

    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver",
        lambda eco, *, project_dir: _StubResolver(),
    )

    applied = [
        _make_change(ecosystem="Go", manifest=cwd / "go.mod"),
        _make_change(ecosystem="npm", manifest=cwd / "package.json"),
        _make_change(ecosystem="PyPI", manifest=cwd / "requirements.txt"),
    ]
    update._run_cascade_validation(applied, out)
    cascade = json.loads((out / "cascade.json").read_text())
    assert [row["ecosystem"] for row in cascade] == ["Go", "npm", "PyPI"]


def test_cascade_threads_run_concurrently(
    tmp_path: Path, monkeypatch,
) -> None:
    """Three resolvers all rendezvous at a barrier — proves the
    thread pool genuinely runs them in parallel rather than
    serialising."""
    import threading
    cwd = Path.cwd()
    out = _make_proposed(tmp_path, {})

    barrier = threading.Barrier(3, timeout=5)
    resolvers = [_StubResolver(barrier=barrier) for _ in range(3)]

    def fake_get_resolver(eco, *, project_dir):
        return {
            "npm": resolvers[0],
            "PyPI": resolvers[1],
            "Go": resolvers[2],
        }.get(eco)

    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver", fake_get_resolver,
    )

    applied = [
        _make_change(ecosystem="npm", manifest=cwd / "package.json"),
        _make_change(ecosystem="PyPI", manifest=cwd / "requirements.txt"),
        _make_change(ecosystem="Go", manifest=cwd / "go.mod"),
    ]
    # If the implementation were sequential, the barrier would never
    # release (only one thread ever arrives at a time), and dry_run
    # would raise BrokenBarrierError on timeout. Successful
    # completion proves concurrent execution.
    update._run_cascade_validation(applied, out)
    cascade = json.loads((out / "cascade.json").read_text())
    assert len(cascade) == 3
    assert all(r["verdict"] == "ok" for r in cascade)


def test_cascade_empty_applied_no_op(
    tmp_path: Path, monkeypatch,
) -> None:
    """Defensive: empty input → empty cascade.json, no exceptions."""
    out = _make_proposed(tmp_path, {})
    monkeypatch.setattr(
        "packages.sca.resolvers.get_resolver",
        lambda eco, *, project_dir: _StubResolver(),
    )
    update._run_cascade_validation([], out)
    cascade = json.loads((out / "cascade.json").read_text())
    assert cascade == []
