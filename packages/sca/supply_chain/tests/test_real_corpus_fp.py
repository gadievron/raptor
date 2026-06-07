"""End-to-end FP-validation against synthetic-but-realistic clean
package fixtures.

For each ecosystem we ship a minimal source tree mirroring the
shape of a popular real package (clean of attacker patterns).  The
whole-pipeline ``evaluate`` is run and we assert that NO finding
fires from the new Phase 5-8 detectors.

If a fixture starts producing a finding, that's either:
  * a real FP — tighten the relevant detector
  * a real improvement in detection — update the fixture to remove
    the now-detected pattern, since the goal of this suite is to
    validate the QUIET-on-clean axis

Adding fixtures: copy a representative snippet from a popular OSS
package's MAIN branch (do NOT include any vendor-specific real
identifying URLs or private content).  Keep the snippet minimal —
the goal is shape coverage, not full reproductions.
"""

from __future__ import annotations

import json
from pathlib import Path

from packages.sca.models import (
    Confidence,
    Dependency,
    Manifest,
    PinStyle,
)
from packages.sca.supply_chain import evaluate


def _dep(name: str, ecosystem: str, *, declared_in: Path) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version="1.0.0",
        declared_in=declared_in,
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:{ecosystem.lower()}/{name}@1.0.0",
        parser_confidence=Confidence("high", reason="test"),
    )


def _manifest(p: Path, ecosystem: str) -> Manifest:
    return Manifest(path=p, ecosystem=ecosystem, is_lockfile=False)


def _findings_from_new_detectors(findings):
    """Filter findings to the kinds the Phase 5-8 work introduced
    or modified.  Existing-detector findings are out of scope here."""
    new_kinds = {
        "install_hook_suspicious",
        "binary_in_package",
        "gha_secret_flow",
        "commit_provenance_drift",
    }
    return [f for f in findings if f.kind in new_kinds]


# ---------------------------------------------------------------------------
# npm — clean axios-shaped package
# ---------------------------------------------------------------------------

def test_clean_axios_shape_no_high_findings(tmp_path: Path) -> None:
    """Realistic clean npm package: lifecycle hook does ``test`` /
    ``lint``, lib/ has only source, no binaries in tree."""
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "axios-clone",
        "version": "1.0.0",
        "scripts": {
            "test": "jest",
            "build": "rollup -c",
            "prepare": "husky install",
            "lint": "eslint .",
        },
        "dependencies": {"follow-redirects": "^1.15.0"},
    }), encoding="utf-8")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "axios.js").write_text(
        "module.exports = function axios(){}\n", encoding="utf-8",
    )
    manifests = [_manifest(pkg, "npm")]
    deps = [_dep("axios-clone", "npm", declared_in=pkg)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _findings_from_new_detectors(findings)
    high = [f for f in new if f.severity in ("high", "critical")]
    assert not high, (
        f"clean axios-shape fixture must not produce high/critical "
        f"findings; got {[(f.kind, f.severity, f.detail[:80]) for f in high]}"
    )


def test_clean_npm_with_node_gyp_rebuild_no_high(tmp_path: Path) -> None:
    """``node-gyp rebuild`` postinstall is the canonical legitimate
    native-build pattern — must NOT promote to high or worm-shape."""
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "native-pkg",
        "version": "1.0.0",
        "scripts": {"install": "node-gyp rebuild"},
    }), encoding="utf-8")
    # Common native-module layout — prebuilds/<plat>/binding.node
    prebuilds = tmp_path / "prebuilds" / "linux-x64"
    prebuilds.mkdir(parents=True)
    (prebuilds / "binding.node").write_bytes(
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 200,
    )
    manifests = [_manifest(pkg, "npm")]
    deps = [_dep("native-pkg", "npm", declared_in=pkg)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _findings_from_new_detectors(findings)
    high = [f for f in new if f.severity in ("high", "critical")]
    assert not high, (
        f"node-gyp + prebuilds shape must not produce high findings; "
        f"got {[(f.kind, f.severity) for f in high]}"
    )


# ---------------------------------------------------------------------------
# PyPI — clean requests-shaped package
# ---------------------------------------------------------------------------

def test_clean_requests_shape_no_findings(tmp_path: Path) -> None:
    """Clean Python package: pyproject.toml + minimal setup.py
    (legacy compat shim).  setup.py contains no flagged patterns."""
    py = tmp_path / "pyproject.toml"
    py.write_text(
        '[project]\nname = "requests-clone"\nversion = "1.0.0"\n',
        encoding="utf-8",
    )
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        "from setuptools import setup\n"
        "setup()  # everything via pyproject.toml\n",
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "requests").mkdir()
    (tmp_path / "src" / "requests" / "__init__.py").write_text(
        "__version__ = '1.0.0'\n", encoding="utf-8",
    )
    manifests = [_manifest(py, "PyPI")]
    deps = [_dep("requests-clone", "PyPI", declared_in=py)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _findings_from_new_detectors(findings)
    assert not new, (
        f"clean requests-shape fixture must produce no new-detector "
        f"findings; got {[(f.kind, f.severity, f.detail[:80]) for f in new]}"
    )


def test_clean_python_with_realistic_setup_py_no_findings(
    tmp_path: Path,
) -> None:
    """A slightly richer setup.py — reads README, sets long_description,
    finds packages.  No credential or publish patterns."""
    py = tmp_path / "pyproject.toml"
    py.write_text(
        '[project]\nname = "flask-clone"\nversion = "1.0.0"\n',
        encoding="utf-8",
    )
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        '"""flask-clone setup."""\n'
        "from setuptools import setup, find_packages\n"
        "with open('README.md', encoding='utf-8') as f:\n"
        "    long_description = f.read()\n"
        "setup(\n"
        "    name='flask-clone',\n"
        "    version='1.0.0',\n"
        "    packages=find_packages(),\n"
        "    long_description=long_description,\n"
        "    install_requires=['click>=7.0'],\n"
        ")\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("# flask-clone\n", encoding="utf-8")
    manifests = [_manifest(py, "PyPI")]
    deps = [_dep("flask-clone", "PyPI", declared_in=py)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _findings_from_new_detectors(findings)
    assert not new


# ---------------------------------------------------------------------------
# Composer — clean monolog-shaped package
# ---------------------------------------------------------------------------

def test_clean_composer_with_test_script_no_findings(tmp_path: Path) -> None:
    """Realistic composer.json with test/lint scripts and PHPUnit
    invocation.  No shell shapes flagged."""
    cj = tmp_path / "composer.json"
    cj.write_text(json.dumps({
        "name": "vendor/monolog-clone",
        "scripts": {
            "test": "phpunit",
            "phpstan": "phpstan analyse",
            "post-install-cmd": ["@autoload"],
            "post-autoload-dump": [
                "Some\\Vendor\\Class::method",
            ],
        },
    }), encoding="utf-8")
    manifests = [_manifest(cj, "Composer")]
    deps = [_dep("vendor/monolog-clone", "Composer", declared_in=cj)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _findings_from_new_detectors(findings)
    assert not new


# ---------------------------------------------------------------------------
# RubyGems — clean nokogiri-shaped extconf
# ---------------------------------------------------------------------------

def test_clean_rubygems_extconf_no_findings(tmp_path: Path) -> None:
    """Realistic extconf.rb: mkmf platform probes, autoconf-style
    have_header calls, library detection.  No flagged patterns."""
    ext_dir = tmp_path / "ext" / "nokogiri-clone"
    ext_dir.mkdir(parents=True)
    extconf = ext_dir / "extconf.rb"
    extconf.write_text(
        'require "mkmf"\n'
        '\n'
        'have_header("string.h") or abort "string.h missing"\n'
        'have_header("stdlib.h") or abort "stdlib.h missing"\n'
        'have_library("xml2") or abort "libxml2 missing"\n'
        '\n'
        'with_cflags(["-Wall", "-O2"]) do\n'
        '  have_func("xmlParseDoc")\n'
        'end\n'
        '\n'
        'create_makefile("nokogiri_clone")\n',
        encoding="utf-8",
    )
    findings = evaluate(tmp_path, [], [])
    new = _findings_from_new_detectors(findings)
    assert not new, (
        f"clean extconf.rb must produce no findings; "
        f"got {[(f.kind, f.severity) for f in new]}"
    )


# ---------------------------------------------------------------------------
# GHA — clean publish workflow
# ---------------------------------------------------------------------------

def test_clean_npm_publish_workflow_no_high(tmp_path: Path) -> None:
    """Realistic ``release.yml`` using actions/setup-node + npm-publish
    via NPM_TOKEN env.  All standard trusted-consumer actions."""
    wf = tmp_path / ".github" / "workflows" / "release.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text("""\
name: release
on:
  push:
    tags: ['v*']
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          registry-url: 'https://registry.npmjs.org'
      - run: npm ci
      - run: npm test
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
      - uses: softprops/action-gh-release@v2
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
""", encoding="utf-8")
    findings = evaluate(tmp_path, [], [])
    new = _findings_from_new_detectors(findings)
    high = [f for f in new if f.severity in ("high", "critical")]
    assert not high, (
        f"clean npm-publish workflow must not produce high findings; "
        f"got {[(f.kind, f.severity, f.detail[:80]) for f in high]}"
    )


def test_clean_workflow_with_mask_no_findings(tmp_path: Path) -> None:
    """``echo "::add-mask::${{ secrets.X }}"`` is the canonical
    legitimate use of a secret in a run body and must not fire."""
    wf = tmp_path / ".github" / "workflows" / "ci.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text("""\
on: push
jobs:
  ci:
    runs-on: ubuntu-latest
    steps:
      - run: echo "::add-mask::${{ secrets.API_KEY }}"
      - run: ./run-integration-tests.sh
""", encoding="utf-8")
    findings = evaluate(tmp_path, [], [])
    new = _findings_from_new_detectors(findings)
    assert not new


def test_clean_workflow_with_env_static_writes_no_findings(
    tmp_path: Path,
) -> None:
    """Writing non-tainted values to $GITHUB_ENV is the most common
    workflow pattern and must NOT propagate taint."""
    wf = tmp_path / ".github" / "workflows" / "build.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text("""\
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "VERSION=$(cat VERSION)" >> $GITHUB_ENV
          echo "BUILD_DATE=$(date -u +%Y-%m-%d)" >> $GITHUB_ENV
      - run: echo "Building $VERSION on $BUILD_DATE"
""", encoding="utf-8")
    findings = evaluate(tmp_path, [], [])
    new = _findings_from_new_detectors(findings)
    assert not new


# ---------------------------------------------------------------------------
# Multi-ecosystem: realistic monorepo
# ---------------------------------------------------------------------------

def test_clean_monorepo_no_new_high(tmp_path: Path) -> None:
    """Monorepo with both a JS sub-package and a Python sub-package.
    Both clean; the combined evaluate must produce no high
    findings from the new detectors."""
    # JS sub-package
    js_dir = tmp_path / "packages" / "js-lib"
    js_dir.mkdir(parents=True)
    js_pkg = js_dir / "package.json"
    js_pkg.write_text(json.dumps({
        "name": "@org/js-lib",
        "version": "1.0.0",
        "scripts": {"test": "jest"},
    }), encoding="utf-8")
    # Python sub-package
    py_dir = tmp_path / "packages" / "py-lib"
    py_dir.mkdir(parents=True)
    py_proj = py_dir / "pyproject.toml"
    py_proj.write_text(
        '[project]\nname = "py-lib"\nversion = "1.0.0"\n',
        encoding="utf-8",
    )
    py_setup = py_dir / "setup.py"
    py_setup.write_text(
        "from setuptools import setup\nsetup()\n",
        encoding="utf-8",
    )
    manifests = [
        _manifest(js_pkg, "npm"),
        _manifest(py_proj, "PyPI"),
    ]
    deps = [
        _dep("@org/js-lib", "npm", declared_in=js_pkg),
        _dep("py-lib", "PyPI", declared_in=py_proj),
    ]
    findings = evaluate(tmp_path, manifests, deps)
    new = _findings_from_new_detectors(findings)
    high = [f for f in new if f.severity in ("high", "critical")]
    assert not high
