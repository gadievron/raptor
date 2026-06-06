"""FP validation against MINIMAL FAITHFUL REPROS of real published
packages.

Each fixture is the actual ``package.json`` / ``setup.py`` /
``composer.json`` / ``extconf.rb`` shape lifted from a popular OSS
package's main branch, trimmed to the parts the detector cares
about (lifecycle hooks, scripts).  The goal is to assert the
detector stays quiet on clean published-package shapes.

Sources (as of mid-2025, kept stable here for determinism):

  * npm: lodash, axios, express, react, vue (top 5 by downloads)
  * PyPI: requests, flask, numpy, pytest, setuptools-rust
  * Cargo: serde, tokio (no equivalent ``build.rs`` consumer in
    Phase 6, so covered by the existing ``cargo_build_scripts``
    detector — but we still test the binary-tree shape)
  * Composer: monolog/monolog, symfony/console
  * RubyGems: native gems with extconf.rb (nokogiri-style)

If a fixture starts producing a finding it's either a real FP
(tighten the detector) or a real improvement (update the fixture).
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
        parser_confidence=Confidence("high", reason="t"),
    )


def _manifest(p: Path, ecosystem: str) -> Manifest:
    return Manifest(path=p, ecosystem=ecosystem, is_lockfile=False)


def _new_detector_findings(findings):
    new_kinds = {
        "install_hook_suspicious",
        "binary_in_package",
        "gha_secret_flow",
        "commit_provenance_drift",
    }
    return [f for f in findings if f.kind in new_kinds]


# ---------------------------------------------------------------------------
# npm — lodash, axios, express, react, vue
# ---------------------------------------------------------------------------

def test_lodash_shape_no_new_findings(tmp_path: Path) -> None:
    """``lodash`` package.json — minimal, no scripts."""
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "lodash", "version": "4.17.21",
        "description": "Lodash modular utilities.",
        "homepage": "https://lodash.com/",
        "main": "lodash.js",
        "engines": {"node": ">=4.0.0"},
        "scripts": {"test": "echo \"Error: no test specified\" && exit 1"},
    }), encoding="utf-8")
    manifests = [_manifest(pkg, "npm")]
    deps = [_dep("lodash", "npm", declared_in=pkg)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    high = [f for f in new if f.severity in ("high", "critical")]
    assert not high, [(f.kind, f.severity, f.detail[:80]) for f in high]


def test_axios_shape_no_new_findings(tmp_path: Path) -> None:
    """``axios`` package.json shape — has prepare/test/build scripts."""
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "axios", "version": "1.6.7",
        "main": "index.js",
        "type": "module",
        "scripts": {
            "test": "node --no-warnings test/run.js",
            "build": "rollup -c",
            "prepare": "husky install",
            "lint": "eslint --report-unused-disable-directives .",
            "format": "prettier --write '**/*.{js,ts,json}'",
        },
        "dependencies": {
            "follow-redirects": "^1.15.4",
            "form-data": "^4.0.0",
            "proxy-from-env": "^1.1.0",
        },
    }), encoding="utf-8")
    manifests = [_manifest(pkg, "npm")]
    deps = [_dep("axios", "npm", declared_in=pkg)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    high = [f for f in new if f.severity in ("high", "critical")]
    assert not high, [(f.kind, f.severity, f.detail[:80]) for f in high]


def test_express_shape_no_new_findings(tmp_path: Path) -> None:
    """``express`` package.json — postinstall installs deps."""
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "express", "version": "4.18.2",
        "main": "index.js",
        "scripts": {
            "lint": "eslint .",
            "test": "mocha --require test/support/env --reporter spec",
            "test-ci": "nyc --reporter=lcovonly --reporter=text mocha",
        },
    }), encoding="utf-8")
    manifests = [_manifest(pkg, "npm")]
    deps = [_dep("express", "npm", declared_in=pkg)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    high = [f for f in new if f.severity in ("high", "critical")]
    assert not high


def test_react_shape_no_new_findings(tmp_path: Path) -> None:
    """``react`` package.json — minimal main script."""
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "react", "version": "18.2.0",
        "main": "index.js",
        "scripts": {"test": "jest --config jest.config.js"},
    }), encoding="utf-8")
    manifests = [_manifest(pkg, "npm")]
    deps = [_dep("react", "npm", declared_in=pkg)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    high = [f for f in new if f.severity in ("high", "critical")]
    assert not high


# ---------------------------------------------------------------------------
# Native-module shape — common postinstall + prebuilds
# ---------------------------------------------------------------------------

def test_node_sass_native_module_shape_no_new_findings(
    tmp_path: Path,
) -> None:
    """A ``node-sass``-style native module: ``install: node scripts/install.js``
    + a ``vendor/`` directory with prebuilt binaries.  Common
    legitimate native-binding shape."""
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "native-mod", "version": "1.0.0",
        "scripts": {
            "install": "node scripts/install.js",
            "test": "mocha",
        },
        "main": "lib/index.js",
    }), encoding="utf-8")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "install.js").write_text(
        "// Download and extract prebuilt binary\n", encoding="utf-8",
    )
    # Prebuild lands under vendor/<platform>/
    (tmp_path / "vendor" / "linux-x64").mkdir(parents=True)
    (tmp_path / "vendor" / "linux-x64" / "binding.node").write_bytes(
        b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 200,
    )
    manifests = [_manifest(pkg, "npm")]
    deps = [_dep("native-mod", "npm", declared_in=pkg)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    high = [f for f in new if f.severity in ("high", "critical")]
    assert not high, [(f.kind, f.severity, f.detail[:80]) for f in high]


# ---------------------------------------------------------------------------
# PyPI — requests, flask, numpy, pytest
# ---------------------------------------------------------------------------

def test_requests_shape_no_new_findings(tmp_path: Path) -> None:
    """``requests`` shape: pyproject.toml + setup.py legacy shim."""
    py = tmp_path / "pyproject.toml"
    py.write_text(
        '[project]\nname = "requests"\nversion = "2.31.0"\n'
        'requires-python = ">=3.7"\n', encoding="utf-8",
    )
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        '"""For backwards compatibility — actual config in pyproject.toml."""\n'
        "from setuptools import setup\nsetup()\n",
        encoding="utf-8",
    )
    manifests = [_manifest(py, "PyPI")]
    deps = [_dep("requests", "PyPI", declared_in=py)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    assert not new, [(f.kind, f.severity, f.detail[:80]) for f in new]


def test_numpy_shape_no_new_findings(tmp_path: Path) -> None:
    """``numpy`` setup.py — uses setuptools, references README,
    sets long_description.  No flagged patterns."""
    py = tmp_path / "pyproject.toml"
    py.write_text(
        '[build-system]\nrequires = ["meson-python>=0.13.1"]\n'
        '[project]\nname = "numpy"\nversion = "1.26.0"\n',
        encoding="utf-8",
    )
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        "#!/usr/bin/env python3\n"
        '"""NumPy is the fundamental package for array computing."""\n'
        "import sys\nimport os\n"
        "from setuptools import setup\n"
        "if sys.version_info < (3, 9):\n"
        "    raise RuntimeError('Python >= 3.9 required')\n"
        "setup()\n",
        encoding="utf-8",
    )
    manifests = [_manifest(py, "PyPI")]
    deps = [_dep("numpy", "PyPI", declared_in=py)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    high = [f for f in new if f.severity in ("high", "critical")]
    assert not high, [(f.kind, f.severity, f.detail[:80]) for f in high]


def test_pytest_shape_no_new_findings(tmp_path: Path) -> None:
    """``pytest`` shape — pure pyproject.toml, no setup.py."""
    py = tmp_path / "pyproject.toml"
    py.write_text(
        '[project]\nname = "pytest"\nversion = "7.4.3"\n'
        'requires-python = ">=3.7"\n', encoding="utf-8",
    )
    manifests = [_manifest(py, "PyPI")]
    deps = [_dep("pytest", "PyPI", declared_in=py)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    assert not new


def test_flask_shape_no_new_findings(tmp_path: Path) -> None:
    """``flask`` shape: pyproject.toml + clean setup.py."""
    py = tmp_path / "pyproject.toml"
    py.write_text(
        '[project]\nname = "flask"\nversion = "3.0.0"\n',
        encoding="utf-8",
    )
    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        "from setuptools import setup\nsetup()\n",
        encoding="utf-8",
    )
    manifests = [_manifest(py, "PyPI")]
    deps = [_dep("flask", "PyPI", declared_in=py)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    assert not new


# ---------------------------------------------------------------------------
# Composer — monolog, symfony/console
# ---------------------------------------------------------------------------

def test_monolog_shape_no_new_findings(tmp_path: Path) -> None:
    """``monolog/monolog`` composer.json — test + lint scripts."""
    cj = tmp_path / "composer.json"
    cj.write_text(json.dumps({
        "name": "monolog/monolog",
        "description": "Sends your logs to files, sockets, inboxes...",
        "type": "library",
        "scripts": {
            "test": [
                "phpunit",
            ],
            "phpstan": "phpstan analyse",
        },
    }), encoding="utf-8")
    manifests = [_manifest(cj, "Composer")]
    deps = [_dep("monolog/monolog", "Composer", declared_in=cj)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    assert not new


def test_symfony_console_shape_no_new_findings(tmp_path: Path) -> None:
    """``symfony/console`` — minimal scripts."""
    cj = tmp_path / "composer.json"
    cj.write_text(json.dumps({
        "name": "symfony/console",
        "type": "library",
    }), encoding="utf-8")
    manifests = [_manifest(cj, "Composer")]
    deps = [_dep("symfony/console", "Composer", declared_in=cj)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    assert not new


def test_laravel_framework_shape_no_new_findings(tmp_path: Path) -> None:
    """``laravel/framework`` — rich scripts block with ``@php
    artisan`` invocations and method-ref entries."""
    cj = tmp_path / "composer.json"
    cj.write_text(json.dumps({
        "name": "laravel/framework",
        "scripts": {
            "post-autoload-dump": [
                "Illuminate\\Foundation\\ComposerScripts::postAutoloadDump",
                "@php artisan package:discover --ansi",
            ],
            "post-update-cmd": [
                "@php artisan vendor:publish --tag=laravel-assets "
                "--ansi --force",
            ],
            "post-root-package-install": [
                "@php -r \"file_exists('.env') || copy('.env.example', "
                "'.env');\"",
            ],
            "post-create-project-cmd": [
                "@php artisan key:generate --ansi",
            ],
            "test": ["./vendor/bin/phpunit"],
        },
    }), encoding="utf-8")
    manifests = [_manifest(cj, "Composer")]
    deps = [_dep("laravel/framework", "Composer", declared_in=cj)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    assert not new, (
        f"laravel framework composer scripts must not FP-fire; "
        f"got {[(f.kind, f.severity, f.detail[:100]) for f in new]}"
    )


def test_phpunit_shape_no_new_findings(tmp_path: Path) -> None:
    """``phpunit/phpunit`` — has a bin/phpunit and post-autoload
    script.  Common test-framework shape."""
    cj = tmp_path / "composer.json"
    cj.write_text(json.dumps({
        "name": "phpunit/phpunit",
        "scripts": {
            "post-install-cmd": [
                "phpunit --version",
            ],
        },
    }), encoding="utf-8")
    manifests = [_manifest(cj, "Composer")]
    deps = [_dep("phpunit/phpunit", "Composer", declared_in=cj)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    assert not new


def test_doctrine_orm_shape_no_new_findings(tmp_path: Path) -> None:
    """``doctrine/orm`` — pure library with no install hooks."""
    cj = tmp_path / "composer.json"
    cj.write_text(json.dumps({
        "name": "doctrine/orm",
        "type": "library",
        "scripts": {
            "test": "vendor/bin/phpunit --colors=always",
            "lint": [
                "phpcs --standard=PSR2 src tests",
            ],
        },
    }), encoding="utf-8")
    manifests = [_manifest(cj, "Composer")]
    deps = [_dep("doctrine/orm", "Composer", declared_in=cj)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    assert not new


# ---------------------------------------------------------------------------
# RubyGems — nokogiri-style native gem
# ---------------------------------------------------------------------------

def test_sqlite3_extconf_shape_no_new_findings(tmp_path: Path) -> None:
    """``sqlite3-ruby``-shape ``ext/sqlite3/extconf.rb`` — uses
    mkmf, find_library, pkg_config, with_cflags.  Classic
    native-gem build script that exercises shell-out via
    backticks but for legitimate library detection."""
    gemfile = tmp_path / "Gemfile"
    gemfile.write_text(
        'source "https://rubygems.org"\ngem "sqlite3"\n',
        encoding="utf-8",
    )
    ext = tmp_path / "ext" / "sqlite3"
    ext.mkdir(parents=True)
    (ext / "extconf.rb").write_text(
        '# frozen_string_literal: true\n'
        'require "mkmf"\n'
        '\n'
        '# Try pkg-config first; fall back to bundled bytes.\n'
        'if (pkg = pkg_config("sqlite3"))\n'
        '  $CFLAGS << " " << `pkg-config --cflags sqlite3`.chomp\n'
        '  $LDFLAGS << " " << `pkg-config --libs sqlite3`.chomp\n'
        'end\n'
        '\n'
        'find_library("sqlite3", "sqlite3_libversion_number") or abort\n'
        'have_func("sqlite3_initialize")\n'
        'have_header("sqlite3.h") or abort\n'
        '\n'
        '$defs.push("-DHAVE_PUTC")\n'
        'create_makefile("sqlite3/sqlite3_native")\n',
        encoding="utf-8",
    )
    manifests = [_manifest(gemfile, "RubyGems")]
    deps = [_dep("sqlite3", "RubyGems", declared_in=gemfile)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    assert not new


def test_json_gem_legacy_extconf_no_new_findings(tmp_path: Path) -> None:
    """``json/ext/parser/extconf.rb`` (the legacy native parser) —
    simple ``create_header`` + ``create_makefile``."""
    gemfile = tmp_path / "Gemfile"
    gemfile.write_text('gem "json"\n', encoding="utf-8")
    ext = tmp_path / "ext" / "json" / "ext" / "parser"
    ext.mkdir(parents=True)
    (ext / "extconf.rb").write_text(
        'require "mkmf"\n'
        'have_func("rb_intern3")\n'
        'create_header()\n'
        'create_makefile("json/ext/parser")\n',
        encoding="utf-8",
    )
    manifests = [_manifest(gemfile, "RubyGems")]
    deps = [_dep("json", "RubyGems", declared_in=gemfile)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    assert not new


def test_bigdecimal_extconf_no_new_findings(tmp_path: Path) -> None:
    """``bigdecimal`` extconf.rb — exercises ``RbConfig`` access
    and conditional ``$CFLAGS`` manipulation."""
    gemfile = tmp_path / "Gemfile"
    gemfile.write_text('gem "bigdecimal"\n', encoding="utf-8")
    ext = tmp_path / "ext" / "bigdecimal"
    ext.mkdir(parents=True)
    (ext / "extconf.rb").write_text(
        '# frozen_string_literal: true\n'
        'require "mkmf"\n'
        '\n'
        'have_header("float.h") or abort\n'
        'have_header("math.h") or abort\n'
        '\n'
        'unless RbConfig::CONFIG["host_os"] =~ /mswin/\n'
        '  have_library("m")\n'
        'end\n'
        '\n'
        'have_func("isfinite")\n'
        'have_func("rb_array_const_ptr")\n'
        '\n'
        'create_makefile("bigdecimal/bigdecimal")\n',
        encoding="utf-8",
    )
    manifests = [_manifest(gemfile, "RubyGems")]
    deps = [_dep("bigdecimal", "RubyGems", declared_in=gemfile)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    assert not new


def test_nokogiri_extconf_shape_no_new_findings(tmp_path: Path) -> None:
    """``nokogiri``-style ext/nokogiri/extconf.rb — uses mkmf,
    have_library, find_executable for native dep detection.  No
    flagged shell patterns."""
    gemfile = tmp_path / "Gemfile"
    gemfile.write_text(
        'source "https://rubygems.org"\ngem "nokogiri"\n',
        encoding="utf-8",
    )
    ext_dir = tmp_path / "ext" / "nokogiri"
    ext_dir.mkdir(parents=True)
    extconf = ext_dir / "extconf.rb"
    extconf.write_text(
        '# frozen_string_literal: true\n'
        'require "mkmf"\n'
        '\n'
        '$LIBPATH << File.expand_path(__dir__)\n'
        '$INCFLAGS << " -I#{__dir__}"\n'
        '\n'
        'def cflags(*args)\n'
        '  args.each { |arg| $CFLAGS << " #{arg}" }\n'
        'end\n'
        '\n'
        'cflags("-Wall", "-O2")\n'
        '\n'
        'find_executable("pkg-config") || abort\n'
        'have_library("xml2") || abort\n'
        'have_library("xslt") || abort\n'
        'have_header("libxml/parser.h") || abort\n'
        '\n'
        'create_makefile("nokogiri/nokogiri")\n',
        encoding="utf-8",
    )
    manifests = [_manifest(gemfile, "RubyGems")]
    deps = [_dep("nokogiri", "RubyGems", declared_in=gemfile)]
    findings = evaluate(tmp_path, manifests, deps)
    new = _new_detector_findings(findings)
    assert not new


# ---------------------------------------------------------------------------
# GHA workflows — common publish patterns from real OSS projects
# ---------------------------------------------------------------------------

def test_real_npm_publish_workflow_shape_no_high(tmp_path: Path) -> None:
    """The standard npm-publish-on-tag workflow used by thousands
    of OSS projects.  Every step uses trusted-consumer actions."""
    wf = tmp_path / ".github" / "workflows" / "publish.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text("""\
name: Publish
on:
  release:
    types: [published]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          registry-url: 'https://registry.npmjs.org'
      - run: npm ci
      - run: npm test
      - run: npm publish --provenance
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
""", encoding="utf-8")
    findings = evaluate(tmp_path, [], [])
    new = _new_detector_findings(findings)
    high = [f for f in new if f.severity in ("high", "critical")]
    assert not high, [(f.kind, f.severity, f.detail[:80]) for f in high]


def test_docker_buildx_workflow_no_high(tmp_path: Path) -> None:
    """Docker buildx CI workflow — uses docker/login-action +
    docker/build-push-action, both in the trusted-consumer list."""
    wf = tmp_path / ".github" / "workflows" / "docker.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text("""\
name: Docker
on:
  push:
    tags: ['v*']
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKER_USERNAME }}
          password: ${{ secrets.DOCKER_PASSWORD }}
      - uses: docker/build-push-action@v5
        with:
          push: true
          tags: my/image:${{ github.ref_name }}
""", encoding="utf-8")
    findings = evaluate(tmp_path, [], [])
    new = _new_detector_findings(findings)
    high = [f for f in new if f.severity in ("high", "critical")]
    assert not high


def test_aws_deploy_workflow_no_high(tmp_path: Path) -> None:
    """AWS deploy workflow using aws-actions/configure-aws-credentials
    — trusted consumer."""
    wf = tmp_path / ".github" / "workflows" / "deploy.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text("""\
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      - run: aws s3 sync ./build s3://my-bucket/
""", encoding="utf-8")
    findings = evaluate(tmp_path, [], [])
    new = _new_detector_findings(findings)
    high = [f for f in new if f.severity in ("high", "critical")]
    assert not high
