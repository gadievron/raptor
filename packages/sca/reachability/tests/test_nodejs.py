"""Tests for the npm reachability scanner."""

from __future__ import annotations

from pathlib import Path

from packages.sca.reachability.nodejs import resolve_dep, scan_imports


def _write(p: Path, body: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def test_require_and_import_collected(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "a.js", "const lodash = require('lodash');\n")
    _write(repo / "b.ts", "import _ from 'lodash';\n")
    _write(repo / "c.mjs", "import 'side-effect-only';\n")
    scan = scan_imports(repo)
    assert "lodash" in scan
    assert "side-effect-only" in scan


def test_scoped_package_kept_intact(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "a.ts", "import * as t from '@types/node';\n"
                          "import { Logger } from '@scope/pkg/sub';\n")
    scan = scan_imports(repo)
    assert "@types/node" in scan
    assert "@scope/pkg" in scan


def test_relative_and_absolute_paths_ignored(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "a.js",
           "require('./local'); require('../other'); require('/abs/file');\n")
    scan = scan_imports(repo)
    assert scan == {}


def test_node_builtin_ignored(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "a.js", "const fs = require('fs');\n"
                          "const path = require('node:path');\n")
    scan = scan_imports(repo)
    assert scan == {}


def test_test_file_marked(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "src" / "a.js", "require('lodash');\n")
    _write(repo / "src" / "a.test.js", "require('lodash');\n")
    scan = scan_imports(repo)
    flags = sorted(is_test for _f, _l, is_test in scan["lodash"])
    assert flags == [False, True]


def test_node_modules_excluded(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "src" / "a.js", "require('ok');\n")
    _write(repo / "node_modules" / "evil" / "i.js", "require('poison');\n")
    scan = scan_imports(repo)
    assert "ok" in scan
    assert "poison" not in scan


def test_resolve_imported_high_confidence(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "a.js", "require('lodash');\n")
    r = resolve_dep("lodash", scan_imports(repo), target=repo)
    assert r.verdict == "imported"
    assert r.confidence.level == "high"


def test_resolve_test_only_is_not_reachable(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "a.spec.js", "require('mocha');\n")
    r = resolve_dep("mocha", scan_imports(repo), target=repo)
    assert r.verdict == "not_reachable"
    assert "test code" in r.confidence.reason


def test_resolve_unknown_dep_not_reachable(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "a.js", "require('lodash');\n")
    r = resolve_dep("never-imported", scan_imports(repo), target=repo)
    assert r.verdict == "not_reachable"


def test_dynamic_import_recognised(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "a.js", "const m = await import('lodash');\n")
    scan = scan_imports(repo)
    assert "lodash" in scan


def test_export_from_recognised(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / "a.ts", "export { default } from 'lodash';\n")
    scan = scan_imports(repo)
    assert "lodash" in scan
