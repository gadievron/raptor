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


def test_test_classification_conventions_unchanged(tmp_path: Path) -> None:
    """The test-path predicate is shared with ``_test_paths`` — the
    JS conventions the module recognised with its private copy must
    classify identically: ``.test.``/``.spec.`` filenames and test
    directory ancestors mark test code; ordinary sources don't."""
    repo = tmp_path / "repo"
    _write(repo / "src" / "app.js", "require('lodash');\n")
    _write(repo / "src" / "app.spec.tsx", "require('lodash');\n")
    _write(repo / "src" / "app.test.mjs", "require('lodash');\n")
    _write(repo / "__tests__" / "b.js", "require('lodash');\n")
    _write(repo / "e2e" / "c.cjs", "require('lodash');\n")
    scan = scan_imports(repo)
    by_name = {f.name: is_test for f, _l, is_test in scan["lodash"]}
    assert by_name == {
        "app.js": False,
        "app.spec.tsx": True,
        "app.test.mjs": True,
        "b.js": True,
        "c.cjs": True,
    }


# ---------------------------------------------------------------------------
# Re-export branch — statement-local, linear-time
# ---------------------------------------------------------------------------

def test_export_heavy_source_scans_in_linear_time(tmp_path):
    """From-less ``export const`` runs (minified / codegen output)
    made the re-export branch rescan to the next quote in the file
    per ``export`` token — measured 1.03s at 3000 lines and 4.11s at
    6000 pre-fix.  Budget: CPU time, generous for CI variability."""
    import time
    lines = [f"export const x{i} = {i};" for i in range(6000)]
    lines.append("import lodash from 'lodash';")
    (tmp_path / "gen.js").write_text("\n".join(lines), encoding="utf-8")
    start = time.process_time()
    scan = scan_imports(tmp_path)
    elapsed = time.process_time() - start
    assert "lodash" in scan
    assert elapsed < 0.5, f"export-heavy scan took {elapsed:.2f}s CPU"


def test_export_branch_does_not_span_statements(tmp_path):
    """Pre-fix the DOTALL ``.+?`` let ``export`` on line 1 pair with
    a quote on a LATER line, mis-attributing the import evidence."""
    (tmp_path / "a.js").write_text(
        "export const banner = 1;\n"
        "const other = 2;\n"
        "import lodash from 'lodash';\n",
        encoding="utf-8",
    )
    scan = scan_imports(tmp_path)
    assert [(p.name, line) for p, line, _ in scan["lodash"]] == [("a.js", 3)]


def test_multiline_reexport_still_detected(tmp_path):
    (tmp_path / "b.js").write_text(
        "export {\n  a,\n  b\n} from 'left-pad';\n",
        encoding="utf-8",
    )
    scan = scan_imports(tmp_path)
    assert "left-pad" in scan


def test_es2022_string_named_reexport_detected(tmp_path):
    """``export { a as "string name" } from 'mod'`` — the quoted
    export name must not stop the statement-local scan short of the
    ``from`` specifier."""
    (tmp_path / "c.js").write_text(
        'export { a as "weird name" } from \'left-pad\';\n',
        encoding="utf-8",
    )
    scan = scan_imports(tmp_path)
    assert "left-pad" in scan
