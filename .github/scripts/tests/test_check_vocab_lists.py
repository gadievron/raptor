"""Detector-correctness tests for the vocabulary-list guardrail."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "check_vocab_lists.py"


@pytest.fixture(scope="module")
def det():
    spec = importlib.util.spec_from_file_location("check_vocab_lists", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _tree(tmp_path: Path, rel: str, body: str) -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return tmp_path


BIG_LIST = (
    "_SINKS = frozenset({\n"
    + "".join(f'    "api_fn_{i}",\n' for i in range(12))
    + "})\n"
)

SEED_LIST = (
    "_SEEDS = frozenset({\n"
    + "".join(f'    "api_fn_{i}",\n' for i in range(9))
    + "})\n"
)


class TestDetection:
    def test_big_literal_list_flagged(self, det, tmp_path):
        root = _tree(tmp_path, "core/foo.py", BIG_LIST)
        findings = det.scan_tree(root)
        assert [f.key for f in findings] == ["core/foo.py::_SINKS"]
        assert findings[0].kind == "literal"
        assert findings[0].count == 12

    def test_seed_sized_list_ignored(self, det, tmp_path):
        root = _tree(tmp_path, "core/foo.py", SEED_LIST)
        assert det.scan_tree(root) == []

    def test_alternation_string_flagged(self, det, tmp_path):
        alts = "|".join(f"kapi_{i}" for i in range(11))
        body = f'_RE = re.compile(r"\\b({alts})\\s*\\(")\n'
        root = _tree(tmp_path, "core/foo.py", "import re\n" + body)
        findings = det.scan_tree(root)
        assert [f.kind for f in findings] == ["alternation"]

    def test_prose_with_pipes_not_flagged(self, det, tmp_path):
        segs = " | ".join(f"choice number {i}" for i in range(12))
        root = _tree(tmp_path, "core/foo.py", f'MSG = "{segs}"\n')
        assert det.scan_tree(root) == []

    def test_non_name_lists_ignored(self, det, tmp_path):
        body = (
            "PATHS = [\n"
            + "".join(f'    "/etc/thing-{i}.conf",\n' for i in range(12))
            + "]\n"
        )
        root = _tree(tmp_path, "core/foo.py", body)
        assert det.scan_tree(root) == []

    def test_dunder_all_ignored(self, det, tmp_path):
        body = (
            "__all__ = [\n"
            + "".join(f'    "sym_{i}",\n' for i in range(15))
            + "]\n"
        )
        root = _tree(tmp_path, "core/foo.py", body)
        assert det.scan_tree(root) == []

    def test_qualified_names_count(self, det, tmp_path):
        body = (
            "_SINKS = {\n"
            + "".join(f'    "os.mod_{i}.fn": 1,\n' for i in range(12))
            + "}\n"
        )
        root = _tree(tmp_path, "core/foo.py", body)
        findings = det.scan_tree(root)
        assert len(findings) == 1


class TestAllowedPaths:
    def test_taxonomy_exempt(self, det, tmp_path):
        root = _tree(
            tmp_path, "core/function_taxonomy/__init__.py", BIG_LIST,
        )
        assert det.scan_tree(root) == []

    def test_data_dirs_exempt(self, det, tmp_path):
        root = _tree(tmp_path, "core/audit/data/gen.py", BIG_LIST)
        assert det.scan_tree(root) == []

    def test_tests_and_fixtures_exempt(self, det, tmp_path):
        _tree(tmp_path, "core/audit/tests/test_x.py", BIG_LIST)
        root = _tree(tmp_path, "packages/x/fixtures/f.py", BIG_LIST)
        assert det.scan_tree(root) == []

    def test_outside_py_roots_not_scanned(self, det, tmp_path):
        root = _tree(tmp_path, "docs/example.py", BIG_LIST)
        assert det.scan_tree(root) == []


class TestBaselineSemantics:
    def _run(self, det, root, baseline, capsys):
        import sys
        argv = sys.argv
        sys.argv = [
            "check_vocab_lists.py", "--root", str(root),
            "--baseline", str(baseline),
        ]
        try:
            rc = det.main()
        finally:
            sys.argv = argv
        return rc, capsys.readouterr().out

    def test_new_finding_fails(self, det, tmp_path, capsys):
        root = _tree(tmp_path, "core/foo.py", BIG_LIST)
        baseline = tmp_path / "baseline.json"
        baseline.write_text("{}", encoding="utf-8")
        rc, out = self._run(det, root, baseline, capsys)
        assert rc == 1
        assert "core/foo.py::_SINKS" in out

    def test_baselined_finding_passes(self, det, tmp_path, capsys):
        root = _tree(tmp_path, "core/foo.py", BIG_LIST)
        baseline = tmp_path / "baseline.json"
        baseline.write_text(json.dumps({
            "core/foo.py::_SINKS": {"kind": "literal", "count": 12},
        }), encoding="utf-8")
        rc, _out = self._run(det, root, baseline, capsys)
        assert rc == 0

    def test_growth_warns_but_passes(self, det, tmp_path, capsys):
        root = _tree(tmp_path, "core/foo.py", BIG_LIST)
        baseline = tmp_path / "baseline.json"
        baseline.write_text(json.dumps({
            "core/foo.py::_SINKS": {"kind": "literal", "count": 10},
        }), encoding="utf-8")
        rc, out = self._run(det, root, baseline, capsys)
        assert rc == 0
        assert "WARN grown" in out

    def test_stale_entry_warns_but_passes(self, det, tmp_path, capsys):
        root = _tree(tmp_path, "core/foo.py", SEED_LIST)
        baseline = tmp_path / "baseline.json"
        baseline.write_text(json.dumps({
            "core/gone.py::_OLD": {"kind": "literal", "count": 20},
        }), encoding="utf-8")
        rc, out = self._run(det, root, baseline, capsys)
        assert rc == 0
        assert "WARN stale" in out


class TestRepoBaseline:
    @pytest.mark.slow
    def test_checked_in_baseline_is_current(self, det):
        """The committed baseline matches the tree (fails on regressions
        AND on unrecorded cleanups — regenerate with --write-baseline).

        Full-tree scan — genuine I/O over the whole checkout that only
        grows with the repo, so it rides the nightly tier alongside the
        env-docs repo-tree test. The default-tier signal is the detector
        script itself, which the miswiring-scan workflow runs directly
        against the repo.
        """
        root = Path(_SCRIPT).resolve().parents[2]
        findings = {f.key for f in det.scan_tree(root)}
        baseline = set(det.load_baseline(det.DEFAULT_BASELINE))
        assert findings - baseline == set(), "new vocabulary lists"
        assert baseline - findings == set(), "stale baseline entries"
