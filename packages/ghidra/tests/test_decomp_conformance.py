"""Tests for the decomp-tree conformance metric.

Hermetic: both tool legs go through the injection points
(``ts_scan_fn`` / ``run_rule_fn``); no sandbox, semgrep, or
tree-sitter child is spawned. The child's pure scan logic gets a
direct test gated on tree-sitter availability.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from packages.ghidra.decomp_conformance import (
    CONFORMANCE_NAME,
    measure_conformance,
)
from packages.ghidra.decomp_tree import write_decomp_tree
from packages.ghidra.model import REDatabase


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "decomp-tree"
    root.mkdir()
    for name, text in files.items():
        (root / name).write_text(text, encoding="utf-8")
    return root


def _ts_leg(per_file: dict):
    def _scan(root: Path) -> dict:
        return {"available": True, "reason": "", "files": per_file}
    return _scan


class _FakeResult:
    def __init__(self, examined=(), failed=(), errors=(),
                 returncode=0):
        self.files_examined = list(examined)
        self.files_failed = list(failed)
        self.errors = list(errors)
        self.returncode = returncode
        self.findings = []


class TestMeasure:
    def test_fully_parseable_tree(self, tmp_path):
        root = _tree(tmp_path, {"g1.c": "int f(void) { return 0; }\n"})

        def _run_rule(target, config, **kwargs):
            return _FakeResult(examined=[str(root / "g1.c")])

        record = measure_conformance(
            root,
            ts_scan_fn=_ts_leg({"g1.c": {"ok": True, "reason": ""}}),
            run_rule_fn=_run_rule,
        )
        assert record["files_total"] == 1
        assert record["tree_sitter"]["rate"] == 1.0
        assert record["semgrep"]["rate"] == 1.0
        assert record["parsed_rate"] == 1.0
        assert record["quarantine"] == []
        on_disk = json.loads(
            (root / CONFORMANCE_NAME).read_text(encoding="utf-8"))
        assert on_disk["parsed_rate"] == 1.0

    def test_unparseable_file_quarantined_with_reasons(self, tmp_path):
        root = _tree(tmp_path, {
            "g1.c": "int f(void) { return 0; }\n",
            "g2.c": "int broken( {{{\n",
        })

        def _run_rule(target, config, **kwargs):
            return _FakeResult(
                examined=[str(root / "g1.c")],
                failed=[{"path": str(root / "g2.c"),
                         "reason": "syntax error \x1b[31mboom"}],
            )

        record = measure_conformance(
            root,
            ts_scan_fn=_ts_leg({
                "g1.c": {"ok": True, "reason": ""},
                "g2.c": {"ok": False,
                         "reason": "parse errors present"},
            }),
            run_rule_fn=_run_rule,
        )
        assert record["files_total"] == 2
        assert record["parsed_rate"] == 0.5
        assert record["quarantine_total"] == 1
        q = record["quarantine"][0]
        assert q["file"] == "g2.c"
        assert any("tree-sitter" in r for r in q["reasons"])
        assert any("semgrep" in r for r in q["reasons"])
        # Escaped at capture: tool-reported reasons carry no raw ESC.
        assert all("\x1b" not in r for r in q["reasons"])

    def test_parsed_rate_is_minimum_of_available_legs(self, tmp_path):
        root = _tree(tmp_path, {
            "g1.c": "int f(void) { return 0; }\n",
            "g2.c": "int g(void) { return 1; }\n",
        })

        def _run_rule(target, config, **kwargs):
            # semgrep parses both; tree-sitter only one — the honest
            # denominator is the CONSERVATIVE leg.
            return _FakeResult(examined=[str(root / "g1.c"),
                                         str(root / "g2.c")])

        record = measure_conformance(
            root,
            ts_scan_fn=_ts_leg({
                "g1.c": {"ok": True, "reason": ""},
                "g2.c": {"ok": False, "reason": "parse errors"},
            }),
            run_rule_fn=_run_rule,
        )
        assert record["semgrep"]["rate"] == 1.0
        assert record["tree_sitter"]["rate"] == 0.5
        assert record["parsed_rate"] == 0.5

    def test_empty_tree(self, tmp_path):
        root = tmp_path / "decomp-tree"
        root.mkdir()
        called = []

        record = measure_conformance(
            root,
            ts_scan_fn=lambda r: called.append(r),
            run_rule_fn=lambda *a, **k: called.append(a),
        )
        assert record["files_total"] == 0
        assert record["parsed_rate"] is None
        assert called == []  # no tool leg runs over nothing
        assert (root / CONFORMANCE_NAME).is_file()

    def test_unavailable_legs_yield_none_rate_never_hundred(
            self, tmp_path):
        root = _tree(tmp_path, {"g1.c": "int f(void) { return 0; }\n"})

        record = measure_conformance(
            root,
            ts_scan_fn=lambda r: {"available": False,
                                  "reason": "core.sandbox unavailable",
                                  "files": {}},
            run_rule_fn=lambda *a, **k: _FakeResult(
                errors=["semgrep not installed"], returncode=-1),
        )
        assert record["tree_sitter"]["available"] is False
        assert record["semgrep"]["available"] is False
        assert record["parsed_rate"] is None
        assert "sandbox" in record["tree_sitter"]["reason"]

    def test_unexamined_file_counts_failed_not_parsed(self, tmp_path):
        """Silently skipped scans are not parses (scanned-witness
        honesty): a file absent from paths.scanned fails the leg."""
        root = _tree(tmp_path, {
            "g1.c": "int f(void) { return 0; }\n",
            "g2.c": "int g(void) { return 1; }\n",
        })
        record = measure_conformance(
            root,
            ts_scan_fn=_ts_leg({
                "g1.c": {"ok": True, "reason": ""},
                "g2.c": {"ok": True, "reason": ""},
            }),
            run_rule_fn=lambda *a, **k: _FakeResult(
                examined=[str(root / "g1.c")]),
        )
        assert record["semgrep"]["parsed"] == 1
        assert record["semgrep"]["failed"] == 1
        q = {e["file"] for e in record["quarantine"]}
        assert "g2.c" in q

    def test_enumeration_skew_gets_a_stated_reason(self, tmp_path):
        """An available leg with NO verdict for an enumerated file
        counts against the rate AND states why in quarantine — never
        a silent penalty."""
        root = _tree(tmp_path, {
            "g1.c": "int f(void) { return 0; }\n",
            "g2.c": "int g(void) { return 1; }\n",
        })
        record = measure_conformance(
            root,
            # tree-sitter leg only reported g1.c (skewed enumeration).
            ts_scan_fn=_ts_leg({"g1.c": {"ok": True, "reason": ""}}),
            run_rule_fn=lambda *a, **k: _FakeResult(
                examined=[str(root / "g1.c"), str(root / "g2.c")]),
        )
        assert record["tree_sitter"]["parsed"] == 1
        assert record["tree_sitter"]["failed"] == 1
        q = {e["file"]: e["reasons"] for e in record["quarantine"]}
        assert any("enumeration skew" in r for r in q["g2.c"])

    def test_no_write_flag(self, tmp_path):
        root = _tree(tmp_path, {"g1.c": "int f(void) { return 0; }\n"})
        measure_conformance(
            root,
            ts_scan_fn=_ts_leg({"g1.c": {"ok": True, "reason": ""}}),
            run_rule_fn=lambda *a, **k: _FakeResult(
                examined=[str(root / "g1.c")]),
            write=False,
        )
        assert not (root / CONFORMANCE_NAME).exists()


class TestSandboxPins:
    """The measurement legs must stay on the sandboxed paths — same
    pins the audit's decomp sweep carries for its semgrep lane."""

    def test_semgrep_leg_never_passes_the_sandbox_opt_out(
            self, tmp_path):
        root = _tree(tmp_path, {"g1.c": "int f(void) { return 0; }\n"})
        calls: list = []

        def _recorder(target, config, **kwargs):
            calls.append({"target": Path(target), "config": config,
                          "kwargs": dict(kwargs)})
            return _FakeResult(examined=[str(root / "g1.c")])

        measure_conformance(
            root,
            ts_scan_fn=_ts_leg({"g1.c": {"ok": True, "reason": ""}}),
            run_rule_fn=_recorder, write=False,
        )
        assert calls and calls[0]["target"] == root
        for call in calls:
            assert "unsandboxed" not in call["kwargs"]
            assert "subprocess_runner" not in call["kwargs"]

    def test_source_never_spells_the_opt_out(self):
        import packages.ghidra.decomp_conformance as dc
        src = Path(dc.__file__).read_text(encoding="utf-8")
        assert "unsandboxed=True" not in src

    def test_production_ts_leg_routes_the_sandbox(
            self, tmp_path, monkeypatch):
        """The default tree-sitter leg goes through core.sandbox.run
        with the network blocked and the tree as the target — never
        an in-process or bare-subprocess parse."""
        import json as _json

        import core.sandbox.context as sandbox_ctx

        from packages.ghidra.decomp_conformance import _sandboxed_ts_scan

        root = _tree(tmp_path, {"g1.c": "int f(void) { return 0; }\n"})
        calls: list = []

        class _Proc:
            returncode = 0
            stderr = ""
            stdout = _json.dumps({
                "available": True, "reason": "",
                "files": {"g1.c": {"ok": True, "reason": ""}},
            })

        def _fake_run(cmd, **kwargs):
            calls.append({"cmd": list(cmd), "kwargs": dict(kwargs)})
            return _Proc()

        monkeypatch.setattr(sandbox_ctx, "run", _fake_run)
        out = _sandboxed_ts_scan(root)
        assert out["available"] is True
        assert len(calls) == 1
        call = calls[0]
        assert call["kwargs"]["block_network"] is True
        assert call["kwargs"]["target"] == str(root)
        assert any("_conformance_child.py" in str(a)
                   for a in call["cmd"])

    def test_production_ts_leg_grants_python_runtime_and_repo_root(
            self, tmp_path, monkeypatch):
        """A python-spawning sandbox call must grant the interpreter's
        runtime roots (venv installs live outside the mount-ns
        baseline, and the sandboxed child execs the ORIGINAL argv
        path) plus the RAPTOR tree root the child self-anchors its
        core.* imports on — neither is under target. Without the
        grants every conformance scan pays a doomed mount-ns spawn
        and demotes the whole process to the mountless backend for
        the interpreter."""
        import json as _json

        import core.sandbox.context as sandbox_ctx
        from core.sandbox.python_paths import python_runtime_tool_paths

        import packages.ghidra.decomp_conformance as dc
        from packages.ghidra.decomp_conformance import _sandboxed_ts_scan

        root = _tree(tmp_path, {"g1.c": "int f(void) { return 0; }\n"})
        calls: list = []

        class _Proc:
            returncode = 0
            stderr = ""
            stdout = _json.dumps({
                "available": True, "reason": "", "files": {},
            })

        def _fake_run(cmd, **kwargs):
            calls.append({"cmd": list(cmd), "kwargs": dict(kwargs)})
            return _Proc()

        monkeypatch.setattr(sandbox_ctx, "run", _fake_run)
        _sandboxed_ts_scan(root)
        assert len(calls) == 1
        tool_paths = calls[0]["kwargs"].get("tool_paths") or []
        # Interpreter runtime roots (empty on a bare system-python
        # host — the helper excludes baseline prefixes).
        for p in python_runtime_tool_paths():
            assert p in tool_paths
        # The tree root the child's sys.path anchor resolves to.
        repo_root = Path(dc.__file__).resolve().parents[2]
        assert str(repo_root) in tool_paths


class TestBuildSeam:
    def _db(self) -> REDatabase:
        return REDatabase.from_dict({
            "source_tool": "test",
            "binary_path": "/opt/demo",
            "functions": [
                {"name": "f", "address": 0x1000, "size": 16,
                 "decompilation": "int f(void)\n{\n  return 0;\n}"},
            ],
            "xrefs": [],
        })

    def test_write_decomp_tree_measures_by_default(
            self, tmp_path, monkeypatch):
        from packages.ghidra import decomp_conformance
        calls: list = []
        monkeypatch.setattr(
            decomp_conformance, "measure_conformance",
            lambda root, **kw: calls.append(Path(root)) or {},
        )
        write_decomp_tree(self._db(), tmp_path)
        assert calls == [tmp_path]

    def test_conformance_false_skips_measurement(
            self, tmp_path, monkeypatch):
        from packages.ghidra import decomp_conformance
        calls: list = []
        monkeypatch.setattr(
            decomp_conformance, "measure_conformance",
            lambda root, **kw: calls.append(Path(root)) or {},
        )
        write_decomp_tree(self._db(), tmp_path, conformance=False)
        assert calls == []

    def test_measurement_failure_never_fails_the_build(
            self, tmp_path, monkeypatch):
        from packages.ghidra import decomp_conformance

        def _boom(root, **kw):
            raise RuntimeError("measurement exploded")

        monkeypatch.setattr(
            decomp_conformance, "measure_conformance", _boom)
        tree = write_decomp_tree(self._db(), tmp_path)
        assert tree.functions_emitted == 1
        assert (tmp_path / "decomp-map.json").is_file()


def _git_available() -> bool:
    import shutil
    return shutil.which("git") is not None


class TestGitignoreLive:
    """Real-semgrep scope fence at the decomp-tree shape.

    Decomp-trees are emitted under run output directories that are
    routinely gitignored (RAPTOR's own ``out/`` is). The semgrep
    runner's default scope pins (``--no-git-ignore``,
    ``--x-ignore-semgrepignore-files`` in build_cmd) are all that keep
    this leg — and the decomp-tree sweep, which rides the same runner
    default — from reading such a tree as vacuously clean: rc 0, no
    errors, empty paths.scanned, every file "not examined",
    parsed_rate 0.0.

    The runner's own live scope tests pin that default on a python
    rule with a file-pattern ``.gitignore``, asserting on findings.
    This lane depends on a different shape: the C conformance probe
    (a never-matching rule), a directory-pattern ``.gitignore``
    (``out/``), a nested synthetic tree, and the ``files_examined``
    channel — the conformance leg reads paths.scanned, never
    findings. Pin the default on exactly that shape, in both
    directions that exist today: the default scans the tree, and a
    call site that duplicates ``--no-git-ignore`` through extra_args
    fails LOUDLY (semgrep refuses the repeated option at rc 2, an
    engine error) — never a silent scope change.

    Trusted local fixture content (authored here), hence
    ``unsandboxed=True`` — same posture as the runner's own live
    scope tests.
    """

    @staticmethod
    def _gitignored_tree(tmp_path: Path) -> Path:
        import subprocess
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True,
                       timeout=60)
        (repo / ".gitignore").write_text("out/\n", encoding="utf-8")
        tree = repo / "out" / "decomp-tree"
        tree.mkdir(parents=True)
        # Synthetic decompiler-shaped pseudo-C — authored fixture,
        # no target-derived content.
        (tree / "g001_FUN_00101000.c").write_text(
            "undefined8 FUN_00101000(long param_1)\n"
            "{\n  return *(undefined8 *)(param_1 + 8);\n}\n",
            encoding="utf-8",
        )
        return tree

    @pytest.mark.skipif(
        not _git_available(), reason="git not installed")
    def test_default_scans_gitignored_tree(self, tmp_path):
        """Regression fence for the runner's scope default: a bare
        run_rule on a decomp-tree under a gitignored directory of a
        git repo examines the tree's files. A revert of the default
        turns every such sweep/conformance scan vacuously clean —
        this fails first, on the exact shape this lane consumes."""
        from packages.ghidra.decomp_conformance import _PROBE_RULE
        from packages.semgrep.runner import is_available, run_rule
        if not is_available():
            pytest.skip("semgrep not installed")
        tree = self._gitignored_tree(tmp_path)

        result = run_rule(tree, str(_PROBE_RULE), timeout=300,
                          unsandboxed=True)
        assert result.returncode in (0, 1)
        assert result.errors == []
        assert any("g001_FUN_00101000.c" in str(p)
                   for p in result.files_examined)

    @pytest.mark.skipif(
        not _git_available(), reason="git not installed")
    def test_duplicated_scope_flag_errors_loudly(self, tmp_path):
        """Duplicate-flag direction: build_cmd already emits
        ``--no-git-ignore``; a call site that adds it again through
        extra_args (belt-and-braces) does not get a quietly-doubled
        no-op — semgrep refuses the repeated option (rc 2), and
        run_rule surfaces that as an engine error. Pins that the
        wrong belt-and-braces pattern fails LOUDLY at the first live
        scan instead of silently changing scan scope, and documents
        why call sites must leave the scope flags to the runner."""
        from packages.ghidra.decomp_conformance import _PROBE_RULE
        from packages.semgrep.runner import is_available, run_rule
        if not is_available():
            pytest.skip("semgrep not installed")
        tree = self._gitignored_tree(tmp_path)

        result = run_rule(tree, str(_PROBE_RULE), timeout=300,
                          unsandboxed=True,
                          extra_args=["--no-git-ignore"])
        assert result.returncode == 2
        assert result.errors
        assert result.files_examined == []


class TestChildScan:
    def test_scan_tree_verdicts(self, tmp_path):
        pytest.importorskip("tree_sitter")
        from core.inventory.extractors import _ts_parser_for
        if _ts_parser_for("c") is None:
            pytest.skip("tree-sitter C grammar unavailable")
        from packages.ghidra._conformance_child import scan_tree
        root = _tree(tmp_path, {
            "good.c": "int f(void) { return 0; }\n",
            "bad.c": "int broken( {{{ ;;\n",
        })
        out = scan_tree(str(root))
        assert out["available"] is True
        assert out["files"]["good.c"]["ok"] is True
        assert out["files"]["bad.c"]["ok"] is False
        assert out["files"]["bad.c"]["reason"]

    def test_scan_tree_degrades_without_grammar(
            self, tmp_path, monkeypatch):
        import core.inventory.extractors as ex
        monkeypatch.setattr(ex, "_ts_parser_for", lambda lang: None)
        from packages.ghidra._conformance_child import scan_tree
        root = _tree(tmp_path, {"g1.c": "int f(void) { return 0; }\n"})
        out = scan_tree(str(root))
        assert out["available"] is False
        assert "unavailable" in out["reason"]
