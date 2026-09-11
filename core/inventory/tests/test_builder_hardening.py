"""Builder input-hardening and cache-correctness regressions.

Covers: computed ``__all__`` handling, coverage carry-forward merge
semantics and key granularity, parse-fingerprint invalidation for
explicit output dirs, legacy checklist entries, single-file shebang
targets, scope validation, walk-time exclude honouring, FIFO-safe file
collection, and surrogate-safe cache keys.

Hermetic: every build here runs on a tiny tempdir tree (sequential
path — no worker pools), no network, no external binaries.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from core.inventory.builder import (
    _carry_forward_coverage,
    _collect_source_files,
    _extract_python_dunder_all,
    _is_github_workflow,
    build_inventory,
    default_cache_dir,
)


# ---------------------------------------------------------------------------
# __all__ extraction
# ---------------------------------------------------------------------------


class TestDunderAll:
    def test_literal_list(self):
        assert _extract_python_dunder_all("__all__ = ['a', 'b']") == ["a", "b"]

    def test_no_declaration(self):
        assert _extract_python_dunder_all("x = 1") is None

    def test_computed_comprehension_is_unknown_not_empty(self):
        # [] would read as an authoritative "nothing exported" and turn
        # every public function into a confident dead-island candidate.
        assert _extract_python_dunder_all(
            "__all__ = [n for n in dir() if not n.startswith('_')]"
        ) is None

    def test_computed_call_is_unknown(self):
        assert _extract_python_dunder_all(
            "REGISTRY = {}\n__all__ = list(REGISTRY)\n") is None

    def test_augassign_extends(self):
        assert _extract_python_dunder_all(
            "__all__ = ['a']\n__all__ += ['b']\n") == ["a", "b"]

    def test_append_and_extend_literals(self):
        assert _extract_python_dunder_all(
            "__all__ = ['a']\n__all__.append('b')\n__all__.extend(['c'])\n"
        ) == ["a", "b", "c"]

    def test_non_literal_extension_degrades_to_unknown(self):
        assert _extract_python_dunder_all(
            "__all__ = ['a']\n__all__.extend(make())\n") is None
        assert _extract_python_dunder_all(
            "__all__ = ['a']\n__all__ += make()\n") is None

    def test_reassignment_replaces(self):
        assert _extract_python_dunder_all(
            "__all__ = ['a']\n__all__ = ['b']\n") == ["b"]


# ---------------------------------------------------------------------------
# Coverage carry-forward
# ---------------------------------------------------------------------------


def _inv(path: str, items: list[dict]) -> dict:
    return {"files": [{"path": path, "items": items}]}


class TestCarryForwardCoverage:
    def test_same_named_twins_do_not_smear(self):
        old = _inv("a.py", [
            {"name": "run", "kind": "function", "checked_by": ["scan-1"]},
            {"name": "run", "kind": "function"},
        ])
        new = _inv("a.py", [
            {"name": "run", "kind": "function"},
            {"name": "run", "kind": "function"},
        ])
        _carry_forward_coverage(old, new)
        items = new["files"][0]["items"]
        assert items[0].get("checked_by") == ["scan-1"]
        assert not items[1].get("checked_by")

    def test_merge_is_union_not_overwrite(self):
        # The multi-run promotion applies OLDER checklists onto the
        # newest; an overwrite regressed fresh marks to stale ones.
        older = _inv("a.py", [
            {"name": "run", "kind": "function", "checked_by": ["stale-old"]},
        ])
        promoted = _inv("a.py", [
            {"name": "run", "kind": "function", "checked_by": ["newest"]},
        ])
        _carry_forward_coverage(older, promoted)
        assert promoted["files"][0]["items"][0]["checked_by"] == [
            "newest", "stale-old"]

    def test_duplicate_runs_not_repeated(self):
        older = _inv("a.py", [
            {"name": "f", "kind": "function", "checked_by": ["r1", "r2"]},
        ])
        promoted = _inv("a.py", [
            {"name": "f", "kind": "function", "checked_by": ["r1"]},
        ])
        _carry_forward_coverage(older, promoted)
        assert promoted["files"][0]["items"][0]["checked_by"] == ["r1", "r2"]

    def test_modified_files_cleared(self):
        old = _inv("a.py", [
            {"name": "f", "kind": "function", "checked_by": ["r1"]},
        ])
        new = _inv("a.py", [{"name": "f", "kind": "function"}])
        _carry_forward_coverage(old, new, modified={"a.py"})
        assert not new["files"][0]["items"][0].get("checked_by")

    def test_legacy_functions_key_still_read(self):
        old = {"files": [{"path": "a.py", "functions": [
            {"name": "f", "kind": "function", "checked_by": ["r1"]},
        ]}]}
        new = _inv("a.py", [{"name": "f", "kind": "function"}])
        _carry_forward_coverage(old, new)
        assert new["files"][0]["items"][0]["checked_by"] == ["r1"]


# ---------------------------------------------------------------------------
# Parse-fingerprint invalidation (explicit output_dir)
# ---------------------------------------------------------------------------


def _write_compile_commands(root: Path, entries: list[str]) -> None:
    (root / "compile_commands.json").write_text(json.dumps([
        {"directory": str(root), "command": f"cc -c {e}",
         "file": str(root / e)} for e in entries
    ]))


class TestParseFingerprint:
    def test_compile_commands_change_clears_stale_build_excluded(
        self, tmp_path: Path,
    ) -> None:
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int f(void) { return 1; }\n")
        (target / "b.c").write_text("int g(void) { return 2; }\n")
        out = tmp_path / "out"
        _write_compile_commands(target, ["b.c"])
        inv1 = build_inventory(str(target), output_dir=str(out),
                               parallel=False)
        rec1 = {f["path"]: f for f in inv1["files"]}
        assert "build_excluded" in rec1["a.c"]
        # a.c joins the build; its bytes and stat are unchanged, so the
        # per-file fast path alone would return the stale record.
        _write_compile_commands(target, ["a.c", "b.c"])
        inv2 = build_inventory(str(target), output_dir=str(out),
                               parallel=False)
        rec2 = {f["path"]: f for f in inv2["files"]}
        assert "build_excluded" not in rec2["a.c"]

    def test_unchanged_config_keeps_fast_path(self, tmp_path: Path) -> None:
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.py").write_text("def f():\n    pass\n")
        out = tmp_path / "out"
        build_inventory(str(target), output_dir=str(out), parallel=False)
        inv2 = build_inventory(str(target), output_dir=str(out),
                               parallel=False)
        assert inv2.get("source_unchanged") is True


# ---------------------------------------------------------------------------
# Legacy checklist entries ('functions' key)
# ---------------------------------------------------------------------------


def test_legacy_functions_key_checklist_is_reusable(tmp_path: Path) -> None:
    target = tmp_path / "src"
    target.mkdir()
    (target / "x.py").write_text("def f():\n    pass\n")
    out = tmp_path / "out"
    build_inventory(str(target), output_dir=str(out), parallel=False)
    checklist = out / "checklist.json"
    data = json.loads(checklist.read_text())
    for f in data["files"]:
        f["functions"] = f.pop("items")
    checklist.write_text(json.dumps(data))
    # Pre-fix: KeyError 'items' in sequential mode; parallel mode
    # dropped every unchanged file as processing_error.
    inv = build_inventory(str(target), output_dir=str(out), parallel=False)
    assert inv["total_files"] == 1
    assert not any(e["reason"] == "processing_error"
                   for e in inv["excluded_files"])


# ---------------------------------------------------------------------------
# Single-file targets
# ---------------------------------------------------------------------------


def test_single_file_shebang_script_target(tmp_path: Path) -> None:
    script = tmp_path / "deploy"
    script.write_text("#!/usr/bin/env python3\nprint(1)\n")
    inv = build_inventory(str(script), output_dir=str(tmp_path / "out"),
                          parallel=False)
    assert inv["total_files"] == 1


def test_single_file_unknown_extension_still_rejected(
    tmp_path: Path,
) -> None:
    f = tmp_path / "data.bin"
    f.write_text("not source")
    with pytest.raises(ValueError, match="no recognized source extension"):
        build_inventory(str(f), output_dir=str(tmp_path / "out"))


# ---------------------------------------------------------------------------
# Scope validation
# ---------------------------------------------------------------------------


class TestScopeValidation:
    @pytest.fixture()
    def target(self, tmp_path: Path) -> Path:
        t = tmp_path / "proj"
        (t / "src").mkdir(parents=True)
        (t / "src" / "m.py").write_text("def f():\n    pass\n")
        (t / "other.py").write_text("def g():\n    pass\n")
        return t

    def test_absolute_scope_outside_target_rejected(
        self, target: Path, tmp_path: Path,
    ) -> None:
        # pathlib joins DISCARD the lhs for absolute rhs — pre-fix the
        # inventory silently emptied instead of erroring.
        with pytest.raises(ValueError, match="escapes the target"):
            build_inventory(str(target),
                            output_dir=str(tmp_path / "out"),
                            scope=["/somewhere/src"])

    def test_root_scope_rejected(self, target: Path, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="escapes the target"):
            build_inventory(str(target),
                            output_dir=str(tmp_path / "out"), scope=["/"])

    def test_dotdot_scope_rejected(self, target: Path,
                                   tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="escapes the target"):
            build_inventory(str(target),
                            output_dir=str(tmp_path / "out"),
                            scope=["../escape"])

    def test_relative_scope_filters(self, target: Path,
                                    tmp_path: Path) -> None:
        inv = build_inventory(str(target),
                              output_dir=str(tmp_path / "out"),
                              scope=["src"], parallel=False)
        assert [f["path"] for f in inv["files"]] == ["src/m.py"]

    def test_absolute_scope_under_target_accepted(
        self, target: Path, tmp_path: Path,
    ) -> None:
        inv = build_inventory(str(target),
                              output_dir=str(tmp_path / "out"),
                              scope=[str(target / "src")], parallel=False)
        assert [f["path"] for f in inv["files"]] == ["src/m.py"]


# ---------------------------------------------------------------------------
# Walk-time exclude honouring
# ---------------------------------------------------------------------------


class TestWalkHonoursCallerExcludes:
    def test_empty_exclude_list_reincludes_default_dirs(
        self, tmp_path: Path,
    ) -> None:
        t = tmp_path / "proj"
        (t / "vendor").mkdir(parents=True)
        (t / "vendor" / "v.py").write_text("def v():\n    pass\n")
        (t / "main.py").write_text("def m():\n    pass\n")
        inv = build_inventory(str(t), output_dir=str(tmp_path / "o1"),
                              exclude_patterns=[], parallel=False)
        assert "vendor/v.py" in [f["path"] for f in inv["files"]]
        # Artifact truthfulness: the applied list is the recorded list.
        assert inv["excluded_patterns"] == []

    def test_default_excludes_still_prune(self, tmp_path: Path) -> None:
        t = tmp_path / "proj"
        (t / "vendor").mkdir(parents=True)
        (t / "vendor" / "v.py").write_text("def v():\n    pass\n")
        (t / "main.py").write_text("def m():\n    pass\n")
        inv = build_inventory(str(t), output_dir=str(tmp_path / "o2"),
                              parallel=False)
        assert "vendor/v.py" not in [f["path"] for f in inv["files"]]


# ---------------------------------------------------------------------------
# FIFO-safe collection
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX-only FIFO test")
def test_collection_ignores_fifos(tmp_path: Path) -> None:
    """The extensionless-shebang probe opens directory entries in the
    MAIN process; a plain open() of a reader-less FIFO blocks forever
    and wedged the whole inventory build."""
    (tmp_path / "a.py").write_text("def f():\n    pass\n")
    os.mkfifo(tmp_path / "apipe")
    files, _pruned = _collect_source_files(tmp_path, {".py"})
    assert [f.name for f in files] == ["a.py"]


# ---------------------------------------------------------------------------
# Workflow predicate parity with the yaml extractor
# ---------------------------------------------------------------------------


def test_jobs_block_without_trigger_key_is_workflow_shaped() -> None:
    # The extractor emits job items for any top-level jobs: block; the
    # builder gate must not additionally require a trigger key (Azure
    # Pipelines yaml, or a roundtripped workflow whose on: became
    # true:, was excluded as unreviewable).
    azure = "trigger:\n- main\njobs:\n  build:\n    steps: []\n"
    assert _is_github_workflow("ci/pipeline.yml", azure)
    assert not _is_github_workflow("cfg/app.yml", "server:\n  port: 80\n")
    # Scalar jobs value — the extractor yields nothing for it either.
    assert not _is_github_workflow("config.yml", "jobs: none\n")


# ---------------------------------------------------------------------------
# Surrogate-safe cache keys
# ---------------------------------------------------------------------------


def test_default_cache_dir_accepts_surrogate_paths() -> None:
    # Filesystem paths need not be valid UTF-8; a strict encode raised
    # UnicodeEncodeError before any inventory work started.
    p = default_cache_dir("/tmp/bad\udcff-dir")
    assert len(p.name) == 16
