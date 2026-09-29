"""Tests for Ghidra diff priority filter."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from packages.ghidra.diff_priority import (
    _load_changed_names,
    apply_diff_priority,
)


@pytest.fixture()
def version_diff(tmp_path):
    diff = {
        "added": [
            {"name": "new_handler", "address": 0x1000, "size": 100},
            {"name": "FUN_00402000", "address": 0x2000, "size": 50},
        ],
        "changed": [
            {"name": "parse_input", "old_size": 100, "new_size": 120},
        ],
        "removed": [
            {"name": "old_func", "address": 0x3000, "size": 80},
        ],
    }
    path = tmp_path / "version-diff.json"
    path.write_text(json.dumps(diff))
    return path


@pytest.fixture()
def checklist(tmp_path):
    data = {
        "files": [
            {
                "path": "src/main.c",
                "items": [
                    {"function": "parse_input", "name": "parse_input", "priority": "medium"},
                    {"function": "new_handler", "name": "new_handler"},
                    {"function": "unrelated_func", "name": "unrelated_func", "priority": "low"},
                    {"function": "old_func", "name": "old_func"},
                ],
            },
        ],
    }
    path = tmp_path / "checklist.json"
    path.write_text(json.dumps(data))
    return path


class TestLoadChangedNames:
    def test_extracts_added_and_changed(self, version_diff):
        names = _load_changed_names(version_diff)
        assert "new_handler" in names
        assert "FUN_00402000" in names
        assert "parse_input" in names

    def test_excludes_removed(self, version_diff):
        names = _load_changed_names(version_diff)
        assert "old_func" not in names

    def test_empty_diff(self, tmp_path):
        path = tmp_path / "empty.json"
        path.write_text(json.dumps({}))
        names = _load_changed_names(path)
        assert names == set()

    def test_skips_empty_names(self, tmp_path):
        path = tmp_path / "diff.json"
        path.write_text(json.dumps({
            "added": [{"name": ""}, {"name": "real_func"}],
        }))
        names = _load_changed_names(path)
        assert names == {"real_func"}


class TestApplyDiffPriority:
    def test_boosts_changed_functions(self, tmp_path, version_diff, checklist):
        with patch(
            "packages.ghidra.diff_priority._find_version_diff",
            return_value=version_diff,
        ):
            n = apply_diff_priority(tmp_path, checklist)

        assert n == 2

        with open(checklist) as f:
            data = json.load(f)
        items = data["files"][0]["items"]

        parse = next(i for i in items if i["function"] == "parse_input")
        assert parse["priority"] == "high"
        assert "ghidra-diff" in parse.get("priority_reason", "")

        new = next(i for i in items if i["function"] == "new_handler")
        assert new["priority"] == "high"
        assert "ghidra-diff" in new.get("priority_reason", "")

    def test_unrelated_not_boosted(self, tmp_path, version_diff, checklist):
        with patch(
            "packages.ghidra.diff_priority._find_version_diff",
            return_value=version_diff,
        ):
            apply_diff_priority(tmp_path, checklist)

        with open(checklist) as f:
            data = json.load(f)
        items = data["files"][0]["items"]
        unrelated = next(
            i for i in items if i["function"] == "unrelated_func"
        )
        assert unrelated["priority"] == "low"

    def test_already_high_not_double_boosted(self, tmp_path, version_diff):
        data = {
            "files": [{
                "path": "src/main.c",
                "items": [
                    {"function": "parse_input", "name": "parse_input", "priority": "high"},
                ],
            }],
        }
        cl = tmp_path / "checklist.json"
        cl.write_text(json.dumps(data))

        with patch(
            "packages.ghidra.diff_priority._find_version_diff",
            return_value=version_diff,
        ):
            n = apply_diff_priority(tmp_path, cl)

        assert n == 0

    def test_no_diff_returns_zero(self, tmp_path, checklist):
        with patch(
            "packages.ghidra.diff_priority._find_version_diff",
            return_value=None,
        ):
            n = apply_diff_priority(tmp_path, checklist)
        assert n == 0

    def test_empty_diff_returns_zero(self, tmp_path, checklist):
        empty = tmp_path / "empty-diff.json"
        empty.write_text(json.dumps({}))
        with patch(
            "packages.ghidra.diff_priority._find_version_diff",
            return_value=empty,
        ):
            n = apply_diff_priority(tmp_path, checklist)
        assert n == 0

    def test_name_key_fallback(self, tmp_path, version_diff):
        data = {
            "files": [{
                "path": "src/main.c",
                "items": [
                    {"name": "parse_input"},
                ],
            }],
        }
        cl = tmp_path / "checklist.json"
        cl.write_text(json.dumps(data))

        with patch(
            "packages.ghidra.diff_priority._find_version_diff",
            return_value=version_diff,
        ):
            n = apply_diff_priority(tmp_path, cl)

        assert n == 1
        with open(cl) as f:
            result = json.load(f)
        assert result["files"][0]["items"][0]["priority"] == "high"

    def test_appends_to_existing_reason(self, tmp_path, version_diff):
        data = {
            "files": [{
                "path": "src/main.c",
                "items": [
                    {
                        "function": "parse_input",
                        "name": "parse_input",
                        "priority": "low",
                        "priority_reason": "binary-oracle: symbol present",
                    },
                ],
            }],
        }
        cl = tmp_path / "checklist.json"
        cl.write_text(json.dumps(data))

        with patch(
            "packages.ghidra.diff_priority._find_version_diff",
            return_value=version_diff,
        ):
            n = apply_diff_priority(tmp_path, cl)

        assert n == 1
        with open(cl) as f:
            result = json.load(f)
        reason = result["files"][0]["items"][0]["priority_reason"]
        assert "binary-oracle" in reason
        assert "ghidra-diff" in reason


class TestChecklistWriteChokepoint:
    def test_boost_write_routes_through_update_checklist(
        self, tmp_path, version_diff, checklist,
    ):
        """checklist.json has concurrent lock-free readers and an
        integrity token minted only at the core.inventory write
        chokepoint — the boost write must route through the
        ``update_checklist`` RMW (flock + atomic replace + re-stamp),
        never a raw load + save that preserves a stale frame token
        (which would read back tampered and brick the checklist)."""
        import core.inventory as inv

        real_update = inv.update_checklist
        calls = []

        def spy(output_dir, transform_fn):
            calls.append(Path(output_dir))
            return real_update(output_dir, transform_fn)

        with patch(
            "packages.ghidra.diff_priority._find_version_diff",
            return_value=version_diff,
        ), patch.object(inv, "update_checklist", spy):
            n = apply_diff_priority(tmp_path, checklist)

        assert n == 2
        assert tmp_path in calls
        # And the content survived the accessor path.
        data = json.loads(checklist.read_text())
        parse = next(
            i for i in data["files"][0]["items"]
            if i["function"] == "parse_input"
        )
        assert parse["priority"] == "high"

    def test_stamped_checklist_stays_verified_after_boost(
        self, tmp_path, version_diff,
    ):
        """A frame-stamped checklist run through apply_diff_priority
        must still read VERIFIED afterward — the boost write re-mints
        the token instead of preserving the stale one."""
        from core.inventory import checklist_frame_mac, read_checklist, save_checklist

        save_checklist(tmp_path, {
            "files": [{
                "path": "src/main.c",
                "items": [
                    {"function": "parse_input", "name": "parse_input",
                     "priority": "medium"},
                ],
            }],
        })
        cl = tmp_path / "checklist.json"
        assert checklist_frame_mac.FRAME_TOKEN_KEY in json.loads(cl.read_text())

        with patch(
            "packages.ghidra.diff_priority._find_version_diff",
            return_value=version_diff,
        ):
            n = apply_diff_priority(tmp_path, cl)

        assert n == 1
        on_disk = json.loads(cl.read_text())
        assert checklist_frame_mac.frame_provenance(
            on_disk, checklist_frame_mac.frame_binding(tmp_path),
            checklist_frame_mac.FORM_SINGLE,
        ) == checklist_frame_mac.FRAME_VERIFIED
        data = read_checklist(tmp_path)
        assert data["files"][0]["items"][0]["priority"] == "high"

    def test_tampered_checklist_never_boosted_or_laundered(
        self, tmp_path, version_diff,
    ):
        """A tampered frame is refused by the gated read: no boost,
        and the artifact is left byte-identical (never rewritten
        under a fresh stamp)."""
        from core.inventory import save_checklist

        save_checklist(tmp_path, {
            "files": [{
                "path": "src/main.c",
                "items": [
                    {"function": "parse_input", "name": "parse_input",
                     "priority": "medium"},
                ],
            }],
        })
        cl = tmp_path / "checklist.json"
        on_disk = json.loads(cl.read_text())
        on_disk["files"][0]["items"][0]["priority"] = "low"  # in-place edit
        cl.write_text(json.dumps(on_disk))
        before = cl.read_text()

        with patch(
            "packages.ghidra.diff_priority._find_version_diff",
            return_value=version_diff,
        ):
            n = apply_diff_priority(tmp_path, cl)

        assert n == 0
        assert cl.read_text() == before


class TestFindVersionDiffOutBase:
    def test_fallback_glob_uses_configured_out_base(
            self, tmp_path, monkeypatch):
        # A bare Path("out") resolved against the process CWD — any
        # caller not launched from the repo root silently got "no
        # version diff" (diff priority skipped, no error).
        from packages.ghidra.diff_priority import _find_version_diff

        out_base = tmp_path / "custom-out"
        diff_dir = out_base / "ghidra-diff-20260914"
        diff_dir.mkdir(parents=True)
        (diff_dir / "version-diff.json").write_text('{"added": []}')

        from core.config import RaptorConfig
        monkeypatch.setattr(
            RaptorConfig, "get_out_dir", staticmethod(lambda: out_base))

        # A project resolves but carries no diff in its run dirs —
        # the glob fallback lane. It must search the CONFIGURED base
        # even from a foreign CWD.
        class _Project:
            def get_run_dirs(self):
                return []

        class _Mgr:
            def find_project_for_target(self, target):
                return _Project()

        import core.project.project as project_mod
        monkeypatch.setattr(project_mod, "ProjectManager", _Mgr)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        found = _find_version_diff(tmp_path / "no-such-target")
        assert found == diff_dir / "version-diff.json"
