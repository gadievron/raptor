"""Tests for core.orchestration.firmware_enrichment — the firmware
high-value-target priority stamps and prefer-globs for /agentic."""

from __future__ import annotations

from core.orchestration.firmware_enrichment import (
    hvt_paths,
    hvt_prefer_globs,
    stamp_hvt_priority,
)

_INVENTORY = {
    "detected_arch": "mips",
    "total_elfs": 4,
    "high_value_targets": [
        {"path": "usr/sbin/uhttpd", "arch": "mips", "interest_score": 10},
        {"path": "www/cgi-bin/admin.cgi", "arch": "mips", "interest_score": 10},
    ],
}


def _checklist() -> dict:
    return {
        "files": [
            {
                "path": "www/cgi-bin/handler.c",
                "items": [
                    {"function": "do_auth"},
                    {"function": "helper", "priority": "low",
                     "priority_reason": "dead code"},
                ],
            },
            {
                "path": "usr/sbin/uhttpd",
                "items": [{"function": "main"}],
            },
            {
                "path": "lib/util.c",
                "items": [{"function": "trim"}],
            },
        ],
    }


class TestHvtPaths:
    def test_paths_in_inventory_order(self):
        assert hvt_paths(_INVENTORY) == [
            "usr/sbin/uhttpd", "www/cgi-bin/admin.cgi",
        ]

    def test_malformed_inventory(self):
        assert hvt_paths({}) == []
        assert hvt_paths({"high_value_targets": [{"nope": 1}, "x"]}) == []


class TestPreferGlobs:
    def test_suffix_and_directory_globs(self):
        globs = hvt_prefer_globs(_INVENTORY)
        assert "*usr/sbin/uhttpd" in globs
        assert "usr/sbin/*" in globs
        assert "*/usr/sbin/*" in globs
        assert "*www/cgi-bin/admin.cgi" in globs
        assert "www/cgi-bin/*" in globs

    def test_single_component_parent_gets_no_dir_glob(self):
        """A top-level parent like ``bin`` must not become a directory
        glob — ``*bin/*`` would fnmatch ``usr/sbin/...`` and half the
        tree."""
        inv = {"high_value_targets": [{"path": "bin/busybox"}]}
        globs = hvt_prefer_globs(inv)
        assert globs == ["*bin/busybox"]

    def test_cap(self):
        big = {"high_value_targets": [
            {"path": f"bin/daemon{i}"} for i in range(40)
        ]}
        assert len(hvt_prefer_globs(big, cap=20)) == 20


class TestStampPriority:
    def test_top_level_dir_does_not_match_everywhere(self):
        """HVT ``bin/busybox``: ``usr/local/bin/helper.sh`` must NOT be
        stamped (a bare ``bin`` dir must not match every /bin/ path)."""
        inv = {"high_value_targets": [{"path": "bin/busybox"}]}
        checklist = {"files": [
            {"path": "usr/local/bin/helper.sh", "items": [{"function": "f"}]},
            {"path": "bin/busybox", "items": [{"function": "main"}]},
        ]}
        assert stamp_hvt_priority(checklist, inv) == 1
        assert checklist["files"][0]["items"][0].get("priority") is None
        assert checklist["files"][1]["items"][0]["priority"] == "high"

    def test_stamps_hvt_files_and_sibling_dirs(self):
        checklist = _checklist()
        stamped = stamp_hvt_priority(checklist, _INVENTORY)
        # handler.c lives in the CGI target's directory; uhttpd IS a
        # target. util.c is neither. helper already had a priority.
        assert stamped == 2
        by_file = {f["path"]: f["items"] for f in checklist["files"]}
        assert by_file["www/cgi-bin/handler.c"][0]["priority"] == "high"
        assert "firmware" in by_file["www/cgi-bin/handler.c"][0]["priority_reason"]
        assert by_file["usr/sbin/uhttpd"][0]["priority"] == "high"
        assert by_file["lib/util.c"][0].get("priority") is None

    def test_existing_priority_not_overwritten(self):
        checklist = _checklist()
        stamp_hvt_priority(checklist, _INVENTORY)
        helper = checklist["files"][0]["items"][1]
        assert helper["priority"] == "low"
        assert helper["priority_reason"] == "dead code"

    def test_empty_inputs_are_noops(self):
        checklist = _checklist()
        assert stamp_hvt_priority(checklist, {}) == 0
        assert stamp_hvt_priority({}, _INVENTORY) == 0
        assert stamp_hvt_priority({"files": "nope"}, _INVENTORY) == 0


class TestGlobCompatibility:
    def test_globs_match_agent_fnmatch_semantics(self):
        """Joint pin: the globs this module emits must fnmatch the file
        paths findings actually carry (absolute or root-relative), the
        way the analysis agent's prefer matcher applies them."""
        import fnmatch

        globs = hvt_prefer_globs(_INVENTORY)

        def preferred(path: str) -> bool:
            return any(fnmatch.fnmatch(path, g) for g in globs)

        assert preferred("/work/fw/usr/sbin/uhttpd")
        assert preferred("usr/sbin/uhttpd")
        assert preferred("www/cgi-bin/handler.c")
        assert preferred("/work/fw/www/cgi-bin/handler.c")
        assert not preferred("lib/util.c")
        assert not preferred("/work/fw/lib/util.c")


class TestAttackSurfaceSources:
    def test_records_shape(self):
        from core.orchestration.firmware_enrichment import (
            hvt_attack_surface_sources,
        )
        sources = hvt_attack_surface_sources(_INVENTORY)
        assert len(sources) == 2
        assert sources[0] == {
            "type": "firmware_hvt",
            "entry": "usr/sbin/uhttpd (mips, interest 10)",
            "path": "usr/sbin/uhttpd",
            "trust_level": "attacker_controlled",
            "origin": "firmware-inventory",
        }


class TestAugmentFirmwareSurface:
    def test_backfills_and_is_idempotent(self):
        from core.orchestration.firmware_enrichment import (
            augment_firmware_surface,
        )
        context_map = {
            "entry_points": [
                # LLM already found the CGI — must not duplicate
                {"id": "EP-001", "type": "http_route",
                 "file": "www/cgi-bin/admin.cgi"},
            ],
            "sources": [],
        }
        added = augment_firmware_surface(context_map, _INVENTORY)
        assert added == 1
        fw_eps = [ep for ep in context_map["entry_points"]
                  if ep.get("origin") == "firmware-inventory"]
        assert [ep["file"] for ep in fw_eps] == ["usr/sbin/uhttpd"]
        assert fw_eps[0]["type"] == "firmware_service"
        assert len(context_map["sources"]) == 2
        # Second run adds nothing (origin/file dedup).
        assert augment_firmware_surface(context_map, _INVENTORY) == 0
        assert len(context_map["sources"]) == 2
        assert len(context_map["entry_points"]) == 2

    def test_empty_inputs(self):
        from core.orchestration.firmware_enrichment import (
            augment_firmware_surface,
        )
        assert augment_firmware_surface({}, {}) == 0
        assert augment_firmware_surface({"entry_points": "bad"}, _INVENTORY) == 0


class TestFindInventory:
    def test_scan_subdir_then_top_level(self, tmp_path):
        from core.orchestration.firmware_enrichment import (
            find_firmware_inventory,
        )
        assert find_firmware_inventory(tmp_path) is None
        (tmp_path / "firmware-inventory.json").write_text("{}")
        assert find_firmware_inventory(tmp_path).name == "firmware-inventory.json"
        (tmp_path / "scan").mkdir()
        (tmp_path / "scan" / "firmware-inventory.json").write_text("{}")
        assert find_firmware_inventory(tmp_path).parent.name == "scan"


class TestNormalizePassSeven:
    def test_normalize_context_map_runs_firmware_pass(self):
        from core.orchestration.understand_bridge import normalize_context_map
        context_map = {"entry_points": [], "sources": [], "sinks": []}
        normalize_context_map(context_map, {}, firmware_inventory=_INVENTORY)
        assert any(ep.get("origin") == "firmware-inventory"
                   for ep in context_map["entry_points"])

    def test_no_inventory_no_pass(self):
        from core.orchestration.understand_bridge import normalize_context_map
        context_map = {"entry_points": [], "sources": [], "sinks": []}
        normalize_context_map(context_map, {})
        assert context_map["entry_points"] == []


class TestInventoryDrift:
    def test_rescan_with_new_hvt_no_id_collision_no_dup_source(self):
        """A rescan that prepends a new HVT (or changes a score) must
        extend ids past the existing max and must not re-add a source
        for a binary already recorded."""
        from core.orchestration.firmware_enrichment import (
            augment_firmware_surface,
        )
        context_map = {"entry_points": [], "sources": []}
        augment_firmware_surface(context_map, _INVENTORY)
        drifted = {
            "high_value_targets": [
                {"path": "www/cgi-bin/login.cgi", "arch": "mips",
                 "interest_score": 10},
                # same binary, new score
                {"path": "usr/sbin/uhttpd", "arch": "mips",
                 "interest_score": 11},
            ],
        }
        augment_firmware_surface(context_map, drifted)
        ids = [ep["id"] for ep in context_map["entry_points"]]
        assert len(ids) == len(set(ids)), ids
        paths = [s["path"] for s in context_map["sources"]]
        assert paths.count("usr/sbin/uhttpd") == 1
