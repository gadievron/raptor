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
