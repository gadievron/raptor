"""Tests for core.orchestration.context_map_sinks."""

from __future__ import annotations

from pathlib import Path

from core.orchestration.context_map_sinks import (
    _annotate_entry_points,
    _classify_sink_type,
    _merge_discovered_sinks,
    _merge_framework_apis,
    _next_sink_id,
    enrich_with_sink_discovery,
)
from core.inventory.sink_discovery import (
    FrameworkAPI,
    SinkDiscoveryResult,
    SinkInfo,
    TransitiveReach,
)


def _sample_result() -> SinkDiscoveryResult:
    return SinkDiscoveryResult(
        direct_sinks=[
            SinkInfo(
                file="src/handler.lua",
                function="run_cmd",
                line=42,
                target="os.execute",
            ),
            SinkInfo(
                file="src/util.lua",
                function="read_pipe",
                line=10,
                target="io.popen",
            ),
        ],
        transitive_reach=[
            TransitiveReach(
                file="src/handler.lua",
                function="dispatch",
                distance=1,
                sinks=["os.execute"],
            ),
        ],
        framework_apis=[
            FrameworkAPI(
                name="uci.get",
                caller_count=50,
                files=["a.lua", "b.lua", "c.lua"],
            ),
        ],
        dangerous_target_counts={"os.execute": 1, "io.popen": 1},
    )


class TestMergeDiscoveredSinks:
    def test_adds_new_sinks(self):
        context_map = {"sink_details": []}
        result = _sample_result()
        added = _merge_discovered_sinks(context_map, result)
        assert added == 2
        assert len(context_map["sink_details"]) == 2
        assert context_map["sink_details"][0]["source"] == "mechanical"
        assert context_map["sink_details"][0]["dangerous_target"] == "os.execute"

    def test_skips_existing_by_file_line(self):
        context_map = {
            "sink_details": [
                {"id": "SINK-001", "file": "src/handler.lua", "line": 42},
            ]
        }
        result = _sample_result()
        added = _merge_discovered_sinks(context_map, result)
        assert added == 1  # Only io.popen added, os.execute deduplicated

    def test_creates_sink_details_if_missing(self):
        context_map = {}
        result = _sample_result()
        added = _merge_discovered_sinks(context_map, result)
        assert added == 2
        assert "sink_details" in context_map

    def test_assigns_sequential_ids(self):
        context_map = {
            "sink_details": [
                {"id": "SINK-005", "file": "x.py", "line": 1},
            ]
        }
        result = _sample_result()
        _merge_discovered_sinks(context_map, result)
        ids = [s["id"] for s in context_map["sink_details"][1:]]
        assert ids == ["SINK-006", "SINK-007"]


class TestAnnotateEntryPoints:
    def test_adds_reachable_sinks(self):
        context_map = {
            "entry_points": [
                {"file": "src/handler.lua", "name": "run_cmd"},
                {"file": "src/handler.lua", "name": "dispatch"},
                {"file": "src/other.lua", "name": "safe_fn"},
            ]
        }
        result = _sample_result()
        enriched = _annotate_entry_points(context_map, result)
        assert enriched == 2  # run_cmd (direct) + dispatch (transitive)

        ep0 = context_map["entry_points"][0]
        assert "reachable_sinks" in ep0
        assert "os.execute" in ep0["reachable_sinks"]

        ep1 = context_map["entry_points"][1]
        assert "reachable_sinks" in ep1
        assert "os.execute" in ep1["reachable_sinks"]

        ep2 = context_map["entry_points"][2]
        assert "reachable_sinks" not in ep2

    def test_no_entry_points(self):
        context_map = {}
        result = _sample_result()
        enriched = _annotate_entry_points(context_map, result)
        assert enriched == 0


class TestMergeFrameworkApis:
    def test_adds_to_meta(self):
        context_map = {"meta": {}}
        result = _sample_result()
        _merge_framework_apis(context_map, result)
        discovered = context_map["meta"]["frameworks_discovered"]
        assert len(discovered) == 1
        assert discovered[0]["name"] == "uci.get"
        assert discovered[0]["source"] == "mechanical"

    def test_deduplicates_existing_frameworks(self):
        context_map = {
            "meta": {
                "frameworks": ["uci.get"],
            }
        }
        result = _sample_result()
        added = _merge_framework_apis(context_map, result)
        assert added == 0
        # No frameworks_discovered key should be created when nothing to add
        assert context_map["meta"].get("frameworks_discovered") is None or \
            len(context_map["meta"]["frameworks_discovered"]) == 0

    def test_creates_meta_if_missing(self):
        context_map = {}
        result = _sample_result()
        _merge_framework_apis(context_map, result)
        assert "meta" in context_map
        assert "frameworks_discovered" in context_map["meta"]


class TestClassifySinkType:
    def test_shell_execution(self):
        assert _classify_sink_type("os.execute") == "shell_execution"
        assert _classify_sink_type("subprocess.Popen") == "shell_execution"
        assert _classify_sink_type("io.popen") == "shell_execution"

    def test_code_execution(self):
        assert _classify_sink_type("eval") == "code_execution"
        assert _classify_sink_type("loadstring") == "code_execution"

    def test_deserialization(self):
        assert _classify_sink_type("pickle.loads") == "deserialization"

    def test_process_execution(self):
        assert _classify_sink_type("execve") == "process_execution"

    def test_fallback(self):
        assert _classify_sink_type("unknown_dangerous") == "dangerous_call"


class TestNextSinkId:
    def test_empty_list(self):
        assert _next_sink_id([]) == 1

    def test_with_existing(self):
        assert _next_sink_id([
            {"id": "SINK-003"},
            {"id": "SINK-007"},
        ]) == 8

    def test_non_numeric_ids_ignored(self):
        assert _next_sink_id([
            {"id": "SINK-abc"},
            {"id": "SINK-002"},
        ]) == 3


class TestEnrichWithSinkDiscovery:
    """Integration tests using Python files (stdlib ast — no tree-sitter)."""

    def test_integration(self, tmp_path: Path):
        target = tmp_path / "project"
        target.mkdir()
        (target / "handler.py").write_text(
            "import subprocess\n"
            "def run_cmd(cmd):\n"
            "    subprocess.call(cmd, shell=True)\n"
            "def dispatch(cmd):\n"
            "    run_cmd(cmd)\n"
        )

        context_map = {
            "entry_points": [
                {"file": "handler.py", "name": "dispatch"},
            ],
            "sink_details": [],
            "meta": {},
        }

        enriched = enrich_with_sink_discovery(context_map, target)
        assert enriched > 0
        assert len(context_map["sink_details"]) > 0
        assert "sink_discovery" in context_map

    def test_framework_only_target_persists(self, tmp_path: Path):
        """Target with framework APIs but no sinks still saves results."""
        target = tmp_path / "project"
        target.mkdir()
        for i in range(10):
            subdir = target / f"mod_{i}"
            subdir.mkdir()
            (subdir / f"f_{i}.py").write_text(
                f"import config\n"
                f"def fn_{i}():\n"
                f"    config.get('section')\n"
            )

        context_map = {
            "entry_points": [],
            "sink_details": [],
            "meta": {},
        }

        modified = enrich_with_sink_discovery(context_map, target)
        if context_map.get("sink_discovery", {}).get("framework_apis"):
            assert modified > 0

    def test_idempotent_no_growth(self, tmp_path: Path):
        """Running twice doesn't duplicate sinks or framework APIs."""
        target = tmp_path / "project"
        target.mkdir()
        (target / "cmd.py").write_text(
            "import os\n"
            "def run(c):\n"
            "    os.system(c)\n"
        )

        context_map = {
            "entry_points": [],
            "sink_details": [],
            "meta": {},
        }

        enrich_with_sink_discovery(context_map, target)
        sinks_after_first = len(context_map["sink_details"])
        fw_after_first = len(
            context_map.get("meta", {}).get("frameworks_discovered", [])
        )

        enrich_with_sink_discovery(context_map, target)
        assert len(context_map["sink_details"]) == sinks_after_first
        assert len(
            context_map.get("meta", {}).get("frameworks_discovered", [])
        ) == fw_after_first


class TestE2ELibexecShim:
    """E2E tests exercising the full libexec pipeline.

    Synthetic tests use Python files (stdlib ast extractor, no
    tree-sitter dependency — works in CI).
    """

    def test_e2e_synthetic_target(self, tmp_path: Path):
        """Full pipeline: synthetic Python target -> enriched context-map."""
        import json
        import subprocess

        target = tmp_path / "app"
        target.mkdir()
        (target / "views.py").write_text(
            "import subprocess\n"
            "def handle_cmd(cmd):\n"
            "    subprocess.Popen(cmd, shell=True)\n"
            "def safe_handler():\n"
            "    return 'ok'\n"
        )
        (target / "util.py").write_text(
            "import os\n"
            "def run_shell(cmd):\n"
            "    os.system(cmd)\n"
            "def wrap(cmd):\n"
            "    run_shell(cmd)\n"
        )

        workdir = tmp_path / "workdir"
        workdir.mkdir()
        (workdir / "checklist.json").write_text(json.dumps({
            "target_path": str(target),
        }))
        (workdir / "context-map.json").write_text(json.dumps({
            "entry_points": [
                {"id": "EP-001", "file": "views.py",
                 "name": "handle_cmd", "line": 2},
            ],
            "sink_details": [],
            "trust_boundaries": [],
            "meta": {},
        }))

        raptor_dir = Path(__file__).resolve().parents[3]
        result = subprocess.run(
            ["python3", str(raptor_dir / "libexec" / "raptor-enrich-context-map-sinks"),
             str(workdir)],
            capture_output=True, text=True,
            env={
                **dict(__import__("os").environ),
                "_RAPTOR_TRUSTED": "1",
                "RAPTOR_DIR": str(raptor_dir),
            },
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "enriched" in result.stdout

        with open(workdir / "context-map.json") as f:
            cm = json.load(f)

        mech_sinks = [
            s for s in cm["sink_details"]
            if s.get("source") == "mechanical"
        ]
        assert len(mech_sinks) >= 2
        targets = {s["dangerous_target"] for s in mech_sinks}
        assert targets & {"subprocess.Popen", "os.system"}

        ep = cm["entry_points"][0]
        assert "reachable_sinks" in ep
        assert "subprocess.Popen" in ep["reachable_sinks"]

        assert "sink_discovery" in cm
        sd = cm["sink_discovery"]
        assert len(sd["direct_sinks"]) >= 2

        for s in mech_sinks:
            assert "id" in s
            assert s["id"].startswith("SINK-")
            assert "type" in s
            assert s["type"] in {
                "shell_execution", "code_execution",
                "deserialization", "process_execution",
                "dangerous_call",
            }

        # Verify idempotency
        result2 = subprocess.run(
            ["python3", str(raptor_dir / "libexec" / "raptor-enrich-context-map-sinks"),
             str(workdir)],
            capture_output=True, text=True,
            env={
                **dict(__import__("os").environ),
                "_RAPTOR_TRUSTED": "1",
                "RAPTOR_DIR": str(raptor_dir),
            },
        )
        assert result2.returncode == 0

        with open(workdir / "context-map.json") as f:
            cm2 = json.load(f)

        mech_sinks2 = [
            s for s in cm2["sink_details"]
            if s.get("source") == "mechanical"
        ]
        assert len(mech_sinks2) == len(mech_sinks)
