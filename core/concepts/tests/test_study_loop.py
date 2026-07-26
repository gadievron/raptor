"""Tests for libexec/raptor-study-loop orchestrator."""

import subprocess
import sys
from pathlib import Path

RAPTOR_DIR = Path(__file__).resolve().parents[3]
STUDY_LOOP = str(RAPTOR_DIR / "libexec" / "raptor-study-loop")


def _run_loop(args: list[str], env_extra: dict | None = None) -> subprocess.CompletedProcess:
    """Run study-loop with trust marker set."""
    import os
    env = os.environ.copy()
    env["_RAPTOR_TRUSTED"] = "1"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, STUDY_LOOP] + args,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


class TestStudyLoopCLI:
    def test_help(self):
        result = _run_loop(["--help"])
        assert result.returncode == 0
        assert "Multi-pass" in result.stdout

    def test_missing_target_produces_no_items(self, tmp_path):
        result = _run_loop(["/nonexistent/target", str(tmp_path)])
        # study-prep handles missing dirs gracefully (0 files → 0 items)
        assert "no study items" in result.stderr.lower() or result.returncode == 0

    def test_creates_output_dir(self, tmp_path):
        out = tmp_path / "loop-out"
        # Will fail because target has no C files, but output dir should exist
        target = tmp_path / "src"
        target.mkdir()
        _run_loop([str(target), str(out)])
        assert out.is_dir()


class TestStudyLoopConvergence:
    """Test that the loop terminates correctly."""

    def test_empty_target_terminates(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        out = tmp_path / "out"
        result = _run_loop([str(target), str(out)])
        assert "no study items" in result.stderr.lower() or result.returncode == 0


class TestReadingListDrain:
    """Test reading-list integration in the loop."""

    def test_reading_list_items_extracted(self):
        """Verify the helper that extracts identifiers from reading list."""
        import importlib.util
        import os
        os.environ["_RAPTOR_TRUSTED"] = "1"
        sys.path.insert(0, str(RAPTOR_DIR))

        spec = importlib.util.spec_from_file_location(
            "study_loop", STUDY_LOOP,
            submodule_search_locations=[],
        )
        if spec is None or spec.loader is None:
            # Fallback: exec the file directly and grab the function
            import types
            mod = types.ModuleType("study_loop")
            mod.__file__ = STUDY_LOOP
            exec(
                compile(
                    Path(STUDY_LOOP).read_text(encoding="utf-8"),
                    STUDY_LOOP, "exec",
                ),
                mod.__dict__,
            )
        else:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

        pending = [
            {"question": "struct page ownership", "resolution": "identifier",
             "context": "Need to understand `page` lifecycle"},
            {"question": "memory aliasing semantics", "resolution": "concept",
             "context": ""},
        ]
        idents, concepts = mod._extract_rl_identifiers(pending)
        assert "page" in idents
        assert "memory aliasing semantics" in concepts
