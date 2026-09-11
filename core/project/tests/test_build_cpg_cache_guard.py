"""'No project active' guard in ``libexec/raptor-build-cpg-cache``.

The CPG cache is one slot per cache dir; a standalone (project-less)
run's parent is the shared ``out/`` directory, where runs against
different targets would evict each other's cache. The guard must skip
standalone run dirs and only build into managed project dirs.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-build-cpg-cache"


@pytest.fixture(scope="module")
def cpg_cli():
    prior = os.environ.get("_RAPTOR_TRUSTED")
    os.environ["_RAPTOR_TRUSTED"] = "1"
    try:
        loader = importlib.machinery.SourceFileLoader(
            "raptor_build_cpg_cache", str(SCRIPT),
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        yield mod
    finally:
        if prior is None:
            os.environ.pop("_RAPTOR_TRUSTED", None)
        else:
            os.environ["_RAPTOR_TRUSTED"] = prior


def _make_understand_dir(tmp_path: Path) -> Path:
    understand_dir = tmp_path / "out" / "understand_1"
    understand_dir.mkdir(parents=True)
    target = tmp_path / "src"
    target.mkdir()
    (understand_dir / "checklist.json").write_text(
        json.dumps({"target_path": str(target)}), encoding="utf-8",
    )
    return understand_dir


def _run_main(cpg_cli, monkeypatch, understand_dir: Path,
              is_project: bool) -> tuple[int, list]:
    import packages.joern.prereqs as prereqs
    import packages.joern.runner as runner
    from core.project import project as project_mod

    monkeypatch.setattr(prereqs, "is_available", lambda: True)
    monkeypatch.setattr(
        project_mod, "is_project_output_dir",
        lambda directory, exact=False: is_project,
    )

    built: list = []

    class _FakeCpg:
        path = understand_dir.parent / "joern-cpg" / "cpg.bin"
        build_time_ms = 1

        def exists(self) -> bool:
            return True

    monkeypatch.setattr(runner, "load_cached_cpg", lambda t, d: None)
    monkeypatch.setattr(
        runner, "build_cpg_cached",
        lambda t, d: built.append((t, d)) or _FakeCpg(),
    )
    monkeypatch.setattr(
        "sys.argv", ["raptor-build-cpg-cache", str(understand_dir)],
    )
    return cpg_cli.main(), built


class TestNoProjectGuard:
    def test_standalone_run_skips(self, cpg_cli, monkeypatch,
                                  tmp_path: Path, capsys):
        understand_dir = _make_understand_dir(tmp_path)
        rc, built = _run_main(
            cpg_cli, monkeypatch, understand_dir, is_project=False,
        )
        assert rc == 0
        assert built == []
        assert "no project active" in capsys.readouterr().out

    def test_project_run_builds(self, cpg_cli, monkeypatch,
                                tmp_path: Path):
        understand_dir = _make_understand_dir(tmp_path)
        rc, built = _run_main(
            cpg_cli, monkeypatch, understand_dir, is_project=True,
        )
        assert rc == 0
        assert len(built) == 1
        # Cache lands in the project dir (the run dir's parent).
        assert built[0][1] == understand_dir.parent
