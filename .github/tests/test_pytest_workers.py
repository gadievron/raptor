"""Keep narrow selections cheap and broad selections bounded."""

import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "ci_pytest_workers", Path(__file__).resolve().parents[1] / "scripts/pytest_workers.py",
)
workers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(workers)


def test_cases_from_one_file_stay_serial(tmp_path):
    source = tmp_path / "test_one.py"
    source.touch()
    assert workers.worker_count([f"{source}::test_a", f"{source}::test_b"]) == 0


def test_more_files_cannot_exceed_the_runner_limit(tmp_path):
    files = [tmp_path / f"test_{i}.py" for i in range(8)]
    for source in files:
        source.touch()
    assert workers.worker_count(list(map(str, files))) == 2
    assert workers.worker_count(list(map(str, files)), maximum=1) == 0


def test_directory_selections_allow_parallel_collection(tmp_path):
    assert workers.worker_count([str(tmp_path)]) == 2


def test_aliases_of_one_module_do_not_spawn_an_idle_worker(tmp_path, monkeypatch):
    source = tmp_path / "test_one.py"
    source.touch()
    monkeypatch.chdir(tmp_path)
    assert workers.worker_count([str(source), "./test_one.py"]) == 0


@pytest.mark.parametrize("targets,maximum", [([], 2), (["missing.py"], 2), (["."], 0)])
def test_invalid_plans_fail_instead_of_running_an_empty_selection(targets, maximum):
    with pytest.raises(ValueError):
        workers.worker_count(targets, maximum=maximum)
