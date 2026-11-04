"""Runtime discovery must not turn relative paths into cwd-based grants."""

from types import SimpleNamespace

import pytest

from core.sandbox import python_paths


@pytest.mark.parametrize("attribute,value", [
    ("prefix", "runtime"),
    ("base_prefix", "runtime"),
    ("exec_prefix", "runtime"),
    ("base_exec_prefix", "runtime"),
    ("executable", "runtime/python3"),
    ("executable", "python3"),
    ("prefix", "."),
    ("prefix", ".."),
])
def test_relative_runtime_candidate_is_skipped(
    tmp_path, monkeypatch, attribute, value,
):
    (tmp_path / "runtime").mkdir()
    (tmp_path / "bin").mkdir()
    monkeypatch.setattr(python_paths, "_home_roots", lambda: (tmp_path,))
    monkeypatch.chdir(tmp_path)
    interpreter = SimpleNamespace(**{attribute: value})
    monkeypatch.setattr(python_paths, "sys", interpreter)
    assert python_paths.python_runtime_tool_paths() == []


def test_relative_candidate_does_not_hide_absolute_runtime(tmp_path, monkeypatch):
    valid = tmp_path / "absolute-runtime"
    valid.mkdir()
    (tmp_path / "relative-runtime").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(python_paths, "sys", SimpleNamespace(
        prefix="relative-runtime", base_prefix=str(valid), executable="python3",
    ))
    assert python_paths.python_runtime_tool_paths() == [str(valid.resolve())]
