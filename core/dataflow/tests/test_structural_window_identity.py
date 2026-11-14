import functools

import pytest

from core.dataflow import structural_validator as sv
from core.testing.module_state import isolated_module_state


_SOURCE = "def sanitize(value):\n    return value\n\ndef run():\n    value = input()\n    value = sanitize(value)\n    eval(value)\n"


@pytest.fixture(autouse=True)
def _private_function_span_memo():
    original = sv._extract_functions_cached
    private = functools.lru_cache(**original.cache_parameters())(original.__wrapped__)
    with isolated_module_state(sv, {"_extract_functions_cached": private}):
        yield


@pytest.mark.parametrize("alias", ["absolute", "dot_relative", "symlink"])
def test_source_aliases_share_one_sanitizer_observation_window(tmp_path, alias):
    source = tmp_path / "app.py"
    source.write_text(_SOURCE)
    if alias == "absolute":
        sink_name = str(source)
    elif alias == "dot_relative":
        sink_name = "./app.py"
    else:
        (tmp_path / "alias.py").symlink_to(source)
        sink_name = "alias.py"
    result = sv.validate_structurally({
        "source": {"file": "app.py", "line": 5},
        "sink": {"file": sink_name, "line": 7},
    }, tmp_path, language="python")
    assert result.verdict == "confirmed"
    assert result.sanitizers == ["sanitize"]  # Name observation, not a safety proof.


def test_distinct_files_do_not_share_observation_windows(tmp_path):
    for directory in ("a", "b"):
        folder = tmp_path / directory
        folder.mkdir()
        (folder / "app.py").write_text(_SOURCE)
    result = sv.validate_structurally({
        "source": {"file": "a/app.py", "line": 5},
        "sink": {"file": "b/app.py", "line": 7},
    }, tmp_path, language="python")
    assert result.sanitizers == []
    assert result.verdict != "confirmed"
