"""Header cache identity using owned files and scalar parser replacements."""

from collections import OrderedDict
from pathlib import Path
import re

import pytest

from core.inventory import header_functions as hf


@pytest.fixture
def owned(monkeypatch):
    monkeypatch.setattr(hf, "_cache", OrderedDict())
    monkeypatch.setattr(hf, "_FUNC_DEF_RE", re.compile("(OWNED)"))
    monkeypatch.setattr(hf, "_extract_function_body", lambda lines, line: " / ".join(lines))
    monkeypatch.setattr(hf, "iter_regular_files", lambda root, extensions: iter([root / "owned.h"]))


def write(root, value):
    root.mkdir(parents=True)
    (root / "owned.h").write_text("OWNED " + value + "\n")


def test_relative_header_targets_do_not_share_cache(tmp_path, monkeypatch, owned):
    first = tmp_path / "first"
    second = tmp_path / "second"
    write(first / "src", "FIRST")
    write(second / "src", "SECOND")
    monkeypatch.chdir(first)
    assert hf.build_header_function_index(Path("src"))["OWNED"] == ("owned.h", "OWNED FIRST")
    monkeypatch.chdir(second)
    result = hf.build_header_function_index(Path("src"))
    assert result["OWNED"] == ("owned.h", "OWNED SECOND")
    assert hf.build_header_function_index(str(second / "src")) is result
    assert len(hf._cache) == 2


def test_walk_stays_bound_to_identified_header_target(tmp_path, monkeypatch, owned):
    first = tmp_path / "first"
    second = tmp_path / "second"
    write(first / "src", "FIRST")
    write(second / "src", "SECOND")
    monkeypatch.chdir(first)

    def drift(root, extensions):
        monkeypatch.chdir(second)
        return iter([root / "owned.h"])

    monkeypatch.setattr(hf, "iter_regular_files", drift)
    assert hf.build_header_function_index(Path("src"))["OWNED"] == ("owned.h", "OWNED FIRST")


def test_unknown_header_target_location_withholds_cache(monkeypatch, owned):
    def unavailable(path):
        raise OSError("owned unavailable location")

    monkeypatch.setattr(hf, "Path", unavailable)
    assert hf.build_header_function_index(Path("src")) == {}
    assert not hf._cache
