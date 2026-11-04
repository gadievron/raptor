"""Content-keyed lexical reuse must preserve security gates and bounded memory."""

import os
from types import SimpleNamespace

import pytest

from packages.coccinelle import runner


@pytest.fixture(autouse=True)
def empty_lexical_cache():
    runner._cached_lexical_scan.cache_clear()
    yield
    runner._cached_lexical_scan.cache_clear()


@pytest.mark.parametrize("text", [
    "@r@\n@@\nfree(...);",
    "/* @script:python@ */\n@r@\n@@\nfree(...);",
    '// comment\n@script:python@\n@@\nprint("hello")',
    '"@script:python@"',
    "'script:ocaml'\n@script:python@\n@@\npass",
    '"unterminated\n/* hidden */\n"\n@script:python@',
    "/* unterminated",
    "'unpaired",
])
def test_cached_views_and_ambiguity_match_uncached_scan(text):
    expected = runner._lexical_scan_uncached(text, runner._CHAR_LITERAL_CAP)
    assert runner._lexical_scan(text) == expected
    assert runner._lexical_scan(text) == expected
    info = runner._cached_lexical_scan.cache_info()
    assert (info.hits, info.misses) == (1, 1)


def test_character_limit_is_part_of_cache_identity(monkeypatch):
    text = "'abcd'"
    assert runner._lexical_scan(text)[1] is False
    monkeypatch.setattr(runner, "_CHAR_LITERAL_CAP", 2)
    assert runner._lexical_scan(text)[1] is True
    assert runner._cached_lexical_scan.cache_info().misses == 2


def test_cache_bounds_and_unhashable_subclass_bypass():
    for index in range(40):
        runner._lexical_scan(f"rule_{index}")
    assert runner._cached_lexical_scan.cache_info().currsize == 32
    before = runner._cached_lexical_scan.cache_info()
    large = "a" * (64 * 1024 + 1)
    assert runner._lexical_scan(large) == (large, False)

    class UnhashableText(str):
        __hash__ = None

    assert runner._lexical_scan(UnhashableText("safe")) == ("safe", False)
    assert runner._cached_lexical_scan.cache_info() == before


def test_same_path_size_and_mtime_edit_still_enforces_script_gate(tmp_path, monkeypatch):
    rule = tmp_path / "edit.cocci"
    benign = "@r@\nposition p;\n@@\nfree@p(...);\n"
    scripted = "@script:python@\n@@\npass\n"
    rule.write_text(benign.ljust(200))
    old = rule.stat()
    target = tmp_path / "target.c"
    target.write_text("void f(void *p) { free(p); }\n")
    calls = []
    monkeypatch.setattr(runner, "is_available", lambda: True)
    monkeypatch.setattr(runner, "version", lambda: "1.3.0")

    def execute(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    first = runner.run_rule(target, rule, subprocess_runner=execute)
    assert not first.errors and len(calls) == 1
    rule.write_text(scripted.ljust(200))
    os.utime(rule, ns=(old.st_atime_ns, old.st_mtime_ns))
    assert rule.stat().st_size == old.st_size
    assert rule.stat().st_mtime_ns == old.st_mtime_ns
    edited = runner.run_rule(target, rule, subprocess_runner=execute)
    assert edited.errors and "scripting block" in edited.errors[0]
    assert len(calls) == 1
