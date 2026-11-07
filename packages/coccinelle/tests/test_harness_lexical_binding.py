"""Reporting harnesses bind real rule declarations, not comment or literal examples."""

import subprocess
from pathlib import Path

import pytest

from packages.coccinelle import runner


BASE = "@r@\nexpression E;\nposition p;\n@@\nfree@p(E);\n"
PUTS = '@r@\nposition p;\n@@\nputs@p("script:python position phantom; @phantom@");\n'
PUTS_BASELINE = "@r@\nposition p;\n@@\nputs@p(...);\n"
CASES = [
    pytest.param("// script:python is only documentation\n" + BASE, BASE, id="script-comment"),
    pytest.param("// position phantom; @phantom@\n" + BASE, BASE, id="line-comment"),
    pytest.param("/* position phantom; @phantom@ */\n" + BASE, BASE, id="block-comment"),
    pytest.param("// position __import__;\n" + BASE, BASE, id="reserved-name-comment"),
    pytest.param(BASE.replace("position p;", "position /* note */ p;"), BASE, id="comment-in-declaration"),
    pytest.param(BASE.replace("@r@", "@/* note */r@"), BASE, id="comment-in-header"),
    pytest.param(PUTS, PUTS_BASELINE, id="string-literal"),
]


def _positions(result):
    return tuple((m.file, m.line, m.column, m.line_end, m.column_end)
                 for m in result.matches)


@pytest.fixture(scope="module")
def reference_matches(tmp_path_factory):
    """Run each unchanged baseline once; share only immutable observations."""
    root = tmp_path_factory.mktemp("lexical-reference")
    source = root / "input.c"
    source.write_text('void f(void *p) { free(p); }\n'
                      'void g(void) { puts("script:python position phantom; @phantom@"); }\n')
    references = {}

    def reference(baseline):
        # Laziness also avoids unused native runs for a single selected case
        # or a worker that receives only one of the two baseline families.
        if baseline not in references:
            original = root / f"original-{len(references)}.cocci"
            original.write_text(baseline)
            expected = runner.run_rule(source, original, no_includes=True, timeout=20)
            assert expected.ok, expected.errors
            assert expected.match_count == 1
            references[baseline] = (_positions(expected), tuple(expected.files_examined))
        return source, *references[baseline]

    return reference


@pytest.mark.parametrize("rule,baseline", CASES)
def test_harness_uses_only_live_position_and_rule_names(rule, baseline):
    result = runner._inject_harness(rule, "example")
    assert result.startswith(rule)
    harness = result[len(rule):]
    assert "@script:python@" in harness
    assert "p << r.p;" in harness
    assert "phantom" not in harness and "__import__" not in harness
    python_block = harness.split("@@", 1)[1]
    compile(python_block.strip(), "<reporting-harness>", "exec")


@pytest.mark.parametrize("rule", [
    "// position phantom;\n@r@\n@@\nfree(...);\n",
    '@r@\n@@\nputs("position phantom; @phantom@");\n',
    "@r@\n@@\nexposition decoy;\n",
    BASE + "\n@other@\n@@\nputs(...);\n",
    BASE + '\n"multiline\nclosed"\n',
])
def test_non_declarations_and_ambiguous_or_multi_rule_files_do_not_get_harnesses(rule):
    assert runner._inject_harness(rule, "example") == rule


@pytest.mark.parametrize("name", ["__import__", "_p", "json"])
def test_reserved_live_position_names_remain_refused(name):
    rule = BASE.replace("position p;", f"position {name};").replace("free@p", f"free@{name}")
    assert runner._inject_harness(rule, "example") == rule


@pytest.mark.skipif(not runner.is_available(), reason="spatch not installed")
@pytest.mark.parametrize("rule,baseline", CASES)
def test_real_spatch_recovers_the_same_match_as_the_undecorated_rule(
    tmp_path, rule, baseline, reference_matches,
):
    source, expected_positions, expected_files = reference_matches(baseline)
    decorated = tmp_path / "decorated.cocci"
    decorated.write_text(rule)
    actual = runner.run_rule(source, decorated, no_includes=True, timeout=20)
    assert actual.ok, actual.errors
    assert actual.match_count == 1
    assert _positions(actual) == expected_positions
    assert tuple(actual.files_examined) == expected_files


def test_comment_only_script_mention_still_gets_a_generated_reporter(tmp_path, monkeypatch):
    source = tmp_path / "input.c"
    source.write_text("void f(void *p) { free(p); }\n")
    rule = tmp_path / "rule.cocci"
    rule.write_text("// script:python is documentation\n" + BASE)
    monkeypatch.setattr(runner, "is_available", lambda: True)
    monkeypatch.setattr(runner, "_spatch_path", lambda: "/unused/spatch")
    executed = []

    def execute(command, **kwargs):
        text = Path(command[command.index("--sp-file") + 1]).read_text()
        executed.append(text)
        assert "\n@script:python@\n" in text
        assert "p << r.p;" in text
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    result = runner.run_rule(source, rule, subprocess_runner=execute)
    assert result.ok and len(executed) == 1
