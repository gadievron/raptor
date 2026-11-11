"""Native suspension cannot freeze a module or captured name slot."""
import pytest

from core.analysis import validator_control_scope, validator_value_scope
from core.dataflow import smt_barrier as sb

GUARD = ' if (!/^[a-z]+$/.test(value)) return;'


@pytest.fixture(autouse=True)
def native():
    pytest.importorskip("z3")


def check(tmp_path, language, before, header, middle, *, after="", resume=" await checkpoint();"):
    pytest.importorskip("tree_sitter_javascript" if language == "javascript" else "tree_sitter_typescript")
    source = before + header + '\n' + middle + GUARD + '\n' + resume + '\n consume(value);\n}\n' + after
    assert validator_control_scope._native_source_tree(source, language) is not None
    lines = source.splitlines()
    sink_line = lines.index(' consume(value);') + 1
    name = 'app.js' if language == 'javascript' else 'app.ts'
    (tmp_path / name).write_text(source)
    return sb.try_tier0(fix_diff='+' + GUARD + '\n', repo_root=tmp_path,
                       sink_uri=name, sink_line=sink_line, sink_class="xss", language=language)


@pytest.mark.parametrize("language", ["javascript", "typescript"])
@pytest.mark.parametrize("case", ["module", "closure", "block-shadow", "nested-writer", "nested-loop-writer",
                                  "class-field-writer", "yield", "async-for"])
def test_shared_slot_is_unverified_after_native_suspension(tmp_path, language, case):
    before = 'let value = "abc";\nasync function mutate() { value = " "; }\n'
    header, middle, after, resume = 'async function handle() {', '', '', ' await mutate();'
    if case == 'closure':
        before += 'function outer() {\n let value = "abc";\n'
        after = '}\n'
    elif case == 'block-shadow':
        middle = ' { let value = "abc"; }\n'
    elif case == 'nested-writer':
        middle = ' let value = "abc";\n function mutateLocal() { value = " "; }\n'
        resume = ' await mutateLocal();'
    elif case == 'nested-loop-writer':
        header = 'async function handle(value) {'
        middle = ' async function mutateLocal() { for (value of [" "]) {} }\n'
        resume = ' await mutateLocal();'
    elif case == 'class-field-writer':
        header = 'async function handle(value) {'
        middle = ' class C { field = (value = " "); }\n'
        resume = ' await createC();'
    elif case == 'yield':
        header, resume = 'function* handle() {', ' yield 0;'
    elif case == 'async-for':
        resume = ' for await (const other of stream) { consume(value); }'
    result = check(tmp_path, language, before, header, middle, after=after, resume=resume)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert result.artifact is None


@pytest.mark.parametrize("language", ["javascript", "typescript"])
@pytest.mark.parametrize("binding", ["parameter", "let", "const", "var", "snapshot"])
def test_function_owned_slot_remains_eligible(tmp_path, language, binding):
    before = 'let shared = "abc";\nasync function mutate() { shared = " "; }\n'
    header = 'async function handle(value) {'
    middle = ''
    if binding != 'parameter':
        header = 'async function handle() {'
        middle = (' const value = shared;\n' if binding == 'snapshot'
                  else ' ' + binding + ' value = "abc";\n')
    result = check(tmp_path, language, before, header, middle, resume=' await mutate();')
    assert result.status is sb.Tier0Status.SOUND, result.reasoning


@pytest.mark.parametrize("language", ["javascript", "typescript"])
def test_nested_suspension_without_execution_keeps_existing_epoch(tmp_path, language):
    result = check(tmp_path, language, 'let value = "abc";\n', 'async function handle() {',
                   '', resume=' async function later() { await checkpoint(); }')
    # Existing public dominance rejects the intervening function boundary.
    assert result.status is sb.Tier0Status.NOT_APPLICABLE, result.reasoning
    assert "does not dominate" in result.reasoning
    name = 'app.js' if language == 'javascript' else 'app.ts'
    source = (tmp_path / name).read_text()
    assert not validator_value_scope.implicit_value_epoch_unverified(
        source, "value", 3, 5, language=language,
    )


@pytest.mark.parametrize("language", ["javascript", "typescript"])
def test_validation_after_suspension_refreshes_shared_slot(tmp_path, language):
    result = check(tmp_path, language, 'let value = "abc";\n', 'async function handle() {',
                   ' await checkpoint();\n', resume='')
    assert result.status is sb.Tier0Status.SOUND, result.reasoning
