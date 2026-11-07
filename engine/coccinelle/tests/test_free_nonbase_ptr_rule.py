"""Fixture tests for the free_nonbase_ptr rule.

Postfix increment preserves the argument value. Explicit zero offsets and
recognized offsetof recovery shapes are excluded; remaining arithmetic is
candidate evidence until the allocation origin is established.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "free_nonbase_ptr.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_free_offset_pointer_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(char *p, int n)
            {
                free(p + n);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "free_nonbase_ptr"

    def test_free_minus_literal_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(char *p)
            {
                kfree(p - 1);
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_offsetof_base_recovery_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            struct wrap { int hdr; struct node node; };
            void put_node(struct node *n)
            {
                free((char *)n - offsetof(struct wrap, node));
            }
        """)
        assert results == []


def test_argument_values_across_allocator_families(tmp_path):
    allocators = (
        ('free', 'malloc(32)'), ('kfree', 'kmalloc(32, 0)'),
        ('vfree', 'vmalloc(32)'), ('kvfree', 'kvmalloc(32, 0)'),
        ('kfree_sensitive', 'kmalloc(32, 0)'), ('kzfree', 'kmalloc(32, 0)'),
    )
    cases = (
        ('p + 1', 'free_nonbase_ptr'), ('p - 1', 'free_nonbase_ptr'),
        ('p + n', 'free_nonbase_ptr'), ('++p', 'free_nonbase_ptr_inc'),
        ('p++', None), ('(p)++', None), ('p', None),
        ('p + 0', None), ('0 + p', None), ('p - 0', None),
        ('p + 0U', None), ('p - 0UL', None), ('p + 0x0', None),
        ('p + 00', None), ('p + (0)', None), ('p - ((0))', None),
        ('p + (int)0', None), ('p - (unsigned long)0', None),
        ('p + (-0)', None), ('p - (+0U)', None),
        ('p + (unsigned long)(int)0', None), ('p + (0 /* zero */)', None),
        ('p + (unsigned long)1', 'free_nonbase_ptr'),
        ('p + int0', 'free_nonbase_ptr'),
    )
    lines = [
        'void *malloc(unsigned long);', 'void *kmalloc(unsigned long, int);',
        'void *vmalloc(unsigned long);', 'void *kvmalloc(unsigned long, int);',
    ]
    lines += [f'void {name}(void *);' for name, _ in allocators]
    expected = set()
    for deallocate, allocate in allocators:
        for expression, rule_id in cases:
            lines += [f'void case_{len(lines)}(int n, int int0) {{',
                      f'  char *p = {allocate};', '  if (!p) return;',
                      f'  {deallocate}({expression});', '}']
            if rule_id:
                expected.add((len(lines) - 1, rule_id))
    for index in range(120):
        lines += [f'void repeated_{index}(void) {{', '  char *p = malloc(32);',
                  '  if (!p) return;', '  free(p + 1);', '}']
        expected.add((len(lines) - 1, 'free_nonbase_ptr'))
    results = _run_rule(tmp_path, '\n'.join(lines) + '\n')
    actual = {(row['line'], row['rule']) for row in results}
    assert actual == expected, {'missing': sorted(expected - actual),
                                'unexpected': sorted(actual - expected)}
    assert len(results) == len(expected)


@pytest.mark.integration
def test_zero_filter_keeps_production_batching(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "batch.c"
    source.write_text(
        "void free(void *);\n"
        "void candidates(char *p) { free(p + 1); free(p++); free(p + 0U); free(++p); }\n"
        "void invalid_stack_free(void) { char a[8]; free(a); }\n",
    )
    original = runner._confined_default_runner
    invocations = []

    def observe(*args, **kwargs):
        execute = original(*args, **kwargs)

        def invoke(argv, **options):
            invocations.append(tuple(argv))
            return execute(argv, **options)

        return invoke

    monkeypatch.setattr(runner, "_confined_default_runner", observe)
    results = runner.run_rules_batched(
        source, [_RULE, _RULE.with_name("free_stack_array.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"free_nonbase_ptr", "free_stack_array"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["free_nonbase_ptr"].matches) == 2
    assert len(results["free_stack_array"].matches) == 1
    assert len(invocations) == 1, invocations
