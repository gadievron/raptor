"""Fixture tests for the alloc_narrow_count detection-grade rule.

An unsigned-int count produced by a division helper can narrow a wider
result before feeding an allocation size. Helper contracts, bounds and
capacity still need review; neither a match nor silence proves safety.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "alloc_narrow_count.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositive:
    def test_div_count_roundup_alloc_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int create(struct tgt *t, unsigned int rsize)
            {
                unsigned int count;
                size_t bits;
                void *p;

                count = sector_div_up(t->len, rsize);
                bits = round_up_helper(count, 64);
                p = vmalloc(bits);
                return p != 0;
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "alloc_narrow_count"


class TestNegatives:
    def test_wide_count_does_not_fire(self, tmp_path):
        # size_t count: the arithmetic happens at allocator width.
        results = _run_rule(tmp_path, """\
            int create(struct tgt *t, unsigned int rsize)
            {
                size_t count;
                size_t bits;
                void *p;

                count = sector_div_up(t->len, rsize);
                bits = round_up_helper(count, 64);
                p = vmalloc(bits);
                return p != 0;
            }
        """)
        assert results == []

    def test_alloc_unrelated_to_count_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int create(struct tgt *t, unsigned int rsize)
            {
                unsigned int count;
                void *p;

                count = sector_div_up(t->len, rsize);
                p = vmalloc(sizeof(struct tgt));
                return p != 0 && count;
            }
        """)
        assert results == []

    def test_count_not_from_division_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int create(unsigned int n)
            {
                unsigned int count;
                size_t bits;
                void *p;

                count = clamp_helper(n);
                bits = round_up_helper(count, 64);
                p = vmalloc(bits);
                return p != 0;
            }
        """)
        assert results == []


def test_live_count_and_size_origins(tmp_path):
    cases = [
        ("", "", True),
        ("count = 1;", "", False),
        ("mutate_count(&count);", "", False),
        ("", "bits = 16;", False),
        ("", "mutate_size(&bits);", False),
        ("if (choose) count = 1;", "", True),
        ("", "if (choose) bits = 16;", True),
        ("consume(count);", "consume(bits);", True),
        ("count++;", "", True),
    ]
    lines = []
    expected = set()
    for before_size, before_alloc, candidate in cases:
        index = len(lines)
        lines += [
            f"void *origin_{index}(unsigned long length, unsigned int divisor, int choose) {{",
            "  unsigned int count;",
            "  size_t bits;",
            "  void *p;",
            "  count = sector_div_up(length, divisor);",
            f"  {before_size}",
            "  bits = round_up_helper(count, 64);",
            f"  {before_alloc}",
            "  p = vmalloc(bits);",
            "  return p;",
            "}",
        ]
        if candidate:
            expected.add(len(lines) - 2)
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in rows} == expected
    assert len(rows) == len(expected)


@pytest.mark.integration
def test_narrow_count_keeps_production_batching(tmp_path, monkeypatch):
    from core.audit.evidence_grade import is_verification_evidence
    from packages.coccinelle import runner

    monkeypatch.setenv("RAPTOR_DIR", str(Path(__file__).resolve().parents[3]))
    source = tmp_path / "batch.c"
    source.write_text(
        "void *narrow(unsigned long length, unsigned int divisor) { unsigned int count; "
        "size_t bits; void *p; count = sector_div_up(length, divisor); "
        "bits = round_up_helper(count, 64); p = vmalloc(bits); return p; }\n"
        "void *scaled(unsigned long n) { return malloc(n * sizeof(int) * sizeof(int)); }\n"
        "void invalid_free(void) { char local[8]; free(local); }\n",
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
        source, [_RULE, _RULE.with_name("double_sizeof.cocci"),
                 _RULE.with_name("free_stack_array.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"alloc_narrow_count", "double_sizeof", "free_stack_array"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["alloc_narrow_count"].matches) == 1
    assert len(results["double_sizeof"].matches) == 1
    assert len(results["free_stack_array"].matches) == 1
    for owner, result in results.items():
        for hit in result.matches:
            assert is_verification_evidence(f"coccinelle:{hit.rule}") is (owner == "free_stack_array")
    assert len(invocations) == 1, invocations



@pytest.mark.integration
@pytest.mark.parametrize("other_hit", [False, True], ids=["file-empty", "other-function-hit"])
def test_narrow_count_silence_is_inconclusive(tmp_path, other_hit):
    from core.audit.sweep import run_coccinelle_file_sweep, scope_coccinelle_result

    lines = ["void safe(void) { consume(16); }"]
    if other_hit:
        lines.append(
            "void *other(unsigned long length, unsigned int divisor) { unsigned int count; "
            "size_t bits; void *p; count = sector_div_up(length, divisor); "
            "bits = round_up_helper(count, 64); p = vmalloc(bits); return p; }"
        )
    (tmp_path / "safe.c").write_text("\n".join(lines) + "\n")
    result = run_coccinelle_file_sweep(
        target_path=tmp_path, file_path="safe.c", cocci_rule=str(_RULE), language="c",
    )
    assert result.outcome == ("confirmed" if other_hit else "inconclusive"), result.errors
    assert len(result.matches) == int(other_hit)
    assert result.details["confirm_only"]
    scoped = scope_coccinelle_result(
        result, target_path=tmp_path, function_name="safe", line_start=1, line_end=1,
        language="c",
    )
    assert scoped.outcome == "inconclusive"
    assert scoped.details["confirm_only"]
    assert not scoped.matches
