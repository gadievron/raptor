"""Native heap-lifetime candidate contracts and ownership controls."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "double_free.cocci"
)

# Real-tool fixtures belong to engine CI's native integration partition.
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("spatch") is None, reason="coccinelle not installed"),
]


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_sequential_double_free_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(char *p)
            {
                free(p);
                free(p);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "double_free"

    def test_same_line_double_free_fires(self, tmp_path):
        # The self-pairing guard must compare positions, not lines:
        # the identical two-free sequence on ONE line is the same bug.
        results = _run_rule(tmp_path, """\
            void bug(char *p)
            {
                free(p); free(p);
            }
        """)
        assert len(results) == 1
        assert results[0]["rule"] == "double_free"

    def test_kfree_double_free_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bug(struct s *p)
            {
                kfree(p);
                log_it();
                kfree(p);
            }
        """)
        assert len(results) == 1

    def test_branch_free_without_return_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            int bug(struct s *p)
            {
                if (bad(p)) {
                    kfree(p);
                }
                kfree(p);
                return 0;
            }
        """)
        assert len(results) >= 1


class TestNegatives:
    def test_reassignment_between_frees_does_not_fire(self, tmp_path):
        # free(p); p = q; free(p); frees two different objects.
        results = _run_rule(tmp_path, """\
            void ok(char *p, char *q)
            {
                free(p);
                p = q;
                free(p);
            }
        """)
        assert results == []

    def test_list_free_loop_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void teardown(struct node *head)
            {
                struct node *cur = head;
                struct node *nxt;
                while (cur) {
                    nxt = cur->next;
                    free(cur);
                    cur = nxt;
                }
            }
        """)
        assert results == []

    def test_error_cleanup_branch_with_return_does_not_fire(self, tmp_path):
        # Branch frees AND returns: no CFG path connects the frees —
        # the canonical error-cleanup idiom.
        results = _run_rule(tmp_path, """\
            int ok(struct s *p)
            {
                if (setup(p) < 0) {
                    kfree(p);
                    return -1;
                }
                finish(p);
                kfree(p);
                return 0;
            }
        """)
        assert results == []

    def test_branch_reassignment_does_not_fire(self, tmp_path):
        # Branch frees then reassigns (no return): the fallthrough
        # free targets the new object.
        results = _run_rule(tmp_path, """\
            int ok(struct s *p, struct s *q)
            {
                if (bad(p)) {
                    kfree(p);
                    p = q;
                }
                kfree(p);
                return 0;
            }
        """)
        assert results == []

    def test_allocator_reassignment_still_suppresses(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void ok(struct s *p)
            {
                kfree(p);
                p = kmalloc(sizeof(*p), GFP_KERNEL);
                kfree(p);
            }
        """)
        assert results == []


@pytest.mark.parametrize(("body", "fires"), [
    ("if (flag) { kfree(p); p = kmalloc(16, 0); } kfree(p);", False),
    ("if (flag) { kfree(p); p = q; } kfree(p);", False),
    ("if (flag) { kfree(p); p = 0; } kfree(p);", False),
    ("if (flag) { if (other) { kfree(p); p = q; } } kfree(p);", False),
    ("if (flag) { kfree(p); goto out; } kfree(p); out: return;", False),
    ("if (flag) { kfree(p); } else { kfree(p); }", False),
    ("while (flag--) { if (other) { kfree(p); p = q; } kfree(p); p = 0; }", False),
    ("while (flag--) { if (other) { kfree(p); p = kmalloc(16, 0); if (!p) goto fail; } if (flag) { kfree(p); p = 0; } } kfree(p); return; fail: kfree(p);", False),
    ("if (flag) { if (other) { kfree(p); } } kfree(p);", True),
    ("if (flag) { kfree(p); log_it(); } kfree(p);", True),
    ("if (flag) { kfree(p); if (other) p = q; } kfree(p);", True),
    ("while (flag--) { kfree(p); if (other) kfree(p); }", True),
    ("kfree(p); while (flag--) { kfree(p); }", True),
    ("if (flag) { kfree(p); goto fail; } return; fail: kfree(p);", True),
    ("if (flag) { kvfree(p); } kvfree(p);", True),
    ("if (flag) { free(p); } free(p);", True),
])
def test_branch_and_loop_paths(tmp_path, body, fires):
    results = _run_rule(tmp_path, "void sample(char *p, char *q, int flag, int other) { " + body + " }\n")
    assert bool(results) is fires


def test_single_free_site_loop_remains_a_documented_miss(tmp_path):
    # A repeated execution of one free site is not distinguished from a
    # reflexive position pairing. Do not turn every single free into an alert.
    assert _run_rule(tmp_path, "void sample(char *p, int count) { while (count--) { kfree(p); } }\n") == []


@pytest.mark.parametrize("rule_name", ["double_free", "use_after_free"])
@pytest.mark.parametrize("storage,receiver,replacement", [
    ("p", "p", "other"), ("ctx->p", "ctx", "next_ctx"),
    ("item.p", "item", "next_item"), ("*slot", "slot", "next_slots"),
    ("values[0]", "values", "next_slots"), ("values[index]", "index", "next_index"),
], ids=["local", "pointer-field", "value-field", "pointer-slot", "array-slot", "indexed-slot"])
@pytest.mark.parametrize("phase", ["value", "receiver"])
def test_heap_storage_identity_and_surviving_paths(tmp_path, rule_name, storage, receiver, replacement, phase):
    cases = {
        "value": [
            ("observe(B);", True), ("if (B) observe();", True),
            ("B = other;", False), ("B += step;", False),
            ("B++;", False), ("replace(&B);", False),
            ("if (branch) B = other;", True),
            ("if (branch) B = other; else B = other;", False),
        ],
        "receiver": [
            (f"{receiver} = {replacement};", False),
            (f"replace_base(&{receiver});", False),
            (f"++{storage if receiver == 'item' else receiver};", False),
            (f"if (branch) {receiver} = {replacement};", True),
            (f"if (branch) {receiver} = {replacement}; else B = other;", False),
            ("unrelated++;", True),
        ],
    }[phase]
    lines = ["struct node { int value; };", "struct owner { struct node *p; };"]
    expected = set()
    params = "struct node *p, struct node *other, struct node **slot, struct node **values, struct node **next_slots, struct owner *ctx, struct owner *next_ctx, struct owner item, struct owner next_item, int index, int next_index, int step, int branch, int unrelated"
    for number, (between, reports) in enumerate(cases):
        lines += [f"void f_{number}({params}) {{", f"free({storage});", between.replace("B", storage)]
        lines.append(f"free({storage});" if rule_name == "double_free" else f"inspect(({storage})->value);")
        if reports:
            expected.add(len(lines))
        lines.append("}")
    rows = run_rule(tmp_path, "\n".join(lines) + "\n", _RULE.with_name(f"{rule_name}.cocci"))
    actual = {row["line"] for row in rows}
    assert actual == expected, {"missing": expected - actual, "unexpected": actual - expected}
    assert len(rows) == len(expected)
    assert {row["rule"] for row in rows} == {rule_name}
    assert all(row["message"].startswith("Candidate:") for row in rows)
    assert all(row["line_end"] >= row["line"] and row["col_end"] > row["col"] for row in rows)


@pytest.mark.parametrize("first", ["free", "kfree", "kvfree", "vfree", "kfree_sensitive"])
def test_release_families_and_literal_nulls(tmp_path, first):
    lines = []
    expected = set()
    for number, second in enumerate(("free", "kfree", "kvfree", "vfree", "kfree_sensitive")):
        lines += [f"void f_{number}(void *p) {{", f"{first}(p);", f"{second}(p);", "}"]
        expected.add(len(lines) - 1)
    for number, value in enumerate(("NULL", "nullptr", "0", "0U", "0x0")):
        lines += [f"void null_{number}(void) {{", f"{first}({value});", f"{first}({value});", "}"]
    rows = _run_rule(tmp_path, "\n".join(lines) + "\n")
    assert {row["line"] for row in rows} == expected
    assert len(rows) == len(expected)


def test_zero_sized_kernel_sentinels_do_not_establish_allocation_lifetime(tmp_path):
    rows = _run_rule(tmp_path, "void f(void) { kfree(ZERO_SIZE_PTR); kvfree(ZERO_SIZE_PTR); kfree(ZERO_SIZE_PTR); }\n")
    assert rows == []


@pytest.mark.parametrize("rule_name", ["double_free", "use_after_free"])
def test_computed_storage_requires_separate_analysis(tmp_path, rule_name):
    lines = ["struct node { int value; };",
             "struct owner { struct owner *child; struct node *p; };",
             "struct node *choose_pointer(void);"]
    for number, storage in enumerate(("choose_pointer()", "values[index + 1]", "ctx->child->p")):
        lines += [f"void f_{number}(struct node **values, int index, struct owner *ctx) {{", f"free({storage});",
                  f"free({storage});" if rule_name == "double_free" else f"inspect(({storage})->value);", "}"]
    rows = run_rule(tmp_path, "\n".join(lines) + "\n", _RULE.with_name(f"{rule_name}.cocci"))
    assert rows == []


def test_later_releases_are_unique_across_chains_and_merged_origins(tmp_path):
    from packages.coccinelle import runner

    lines = ["void chain(void *p) {", "free(p);"]
    expected = set()
    for _ in range(15):
        lines.append("free(p);")
        expected.add(len(lines))
    lines += ["}", "void merged(void *p, int branch) {", "if (branch) free(p); else free(p);", "free(p);", "}"]
    expected.add(len(lines) - 1)
    source = tmp_path / "releases.c"
    source.write_text("\n".join(lines) + "\n")
    result = runner.run_rule(source, _RULE, allow_scripting=True, no_includes=True, timeout=60)
    assert result.returncode == 0 and not result.errors, result.errors
    assert {row.line for row in result.matches} == expected
    assert len(result.matches) == len(expected)


def test_learned_releases_preserve_pairing_and_replacements(tmp_path):
    from core.audit.condition_smt import DomainVocabulary
    from engine.coccinelle.vocab_renderer import render

    rendered = render(_RULE, DomainVocabulary(deallocators=frozenset({"project_free"})))
    assert rendered is not None
    try:
        lines = ["void f(void *p) {", "project_free(p);", "free(p);", "}",
                 "void g(void *p, void *other) { project_free(p); p = other; project_free(p); }",
                 "void null(void) { project_free(NULL); project_free(NULL); }"]
        rows = run_rule(tmp_path, "\n".join(lines) + "\n", rendered)
        assert [row["line"] for row in rows] == [lines.index("free(p);") + 1]
    finally:
        rendered.unlink()


def test_heap_rules_keep_production_batching(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source = tmp_path / "heap.c"
    source.write_text(
        "struct node { int value; }; struct owner { struct node *p; };\n"
        "void a(struct node *p) { free(p); free(p); }\n"
        "void b(struct node *p) { free(p); inspect(p->value); inspect(p[0]); }\n"
        "void c(struct owner *ctx, struct owner *next) { kfree(ctx->p); ctx = next; inspect(ctx->p->value); free(ctx->p); }\n"
        "void d(struct node *p) { kfree(p); record_address(p); }\n"
        "void e(void) { free(NULL); free(NULL); }\n"
        "void f(void *p, int branch) { if (branch) free(p); else free(p); free(p); }\n"
        "void g(void *p) { free(p); observe(p); free(p); }\n"
        "void h(char *p, unsigned long n) { p = reallocarray(p, n, sizeof(char)); }\n",
    )
    original = runner._confined_default_runner
    calls = []

    def observe(*args, **kwargs):
        execute = original(*args, **kwargs)

        def invoke(argv, **options):
            calls.append(tuple(argv))
            return execute(argv, **options)

        return invoke

    monkeypatch.setattr(runner, "_confined_default_runner", observe)
    results = runner.run_rules_batched(
        source, [_RULE, _RULE.with_name("use_after_free.cocci"), _RULE.with_name("realloc_losing_ptr.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results) == {"double_free", "use_after_free", "realloc_losing_ptr"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["double_free"].matches) == 3
    assert len(results["use_after_free"].matches) == 3
    assert len(results["realloc_losing_ptr"].matches) == 1
    assert len(calls) == 1


@pytest.mark.parametrize("rule_name", ["double_free", "use_after_free", "realloc_losing_ptr", "resource_leak_err"])
def test_heap_silence_stays_inconclusive_after_file_memo_and_function_scoping(tmp_path, rule_name):
    from core.audit.sweep import run_coccinelle_file_sweep, scope_coccinelle_result
    from core.audit.sweep_memo import SweepMemo

    source = tmp_path / "scope.c"
    source.write_text("void quiet(void) { return; }\n")
    rule = str(_RULE.with_name(f"{rule_name}.cocci"))
    empty = run_coccinelle_file_sweep(target_path=tmp_path, file_path=source.name, cocci_rule=rule)
    assert not empty.errors, empty.errors
    assert empty.outcome == "inconclusive"
    assert empty.details["confirm_only"] is True
    assert empty.to_log_entry()["outcome"] == "inconclusive"

    body = {
        "double_free": ["free(p);", "free(p);"],
        "use_after_free": ["free(p);", "inspect(p->value);"],
        "realloc_losing_ptr": ["p = realloc(p, sizeof(*p));"],
        "resource_leak_err": ["p = kmalloc(sizeof(*p), 0);", "if (p && failure()) { return -1; }"],
    }[rule_name]
    lines = ["struct node { int value; };", "int bad(struct node *p) {", *body, "return 0;", "}",
             "void quiet(void) {", "return;", "}"]
    source.write_text("\n".join(lines) + "\n")
    full = run_coccinelle_file_sweep(target_path=tmp_path, file_path=source.name, cocci_rule=rule)
    assert full.outcome == "confirmed" and full.matches and not full.errors, full.errors
    memo = SweepMemo()
    key = ("coccinelle", rule_name, source.read_text())
    memo.put(key, full)
    cached = memo.get(key)
    assert cached is not None and cached.details["confirm_only"] is True
    clean_start = lines.index("void quiet(void) {") + 1
    clean = scope_coccinelle_result(cached, target_path=tmp_path, function_name="quiet",
                                    line_start=clean_start, line_end=len(lines))
    assert clean.outcome == "inconclusive" and not clean.matches
    bad = scope_coccinelle_result(cached, target_path=tmp_path, function_name="bad",
                                  line_start=lines.index("int bad(struct node *p) {") + 1,
                                  line_end=lines.index("}") + 1)
    assert bad.outcome == "confirmed" and bad.matches
    assert cached.matches == full.matches and cached.outcome == "confirmed"
    assert "reason" not in cached.details
