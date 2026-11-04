"""Caller signatures and setup survive the narrow call-site window."""

from core.audit.caller_context import CALLER_ENTRY_CHARS, CALLER_ENTRY_LINES, enrich_caller_entries
from core.audit.context import _defend_assembled_context, format_context_for_prompt


def test_multiline_parameters_and_setup_are_rendered(tmp_path):
    source = (
        "void proxy(struct waiter *waiter,\n"
        "           struct task *task)\n"
        "{\n"
        "    int result = prepare(waiter, task);\n"
        "    if (result)\n"
        "        cleanup(waiter);\n"
        "}\n"
    )
    (tmp_path / "api.c").write_text(source)
    callers = [{"file": "api.c", "name": "proxy", "line_start": 1,
                "call_site": "if (result)\n    cleanup(waiter);"}]
    inventory = {"files": [{"path": "api.c", "items": [
        {"name": "proxy", "line_start": 1, "line_end": 7},
    ]}]}
    enrich_caller_entries(callers, tmp_path, inventory)
    ctx = {"file": "impl.c", "function": "cleanup", "line_start": 1,
           "source": "void cleanup(void);",
           "callers": callers, "metadata": {}, "callees": []}
    _defend_assembled_context(ctx, "impl.c", "cleanup")
    prompt = format_context_for_prompt(ctx)
    assert "struct task *task" in prompt
    assert "prepare(waiter, task)" in prompt
    assert "cleanup(waiter)" in prompt


def test_entry_stops_at_recorded_function_end(tmp_path):
    (tmp_path / "api.c").write_text("void f(void) {}\nvoid unrelated(void) {}\n")
    callers = [{"file": "api.c", "name": "f", "line_start": 1}]
    inventory = {"files": [{"path": "api.c", "items": [
        {"name": "f", "line_start": 1, "line_end": 1},
    ]}]}
    enrich_caller_entries(callers, tmp_path, inventory)
    assert "unrelated" not in callers[0]["caller_entry"]


def test_unknown_span_is_not_guessed_and_entry_is_bounded(tmp_path):
    (tmp_path / "api.c").write_text(("x" * 1000 + "\n") * 40)
    callers = [{"file": "api.c", "name": "f", "line_start": 1}]
    enrich_caller_entries(callers, tmp_path, None)
    assert "caller_entry" not in callers[0]
    inventory = {"files": [{"path": "api.c", "items": [
        {"name": "f", "line_start": 1, "line_end": 40},
    ]}]}
    enrich_caller_entries(callers, tmp_path, inventory)
    entry = callers[0]["caller_entry"]
    assert len(entry) <= CALLER_ENTRY_CHARS
    assert len(entry.splitlines()) <= CALLER_ENTRY_LINES + 1


def test_adjacent_caller_contract_summary_is_included(tmp_path):
    (tmp_path / "api.c").write_text(
        "/**\n * proxy() - Prepare work for another task\n * @task: logical owner\n */\n"
        "void proxy(struct task *task) { prepare(task); }\n",
    )
    callers = [{"file": "api.c", "name": "proxy", "line_start": 5}]
    inventory = {"files": [{"path": "api.c", "items": [
        {"name": "proxy", "line_start": 5, "line_end": 5},
    ]}]}
    enrich_caller_entries(callers, tmp_path, inventory)
    entry = callers[0]["caller_entry"]
    assert "Prepare work for another task" in entry
    assert "@task" not in entry
    assert "struct task *task" in entry


def test_nonadjacent_comment_is_not_attached_to_caller(tmp_path):
    (tmp_path / "api.c").write_text(
        "/** Other function contract. */\nvoid other(void) {}\nvoid f(void) {}\n",
    )
    callers = [{"file": "api.c", "name": "f", "line_start": 3}]
    inventory = {"files": [{"path": "api.c", "items": [
        {"name": "f", "line_start": 3, "line_end": 3},
    ]}]}
    enrich_caller_entries(callers, tmp_path, inventory)
    assert "Other function contract" not in callers[0]["caller_entry"]


def test_inline_comment_on_previous_declaration_is_not_a_doc_summary(tmp_path):
    (tmp_path / "api.c").write_text("int other; /* Other contract. */\nvoid f(void) {}\n")
    callers = [{"file": "api.c", "name": "f", "line_start": 2}]
    inventory = {"files": [{"path": "api.c", "items": [
        {"name": "f", "line_start": 2, "line_end": 2},
    ]}]}
    enrich_caller_entries(callers, tmp_path, inventory)
    assert "Other contract" not in callers[0]["caller_entry"]
