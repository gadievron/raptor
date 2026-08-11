"""Tests for core.audit.dispatch_completeness — dispatch-gap detection."""

from __future__ import annotations

import pytest

from core.audit.dispatch_completeness import (
    DispatchGap,
    _shares_affix,
    find_dispatch_gaps,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _gaps_for(sources: dict[str, str]) -> list[DispatchGap]:
    """Run find_dispatch_gaps over in-memory source strings."""
    call_graphs = {f: {} for f in sources}
    return find_dispatch_gaps(call_graphs, source_texts=sources)


# ---------------------------------------------------------------------------
# Test: dict dispatch with a gap
# ---------------------------------------------------------------------------


class TestDictDispatchGap:
    """A dict maps some keys to handlers, but a producer yields a key
    the dict doesn't cover."""

    SOURCE = '''\
HANDLERS = {
    "python": handle_python,
    "java": handle_java,
    "go": handle_go,
}


def detect_language(path):
    if path.endswith(".py"):
        return "python"
    if path.endswith(".java"):
        return "java"
    if path.endswith(".go"):
        return "go"
    if path.endswith(".rs"):
        return "rust"
'''

    def test_missing_key_found(self):
        gaps = _gaps_for({"handlers.py": self.SOURCE})
        missing = {g.missing_key for g in gaps}
        assert "rust" in missing

    def test_handled_keys_not_flagged(self):
        gaps = _gaps_for({"handlers.py": self.SOURCE})
        missing = {g.missing_key for g in gaps}
        assert "python" not in missing
        assert "java" not in missing
        assert "go" not in missing

    def test_table_metadata(self):
        gaps = _gaps_for({"handlers.py": self.SOURCE})
        rust_gap = next(g for g in gaps if g.missing_key == "rust")
        assert rust_gap.table.table_type == "dict"
        assert rust_gap.table.file == "handlers.py"
        assert rust_gap.confidence == "high"  # same file


# ---------------------------------------------------------------------------
# Test: if/elif chain with a gap
# ---------------------------------------------------------------------------


class TestIfElifGap:
    """An if/elif chain dispatches on a variable, but a producer
    elsewhere yields a value the chain doesn't check."""

    SOURCE = '''\
def route(method):
    if method == "GET":
        return get_handler()
    elif method == "POST":
        return post_handler()
    elif method == "PUT":
        return put_handler()


METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]
'''

    def test_missing_methods(self):
        gaps = _gaps_for({"router.py": self.SOURCE})
        missing = {g.missing_key for g in gaps}
        assert "DELETE" in missing or "PATCH" in missing

    def test_enclosing_function_resolved(self):
        """If/elif table inside a function should report that function."""
        gaps = _gaps_for({"router.py": self.SOURCE})
        elif_gaps = [g for g in gaps if g.table.table_type == "if_elif"]
        assert elif_gaps
        assert elif_gaps[0].table.function == "route"


# ---------------------------------------------------------------------------
# Test: match statement dispatch with a gap
# ---------------------------------------------------------------------------


class TestMatchStatementGap:
    """Python 3.10+ match/case as a dispatch table."""

    SOURCE = '''\
def handle_event(event_type):
    match event_type:
        case "click":
            handle_click()
        case "hover":
            handle_hover()

EVENTS = ["click", "hover", "drag"]
'''

    def test_missing_key_found(self):
        gaps = _gaps_for({"events.py": self.SOURCE})
        missing = {g.missing_key for g in gaps}
        assert "drag" in missing

    def test_table_metadata(self):
        gaps = _gaps_for({"events.py": self.SOURCE})
        drag_gap = next(g for g in gaps if g.missing_key == "drag")
        assert drag_gap.table.table_type == "match"
        assert drag_gap.table.function == "handle_event"
        assert drag_gap.confidence == "high"

    def test_match_or_patterns_captured(self):
        """case 'a' | 'b': should contribute both keys to the table."""
        source = '''\
def route(method):
    match method:
        case "GET" | "HEAD":
            handle_read()
        case "POST":
            handle_write()

METHODS = ["GET", "HEAD", "POST", "DELETE"]
'''
        gaps = _gaps_for({"router.py": source})
        missing = {g.missing_key for g in gaps}
        assert "DELETE" in missing
        assert "GET" not in missing
        assert "HEAD" not in missing


# ---------------------------------------------------------------------------
# Test: complete dispatch (no gaps)
# ---------------------------------------------------------------------------


class TestCompleteDispatch:
    """When every produced key is handled, no gaps should be reported."""

    SOURCE = '''\
DISPATCH = {
    "alpha": do_alpha,
    "beta": do_beta,
    "gamma": do_gamma,
}

KEYS = ["alpha", "beta", "gamma"]
'''

    def test_no_gaps(self):
        gaps = _gaps_for({"complete.py": self.SOURCE})
        assert gaps == []


# ---------------------------------------------------------------------------
# Test: multiple dispatch tables in the same file
# ---------------------------------------------------------------------------


class TestMultipleTables:
    """Two independent dispatch tables in the same file, each with
    its own producer set."""

    SOURCE = '''\
COLOR_HANDLERS = {
    "red": handle_red,
    "blue": handle_blue,
}

SHAPE_HANDLERS = {
    "circle": draw_circle,
    "square": draw_square,
}

COLORS = ["red", "blue", "green"]
SHAPES = ["circle", "square", "triangle"]
'''

    def test_both_gaps_found(self):
        gaps = _gaps_for({"multi.py": self.SOURCE})
        missing = {g.missing_key for g in gaps}
        # "green" is missing from COLOR_HANDLERS.
        assert "green" in missing
        # "triangle" is missing from SHAPE_HANDLERS.
        assert "triangle" in missing

    def test_gap_associated_with_correct_table(self):
        gaps = _gaps_for({"multi.py": self.SOURCE})
        green_gaps = [g for g in gaps if g.missing_key == "green"]
        # "green" should be flagged against the COLOR_HANDLERS table.
        tables_for_green = {frozenset(g.table.keys) for g in green_gaps}
        assert frozenset({"red", "blue"}) in tables_for_green

        triangle_gaps = [g for g in gaps if g.missing_key == "triangle"]
        # "triangle" should be flagged against the SHAPE_HANDLERS table.
        tables_for_tri = {frozenset(g.table.keys) for g in triangle_gaps}
        assert frozenset({"circle", "square"}) in tables_for_tri


# ---------------------------------------------------------------------------
# Test: cross-file gap
# ---------------------------------------------------------------------------


class TestCrossFileGap:
    """Producer in one file, dispatch table in another.

    Cross-file gaps are only emitted when the produced key shares a
    prefix or suffix (>= 3 chars) with at least one existing table key.
    This filters unrelated strings from different modules while catching
    legitimate missed enum cases like ``'status_timeout'`` not handled
    when ``'status_ok'`` and ``'status_err'`` are.
    """

    TABLE_SOURCE = '''\
STATUS_MAP = {
    "status_ok": on_success,
    "status_err": on_failure,
    "status_pending": on_pending,
}
'''

    PRODUCER_SOURCE = '''\
def compute_status(result):
    if result > 0:
        return "status_ok"
    if result < 0:
        return "status_err"
    return "status_timeout"
'''

    def test_cross_file_gap(self):
        gaps = _gaps_for({
            "dispatch.py": self.TABLE_SOURCE,
            "producer.py": self.PRODUCER_SOURCE,
        })
        missing = {g.missing_key for g in gaps}
        assert "status_timeout" in missing

    def test_cross_file_confidence(self):
        gaps = _gaps_for({
            "dispatch.py": self.TABLE_SOURCE,
            "producer.py": self.PRODUCER_SOURCE,
        })
        timeout_gap = next(g for g in gaps if g.missing_key == "status_timeout")
        assert timeout_gap.confidence == "medium"  # different file


class TestCrossFileUnrelatedFiltered:
    """Cross-file strings that don't share a prefix/suffix with any table
    key are filtered to prevent the false-positive explosion (Bug 5)."""

    TABLE_SOURCE = '''\
STATUS_MAP = {
    "success": on_success,
    "failure": on_failure,
    "pending": on_pending,
}
'''

    PRODUCER_SOURCE = '''\
def compute_status(result):
    if result > 0:
        return "success"
    if result < 0:
        return "failure"
    return "unknown"
'''

    def test_unrelated_cross_file_string_filtered(self):
        gaps = _gaps_for({
            "dispatch.py": self.TABLE_SOURCE,
            "producer.py": self.PRODUCER_SOURCE,
        })
        missing = {g.missing_key for g in gaps}
        # "unknown" doesn't share a 3-char prefix or suffix with any of
        # "success", "failure", "pending" — filtered as cross-file noise.
        assert "unknown" not in missing


# ---------------------------------------------------------------------------
# Test: _shares_affix helper
# ---------------------------------------------------------------------------


class TestSharesAffix:
    """Unit tests for the cross-file relatedness gate."""

    def test_shared_prefix(self):
        assert _shares_affix("status_timeout", {"status_ok", "status_err"})

    def test_shared_suffix(self):
        assert _shares_affix("read_handler", {"write_handler", "exec_handler"})

    def test_no_shared_affix(self):
        assert not _shares_affix("mysql_query", {"click", "hover", "drag"})

    def test_unrelated_short_strings(self):
        assert not _shares_affix("unknown", {"success", "failure", "pending"})

    def test_exact_match_shares_prefix(self):
        # An exact match trivially shares the full string as affix
        assert _shares_affix("alpha", {"alpha", "beta"})

    def test_empty_keys(self):
        assert not _shares_affix("anything", set())

    def test_short_affix_below_threshold(self):
        # 2-char shared prefix "ab" is below the default min_affix=3
        assert not _shares_affix("abX", {"abY"})

    def test_exactly_at_threshold(self):
        # 3-char shared prefix "abc" meets the default min_affix=3
        assert _shares_affix("abcX", {"abcY"})


# ---------------------------------------------------------------------------
# Test: non-Python dispatch tables via tree-sitter
# ---------------------------------------------------------------------------


class TestNonPythonDispatch:
    """Switch/case tables extracted via tree-sitter for non-Python files."""

    def test_c_switch_detected(self):
        """C switch/case dispatch table should be found."""
        source = '''\
void handle_event(const char *event_type) {
    switch (event_type) {
        case "click":
            handle_click();
            break;
        case "hover":
            handle_hover();
            break;
        case "drag":
            handle_drag();
            break;
    }
}
'''
        from core.audit.dispatch_completeness import _extract_dispatch_tables_ts
        tables = _extract_dispatch_tables_ts("events.c", source)
        if not tables:
            pytest.skip("tree-sitter not available")
        assert len(tables) >= 1
        keys = tables[0].keys
        assert "click" in keys
        assert "hover" in keys

    def test_go_switch_detected(self):
        """Go expression switch should be found."""
        source = '''\
package main

func route(method string) {
    switch method {
    case "GET":
        handleGet()
    case "POST":
        handlePost()
    case "DELETE":
        handleDelete()
    }
}
'''
        from core.audit.dispatch_completeness import _extract_dispatch_tables_ts
        tables = _extract_dispatch_tables_ts("router.go", source)
        if not tables:
            pytest.skip("tree-sitter not available")
        assert len(tables) >= 1
        keys = tables[0].keys
        assert "GET" in keys
        assert "POST" in keys
        assert "DELETE" in keys
        assert tables[0].function == "route"

    def test_js_switch_detected(self):
        """JS switch statement should be found."""
        source = '''\
function dispatch(action) {
    switch (action) {
        case "increment":
            return state + 1;
        case "decrement":
            return state - 1;
        case "reset":
            return 0;
    }
}
'''
        from core.audit.dispatch_completeness import _extract_dispatch_tables_ts
        tables = _extract_dispatch_tables_ts("reducer.js", source)
        if not tables:
            pytest.skip("tree-sitter not available")
        assert len(tables) >= 1
        keys = tables[0].keys
        assert "increment" in keys
        assert "reset" in keys

    def test_python_not_used_for_ts_path(self):
        """Python files should NOT go through ts_extract path."""
        source = '''\
match event:
    case "click":
        handle_click()
    case "hover":
        handle_hover()
'''
        from core.audit.dispatch_completeness import _extract_dispatch_tables_ts
        tables = _extract_dispatch_tables_ts("events.py", source)
        assert len(tables) == 0

    def test_go_cross_reference_gap(self):
        """Go switch + Go producer should detect missing key when keys
        share a common prefix."""
        go_switch = '''\
package main

func route(method string) {
    switch method {
    case "method_GET":
        handleGet()
    case "method_POST":
        handlePost()
    }
}
'''
        go_producer = '''\
package main

func getMethods() []string {
    return "method_GET"
}

func otherMethod() string {
    return "method_DELETE"
}
'''
        gaps = _gaps_for({"router.go": go_switch, "methods.go": go_producer})
        if not gaps:
            pytest.skip("tree-sitter not available")
        missing = {g.missing_key for g in gaps}
        assert "method_DELETE" in missing
        assert "method_GET" not in missing


# ---------------------------------------------------------------------------
# Test: per-table gap cap
# ---------------------------------------------------------------------------


class TestPerTableGapCap:
    """When a single table generates more than 50 gaps, it is matching
    noise — all gaps for that table are discarded (Bug 5 fix)."""

    def test_noisy_table_gaps_dropped(self):
        # Build a dispatch table with 2 keys and 60 same-file producer
        # strings that share the same prefix (so they pass the affix
        # check).  The per-table cap should discard all of them.
        table_keys = '    "pfx_a": handle_a,\n    "pfx_b": handle_b,\n'
        table_src = f"DISPATCH = {{\n{table_keys}}}\n"
        # 60 producers sharing "pfx_" prefix → exceeds cap of 50
        returns = "\n".join(
            f'    return "pfx_{i}"' if i < 60
            else '    return "pfx_a"'
            for i in range(62)
        )
        producer_src = f"def gen(x):\n{returns}\n"
        source = table_src + "\n" + producer_src
        gaps = _gaps_for({"noisy.py": source})
        # All gaps for this table should be dropped because > 50 gaps.
        assert len(gaps) == 0

    def test_reasonable_table_gaps_kept(self):
        # A table with a few legitimate gaps should not be capped.
        source = '''\
HANDLERS = {
    "cmd_alpha": handle_alpha,
    "cmd_beta": handle_beta,
}

def get_cmd():
    return "cmd_gamma"

def get_cmd2():
    return "cmd_delta"
'''
        gaps = _gaps_for({"cmds.py": source})
        missing = {g.missing_key for g in gaps}
        assert "cmd_gamma" in missing
        assert "cmd_delta" in missing
