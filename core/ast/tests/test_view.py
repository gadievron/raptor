"""Tests for ``core.ast.view``.

End-to-end coverage of the composition layer: each language fixture
in ``./fixtures/`` is opened, ``view()`` is called for known
functions, and the resulting :class:`FunctionView` is asserted
against the expected shape.

The per-language walker tests (``core/inventory/tests/test_call_graph_*``)
pin the lower-level extraction. These tests pin the *composition*:
that ``view()`` glues function discovery + calls + returns + asm
correctly, handles edge cases (missing file / function / language),
and emits a stable JSON-serialisable schema.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.ast import view
from core.ast.model import SCHEMA_VERSION

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Per-language end-to-end
# ---------------------------------------------------------------------------


class TestC:
    """C uses tree-sitter for calls + returns + asm. C is a load-
    bearing language for the /audit Phase A kernel CVE benchmark
    list, so the basic shape gets pinned here."""

    pytestmark = pytest.mark.skipif(
        not (FIXTURES / "sample.c").exists(), reason="fixture missing",
    )

    def test_main_view(self):
        fv = view(FIXTURES / "sample.c", "main")
        assert fv is not None
        assert fv.function == "main"
        assert fv.language == "c"
        # Three calls: helper (line 10), printf (line 11). The asm
        # statement is not a call. The conditional check on helper(argc)
        # also counts.
        call_chains = [c.chain for c in fv.calls_made]
        assert ["helper"] in call_chains
        assert ["printf"] in call_chains
        # Two explicit returns.
        return_lines = sorted(r.line for r in fv.returns)
        assert len(return_lines) == 2
        # Inline asm detected.
        assert fv.has_inline_asm is True

    def test_helper_view_no_asm(self):
        fv = view(FIXTURES / "sample.c", "helper")
        assert fv is not None
        assert fv.has_inline_asm is False
        assert len(fv.returns) == 1
        assert fv.returns[0].value_text == "x + 1"
        # No calls inside helper.
        assert fv.calls_made == ()


class TestCpp:
    """C++ extends C with classes, qualified ids, ``this->``. The
    ``run`` method exercises out-of-line definition + receiver_class
    tagging at once."""

    pytestmark = pytest.mark.skipif(
        not (FIXTURES / "sample.cpp").exists(), reason="fixture missing",
    )

    def test_run_method_this_arrow(self):
        # Use --at-line equivalent because ``run`` might collide
        # with other names; in this fixture it's unique so name
        # match suffices.
        fv = view(FIXTURES / "sample.cpp", "run")
        assert fv is not None
        assert fv.language == "cpp"
        # this->setup() inside run → receiver_class="Widget"
        this_setup = [
            c for c in fv.calls_made
            if c.chain == ["this", "setup"]
        ]
        assert len(this_setup) == 1
        assert this_setup[0].receiver_class == "Widget"
        # Two explicit returns.
        assert len(fv.returns) == 2

    def test_setup_method_out_of_line(self):
        fv = view(FIXTURES / "sample.cpp", "setup")
        assert fv is not None
        # ``helper()`` is a free function, not a Widget method →
        # no receiver_class tag.
        helper_calls = [
            c for c in fv.calls_made if c.chain == ["helper"]
        ]
        assert len(helper_calls) == 1
        assert helper_calls[0].receiver_class is None

    def test_destructor_view(self):
        """Out-of-line destructor (``Widget::~Widget()``) is
        surfaced by inventory and the view() composition picks it up.

        Originally pinned as a known-gap test (TreeSitterExtractor's
        ``_get_name`` didn't handle qualified+destructor declarators
        and the cpp branch used the C grammar). Fixed inline as part
        of PR1 after adversarial review surfaced the broader
        inline-method gap that shared the same root cause."""
        fv = view(FIXTURES / "sample.cpp", "~Widget")
        assert fv is not None
        assert fv.function == "~Widget"
        # cleanup() called inside destructor body
        assert any(c.chain == ["cleanup"] for c in fv.calls_made)


class TestPython:
    """Python uses stdlib ``ast`` for both function discovery and
    returns. Tests pin source-order return sorting and that the
    composition flows through correctly despite the local
    ``core.ast`` namespace collision with stdlib ``ast``."""

    pytestmark = pytest.mark.skipif(
        not (FIXTURES / "sample.py").exists(), reason="fixture missing",
    )

    def test_check_password_view(self):
        fv = view(FIXTURES / "sample.py", "check_password")
        assert fv is not None
        assert fv.language == "python"
        # All three function calls.
        names = [".".join(c.chain) for c in fv.calls_made]
        assert "compute_hash" in names
        assert "log_attempt" in names
        assert "constant_time_compare" in names
        # Three explicit returns, in source order.
        lines = [r.line for r in fv.returns]
        assert lines == sorted(lines), (
            "returns are not in source order — Python's ast.walk "
            "doesn't guarantee order; _walk_returns_python must sort"
        )

    def test_method_inside_class(self):
        fv = view(FIXTURES / "sample.py", "login")
        assert fv is not None
        # check_password call inside login.
        assert any(
            c.chain == ["check_password"] for c in fv.calls_made
        )

    def test_python_no_inline_asm(self):
        fv = view(FIXTURES / "sample.py", "check_password")
        assert fv is not None
        assert fv.has_inline_asm is False


class TestGo:
    pytestmark = pytest.mark.skipif(
        not (FIXTURES / "sample.go").exists(), reason="fixture missing",
    )

    def test_main_view(self):
        fv = view(FIXTURES / "sample.go", "main")
        if fv is None:
            pytest.skip("go grammar not installed")
        # fmt.Println called twice in main.
        println = [c for c in fv.calls_made if c.chain[-1] == "Println"]
        assert len(println) >= 1

    def test_go_no_inline_asm(self):
        fv = view(FIXTURES / "sample.go", "main")
        if fv is None:
            pytest.skip("go grammar not installed")
        assert fv.has_inline_asm is False


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_missing_file_returns_none(self):
        assert view(Path("/no/such/file.c"), "foo") is None

    def test_unknown_extension_returns_none(self, tmp_path):
        f = tmp_path / "unknown.xyz"
        f.write_text("whatever")
        assert view(f, "foo") is None

    def test_function_not_found_returns_none(self, tmp_path):
        f = tmp_path / "x.c"
        f.write_text('int main(void) { return 0; }\n')
        assert view(f, "nonexistent") is None
        # Sanity check that the file/function are otherwise findable.
        assert view(f, "main") is not None

    def test_language_override(self, tmp_path):
        # File with no extension: detect_language returns None,
        # but with --language given, view() proceeds.
        f = tmp_path / "noext"
        f.write_text('int main(void) { return 0; }\n')
        assert view(f, "main") is None  # detection fails
        fv = view(f, "main", language="c")
        assert fv is not None
        assert fv.language == "c"

    def test_at_line_disambiguates_collision(self, tmp_path):
        # Two functions named __init__ — typical Python class methods.
        f = tmp_path / "x.py"
        f.write_text(
            'class A:\n'
            '    def __init__(self):\n'
            '        self.a = 1\n'
            'class B:\n'
            '    def __init__(self):\n'
            '        self.b = 2\n'
        )
        # Without --at-line, the first match wins (extractor order).
        # With --at-line=5, we should hit B's __init__.
        fv = view(f, "__init__", at_line=5)
        # Should be B's __init__: line 5 inside its range.
        assert fv is not None
        # The disambiguation worked iff the view covers a range
        # that includes line 5.
        assert fv.lines[0] <= 5 <= fv.lines[1]


# ---------------------------------------------------------------------------
# Schema round-trip
# ---------------------------------------------------------------------------


class TestSchema:
    pytestmark = pytest.mark.skipif(
        not (FIXTURES / "sample.c").exists(), reason="fixture missing",
    )

    def test_to_dict_carries_full_schema(self):
        fv = view(FIXTURES / "sample.c", "main")
        d = fv.to_dict()
        # Top-level keys.
        assert set(d.keys()) >= {
            "function", "file", "language", "lines", "signature",
            "calls_made", "returns", "has_inline_asm", "schema_version",
        }
        assert d["schema_version"] == SCHEMA_VERSION
        # Calls have receiver_class (None for C is fine).
        for c in d["calls_made"]:
            assert set(c.keys()) >= {"line", "chain", "caller", "receiver_class"}
        # Returns have line + value_text.
        for r in d["returns"]:
            assert set(r.keys()) == {"line", "value_text"}

    def test_to_dict_is_json_serialisable(self):
        import json
        fv = view(FIXTURES / "sample.c", "main")
        # Round-trip through JSON — pin no non-serialisable types.
        s = json.dumps(fv.to_dict())
        d = json.loads(s)
        assert d["function"] == "main"
