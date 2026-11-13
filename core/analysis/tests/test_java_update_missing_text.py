"""A missing update-identifier text aborts constant-index construction."""

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis import const_fold_java as fold  # noqa: E402


def test_missing_update_operand_text_aborts_index_construction(monkeypatch):
    source = "class T { void m() { int n=0; (n)++; } }"
    original = fold._paren_unwrap
    reached = []
    original_failures = []

    class MissingTextIdentifier:
        def __init__(self, node):
            self.node = node

        @property
        def text(self):
            return None

        def __getattr__(self, name):
            return getattr(self.node, name)

    def unwrap(value):
        operand = original(value)
        assert operand is not None and operand.type == "identifier"
        reached.append(operand)
        missing_text = MissingTextIdentifier(operand)
        with pytest.raises(AttributeError) as original_error:
            set().add(missing_text.text.decode())
        original_failures.append(original_error.value)
        return missing_text

    index = None
    with monkeypatch.context() as scope:
        scope.setattr(fold, "_paren_unwrap", unwrap)
        with pytest.raises(AttributeError, match="^'NoneType' object has no attribute 'decode'$") as error:
            index = fold.JavaConstIndex(source, (1, 1))
    assert fold._paren_unwrap is original
    assert len(reached) == 1
    assert index is None
    assert error.value.name == "decode"
    assert error.value.obj is None
    assert len(original_failures) == 1
    assert type(error.value) is type(original_failures[0])
    assert error.value.args == original_failures[0].args
    assert error.value.name == original_failures[0].name
    assert error.value.obj is original_failures[0].obj


def test_normal_update_operand_bytes_poison_constant_index():
    index = fold.JavaConstIndex("class T { void m() { int n=0; (n)++; } }", (1, 1))
    assert index.ok
    assert "n" in index._compound_writers
