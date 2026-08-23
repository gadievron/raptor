"""Tests for engine.coccinelle.vocab_renderer."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from engine.coccinelle.vocab_renderer import render


@dataclass
class FakeVocab:
    allocators: frozenset = field(default_factory=frozenset)
    deallocators: frozenset = field(default_factory=frozenset)
    lock_acquires: frozenset = field(default_factory=frozenset)
    lock_releases: frozenset = field(default_factory=frozenset)
    refcount_gets: frozenset = field(default_factory=frozenset)
    refcount_puts: frozenset = field(default_factory=frozenset)
    callback_cancels: frozenset = field(default_factory=frozenset)


class TestAlternationExtension:
    def test_extends_deallocator_alternation(self, tmp_path):
        rule = tmp_path / "test.cocci"
        rule.write_text(
            "// @vocab: deallocators\n"
            r"\(kfree\|kvfree\)(E);" + "\n"
        )
        vocab = FakeVocab(deallocators=frozenset({"rxrpc_free_skb"}))
        result = render(rule, vocab)
        assert result is not None
        text = result.read_text()
        assert r"\|rxrpc_free_skb\)" in text
        assert r"\(kfree\|kvfree" in text
        Path(result).unlink()

    def test_extends_allocator_alternation(self, tmp_path):
        rule = tmp_path / "test.cocci"
        rule.write_text(
            "// @vocab: allocators\n"
            r"... when != E = \(\(kmalloc\|kzalloc\)(...)\|NULL\)" + "\n"
        )
        vocab = FakeVocab(allocators=frozenset({"my_alloc"}))
        result = render(rule, vocab)
        assert result is not None
        text = result.read_text()
        assert r"\|my_alloc" in text
        Path(result).unlink()

    def test_no_change_when_bucket_empty(self, tmp_path):
        rule = tmp_path / "test.cocci"
        rule.write_text(
            "// @vocab: deallocators\n"
            r"\(kfree\|kvfree\)(E);" + "\n"
        )
        vocab = FakeVocab()
        result = render(rule, vocab)
        assert result is None

    def test_no_change_without_markers(self, tmp_path):
        rule = tmp_path / "test.cocci"
        rule.write_text(r"\(kfree\|kvfree\)(E);" + "\n")
        vocab = FakeVocab(deallocators=frozenset({"extra"}))
        result = render(rule, vocab)
        assert result is None


class TestIdentifierListExtension:
    def test_extends_identifier_list(self, tmp_path):
        rule = tmp_path / "test.cocci"
        rule.write_text(
            "// @vocab: allocators\n"
            "identifier unsafe_fn = {malloc, calloc, free};\n"
        )
        vocab = FakeVocab(allocators=frozenset({"pool_alloc"}))
        result = render(rule, vocab)
        assert result is not None
        text = result.read_text()
        assert "pool_alloc" in text
        assert "malloc" in text
        Path(result).unlink()


class TestPythonSetExtension:
    def test_extends_python_set(self, tmp_path):
        rule = tmp_path / "test.cocci"
        rule.write_text(
            '// @vocab: deallocators\n'
            '_safe = {"kfree", "kvfree", "vfree"}\n'
        )
        vocab = FakeVocab(deallocators=frozenset({"custom_free"}))
        result = render(rule, vocab)
        assert result is not None
        text = result.read_text()
        assert '"custom_free"' in text
        assert '"kfree"' in text
        Path(result).unlink()


class TestDisjunctionExtension:
    def test_extends_disjunction_with_template(self, tmp_path):
        rule = tmp_path / "test.cocci"
        rule.write_text(
            "// @vocab: allocators\n"
            "// @vocab-tmpl: ptr =@p_alloc %s(...)\n"
            "(\n"
            "  ptr =@p_alloc kmalloc(sz, flags)\n"
            "|\n"
            "  ptr =@p_alloc kzalloc(sz, flags)\n"
            ")\n"
        )
        vocab = FakeVocab(allocators=frozenset({"zone_alloc"}))
        result = render(rule, vocab)
        assert result is not None
        text = result.read_text()
        assert "zone_alloc" in text
        assert "ptr =@p_alloc zone_alloc(...)" in text
        assert "kmalloc" in text
        Path(result).unlink()


class TestWhenClauseExtension:
    def test_extends_when_block(self, tmp_path):
        rule = tmp_path / "test.cocci"
        rule.write_text(
            "// @vocab: deallocators\n"
            "  ... when != kfree(ptr)\n"
            "      when != kvfree(ptr)\n"
            "  return@p_ret E;\n"
        )
        vocab = FakeVocab(deallocators=frozenset({"my_free"}))
        result = render(rule, vocab)
        assert result is not None
        text = result.read_text()
        assert "when != my_free(...)" in text
        assert "when != kfree(ptr)" in text
        assert "when != kvfree(ptr)" in text
        Path(result).unlink()


class TestIdentifierGate:
    """Vocabulary names are LLM study output over the untrusted repo
    and get spliced into .cocci that spatch runs with
    allow_scripting=True — anything beyond a plain identifier is
    rejected, never spliced (U12-F260)."""

    # The PoC payload: a hostile 'deallocator' name that would close
    # the SmPL construct and open an attacker @script:python block.
    HOSTILE = '};\n@script:python@\n@@\nimport os\nos.system("id")\n'

    def test_hostile_name_never_spliced_into_alternation(self, tmp_path):
        rule = tmp_path / "test.cocci"
        rule.write_text(
            "// @vocab: deallocators\n"
            r"\(kfree\|kvfree\)(E);" + "\n"
        )
        vocab = FakeVocab(deallocators=frozenset({self.HOSTILE}))
        result = render(rule, vocab)
        # Only the hostile name existed — nothing splice-worthy left.
        assert result is None

    def test_hostile_name_dropped_benign_kept(self, tmp_path):
        rule = tmp_path / "test.cocci"
        rule.write_text(
            "// @vocab: deallocators\n"
            r"\(kfree\|kvfree\)(E);" + "\n"
        )
        vocab = FakeVocab(
            deallocators=frozenset({self.HOSTILE, "rxrpc_free_skb"}),
        )
        result = render(rule, vocab)
        assert result is not None
        text = result.read_text()
        assert "rxrpc_free_skb" in text
        assert "@script" not in text
        assert "os.system" not in text
        Path(result).unlink()

    def test_python_set_quote_breakout_rejected(self, tmp_path):
        rule = tmp_path / "test.cocci"
        rule.write_text(
            "// @vocab: deallocators\n"
            '_safe = {"kfree", "vfree"}\n'
        )
        vocab = FakeVocab(
            deallocators=frozenset({'ok_name", "memcpy'}),
        )
        result = render(rule, vocab)
        assert result is None

    @pytest.mark.parametrize("payload", [
        "a(b)",           # parens (call syntax)
        "a b",            # whitespace
        "a\\|kfree",      # alternation injection
        "a\nb",           # newline
        'a"b',            # quote
        "a@p",            # position-metavariable syntax
        "",               # empty
        "0abc",           # leading digit
        "x" * 200,        # over-long
    ])
    def test_non_identifier_shapes_rejected(self, tmp_path, payload):
        rule = tmp_path / "test.cocci"
        rule.write_text(
            "// @vocab: deallocators\n"
            r"\(kfree\|kvfree\)(E);" + "\n"
        )
        vocab = FakeVocab(deallocators=frozenset({payload}))
        result = render(rule, vocab)
        assert result is None, f"non-identifier {payload!r} was spliced"

    def test_callback_cancels_bucket_now_mapped(self, tmp_path):
        # U12-F265: _BUCKET_MAP lacked callback_cancels — the
        # teardown_lifetime extension slots were silently dead.
        rule = tmp_path / "test.cocci"
        rule.write_text(
            "// @vocab: callback_cancels\n"
            r"\(del_timer\|cancel_work\)(E);" + "\n"
        )
        vocab = FakeVocab(callback_cancels=frozenset({"my_cancel"}))
        result = render(rule, vocab)
        assert result is not None
        assert r"\|my_cancel" in result.read_text()
        Path(result).unlink()

    def test_unknown_bucket_warns_and_splices_nothing(
        self, tmp_path, caplog,
    ):
        import logging as _logging

        rule = tmp_path / "test.cocci"
        rule.write_text(
            "// @vocab: callback_cancels_async\n"
            r"\(del_timer\|cancel_work\)(E);" + "\n"
        )
        vocab = FakeVocab(callback_cancels=frozenset({"my_cancel"}))
        with caplog.at_level(
            _logging.WARNING, logger="engine.coccinelle.vocab_renderer",
        ):
            result = render(rule, vocab)
        assert result is None
        assert any("unknown @vocab bucket" in r.message
                   for r in caplog.records)


class TestNoneVocab:
    def test_none_vocab_returns_none(self, tmp_path):
        rule = tmp_path / "test.cocci"
        rule.write_text(
            "// @vocab: deallocators\n"
            r"\(kfree\|kvfree\)(E);" + "\n"
        )
        assert render(rule, None) is None


class TestRealRules:
    """Smoke-test rendering on the actual rule files."""

    RULES_DIR = Path(__file__).parent.parent / "rules"
    MARKED_RULES = [
        "use_after_free.cocci",
        "double_free.cocci",
        "lock_imbalance.cocci",
        "resource_leak_err.cocci",
        "missing_null_check.cocci",
        "signal_handler_unsafe.cocci",
    ]

    @pytest.mark.parametrize("rule_name", MARKED_RULES)
    def test_renders_without_error(self, rule_name):
        rule_path = self.RULES_DIR / rule_name
        if not rule_path.exists():
            pytest.skip(f"{rule_name} not found")
        vocab = FakeVocab(
            allocators=frozenset({"test_alloc"}),
            deallocators=frozenset({"test_free"}),
            lock_acquires=frozenset({"test_lock"}),
            lock_releases=frozenset({"test_unlock"}),
        )
        result = render(rule_path, vocab)
        assert result is not None, f"{rule_name} should produce output with vocab"
        text = result.read_text()
        assert "test_" in text
        assert "// @vocab:" in text
        Path(result).unlink()

    @pytest.mark.parametrize("rule_name", MARKED_RULES)
    def test_no_change_with_empty_vocab(self, rule_name):
        rule_path = self.RULES_DIR / rule_name
        if not rule_path.exists():
            pytest.skip(f"{rule_name} not found")
        vocab = FakeVocab()
        result = render(rule_path, vocab)
        assert result is None
