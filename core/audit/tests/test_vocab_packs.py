"""Tests for target-kind vocab packs and the DomainVocabulary extension."""

from __future__ import annotations

import pytest

from core.audit import vocab_packs
from core.audit.condition_smt import DomainVocabulary
from core.audit.vocab_packs import is_kernel_tree, load_pack, pack_for_target


@pytest.fixture(autouse=True)
def _clear_caches():
    vocab_packs._pack_cache.clear()
    vocab_packs._kernel_tree_cache.clear()
    yield
    vocab_packs._pack_cache.clear()
    vocab_packs._kernel_tree_cache.clear()


class TestKernelPack:
    def test_pack_loads_with_all_classes(self):
        pack = load_pack("linux_kernel")
        assert pack is not None
        assert "devm_kzalloc" in pack.allocators
        assert "kfree_skb" in pack.deallocators
        assert ("down_read", "up_read") in pack.lock_pairs
        assert ("local_irq_save", "local_irq_restore") in pack.lock_pairs
        assert "dev_get_drvdata" in pack.nullable_returns
        assert ("ns_capable", "capability") in pack.auth_predicates
        assert "cap_effective" in pack.security_fields
        assert "_copy_from_iter" in pack.boundary_transfers
        assert pack.has_content

    def test_lock_name_sets_derive_from_pairs(self):
        pack = load_pack("linux_kernel")
        assert pack.lock_acquires == {a for a, _ in pack.lock_pairs}
        assert pack.lock_releases == {r for _, r in pack.lock_pairs}

    def test_missing_pack_returns_none(self):
        assert load_pack("no_such_pack") is None

    def test_pack_is_cached(self):
        a = load_pack("linux_kernel")
        b = load_pack("linux_kernel")
        assert a is b


class TestKernelTreeDetection:
    def test_kconfig_marks_kernel(self, tmp_path):
        (tmp_path / "Kconfig").write_text("config FOO\n")
        assert is_kernel_tree(tmp_path)

    def test_kbuild_marks_kernel(self, tmp_path):
        (tmp_path / "Kbuild").write_text("obj-y += foo.o\n")
        assert is_kernel_tree(tmp_path)

    def test_include_linux_marks_kernel(self, tmp_path):
        (tmp_path / "include" / "linux").mkdir(parents=True)
        assert is_kernel_tree(tmp_path)

    def test_out_of_tree_module_makefile(self, tmp_path):
        (tmp_path / "Makefile").write_text(
            "obj-m += mydriver.o\n\nall:\n\tmake -C /lib/modules ...\n",
        )
        assert is_kernel_tree(tmp_path)

    def test_plain_userland_project_is_not_kernel(self, tmp_path):
        (tmp_path / "Makefile").write_text(
            "all:\n\tcc -o app main.c\n",
        )
        (tmp_path / "main.c").write_text("int main(void){return 0;}\n")
        assert not is_kernel_tree(tmp_path)

    def test_pack_for_target_gates_on_detection(self, tmp_path):
        assert pack_for_target(tmp_path) is None
        (tmp_path / "Kconfig").write_text("config FOO\n")
        vocab_packs._kernel_tree_cache.clear()
        assert pack_for_target(tmp_path) is not None


class TestFromDomainModelMerge:
    def test_no_model_no_pack_is_empty(self, tmp_path):
        vocab = DomainVocabulary.from_domain_model(None, target_path=tmp_path)
        assert not vocab.has_content

    def test_kernel_target_gets_pack_without_model(self, tmp_path):
        (tmp_path / "Kconfig").write_text("config FOO\n")
        vocab = DomainVocabulary.from_domain_model(None, target_path=tmp_path)
        assert "devm_kzalloc" in vocab.allocators
        assert ("preempt_disable", "preempt_enable") in vocab.lock_pairs

    def test_learned_model_merges_with_pack(self, tmp_path):
        (tmp_path / "Kconfig").write_text("config FOO\n")
        dm = {
            "paired_operations": [
                {
                    "acquire": "foo_lock(dev)",
                    "release": "foo_unlock(dev)",
                    "kind": "mutex",
                },
                {
                    "acquire": "foo_alloc_ctx",
                    "release": "foo_free_ctx",
                    "kind": "alloc",
                },
            ],
            "auth_predicates": ["foo_may_access"],
            "nullable_returns": ["foo_get_dev()"],
        }
        vocab = DomainVocabulary.from_domain_model(dm, target_path=tmp_path)
        assert ("foo_lock", "foo_unlock") in vocab.lock_pairs
        assert ("down_write", "up_write") in vocab.lock_pairs
        assert "foo_alloc_ctx" in vocab.allocators
        assert "kvmalloc" in vocab.allocators
        assert ("foo_may_access", "domain") in vocab.auth_predicates
        assert "foo_get_dev" in vocab.nullable_returns

    def test_no_target_path_keeps_pre_pack_behaviour(self):
        dm = {
            "paired_operations": [
                {"acquire": "a_lock", "release": "a_unlock", "kind": "lock"},
            ],
        }
        vocab = DomainVocabulary.from_domain_model(dm)
        assert vocab.lock_acquires == {"a_lock"}
        assert "down_read" not in vocab.lock_acquires

    def test_auth_predicate_dict_entries(self):
        dm = {
            "auth_predicates": [
                {"name": "acl_check(req)", "kind": "permission"},
            ],
        }
        vocab = DomainVocabulary.from_domain_model(dm)
        assert ("acl_check", "permission") in vocab.auth_predicates


class TestCallbackVocabClasses:
    def test_pack_carries_callback_registers_and_cancels(self):
        pack = load_pack("linux_kernel")
        assert pack is not None
        assert "timer_setup" in pack.callback_registers
        assert "queue_work" in pack.callback_registers
        assert "del_timer_sync" in pack.callback_cancels
        assert "remove_wait_queue" in pack.callback_cancels

    def test_callback_pairs_parse_from_domain_model(self):
        dm = {
            "paired_operations": [
                {
                    "acquire": "foo_register_handler(dev, cb)",
                    "release": "foo_cancel_handler(dev)",
                    "kind": "callback",
                },
                {
                    "acquire": "foo_arm_timer",
                    "release": "foo_disarm_timer",
                    "kind": "timer",
                },
            ],
        }
        vocab = DomainVocabulary.from_domain_model(dm)
        assert "foo_register_handler" in vocab.callback_registers
        assert "foo_arm_timer" in vocab.callback_registers
        assert "foo_cancel_handler" in vocab.callback_cancels
        assert "foo_disarm_timer" in vocab.callback_cancels
        # Callback pairs do not leak into the lock vocabulary.
        assert "foo_register_handler" not in vocab.lock_acquires
        assert vocab.has_content

    def test_merged_unions_callback_classes(self):
        a = DomainVocabulary(callback_registers=frozenset({"a_reg"}))
        b = DomainVocabulary(callback_cancels=frozenset({"b_cancel"}))
        m = a.merged(b)
        assert m.callback_registers == {"a_reg"}
        assert m.callback_cancels == {"b_cancel"}


class TestProvenanceTierGate:
    """Vocabulary entries carrying study provenance tiers.

    ``llm_prior`` (training memory, no on-disk evidence) is never
    consumed; every other tier — and untiered legacy entries — is.
    """

    def test_llm_prior_entries_are_dropped(self):
        dm = {
            "paired_operations": [
                {
                    "acquire": "ghost_lock",
                    "release": "ghost_unlock",
                    "kind": "lock",
                    "provenance": "llm_prior",
                },
            ],
            "nullable_returns": [
                {"name": "ghost_get", "provenance": "llm_prior"},
            ],
            "auth_predicates": [
                {"name": "ghost_capable", "provenance": "llm_prior"},
            ],
            "security_fields": [
                {"name": "ghost_field", "provenance": "llm_prior"},
            ],
        }
        vocab = DomainVocabulary.from_domain_model(dm)
        assert not vocab.has_content

    def test_tiered_dict_entries_are_consumed(self):
        dm = {
            "paired_operations": [
                {
                    "acquire": "proj_lock",
                    "release": "proj_unlock",
                    "kind": "mutex",
                    "provenance": "mechanical",
                },
            ],
            "nullable_returns": [
                {"name": "proj_get_ctx()", "provenance": "llm_summarized"},
            ],
            "auth_predicates": [
                {
                    "name": "proj_may_write",
                    "kind": "permission",
                    "provenance": "mechanical",
                },
            ],
            "security_fields": [
                {"name": "acl_mask", "provenance": "llm_summarized"},
            ],
        }
        vocab = DomainVocabulary.from_domain_model(dm)
        assert ("proj_lock", "proj_unlock") in vocab.lock_pairs
        assert "proj_get_ctx" in vocab.nullable_returns
        assert ("proj_may_write", "permission") in vocab.auth_predicates
        assert "acl_mask" in vocab.security_fields

    def test_plain_string_entries_still_accepted(self):
        dm = {
            "security_fields": ["cred_ptr"],
            "nullable_returns": ["find_ctx()"],
        }
        vocab = DomainVocabulary.from_domain_model(dm)
        assert "cred_ptr" in vocab.security_fields
        assert "find_ctx" in vocab.nullable_returns
