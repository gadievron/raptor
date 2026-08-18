"""Tests for core.audit.strategy — adaptive review strategy selection."""

from __future__ import annotations

from core.audit.strategy import (
    STRATEGY_ALIASING,
    STRATEGY_AUTH,
    STRATEGY_CONCURRENCY,
    STRATEGY_CRYPTO,
    STRATEGY_GENERAL,
    STRATEGY_INPUT,
    STRATEGY_MEMORY,
    infer_strategies,
    primers_for_strategies,
    strategies_from_item,
)


class TestInferStrategies:
    def test_always_includes_general(self):
        result = infer_strategies(
            file_path="src/utils.c",
            function_name="helper",
        )
        assert STRATEGY_GENERAL in result

    def test_parser_path_triggers_input(self):
        result = infer_strategies(
            file_path="src/parser/json_decode.c",
            function_name="decode_value",
        )
        assert STRATEGY_INPUT in result

    def test_lock_path_triggers_concurrency(self):
        result = infer_strategies(
            file_path="src/sync/mutex_pool.c",
            function_name="acquire_lock",
        )
        assert STRATEGY_CONCURRENCY in result

    def test_alloc_path_triggers_memory(self):
        result = infer_strategies(
            file_path="src/memory/slab_alloc.c",
            function_name="alloc_page",
        )
        assert STRATEGY_MEMORY in result

    def test_auth_path_triggers_auth(self):
        result = infer_strategies(
            file_path="src/auth/permission_check.c",
            function_name="check_access",
        )
        assert STRATEGY_AUTH in result

    def test_crypto_path_triggers_crypto(self):
        result = infer_strategies(
            file_path="src/crypto/aes_cbc.c",
            function_name="encrypt_block",
        )
        assert STRATEGY_CRYPTO in result

    def test_splice_path_triggers_aliasing(self):
        result = infer_strategies(
            file_path="net/splice_handler.c",
            function_name="do_splice",
        )
        assert STRATEGY_ALIASING in result

    def test_char_star_param_triggers_input(self):
        result = infer_strategies(
            file_path="src/util.c",
            function_name="process",
            parameters=[("buf", "char *"), ("len", "size_t")],
        )
        assert STRATEGY_INPUT in result

    def test_void_star_param_triggers_memory(self):
        result = infer_strategies(
            file_path="src/util.c",
            function_name="free_obj",
            parameters=[("ptr", "void *")],
        )
        assert STRATEGY_MEMORY in result

    def test_void_star_return_triggers_memory(self):
        result = infer_strategies(
            file_path="src/util.c",
            function_name="create",
            return_type="void *",
        )
        assert STRATEGY_MEMORY in result

    def test_user_attribute_triggers_input(self):
        result = infer_strategies(
            file_path="src/syscall.c",
            function_name="sys_read",
            attributes=["__user"],
        )
        assert STRATEGY_INPUT in result

    def test_reachable_sinks_triggers_input(self):
        result = infer_strategies(
            file_path="src/handler.py",
            function_name="dispatch",
            reachable_sinks=["subprocess.Popen"],
        )
        assert STRATEGY_INPUT in result

    def test_function_name_signal(self):
        result = infer_strategies(
            file_path="src/net.c",
            function_name="parse_packet",
        )
        assert STRATEGY_INPUT in result

    def test_multiple_strategies(self):
        result = infer_strategies(
            file_path="src/crypto/key_alloc.c",
            function_name="allocate_key",
            parameters=[("data", "void *")],
        )
        assert STRATEGY_CRYPTO in result
        assert STRATEGY_MEMORY in result
        assert STRATEGY_GENERAL in result

    def test_no_false_positive_on_plain_util(self):
        result = infer_strategies(
            file_path="src/util.c",
            function_name="add_numbers",
            parameters=[("a", "int"), ("b", "int")],
            return_type="int",
        )
        assert result == frozenset({STRATEGY_GENERAL})

    def test_include_signals_concurrency(self):
        result = infer_strategies(
            file_path="src/worker.c",
            function_name="run",
            includes=["#include <pthread.h>"],
        )
        assert STRATEGY_CONCURRENCY in result

    def test_include_signals_crypto(self):
        result = infer_strategies(
            file_path="src/tls.c",
            function_name="handshake",
            includes=["from cryptography.fernet import Fernet"],
        )
        assert STRATEGY_CRYPTO in result


class TestStrategiesFromItem:
    def test_basic_item(self):
        item = {
            "name": "parse_request",
            "metadata": {
                "parameters": [
                    {"name": "buf", "type": "char *"},
                    {"name": "len", "type": "size_t"},
                ],
                "return_type": "int",
            },
        }
        result = strategies_from_item(item, "src/handler.c")
        assert STRATEGY_INPUT in result

    def test_item_without_metadata(self):
        item = {"name": "helper"}
        result = strategies_from_item(item, "src/util.c")
        assert result == frozenset({STRATEGY_GENERAL})

    def test_item_with_reachable_sinks(self):
        item = {"name": "dispatch"}
        result = strategies_from_item(
            item, "src/handler.py",
            reachable_sinks=["os.system"],
        )
        assert STRATEGY_INPUT in result

    def test_item_with_attributes(self):
        item = {
            "name": "sys_read",
            "metadata": {
                "attributes": ["__user", "__must_check"],
            },
        }
        result = strategies_from_item(item, "kernel/syscall.c")
        assert STRATEGY_INPUT in result
        assert STRATEGY_MEMORY in result

    def test_item_with_shared_state(self):
        item = {"name": "update", "metadata": {}}
        result = strategies_from_item(
            item, "data.c",
            shared_state=[{"kind": "spin_acquire", "fn": "spin_lock"}],
        )
        assert STRATEGY_CONCURRENCY in result

    def test_item_with_crypto_inventory(self):
        item = {"name": "encrypt", "metadata": {}}
        result = strategies_from_item(
            item, "security.c",
            crypto_inventory=[{"kind": "cipher", "api": "AES_encrypt"}],
        )
        assert STRATEGY_CRYPTO in result

    def test_item_with_ownership_model(self):
        item = {"name": "create", "metadata": {}}
        result = strategies_from_item(
            item, "factory.c",
            ownership_model=[{"kind": "allocator", "role": "custom_alloc"}],
        )
        assert STRATEGY_MEMORY in result


class TestIncludesSignalThroughWrapper:
    """The ``includes`` signal reaches infer_strategies through the
    strategies_from_item wrapper (additive keyword; checklist metadata
    carries no include data, so callers supply it)."""

    # Path and name chosen to match no path-signal tokens, so any extra
    # strategy must come from the includes signal alone.
    _ITEM = {"name": "compute_sum", "kind": "function", "metadata": {}}
    _FILE = "src/mathops.c"

    def test_baseline_without_includes(self):
        strategies = strategies_from_item(self._ITEM, self._FILE)
        assert STRATEGY_GENERAL in strategies
        assert STRATEGY_CONCURRENCY not in strategies
        assert STRATEGY_CRYPTO not in strategies

    def test_concurrency_include_forwarded(self):
        strategies = strategies_from_item(
            self._ITEM, self._FILE, includes=["#include <pthread.h>"],
        )
        assert STRATEGY_CONCURRENCY in strategies

    def test_crypto_include_forwarded(self):
        strategies = strategies_from_item(
            self._ITEM, self._FILE, includes=["#include <openssl/evp.h>"],
        )
        assert STRATEGY_CRYPTO in strategies

    def test_include_matching_is_case_insensitive(self):
        strategies = strategies_from_item(
            self._ITEM, self._FILE, includes=["import Threading"],
        )
        assert STRATEGY_CONCURRENCY in strategies

    def test_none_includes_is_default_compatible(self):
        assert strategies_from_item(self._ITEM, self._FILE, includes=None) == \
            strategies_from_item(self._ITEM, self._FILE)


class TestInferStrategiesMapEnrichments:
    def test_shared_state_adds_concurrency(self):
        result = infer_strategies(
            file_path="data.c",
            function_name="update",
            shared_state=[{"kind": "spin"}],
        )
        assert STRATEGY_CONCURRENCY in result

    def test_crypto_inventory_adds_crypto(self):
        result = infer_strategies(
            file_path="util.c",
            function_name="process",
            crypto_inventory=[{"kind": "hash"}],
        )
        assert STRATEGY_CRYPTO in result

    def test_ownership_model_adds_memory(self):
        result = infer_strategies(
            file_path="core.c",
            function_name="init",
            ownership_model=[{"kind": "allocator"}],
        )
        assert STRATEGY_MEMORY in result

    def test_empty_lists_no_effect(self):
        result = infer_strategies(
            file_path="util.c",
            function_name="helper",
            shared_state=[],
            crypto_inventory=[],
            ownership_model=[],
        )
        assert result == frozenset({STRATEGY_GENERAL})

    def test_none_no_effect(self):
        result = infer_strategies(
            file_path="util.c",
            function_name="helper",
            shared_state=None,
            crypto_inventory=None,
            ownership_model=None,
        )
        assert result == frozenset({STRATEGY_GENERAL})


class TestKindStrategy:
    def test_global_kind_adds_concurrency(self):
        result = infer_strategies(
            file_path="src/state.c",
            function_name="connection_count",
            kind="global",
        )
        assert STRATEGY_CONCURRENCY in result

    def test_macro_kind_adds_input(self):
        result = infer_strategies(
            file_path="include/defs.h",
            function_name="COPY_FROM_USER",
            kind="macro",
        )
        assert STRATEGY_INPUT in result

    def test_function_kind_no_extra(self):
        result = infer_strategies(
            file_path="src/util.c",
            function_name="helper",
            kind="function",
        )
        assert result == frozenset({STRATEGY_GENERAL})

    def test_none_kind_no_crash(self):
        result = infer_strategies(
            file_path="src/util.c",
            function_name="helper",
            kind=None,
        )
        assert result == frozenset({STRATEGY_GENERAL})


class TestStrategiesFromItemKind:
    def test_global_item(self):
        item = {"name": "g_count", "kind": "global", "metadata": {}}
        result = strategies_from_item(item, "src/state.c")
        assert STRATEGY_CONCURRENCY in result

    def test_macro_item(self):
        item = {"name": "PARSE_BUF", "kind": "macro", "metadata": {}}
        result = strategies_from_item(item, "include/defs.h")
        assert STRATEGY_INPUT in result


class TestVisibilityStrategy:
    def test_exported_adds_input(self):
        result = infer_strategies(
            file_path="src/api.c",
            function_name="handle",
            visibility="exported",
        )
        assert STRATEGY_INPUT in result

    def test_extern_adds_input(self):
        result = infer_strategies(
            file_path="src/lib.c",
            function_name="public_fn",
            visibility="extern",
        )
        assert STRATEGY_INPUT in result

    def test_public_adds_input(self):
        result = infer_strategies(
            file_path="src/api.c",
            function_name="process",
            visibility="public",
        )
        assert STRATEGY_INPUT in result

    def test_static_no_extra(self):
        result = infer_strategies(
            file_path="src/internal.c",
            function_name="helper",
            visibility="static",
        )
        assert result == frozenset({STRATEGY_GENERAL})

    def test_none_visibility_no_crash(self):
        result = infer_strategies(
            file_path="src/util.c",
            function_name="fn",
            visibility=None,
        )
        assert result == frozenset({STRATEGY_GENERAL})

    def test_visibility_via_item(self):
        item = {
            "name": "api_call",
            "metadata": {"visibility": "exported"},
        }
        result = strategies_from_item(item, "src/api.c")
        assert STRATEGY_INPUT in result


class TestPrimers:
    def test_aliasing_primer_returned(self):
        strategies = frozenset({STRATEGY_GENERAL, STRATEGY_ALIASING})
        primers = primers_for_strategies(strategies)
        assert any("ALIASING" in p for p in primers)

    def test_crypto_primer_returned(self):
        strategies = frozenset({STRATEGY_GENERAL, STRATEGY_CRYPTO})
        primers = primers_for_strategies(strategies)
        assert any("CRYPTO" in p for p in primers)

    def test_general_only_returns_no_primers(self):
        strategies = frozenset({STRATEGY_GENERAL})
        primers = primers_for_strategies(strategies)
        assert primers == []

    def test_multiple_strategies_return_multiple_primers(self):
        strategies = frozenset({STRATEGY_ALIASING, STRATEGY_CRYPTO})
        primers = primers_for_strategies(strategies)
        assert len(primers) == 2


class TestKernelStrategyPack:
    """The kernel token bulk moved to data/strategy_packs/
    linux_kernel.json, gated on kernel-tree detection. Equivalence:
    a kernel-marked target reproduces the pre-shrink routing; floor:
    without the pack the kernel tokens no longer route (proving the
    shrink is real)."""

    @staticmethod
    def _kernel_tree(tmp_path):
        (tmp_path / "Kconfig").write_text("config FOO\n")
        return tmp_path

    def test_rcu_source_routes_concurrency_on_kernel_target(self, tmp_path):
        src = "rcu_read_lock();\np = rcu_dereference(head);\n"
        base = infer_strategies(
            file_path="drivers/foo.c", function_name="get",
            source=src,
        )
        assert STRATEGY_CONCURRENCY not in base
        kernel = infer_strategies(
            file_path="drivers/foo.c", function_name="get",
            source=src, target_path=self._kernel_tree(tmp_path),
        )
        assert STRATEGY_CONCURRENCY in kernel

    def test_kref_source_routes_memory_on_kernel_target(self, tmp_path):
        # kref_get/kref_put are pack-tier tokens with no universal
        # substring overlap (unlike kmalloc/kfree, which the universal
        # "malloc("/"free(" seeds still catch as substrings).
        src = "kref_get(&f->kref);\nkref_put(&f->kref, rel);\n"
        assert STRATEGY_MEMORY not in infer_strategies(
            file_path="drivers/foo.c", function_name="setup",
            source=src,
        )
        assert STRATEGY_MEMORY in infer_strategies(
            file_path="drivers/foo.c", function_name="setup",
            source=src, target_path=self._kernel_tree(tmp_path),
        )

    def test_skb_path_routes_aliasing_on_kernel_target(self, tmp_path):
        assert STRATEGY_ALIASING not in infer_strategies(
            file_path="net/core/skbuff.c", function_name="clone",
        )
        assert STRATEGY_ALIASING in infer_strategies(
            file_path="net/core/skbuff.c", function_name="clone",
            target_path=self._kernel_tree(tmp_path),
        )

    def test_non_kernel_target_is_equivalent_to_no_target(self, tmp_path):
        (tmp_path / "Makefile").write_text("all:\n\tcc -o app app.c\n")
        kwargs = {
            "file_path": "net/core/skbuff.c",
            "function_name": "clone",
            "source": "rcu_read_lock();\nkmalloc(1, 0);\n",
        }
        assert infer_strategies(**kwargs) == infer_strategies(
            **kwargs, target_path=tmp_path,
        )

    def test_universal_seeds_route_without_pack(self):
        result = infer_strategies(
            file_path="src/server.c", function_name="drain",
            source=(
                "pthread_mutex_lock(&m);\n"
                "buf = malloc(n);\nfree(buf);\n"
            ),
        )
        assert STRATEGY_CONCURRENCY in result
        assert STRATEGY_MEMORY in result


class TestLearnedVocabStrategies:
    """Study-learned vocabulary routes project verbs — coverage the
    universal maps lack."""

    @staticmethod
    def _vocab():
        from core.audit.condition_smt import DomainVocabulary

        return DomainVocabulary.from_domain_model({
            "paired_operations": [
                {"acquire": "obj_take", "release": "obj_give",
                 "kind": "alloc"},
                {"acquire": "st_enter", "release": "st_leave",
                 "kind": "mutex"},
                {"acquire": "watch_arm", "release": "watch_disarm",
                 "kind": "callback"},
            ],
            "auth_predicates": [
                {"name": "sess_may_write", "kind": "permission"},
            ],
        })

    def test_learned_allocator_routes_memory(self):
        kwargs = {
            "file_path": "src/objstore.c",
            "function_name": "recycle",
            "source": "h = obj_take(store);\nobj_give(store, h);\n",
        }
        assert STRATEGY_MEMORY not in infer_strategies(**kwargs)
        assert STRATEGY_MEMORY in infer_strategies(
            **kwargs, domain_vocab=self._vocab(),
        )

    def test_learned_callback_verbs_route_memory(self):
        kwargs = {
            "file_path": "src/wd.c",
            "function_name": "teardown",
            "source": "watch_arm(&w, cb);\n",
        }
        assert STRATEGY_MEMORY not in infer_strategies(**kwargs)
        assert STRATEGY_MEMORY in infer_strategies(
            **kwargs, domain_vocab=self._vocab(),
        )

    def test_learned_lock_routes_concurrency(self):
        kwargs = {
            "file_path": "src/fsm.c",
            "function_name": "advance",
            "source": "st_enter(&s);\nst_leave(&s);\n",
        }
        assert STRATEGY_CONCURRENCY not in infer_strategies(**kwargs)
        assert STRATEGY_CONCURRENCY in infer_strategies(
            **kwargs, domain_vocab=self._vocab(),
        )

    def test_learned_auth_predicate_routes_auth(self):
        kwargs = {
            "file_path": "src/sess.c",
            "function_name": "commit",
            "source": "if (!sess_may_write(s)) return -1;\n",
        }
        assert STRATEGY_AUTH not in infer_strategies(**kwargs)
        assert STRATEGY_AUTH in infer_strategies(
            **kwargs, domain_vocab=self._vocab(),
        )

    def test_vocab_requires_call_site_in_source(self):
        # The learned name must be CALLED in the source — a comment
        # mention (no open paren) does not route.
        result = infer_strategies(
            file_path="src/objstore.c", function_name="doc",
            source="/* see obj_take for details */\n",
            domain_vocab=self._vocab(),
        )
        assert STRATEGY_MEMORY not in result

    def test_strategies_from_item_threads_vocab(self):
        item = {"name": "recycle", "kind": "function", "metadata": {}}
        result = strategies_from_item(
            item, "src/objstore.c",
            source="h = obj_take(pool);\n",
            domain_vocab=self._vocab(),
        )
        assert STRATEGY_MEMORY in result
