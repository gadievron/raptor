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
