"""Tests for contract pair detection."""

from __future__ import annotations

from core.concepts.contract_pairs import (
    ContractKind,
    _split_name,
    discover_project_verbs,
)


def _func(name: str, file: str = "mod.c", line: int = 1) -> dict:
    return {"name": name, "file": file, "line": line}


# ── Verb extraction ──────────────────────────────────────────────────


class TestSplitName:
    """Verify underscore/camelCase/PascalCase splitting."""

    def test_underscore(self):
        assert _split_name("af_alg_count_tsgl") == ["af", "alg", "count", "tsgl"]

    def test_camel(self):
        assert _split_name("createWidget") == ["create", "widget"]

    def test_pascal(self):
        assert _split_name("DestroyWidget") == ["destroy", "widget"]

    def test_mixed_camel_upper(self):
        assert _split_name("getHTTPResponse") == ["get", "http", "response"]

    def test_leading_underscores(self):
        assert _split_name("__init__") == ["init"]

    def test_single_word(self):
        assert _split_name("free") == ["free"]

    def test_empty(self):
        assert _split_name("") == []


class TestDiscoverProjectVerbs:
    """Verb pair mining from function naming conventions."""

    def test_anchored_discovery(self):
        """kfree co-occurs with known alloc across 2+ nouns."""
        funcs = [
            _func("alloc_skb"), _func("kfree_skb"),
            _func("alloc_msg"), _func("kfree_msg"),
            _func("alloc_sock"), _func("kfree_sock"),
        ]
        discovered = discover_project_verbs(funcs)
        found_kfree = any(
            "kfree" in cons for _, cons, _ in discovered
        )
        assert found_kfree

    def test_unanchored_discovery(self):
        """begin/end co-occur across 2+ nouns → DISCOVERED kind."""
        funcs = [
            _func("begin_transaction"), _func("end_transaction"),
            _func("begin_session"), _func("end_session"),
        ]
        discovered = discover_project_verbs(funcs)
        found = any(
            k == ContractKind.DISCOVERED for _, _, k in discovered
        )
        assert found

    def test_prefix_filter_rejects_module_names(self):
        """Words appearing as first word in >10 functions are prefixes."""
        funcs = [_func(f"mod_{op}") for op in [
            "init", "exit", "bind", "release", "sendmsg",
            "recvmsg", "accept", "connect", "listen", "close",
            "poll", "ioctl",
        ]]
        discovered = discover_project_verbs(funcs)
        mod_verbs = [
            d for d in discovered
            if "mod" in d[0] or "mod" in d[1]
        ]
        assert mod_verbs == []

    def test_insufficient_evidence(self):
        """Single noun sharing is not enough (min_nouns=2)."""
        funcs = [
            _func("begin_work"), _func("end_work"),
        ]
        discovered = discover_project_verbs(funcs)
        assert discovered == []

    def test_empty_input(self):
        assert discover_project_verbs([]) == []

    def test_anchored_inherits_kind(self):
        """Discovered verb inherits contract kind from its anchor."""
        funcs = [
            _func("alloc_buf"), _func("release_buf"),
            _func("alloc_conn"), _func("release_conn"),
        ]
        discovered = discover_project_verbs(funcs)
        release_entries = [
            (p, c, k) for p, c, k in discovered
            if "release" in c or "release" in p
        ]
        if release_entries:
            _, _, kind = release_entries[0]
            assert kind != ContractKind.DISCOVERED


# ── Call-graph enrichment ───────────────────────────────────────────
