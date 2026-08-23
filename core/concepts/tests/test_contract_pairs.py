"""Tests for contract pair detection."""

from __future__ import annotations

from core.concepts.contract_pairs import (
    ContractKind,
    ContractPairGroup,
    _extract_verb_noun,
    _load_verbs_from_file,
    _split_name,
    build_contract_index,
    detect_contract_pairs,
    discover_project_verbs,
    format_contract_pairs_for_prompt,
    load_project_verbs,
    load_project_verbs_with_siblings,
    save_project_verbs,
)


def _func(name: str, file: str = "mod.c", line: int = 1) -> dict:
    return {"name": name, "file": file, "line": line}


# ── Verb extraction ──────────────────────────────────────────────────


class TestExtractVerbNoun:
    def test_count_tsgl(self):
        results = _extract_verb_noun("af_alg_count_tsgl")
        kinds = {(v, n, k.value, r) for v, n, k, r in results}
        assert ("count", "af_alg_tsgl", "size_consumer", "producer") in kinds

    def test_pull_tsgl(self):
        results = _extract_verb_noun("af_alg_pull_tsgl")
        kinds = {(v, n, k.value, r) for v, n, k, r in results}
        assert ("pull", "af_alg_tsgl", "size_consumer", "consumer") in kinds

    def test_alloc_free(self):
        alloc = _extract_verb_noun("my_cache_alloc")
        free = _extract_verb_noun("my_cache_free")
        alloc_nouns = {(n, k.value) for _, n, k, _ in alloc}
        free_nouns = {(n, k.value) for _, n, k, _ in free}
        assert ("my_cache", "alloc_free") in alloc_nouns
        assert ("my_cache", "alloc_free") in free_nouns

    def test_lock_unlock(self):
        lock = _extract_verb_noun("lock_sock")
        unlock = _extract_verb_noun("unlock_sock")
        assert any(
            n == "sock" and k == ContractKind.LOCK_UNLOCK and r == "producer"
            for _, n, k, r in lock
        )
        assert any(
            n == "sock" and k == ContractKind.LOCK_UNLOCK and r == "consumer"
            for _, n, k, r in unlock
        )

    def test_get_put_page(self):
        get = _extract_verb_noun("get_page")
        put = _extract_verb_noun("put_page")
        assert any(
            n == "page" and k == ContractKind.REF_UNREF and r == "producer"
            for _, n, k, r in get
        )
        assert any(
            n == "page" and k == ContractKind.REF_UNREF and r == "consumer"
            for _, n, k, r in put
        )

    def test_init_exit(self):
        init = _extract_verb_noun("algif_aead_init")
        exit_ = _extract_verb_noun("algif_aead_exit")
        assert any(
            n == "algif_aead" and k == ContractKind.INIT_CLEANUP
            for _, n, k, _ in init
        )
        assert any(
            n == "algif_aead" and k == ContractKind.INIT_CLEANUP
            for _, n, k, _ in exit_
        )

    def test_register_unregister(self):
        reg = _extract_verb_noun("af_alg_register_type")
        unreg = _extract_verb_noun("af_alg_unregister_type")
        assert any(
            k == ContractKind.INIT_CLEANUP and r == "producer"
            for _, _, k, r in reg
        )
        assert any(
            k == ContractKind.INIT_CLEANUP and r == "consumer"
            for _, _, k, r in unreg
        )

    def test_single_word_returns_empty(self):
        assert _extract_verb_noun("main") == []

    def test_leading_underscore_stripped(self):
        results = _extract_verb_noun("_create_buffer")
        assert any(
            k == ContractKind.ALLOC_FREE and r == "producer"
            for _, _, k, r in results
        )

    def test_noise_noun_rejected(self):
        results = _extract_verb_noun("alloc_data")
        assert all(n != "data" for _, n, _, _ in results)

    def test_open_close(self):
        op = _extract_verb_noun("open_connection")
        cl = _extract_verb_noun("close_connection")
        assert any(
            n == "connection" and k == ContractKind.ALLOC_FREE
            for _, n, k, _ in op
        )
        assert any(
            n == "connection" and k == ContractKind.ALLOC_FREE
            for _, n, k, _ in cl
        )

    def test_multiword_verb_teardown(self):
        results = _extract_verb_noun("subsys_teardown")
        assert any(
            k == ContractKind.INIT_CLEANUP and r == "consumer"
            for _, _, k, r in results
        )


# ── Detection ─────────────────────────────────────────────────────────


class TestDetectContractPairs:
    def test_count_pull_pair(self):
        funcs = [
            _func("af_alg_count_tsgl", "af_alg.c", 646),
            _func("af_alg_pull_tsgl", "af_alg.c", 702),
        ]
        pairs = detect_contract_pairs(funcs)
        assert len(pairs) >= 1
        pair = next(
            p for p in pairs if p.contract_kind == ContractKind.SIZE_CONSUMER
        )
        assert pair.noun == "af_alg_tsgl"
        assert len(pair.producers) == 1
        assert len(pair.consumers) == 1
        assert pair.producers[0].function == "af_alg_count_tsgl"
        assert pair.consumers[0].function == "af_alg_pull_tsgl"

    def test_alloc_free_pair(self):
        funcs = [
            _func("widget_alloc", "widget.c"),
            _func("widget_free", "widget.c"),
        ]
        pairs = detect_contract_pairs(funcs)
        af_pairs = [
            p for p in pairs if p.contract_kind == ContractKind.ALLOC_FREE
        ]
        assert len(af_pairs) >= 1
        pair = af_pairs[0]
        assert pair.producers[0].function == "widget_alloc"
        assert pair.consumers[0].function == "widget_free"

    def test_one_to_many_free(self):
        funcs = [
            _func("channel_alloc"),
            _func("channel_free"),
            _func("channel_destroy"),
        ]
        pairs = detect_contract_pairs(funcs)
        af_pairs = [
            p for p in pairs if p.contract_kind == ContractKind.ALLOC_FREE
        ]
        assert len(af_pairs) >= 1
        pair = af_pairs[0]
        assert len(pair.producers) == 1
        assert len(pair.consumers) >= 2

    def test_lock_unlock(self):
        funcs = [_func("lock_sock"), _func("unlock_sock")]
        pairs = detect_contract_pairs(funcs)
        lu = [p for p in pairs if p.contract_kind == ContractKind.LOCK_UNLOCK]
        assert len(lu) == 1
        assert lu[0].producers[0].function == "lock_sock"
        assert lu[0].consumers[0].function == "unlock_sock"

    def test_ref_unref(self):
        funcs = [_func("get_page"), _func("put_page")]
        pairs = detect_contract_pairs(funcs)
        rr = [p for p in pairs if p.contract_kind == ContractKind.REF_UNREF]
        assert len(rr) == 1

    def test_init_cleanup(self):
        funcs = [
            _func("algif_aead_init"),
            _func("algif_aead_exit"),
        ]
        pairs = detect_contract_pairs(funcs)
        ic = [p for p in pairs if p.contract_kind == ContractKind.INIT_CLEANUP]
        assert len(ic) >= 1

    def test_no_partner_no_pair(self):
        funcs = [_func("count_items")]
        pairs = detect_contract_pairs(funcs)
        sc = [p for p in pairs if p.contract_kind == ContractKind.SIZE_CONSUMER]
        assert sc == []

    def test_empty_input(self):
        assert detect_contract_pairs([]) == []

    def test_cross_file_default(self):
        funcs = [
            _func("cache_alloc", "alloc.c"),
            _func("cache_free", "free.c"),
        ]
        pairs = detect_contract_pairs(funcs, cross_file=True)
        assert len(pairs) >= 1

    def test_same_file_only(self):
        funcs = [
            _func("cache_alloc", "alloc.c"),
            _func("cache_free", "free.c"),
        ]
        pairs = detect_contract_pairs(funcs, cross_file=False)
        af = [p for p in pairs if p.contract_kind == ContractKind.ALLOC_FREE]
        assert af == []

    def test_same_file_passes_filter(self):
        funcs = [
            _func("cache_alloc", "cache.c"),
            _func("cache_free", "cache.c"),
        ]
        pairs = detect_contract_pairs(funcs, cross_file=False)
        af = [p for p in pairs if p.contract_kind == ContractKind.ALLOC_FREE]
        assert len(af) >= 1

    def test_invariant_populated(self):
        funcs = [_func("lock_db"), _func("unlock_db")]
        pairs = detect_contract_pairs(funcs)
        lu = [p for p in pairs if p.contract_kind == ContractKind.LOCK_UNLOCK]
        assert lu[0].invariant
        assert "lock" in lu[0].invariant.lower() or "unlock" in lu[0].invariant.lower()


# ── Index ─────────────────────────────────────────────────────────────


class TestBuildContractIndex:
    def test_lookup_by_function(self):
        funcs = [
            _func("af_alg_count_tsgl"),
            _func("af_alg_pull_tsgl"),
        ]
        pairs = detect_contract_pairs(funcs)
        idx = build_contract_index(pairs)
        assert "af_alg_count_tsgl" in idx
        assert "af_alg_pull_tsgl" in idx

    def test_empty_pairs(self):
        assert build_contract_index([]) == {}


# ── Group methods ─────────────────────────────────────────────────────


class TestContractPairGroup:
    def _make_pair(self) -> ContractPairGroup:
        funcs = [
            _func("af_alg_count_tsgl", "af_alg.c"),
            _func("af_alg_pull_tsgl", "af_alg.c"),
        ]
        pairs = detect_contract_pairs(funcs)
        return next(
            p for p in pairs if p.contract_kind == ContractKind.SIZE_CONSUMER
        )

    def test_partners_of_producer(self):
        pair = self._make_pair()
        partners = pair.partners_of("af_alg_count_tsgl")
        assert len(partners) == 1
        assert partners[0].function == "af_alg_pull_tsgl"

    def test_partners_of_consumer(self):
        pair = self._make_pair()
        partners = pair.partners_of("af_alg_pull_tsgl")
        assert len(partners) == 1
        assert partners[0].function == "af_alg_count_tsgl"

    def test_partners_of_unknown(self):
        pair = self._make_pair()
        assert pair.partners_of("unknown_func") == []

    def test_role_of(self):
        pair = self._make_pair()
        assert pair.role_of("af_alg_count_tsgl") == "producer"
        assert pair.role_of("af_alg_pull_tsgl") == "consumer"
        assert pair.role_of("other") == ""

    def test_to_dict(self):
        pair = self._make_pair()
        d = pair.to_dict()
        assert d["contract_kind"] == "size_consumer"
        assert d["noun"] == "af_alg_tsgl"
        assert len(d["producers"]) == 1
        assert len(d["consumers"]) == 1


# ── Prompt formatting ─────────────────────────────────────────────────


class TestFormatForPrompt:
    def test_empty(self):
        assert format_contract_pairs_for_prompt([], "foo") == ""

    def test_consumer_sees_producer(self):
        funcs = [
            _func("af_alg_count_tsgl", "af_alg.c"),
            _func("af_alg_pull_tsgl", "af_alg.c"),
        ]
        pairs = detect_contract_pairs(funcs)
        text = format_contract_pairs_for_prompt(pairs, "af_alg_pull_tsgl")
        assert "af_alg_count_tsgl" in text
        assert "consumer" in text
        assert "traversal" in text.lower() or "invariant" in text.lower()

    def test_producer_sees_consumer(self):
        funcs = [
            _func("af_alg_count_tsgl", "af_alg.c"),
            _func("af_alg_pull_tsgl", "af_alg.c"),
        ]
        pairs = detect_contract_pairs(funcs)
        text = format_contract_pairs_for_prompt(pairs, "af_alg_count_tsgl")
        assert "af_alg_pull_tsgl" in text
        assert "producer" in text

    def test_multiple_consumers(self):
        funcs = [
            _func("channel_alloc"),
            _func("channel_free"),
            _func("channel_destroy"),
        ]
        pairs = detect_contract_pairs(funcs)
        text = format_contract_pairs_for_prompt(pairs, "channel_alloc")
        assert "channel_free" in text
        assert "channel_destroy" in text

    def test_no_matching_group(self):
        group = ContractPairGroup(
            group_id="test",
            contract_kind=ContractKind.LOCK_UNLOCK,
            noun="foo",
        )
        text = format_contract_pairs_for_prompt([group], "unrelated_func")
        assert "Contract partners" in text or text == ""


# ── Real-world patterns ──────────────────────────────────────────────


class TestRealWorldPatterns:
    """Patterns drawn from real kernel/userspace code."""

    def test_kernel_register_unregister(self):
        funcs = [
            _func("af_alg_register_type", "af_alg.c"),
            _func("af_alg_unregister_type", "af_alg.c"),
        ]
        pairs = detect_contract_pairs(funcs)
        ic = [p for p in pairs if p.contract_kind == ContractKind.INIT_CLEANUP]
        assert len(ic) >= 1

    def test_kernel_module_init_exit(self):
        funcs = [
            _func("algif_aead_init"),
            _func("algif_aead_exit"),
        ]
        pairs = detect_contract_pairs(funcs)
        ic = [p for p in pairs if p.contract_kind == ContractKind.INIT_CLEANUP]
        assert len(ic) >= 1

    def test_sock_kmalloc_kfree(self):
        funcs = [
            _func("sock_alloc"),
            _func("sock_free"),
        ]
        pairs = detect_contract_pairs(funcs)
        af = [p for p in pairs if p.contract_kind == ContractKind.ALLOC_FREE]
        assert len(af) >= 1

    def test_python_incref_decref(self):
        funcs = [
            _func("widget_incref"),
            _func("widget_decref"),
        ]
        pairs = detect_contract_pairs(funcs)
        rr = [p for p in pairs if p.contract_kind == ContractKind.REF_UNREF]
        assert len(rr) >= 1

    def test_mutex_lock_unlock(self):
        funcs = [
            _func("lock_session"),
            _func("unlock_session"),
        ]
        pairs = detect_contract_pairs(funcs)
        lu = [p for p in pairs if p.contract_kind == ContractKind.LOCK_UNLOCK]
        assert len(lu) == 1
        assert lu[0].noun == "session"

    def test_mixed_kinds_same_noun(self):
        """Different contract kinds can share a noun without conflict."""
        funcs = [
            _func("conn_open"),
            _func("conn_close"),
            _func("conn_lock"),
            _func("conn_unlock"),
        ]
        pairs = detect_contract_pairs(funcs)
        af = [p for p in pairs if p.contract_kind == ContractKind.ALLOC_FREE]
        lu = [p for p in pairs if p.contract_kind == ContractKind.LOCK_UNLOCK]
        assert len(af) >= 1
        assert len(lu) >= 1

    def test_create_destroy_pattern(self):
        funcs = [
            _func("session_create"),
            _func("session_destroy"),
        ]
        pairs = detect_contract_pairs(funcs)
        af = [p for p in pairs if p.contract_kind == ContractKind.ALLOC_FREE]
        assert len(af) >= 1


# ── Adversarial / edge cases ─────────────────────────────────────────


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


class TestAdversarialExtraction:
    """Edge cases that previously produced false matches."""

    def test_get_name_is_noise(self):
        """get_name should NOT match — 'name' is a noise noun."""
        results = _extract_verb_noun("get_name")
        assert results == []

    def test_put_name_is_noise(self):
        results = _extract_verb_noun("put_name")
        assert results == []

    def test_lock_state_is_noise(self):
        results = _extract_verb_noun("lock_state")
        assert results == []

    def test_create_table_is_noise(self):
        results = _extract_verb_noun("create_table")
        assert results == []

    def test_get_page_not_noise(self):
        """get_page SHOULD match — 'page' is a real resource noun."""
        results = _extract_verb_noun("get_page")
        assert any(k == ContractKind.REF_UNREF for _, _, k, _ in results)

    def test_dunder_init_returns_empty(self):
        """__init__ splits to single word 'init' — too short."""
        assert _extract_verb_noun("__init__") == []

    def test_multi_verb_name(self):
        """A name containing multiple verbs extracts multiple matches,
        but they have different nouns — so no false pair is created
        unless a matching partner exists for each."""
        results = _extract_verb_noun("count_free_alloc_init")
        assert len(results) >= 3
        nouns = {n for _, n, _, _ in results}
        assert len(nouns) >= 3

    def test_multi_verb_no_false_pair(self):
        """Even with multi-verb extraction, no pair unless partner exists."""
        funcs = [_func("count_free_alloc_init")]
        pairs = detect_contract_pairs(funcs)
        assert pairs == []

    def test_empty_function_name(self):
        assert _extract_verb_noun("") == []

    def test_verb_only(self):
        """A name that IS a verb but has no noun part → no extraction."""
        assert _extract_verb_noun("init") == []
        assert _extract_verb_noun("free") == []
        assert _extract_verb_noun("count") == []


class TestAdversarialDetection:
    """Detection-level edge cases."""

    def test_cross_file_false_filters_per_partner(self):
        """With cross_file=False, only partners in shared files survive."""
        funcs = [
            _func("channel_alloc", "a.c"),
            _func("channel_free", "a.c"),
            _func("channel_destroy", "b.c"),
        ]
        pairs = detect_contract_pairs(funcs, cross_file=False)
        af = [p for p in pairs if p.contract_kind == ContractKind.ALLOC_FREE]
        assert len(af) == 1
        consumer_files = {c.file for c in af[0].consumers}
        assert consumer_files == {"a.c"}

    def test_noise_pair_not_created(self):
        """get_name + put_name should NOT create a ref_unref pair."""
        funcs = [_func("get_name"), _func("put_name")]
        pairs = detect_contract_pairs(funcs)
        rr = [p for p in pairs if p.contract_kind == ContractKind.REF_UNREF]
        assert rr == []

    def test_real_pair_still_detected_after_noise_filter(self):
        """get_page + put_page should still work."""
        funcs = [_func("get_page"), _func("put_page")]
        pairs = detect_contract_pairs(funcs)
        rr = [p for p in pairs if p.contract_kind == ContractKind.REF_UNREF]
        assert len(rr) == 1


class TestCamelCaseDetection:
    """CamelCase and PascalCase function naming."""

    def test_camel_alloc_free(self):
        funcs = [_func("createWidget"), _func("destroyWidget")]
        pairs = detect_contract_pairs(funcs)
        af = [p for p in pairs if p.contract_kind == ContractKind.ALLOC_FREE]
        assert len(af) >= 1

    def test_camel_ref_unref(self):
        funcs = [_func("retainTexture"), _func("dropTexture")]
        pairs = detect_contract_pairs(funcs)
        rr = [p for p in pairs if p.contract_kind == ContractKind.REF_UNREF]
        assert len(rr) >= 1

    def test_pascal_init_cleanup(self):
        funcs = [_func("InitSubsystem"), _func("CleanupSubsystem")]
        pairs = detect_contract_pairs(funcs)
        ic = [p for p in pairs if p.contract_kind == ContractKind.INIT_CLEANUP]
        assert len(ic) >= 1


# ── Verb discovery ──────────────────────────────────────────────────


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


def _cg(calls):
    """Build a minimal call_graph dict for testing."""
    return {"calls": calls}


def _call(caller, callee, line=0):
    """Build a call entry."""
    return {"caller": caller, "chain": [callee], "line": line}


class TestCallGraphEnrichment:
    """Call-graph co-occurrence evidence on name-based pairs."""

    def test_enrichment_adds_evidence(self):
        funcs = [
            _func("count_entries", "mod.c"),
            _func("pull_entries", "mod.c"),
        ]
        call_graphs = {
            "caller.c": _cg([
                _call("do_work", "count_entries", 10),
                _call("do_work", "pull_entries", 20),
            ]),
        }
        pairs = detect_contract_pairs(funcs, call_graphs=call_graphs)
        sc = [p for p in pairs if p.contract_kind == ContractKind.SIZE_CONSUMER]
        assert len(sc) == 1
        assert len(sc[0].callers_evidence) == 1
        ev = sc[0].callers_evidence[0]
        assert ev["caller"] == "do_work"
        assert ev["producer_calls"][0]["line"] == 10
        assert ev["consumer_calls"][0]["line"] == 20

    def test_no_enrichment_without_call_graph(self):
        funcs = [
            _func("count_entries"), _func("pull_entries"),
        ]
        pairs = detect_contract_pairs(funcs)
        sc = [p for p in pairs if p.contract_kind == ContractKind.SIZE_CONSUMER]
        assert len(sc) == 1
        assert sc[0].callers_evidence == []

    def test_multiple_callers(self):
        funcs = [
            _func("lock_db", "db.c"),
            _func("unlock_db", "db.c"),
        ]
        call_graphs = {
            "a.c": _cg([
                _call("handler_a", "lock_db", 5),
                _call("handler_a", "unlock_db", 15),
            ]),
            "b.c": _cg([
                _call("handler_b", "lock_db", 8),
                _call("handler_b", "unlock_db", 22),
            ]),
        }
        pairs = detect_contract_pairs(funcs, call_graphs=call_graphs)
        lu = [p for p in pairs if p.contract_kind == ContractKind.LOCK_UNLOCK]
        assert len(lu) == 1
        assert len(lu[0].callers_evidence) == 2

    def test_prompt_includes_callgraph_evidence(self):
        funcs = [
            _func("count_entries", "mod.c"),
            _func("pull_entries", "mod.c"),
        ]
        call_graphs = {
            "caller.c": _cg([
                _call("do_work", "count_entries", 10),
                _call("do_work", "pull_entries", 20),
            ]),
        }
        pairs = detect_contract_pairs(funcs, call_graphs=call_graphs)
        text = format_contract_pairs_for_prompt(pairs, "pull_entries")
        assert "Call-graph" in text
        assert "do_work" in text
        assert "10" in text


# ── Call-graph co-occurrence discovery ──────────────────────────────


class TestCallGraphDiscovery:
    """Discovery of unnamed pairs from caller patterns."""

    def test_discovers_co_invoked_pair(self):
        funcs = [
            _func("foo", "mod.c"),
            _func("bar", "mod.c"),
        ]
        call_graphs = {
            "a.c": _cg([
                _call("caller_a", "foo", 10),
                _call("caller_a", "bar", 20),
            ]),
            "b.c": _cg([
                _call("caller_b", "foo", 5),
                _call("caller_b", "bar", 15),
            ]),
        }
        pairs = detect_contract_pairs(funcs, call_graphs=call_graphs)
        cg = [p for p in pairs if p.discovery_source == "call_graph"]
        assert len(cg) >= 1
        names = {
            p.function
            for g in cg
            for p in g.all_partners()
        }
        assert "foo" in names
        assert "bar" in names

    def test_skips_already_paired(self):
        """Functions already in name-based pairs are not re-discovered."""
        funcs = [
            _func("count_entries", "mod.c"),
            _func("pull_entries", "mod.c"),
        ]
        call_graphs = {
            "a.c": _cg([
                _call("c1", "count_entries", 10),
                _call("c1", "pull_entries", 20),
            ]),
            "b.c": _cg([
                _call("c2", "count_entries", 5),
                _call("c2", "pull_entries", 15),
            ]),
        }
        pairs = detect_contract_pairs(funcs, call_graphs=call_graphs)
        cg = [p for p in pairs if p.discovery_source == "call_graph"]
        cg_names = {
            p.function for g in cg for p in g.all_partners()
        }
        assert "count_entries" not in cg_names
        assert "pull_entries" not in cg_names

    def test_single_caller_insufficient(self):
        """min_callers=2: one caller is not enough."""
        funcs = [_func("foo"), _func("bar")]
        call_graphs = {
            "a.c": _cg([
                _call("sole_caller", "foo"),
                _call("sole_caller", "bar"),
            ]),
        }
        pairs = detect_contract_pairs(funcs, call_graphs=call_graphs)
        cg = [p for p in pairs if p.discovery_source == "call_graph"]
        assert cg == []

    def test_utility_functions_filtered(self):
        """Functions called from >12 callers are treated as utilities."""
        funcs = [_func("util"), _func("rare")]
        calls = [_call(f"caller_{i}", "util") for i in range(15)]
        calls.extend([
            _call("caller_0", "rare"),
            _call("caller_1", "rare"),
        ])
        call_graphs = {"mod.c": _cg(calls)}
        pairs = detect_contract_pairs(funcs, call_graphs=call_graphs)
        cg = [p for p in pairs if p.discovery_source == "call_graph"]
        assert cg == []


# ── Persistence ─────────────────────────────────────────────────────


class TestPersistence:
    """Save/load discovered vocabulary."""

    def test_roundtrip(self, tmp_path):
        verbs = [
            (frozenset({"kfree"}), frozenset(), ContractKind.ALLOC_FREE),
            (frozenset({"begin"}), frozenset({"end"}), ContractKind.DISCOVERED),
        ]
        save_project_verbs(tmp_path, verbs)
        loaded = load_project_verbs(tmp_path)
        assert len(loaded) == 2
        kinds = {k.value for _, _, k in loaded}
        assert "alloc_free" in kinds
        assert "discovered" in kinds

    def test_load_missing_file(self, tmp_path):
        assert load_project_verbs(tmp_path) == []

    def test_serialisation_is_order_independent(self, tmp_path):
        # The caller dedups via a set, so input order is arbitrary —
        # identical vocabularies must produce byte-identical files.
        verbs = [
            (frozenset({"kfree"}), frozenset(), ContractKind.ALLOC_FREE),
            (frozenset({"begin"}), frozenset({"end"}), ContractKind.DISCOVERED),
            (frozenset({"open"}), frozenset({"close"}), ContractKind.DISCOVERED),
        ]
        a_dir = tmp_path / "a"
        b_dir = tmp_path / "b"
        a_dir.mkdir()
        b_dir.mkdir()
        save_project_verbs(a_dir, verbs)
        save_project_verbs(b_dir, list(reversed(verbs)))
        a = (a_dir / "verb-contracts.json").read_text(encoding="utf-8")
        b = (b_dir / "verb-contracts.json").read_text(encoding="utf-8")
        assert a == b

    def test_load_corrupt_json(self, tmp_path):
        (tmp_path / "verb-contracts.json").write_text("not json")
        assert load_project_verbs(tmp_path) == []

    def test_detection_uses_persisted_verbs(self, tmp_path):
        """Prior run discovered kfree; this run uses it."""
        save_project_verbs(tmp_path, [
            (frozenset(), frozenset({"kfree"}), ContractKind.ALLOC_FREE),
        ])
        funcs = [_func("alloc_skb"), _func("kfree_skb")]
        pairs = detect_contract_pairs(funcs, project_dir=tmp_path)
        af = [p for p in pairs if p.contract_kind == ContractKind.ALLOC_FREE]
        assert len(af) >= 1


class TestLoadProjectVerbsWithSiblings:
    """Tests for sibling-directory verb vocabulary transfer."""

    def test_finds_verbs_in_own_dir(self, tmp_path):
        run = tmp_path / "project" / "run1"
        run.mkdir(parents=True)
        save_project_verbs(run, [
            (frozenset({"kfree"}), frozenset(), ContractKind.ALLOC_FREE),
        ])
        result = load_project_verbs_with_siblings(run)
        assert len(result) == 1

    def test_finds_verbs_in_sibling(self, tmp_path):
        project = tmp_path / "project"
        run1 = project / "run1"
        run2 = project / "run2"
        run1.mkdir(parents=True)
        run2.mkdir(parents=True)
        save_project_verbs(run1, [
            (frozenset({"lock"}), frozenset({"unlock"}), ContractKind.LOCK_UNLOCK),
        ])
        result = load_project_verbs_with_siblings(run2)
        assert len(result) == 1
        assert result[0][2] == ContractKind.LOCK_UNLOCK

    def test_prefers_own_dir_over_sibling(self, tmp_path):
        project = tmp_path / "project"
        run1 = project / "run1"
        run2 = project / "run2"
        run1.mkdir(parents=True)
        run2.mkdir(parents=True)
        save_project_verbs(run1, [
            (frozenset({"lock"}), frozenset({"unlock"}), ContractKind.LOCK_UNLOCK),
        ])
        save_project_verbs(run2, [
            (frozenset({"kfree"}), frozenset(), ContractKind.ALLOC_FREE),
        ])
        result = load_project_verbs_with_siblings(run2)
        assert len(result) == 1
        assert result[0][2] == ContractKind.ALLOC_FREE

    def test_no_verbs_anywhere(self, tmp_path):
        project = tmp_path / "project"
        run = project / "run1"
        run.mkdir(parents=True)
        assert load_project_verbs_with_siblings(run) == []

    def test_skips_symlinks(self, tmp_path):
        project = tmp_path / "project"
        run1 = project / "run1"
        run1.mkdir(parents=True)
        malicious = tmp_path / "elsewhere"
        malicious.mkdir()
        save_project_verbs(malicious, [
            (frozenset({"evil"}), frozenset(), ContractKind.DISCOVERED),
        ])
        (project / "run0_symlink").symlink_to(malicious)
        result = load_project_verbs_with_siblings(run1)
        assert result == []

    def test_skips_files_not_dirs(self, tmp_path):
        project = tmp_path / "project"
        run1 = project / "run1"
        run1.mkdir(parents=True)
        (project / "some_file").write_text("not a dir")
        assert load_project_verbs_with_siblings(run1) == []


class TestLoadVerbsFromFileValidation:
    """Tests for type validation in _load_verbs_from_file."""

    def test_string_producers_rejected(self, tmp_path):
        """frozenset('alloc') character explosion must not happen."""
        import json
        vf = tmp_path / "verb-contracts.json"
        vf.write_text(json.dumps({"discovered_verbs": [
            {"producers": "alloc", "consumers": [], "kind": "alloc_free"},
        ]}))
        assert _load_verbs_from_file(vf) == []

    def test_non_string_list_elements_rejected(self, tmp_path):
        import json
        vf = tmp_path / "verb-contracts.json"
        vf.write_text(json.dumps({"discovered_verbs": [
            {"producers": [1, None], "consumers": ["free"], "kind": "alloc_free"},
        ]}))
        assert _load_verbs_from_file(vf) == []

    def test_valid_list_accepted(self, tmp_path):
        import json
        vf = tmp_path / "verb-contracts.json"
        vf.write_text(json.dumps({"discovered_verbs": [
            {"producers": ["alloc"], "consumers": ["free"], "kind": "alloc_free"},
        ]}))
        result = _load_verbs_from_file(vf)
        assert len(result) == 1
        assert result[0][0] == frozenset({"alloc"})
