"""Resource-bounds channel tests (design §1.7) — hermetic, CVE-anchored
fixture pairs: the deviant form asserts full receipts, the twin asserts
the exact enumerated reason string (the consistency test discipline)."""

from __future__ import annotations

import pytest

from core.audit.fail_open_roles import SEED_SET_CAP, RoleContext
from core.audit.resource_bounds import (
    DETECTION_VARIANT_SUFFIX,
    INCONCLUSIVE_REASONS,
    REASON_GUARD_UNDECIDED,
    REASON_HYPOTHESIS_UNBINDABLE,
    REASON_LANGUAGE_UNSUPPORTED,
    REASON_VOCAB_UNBOUND,
    RESOURCE_BOUNDS_CWES,
    RULE_UNBOUNDED,
    _SEED_ALLOC_NAMES,
    _SEED_INSERT_NAMES,
    is_detection_rule_id,
    is_resource_bounds_hypothesis,
    learned_collection_pairs,
    resource_bounds_applicable,
    run_resource_bounds_check,
    run_resource_bounds_prepass,
    seed_budget_violations,
)

pytest.importorskip("tree_sitter_c", reason="CFG leg needs tree-sitter")


HYP = "the session list grows without limit — memory exhaustion"

# CVE-2024-2511 anchor (OpenSSL session-cache unbounded growth):
# insert-into-list on the accept path, no cap anywhere in scope.
CVE_2024_2511 = """\
int ssl_session_cache_add(struct ssl_ctx *ctx, struct sess *s)
{
    lock(ctx);
    list_add(&ctx->sessions, s);
    ctx->sess_count++;
    unlock(ctx);
    return 0;
}

int accept_conn(struct ssl_ctx *ctx, struct sess *s)
{
    return ssl_session_cache_add(ctx, s);
}
"""

CVE_2024_2511_TWIN = """\
int ssl_session_cache_add(struct ssl_ctx *ctx, struct sess *s)
{
    if (ctx->sess_count >= MAX_SESSIONS)
        return -1;
    list_add(&ctx->sessions, s);
    ctx->sess_count++;
    return 0;
}
"""

# quic_port-shaped fixture: insert + TODO comment admitting the gap.
QUIC_PORT = """\
int port_on_new_conn(struct port *p, struct conn *c)
{
    /* TODO(QUIC FUTURE): add a half-open accounting limit */
    ossl_track_conn(&p->incoming_channel_list, c);
    return 0;
}
"""

CALLER_BOUND_DEPTH2 = {
    "src/inner.c": """\
int cache_insert(struct cache *cc, struct item *it)
{
    list_add(&cc->items, it);
    return 0;
}
""",
    "src/mid.c": """\
int cache_store(struct cache *cc, struct item *it)
{
    return cache_insert(cc, it);
}
""",
    "src/outer.c": """\
int handle_request(struct cache *cc, struct item *it)
{
    if (cc->item_count >= CACHE_LIMIT)
        return -1;
    return cache_store(cc, it);
}
""",
}

ALLOC_IN_LOOP = """\
int parse_records(struct hdr *hdr, char *dst)
{
    int len = ntohs(hdr->count);
    int i;
    for (i = 0; i < len; i++) {
        char *rec = malloc(REC_SIZE);
        consume(rec, dst);
    }
    return 0;
}
"""

ALLOC_IN_LOOP_TWIN = """\
int parse_records(struct hdr *hdr, char *dst)
{
    int len = ntohs(hdr->count);
    int i;
    len = min(len, MAX_RECORDS);
    for (i = 0; i < len; i++) {
        char *rec = malloc(REC_SIZE);
        consume(rec, dst);
    }
    return 0;
}
"""


def _write(tmp_path, rel, text):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def _entry_ctx(file, function):
    return RoleContext(context_map={
        "entry_points": [{"file": file, "function": function}],
    })


class TestClassifier:
    def test_positive_shapes(self):
        for text in (
            "the incoming list grows without limit",
            "unbounded allocation of channel structs per packet",
            "no upper bound on queued requests — memory exhaustion",
            "attacker can enqueue unlimited allocations",
            "no backpressure on the accept path",
        ):
            assert is_resource_bounds_hypothesis(text), text

    def test_negative_dispatch(self):
        # §1.7: an unchecked-memcpy hypothesis must not classify.
        assert not is_resource_bounds_hypothesis(
            "unchecked memcpy overflow of `dst` in handler",
        )
        assert not is_resource_bounds_hypothesis("")

    def test_cwe_membership(self):
        assert resource_bounds_applicable("CWE-770")
        assert resource_bounds_applicable("CWE-400")
        assert resource_bounds_applicable("400")
        assert not resource_bounds_applicable("CWE-120")
        assert RESOURCE_BOUNDS_CWES == {"CWE-770", "CWE-400", "CWE-772"}

    def test_detection_rule_id(self):
        assert is_detection_rule_id(
            RULE_UNBOUNDED + DETECTION_VARIANT_SUFFIX,
        )
        assert not is_detection_rule_id(RULE_UNBOUNDED)
        assert not is_detection_rule_id("fail_open:ignored-return-naming")


class TestVocabPolicy:
    def test_seed_budget(self):
        assert seed_budget_violations() == []
        assert len(_SEED_INSERT_NAMES) <= SEED_SET_CAP
        assert len(_SEED_ALLOC_NAMES) <= SEED_SET_CAP

    def test_learned_pairs_exclude_llm_prior(self):
        dm = {"paired_operations": [
            {"acquire": "a_add", "release": "a_del", "kind": "collection",
             "provenance": "mechanical"},
            {"acquire": "b_add", "release": "b_del", "kind": "collection",
             "provenance": "llm_prior"},
            {"acquire": "c_get", "release": "c_put", "kind": "refcount"},
        ]}
        pairs = learned_collection_pairs(dm)
        assert [p["insert"] for p in pairs] == ["a_add"]

    def test_project_verb_without_vocab_is_vocab_unbound(self, tmp_path):
        # No hidden hardcoded list: a project-specific insert verb
        # yields vocab-unbound until the study loop teaches it.
        _write(tmp_path, "src/a.c", QUIC_PORT)
        res = run_resource_bounds_check(
            tmp_path, "src/a.c", "port_on_new_conn",
            "`ossl_track_conn` grows the incoming list without limit",
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_VOCAB_UNBOUND)


class TestAnchorPairs:
    def test_cve_2024_2511_confirmed_with_searched_callers(self, tmp_path):
        _write(tmp_path, "src/ssl_sess.c", CVE_2024_2511)
        res = run_resource_bounds_check(
            tmp_path, "src/ssl_sess.c", "ssl_session_cache_add", HYP,
        )
        assert res.outcome == "confirmed"
        assert res.rule_id.startswith(RULE_UNBOUNDED)
        # Receipt records the searched caller set (the honesty rule).
        callers = {c["caller"] for c in res.bound_search["callers"]}
        assert "accept_conn" in callers
        assert "accept_conn" in res.reason
        assert res.site["line"] == 4
        d = res.to_dict()
        assert d["resource"]["verb"] == "list_add"
        assert d["bound_search"]["local"] is None

    def test_cve_2024_2511_twin_refuted_with_guard_receipt(self, tmp_path):
        _write(tmp_path, "src/ssl_sess.c", CVE_2024_2511_TWIN)
        res = run_resource_bounds_check(
            tmp_path, "src/ssl_sess.c", "ssl_session_cache_add", HYP,
        )
        assert res.outcome == "refuted"
        local = res.bound_search["local"]
        assert local["count"] == "ctx->sess_count"
        assert local["bound"] == "MAX_SESSIONS"
        assert "MAX_SESSIONS" in res.reason

    def test_quic_port_learned_pair_registry_grade(self, tmp_path):
        _write(tmp_path, "src/quic_port.c", QUIC_PORT)
        dm = {"paired_operations": [
            {"acquire": "ossl_track_conn", "release": "ossl_untrack_conn",
             "kind": "collection", "provenance": "mechanical"},
        ]}
        res = run_resource_bounds_check(
            tmp_path, "src/quic_port.c", "port_on_new_conn", HYP,
            domain_model=dm,
            context=_entry_ctx("src/quic_port.c", "port_on_new_conn"),
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_UNBOUNDED          # registry grade
        assert res.resource["vocab_source"] == "learned"
        # Removal-parity corroboration (learned pair, remove absent).
        assert any(
            c.get("kind") == "removal-parity" for c in res.corroboration
        )

    def test_quic_port_seed_only_is_naming_variant(self, tmp_path):
        # Same shape, seed-only vocabulary ⇒ -naming detection rule-id
        # even when entry-reachable (asserts the grade split).
        src = QUIC_PORT.replace("ossl_track_conn", "list_add")
        _write(tmp_path, "src/quic_port.c", src)
        res = run_resource_bounds_check(
            tmp_path, "src/quic_port.c", "port_on_new_conn", HYP,
            context=_entry_ctx("src/quic_port.c", "port_on_new_conn"),
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_UNBOUNDED + DETECTION_VARIANT_SUFFIX
        assert is_detection_rule_id(res.rule_id)

    def test_unknown_reachability_caps_at_detection(self, tmp_path):
        # Registry vocabulary but no context map ⇒ detection grade
        # (absence never blocks — it caps; §1.3).
        _write(tmp_path, "src/quic_port.c", QUIC_PORT)
        dm = {"paired_operations": [
            {"acquire": "ossl_track_conn", "release": "",
             "kind": "collection", "provenance": "mechanical"},
        ]}
        res = run_resource_bounds_check(
            tmp_path, "src/quic_port.c", "port_on_new_conn", HYP,
            domain_model=dm,
        )
        assert res.outcome == "confirmed"
        assert res.rule_id.endswith(DETECTION_VARIANT_SUFFIX)

    def test_caller_bound_at_depth_two_refutes(self, tmp_path):
        for rel, text in CALLER_BOUND_DEPTH2.items():
            _write(tmp_path, rel, text)
        res = run_resource_bounds_check(
            tmp_path, "src/inner.c", "cache_insert",
            "items list grows without limit",
        )
        assert res.outcome == "refuted"
        assert "bound-in-caller" in res.reason
        depths = [c["depth"] for c in res.bound_search["callers"]
                  if "bound" in c]
        assert depths == [2]

    def test_alloc_in_loop_confirmed(self, tmp_path):
        _write(tmp_path, "src/parse.c", ALLOC_IN_LOOP)
        res = run_resource_bounds_check(
            tmp_path, "src/parse.c", "parse_records",
            "peer-controlled count drives unbounded allocation",
        )
        assert res.outcome == "confirmed"
        assert res.resource["kind"] == "alloc_in_loop"
        assert res.resource["verb"] == "malloc"

    def test_alloc_in_loop_clamped_twin_refuted(self, tmp_path):
        _write(tmp_path, "src/parse.c", ALLOC_IN_LOOP_TWIN)
        res = run_resource_bounds_check(
            tmp_path, "src/parse.c", "parse_records",
            "peer-controlled count drives unbounded allocation",
        )
        assert res.outcome == "refuted"
        local = res.bound_search["local"]
        assert local["bound"] == "MAX_RECORDS"
        assert local["bound_source"] == "clamp-min"


class TestEnumeratedReasons:
    def test_language_unsupported(self, tmp_path):
        _write(tmp_path, "src/a.py", "def f():\n    items.append(1)\n")
        res = run_resource_bounds_check(
            tmp_path, "src/a.py", "f", HYP,
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_LANGUAGE_UNSUPPORTED)

    def test_hypothesis_unbindable(self, tmp_path):
        _write(tmp_path, "src/a.c",
               "int f(int a)\n{\n    return a + 1;\n}\n")
        res = run_resource_bounds_check(tmp_path, "src/a.c", "f", HYP)
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_HYPOTHESIS_UNBINDABLE)

    def test_guard_undecided(self, tmp_path):
        src = """\
int f(struct c *c, struct item *it)
{
    if (c->count >= c->other_field)
        return -1;
    list_add(&c->items, it);
    return 0;
}
"""
        _write(tmp_path, "src/a.c", src)
        res = run_resource_bounds_check(tmp_path, "src/a.c", "f", HYP)
        assert res.outcome == "inconclusive"
        assert REASON_GUARD_UNDECIDED in res.reason

    def test_all_reasons_enumerated(self):
        assert REASON_VOCAB_UNBOUND in INCONCLUSIVE_REASONS
        assert len(INCONCLUSIVE_REASONS) == 5


class TestPrepass:
    def test_prepass_finds_and_caps(self, tmp_path):
        texts = {
            "src/ssl_sess.c": CVE_2024_2511,
            "src/guarded.c": CVE_2024_2511_TWIN.replace(
                "ssl_session_cache_add", "guarded_add",
            ),
        }
        out = run_resource_bounds_prepass(
            texts, target_path=tmp_path, out_dir=tmp_path,
        )
        tele = out["telemetry"]
        assert tele["confirmed"] >= 1
        assert tele["refuted"] >= 1
        files = {f["file"] for f in out["findings"]}
        assert "src/ssl_sess.c" in files
        assert "src/guarded.c" not in files
        for f in out["findings"]:
            assert f["cwe"] == "CWE-770"
            assert f["status"] in ("finding", "suspicious")
            assert f["receipts"]["outcome"] == "confirmed"
        assert (tmp_path / "resource-bounds.json").is_file()

    def test_prepass_budget_telemetry(self, tmp_path):
        out = run_resource_bounds_prepass(
            {"src/a.c": CVE_2024_2511}, target_path=tmp_path,
            budget_s=0.0,
        )
        assert out["telemetry"]["budget_exceeded"] is True


# v4 head-to-head shape: OpenSSL's DEFINE_LIST_OF_IMPL generates the
# insert function (ossl_list_<name>_insert_tail) — it has no definition
# anywhere for the study loop to index, and the verb is word-internal
# so exact-name vocabulary can never match. The naming-stem tier binds
# it structurally at detection grade.
MACRO_LIST_INSERT = """\
static void port_bind_channel(struct port *port, struct conn *ch)
{
    ossl_list_incoming_ch_insert_tail(&port->incoming_channel_list, ch);
    port->have_incoming = 1;
}
"""

MACRO_LIST_INSERT_TWIN = """\
static void port_bind_channel(struct port *port, struct conn *ch)
{
    if (port->incoming_count >= MAX_INCOMING)
        return;
    ossl_list_incoming_ch_insert_tail(&port->incoming_channel_list, ch);
    port->incoming_count++;
}
"""

ARITHMETIC_ADD = """\
static int bn_sum(struct bn *r, struct bn *a, struct bn *b)
{
    BN_add(r, a, b);
    BN_mod_add(r, r, b, r, 0);
    return 1;
}
"""


class TestNamingStemBinding:
    def test_macro_generated_insert_binds_at_detection_grade(
        self, tmp_path,
    ):
        _write(tmp_path, "src/quic_port.c", MACRO_LIST_INSERT)
        res = run_resource_bounds_check(
            tmp_path, "src/quic_port.c", "port_bind_channel",
            "incoming channels accumulate in incoming_channel_list "
            "with no bound",
        )
        assert res.outcome == "confirmed"
        # Detection grade ONLY: naming evidence never earns the
        # registry rule-id.
        assert res.rule_id == RULE_UNBOUNDED + DETECTION_VARIANT_SUFFIX
        assert is_detection_rule_id(res.rule_id)
        assert res.resource["verb"] == "ossl_list_incoming_ch_insert_tail"
        assert res.resource["vocab_source"] == "naming"

    def test_twin_with_bound_witness_refutes(self, tmp_path):
        _write(tmp_path, "src/quic_port.c", MACRO_LIST_INSERT_TWIN)
        res = run_resource_bounds_check(
            tmp_path, "src/quic_port.c", "port_bind_channel",
            "incoming channels accumulate in incoming_channel_list "
            "with no bound",
        )
        assert res.outcome == "refuted"
        assert "MAX_INCOMING" in res.reason

    def test_arithmetic_add_does_not_bind(self, tmp_path):
        # BN_add-style arithmetic must not become an accumulation
        # site: weak verbs (add/push/append) bind only when the
        # identifier also names a collection.
        _write(tmp_path, "src/bn_add.c", ARITHMETIC_ADD)
        res = run_resource_bounds_check(
            tmp_path, "src/bn_add.c", "bn_sum",
            "the sum list grows without limit",
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_HYPOTHESIS_UNBINDABLE)

    def test_stem_collection_token_requires_word_boundary(self):
        """The collection noun must be a whole snake_case segment —
        substring hits (string_append via "ring", task_add/mask_add
        via "sk", offset_add via "set") are the BN_add-class
        arithmetic the weak-verb tier exists to exclude."""
        from core.audit.resource_bounds import _STEM_INSERT_RE

        for bad in ("string_append(s, c);", "task_add(t);",
                    "mask_add(m, bit);", "offset_add(o, 4);",
                    "strbuf_append(sb, c);"):
            assert _STEM_INSERT_RE.search(bad) is None, bad
        for good in ("my_list_add(l, e);", "queue_push(q, e);",
                     "hash_table_add(h, k);", "conn_set_add(s, c);",
                     "ring_buffer_append(rb, e);",
                     "pkt_queue_push_tail(q, p);"):
            assert _STEM_INSERT_RE.search(good) is not None, good

    def test_exact_vocabulary_still_wins_over_stem(self, tmp_path):
        # A seed-vocabulary verb keeps its seed provenance — the stem
        # tier only picks up what exact matching cannot see.
        _write(tmp_path, "src/ssl_sess.c", CVE_2024_2511)
        res = run_resource_bounds_check(
            tmp_path, "src/ssl_sess.c", "ssl_session_cache_add", HYP,
        )
        assert res.outcome == "confirmed"
        assert res.resource["vocab_source"] == "seed"

    def test_prepass_discovers_stem_only_candidates(self, tmp_path):
        # The prepass candidate filter must see stem-only files too —
        # exact vocabulary alone skipped them before enumeration.
        res = run_resource_bounds_prepass(
            {"src/quic_port.c": MACRO_LIST_INSERT},
            target_path=tmp_path,
        )
        assert res["telemetry"]["candidates"] == 1
        assert res["telemetry"]["confirmed"] == 1
        leads = res.get("leads", [])
        assert leads and "ossl_list_incoming_ch_insert_tail" in (
            leads[0]["mechanism"]
        )


class TestPrepassLanguage:
    def test_language_derived_from_suffix(self, monkeypatch):
        import core.audit.resource_bounds as rb

        seen: dict[str, str] = {}

        def _fake_site(site, source, fp, name, language, **_kw):
            seen[fp] = language
            return rb._inconclusive(rb.REASON_VOCAB_UNBOUND)

        monkeypatch.setattr(rb, "_adjudicate_site", _fake_site)
        rb.run_resource_bounds_prepass({
            "src/cache.cpp": (
                "void grow(void)\n{\n    list_add(x, y);\n}\n"
            ),
        })
        assert seen.get("src/cache.cpp") == "cpp"


class TestCallerWalkDeadline:
    def test_expired_deadline_stops_the_walk(self):
        from core.audit.resource_bounds import _caller_bound_search

        witness, receipts = _caller_bound_search(
            "insert_fn",
            {"a.c": "void caller(void)\n{\n    insert_fn(x);\n}\n"},
            "a.c", None, frozenset(), "c",
            deadline=0.0,
        )
        assert witness is None
        assert receipts == []


class TestCheckBudget:
    def test_zero_budget_bails_inconclusive(self, tmp_path):
        # budget_s was accepted-and-deleted: the walk ran deadline-free
        # regardless. A zero budget must stop before adjudicating and
        # degrade to inconclusive (never refuted/confirmed on no work).
        _write(tmp_path, "src/ssl_sess.c", CVE_2024_2511)
        res = run_resource_bounds_check(
            tmp_path, "src/ssl_sess.c", "ssl_session_cache_add", HYP,
            budget_s=0.0,
        )
        assert res.outcome == "inconclusive"
        assert "budget" in res.reason

    def test_no_budget_unchanged(self, tmp_path):
        _write(tmp_path, "src/ssl_sess.c", CVE_2024_2511)
        res = run_resource_bounds_check(
            tmp_path, "src/ssl_sess.c", "ssl_session_cache_add", HYP,
        )
        assert res.outcome == "confirmed"


class TestPackCollectionVerbsCache:
    def test_pack_read_once_per_process(self, tmp_path, monkeypatch):
        # The pack JSON was re-read and re-parsed on every check call.
        import core.audit.resource_bounds as rb
        import core.audit.vocab_packs as vp

        pack_dir = tmp_path / "packs"
        pack_dir.mkdir()
        (pack_dir / "linux_kernel.json").write_text(
            '{"collection_inserts": ["list_add"],'
            ' "collection_removes": ["list_del"]}',
        )
        monkeypatch.setattr(vp, "_PACK_DIR", pack_dir)
        monkeypatch.setattr(vp, "is_kernel_tree", lambda p: True)
        rb._pack_collection_cache.clear()

        first = rb._pack_collection_verbs(tmp_path)
        assert first == (frozenset({"list_add"}), frozenset({"list_del"}))
        # Cache must serve the second call — the file is gone.
        (pack_dir / "linux_kernel.json").unlink()
        assert rb._pack_collection_verbs(tmp_path) == first


class TestSanitizedViewMatching:
    """Lexical witnesses are earned on the sanitized view (comments/
    strings blanked) — both directions are hostile-repo steerable:
    a comment clamp mints a refutation, a comment insert mints a
    site."""

    _CLAMP_SEG = [
        "void f(struct list *l, int count) {",
        "    {CLAMP}",
        "    for (i = 0; i < n; i++) {",
        "        p = malloc(64);",
        "    }",
        "}",
    ]

    def _clamp(self, clamp_line):
        from core.audit.resource_bounds import _clamp_witness
        seg = [ln.replace("{CLAMP}", clamp_line) for ln in self._CLAMP_SEG]
        return _clamp_witness(
            seg, 1, 4, None, frozenset(), file_path="src/a.c",
        )

    def test_comment_clamp_does_not_refute(self):
        assert self._clamp("/* n = min(count, MAX_CONN) */") is None

    def test_real_clamp_still_witnesses(self):
        w = self._clamp("n = min(count, MAX_CONN);")
        assert w is not None
        assert w["bound"] == "MAX_CONN"

    def test_comment_insert_does_not_mint_site(self):
        from core.audit.resource_bounds import _enumerate_sites
        seg = [
            "void g(struct list *l, struct conn *c) {",
            "    /* list_add(&c->node, l); */",
            "}",
        ]
        sites = _enumerate_sites(
            seg, 1, {"list_add": ("seed", "seed")}, {},
            file_path="src/a.c",
        )
        assert sites == []

    def test_real_insert_still_mints_site(self):
        from core.audit.resource_bounds import _enumerate_sites
        seg = [
            "void g(struct list *l, struct conn *c) {",
            "    list_add(&c->node, l);",
            "}",
        ]
        sites = _enumerate_sites(
            seg, 1, {"list_add": ("seed", "seed")}, {},
            file_path="src/a.c",
        )
        assert [s.verb for s in sites] == ["list_add"]
        # Receipt shows the ORIGINAL line, not the blanked view.
        assert "list_add(&c->node, l);" in sites[0].code


class TestGatherSourceTextsContainment:
    """_gather_source_texts is a hypothesis-file intake: file paths
    arrive from LLM-writable artifacts, so reads must be contained to
    the analysed root and byte-capped (the release_order idiom)."""

    def _tree(self, tmp_path):
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src/a.c").write_text("int f(void) { return 1; }\n")
        secret = tmp_path / "secret.c"
        secret.write_text("int host_secret(void) { return 42; }\n")
        return target, secret

    def test_absolute_primary_path_refused(self, tmp_path):
        from core.audit.resource_bounds import (
            _gather_source_texts as _rb_gather_source_texts,
        )
        target, secret = self._tree(tmp_path)
        texts = _rb_gather_source_texts(target, str(secret))
        assert str(secret) not in texts
        assert not any("host_secret" in t for t in texts.values())

    def test_traversal_primary_path_refused(self, tmp_path):
        from core.audit.resource_bounds import (
            _gather_source_texts as _rb_gather_source_texts,
        )
        target, _secret = self._tree(tmp_path)
        texts = _rb_gather_source_texts(target, "../secret.c")
        assert "../secret.c" not in texts
        assert not any("host_secret" in t for t in texts.values())

    def test_symlink_escape_refused(self, tmp_path):
        from core.audit.resource_bounds import (
            _gather_source_texts as _rb_gather_source_texts,
        )
        target, secret = self._tree(tmp_path)
        (target / "src/link.c").symlink_to(secret)
        texts = _rb_gather_source_texts(target, "src/a.c")
        assert not any("host_secret" in t for t in texts.values())

    def test_primary_read_is_capped(self, tmp_path):
        from core.audit import resource_bounds
        from core.audit.resource_bounds import (
            _gather_source_texts as _rb_gather_source_texts,
        )
        target, _secret = self._tree(tmp_path)
        big = "int g;\n" * (
            resource_bounds._MAX_FILE_BYTES // 7 + 10
        )
        (target / "src/big.c").write_text(big)
        texts = _rb_gather_source_texts(target, "src/big.c")
        got = texts.get("src/big.c")
        assert got is not None
        assert len(got) <= resource_bounds._MAX_FILE_BYTES

    def test_contained_relative_file_still_read(self, tmp_path):
        from core.audit.resource_bounds import (
            _gather_source_texts as _rb_gather_source_texts,
        )
        target, _secret = self._tree(tmp_path)
        texts = _rb_gather_source_texts(target, "src/a.c")
        assert "src/a.c" in texts
        assert "int f" in texts["src/a.c"]


class TestSourceCensusAndMemo:
    """The census walk is a pure function of the tree, priced once
    per run (orchestrator memo) instead of once per hypothesis
    dispatch; VCS internals are pruned — the old whole-tree rglob
    materialised a kernel-sized .git/objects on every call."""

    def _tree(self, tmp_path):
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src/a.c").write_text("int f(void) { return 1; }\n")
        (target / "src/b.c").write_text("int g(void) { return 2; }\n")
        git = target / ".git" / "objects" / "ab"
        git.mkdir(parents=True)
        (git / "planted.c").write_text("int git_internal(void);\n")
        return target

    def test_census_prunes_vcs_internals(self, tmp_path):
        from core.audit.resource_bounds import _source_census

        target = self._tree(tmp_path)
        rels = [rel for rel, _ in _source_census(target)]
        assert "src/a.c" in rels and "src/b.c" in rels
        assert not any(".git" in r for r in rels)

    def test_census_selection_matches_rglob_order(self, tmp_path):
        from core.audit import resource_bounds
        from core.audit.resource_bounds import _source_census

        target = tmp_path / "target"
        for d in ("z", "a/nested", "m"):
            (target / d).mkdir(parents=True)
        names = [
            "z/x.c", "a/nested/y.c", "m/q.h", "a/top.cpp", "root.c",
        ]
        for nm in names:
            (target / nm).write_text(f"// {nm}\n")
        rels = [rel for rel, _ in _source_census(target)]
        expected = [
            str(p.relative_to(target))
            for p in sorted(target.rglob("*"))
            if p.is_file() and p.suffix in resource_bounds._SOURCE_SUFFIXES
        ]
        assert rels == expected[:resource_bounds._MAX_SCAN_FILES]

    def test_gather_with_census_does_not_walk(self, tmp_path, monkeypatch):
        import os as _os

        from core.audit.resource_bounds import (
            _gather_source_texts as _rb_gather_source_texts,
        )

        target = self._tree(tmp_path)
        census = [("src/b.c", "int g(void) { return 2; }\n")]

        def boom(*a, **k):
            raise AssertionError("walk must not run with a census")

        monkeypatch.setattr(_os, "walk", boom)
        texts = _rb_gather_source_texts(target, "src/a.c", census=census)
        assert "src/a.c" in texts and "src/b.c" in texts

    def test_orchestrator_memo_prices_census_once(
        self, tmp_path, monkeypatch,
    ):
        from types import SimpleNamespace

        from core.audit import resource_bounds
        from core.audit.orchestrator import _hypothesis_source_texts
        from core.audit.run_memo import BoundedMemo

        target = self._tree(tmp_path)
        calls = {"n": 0}
        real = resource_bounds._source_census

        def counting(t):
            calls["n"] += 1
            return real(t)

        monkeypatch.setattr(resource_bounds, "_source_census", counting)
        config = SimpleNamespace(hypothesis_source_memo=BoundedMemo(16))
        t1 = _hypothesis_source_texts(config, target, "src/a.c")
        t2 = _hypothesis_source_texts(config, target, "src/b.c")
        assert calls["n"] == 1
        assert "src/a.c" in t1 and "src/b.c" in t2

    def test_non_c_primary_skips_intake(self, tmp_path, monkeypatch):
        from types import SimpleNamespace

        from core.audit import resource_bounds
        from core.audit.orchestrator import _hypothesis_source_texts
        from core.audit.run_memo import BoundedMemo

        target = self._tree(tmp_path)

        def boom(t):
            raise AssertionError("census must not run for non-C primary")

        monkeypatch.setattr(resource_bounds, "_source_census", boom)
        config = SimpleNamespace(hypothesis_source_memo=BoundedMemo(16))
        assert _hypothesis_source_texts(config, target, "app.py") is None


class TestConsistencyGatherContainment:
    """Structural twin in consistency_verify: same intake contract."""

    def test_absolute_and_traversal_refused(self, tmp_path):
        from core.audit.consistency_verify import _gather_source_texts
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src/a.c").write_text("int f(void) { helper(); }\n")
        secret = tmp_path / "secret.c"
        secret.write_text("int host_secret(void) { return 42; }\n")
        for hostile in (str(secret), "../secret.c"):
            texts = _gather_source_texts(target, hostile, ["helper"])
            assert hostile not in texts
            assert not any(
                "host_secret" in t for t in texts.values()
            ), hostile
        ok = _gather_source_texts(target, "src/a.c", ["helper"])
        assert "src/a.c" in ok
