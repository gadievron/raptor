"""Tests for core.audit.prefilter."""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest

import core.audit.prefilter as _prefilter
from core.audit.prefilter import (
    detect_language,
    run_prefilter,
)


def test_detect_language():
    assert detect_language("foo.c") == "c"
    assert detect_language("bar.py") == "python"
    assert detect_language("baz.java") == "java"
    assert detect_language("quux.rs") == "rust"
    assert detect_language("unknown.xyz") == ""


def test_simple_accessor_skipped(tmp_path):
    source = """\
const char *req_get_method(const Request *req)
{
    return req->method;
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="reqparse.c",
        function_name="req_get_method",
        source=source,
        line_start=1,
    )
    assert result.skip_llm is True
    assert "accessor" in result.skip_reason


def test_simple_accessor_with_array_not_skipped(tmp_path):
    source = """\
const char *req_get_header(const Request *req, int index)
{
    return req->headers[index].value;
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="reqparse.c",
        function_name="req_get_header",
        source=source,
        line_start=1,
    )
    assert result.skip_llm is False
    assert result.has_array_access is True


def test_strcpy_detected(tmp_path):
    source = """\
int parse_query_string(const char *path, char *query, size_t query_cap)
{
    const char *qmark = strchr(path, '?');
    if (!qmark) {
        query[0] = '\\0';
        return 0;
    }
    strcpy(query, qmark + 1);
    return 1;
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="reqparse.c",
        function_name="parse_query_string",
        source=source,
        line_start=267,
    )
    assert result.skip_llm is False
    assert any(h.rule_id == "unbounded-strcpy" for h in result.hits)


def test_sql_injection_detected(tmp_path):
    source = """\
void lookup_user(const char *username, Response *resp)
{
    char query[512];
    snprintf(query, sizeof(query),
             "SELECT id, name, email FROM users WHERE name = '%s'",
             username);
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="database.c",
        function_name="lookup_user",
        source=source,
        line_start=21,
    )
    assert result.skip_llm is False
    assert any(h.rule_id == "sql-string-format" for h in result.hits)


def test_uint16_offset_detected(tmp_path):
    source = """\
static int parse_headers(const char *buf, size_t len, Request *req)
{
    uint16_t offset = 0;
    while (offset < len) {
        offset += line_len + 1;
    }
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="reqparse.c",
        function_name="parse_headers",
        source=source,
        line_start=90,
    )
    assert result.skip_llm is False
    assert any(h.rule_id == "narrow-integer-size" for h in result.hits)


def test_python_path_traversal_detected(tmp_path):
    source = """\
def read_user_file(base_dir: str, username: str, filename: str) -> bytes:
    decoded_name = decode_url(filename)
    user_dir = os.path.join(base_dir, username)
    path = os.path.join(user_dir, decoded_name)
    with open(path, "rb") as f:
        return f.read()
"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="bindings.py",
        function_name="read_user_file",
        source=source,
        line_start=63,
    )
    assert result.skip_llm is False
    assert any(h.rule_id == "path-join-no-containment" for h in result.hits)


def test_python_simple_return_skipped(tmp_path):
    source = """\
def get_name(self):
    return self.name
"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="model.py",
        function_name="get_name",
        source=source,
        line_start=1,
    )
    assert result.skip_llm is True


def test_mechanical_evidence_formatted(tmp_path):
    source = """\
void f(const char *s) {
    char buf[32];
    strcpy(buf, s);
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="vuln.c",
        function_name="f",
        source=source,
        line_start=1,
    )
    evidence = result.mechanical_evidence
    assert "unbounded-strcpy" in evidence
    assert "Mechanical pre-sweep" in evidence


def test_no_hits_no_evidence(tmp_path):
    source = """\
int add(int a, int b) {
    return a + b;
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="math.c",
        function_name="add",
        source=source,
        line_start=1,
    )
    assert result.mechanical_evidence == ""


def test_dangerous_callees_prevent_skip(tmp_path):
    source = """\
void f(void) {
    return;
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="util.c",
        function_name="f",
        source=source,
        line_start=1,
        callees=[{"name": "memcpy"}],
    )
    assert result.skip_llm is False


def test_pointer_ops_prevent_skip(tmp_path):
    source = """\
int f(int *p) {
    return *(p + 1);
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="ptr.c",
        function_name="f",
        source=source,
        line_start=1,
    )
    assert result.skip_llm is False
    assert result.has_pointer_ops is True


def test_array_index_no_bounds_check(tmp_path):
    source = """\
int get(int *arr, int idx) {
    return arr[idx];
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="arr.c",
        function_name="get",
        source=source,
        line_start=1,
    )
    hits = [h for h in result.hits if h.rule_id == "array-index-unchecked"]
    assert len(hits) >= 1


def test_array_index_with_bounds_check_no_hit(tmp_path):
    source = """\
int get(int *arr, int idx, int len) {
    if (idx < 0 || idx >= len)
        return -1;
    return arr[idx];
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="arr.c",
        function_name="get",
        source=source,
        line_start=1,
    )
    hits = [h for h in result.hits if h.rule_id == "array-index-unchecked"]
    assert len(hits) == 0


def test_use_after_free_detected(tmp_path):
    source = """\
void process(struct node *n) {
    free(n);
    printf("%d", n->value);
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="uaf.c",
        function_name="process",
        source=source,
        line_start=1,
    )
    assert any(h.rule_id == "use-after-free" for h in result.hits)


def test_double_free_detected(tmp_path):
    source = """\
void cleanup(char *buf) {
    free(buf);
    if (error)
        free(buf);
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="dfree.c",
        function_name="cleanup",
        source=source,
        line_start=1,
    )
    assert any(h.rule_id == "double-free" for h in result.hits)


def test_no_uaf_after_reassign(tmp_path):
    source = """\
void process(char *buf) {
    free(buf);
    buf = malloc(32);
    buf[0] = 'a';
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="safe.c",
        function_name="process",
        source=source,
        line_start=1,
    )
    assert not any(h.rule_id == "use-after-free" for h in result.hits)
    assert not any(h.rule_id == "double-free" for h in result.hits)


def test_toctou_detected(tmp_path):
    source = """\
int safe_open(const char *path) {
    if (access(path, R_OK) != 0)
        return -1;
    int fd = open(path, O_RDONLY);
    return fd;
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="toctou.c",
        function_name="safe_open",
        source=source,
        line_start=1,
    )
    assert any(h.rule_id == "toctou-filesystem" for h in result.hits)


def test_post_loop_oob_detected(tmp_path):
    source = """\
ssize_t url_decode(const char *src, size_t src_len,
                   char *dst, size_t dst_cap)
{
    size_t si = 0, di = 0;
    while (si < src_len && di < dst_cap) {
        dst[di++] = src[si++];
    }
    dst[di] = '\\0';
    return (ssize_t)di;
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="decode.c",
        function_name="url_decode",
        source=source,
        line_start=1,
    )
    assert any(h.rule_id == "post-loop-oob-write" for h in result.hits)


def test_post_loop_oob_safe_cap_minus_one(tmp_path):
    source = """\
void safe_copy(const char *src, char *dst, size_t cap) {
    size_t i = 0;
    while (i < cap - 1 && src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\\0';
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="safe.c",
        function_name="safe_copy",
        source=source,
        line_start=1,
    )
    assert not any(h.rule_id == "post-loop-oob-write" for h in result.hits)


def test_post_loop_oob_safe_guarded(tmp_path):
    source = """\
void safe2(const char *src, char *dst, size_t cap) {
    size_t i = 0;
    while (i < cap && src[i]) {
        dst[i] = src[i];
        i++;
    }
    if (i < cap)
        dst[i] = '\\0';
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="safe2.c",
        function_name="safe2",
        source=source,
        line_start=1,
    )
    assert not any(h.rule_id == "post-loop-oob-write" for h in result.hits)


def test_post_loop_oob_braceless_loop_no_fp(tmp_path):
    source = """\
void copy_args(struct info *info, unsigned long *args, int n) {
    int i;
    for (i = 0; i < n; i++)
        info->args[i] = args[i];
    return;
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="braceless.c",
        function_name="copy_args",
        source=source,
        line_start=1,
    )
    assert not any(h.rule_id == "post-loop-oob-write" for h in result.hits)


def test_malloc_multiply_overflow(tmp_path):
    source = """\
void alloc_items(int count) {
    struct item *items = malloc(count * sizeof(struct item));
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="alloc.c",
        function_name="alloc_items",
        source=source,
        line_start=1,
    )
    assert any(h.rule_id == "malloc-multiply-overflow" for h in result.hits)


# ── Sink unreachable skip gate ─────────────────────────────────────


def test_sink_unreachable_small_fn_skipped(tmp_path):
    source = """\
void log_status(struct ctx *c) {
    int x = c->count;
    int y = c->limit;
    c->total = x;
    c->logged = 1;
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="util.c",
        function_name="log_status",
        source=source,
        line_start=1,
        sink_unreachable=True,
    )
    assert result.skip_llm
    assert "no sink path" in result.skip_reason


def test_sink_unreachable_large_fn_not_skipped(tmp_path):
    source = "\n".join(f"    int x{i} = {i};" for i in range(35))
    source = f"void big(int a) {{\n{source}\n}}"
    result = run_prefilter(
        target_path=tmp_path,
        file_path="big.c",
        function_name="big",
        source=source,
        line_start=1,
        sink_unreachable=True,
    )
    assert not result.skip_llm


def test_sink_unreachable_auth_keyword_not_skipped(tmp_path):
    source = """\
int check_permission(struct user *u, int resource_id) {
    int role = u->role;
    int level = get_access_level(role);
    if (level < REQUIRED_LEVEL) {
        log_denied(u->id, resource_id);
        return -1;
    }
    grant_access(u, resource_id);
    return 0;
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="auth.c",
        function_name="check_permission",
        source=source,
        line_start=1,
        sink_unreachable=True,
    )
    assert not result.skip_llm


def test_sink_unreachable_crypto_not_skipped(tmp_path):
    source = """\
void hash_input(char *buf, int len) {
    sha256(buf, len, out);
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="crypto.c",
        function_name="hash_input",
        source=source,
        line_start=1,
        sink_unreachable=True,
    )
    assert not result.skip_llm


def test_sink_unreachable_openssl_prefix_not_skipped(tmp_path):
    # The OpenSSL prefixes were spelled uppercase in the vocab while
    # every consumer matches the LOWERCASED view — the exclusion was
    # dead and an SSL_VERIFY_NONE misconfiguration in a small
    # sink-unreachable function was hard-suppressed pre-LLM.
    source = """\
void setup_tls(struct conn *c) {
    SSL_CTX_set_verify(c->ctx, SSL_VERIFY_NONE, 0);
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="tls.c",
        function_name="setup_tls",
        source=source,
        line_start=1,
        sink_unreachable=True,
    )
    assert not result.skip_llm


def test_crypto_vocab_entries_all_lowercase():
    # Every consumer lowercases before matching; an uppercase entry
    # can never fire.  Guard the vocab against re-introducing one.
    from core.audit.prefilter import _CRYPTO_APIS
    assert all(api == api.lower() for api in _CRYPTO_APIS)


def test_sink_unreachable_mutex_not_skipped(tmp_path):
    source = """\
void inc(struct counter *c) {
    pthread_mutex_lock(&c->lock);
    c->val++;
    pthread_mutex_unlock(&c->lock);
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="counter.c",
        function_name="inc",
        source=source,
        line_start=1,
        sink_unreachable=True,
    )
    assert not result.skip_llm


def test_sink_unreachable_false_still_reviews(tmp_path):
    source = """\
int get_count(struct ctx *c) {
    return c->count;
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="util.c",
        function_name="get_count",
        source=source,
        line_start=1,
        sink_unreachable=False,
    )
    # Without sink_unreachable, SLOC > 8 means no skip (unless simple accessor)
    # This is a simple accessor so it may skip on that path
    # The point: sink_unreachable=False doesn't trigger the new gate
    assert not result.skip_reason or "no sink path" not in result.skip_reason


def test_sink_unreachable_with_hits_not_skipped(tmp_path):
    source = """\
void parse(char *buf) {
    strcpy(dst, buf);
}"""
    result = run_prefilter(
        target_path=tmp_path,
        file_path="parse.c",
        function_name="parse",
        source=source,
        line_start=1,
        sink_unreachable=True,
    )
    # Has dangerous API hits — shouldn't skip even with sink_unreachable
    # (But note: sink_unreachable + dangerous API is contradictory in practice;
    # the test verifies the prefilter's own safety check)
    if result.hits:
        assert not result.skip_llm or "no sink path" not in result.skip_reason


class TestAssignInConditional:
    def _run(self, tmp_path, source, function_name="check"):
        return run_prefilter(
            target_path=tmp_path,
            file_path="test.c", function_name=function_name,
            source=source, line_start=1,
        )

    def _hits(self, result):
        return [h for h in result.hits if h.rule_id == "assign-in-conditional"]

    def test_null(self, tmp_path):
        r = self._run(tmp_path, """\
void foo(struct bar *b) {
    if (b = NULL) {
        return;
    }
}
""", "foo")
        hits = self._hits(r)
        assert len(hits) == 1
        assert "b = NULL" in hits[0].message

    def test_zero(self, tmp_path):
        r = self._run(tmp_path, """\
int check(int x) {
    if (x = 0)
        return -1;
    return 0;
}
""")
        hits = self._hits(r)
        assert len(hits) == 1
        assert "x = 0" in hits[0].message

    def test_false(self, tmp_path):
        r = self._run(tmp_path, """\
void check(bool ok) {
    if (ok = false) return;
}
""")
        assert len(self._hits(r)) == 1

    def test_minus_one(self, tmp_path):
        r = self._run(tmp_path, """\
int check(int fd) {
    if (fd = -1) return -1;
}
""")
        assert len(self._hits(r)) == 1

    def test_intentional_paren(self, tmp_path):
        """if ((ptr = malloc(n)) == NULL) is intentional — skip."""
        r = self._run(tmp_path, """\
void *alloc(size_t n) {
    void *p;
    if ((p = malloc(n)) == NULL) return NULL;
    return p;
}
""", "alloc")
        assert len(self._hits(r)) == 0

    def test_intentional_func_call(self, tmp_path):
        """if (ret = do_something(...)) is intentional — skip."""
        r = self._run(tmp_path, """\
int process(void) {
    int ret;
    if (ret = do_something(buf, len))
        return ret;
    return 0;
}
""", "process")
        assert len(self._hits(r)) == 0

    def test_comparison_not_flagged(self, tmp_path):
        """if (x == 0) is correct comparison — no hit."""
        r = self._run(tmp_path, """\
int check(int x) {
    if (x == 0) return -1;
    return 0;
}
""")
        assert len(self._hits(r)) == 0

    def test_comment_line_skipped(self, tmp_path):
        r = self._run(tmp_path, """\
int check(int x) {
    // if (x = 0) this was a bug
    if (x == 0) return -1;
    return 0;
}
""")
        assert len(self._hits(r)) == 0


class TestKernelVocabViaPack:
    """The kernel API bulk reaches the prefilter via the vocab pack.

    _DANGEROUS_C_APIS keeps only the classic kernel core (kmalloc /
    kzalloc / kfree / copy_from_user / copy_to_user); the kv* / devm_*
    and __copy/_copy_iter variants come from the linux_kernel pack
    through domain_vocab.
    """

    def _run(self, source, callees=None, vocab=None):
        from core.audit.prefilter import run_prefilter

        return run_prefilter(
            target_path=Path("/tmp"),
            file_path="drv.c",
            function_name="f",
            source=source,
            callees=callees,
            domain_vocab=vocab,
        )

    def test_seed_core_still_hardcoded(self):
        src = "int f(void){ p = kmalloc(8, GFP_KERNEL); copy_from_user(d, s, n); kfree(p); return 0; }"
        r = self._run(src)
        assert r.has_dangerous_apis

    def test_pack_tier_names_need_vocab(self):
        src = (
            "int f(void){\n"
            "    p = devm_kzalloc(dev, 8, GFP_KERNEL);\n"
            "    _copy_from_iter(p, n, iter);\n"
            "    return 0;\n"
            "}"
        )
        assert not self._run(src).has_dangerous_apis

        from core.audit.vocab_packs import load_pack

        r = self._run(src, vocab=load_pack("linux_kernel"))
        assert r.has_dangerous_apis

    def test_boundary_transfers_flow_through_vocab_union(self):
        from core.audit.condition_smt import DomainVocabulary

        vocab = DomainVocabulary(
            boundary_transfers=frozenset({"acme_copy_in"}),
            nullable_returns=frozenset({"acme_find_port"}),
        )
        src = "int f(void){ acme_copy_in(dst, src, n); return 0; }"
        assert not self._run(src).has_dangerous_apis
        assert self._run(src, vocab=vocab).has_dangerous_apis

    def test_pack_callee_marks_dangerous(self):
        from core.audit.vocab_packs import load_pack

        src = "int f(struct x *x){ int v = x->a; helper(x); return v; }"
        callees = [{"name": "kvfree_rcu"}]
        seeds_only = self._run(src, callees=callees)
        with_pack = self._run(
            src, callees=callees, vocab=load_pack("linux_kernel"),
        )
        assert not seeds_only.has_dangerous_apis
        assert with_pack.has_dangerous_apis


class TestPrefilterSkipKnobWiring:
    """OrchestratorConfig.prefilter_skip=False must neuter the
    prefilter's skip_llm shortcut in the review loop (source-level
    wiring check — the heavy review_one_function scaffolding is
    exercised in integration tests, mirroring
    TestPinnedGapNeverTriageSkipped)."""

    def test_review_loop_guard_precedes_skip_block(self):
        src = (Path(__file__).resolve().parents[1]
               / "orchestrator.py").read_text()
        idx = src.find("def review_one_function")
        assert idx != -1
        end = src.find("\ndef ", idx)
        window = src[idx:end if end != -1 else len(src)]
        guard = window.find(
            'pf_result.skip_llm and not getattr(config, "prefilter_skip"'
        )
        skip_block = window.find('evidence_tool="prefilter:skip"')
        assert guard != -1, "prefilter_skip guard missing"
        assert skip_block != -1, "prefilter skip block missing"
        assert guard < skip_block

    def test_config_default_on(self):
        from core.audit.orchestrator import OrchestratorConfig

        cfg = OrchestratorConfig(target_path=Path("."), out_dir=Path("."))
        assert cfg.prefilter_skip is True


class TestAccessorTierHonesty:
    """The simple-accessor skip judges the WHOLE body on the shared
    sanitized views — never raw prefix-dropped lines or a
    suffix-anchored arm.

    The old mechanism dropped any raw line starting with ``*`` or
    ``#`` (a column-0 deref-store read as a block-comment
    continuation; a string-continuation line carrying live code read
    as a comment) and matched its arms with a suffix anchor (any
    side-effecting statement rode in front of the accessor return).
    Each shape below was journalled durably clean ("cannot contain
    vulnerabilities") over live deref-stores, lifecycle ops, and an
    os.system call.
    """

    def _run(self, name, fp, src, callees=None):
        return run_prefilter(
            target_path=Path("/nonexistent-target"), file_path=fp,
            function_name=name, source=src, callees=callees,
        )

    def test_c_deref_store_col0_not_an_accessor(self):
        r = self._run("get_val", "a.c",
            "int get_val(struct ctx *x, int v) {\n"
            "*x->owner_uid = v;\nreturn x->val;\n}")
        assert not r.skip_llm

    def test_c_privilege_flag_store_not_an_accessor(self):
        r = self._run("mk", "a.c",
            "int mk(struct s *s) {\n*s->is_admin = 1;\nreturn s->val;\n}")
        assert not r.skip_llm

    def test_go_deref_store_not_an_accessor(self):
        r = self._run("G", "a.go",
                      "func G(p *int, s *S) int {\n*p = 9\nreturn s.f\n}")
        assert not r.skip_llm

    def test_py_side_effect_before_return_not_an_accessor(self):
        r = self._run("f", "a.py",
                      "def f(path, ok):\n    os.unlink(path)\n    return ok",
                      callees=[{"name": "os.unlink"}])
        assert not r.skip_llm

    def test_c_refcount_put_not_an_accessor(self):
        r = self._run("put", "a.c",
            "void put(struct obj *p){\np->refs--;\nreturn p->parent;\n}")
        assert not r.skip_llm

    def test_py_hash_continuation_hides_no_sink(self):
        r = self._run("f", "a.py",
            'def f(c):\n    s = """\n#"""; os.system(c)\n    return ok')
        assert not r.skip_llm

    def test_c_array_store_control_still_refused(self):
        r = self._run("get_val", "a.c",
            "int get_val(struct ctx *x, int v) {\n  y[0] = v;\n"
            "  return x->val;\n}")
        assert not r.skip_llm

    # ── keep direction: honest accessors keep their skip ────────────

    def test_c_field_accessor_keeps_skip(self):
        r = self._run("get_uid", "a.c",
            "int get_uid(const struct ctx *x)\n{\n"
            "    /* owner uid */\n    return x->owner_uid;\n}")
        assert r.skip_llm and "accessor" in r.skip_reason

    def test_py_self_field_accessor_keeps_skip(self):
        r = self._run("value", "a.py",
                      "def value(self):\n    return self._value")
        assert r.skip_llm and "accessor" in r.skip_reason

    def test_py_docstring_accessor_keeps_skip(self):
        r = self._run("value", "a.py",
                      'def value(self):\n    """The value."""\n'
                      "    return self._value")
        assert r.skip_llm and "accessor" in r.skip_reason

    def test_go_field_accessor_keeps_skip(self):
        r = self._run("F", "a.go", "func (s *S) F() int {\nreturn s.f\n}")
        assert r.skip_llm and "accessor" in r.skip_reason

    def test_java_field_accessor_keeps_skip(self):
        r = self._run("getName", "A.java",
            "public String getName() {\n    return this.name;\n}")
        assert r.skip_llm and "accessor" in r.skip_reason

    def test_returned_sink_reference_refused_every_language(self):
        # The dangerous-name gate the lua arm documented, applied to
        # every arm: handing a sink back as a VALUE is never a clean
        # accessor.
        for name, fp, src in [
            ("get", "a.py", "def get(self):\n    return system"),
            ("get", "a.go", "func get() F {\nreturn os.Exec\n}"),
        ]:
            r = self._run(name, fp, src)
            assert not r.skip_llm, (fp, src)


class TestAccessorDefTimeCode:
    """Def-time-executed expressions (decorators, default args,
    annotations) are live code the body-shape check never sees — a
    Call/NamedExpr/Await in any of them refuses the accessor skip.
    Pre-existing at BASE (adversarial-review member): the AST arm
    judged only the body statements."""

    def _run(self, src):
        return run_prefilter(
            target_path=Path("/nonexistent-target"), file_path="a.py",
            function_name="g", source=src,
        )

    def test_decorator_call_refuses(self):
        r = self._run(
            "@reg(os.system(c))\ndef g(self):\n    return self._x")
        assert not r.skip_llm

    def test_walrus_default_refuses(self):
        r = self._run(
            "def g(self, n=(m := f(c))):\n    return self._x")
        assert not r.skip_llm

    def test_return_annotation_call_refuses(self):
        r = self._run("def g(self) -> f(c):\n    return self._x")
        assert not r.skip_llm

    def test_param_annotation_call_refuses(self):
        r = self._run("def g(self, x: f(c)):\n    return self._x")
        assert not r.skip_llm

    def test_default_call_refuses(self):
        r = self._run("def g(self, x=f(c)):\n    return self._x")
        assert not r.skip_llm

    # ── keep direction ───────────────────────────────────────────────

    def test_property_accessor_keeps_skip(self):
        r = self._run("@property\ndef g(self):\n    return self._x")
        assert r.skip_llm and "accessor" in r.skip_reason

    def test_plain_annotations_and_defaults_keep_skip(self):
        for src in (
            "def g(self) -> bool:\n    return True",
            "def g(self, x: int = 3):\n    return self._x",
        ):
            r = self._run(src)
            assert r.skip_llm and "accessor" in r.skip_reason, src


class TestAccessorSplitSignature:
    """The BSD/K&R return-type-on-its-own-line form (`int\\nname(...)
    \\n{\\n\\treturn 0;\\n}`) — the dominant kernel style — was refused
    wholesale after the whole-body rewrite (the signature matcher only
    understood one-line signatures). The type-only leading line joins
    the signature; honesty still rests on the whole-body arm."""

    def _run(self, name, src):
        return run_prefilter(
            target_path=Path("/nonexistent-target"), file_path="a.c",
            function_name=name, source=src,
        )

    def test_type_on_own_line_field_accessor_skips(self):
        r = self._run("get_name",
            "static const char *\nget_name(struct s *x)\n{\n"
            "\treturn x->name;\n}")
        assert r.skip_llm and "accessor" in r.skip_reason

    def test_type_on_own_line_constant_return_skips(self):
        r = self._run("diskmapopen",
            "int\ndiskmapopen(dev_t dev, int flag, int mode)\n{\n"
            "\treturn 0;\n}")
        assert r.skip_llm and "accessor" in r.skip_reason

    def test_statement_first_line_still_refused(self):
        r = self._run("get_val",
            "int get_val(struct ctx *x, int v)\n{\n"
            "*x->owner_uid = v;\nreturn x->val;\n}")
        assert not r.skip_llm

    def test_two_statement_body_still_refused(self):
        r = self._run("put",
            "void\nput(struct obj *p)\n{\np->refs--;\nreturn p->parent;\n}")
        assert not r.skip_llm


# ---------------------------------------------------------------------------
# php-sql-injection: monotonic over main; additions are method/static
# sinks and other executors, with a statement-scoped prepare guard and an
# operand-scoped sanitiser filter (for additions only).
# ---------------------------------------------------------------------------

class _AdditionsObserver:
    """Wraps the real additions: records every exception, then re-raises
    it.  Production contains such an exception (main's lines are kept),
    so without this a crash on a test's input would go unnoticed."""

    def __init__(self, real):
        self.real = real
        self.raised: list[BaseException] = []

    def __call__(self, source: str, line_start: int) -> set[int]:
        try:
            return self.real(source, line_start)
        except BaseException as exc:
            self.raised.append(exc)
            raise


@pytest.fixture(autouse=True)
def _php_sql_additions_observed(request, monkeypatch):
    """Every test in this module fails if the additions raised during it,
    even where run_prefilter contained the exception.  A class that makes
    them raise on purpose sets ``_ADDITIONS_MAY_RAISE``."""
    if getattr(request.cls, "_ADDITIONS_MAY_RAISE", False):
        yield None
        return
    observer = _AdditionsObserver(_prefilter._php_sql_additions)
    monkeypatch.setattr(_prefilter, "_php_sql_additions", observer)
    yield observer
    _assert_additions_never_raised(observer)


def _assert_additions_never_raised(observer):
    assert not observer.raised, [repr(e) for e in observer.raised[:3]]


def test_teardown_check_fails_on_a_single_recorded_crash():
    """The teardown check passes with no crash and fails on a single one."""
    observer = _AdditionsObserver(lambda _source, _line_start: set())
    _assert_additions_never_raised(observer)
    observer.raised.append(IndexError("injected"))
    with pytest.raises(AssertionError):
        _assert_additions_never_raised(observer)


def test_additions_observer_records_and_reraises():
    """The observer re-raises what the additions raise (interrupts too) and
    records it; a clean call returns its result."""
    def boom(_source, _line_start):
        raise IndexError("injected")

    failing = _AdditionsObserver(boom)
    with pytest.raises(IndexError):
        failing("", 1)
    assert [type(e) for e in failing.raised] == [IndexError]

    def interrupted(_source, _line_start):
        raise KeyboardInterrupt

    interrupting = _AdditionsObserver(interrupted)
    with pytest.raises(KeyboardInterrupt):
        interrupting("", 1)
    assert [type(e) for e in interrupting.raised] == [KeyboardInterrupt]
    clean = _AdditionsObserver(lambda _source, _line_start: {7})
    assert clean("", 1) == {7}
    assert clean.raised == []


def test_additions_observer_sees_a_contained_crash(
    tmp_path, monkeypatch, _php_sql_additions_observed,
):
    """run_prefilter keeps main's line and returns normally; the observer
    still records the exception."""
    def boom(*_a, **_k):
        raise IndexError("injected")

    monkeypatch.setattr(_prefilter, "_php_sql_lex", boom)
    monkeypatch.setattr(_prefilter, "_php_sql_additions_warned", True)
    result = run_prefilter(
        target_path=tmp_path, file_path="app.php", function_name="f",
        source='function f($c, $id) {\n  mysqli_query($c, "x $id");\n}',
        line_start=1,
    )
    assert [h.line for h in result.hits
            if h.rule_id == "php-sql-injection"] == [2]
    assert [type(e) for e in _php_sql_additions_observed.raised] == [
        IndexError]
    _php_sql_additions_observed.raised.clear()


def _php_sql_base_lines(source: str) -> list[int]:
    """Oracle: the historical php-sql-injection rule (pre-change main)."""
    import re as _re
    if _re.search(r'prepare\s*\(|bind_param|pg_query_params', source):
        return []
    return [
        i for i, line in enumerate(source.splitlines(), start=1)
        if _re.search(r'\b(?:mysql_query|mysqli_query|pg_query)\s*\(',
                      line.strip())
        and '$' in line
    ]


def _php_sql_rule_lines(tmp_path, source: str) -> list[int]:
    result = run_prefilter(
        target_path=tmp_path, file_path="app.php", function_name="f",
        source=source, line_start=1,
    )
    hits = sorted(h.line for h in result.hits
                  if h.rule_id == "php-sql-injection")
    # monotonic over the historical rule, asserted on every call
    assert set(_php_sql_base_lines(source)) <= set(hits), source
    # the additions run here without the production fail-safe, so an
    # exception in them fails the test instead of being contained
    added = _prefilter._php_sql_additions(source, 1)
    assert set(hits) == set(_php_sql_base_lines(source)) | added, source
    return hits


def _php_sql_template(body: str) -> str:
    return "function getUser($c, $pdo, $db, $mysqli, $id) {\n" + body + "\n}"


def _php_sql_hit_lines(tmp_path, body: str) -> list[int]:
    return _php_sql_rule_lines(tmp_path, _php_sql_template(body))


def _php_sql_added_lines(tmp_path, body: str) -> list[int]:
    """Hits beyond the historical rule (its own hits, including its
    false positives on sanitised procedural calls, are unchanged)."""
    source = _php_sql_template(body)
    base = set(_php_sql_base_lines(source))
    return [ln for ln in _php_sql_rule_lines(tmp_path, source)
            if ln not in base]


class TestPhpSqlInjection:
    """Method/static sinks, the statement-scoped prepare guard and the
    operand-scoped sanitiser filter; main's own hits are kept."""
    @pytest.mark.parametrize("sink", [
        'return $pdo->query("SELECT * FROM u WHERE id=$id");',
        'return $db->query("SELECT * FROM u WHERE id=" . $id);',
        'return $mysqli->query("SELECT * FROM u WHERE id=$id");',
        'return $pdo->exec("DELETE FROM u WHERE id=" . $id);',
        'return $mysqli->multi_query("UPDATE u SET a=1 WHERE id=" . $id);',
        'return $mysqli->real_query("SELECT * FROM u WHERE n=\'{$id}\'");',
        'return $this->db->query("SELECT * FROM u WHERE id=" . $_GET[\'id\']);',
        'return $pdo->query("SELECT * FROM u WHERE id=" . $req->getId());',
        'return DB::select("SELECT * FROM u WHERE id = $id");',
        'return \\DB::statement("DELETE FROM u WHERE id = " . $id);',
        'return $pdo -> query ( "SELECT * FROM u WHERE id=$id" );',
    ])
    def test_method_and_static_sinks_flagged(self, tmp_path, sink):
        """Main knows only three procedural calls, so a tainted PDO/mysqli
        method or Laravel DB:: call produced no hit and the finding lost its
        prefilter evidence."""
        assert _php_sql_hit_lines(tmp_path, "  " + sink) == [2], sink

    def test_procedural_sink_still_flagged(self, tmp_path):
        """The procedural spelling main already flags must stay flagged."""
        assert _php_sql_hit_lines(
            tmp_path,
            '  return mysqli_query($c, "SELECT * FROM u WHERE id=$id");',
        ) == [2]

    def test_procedural_bare_variable_query_still_flagged(self, tmp_path):
        # The historical "variable in the statement" test is kept for the
        # procedural spellings: no FN regression on a query built elsewhere.
        """Main's "variable on the line" test for procedural sinks is kept, so
        a query built elsewhere is not a new false negative."""
        assert _php_sql_hit_lines(
            tmp_path, "  return mysqli_query($c, $sql);",
        ) == [2]

    @pytest.mark.parametrize("body", [
        # prepare() on another line of the function
        '  $x = $pdo->prepare("SELECT 1");\n'
        '  return mysqli_query($c, "SELECT * FROM u WHERE id=$id");',
        # prepare() earlier on the same line, separate statement
        '  $x = $pdo->prepare("SELECT 1"); '
        'return mysqli_query($c, "SELECT * FROM u WHERE id=$id");',
        # bind_param elsewhere, method sink
        '  $s->bind_param("i", $id);\n'
        '  return $mysqli->query("SELECT * FROM u WHERE id=" . $id);',
        # pg_query_params elsewhere, procedural pg_query
        '  pg_query_params($c, "SELECT 1 WHERE a=$1", [$id]);\n'
        '  return pg_query($c, "SELECT * FROM u WHERE id=" . $id);',
    ])
    def test_prepare_elsewhere_does_not_suppress(self, tmp_path, body):
        """Main's guard read the whole function: one prepare( anywhere hid an
        injectable call on another line or in another statement."""
        assert _php_sql_hit_lines(tmp_path, body) != [], body

    @pytest.mark.parametrize("body", [
        '  $s = $pdo->prepare("SELECT * FROM u WHERE id=?");\n'
        '  $s->execute([$id]);',
        '  $s = $pdo->prepare("SELECT * FROM u WHERE id=?"); '
        '$s->execute([$id]);',
        '  $s = $mysqli->prepare("SELECT * FROM u WHERE id=?");\n'
        '  $s->bind_param("i", $id);\n  $s->execute();',
        # the sink's own value comes from a prepared statement
        '  return $wpdb->query($wpdb->prepare('
        '"DELETE FROM {$wpdb->posts} WHERE id = %d", $id));',
        '  return pg_query_params($c, "SELECT * FROM u WHERE id=$1", [$id]);',
    ])
    def test_prepared_statement_not_flagged(self, tmp_path, body):
        """A prepared statement in the sink's own statement adds no hit."""
        assert _php_sql_added_lines(tmp_path, body) == [], body

    @pytest.mark.parametrize("sink", [
        'return $pdo->query("SELECT * FROM u WHERE n = " . $pdo->quote($n));',
        'return $pdo->query("SELECT * FROM u WHERE n = " '
        '. $pdo->quote($_GET[\'n\']));',
        'return $db->query("SELECT * FROM u WHERE id = " . intval($id));',
        'return $db->query("SELECT * FROM u WHERE id = " '
        '. (int)$_GET[\'id\']);',
        'return $db->query("SELECT * FROM u WHERE id = " . (int) $id '
        '. " LIMIT 1");',
        'return mysqli_query($c, "SELECT * FROM u WHERE id = " . intval($id));',
    ])
    def test_sanitised_operand_adds_nothing(self, tmp_path, sink):
        """A method sink whose only variable operand is quote()d, intval()ed
        or cast adds no hit (main's own procedural hit is unchanged)."""
        assert _php_sql_added_lines(tmp_path, "  " + sink) == [], sink

    @pytest.mark.parametrize("sink", [
        # the sanitiser covers one operand; another reaches the sink raw
        'return $pdo->query("SELECT * FROM u WHERE n = " . $pdo->quote($n) '
        '. " AND id = " . $id);',
        'return $pdo->query("SELECT * FROM u WHERE n = " . $pdo->quote($n) '
        '. " AND id = $id");',
        'return mysqli_query($c, "SELECT * FROM u WHERE a = " . intval($a) '
        '. " AND b = " . $b);',
        # escape functions never prove (dialect/charset dependent)
        'return $mysqli->query("SELECT * FROM u WHERE n = \'" '
        '. $mysqli->real_escape_string($n) . "\'");',
        'return mysqli_query($c, "SELECT * FROM u WHERE n = \'" '
        '. mysqli_real_escape_string($c, $n) . "\'");',
        # escaping without enclosing quotes does not make a number safe
        'return $mysqli->query("SELECT * FROM u WHERE id = " '
        '. $mysqli->real_escape_string($id));',
        # a sanitiser in a sibling statement does not cover the sink
        '$n = $pdo->quote($n); '
        'return $pdo->query("SELECT * FROM u WHERE id = " . $id);',
    ])
    def test_sanitiser_scoped_to_its_operand(self, tmp_path, sink):
        """A sanitiser covers only its own operand: a raw operand beside it,
        an escape function, or a sanitiser in a sibling statement keeps the
        hit."""
        assert _php_sql_hit_lines(tmp_path, "  " + sink) == [2], sink

    @pytest.mark.parametrize("body", [
        '  return $pdo->query("SELECT 1");',
        "  return $pdo->query('SELECT * FROM u WHERE id = $id');",
        '  return $client->query("/api/users/" . $id);',
        '  return $q->query()->where("id", $id);',
        '  $msg = "call $pdo->query(SELECT " . $id . ")";',
        '  return $pdo->query($sql);',
    ])
    def test_non_sql_or_constant_method_calls_not_flagged(self, tmp_path, body):
        """->query() with no SQL-shaped literal, a single-quoted literal, or a
        variable built elsewhere is not an addition."""
        assert _php_sql_added_lines(tmp_path, body) == [], body

    def test_shell_exec_not_sql(self, tmp_path):
        """exec() is shell execution: it stays php-command-exec and never
        becomes an SQL sink."""
        source = 'function f($d) {\n  return exec("ls " . $d);\n}'
        # called directly too: run_prefilter would contain a crash
        assert _prefilter._php_sql_additions(source, 1) == set()
        result = run_prefilter(
            target_path=tmp_path, file_path="a.php", function_name="f",
            source=source, line_start=1,
        )
        ids = {h.rule_id for h in result.hits}
        assert "php-command-exec" in ids
        assert "php-sql-injection" not in ids

    def test_hostile_line_is_linear(self, tmp_path):
        # Hostile shapes for the new helpers: unterminated escapes,
        # unbalanced sanitiser calls, long member chains and concat runs.
        """The lexer and operand scans must stay linear on hostile lines;
        a quadratic scan would stall the prefilter on one long line."""
        import time
        lines = [
            '$pdo->query("SELECT ' + '\\"' * 20000,
            '$pdo->query("SELECT x" . ' + 'intval(' * 20000,
            '$pdo->query("SELECT x" . $a' + '->b' * 20000,
            '$pdo->query("SELECT x"' + ' .' * 20000,
            '$pdo->query("SELECT x" . (int)' + ' ' * 20000,
            '$x . mysqli_query(' * 20000,
            # sanitised-only nested sinks: each must not rescan the rest
            'mysqli_query(intval(1), ' * 3000 + '$x',
            '$x . $db->query(' * 20000,
            '/* it\'s */ $db->query("SELECT x" . f(' * 20000,
        ]
        for ln in lines:
            t0 = time.perf_counter()
            _php_sql_hit_lines(tmp_path, ln)
            # guards against catastrophic (super-linear) blowup, not speed
            assert time.perf_counter() - t0 < 30.0, ln[:40]



class TestPhpSqlInjectionLexing:
    """Comments, escapes and statement/argument bounds of the PHP SQL model."""

    @pytest.mark.parametrize("body,line", [
        # a quote inside a comment must not open a string literal
        ("  /* it's ok */ $r = mysqli_query($c, "
         "\"SELECT * FROM u WHERE id=\" . $id);", 2),
        ("  /* it's ok */ $r = $pdo->query("
         "\"SELECT * FROM u WHERE id=\" . $id);", 2),
        ("  /* say \"hi */ $r = $pdo->query("
         "\"SELECT * FROM u WHERE id=\" . $id);", 2),
        ("  $a = 1; /* it's */ $r = intval(1) . mysqli_query($c, "
         "\"SELECT * FROM u WHERE id=\" . $id);", 2),
        # the line opens inside a block comment begun on an earlier line
        ("  /*\n  it's done */ $r = $pdo->query("
         "\"SELECT * FROM u WHERE id=\" . $id);", 3),
        ("  /*\n  it's done */ $r = mysqli_query($c, "
         "\"SELECT * FROM u WHERE id=\" . intval($id) . $n);", 3),
        # procedural mentions keep the raw-text positive (never fewer
        # procedural hits than the historical rule)
        ("  // mysqli_query($c, \"SELECT * FROM u WHERE id=\" . $id);", 2),
    ])
    def test_comment_quote_does_not_hide_sink(self, tmp_path, body, line):
        """An apostrophe or quote inside a comment must not open a string that
        swallows the sink after it."""
        assert _php_sql_hit_lines(tmp_path, body) == [line], body

    @pytest.mark.parametrize("sink", [
        # escaped quotes and `;` inside a literal stay inside it
        'return $pdo->query("SELECT \\"a;$b\\" FROM u WHERE id=1");',
        # left operand only
        'return $db->query($id . " WHERE x = 1");',
        # clause keyword only (no leading verb in the literal)
        'return $db->query($base . " WHERE id = " . $id);',
        'return $db->query($base . " ORDER BY " . $sort);',
        # statements beyond select/insert/update/delete
        'return $pdo->exec("DROP TABLE " . $t);',
        'return $pdo->exec("TRUNCATE " . $t);',
        'return $pdo->query("SHOW COLUMNS FROM " . $t);',
        # tainted value wrapped in a non-sanitising call, last operand
        'return $pdo->query("SELECT * FROM u WHERE id=" . trim($_GET[\'id\']));',
        'return $pdo->query("SELECT * FROM u WHERE n=" '
        '. strtolower(trim($n)));',
        # PHP function and method names are case-insensitive
        'return $pdo->Query("SELECT * FROM u WHERE id=" . $id);',
        'return MYSQLI_QUERY($c, "SELECT * FROM u WHERE id=" . $id);',
        'return db::Select("SELECT * FROM u WHERE id = $id");',
        # guard tokens are calls, not substrings of names
        'return mysqli_query($c, "SELECT * FROM u WHERE id=" '
        '. $bind_param_id);',
        'return mysqli_query($c, "SELECT * FROM u WHERE id=" . $id '
        '. log_prepare($id));',
        # a sanitiser covers its own (any-depth) argument only
        'return $pdo->query("SELECT * FROM u WHERE id=" '
        '. intval(trim(substr($id, 0, 3))) . " AND n=" . $n);',
        # prepare() in a sibling statement on the same line
        '$x = $pdo->prepare("SELECT 1"); '
        'return $pdo->query("SELECT * FROM u WHERE id=" . $id);',
        # a sanitiser call not closed on this line proves nothing
        'return $pdo->query("SELECT * FROM u WHERE n=" . $pdo->quote($n',
        # code after a PHP 8 attribute is code, not a `#` comment
        '#[Pure] function q($pdo, $id) { return $pdo->query('
        '"SELECT * FROM u WHERE id=" . $id); }',
        # a second sink after the first call's argument list
        'return $db->query("SELECT 1")->fetch() '
        '. $db->query("SELECT * FROM u WHERE id=" . $id);',
    ])
    def test_flagged(self, tmp_path, sink):
        """Escapes, interpolation and multi-line calls must not cut a tainted
        argument off from its sink."""
        assert _php_sql_hit_lines(tmp_path, "  " + sink) == [2], sink

    @pytest.mark.parametrize("body", [
        # no variable anywhere on the line
        '  pg_query("SELECT 1");',
        # escaped `\$` is not interpolation
        "  return $pdo->query(\"SELECT * FROM u WHERE n='\\$name'\");",
        '  return $db->query("SELECT * FROM u WHERE p = " . floatval($p));',
        '  return $db->query("SELECT * FROM u WHERE b = " . boolval($b));',
        '  return $db->query("SELECT * FROM u WHERE id = " . INTVAL($id));',
        '  return $pdo->query("SELECT * FROM u WHERE id=" '
        '. intval(intval($id)));',
        '  return $pdo->query("SELECT * FROM u WHERE n=" '
        '. $pdo->quote($n));',
        # SQL-looking literal and interpolation outside the sink's arguments
        '  $r = $cache->get("SELECT x") ?: $client->query("/api/" . $id);',
        '  $m = "user $id" . $pdo->query("SELECT COUNT(*) FROM u")'
        '->fetchColumn();',
        '  $out = $pdo->query("SELECT COUNT(*) FROM users")->fetchColumn()'
        ' . $sep;',
        # ->query / ->exec on non-SQL receivers
        "  $r = $xp->query(\"//item[@type='update' and @n='\" . $n . \"']\");",
        '  $p->exec("sed --replace " . $file);',
        '  $r = $es->query("where:" . $n);',
        # commented-out method sink
        '  // $r = $pdo->query("SELECT * FROM u WHERE id=" . $id);',
    ])
    def test_not_flagged(self, tmp_path, body):
        """Statement and argument bounds keep a variable in another statement
        or call from making a constant query an addition."""
        assert _php_sql_added_lines(tmp_path, body) == [], body



class TestPhpSqlInjectionCanonical:
    """An ADDITIONAL hit is dropped only on a complete parse with every
    operand directly sanitised; the historical hits stay (its false
    positives on sanitised procedural calls are unchanged from main)."""

    @pytest.mark.parametrize("body,line", [
        # a sanitiser elsewhere in the call proves nothing
        ('  $r = mysqli_query($c, sprintf("SELECT * FROM u WHERE id=%d '
         'AND n=\'%s\'", intval($id), $name));', 2),
        ('  $r = mysqli_query($c, str_replace(":n", $name, "SELECT * FROM u '
         'WHERE id=" . intval($id) . " AND n=:n"));', 2),
        ('  $r = mysqli_query($c, $id ? "SELECT * FROM u WHERE id=" '
         '. intval($id) : $name);', 2),
        ('  $r = mysqli_query($c, "SELECT * FROM u WHERE id=" '
         '. (intval($id) ?: $name));', 2),
        # tainted connection argument
        ('  $r = mysqli_query($conns[intval($id)], $name);', 2),
        ('  $r = mysqli_query($conns[$i], "SELECT 1");', 2),
        # the argument list continues on the next line
        ('  $r = mysqli_query($c, "SELECT * FROM u WHERE id=" . intval($id)\n'
         '    . " AND n=\'" . $name . "\'");', 2),
        # the variable is only on a continuation line
        ('  $r = mysqli_query(\n    $c, "SELECT * FROM u WHERE id=" . $id);', 2),
        ('  $r = $pdo->query(\n    "SELECT * FROM u WHERE id=" . $id);', 2),
        # unclosed argument list (statement ends first)
        ('  $r = mysqli_query($c, "SELECT * FROM u WHERE id=" . intval($id)',
         2),
        ('  $r = $pdo->query("SELECT * FROM u WHERE id=" . intval($id)', 2),
        # escape call without a closing quote after it
        ('  $r = mysqli_query($c, "SELECT * FROM u WHERE n=\'" '
         '. mysqli_real_escape_string($c, $n));', 2),
        # cast of more than one operand
        ('  $r = mysqli_query($c, "SELECT * FROM u WHERE id=" '
         '. (int)$a + $b);', 2),
        # interpolated literal next to a sanitised operand
        ('  $r = mysqli_query($c, "SELECT * FROM u WHERE id=" '
         '. intval($id) . " AND n=\'$name\'");', 2),
        # a sink nested in another sink's arguments is never proved
        ('  $r = mysqli_query($c, mysqli_query($c, $sql));', 2),
        # `#[` parses differently in PHP 7 and 8: main keeps these hits
        ('  mysqli_query($c, "SELECT 1" . intval($id)); #[A] function ff() {}'
         ' pg_send_query($c, "SELECT * FROM t WHERE id = $id"); /* it\'s */', 2),
        ('  #[Attr("x")] mysqli_query($c, "SELECT 1");', 2),
        # main keeps these hits (monotonic), whatever else the line holds
        ('  return mysqli_query($c, "SELECT * FROM u WHERE id = " '
         '. intval(trim($id)));', 2),
        ('  $r = mysqli_query($c, "SELECT * FROM t WHERE id=" . intval($id))'
         ' or die("bad $id");', 2),
        ('  mysqli_query($c, "SELECT 1"); $s->execute([$id]);', 2),
        # the guard keeps main's case-sensitive tokens for every sink kind
        ('  return $wpdb->query($wpdb->PREPARE('
         '"DELETE FROM t WHERE a = %s AND b = $x", $id));', 2),
        # quote() proves only for the sink's own connection object, and
        # escape functions never prove
        ('  $r = mysqli_query($c, "SELECT * FROM u WHERE id=" . intval($id)\n'
         '    . " AND n=" . $pdo->quote($n));', 2),
        ('  $r = mysql_query("SELECT * FROM u WHERE n=\'" '
         '. mysql_real_escape_string($n) . "\'", $link);', 2),
        ('  $r = mysqli_query($c, "SELECT " '
         '. intval(mysqli_query($c, $sql)));', 2),
        # a term that starts with a literal but continues
        ('  $r = mysqli_query($c, "SELECT * FROM t WHERE n=1" ?: $name);', 2),
        # shell output is not a safe operand
        ('  $r = mysqli_query($c, "SELECT * FROM t WHERE n=" . `cat /tmp/n`);',
         2),
        # escape call with only one side quoted
        ('  $r = mysqli_query($c, "SELECT * FROM u WHERE n=\'" '
         '. mysqli_real_escape_string($c, $n) . " LIMIT 1");', 2),
        ('  $r = mysqli_query($c, "SELECT * FROM u WHERE n=" '
         '. mysqli_real_escape_string($c, $n) . "\' LIMIT 1");', 2),
        # parenthesis nesting beyond the parser's depth bound
        ('  $r = mysqli_query($c, "SELECT * FROM u WHERE id=" . ((((((((((((((((((((((((((((((((((((((((intval($id))))))))))))))))))))))))))))))))))))))))));', 2),
        # an extra argument carrying a variable
        ('  $r = mysqli_query($c, "SELECT 1", $mode);', 2),
        # a prepare() in an enclosing condition is another statement
        ('  if ($s = $db->prepare("x")) { $r = mysqli_query($c, $sql); }', 2),
        # interpolating heredoc SQL
        ('  $r = $pdo->query(<<<SQL\n  SELECT * FROM t WHERE id = $id\n'
         '  SQL\n  );', 2),
        # a sink after `// */` on the same line
        ('  $r = mysqli_query($c, $sql . $id); // */ mysqli_query($c, '
         '"SELECT 1 WHERE id=" . intval($id));', 2),
        ('  $r = $pdo->query("CALL proc(" . $id . ")");', 2),
        ('  $r = $pdo->query("WITH t AS (SELECT 1) SELECT * FROM t WHERE '
         'id=" . $id);', 2),
        ('  $r = $pdo->query("SHOW TABLES LIKE \'" . $p . "\'");', 2),
        ('  $r = $pdo->exec("CREATE TABLE " . $t . " (id int)");', 2),
        # backtick strings are literals: `//`, `#`, `/*` inside them
        ('  $h = `curl -s http://host/`; $r = $pdo->query('
         '"SELECT * FROM t WHERE id=" . $id);', 2),
        ('  $h = `ls #`; $r = $pdo->query("SELECT * FROM t WHERE id=" . $id);',
         2),
        ('  $h = `ls /*`; $r = $pdo->query("SELECT * FROM t WHERE id=" . $id);',
         2),
    ])
    def test_kept(self, tmp_path, body, line):
        """Any operand the filter cannot prove safe keeps the hit."""
        assert line in _php_sql_hit_lines(tmp_path, body), body

    @pytest.mark.parametrize("body", [
        # complete parse, every operand directly sanitised
        '  $r = mysqli_query($c, "SELECT * FROM u WHERE id=" . intval($id)\n'
        '    . " AND k=" . (int)$k);',
        '  $r = mysqli_query($this->db, "SELECT * FROM u WHERE id="\n'
        '    . (int)$_GET[\'id\'] . " LIMIT " . 10);',
        '  $r = pg_query($c, ("SELECT * FROM u WHERE id=" . intval($id)));',
        '  $r = mysqli_query($c, "SELECT 1", MYSQLI_USE_RESULT);',
        '  return (mysqli_query($c, "SELECT * FROM u WHERE id=" '
        '. (int)$id));',
        '  $r = MYSQLI_QUERY($c, "SELECT 1");',
        # sanitised method sinks: intval/quote of any expression
        '  return $db->query("SELECT * FROM u WHERE id = " '
        '. intval(trim($id)));',
        '  return $pdo->query("SELECT * FROM u WHERE n=" '
        '. $pdo->quote(trim($a) . $b));',
        # no variable on the line or in the call
        '  pg_query(SQL_ALL_USERS);',
        # nowdoc does not interpolate
        "  $r = $pdo->query(<<<'SQL'\n  SELECT * FROM t WHERE a = '$x'\n"
        "  SQL\n  );",
        # a safe sink followed by a comment
        '  $r = mysqli_query($c, "SELECT * FROM t WHERE id=" . intval($id));'
        ' /* note */',
        # `#` comments hold no code
        '  $x = 1; # $pdo->query("SELECT * FROM t WHERE id=" . $id);',
        # literals after the sink's argument list are not its SQL
        '  $r = $cache->query("k" . $id) or error_log("SELECT failed");',
        '  $r = $pdo->query("SELECT * FROM t WHERE k=" . T_KIND)'
        ' or die("bad $id");',
        # non-SQL receivers holding an English SQL word
        '  $n = $xpath->query("//entry[source=\'from " . $id . "\']");',
        '  $u = $url->query("from " . $id);',
        '  $o = $ssh->exec("show version " . $id);',
        '  $r = $api->exec("create user " . $id);',
        '  $r = $gql->query("query { user(id: " . $id . ") { name } }");',
        # bindings and fetch modes are not the SQL argument
        '  $r = $db->query("SELECT * FROM t WHERE id = ?", [$id]);',
        '  $r = DB::select("SELECT * FROM t WHERE id = ?", [$id]);',
    ])
    def test_no_addition(self, tmp_path, body):
        """Fully proved calls add nothing beyond main."""
        assert _php_sql_added_lines(tmp_path, body) == [], body

    def test_property_tainted_operand_fires_sanitised_adds_nothing(
        self, tmp_path,
    ):
        """Random mixes of safe and tainted operands: one tainted operand
        always fires, all-safe operands never add a hit."""
        import random

        rnd = random.Random(20261020)
        safe = [
            "intval($v{k})", "(int)$v{k}", "(int) $_GET['v{k}']",
            "$pdo->quote($v{k})", "floatval($v{k})", "boolval($v{k})",
            "intval(trim($v{k}))", "$db->quote(strtolower($v{k}))",
            "INTVAL($v{k})", "(int)$o->p{k}", "(bool)$f{k}", "17",
            "(intval($v{k}))",
        ]
        unsafe = [
            "$v{k}", "$_GET['v{k}']", "trim($v{k})", "$o->get($v{k})",
            "strtolower($v{k})", '"x$v{k}"', '"x$o->p{k}"',
            "intval($a) + $v{k}", "$v{k} ?: 1", "(string)$v{k}",
            "addslashes($v{k})", "htmlspecialchars($v{k})",
            "$v{k}[intval($i)]", "(int)$a . $v{k}", "md5($v{k})",
        ]
        sinks = [
            ("mysqli_query({conn}, ", True), ("pg_query({conn}, ", True),
            ("mysql_query(", True), ("$pdo->query(", False),
            ("$db->exec(", False), ("DB::select(", False),
            ("$mysqli->real_query(", False),
        ]
        conns = [("$c", True), ("$this->db", True), ("$conns[$i]", False),
                 ("$conns[intval($i)]", False), ("getConn()", False)]
        lines: list[str] = []
        expect: dict[int, bool] = {}  # sink line -> no addition expected
        cases = 0
        while cases < 2400:
            sink, proc = rnd.choice(sinks)
            ok = True
            if "{conn}" in sink:
                conn, conn_ok = rnd.choice(conns)
                sink = sink.replace("{conn}", conn)
                ok = conn_ok
            parts = ['"SELECT * FROM t WHERE c0 = "']
            for k in range(1, rnd.randint(1, 4) + 1):
                roll = rnd.random()
                if roll < 0.15:  # escape call: never a proof
                    q = "'" if rnd.random() < 0.6 else ""
                    parts[-1] = parts[-1][:-1] + q + '"'
                    parts.append(
                        f"mysqli_real_escape_string($c, $v{k})")
                    parts.append(f'"{q} AND c{k} = "')
                    ok = False
                    continue
                if roll < 0.6:
                    op = rnd.choice(safe)
                    # quote() is safe only on the sink's own receiver
                    if "->quote(" in op and not sink.startswith(
                        op.split("->quote(")[0] + "->"
                    ):
                        ok = False
                else:
                    op = rnd.choice(unsafe)
                    ok = False
                parts.append(op.replace("{k}", str(k)))
                parts.append(f'" AND c{k} = "')
            sep = rnd.choice([" . ", " . ", "\n    . "])
            expr = sep.join(parts)
            wrap = rnd.random()
            if wrap < 0.08:
                expr = f'sprintf("%s%s", {expr}, $w)'
                ok = False
            elif wrap < 0.14:
                expr = f'str_replace(":x", $w, {expr})'
                ok = False
            elif wrap < 0.20:
                expr = f'$f ? {expr} : "SELECT 1"'
                ok = False
            elif wrap < 0.25:
                expr = f'({expr})'
            line_no = len(lines) + 2  # function header is line 1
            text = f"  $r{cases} = {sink}{expr});"
            lines.extend(text.split("\n"))
            expect[line_no] = ok
            cases += 1
        full = "\n".join(lines)
        hits = set(_php_sql_hit_lines(tmp_path, full))
        base = set(_php_sql_base_lines(_php_sql_template(full)))
        leaked = [ln for ln, ok in expect.items() if not ok and ln not in hits]
        # a proved call adds nothing; the historical hit stays
        over = [ln for ln, ok in expect.items()
                if ok and ln in hits and ln not in base]
        src = ["", ""] + lines
        assert not leaked, [src[ln] for ln in leaked[:5]]
        assert not over, [src[ln] for ln in over[:5]]
        assert sum(1 for ok in expect.values() if not ok) > 1000
        assert sum(1 for ok in expect.values() if ok) > 200


class TestPhpSqlInjectionTiming:
    """The rule stays linear: bounded relative to the PHP prefilter with
    the SQL rule stubbed out (the rest of base's per-line work)."""

    @staticmethod
    def _timed(tmp_path, source, monkeypatch=None, stub=False):
        import time

        import core.audit.prefilter as pf
        if stub:
            monkeypatch.setattr(pf, "_php_sql_injection_lines",
                                lambda s, n: set())
        t0 = time.perf_counter()
        run_prefilter(
            target_path=tmp_path, file_path="big.php", function_name="f",
            source=source, line_start=1,
        )
        return time.perf_counter() - t0

    @pytest.mark.parametrize("line", [
        "$a; " + 'mysqli_query($c, "x" . intval($i)) . ' * 4000,
        "$a; " + "mysqli_query(" * 4000,
        "$a" + '; mysqli_query($c, "x" . intval($i))' * 4000,
        '$pdo->query(' + '"a" . ' * 20000 + '$x)',
        '$a->query("select x where " . $b' + ')->query(' * 4000,
        'mysqli_query($c, "x"' + ' . (' * 4000 + '$a' + ')' * 4000 + ');',
        'mysqli_query($c, "\'"' + ' . mysqli_real_escape_string(' * 4000,
        'mysqli_query($c, "x" . ' + '(' * 3000 + 'intval($a)' + ')' * 3000
        + ');',
        "#[A] " * 20000 + "mysqli_query($c, $id);",
        '$x = "' + '{$a["' * 20000 + '"]}' * 20000 + '"; mysqli_query($c, $id);',
        "$a; " + '// x ?><?php mysqli_query($c, "x"); ' * 4000,
        'mysqli_query($c, "\'"' + ' . mysqli_real_escape_string($c, $n)'
        ' . "\'\'"' * 4000 + ' . "\'");',
        "$a; mysqli_query($c, 'x'); " + "a" * 100000 + "query(",
    ])
    def test_hostile_line(self, tmp_path, monkeypatch, line):
        """Hostile lines cost at most a small multiple of the PHP prefilter
        without the SQL rule, so the rule cannot dominate a scan."""
        source = "function f() {\n" + line + "\n}"
        # called directly too: run_prefilter would contain a crash
        _prefilter._php_sql_additions(source, 1)
        rule = self._timed(tmp_path, source)
        ref = self._timed(tmp_path, source, monkeypatch, stub=True)
        assert rule <= 3 * ref + 0.5, (len(line), rule, ref)

    def test_multi_megabyte_function(self, tmp_path, monkeypatch):
        """A multi-megabyte function with every lexer construct finishes in
        bounded time (no per-line rescans of the function)."""
        block = (
            "  // it's a comment with mysqli_query( and \"quotes\n"
            "  $r = mysqli_query($c, \"SELECT * FROM u WHERE id=\" "
            ". intval($id));\n"
            "  $s = $pdo->query(\"SELECT * FROM u WHERE n='\" . $n . \"'\");\n"
            "  /* block\n     it's */ $t = `ls -l`;\n"
            "  $q = <<<SQL\n  SELECT * FROM t WHERE a = $a\n  SQL;\n"
            "  $x = $db->query($sql, [$id]) . 'tail;{}';\n"
        )
        source = "function f() {\n" + block * (2_200_000 // len(block)) + "}"
        assert len(source) > 2_000_000
        # called directly too: run_prefilter would contain a crash
        _prefilter._php_sql_additions(source, 1)
        rule = self._timed(tmp_path, source)
        ref = self._timed(tmp_path, source, monkeypatch, stub=True)
        assert rule <= 2 * ref + 1.0, (rule, ref)



def _php_file_sql_lines(tmp_path, source: str) -> list[int]:
    return _php_sql_rule_lines(tmp_path, source)


def _php_file_added_lines(tmp_path, source: str) -> list[int]:
    base = set(_php_sql_base_lines(source))
    return [ln for ln in _php_sql_rule_lines(tmp_path, source)
            if ln not in base]


_T_PROC = 'mysqli_query($c, "SELECT * FROM t WHERE id=" . $_GET["id"]);'
_T_METH = '$pdo->query("SELECT * FROM t WHERE id=" . $_GET["id"]);'


class TestPhpSqlInjectionRawText:
    """Lexer-confusing constructs never cost a historical hit (it is read
    from raw text and never filtered); method sinks they hide are a bounded
    gap of the additions."""

    @pytest.mark.parametrize("source,line", [
        # lexer blind spots next to a proved sink spelled `name/**/(`
        ('<?php\nmysqli_query/**/($c, "SELECT 1"); $x = "{$a["\\""]}"; '
         + _T_PROC + "\n", 2),
        ('<?php\nmysqli_query/**/($c, "SELECT 1"); // done ?><?php '
         + _T_PROC + "\n", 2),
        ("<?php\nmysqli_query/**/($c, \"SELECT 1\"); ?><a title='x<?php "
         + _T_PROC + " ?>'>\n", 2),
        ('<?php\nmysqli_query/**/($c, "SELECT 1"); # ?><?php '
         + _T_PROC + "\n", 2),
        ("<?php\nmysqli_query/**/($c, \"SELECT 1\"); $x = \"{$m['\"']}\"; "
         + _T_PROC.replace('"id"', "'id'") + "\n", 2),
        ('<?php\nmysqli_query($c, "SELECT 1"); // done ?><?php '
         + _T_PROC + "\n", 2),
        # a method-name token on the line that is not a proved call
        ('<?php\nmysqli_query($c, "SELECT 1"); DB :: select("x" . $id);\n',
         2),
        # method sinks after constructs that used to flip quote parity
        ('<?php\n$x = "{$a["\\""]}";\n' + _T_METH + "\n", 3),
        ('<?php\n// end ?><?php\n' + _T_METH + "\n", 3),
        ("<?php\n#[todo] don't\n" + _T_METH + "\n$y = 'x';\n", 3),
        # `?>` ends a line comment; inline HTML is not PHP
        ('<?php\n$x = 1; // end ?><?php ' + _T_METH + "\n", 2),
        ("<?php\n?><p>it's</p><?php\n" + _T_METH + "\n", 3),
        # `?>` also ends the statement: a prepare() before it guards nothing
        ('<?php\n$s = $db->prepare("x") ?><b>x</b><?php '
         'mysqli_query($c, $sql . $id);\n', 2),
        # the procedural guard keeps main's case-sensitive tokens
        ('<?php\n$s = $db->PREPARE("x") and mysqli_query($c, $sql . $id);\n',
         2),
        ('<?php\n$x = "{$a["\\""]}";\nmysqli_query($c,\n'
         ' "SELECT * FROM t WHERE id=" . $_GET["id"]);\n', 3),
        # PHP label characters include bytes >= 0x80: `EOT€` is no closer
        ('<?php\n$q = <<<EOT\nEOT\u20ac "\nEOT;\n' + _T_METH
         + '\n$z = "";\n', 5),
        ('<?php\n$q = <<<EOT\nEOT\u20ac "\nEOT;\nmysqli_query/**/($c, '
         '"SELECT 1"); ' + _T_PROC + '\n$z = "";\n', 5),
        ("<?php\n$r = $pdo->query(<<<SQL\nSELECT * FROM t WHERE a = 1\n"
         "SQL_X '\nSQL\n . $id);\n", 2),
        # escape call outside an SQL string (quote parity even)
        ('<?php\nmysqli_query($c, "SELECT * FROM t WHERE a=\'\'" '
         '. mysqli_real_escape_string($c, $_GET["a"]) . "\'\'");\n', 2),
        # escape functions never prove, even between correct quotes
        ('<?php\nmysqli_query($c, "SELECT * FROM t WHERE a=\'" '
         '. mysqli_real_escape_string($c, $_GET["a"]) . "\'");\n', 2),
        # escape call that does not end its term / is not an escape
        ('<?php\n$r = mysqli_query($c, "SELECT * FROM u WHERE n=\'" '
         '. mysqli_real_escape_string($c, $n) ?? $_GET["x"] . "\'");\n', 2),
        ('<?php\n$r = mysqli_query($c, "SELECT * FROM u WHERE n=\'" '
         '. $db->unescape($_GET["n"]) . "\'");\n', 2),
        # method sinks whose variable sits after a `{` or in backticks
        ('<?php\n$r = $pdo->query("SELECT * FROM t WHERE a = " '
         '. match(true) { default => $_GET["id"] });\n', 2),
        ('<?php\n$r = DB::select("SELECT * FROM t WHERE a = " '
         '. (function() { return $x; })());\n', 2),
        ('<?php\n$r = $pdo->query("SELECT * FROM t WHERE a = " . `cat $f`);\n',
         2),
    ])
    def test_kept(self, tmp_path, source, line):
        """Lexer-confusing constructs never cost a hit main reports."""
        assert line in _php_file_sql_lines(tmp_path, source), source

    @pytest.mark.parametrize("source", [
        '<?php\nmysqli_query/**/($c, "SELECT 1");\n',
        '<?php\nmysqli_query($c, "SELECT 1"); $s = $pdo->query("SELECT 2");\n',
        '<?php\nmysqli_query($c, "SELECT " . intval($id)); '
        '$r = DB::select("SELECT 1");\n',
        # a call spelled inside a string literal is not a call
        '<?php\nmysqli_query($c, "SELECT 1"); $x = "->query($id)";\n',
        # guarded statement: no addition (main's function-wide guard
        # silences it too)
        '<?php\n$r = mysqli_query($c, $sql) && $s->bind_param("i", $id);\n',
    ])
    def test_no_addition(self, tmp_path, source):
        """The same constructs around constant or proved calls add nothing."""
        assert _php_file_added_lines(tmp_path, source) == [], source

    def test_property_confusers_never_hide_a_tainted_call(self, tmp_path):
        """Random confusers around a tainted call never hide main's hit."""
        import random

        rnd = random.Random(20261021)
        safe = [
            'mysqli_query($c, "SELECT 1");',
            'mysqli_query/**/($c, "SELECT 1");',
            'MYSQLI_QUERY ($c, "SELECT 1");',
            'pg_query($c, "SELECT " . intval($id));',
            'mysql_query("SELECT \'" . mysql_real_escape_string($n) . "\'");',
        ]
        # main's own sink names: kept from raw text whatever the lexer
        # makes of the line (code PHP itself hides in a literal, comment
        # or `?>` block is not a call; additions there are a bounded gap)
        tainted = [
            _T_PROC,
            'pg_query($c, "SELECT " . $id);',
            'mysql_query("SELECT " . $x);',
            'mysqli_query ($c, $sql);',
        ]
        confusers = [
            "// done ?><?php ", "# note ?><?php ", "?><a title='x<?php ",
            '$x = "{$a["\\""]}"; ', "$x = \"{$m['\"']}\"; ",
            "$h = `ls #`; ", "/* it's */ ", "$y = 'a\\'b'; ",
            '$z = "a\\"b"; ', "#[A] ", "' ", '" ', "` ", "/* ", "// ",
            "# ", "?> ", '$s = "${a["}"]}"; ', "<<<EOT ",
        ]
        lines = []
        for _ in range(2400):
            parts = [rnd.choice(safe), rnd.choice(tainted)]
            rnd.shuffle(parts)
            mid = "".join(rnd.choice(confusers)
                          for _ in range(rnd.randint(1, 3)))
            lines.append(parts[0] + " " + mid + parts[1])
        source = "<?php\n" + "\n".join(lines) + "\n"
        hits = set(_php_file_sql_lines(tmp_path, source))
        missed = [ln for ln in range(2, len(lines) + 2) if ln not in hits]
        assert not missed, [lines[ln - 2] for ln in missed[:5]]



_ESC = 'mysqli_real_escape_string($c, $n)'


class TestPhpSqlInjectionSinkFamily:
    """Other SQL executors are additions; escape functions never prove,
    and the historical hits stay whatever the line holds."""

    @pytest.mark.parametrize("source,line", [
        # off-list executors next to a proved in-list call
        ("<?php\nmysqli_query($c, 'SET NAMES utf8'); mysqli_multi_query($c, "
         "\"DELETE FROM t WHERE id = $id\");\n", 2),
        ("<?php\nmysqli_query($c, 'SELECT 1'); mysqli_real_query($c, "
         "'SELECT * FROM t WHERE id = ' . $_GET['id']);\n", 2),
        ("<?php\npg_query($c, 'BEGIN'); pg_send_query($c, "
         "\"SELECT * FROM t WHERE n = '$n'\");\n", 2),
        ("<?php\nmysqli_query($c, 'SELECT 1'); sqlite_query($db, "
         "\"SELECT * FROM t WHERE id=\" . $id);\n", 2),
        ("<?php\nmysqli_query($c, 'SELECT 1'); odbc_exec($c, "
         "\"SELECT * FROM t WHERE id=\" . $id);\n", 2),
        # newly parsed executors fire on their own
        ('<?php\n$r = sqlsrv_query($conn, "SELECT * FROM t WHERE id = " . $id);'
         '\n', 2),
        ('<?php\n$s = oci_parse($conn, "SELECT * FROM t WHERE id = " . $id);'
         '\n', 2),
        ('<?php\n$r = db2_exec($conn, "SELECT * FROM t WHERE id = " . $id);\n',
         2),
        ('<?php\n$r = mysql_db_query("db", "SELECT * FROM t WHERE id = " '
         '. $id);\n', 2),
        ('<?php\n$r = mysql_unbuffered_query("SELECT * FROM t WHERE id = " '
         '. $id);\n', 2),
        # the escape lands outside an SQL string
        ('<?php\nmysqli_query($c, "SELECT * FROM t WHERE a = \'\\\\" . "\' AND '
         'n = \'" . ' + _ESC + ' . "\'");\n', 2),
        ('<?php\nmysqli_query($c, "SELECT * FROM t WHERE a = \'\\x5c\' AND '
         'n = \'" . ' + _ESC + ' . "\'");\n', 2),
        ('<?php\nmysqli_query($c, "SELECT * FROM t /* don\'t */ WHERE a = '
         '\'x\'" . ' + _ESC + ' . "\'");\n', 2),
        ('<?php\nmysqli_query($c, "SELECT 1 --it\'s\\nWHERE n=\'" . ' + _ESC
         + ' . "\'");\n', 2),
        # a hidden executor token not in the method/procedural lists
        ("<?php\nmysqli_query($c, 'SELECT 1'); ' oci_parse($conn, "
         "\"SELECT \" . $id);\n", 2),
        # a backslash inside the SQL string: NO_BACKSLASH_ESCAPES decides
        ('<?php\nmysqli_query($c, "SELECT * FROM t WHERE a = \'x\\\\\'y\' AND '
         'n = \'" . ' + _ESC + ' . "\'");\n', 2),
        # quote() inside an open SQL string
        ('<?php\nmysqli_query($c, "SELECT * FROM t WHERE a = \'" '
         '. $pdo->quote($a) . "\'");\n', 2),
        # heredoc escape rules are not modelled: no escape proof
        ("<?php\n$r = mysqli_query($c, <<<SQL\nSELECT * FROM t WHERE n = '\n"
         "SQL . " + _ESC + " . \"'\");\n", 2),
        # database-name argument that is neither plain nor constant
        ('<?php\n$r = mysql_db_query($dbs[$i], "SELECT 1");\n', 2),
        # escape functions never prove: correct quoting,
        # \' in a single-quoted literal, LIKE, SQL comments, wrong dialect
        ('<?php\nmysqli_query($c, "SELECT * FROM t WHERE n = \'" . ' + _ESC
         + ' . "\'");\n', 2),
        ("<?php\nmysqli_query($c, 'SELECT * FROM t WHERE a = \\'x\\' AND n = "
         "\\'' . " + _ESC + " . \"'\");\n", 2),
        ('<?php\n$r = $this->db->query("SELECT * FROM posts WHERE title LIKE '
         '\'%" . $this->db->real_escape_string($q) . "%\'");\n', 2),
        ('<?php\nmysqli_query($c, "SELECT 1 # it\'s\\nWHERE n=\'" . ' + _ESC
         + ' . "\'");\n', 2),
        ('<?php\npg_query($c, "SELECT 1 FROM t WHERE a = 1 --\'\\n" '
         '. pg_escape_string($x) . "\'");\n', 2),
        ('<?php\npg_query($c, "SELECT * FROM t WHERE n = \'" '
         '. mysqli_real_escape_string($m, $x) . "\'");\n', 2),
        ('<?php\nmysqli_query($c, "SELECT * FROM t WHERE n = \'" '
         '. pg_escape_string($x) . "\'");\n', 2),
        ('<?php\npg_query($c, "SELECT * FROM t WHERE n = E\'" '
         '. pg_escape_string($x) . "\'");\n', 2),
        ('<?php\nmysqli_query($c, "SELECT * FROM t WHERE a = " '
         '. $pdo->quote($a) . " AND n = \'" . ' + _ESC + ' . "\'");\n', 2),
        # quote() from another connection object, or inside an open string
        ('<?php\n$r = $db->query("SELECT * FROM t WHERE n = " '
         '. $pdo->quote($n));\n', 2),
        ('<?php\n$r = $pdo->query("SELECT * FROM t WHERE n = \'" '
         '. $pdo->quote($n) . "\'");\n', 2),
        # ... or next to a double quote or backtick in the SQL text
        ("<?php\n$r = $pdo->query('SELECT * FROM t WHERE n = \"' "
         ". $pdo->quote($n));\n", 2),
        ('<?php\n$r = $pdo->query("SELECT `" . $pdo->quote($n) . "` FROM t");\n',
         2),
        # ... also through parentheses
        ('<?php\n$r = $pdo->query("SELECT * FROM t WHERE n = \'" '
         '. ($pdo->quote($n)) . "\'");\n', 2),
        ('<?php\n$r = $pdo->query(("SELECT * FROM t WHERE n = \'") '
         '. $pdo->quote($n));\n', 2),
        # dynamic calls and further executor names next to a proved call
        ("<?php\nmysqli_query($c, 'SELECT 1'); "
         "call_user_func('mysqli_query', $c, $sql);\n", 2),
        ("<?php\nmysqli_query($c, 'SELECT 1'); "
         '$f($c, "SELECT * FROM t WHERE id = $id");\n', 2),
        ("<?php\nmysqli_query($c, 'SELECT 1'); "
         '$db->$m("SELECT * FROM t WHERE id = $id");\n', 2),
        ("<?php\nmysqli_query($c, 'SELECT 1'); "
         '$conn->executeStatement("DELETE FROM t WHERE id = $id");\n', 2),
        ("<?php\nmysqli_query($c, 'SELECT 1'); "
         '$wpdb->get_results("SELECT * FROM t WHERE id = $id");\n', 2),
        ("<?php\nmysqli_query($c, 'SELECT 1'); "
         'DB::selectOne("SELECT * FROM t WHERE id = $id");\n', 2),
        ("<?php\nmysqli_query($c, 'SELECT 1'); "
         '$q->whereRaw("id = $id");\n', 2),
        ("<?php\nmysqli_query($c, 'SELECT 1'); "
         'my_QUERY("DELETE FROM t WHERE id = $id");\n', 2),
        # a parsed executor fires on its own
        ('<?php\n$r = pg_send_query($c, "SELECT * FROM t WHERE id=" . $id);\n',
         2),
        ("<?php\nmysqli_query($c, 'SELECT 1'); "
         '$db->{"query"}("DELETE FROM t WHERE id = $id");\n', 2),
        ("<?php\nmysqli_query($c, 'SELECT 1'); "
         'DB::scalar("SELECT n FROM t WHERE id = $id");\n', 2),
        # \u{110000} in a literal must not crash the rule
        ('<?php\n$r = $pdo->query("SELECT \\u{110000} FROM t WHERE id=" . $id);'
         '\n', 2),
        # inside a double-quoted SQL string: depends on ANSI_QUOTES
        ('<?php\nmysqli_query($c, "SELECT * FROM t WHERE n = \\"" . ' + _ESC
         + ' . "\\"");\n', 2),
        # non-ASCII heredoc labels, quotes inside them
        ("<?php\n$h = <<<\u00c9\nit\"s\n\u00c9;\n$db->query("
         "\"SELECT * FROM t WHERE id = $id\");\n", 5),
        ("<?php\n$s = \"a ${a[\"it's\"]} b\"; $db->query("
         "\"SELECT * FROM t WHERE id = $id\");\n", 2),
        ("<?php\n$s = \"a {$a[\"x}y\"]} b\"; $db->query("
         "\"SELECT * FROM t WHERE id = $id\");\n", 2),
        ("<?php\n?><b><?= $x ?>it's</b>\n<?php $db->query("
         "\"SELECT * FROM t WHERE id = $id\");\n", 3),
        ("<?php\n?><b><?= $db->query(\"SELECT * FROM t WHERE id = $id\") ?>"
         "</b>\n<?php echo 1;\n", 2),
        ("<?php\n#[todo] fix \"later\n$db->query("
         "\"SELECT * FROM t WHERE id = $id\");\n", 3),
    ])
    def test_kept(self, tmp_path, source, line):
        """Executors main does not list (mysqli_real_query, sqlsrv_query, ...)
        are additions, and escape functions never prove an operand safe."""
        assert line in _php_file_sql_lines(tmp_path, source), source

    @pytest.mark.parametrize("source", [
        # a proved newly parsed executor on a main-positive line
        "<?php\nmysqli_query($c, 'SET NAMES utf8'); "
        'mysqli_multi_query($c, "SELECT 1; SELECT 2");\n',
        # newly parsed executors, proved
        '<?php\n$r = mysqli_multi_query($c, "SELECT 1; SELECT 2");\n',
        '<?php\n$r = pg_send_query($c, "SELECT " . intval($id));\n',
        '<?php\n$r = sqlsrv_query($conn, "SELECT * FROM t WHERE id = ?", '
        '[$id]);\n',
        '<?php\n$r = mysql_db_query("db", "SELECT 1", $link);\n',
        # mysql_query(query, link): the link is the second argument
        '<?php\n$r = mysql_query("SELECT * FROM t WHERE id=" . intval($id), '
        '$link);\n',
        # quote() on the sink's own receiver, no quote in the literals
        '<?php\n$r = $this->db->query("SELECT * FROM t WHERE n = " '
        '. $this->db->quote($n));\n',
        '<?php\n$r = $pdo->query("SELECT * FROM t WHERE n = " . $pdo->quote($n)'
        ' . " AND id = " . intval($id));\n',
    ])
    def test_no_addition(self, tmp_path, source):
        """Proved calls of those executors add nothing."""
        assert _php_file_added_lines(tmp_path, source) == [], source



_CALL_SHAPE_KEPT = [
    # quote() after \x27 literal, same line
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); $db->query("SELECT * FROM t WHERE a = \\x27" . $db->quote($x));\n', 2),
    # quote() after \047 literal
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); $db->query("SELECT * FROM t WHERE a = \\047" . $db->quote($x));\n', 2),
    # quote() after \u{27} literal
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); $db->query("SELECT * FROM t WHERE a = \\u{27}" . $db->quote($x));\n', 2),
    # control: quote() after a literal holding a plain '
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); $db->query("SELECT * FROM t WHERE a = \'" . $db->quote($x));\n', 2),
    # Arabic-Indic digit: a constant name to PHP, not a number
    ('<?php\ndefine("١", $_GET["x"]);\nmysqli_query($c, "SELECT * FROM t WHERE a = " . ١);\n', 3),
    # superscript two: a constant name to PHP, not a number
    ('<?php\nmysqli_query($c, "SELECT * FROM t WHERE a = " . ²);\n', 2),
    # control: ASCII-named constant
    ('<?php\nmysqli_query($c, "SELECT * FROM t WHERE a = " . X);\n', 2),
    # 'Prepare()' inside a string in the method sink's statement is not a guard
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); $db->query("SELECT * FROM t WHERE id = $id") or die("Prepare() failed");\n', 2),
    # ADOdb ->Prepare( as an argument of the method sink
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); $db->query("SELECT * FROM t WHERE id = $id", $db->Prepare("x"));\n', 2),
    # control: no guard text in the statement
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); $db->query("SELECT * FROM t WHERE id = $id") or die("failed");\n', 2),
    # ->query, then "(" on the next line
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); $r = $db->query\n    ($sql);\n', 2),
    # call_user_func, then "(" on the next line
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); call_user_func\n    ("mysqli_query", $c, "DELETE FROM t WHERE id = $id");\n', 2),
    # control: ->query($sql) on one line
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); $r = $db->query($sql);\n', 2),
    # tainted ->query nested in intval(), continued on the next line
    ('<?php\n$n = mysqli_query($c, "SELECT * FROM log WHERE uid = " . intval(\n    $pdo->query("SELECT id FROM users WHERE name = \'$name\'")->fetchColumn()));\n', 2),
    # tainted ->query nested in an (int) cast, continued on the next line
    ('<?php\n$n = mysqli_query($c, "SELECT * FROM log WHERE uid = " . (int)$pdo\n    ->query("SELECT id FROM users WHERE name = \'$name\'")->fetchColumn());\n', 2),
    # tainted DB::select nested in intval(), continued on the next line
    ('<?php\n$n = mysqli_query($c, "SELECT * FROM log WHERE uid = " . intval(\n    DB::select("select id from users where name = \'$name\'")[0]->id));\n', 2),
    # control: the same nesting on one line
    ('<?php\n$n = mysqli_query($c, "SELECT * FROM log WHERE uid = " . intval($pdo->query("SELECT id FROM users WHERE name = \'$name\'")->fetchColumn()));\n', 2),
    # control: the inner method sink on its own
    ('<?php\n$id = $pdo->query("SELECT id FROM users WHERE name = \'$name\'")->fetchColumn();\n', 2),
    # [$db,'query'](...)
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); [$db, "query"]("DELETE FROM t WHERE id = $id");\n', 2),
    # 'mysqli_query'(...)
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); "mysqli_query"($c, "DELETE FROM t WHERE id = $id");\n', 2),
    # ($fn)(...)
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); ($fn)($c, "DELETE FROM t WHERE id = $id");\n', 2),
    # $a['f'](...)
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); $a["f"]($c, "DELETE FROM t WHERE id = $id");\n', 2),
    # array_filter cb
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); array_filter(["DELETE FROM t WHERE id = $id"], [$db, "query"]);\n', 2),
    # Closure::fromCallable
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); Closure::fromCallable([$db, "query"])("DELETE FROM t WHERE id = $id");\n', 2),
    # control $f(...)
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); $f($c, "DELETE FROM t WHERE id = $id");\n', 2),
    # #[A] attribute on an arrow function, then an odd quote count
    ('<?php\nmysqli_query($c, "SELECT * FROM t WHERE id = " . (#[A] fn() => $_GET[\'id\'])() . " AND n = \'a\\\'b\'" .\n    1);\n', 2),
    # ->execute($sql) CakePHP
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); $conn->execute("DELETE FROM t WHERE id = $id");\n', 2),
    # ->select() Laravel conn
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); $conn->select("select * from t where id = $id");\n', 2),
    # ->fetchAllAssociative Doctrine
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); $conn->fetchAllAssociative("SELECT * FROM t WHERE id = $id");\n', 2),
    # ADOdb ->GetAll
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); $db->GetAll("SELECT * FROM t WHERE id = $id");\n', 2),
    # odbc_do
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); odbc_do($o, "SELECT * FROM t WHERE id = $id");\n', 2),
    # user wrapper run_sql
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); run_sql("SELECT * FROM t WHERE id = $id");\n', 2),
    # Yii createCommand()->execute()
    ('<?php\nmysqli_query($c, "SET NAMES utf8"); Yii::$app->db->createCommand("DELETE FROM t WHERE id = $id")->execute();\n', 2),
]

_CALL_SHAPE_NO_ADDITION = [
    # control quote() plain
    '<?php\nmysqli_query($c, "SET NAMES utf8"); $db->query("SELECT * FROM t WHERE a = " . $db->quote($x));\n',
    # control: an ASCII digit
    '<?php\nmysqli_query($c, "SELECT * FROM t WHERE a = " . 1);\n',
]


class TestPhpSqlInjectionCallShapes:
    """Calls of every shape next to a
    sanitised procedural call keep main's hit (monotonic), and as an
    operand of a proved method sink they keep the addition."""

    @pytest.mark.parametrize("source,line", _CALL_SHAPE_KEPT)
    def test_call_shape_kept(self, tmp_path, source, line):
        """Calls of every shape next to a sanitised call keep the hit."""
        assert line in _php_file_sql_lines(tmp_path, source), source

    @pytest.mark.parametrize("source", _CALL_SHAPE_NO_ADDITION)
    def test_call_shape_no_addition(self, tmp_path, source):
        """Allowlisted operands of a proved call add nothing."""
        assert _php_file_added_lines(tmp_path, source) == [], source

    def test_property_any_other_call_operand_keeps_the_addition(
        self, tmp_path,
    ):
        """Additions only: main never flags these method/static sinks, so
        every hit here comes from the PR's own proof (`_php_sql_proved`).
        Any non-allowlisted call used as an SQL operand of an otherwise
        proved call keeps the addition; allowlisted operands add nothing.
        With main's rule alone every case would fail."""
        import random

        rnd = random.Random(20261022)
        proved = [
            '$pdo->query("SELECT * FROM t WHERE id = " . intval($id)'
            ' . " AND x = " . {op})',
            '$db->exec("DELETE FROM t WHERE id = " . (int)$id'
            ' . " AND k = " . {op})',
            'DB::select("SELECT * FROM t WHERE p = " . floatval($p)'
            ' . " AND q = " . {op})',
        ]
        shapes = [
            '[$db, "query"]($s)', '"mysqli_query"($c, $s)', '($fn)($s)',
            '$h["k"]($s)', 'array_filter($a, "mysqli_query")',
            'usort($a, [$db, "query"])', 'Closure::fromCallable([$db, "q"])($s)',
            '$db->execute($s)', 'run_sql($s)', 'new Foo($s)',
            'match($s) { default => 1 }', 'isset($a[$s])', 'empty($s)',
            'fn($v) => $v', 'function () { return 1; }', '$o->m($s)',
            'Foo::bar($s)', 'trim($s)', '$f($s)', '$o->$m($s)',
            '$o->{"query"}($s)', '$$v($s)', 'call_user_func("q", $s)',
            '$pdo->query("SELECT 1")->fetch()', 'die(mysqli_error($c))',
            '$o->intval($s)', 'Foo::intval($s)',
            '$other->quote($s)', 'print($s)', 'sprintf("%d", $s)',
        ]
        safe = [
            "intval($v)", "(int)$v", "7", "DB_PREFIX", "self::T",
            "(int)$o->get($v)", "floatval($v)", "boolval($v)",
        ]
        rows: list[tuple[str, bool]] = []
        for _ in range(2400):
            op = rnd.choice(shapes)
            if rnd.random() < 0.3:  # the operand on a continuation line
                op = "\n    " + op
            rows.append((rnd.choice(proved).replace("{op}", op), True))
        for _ in range(400):
            rows.append((rnd.choice(proved).replace("{op}", rnd.choice(safe)),
                         False))
        rnd.shuffle(rows)
        body, expect = [], {}
        for text, keep in rows:
            expect[len(body) + 2] = keep
            body.extend(("  $r = " + text + ";").split("\n"))
        full = "\n".join(body)
        added = set(_php_sql_added_lines(tmp_path, full))
        assert not _php_sql_base_lines(_php_sql_template(full))
        src = ["", ""] + body
        lost = [ln for ln, k in expect.items() if k and ln not in added]
        over = [ln for ln, k in expect.items() if not k and ln in added]
        assert not lost, [src[ln] for ln in lost[:5]]
        assert not over, [src[ln] for ln in over[:5]]


_INTERP_SHADOW_KEPT = [
    # ${expr} interpolation holding a call (no `{$` in the body)
    ('<?php\nfunction f($c, $db, $id, $q) {\nmysqli_query($c, "SELECT a FROM t '
     'WHERE b = " . intval($id)); $o = "${a[$db->query($q)]}";\n}\n', 3),
    # double-quoted {$...} interpolation holding ->query()
    ('<?php\nfunction f($c, $db, $id, $q) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $o = "{$db->query("SELECT x FROM y WHERE z = \'$q\'")}";\n}\n', 3),
    # double-quoted ${expr} variable-variable holding ->query()
    ('<?php\nfunction f($c, $db, $id, $q) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $o = "${$db->query($q)}";\n}\n', 3),
    # double-quoted {$a[call()]} index holding ->query()
    ('<?php\nfunction f($c, $db, $id, $q) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $o = "{$a[$db->query($q)]}";\n}\n', 3),
    # backtick {$...} interpolation holding ->query()
    ('<?php\nfunction f($c, $db, $id, $q) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $o = `x {$db->query($q)}`;\n}\n', 3),
    # {$...} ->query() concatenated in the same statement
    ('<?php\nfunction f($c, $db, $id, $q) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)) . "{$db->query($q)}";\n}\n', 3),
    # procedural sink inside a double-quoted interpolation
    ('<?php\nfunction f($c, $db, $id, $q) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $o = "{$f(mysqli_query($c, $q))}";\n}\n', 3),
    # intval redeclared in a namespace
    ('<?php\nnamespace X;\nfunction intval($v) { return $v; }\nfunction f($c, $id) {\nmysqli_query($c, "SELECT * FROM t WHERE a = " . intval($id));\n}\n', 5),
    # new without parentheses
    ('<?php\nfunction f($c, $id, $q) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $o = new $q;\n}\n', 3),
    # method sink in a string interpolation
    ('<?php\nfunction f($c, $id, $q) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $o = "{$c->query($q)}";\n}\n', 3),
    # method sink in a heredoc interpolation
    ('<?php\nfunction f($c, $id, $q) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $o = <<<E\n{$c->query($q)}\nE;\n}\n', 3),
    # intval imported with use function
    ('<?php\nuse function Evil\\intval;\nfunction f($c, $id) {\nmysqli_query($c, "SELECT * FROM t WHERE a = " . intval($id));\n}\n', 4),
    # bad stmt tail shares line
    ('<?php\nfunction f($c, $db, $id, $q) {\n$r = run_sql($q,\n  1); mysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id));\n}\n', 4),
    # new intval class
    ('<?php\nfunction f($c, $db, $id, $q) {\n$o = new intval($q) . mysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id));\n}\n', 3),
]

_INTERP_SHADOW_NO_ADDITION = [
    # simple interpolation "$db->query" (a property read, no call)
    '<?php\nfunction f($c, $db, $id, $q) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $o = "$db->query";\n}\n',
]


class TestPhpSqlInjectionInterpolationAndShadowing:
    """Interpolation, shadowed helpers and
    `new`: the historical hit is kept (monotonic)."""

    @pytest.mark.parametrize("source,line", _INTERP_SHADOW_KEPT)
    def test_interp_shadow_kept(self, tmp_path, source, line):
        """Calls inside {$...} interpolation, `new`, and a source that
        shadows intval keep the hit."""
        assert line in _php_file_sql_lines(tmp_path, source), source

    @pytest.mark.parametrize("source", _INTERP_SHADOW_NO_ADDITION)
    def test_interp_shadow_no_addition(self, tmp_path, source):
        """Plain interpolation-free proved calls add nothing."""
        assert _php_file_added_lines(tmp_path, source) == [], source



_COMPLEX_INTERP_KEPT = [
    # the helper imported by a second `use function` statement
    ("<?php\nuse function A\\a;\nuse function B\\intval;\nmysqli_query($c, "
     "\"SELECT * FROM t WHERE a = \" . intval($id));\n", 4),
    ("<?php\nUSE FUNCTION X\\INTVAL;\nmysqli_query($c, "
     "\"SELECT * FROM t WHERE a = \" . intval($id));\n", 3),
    ("<?php\nuse function X\\floatval;\nmysqli_query($c, "
     "\"SELECT * FROM t WHERE p = \" . floatval($p));\n", 3),
    # complex interpolation next to a proved call
    ('<?php\n$x = "{$a["k"]}"; mysqli_query($c, "SELECT 1");\n', 2),
    # /* } */ comment inside {$...}, then a '"' array key
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = "{$a[/* } */ \'"\']}"; $db->query("SELECT * FROM t WHERE x = $q"); // \'\n$k = 1;\n}\n', 3),
    # # } comment inside {$...} (ended by a newline)
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = "{$a[# }\n\'"\']}"; $db->query("SELECT * FROM t WHERE x = $q"); // \'\n$k = 1;\n}\n', 3),
    # // } comment inside {$...}
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = "{$a[// }\n\'"\']}"; $db->query("SELECT * FROM t WHERE x = $q"); // \'\n$k = 1;\n}\n', 3),
    # /* " */ comment inside {$...}
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = "{$a[/* " */ 0]}"; $db->query("SELECT * FROM t WHERE x = $q"); $z = "}"; // "\n$k = 1;\n}\n', 3),
    # /* ' */ comment inside {$...}
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = "{$a[/* \' */ 0]}"; $db->query("SELECT * FROM t WHERE x = $q"); // \'\n$k = 1;\n}\n', 3),
    # heredoc {$...} holding a } comment and quotes
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = <<<EOT\n{$a[/* } */ \'"\']}\nEOT;\n$db->query("SELECT * FROM t WHERE x = $q"); // \'\n$k = 1;\n}\n', 3),
    # heredoc closing label inside an interpolation
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = <<<EOT\n{$a["\nEOT"]}\nEOT; $db->query("SELECT * FROM t WHERE x = $q"); $z = "\n";\n}\n', 3),
    # new inside a {$...} index
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = "{$a[new Q]}";\n}\n', 3),
    # intval redeclared with a comment before "("
    ('<?php\nnamespace X; function intval/**/($x) { return $x; }\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id));\n', 3),
    # intval redeclared with "(" on the next line
    ('<?php\nnamespace X; function intval\n($x) { return $x; }\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id));\n', 4),
    # intval imported by a grouped use function
    ('<?php\nuse function X\\{intval};\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id));\n', 3),
    # intval far down a long use function list
    ('<?php\nuse function A\\a, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\b, A\\intval;\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id));\n', 3),
    # NEW in upper case
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $o = NEW Q;\n}\n', 3),
    # boolval redeclared
    ('<?php\nnamespace X; function boolval($v) { return $v; }\nmysqli_query($c, "SELECT a FROM t WHERE b = " . boolval($id));\n', 3),
    # intval redeclared by reference (function &intval)
    ('<?php\nnamespace X; function &intval($v) { return $v; }\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id));\n', 3),
    # INTVAL redeclared in upper case
    ('<?php\nnamespace X; FUNCTION INTVAL($v) { return $v; }\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id));\n', 3),
    # NEW Q in upper case
    ('<?php\nfunction f($c, $id) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $o = NEW Q;\n}\n', 3),
    # {$...} call before a ${} interpolation
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = "{$db->query($q)} ${a}";\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = "txt v ${a[/* } */ \'"\']}"; $db->query("SELECT * FROM t WHERE x = $q"); $s = "{ } txt"; // \'\n$k = 1;\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = "{$a[# }\n\'"\'][0]} v {"; $db->query("SELECT * FROM t WHERE x = $q"); $s = <<<EOT\n${a[// }\n\'x\']} { }\nEOT; $s = <<<EOT\nw w\nEOT; // \'\n$k = 1;\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = "${a[/*}}*/ "\'"]}"; $db->query("SELECT * FROM t WHERE x = $q"); $s = "txt { }"; // \'\n$k = "";\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = "{$a[# }\n\'x\']} } {$a[/* } */ \'"\']}"; $s = "}"; $s = "${a[\'y\']} w"; $db->query("SELECT * FROM t WHERE x = $q"); # \'\n$k = "";\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = <<<EOT\nw v txt\nEOT; $s = "{$a[/* } */ \'"\'][0]}"; $db->query("SELECT * FROM t WHERE x = $q"); $s = "w txt"; // \'\n$k = \'\';\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = <<<EOT\nw\nEOT; $s = "{$a[// }\n\'"\']}"; $s = <<<EOT\n{\nEOT; $db->query("SELECT * FROM t WHERE x = $q"); // \'\n$k = "";\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = <<<EOT\n\'\nEOT; $s = "{$a[# }\n\'x\']} txt {$a[// }\n\'"\']}"; $db->query("SELECT * FROM t WHERE x = $q"); $s = "v"; // "\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = "w }"; $s = "txt {$a[/*}}*/ "\'"]} {"; $db->query("SELECT * FROM t WHERE x = $q"); // \'\n$k = \'\';\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = "} {"; $s = <<<EOT\n{$a[# }\n\'"\'][0]}\nEOT; $s = "{$a[// }\n\'"\']} { txt"; $db->query("SELECT * FROM t WHERE x = $q"); # \'\n$k = 1;\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = "v {$a[/*}}*/ "\'"]} {$a[// }\n\'x\']}"; $db->query("SELECT * FROM t WHERE x = $q"); $s = <<<EOT\n} { \'\nEOT; $s = <<<EOT\nw \' txt\nEOT; // \'\n$k = "";\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = "} w"; $s = "${a[// }\n\'"\']}"; $db->query("SELECT * FROM t WHERE x = $q"); # \'\n$k = 1;\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('<?php\nfunction f($c, $id, $db, $q, $a) {\nmysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id)); $s = <<<EOT\n\' v }\nEOT; $s = "{ w {$a[/* { */ \'x\']}"; $db->query("SELECT * FROM t WHERE x = $q"); $s = "w \' w"; // \'\n$k = \'\';\n}\n', 3),
]


class TestPhpSqlInjectionComplexInterpolation:
    """Comments in interpolation and shadowed
    helpers (PHP 7.4/8.3 run the hidden tainted query): the
    historical hit is kept (monotonic)."""

    @pytest.mark.parametrize("source,line", _COMPLEX_INTERP_KEPT)
    def test_complex_interp_kept(self, tmp_path, source, line):
        """Comments inside interpolation once desynced the lexer and hid a
        query PHP runs; main's hit must survive them."""
        assert line in _php_file_sql_lines(tmp_path, source), source


_ATTRIBUTE_KEPT = [
    # attr ml dq
    ('function f($c, $db, $q, $id) {\n  $g = #[A("\n")] fn() => 1; $db->query(\'SELECT * FROM t WHERE x = \' . $q); /* " */ mysqli_query($c, \'SELECT a FROM t WHERE b = \' . intval($id));\n}\n', 3),
    # attr ml sq
    ('function f($c, $db, $q, $id) {\n  $g = #[A(\'\n\')] fn() => 1; $db->query("SELECT * FROM t WHERE x = " . $q); /* \' */ mysqli_query($c, \'SELECT a FROM t WHERE b = \' . intval($id));\n}\n', 3),
    # 1-line attr ] in string
    ('function f($c, $db, $q, $id) {\n  $g = #[A("]", \'"\')] fn() => 1;\n  $db->query("SELECT * FROM t WHERE x = " . $q); /* \' */ mysqli_query($c, "SELECT a FROM t WHERE b = " . intval($id));\n}\n', 3),
    # intval shadow hidden by a PHP 7/8 attribute lexing difference (raw text only)
    ('namespace X;\nfunction f($c, $q) {\n  $g = #[A("\n")] fn() => 1; function intval($x) { return $x; } /* " */ mysqli_query($c, \'SELECT a FROM t WHERE b = \' . intval($q));\n}\n', 4),
    # generated mix: PHP 8.3 runs the tainted query
    ('function f($c, $db, $q, $id) {\n  #[A(\'\n \')] fn() => 1; $db->real_query("UPDATE t SET a = 1 WHERE b = " . $q); /*\'*/ mysqli_query($c, "SELECT a FROM t WHERE b = " . (int) $id);\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('function f($c, $db, $q, $id) {\n  $g = #[A(1, " \n")] static function () {}; $db->query(\'SELECT * FROM t WHERE x = \' . $q); /*"*/ mysqli_query($c, \'SELECT a FROM t WHERE b = \' . (int) $id);\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('function f($c, $db, $q, $id) {\n  $g = #[A(["\\n\n "])] function () { return 1; }; $db->query(\'SELECT * FROM t WHERE x = \' . $q); /*"*/ mysqli_query($c, \'SELECT a FROM t WHERE b = \' . intval($id));\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('function f($c, $db, $q, $id) {\n  #[A(1, "\\n\n ")] function () { return 1; }; $db->multi_query(\'SELECT 1 FROM t WHERE y = \' . $q); /* " */ mysqli_query($c, \'SELECT a FROM t WHERE b = \' . intval($id));\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('function f($c, $db, $q, $id) {\n  $g = #[A(x: "\n ")] fn() => 1; $db->exec(\'DELETE FROM t WHERE x = \' . $q); /** " */ mysqli_query($c, \'SELECT a FROM t WHERE b = \' . (int) $id);\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('function f($c, $db, $q, $id) {\n  #[A(["z\nk"])] static function () {}; $db->exec(\'DELETE FROM t WHERE x = \' . $q); /*"*/ mysqli_query($c, \'SELECT a FROM t WHERE b = \' . (int) $id);\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('function f($c, $db, $q, $id) {\n  #[A(1, "\\n\nk")] fn() => 1; $db->real_query(\'UPDATE t SET a = 1 WHERE b = \' . $q); /* " */ mysqli_query($c, \'SELECT a FROM t WHERE b = \' . (int) $id);\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('function f($c, $db, $q, $id) {\n  $g = [#[\\N\\A("\\n\n ")] static function () {}]; $db->query(\'SELECT * FROM t WHERE x = \' . $q); /*"*/ mysqli_query($c, \'SELECT a FROM t WHERE b = \' . intval($id));\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('function f($c, $db, $q, $id) {\n  $g = #[A(["\\n\nk"])] function () { return 1; }; $db->exec(\'DELETE FROM t WHERE x = \' . $q); /** " */ mysqli_query($c, \'SELECT a FROM t WHERE b = \' . intval($id));\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('function f($c, $db, $q, $id) {\n  $g = [#[A(1, " \nk")] function () { return 1; }]; $db->real_query(\'UPDATE t SET a = 1 WHERE b = \' . $q); /** " */ mysqli_query($c, \'SELECT a FROM t WHERE b = \' . (int) $id);\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('function f($c, $db, $q, $id) {\n  #[A, B(\'\n \')] static fn() => 1; $db->exec("DELETE FROM t WHERE x = " . $q); /** \' */ mysqli_query($c, "SELECT a FROM t WHERE b = " . (int) $id);\n}\n', 3),
    # generated mix: PHP 8.3 runs the tainted query
    ('function f($c, $db, $q, $id) {\n  #[A(1, "z\n ")] static fn() => 1; $db->query(\'SELECT * FROM t WHERE x = \' . $q); /** " */ mysqli_query($c, \'SELECT a FROM t WHERE b = \' . (int) $id);\n}\n', 3),
]


class TestPhpSqlInjectionMonotonic:
    """Every hit of the historical rule (pre-change main) is kept; the
    proofs only filter the rule's ADDITIONAL (method/static and other
    executor) hits.  Every helper call above also asserts the superset."""

    _CORPORA = [
        ("call-shapes", [s for s, _l in _CALL_SHAPE_KEPT] + list(_CALL_SHAPE_NO_ADDITION)),
        ("interp-shadow", [s for s, _l in _INTERP_SHADOW_KEPT] + list(_INTERP_SHADOW_NO_ADDITION)),
        ("complex-interp", [s for s, _l in _COMPLEX_INTERP_KEPT]),
        ("attribute", [s for s, _l in _ATTRIBUTE_KEPT]),
    ]

    @pytest.mark.parametrize("name,sources", _CORPORA)
    def test_corpora_superset_of_base(self, tmp_path, name, sources):
        """Every hit main reports on these corpora is still reported."""
        for source in sources:
            hits = set(_php_file_sql_lines(tmp_path, source))
            assert set(_php_sql_base_lines(source)) <= hits, (name, source)

    @pytest.mark.parametrize("source,line", _ATTRIBUTE_KEPT)
    def test_attribute_kept(self, tmp_path, source, line):
        """A PHP 8 #[...] attribute with an unbalanced quote must not hide
        main's hit on the same line."""
        assert line in _php_file_sql_lines(tmp_path, source), source

    def test_property_random_mixes_never_lose_a_base_hit(self, tmp_path):
        """Random concatenations of corpus pieces never lose a hit main
        reports."""
        import random

        rnd = random.Random(20261023)
        pieces = []
        for _name, sources in self._CORPORA:
            for source in sources:
                pieces.extend(
                    ln for ln in source.splitlines()
                    if ln.strip() and not ln.startswith(("<?php", "function"))
                    and ln.strip() != "}"
                )
        pieces += [
            'mysqli_query($c, "SELECT * FROM t WHERE id = " . intval($id));',
            'pg_query($c, "SELECT " . $id);', "$s = $db->prepare($q);",
            '$s = "{$a["}"]}";', "# it's", "/* open", "?>x<?php", "' ", '" ',
            "#[A(\"", "$h = <<<E", "E;", "$x = `ls`;", "} {",
        ]
        for _ in range(300):
            body = "\n".join(rnd.choice(pieces)
                             for _ in range(rnd.randint(1, 8)))
            source = "<?php\nfunction f($c, $db, $id, $q, $a) {\n" + body + "\n}\n"
            _php_file_sql_lines(tmp_path, source)  # asserts the superset

    @pytest.mark.parametrize("source", [
        # method-sink injections the historical rule misses
        '<?php\n$r = $pdo->query("SELECT * FROM t WHERE id = " . $id);\n',
        '<?php\n$r = $db->exec("DELETE FROM t WHERE id = $id");\n',
        '<?php\n$r = DB::select("SELECT * FROM t WHERE id = $id");\n',
        '<?php\n$r = $m->real_query("SELECT * FROM t WHERE n = \'$n\'");\n',
        '<?php\n$r = $pdo->query("SELECT * FROM t WHERE id = " . intval($a) '
        '. " AND n = " . $n);\n',
    ])
    def test_known_method_sink_injections_fire(self, tmp_path, source):
        """Known-vulnerable method-sink shapes are additions."""
        assert 2 in _php_file_sql_lines(tmp_path, source), source

    @pytest.mark.parametrize("source", [
        # sanitised method sinks: the addition is filtered as an FP
        '<?php\n$r = $pdo->query("SELECT * FROM t WHERE id = " . intval($id));\n',
        '<?php\n$r = $pdo->query("SELECT * FROM t WHERE id = " . (int)$id);\n',
        '<?php\n$r = $pdo->query("SELECT * FROM t WHERE p = " . floatval($p));\n',
        '<?php\n$r = $pdo->query("SELECT * FROM t WHERE n = " . $pdo->quote($n));\n',
        '<?php\n$r = DB::select("SELECT * FROM t WHERE id = ?", [$id]);\n',
    ])
    def test_sanitised_method_sinks_add_nothing(self, tmp_path, source):
        """Their sanitised twins add nothing."""
        assert _php_file_added_lines(tmp_path, source) == [], source



_FILTER_KEPT = [
    # shell output is not a safe operand
    ("function f($db) {\n  $db->query('SELECT * FROM t WHERE n = ' "
     ". `cat /tmp/x`);\n}\n", 2),
    # cast then ternary: `.` binds tighter, the ternary yields $b
    ('function f($c, $db, $pdo, $a, $b, $q, $n) {\n  $db->query(\'SELECT * '
     'FROM t WHERE id = \' . (int)$a ? $b : \'x\');\n}\n', 2),
    # a cast whose expression may itself execute SQL proves nothing
    ('function f($db, $q) {\n  $db->query("SELECT * FROM t WHERE id = " '
     '. (int)$db->query("SELECT c FROM u WHERE d = \'$q\'")->fetchColumn());'
     '\n}\n', 2),
    ('function f($db, $q) {\n  $db->query("SELECT * FROM t WHERE id = " '
     '. (int)$db->Prepare("SELECT 1")->execute([$q]));\n}\n', 2),
    ('function f($db, $f, $q) {\n  $db->query("SELECT * FROM t WHERE id = " '
     '. (int)$o->get($f($q)));\n}\n', 2),
    ('function f($db, $cb, $q) {\n  $db->query("SELECT * FROM t WHERE id = " '
     '. (int)call_user_func($cb, $q));\n}\n', 2),
    ('function f($db, $q) {\n  $db->query("SELECT * FROM t WHERE id = " '
     '. (int)(new Repo($q))->count());\n}\n', 2),
    ('function f($db, $o, $b) {\n  $db->query("SELECT * FROM t WHERE id = " '
     '. (int)$o->get() ? $b : 1);\n}\n', 2),
    ('function f($db, $o, $q) {\n  $db->query("SELECT * FROM t WHERE id = " '
     '. (int)$o->get()($q));\n}\n', 2),
    # tainted operand beside a constant (true positive)
    ('function f($c, $db, $id, $ids, $q) {\n  $db->query("SELECT * FROM `" . DB_PREFIX . "api` WHERE `api_id` = \'" . $id . "\'");\n}\n', 2),
    # quote() on a different (Unicode-named) receiver than the sink
    ('function f($c, $db, $pdo, $mysqli, $id, $name, $n, $a, $b) {\n  $İİİ->b->q->query("SELECT * FROM t WHERE n = " . $İİİ->b->quote($n));\n}\n', 2),
    # intval redefined as a user function
    ('function intval($x) { return $x; }\nfunction f($c, $db, $pdo, $mysqli, $id, $name, $n, $a, $b) {\n  $db->query("SELECT * FROM t WHERE id = " . intval($id));\n}\n', 3),
    # dotless-i ıntval is a user function, not intval
    ('function ıntval($x) { return $x; }\nfunction f($c, $db, $pdo, $mysqli, $id, $name, $n, $a, $b) {\n  $db->query("SELECT * FROM t WHERE id = " . ıntval($id));\n}\n', 3),
    # intval redefined in a namespace
    ('namespace App;\nfunction intval($x) { return $x; }\nfunction f($db, $id) {\n  $db->query("SELECT * FROM t WHERE id = " . intval($id));\n}\n', 4),
    # intval imported with use function
    ('namespace App;\nuse function Lib\\intval;\nfunction f($db, $id) {\n  $db->query("SELECT * FROM t WHERE id = " . intval($id));\n}\n', 4),
    # dotless-i ıntval
    ('function ıntval($x) { return $x; }\nfunction f($db, $id) {\n  $db->query("SELECT * FROM t WHERE id = " . ıntval($id));\n}\n', 3),
    # nested tainted method sink in intval of a method sink
    ('function f($c, $db, $pdo, $a, $b, $q, $n) {\n  $db->query(\'SELECT a FROM t WHERE b = \' . intval($db->query("SELECT c FROM u WHERE d = \'$q\'")->fetchColumn()));\n}\n', 2),
    # nested procedural sink in a guarded function
    ('function f($c, $db, $pdo, $a, $b, $q, $n) {\n  $s = $db->prepare(\'SELECT 1\');\n  mysqli_query($c, \'SELECT a FROM t WHERE b = \' . intval(mysqli_real_query($c, "SELECT c FROM u WHERE d = \'$q\'")));\n}\n', 3),
    # variable on the continuation line
    ('function f($c, $db, $pdo, $a, $b, $q, $n) {\n  mysqli_real_query(\n    $c, "SELECT * FROM t WHERE id = $q");\n}\n', 2),
    # backslash-spelled quote before quote()
    ('function f($c, $db, $pdo, $a, $b, $q, $n) {\n  $pdo->query("SELECT * FROM t WHERE n = \\x27" . $pdo->quote($n) . "\\x27");\n}\n', 2),
]

_FILTER_NO_ADDITION = [
    # a cast of a method call is numeric
    ("function f($db, $id) {\n  $db->query(\"SELECT * FROM `\" . DB_PREFIX . "
     "\"order_status` WHERE `order_status_id` = '\" . (int)$id . \"' AND "
     "`language_id` = '\" . (int)$this->config->get('config_language_id') "
     ". \"'\");\n}\n"),
    ('function f($db, $o, $x) {\n  $db->query("SELECT * FROM t WHERE id = " '
     '. (int)$o->get($x ? 1 : 2) . " LIMIT " . (int)count($x));\n}\n'),
    # a cast of a parenthesised call-free expression
    'function f($db, $a, $b) {\n  $db->query("SELECT * FROM t WHERE id = " '
    '. (int)($a + $b));\n}\n',
    # DB_PREFIX constant with an (int) cast
    'function f($c, $db, $id, $ids, $q) {\n  $db->query("SELECT * FROM `" . DB_PREFIX . "api` WHERE `api_id` = \'" . (int)$id . "\'");\n}\n',
    # MAIN_DB_PREFIX constant with a parenthesised (int) cast
    'function f($c, $db, $id, $ids, $q) {\n  $db->query("UPDATE ".MAIN_DB_PREFIX."blockedlog SET certified = 1 WHERE rowid = ".((int) $id));\n}\n',
    # self::TABLE constant with intval()
    'function f($c, $db, $id, $ids, $q) {\n  $db->query("SELECT * FROM " . self::TABLE . " WHERE id = " . intval($id));\n}\n',
    # DB_PREFIX constant with a (bool) cast
    'function f($c, $db, $id, $ids, $q) {\n  $db->query("UPDATE `" . DB_PREFIX . "x` SET `status` = \'" . (bool)$id . "\' WHERE `x_id` = \'" . (int)$id . "\'");\n}\n',
    # (int) cast with no constant
    'function f($c, $db, $id, $ids, $q) {\n  $db->query("SELECT * FROM `oc_api` WHERE `api_id` = \'" . (int)$id . "\'");\n}\n',
    # pg_query_params elsewhere silences main; proved call adds nothing
    "function f($c, $db, $pdo, $a, $b, $q, $n) {\n  pg_query_params($c, 'SELECT 1 WHERE a = $1', [$a]);\n  mysqli_query($c, 'SELECT * FROM t WHERE id = ' . intval($q));\n}\n",
    # long-s myſql_query is another function
    'function f($c, $db, $pdo, $a, $b, $q, $n) {\n  myſql_query($c, "SELECT * FROM t WHERE id = " . $q);\n}\n',
]


class TestPhpSqlInjectionAdditionsFilter:
    """The additions' false-positive filter: named
    constants and call-free numeric casts are safe operands (OpenCart
    `DB_PREFIX` + `(int)`); nested sinks, continuation-line variables,
    backslash-spelled quotes, cast-then-ternary, shadowed or look-alike
    helpers and Unicode receivers never prove."""

    @pytest.mark.parametrize("source,line", _FILTER_KEPT)
    def test_filter_kept(self, tmp_path, source, line):
        """Nested sinks, continuation-line variables, cast-then-ternary,
        shadowed or look-alike helpers and Unicode names never prove."""
        assert line in _php_file_sql_lines(tmp_path, source), source

    @pytest.mark.parametrize("source", _FILTER_NO_ADDITION)
    def test_filter_no_addition(self, tmp_path, source):
        """Named constants and call-free numeric casts are safe operands
        (OpenCart DB_PREFIX + (int)), so these add no hit."""
        assert _php_file_sql_lines(tmp_path, source) == [], source



_FALSE_NEGATIVE_GUARDS = [
    # a `use function` whose comment holds `;`: read on the code view
    ('<?php\nfunction f($c, $db, $pdo, $id, $name, $a, $b, $m) {\n  use function /* ; */ My\\intval;\n  $db->query("SELECT * FROM t WHERE id = " . intval($id));\n}\n', 4),
    # `(int)$a | $name`: a string bitwise OR copies $name's tail
    ('<?php\nfunction f($c, $db, $pdo, $id, $name, $a, $b, $m) {\n  $db->query("SELECT * FROM t WHERE id = " . (int)$a | $name);\n}\n', 3),
    # a constant prefix is not a constant: GETID(...) is a call
    ('<?php\nfunction f($c, $db, $pdo, $id, $name, $a, $b, $m) {\n  $db->query("SELECT * FROM t WHERE id = " . GETID($_GET["x"]) . (int)$a);\n}\n', 3),
    # constant then `?:` takes the whole SQL
    ('<?php\nfunction f($c, $db, $pdo, $id, $name, $a, $b, $m) {\n  $db->query("SELECT * FROM t WHERE id = " . X ?: $name);\n}\n', 3),
    # shadowed intval inside a parenthesised term
    ('<?php\nfunction intval($x) { return $x; }\nfunction f($db, $id) {\n  $db->query("SELECT * FROM t WHERE id = " . (intval($id)));\n}\n', 4),
    # shadowed intval inside a parenthesised term (same source)
    ('<?php\nfunction intval($x) { return $x; }\nfunction f($c, $db, $pdo, $id, $name, $a, $b, $m) {\n  $db->query("SELECT * FROM t WHERE id = " . (intval($id)));\n}\n', 4),
    # shadowed intval in a procedural sink
    ('<?php\nfunction intval($x) { return $x; }\nfunction f($c, $db, $pdo, $id, $name, $a, $b, $m) {\n  mysqli_real_query($c, "SELECT * FROM t WHERE id = " . intval($id));\n}\n', 4),
]


class TestPhpSqlInjectionFalseNegativeGuards:
    """Lines the additions must keep: each case fails if the matching
    check of the additions' filter is weakened."""

    @pytest.mark.parametrize("source,line", _FALSE_NEGATIVE_GUARDS)
    def test_false_negative_guard_kept(self, tmp_path, source, line):
        """The line stays flagged; it is lost if the matching filter check
        is weakened."""
        assert line in _php_file_sql_lines(tmp_path, source), source


class TestPhpSqlInjectionFailSafe:
    """An exception in the additions (lexer, statement walk, proofs) costs
    nothing but the additions: main's lines and every other PHP rule's hits
    are still reported, and the failure is counted and logged once."""

    # these tests make the additions raise on purpose
    _ADDITIONS_MAY_RAISE = True

    _SRC = (
        '<?php\nfunction f($c, $db, $id, $cmd, $x) {\n'
        '  mysql_query("SELECT * FROM t WHERE id = $id");\n'
        '  $db->query("SELECT * FROM t WHERE id = $id");\n'
        '  $db->query("DELETE FROM t WHERE id = $id");\n'
        '  system($cmd);\n'
        '  eval($x);\n'
        '}\n'
    )

    @staticmethod
    def _run(tmp_path, source, line_start=1):
        result = run_prefilter(
            target_path=tmp_path, file_path="app.php", function_name="f",
            source=source, line_start=line_start,
        )
        return sorted((h.rule_id, h.line) for h in result.hits)

    @staticmethod
    def _raise(exc):
        def boom(*_a, **_k):
            raise exc
        return boom

    @pytest.fixture(autouse=True)
    def _fresh_state(self, monkeypatch):
        monkeypatch.setattr(_prefilter, "_php_sql_additions_warned", False)

    def test_lexer_error_keeps_main_and_other_rules(self, tmp_path,
                                                    monkeypatch):
        """Without the fail-safe the exception left run_prefilter and every
        hit of the function was lost."""
        assert self._run(tmp_path, self._SRC) == [
            ("php-command-exec", 6), ("php-eval-variable", 7),
            ("php-sql-injection", 3), ("php-sql-injection", 4),
            ("php-sql-injection", 5),
        ]
        monkeypatch.setattr(_prefilter, "_php_sql_lex",
                            self._raise(RuntimeError("injected")))
        assert self._run(tmp_path, self._SRC) == [
            ("php-command-exec", 6), ("php-eval-variable", 7),
            ("php-sql-injection", 3),
        ]

    def test_error_after_an_addition_returns_main_exactly(self, tmp_path,
                                                          monkeypatch):
        """Line 4's addition is accumulated before line 5's sink raises; the
        partial additions are dropped and main's result is returned."""
        real = _prefilter._php_sql_receiver
        calls = []

        def second_call_raises(*args, **kwargs):
            calls.append(args)
            if len(calls) == 2:
                raise RecursionError("injected")
            return real(*args, **kwargs)

        monkeypatch.setattr(_prefilter, "_php_sql_receiver",
                            second_call_raises)
        lines = [ln for rule, ln in self._run(tmp_path, self._SRC)
                 if rule == "php-sql-injection"]
        assert len(calls) == 2
        assert lines == _php_sql_base_lines(self._SRC) == [3]

    def test_non_default_line_start(self, tmp_path, monkeypatch):
        """With line_start=40, a failure keeps main's line and the other
        rules' hits at their shifted lines."""
        monkeypatch.setattr(_prefilter, "_php_sql_lex",
                            self._raise(ValueError("injected")))
        assert self._run(tmp_path, self._SRC, line_start=40) == [
            ("php-command-exec", 45), ("php-eval-variable", 46),
            ("php-sql-injection", 42),
        ]

    def test_base_guard_present(self, tmp_path, monkeypatch):
        """main's guard silences its own hit; the addition is lost with the
        exception and nothing else changes."""
        source = (
            '<?php\nfunction f($c, $pdo, $id) {\n'
            '  $s = $pdo->prepare("SELECT 1");\n'
            '  mysqli_query($c, "SELECT * FROM t WHERE id = $id");\n'
            '}\n'
        )
        assert self._run(tmp_path, source) == [("php-sql-injection", 4)]
        monkeypatch.setattr(_prefilter, "_php_sql_lex",
                            self._raise(RuntimeError("injected")))
        assert self._run(tmp_path, source) == []

    def test_failures_counted_and_warned_once_without_source(
        self, tmp_path, monkeypatch, caplog,
    ):
        """Two failures are both counted, warned once, and no record holds
        source text."""
        monkeypatch.setattr(_prefilter, "_php_sql_lex",
                            self._raise(RuntimeError("injected")))
        before = _prefilter.php_sql_additions_failure_count()
        marker = "SECRET_MARKER_7f3a"
        source = self._SRC.replace("t WHERE", marker + " WHERE")
        with caplog.at_level("WARNING", logger="core.audit.prefilter"):
            self._run(tmp_path, source)
            self._run(tmp_path, source)
        assert _prefilter.php_sql_additions_failure_count() == before + 2
        warnings = [r for r in caplog.records
                    if r.levelname == "WARNING"
                    and "php-sql-injection" in r.getMessage()]
        assert len(warnings) == 1
        assert all(marker not in r.getMessage() for r in caplog.records)

    def test_main_rule_is_outside_the_fail_safe(self, tmp_path,
                                                monkeypatch):
        """Only the additions are contained: an error in main's own rule is
        not turned into an empty result."""
        monkeypatch.setattr(_prefilter, "_php_sql_main_rule_lines",
                            self._raise(RuntimeError("injected")))
        before = _prefilter.php_sql_additions_failure_count()
        with pytest.raises(RuntimeError):
            self._run(tmp_path, self._SRC)
        assert _prefilter.php_sql_additions_failure_count() == before

    @pytest.mark.parametrize("exc", [KeyboardInterrupt, SystemExit])
    def test_interrupts_propagate(self, tmp_path, monkeypatch, caplog, exc):
        """KeyboardInterrupt and SystemExit from the additions propagate as
        the same object, uncounted and with no warning."""
        raised = exc()
        monkeypatch.setattr(_prefilter, "_php_sql_lex", self._raise(raised))
        before = _prefilter.php_sql_additions_failure_count()
        with caplog.at_level("DEBUG", logger="core.audit.prefilter"):
            with pytest.raises(exc) as info:
                self._run(tmp_path, self._SRC)
        assert info.value is raised
        assert _prefilter.php_sql_additions_failure_count() == before
        assert not [r for r in caplog.records
                    if r.name == "core.audit.prefilter"
                    and r.levelno >= logging.WARNING]

    # Each exception is constructed the way the runtime raises it.
    _CONTAINED = [
        RuntimeError("injected"), ValueError("injected"),
        RecursionError("injected"), IndexError("injected"),
        TypeError("injected"), KeyError("injected"),
        AttributeError("injected"),
        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
        re.error("injected"), MemoryError(), ZeroDivisionError("injected"),
    ]

    @pytest.mark.parametrize("exc", _CONTAINED,
                             ids=[type(e).__name__ for e in _CONTAINED])
    def test_every_ordinary_exception_is_contained(self, monkeypatch, exc):
        """Any Exception from the additions returns main's lines exactly
        and is counted once; a narrower catch, or re-raising one kind
        (MemoryError included), loses main's hits."""
        monkeypatch.setattr(_prefilter, "_php_sql_additions",
                            self._raise(exc))
        main = _prefilter._php_sql_main_rule_lines(self._SRC, 1)
        assert main == {3}
        before = _prefilter.php_sql_additions_failure_count()
        assert _prefilter._php_sql_injection_lines(self._SRC, 1) == main
        assert _prefilter.php_sql_additions_failure_count() == before + 1

    def test_success_is_not_counted(self):
        """A clean run with additions beyond main returns their union and
        leaves the failure count alone."""
        main = _prefilter._php_sql_main_rule_lines(self._SRC, 1)
        added = _prefilter._php_sql_additions(self._SRC, 1)
        assert added - main == {4, 5}
        before = _prefilter.php_sql_additions_failure_count()
        assert _prefilter._php_sql_injection_lines(self._SRC, 1) == {3, 4, 5}
        assert _prefilter.php_sql_additions_failure_count() == before

    def test_success_with_no_additions_is_not_counted(self, monkeypatch):
        """A successful run that adds nothing does not touch the failure
        count."""
        before = _prefilter.php_sql_additions_failure_count()
        assert _prefilter._php_sql_injection_lines(
            "function f() {\n  return 1;\n}", 1) == set()
        monkeypatch.setattr(_prefilter, "_php_sql_additions",
                            lambda _source, _line_start: set())
        assert _prefilter._php_sql_injection_lines(self._SRC, 1) == {3}
        assert _prefilter.php_sql_additions_failure_count() == before

    @staticmethod
    def _prefilter_records(caplog, level):
        return [r for r in caplog.records
                if r.name == "core.audit.prefilter" and r.levelno == level]

    def test_warning_names_the_type_not_the_message(self, monkeypatch,
                                                    caplog):
        """The one warning carries the exception type only: its message can
        hold source text.  Later failures are still counted."""
        marker = "SECRET_MARKER_9c1e"
        monkeypatch.setattr(
            _prefilter, "_php_sql_additions",
            self._raise(RuntimeError(marker + " $id = 'x'")),
        )
        before = _prefilter.php_sql_additions_failure_count()
        with caplog.at_level("DEBUG", logger="core.audit.prefilter"):
            for _ in range(3):
                assert _prefilter._php_sql_injection_lines(
                    self._SRC, 1) == {3}
        assert _prefilter.php_sql_additions_failure_count() == before + 3
        warnings = [r.getMessage() for r in
                    self._prefilter_records(caplog, logging.WARNING)]
        assert len(warnings) == 1
        assert "RuntimeError" in warnings[0]
        assert marker not in warnings[0]

    def test_each_failure_leaves_a_debug_traceback_without_source(
        self, monkeypatch, caplog,
    ):
        """Every failure leaves one DEBUG record with the traceback and no
        source text."""
        marker = "SECRET_MARKER_4b2d"
        source = self._SRC.replace("t WHERE", marker + " WHERE")
        monkeypatch.setattr(_prefilter, "_php_sql_additions",
                            self._raise(IndexError("injected")))
        with caplog.at_level("DEBUG", logger="core.audit.prefilter"):
            _prefilter._php_sql_injection_lines(source, 1)
            _prefilter._php_sql_injection_lines(source, 1)
        debug = self._prefilter_records(caplog, logging.DEBUG)
        assert [r.exc_info[0] if r.exc_info else None for r in debug] == [
            IndexError, IndexError]
        assert all(marker not in r.getMessage() for r in caplog.records)

    def test_failure_is_counted_under_the_lock(self, monkeypatch):
        """Concurrent scans update the count and the warned flag under the
        module lock, so no failure is lost."""
        seen = []

        class RecordingLock:
            def __enter__(self):
                seen.append(("enter",
                             _prefilter.php_sql_additions_failure_count()))

            def __exit__(self, *_exc):
                seen.append(("exit",
                             _prefilter.php_sql_additions_failure_count()))
                return False

        monkeypatch.setattr(_prefilter, "_php_sql_additions_lock",
                            RecordingLock())
        monkeypatch.setattr(_prefilter, "_php_sql_additions",
                            self._raise(RuntimeError("injected")))
        before = _prefilter.php_sql_additions_failure_count()
        assert _prefilter._php_sql_injection_lines(self._SRC, 1) == {3}
        assert seen == [("enter", before), ("exit", before + 1)]

    def test_accounting_failure_is_not_hidden(self, monkeypatch):
        """Only the logging is best-effort: an error while counting
        surfaces instead of silently leaving the count wrong."""
        class BrokenLock:
            def __enter__(self):
                raise RuntimeError("lock")

            def __exit__(self, *_exc):
                return False

        monkeypatch.setattr(_prefilter, "_php_sql_additions_lock",
                            BrokenLock())
        monkeypatch.setattr(_prefilter, "_php_sql_additions",
                            self._raise(IndexError("injected")))
        with pytest.raises(RuntimeError, match="lock"):
            _prefilter._php_sql_injection_lines(self._SRC, 1)

    # Ordinary exceptions a logging call can raise, constructed validly.
    _LOGGING_ERRORS = [
        RecursionError("while logging"), MemoryError(),
        RuntimeError("while logging"), ValueError("while logging"),
        OSError("while logging"),
        UnicodeEncodeError("ascii", "\xe9", 0, 1, "ordinal not in range"),
    ]

    class _Recorder:
        """Stands in for logger.warning or logger.debug: records each call
        and raises the next queued exception (None: return normally)."""

        def __init__(self, *raises):
            self.calls = []
            self.raises = list(raises)

        def __call__(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            if self.raises:
                exc = self.raises.pop(0)
                if exc is not None:
                    raise exc

    def _fail_additions(self, monkeypatch, exc=None):
        monkeypatch.setattr(
            _prefilter, "_php_sql_additions",
            self._raise(exc if exc is not None else IndexError("injected")),
        )

    def _log_with(self, monkeypatch, warning, debug):
        monkeypatch.setattr(_prefilter.logger, "warning", warning)
        monkeypatch.setattr(_prefilter.logger, "debug", debug)

    @pytest.mark.parametrize("failing", ["warning", "debug", "both"])
    @pytest.mark.parametrize("error", _LOGGING_ERRORS,
                             ids=[type(e).__name__ for e in _LOGGING_ERRORS])
    def test_logging_failure_keeps_main_and_the_count(self, monkeypatch,
                                                      failing, error):
        """Either logging call, or both, raising an ordinary exception
        (e.g. RecursionError near the stack limit) returns main's lines,
        counts the failure once, and a failing warning does not skip the
        debug traceback."""
        warning = self._Recorder(None if failing == "debug" else error)
        debug = self._Recorder(None if failing == "warning" else error)
        self._log_with(monkeypatch, warning, debug)
        self._fail_additions(monkeypatch)
        before = _prefilter.php_sql_additions_failure_count()
        assert _prefilter._php_sql_injection_lines(self._SRC, 1) == {3}
        assert (len(warning.calls), len(debug.calls)) == (1, 1)
        assert _prefilter.php_sql_additions_failure_count() == before + 1

    @pytest.mark.parametrize("call", ["warning", "debug"])
    @pytest.mark.parametrize("kind", [KeyboardInterrupt, SystemExit])
    def test_interrupt_while_logging_propagates(self, monkeypatch, call,
                                                kind):
        """An interrupt from either logging call propagates unchanged and
        the failure is still counted.  From the warning it releases the
        reservation; from the debug call (warning given) it does not."""
        raised = kind()
        warning = self._Recorder(raised if call == "warning" else None)
        debug = self._Recorder(raised if call == "debug" else None)
        self._log_with(monkeypatch, warning, debug)
        self._fail_additions(monkeypatch)
        before = _prefilter.php_sql_additions_failure_count()
        with pytest.raises(kind) as info:
            _prefilter._php_sql_injection_lines(self._SRC, 1)
        assert info.value is raised
        assert _prefilter.php_sql_additions_failure_count() == before + 1
        assert _prefilter._php_sql_additions_warned is (call == "debug")

    def test_warning_given_once_then_debug_only(self, monkeypatch):
        """After a warning that returns, later failures log DEBUG only and
        stay counted."""
        warning, debug = self._Recorder(), self._Recorder()
        self._log_with(monkeypatch, warning, debug)
        self._fail_additions(monkeypatch)
        before = _prefilter.php_sql_additions_failure_count()
        for _ in range(2):
            assert _prefilter._php_sql_injection_lines(self._SRC, 1) == {3}
        assert (len(warning.calls), len(debug.calls)) == (1, 2)
        assert _prefilter.php_sql_additions_failure_count() == before + 2
        assert _prefilter._php_sql_additions_warned is True

    def test_failed_warning_is_retried_until_one_returns(self, monkeypatch):
        """The first warning raises, the next failure's warning returns,
        and a third failure gives none."""
        warning = self._Recorder(RuntimeError("while logging"), None)
        debug = self._Recorder()
        self._log_with(monkeypatch, warning, debug)
        self._fail_additions(monkeypatch)
        before = _prefilter.php_sql_additions_failure_count()
        for _ in range(3):
            assert _prefilter._php_sql_injection_lines(self._SRC, 1) == {3}
        assert (len(warning.calls), len(debug.calls)) == (2, 3)
        assert _prefilter.php_sql_additions_failure_count() == before + 3
        assert _prefilter._php_sql_additions_warned is True

    def test_debug_failure_keeps_the_warning_given(self, monkeypatch):
        """A raising DEBUG call does not release the warning already given."""
        warning = self._Recorder()
        debug = self._Recorder(RuntimeError("while logging"),
                               RuntimeError("while logging"))
        self._log_with(monkeypatch, warning, debug)
        self._fail_additions(monkeypatch)
        for _ in range(2):
            assert _prefilter._php_sql_injection_lines(self._SRC, 1) == {3}
        assert (len(warning.calls), len(debug.calls)) == (1, 2)
        assert _prefilter._php_sql_additions_warned is True

    def test_debug_traceback_is_the_additions_exception(self, monkeypatch,
                                                        caplog):
        """With the warning raising, the debug record still carries the
        additions' own exception, not the logging one."""
        original = IndexError("injected")
        self._fail_additions(monkeypatch, original)
        monkeypatch.setattr(_prefilter.logger, "warning",
                            self._Recorder(RuntimeError("while logging")))
        with caplog.at_level("DEBUG", logger="core.audit.prefilter"):
            assert _prefilter._php_sql_injection_lines(self._SRC, 1) == {3}
        debug = self._prefilter_records(caplog, logging.DEBUG)
        assert len(debug) == 1
        assert debug[0].exc_info[1] is original

    def test_concurrent_failure_skips_a_pending_warning(self, monkeypatch):
        """While one failure's warning is in progress, another failure
        neither warns nor releases; the first, when its warning raises,
        releases the reservation.  Both failures are counted."""
        import threading

        started, go = threading.Event(), threading.Event()
        warned_by = []

        def slow_failing_warning(*_a, **_k):
            warned_by.append(threading.current_thread().name)
            started.set()
            go.wait(10)
            raise RuntimeError("while logging")

        self._log_with(monkeypatch, slow_failing_warning, self._Recorder())
        self._fail_additions(monkeypatch)
        before = _prefilter.php_sql_additions_failure_count()
        results = {}

        def first():
            results["first"] = _prefilter._php_sql_injection_lines(
                self._SRC, 1)

        thread = threading.Thread(target=first, name="reserving")
        thread.start()
        try:
            assert started.wait(10)
            results["second"] = _prefilter._php_sql_injection_lines(
                self._SRC, 1)
            assert _prefilter._php_sql_additions_warned is True
        finally:
            go.set()
            thread.join(10)
        assert not thread.is_alive()
        assert results == {"first": {3}, "second": {3}}
        assert warned_by == ["reserving"]
        assert _prefilter.php_sql_additions_failure_count() == before + 2
        assert _prefilter._php_sql_additions_warned is False

    def test_reservation_is_released_under_the_lock(self, monkeypatch):
        """A raising warning call releases its reservation inside the lock."""
        seen = []

        class RecordingLock:
            def __enter__(self):
                seen.append(("enter", _prefilter._php_sql_additions_warned))

            def __exit__(self, *_exc):
                seen.append(("exit", _prefilter._php_sql_additions_warned))
                return False

        monkeypatch.setattr(_prefilter, "_php_sql_additions_lock",
                            RecordingLock())
        self._log_with(monkeypatch,
                       self._Recorder(RuntimeError("while logging")),
                       self._Recorder())
        self._fail_additions(monkeypatch)
        assert _prefilter._php_sql_injection_lines(self._SRC, 1) == {3}
        assert seen == [("enter", False), ("exit", True),
                        ("enter", True), ("exit", False)]


_LINE_ENDING_SRC = (
    '<?php\nfunction f($c, $db, $id) {\n'
    '  $r = $db->query(\n'
    '    "SELECT * FROM t WHERE id = "\n'
    '    . $id);\n'
    '  mysqli_query($c,\n'
    '    "SELECT * FROM t WHERE n = \'$id\'");\n'
    '  mysql_query("SELECT * FROM t WHERE id = $id");\n'
    '}\n'
)


def _mixed_line_endings(source: str) -> str:
    parts = source.split("\n")
    seps = ["\r\n", "\r", "\n"]
    out = "".join(p + seps[i % 3] for i, p in enumerate(parts[:-1]))
    return out.replace("    ", "\t")


class TestPhpSqlInjectionInputShapes:
    """CRLF, CR-only (each CR is a line break, as for splitlines), tabs and
    statements with several sinks: the additions are called directly and
    give the same, explicit lines."""

    @pytest.mark.parametrize("source", [
        _LINE_ENDING_SRC,
        _LINE_ENDING_SRC.replace("\n", "\r\n"),
        _LINE_ENDING_SRC.replace("\n", "\r"),
        _LINE_ENDING_SRC.replace("  ", "\t"),
        _mixed_line_endings(_LINE_ENDING_SRC),
    ], ids=["lf", "crlf", "cr", "tabs", "mixed"])
    def test_line_endings_and_tabs(self, tmp_path, source):
        """LF, CRLF, CR, tabs and mixed endings give the same additions,
        shifted by line_start."""
        assert _prefilter._php_sql_additions(source, 1) == {3, 6, 8}
        assert _prefilter._php_sql_additions(source, 20) == {22, 25, 27}
        assert _prefilter._php_sql_main_rule_lines(source, 1) == {6, 8}
        assert _php_sql_rule_lines(tmp_path, source) == [3, 6, 8]

    def test_four_sinks_in_one_statement(self, tmp_path):
        """Each of four sinks in one statement is added on its own line."""
        source = (
            '<?php\nfunction f($c, $db, $pdo, $id) {\n'
            '  $r = $db->query("SELECT a FROM t WHERE id = $id")\n'
            '    . $pdo->query("SELECT b FROM t WHERE id = $id")\n'
            '    . mysqli_query($c, "SELECT c FROM t WHERE id = $id")\n'
            '    . $db->exec("DELETE FROM t WHERE id = $id");\n'
            '  $s = $db->query("SELECT 1");\n'
            '}\n'
        )
        assert _prefilter._php_sql_additions(source, 1) == {3, 4, 5, 6}
        assert _php_sql_rule_lines(tmp_path, source) == [3, 4, 5, 6]


class TestPhpSqlInjectionResolution:
    """End-to-end: the in-review evidence stamp decides finding vs clean.

    Real ``_sweep_validate`` (prefilter stage + tool chain), real G2
    gate, real ``_resolve_gate_demoted`` and export; only the semgrep
    sweep is stubbed to the ``refuted`` verdict a working host books
    for concatenated/interpolated SQL.
    """

    @staticmethod
    def _resolve(tmp_path, monkeypatch, sink):
        from core.audit import orchestrator as o
        from core.audit.findings_export import export_findings
        from core.audit.sweep import SarifCache, SweepResult

        monkeypatch.setattr(
            o, "run_semgrep_sweep",
            lambda **k: SweepResult(
                tool="semgrep", file_path=k["file_path"],
                function_name=k["function_name"], outcome="refuted",
            ),
        )
        tgt = tmp_path / "tgt"
        tgt.mkdir()
        (tgt / "app.php").write_text(
            TestPhpSqlInjectionResolution._file(sink),
        )
        out = tmp_path / "out"
        out.mkdir()
        cfg = o.OrchestratorConfig(target_path=tgt, out_dir=out)
        sc = SarifCache()
        ck = {"files": [{"path": "app.php", "items": [
            {"name": "getUser", "line_start": 2, "line_end": 4}]}]}
        oc = o.ReviewOutcome(
            file="app.php", function="getUser", status="finding", body="m",
            hypothesis="SQL injection: id concatenated into the query",
            evidence_tool="", line=2,
            review_result={"cwe": "CWE-89", "mechanism": "SQL injection"},
        )
        oc = o._sweep_validate(oc, cfg, sc)
        evidence = oc.evidence_tool
        violations = (
            o._check_finding_gates(oc) if oc.status == "finding" else []
        )
        if any(v.startswith("G2") for v in violations):
            oc = o._demote_outcome(
                oc, f"[gate violation: {'; '.join(violations)}]",
            )
        res = o.OrchestratorResult()
        res.outcomes = [oc]
        res.suspicious = 1 if oc.status == "suspicious" else 0
        o._resolve_gate_demoted(
            res, cfg, sc, ck,
            available_tools={"joern": False, "semgrep": True},
            mechanical_findings={},
        )
        final = res.outcomes[0]
        return (
            evidence, final.status,
            len(export_findings(res.outcomes)["findings"]),
        )

    @staticmethod
    def _file(sink):
        return "<?php\nfunction getUser($c, $pdo, $id) {\n  " + sink + "\n}\n"

    @pytest.mark.parametrize("sink", [
        'return mysqli_query($c, "SELECT * FROM users WHERE id = " . $id);',
        'return $pdo->query("SELECT * FROM users WHERE id = " . $id);',
        'return $pdo->query("SELECT * FROM users WHERE id = $id");',
    ])
    def test_vulnerable_sink_kept_as_finding(self, tmp_path, monkeypatch, sink):
        """End to end: with the prefilter hit the CWE-89 finding keeps its
        evidence and is exported even when semgrep refutes it."""
        # called directly too: run_prefilter would contain a crash
        assert _prefilter._php_sql_additions(self._file(sink), 1) == {3}
        assert self._resolve(tmp_path, monkeypatch, sink) == (
            "prefilter:php-sql-injection", "finding", 1,
        )

    def test_quote_sanitised_sink_not_stamped(self, tmp_path, monkeypatch):
        """A quote()-sanitised method sink gets no prefilter stamp, so it is
        not promoted to a finding."""
        sink = ('return $pdo->query("SELECT * FROM users WHERE n = " '
                '. $pdo->quote($id));')
        # called directly too: run_prefilter would contain a crash
        assert _prefilter._php_sql_additions(self._file(sink), 1) == set()
        evidence, status, _ = self._resolve(tmp_path, monkeypatch, sink)
        assert evidence != "prefilter:php-sql-injection"
        assert status != "finding"
