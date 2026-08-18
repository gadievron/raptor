"""Tests for core.audit.prefilter."""

from __future__ import annotations

from pathlib import Path

from core.audit.prefilter import (
    detect_language,
    run_prefilter,
    run_prefilter_batch,
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


class TestRunPrefilterBatch:
    def test_batch_returns_keyed_dict(self, tmp_path: Path):
        (tmp_path / "handler.c").write_text(
            "void handle(char *buf) { strcpy(dst, buf); }\n"
        )
        functions = [
            {
                "file": "handler.c",
                "name": "handle",
                "source": "void handle(char *buf) { strcpy(dst, buf); }",
                "line_start": 1,
                "line_end": 1,
            },
        ]
        results = run_prefilter_batch(
            target_path=tmp_path, functions=functions,
        )
        assert "handler.c:handle" in results
        result = results["handler.c:handle"]
        assert hasattr(result, "hits")
        assert hasattr(result, "skip_llm")

    def test_batch_multiple_functions(self, tmp_path: Path):
        functions = [
            {
                "file": "a.c",
                "name": "f1",
                "source": "int f1() { return 0; }",
                "line_start": 1,
                "line_end": 1,
            },
            {
                "file": "b.c",
                "name": "f2",
                "source": "void f2(char *s) { system(s); }",
                "line_start": 1,
                "line_end": 1,
            },
        ]
        results = run_prefilter_batch(
            target_path=tmp_path, functions=functions,
        )
        assert len(results) == 2
        assert "a.c:f1" in results
        assert "b.c:f2" in results

    def test_batch_reads_source_from_disk(self, tmp_path: Path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "vuln.c").write_text(
            "void vuln(char *input) {\n"
            "    char buf[16];\n"
            "    strcpy(buf, input);\n"
            "}\n"
        )
        functions = [
            {
                "file": "src/vuln.c",
                "name": "vuln",
                "line_start": 1,
                "line_end": 4,
            },
        ]
        results = run_prefilter_batch(
            target_path=tmp_path, functions=functions,
        )
        assert "src/vuln.c:vuln" in results
        result = results["src/vuln.c:vuln"]
        assert len(result.hits) > 0

    def test_batch_empty_list(self, tmp_path: Path):
        results = run_prefilter_batch(
            target_path=tmp_path, functions=[],
        )
        assert results == {}


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
