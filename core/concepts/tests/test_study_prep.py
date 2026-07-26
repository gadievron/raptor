"""Tests for libexec/raptor-study-prep — mechanical extraction."""

from __future__ import annotations

import importlib.machinery
import importlib.util
from pathlib import Path
from types import ModuleType

# Load the prep script as a module (it's a libexec, not a package).
_PREP_PATH = Path(__file__).resolve().parents[3] / "libexec" / "raptor-study-prep"


def _load_prep() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader("raptor_study_prep", str(_PREP_PATH))
    spec = importlib.util.spec_from_file_location(
        "raptor_study_prep", str(_PREP_PATH), loader=loader,
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


prep = _load_prep()


# ------------------------------------------------------------------
# Struct extraction
# ------------------------------------------------------------------

class TestExtractStructBlocks:
    def test_simple_struct(self) -> None:
        src = """\
struct page {
    unsigned long flags;
    atomic_t _refcount;
    atomic_t _mapcount;
};
"""
        results = prep._extract_struct_blocks(src, "mm_types.h")
        assert len(results) == 1
        assert results[0]["name"] == "page"
        assert results[0]["file"] == "mm_types.h"
        assert results[0]["line"] == 1
        assert "_refcount" in results[0]["fields"]
        assert "_mapcount" in results[0]["fields"]
        assert "_refcount" in results[0]["refcount_fields"]

    def test_typedef_struct(self) -> None:
        src = """\
typedef struct scatterlist {
    unsigned long page_link;
    unsigned int offset;
    unsigned int length;
} scatterlist_t;
"""
        results = prep._extract_struct_blocks(src, "sg.h")
        assert len(results) == 1
        assert results[0]["name"] == "scatterlist"

    def test_union(self) -> None:
        src = """\
union cra_u {
    struct ablkcipher_request ablkcipher_req;
    struct aead_request aead_req;
};
"""
        results = prep._extract_struct_blocks(src, "algif.h")
        assert len(results) == 1
        assert results[0]["name"] == "cra_u"

    def test_enum(self) -> None:
        src = """\
enum crypto_flags {
    CRYPTO_TFM_REQ_WEAK_KEY = 1,
    CRYPTO_TFM_RES_WEAK_KEY = 2,
};
"""
        results = prep._extract_struct_blocks(src, "crypto.h")
        assert len(results) == 1
        assert results[0]["name"] == "crypto_flags"

    def test_no_structs(self) -> None:
        src = "int main() { return 0; }\n"
        results = prep._extract_struct_blocks(src, "main.c")
        assert results == []

    def test_doc_comment_extracted(self) -> None:
        src = """\
/* This is a page descriptor.
 * It tracks the physical page frame.
 */
struct page {
    unsigned long flags;
};
"""
        results = prep._extract_struct_blocks(src, "mm.h")
        assert len(results) == 1
        assert "page descriptor" in results[0]["doc_comment"]

    def test_brace_in_comment_not_counted(self) -> None:
        src = """\
struct tricky {
    int x; /* } not a real close */
    int y;
};
"""
        results = prep._extract_struct_blocks(src, "tricky.h")
        assert len(results) == 1
        assert "y" in results[0]["fields"]

    def test_brace_in_string_not_counted(self) -> None:
        src = """\
struct tricky2 {
    char *fmt;  // = "}"
    int z;
};
"""
        results = prep._extract_struct_blocks(src, "tricky2.h")
        assert len(results) == 1
        assert "z" in results[0]["fields"]

    def test_unterminated_struct_skipped(self) -> None:
        src = """\
struct broken {
    int x;
"""
        results = prep._extract_struct_blocks(src, "broken.h")
        assert len(results) == 0

    def test_doc_comment_non_asterisk_block(self) -> None:
        src = """\
/*
  This is a block comment
  without leading asterisks.
*/
struct example {
    int val;
};
"""
        results = prep._extract_struct_blocks(src, "example.h")
        assert len(results) == 1
        doc = results[0]["doc_comment"]
        assert "block comment" in doc
        assert "without leading" in doc

    def test_bitfield_extracts_field_name_not_width(self) -> None:
        src = """\
struct flags {
    unsigned int readable : 1;
    unsigned int writable : 1;
    unsigned int executable : 1;
    unsigned int reserved : 29;
};
"""
        results = prep._extract_struct_blocks(src, "flags.h")
        assert len(results) == 1
        fields = results[0]["fields"]
        assert "readable" in fields
        assert "writable" in fields
        assert "1" not in fields
        assert "29" not in fields


# ------------------------------------------------------------------
# Function extraction
# ------------------------------------------------------------------

class TestExtractFunctions:
    def test_simple_function(self) -> None:
        src = """\
void get_page(struct page *page)
{
    atomic_inc(&page->_refcount);
}
"""
        results = prep._extract_functions(src, "mm.c")
        assert any(f["name"] == "get_page" for f in results)

    def test_pointer_return(self) -> None:
        src = """\
struct page *alloc_page(gfp_t gfp)
{
    return __alloc_pages(gfp, 0, NULL);
}
"""
        results = prep._extract_functions(src, "page_alloc.c")
        names = [f["name"] for f in results]
        assert "alloc_page" in names

    def test_static_function(self) -> None:
        src = """\
static int crypto_init(void)
{
    return 0;
}
"""
        results = prep._extract_functions(src, "crypto.c")
        assert any(f["name"] == "crypto_init" for f in results)


# ------------------------------------------------------------------
# Parameter type extraction with qualifiers
# ------------------------------------------------------------------

class TestParseParamTypes:
    def test_plain_struct(self) -> None:
        sig = "void sg_init_table(struct scatterlist *sgl, unsigned int nents)"
        result = prep._parse_param_types_regex(sig)
        assert result == ["struct scatterlist", "unsigned"]

    def test_const_struct(self) -> None:
        sig = "int sg_nents(const struct scatterlist *sg)"
        result = prep._parse_param_types_regex(sig)
        assert result == ["struct scatterlist"]

    def test_volatile_pointer(self) -> None:
        sig = "void write_reg(volatile unsigned int *addr, int val)"
        result = prep._parse_param_types_regex(sig)
        assert result == ["unsigned", "int"]

    def test_static_inline_stripped_from_return(self) -> None:
        sig = "static inline struct page *sg_page(struct scatterlist *sg)"
        result = prep._parse_param_types_regex(sig)
        assert result == ["struct scatterlist"]

    def test_multiple_qualifiers(self) -> None:
        sig = "void foo(const volatile struct mutex *m, register int x)"
        result = prep._parse_param_types_regex(sig)
        assert result == ["struct mutex", "int"]

    def test_restrict_qualifier(self) -> None:
        sig = "void memcpy(void *restrict dst, const void *restrict src, size_t n)"
        result = prep._parse_param_types_regex(sig)
        assert result == ["void", "void", "size_t"]

    def test_always_inline_attr(self) -> None:
        sig = "static __always_inline int get_val(const struct page *p)"
        result = prep._parse_param_types_regex(sig)
        assert result == ["struct page"]

    def test_void_param(self) -> None:
        sig = "int foo(void)"
        result = prep._parse_param_types_regex(sig)
        assert result == []

    def test_no_parens(self) -> None:
        sig = "int foo"
        result = prep._parse_param_types_regex(sig)
        assert result == []


class TestParseReturnType:
    def test_static_inline(self) -> None:
        sig = "static inline struct page *sg_page(struct scatterlist *sg)"
        result = prep._parse_return_type_regex(sig)
        assert result == "page"

    def test_const_return(self) -> None:
        sig = "const char *get_name(int id)"
        result = prep._parse_return_type_regex(sig)
        assert result == "char"

    def test_plain(self) -> None:
        sig = "int foo(void)"
        result = prep._parse_return_type_regex(sig)
        assert result == "int"

    def test_extern_volatile(self) -> None:
        sig = "extern volatile int read_status(void)"
        result = prep._parse_return_type_regex(sig)
        assert result == "int"


# ------------------------------------------------------------------
# Paired operations
# ------------------------------------------------------------------

class TestFindPairedOperations:
    def test_get_put_pair(self) -> None:
        funcs = [
            {"name": "get_page", "file": "mm.h", "line": 1, "signature": ""},
            {"name": "put_page", "file": "mm.h", "line": 10, "signature": ""},
        ]
        pairs = prep._find_paired_operations(funcs)
        assert ("get_page", "put_page") in pairs

    def test_alloc_free_pair(self) -> None:
        funcs = [
            {"name": "alloc_skb", "file": "skbuff.h", "line": 1, "signature": ""},
            {"name": "free_skb", "file": "skbuff.h", "line": 10, "signature": ""},
        ]
        pairs = prep._find_paired_operations(funcs)
        assert ("alloc_skb", "free_skb") in pairs

    def test_no_pair(self) -> None:
        funcs = [
            {"name": "get_page", "file": "mm.h", "line": 1, "signature": ""},
            {"name": "do_something", "file": "mm.h", "line": 10, "signature": ""},
        ]
        pairs = prep._find_paired_operations(funcs)
        assert len(pairs) == 0

    def test_create_destroy_pair(self) -> None:
        funcs = [
            {"name": "create_ctx", "file": "ctx.c", "line": 1, "signature": ""},
            {"name": "destroy_ctx", "file": "ctx.c", "line": 50, "signature": ""},
        ]
        pairs = prep._find_paired_operations(funcs)
        assert ("create_ctx", "destroy_ctx") in pairs


# ------------------------------------------------------------------
# Include resolution
# ------------------------------------------------------------------

class TestIncludeResolution:
    def test_resolve_existing_include(self, tmp_path: Path) -> None:
        (tmp_path / "linux").mkdir()
        (tmp_path / "linux" / "mm.h").write_text("struct page {};", encoding="utf-8")
        result = prep._resolve_include("linux/mm.h", [tmp_path], tmp_path)
        assert result is not None
        assert result.name == "mm.h"

    def test_resolve_missing_include(self, tmp_path: Path) -> None:
        result = prep._resolve_include("linux/nonexistent.h", [tmp_path], tmp_path)
        assert result is None

    def test_path_traversal_blocked(self, tmp_path: Path) -> None:
        src_root = tmp_path / "project"
        src_root.mkdir()
        (src_root / "include").mkdir()
        (src_root / "include" / "safe.h").write_text("int x;", encoding="utf-8")
        (tmp_path / "secret.h").write_text("SECRET", encoding="utf-8")
        result = prep._resolve_include(
            "../secret.h", [src_root / "include"], src_root,
        )
        assert result is None

    def test_extract_includes(self) -> None:
        src = """\
#include <linux/mm.h>
#include "local.h"
#include <linux/scatterlist.h>
"""
        includes = prep._extract_includes(src)
        assert "linux/mm.h" in includes
        assert "local.h" in includes
        assert "linux/scatterlist.h" in includes


# ------------------------------------------------------------------
# Source root detection
# ------------------------------------------------------------------

class TestDetectSourceRoot:
    def test_git_root(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        (tmp_path / "src").mkdir()
        result = prep._detect_source_root(tmp_path / "src")
        assert result == tmp_path

    def test_makefile_root(self, tmp_path: Path) -> None:
        (tmp_path / "Makefile").write_text("", encoding="utf-8")
        (tmp_path / "crypto").mkdir()
        result = prep._detect_source_root(tmp_path / "crypto")
        assert result == tmp_path

    def test_no_indicator_returns_target(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()
        result = prep._detect_source_root(tmp_path / "src")
        assert result == tmp_path / "src"


# ------------------------------------------------------------------
# Build study items
# ------------------------------------------------------------------

class TestBuildStudyItems:
    def test_struct_with_refcount_creates_items(self) -> None:
        structs = [{
            "name": "page",
            "file": "mm_types.h",
            "line": 42,
            "kind": "struct",
            "definition": "struct page { atomic_t _refcount; };",
            "fields": ["flags", "_refcount"],
            "refcount_fields": ["_refcount"],
            "doc_comment": "",
        }]
        items = prep._build_study_items(structs, [], [])
        struct_items = [i for i in items if i.id == "struct_page"]
        assert len(struct_items) == 1
        assert struct_items[0].kind == "struct"

        refcount_items = [i for i in items if i.id.startswith("refcount_")]
        assert len(refcount_items) == 1

    def test_paired_ops_create_item(self) -> None:
        pairs = [("get_page", "put_page")]
        items = prep._build_study_items([], [], pairs)
        assert len(items) == 1
        assert items[0].kind == "paired_ops"
        assert items[0].name == "get_page/put_page"

    def test_word_boundary_callees_matching(self) -> None:
        """'stat' must not match 'static' in signatures."""
        structs = [{
            "name": "stat",
            "file": "sys.h",
            "line": 1,
            "kind": "struct",
            "definition": "struct stat { int st_mode; };",
            "fields": ["st_mode"],
            "refcount_fields": [],
            "doc_comment": "",
        }]
        funcs = [
            {"name": "do_stat", "file": "fs.c", "line": 1,
             "signature": "int do_stat(struct stat *buf)",
             "param_types": ["stat"], "return_type": "int", "body": ""},
            {"name": "init_static", "file": "fs.c", "line": 20,
             "signature": "static void init_static(void)",
             "param_types": [], "return_type": "void", "body": ""},
        ]
        type_ref_index = prep._build_type_reference_index(funcs, funcs)
        items = prep._build_study_items(structs, funcs, [], type_ref_index)
        struct_items = [i for i in items if i.id == "struct_stat"]
        assert len(struct_items) == 1
        assert "do_stat" in struct_items[0].callees
        assert "init_static" not in struct_items[0].callees

    def test_no_duplicates(self) -> None:
        structs = [{
            "name": "page",
            "file": "mm_types.h",
            "line": 42,
            "kind": "struct",
            "definition": "struct page {};",
            "fields": [],
            "refcount_fields": [],
            "doc_comment": "",
        }]
        items = prep._build_study_items(structs + structs, [], [])
        ids = [i.id for i in items]
        assert len(ids) == len(set(ids))


# ------------------------------------------------------------------
# End-to-end (small synthetic target)
# ------------------------------------------------------------------

# ------------------------------------------------------------------
# Structural signal extraction
# ------------------------------------------------------------------

class TestStructuralSignals:
    def test_lock_sites_detected(self) -> None:
        body = """\
{
    spin_lock(&sma->sem_perm.lock);
    do_something();
    spin_unlock(&sma->sem_perm.lock);
}
"""
        signals = prep._extract_structural_signals(body)
        assert "spin_lock" in signals["lock_sites"]
        assert "spin_unlock" in signals["lock_sites"]

    def test_rcu_usage_detected(self) -> None:
        body = """\
{
    rcu_read_lock();
    p = rcu_dereference(ptr);
    list_for_each_entry_rcu(un, &ulp->list_proc, list_proc) {
        do_something(un);
    }
    rcu_read_unlock();
}
"""
        signals = prep._extract_structural_signals(body)
        assert "rcu_read_lock" in signals["rcu_usage"]
        assert "rcu_dereference" in signals["rcu_usage"]
        assert "list_for_each_entry_rcu" in signals["rcu_usage"]
        assert "rcu_read_unlock" in signals["rcu_usage"]

    def test_ordering_annotations_detected(self) -> None:
        body = """\
{
    smp_store_release(&sma->use_global_lock, 0);
    val = READ_ONCE(queue.status);
    WRITE_ONCE(queue.status, -EINTR);
    smp_acquire__after_ctrl_dep();
}
"""
        signals = prep._extract_structural_signals(body)
        assert "smp_store_release" in signals["ordering_annotations"]
        assert "READ_ONCE" in signals["ordering_annotations"]
        assert "WRITE_ONCE" in signals["ordering_annotations"]
        assert "smp_acquire__after_ctrl_dep" in signals["ordering_annotations"]

    def test_bounds_guards_detected(self) -> None:
        body = """\
{
    int idx = array_index_nospec(sop->sem_num, sma->sem_nsems);
    if (!access_ok(buf, count))
        return -EFAULT;
    copy_from_user(kbuf, ubuf, count);
}
"""
        signals = prep._extract_structural_signals(body)
        assert "array_index_nospec" in signals["bounds_guards"]
        assert "access_ok" in signals["bounds_guards"]
        assert "copy_from_user" in signals["bounds_guards"]

    def test_error_gotos_detected(self) -> None:
        body = """\
{
    if (err)
        goto out_unlock;
    if (invalid)
        goto would_block;
    return 0;
out_unlock:
    spin_unlock(&lock);
would_block:
    return -EAGAIN;
}
"""
        signals = prep._extract_structural_signals(body)
        assert "out_unlock" in signals["error_gotos"]
        assert "would_block" in signals["error_gotos"]

    def test_clamping_detected(self) -> None:
        body = """\
{
    val = clamp_t(int, val, 0, SEMVMX);
    x = min_t(unsigned, x, limit);
}
"""
        signals = prep._extract_structural_signals(body)
        assert "clamp_t" in signals["clamping_patterns"]
        assert "min_t" in signals["clamping_patterns"]

    def test_no_signals_returns_empty(self) -> None:
        body = "{ return 0; }"
        signals = prep._extract_structural_signals(body)
        assert not prep._has_signals(signals)

    def test_has_signals_true_when_present(self) -> None:
        signals = {"lock_sites": ["spin_lock"], "rcu_usage": [],
                    "ordering_annotations": [], "bounds_guards": [],
                    "error_gotos": [], "clamping_patterns": [],
                    "flag_checks": [], "alloc_frees": []}
        assert prep._has_signals(signals)

    def test_has_signals_false_when_all_empty(self) -> None:
        signals = {"lock_sites": [], "rcu_usage": [],
                    "ordering_annotations": [], "bounds_guards": [],
                    "error_gotos": [], "clamping_patterns": [],
                    "flag_checks": [], "alloc_frees": []}
        assert not prep._has_signals(signals)


class TestOwnedTypes:
    def test_pointer_fields_detected(self) -> None:
        defn = """\
struct sem {
    struct pid *sempid;
    struct task_struct *owner;
    spinlock_t lock;
};
"""
        owned = prep._extract_owned_types(defn)
        assert "pid" in owned
        assert "task_struct" in owned

    def test_infra_types_filtered(self) -> None:
        defn = """\
struct example {
    struct list_head list;
    struct rcu_head rcu;
    struct hlist_node node;
    struct real_data *data;
};
"""
        owned = prep._extract_owned_types(defn)
        assert "real_data" in owned
        assert "list_head" not in owned
        assert "rcu_head" not in owned
        assert "hlist_node" not in owned

    def test_no_pointer_fields(self) -> None:
        defn = "struct simple { int x; int y; };"
        assert prep._extract_owned_types(defn) == []


class TestFlexibleArrays:
    def test_trailing_flex_array(self) -> None:
        defn = """\
struct sem_array {
    int sem_nsems;
    struct sem sems[];
};
"""
        flex = prep._extract_flexible_arrays(defn)
        assert "sems" in flex

    def test_no_flex_array(self) -> None:
        defn = "struct simple { int x; };"
        assert prep._extract_flexible_arrays(defn) == []

    def test_fixed_array_not_matched(self) -> None:
        defn = "struct buf { char data[256]; };"
        assert prep._extract_flexible_arrays(defn) == []


class TestFunctionSignalExtraction:
    def test_function_with_signals_gets_signals_dict(self) -> None:
        src = """\
void lock_and_work(struct sem_array *sma)
{
    spin_lock(&sma->lock);
    sma->val++;
    spin_unlock(&sma->lock);
}
"""
        funcs = prep._extract_functions(src, "test.c")
        assert len(funcs) == 1
        signals = funcs[0]["signals"]
        assert "spin_lock" in signals["lock_sites"]
        assert "spin_unlock" in signals["lock_sites"]

    def test_declaration_gets_no_signals(self) -> None:
        src = "void do_something(int x);\n"
        funcs = prep._extract_functions(src, "test.h")
        assert len(funcs) == 1
        assert funcs[0]["signals"] == {}

    def test_signal_rich_function_emitted_as_study_item(self) -> None:
        funcs = [{
            "name": "sem_lock",
            "file": "ipc/sem.c",
            "line": 389,
            "signature": "static inline int sem_lock(struct sem_array *sma, ...)",
            "signals": {
                "lock_sites": ["ipc_lock_object", "spin_lock", "spin_unlock"],
                "rcu_usage": [],
                "ordering_annotations": ["READ_ONCE", "smp_load_acquire"],
                "bounds_guards": ["array_index_nospec"],
                "error_gotos": [],
                "clamping_patterns": [],
            },
        }]
        items = prep._build_study_items([], funcs, [])
        func_items = [i for i in items if i.kind == "function"]
        assert len(func_items) == 1
        assert func_items[0].name == "sem_lock"
        assert "spin_lock" in func_items[0].lock_sites
        assert "smp_load_acquire" in func_items[0].ordering_annotations
        assert "array_index_nospec" in func_items[0].bounds_guards

    def test_signal_free_function_not_emitted(self) -> None:
        funcs = [{
            "name": "simple_add",
            "file": "math.c",
            "line": 1,
            "signature": "int simple_add(int a, int b)",
            "signals": {
                "lock_sites": [], "rcu_usage": [],
                "ordering_annotations": [], "bounds_guards": [],
                "error_gotos": [], "clamping_patterns": [],
            },
        }]
        items = prep._build_study_items([], funcs, [])
        func_items = [i for i in items if i.kind == "function"]
        assert len(func_items) == 0

    def test_struct_item_gets_owned_types_and_flex(self) -> None:
        structs = [{
            "name": "sem_array",
            "file": "ipc/sem.c",
            "line": 114,
            "kind": "struct",
            "definition": "struct sem_array { struct pid *pid; struct sem sems[]; };",
            "fields": ["pid", "sems"],
            "refcount_fields": [],
            "doc_comment": "",
            "owned_types": ["pid", "sem"],
            "flexible_arrays": ["sems"],
        }]
        items = prep._build_study_items(structs, [], [])
        struct_items = [i for i in items if i.id == "struct_sem_array"]
        assert len(struct_items) == 1
        assert "pid" in struct_items[0].owned_types
        assert "sems" in struct_items[0].flexible_arrays


# ------------------------------------------------------------------
# End-to-end (small synthetic target)
# ------------------------------------------------------------------

class TestEndToEnd:
    def test_synthetic_target(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "main.c").write_text("""\
#include "types.h"

struct ctx {
    int ref_count;
    void *data;
};

void *alloc_ctx(void, encoding="utf-8") { return NULL; }
void free_ctx(struct ctx *c) { }
void get_ctx(struct ctx *c) { c->ref_count++; }
void put_ctx(struct ctx *c) { c->ref_count--; }
""", encoding="utf-8")
        (src_dir / "types.h").write_text("""\
struct base {
    int flags;
};
""", encoding="utf-8")

        out_dir = tmp_path / "out"
        out_dir.mkdir()

        structs_main = prep._extract_struct_blocks(
            (src_dir / "main.c").read_text(encoding="utf-8"), "src/main.c",
        )
        structs_hdr = prep._extract_struct_blocks(
            (src_dir / "types.h").read_text(encoding="utf-8"), "src/types.h",
        )
        funcs = prep._extract_functions(
            (src_dir / "main.c").read_text(encoding="utf-8"), "src/main.c",
        )

        all_structs = structs_main + structs_hdr
        pairs = prep._find_paired_operations(funcs)
        items = prep._build_study_items(all_structs, funcs, pairs)

        assert any(i.name == "ctx" for i in items)
        assert any(i.kind == "paired_ops" and "get_ctx" in i.name for i in items)
        assert any("ref_count" in i.refcount_fields for i in items if i.refcount_fields)


# ------------------------------------------------------------------
# File-level include dedup
# ------------------------------------------------------------------

class TestIncludeDedup:
    def test_included_file_not_extracted_twice(self, tmp_path: Path) -> None:
        """When a.c includes types.h AND types.h is also in rglob,
        structs from types.h should appear once, not twice."""
        src = tmp_path / "proj"
        src.mkdir()
        (src / "types.h").write_text("""\
struct unique_thing {
    int x;
};
""", encoding="utf-8")
        (src / "main.c").write_text("""\
#include "types.h"
void foo(void, encoding="utf-8") {}
""", encoding="utf-8")
        source_root = src

        source_files = sorted(
            f for f in src.rglob("*")
            if f.suffix in {".c", ".h"} and f.is_file() and not f.is_symlink()
        )

        all_structs = []
        all_funcs = []
        seen_files = {sf.resolve() for sf in source_files}

        for sf in source_files:
            content = sf.read_text(encoding="utf-8")
            rel = str(sf.relative_to(source_root))
            nl = prep._build_newline_index(content)
            all_structs.extend(prep._extract_struct_blocks(content, rel, _nl_index=nl))
            all_funcs.extend(prep._extract_functions(content, rel, _nl_index=nl))

            for inc in prep._extract_includes(content):
                resolved = prep._resolve_include(inc, [source_root], source_root)
                if resolved and resolved.resolve() not in seen_files:
                    seen_files.add(resolved.resolve())
                    inc_content = resolved.read_text(encoding="utf-8")
                    inc_rel = str(resolved.relative_to(source_root))
                    inc_nl = prep._build_newline_index(inc_content)
                    all_structs.extend(
                        prep._extract_struct_blocks(inc_content, inc_rel, _nl_index=inc_nl),
                    )

        unique_names = [s["name"] for s in all_structs if s["name"] == "unique_thing"]
        assert len(unique_names) == 1


# ------------------------------------------------------------------
# Call graph extraction
# ------------------------------------------------------------------

class TestCallGraph:
    def test_direct_call_detected(self) -> None:
        src = """\
void helper(int x) { }
void caller(void)
{
    helper(42);
}
"""
        funcs = prep._extract_functions(src, "test.c")
        graph = prep._build_call_graph(funcs)
        assert "helper" in graph["caller"]

    def test_self_call_excluded(self) -> None:
        src = """\
void recurse(int n)
{
    if (n > 0) recurse(n - 1);
}
"""
        funcs = prep._extract_functions(src, "test.c")
        graph = prep._build_call_graph(funcs)
        assert "recurse" not in graph["recurse"]

    def test_no_body_empty_calls(self) -> None:
        src = "void decl_only(int x);\n"
        funcs = prep._extract_functions(src, "test.h")
        graph = prep._build_call_graph(funcs)
        assert graph["decl_only"] == []

    def test_multiple_calls(self) -> None:
        src = """\
void a(void) { }
void b(void) { }
void c(void)
{
    a();
    b();
}
"""
        funcs = prep._extract_functions(src, "test.c")
        graph = prep._build_call_graph(funcs)
        assert "a" in graph["c"]
        assert "b" in graph["c"]
        assert graph["a"] == []
        assert graph["b"] == []

    def test_reverse_callers_in_study_item(self) -> None:
        src = """\
void target(void) { }
void caller1(void)
{
    target();
}
void caller2(void)
{
    target();
}
"""
        funcs = prep._extract_functions(src, "test.c")
        items = prep._build_study_items([], funcs, [])
        target_items = [i for i in items if i.name == "target"]
        assert len(target_items) == 1
        assert "caller1" in target_items[0].callers
        assert "caller2" in target_items[0].callers

    def test_calls_field_in_study_item(self) -> None:
        src = """\
void leaf(void) { }
void mid(void)
{
    leaf();
}
"""
        funcs = prep._extract_functions(src, "test.c")
        items = prep._build_study_items([], funcs, [])
        mid_items = [i for i in items if i.name == "mid"]
        assert len(mid_items) == 1
        assert "leaf" in mid_items[0].calls


# ------------------------------------------------------------------
# Flag check extraction
# ------------------------------------------------------------------

class TestFlagChecks:
    def test_simple_flag_check(self) -> None:
        body = """\
{
    if (flags & MSG_SPLICE_PAGES)
        goto splice_path;
}
"""
        signals = prep._extract_structural_signals(body)
        assert "flags & MSG_SPLICE_PAGES" in signals["flag_checks"]

    def test_multiple_flag_checks(self) -> None:
        body = """\
{
    if (mode & FMODE_READ)
        do_read();
    if (mode & FMODE_WRITE)
        do_write();
    if (sma->sem_perm.mode & SEM_UNDO)
        handle_undo();
}
"""
        signals = prep._extract_structural_signals(body)
        assert len(signals["flag_checks"]) == 3

    def test_no_flag_checks(self) -> None:
        body = "{ return x + y; }"
        signals = prep._extract_structural_signals(body)
        assert signals["flag_checks"] == []

    def test_flag_check_in_study_item(self) -> None:
        funcs = [{
            "name": "send_msg",
            "file": "net/socket.c",
            "line": 100,
            "signature": "int send_msg(struct socket *sock, int flags)",
            "doc_comment": "",
            "signals": {
                "lock_sites": [], "rcu_usage": [],
                "ordering_annotations": [], "bounds_guards": [],
                "error_gotos": [], "clamping_patterns": [],
                "flag_checks": ["flags & MSG_SPLICE_PAGES",
                                "flags & MSG_DONTWAIT"],
                "alloc_frees": [],
            },
            "body": "{ if (flags & MSG_SPLICE_PAGES) {} }",
        }]
        items = prep._build_study_items([], funcs, [])
        func_items = [i for i in items if i.name == "send_msg"]
        assert len(func_items) == 1
        assert "flags & MSG_SPLICE_PAGES" in func_items[0].flag_checks


# ------------------------------------------------------------------
# Alloc/free extraction
# ------------------------------------------------------------------

class TestAllocFrees:
    def test_kmalloc_detected(self) -> None:
        body = """\
{
    p = kmalloc(sizeof(*p), GFP_KERNEL);
    if (!p)
        return -ENOMEM;
}
"""
        signals = prep._extract_structural_signals(body)
        assert "kmalloc" in signals["alloc_frees"]

    def test_kfree_detected(self) -> None:
        body = "{ kfree(ptr); }"
        signals = prep._extract_structural_signals(body)
        assert "kfree" in signals["alloc_frees"]

    def test_page_alloc_free(self) -> None:
        body = """\
{
    struct page *p = alloc_page(GFP_KERNEL);
    put_page(p);
}
"""
        signals = prep._extract_structural_signals(body)
        assert "alloc_page" in signals["alloc_frees"]
        assert "put_page" in signals["alloc_frees"]

    def test_no_alloc_frees(self) -> None:
        body = "{ return x * 2; }"
        signals = prep._extract_structural_signals(body)
        assert signals["alloc_frees"] == []

    def test_alloc_frees_in_study_item(self) -> None:
        funcs = [{
            "name": "create_obj",
            "file": "obj.c",
            "line": 10,
            "signature": "struct obj *create_obj(void)",
            "doc_comment": "",
            "signals": {
                "lock_sites": [], "rcu_usage": [],
                "ordering_annotations": [], "bounds_guards": [],
                "error_gotos": [], "clamping_patterns": [],
                "flag_checks": [],
                "alloc_frees": ["kzalloc"],
            },
            "body": "{ return kzalloc(sizeof(struct obj), GFP_KERNEL); }",
        }]
        items = prep._build_study_items([], funcs, [])
        func_items = [i for i in items if i.name == "create_obj"]
        assert len(func_items) == 1
        assert "kzalloc" in func_items[0].alloc_frees


# ------------------------------------------------------------------
# Function doc comments
# ------------------------------------------------------------------

class TestFunctionDocComments:
    def test_kernel_doc_comment_extracted(self) -> None:
        src = """\
/**
 * get_page - increment page refcount
 * @page: the page to increment
 *
 * Caller must ensure the page is not freed.
 */
void get_page(struct page *page)
{
    atomic_inc(&page->_refcount);
}
"""
        funcs = prep._extract_functions(src, "mm.c")
        gp = [f for f in funcs if f["name"] == "get_page"]
        assert len(gp) == 1
        assert "increment page refcount" in gp[0]["doc_comment"]
        assert "Caller must ensure" in gp[0]["doc_comment"]

    def test_no_doc_comment(self) -> None:
        src = """\
void bare_function(int x)
{
    return;
}
"""
        funcs = prep._extract_functions(src, "test.c")
        assert funcs[0]["doc_comment"] == ""

    def test_doc_comment_creates_study_item(self) -> None:
        """A function with only a doc comment (no signals, no calls) is emitted."""
        src = """\
/**
 * important_func - does critical work
 * Caller holds the big lock.
 */
void important_func(void)
{
    return;
}
"""
        funcs = prep._extract_functions(src, "critical.c")
        items = prep._build_study_items([], funcs, [])
        func_items = [i for i in items if i.name == "important_func"]
        assert len(func_items) == 1
        assert "critical work" in func_items[0].doc_comment

    def test_line_comment_doc(self) -> None:
        src = """\
// Release the object and free memory.
void release_obj(struct obj *o)
{
    kfree(o);
}
"""
        funcs = prep._extract_functions(src, "obj.c")
        rel = [f for f in funcs if f["name"] == "release_obj"]
        assert len(rel) == 1
        assert "Release the object" in rel[0]["doc_comment"]


# ------------------------------------------------------------------
# Emission criteria widening
# ------------------------------------------------------------------

class TestEmissionCriteria:
    def test_function_with_only_calls_emitted(self) -> None:
        """A function with no signals but forward calls is still emitted."""
        src = """\
void leaf(void) { }
void wrapper(void)
{
    leaf();
}
"""
        funcs = prep._extract_functions(src, "test.c")
        items = prep._build_study_items([], funcs, [])
        wrapper = [i for i in items if i.name == "wrapper"]
        assert len(wrapper) == 1
        assert "leaf" in wrapper[0].calls

    def test_function_with_only_callers_emitted(self) -> None:
        """A function with no signals that is called by others is emitted."""
        src = """\
void target(void) { }
void caller(void)
{
    target();
}
"""
        funcs = prep._extract_functions(src, "test.c")
        items = prep._build_study_items([], funcs, [])
        target = [i for i in items if i.name == "target"]
        assert len(target) == 1
        assert "caller" in target[0].callers

    def test_truly_empty_function_not_emitted(self) -> None:
        """A function with no signals, no calls, no callers, no doc is skipped."""
        funcs = [{
            "name": "noop",
            "file": "test.c",
            "line": 1,
            "signature": "void noop(void)",
            "doc_comment": "",
            "signals": {
                "lock_sites": [], "rcu_usage": [],
                "ordering_annotations": [], "bounds_guards": [],
                "error_gotos": [], "clamping_patterns": [],
                "flag_checks": [], "alloc_frees": [],
            },
            "body": "",
        }]
        items = prep._build_study_items([], funcs, [])
        assert len([i for i in items if i.name == "noop"]) == 0
