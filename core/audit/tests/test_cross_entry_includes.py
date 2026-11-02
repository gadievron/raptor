"""Auxiliary header search resolves declarations without widening source scope."""
from dataclasses import replace
from pathlib import Path

from core.audit.cross_entry import Limits, build_access_index
from core.audit.cross_entry.integration import collect_sources, prepare_cross_entry
from core.audit.cross_entry.progress import acknowledge_delivery
from core.audit.tests.test_cross_entry import dispatch_sources, fn
from core.audit.tests.test_cross_entry import grammar as grammar


def repository(tmp_path):
    root = tmp_path/"project"/"subsystem"
    include = root.parent/"include"
    root.mkdir(parents=True)
    include.mkdir()
    src = dispatch_sources()
    for fp,source in src.items():
        (include/fp if fp == "api.h" else root/fp).write_text(source)
    return root,include


def test_external_headers_are_opt_in_and_only_referenced_headers_are_read(tmp_path):
    root,include = repository(tmp_path)
    (include/"unrelated.h").write_text("do not collect")
    sources,coverage = collect_sources(root,["consumer.c"],Limits())
    assert not coverage["auxiliary_headers"]
    assert all(not key.startswith("../") for key in sources)
    sources,coverage = collect_sources(root,["consumer.c"],Limits(),include_dirs=[include])
    assert "../include/api.h" in sources
    assert "../include/unrelated.h" not in sources
    assert set(coverage["auxiliary_headers"]) == {"../include/api.h"}
    assert coverage["report_scope"] == ["consumer.c"]
    index = build_access_index(sources,include_edges=coverage["include_edges"])
    call = next(c for c in index.calls if c.name == "get_ops(i)->run")
    assert call.dispatch_candidates == [fn(index,"implementation")]


def test_report_header_frontier_finds_nested_layout_before_siblings_fill_budget(tmp_path):
    root,include = repository(tmp_path)
    (include/"api.h").rename(include/"actual.h")
    (include/"api.h").write_text('#include "actual.h"\n')
    for i in range(30):
        (root/f"filler{i}.c").write_text("void nothing(void) {}")
    sources,coverage = collect_sources(root,["consumer.c"],replace(Limits(),max_files=12),include_dirs=[include])
    assert "../include/actual.h" in sources
    assert "setup.c" in sources or coverage["truncated"]
    assert coverage["include_edges"]["../include/api.h"]["actual.h"] == "../include/actual.h"


def test_auxiliary_search_rejects_escaping_symlinks_and_source_files(tmp_path):
    root,include = repository(tmp_path)
    (tmp_path/"secret.h").write_text("secret")
    (include/"escape.h").symlink_to(tmp_path/"secret.h")
    (include/"hidden.c").write_text("source outside report scope")
    (root/"consumer.c").write_text('#include <escape.h>\n#include <hidden.c>\n')
    sources,coverage = collect_sources(root,["consumer.c"],Limits(),include_dirs=[include])
    assert not any("secret" in value or "source outside report scope" in value for value in sources.values())
    assert {s.get("include") for s in coverage["skipped"]} >= {"escape.h","hidden.c"}


def test_include_search_order_selects_one_declaration_identity(tmp_path):
    root,include = repository(tmp_path)
    other = tmp_path/"other"
    other.mkdir()
    (other/"api.h").write_text((include/"api.h").read_text())
    sources,coverage = collect_sources(root,["consumer.c"],Limits(),include_dirs=[include,other])
    assert "../include/api.h" in sources
    assert not any("other" in p for p in sources)
    assert coverage["include_edges"]["consumer.c"]["api.h"] == "../include/api.h"
    index = build_access_index(sources,include_edges=coverage["include_edges"])
    assert next(c for c in index.calls if c.name == "get_ops(i)->run").dispatch_candidates


def test_auxiliary_headers_count_against_file_and_byte_budgets(tmp_path):
    root,include = repository(tmp_path)
    sources,coverage = collect_sources(root,["consumer.c"],replace(Limits(),max_files=1),include_dirs=[include])
    assert list(sources) == ["consumer.c"]
    assert coverage["truncated"]
    (include/"api.h").write_text("x"*10_000)
    sources,coverage = collect_sources(root,["consumer.c"],replace(Limits(),max_bytes=2000),include_dirs=[include])
    assert "../include/api.h" not in sources
    assert any(s["reason"] == "byte_budget" for s in coverage["skipped"])


def test_header_changes_invalidate_delivered_context_without_widening_catalogue(tmp_path):
    import sqlite3
    from core.json import load_json
    root,include = repository(tmp_path)
    out = tmp_path/"out"
    receipts = {}
    gaps = [{"file":"consumer.c","name":"consume"}]
    contexts = prepare_cross_entry(root,gaps,mode="context",out_dir=out,include_dirs=[include],
                                   drain_index=True,delivery_receipts=receipts)
    assert set(contexts) == {"consumer.c:consume"}
    first = receipts["consumer.c:consume"]
    acknowledge_delivery(out,first)
    header = include/"api.h"
    header.write_text(header.read_text()+"\nstruct extra { int changed; };\n")
    newer = {}
    prepare_cross_entry(root,gaps,mode="context",out_dir=out,include_dirs=[include],
                        drain_index=True,delivery_receipts=newer)
    assert newer["consumer.c:consume"]["job"] == first["job"]
    assert newer["consumer.c:consume"]["evidence"] != first["evidence"]
    catalogue = load_json(out/"cross-entry-progress.json")["indexing"]["catalogue"]
    with sqlite3.connect(catalogue) as db:
        assert not any(row[0].startswith("../") for row in db.execute("SELECT path FROM files"))
    assert not (include/"cross-entry-work.sqlite").exists()


def test_pipeline_forwards_include_search_dirs():
    from core.audit.pipeline import AuditPipelineOpts, ReviewMode, _build_orchestrator_config
    opts = AuditPipelineOpts(target_path=Path("."),out_dir=Path("out"),cross_entry_include_dirs=[Path("include")])
    cfg = _build_orchestrator_config(opts,None,[],ReviewMode.SECURITY)
    assert cfg.cross_entry_include_dirs == [Path("include")]


def test_auto_detect_ancestor_includes_when_none_supplied(tmp_path):
    """prepare() auto-detects sibling include/ dirs via BuildDetector."""
    root = tmp_path / "project" / "subsystem"
    include = root.parent / "include"
    root.mkdir(parents=True)
    include.mkdir()
    (include / "api.h").write_text("struct T { int x; };")
    (root / "main.c").write_text('#include "api.h"\nvoid f(struct T *t) { t->x = 1; }')
    out = tmp_path / "out"
    receipts = {}
    contexts = prepare_cross_entry(
        root, [{"file": "main.c", "name": "f"}],
        mode="context", out_dir=out, drain_index=True,
        delivery_receipts=receipts,
    )
    assert "main.c:f" in contexts
    assert "struct T" in contexts["main.c:f"]


def test_explicit_include_dirs_override_auto_detect(tmp_path):
    """Explicit --cross-entry-include-dir suppresses auto-detection."""
    root = tmp_path / "project" / "subsystem"
    ancestor_inc = root.parent / "include"
    explicit_inc = tmp_path / "custom_inc"
    root.mkdir(parents=True)
    ancestor_inc.mkdir()
    explicit_inc.mkdir()
    (ancestor_inc / "api.h").write_text("struct A { int a; };")
    (explicit_inc / "api.h").write_text("struct B { int b; };")
    (root / "main.c").write_text('#include "api.h"\nvoid f(struct B *t) { t->b = 1; }')
    out = tmp_path / "out"
    contexts = prepare_cross_entry(
        root, [{"file": "main.c", "name": "f"}],
        mode="context", out_dir=out, drain_index=True,
        include_dirs=[explicit_inc],
    )
    assert "main.c:f" in contexts
    assert "struct B" in contexts["main.c:f"]
