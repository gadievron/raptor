"""Inventory language/extension gap closure.

Covers the recall holes where whole file classes contributed zero
checklist items: Perl, shell, GitHub workflow YAML, Objective-C,
assembly, and ``.inc`` fragments now extract reviewable units;
``.h`` headers route to C++ parsing on content markers; and every
file the inventory skips is RECORDED in ``excluded_files`` with a
reason — no silent invisibility.
"""

import pytest

from core.inventory.builder import _is_github_workflow, build_inventory
from core.inventory.extractors import (
    AsmExtractor,
    GitHubWorkflowExtractor,
    ObjCExtractor,
    PerlExtractor,
    ShellExtractor,
)
from core.inventory.languages import detect_language, refine_language


def _items(inv, path):
    for f in inv["files"]:
        if f["path"] == path:
            return {i["name"]: i for i in f["items"]}
    raise AssertionError(f"{path} not in inventory files")


def _excluded(inv):
    return {e["path"]: e["reason"] for e in inv["excluded_files"]}


# ---------------------------------------------------------------------
# Extension → language mapping
# ---------------------------------------------------------------------

@pytest.mark.parametrize("filename,language", [
    ("a.pl", "perl"),
    ("a.pm", "perl"),
    ("a.sh", "shell"),
    ("a.bash", "shell"),
    ("a.m", "objc"),
    ("a.mm", "objc"),
    ("a.s", "asm"),
    ("a.S", "asm"),
    ("a.asm", "asm"),
    ("a.inc", "inc"),
    ("a.yml", "yaml"),
    ("a.yaml", "yaml"),
])
def test_new_extensions_detected(filename, language):
    assert detect_language(filename) == language


# ---------------------------------------------------------------------
# Regex-fallback extractors
# ---------------------------------------------------------------------

def test_perl_subs_with_spans():
    src = (
        "#!/usr/bin/perl\n"
        "sub handler {\n"
        "  my $x = shift;\n"
        "  return $x;\n"
        "}\n"
        "sub forward_decl;\n"
    )
    fns = {f.name: f for f in PerlExtractor().extract("t.pl", src)}
    assert set(fns) == {"handler"}
    assert fns["handler"].line_start == 2
    assert fns["handler"].line_end == 5


def test_shell_posix_and_bash_function_forms():
    src = (
        "#!/bin/sh\n"
        "do_install() {\n"
        "  cp a b\n"
        "}\n"
        "function cleanup {\n"
        "  rm -f a  # } brace in comment must not close early\n"
        "  true\n"
        "}\n"
    )
    fns = {f.name: f for f in ShellExtractor().extract("i.sh", src)}
    assert set(fns) == {"do_install", "cleanup"}
    assert fns["do_install"].line_end == 4
    assert fns["cleanup"].line_end == 8


def test_objc_methods_and_c_functions():
    src = (
        "#import <Foundation/Foundation.h>\n"
        "- (void)load:(NSString *)path {\n"
        "  NSLog(@\"%@\", path);\n"
        "}\n"
        "+ (instancetype)shared;\n"  # declaration — no body, skipped
        "static int helper(int x) {\n"
        "  return x + 1;\n"
        "}\n"
    )
    fns = {f.name: f for f in ObjCExtractor().extract("v.m", src)}
    assert "load" in fns and fns["load"].line_end == 4
    assert "helper" in fns
    assert "shared" not in fns


def test_asm_labels_with_exported_visibility():
    src = (
        ".globl _start\n"
        "_start:\n"
        "  mov $1, %eax\n"
        ".Llocal:\n"
        "  ret\n"
        "helper_fn:\n"
        "  nop\n"
    )
    fns = {f.name: f for f in AsmExtractor().extract("b.s", src)}
    assert set(fns) == {"_start", "helper_fn"}
    assert fns["_start"].metadata.visibility == "exported"
    assert fns["helper_fn"].metadata.visibility is None


WORKFLOW = """\
name: CI
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: run it
        run: echo "${{ github.event.pull_request.title }}"
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: make lint
"""


def test_workflow_jobs_and_run_steps_are_units():
    items = {i.name: i for i in
             GitHubWorkflowExtractor().extract("ci.yml", WORKFLOW)}
    assert "job:build" in items
    assert "job:lint" in items
    # Only steps with a run: script become units (injection surface).
    assert "job:build.step-2" in items
    assert "job:build.step-1" not in items
    assert items["job:build"].line_start == 4


def test_non_workflow_yaml_yields_nothing():
    assert GitHubWorkflowExtractor().extract("c.yml", "foo: bar\n") == []


def test_workflow_detection():
    assert _is_github_workflow(".github/workflows/ci.yml", "anything")
    assert _is_github_workflow("ci.yml", WORKFLOW)
    assert not _is_github_workflow("config.yml", "foo: bar\njobs: none\n")


# ---------------------------------------------------------------------
# Content-based routing
# ---------------------------------------------------------------------

def test_h_header_with_cpp_markers_routes_to_cpp():
    cpp_hdr = "template <typename T>\nclass Widget {\npublic:\n  T t_;\n};\n"
    c_hdr = "#pragma once\nint add(int a, int b);\n"
    assert refine_language("c", "w.h", cpp_hdr) == "cpp"
    assert refine_language("c", "w.h", c_hdr) == "c"


def test_inc_fragment_routing():
    assert refine_language("inc", "f.inc", "<?php\nfunction f() {}\n") == "php"
    assert refine_language("inc", "f.inc", ".macro save\n.endm\n") == "asm"
    assert refine_language("inc", "f.inc", "#define X 1\n") == "c"
    assert refine_language("inc", "f.inc", "just text\n") == "inc"


# ---------------------------------------------------------------------
# End-to-end: checklist admission + recorded exclusions
# ---------------------------------------------------------------------

def test_new_extension_files_enter_checklist(tmp_path):
    src = tmp_path / "src"
    out = tmp_path / "out"
    (src / ".github" / "workflows").mkdir(parents=True)
    (src / ".github" / "workflows" / "ci.yml").write_text(WORKFLOW)
    (src / "tool.pl").write_text("sub run_query {\n  return 1;\n}\n")
    (src / "install.sh").write_text("main() {\n  echo hi\n}\n")
    (src / "view.m").write_text("- (void)load {\n  x();\n}\n")
    (src / "boot.s").write_text("_start:\n  ret\n")
    (src / "frag.inc").write_text("<?php\nfunction inc_fn() {\n}\n")

    inv = build_inventory(str(src), str(out), parallel=False)
    by_path = {f["path"]: f for f in inv["files"]}

    assert "run_query" in _items(inv, "tool.pl")
    assert "main" in _items(inv, "install.sh")
    assert "load" in _items(inv, "view.m")
    assert "_start" in _items(inv, "boot.s")
    assert "inc_fn" in _items(inv, "frag.inc")
    assert "job:build" in _items(inv, ".github/workflows/ci.yml")
    assert by_path["frag.inc"]["language"] == "php"


def test_skipped_files_are_recorded_with_reasons(tmp_path):
    src = tmp_path / "src"
    out = tmp_path / "out"
    src.mkdir()
    (src / "config.yml").write_text("foo: bar\n")           # not a workflow
    (src / "gram.y").write_text("%%\nexpr: NUM;\n%%\n")     # unsupported
    (src / "blob.c").write_bytes(b"int x;\x00\xff\xfe")     # binary content

    inv = build_inventory(str(src), str(out), parallel=False)
    excluded = _excluded(inv)

    assert excluded["config.yml"] == "yaml_without_reviewable_units"
    assert excluded["gram.y"] == "unsupported_source_extension"
    assert excluded["blob.c"] == "binary_content"
    # Nothing skipped without a record.
    assert inv["skipped_files"] == len(inv["excluded_files"])
    assert inv["total_files"] == 0


def test_h_routing_end_to_end(tmp_path):
    src = tmp_path / "src"
    out = tmp_path / "out"
    src.mkdir()
    (src / "widget.h").write_text(
        "template <typename T>\nclass Widget {\npublic:\n"
        "  T get() { return t_; }\n  T t_;\n};\n"
    )
    (src / "plain.h").write_text("#pragma once\nint add(int a, int b);\n")

    inv = build_inventory(str(src), str(out), parallel=False)
    by_path = {f["path"]: f for f in inv["files"]}
    assert by_path["widget.h"]["language"] == "cpp"
    assert by_path["plain.h"]["language"] == "c"
