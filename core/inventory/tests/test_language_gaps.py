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


def test_inc_space_run_is_fast():
    """Hostile .inc content that is one long horizontal SPACE run: in
    the C-signature branch a naive ``[^\\S\\n]*[\\w* \\t]+\\w+``
    spelling lets the indent span and the token span compete over the
    same run — quadratic on a single anchor (seconds at the 16K sniff
    head alone). The deterministic token-span spelling is linear.
    Both-direction bound: fast AND a real same-line signature still
    routes to C, while a line-broken signature still does not."""
    import time

    from core.inventory.languages import _INC_C_RE

    run = " " * (1 << 17)
    start = time.monotonic()
    assert _INC_C_RE.search(run) is None
    assert refine_language("inc", "f.inc", run) == "inc"
    assert time.monotonic() - start < 5.0
    # The real C signal still routes.
    assert refine_language(
        "inc", "f.inc", "static int frag_fn(int a, char *b) {\n") == "c"
    # Token span stays line-bound: a line-broken signature alone is
    # not a C signal.
    assert refine_language(
        "inc", "f.inc", "static int\nf(int x) {\n}\n") == "inc"


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


# ---------------------------------------------------------------------------
# Extension-case and shebang-probe hardening
# ---------------------------------------------------------------------------


def test_uppercase_c_extension_is_cpp():
    """GNU convention: ``.C`` (uppercase) is C++ source. The
    lowercasing fold routed it to the C grammar, mis-parsing every
    class method."""
    assert detect_language("Signer.C") == "cpp"
    assert detect_language("plain.c") == "c"


def test_cjs_extension_is_javascript():
    assert detect_language("mod.cjs") == "javascript"


@pytest.mark.skipif(not hasattr(__import__("os"), "mkfifo"),
                    reason="POSIX-only FIFO test")
def test_shebang_probe_ignores_fifos(tmp_path):
    """A plain open() of a reader-less FIFO blocks forever; the probe
    runs on every extensionless entry in the main process, so one
    stray pipe wedged the whole inventory build."""
    import os

    from core.inventory.languages import detect_language_from_shebang

    fifo = tmp_path / "apipe"
    os.mkfifo(fifo)
    assert detect_language_from_shebang(str(fifo)) is None


def test_shebang_probe_still_reads_regular_files(tmp_path):
    from core.inventory.languages import detect_language_from_shebang

    script = tmp_path / "deploy"
    script.write_text("#!/usr/bin/env python3\nprint(1)\n")
    assert detect_language_from_shebang(str(script)) == "python"
    other = tmp_path / "run"
    other.write_text("#!/bin/sh\necho hi\n")
    assert detect_language_from_shebang(str(other)) == "shell"


# ---------------------------------------------------------------------------
# Grammar-absent regex fallback (Kotlin fun / paren-less Ruby defs)
# ---------------------------------------------------------------------------


def _force_grammars_absent(monkeypatch):
    """Simulate a host with tree-sitter installed but no grammar
    packages: the loader finds nothing, and the per-thread parser cache
    is emptied so previously-cached parsers can't serve the language."""
    from core.inventory import extractors

    monkeypatch.setattr(extractors, "_ts_language", lambda _lang: None)
    monkeypatch.setattr(extractors._TS_PARSER_LOCAL, "parsers", {},
                        raising=False)


def test_kotlin_fun_extracted_by_regex_fallback(monkeypatch):
    """`fun` was missing from the GenericExtractor keyword alternation,
    so a grammar-less host extracted ZERO functions from Kotlin."""
    from core.inventory.extractors import extract_functions

    _force_grammars_absent(monkeypatch)
    src = (
        'fun greet(name: String): String {\n'
        '    return "hi " + name\n'
        '}\n'
        '\n'
        'private fun main(args: Array<String>) {\n'
        '    println(greet("x"))\n'
        '}\n'
    )
    names = {f.name for f in extract_functions("a.kt", "kotlin", src)}
    assert {"greet", "main"} <= names


def test_ruby_parenless_defs_extracted_by_regex_fallback(monkeypatch):
    """Idiomatic Ruby defines methods without parentheses; the generic
    pattern's mandatory `(` matched none of them."""
    from core.inventory.extractors import extract_functions

    _force_grammars_absent(monkeypatch)
    src = (
        "class Order\n"
        "  def total\n"
        "    @items.sum\n"
        "  end\n"
        "\n"
        "  def self.create\n"
        "  end\n"
        "\n"
        "  def valid?\n"
        "  end\n"
        "\n"
        "  def apply!(coupon)\n"
        "  end\n"
        "end\n"
        "# def commented_out\n"
    )
    names = {f.name for f in extract_functions("a.rb", "ruby", src)}
    assert {"total", "create", "valid?", "apply!"} <= names
    assert "commented_out" not in names


def test_missing_grammar_records_per_language_limitation(
        tmp_path, monkeypatch):
    """A language whose grammar can't load must leave a loud
    per-language note in inventory['limitations'] — previously the only
    signal was the generic tree-sitter-missing line, which never fires
    when tree-sitter itself is importable."""
    _force_grammars_absent(monkeypatch)
    (tmp_path / "app.kt").write_text(
        'fun main() {\n    println("x")\n}\n')
    (tmp_path / "order.rb").write_text("def total\n  1\nend\n")
    out = tmp_path / "out"
    inv = build_inventory(str(tmp_path), output_dir=str(out),
                          parallel=False)

    lims = inv.get("limitations", [])
    assert any(note.startswith("kotlin:") for note in lims), lims
    assert any(note.startswith("ruby:") for note in lims), lims
    # Fallback still extracted the functions themselves.
    assert "main" in _items(inv, "app.kt")
    assert "total" in _items(inv, "order.rb")


def test_no_limitation_note_when_grammar_present(tmp_path):
    """With the grammar importable the note must NOT appear."""
    pytest.importorskip("tree_sitter_ruby")
    (tmp_path / "order.rb").write_text("def total\n  1\nend\n")
    out = tmp_path / "out"
    inv = build_inventory(str(tmp_path), output_dir=str(out),
                          parallel=False)
    assert not any(
        note.startswith("ruby:") for note in inv.get("limitations", []))
