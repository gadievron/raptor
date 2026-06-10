"""Phase 8 substrate spike — tree-sitter prototype.

Walks ``fixture.c`` and prints, per function, the (defs, uses,
call_sites) extraction. The point isn't production code — it's
evidence the chosen substrate can recover what Phase 9 needs.

Run via the repo venv (which has tree_sitter_c installed):

    .venv/bin/python docs/phase-8-substrate-spike/prototype_tree_sitter.py

The output gets pinned in the decision doc as the "measurement" half
of the spike. Hand-compare the extraction against ``fixture.c`` to
score def/use accuracy.
"""
from __future__ import annotations

import time
from pathlib import Path

import tree_sitter_c
from tree_sitter import Language, Parser


_FIXTURE = Path(__file__).with_name("fixture.c")


def _build_parser() -> Parser:
    lang = Language(tree_sitter_c.language())
    return Parser(lang)


# ---------------------------------------------------------------------------
# AST walks — defs, uses, call_sites per function definition
# ---------------------------------------------------------------------------


def _function_name(fn_node) -> str | None:
    """Pull the function identifier out of a function_definition."""
    decl = fn_node.child_by_field_name("declarator")
    while decl is not None:
        if decl.type == "function_declarator":
            ident = decl.child_by_field_name("declarator")
            if ident is not None and ident.type == "identifier":
                return ident.text.decode()
            return None
        decl = decl.child_by_field_name("declarator")
    return None


def _walk_function(fn_node):
    """Yield (kind, name, lineno) tuples for every interesting symbol
    interaction inside the function body."""
    body = fn_node.child_by_field_name("body")
    if body is None:
        return
    stack = [body]
    while stack:
        n = stack.pop()
        t = n.type
        # init_declarator: ``const char *y = escape_html(x);`` —
        # the ``y`` identifier is a def, the RHS is a use.
        if t == "init_declarator":
            tgt = n.child_by_field_name("declarator")
            tgt_name = _innermost_ident(tgt) if tgt else None
            if tgt_name:
                yield ("def", tgt_name, n.start_point[0] + 1)
            val = n.child_by_field_name("value")
            if val is not None:
                yield from _walk_uses_and_calls(val)
        # assignment_expression: ``out = escape_html(x);``
        elif t == "assignment_expression":
            lhs = n.child_by_field_name("left")
            lhs_name = _innermost_ident(lhs) if lhs else None
            if lhs_name:
                yield ("def", lhs_name, n.start_point[0] + 1)
            rhs = n.child_by_field_name("right")
            if rhs is not None:
                yield from _walk_uses_and_calls(rhs)
        # call_expression at statement position: ``render(y);``
        elif t == "call_expression":
            yield from _walk_uses_and_calls(n)
            continue                                # already descended
        for child in n.children:
            stack.append(child)


def _walk_uses_and_calls(n):
    """Yield ``use``/``call_site`` tuples from an expression subtree."""
    stack = [n]
    while stack:
        cur = stack.pop()
        t = cur.type
        if t == "call_expression":
            callee = cur.child_by_field_name("function")
            callee_name = _innermost_ident(callee) if callee else None
            arg_list = cur.child_by_field_name("arguments")
            arg_names = []
            if arg_list is not None:
                for arg in arg_list.children:
                    if arg.is_named:
                        arg_names.append(_innermost_ident(arg) or "<expr>")
            if callee_name:
                yield ("call_site", callee_name,
                       cur.start_point[0] + 1, tuple(arg_names))
            # descend into arguments so nested uses register
            if arg_list is not None:
                stack.append(arg_list)
        elif t == "identifier":
            yield ("use", cur.text.decode(), cur.start_point[0] + 1)
        else:
            for c in cur.children:
                stack.append(c)


def _innermost_ident(n):
    """Return the leftmost identifier under ``n`` (handles pointer
    declarators, field expressions, parens)."""
    if n is None:
        return None
    if n.type == "identifier":
        return n.text.decode()
    for child in n.children:
        r = _innermost_ident(child)
        if r is not None:
            return r
    return None


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def main() -> int:
    src = _FIXTURE.read_text(encoding="utf-8")
    parser = _build_parser()

    t0 = time.perf_counter()
    tree = parser.parse(src.encode("utf-8"))
    parse_ms = (time.perf_counter() - t0) * 1000

    # Count nodes the brute-force way to feed the "node count" metric.
    node_count = 0
    stack = [tree.root_node]
    while stack:
        cur = stack.pop()
        node_count += 1
        stack.extend(cur.children)

    print(f"# Phase 8 spike — tree-sitter on {_FIXTURE.name}")
    print(f"parse_ms: {parse_ms:.2f}")
    print(f"node_count: {node_count}")
    print(f"has_errors: {tree.root_node.has_error}")
    print()

    # Walk top-level for function definitions.
    for child in tree.root_node.children:
        if child.type != "function_definition":
            continue
        name = _function_name(child) or "<anon>"
        print(f"## fn {name}  (lines {child.start_point[0]+1}-"
              f"{child.end_point[0]+1})")
        defs, uses, calls = [], [], []
        for kind, *rest in _walk_function(child):
            if kind == "def":
                defs.append(rest)
            elif kind == "use":
                uses.append(rest)
            elif kind == "call_site":
                calls.append(rest)
        print(f"  defs       ({len(defs)}): {defs}")
        print(f"  uses       ({len(uses)}): {uses}")
        print(f"  call_sites ({len(calls)}): {calls}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
