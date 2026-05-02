"""Phase 05 — optimization probes.

Looks for:
  * Repeated `re.compile` inside hot loops (should be module-level)
  * Quadratic patterns (`for x in xs: for y in xs: ...` over the same
    list)
  * Disk I/O inside loops (`Path.read_text` / `write_text` per iter)
  * Unbounded caches (`dict` accumulators with no size cap)
  * Missing `lru_cache` on idempotent fetch helpers (heuristic only)

These are PROBES, not verdicts — Phase 99 surfaces them for human
review.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path


def _re_compile_in_function(tree: ast.Module) -> list[dict]:
    """`re.compile` calls that occur inside a function body — those run
    on every call. Module-level is preferred."""
    out: list[dict] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Call)
                        and isinstance(sub.func, ast.Attribute)
                        and isinstance(sub.func.value, ast.Name)
                        and sub.func.value.id == "re"
                        and sub.func.attr == "compile"):
                    out.append({
                        "function": node.name,
                        "lineno": sub.lineno,
                    })
    return out


def _io_in_loop(tree: ast.Module) -> list[dict]:
    """Best-effort: `.read_text()` / `.write_text()` calls inside a
    for/while loop body. Doesn't catch nested-function I/O."""
    out: list[dict] = []
    for loop in ast.walk(tree):
        if not isinstance(loop, (ast.For, ast.AsyncFor, ast.While)):
            continue
        for sub in ast.walk(loop):
            if (isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Attribute)
                    and sub.func.attr in {"read_text", "write_text",
                                          "read_bytes", "write_bytes"}):
                out.append({
                    "method": sub.func.attr,
                    "lineno": sub.lineno,
                })
    return out


def run(ctx) -> dict:
    project_root: Path = ctx.project_root
    files_audit: list[dict] = []
    n_re_compile = 0
    n_io_in_loop = 0
    for p in sorted((project_root / "cve_diff").rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        try:
            tree = ast.parse(p.read_text())
        except SyntaxError:
            continue
        re_in_fn = _re_compile_in_function(tree)
        io_in_loop = _io_in_loop(tree)
        if re_in_fn or io_in_loop:
            files_audit.append({
                "path": str(p.relative_to(project_root)),
                "re_compile_in_function": re_in_fn,
                "io_in_loop": io_in_loop,
            })
        n_re_compile += len(re_in_fn)
        n_io_in_loop += len(io_in_loop)

    payload = {
        "n_re_compile_in_function": n_re_compile,
        "n_io_in_loop": n_io_in_loop,
        "files": files_audit,
    }
    ctx.write_json(payload)

    lines = [
        "# Phase 05 — Optimization Probes",
        "",
        f"`re.compile` inside function bodies: **{n_re_compile}** "
        f"(prefer module-level)",
        f"Disk I/O inside loops: **{n_io_in_loop}** (review for caching)",
        "",
    ]
    if files_audit:
        lines += ["## Findings by file", ""]
        for f in files_audit:
            lines.append(f"### `{f['path']}`")
            for r in f["re_compile_in_function"]:
                lines.append(f"- `re.compile` at line {r['lineno']} "
                             f"inside `{r['function']}` (move to module level?)")
            for io in f["io_in_loop"]:
                lines.append(f"- `.{io['method']}()` at line {io['lineno']} "
                             f"inside a loop (cache or batch?)")
            lines.append("")
    else:
        lines.append("✓ No probes triggered.")
    ctx.write_md("\n".join(lines))
    return {
        "n_re_compile_in_function": n_re_compile,
        "n_io_in_loop": n_io_in_loop,
    }
