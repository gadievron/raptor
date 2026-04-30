"""Phase 01 — file-by-file inventory.

Walks every .py in `cve_diff/` and records:

  * docstring presence (module-level)
  * function/class count, longest function (LOC)
  * type-annotated public-function ratio
  * `# noqa`, `# type: ignore`, `# TODO`, `# FIXME`, `# XXX` counts
  * bare `except Exception` count + `except: pass` count
  * `print(` and `eval(` and `exec(` and `os.system` calls (smell)
  * subprocess usage (any `subprocess.` symbol)

These are FACTS — every count is computed, file:line for every smell
is captured. Phase 99 surfaces the top offenders.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path


# Patterns we flag with file:line. Each one a tuple
# (label, regex). Regex is line-oriented (matched against full lines).
_LINE_PATTERNS: dict[str, re.Pattern[str]] = {
    "noqa": re.compile(r"#\s*noqa\b"),
    "type_ignore": re.compile(r"#\s*type:\s*ignore"),
    "TODO": re.compile(r"#\s*TODO\b", re.IGNORECASE),
    "FIXME": re.compile(r"#\s*FIXME\b", re.IGNORECASE),
    "XXX": re.compile(r"#\s*XXX\b"),
    "HACK": re.compile(r"#\s*HACK\b", re.IGNORECASE),
    "bare_except": re.compile(r"^\s*except\s*:"),
    "except_exception": re.compile(r"except\s+Exception"),
    "print_call": re.compile(r"\bprint\s*\("),
    "eval_call": re.compile(r"\beval\s*\("),
    "exec_call": re.compile(r"\bexec\s*\("),
    "os_system": re.compile(r"\bos\.system\s*\("),
    "shell_true": re.compile(r"shell\s*=\s*True"),
}


def _func_metrics(tree: ast.Module) -> dict:
    """Count functions, find the longest, measure type-annotation ratio
    on public functions."""
    funcs: list[ast.FunctionDef] = []
    classes = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.append(node)
        elif isinstance(node, ast.ClassDef):
            classes += 1

    longest_loc = 0
    longest_name = ""
    for fn in funcs:
        end_line = getattr(fn, "end_lineno", fn.lineno)
        loc = (end_line - fn.lineno) + 1
        if loc > longest_loc:
            longest_loc = loc
            longest_name = fn.name

    public_funcs = [f for f in funcs if not f.name.startswith("_")]
    annotated = 0
    for fn in public_funcs:
        # Counts as annotated if return type annotated AND every non-self
        # arg is annotated.
        args = [a for a in fn.args.args if a.arg not in {"self", "cls"}]
        all_args_annotated = all(a.annotation is not None for a in args)
        if fn.returns is not None and all_args_annotated:
            annotated += 1

    return {
        "n_functions": len(funcs),
        "n_classes": classes,
        "longest_function_loc": longest_loc,
        "longest_function_name": longest_name,
        "public_functions": len(public_funcs),
        "annotated_public": annotated,
    }


def _line_smells(text: str) -> dict[str, list[int]]:
    """Find line numbers for each smell pattern."""
    found: dict[str, list[int]] = {label: [] for label in _LINE_PATTERNS}
    for i, line in enumerate(text.splitlines(), 1):
        for label, pat in _LINE_PATTERNS.items():
            if pat.search(line):
                found[label].append(i)
    return found


def run(ctx) -> dict:
    project_root = ctx.project_root
    inventory = []
    for p in sorted((project_root / "cve_diff").rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        text = p.read_text()
        try:
            tree = ast.parse(text)
            module_doc = ast.get_docstring(tree)
        except SyntaxError:
            tree = None
            module_doc = None

        smells = _line_smells(text)
        record = {
            "path": str(p.relative_to(project_root)),
            "loc": sum(1 for ln in text.splitlines() if ln.strip()),
            "has_module_docstring": bool(module_doc),
            "smells": smells,
            "smells_total": sum(len(v) for v in smells.values()),
        }
        if tree is not None:
            record.update(_func_metrics(tree))
        inventory.append(record)

    # Aggregate.
    # Empty / re-export-only `__init__.py` files don't need a docstring
    # by Python convention; exempt them from the count so the audit
    # focuses on real modules.
    def _needs_docstring(f: dict) -> bool:
        if f["has_module_docstring"]:
            return False
        path = Path(f["path"])
        if path.name == "__init__.py" and f["loc"] <= 25:
            return False
        return True

    aggregate: dict = {
        "n_files": len(inventory),
        "files_without_docstring": sum(
            1 for f in inventory if _needs_docstring(f)
        ),
        "smells_total": sum(f["smells_total"] for f in inventory),
        "smells_by_label": {},
        "longest_function_overall": max(
            (
                (f.get("longest_function_loc", 0), f.get("longest_function_name", ""), f["path"])
                for f in inventory
            ),
            default=(0, "", ""),
        ),
        "files_with_long_functions": [],
    }
    for f in inventory:
        for label, lines in f["smells"].items():
            aggregate["smells_by_label"].setdefault(label, 0)
            aggregate["smells_by_label"][label] += len(lines)
        if f.get("longest_function_loc", 0) > 80:
            aggregate["files_with_long_functions"].append({
                "path": f["path"],
                "function": f.get("longest_function_name"),
                "loc": f["longest_function_loc"],
            })

    ctx.write_json({"aggregate": aggregate, "files": inventory})

    # Markdown rendering.
    lines = [
        "# Phase 01 — File Inventory",
        "",
        f"Files: **{aggregate['n_files']}**, "
        f"missing module docstring: **{aggregate['files_without_docstring']}**",
        "",
        "## Smells (counts across project)",
        "",
        "| Pattern | Count |",
        "|---|---:|",
    ]
    for label in sorted(aggregate["smells_by_label"], key=lambda k: -aggregate["smells_by_label"][k]):
        lines.append(f"| `{label}` | {aggregate['smells_by_label'][label]} |")
    lines.append("")

    lines += [
        "## Functions over 80 LOC (review for splitting)",
        "",
    ]
    if not aggregate["files_with_long_functions"]:
        lines.append("_(none — all functions ≤ 80 LOC)_")
    else:
        lines += ["| File | Function | LOC |", "|---|---|---:|"]
        for f in sorted(aggregate["files_with_long_functions"],
                        key=lambda x: -x["loc"]):
            lines.append(f"| `{f['path']}` | `{f['function']}` | {f['loc']} |")
    lines.append("")

    longest = aggregate["longest_function_overall"]
    if longest[0]:
        lines += [
            f"### Longest function in project",
            f"`{longest[1]}` in `{longest[2]}` — **{longest[0]} LOC**",
            "",
        ]

    lines += [
        "## Per-file detail",
        "",
        "| File | LOC | Funcs | Public | Annotated | Doc | Smells |",
        "|---|---:|---:|---:|---:|---|---:|",
    ]
    for f in sorted(inventory, key=lambda x: -x["loc"]):
        doc = "✓" if f["has_module_docstring"] else "✗"
        ratio = (
            f"{f.get('annotated_public', 0)}/{f.get('public_functions', 0)}"
            if f.get("public_functions") else "-"
        )
        lines.append(
            f"| `{f['path']}` | {f['loc']:>4} | "
            f"{f.get('n_functions', 0):>3} | {f.get('public_functions', 0):>3} | "
            f"{ratio} | {doc} | {f['smells_total']} |"
        )
    lines.append("")

    ctx.write_md("\n".join(lines))
    return {
        "n_files": aggregate["n_files"],
        "smells_total": aggregate["smells_total"],
        "long_functions": len(aggregate["files_with_long_functions"]),
        "files_no_docstring": aggregate["files_without_docstring"],
    }
