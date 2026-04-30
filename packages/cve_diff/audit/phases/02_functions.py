"""Phase 02 — function-by-function audit on critical-path files.

Walks each function in the critical-path files via AST, computes
cyclomatic complexity (decision points), counts arguments, checks for:

  * docstring presence
  * type-annotated args + return
  * complexity > 10 (refactor candidate)
  * argument count > 7 (parameter-explosion smell)
  * return-type mismatch in pyright/mypy is out of scope here

Critical-path files: pipeline.py, agent/loop.py, agent/invariants.py,
agent/tools.py, diffing/extractor.py, diffing/extract_via_*.py,
diffing/extraction_agreement.py, cli/main.py, cli/bench.py,
report/markdown.py, report/flow.py, security/validators.py.
"""
from __future__ import annotations

import ast
from pathlib import Path

CRITICAL_PATHS: tuple[str, ...] = (
    "cve_diff/pipeline.py",
    "cve_diff/agent/loop.py",
    "cve_diff/agent/invariants.py",
    "cve_diff/agent/tools.py",
    "cve_diff/agent/source_classes.py",
    "cve_diff/diffing/extractor.py",
    "cve_diff/diffing/extract_via_api.py",
    "cve_diff/diffing/extract_via_gitlab_api.py",
    "cve_diff/diffing/extract_via_patch_url.py",
    "cve_diff/diffing/extraction_agreement.py",
    "cve_diff/diffing/commit_resolver.py",
    "cve_diff/acquisition/layers.py",
    "cve_diff/cli/main.py",
    "cve_diff/cli/bench.py",
    "cve_diff/report/markdown.py",
    "cve_diff/report/flow.py",
    "cve_diff/report/consensus.py",
    "cve_diff/report/osv_schema.py",
    "cve_diff/security/validators.py",
)


_DECISION_NODES = (
    ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp,
    ast.With, ast.AsyncWith, ast.Try, ast.Match, ast.ExceptHandler,
    ast.BoolOp,  # and/or short-circuits add branches
)


def _complexity(fn: ast.AST) -> int:
    """Approximate cyclomatic complexity: 1 + count of decision points."""
    n = 1
    for node in ast.walk(fn):
        if isinstance(node, _DECISION_NODES):
            n += 1
    return n


def _audit_function(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> dict:
    args = [a for a in fn.args.args if a.arg not in {"self", "cls"}]
    args += [a for a in fn.args.kwonlyargs]
    end_line = getattr(fn, "end_lineno", fn.lineno)
    annotated = sum(1 for a in args if a.annotation is not None)
    return {
        "name": fn.name,
        "lineno": fn.lineno,
        "loc": (end_line - fn.lineno) + 1,
        "complexity": _complexity(fn),
        "n_args": len(args),
        "annotated_args": annotated,
        "has_return_type": fn.returns is not None,
        "has_docstring": ast.get_docstring(fn) is not None,
        "is_public": not fn.name.startswith("_"),
    }


def run(ctx) -> dict:
    project_root: Path = ctx.project_root
    out_files: list[dict] = []
    flagged: list[dict] = []

    for rel in CRITICAL_PATHS:
        p = project_root / rel
        if not p.exists():
            out_files.append({"path": rel, "missing": True, "functions": []})
            continue
        text = p.read_text()
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            out_files.append({"path": rel, "syntax_error": str(exc), "functions": []})
            continue

        funcs: list[dict] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                rec = _audit_function(node)
                rec["path"] = rel
                funcs.append(rec)
                # Flag the worst offenders.
                if rec["complexity"] > 12:
                    flagged.append({
                        "kind": "complexity",
                        "path": rel,
                        "function": rec["name"],
                        "lineno": rec["lineno"],
                        "value": rec["complexity"],
                    })
                if rec["loc"] > 80:
                    flagged.append({
                        "kind": "length",
                        "path": rel,
                        "function": rec["name"],
                        "lineno": rec["lineno"],
                        "value": rec["loc"],
                    })
                if rec["n_args"] > 7:
                    flagged.append({
                        "kind": "params",
                        "path": rel,
                        "function": rec["name"],
                        "lineno": rec["lineno"],
                        "value": rec["n_args"],
                    })
                if rec["is_public"] and not rec["has_docstring"]:
                    flagged.append({
                        "kind": "no_docstring",
                        "path": rel,
                        "function": rec["name"],
                        "lineno": rec["lineno"],
                    })
                if rec["is_public"] and (
                    not rec["has_return_type"]
                    or rec["annotated_args"] < rec["n_args"]
                ):
                    flagged.append({
                        "kind": "missing_annotations",
                        "path": rel,
                        "function": rec["name"],
                        "lineno": rec["lineno"],
                    })
        out_files.append({"path": rel, "functions": funcs})

    aggregate = {
        "n_files_audited": len(out_files),
        "n_functions_audited": sum(len(f.get("functions", [])) for f in out_files),
        "flagged_count": len(flagged),
        "by_kind": {},
    }
    for f in flagged:
        aggregate["by_kind"].setdefault(f["kind"], 0)
        aggregate["by_kind"][f["kind"]] += 1

    ctx.write_json({
        "aggregate": aggregate,
        "files": out_files,
        "flagged": flagged,
    })

    # Markdown.
    lines = [
        "# Phase 02 — Function-by-function audit",
        "",
        f"Files audited: **{aggregate['n_files_audited']}**, "
        f"functions audited: **{aggregate['n_functions_audited']}**, "
        f"flagged: **{aggregate['flagged_count']}**",
        "",
        "## Flag breakdown",
        "",
        "| Kind | Count |",
        "|---|---:|",
    ]
    for kind in sorted(aggregate["by_kind"], key=lambda k: -aggregate["by_kind"][k]):
        lines.append(f"| `{kind}` | {aggregate['by_kind'][kind]} |")
    lines.append("")

    # Top complexity offenders.
    by_complex = sorted(
        [f for f in flagged if f["kind"] == "complexity"],
        key=lambda x: -x["value"],
    )[:10]
    if by_complex:
        lines += [
            "## Highest cyclomatic complexity (top 10)",
            "",
            "| Function | File:Line | Complexity |",
            "|---|---|---:|",
        ]
        for f in by_complex:
            lines.append(
                f"| `{f['function']}` | `{f['path']}:{f['lineno']}` | "
                f"{f['value']} |"
            )
        lines.append("")

    # Top length offenders.
    by_len = sorted(
        [f for f in flagged if f["kind"] == "length"],
        key=lambda x: -x["value"],
    )[:10]
    if by_len:
        lines += [
            "## Longest functions (top 10, > 80 LOC)",
            "",
            "| Function | File:Line | LOC |",
            "|---|---|---:|",
        ]
        for f in by_len:
            lines.append(
                f"| `{f['function']}` | `{f['path']}:{f['lineno']}` | "
                f"{f['value']} |"
            )
        lines.append("")

    # Public missing docstring or annotations.
    no_doc = [f for f in flagged if f["kind"] == "no_docstring"]
    no_ann = [f for f in flagged if f["kind"] == "missing_annotations"]
    if no_doc:
        lines += [
            f"## Public functions missing docstring ({len(no_doc)})",
            "",
        ]
        lines += [f"- `{f['function']}` at `{f['path']}:{f['lineno']}`"
                  for f in no_doc[:20]]
        if len(no_doc) > 20:
            lines.append(f"- _(+{len(no_doc) - 20} more)_")
        lines.append("")
    if no_ann:
        lines += [
            f"## Public functions with incomplete type annotations ({len(no_ann)})",
            "",
        ]
        lines += [f"- `{f['function']}` at `{f['path']}:{f['lineno']}`"
                  for f in no_ann[:20]]
        if len(no_ann) > 20:
            lines.append(f"- _(+{len(no_ann) - 20} more)_")
        lines.append("")

    ctx.write_md("\n".join(lines))
    return {
        "n_files_audited": aggregate["n_files_audited"],
        "n_functions_audited": aggregate["n_functions_audited"],
        "flagged_count": aggregate["flagged_count"],
    }
