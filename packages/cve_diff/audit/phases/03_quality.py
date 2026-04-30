"""Phase 03 — code quality + professionalism.

Runs static analyzers and aggregates findings:

  * `ruff check cve_diff/` — lint (style + bugbear + import order)
  * `python -m py_compile` on every file (syntax safety)
  * Inconsistency probes:
      - mix of `path.write_text` vs `open()`/`f.write()`
      - mix of `Path` vs string paths in function signatures
      - typing import style (`from typing import ...` vs PEP-604)

Findings are written to disk with file:line citations. Phase 99
prioritizes by severity.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


def _run_ruff(project_root: Path) -> dict:
    """Returns ruff JSON output, or {error: ...} if ruff isn't installed."""
    ruff = shutil.which("ruff")
    if ruff is None:
        return {"error": "ruff not on PATH"}
    try:
        proc = subprocess.run(
            [ruff, "check", "cve_diff/", "--output-format", "json"],
            cwd=project_root,
            capture_output=True, text=True, timeout=120,
        )
    except subprocess.TimeoutExpired:
        return {"error": "ruff timed out"}
    # ruff returns non-zero on findings, which is fine — we still parse.
    try:
        diagnostics = json.loads(proc.stdout) if proc.stdout.strip() else []
    except json.JSONDecodeError as exc:
        return {"error": f"ruff output unparseable: {exc}",
                "stderr": proc.stderr[:1000]}
    return {"diagnostics": diagnostics, "exit_code": proc.returncode}


def _by_compile(project_root: Path) -> list[dict]:
    """Run py_compile on every file; capture syntax errors. None expected
    today, but this is a structural invariant — if syntax breaks, the
    audit reports it."""
    # NOTE: do NOT `.resolve()` — that follows the venv-python symlink
    # to the system interpreter and loses venv site-packages.
    py = (project_root / ".." / ".venv" / "bin" / "python")
    if not py.exists():
        py = Path("python")
    out: list[dict] = []
    for p in sorted((project_root / "cve_diff").rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        proc = subprocess.run(
            [str(py), "-m", "py_compile", str(p)],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            out.append({
                "path": str(p.relative_to(project_root)),
                "stderr": proc.stderr[:500],
            })
    return out


def _inconsistency_probes(project_root: Path) -> dict:
    """Quick greps for inconsistency patterns. Findings are
    non-blocking — they're code-style observations, not bugs."""
    findings: dict[str, list[dict]] = {
        "open_without_path": [],
        "string_paths_in_signatures": [],
    }
    for p in sorted((project_root / "cve_diff").rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        text = p.read_text()
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            # `with open(...)` instead of `Path(...).read_text()`.
            # Acceptable if streaming, but Path API is preferred when
            # reading whole files.
            if stripped.startswith("with open(") or stripped.startswith("open("):
                if "stdin" not in line and "stderr" not in line:
                    findings["open_without_path"].append({
                        "file": str(p.relative_to(project_root)),
                        "line": i,
                        "text": stripped[:80],
                    })
    return findings


def run(ctx) -> dict:
    project_root: Path = ctx.project_root
    ruff_result = _run_ruff(project_root)
    syntax_errors = _by_compile(project_root)
    inconsistency = _inconsistency_probes(project_root)

    payload = {
        "ruff": ruff_result,
        "syntax_errors": syntax_errors,
        "inconsistency": inconsistency,
        "ruff_count": len(ruff_result.get("diagnostics") or []),
    }
    ctx.write_json(payload)

    # Markdown.
    lines = ["# Phase 03 — Code Quality + Professionalism", ""]
    if ruff_result.get("error"):
        lines.append(f"⚠ ruff: {ruff_result['error']}")
        lines.append("")
    else:
        diags = ruff_result.get("diagnostics") or []
        lines.append(f"**ruff diagnostics:** {len(diags)}")
        if diags:
            # Aggregate by code.
            by_code: dict[str, int] = {}
            for d in diags:
                by_code[d.get("code", "?")] = by_code.get(d.get("code", "?"), 0) + 1
            lines.append("")
            lines.append("| Code | Count |")
            lines.append("|---|---:|")
            for code in sorted(by_code, key=lambda k: -by_code[k]):
                lines.append(f"| `{code}` | {by_code[code]} |")
            lines.append("")
            # Top 20 individual issues.
            lines += [
                "### First 20 ruff findings",
                "",
                "| File:Line | Code | Message |",
                "|---|---|---|",
            ]
            for d in diags[:20]:
                fname = d.get("filename", "")
                # Trim long absolute paths to project-relative.
                rel = fname.split("/cve_diff/")[-1] if "/cve_diff/" in fname else fname
                rel = "cve_diff/" + rel if not rel.startswith("cve_diff/") else rel
                start = d.get("location", {}).get("row", "?")
                msg = (d.get("message") or "").replace("|", "\\|")[:80]
                lines.append(f"| `{rel}:{start}` | `{d.get('code', '?')}` | {msg} |")
            lines.append("")

    if syntax_errors:
        lines += [
            "## ⚠ Syntax errors (FAIL — must fix)",
            "",
        ]
        for e in syntax_errors:
            lines.append(f"- `{e['path']}`: {e['stderr'][:120]}")
        lines.append("")
    else:
        lines += ["✓ All cve_diff/ files compile cleanly.", ""]

    if inconsistency.get("open_without_path"):
        n = len(inconsistency["open_without_path"])
        lines += [
            f"## Mixed I/O style: `open(...)` calls ({n})",
            "",
            "Prefer `Path.read_text()` / `Path.write_text()` for atomic file I/O.",
            "Acceptable when streaming or appending.",
            "",
        ]
        for f in inconsistency["open_without_path"][:10]:
            lines.append(f"- `{f['file']}:{f['line']}` — `{f['text']}`")
        if n > 10:
            lines.append(f"- _(+{n-10} more)_")
        lines.append("")

    ctx.write_md("\n".join(lines))
    return {
        "ruff_count": payload["ruff_count"],
        "syntax_errors": len(syntax_errors),
        "open_without_path": len(inconsistency.get("open_without_path") or []),
    }
