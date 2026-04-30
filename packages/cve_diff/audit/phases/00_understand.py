"""Phase 00 — architectural map.

Purpose: anchor every later finding against a stable, evidence-backed
description of what the project IS. Reads the project's CLAUDE.md +
README.md + key entry-point docstrings + the published exit-code
table, then derives:

  * package layout (modules + LOC)
  * data flow at the level of "what file calls what file"
  * the 5-stage pipeline contract per ``cve_diff/pipeline.py``
  * exit codes per ``cve_diff/cli/main.py``

Output: ``audit/findings/00_understand.md`` (human) + ``.json``
(machine; later phases query it). All claims here are evidence-cited
back to file:line; later phases verify the evidence still exists.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

# Relative imports break when the runner imports phases/00_understand.py
# by string ("audit.phases.00_understand"). The leading-digit name is
# legal as a module file but Python treats `import audit.phases.00_...`
# as invalid identifier syntax. The runner uses ``importlib.import_module``
# so it works there. For type hints we use string-only forms.


def _walk_python_files(root: Path) -> list[Path]:
    """Every .py under cve_diff/ except __pycache__/."""
    return sorted(
        p for p in (root / "cve_diff").rglob("*.py")
        if "__pycache__" not in p.parts
    )


def _module_name(p: Path, project_root: Path) -> str:
    rel = p.relative_to(project_root).with_suffix("")
    return ".".join(rel.parts)


def _exports(path: Path) -> list[str]:
    """Public symbols (not starting with _) defined at module top-level."""
    try:
        tree = ast.parse(path.read_text())
    except SyntaxError:
        return []
    out: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if not node.name.startswith("_"):
                out.append(node.name)
    return out


def _imports(path: Path, *, package: str = "cve_diff") -> list[str]:
    """Internal `cve_diff.*` imports — useful for the call graph."""
    try:
        tree = ast.parse(path.read_text())
    except SyntaxError:
        return []
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(package):
            out.add(node.module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith(package):
                    out.add(alias.name)
    return sorted(out)


# Pipeline canonical-stage map. Mirrors cve_diff/pipeline.py:_CANONICAL_STAGE_OF.
# Phase 99 will verify both copies stay in sync.
_PIPELINE_STAGES: tuple[str, ...] = (
    "discover", "acquire", "resolve", "diff", "render",
)


# CLI exit codes per cve_diff/cli/main.py. Phase 99 will verify these
# are still in sync with the actual `except` blocks. Code 0 falls off
# the bottom of `run()` (no explicit `typer.Exit(code=0)` call), so it
# won't appear in the source-grep step — that's expected.
_EXIT_CODES: dict[int, str] = {
    0: "success",
    1: "health command — at least one critical service unhealthy",
    4: "UnsupportedSource (closed-source vendor)",
    5: "DiscoveryError (no canonical repo found)",
    6: "AcquisitionError (clone/fetch cascade failed)",
    7: "IdenticalCommitsError (would diff HEAD..HEAD)",
    9: "AnalysisError / LLMCallFailed",
}


def _verify_exit_codes(project_root: Path) -> dict[int, dict]:
    """For each documented exit code, find the `raise typer.Exit(code=N)` in
    cli/main.py and capture the file:line. If a code we documented isn't
    found in the source, that's a finding. Conversely, if the source has
    a `typer.Exit(code=N)` that we didn't document, also a finding."""
    main_py = project_root / "cve_diff" / "cli" / "main.py"
    text = main_py.read_text()
    found: dict[int, list[int]] = {}
    for i, line in enumerate(text.splitlines(), 1):
        m = re.search(r"typer\.Exit\(\s*code\s*=\s*(\d+)\s*\)", line)
        if m:
            code = int(m.group(1))
            found.setdefault(code, []).append(i)
    out: dict[int, dict] = {}
    for code, desc in _EXIT_CODES.items():
        out[code] = {
            "description": desc,
            "lines_in_main_py": found.get(code, []),
            "found_in_source": bool(found.get(code)),
        }
    # Codes in source but not documented:
    for code, lines in found.items():
        if code not in out:
            out[code] = {
                "description": "(undocumented — appears in source only)",
                "lines_in_main_py": lines,
                "found_in_source": True,
                "undocumented": True,
            }
    return out


def _verify_canonical_stages(project_root: Path) -> dict:
    """Pull the actual ``_CANONICAL_STAGE_OF`` map from pipeline.py and
    confirm we've covered every canonical stage in this phase's static
    list."""
    pipe = project_root / "cve_diff" / "pipeline.py"
    text = pipe.read_text()
    m = re.search(
        r"_CANONICAL_STAGE_OF:[^=]*=\s*\{(.*?)\}",
        text, flags=re.DOTALL,
    )
    if not m:
        return {"error": "could not locate _CANONICAL_STAGE_OF in pipeline.py"}
    body = m.group(1)
    pairs = re.findall(r'"([^"]+)"\s*:\s*"([^"]+)"', body)
    targets = sorted({v for _k, v in pairs})
    # `render` is intentionally NOT in `_CANONICAL_STAGE_OF` — pipeline
    # stamps `_stage_status["render"] = {"status": "ok"}` directly at the
    # end of `Pipeline.run`. Same outcome (Stage 5 marker on the trace),
    # different mechanism. The check below treats `render` as a known
    # exception so the audit doesn't false-flag.
    expected_in_emit_map = {"discover", "acquire", "resolve", "diff"}
    actual_in_emit_map = set(targets)
    return {
        "raw_map": dict(pairs),
        "canonical_stages_in_source": targets,
        "phase_static_list": list(_PIPELINE_STAGES),
        "render_stamped_separately": True,
        "match": actual_in_emit_map == expected_in_emit_map,
    }


def run(ctx) -> dict:
    project_root: Path = ctx.project_root
    files = _walk_python_files(project_root)

    inventory: list[dict] = []
    for p in files:
        text = p.read_text()
        loc = sum(1 for ln in text.splitlines() if ln.strip())
        inventory.append({
            "module": _module_name(p, project_root),
            "path": str(p.relative_to(project_root)),
            "loc": loc,
            "exports": _exports(p),
            "imports_internal": _imports(p),
        })

    exit_codes = _verify_exit_codes(project_root)
    stage_check = _verify_canonical_stages(project_root)

    payload = {
        "project_root": str(project_root),
        "n_files": len(inventory),
        "total_loc": sum(f["loc"] for f in inventory),
        "files": inventory,
        "pipeline_stages": list(_PIPELINE_STAGES),
        "stage_consistency_check": stage_check,
        "exit_codes": exit_codes,
    }
    ctx.write_json(payload)

    # Markdown rendering — human-readable map.
    lines: list[str] = [
        "# Phase 00 — Architectural Map",
        "",
        f"Total files: **{payload['n_files']}**  ·  "
        f"Total LOC (non-blank): **{payload['total_loc']}**",
        "",
        "## Pipeline (5 stages)",
        "",
        "Per `cve_diff/pipeline.py::Pipeline.run`:",
        "",
        "```",
        "  " + "  →  ".join(_PIPELINE_STAGES),
        "```",
        "",
    ]
    if stage_check.get("error"):
        lines += [f"⚠ stage-map probe failed: `{stage_check['error']}`", ""]
    elif not stage_check["match"]:
        lines += [
            "⚠ **Drift detected** — phase static list "
            f"`{stage_check['phase_static_list']}` does not match "
            f"`pipeline.py:_CANONICAL_STAGE_OF` targets "
            f"`{stage_check['canonical_stages_in_source']}`.",
            "",
        ]
    else:
        lines += ["✓ Phase static list matches `_CANONICAL_STAGE_OF` in source.", ""]

    lines += [
        "## CLI exit codes",
        "",
        "| Code | Meaning | Source location(s) |",
        "|---:|---|---|",
    ]
    for code in sorted(exit_codes):
        e = exit_codes[code]
        locs = (", ".join(f"main.py:{ln}" for ln in e["lines_in_main_py"])
                or "**MISSING from main.py**")
        lines.append(f"| {code} | {e['description']} | {locs} |")
    lines.append("")

    lines += [
        "## File inventory",
        "",
        "| Module | LOC | Exports |",
        "|---|---:|---|",
    ]
    for f in sorted(inventory, key=lambda x: -x["loc"]):
        ex = ", ".join(f["exports"][:5])
        if len(f["exports"]) > 5:
            ex += f", … (+{len(f['exports']) - 5})"
        lines.append(f"| `{f['module']}` | {f['loc']:>4} | {ex or '_(internal)_'} |")
    lines.append("")

    ctx.write_md("\n".join(lines))
    return {
        "n_files": payload["n_files"],
        "total_loc": payload["total_loc"],
        "stage_check_match": stage_check.get("match"),
        "exit_codes_documented": len([c for c in exit_codes if not exit_codes[c].get("undocumented")]),
        "exit_codes_undocumented": len([c for c in exit_codes if exit_codes[c].get("undocumented")]),
    }
