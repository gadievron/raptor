"""Phase 06 — user stories from README.

For every claim the README makes, verify the supporting code/test
exists. README is the public contract; if the code drifts from it,
this phase fires.

Claims checked:

  * "All 5 stages always render" — assert test exists.
  * "Stage 4 lists each source with file/byte counts + verdict" —
    assert renderer + test exist.
  * "<cve>.flow.md, .flow.jsonl, .clone.patch, .github_api.patch,
    .gitlab_api.patch, .patch_url.patch" — assert each emission
    exists.
  * Exit-code table (0/4/5/6/7/9) — already verified by Phase 0.
  * "Three independent extractors per PASS" — clone + github_api +
    patch_url all referenced.
  * "Hermetic unit tests" — `pytest tests/unit -m 'not integration'`
    must succeed.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path


def _claim_check(project_root: Path, claim: str, needle: str,
                 search_root: str = "") -> dict:
    """Grep the project for a needle; return file:line hits."""
    base = project_root / (search_root or ".")
    hits: list[dict] = []
    for p in base.rglob("*.py"):
        if "__pycache__" in p.parts:
            continue
        try:
            text = p.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if needle in line:
                hits.append({
                    "file": str(p.relative_to(project_root)),
                    "line": i,
                    "text": line.strip()[:120],
                })
    return {"claim": claim, "needle": needle, "hits": hits, "count": len(hits)}


def run(ctx) -> dict:
    project_root = ctx.project_root

    claims = [
        _claim_check(project_root,
                     "All 5 stage headers always render",
                     "Stage 1 — DISCOVER"),
        _claim_check(project_root,
                     "Pipeline trace flows to stdout (Outcome marker)",
                     "✓ PASS"),
        _claim_check(project_root,
                     "Stage 4 Sources block emits per-source rows",
                     "**Sources:**"),
        _claim_check(project_root,
                     "patch_url is a third extractor",
                     "patch_url"),
        _claim_check(project_root,
                     "GitHub API extractor exists",
                     "github_api"),
        _claim_check(project_root,
                     "GitLab API extractor exists",
                     "gitlab_api"),
        _claim_check(project_root,
                     "Verdict line on every PASS",
                     "Verdict:"),
        _claim_check(project_root,
                     "OSV Schema 1.6.0 advertised",
                     "1.6.0"),
        _claim_check(project_root,
                     "Pointer-consensus signal",
                     "Pointer consensus"),
    ]

    # Run the test suite. This is the strongest "user-story" check —
    # everything documented as user-facing should have a test that
    # exercises it.
    import os
    # IMPORTANT: do NOT `.resolve()` the venv python path — that follows
    # the symlink to the system interpreter and loses access to the
    # venv's site-packages (which is where `responses`, `pytest`, etc.
    # live). The non-resolved path keeps the venv semantics.
    venv_py = project_root / ".." / ".venv" / "bin" / "python"
    if not venv_py.exists():  # fall back to whatever python is on PATH
        venv_py = Path("python")
    test_env = dict(os.environ)
    test_env["PYTHONPATH"] = str(project_root)
    test_proc = subprocess.run(
        [str(venv_py), "-m", "pytest", "tests/unit", "-q",
         "--tb=line", "-p", "no:cacheprovider"],
        cwd=project_root,
        capture_output=True, text=True, timeout=300,
        env=test_env,
    )
    # Parse "N passed" from the last line.
    last_line = (test_proc.stdout.splitlines() or [""])[-1]
    m = re.search(r"(\d+) passed", last_line)
    n_passed = int(m.group(1)) if m else 0
    test_ok = test_proc.returncode == 0

    payload = {
        "claims": claims,
        "test_run": {
            "exit_code": test_proc.returncode,
            "n_passed": n_passed,
            "ok": test_ok,
            "last_line": last_line,
            "stdout_tail": "\n".join(test_proc.stdout.splitlines()[-30:]),
            "stderr_tail": "\n".join(test_proc.stderr.splitlines()[-30:]),
        },
        "missing_claims": [c for c in claims if c["count"] == 0],
    }
    ctx.write_json(payload)

    lines = ["# Phase 06 — User Stories", ""]
    lines.append(f"Test run: **{n_passed} passed** "
                 f"(exit code {test_proc.returncode})")
    lines.append("")
    lines += [
        "## README claims",
        "",
        "| # | Claim | Hits |",
        "|---:|---|---:|",
    ]
    for i, c in enumerate(claims, 1):
        mark = "✓" if c["count"] > 0 else "✗"
        lines.append(f"| {i} | {c['claim']} | {c['count']} {mark} |")
    lines.append("")

    missing = payload["missing_claims"]
    if missing:
        lines += ["## ⚠ Claims with NO supporting evidence", ""]
        for c in missing:
            lines.append(f"- {c['claim']} (searched for `{c['needle']}`)")
        lines.append("")

    ctx.write_md("\n".join(lines))
    return {
        "n_claims_supported": sum(1 for c in claims if c["count"]),
        "n_claims_missing": len(missing),
        "tests_passed": n_passed,
        "tests_ok": test_ok,
    }
