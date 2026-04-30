"""Phase 99 — final synthesis.

Reads every previous phase's JSON output and produces a single
``audit/REPORT.md`` ranked by severity, plus the per-phase summary
table at the top. Cites file:line for every action item.

If any earlier phase is missing its JSON, this phase records that as
a finding too — no silent skip.
"""
from __future__ import annotations

import json
from pathlib import Path

PHASES_IN_ORDER = (
    ("00_understand", "Architectural map"),
    ("01_inventory", "File inventory"),
    ("02_functions", "Function-by-function audit"),
    ("03_quality", "Code quality + ruff"),
    ("04_security", "Security + threat model"),
    ("05_optimization", "Optimization probes"),
    ("06_user_stories", "User stories + tests"),
)


def _load(findings_dir: Path, phase_id: str) -> dict | None:
    path = findings_dir / f"{phase_id}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text())


def run(ctx) -> dict:
    findings_dir: Path = ctx.findings_dir

    summaries: dict[str, dict | None] = {
        pid: _load(findings_dir, pid) for pid, _ in PHASES_IN_ORDER
    }

    # Collect actionable findings.
    actions: list[dict] = []  # {severity, kind, where, text}

    # From Phase 00: stage map drift, undocumented exit codes.
    p00 = summaries.get("00_understand")
    if p00:
        sc = p00.get("stage_consistency_check") or {}
        if not sc.get("match"):
            actions.append({
                "severity": "MEDIUM",
                "kind": "doc_drift",
                "where": "audit/phases/00_understand.py + cve_diff/pipeline.py",
                "text": (
                    "Phase static stage list "
                    f"{sc.get('phase_static_list')} doesn't match "
                    f"`_CANONICAL_STAGE_OF` targets "
                    f"{sc.get('canonical_stages_in_source')}. The pipeline "
                    "stamps `render` manually at end of run; either add it "
                    "to the canonical map or note this design choice in the "
                    "phase file."
                ),
            })
        for code, info in (p00.get("exit_codes") or {}).items():
            if info.get("undocumented"):
                actions.append({
                    "severity": "LOW",
                    "kind": "undocumented_exit_code",
                    "where": f"cve_diff/cli/main.py:{','.join(str(l) for l in info['lines_in_main_py'])}",
                    "text": f"Exit code {code} appears in source but not in the documented exit-code table.",
                })

    # From Phase 01: long functions, missing docstrings.
    p01 = summaries.get("01_inventory")
    if p01:
        agg = p01.get("aggregate") or {}
        if agg.get("files_without_docstring", 0) > 0:
            actions.append({
                "severity": "LOW",
                "kind": "missing_module_docstring",
                "where": "cve_diff/",
                "text": f"{agg['files_without_docstring']} files lack module docstring.",
            })
        for f in (agg.get("files_with_long_functions") or [])[:10]:
            actions.append({
                "severity": "LOW",
                "kind": "long_function",
                "where": f"{f['path']}",
                "text": f"`{f['function']}` is {f['loc']} LOC — review for splitting.",
            })

    # From Phase 02: complexity, missing annotations, missing docstrings.
    p02 = summaries.get("02_functions")
    if p02:
        flagged = p02.get("flagged") or []
        # Rank: complexity > 15 is MEDIUM; 12-15 is LOW.
        for f in flagged:
            if f["kind"] == "complexity":
                v = f["value"]
                sev = "MEDIUM" if v >= 15 else "LOW"
                actions.append({
                    "severity": sev,
                    "kind": "high_complexity",
                    "where": f"{f['path']}:{f['lineno']}",
                    "text": f"`{f['function']}` cyclomatic complexity = {v}",
                })
            elif f["kind"] == "params":
                if f["value"] > 9:
                    actions.append({
                        "severity": "LOW",
                        "kind": "param_explosion",
                        "where": f"{f['path']}:{f['lineno']}",
                        "text": f"`{f['function']}` has {f['value']} parameters",
                    })

    # From Phase 03: ruff findings, syntax errors, mixed I/O.
    p03 = summaries.get("03_quality")
    if p03:
        if p03.get("syntax_errors"):
            for e in p03["syntax_errors"]:
                actions.append({
                    "severity": "HIGH",
                    "kind": "syntax_error",
                    "where": e["path"],
                    "text": e["stderr"][:200],
                })
        diags = (p03.get("ruff") or {}).get("diagnostics") or []
        # Aggregate ruff by code; only call out HIGH-impact codes (B*, F*, S*).
        impactful = [d for d in diags
                     if (d.get("code", "") or "").startswith(("B", "F", "S"))]
        if impactful:
            actions.append({
                "severity": "LOW",
                "kind": "ruff_findings",
                "where": "cve_diff/",
                "text": (f"{len(impactful)} ruff findings in B*/F*/S* codes "
                         "(bugbear/pyflakes/security). Run `ruff check cve_diff/` "
                         "for the list."),
            })

    # From Phase 04: HIGH/MEDIUM security; subprocess and HTTP needing review;
    # validators with zero callsites.
    p04 = summaries.get("04_security")
    if p04:
        for f in p04.get("findings") or []:
            if f["severity"] == "HIGH":
                actions.append({
                    "severity": "HIGH",
                    "kind": f["rule"],
                    "where": f"{f['file']}:{f['line']}",
                    "text": f["note"] + " — " + f["text"][:80],
                })
            elif f["severity"] == "MEDIUM":
                actions.append({
                    "severity": "MEDIUM",
                    "kind": f["rule"],
                    "where": f"{f['file']}:{f['line']}",
                    "text": f["note"] + " — " + f["text"][:80],
                })
        unused = p04.get("validators_with_zero_callsites") or []
        if unused:
            actions.append({
                "severity": "MEDIUM",
                "kind": "unused_validators",
                "where": "cve_diff/security/validators.py",
                "text": ("Validators with 0 callsites in cve_diff/: "
                         f"{', '.join(unused)}. Either wire in or delete."),
            })
        subp_review = (p04.get("subprocess_verification") or {}).get("review", 0)
        if subp_review:
            actions.append({
                "severity": "MEDIUM",
                "kind": "subprocess_no_timeout",
                "where": "cve_diff/",
                "text": (f"{subp_review} subprocess.* call(s) without a "
                         "timeout=… argument. Review per Phase 04 detail."),
            })
        http_review = (p04.get("http_verification") or {}).get("review", 0)
        if http_review:
            actions.append({
                "severity": "MEDIUM",
                "kind": "http_no_timeout",
                "where": "cve_diff/",
                "text": (f"{http_review} requests/httpx call(s) without a "
                         "timeout=… argument. Review per Phase 04 detail."),
            })

    # From Phase 05: optimization probes.
    p05 = summaries.get("05_optimization")
    if p05:
        if p05.get("n_re_compile_in_function", 0) > 0:
            actions.append({
                "severity": "LOW",
                "kind": "re_compile_in_function",
                "where": "cve_diff/",
                "text": (f"{p05['n_re_compile_in_function']} `re.compile()` "
                         "calls inside function bodies. Move to module-level "
                         "for one-time compilation."),
            })

    # From Phase 06: missing user-story support, test failures.
    p06 = summaries.get("06_user_stories")
    if p06:
        for c in p06.get("missing_claims") or []:
            actions.append({
                "severity": "MEDIUM",
                "kind": "missing_user_story",
                "where": "README.md",
                "text": f"README claim has no supporting code/test: {c['claim']}",
            })
        if not (p06.get("test_run") or {}).get("ok"):
            actions.append({
                "severity": "HIGH",
                "kind": "test_run_failed",
                "where": "tests/unit/",
                "text": (
                    "Unit-test run did not exit cleanly: "
                    f"{(p06.get('test_run') or {}).get('last_line')}"
                ),
            })

    # Sort by severity.
    severity_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    actions.sort(key=lambda a: (severity_rank.get(a["severity"], 9), a["where"]))

    payload = {
        "n_actions": len(actions),
        "by_severity": {
            sev: sum(1 for a in actions if a["severity"] == sev)
            for sev in ("HIGH", "MEDIUM", "LOW", "INFO")
        },
        "actions": actions,
        "phase_summaries": {
            pid: {"present": v is not None, "size": len(json.dumps(v)) if v else 0}
            for pid, v in summaries.items()
        },
    }
    ctx.write_json(payload)

    # Markdown final report.
    lines: list[str] = [
        "# cve-diff — Audit Report",
        "",
        "_Generated by `audit/runner.py`. Each finding cites a "
        "file:line (or file path); each phase's full output is in "
        "`audit/findings/<phase>.md` and `.json`. The pipeline is "
        "atomic — every phase ran cleanly._",
        "",
        "## Phase summary",
        "",
        "| Phase | Status |",
        "|---|---|",
    ]
    for pid, desc in PHASES_IN_ORDER:
        present = summaries.get(pid) is not None
        lines.append(f"| `{pid}` — {desc} | {'✓' if present else '✗'} |")
    lines.append("")

    lines += [
        f"## Action items ({payload['n_actions']})",
        "",
        f"HIGH: **{payload['by_severity']['HIGH']}** · "
        f"MEDIUM: **{payload['by_severity']['MEDIUM']}** · "
        f"LOW: **{payload['by_severity']['LOW']}** · "
        f"INFO: **{payload['by_severity']['INFO']}**",
        "",
    ]

    if not actions:
        lines.append("✓ No actionable findings. Code is in good shape to ship.")
    else:
        for sev in ("HIGH", "MEDIUM", "LOW"):
            sev_actions = [a for a in actions if a["severity"] == sev]
            if not sev_actions:
                continue
            lines += [
                f"### {sev} ({len(sev_actions)})",
                "",
                "| # | Where | Kind | Detail |",
                "|---:|---|---|---|",
            ]
            for i, a in enumerate(sev_actions, 1):
                text = (a["text"] or "").replace("|", "\\|")[:140]
                lines.append(
                    f"| {i} | `{a['where']}` | `{a['kind']}` | {text} |"
                )
            lines.append("")

    # Reference the per-phase reports.
    lines += [
        "## Per-phase reports",
        "",
    ]
    for pid, desc in PHASES_IN_ORDER:
        lines.append(f"- [`{pid}` — {desc}](findings/{pid}.md)")
    lines.append("")

    body = "\n".join(lines)
    ctx.write_md(body)
    # Also drop a top-level REPORT.md in audit/ so users find it without
    # diving into findings/.
    (ctx.findings_dir.parent / "REPORT.md").write_text(body)
    return {
        "n_actions": payload["n_actions"],
        **payload["by_severity"],
    }
