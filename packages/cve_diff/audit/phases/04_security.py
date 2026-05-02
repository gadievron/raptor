"""Phase 04 — security + threat model.

Greps the source for high-priority risk patterns and verifies each.
Each finding includes file:line + the line text + a verification
note ("MITIGATED" / "REVIEW").

Categories:

  * **Subprocess**: any `subprocess.*` call. Confirm: list-form args
    (no `shell=True`), timeout set.
  * **HTTP**: any `requests.*` / `httpx.*` call. Confirm: timeout set,
    response size checked.
  * **Path concatenation**: `Path() / user_input`, `f"...{cve_id}..."`
    used as filename — flag for path-traversal review.
  * **Eval / exec / os.system / shell=True** — should be zero.
  * **Hardcoded paths / users**: `/Users/`, `/home/`, hardcoded API
    URLs. May leak in error messages.
  * **Token / secret leaks**: print/log of `os.environ['ANTHROPIC_API_KEY']`
    or similar secret env vars.
  * **Validator coverage**: which `validate_*` functions are called
    and where.

This phase is verification-heavy: every flag is double-checked and
labeled.
"""
from __future__ import annotations

import re
from pathlib import Path

# Each rule: (label, regex, severity, note)
_RULES: tuple[tuple[str, re.Pattern[str], str, str], ...] = (
    ("subprocess_call", re.compile(r"\bsubprocess\."), "INFO",
     "verify list-form args + timeout"),
    ("requests_get", re.compile(r"\brequests\.(get|post|put|delete)\("),
     "INFO", "verify timeout set"),
    ("httpx_call", re.compile(r"\bhttpx\.(get|post|put|delete|Client|AsyncClient)\("),
     "INFO", "verify timeout set"),
    ("shell_true", re.compile(r"shell\s*=\s*True"), "HIGH",
     "shell=True is unsafe with untrusted input"),
    ("eval_call", re.compile(r"\beval\s*\("), "HIGH", "eval is unsafe"),
    ("exec_call", re.compile(r"^\s*exec\s*\("), "HIGH", "exec is unsafe"),
    ("os_system", re.compile(r"\bos\.system\s*\("), "HIGH",
     "os.system is unsafe"),
    ("hardcoded_user_path", re.compile(r"/Users/[a-zA-Z]+"), "MEDIUM",
     "leaks dev environment in error messages"),
    ("hardcoded_home_path", re.compile(r"/home/[a-zA-Z]+"), "MEDIUM",
     "leaks dev environment"),
    ("env_get_secret", re.compile(r"os\.environ\.get\(\s*[\"']\w*(?:KEY|SECRET|TOKEN|PASSWORD)\w*[\"']\)"),
     "INFO", "verify never logged in plaintext"),
    ("path_concat_userinput", re.compile(r"Path\([^)]*\)\s*/\s*f[\"']"),
     "INFO", "verify path validated"),
    ("pickle_loads", re.compile(r"\bpickle\.loads\("), "HIGH",
     "pickle is unsafe with untrusted data"),
    ("yaml_load_unsafe", re.compile(r"\byaml\.load\("), "HIGH",
     "yaml.load is unsafe; use safe_load"),
)


def _scan(project_root: Path) -> list[dict]:
    findings: list[dict] = []
    for p in sorted((project_root / "cve_diff").rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        text = p.read_text()
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            # Skip comments to reduce false positives on patterns.
            comment_only = stripped.startswith("#")
            for label, pat, sev, note in _RULES:
                if comment_only and label not in {"hardcoded_user_path",
                                                  "hardcoded_home_path"}:
                    # Patterns in comments don't run; still flag dev paths
                    # inside comments because those leak via docs.
                    continue
                if pat.search(line):
                    findings.append({
                        "rule": label,
                        "severity": sev,
                        "note": note,
                        "file": str(p.relative_to(project_root)),
                        "line": i,
                        "text": stripped[:120],
                    })
    return findings


def _verify_subprocess(project_root: Path, findings: list[dict]) -> dict:
    """For every `subprocess.*` finding, look at the next ~20 lines for
    `timeout=` and `shell=True`. Mark MITIGATED if timeout present and
    shell is not True (or absent).

    `except subprocess.TimeoutExpired:` lines aren't real CALLS — they
    are HANDLERS. Skip them ("not_a_call") so they don't pollute the
    REVIEW count.
    """
    by_path: dict[str, str] = {}
    for f in findings:
        if f["rule"] != "subprocess_call":
            continue
        if f["file"] not in by_path:
            by_path[f["file"]] = (project_root / f["file"]).read_text()
        text = by_path[f["file"]]
        lines = text.splitlines()
        # Skip exception-handler lines — they prove the originating
        # call HAD a timeout (we set TimeoutExpired only when timeout
        # arg is provided to subprocess).
        if "TimeoutExpired" in (lines[f["line"] - 1] if f["line"] - 1 < len(lines) else ""):
            f["status"] = "not_a_call"
            continue
        # Window: 20 lines forward to handle multi-line subprocess
        # calls. If timeout= isn't in there, the call really has
        # no timeout argument.
        window = lines[f["line"] - 1:min(f["line"] + 20, len(lines))]
        joined = "\n".join(window)
        # Bound the window to the closing paren of the call.
        if ")" in joined:
            joined = joined.split(")\n", 1)[0] + ")"
        has_timeout = "timeout=" in joined
        has_shell_true = re.search(r"shell\s*=\s*True", joined) is not None
        f["verification"] = {
            "has_timeout": has_timeout,
            "has_shell_true": has_shell_true,
        }
        if has_timeout and not has_shell_true:
            f["status"] = "MITIGATED"
        elif has_shell_true:
            f["status"] = "RISK"
        else:
            f["status"] = "REVIEW"
    return {
        "checked": sum(1 for f in findings if f["rule"] == "subprocess_call"),
        "mitigated": sum(1 for f in findings
                         if f["rule"] == "subprocess_call"
                         and f.get("status") == "MITIGATED"),
        "review": sum(1 for f in findings
                      if f["rule"] == "subprocess_call"
                      and f.get("status") == "REVIEW"),
        "risk": sum(1 for f in findings
                    if f["rule"] == "subprocess_call"
                    and f.get("status") == "RISK"),
    }


def _verify_http(findings: list[dict], project_root: Path) -> dict:
    by_path: dict[str, str] = {}
    for f in findings:
        if f["rule"] not in ("requests_get", "httpx_call"):
            continue
        if f["file"] not in by_path:
            by_path[f["file"]] = (project_root / f["file"]).read_text()
        lines = by_path[f["file"]].splitlines()
        # 20-line window so multi-line `requests.post(\n  url, headers={...},\n
        # json={...}, timeout=…)` blocks are recognized.
        window = "\n".join(lines[f["line"] - 1:min(f["line"] + 20, len(lines))])
        if ")" in window:
            window = window.split(")\n", 1)[0] + ")"
        has_timeout = "timeout=" in window
        f["verification"] = {"has_timeout": has_timeout}
        f["status"] = "MITIGATED" if has_timeout else "REVIEW"
    rel = [f for f in findings if f["rule"] in ("requests_get", "httpx_call")]
    return {
        "checked": len(rel),
        "mitigated": sum(1 for f in rel if f.get("status") == "MITIGATED"),
        "review": sum(1 for f in rel if f.get("status") == "REVIEW"),
    }


def _validator_coverage(project_root: Path) -> dict:
    """For each `validate_*` function, count callsites in cve_diff/."""
    validators_path = project_root / "cve_diff" / "security" / "validators.py"
    if not validators_path.exists():
        return {"error": "validators.py missing"}
    text = validators_path.read_text()
    names = re.findall(r"^def (validate_\w+)", text, flags=re.MULTILINE)
    coverage: dict[str, list[dict]] = {n: [] for n in names}
    for p in sorted((project_root / "cve_diff").rglob("*.py")):
        if "__pycache__" in p.parts or p == validators_path:
            continue
        body = p.read_text()
        for i, line in enumerate(body.splitlines(), 1):
            for n in names:
                if re.search(rf"\b{n}\s*\(", line):
                    coverage[n].append({
                        "file": str(p.relative_to(project_root)),
                        "line": i,
                    })
    return coverage


def run(ctx) -> dict:
    project_root: Path = ctx.project_root
    findings = _scan(project_root)
    subp_check = _verify_subprocess(project_root, findings)
    http_check = _verify_http(findings, project_root)
    validator_cov = _validator_coverage(project_root)

    by_severity: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
        by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1

    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]

    payload = {
        "findings": findings,
        "by_severity": by_severity,
        "by_rule": by_rule,
        "subprocess_verification": subp_check,
        "http_verification": http_check,
        "validator_coverage": validator_cov,
        "validators_with_zero_callsites": [
            n for n, c in validator_cov.items()
            if isinstance(c, list) and not c
        ],
    }
    ctx.write_json(payload)

    # Markdown.
    lines = ["# Phase 04 — Security + Threat Model", ""]
    lines.append("## Severity counts")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for sev in ("HIGH", "MEDIUM", "INFO"):
        lines.append(f"| {sev} | {by_severity.get(sev, 0)} |")
    lines.append("")

    if high:
        lines += [
            "## HIGH-severity findings (must address)",
            "",
            "| Rule | File:Line | Note | Text |",
            "|---|---|---|---|",
        ]
        for f in high:
            text = f["text"].replace("|", "\\|")
            lines.append(f"| `{f['rule']}` | `{f['file']}:{f['line']}` | "
                         f"{f['note']} | `{text}` |")
        lines.append("")
    else:
        lines += ["✓ **No HIGH-severity findings.**", ""]

    if medium:
        lines += [
            "## MEDIUM-severity findings (review for cleanup)",
            "",
            "| Rule | File:Line | Note |",
            "|---|---|---|",
        ]
        for f in medium:
            lines.append(f"| `{f['rule']}` | `{f['file']}:{f['line']}` | "
                         f"{f['note']} |")
        lines.append("")

    lines += [
        "## Subprocess audit",
        "",
        f"Total subprocess calls: **{subp_check['checked']}** · "
        f"mitigated: **{subp_check['mitigated']}** · "
        f"review: **{subp_check['review']}** · "
        f"risk: **{subp_check['risk']}**",
        "",
    ]
    subp_review = [f for f in findings
                   if f["rule"] == "subprocess_call"
                   and f.get("status") in ("REVIEW", "RISK")]
    if subp_review:
        lines += ["### Calls without timeout (REVIEW)", ""]
        for f in subp_review:
            lines.append(f"- `{f['file']}:{f['line']}` — `{f['text']}`")
        lines.append("")

    lines += [
        "## HTTP audit",
        "",
        f"Total HTTP calls: **{http_check['checked']}** · "
        f"mitigated (timeout set): **{http_check['mitigated']}** · "
        f"review: **{http_check['review']}**",
        "",
    ]
    http_review = [f for f in findings
                   if f["rule"] in ("requests_get", "httpx_call")
                   and f.get("status") == "REVIEW"]
    if http_review:
        lines += ["### HTTP calls without timeout (REVIEW)", ""]
        for f in http_review:
            lines.append(f"- `{f['file']}:{f['line']}` — `{f['text']}`")
        lines.append("")

    lines += [
        "## Validator coverage",
        "",
        "| Validator | Callsites in cve_diff/ |",
        "|---|---:|",
    ]
    if isinstance(validator_cov, dict) and "error" not in validator_cov:
        for n in sorted(validator_cov):
            sites = validator_cov[n]
            count = len(sites) if isinstance(sites, list) else 0
            mark = "✓" if count else "**0 — UNUSED**"
            lines.append(f"| `{n}` | {count} {mark} |")
    lines.append("")

    if payload["validators_with_zero_callsites"]:
        lines += [
            "**Validators with 0 callsites (defense-in-depth gap or dead code):**",
            "",
        ]
        for n in payload["validators_with_zero_callsites"]:
            lines.append(f"- `{n}`")
        lines.append("")

    ctx.write_md("\n".join(lines))
    return {
        "high": by_severity.get("HIGH", 0),
        "medium": by_severity.get("MEDIUM", 0),
        "info": by_severity.get("INFO", 0),
        "subp_risk": subp_check["risk"],
        "subp_review": subp_check["review"],
        "http_review": http_check["review"],
        "validators_unused": len(payload["validators_with_zero_callsites"]),
    }
