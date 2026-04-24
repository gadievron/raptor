"""Seed a realistic raptor-studio demo project."""

import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from packages.studio.services.raptor_writer import create_project, ProjectCreateError

OUT_BASE = Path.home() / "raptor-studio-demo-output"
PROJECTS = Path.home() / ".raptor-studio-demo" / "projects"

# Clean slate for repeatable demo.
if OUT_BASE.exists():
    shutil.rmtree(OUT_BASE)
if PROJECTS.exists():
    shutil.rmtree(PROJECTS)

PROJECTS.mkdir(parents=True)

# Create three projects to show cross-project perspective.
try:
    create_project("demo-webapp", "/tmp/demo-webapp",
                   description="Sample Python + Java web app under continuous security review",
                   projects_dir=PROJECTS, output_base=OUT_BASE)
    create_project("demo-firmware", "/tmp/demo-firmware",
                   description="Embedded binary targets in a fuzzing campaign",
                   projects_dir=PROJECTS, output_base=OUT_BASE)
    create_project("aws-toolkit", "/tmp/aws-toolkit-vscode",
                   description="OSS forensics: supply-chain incident investigation",
                   projects_dir=PROJECTS, output_base=OUT_BASE)
except ProjectCreateError as e:
    print(f"create_project failed: {e}")

# --- demo-webapp: scan A, scan B (for diff), validate, exploits, patches ---
webapp_out = OUT_BASE / "demo-webapp"

scan_a = webapp_out / "scan_demo_20260420_100000"
scan_a.mkdir(parents=True)
(scan_a / ".raptor-run.json").write_text(json.dumps({
    "version": 1, "command": "python raptor.py scan --repo /tmp/demo-webapp --policy-groups owasp,secrets",
    "timestamp": "2026-04-20T10:00:00Z", "status": "completed",
}))
(scan_a / "findings.json").write_text(json.dumps([
    {"id": "A1", "file": "src/shell.py", "line": 42, "vuln_type": "command_injection", "cwe_id": "CWE-78",
     "final_status": "pending", "verdict": "unknown", "impact": "unknown", "tool": "semgrep"},
    {"id": "A2", "file": "src/db/query.py", "line": 15, "vuln_type": "sql_injection", "cwe_id": "CWE-89",
     "final_status": "pending", "verdict": "unknown", "impact": "unknown", "tool": "semgrep"},
    {"id": "A3", "file": "src/render.py", "line": 88, "vuln_type": "xss", "cwe_id": "CWE-79",
     "final_status": "pending", "verdict": "unknown", "impact": "unknown", "tool": "semgrep"},
    {"id": "A4", "file": "src/old_module.py", "line": 200, "vuln_type": "hardcoded_secret", "cwe_id": "CWE-798",
     "final_status": "pending", "verdict": "unknown", "impact": "unknown", "tool": "semgrep"},
]))
(scan_a / "scan_metrics.json").write_text(json.dumps({
    "files_scanned": 187, "semgrep_findings": 4, "codeql_findings": 0,
    "policy_groups": ["owasp", "secrets"], "duration_sec": 23,
}))
(scan_a / "semgrep_owasp.sarif").write_text(json.dumps({
    "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep", "rules": []}}, "results": []}],
}))

# scan B: a few days later — some fixed, one new
scan_b = webapp_out / "scan_demo_20260423_110000"
scan_b.mkdir(parents=True)
(scan_b / ".raptor-run.json").write_text(json.dumps({
    "version": 1, "command": "python raptor_agentic.py --repo /tmp/demo-webapp",
    "timestamp": "2026-04-23T11:00:00Z", "status": "completed",
}))
(scan_b / "findings.json").write_text(json.dumps([
    # Still present, status upgraded
    {"id": "B1", "file": "src/shell.py", "line": 42, "vuln_type": "command_injection", "cwe_id": "CWE-78",
     "final_status": "exploitable", "verdict": "exploitable", "impact": "code_execution",
     "attack_scenario": "User-provided cmd param flows into os.system without sanitisation.",
     "proof": {"source": "flask.request.args['cmd']",
               "sink": "os.system(full_cmd)",
               "vulnerable_code": "cmd = request.args.get('cmd')\nfull_cmd = f'ls {cmd}'\nos.system(full_cmd)",
               "flow": ["HTTP param arrives at /list handler",
                        "Concatenated into shell string with no escaping",
                        "Passed to os.system"]},
     "poc": {"description": "Append ';id' to cmd param.",
             "payload": "GET /list?cmd=foo%3B%20id HTTP/1.1",
             "result": "id output appended to ls output, confirming command execution"}},
    # Still present, unchanged
    {"id": "B2", "file": "src/db/query.py", "line": 15, "vuln_type": "sql_injection", "cwe_id": "CWE-89",
     "final_status": "likely_exploitable", "verdict": "likely_exploitable", "impact": "data_corruption",
     "attack_scenario": "User-controlled ID concatenated into SELECT; sanitisation inconsistent.",
     "proof": {"source": "request.form['user_id']", "sink": "cursor.execute(sql)"}},
    # A3 (xss) resolved
    # A4 (hardcoded_secret) resolved
    # NEW: stack overflow in C binding
    {"id": "B5", "file": "src/parser/decode.c", "line": 77, "vuln_type": "stack_overflow", "cwe_id": "CWE-121",
     "final_status": "confirmed_constrained", "verdict": "difficult", "impact": "code_execution",
     "attack_scenario": "strcpy of attacker-controlled length into fixed 64-byte stack buffer in the CJSON binding.",
     "proof": {"source": "read(0, buf, n)", "sink": "strcpy(frame, buf)",
               "vulnerable_code": "char frame[64];\nstrcpy(frame, buf);  // buf can be > 64 bytes",
               "flow": ["read reads untrusted bytes from stdin",
                        "No length check before strcpy",
                        "strcpy writes past frame, clobbers return address"]},
     "poc": {"payload": "A" * 72 + "\\x00\\x04\\x00\\x00"},
     "feasibility": {
         "verdict": "difficult",
         "binary_analysis": {
             "protections": {"PIE": True, "NX": True, "Canary": True, "RELRO": "Full"},
             "exploitation_paths": [
                 {"technique": "canary-byte leak via format string",
                  "target": "stack frame @ 0x7ffff"},
                 {"technique": "ROP chain → system('/bin/sh')",
                  "target": "libc offset 0x50dc0"},
             ],
         },
         "chain_breaks": ["[binary] Stack canary present",
                          "[source] Length check prevents > 128 bytes"],
         "what_would_help": ["Find a canary leak primitive",
                             "Bypass length check via integer wraparound"],
     }},
]))
(scan_b / "scan_metrics.json").write_text(json.dumps({
    "files_scanned": 192, "semgrep_findings": 3, "codeql_findings": 1,
    "policy_groups": ["all"], "duration_sec": 184,
}))
(scan_b / "exploits").mkdir()
(scan_b / "exploits" / "cmd_injection_poc.py").write_text("""#!/usr/bin/env python3
# Exploit for B1 — command injection in /list handler
import requests
r = requests.get("http://target/list", params={"cmd": "foo; id"})
print(r.text)
""")
(scan_b / "patches").mkdir()
(scan_b / "patches" / "shlex-escape.patch").write_text("""--- a/src/shell.py
+++ b/src/shell.py
@@ -38,5 +38,7 @@ def list_handler():
     cmd = request.args.get('cmd', '')
-    full_cmd = f'ls {cmd}'
-    os.system(full_cmd)
+    import shlex, subprocess
+    if not cmd.isalnum():
+        abort(400)
+    subprocess.run(['ls', cmd], check=True)
""")
(scan_b / "validation-report.md").write_text("""# Validation Report

## Summary
4 total findings analysed; 2 confirmed exploitable/likely, 1 constrained, 0 ruled out.

## Confirmed exploitable
- B1 command_injection @ src/shell.py:42 — standard techniques work

## Likely exploitable
- B2 sql_injection @ src/db/query.py:15 — viable paths exist with some constraints

## Constrained
- B5 stack_overflow @ src/parser/decode.c:77 — canary + length check
""")

# --- demo-webapp: rich /validate run with full artifact bundle + attack-surface ---
validate_run = webapp_out / "exploitability-validation-20260423_113000"
validate_run.mkdir(parents=True)
(validate_run / ".raptor-run.json").write_text(json.dumps({
    "version": 1, "command": "/validate",
    "timestamp": "2026-04-23T11:30:00Z", "status": "completed",
}))
(validate_run / "findings.json").write_text(json.dumps([
    {"id": "V1", "file": "src/shell.py", "line": 42, "vuln_type": "command_injection",
     "final_status": "exploitable", "verdict": "exploitable", "impact": "code_execution"},
]))
(validate_run / "attack-surface.json").write_text(json.dumps({
    "sources": [
        "flask.request.args (HTTP query params)",
        "flask.request.form (HTTP form)",
        "os.environ (env vars)",
        "stdin (CLI input)",
    ],
    "sinks": [
        "os.system",
        "subprocess.run(shell=True)",
        "sqlite3.Cursor.execute (string concat)",
        "eval / exec",
    ],
    "trust_boundaries": [
        "HTTP handler entry",
        "CLI argv parse",
        "Worker job consumer",
    ],
}))
(validate_run / "attack-tree.json").write_text(json.dumps([
    {"node": "rce-via-cmd-injection", "children": ["shell.py:42", "utils.py:88"]},
    {"node": "info-leak-via-sqli",    "children": ["db/query.py:15"]},
]))
(validate_run / "hypotheses.json").write_text(json.dumps([
    {"h": "cmd injection gives RCE"},
    {"h": "sqli enables data exfil"},
    {"h": "xss is effectively CSRF"},
]))
(validate_run / "disproven.json").write_text(json.dumps([
    {"approach": "xss → account takeover (blocked by SameSite=Strict)"},
]))
(validate_run / "validation-report.md").write_text("""# Validation Report

Stages A–F executed. 1 exploitable confirmed.

## Timeline
- Stage A (one-shot): command_injection appears real
- Stage B (process): attack path confirmed — unauthed HTTP → shell
- Stage C (sanity): code verbatim, flow real, no test-only guards
- Stage D (ruling): final_status = exploitable
- Stage E (feasibility): n/a for cmd injection (not memory corruption)
- Stage F (self-review): all checks pass
""")

# --- demo-firmware: fuzz run + crashes + exploits ---
fw_out = OUT_BASE / "demo-firmware"
fuzz_run = fw_out / "fuzz_parser_20260423_140000"
fuzz_run.mkdir(parents=True)
(fuzz_run / ".raptor-run.json").write_text(json.dumps({
    "version": 1, "command": "python raptor_fuzzing.py --binary /tmp/parser --autonomous --duration 1800 --goal 'find heap overflow'",
    "timestamp": "2026-04-23T14:00:00Z", "status": "completed",
}))
(fuzz_run / "fuzzing_report.json").write_text(json.dumps({
    "duration_sec": 1800,
    "unique_crashes": 7,
    "deduped_crashes": 4,
    "coverage_pct": 48.3,
    "total_cost_usd": 0.12,
    "llm_model": "claude-opus-4-6",
    "parallel": 4,
    "autonomous_corpus": True,
    "goal": "find heap overflow",
}))
(fuzz_run / "afl_output" / "main" / "crashes").mkdir(parents=True)
for i in range(4):
    (fuzz_run / "afl_output" / "main" / "crashes" / f"id-00000{i}").write_bytes(b"\x00" * 64)
(fuzz_run / "afl_output" / "main" / "crashes" / "README.txt").write_text("afl readme placeholder")
(fuzz_run / "analysis" / "exploits").mkdir(parents=True)
(fuzz_run / "analysis" / "exploits" / "crash_0001_exploit.c").write_text("""/* heap-buffer-overflow in cjson_parse */
int main() { /* pwn poc elided */ return 0; }
""")
(fuzz_run / "analysis" / "exploits" / "crash_0002_exploit.c").write_text("""/* UAF in json_get_item */
int main() { /* pwn poc elided */ return 0; }
""")

# --- aws-toolkit: OSS forensics walkthrough ---
forensics_out = OUT_BASE / "aws-toolkit"
forensics_run = forensics_out / "oss-forensics-20260423_160000"
forensics_run.mkdir(parents=True)
(forensics_run / ".raptor-run.json").write_text(json.dumps({
    "version": 1,
    "command": "/oss-forensics https://github.com/aws/aws-toolkit-vscode --focus 'July 13 incident'",
    "timestamp": "2026-04-23T16:00:00Z", "status": "completed",
}))
(forensics_run / "evidence.json").write_text(json.dumps({
    "research_question": "Who introduced the malicious push to aws-toolkit-vscode on 2025-07-13, and what credential did they use?",
    "github_api":  [
        {"commit": "abc123", "author": "lkmanka58"},
        {"commit": "def456", "author": "lkmanka58"},
        {"commit": "789xyz", "author": "automation-bot"},
    ],
    "gh_archive":  [
        {"event": "PushEvent", "actor": "lkmanka58", "ts": "2025-07-13T04:23:00Z"},
        {"event": "ForkEvent", "actor": "attacker-1", "ts": "2025-07-12T20:00:00Z"},
    ],
    "wayback":     [
        {"url": "https://web.archive.org/web/20250713/github.com/aws/aws-toolkit-vscode/releases"},
    ],
    "local_git":   [
        {"dangling_commit": "badc0ffee", "found_in_reflog": True},
    ],
    "ioc_extractor": [
        {"ioc": "pastebin.com/raw/X", "type": "c2_url"},
    ],
}))
(forensics_run / "evidence-verification-report.md").write_text("""# Evidence Verification Report

All 4 primary sources cross-checked:
- GitHub API: 3 commits verified against GH Archive immutable record
- GH Archive: 2 events confirmed via BigQuery
- Wayback: 1 snapshot preserved pre-force-push
- Local git: dangling commit recovered from reflog

No contradictions. No evidence was fabricated.
""")
(forensics_run / "hypothesis-001.md").write_text("""# Hypothesis 1: leaked PAT used by external attacker

The attacker used a Personal Access Token stolen from a compromised developer laptop.

## Evidence
- gh_archive shows PushEvent at 04:23 UTC
- No IP correlation available from GitHub API

## Weakness
PAT would appear in auth logs with a distinct UA; not observed.
""")
(forensics_run / "hypothesis-002-rebuttal.md").write_text("""# Hypothesis 2 (rebuttal of H1)

## Counter-evidence
Developer laptop telemetry (via external report) shows no anomalous activity during window.
PAT theory unsupported.
""")
(forensics_run / "hypothesis-003-confirmed.md").write_text("""# Hypothesis 3: committed-then-exploited token

## Theory
A developer accidentally committed a token in a feature branch on 2025-07-10.
The token was scraped by a public GitHub indexer (gh-archive public firehose).
An automated bot then cloned the repo, used the token, and force-pushed the malicious payload.

## Evidence
- Local git reflog shows token committed and immediately removed 2025-07-10
- Public GH Archive captured the commit before it was rewritten
- Push at 04:23 UTC from automation-bot-like User Agent
- Pastebin c2_url embedded in the payload

## Confidence
HIGH. All corroborating evidence consistent.
""")
(forensics_run / "forensic-report.md").write_text("""# Forensic Report: aws-toolkit-vscode 2025-07-13 Incident

## Executive Summary
Automated bot exploited an accidentally-committed PAT to push a malicious payload.
Root cause: token committed in feature branch and scraped from public GH firehose before removal.

## Timeline
- 2025-07-10 14:22 UTC — PAT committed by dev (feature branch, quickly reverted)
- 2025-07-10 14:22 UTC — Commit captured by public GH Archive firehose
- 2025-07-12 20:00 UTC — Attacker forks repo (reconnaissance)
- 2025-07-13 04:23 UTC — Malicious push by automation-bot UA using scraped PAT
- 2025-07-13 04:27 UTC — AWS revokes token + rolls back affected release

## Attribution
Automated exploitation. Actor handle lkmanka58 is a burner account.
IOC: pastebin.com/raw/X (c2 URL embedded in payload).

## Recommendations
1. Rotate all developer PATs.
2. Enable GitHub push-protection for secret scanning (not enabled at incident time).
3. Audit public commit stream for 14-day lookback window.
""")

# --- Activity log across projects ---
for proj_out in (webapp_out, fw_out, forensics_out):
    (proj_out / "logs").mkdir(exist_ok=True)
    (proj_out / "logs" / "raptor.jsonl").write_text("\n".join([
        json.dumps({"timestamp": "2026-04-23 10:00:00,001", "level": "INFO", "message": f"{proj_out.name}: run started"}),
        json.dumps({"timestamp": "2026-04-23 10:00:45,123", "level": "INFO", "message": "Semgrep scan complete"}),
        json.dumps({"timestamp": "2026-04-23 10:01:22,456", "level": "WARNING", "message": "CodeQL database creation slow (> 60s)"}),
        json.dumps({"timestamp": "2026-04-23 10:05:00,789", "level": "INFO", "message": "Validation complete"}),
    ]) + "\n")

print(f"Demo seeded.")
print(f"  Projects dir: {PROJECTS}")
print(f"  Output base: {OUT_BASE}")
print(f"  Projects:")
for p in PROJECTS.glob("*.json"):
    meta = json.loads(p.read_text())
    print(f"    - {meta['name']}: {meta['target']}")
