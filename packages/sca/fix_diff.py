"""``raptor-sca fix-diff`` — acquire upstream fix diffs for SCA findings.

Bridges SCA advisories to the /cve-diff pipeline: for each CVE named by
a ``findings.json`` advisory (or passed explicitly with ``--cve``),
invoke ``libexec/raptor-cve-diff run`` and collect the discovered fix
pointer. The result is the concrete patch behind the advisory — what an
operator needs for backport checks ("is this fix actually present in
the pinned version?") and for variant hunting via the checker-synthesis
bridge.

Each CVE runs as its own subprocess through the libexec shim so the
per-run machinery applies unchanged (run lifecycle, llm-telemetry,
budget caps, SAGE fix-pointer recall — a CVE already solved by a prior
run short-circuits its agent spend). Discovery is agentic and costs
real money, so the sweep is explicitly opt-in and capped
(``--max-cves``, default 5).

Outputs, under ``--output-dir`` (default ``fix-diffs/`` next to the
findings file): one run directory per CVE plus ``summary.json`` mapping
CVE → {ok, repository_url, fix_commit, output_dir | error_class}.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

logger = logging.getLogger(__name__)

_RAPTOR_DIR = Path(__file__).resolve().parents[2]
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Hard wall-clock cap per CVE subprocess: the discovery agent's own
# budget is ~12 minutes; double it to leave room for clone + diff on
# large repos before this backstop fires.
_PER_CVE_TIMEOUT_S = 1800


def collect_cve_ids(rows: Sequence[dict[str, Any]]) -> list[str]:
    """Unique CVE ids from findings.json rows, first-seen order.

    Reads ``row["sca"]["advisory"]`` (id + aliases) — the shape
    ``render.py`` consumes. Suppressed rows are skipped: the operator
    already ruled them out, so spending discovery budget on them would
    be waste.
    """
    seen: set[str] = set()
    out: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or row.get("suppressed"):
            continue
        sca = row.get("sca") or {}
        adv = sca.get("advisory") or {}
        if not isinstance(adv, dict):
            continue
        candidates = [adv.get("id") or ""]
        candidates.extend(adv.get("aliases") or [])
        for cand in candidates:
            cve = str(cand).strip().upper()
            if _CVE_RE.match(cve) and cve not in seen:
                seen.add(cve)
                out.append(cve)
    return out


def _parse_summary(stdout: str) -> dict[str, Any] | None:
    """Extract the shim's JSON summary — the last top-level JSON object
    on stdout (the shim prints it last, after the OUTPUT_DIR sentinel
    and any progress lines)."""
    starts = [m.start() for m in re.finditer(r"^\{", stdout, re.MULTILINE)]
    for start in reversed(starts):
        try:
            parsed = json.loads(stdout[start:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and "ok" in parsed:
            return parsed
    return None


def run_one(cve_id: str, output_dir: Path, *, budget_multiplier: float = 1.0,
            model: str | None = None) -> dict[str, Any]:
    """Run /cve-diff for one CVE via the libexec shim; return a summary
    row for summary.json. Never raises."""
    cmd = [
        sys.executable,
        str(_RAPTOR_DIR / "libexec" / "raptor-cve-diff"),
        "run", cve_id,
        "--output-dir", str(output_dir / cve_id.lower()),
    ]
    if budget_multiplier != 1.0:
        cmd += ["--budget-multiplier", str(budget_multiplier)]
    if model:
        cmd += ["--model", model]
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=_PER_CVE_TIMEOUT_S, env=env, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"ok": False, "cve_id": cve_id,
                "error_class": type(exc).__name__,
                "error_detail": str(exc)[:200]}

    summary = _parse_summary(proc.stdout or "")
    if summary is None:
        return {"ok": False, "cve_id": cve_id,
                "error_class": "NoSummary",
                "error_detail": (proc.stderr or "")[-200:],
                "exit_code": proc.returncode}
    row: dict[str, Any] = {
        "ok": bool(summary.get("ok")),
        "cve_id": cve_id,
        "output_dir": summary.get("output_dir"),
        "exit_code": proc.returncode,
    }
    bundle = summary.get("bundle") or {}
    if bundle:
        row["repository_url"] = bundle.get("repository_url")
        row["fix_commit"] = bundle.get("fix_commit")
        row["files_changed"] = bundle.get("files_changed")
    if not row["ok"]:
        row["error_class"] = summary.get("error_class")
        row["error_detail"] = summary.get("error_detail")
    return row


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="raptor-sca fix-diff",
        description="Fetch upstream fix diffs for CVEs named by SCA "
                    "findings (agentic — costs LLM budget per CVE).",
    )
    parser.add_argument("findings", nargs="?", default=None,
                        help="findings.json from a raptor-sca run")
    parser.add_argument("--cve", action="append", default=[], metavar="CVE-ID",
                        help="explicit CVE id (repeatable; skips findings)")
    parser.add_argument("--output-dir", default=None,
                        help="where per-CVE run dirs + summary.json land "
                             "(default: fix-diffs/ next to the findings file)")
    parser.add_argument("--max-cves", type=int, default=5, metavar="N",
                        help="cap on CVEs to run (default: 5 — each costs "
                             "an agentic discovery run)")
    parser.add_argument("--budget-multiplier", type=float, default=1.0)
    parser.add_argument("--model", default=None,
                        help="model override, passed through to /cve-diff")
    return parser.parse_args(list(argv))


def main(argv: Sequence[str]) -> int:
    args = _parse_args(argv)

    cves: list[str] = []
    for c in args.cve:
        cve = str(c).strip().upper()
        if not _CVE_RE.match(cve):
            print(f"raptor-sca fix-diff: not a CVE id: {c!r}", file=sys.stderr)
            return 2
        cves.append(cve)

    findings_path: Path | None = None
    if not cves:
        if not args.findings:
            print("raptor-sca fix-diff: pass findings.json or --cve CVE-ID",
                  file=sys.stderr)
            return 2
        findings_path = Path(args.findings).resolve()
        try:
            rows = json.loads(findings_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"raptor-sca fix-diff: cannot read {findings_path}: {e}",
                  file=sys.stderr)
            return 2
        if not isinstance(rows, list):
            print(f"raptor-sca fix-diff: {findings_path} is not a finding "
                  "list", file=sys.stderr)
            return 2
        cves = collect_cve_ids(rows)

    if not cves:
        print("raptor-sca fix-diff: no CVE-identified advisories found — "
              "nothing to do")
        return 0

    dropped = 0
    if len(cves) > args.max_cves:
        dropped = len(cves) - args.max_cves
        cves = cves[: args.max_cves]

    if args.output_dir:
        out_dir = Path(args.output_dir).resolve()
    elif findings_path is not None:
        out_dir = findings_path.parent / "fix-diffs"
    else:
        out_dir = Path.cwd() / "fix-diffs"
    out_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for i, cve in enumerate(cves, 1):
        print(f"[{i}/{len(cves)}] /cve-diff {cve} …", file=sys.stderr)
        row = run_one(
            cve, out_dir,
            budget_multiplier=args.budget_multiplier, model=args.model,
        )
        status = "ok" if row["ok"] else f"failed ({row.get('error_class')})"
        print(f"[{i}/{len(cves)}] {cve}: {status}", file=sys.stderr)
        results.append(row)

    summary_path = out_dir / "summary.json"
    summary_path.write_text(
        json.dumps({"results": results, "dropped_over_cap": dropped},
                   indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {summary_path}")
    if dropped:
        # No silent caps: the operator must see what was not attempted.
        print(f"note: {dropped} CVE(s) beyond --max-cves were not attempted",
              file=sys.stderr)

    ok = sum(1 for r in results if r["ok"])
    print(f"fix-diff: {ok}/{len(results)} CVEs resolved to fix commits")
    return 0 if ok == len(results) else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
