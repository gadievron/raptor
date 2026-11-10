"""Choose a verified cumulative push base; uncertainty requires full coverage.

A successful pre-policy run is not a checkpoint: it may itself have skipped
changes from cancelled pushes. The versioned step is present only in the new
policy. Its latest scope job and the whole workflow must have succeeded on
that exact SHA. Targeted reruns can retain an earlier successful scope job.
No artifact, mutable branch pointer, or event.before is trusted.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.parse import quote

CHECKPOINT_STEP = "Record verified push scope v1"
FULL_BASE = "0" * 40
CHECKPOINT_JOBS = {
    "tests.yml": "changes",
    "sandbox-wrappers.yml": "scope",
    "codeql.yml": "changes",
    "lint.yml": "command-metadata",
}


def _api(endpoint):
    try:
        started = time.monotonic()
    except BaseException:
        # An optional observer must never prevent the API operation.
        started = None
    try:
        response = subprocess.run(
            ["gh", "api", endpoint], capture_output=True, text=True,
            timeout=20, check=True,
        )
        return json.loads(response.stdout)
    finally:
        if started is not None:
            try:
                phase = ("compare" if "/compare/" in endpoint else
                         "jobs" if "/jobs?" in endpoint else "checkpoint-run")
                print(f"Push checkpoint {phase}: {time.monotonic() - started:.3f}s",
                      file=sys.stderr)
            except BaseException:
                # Confine observer failures here, preserving the original
                # API/JSON outcome, including interrupts. No endpoint or
                # response contents enter the diagnostic.
                pass


def _sha(value):
    return bool(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value) and set(value) != {"0"})


def checkpoint(repo, branch, head, current_run, workflow, *, api=None):
    """Return (base, comparison) only after verifying the coverage checkpoint."""
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo)
            or not branch or not _sha(head) or not current_run.isdecimal()
            or workflow not in CHECKPOINT_JOBS):
        raise ValueError("missing push identity")
    api = _api if api is None else api
    runs = api(
        f"repos/{repo}/actions/workflows/{workflow}/runs"
        f"?branch={quote(branch, safe='')}&event=push&status=success&per_page=1"
    )["workflow_runs"]
    if not isinstance(runs, list) or len(runs) != 1:
        raise ValueError("no successful push checkpoint")
    run = runs[0]
    run_id, attempt, base = run["id"], run["run_attempt"], run["head_sha"]
    if (type(run_id) is not int or run_id <= 0 or run_id == int(current_run)
            or type(attempt) is not int or attempt <= 0 or not _sha(base)
            or run["status"] != "completed" or run["conclusion"] != "success"
            or run["event"] != "push" or run["head_branch"] != branch
            or run["path"] != f".github/workflows/{workflow}"
            or run["repository"]["full_name"] != repo
            or run["head_repository"]["full_name"] != repo):
        raise ValueError("checkpoint identity does not match this push")
    # Failed-job reruns retain successful jobs from earlier attempts. Read
    # all attempts and choose the newest scope execution, never resurrecting
    # an older marker over a newer failed or unmarked scope job.
    page = api(f"repos/{repo}/actions/runs/{run_id}/jobs?filter=all&per_page=100")
    jobs = page["jobs"]
    if not isinstance(jobs, list) or type(page["total_count"]) is not int or page["total_count"] != len(jobs):
        raise ValueError("incomplete checkpoint job list")
    matches = [job for job in jobs if job["name"] == CHECKPOINT_JOBS[workflow]]
    if not matches or any(type(job["run_attempt"]) is not int
                          or not 1 <= job["run_attempt"] <= attempt for job in matches):
        raise ValueError("missing or invalid scope attempt")
    latest_attempt = max(job["run_attempt"] for job in matches)
    latest = [job for job in matches if job["run_attempt"] == latest_attempt]
    if len(latest) != 1:
        raise ValueError("ambiguous checkpoint job")
    job = latest[0]
    if (job["run_id"] != run_id or job["head_sha"] != base
            or job["status"] != "completed" or job["conclusion"] != "success"
            or not any(step["name"] == CHECKPOINT_STEP and step["status"] == "completed"
                       and step["conclusion"] == "success" for step in job["steps"])):
        raise ValueError("successful cumulative-scope marker is absent")
    comparison = api(f"repos/{repo}/compare/{base}...{head}")
    if (comparison["base_commit"]["sha"] != base
            or comparison["merge_base_commit"]["sha"] != base
            or comparison["status"] != ("identical" if base == head else "ahead")):
        raise ValueError("checkpoint is not an ancestor of this push")
    if not isinstance(comparison["files"], list):
        raise ValueError("comparison file list is unavailable")
    for entry in comparison["files"]:
        for field in ("filename", "previous_filename"):
            if field not in entry and field == "previous_filename":
                continue
            name = entry[field]
            if not isinstance(name, str) or not name or any(c in name for c in "\r\n\0"):
                raise ValueError("comparison paths cannot use the line-list interface")
    return base, comparison


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", required=True, choices=CHECKPOINT_JOBS)
    parser.add_argument("--compare-out", type=Path)
    args = parser.parse_args(argv)
    base, compare_path = FULL_BASE, ""
    try:
        if os.environ.get("GITHUB_EVENT_NAME") != "push":
            raise ValueError("not a push event")
        base, comparison = checkpoint(
            os.environ.get("GITHUB_REPOSITORY", ""), os.environ.get("GITHUB_REF_NAME", ""),
            os.environ.get("GITHUB_SHA", ""), os.environ.get("GITHUB_RUN_ID", ""), args.workflow,
        )
        if args.compare_out:
            args.compare_out.write_text(json.dumps(comparison), encoding="utf-8")
            compare_path = str(args.compare_out)
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, AttributeError):
        base, compare_path = FULL_BASE, ""
        print("::notice::No verified cumulative push checkpoint; using full coverage.")
    else:
        print(f"Verified cumulative push base: {base}")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write(f"base={base}\ncompare={compare_path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
