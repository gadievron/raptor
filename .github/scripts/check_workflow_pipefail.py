"""Workflow pipeline / pipefail guardrail.

Self-contained, stdlib-only. Flags any workflow ``run:`` step whose
script contains a shell PIPELINE (``cmd | cmd`` — the ``| tee log``
idiom is the recurring case) without pipefail protection.

Why: GitHub Actions' DEFAULT shell for ``run:`` steps is ``bash -e``
only — no ``pipefail`` — so the exit code of everything left of a
pipe is swallowed and a failing gate quietly turns into a no-op
behind its ``| tee``. Protection is any of:

* ``shell: bash`` on the step — the BUILT-IN keyword makes GHA run
  ``bash --noprofile --norc -eo pipefail {0}``. Only the exact
  keyword counts: a custom template (``bash -x {0}``) does NOT get
  the implicit flags.
* ``set -o pipefail`` in the script body (any ``set`` line whose
  short-flag cluster ends in ``o`` followed by ``pipefail``, e.g.
  ``set -euo pipefail``).
* an explicit ``PIPESTATUS`` inspection — the author is reading the
  per-stage exit codes by hand.

CI semantics (baseline pattern, cf. ``check_vocab_lists.py``):
findings are keyed ``<workflow>::<job>::<step name|index>`` and
compared against ``workflow_pipefail_baseline.json`` next to this
script. A key not in the baseline fails the run — protect the step,
or (deliberately, with a note) add the key to the baseline. Baseline
entries that no longer fire warn as stale.

The detector is line-based, not a full shell parse: quoted spans and
``${{ ... }}`` expressions are removed first (jq filters and GHA
expressions carry ``|``/``||`` that are not shell pipes), full-line
and trailing unquoted comments are dropped (word-boundary aware —
``${FILE#./}`` is not a comment), ``||`` is not a pipe. The pipefail
credit is line-ordered: only a ``set -o pipefail`` still in effect
when the pipe runs counts. Not covered: YAML anchors/aliases are not
expanded, so a run body reaching a step through an alias would be
invisible to the line parser (GHA workflow YAML does not currently
accept anchors, and no workflow here uses them; revisit if either
changes), and job/workflow-level ``defaults.run.shell`` is not
credited — a step relying on it flags loudly rather than passing
silently (none exist in the tree today).

Usage:
    python3 .github/scripts/check_workflow_pipefail.py            # CI
    python3 .github/scripts/check_workflow_pipefail.py --root <tree>
    python3 .github/scripts/check_workflow_pipefail.py --write-baseline

Exit codes: 0 clean (stale warnings only), 1 new findings, 2 usage
error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

DEFAULT_BASELINE = (
    Path(__file__).resolve().parent / "workflow_pipefail_baseline.json"
)

# Spans removed before pipe detection, in order: GHA expressions,
# then quoted strings (single first — inside single quotes a double
# quote is literal, and vice versa; sequential non-greedy removal is
# an approximation that errs toward removal, i.e. toward fewer
# findings on weird nesting).
_EXPR_RE = re.compile(r"\$\{\{.*?\}\}")
_SQUOTE_RE = re.compile(r"'[^']*'")
_DQUOTE_RE = re.compile(r'"[^"]*"')

# A set line whose short-flag cluster includes -o followed by
# pipefail (covers ``set -o pipefail``, ``set -eo pipefail``,
# ``set -euo pipefail``), or the long spelling.
_PIPEFAIL_RE = re.compile(
    r"^\s*set\s+(-[a-np-z]*o\s+pipefail|-o\s+pipefail)\b",
)

# The corresponding switch-OFF (``set +o pipefail``, ``set +euo
# pipefail``): a credit taken before the pipe stops counting if it
# was revoked before the pipe ran.
_PIPEFAIL_OFF_RE = re.compile(
    r"^\s*set\s+\+[a-np-z]*o\s+pipefail\b",
)

# Comment truncation point: ``#`` opens a bash comment only at line
# start or after whitespace — mid-word ``#`` is live syntax
# (``${FILE#./}`` parameter expansion, URL fragments), and cutting
# there hid real pipes on the rest of the line.
_COMMENT_RE = re.compile(r"(?:^|\s)#")


class Step:
    def __init__(self, workflow: str, job: str, index: int) -> None:
        self.workflow = workflow
        self.job = job
        self.index = index
        self.name = ""
        self.shell = ""
        self.run_body: list[str] = []

    @property
    def key(self) -> str:
        label = self.name if self.name else f"step-{self.index}"
        return f"{self.workflow}::{self.job}::{label}"


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def parse_steps(workflow_name: str, text: str) -> list[Step]:
    """Extract every job's steps (name, shell, run body) without a
    YAML dependency (the lint lane installs only pytest; gate scripts
    are stdlib-only by convention). Assumes the repo's block style:
    ``jobs:`` at column 0, one key per line — the same assumption the
    other workflow-shape tests in .github/tests make.
    """
    lines = text.split("\n")
    steps: list[Step] = []

    jobs_at = None
    for i, ln in enumerate(lines):
        if ln.rstrip() == "jobs:":
            jobs_at = i
            break
    if jobs_at is None:
        return steps

    job_indent = None
    job_id = ""
    steps_indent = None       # indent of the "steps:" key in this job
    step_item_indent = None   # indent of each "- " step item
    current: Step | None = None
    run_indent = None         # indent of a step's "run:" key, while in body

    key_re = re.compile(r"^([A-Za-z0-9_-]+):")

    for ln in lines[jobs_at + 1:]:
        if ln.strip() == "" or ln.lstrip().startswith("#"):
            if current is not None and run_indent is not None:
                current.run_body.append("")
            continue
        ind = _indent(ln)
        stripped = ln.strip()

        # New top-level section after jobs: (e.g. nothing in practice).
        if ind == 0:
            break

        # Job boundary.
        if job_indent is None:
            job_indent = ind
        if ind == job_indent and key_re.match(stripped):
            job_id = key_re.match(stripped).group(1)
            steps_indent = None
            step_item_indent = None
            current = None
            run_indent = None
            continue

        # Inside a run body?
        if current is not None and run_indent is not None:
            if ind > run_indent:
                current.run_body.append(ln)
                continue
            run_indent = None  # body ended; fall through

        if stripped == "steps:":
            steps_indent = ind
            continue
        if steps_indent is None:
            continue

        # New step item.
        if stripped.startswith("- ") or stripped == "-":
            if step_item_indent is None:
                step_item_indent = ind
            if ind == step_item_indent:
                current = Step(
                    workflow=workflow_name, job=job_id,
                    index=sum(
                        1 for s in steps if s.job == job_id
                    ),
                )
                steps.append(current)
                # A step can open with its first key on the dash line.
                stripped = stripped[1:].strip()
                if not stripped:
                    continue
                ind = ind + 2  # first-key position for the checks below

        if current is None:
            continue

        m = key_re.match(stripped)
        if m:
            keyname = m.group(1)
            value = stripped[len(keyname) + 1:].strip()
            if keyname == "name" and not current.name:
                current.name = value.strip("'\"")
            elif keyname == "shell":
                current.shell = value.strip("'\"")
            elif keyname == "run":
                if value in ("|", "|-", "|+", ">", ">-", ">+"):
                    run_indent = ind
                elif value:
                    current.run_body.append(value)
    return steps


def _has_pipe(line: str) -> bool:
    code = _EXPR_RE.sub("", line)
    code = _SQUOTE_RE.sub("''", code)
    code = _DQUOTE_RE.sub('""', code)
    # Trailing unquoted comment — word-boundary aware (see
    # _COMMENT_RE): ``${FILE#./}`` and URL fragments are not
    # comments, and truncating at a mid-word ``#`` hid real pipes.
    m = _COMMENT_RE.search(code)
    if m is not None:
        code = code[:m.start()]
    code = code.replace("||", "")
    return "|" in code


def _unprotected_pipe(step: Step) -> bool:
    """True when the step's body pipes without protection IN EFFECT
    at the pipe. The pipefail credit is line-ordered: a ``set -o
    pipefail`` AFTER the pipeline (or revoked by ``set +o pipefail``
    before it) protected nothing. PIPESTATUS stays a whole-body
    credit — an rc capture legitimately reads it after the pipe.
    """
    if "PIPESTATUS" in "\n".join(step.run_body):
        return False
    pipefail_on = False
    for ln in step.run_body:
        if _PIPEFAIL_RE.match(ln):
            pipefail_on = True
            continue
        if _PIPEFAIL_OFF_RE.match(ln):
            pipefail_on = False
            continue
        if not pipefail_on and _has_pipe(ln):
            return True
    return False


def step_findings(steps: list[Step]) -> list[Step]:
    findings = []
    for step in steps:
        if not step.run_body:
            continue
        if step.shell == "bash":
            continue
        if _unprotected_pipe(step):
            findings.append(step)
    return findings


def scan_tree(root: Path) -> list[Step]:
    findings: list[Step] = []
    # *.y*ml: GHA accepts both .yml and .yaml workflow files.
    workflows = sorted((root / ".github" / "workflows").glob("*.y*ml"))
    for wf in workflows:
        steps = parse_steps(
            wf.name, wf.read_text(encoding="utf-8", errors="replace"),
        )
        findings.extend(step_findings(steps))
    return findings


def load_baseline(path: Path) -> dict:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(loaded, dict):
        return {}
    return {k: v for k, v in loaded.items() if isinstance(v, dict)}


def write_baseline(path: Path, findings: list[Step]) -> None:
    """Note-preserving refresh, same contract as the other gates: for
    every key that survives, fields other than nothing (there is no
    regenerated field here — the row is the review note) carry over;
    new keys start bare, awaiting their note. A present-but-unreadable
    baseline refuses the rewrite."""
    old_entries: dict[str, dict] = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(
                f"[pipefail] refusing --write-baseline: cannot parse the "
                f"existing baseline at {path} ({exc}); fix or remove it "
                f"first — overwriting would erase every review note",
                file=sys.stderr,
            )
            raise SystemExit(2) from exc
        if isinstance(loaded, dict):
            old_entries = {
                k: v for k, v in loaded.items() if isinstance(v, dict)
            }
    entries = {
        f.key: dict(old_entries.get(f.key, {})) for f in findings
    }
    path.write_text(
        json.dumps(entries, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path,
                    default=Path(__file__).resolve().parents[2])
    ap.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    ap.add_argument("--write-baseline", action="store_true",
                    help="write the current findings as the new baseline")
    args = ap.parse_args()

    if not (args.root / ".github" / "workflows").is_dir():
        print(f"[pipefail] no workflows under --root: {args.root}",
              file=sys.stderr)
        return 2

    findings = scan_tree(args.root)
    by_key = {f.key: f for f in findings}

    if args.write_baseline:
        write_baseline(args.baseline, findings)
        print(f"[pipefail] wrote baseline with {len(by_key)} entries "
              f"to {args.baseline}")
        return 0

    baseline = load_baseline(args.baseline)
    new = [f for k, f in sorted(by_key.items()) if k not in baseline]
    stale = sorted(set(baseline) - set(by_key))

    for k in stale:
        print(f"[pipefail] WARN stale baseline entry (no longer fires): {k}")

    if new:
        print(f"[pipefail] {len(new)} workflow step(s) contain a shell "
              f"pipeline without pipefail protection:")
        for f in new:
            print(f"  {f.key}")
        print(
            "[pipefail] The default GHA shell is bash -e only — a pipe "
            "swallows the left side's exit code. Set `shell: bash` on "
            "the step (the built-in keyword adds -o pipefail) or open "
            "the script with `set -euo pipefail`; if the pipeline's "
            "exit code is deliberately non-gating, add the key to "
            ".github/scripts/workflow_pipefail_baseline.json with a "
            "review note.",
        )
        return 1

    print(f"[pipefail] clean: no unprotected pipeline steps "
          f"({len(baseline)} baselined, {len(stale)} stale).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
