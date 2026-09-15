#!/usr/bin/env python3
"""Report-writer closure gate.

The report-writer audit (core/security/report_writer_audit.py) only
walks files REGISTERED in ``_REPORT_WRITER_FILES`` — so an
unregistered new writer that prints LLM-/target-/tool-derived text was
invisible to CI, and the terminal-escape class kept getting re-found
by hand, writer by writer. This gate closes the class mechanically:

* every git-tracked ``*.py`` file plus ``libexec/``/``bin/`` script
  (tests, fixtures, and ``.github/`` excluded) is walked with the
  audit's own detector (LLM-derived + tool-output foreign keys,
  recognised-sanitiser vocabulary, allowlist applied);
* a hit in a REGISTERED file fails (fix the site or add an
  ``AllowlistEntry`` in the audit module — same rules as the unit
  test, this is the same detector);
* a hit in an UNREGISTERED file must appear in
  ``report_writer_closure_baseline.json`` next to this script — a
  triaged residual with a mandatory note. A hit not in the baseline
  fails: **register the file in _REPORT_WRITER_FILES and sanitise the
  site, or (deliberately, with a note) add a baseline entry**;
* baseline entries that no longer fire are reported as stale warnings
  (clean exit) so entries can be retired without racing in-flight
  branches;
* NON-PYTHON ``libexec/``/``bin/`` scripts (bash launchers) cannot be
  walked by the AST detector at all — registering one in
  ``_REPORT_WRITER_FILES`` would be vacuous. Every such script must
  instead appear in the baseline's ``bash_manual_audit`` section with
  a note recording its manual review (mechanism tier:
  registered-with-manual-audit). A new bash script fails the gate
  until a human adds the note.

Walk-scope note: candidates come from ``git ls-files`` — untracked
files are invisible until added, and the AST detector sees one module
at a time (cross-module helper flows are out of scope; see the audit
module's docstrings for per-arm residuals).

Finding keys carry no line numbers (``file::func::kind::detail``) so
unrelated churn does not invalidate them; a changed call site that
still matches its key stays covered by its triage note.

Usage:
    python3 .github/scripts/check_report_writer_closure.py
    python3 .github/scripts/check_report_writer_closure.py --root <tree>
    python3 .github/scripts/check_report_writer_closure.py --write-baseline

Exit codes: 0 clean (stale-only is clean), 1 new findings, 2 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_DEFAULT_ROOT = _SCRIPT_DIR.parents[1]
_BASELINE_PATH = _SCRIPT_DIR / "report_writer_closure_baseline.json"

# Worker-side state, set by _init_worker (module global so the worker
# function stays picklable under any multiprocessing start method).
_WORKER_ROOT: Path | None = None


def _init_worker(root_str: str) -> None:
    """Make the scanned tree's own audit module importable in this
    process (the gate audits scratch trees carrying their own copy)."""
    global _WORKER_ROOT
    _WORKER_ROOT = Path(root_str)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)


def _audit_one(rel: str) -> list:
    """Audit one candidate file; returns its allowlist-filtered
    violations.

    Every candidate gets the full AST scan — deliberately no content
    prescreen. A text-level "file never mentions a foreign key /
    fence" skip is unsound: the parser folds adjacent string literals
    and escape sequences into plain ``ast.Constant`` values
    (``f["tit" "le"]``, ``f["\\x74itle"]``), so the detectors catch
    key/fence literals whose source text never contains the token,
    and a prescreen would skip exactly those files. The process pool
    below is what keeps the whole-tree walk inside the CI budget.
    """
    import core.security.report_writer_audit as rwa

    assert _WORKER_ROOT is not None
    try:
        source = (_WORKER_ROOT / rel).read_text(encoding="utf-8")
    except OSError:
        return []
    return rwa.filter_allowlisted(rwa.audit_source(source, rel))


def _audit_candidates(root: Path, rels: list[str]) -> list[list]:
    """Per-file violation lists, in ``rels`` order. Parallel across a
    small process pool (the scan is CPU-bound pure Python); falls back
    to a serial in-process scan when a pool cannot be created or dies
    (restricted sandboxes without working /dev/shm semaphores)."""
    workers = min(8, len(rels) or 1, os.cpu_count() or 1)
    if workers > 1:
        try:
            with ProcessPoolExecutor(
                    max_workers=workers,
                    initializer=_init_worker,
                    initargs=(str(root),)) as pool:
                return list(pool.map(_audit_one, rels, chunksize=16))
        except Exception as exc:  # noqa: BLE001 — any pool failure degrades to serial
            print(f"note: parallel scan unavailable ({exc.__class__.__name__}); "
                  f"scanning serially", file=sys.stderr)
    _init_worker(str(root))
    return [_audit_one(rel) for rel in rels]


def _candidates(root: Path) -> list[str]:
    """Git-tracked python-ish files that can host a report writer."""
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files"],
        capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    result = []
    for rel in out:
        if not (rel.endswith(".py") or rel.startswith(("libexec/", "bin/"))):
            continue
        if rel.startswith(".github/"):
            continue
        parts = rel.split("/")
        if "tests" in parts or "fixtures" in parts:
            continue
        if parts[-1].startswith("test_") or parts[-1] == "conftest.py":
            continue
        result.append(rel)
    return result


def _shebang_kind(root: Path, rel: str) -> str:
    """"python" / "bash" / "other" by shebang (first line)."""
    try:
        with (root / rel).open("rb") as fh:
            first = fh.readline(120).decode("utf-8", errors="replace")
    except OSError:
        return "other"
    if "python" in first:
        return "python"
    if first.startswith("#!"):
        return "bash" if ("bash" in first or first.strip().endswith("sh")) else "other"
    return "python" if rel.endswith(".py") else "other"


def _finding_key(v) -> str:
    return f"{v.file}::{v.func_name}::{v.kind}::{v.detail}"


def _load_baseline(path: Path) -> tuple[dict[str, dict], dict[str, dict]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    entries = data.get("entries", {})
    bash_entries = data.get("bash_manual_audit", {})
    bad = [k for k, e in list(entries.items()) + list(bash_entries.items())
           if not str(e.get("note", "")).strip()
           or "TODO" in str(e.get("note", ""))]
    if bad:
        raise SystemExit(
            "baseline entries missing a real note (empty/TODO): "
            + ", ".join(sorted(bad))
        )
    return entries, bash_entries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=_DEFAULT_ROOT)
    parser.add_argument("--baseline", type=Path, default=_BASELINE_PATH,
                        help="baseline JSON path (tests point this at "
                             "scratch baselines)")
    parser.add_argument("--write-baseline", action="store_true",
                        help="regenerate the baseline from current "
                             "unregistered hits (notes must then be "
                             "filled in by hand)")
    args = parser.parse_args(argv)
    root = args.root.resolve()

    sys.path.insert(0, str(root))
    import core.security.report_writer_audit as rwa

    registered = set(rwa._REPORT_WRITER_FILES) | set(rwa._MERMAID_FENCE_FILES)

    all_candidates = _candidates(root)
    # Non-Python launcher scripts: the AST detector cannot walk them —
    # they take the manual-audit tier instead of the scan.
    bash_scripts = [rel for rel in all_candidates
                    if rel.startswith(("libexec/", "bin/"))
                    and _shebang_kind(root, rel) != "python"]
    candidates = [rel for rel in all_candidates if rel not in set(bash_scripts)]

    registered_hits = []
    unregistered: dict[str, list] = {}
    for rel, vs in zip(candidates, _audit_candidates(root, candidates)):
        if not vs:
            continue
        if rel in registered:
            registered_hits.extend(vs)
        else:
            for v in vs:
                unregistered.setdefault(_finding_key(v), []).append(v)

    if args.write_baseline:
        entries = {k: {"note": "TODO: triage"} for k in sorted(unregistered)}
        args.baseline.write_text(json.dumps(
            {"_comment": "see check_report_writer_closure.py",
             "entries": entries}, indent=2) + "\n", encoding="utf-8")
        print(f"baseline written: {len(entries)} entries "
              f"(fill in the notes before committing)")
        return 0

    baseline, bash_audited = _load_baseline(args.baseline)
    new = {k: vs for k, vs in unregistered.items() if k not in baseline}
    stale = [k for k in baseline if k not in unregistered]
    bash_new = sorted(set(bash_scripts) - set(bash_audited))
    bash_stale = sorted(set(bash_audited) - set(bash_scripts))

    failed = False
    if bash_new:
        failed = True
        print(f"{len(bash_new)} non-Python launcher script(s) outside the "
              "manual-audit tier.")
        print("The AST detector cannot walk bash — review the script's "
              "echo/printf lanes by hand for untrusted interpolations, then "
              "add a bash_manual_audit entry with a note to "
              "report_writer_closure_baseline.json:")
        for rel in bash_new:
            print(f"  {rel}")
        print()
    if registered_hits:
        failed = True
        print("REGISTERED report writers with unsanitised foreign values "
              "(fix the site or add an AllowlistEntry in "
              "core/security/report_writer_audit.py):")
        print(rwa.render_violations(registered_hits))
        print()
    if new:
        failed = True
        print(f"{len(new)} NEW unregistered report-writer finding(s).")
        print("An operator-facing print/report site is emitting "
              "LLM-/tool-derived text outside the audited writer set.")
        print("Remediation (in order of preference):")
        print("  1. sanitise the site (sanitise_for_terminal for TTY "
              "output, sanitise_string/_inline/_code for markdown) AND "
              "register the file in _REPORT_WRITER_FILES;")
        print("  2. if the site is genuinely safe, register the file and "
              "add an AllowlistEntry with an audit note;")
        print("  3. only for triaged residuals: add a baseline entry with "
              "a note to report_writer_closure_baseline.json.")
        print()
        for key in sorted(new):
            v = new[key][0]
            print(f"  {v.file}:{v.line} [{v.kind}] detail={v.detail!r} "
                  f"in {v.func_name}()  key={key}")
        print()
    if stale:
        print(f"note: {len(stale)} stale baseline entr"
              f"{'y' if len(stale) == 1 else 'ies'} no longer fire "
              "(safe to remove):")
        for k in stale:
            print(f"  {k}")

    if bash_stale:
        print(f"note: {len(bash_stale)} stale bash_manual_audit entr"
              f"{'y' if len(bash_stale) == 1 else 'ies'} (script gone or "
              "now Python; safe to remove):")
        for rel in bash_stale:
            print(f"  {rel}")

    counts = Counter(v.file for vs in unregistered.values() for v in vs)
    print(f"closure scan: {len(candidates)} candidates, "
          f"{len(registered)} registered writers, "
          f"{sum(counts.values())} baselined hits in {len(counts)} files, "
          f"{len(new)} new, {len(stale)} stale, "
          f"{len(bash_scripts)} bash manual-audit")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
