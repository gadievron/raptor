"""Decomp-tree conformance metric — the honest sweep denominator.

Measures how much of an emitted decomp-tree the downstream tool
substrate can actually parse, per tool leg:

* **tree-sitter C** — one sandboxed child process
  (:mod:`packages.ghidra._conformance_child` under ``core.sandbox.run``:
  namespace + Landlock, network blocked) parses every tree file and
  reports per-file ok / parse-error verdicts. The parse never runs in
  the parent, and never runs unsandboxed: decomp-tree content is
  decompiled from the analysed binary, and a leg whose sandbox cannot
  engage is reported UNAVAILABLE instead of measured unsafely.
* **semgrep** — one bounded scan with a never-matching probe rule
  through :func:`packages.semgrep.runner.run_rule`'s default sandboxed
  path; ``paths.scanned`` / per-file error sidecars become the per-file
  parsed / failed verdicts.

The aggregate ``parsed_rate`` is the MINIMUM across available legs —
the conservative fraction of the tree every sweep tool could read.
(A per-leg maximum would let one tolerant parser hide the other leg's
blind spot; consumers wanting a per-tool number read the leg blocks.)
Files failing any available leg land on the quarantine list with
escaped reasons.

Written as ``decomp-tree-conformance.json`` next to the tree's
``decomp-map.json`` — at tree build time via the
:func:`packages.ghidra.decomp_tree.write_decomp_tree` seam, and
on demand via ``packages/ghidra/scripts/decomp-tree-conformance``.
The audit report cites this file as the sweep-coverage denominator.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CONFORMANCE_NAME = "decomp-tree-conformance.json"

#: Wall budget for the sandboxed tree-sitter child over the whole
#: tree. Lower and a legitimately large tree (the emitter allows up
#: to 256 MiB) reports the leg unavailable; higher and a crafted
#: pathological file holds the build/sweep phase hostage. One
#: interpreter boot plus a linear parse fits comfortably.
TS_CHILD_TIMEOUT_S = 300
#: Same trade-off for the semgrep probe scan (semgrep startup is
#: heavier, parse is the same linear pass).
SEMGREP_PROBE_TIMEOUT_S = 600
#: Child stdout ceiling — sized by MAX_FILES short per-file records,
#: not by tree content; anything larger is a malfunctioning or
#: compromised child and the leg reports unavailable.
MAX_CHILD_OUTPUT_BYTES = 8 * 1024 * 1024
#: File-count ceiling for enumeration (shared with the child's cap).
MAX_FILES = 4096
#: Quarantine list bound in the written record — counts stay exact.
MAX_QUARANTINE = 200

_PROBE_RULE = Path(__file__).resolve().parent / "data" / \
    "conformance-probe.yaml"


def _esc(text: object, limit: int = 300) -> str:
    from core.security.log_sanitisation import escape_nonprintable
    s = escape_nonprintable(str(text or ""))
    return s if len(s) <= limit else s[:limit] + "…"


def _tree_files(tree_root: Path) -> tuple[list[str], bool]:
    names = sorted(p.name for p in tree_root.glob("*.c") if p.is_file())
    if (tree_root / "types.h").is_file():
        names.append("types.h")
    return names[:MAX_FILES], len(names) > MAX_FILES


def _sandboxed_ts_scan(tree_root: Path) -> dict:
    """Run the tree-sitter child under the sandbox; leg-shaped dict.

    Fail-closed on sandbox absence: the leg reports unavailable —
    this module never parses attacker-shaped pseudo-C in-process or
    in an unsandboxed child (mirrors the semgrep runner's
    no-sandbox-means-no-execution posture).
    """
    try:
        from core.sandbox.context import run as sandbox_run
    except ImportError:
        return {
            "available": False,
            "reason": "core.sandbox unavailable — refusing to parse "
                      "the decomp-tree unsandboxed",
            "files": {},
        }
    child = str(Path(__file__).resolve().with_name(
        "_conformance_child.py"))
    try:
        # Default env handling (get_safe_env + the sandbox's own
        # target-exec scrub); the child needs no RAPTOR env at all —
        # it self-anchors its imports on its own path.
        proc = sandbox_run(
            [sys.executable, "-B", child, str(tree_root)],
            target=str(tree_root),
            block_network=True,
            caller_label="decomp-conformance",
            capture_output=True,
            text=True,
            timeout=TS_CHILD_TIMEOUT_S,
        )
    except Exception as exc:  # noqa: BLE001 — SandboxSetupError, timeout, OSError
        return {"available": False,
                "reason": f"sandboxed tree-sitter child failed: "
                          f"{_esc(exc)}",
                "files": {}}
    out = proc.stdout or ""
    if proc.returncode != 0:
        return {"available": False,
                "reason": f"tree-sitter child exited "
                          f"{proc.returncode}: "
                          f"{_esc(getattr(proc, 'stderr', ''), 200)}",
                "files": {}}
    if len(out) > MAX_CHILD_OUTPUT_BYTES:
        return {"available": False,
                "reason": "tree-sitter child output over budget",
                "files": {}}
    try:
        import json
        data = json.loads(out)
    except ValueError:
        return {"available": False,
                "reason": "tree-sitter child output undecodable",
                "files": {}}
    if not isinstance(data, dict) or not isinstance(
            data.get("files"), dict):
        return {"available": False,
                "reason": "tree-sitter child output malformed",
                "files": {}}
    return data


def _semgrep_leg(
    tree_root: Path,
    names: list[str],
    run_rule_fn: Any = None,
) -> dict:
    """One probe scan → per-file parsed/failed verdicts."""
    if run_rule_fn is None:
        try:
            from packages.semgrep.runner import is_available, run_rule
        except ImportError:
            return {"available": False,
                    "reason": "semgrep runner unavailable"}
        if not is_available():
            return {"available": False,
                    "reason": "semgrep not installed"}
        run_rule_fn = run_rule
    if not _PROBE_RULE.is_file():
        return {"available": False,
                "reason": "conformance probe rule missing"}
    try:
        # Default-sandboxed runner path — the trusted-input opt-out
        # is never passed (decomp-tree content is target-derived).
        result = run_rule_fn(
            tree_root, str(_PROBE_RULE),
            timeout=SEMGREP_PROBE_TIMEOUT_S,
        )
    except Exception as exc:  # noqa: BLE001 — a probe crash = leg unavailable
        return {"available": False,
                "reason": f"probe scan failed: {_esc(exc)}"}
    errors = list(getattr(result, "errors", None) or [])
    rc = getattr(result, "returncode", 0)
    if errors or rc not in (0, 1):
        return {
            "available": False,
            "reason": _esc(errors[0] if errors
                           else f"semgrep exited with code {rc}"),
        }
    examined = {
        Path(str(p)).name
        for p in getattr(result, "files_examined", None) or []
    }
    failed: dict[str, str] = {}
    for rec in getattr(result, "files_failed", None) or []:
        if isinstance(rec, dict) and rec.get("path"):
            failed[Path(str(rec["path"])).name] = _esc(
                rec.get("reason", "parse failure"))
    files: dict[str, dict] = {}
    for name in names:
        if name in failed:
            files[name] = {"ok": False, "reason": failed[name]}
        elif name in examined:
            files[name] = {"ok": True, "reason": ""}
        else:
            # Silently skipped scans are not parses — the same
            # scanned-witness honesty the sweep engine applies.
            files[name] = {
                "ok": False,
                "reason": "not examined (missing from paths.scanned)",
            }
    return {"available": True, "reason": "", "files": files}


def _leg_summary(leg: dict, names: list[str]) -> dict:
    files = leg.get("files") or {}
    parsed = sum(1 for n in names if (files.get(n) or {}).get("ok"))
    summary: dict[str, Any] = {
        "available": bool(leg.get("available")),
        "parsed": parsed,
        "failed": len(names) - parsed if leg.get("available") else 0,
        "rate": (parsed / len(names)) if names and leg.get("available")
        else None,
    }
    if leg.get("reason"):
        summary["reason"] = _esc(leg["reason"], 500)
    return summary


def measure_conformance(
    tree_root: "Path | str",
    *,
    run_rule_fn: Any = None,
    ts_scan_fn: Any = None,
    write: bool = True,
) -> dict[str, Any]:
    """Measure per-tool parse conformance of the tree at *tree_root*.

    Returns the record (and writes ``decomp-tree-conformance.json``
    into the tree root unless ``write=False``). ``run_rule_fn`` /
    ``ts_scan_fn`` are test injection points; production resolves to
    the sandboxed semgrep runner and the sandboxed tree-sitter child.
    Never raises — an unmeasurable tree yields a record whose legs
    say why.
    """
    tree_root = Path(tree_root)
    names, truncated = _tree_files(tree_root)

    if names:
        ts_leg_raw = (ts_scan_fn or _sandboxed_ts_scan)(tree_root)
        if not isinstance(ts_leg_raw, dict):
            ts_leg_raw = {"available": False,
                          "reason": "tree-sitter leg malformed",
                          "files": {}}
        sg_leg_raw = _semgrep_leg(tree_root, names, run_rule_fn)
    else:
        ts_leg_raw = {"available": False, "reason": "empty tree",
                      "files": {}}
        sg_leg_raw = {"available": False, "reason": "empty tree"}

    ts_summary = _leg_summary(ts_leg_raw, names)
    sg_summary = _leg_summary(sg_leg_raw, names)

    rates = [s["rate"] for s in (ts_summary, sg_summary)
             if s["rate"] is not None]
    parsed_rate = min(rates) if rates else None

    quarantine: list[dict] = []
    quarantine_total = 0
    for name in names:
        reasons = []
        for label, leg in (("tree-sitter", ts_leg_raw),
                           ("semgrep", sg_leg_raw)):
            if not leg.get("available"):
                continue
            verdict = (leg.get("files") or {}).get(name)
            if verdict is None:
                # Enumeration skew: an available leg recorded NO
                # verdict for a file the parent enumerated. It counts
                # against the leg's rate (never a silent penalty) and
                # the quarantine entry states why.
                reasons.append(
                    f"{label}: no verdict recorded for this file "
                    "(leg enumeration skew)")
            elif not verdict.get("ok"):
                reasons.append(
                    f"{label}: "
                    f"{_esc(verdict.get('reason') or 'parse failure')}")
        if reasons:
            quarantine_total += 1
            if len(quarantine) < MAX_QUARANTINE:
                quarantine.append({"file": _esc(name, 200),
                                   "reasons": reasons})

    record: dict[str, Any] = {
        "schema": 1,
        "tree_root": str(tree_root),
        "files_total": len(names),
        "files_truncated": truncated,
        "tree_sitter": ts_summary,
        "semgrep": sg_summary,
        # The honest sweep denominator: the conservative (minimum)
        # parsed fraction across AVAILABLE legs; None when no leg
        # could measure — consumers must state "unavailable", never
        # assume 100%.
        "parsed_rate": parsed_rate,
        "quarantine": quarantine,
        "quarantine_total": quarantine_total,
    }
    try:
        from core.coverage.journal import now_iso
        record["generated_at"] = now_iso()
    except Exception:  # noqa: BLE001 — timestamp is best-effort
        pass
    if write:
        try:
            from core.json import save_json
            save_json(tree_root / CONFORMANCE_NAME, record)
        except Exception:  # noqa: BLE001 — measurement must not fail the build
            logger.warning("decomp-tree conformance write failed",
                           exc_info=True)
    return record
