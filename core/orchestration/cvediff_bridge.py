"""Bridge /cve-diff discovery output into /cve-env builds.

A ``/cve-diff run CVE-X`` leaves ``{CVE}.osv.json`` in its run
directory: the fix commit resolved in an actual clone, the pre-patch
parent commit (``database_specific.diff_against``), the diff shape
(mirror-vs-upstream signal), and the two-method pointer consensus.
Those are verified facts a later ``/cve-env build CVE-X`` should start
from instead of re-researching them with LLM turns.

This module is the mechanical reader: no LLM, no ``cve_diff`` package
import (the artifact is plain JSON — same layering rule as
:mod:`core.orchestration.understand_bridge`). Search is three-tier and
needs no ``--out`` alignment:

1. **Explicit / co-located**: ``{CVE}.osv.json`` in a caller-named dir.
2. **Project runs**: run dirs under the active project's output dir.
3. **Global out/**: any run dir carrying the artifact for this CVE.

Candidates are ranked mirror-safety first (``diff_shape == "source"``
and pointer consensus not disagreeing), then newest artifact wins.

The returned facts are HINTS WITH PROVENANCE, never gates: consumers
present them to the agent labeled with their origin, and runtime
evidence always wins. The pre-patch boundary handed over is the
``commit_before`` COMMIT (an exact buildable ref) — the persisted OSV
record carries GIT ranges only, so no version literal is derivable
here; the agent pins the version literal itself as usual.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass(frozen=True)
class FixPointer:
    """Verified discovery facts for one CVE, read from a /cve-diff run."""

    cve_id: str
    repository_url: str
    fix_commit: str
    commit_before: str          # pre-patch commit — the buildable boundary
    diff_shape: str = ""        # "source" | "packaging_only" | "notes_only"
    consensus_verdict: str = ""  # e.g. "agree" / "disagree" / "" (skipped)
    files_changed: int = 0
    source_run: str = ""        # provenance: dir the artifact came from

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def mirror_warning(self) -> bool:
        """True when the discovered repo is likely a downstream mirror
        (packaging/notes-only diff) — repo/commit facts are weak."""
        return bool(self.diff_shape) and self.diff_shape != "source"


@dataclass(frozen=True)
class _Candidate:
    pointer: FixPointer
    mtime_ns: int
    tier: int
    clean: bool = field(default=True)  # source-shaped, consensus not disagreeing


def find_fix_pointer(
    cve_id: str,
    out_dir: Path | str | None = None,
    project_dir: Path | str | None = None,
) -> FixPointer | None:
    """Locate the best /cve-diff discovery for ``cve_id``.

    ``out_dir`` is tier 1 (an explicit run dir, or the enclosing run's
    output dir when artifacts are co-located). ``project_dir`` scopes
    tier 2; when omitted, the active project (``.active`` symlink) is
    used. Tier 3 scans the global out/ root. Returns ``None`` when no
    parseable artifact exists anywhere — the caller's hint is "run
    /cve-diff first".
    """
    if not _CVE_RE.fullmatch(cve_id or ""):
        return None

    candidates: list[_Candidate] = []
    seen: set[Path] = set()

    def _collect(root: Path, tier: int, direct: bool) -> None:
        cand = _load_artifact(root / f"{cve_id}.osv.json", tier)
        if cand is not None and root.resolve() not in seen:
            seen.add(root.resolve())
            candidates.append(cand)
            return
        if direct:
            return
        try:
            children = [d for d in root.iterdir() if d.is_dir()]
        except OSError:
            return
        for child in children:
            resolved = child.resolve()
            if resolved in seen:
                continue
            cand = _load_artifact(child / f"{cve_id}.osv.json", tier)
            if cand is not None:
                seen.add(resolved)
                candidates.append(cand)

    if out_dir:
        _collect(Path(out_dir), tier=1, direct=True)
    if candidates:
        # An explicitly-named dir with a parseable artifact wins outright.
        return candidates[0].pointer

    proj = _resolve_project_dir(project_dir)
    if proj is not None:
        _collect(proj, tier=2, direct=False)
    out_root = _out_root()
    if out_root is not None:
        _collect(out_root, tier=3, direct=False)

    if not candidates:
        return None
    best = sorted(
        candidates,
        key=lambda c: (c.clean, -c.tier, c.mtime_ns),
        reverse=True,
    )[0]
    logger.debug(
        "cvediff_bridge: selected %s (tier %d, clean=%s)",
        best.pointer.source_run, best.tier, best.clean,
    )
    return best.pointer


def write_fix_pointer_artifact(pointer: FixPointer,
                               out_dir: Path | str) -> Path:
    """Write ``{CVE}.osv.json`` in the exact shape ``find_fix_pointer``
    reads — the bridge owns its artifact format from both sides.

    For producers that hold verified pointer facts WITHOUT a /cve-diff
    run (the cvefix corpus: entries carry a public repo + fix commit by
    the provenance hard gate, and the parent commit resolves
    mechanically). The record is minimal-but-valid: readers get the
    same fields a /cve-diff-rendered artifact carries, with
    ``database_specific.synthesized_by`` naming the producer so a
    forensic reader can tell it from a discovery run's output.
    """
    if not _CVE_RE.fullmatch(pointer.cve_id or ""):
        msg = f"not a CVE id: {pointer.cve_id!r}"
        raise ValueError(msg)
    if not (pointer.repository_url and pointer.fix_commit
            and pointer.commit_before):
        msg = (
            "write_fix_pointer_artifact needs repository_url, "
            "fix_commit, and commit_before"
        )
        raise ValueError(msg)
    base = pointer.repository_url.removesuffix(".git").rstrip("/")
    dbs: dict = {
        "files_changed": pointer.files_changed,
        "diff_against": pointer.commit_before,
        "diff_shape": pointer.diff_shape or "source",
        "synthesized_by": pointer.source_run or "cvediff_bridge",
    }
    if pointer.consensus_verdict:
        dbs["consensus"] = {"verdict": pointer.consensus_verdict}
    record = {
        "schema_version": "1.6.0",
        "id": pointer.cve_id,
        "modified": "",
        "references": [
            {"type": "FIX", "url": f"{base}/commit/{pointer.fix_commit}"},
        ],
        "affected": [{
            "ranges": [{
                "type": "GIT",
                "repo": pointer.repository_url,
                "events": [
                    {"introduced": pointer.commit_before},
                    {"fixed": pointer.fix_commit},
                ],
            }],
        }],
        "database_specific": dbs,
    }
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{pointer.cve_id}.osv.json"
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return path


def _resolve_project_dir(project_dir: Path | str | None) -> Path | None:
    if project_dir:
        p = Path(project_dir)
        return p if p.is_dir() else None
    try:
        from core.json import load_json
        from core.startup import PROJECTS_DIR, get_active_name
        name = get_active_name()
        if not name:
            return None
        data = load_json(PROJECTS_DIR / f"{name}.json")
        if isinstance(data, dict) and data.get("output_dir"):
            p = Path(data["output_dir"])
            return p if p.is_dir() else None
    except Exception:  # noqa: BLE001 — bridge is best-effort by contract
        logger.debug("cvediff_bridge: active-project resolution failed",
                     exc_info=True)
    return None


def _out_root() -> Path | None:
    try:
        from core.config import RaptorConfig
        root = Path(RaptorConfig.get_out_dir())
        return root if root.is_dir() else None
    except Exception:  # noqa: BLE001 — bridge is best-effort by contract
        logger.debug("cvediff_bridge: out-root resolution failed",
                     exc_info=True)
        return None


def _load_artifact(path: Path, tier: int) -> _Candidate | None:
    """Parse one ``{CVE}.osv.json`` into a candidate, or None."""
    try:
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        mtime_ns = path.stat().st_mtime_ns
    except (OSError, json.JSONDecodeError):
        logger.debug("cvediff_bridge: unreadable artifact %s", path,
                     exc_info=True)
        return None
    if not isinstance(data, dict):
        return None

    cve_id = data.get("id") or ""
    dbs = data.get("database_specific")
    dbs = dbs if isinstance(dbs, dict) else {}

    repo, fix_commit = "", ""
    for aff in data.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        for rng in aff.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            repo = rng.get("repo") or repo
            for event in rng.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    fix_commit = event["fixed"]
    commit_before = dbs.get("diff_against") or ""
    if not (cve_id and repo and fix_commit and commit_before):
        logger.debug("cvediff_bridge: artifact %s lacks pointer fields", path)
        return None

    consensus = dbs.get("consensus")
    verdict = ""
    if isinstance(consensus, dict):
        verdict = str(consensus.get("verdict") or "")
    shape = str(dbs.get("diff_shape") or "")
    pointer = FixPointer(
        cve_id=cve_id,
        repository_url=repo,
        fix_commit=fix_commit,
        commit_before=commit_before,
        diff_shape=shape,
        consensus_verdict=verdict,
        files_changed=int(dbs.get("files_changed") or 0),
        source_run=str(path.parent),
    )
    clean = (shape in ("", "source")) and verdict != "disagree"
    return _Candidate(pointer=pointer, mtime_ns=mtime_ns, tier=tier,
                      clean=clean)
