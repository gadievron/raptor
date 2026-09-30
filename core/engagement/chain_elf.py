"""ELF per-artifact analysis chain — thin sequencing glue over
EXISTING tools (the ``raptor-binary-study-oneshot`` idiom, extended
to the whole per-class chain the engagement design names for
``elf-linux`` artifacts):

    investigate → import → study → checklist → audit →
    auto-siblings → seed re-review → validate(survivors) →
    ledger verdict write-back

No stage performs new analysis. Each stage invokes one existing
command (``raptor-binary investigate``, ``raptor-ghidra import``,
``raptor-binary-study``, ``raptor-audit run/resume``,
``raptor-binary siblings``) or one existing in-process builder
(``core.inventory.binary_builder.build_binary_checklist``); this
module only sequences them, hands artifacts across stage boundaries,
and writes per-stage status back to the engagement ledger
(``core.engagement.ledger`` — its status vocabulary, unchanged).
LLM-never-classifies holds at every stage: the chain reads journal
VERDICT rows (tool-governed) and file existence, never LLM prose.

Depth policy (read defensively; never assigned here):
    The depth governor writes tier labels into the ledger —
    ``row["policy"]["tier"|"depth"]`` or the existing
    ``row["status"]["depth"]`` slot. This module READS them:
    T0 = chain does not run; T1 = investigate + import;
    T2 = + study + checklist; T3 = full chain. Absent/unrecognised
    labels default to the FULL chain with the assumption recorded in
    the chain state and the verdict record (``assumed_default``).

Classes other than ``elf-linux``:
    A labeled dispatch arm records ``chain_not_built:<class>`` as a
    chain degradation (the design's honesty rule) and skips — the
    other per-class chains are later series, and silence here would
    read as coverage.

Resume (idempotent, operator-schedulable):
    Per-artifact chain state is durable
    (``<output_dir>/chains/<artifact-id>/chain-state.json``); an
    interrupted chain records the reached stage in the ledger and a
    re-run continues from the first unsettled stage. Stage completion
    is judged by the stage's OWN artifact existence plus the recorded
    state — never wall-clock or pid liveness. Distinct exit codes:
    0 advanced/completed, 1 stage failure (resumable), 2 usage,
    3 nothing to do. No hooks, no daemons. A per-artifact run lock
    (flock on ``<chain-dir>/chain-run.lock``) serialises overlapping
    invocations of the SAME artifact's chain — a second invocation
    waits, then finds the stages settled and no-ops, so cron overlap
    never spawns duplicate stage children.

Content binding (fail closed, both layers):
    A chain analyses exactly the bytes the ledger inventoried. Two
    independent gates enforce it: the LEDGER gate (disk sha256 must
    equal the row's ``identity.sha256`` — a hand-edited or drifted
    ledger refuses) and the STATE gate (the chain state's recorded
    ``binary_sha256`` must equal the disk sha256 — settled stages
    from OLD bytes are never inherited by NEW bytes, even when a
    ledger rebuild kept a build-id-anchored artifact_id across a
    content swap; build-ids are attacker-forgeable). On a state
    mismatch the stale chain dir is archived aside
    (``<artifact-id>.stale-<utc>``) and the run refuses; the next
    run starts the chain from scratch.

Degradations (sticky by design):
    Recorded degradations persist across re-runs — with ONE
    documented exception: ``--mechanical-only`` LLM-stage skips carry
    ``rerun_without=mechanical_only`` and re-run when the flag is
    absent (the condition is operator-chosen per invocation, not a
    property of the artifact). RE-database exports at/over the
    512MiB cap (``core.json.utils.RE_DATABASE_MAX_BYTES``) record a
    degradation and the chain CONTINUES — never aborts.

Verdict record (fixed schema):
    ``policy_depth | reached_depth | degradation reasons |
    format_capability_tier`` (at run time) plus journal verdict
    counts (earned coverage — read-coverage is an advisory stratum
    and is not consulted here). "No findings" at any sub-full
    capability renders NON-ATTESTING wording ("no findings within
    <tier> capability"). Attestation additionally requires the
    earned-coverage floor: at least one journal verdict row, loaded
    through the completeness-checked journal API — an empty,
    garbled, or partially-loadable journal renders the chain
    non-attesting with the floor reason recorded
    (``journal_floor``).

Rendering/spawn safety: every echoed value derived from target bytes
(paths, ids from a hand-editable ledger) renders through
``core.security.log_sanitisation``; children receive list-based argv
and a sanitised environment (``get_safe_env()`` for mechanical
stages, ``get_llm_env()`` for the LLM-calling stages so provider
credentials and transport routing reach RAPTOR's own children).
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from core.config import RaptorConfig, pin_raptor_dir
from core.engagement.ledger import (
    STATUS_STATES,
    load_ledger,
    set_artifact_status,
    write_artifact_checklist,
)
from core.atomic_fs.fs_lock import artifact_lock
from core.hash import sha256_file
from core.json import load_json, save_json
from core.security.log_sanitisation import sanitise_for_terminal

# ── Exit codes (distinct + idempotent, safe under operator-side
#    scheduling) ─────────────────────────────────────────────────────
RC_OK = 0        # chain advanced or completed this invocation
RC_FAILED = 1    # a stage failed — state recorded, re-run resumes
RC_USAGE = 2     # operator error (bad id, missing ledger, bad flags)
RC_NOTHING = 3   # nothing to do (already complete / not runnable)

# ── Layout ───────────────────────────────────────────────────────────
CHAIN_DIR_NAME = "chains"
CHAIN_STATE_FILENAME = "chain-state.json"
SURVIVORS_FILENAME = "validate-survivors.json"
CHAIN_SCHEMA_VERSION = 1
VERDICT_SCHEMA = "engage-chain-verdict/1"

#: The one class this chain is built for. Other classes take the
#: labeled not-built arm — never a silent skip, never a guessed chain.
CLASS_ELF = "elf-linux"

# ── Stages ───────────────────────────────────────────────────────────
STAGES: tuple[str, ...] = (
    "investigate", "import", "study", "checklist",
    "audit", "siblings", "seed_rereview", "validate",
)
#: Stages whose child may call LLM providers (env: get_llm_env()).
LLM_STAGES = frozenset({"study", "audit", "seed_rereview"})

#: Minimum engagement depth at which each stage runs. T1 map-tier is
#: investigate+import (the mechanical substrate a later deepening
#: resumes from); T2 adds the study and the coverage denominator;
#: T3 is the full chain.
_STAGE_MIN_DEPTH: dict[str, int] = {
    "investigate": 1, "import": 1,
    "study": 2, "checklist": 2,
    "audit": 3, "siblings": 3, "seed_rereview": 3, "validate": 3,
}
_DEPTH_NUM = {"T0": 0, "T1": 1, "T2": 2, "T3": 3}
DEFAULT_DEPTH = "T3"

#: Stage-outcome vocabulary for chain-state records.
_OUTCOME_STATES = frozenset({"done", "degraded", "skipped", "failed"})

#: Wall bound per child — same rationale as the oneshot stub: the
#: import leg runs a JVM with its own 3600s internal timeout and the
#: audit bounds its own children; this is the belt-and-braces outer
#: bound so a wedged child cannot hang an unattended chain run
#: forever. Too tight kills healthy work on large binaries; too loose
#: costs a workday on a hang.
_CHILD_TIMEOUT_S = 2 * 3600

#: Near-cap warning threshold for the RE database (the design rule:
#: exports NEAR the cap record a degradation, never abort the chain).
_REDB_NEAR_CAP_RATIO = 0.9

#: Own copy of the ledger's artifact-id charset (the ledger's is
#: private by design; a parity test pins the two patterns equal so
#: they cannot drift). Operator-typed ids are gated on this BEFORE
#: they are echoed or used in paths.
_ARTIFACT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,96}$")


def _esc(value: str, max_len: int = 300) -> str:
    """Terminal-safe rendering for target-/operator-derived text."""
    return sanitise_for_terminal(value, max_len=max_len)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _say(msg: str) -> None:
    print(f"engage-chain: {msg}", file=sys.stderr)


# ── The single subprocess seam ───────────────────────────────────────
# Every child of this module goes through _run_child (a CI fence
# censuses this): list-based argv only, sanitised env, own process
# group with killpg on timeout so a wedged JVM/engine grandchild
# cannot outlive the stage.

def _run_child(cmd: list[str], *, llm: bool = False,
               timeout_s: int = _CHILD_TIMEOUT_S) -> int:
    """Run one existing tool as a child; return its exit code.

    ``llm=True`` selects ``get_llm_env()`` (safe env + provider keys +
    transport routing) — required for the LLM-calling stages, whose
    children would otherwise auth-starve; mechanical stages get the
    plain ``get_safe_env()`` allowlist. Both are pinned to THIS tree's
    ``RAPTOR_DIR`` so children import this checkout's modules.
    """
    env = (RaptorConfig.get_llm_env() if llm
           else RaptorConfig.get_safe_env())
    pin_raptor_dir(env)
    # cmd embeds artifact paths derived from the (hostile) target
    # tree — escape the echoed command line.
    _say(f"running {_esc(' '.join(str(c) for c in cmd), max_len=2000)}")
    try:
        proc = subprocess.Popen(cmd, env=env, start_new_session=True)
    except OSError as exc:
        _say(f"failed to run {_esc(str(cmd[0]))}: {_esc(str(exc))}")
        return 1
    try:
        return proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _say(f"child produced no exit within {timeout_s}s — killing "
             "its process group")
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            proc.kill()
        proc.wait()
        return 1


# ── Chain context / state ────────────────────────────────────────────

@dataclass
class ChainContext:
    """Everything one artifact's stage runners need."""

    output_dir: Path
    chain_dir: Path
    artifact_id: str
    binary: Path
    policy_depth: str
    policy_source: str
    model: str | None = None
    max_cost: float | None = None
    mechanical_only: bool = False

    @property
    def libexec(self) -> Path:
        return Path(RaptorConfig.REPO_ROOT) / "libexec"

    @property
    def investigate_dir(self) -> Path:
        return self.chain_dir / "investigate"

    @property
    def import_dir(self) -> Path:
        return self.chain_dir / "ghidra-import"

    @property
    def redb_path(self) -> Path:
        # At the CHAIN ROOT (not inside ghidra-import/) so the audit
        # stage's existing discovery (``core.audit.binary_context.
        # find_redb`` searches out_dir then out_dir.parent) finds it
        # from ``<chain>/audit`` without new discovery code.
        return self.chain_dir / "re-database.json"

    @property
    def study_dir(self) -> Path:
        return self.chain_dir / "study"

    @property
    def audit_dir(self) -> Path:
        return self.chain_dir / "audit"

    @property
    def rereview_dir(self) -> Path:
        return self.chain_dir / "audit-rereview"

    @property
    def seeds_path(self) -> Path:
        # Written by ``raptor-binary siblings <run_dir> --auto`` into
        # the investigate run dir (its landed contract).
        return self.investigate_dir / "sibling-hypotheses.json"


@dataclass
class StageOutcome:
    """One stage attempt's result.

    ``status`` ∈ done | degraded | skipped | failed.
    ``rerun_without`` names the invocation condition whose absence
    re-opens a degraded stage (the stickiness exception — currently
    only ``mechanical_only``). ``extra_degradations`` are chain-level
    degradations recorded even on a ``done`` stage (e.g. an RE
    database near the size cap).
    """

    status: str
    reason: str = ""
    rerun_without: str = ""
    extra_degradations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in _OUTCOME_STATES:
            raise ValueError(f"invalid stage outcome: {self.status!r}")


def chain_dir_for(output_dir: Path | str, artifact_id: str) -> Path:
    """This artifact's durable chain home under the ledger dir."""
    if not _ARTIFACT_ID_RE.fullmatch(artifact_id):
        raise ValueError(f"invalid artifact id: {artifact_id!r}")
    return Path(output_dir) / CHAIN_DIR_NAME / artifact_id


def load_chain_state(chain_dir: Path) -> dict[str, Any]:
    """The chain-state document ({} when absent/unreadable)."""
    doc = load_json(chain_dir / CHAIN_STATE_FILENAME)
    return doc if isinstance(doc, dict) else {}


def _save_chain_state(chain_dir: Path, state: dict[str, Any]) -> None:
    path = chain_dir / CHAIN_STATE_FILENAME
    chain_dir.mkdir(parents=True, exist_ok=True)
    with artifact_lock(path, subject="engagement chain state"):
        save_json(path, state)


# ── Depth policy (read-only; the governor owns assignment) ──────────

def _norm_depth(label: Any) -> str | None:
    """``T0``..``T3`` (any case) → canonical label; else ``None``."""
    if isinstance(label, str) and re.fullmatch(r"[Tt][0-3]",
                                               label.strip()):
        return "T" + label.strip()[1]
    return None


def resolve_policy_depth(row: dict[str, Any]) -> tuple[str, str]:
    """(depth label, source) for one ledger row.

    Defensive read order: the governor's ``policy`` block
    (``tier`` then ``depth``), then the ledger's ``status.depth``
    slot, then the recorded-assumption default (full chain).
    Unrecognised labels fall through — a garbled policy field must
    not silently pick a shallower chain than the default.
    """
    pol = row.get("policy")
    if isinstance(pol, dict):
        for key in ("tier", "depth"):
            norm = _norm_depth(pol.get(key))
            if norm is not None:
                return norm, f"policy.{key}"
    status = row.get("status")
    if isinstance(status, dict):
        norm = _norm_depth(status.get("depth"))
        if norm is not None:
            return norm, "status.depth"
    return DEFAULT_DEPTH, "assumed_default"


def _planned_stages(depth: str) -> list[str]:
    n = _DEPTH_NUM.get(depth, _DEPTH_NUM[DEFAULT_DEPTH])
    return [s for s in STAGES if _STAGE_MIN_DEPTH[s] <= n]


# ── Stage-completion judgement (recorded state + own artifact) ──────

def _investigate_artifact(ctx: ChainContext) -> bool:
    return any((ctx.investigate_dir / name).is_file()
               for name in ("binary-investigation.json",
                            "map-result.json"))


def _stage_artifact_ok(stage: str, ctx: ChainContext) -> bool:
    """Does the stage's own completion artifact exist on disk?"""
    if stage == "investigate":
        return _investigate_artifact(ctx)
    if stage == "import":
        return ctx.redb_path.is_file()
    if stage == "study":
        return (ctx.study_dir / "domain-model.json").is_file()
    if stage == "checklist":
        # Authenticated presence on BOTH handoffs, not raw file
        # existence: a tampered document reads as absent (the frame
        # gate refuses it), and a raw existence check would keep the
        # stage "done" over a slot no consumer can read — stranding
        # the refusal forever. Judging by the readers makes re-running
        # the stage rebuild and re-stamp, which is exactly the remedy
        # the refusal log advertises. read_checklist also handles the
        # sharded layout, where no checklist.json single file exists.
        from core.engagement.ledger import read_artifact_checklist
        from core.inventory import read_checklist
        return (read_artifact_checklist(ctx.output_dir,
                                        ctx.artifact_id) is not None
                and bool(read_checklist(ctx.audit_dir)))
    if stage == "audit":
        return (ctx.audit_dir / "audit-report.json").is_file()
    if stage == "seed_rereview":
        return (ctx.rereview_dir / "audit-report.json").is_file()
    if stage == "validate":
        return (ctx.chain_dir / SURVIVORS_FILENAME).is_file()
    # siblings: run_siblings writes its artifacts only when clusters
    # form — the recorded state is the completion authority.
    return True


def _stage_settled(rec: Any, stage: str, ctx: ChainContext) -> bool:
    """Is this stage finished for THIS invocation's conditions?"""
    if not isinstance(rec, dict):
        return False
    status = rec.get("status")
    if status == "done":
        return _stage_artifact_ok(stage, ctx)
    if status == "degraded":
        # Degradations are sticky — except one whose recorded
        # condition is invocation-scoped and now absent.
        cond = rec.get("rerun_without")
        if cond == "mechanical_only" and not ctx.mechanical_only:
            return False
        return True
    if status == "skipped":
        # Skip conditions are cheap to re-evaluate and may have been
        # lifted by an earlier stage's re-run (e.g. siblings emitting
        # seeds on a deeper pass) — never latch a skip.
        return False
    return False  # failed / unknown → re-run (that IS the resume)


# ── Stage runners (sequencing + handoff only — no new analysis) ─────

def _mechanical_only_skip() -> StageOutcome:
    return StageOutcome(
        "degraded", "llm_stage_skipped:mechanical_only",
        rerun_without="mechanical_only",
    )


def _stage_investigate(ctx: ChainContext) -> StageOutcome:
    cmd = [sys.executable, str(ctx.libexec / "raptor-binary"),
           "investigate", str(ctx.binary),
           "--out", str(ctx.investigate_dir)]
    rc = _run_child(cmd)
    if rc != 0:
        return StageOutcome("failed", f"investigate rc={rc}")
    if not _investigate_artifact(ctx):
        return StageOutcome("failed",
                            "investigate exited 0 but wrote no map "
                            "artifact")
    return StageOutcome("done")


def _stage_import(ctx: ChainContext) -> StageOutcome:
    imported = ctx.import_dir / "re-database.json"
    if not imported.is_file():
        cmd = [sys.executable, str(ctx.libexec / "raptor-ghidra"),
               "import", str(ctx.binary), "--decompile-all",
               "--out", str(ctx.import_dir)]
        rc = _run_child(cmd)
        if rc != 0:
            # Includes the occupied-destination refusal — terminal by
            # the import child's landed semantics; it already printed
            # the operator's options. Never worked around here.
            return StageOutcome("failed", f"ghidra import rc={rc}")
        if not imported.is_file():
            return StageOutcome("failed",
                                "import exited 0 but wrote no "
                                "re-database.json")
    extras: list[str] = []
    from core.json.utils import RE_DATABASE_MAX_BYTES
    size = imported.stat().st_size
    if size > RE_DATABASE_MAX_BYTES:
        # Design rule: a cap-crossing export is a recorded degradation
        # for THIS artifact, never a chain abort — downstream loaders
        # will refuse the file and their stages degrade in turn.
        extras.append("re_database_over_cap")
    elif size >= int(RE_DATABASE_MAX_BYTES * _REDB_NEAR_CAP_RATIO):
        extras.append("re_database_near_cap")
    try:
        if not ctx.redb_path.is_file():
            os.link(imported, ctx.redb_path)
    except OSError:
        try:
            shutil.copy2(imported, ctx.redb_path)
        except OSError as exc:
            return StageOutcome(
                "failed",
                f"could not place re-database at the chain root: "
                f"{type(exc).__name__}")
    return StageOutcome("done", extra_degradations=tuple(extras))


def _stage_study(ctx: ChainContext) -> StageOutcome:
    if ctx.mechanical_only:
        return _mechanical_only_skip()
    redb = ctx.redb_path
    if not redb.is_file():
        return StageOutcome("degraded", "no_re_database")
    from core.json.utils import RE_DATABASE_MAX_BYTES
    if redb.stat().st_size > RE_DATABASE_MAX_BYTES:
        return StageOutcome("degraded", "re_database_over_cap")
    cmd = [sys.executable, str(ctx.libexec / "raptor-binary-study"),
           str(redb), str(ctx.study_dir)]
    # The onramp creates <import-dir>/ghidra-project/<stem>/raptor.gpr;
    # the fallback importers create none — pass --gpr only when it
    # exists (the study runs fine without incremental decompilation).
    gpr = (ctx.import_dir / "ghidra-project" / ctx.binary.stem
           / "raptor.gpr")
    if gpr.is_file():
        cmd.extend(["--gpr", str(gpr)])
    if ctx.model:
        cmd.extend(["--model", ctx.model])
    if ctx.max_cost is not None:
        cmd.extend(["--max-cost", str(ctx.max_cost)])
    rc = _run_child(cmd, llm=True)
    if rc != 0:
        return StageOutcome("failed", f"binary-study rc={rc}")
    if not (ctx.study_dir / "domain-model.json").is_file():
        return StageOutcome("failed",
                            "study exited 0 but wrote no "
                            "domain-model.json")
    return StageOutcome("done")


def _stage_checklist(ctx: ChainContext) -> StageOutcome:
    redb = ctx.redb_path
    if not redb.is_file():
        return StageOutcome("degraded", "no_re_database")
    try:
        from core.audit.binary_context import load_redb
        db = load_redb(redb)
    except (OSError, ValueError):
        # Covers the size-cap refusal (JsonBudgetExceededError is a
        # ValueError) and malformed exports — degradation, continue.
        return StageOutcome("degraded", "re_database_unloadable")
    from core.inventory.binary_builder import build_binary_checklist
    checklist = build_binary_checklist(db, binary_path=ctx.binary)
    if not checklist.get("total_items"):
        return StageOutcome("degraded", "empty_binary_checklist")
    # Two handoffs: the ledger's per-artifact coverage-denominator
    # slot, and a pre-placed run-local copy the audit stage's landed
    # target-match gate honours (recorded target_path = the resolved
    # binary, exactly what the audit resolves).
    # Through the inventory write chokepoint, not bare save_json: the
    # audit stage reads this file with the frame-authenticating
    # accessor, so a bare write hands it a checklist it can only read
    # at legacy tier (authenticated-tier authority withheld, one
    # demotion warning per artifact).
    from core.inventory import ChecklistBudgetExceededError, save_checklist
    try:
        write_artifact_checklist(ctx.output_dir, ctx.artifact_id,
                                 checklist)
        ctx.audit_dir.mkdir(parents=True, exist_ok=True)
        save_checklist(ctx.audit_dir, checklist)
    except (ChecklistBudgetExceededError, OSError) as exc:
        # A named per-row stage failure, never an uncaught abort of a
        # sweep: the chain's checklist carries ONE binary:<stem> files
        # entry, which the sharded writer cannot split — past the hard
        # per-shard reader budget the chokepoint raises instead of
        # sharding. ChecklistPathError (a planted symlink) is a
        # PermissionError and rides the OSError arm.
        return StageOutcome(
            "failed",
            f"checklist write refused: {type(exc).__name__}")
    return StageOutcome("done")


def _audit_cmd(ctx: ChainContext, out_dir: Path,
               extra: list[str]) -> list[str]:
    """``raptor-audit resume`` when the run persisted its config and
    has not completed; else a fresh ``raptor-audit run``."""
    if ((out_dir / "audit-run-config.json").is_file()
            and not (out_dir / "audit-report.json").is_file()):
        return [sys.executable, str(ctx.libexec / "raptor-audit"),
                "resume", str(out_dir)]
    cmd = [sys.executable, str(ctx.libexec / "raptor-audit"), "run",
           str(ctx.binary), "--out", str(out_dir), "--no-validate"]
    cmd.extend(extra)
    if ctx.model:
        cmd.extend(["--model", ctx.model])
    if ctx.max_cost is not None:
        cmd.extend(["--max-cost", str(ctx.max_cost)])
    return cmd


def _stage_audit(ctx: ChainContext) -> StageOutcome:
    if ctx.mechanical_only:
        return _mechanical_only_skip()
    rc = _run_child(_audit_cmd(ctx, ctx.audit_dir, []), llm=True)
    if rc != 0:
        return StageOutcome("failed", f"audit rc={rc}")
    if not (ctx.audit_dir / "audit-report.json").is_file():
        return StageOutcome("failed",
                            "audit exited 0 but wrote no "
                            "audit-report.json")
    return StageOutcome("done")


def _stage_siblings(ctx: ChainContext) -> StageOutcome:
    if not _investigate_artifact(ctx):
        return StageOutcome("degraded", "no_investigate_run")
    cmd = [sys.executable, str(ctx.libexec / "raptor-binary"),
           "siblings", str(ctx.investigate_dir), "--auto"]
    rc = _run_child(cmd)
    if rc != 0:
        # Enrichment lane: peer-group formation failing must not
        # block the verdict write-back — recorded, not fatal.
        return StageOutcome("degraded", f"siblings rc={rc}")
    return StageOutcome("done")


def _stage_seed_rereview(ctx: ChainContext) -> StageOutcome:
    if ctx.mechanical_only:
        return _mechanical_only_skip()
    seeds = ctx.seeds_path
    payload = load_json(seeds) if seeds.is_file() else None
    if not (isinstance(payload, dict) and payload.get("seeds")):
        return StageOutcome("skipped", "no_hypothesis_seeds")
    extra = ["--seed-rereview", "--hypothesis-seeds", str(seeds)]
    if (ctx.audit_dir / "audit-report.json").is_file():
        extra.extend(["--prior-journal", str(ctx.audit_dir)])
    rc = _run_child(_audit_cmd(ctx, ctx.rereview_dir, extra), llm=True)
    if rc != 0:
        return StageOutcome("failed", f"seed re-review rc={rc}")
    if not (ctx.rereview_dir / "audit-report.json").is_file():
        return StageOutcome("failed",
                            "seed re-review exited 0 but wrote no "
                            "audit-report.json")
    return StageOutcome("done")


def _journal_counts(ctx: ChainContext) -> tuple[dict[str, int], bool]:
    """Earned-coverage counts: journal VERDICT rows across the audit
    and re-review runs (read-coverage is advisory and not consulted).
    Tool-governed rows only; no LLM prose is read.

    Returns ``(counts, complete)``. The load goes through the
    completeness-checked API (``load_entries_checked``, fresh — an
    attestation decision never trusts the process-local cache);
    ``complete`` is False when ANY consulted journal loaded partially
    or failed to load, and attestation refuses on it — a bounded
    partial view must never read as full earned coverage."""
    from core.coverage.journal import load_entries_checked
    counts: dict[str, int] = {}
    complete = True
    for run_dir in (ctx.audit_dir, ctx.rereview_dir):
        if not run_dir.is_dir():
            continue
        try:
            loaded = load_entries_checked(run_dir, fresh=True)
        except (OSError, ValueError):
            complete = False
            continue
        if not loaded.complete:
            complete = False
        for entry in loaded.entries:
            counts[entry.verdict] = counts.get(entry.verdict, 0) + 1
    return counts, complete


def _stage_validate(ctx: ChainContext) -> StageOutcome:
    """Survivor handoff — honest about what does NOT exist.

    There is no non-LLM /validate for raw binaries today (the
    raw-binary stage-0 decomp adapter is new, unowned work in the
    design). This stage therefore composes nothing new: it collects
    the finding-grade journal survivors into a durable artifact for
    the operator's /validate follow-up and records the capability gap
    as a degradation whenever survivors exist.
    """
    from core.artifacts.provenance import stamp_provenance
    from core.coverage.journal import load_entries
    survivors: list[dict[str, Any]] = []
    for label, run_dir in (("audit", ctx.audit_dir),
                           ("seed_rereview", ctx.rereview_dir)):
        if not run_dir.is_dir():
            continue
        try:
            entries = load_entries(run_dir)
        except (OSError, ValueError):
            continue
        for entry in entries:
            if entry.verdict == "finding":
                survivors.append({
                    "file": entry.file,
                    "function": entry.function,
                    "run": label,
                })
    degradation = ("validate_decomp_adapter_missing"
                   if survivors else "")
    counts, _complete = _journal_counts(ctx)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "artifact_id": ctx.artifact_id,
        "counts": counts,
        "survivors": survivors,
        "degradation": degradation or None,
        "note": (
            "raw-binary /validate has no mechanical stage-0 decomp "
            "adapter — survivors recorded for operator-run /validate; "
            "nothing here promotes a finding"
        ),
        # file/function are recovered from the hostile binary —
        # escape-at-render applies to every consumer of this artifact.
        "derived_from_target": ["survivors.file", "survivors.function"],
    }
    stamp_provenance(payload, "engage-chain", untrusted=True)
    save_json(ctx.chain_dir / SURVIVORS_FILENAME, payload)
    if degradation:
        return StageOutcome("degraded", degradation)
    return StageOutcome("done", "no finding-grade survivors")


_STAGE_FUNCS: dict[str, Callable[[ChainContext], StageOutcome]] = {
    "investigate": _stage_investigate,
    "import": _stage_import,
    "study": _stage_study,
    "checklist": _stage_checklist,
    "audit": _stage_audit,
    "siblings": _stage_siblings,
    "seed_rereview": _stage_seed_rereview,
    "validate": _stage_validate,
}


# ── Verdict record (fixed schema) ────────────────────────────────────

def _collect_degradations(state: dict[str, Any],
                          plan: list[str]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    stages = state.get("stages") or {}
    for stage in plan:
        rec = stages.get(stage)
        if not isinstance(rec, dict):
            continue
        if rec.get("status") == "degraded":
            out.append({"stage": stage,
                        "reason": str(rec.get("reason", ""))})
        for extra in rec.get("extra_degradations") or []:
            out.append({"stage": stage, "reason": str(extra)})
    return out


def _reached_depth(state: dict[str, Any], plan: list[str],
                   policy_depth: str) -> str:
    """Deepest tier whose EVERY planned stage completed (done or a
    condition-judged skip) — degraded stages do not earn depth."""
    stages = state.get("stages") or {}
    reached = "T0"
    for depth in ("T1", "T2", "T3"):
        if _DEPTH_NUM[depth] > _DEPTH_NUM.get(policy_depth, 0):
            break
        at = [s for s in plan
              if _STAGE_MIN_DEPTH[s] <= _DEPTH_NUM[depth]]
        if at and all(
            isinstance(stages.get(s), dict)
            and stages[s].get("status") in ("done", "skipped")
            for s in at
        ):
            reached = depth
    return reached


def build_verdict(ctx: ChainContext, state: dict[str, Any],
                  row: dict[str, Any]) -> dict[str, Any]:
    """The fixed-schema per-artifact verdict record: policy depth,
    reached depth, degradation reasons, format-capability tier at run
    time, and journal verdict counts."""
    plan = _planned_stages(ctx.policy_depth)
    degradations = _collect_degradations(state, plan)
    reached = _reached_depth(state, plan, ctx.policy_depth)
    counts, journal_complete = _journal_counts(ctx)
    findings = counts.get("finding", 0)
    suspicious = counts.get("suspicious", 0)
    tier = str(row.get("format_tier") or "")
    stages = state.get("stages") or {}
    audit_rec = stages.get("audit")
    # Plan membership matters: a stale audit record from a deeper
    # earlier run must not let a shallower policy attest.
    audit_done = ("audit" in plan
                  and isinstance(audit_rec, dict)
                  and audit_rec.get("status") == "done")
    # Earned-coverage floor: attestation needs at least one journal
    # verdict row AND a complete journal load. An empty or fully
    # garbled journal (zero rows) and a partially-loaded one (bounded
    # read) both fail the floor — "no findings" backed by no evidence
    # is not an attestation.
    journal_floor: str | None = None
    if not journal_complete:
        journal_floor = "journal_load_incomplete"
    elif not sum(counts.values()):
        journal_floor = "journal_no_verdict_rows"
    attesting = (
        findings == 0
        and audit_done
        and not degradations
        and reached == ctx.policy_depth
        and tier == "full"
        and journal_floor is None
    )
    capability = f"{reached}/{tier or 'unknown'}"
    if findings:
        wording = (
            f"{findings} finding-grade and {suspicious} suspicious "
            f"journal rows recorded — survivors in "
            f"{SURVIVORS_FILENAME}; validation pending (no raw-binary "
            "decomp adapter)"
        )
    elif attesting:
        wording = (
            f"no findings at full ELF-chain capability "
            f"(policy depth {ctx.policy_depth})"
        )
    else:
        # Sub-full "no findings" is NEVER an attestation.
        floor_note = (f"; earned-coverage floor not met "
                      f"({journal_floor})" if journal_floor else "")
        wording = (
            f"no findings within {capability} capability — "
            f"non-attesting ({len(degradations)} degradation(s) "
            f"recorded{floor_note})"
        )
    return {
        "schema": VERDICT_SCHEMA,
        "artifact_id": ctx.artifact_id,
        "policy_depth": ctx.policy_depth,
        "policy_source": ctx.policy_source,
        "reached_depth": reached,
        "degradation_reasons": degradations,
        "format_capability_tier": tier,
        "journal_verdicts": counts,
        "journal_floor": journal_floor,
        "attesting": attesting,
        "wording": wording,
        "at": _now(),
    }


# ── Ledger write-back helper ─────────────────────────────────────────

def _write_status(output_dir: Path, artifact_id: str, state: str,
                  detail: str, depth: str) -> None:
    """Best-effort ledger status write (machine-authored detail ONLY —
    stage names, rc numbers, counts; never target bytes)."""
    if state not in STATUS_STATES:
        raise ValueError(f"invalid status state: {state!r}")
    try:
        set_artifact_status(output_dir, artifact_id, state,
                            detail=detail, depth=depth)
    except (OSError, ValueError):
        _say(f"warning: ledger status write failed for "
             f"{_esc(artifact_id)}")


def _write_terminal_status(out: Path, artifact_id: str, depth: str,
                           plan: list[str], state: dict[str, Any],
                           verdict: dict[str, Any]) -> str:
    """Write the chain's terminal ledger status from a verdict record.

    Used at verdict write-back AND to RESTORE the terminal status on a
    nothing-to-do re-run whose stage loop transiently marked the row
    ``in_progress`` while re-evaluating a standing skip — without the
    restore, every cron tick would permanently flip a verdicted row
    back to ``in_progress`` (observed drift; pinned by the battery).
    """
    stages = state.get("stages") or {}
    audit_rec = stages.get("audit")
    audit_done = ("audit" in plan
                  and isinstance(audit_rec, dict)
                  and audit_rec.get("status") == "done")
    terminal = "verdicted" if audit_done else "analysed"
    counts = verdict.get("journal_verdicts") or {}
    n_deg = len(verdict.get("degradation_reasons") or [])
    _write_status(
        out, artifact_id, terminal,
        f"engage-chain: policy={depth} "
        f"reached={verdict.get('reached_depth')} "
        f"findings={counts.get('finding', 0)} "
        f"degradations={n_deg} "
        f"attesting={'yes' if verdict.get('attesting') else 'no'}",
        depth,
    )
    return terminal


# ── Dispatch arms ────────────────────────────────────────────────────

def _record_not_built(output_dir: Path, row: dict[str, Any]) -> int:
    """Labeled arm for classes whose chain is a LATER series: record
    the honesty degradation once, then report nothing-to-do."""
    artifact_id = str(row.get("artifact_id") or "")
    cls = str(row.get("class") or "unknown")
    if not _ARTIFACT_ID_RE.fullmatch(artifact_id):
        _say(f"invalid artifact id in ledger row: {_esc(artifact_id)}")
        return RC_USAGE
    chain_dir = chain_dir_for(output_dir, artifact_id)
    state = load_chain_state(chain_dir)
    reason = f"chain_not_built:{cls}"
    if state.get("not_built"):
        _say(f"{_esc(artifact_id)}: chain not built for "
             f"class={_esc(cls)} (already recorded) — nothing to do")
        return RC_NOTHING
    _save_chain_state(chain_dir, {
        "schema_version": CHAIN_SCHEMA_VERSION,
        "artifact_id": artifact_id,
        "class": cls,
        "not_built": True,
        "degradations": [
            {"stage": "dispatch", "reason": reason, "at": _now()},
        ],
    })
    # Ledger honesty note — but never clobber another lane's
    # progress: only a still-inventoried row takes the annotation.
    # ``cls`` values come from the ledger's bounded class vocabulary
    # (machine-minted labels, never raw target bytes).
    status = row.get("status") or {}
    if status.get("state") == "inventoried":
        depth = _norm_depth(status.get("depth")) or ""
        _write_status(output_dir, artifact_id, "inventoried",
                      f"engage-chain: {reason} (degradation recorded)",
                      depth)
    _say(f"{_esc(artifact_id)}: class={_esc(cls)} — chain not built "
         "for this class; degradation recorded")
    return RC_OK


def _containment_root(doc: dict[str, Any],
                      target_root: Path | None) -> Path | None:
    """The resolved containment root, or ``None`` when NEITHER the
    ledger nor the operator names one. ``None`` is a refusal at the
    caller — a missing root must never quietly fall back to the
    process CWD (``Path("").resolve()``), which would let whatever
    directory the operator happened to launch from become the
    containment boundary for hostile ledger paths."""
    if target_root is not None:
        return target_root.resolve()
    raw = str(doc.get("target_root") or "")
    return Path(raw).resolve() if raw else None


def _resolve_binary(root: Path, row: dict[str, Any]) -> Path | None:
    """The artifact's on-disk path, containment-checked against the
    target root (a hand-edited ledger's ``path`` must not escape)."""
    rel = str(row.get("path") or "")
    if not root.is_dir() or not rel:
        return None
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def _archive_stale_chain(chain_dir: Path) -> Path | None:
    """Move a stale chain dir aside (``<artifact-id>.stale-<utc>``)
    so the next run starts from scratch; ``None`` when the rename
    failed (the caller still refuses — never inherit)."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for n in range(1000):
        suffix = f".stale-{stamp}" + (f"-{n}" if n else "")
        dest = chain_dir.with_name(chain_dir.name + suffix)
        if dest.exists():
            continue
        try:
            chain_dir.rename(dest)
        except OSError:
            continue
        return dest
    return None


def run_chain(output_dir: Path | str, artifact_id: str, *,
              target_root: Path | None = None,
              model: str | None = None,
              max_cost: float | None = None,
              mechanical_only: bool = False) -> int:
    """Run (or resume) one artifact's chain. Returns an RC_* code."""
    out = Path(output_dir)
    if not _ARTIFACT_ID_RE.fullmatch(artifact_id):
        _say(f"invalid artifact id: {_esc(artifact_id)}")
        return RC_USAGE
    doc = load_ledger(out)
    if doc is None:
        _say(f"no ledger at {_esc(str(out))} — build one first")
        return RC_USAGE
    row = next((r for r in doc.get("rows") or []
                if isinstance(r, dict)
                and r.get("artifact_id") == artifact_id), None)
    if row is None:
        _say(f"artifact not in ledger: {_esc(artifact_id)}")
        return RC_USAGE
    return _run_row(out, doc, row, target_root=target_root,
                    model=model, max_cost=max_cost,
                    mechanical_only=mechanical_only)


def _run_row(out: Path, doc: dict[str, Any], row: dict[str, Any], *,
             target_root: Path | None, model: str | None,
             max_cost: float | None, mechanical_only: bool) -> int:
    artifact_id = str(row.get("artifact_id") or "")
    if not _ARTIFACT_ID_RE.fullmatch(artifact_id):
        # A hostile or garbled id in the hand-editable ledger is a
        # NAMED per-row failure, never an uncaught abort — an
        # --all-pending sweep must keep running the rows after it and
        # still print its summary.
        _say(f"invalid artifact id in ledger row: {_esc(artifact_id)}"
             " — row skipped (counted as failed)")
        return RC_USAGE
    status = row.get("status") or {}
    if status.get("state") == "parked":
        # Park acknowledgment is the supervisor capability's contract
        # — this chain never resumes a park on its own.
        _say(f"{_esc(artifact_id)}: parked — not resuming (park "
             "acknowledgment is the supervisor's contract)")
        return RC_NOTHING
    if str(row.get("class") or "") != CLASS_ELF:
        return _record_not_built(out, row)

    depth, source = resolve_policy_depth(row)
    if source == "assumed_default":
        _say(f"{_esc(artifact_id)}: no policy depth recorded — "
             f"assuming {DEFAULT_DEPTH} (full chain); the assumption "
             "is recorded in the chain state")
    if depth == "T0":
        _say(f"{_esc(artifact_id)}: policy depth T0 — chain does not "
             "run at inventory tier")
        return RC_NOTHING

    root = _containment_root(doc, target_root)
    if root is None:
        # Named refusal — NEVER the quiet CWD fallback a bare
        # Path("").resolve() would take.
        _write_status(out, artifact_id, "failed",
                      "engage-chain: no containment root — the ledger "
                      "records no target_root and --target-root was "
                      "not given", depth)
        _say(f"{_esc(artifact_id)}: no containment root — the ledger "
             "records no target_root and --target-root was not given; "
             "refusing")
        return RC_FAILED

    # Content gate (fail closed): the chain must analyse the bytes the
    # ledger inventoried — a swapped binary must not inherit progress.
    binary = _resolve_binary(root, row)
    if binary is None:
        _write_status(out, artifact_id, "failed",
                      "engage-chain: artifact path missing or outside "
                      "the target root", depth)
        _say(f"{_esc(artifact_id)}: artifact path missing or outside "
             "the target root")
        return RC_FAILED
    identity = row.get("identity")
    want = (identity.get("sha256")
            if isinstance(identity, dict) else None)
    have = sha256_file(binary)
    if not want or have != want:
        _write_status(out, artifact_id, "failed",
                      "engage-chain: content hash mismatch — re-run "
                      "the ledger build", depth)
        _say(f"{_esc(artifact_id)}: content hash mismatch against the "
             "ledger identity — refusing (re-run the ledger build)")
        return RC_FAILED

    chain_dir = chain_dir_for(out, artifact_id)
    # Per-artifact run lock: overlapping invocations of the same
    # artifact's chain serialise here — the loser waits, then finds
    # the stages settled and no-ops. (The lock file rides inside the
    # chain dir; a stale-archive rename moves it with the dir, which
    # at worst lets one already-waiting invocation start fresh — the
    # same fresh start it would get anyway.)
    with artifact_lock(chain_dir / "chain-run",
                       subject="engagement chain run"):
        return _run_row_locked(
            out, row, chain_dir=chain_dir, artifact_id=artifact_id,
            binary=binary, have=have, depth=depth, source=source,
            model=model, max_cost=max_cost,
            mechanical_only=mechanical_only)


def _run_row_locked(out: Path, row: dict[str, Any], *, chain_dir: Path,
                    artifact_id: str, binary: Path, have: str,
                    depth: str, source: str, model: str | None,
                    max_cost: float | None,
                    mechanical_only: bool) -> int:
    state = load_chain_state(chain_dir)
    if state and state.get("binary_sha256") != have:
        # State gate (fail closed): the recorded chain state belongs
        # to DIFFERENT bytes — a content swap whose ledger rebuild
        # kept the build-id-anchored artifact_id (build-ids are
        # attacker-forgeable) must not inherit settled stages or an
        # attesting verdict. Archive the stale state aside and
        # refuse; the next run starts the chain from scratch. A
        # missing recorded sha is the same refusal — state that
        # cannot prove its bytes never carries progress forward.
        archived = _archive_stale_chain(chain_dir)
        where = (f"archived to {_esc(archived.name)}" if archived
                 else "archive rename failed — remove the chain dir "
                      f"at chains/{_esc(artifact_id)} manually")
        _write_status(out, artifact_id, "failed",
                      "engage-chain: artifact content changed since "
                      "the chain state was built — stale state set "
                      "aside; re-run starts the chain from scratch",
                      depth)
        _say(f"{_esc(artifact_id)}: artifact content changed since "
             f"the chain state was built — refusing to inherit "
             f"settled stages (stale state {where}); a re-run starts "
             "the chain from scratch")
        return RC_FAILED
    if not state:
        state = {
            "schema_version": CHAIN_SCHEMA_VERSION,
            "artifact_id": artifact_id,
            "class": CLASS_ELF,
            "binary_sha256": have,
            "stages": {},
        }
    state["policy"] = {"depth": depth, "source": source}
    state.setdefault("stages", {})

    ctx = ChainContext(
        output_dir=out, chain_dir=chain_dir, artifact_id=artifact_id,
        binary=binary, policy_depth=depth, policy_source=source,
        model=model, max_cost=max_cost,
        mechanical_only=mechanical_only,
    )

    plan = _planned_stages(depth)
    ran_any = False
    touched_ledger = False
    for stage in plan:
        if _stage_settled(state["stages"].get(stage), stage, ctx):
            continue
        prior = state["stages"].get(stage)
        touched_ledger = True
        _write_status(out, artifact_id, "in_progress",
                      f"engage-chain: stage={stage}", depth)
        outcome = _STAGE_FUNCS[stage](ctx)
        if (outcome.status == "skipped"
                and isinstance(prior, dict)
                and prior.get("status") == "skipped"
                and prior.get("reason") == outcome.reason):
            # Re-evaluated skip whose condition still holds — not
            # progress. Without this, a standing skip (e.g. no
            # hypothesis seeds) would make every re-run report
            # "advanced" forever, breaking cron-safe idempotence.
            continue
        rec: dict[str, Any] = {"status": outcome.status, "at": _now()}
        if outcome.reason:
            rec["reason"] = outcome.reason
        if outcome.rerun_without:
            rec["rerun_without"] = outcome.rerun_without
        if outcome.extra_degradations:
            rec["extra_degradations"] = list(
                outcome.extra_degradations)
        state["stages"][stage] = rec
        _save_chain_state(chain_dir, state)
        ran_any = True
        if outcome.status == "failed":
            _write_status(out, artifact_id, "failed",
                          f"engage-chain: stage={stage} failed "
                          f"({outcome.reason}) — re-run resumes here",
                          depth)
            _say(f"{_esc(artifact_id)}: stage {stage} failed — "
                 f"{_esc(outcome.reason)}; chain state recorded, "
                 "a re-run resumes at this stage")
            return RC_FAILED
        _write_status(out, artifact_id, "in_progress",
                      f"engage-chain: reached={stage}", depth)

    prior_verdict = state.get("verdict")
    if not ran_any and isinstance(prior_verdict, dict) \
            and prior_verdict.get("policy_depth") == depth:
        if touched_ledger:
            # The loop's pre-stage write flipped the row to
            # in_progress while re-evaluating a standing skip —
            # restore the terminal status, or every cron tick would
            # leave a verdicted row drifted to in_progress.
            _write_terminal_status(out, artifact_id, depth, plan,
                                   state, prior_verdict)
        _say(f"{_esc(artifact_id)}: chain complete at policy depth "
             f"{depth} — nothing to do")
        return RC_NOTHING

    verdict = build_verdict(ctx, state, row)
    state["verdict"] = verdict
    _save_chain_state(chain_dir, state)
    terminal = _write_terminal_status(out, artifact_id, depth, plan,
                                      state, verdict)
    _say(f"{_esc(artifact_id)}: {terminal} — "
         f"{_esc(str(verdict['wording']), max_len=500)}")
    return RC_OK


def run_all_pending(output_dir: Path | str, *,
                    target_root: Path | None = None,
                    model: str | None = None,
                    max_cost: float | None = None,
                    mechanical_only: bool = False) -> int:
    """Run every ledger row's dispatch arm in row order. Idempotent:
    complete/not-runnable rows report nothing-to-do and cost only a
    state read — safe under operator-side scheduling."""
    out = Path(output_dir)
    doc = load_ledger(out)
    if doc is None:
        _say(f"no ledger at {_esc(str(out))} — build one first")
        return RC_USAGE
    results: dict[int, int] = {}
    for row in doc.get("rows") or []:
        if not isinstance(row, dict):
            continue
        rc = _run_row(out, doc, row, target_root=target_root,
                      model=model, max_cost=max_cost,
                      mechanical_only=mechanical_only)
        results[rc] = results.get(rc, 0) + 1
    advanced = results.get(RC_OK, 0)
    failed = results.get(RC_FAILED, 0) + results.get(RC_USAGE, 0)
    idle = results.get(RC_NOTHING, 0)
    _say(f"all-pending summary: advanced={advanced} failed={failed} "
         f"nothing-to-do={idle}")
    if failed:
        return RC_FAILED
    if advanced:
        return RC_OK
    return RC_NOTHING


__all__ = [
    "CHAIN_DIR_NAME",
    "CHAIN_STATE_FILENAME",
    "CLASS_ELF",
    "DEFAULT_DEPTH",
    "LLM_STAGES",
    "RC_FAILED",
    "RC_NOTHING",
    "RC_OK",
    "RC_USAGE",
    "STAGES",
    "SURVIVORS_FILENAME",
    "VERDICT_SCHEMA",
    "ChainContext",
    "StageOutcome",
    "build_verdict",
    "chain_dir_for",
    "load_chain_state",
    "resolve_policy_depth",
    "run_all_pending",
    "run_chain",
]
