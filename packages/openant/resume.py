"""Resume a truncated /openant run — validation, seeding, fingerprints.

Mechanism (adjudicated from the pinned upstream's source, not from its
docs): the pinned CLI's own resume contract is a REUSED scan output
directory. Every LLM stage auto-derives ``{scan_dir}/{step}_checkpoints``,
restores completed units from it before dispatching (errored units are
retried, never adopted), and ``build-output`` reconstructs
``pipeline_output.json`` over the union of restored + fresh results. A
step-wise re-orchestration of the per-step subcommands would duplicate
the scan orchestrator (language selection, app-context threading,
reachability re-filter, verify chaining, step-report plumbing) inside
RAPTOR and drift with the pin — so a resume here is: seed a NEW run's
``openant_scan`` directory from the prior run's state (copy, never
mutate the original) and re-invoke ``scan`` against it.

What upstream gates and what it does NOT: the analyze/verify stages
carry a backend-identity adopt gate (``_fingerprint.json`` sidecar —
model/provider/adapter/base-url/prompt-template identity; a mismatch
archives the checkpoints and re-pays). Upstream does NOT bind
checkpoints to the TARGET's content (unit ids are path-based; a body
edit under the same symbol silently adopts the stale verdict — an
upstream-named residual) nor to the core checkout version. The
validation in this module is therefore the ONLY target/core drift
gate a resume has: detected drift REFUSES loudly; undetectable drift
(a prior run that predates fingerprint recording, a non-git target)
warns loudly and proceeds on upstream's id-keyed tolerance.

TRUST STORY — the prior run dir is trusted as THIS installation's own
output. Its checkpoint CONTENTS shape the resumed run's verdicts:
upstream's resume contract adopts completed checkpoints without
content authentication (the sidecar digest is an unknown-writer
filter, not an authenticity seal — anyone who can write the dir can
write a self-consistent sidecar), and the drift gates above verify
target/pin/core IDENTITY only, never checkpoint truthfulness. Resume
only run directories you trust to be RAPTOR's own. Mitigating shape:
the report the gates read (``raptor_openant_report.json``) is
PARENT-written at the run-dir top level, outside the scan child's
sandbox bind (only ``openant_scan/`` is child-writable), so a hostile
SCANNED REPO cannot forge the resume-validation inputs; the seeding
walk additionally refuses anything but child-shaped regular
files/dirs (see :func:`seed_scan_dir`).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from core.json import load_json
from core.logging import get_logger

# Same ceiling as the scanner's other reads of run-dir JSON documents.
from core.coverage.record import RUN_ARTIFACT_MAX_BYTES as _MAX_BYTES

logger = get_logger()

# Prior-run artifacts NOT seeded into the new run's scan dir. The
# checkpoints are the restore source of record; the built outputs are
# reconstructed by the resumed scan, and seeding them would let a
# resume child that dies early leave a stale document masquerading as
# this run's output. Credential/stream residue never travels.
SEED_EXCLUDES = frozenset({
    "pipeline_output.json",
    "results.json",
    "results_verified.json",
    "openant-gateway-spend.json",
    "openant.stderr.log",
    "openant.stdout.log",
    "openant.parse.stderr.log",
    "openant-xdg",
    "final-reports",
})

# Upstream fingerprint sidecar name + the scheme version whose digest
# algorithm ``_key_digest`` replicates. Only sidecars at THIS version
# are ever rebased; any other version is left untouched (upstream then
# fail-closes to archive-and-repay, which is honest, never unsafe).
FINGERPRINT_FILE = "_fingerprint.json"
FINGERPRINT_SCHEME_VERSION = 2


class OpenAntResumeError(RuntimeError):
    """A --resume request that must not proceed (drift, nothing to
    resume, unusable prior state)."""


@dataclass
class PriorRun:
    """Validated prior-run state a resume seeds from."""

    run_dir: Path
    scan_dir: Path
    report: dict
    repository: Path
    prior_cost_usd: float
    remaining: dict
    warnings: list = field(default_factory=list)


def target_fingerprint(repo_path: Path) -> dict[str, Any]:
    """Content-identity fingerprint of the scan target, for drift
    detection between a run and its resume.

    Git targets: the verified HEAD commit id (``HEAD^{commit}`` via the
    strict read-only git argv — the target repo is untrusted, so no
    porcelain). Deliberately NO dirty/status probe: ``git status``
    re-hashes worktree content through ``filter.<name>.clean`` commands
    configured by the (attacker-controlled) repo config — executing
    hostile code to compute a fingerprint inverts the trust boundary.
    Non-git targets record ``{"kind": "non-git"}`` — drift there is
    UNVERIFIABLE and compares as a loud warning, never a match.
    """
    try:
        from core.git import get_safe_git_env, safe_git_readonly_command
        proc = subprocess.run(
            safe_git_readonly_command(
                "-C", str(repo_path), "rev-parse", "--verify",
                "HEAD^{commit}"),
            capture_output=True, text=True, timeout=30, check=False,
            env=get_safe_git_env(),
        )
    except (OSError, subprocess.SubprocessError):
        return {"kind": "non-git"}
    head = proc.stdout.strip().lower()
    if proc.returncode != 0 or not head:
        return {"kind": "non-git"}
    return {"kind": "git", "head": head}


def _phase_status(ckpt_dir: Path) -> dict[str, Any]:
    """Light status of one checkpoint dir: the ``_summary.json``
    counters plus a raw unit-file count. Counters may be absent (a run
    killed before any summary write) — absent reads as unknown, which
    the resumability decision treats as resumable, never as complete.
    """
    status: dict[str, Any] = {"files": 0, "summary": None}
    try:
        names = os.listdir(ckpt_dir)
    except OSError:
        return status
    status["files"] = sum(
        1 for n in names
        if n.endswith(".json")
        and n not in ("_summary.json", FINGERPRINT_FILE))
    summary = load_json(ckpt_dir / "_summary.json", max_bytes=_MAX_BYTES)
    if isinstance(summary, dict):
        status["summary"] = {
            k: summary.get(k)
            for k in ("phase", "total_units", "completed",
                      "incomplete", "errors")
        }
    return status


def assess_remaining(scan_dir: Path) -> dict[str, Any]:
    """What the prior scan state still owes: per-phase checkpoint
    status plus a resumability verdict over it.

    A phase is unfinished when its summary reports errors/incomplete
    units or fewer completed than total, or when unit files exist with
    no readable summary (a mid-flight kill). The built
    ``pipeline_output.json`` missing also marks the run unfinished —
    the checkpointed work exists but the outputs were never assembled.
    """
    phases: dict[str, dict] = {}
    reasons: list[str] = []
    try:
        entries = sorted(os.listdir(scan_dir))
    except OSError:
        entries = []
    for name in entries:
        if not name.endswith("_checkpoints"):
            continue
        p = scan_dir / name
        if not p.is_dir():
            continue
        st = _phase_status(p)
        phases[name] = st
        if st["files"] == 0:
            continue
        summary = st["summary"]
        if summary is None:
            reasons.append(f"{name}: unit files with no summary "
                           f"(interrupted mid-phase)")
            continue
        errors = summary.get("errors") or 0
        incomplete = summary.get("incomplete") or 0
        total = summary.get("total_units") or 0
        completed = summary.get("completed") or 0
        if errors or incomplete:
            reasons.append(
                f"{name}: {errors} errored, {incomplete} incomplete "
                f"unit(s) to retry")
        elif total and completed < total:
            reasons.append(
                f"{name}: {completed}/{total} unit(s) completed")
    if not (scan_dir / "pipeline_output.json").is_file():
        reasons.append("pipeline_output.json was never built")
    return {"phases": phases, "resumable": bool(reasons),
            "reasons": reasons}


def completed_unit_ids(ckpt_dir: Path, step: str) -> set[str]:
    """Unit ids the prior run COMPLETED in one checkpoint dir.

    FORECAST-ONLY consumer: this feeds the resume's remainder census
    (what the resumed scan will still pay for). The dispatch decision
    itself is made by the pinned child's own restore logic — this
    approximation of its error classification (no access to the pin's
    verdict vocabulary, so an unrecognized-but-effective verdict counts
    completed here while upstream retries it) can only skew the
    ESTIMATE slightly low, never re-bill or drop a unit.
    """
    ids: set[str] = set()
    try:
        names = os.listdir(ckpt_dir)
    except OSError:
        return ids
    for name in names:
        if not name.endswith(".json") or name in (
                "_summary.json", FINGERPRINT_FILE):
            continue
        data = load_json(ckpt_dir / name, max_bytes=_MAX_BYTES)
        if not isinstance(data, dict):
            continue
        uid = data.get("id")
        if not isinstance(uid, str) or not uid:
            continue
        if _checkpoint_is_error(data, step):
            continue
        ids.add(uid)
    return ids


def _checkpoint_is_error(data: dict, step: str) -> bool:
    if data.get("error"):
        return True
    if step == "enhance":
        ctx = data.get(data.get("context_key") or "agent_context")
        if not isinstance(ctx, dict):
            return True
        return bool(ctx.get("error")) or (
            ctx.get("security_classification") == "incomplete")
    if step == "analyze":
        res = data.get("result")
        if not isinstance(res, dict):
            return True
        verdict = res.get("verdict")
        finding = res.get("finding")
        if verdict == "ERROR" or finding == "error":
            return True
        has_verdict = isinstance(verdict, str) and verdict.strip() != ""
        has_finding = isinstance(finding, str) and finding.strip() != ""
        return not (has_verdict or has_finding)
    if step == "verify":
        v = data.get("verification")
        if not isinstance(v, dict) or not v:
            return True
        return v.get("correct_finding") == "error" or bool(
            v.get("incomplete"))
    return False


def validate_prior_run(
    prior_dir: Path,
    repo_path: Path | None,
    *,
    pinned_commit: str,
    current_core_head: str | None,
) -> PriorRun:
    """Validate a --resume source. Detected drift REFUSES loudly
    (:class:`OpenAntResumeError`); undetectable drift warns loudly on
    stderr and in the returned record. Read-only over the prior dir.
    """
    prior_dir = Path(prior_dir).resolve()
    warnings: list[str] = []
    if not prior_dir.is_dir():
        raise OpenAntResumeError(
            f"--resume: {prior_dir} is not a directory")
    report = load_json(
        prior_dir / "raptor_openant_report.json", max_bytes=_MAX_BYTES)
    if not isinstance(report, dict) or not report:
        raise OpenAntResumeError(
            f"--resume: {prior_dir} has no readable "
            f"raptor_openant_report.json — not an /openant run directory")

    # In-flight guard: a prior run whose lifecycle still reads
    # ``running`` with its recorded worker alive is not truncated, it
    # is IN FLIGHT — seeding from its scan dir would copy checkpoints
    # mid-write and the resumed run would double-pay work the live run
    # is about to finish. Interrupted runs write their report from the
    # signal handler, so a report's presence no longer implies the
    # worker exited; this liveness verdict is the explicit gate. Same
    # status-scoped semantics as the substrate chokepoint
    # (``core.run.resume.resume_ineligibility``), through the same
    # full-identity liveness check (pid alive AND starttime matching;
    # for session-bound runs the recorded worker is the launching tool
    # shell, whose lifetime tracks the run) — terminal statuses carry
    # no in-flight claim, and absent/unreadable metadata carries no
    # worker claim to check (pre-lifecycle dirs, bare --out runs).
    from core.run.metadata import (
        STATUS_RUNNING,
        load_run_metadata,
        worker_liveness_for_meta,
    )
    meta = load_run_metadata(prior_dir)
    if isinstance(meta, dict) and meta.get("status") == STATUS_RUNNING:
        alive, detail = worker_liveness_for_meta(meta)
        if alive:
            raise OpenAntResumeError(
                f"--resume: the prior run at {prior_dir} is still in "
                f"flight ({detail}) — resuming now would seed from a "
                f"scan dir its worker is still writing and double-pay "
                f"the remainder. Wait for it to stop, or kill it first")
    if report.get("outcome") == "not_configured":
        raise OpenAntResumeError(
            "--resume: the prior run never scanned (outcome "
            "not_configured) — run a fresh scan instead")
    if report.get("outcome") == "forecast_only":
        raise OpenAntResumeError(
            "--resume: the prior run was a --forecast (no scan was "
            "performed, nothing to resume) — run a fresh scan instead")
    scan_dir = prior_dir / "openant_scan"
    if not (scan_dir / "dataset.json").is_file():
        raise OpenAntResumeError(
            f"--resume: {scan_dir} carries no dataset.json — no scan "
            f"state to seed from")

    prior_repo_raw = report.get("repository")
    if not isinstance(prior_repo_raw, str) or not prior_repo_raw:
        raise OpenAntResumeError(
            "--resume: the prior report records no repository path")
    prior_repo = Path(prior_repo_raw)
    if repo_path is not None and (
            Path(repo_path).resolve() != prior_repo.resolve()):
        raise OpenAntResumeError(
            f"--resume: target mismatch — the prior run scanned "
            f"{prior_repo}, this invocation targets "
            f"{Path(repo_path).resolve()}. A resume completes the SAME "
            f"scan; to scan the new target run a fresh /openant")
    repository = (Path(repo_path).resolve() if repo_path is not None
                  else prior_repo.resolve())
    if not repository.exists():
        raise OpenAntResumeError(
            f"--resume: the prior run's target {repository} no longer "
            f"exists")

    # Target content drift: the checkpoints' unit results are only
    # valid against the tree that produced them (upstream adopts
    # path-keyed units content-blind — see the module docstring).
    recorded = report.get("target_fingerprint")
    current = target_fingerprint(repository)
    if isinstance(recorded, dict) and recorded.get("kind") == "git":
        if current.get("kind") != "git" or (
                current.get("head") != recorded.get("head")):
            raise OpenAntResumeError(
                f"--resume: target drift — the prior run scanned the "
                f"tree at commit {str(recorded.get('head'))[:12]}, the "
                f"target is now at "
                f"{str(current.get('head') or 'a non-git state')[:12]}. "
                f"Resuming would adopt per-unit verdicts from a "
                f"different tree; run a fresh scan of the current tree")
    else:
        warnings.append(
            "target drift is UNVERIFIABLE for this resume (the prior "
            "run recorded no git target fingerprint) — unchanged units "
            "restore correctly, but a unit edited since the prior run "
            "would adopt its stale verdict (path-keyed checkpoints)")

    # Pinned-core drift: checkpoint formats, prompts, and verdict
    # vocabularies follow the pin — resuming across cores is schema
    # drift, refused rather than half-adopted.
    prov = (report.get("config") or {}).get("core_provenance") or {}
    prior_pin = prov.get("pinned_commit")
    if isinstance(prior_pin, str) and prior_pin and (
            prior_pin != pinned_commit):
        raise OpenAntResumeError(
            f"--resume: the prior run was made under integration pin "
            f"{prior_pin[:12]}, this RAPTOR pins {pinned_commit[:12]} — "
            f"checkpoint schemas may differ across pins; run a fresh "
            f"scan")
    prior_head = prov.get("head")
    if isinstance(prior_head, str) and prior_head and current_core_head:
        if prior_head != current_core_head:
            raise OpenAntResumeError(
                f"--resume: openant-core drift — the prior run executed "
                f"the core at {prior_head[:12]}, the current core is at "
                f"{current_core_head[:12]}. Check out the same core (or "
                f"run a fresh scan)")
    elif not prior_head:
        warnings.append(
            "the prior run's openant-core provenance is unrecorded/"
            "unverifiable — core drift between the runs cannot be "
            "checked")

    remaining = assess_remaining(scan_dir)
    if not remaining["resumable"]:
        raise OpenAntResumeError(
            "--resume: nothing to resume — the prior run completed "
            "every unit (no errored, incomplete, or missing work in "
            "its checkpoints). Its findings are already in "
            f"{prior_dir / 'openant_findings.json'}")

    try:
        prior_cost = float(
            ((report.get("cost") or {}).get("total_usd")) or 0.0)
    except (TypeError, ValueError):
        prior_cost = 0.0

    for w in warnings:
        logger.warning("openant resume: %s", w)
    return PriorRun(
        run_dir=prior_dir, scan_dir=scan_dir, report=report,
        repository=repository, prior_cost_usd=prior_cost,
        remaining=remaining, warnings=warnings,
    )


def seed_scan_dir(prior_scan: Path, new_scan: Path) -> int:
    """Copy the prior run's scan state into the NEW run's scan dir.

    Copy, never move or mutate: the prior run directory is a durable
    record and stays byte-identical. ``new_scan`` must be empty/absent
    (a fresh run dir) — seeding over existing state is refused.
    Returns the number of top-level entries seeded.

    LSTAT DISCIPLINE (refuse, never dereference): the prior scan dir
    was writable by the sandboxed scan child, so its contents are
    child-authored. A legitimate scan leaves only regular files and
    directories behind — a symlink there is a plant that a
    dereferencing copy would follow, ingesting arbitrary host files
    (or whole trees) into the NEW run dir, which ships in exports and
    feeds later LLM passes; a FIFO/device is a hang/read trap. Every
    entry is therefore classified via fd-true ``lstat``/``fstat``
    (regular files are opened ``O_NOFOLLOW|O_NONBLOCK`` and re-checked
    on the open fd, so a swap between scan and open cannot slip a
    non-regular entry through), and ANY symlink or special file
    REFUSES the whole resume loudly. On any failure the partially
    seeded dir is removed — a refused resume leaves no hostile residue
    in the new run dir.
    """
    prior_scan = Path(prior_scan)
    new_scan = Path(new_scan)
    if new_scan.exists() and any(new_scan.iterdir()):
        raise OpenAntResumeError(
            f"--resume: refusing to seed into non-empty {new_scan}")
    try:
        new_scan.mkdir(parents=True, exist_ok=True)
        _copy_regular_tree(prior_scan, new_scan, top=True)
    except OpenAntResumeError:
        shutil.rmtree(new_scan, ignore_errors=True)
        raise
    except (OSError, shutil.Error) as e:
        shutil.rmtree(new_scan, ignore_errors=True)
        raise OpenAntResumeError(
            f"--resume: seeding from {prior_scan} failed ({e}); the "
            f"partially-seeded run dir was removed") from e
    return sum(1 for _ in new_scan.iterdir())


def _refuse_entry(kind: str, name: str) -> None:
    from core.security.log_sanitisation import sanitise_for_terminal
    raise OpenAntResumeError(
        f"--resume: prior scan dir contains a {kind} "
        f"({sanitise_for_terminal(name, max_len=120)!r}) — a legitimate "
        f"scan leaves only regular files and directories behind; "
        f"refusing to seed from it (nothing was kept)")


def _copy_regular_tree(src: Path, dst: Path, *, top: bool) -> None:
    """Recursive copy admitting ONLY regular files and directories —
    see :func:`seed_scan_dir` for why anything else refuses."""
    with os.scandir(src) as it:
        entries = sorted(it, key=lambda e: e.name)
    for entry in entries:
        name = entry.name
        if top and (name in SEED_EXCLUDES or ".superseded-" in name):
            # Upstream's identity gate archives superseded checkpoint
            # dirs aside (preserve-not-destroy); they are prior-run
            # history, not resume state.
            continue
        if entry.is_symlink():
            _refuse_entry("symlink", name)
        if entry.is_dir(follow_symlinks=False):
            (dst / name).mkdir()
            _copy_regular_tree(Path(entry.path), dst / name, top=False)
        elif entry.is_file(follow_symlinks=False):
            _copy_regular_file(Path(entry.path), dst / name)
        else:
            _refuse_entry("special file (fifo/device/socket)", name)


def _copy_regular_file(src: Path, dst: Path) -> None:
    """Copy one REGULAR file without ever following a link or blocking
    on a special file: ``O_NOFOLLOW`` refuses a symlink at open even
    if one was swapped in after the scandir classification,
    ``O_NONBLOCK`` keeps a swapped-in FIFO from hanging the open, and
    the ``fstat`` on the OPEN fd is the authoritative type check. The
    destination is RAPTOR-created (``O_EXCL`` into a fresh tree)."""
    import stat as stat_mod
    in_fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(in_fd)
        if not stat_mod.S_ISREG(st.st_mode):
            _refuse_entry("special file (fifo/device/socket)", src.name)
    except BaseException:
        os.close(in_fd)
        raise
    with os.fdopen(in_fd, "rb") as inp:
        out_fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(out_fd, "wb") as out:
            shutil.copyfileobj(inp, out)
    # Checkpoint mtimes participate in upstream's dual-stale-file
    # consolidation tie-breaks — preserve them on the copy.
    os.utime(dst, ns=(st.st_atime_ns, st.st_mtime_ns))


def _key_digest(key: dict) -> str:
    """The pinned upstream's fingerprint digest, replicated exactly:
    sha256 over the canonical-JSON KEY (sorted keys, compact
    separators, ASCII). ``core.json.dumps_canonical`` is byte-identical
    to the upstream form for these payloads (upstream pins the same
    sort/separator/ascii options and the KEY carries only
    JSON-native values, so ``default=str`` never fires); the pinned
    cross-check test enforces the byte parity. Guarded by
    scheme-version checks at the caller."""
    from core.json import dumps_canonical
    canonical = dumps_canonical(key)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _loopback_parts(url: Any) -> tuple[int, str] | None:
    """``(port, path)`` when *url* is a plain dispatcher-loopback base
    URL (``http://127.0.0.1:<port><path>``, no userinfo/query/
    fragment), else None."""
    if not isinstance(url, str):
        return None
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        return None
    if (p.scheme != "http" or p.hostname != "127.0.0.1" or port is None
            or p.username or p.password or p.query or p.fragment):
        return None
    return port, p.path


def rebase_gateway_fingerprints(scan_dir: Path, new_base_url: str) -> int:
    """Port-rebase seeded checkpoint identity sidecars for THIS run's
    gateway endpoint. Returns the number of sidecars rewritten.

    The upstream adopt gate keys on ``config_base_url``; on gateway
    runs that is RAPTOR's own dispatcher loopback plane, whose TCP port
    is per-dispatcher-instance. A resume in a new session gets a new
    port, and without this rebase the gate would classify identical
    backends as different — archiving every completed analyze
    checkpoint and re-paying the whole phase. A loopback port on this
    host's own dispatcher is transport plumbing, not backend identity:
    the rebase applies ONLY when old and new URLs differ in nothing but
    that port (same scheme, same 127.0.0.1 host, same provider-route
    path — a front change like a different provider prefix keeps the
    honest reset). Sidecars at any other scheme version, with a
    non-matching stored digest (unknown writer), or with any other key
    difference are left untouched — upstream then fail-closes to
    archive-and-repay, which is safe.
    """
    new_parts = _loopback_parts(new_base_url)
    if new_parts is None:
        return 0
    rebased = 0
    scan_dir = Path(scan_dir)
    try:
        entries = sorted(os.listdir(scan_dir))
    except OSError:
        return 0
    for name in entries:
        if not name.endswith("_checkpoints"):
            continue
        sidecar = scan_dir / name / FINGERPRINT_FILE
        data = load_json(sidecar, max_bytes=_MAX_BYTES)
        if not isinstance(data, dict):
            continue
        if data.get("scheme_version") != FINGERPRINT_SCHEME_VERSION:
            continue
        key = {k: v for k, v in data.items()
               if k not in ("key_digest", "written_at")}
        if data.get("key_digest") != _key_digest(key):
            continue  # unknown writer/shape — leave it to fail closed
        old_parts = _loopback_parts(key.get("config_base_url"))
        if old_parts is None or old_parts[1] != new_parts[1]:
            continue
        if old_parts[0] == new_parts[0]:
            continue  # same port — nothing to rebase
        key["config_base_url"] = (
            f"http://127.0.0.1:{new_parts[0]}{new_parts[1]}")
        updated = dict(data)
        updated.update(key)
        updated["key_digest"] = _key_digest(key)
        try:
            _atomic_write_json(sidecar, updated)
        except OSError as e:
            logger.warning(
                "openant resume: fingerprint rebase failed for %s (%s) "
                "— that phase will re-verify fail-closed", sidecar, e)
            continue
        rebased += 1
    if rebased:
        logger.info(
            "openant resume: rebased %d checkpoint identity sidecar(s) "
            "to this run's gateway port (endpoint identity otherwise "
            "unchanged)", rebased)
    return rebased


def _atomic_write_json(path: Path, data: dict) -> None:
    import tempfile
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
