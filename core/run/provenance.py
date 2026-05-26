"""Run provenance — point-in-time facts sealed into .raptor-run.json.

The manifest answers "what produced this run" and must be captured WHEN
the run executes, never reconstructed afterwards. Today's git SHA, today's
models.json, and today's tool versions have nothing to do with the run that
found a bug weeks ago — citing them later would be a fabrication. So
`start_run` seals the source-control + environment snapshot before analysis
touches anything, and `complete_run` merges in what is only knowable at the
end (the models that actually fired, engine versions).

Every value here is best-effort: a fact that cannot be determined is recorded
as ``None``, never as a fabricated or "today" placeholder. A consumer reading
``base_sha is None`` knows the provenance was unavailable; it must not infer
the current HEAD.
"""

import hashlib
import platform
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

# Repo root = parents[2] of this file:
#   parents[0] = core/run   (this module's dir)
#   parents[1] = core
#   parents[2] = <repo root> (the RAPTOR checkout)
# Derived from __file__ rather than $RAPTOR_DIR so the snapshot always
# reflects the checkout the running code actually lives in. RAPTOR_DIR can
# be unset for direct ``python3 raptor.py`` invocations (see the startup
# doctor's "RAPTOR_DIR not set" warning), whereas __file__ is always right.
_REPO_ROOT = Path(__file__).resolve().parents[2]

# Per-git-call wall-clock cap. start_run sits on the hot path of every
# command; a hung git (network filesystem, index.lock contention) must not
# stall the run. On timeout the affected field degrades to None.
_GIT_TIMEOUT_S = 5.0

# Same cap for `<tool> --version` probes (run once at run completion).
_PROBE_TIMEOUT_S = 5.0

# Version-probe argv per analysis engine. stdout (or stderr) first line is
# taken as the version string. Extend as engines are added.
_VERSION_PROBES = {
    "semgrep": ["semgrep", "--version"],
    "codeql": ["codeql", "version", "--format=terse"],
    "coccinelle": ["spatch", "--version"],
}


def _git(repo_dir: Path, *args: str, untrusted: bool = False) -> Optional[str]:
    """Run ``git <args>`` in ``repo_dir``; return stripped stdout or None.

    Best-effort: returns None on non-zero exit, missing git, timeout, or a
    non-repository directory. Never raises — provenance capture must not be
    able to break a run.

    ``untrusted=True`` MUST be passed when ``repo_dir`` is a SCANNED TARGET
    (attacker-controlled). A hostile ``.git/config`` (``core.fsmonitor``,
    ``core.hooksPath``, …) can otherwise turn a plain ``git status`` into RCE
    (CVE-2024-32002 family). It layers ``safe_git_command``'s per-invocation
    overrides that neutralise those vectors. RAPTOR's own checkout is trusted,
    so ``source_control_snapshot`` leaves it False.
    """
    # get_safe_env strips shell-evaluated vars (EDITOR/PAGER/…) before we spawn
    # git — cheap hygiene and the house rule for every subprocess. Lazy import
    # keeps core.config off this module's import path (no cycle at import time).
    try:
        from core.config import RaptorConfig
        env = RaptorConfig.get_safe_env()
    except Exception:
        env = None
    if untrusted:
        from core.git.clone import safe_git_command
        cmd = safe_git_command("-C", str(repo_dir), *args)
    else:
        cmd = ["git", "-C", str(repo_dir), *args]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_S,
            env=env,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def source_control_snapshot(repo_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Snapshot RAPTOR's own source-control state. Sealed at run START.

    Describes the *framework* version that produced the run — not the scanned
    target (that is recorded separately as ``target_path``). An operator
    running a modified fork shows up as ``dirty=True`` with ``diff_sha256``
    set, so attribution stays honest about "modified from base".

    Returns a dict with:
      base_sha     full 40-char HEAD sha, or None if not a git checkout.
      dirty        True if the working tree has uncommitted changes
                   (including untracked files), False if clean, None if the
                   git state could not be determined.
      diff_sha256  sha256 hex of ``git diff HEAD`` (tracked changes) when
                   dirty, else None. The diff *content* is never stored —
                   only its hash — so the manifest cannot leak source. Note
                   an untracked-only modification sets dirty=True but leaves
                   diff_sha256 None (``git diff HEAD`` omits untracked files).
    """
    repo_dir = repo_dir or _REPO_ROOT
    sha = _git(repo_dir, "rev-parse", "HEAD")
    if sha is None:
        # Not a git checkout (or git unavailable) — provenance unknowable.
        # Report None across the board; do NOT substitute any current value.
        return {"base_sha": None, "dirty": None, "diff_sha256": None}

    porcelain = _git(repo_dir, "status", "--porcelain")
    # Empty porcelain output == clean tree. None == status failed (unknowable).
    dirty = bool(porcelain) if porcelain is not None else None

    diff_sha256 = None
    if dirty:
        diff = _git(repo_dir, "diff", "HEAD")
        if diff:
            diff_sha256 = hashlib.sha256(
                diff.encode("utf-8", "replace")
            ).hexdigest()

    return {"base_sha": sha, "dirty": dirty, "diff_sha256": diff_sha256}


def tool_version(name: str) -> Optional[str]:
    """Best-effort version string for an analysis engine (``semgrep`` /
    ``codeql`` / ``coccinelle``).

    Returns the first line of the tool's ``--version`` output, or None if the
    tool is unknown, not installed, times out, or reports nothing. Never raises
    — engine provenance is best-effort and must not break run finalisation.
    """
    probe = _VERSION_PROBES.get(name)
    if not probe:
        return None
    try:
        from core.config import RaptorConfig
        env = RaptorConfig.get_safe_env()
    except Exception:
        env = None
    try:
        result = subprocess.run(
            probe,
            capture_output=True,
            text=True,
            timeout=_PROBE_TIMEOUT_S,
            env=env,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = (result.stdout or result.stderr or "").strip()
    if not out:
        return None
    return out.splitlines()[0].strip() or None


def target_snapshot(target_path: Optional[Any]) -> Optional[Dict[str, Any]]:
    """Snapshot the SCANNED TARGET's own VCS state. Sealed at run START.

    This is the other half of attribution: ``source_control_snapshot`` records
    the framework version; this records *what code was analysed* — "found X in
    project Y at commit Z". Returns None when there's no path or the target is
    not a git checkout (we record nothing rather than a half-empty block).

    Only commit / dirty / branch — no diff hash. We don't fingerprint someone
    else's (possibly large, possibly sensitive) working diff. The target is
    attacker-controlled, so every git call here uses ``untrusted=True`` (safe
    per-invocation overrides — see ``_git``); a hostile ``.git/config`` cannot
    turn these into code execution.
    """
    if not target_path:
        return None
    p = Path(target_path)
    # untrusted=True: the target is attacker-controlled — a hostile .git/config
    # could turn `git status` into RCE without the safe overrides.
    sha = _git(p, "rev-parse", "HEAD", untrusted=True)
    if sha is None:
        return None
    porcelain = _git(p, "status", "--porcelain", untrusted=True)
    branch = _git(p, "rev-parse", "--abbrev-ref", "HEAD", untrusted=True)
    return {
        "vcs": "git",
        "commit": sha,
        "dirty": bool(porcelain) if porcelain is not None else None,
        "branch": branch,
    }


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def archive_snapshot(archive_path: Optional[Any]) -> Optional[Dict[str, Any]]:
    """Identity of the SCANNED ARCHIVE file — the "which distribution" half.

    Hashes the archive bytes; returns ``{archive_sha256, archive_name, format}``
    or None if it isn't a recognised archive. Publish-safe (hash + name only,
    no path).
    """
    if not archive_path:
        return None
    from core.archive import detect_format
    p = Path(archive_path)
    fmt = detect_format(p)
    if fmt is None:
        return None
    try:
        digest = _sha256_file(p)
    except OSError:
        return None
    return {"archive_sha256": digest, "archive_name": p.name, "format": fmt}


def archive_target_identity(
    archive_path: Optional[Any],
) -> Optional[Dict[str, Any]]:
    """Compose the manifest ``target`` block for an archive target — the
    archive file's ACQUISITION identity ``{source, archive_sha256,
    archive_name, format}``. None if ``archive_path`` isn't a recognised
    archive. Hashes/names only, so (unlike the git block) it's publish-safe.

    The extracted tree's content-EQUIVALENCE id is deliberately not here: that
    is the coverage store's to derive from the inventory (one content identity,
    and it belongs to the store, not a second source of truth in the manifest).
    """
    a = archive_snapshot(archive_path)
    if a is None:
        return None
    return {"source": "archive", **a}


# Canonical per-run output files that signal an engine ran, mapped to the
# probe name in _VERSION_PROBES. Semgrep/CodeQL emit SARIF (``<engine>_*.sarif``;
# ``.json`` tolerated for alternate modes); coccinelle emits ``cocci.sarif``.
_ENGINE_OUTPUT_GLOBS = {
    "semgrep": ("semgrep_*.sarif", "semgrep_*.json"),
    "codeql": ("codeql_*.sarif", "codeql_*.json"),
    "coccinelle": ("cocci.sarif", "coccinelle_*.sarif"),
}


def detect_engines(out_dir: Any) -> Dict[str, Optional[str]]:
    """Which static engines left output in ``out_dir``, with each version.

    Best-effort: version is None if the tool isn't installed. Shared by scan/
    codeql completion and the agentic scan phase so engine capture is uniform.
    """
    out_dir = Path(out_dir)
    engines: Dict[str, Optional[str]] = {}
    for name, patterns in _ENGINE_OUTPUT_GLOBS.items():
        if any(any(out_dir.glob(p)) for p in patterns):
            engines[name] = tool_version(name)
    return engines


# Commands whose verdict is a pure function of the inputs — static rules /
# queries, no LLM and no stochastic/runtime component — so a re-run on the
# same tree reproduces the same findings. Fuzzing (stochastic mutation),
# dynamic web scans (target-state-dependent), and every LLM-mediated command
# (agentic / validate / understand) are NOT deterministically reproducible.
# #4 will refine this single bool into a richer `method` taxonomy
# (mechanical / runtime / llm_assisted); for now the bool preserves exactly
# the scan/codeql=True, everything-else=False behaviour the per-command
# callers hard-coded, while letting the lifecycle apply it uniformly.
_DETERMINISTIC_COMMANDS = frozenset({"scan", "codeql"})


def is_deterministically_reproducible(command: Optional[str]) -> bool:
    """Whether ``command``'s verdict path is deterministic (no LLM, no
    stochastic/runtime component) — i.e. re-running on the same inputs
    reproduces the same findings."""
    return command in _DETERMINISTIC_COMMANDS


def standard_completion_provenance(
    out_dir: Any, command: Optional[str],
) -> Dict[str, Any]:
    """The end-of-run provenance EVERY command contributes, derived only from
    facts the lifecycle can see for itself: which engines left output, and
    whether the command's verdict is deterministic.

    Centralised here so enrichment is uniform across every completion path —
    the Python orchestrators (scan / codeql / agentic) AND the Claude-driven
    commands that finish through the lifecycle stubs (/validate, /understand)
    — instead of being hand-wired per caller (which is why coverage used to be
    uneven). Facts only an in-process orchestrator knows — the models that
    fired — stay with the caller and merge separately; the lifecycle fills
    these two only where the caller didn't supply them.
    """
    return {
        "engines": detect_engines(out_dir),
        "deterministically_reproducible": is_deterministically_reproducible(
            command),
    }


def environment_snapshot() -> Dict[str, Any]:
    """Snapshot the runtime environment. Sealed at run START.

    Coarse but stable facts about the interpreter and OS the run executed
    under. Kept deliberately small — the heavy, run-specific provenance
    (models, engines) is merged later by complete_run.

    ``os`` / ``arch`` are deliberately coarse (``platform.system()`` +
    ``platform.machine()``, e.g. "Linux" / "x86_64") rather than
    ``platform.platform()``. The full string ("Linux-7.0.0-15-generic-
    x86_64-with-glibc2.43") is a near-unique host fingerprint that nothing
    in RAPTOR reads operationally — its only consumers would be debug
    logs. Since the manifest is built to be publishable (for attribution),
    we don't store fingerprint precision we'd only have to redact. Do not
    "enrich" this back to the full platform string.
    """
    return {
        "python": platform.python_version(),
        "os": platform.system(),
        "arch": platform.machine(),
    }


def build_start_manifest(repo_dir: Optional[Path] = None,
                         target: Optional[Any] = None,
                         target_identity: Optional[Dict[str, Any]] = None,
                         ) -> Dict[str, Any]:
    """Assemble the manifest fragment sealed at run START.

    Carries a ``schema`` integer so the manifest can evolve independently of
    the enclosing .raptor-run.json ``version``. complete_run later merges
    end-of-run facts (models, engines) into this same dict.

    The ``target`` block (the "what code was analysed" half of attribution) is
    an ACQUISITION stamp — how the code arrived, NOT a content-equivalence id
    (that is the coverage store's, derived from the inventory's per-file SHAs):
    ``target_identity`` verbatim when the caller supplies one (e.g. the archive
    block from a target the run unpacked), else ``target_snapshot(target)`` for
    a git checkout, else ``{source: "directory"}`` for a plain directory.
    """
    manifest: Dict[str, Any] = {
        "schema": 1,
        "source_control": source_control_snapshot(repo_dir),
        "environment": environment_snapshot(),
    }
    tgt = target_identity if target_identity is not None else target_snapshot(target)
    if not tgt and target and Path(target).is_dir():
        # Non-git, non-archive directory: record only that it was a directory
        # acquisition. Its content identity is the coverage store's to derive.
        tgt = {"source": "directory"}
    if tgt:
        manifest["target"] = tgt
    # WHO — the operator's public-facing identity (#485), from the per-uid
    # ~/.raptor/identity.json. Omitted entirely when unset (no default); the
    # citation view gates on its presence. See core.run.identity.
    from core.run.identity import load_finder_identity
    who = load_finder_identity()
    if who:
        manifest["who"] = who
    return manifest


# Stamp written into the manifest of a run we cannot characterise — adopted
# legacy directories, or anything created before manifest capture existed.
# cite/reporting key off this to degrade honestly ("provenance unavailable")
# instead of reading today's state and pretending it produced the run.
UNAVAILABLE_MANIFEST: Dict[str, Any] = {
    "schema": 1,
    "provenance": "unavailable",
    "reason": "run predates manifest capture",
}


# --- Rendering ------------------------------------------------------------
# Shared formatters so every operator-facing surface (run listings, reports,
# end-of-run footer) renders provenance identically. These are LOCAL views —
# they may show source paths and full SHAs. The publication/redaction view for
# cite is a separate concern and must not reuse these verbatim.

def format_sha_short(manifest: Optional[Dict[str, Any]]) -> str:
    """Compact VCS tag for a one-line run listing: ``<sha7>`` with a trailing
    ``*`` when the tree was modified. Empty string when no source-control info
    is available (legacy / unavailable runs) — callers render nothing.
    """
    sc = (manifest or {}).get("source_control") or {}
    sha = sc.get("base_sha")
    if not sha:
        return ""
    return sha[:7] + ("*" if sc.get("dirty") else "")


def format_manifest_block(manifest: Optional[Dict[str, Any]],
                          indent: str = "  ") -> str:
    """Multi-line human-readable provenance for reports / footers. Empty string
    when there is no manifest. Honest about unavailable provenance rather than
    inventing current state.
    """
    if not manifest:
        return ""
    if manifest.get("provenance") == "unavailable":
        return f"{indent}Provenance: unavailable (run predates manifest capture)"

    lines = []
    sc = manifest.get("source_control") or {}
    if sc.get("base_sha"):
        suffix = " (modified)" if sc.get("dirty") else ""
        lines.append(f"{indent}RAPTOR: {sc['base_sha'][:12]}{suffix}")

    env = manifest.get("environment") or {}
    if env:
        lines.append(
            f"{indent}Env: Python {env.get('python', '?')} "
            f"on {env.get('os', '?')}/{env.get('arch', '?')}"
        )

    engines = manifest.get("engines") or {}
    if engines:
        rendered = ", ".join(
            f"{name} {ver or '?'}" for name, ver in sorted(engines.items())
        )
        lines.append(f"{indent}Engines: {rendered}")

    for m in manifest.get("models") or []:
        resolved = m.get("resolved") or m.get("alias") or "?"
        lines.append(
            f"{indent}Model: {m.get('alias', '?')} → {resolved} "
            f"({m.get('role', '?')}, {m.get('calls', '?')}×)"
        )

    if "deterministically_reproducible" in manifest:
        repro = manifest["deterministically_reproducible"]
        lines.append(
            f"{indent}Reproducible: "
            + ("yes" if repro else "no (LLM-mediated)")
        )

    return "\n".join(lines)


# --- Publication / redaction view ----------------------------------------
# Safe top-level run fields that may be published for attribution/citation.
# Deliberately excludes target_path (leaks operator username, internal dir
# structure, possibly an embargoed target), session_pid / tool_pid (machine
# state), and `extra` (a free-form grab-bag that can carry raw exception
# strings — paths, secrets — via fail_run(error=...)).
_PUBLIC_TOPLEVEL_FIELDS = (
    "command", "timestamp", "end_timestamp", "duration_seconds",
    "status", "version",
)


def public_view(run_metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Publish-safe projection of a run's ``.raptor-run.json`` for citation.

    The full record is for LOCAL use only — `/project status`, sweep,
    diagnostics. It carries the operator's absolute ``target_path``, machine
    PIDs, and a free-form ``extra`` that may include raw exception text. NONE
    of that may leave the machine. This projection is the ONLY thing a
    cite/publish path may emit.

    Allowlist, not denylist: anything not explicitly named is dropped, so a
    field added to ``.raptor-run.json`` later cannot silently leak. ``extra``
    is default-denied wholesale; ``target_path`` is dropped entirely (an
    opt-in target *label* belongs to the cite UX, not to this primitive). The
    manifest is itself publish-safe by construction — base_sha (public repo),
    dirty flag, diff *hash* (never content), coarse env, engine versions, and
    model snapshots — so it is forwarded under an explicit field allowlist.
    """
    md = run_metadata or {}
    out: Dict[str, Any] = {}

    for key in _PUBLIC_TOPLEVEL_FIELDS:
        if key in md:
            out[key] = md[key]

    manifest = md.get("manifest") or {}
    if not manifest:
        return out

    if manifest.get("provenance") == "unavailable":
        out["manifest"] = {"provenance": "unavailable"}
        return out

    pub: Dict[str, Any] = {}
    sc = manifest.get("source_control") or {}
    if sc:
        pub["source_control"] = {
            "base_sha": sc.get("base_sha"),
            "dirty": sc.get("dirty"),
            # Hash only — the diff content is never stored, so this is safe.
            "diff_sha256": sc.get("diff_sha256"),
        }
    # Target block: a git target carries commit/branch (possibly a private
    # engagement) → dropped. A non-git target (archive / directory) is an
    # acquisition stamp — hashes + names only → publish-safe, the attribution a
    # citation wants ("found in archive X"). Discriminate by `commit`. The
    # content-equivalence id is the coverage store's, not published here.
    tgt = manifest.get("target")
    if isinstance(tgt, dict) and not tgt.get("commit"):
        safe_tgt = {
            k: tgt[k] for k in
            ("source", "archive_sha256", "archive_name", "format")
            if k in tgt
        }
        if safe_tgt:
            pub["target"] = safe_tgt
    # Field-allowlist INSIDE each sub-dict too — never forward verbatim, so a
    # crafted/imported manifest can't smuggle a path or secret under an extra
    # key in environment / engines / models.
    env = manifest.get("environment") or {}
    if isinstance(env, dict):
        env_pub = {k: env[k] for k in ("python", "os", "arch") if k in env}
        if env_pub:
            pub["environment"] = env_pub
    engines = manifest.get("engines")
    if isinstance(engines, dict) and engines:
        # name -> version string. Richer engine metadata (rulesets/queries),
        # if ever added, must be re-allowlisted here — don't pass dicts through.
        pub["engines"] = {
            str(name): ver
            for name, ver in engines.items()
            if isinstance(name, str) and (ver is None or isinstance(ver, str))
        }
    models = manifest.get("models")
    if isinstance(models, list) and models:
        pub["models"] = [
            {k: m.get(k) for k in ("provider", "alias", "resolved", "role", "calls")}
            for m in models if isinstance(m, dict)
        ]
    if "deterministically_reproducible" in manifest:
        pub["deterministically_reproducible"] = manifest["deterministically_reproducible"]
    if pub:
        out["manifest"] = pub
    return out


def format_repro_short(manifest: Optional[Dict[str, Any]]) -> str:
    """Compact reproducibility tag for a run listing: ``repro`` (mechanical,
    deterministic) / ``llm`` (LLM-mediated verdict) / ``""`` when unknown."""
    if not manifest or "deterministically_reproducible" not in manifest:
        return ""
    return "repro" if manifest["deterministically_reproducible"] else "llm"


def aggregate_provenance(
    metadatas: Iterable[Optional[Dict[str, Any]]],
) -> Dict[str, Any]:
    """Roll up per-run ``.raptor-run.json`` manifests into a project summary.

    Counts runs by framework SHA, flags modified-tree runs, unions engine
    versions, counts runs per model (by resolved snapshot, else alias), and
    splits reproducible vs LLM-mediated. Runs with no / unavailable manifest
    are counted as ``unavailable`` rather than guessed.
    """
    summary: Dict[str, Any] = {
        "runs": 0,
        "shas": {},          # base_sha -> run count
        "dirty_runs": 0,
        "engines": {},       # name -> sorted versions seen
        "models": {},        # resolved-or-alias -> run count
        "reproducible": {"yes": 0, "no": 0, "unknown": 0},
        "unavailable": 0,
    }
    engines_acc: Dict[str, set] = {}
    for md in metadatas:
        if not md:
            continue
        summary["runs"] += 1
        m = md.get("manifest") or {}
        if not m or m.get("provenance") == "unavailable":
            if m.get("provenance") == "unavailable":
                summary["unavailable"] += 1
            summary["reproducible"]["unknown"] += 1
            continue
        sc = m.get("source_control") or {}
        sha = sc.get("base_sha")
        if sha:
            summary["shas"][sha] = summary["shas"].get(sha, 0) + 1
        if sc.get("dirty"):
            summary["dirty_runs"] += 1
        engines = m.get("engines")
        if isinstance(engines, dict):  # tolerate malformed/imported manifests
            for name, ver in engines.items():
                engines_acc.setdefault(name, set()).add(ver or "?")
        seen = {
            (mdl.get("resolved") or mdl.get("alias") or "?")
            for mdl in (m.get("models") or [])
        }
        for key in seen:
            summary["models"][key] = summary["models"].get(key, 0) + 1
        dr = m.get("deterministically_reproducible")
        bucket = "yes" if dr is True else "no" if dr is False else "unknown"
        summary["reproducible"][bucket] += 1
    summary["engines"] = {k: sorted(v) for k, v in sorted(engines_acc.items())}
    return summary


def format_provenance_rollup(summary: Dict[str, Any]) -> str:
    """Human-readable project-level provenance rollup from aggregate_provenance."""
    runs = summary.get("runs", 0)
    if not runs:
        return "No runs with provenance."
    lines = [f"Provenance across {runs} run(s):"]

    shas = summary.get("shas") or {}
    if shas:
        ordered = sorted(shas.items(), key=lambda kv: (-kv[1], kv[0]))
        lines.append("  Framework SHAs: "
                     + ", ".join(f"{s[:12]} ({n})" for s, n in ordered))
        if len(shas) > 1:
            lines.append(f"    ⚠ {len(shas)} distinct RAPTOR versions across runs")

    dirty = summary.get("dirty_runs", 0)
    if dirty:
        lines.append(f"  Modified-tree runs: {dirty}/{runs}")

    engines = summary.get("engines") or {}
    if engines:
        lines.append("  Engines: "
                     + "; ".join(f"{k} {'/'.join(v)}" for k, v in engines.items()))

    models = summary.get("models") or {}
    if models:
        ordered_m = sorted(models.items(), key=lambda kv: (-kv[1], kv[0]))
        lines.append("  Models: " + ", ".join(f"{k} ({n})" for k, n in ordered_m))

    r = summary.get("reproducible") or {}
    lines.append(
        f"  Reproducible: {r.get('yes', 0)} deterministic, "
        f"{r.get('no', 0)} LLM-mediated, {r.get('unknown', 0)} unknown"
    )
    if summary.get("unavailable"):
        lines.append(f"  Provenance unavailable: {summary['unavailable']} run(s)")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Manifest read accessors — the stable read contract.
#
# Consumers that read a run's provenance (the CoverageStore's import step, the
# /project rollup, a future citation view) go through THESE rather than indexing
# the raw ``.raptor-run.json`` dict, so the manifest's internal shape can evolve
# without breaking them. Every accessor takes the loaded run-metadata dict (from
# ``load_run_metadata(run_dir)``) and degrades gracefully — missing/legacy
# fields return None / empty, never raise — so the same call works against an
# old manifest, today's, and one with fields not yet added.
#
# The companion location convention is ``RUN_METADATA_FILE`` +
# ``load_run_metadata(run_dir)`` in core.run.metadata.
# ---------------------------------------------------------------------------


def run_manifest(run_metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The sealed manifest sub-dict of a loaded run metadata, or ``{}`` when
    absent or the 'unavailable' stamp (legacy/adopted runs). The base every
    field accessor below reads through."""
    if not run_metadata:
        return {}
    m = run_metadata.get("manifest")
    if not isinstance(m, dict) or m.get("provenance") == "unavailable":
        return {}
    return m


def run_engines(run_metadata: Optional[Dict[str, Any]]) -> Dict[str, Optional[str]]:
    """``{engine_name: version}`` that ran (version may be None), or ``{}``."""
    engines = run_manifest(run_metadata).get("engines")
    return dict(engines) if isinstance(engines, dict) else {}


def run_models(run_metadata: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The models that fired — each a dict with ``provider`` / ``alias`` /
    ``resolved`` (the snapshot, not the floating alias) / ``role`` / ``calls``.
    ``[]`` when none (e.g. a mechanical scan)."""
    models = run_manifest(run_metadata).get("models")
    return [m for m in models if isinstance(m, dict)] if isinstance(models, list) else []


def run_target(run_metadata: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The target's ACQUISITION stamp — how the code was acquired: git
    ``{vcs, commit, branch, dirty}`` / archive ``{source, archive_sha256, …}`` /
    ``{source: "directory"}``. None when absent.

    This is the loose, per-acquisition audit stamp, NOT a content-equivalence
    id: two acquisitions of identical bytes (a git checkout vs a zip) carry
    *different* stamps here by design. A consumer that needs content
    equivalence (git-X ≡ zip-X) derives it from the inventory's per-file
    SHA-256 set, not from this field.
    """
    target = run_manifest(run_metadata).get("target")
    return target if isinstance(target, dict) else None


def run_framework_sha(run_metadata: Optional[Dict[str, Any]]) -> Optional[str]:
    """The RAPTOR framework ``base_sha`` that produced the run, or None."""
    sc = run_manifest(run_metadata).get("source_control")
    return sc.get("base_sha") if isinstance(sc, dict) else None


def run_timestamp(run_metadata: Optional[Dict[str, Any]]) -> Optional[str]:
    """The run's start timestamp (ISO 8601). Top-level on the metadata, not in
    the manifest — the accessor hides that."""
    if not run_metadata:
        return None
    ts = run_metadata.get("timestamp")
    return ts if isinstance(ts, str) else None


def run_deterministically_reproducible(
    run_metadata: Optional[Dict[str, Any]],
) -> Optional[bool]:
    """Whether the run's verdict is a pure function of its inputs (mechanical),
    or None when the manifest predates the field — so a consumer can tell
    "not reproducible" apart from "unknown"."""
    v = run_manifest(run_metadata).get("deterministically_reproducible")
    return v if isinstance(v, bool) else None


def run_who(run_metadata: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The operator's public-facing identity (``{name, handle?, url?}``) sealed
    at run start, or None when no identity was set — the WHO a citation
    credits. See core.run.identity."""
    who = run_manifest(run_metadata).get("who")
    return who if isinstance(who, dict) else None


def harness_model_entry(model: Optional[str]) -> Optional[Dict[str, Any]]:
    """A ``models[]`` entry for an agent-supplied ambient harness model — the
    only value only the harness (the Claude session) knows, since RAPTOR's
    Python can't read ``/model`` (no env var). The completion stubs build this
    from the ``--model`` the /validate, /understand skills instruct the agent
    to pass.

    Hardened against the agent getting it wrong (it will): an unsubstituted
    ``<your-model-id>`` placeholder, a stray flag captured as the value (leading
    ``-``), whitespace-bearing prose, an empty/missing string, or an
    implausibly long value all return None — the manifest then omits the model
    rather than recording garbage (a wrong/junk model is worse than absent)."""
    if not isinstance(model, str):
        return None
    m = model.strip()
    if (not m
            or m.startswith("-")                # a stray flag captured as value
            or "<" in m or ">" in m             # unsubstituted <placeholder>
            or len(m) > 128                      # implausibly long
            # printable non-space ASCII only (0x21-0x7e): model ids are ASCII
            # with no spaces, so this single check rejects prose/whitespace,
            # control bytes (\x00, \x1b ANSI escapes), and unicode tricks
            # (RTL-override) that would inject into / spoof the published manifest.
            or any(not (0x21 <= ord(ch) <= 0x7e) for ch in m)):
        return None
    return {"role": "harness", "alias": m, "resolved": m}
