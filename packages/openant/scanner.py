"""OpenAnt integration — invoke OpenAnt via subprocess and collect output.

Runs OpenAnt as a subprocess with PYTHONPATH set to its core directory.
This avoids sys.path contamination: OpenAnt has its own `core/` package
that would shadow Raptor's if added to sys.path directly.

The subprocess exits 0 (no vulns) or 1 (vulns found) on success, 2 on error.
Output is written to out_dir; pipeline_output.json is the primary artifact.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from core.config import RaptorConfig
from core.json import load_json
from core.logging import get_logger

# Budget for OpenAnt's pipeline_output.json (produced over a hostile
# repo) — same ceiling as the run-artifact readers.
from core.coverage.record import RUN_ARTIFACT_MAX_BYTES as _OUTPUT_MAX_BYTES

# Maximum bytes to persist from OpenAnt subprocess stderr. Generous upper bound
# for any reasonable error trace; bounded so a misbehaving OpenAnt that spams
# stderr in a tight loop cannot fill the disk.
STDERR_MAX_BYTES = 1_000_000  # 1 MiB

# Languages exposed by OpenAnt's --language CLI flag.
# Zig and others may be auto-detected but are not valid --language values.
# Source: `openant scan --help` → `--language {auto,python,javascript,go,c,ruby,php}`
_OPENANT_CLI_LANGUAGES = {"auto", "python", "javascript", "go", "c", "ruby", "php"}

from .config import OPENANT_PINNED_COMMIT, OPENANT_UPSTREAM_URL, OpenAntConfig

logger = get_logger()


def _warn_unpinned_provenance(
    result: dict[str, Any], core_path: Path,
) -> dict[str, Any]:
    """One loud stderr warning for EVERY non-pinned provenance shape.

    ``matches is False`` (a git checkout at a different commit) is the
    cooperative-mistake shape; ``matches is None`` (not a git checkout
    at the documented ``libs/openant-core`` layout — tarball extract,
    deleted ``.git``, or an attacker-written directory) is the hostile
    shape. Warning only on the first left the second SILENT, which
    inverted the risk ordering: unverifiable provenance is the shape a
    planted core presents.
    """
    if result["matches"] is True:
        return result
    if result["matches"] is False:
        logger.warning(
            "OpenAnt checkout is at %s, integration is pinned to %s — "
            "schema drift possible; re-checkout the pinned commit or "
            "re-verify the translator's verdict enumeration",
            str(result["head"])[:12], OPENANT_PINNED_COMMIT[:12],
        )
    else:
        logger.warning(
            "OpenAnt core provenance UNVERIFIABLE — %s is not a git "
            "checkout at the documented libs/openant-core layout, so the "
            "pinned commit %s cannot be confirmed. A tampered or "
            "attacker-written core executes with network access; "
            "re-clone %s at the pin or verify the directory by hand",
            core_path, OPENANT_PINNED_COMMIT[:12], OPENANT_UPSTREAM_URL,
        )
    return result


def checkout_provenance(core_path: Path) -> dict[str, Any]:
    """Compare the openant-core checkout's HEAD against the pin.

    The checkout is INTERNET-SOURCED and operator-managed, so its
    .git/config is untrusted — the rev-parse goes through the strict
    read-only argv with the sanitised git env (same posture as the
    recall corpora's pinned-clone verification). Never raises, and
    EVERY non-pinned result warns loudly on stderr (mismatched commit
    AND unverifiable non-git / unexpected-layout shapes); recorded, not
    enforced here (an operator may deliberately run a newer OpenAnt;
    the translator keeps unknown verdicts visible instead of dropping
    them). The ``--openant-core`` consent gate is the enforcement
    point for the flag surface.
    """
    result: dict[str, Any] = {
        "pinned_commit": OPENANT_PINNED_COMMIT,
        "head": None,
        "matches": None,
    }
    try:
        from core.git import get_safe_git_env, safe_git_readonly_command

        def _git(*args: str) -> "subprocess.CompletedProcess[str]":
            return subprocess.run(
                safe_git_readonly_command("-C", str(core_path), *args),
                capture_output=True, text=True, timeout=30, check=False,
                env=get_safe_git_env(),
            )

        # Layout guard: `git -C` discovers UPWARD, so a non-git
        # openant-core (tarball extract) sitting inside an unrelated
        # repository would otherwise record the ENCLOSING repo's HEAD
        # as OpenAnt provenance. Require the documented layout — the
        # checkout's toplevel carries core_path at libs/openant-core.
        top = _git("rev-parse", "--show-toplevel")
        toplevel = top.stdout.strip()
        if top.returncode != 0 or not toplevel:
            return _warn_unpinned_provenance(result, core_path)
        expected = Path(toplevel) / "libs" / "openant-core"
        if expected.resolve() != Path(core_path).resolve():
            return _warn_unpinned_provenance(result, core_path)

        proc = _git("rev-parse", "HEAD")
    except (OSError, subprocess.SubprocessError):
        return _warn_unpinned_provenance(result, core_path)
    head = proc.stdout.strip().lower()
    if proc.returncode != 0 or not head:
        return _warn_unpinned_provenance(result, core_path)
    result["head"] = head
    result["matches"] = head == OPENANT_PINNED_COMMIT
    return _warn_unpinned_provenance(result, core_path)


class OpenAntCoreConsentError(RuntimeError):
    """An explicit ``--openant-core`` path is not a clean checkout of
    the pinned commit and nothing authorizes running it."""


def _read_verified_object(
    git, top: Path, algo: str, otype: str, oid: str,
) -> bytes | None:
    """Raw payload of ``oid``, SELF-HASHED against its claimed name.

    git does NOT re-hash every object on ordinary reads: a loose (or
    packed) object file whose CONTENT was substituted under a genuine
    name is served as-is by ``ls-tree``/``cat-file`` (``git fsck``
    reports it as a hash mismatch, but the read path never checks).
    The object store of an attacker-shipped clone is therefore not in
    the trust base — every object this survey consumes is re-hashed
    in Python (``"<type> <len>\\0" + payload``) against the name its
    verified PARENT claimed, exactly the discipline the survey already
    applies to worktree blobs. Returns ``None`` (fail-closed) on a
    read failure or a hash mismatch. Alternates / replace refs /
    doctored packs cannot help an attacker here: wherever the bytes
    come from, they must hash to the requested name (replace refs are
    additionally pinned off via ``core.useReplaceRefs=false`` in the
    safe-git overrides).
    """
    import hashlib

    proc = git(top, "cat-file", otype, oid)
    if proc.returncode != 0:
        return None
    payload = proc.stdout
    hasher = hashlib.sha1 if algo == "sha1" else hashlib.sha256
    h = hasher(b"%s %d\x00" % (otype.encode("ascii"), len(payload)))
    h.update(payload)
    if h.hexdigest() != oid:
        return None
    return payload


def _parse_tree_payload(
    payload: bytes, oid_len: int,
) -> list[tuple[str, bytes, str]] | None:
    """Parse a raw tree payload into ``(mode, name, hex_oid)`` entries.

    Returns ``None`` on any structural anomaly (a VERIFIED tree from
    the genuine pinned commit is always well-formed, so an anomaly
    means the walk must fail closed). Entry names containing path
    separators or ``.``/``..`` are rejected outright — a genuine git
    tree never contains them.
    """
    entries: list[tuple[str, bytes, str]] = []
    i = 0
    n = len(payload)
    while i < n:
        sp = payload.find(b" ", i)
        if sp < 0:
            return None
        try:
            mode = payload[i:sp].decode("ascii")
        except UnicodeDecodeError:
            return None
        nul = payload.find(b"\x00", sp + 1)
        if nul < 0:
            return None
        name = payload[sp + 1:nul]
        if (not name or name in (b".", b"..") or b"/" in name
                or b"\\" in name):
            return None
        raw_oid = payload[nul + 1:nul + 1 + oid_len]
        if len(raw_oid) != oid_len:
            return None
        entries.append((mode, name, raw_oid.hex()))
        i = nul + 1 + oid_len
    return entries


# Ceiling on tree entries walked by the survey. The verified walk can
# only ever traverse the GENUINE pinned content (every tree self-hashes
# against the pin-anchored chain), so this is a robustness backstop,
# not a hostile-input bound; the genuine OpenAnt tree is a few thousand
# entries.
_TREE_WALK_MAX_ENTRIES = 1_000_000


def _verified_pinned_tree(
    git, top: Path, algo: str, pin: str,
) -> list[tuple[str, str, str]] | None:
    """Merkle-verified recursive listing of the PIN's tree.

    Anchors at the pinned commit id itself (never a ref): the commit
    payload is self-hashed against the pin, the root tree oid is taken
    from that verified payload, and every subtree payload is
    self-hashed against the oid its verified parent claimed before its
    listing is trusted. This extends the survey's Merkle discipline
    one level up — the landed survey hashed worktree blobs against
    HEAD's tree LISTING but took the listing from ``ls-tree``, which
    trusts attacker-shipped tree objects as stored (one substituted
    subtree object whose forged listing matched the hostile on-disk
    files passed the whole gate).

    Returns ``[(mode, blob_oid, relpath), ...]`` for every non-tree
    entry, or ``None`` when any object fails verification
    (fail-closed).
    """
    oid_len = 20 if algo == "sha1" else 32
    hex_len = oid_len * 2

    commit_payload = _read_verified_object(git, top, algo, "commit", pin)
    if commit_payload is None:
        return None
    first_line, _, _ = commit_payload.partition(b"\n")
    if not first_line.startswith(b"tree "):
        return None
    root_oid = first_line[5:].decode("ascii", "replace").strip().lower()
    if len(root_oid) != hex_len or any(
        c not in "0123456789abcdef" for c in root_oid
    ):
        return None

    listing: list[tuple[str, str, str]] = []
    stack: list[tuple[bytes, str]] = [(b"", root_oid)]
    total_entries = 0
    while stack:
        prefix, tree_oid = stack.pop()
        payload = _read_verified_object(git, top, algo, "tree", tree_oid)
        if payload is None:
            return None
        entries = _parse_tree_payload(payload, oid_len)
        if entries is None:
            return None
        total_entries += len(entries)
        if total_entries > _TREE_WALK_MAX_ENTRIES:
            return None
        for mode, name, entry_oid in entries:
            rel = name if not prefix else prefix + b"/" + name
            if mode == "40000":
                stack.append((rel, entry_oid))
            else:
                listing.append((mode, entry_oid, os.fsdecode(rel)))
    return listing


def _pinned_tree_deviations(core_path: Path) -> dict[str, int] | None:
    """Content-true worktree-vs-PIN deviation counts for a checkout
    whose HEAD already matched the pin.

    Returns ``{"modified": n, "untracked": m}`` (``{"modified": 0,
    "untracked": 0}`` when clean), or ``None`` when the survey itself
    fails — the gate treats ``None`` as unverifiable (fail-closed).
    ``modified`` counts tracked entries whose on-disk content, type,
    or executable bit deviates from the pin (missing files and
    unverifiable gitlink entries included); ``untracked`` counts every
    on-disk file that is not in the pin's tree — IGNORED and
    INDEX-STAGED FILES INCLUDED: the attacker controls ``.gitignore``
    and the shipped index alike, and an ignored or pre-staged
    stdlib-shadow module (or a poisoned ``__pycache__`` bytecode file)
    executes all the same.

    Deliberately NOT ``git status``/``git diff``: on an
    attacker-written clone the status machinery re-hashes worktree
    content through ``filter.<name>.clean`` commands (configured in
    the hostile ``.git/config`` + in-tree ``.gitattributes``), which
    the safe-git overrides document as un-neutralisable — the gate
    would execute hostile code BEFORE the consent decision it exists
    to enforce. And the INDEX is not in the trust base at all: the
    attacker ships ``.git/index`` too, so an index-derived untracked
    listing (``ls-files --others``) is blind to a shadow module the
    archive pre-staged with ``git add -f`` (in the index, not in
    HEAD). NEITHER IS THE OBJECT STORE: the attacker ships
    ``.git/objects`` too, and git serves a content-substituted object
    without re-hashing it, so an ``ls-tree`` listing is forgeable
    even when the commit id matched the pin. The survey therefore
    compares DISK against the PIN only, through
    :func:`_verified_pinned_tree`: the pinned commit object is
    self-hashed against the pin id, every tree object is self-hashed
    against the oid its verified parent claimed, a Python filesystem
    walk of the clone toplevel (minus ``.git``) supplies what is
    actually on disk, and tracked content is hashed in Python against
    the verified blob ids — no attacker-shipped byte participates in
    the verification chain unverified. This also defeats fabricated
    index stat data that fools stat-based diffs. Tracked blobs larger
    than the hashing cap fail closed as modified rather than being
    read.
    """
    import hashlib
    import stat as stat_mod

    # Cap on bytes hashed per tracked on-disk file. The verified
    # listing only ever names the genuine pinned content, so legit
    # blob sizes are upstream-bounded; an on-disk file claiming to be
    # larger fails closed without a read.
    max_hash_bytes = 64 * 1024 * 1024
    try:
        from core.git import get_safe_git_env, safe_git_readonly_command

        def _git(cwd: Path, *args: str) -> "subprocess.CompletedProcess[bytes]":
            return subprocess.run(
                safe_git_readonly_command("-C", str(cwd), *args),
                capture_output=True, timeout=120, check=False,
                env=get_safe_git_env(),
            )

        fmt = _git(core_path, "rev-parse", "--show-object-format")
        algo = fmt.stdout.decode("ascii", "replace").strip() or "sha1"
        if fmt.returncode != 0 or algo not in ("sha1", "sha256"):
            return None
        toplevel_proc = _git(core_path, "rev-parse", "--show-toplevel")
        toplevel = toplevel_proc.stdout.decode("utf-8", "replace").strip()
        if toplevel_proc.returncode != 0 or not toplevel:
            return None
        top = Path(toplevel)
        # The WHOLE clone is surveyed, not just the openant-core
        # subtree — anchored at the PIN id, never at HEAD (an
        # attacker-shipped ref is not in the trust base either).
        listing = _verified_pinned_tree(_git, top, algo, OPENANT_PINNED_COMMIT)
        if listing is None:
            return None
    except (OSError, subprocess.SubprocessError):
        return None

    modified = 0
    tracked: set[str] = set()
    for mode, oid, rel_str in listing:
        tracked.add(rel_str)
        path = top / rel_str
        if mode not in ("100644", "100755", "120000"):
            # gitlink (submodule) or unknown mode: content cannot be
            # verified against the pin from here — fail closed.
            modified += 1
            continue
        try:
            st = os.lstat(path)
        except OSError:
            modified += 1  # tracked file missing / unreadable
            continue
        if mode == "120000":
            if not stat_mod.S_ISLNK(st.st_mode):
                modified += 1
                continue
            data = os.fsencode(os.readlink(path))
        else:
            if not stat_mod.S_ISREG(st.st_mode):
                modified += 1
                continue
            want_exec = mode == "100755"
            if bool(st.st_mode & 0o100) != want_exec:
                modified += 1
                continue
            # Size precheck BEFORE any read: an over-cap on-disk file
            # fails closed instead of being slurped (the verified blob
            # hash below catches any size mismatch either way).
            if st.st_size > max_hash_bytes:
                modified += 1
                continue
            try:
                data = path.read_bytes()
            except OSError:
                modified += 1
                continue
        hasher = hashlib.sha1 if algo == "sha1" else hashlib.sha256
        h = hasher(b"blob %d\x00" % len(data))
        h.update(data)
        if h.hexdigest() != oid:
            modified += 1

    # Untracked = ON DISK but not in HEAD's tree, derived WITHOUT the
    # index: a filesystem walk (minus the toplevel .git) set-differenced
    # against the tree paths. Ignored and index-staged files count the
    # same as any other file the pinned commit does not contain.
    untracked = 0
    try:
        for root, dirs, files in os.walk(top, followlinks=False):
            rel_root = os.path.relpath(root, top)
            if rel_root == ".":
                dirs[:] = [d for d in dirs if d != ".git"]
            # Symlinks to directories are tree ENTRIES (link blobs) but
            # os.walk reports them in `dirs` and never descends: count
            # each one not in HEAD's tree instead of losing it.
            for d in list(dirs):
                dpath = os.path.join(root, d)
                if os.path.islink(dpath):
                    dirs.remove(d)
                    drel = d if rel_root == "." else os.path.join(rel_root, d)
                    if drel not in tracked:
                        untracked += 1
            for name in files:
                rel_file = name if rel_root == "." else os.path.join(rel_root, name)
                if rel_file not in tracked:
                    untracked += 1
    except OSError:
        return None
    return {"modified": modified, "untracked": untracked}


def enforce_core_consent(
    core_path: Path,
    *,
    consented: bool,
    target_path: str | Path | None = None,
) -> dict[str, Any]:
    """Consent gate for the ``--openant-core`` FLAG surface.

    The flag lives on pre-approved launcher argv, so without a gate it
    is prompt-free arbitrary code execution: the named directory's
    Python runs in a network-allowed subprocess with the Anthropic API
    key. A non-pinned core passed by flag therefore REFUSES at startup
    unless the operator consents — the per-run
    ``--openant-core-unpinned`` acknowledgement, or the project's
    standing ``config`` trust marker (the ``--trust-repo`` umbrella,
    same one-target rule as every marker consumer).

    Deliberately NOT applied to the ``$OPENANT_CORE`` env / auto-detect
    default: environment and project state are operator-owned surfaces
    (an env-prefixed command string breaks the pre-approved grant), and
    those paths keep the existing warn-not-refuse posture.

    A matching HEAD alone is CONTENT-BLIND — a hostile archive can
    vendor a nested clone at the pinned HEAD with tampered tracked
    files (or an untracked stdlib-shadow module; the child runs with
    the core on its import path) — so a pinned HEAD additionally
    requires a clean working tree (:func:`_pinned_tree_deviations`,
    untracked and ignored files included). A deviating or unverifiable
    tree refuses-unless-consented exactly like a wrong commit, with a
    loud warning that summarises deviation COUNTS only (never echoing
    attacker-controlled filenames).

    Returns the provenance record (already loudly warned when not a
    clean pinned checkout) when the run may proceed; raises
    :class:`OpenAntCoreConsentError` naming the risk and the escape
    hatches otherwise.
    """
    provenance = checkout_provenance(core_path)
    dirty: dict[str, int] | None = None
    if provenance["matches"] is True:
        dirty = _pinned_tree_deviations(core_path)
        if dirty is not None and not (dirty["modified"] or dirty["untracked"]):
            provenance["worktree_clean"] = True
            return provenance
        provenance["worktree_clean"] = False
        provenance["worktree_deviations"] = dirty
        if dirty is None:
            logger.warning(
                "OpenAnt checkout is at the pinned commit but its working "
                "tree could NOT be verified against the pinned content — "
                "treating it like a tampered checkout",
            )
        else:
            logger.warning(
                "OpenAnt checkout is at the pinned commit but its working "
                "tree DEVIATES from the pinned content — %d tracked "
                "file(s) modified/missing, %d untracked file(s) (ignored "
                "files included); a matching HEAD does not cover on-disk "
                "edits",
                dirty["modified"], dirty["untracked"],
            )
    if consented:
        return provenance
    from core.project.trust import resolve_repo_trust
    if resolve_repo_trust(None, target_path=target_path):
        return provenance
    from core.security.log_sanitisation import sanitise_for_terminal
    if provenance["matches"] is True and dirty is None:
        detail = (
            "it is at the pinned commit but its working tree could not "
            "be verified against the pinned content"
        )
    elif provenance["matches"] is True:
        detail = (
            f"it is at the pinned commit but its working tree deviates "
            f"from the pinned content ({dirty['modified']} tracked "
            f"file(s) modified/missing, {dirty['untracked']} untracked "
            f"file(s), ignored files included)"
        )
    elif provenance["matches"] is False:
        detail = (
            f"it is checked out at {str(provenance['head'])[:12]}, not the "
            f"pinned commit {OPENANT_PINNED_COMMIT[:12]}"
        )
    else:
        detail = (
            "its provenance is unverifiable — not a git checkout at the "
            "documented libs/openant-core layout"
        )
    raise OpenAntCoreConsentError(
        f"refusing --openant-core "
        f"{sanitise_for_terminal(str(core_path), max_len=200)}: {detail}. "
        f"An unverified core executes as arbitrary Python with network "
        f"access and the Anthropic API key. To run it anyway, consent "
        f"deliberately: re-run with --openant-core-unpinned, or set the "
        f"project's standing trust marker (/project trust config) — or "
        f"check the core out at the pin "
        f"({OPENANT_UPSTREAM_URL}@{OPENANT_PINNED_COMMIT[:12]})."
    )


def run_openant_scan(
    repo_path: str | Path,
    out_dir: str | Path,
    config: OpenAntConfig,
) -> dict[str, Any]:
    """Run OpenAnt scan and return a normalised result dict.

    Returns:
        pipeline_output_path (str | None)
        pipeline_output       (dict)
        token_usage           (dict)
        error                 (str | None)
        skipped               (bool)
        hard_error            (bool)  True when the scan was attempted and
                                      failed (timeout, launch failure,
                                      exit >= 2, missing output) — the
                                      target was NOT scanned. Absent/False
                                      on success. Not-configured cases
                                      raise RuntimeError instead (see
                                      ``_build_subprocess_env``).
    """
    repo_path = Path(repo_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    provenance = checkout_provenance(config.core_path)
    result = _run_subprocess(repo_path, out_dir, config)
    result["core_provenance"] = provenance
    return result


def _run_subprocess(
    repo_path: Path,
    out_dir: Path,
    config: OpenAntConfig,
) -> dict[str, Any]:
    """Run OpenAnt as a subprocess with PYTHONPATH=config.core_path.

    Using PYTHONPATH (subprocess-scoped) instead of sys.path.insert prevents
    OpenAnt's `core/` package from shadowing Raptor's `core/` in this process.

    cwd is set to config.core_path so that Python's implicit '' sys.path entry
    (the working directory) resolves to openant-core rather than Raptor's repo
    root — which also contains a `core/` package and would otherwise shadow it.
    """
    env = _build_subprocess_env(config)
    cmd = _build_command(repo_path, out_dir, config)

    logger.info(f"Running OpenAnt: {' '.join(str(c) for c in cmd)}")
    try:
        from core.sandbox.context import run as sandbox_run
        proc = sandbox_run(
            cmd,
            block_network=False,
            target=str(repo_path),
            output=str(out_dir),
            readable_paths=[str(config.core_path)],
            caller_label="openant",
            capture_output=True,
            text=True,
            timeout=config.timeout_seconds,
            env=env,
            cwd=str(config.core_path),
        )
    except subprocess.TimeoutExpired:
        return _empty_result(
            f"OpenAnt timed out after {config.timeout_seconds}s",
            hard_error=True,
        )
    except Exception as exc:  # noqa: BLE001
        return _empty_result(f"OpenAnt launch failed: {exc}", hard_error=True)

    # Persist stderr so debugging isn't capped at the 600-char snippet
    # we surface to the caller. (Adversarial-audit finding: long warnings
    # could push the actual error past the truncation point.)
    # Cap at STDERR_MAX_BYTES (1 MiB) so a misbehaving subprocess cannot
    # fill the disk by spamming stderr in a tight loop.
    if proc.stderr:
        try:
            stderr_to_write = proc.stderr[:STDERR_MAX_BYTES]
            if len(proc.stderr) > STDERR_MAX_BYTES:
                stderr_to_write += (
                    f"\n\n[truncated — original was {len(proc.stderr)} bytes, "
                    f"capped at {STDERR_MAX_BYTES}]\n"
                )
            (out_dir / "openant.stderr.log").write_text(stderr_to_write)
        except OSError:
            pass

    if proc.returncode not in (0, 1):
        snippet = (proc.stderr or "")[:600].strip()
        return _empty_result(
            f"OpenAnt exited {proc.returncode}: {snippet} "
            f"(full stderr in {out_dir}/openant.stderr.log)",
            hard_error=True,
        )

    pipeline_output_path = out_dir / "pipeline_output.json"
    pipeline_output = _load_json(pipeline_output_path)
    if not pipeline_output:
        return _empty_result(
            f"OpenAnt produced no pipeline_output.json in {out_dir}",
            hard_error=True,
        )

    token_usage = _extract_usage(proc.stdout, pipeline_output)
    return {
        "pipeline_output_path": str(pipeline_output_path),
        "pipeline_output": pipeline_output,
        "token_usage": token_usage,
        "error": None,
        "skipped": False,
    }


def _find_venv_python(core_path: Path) -> str:
    """Return the Python executable that has OpenAnt's tree-sitter bindings.

    BUG-R-017: sys.executable (Raptor's Python) lacks tree-sitter-c,
    tree-sitter-ruby, tree-sitter-php, tree-sitter-javascript. Those packages
    are only installed in OpenAnt's own venv at core_path/.venv/bin/python3.
    Prefer that venv Python; fall back to sys.executable if the venv is absent.

    Uses os.access(path, os.X_OK) instead of .exists() to avoid returning a
    venv Python that exists on disk but is not executable (e.g., wrong mode bits).
    """
    for candidate in ("python3", "python3.11", "python3.12", "python3.13", "python"):
        venv_python = core_path / ".venv" / "bin" / candidate
        if os.access(venv_python, os.X_OK):
            return str(venv_python)
    return sys.executable


def _build_command(
    repo_path: Path,
    out_dir: Path,
    config: OpenAntConfig,
) -> list[str]:
    python_exe = _find_venv_python(config.core_path)
    # BUG-R-018: not all language names are valid --language CLI choices.
    # Languages like 'zig' are auto-detected but not exposed as CLI values.
    # Fall back to 'auto' for unrecognized language strings.
    lang = config.language if config.language in _OPENANT_CLI_LANGUAGES else "auto"
    cmd: list[str] = [
        python_exe, "-m", "openant",
        "scan", str(repo_path),
        "--output", str(out_dir),
        "--model", config.model,
        "--level", config.level,
        "--language", lang,
        "--workers", str(config.workers),
        "--no-report",
    ]
    if not config.enhance:
        cmd.append("--no-enhance")
    if config.verify:
        cmd.append("--verify")
    return cmd


def _build_subprocess_env(config: OpenAntConfig) -> dict[str, str]:
    safe = RaptorConfig.get_safe_env()
    safe["ANTHROPIC_API_KEY"] = os.environ.get("ANTHROPIC_API_KEY", "")
    # Resolve to absolute path so .. / symlinks / relative components cannot be
    # used to redirect Python's import resolution to an attacker-controlled dir
    # if OPENANT_CORE is set to an untrusted value.
    # Re-raise FileNotFoundError as RuntimeError so callers have a single
    # exception type to handle at the boundary (cleanup C-1 from /work-audit).
    try:
        resolved = config.core_path.resolve(strict=True)
    except FileNotFoundError as e:
        raise RuntimeError(
            f"OpenAnt core path does not exist: {config.core_path} "
            f"(set OPENANT_CORE to a valid libs/openant-core directory)"
        ) from e
    if not (resolved / "core" / "scanner.py").exists():
        raise RuntimeError(f"PYTHONPATH target {resolved} is not an openant-core directory")
    # Exactly the validated core path — never the ambient PYTHONPATH
    # tail. PYTHONPATH is on DANGEROUS_ENV_VARS (redirects Python
    # module imports); get_safe_env() drops it by design, and
    # re-appending the raw os.environ value re-opened the exact
    # env-poisoning lane the allowlist exists to close (the child runs
    # with network and ANTHROPIC_API_KEY). OpenAnt needs only its own
    # core directory on the path.
    safe["PYTHONPATH"] = str(resolved)
    return safe


def _load_json(path: Path) -> dict:
    """Bounded read of an OpenAnt output document (core.json.load_json
    already warns on parse failure / over-budget files)."""
    data = load_json(path, max_bytes=_OUTPUT_MAX_BYTES)
    return data if isinstance(data, dict) else {}


def _extract_usage(stdout: str, pipeline_output: dict) -> dict[str, Any]:
    try:
        data = json.loads(stdout)
        if isinstance(data, dict):
            usage = data.get("data", {}).get("usage")
            if usage:
                return usage
    except (json.JSONDecodeError, AttributeError):
        pass
    stats = pipeline_output.get("pipeline_stats") or {}
    costs = stats.get("costs") or {}
    total_cost = sum(
        v.get("actual", 0) for v in costs.values() if isinstance(v, dict)
    )
    return {"total_cost_usd": total_cost}


def _empty_result(error: str, *, hard_error: bool) -> dict[str, Any]:
    """Skipped-scan result. ``hard_error`` distinguishes an attempted
    scan that FAILED (the caller must not report the target as scanned
    clean) from a scan that never applied."""
    return {
        "pipeline_output_path": None,
        "pipeline_output": {"findings": []},
        "token_usage": {},
        "error": error,
        "skipped": True,
        "hard_error": hard_error,
    }
