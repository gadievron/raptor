"""Content-hash ledger of binaries produced by traced builds.

Traced-build consent (``--traced-build`` / the project ``build`` trust
marker) executes repo-controlled build scripts with a write grant on
the repo tree (``packages/codeql/database_manager.py``). A hostile
build script can write — or overwrite in place — a crafted debug ELF
under that tree; being git-untracked, the file passes binary-oracle
auto-detect's locally-built provenance filter and would acquire full
``absent``-suppression authority (it could suppress real findings as
dead code). The ``build`` marker authorizes executing the build; it is
consent to execute, never an evidence-authority grant, so
build-produced binaries must not inherit suppression authority from it.

Two properties shape the design:

* The exposure is CROSS-RUN: auto-detect runs during argument
  application, before this run's build executes, so a binary planted
  by this run's build is picked up by the NEXT run's auto-detect. The
  record therefore persists across runs.
* The build can also OVERWRITE a pre-existing operator-built untracked
  binary, so the record is a CONTENT-hash set, never a path set.

Capture: the traced-build seam snapshots the auto-detect candidate
universe (the same walk/classifier auto-detect itself uses —
:func:`core.analysis.binary_oracle_autodetect.elf_candidate_paths`)
before and after the build; post-build content hashes are appended
here unless an UNTRACKED pre-build carrier already held them. The
exemption is provenance-gated on purpose: the pre-build snapshot also
sees git-TRACKED ELFs, and a repo committing a crafted DWARF ELF whose
build step copies it to an untracked path would otherwise keep
absent-suppression authority through the mere pre-presence of its
bytes (the binary oracle's provenance doctrine — committed content
never earns suppression authority — applies on both sides of the
build). Consultation: an auto-detect
candidate whose content hash appears in the ledger rides the existing
no-suppression channel (``RaptorConfig.BINARY_ORACLE_NO_SUPPRESS`` →
per-record ``suppression_grade: false``) — verdicts still enrich at
hint tier, ``absent`` never hard-suppresses off them, and consumers
need no new states. Explicit operator assertions (``--binary`` /
``/project binary add``) always keep full authority even when
ledger-listed — operator ownership, the same doctrine as the
provenance-drop consent.

Storage / trust model: JSONL files per target repo under the
per-user XDG data dir (``$XDG_DATA_HOME/raptor/build-ledger/``, else
``~/.local/share/raptor/build-ledger/``). Each repo is keyed TWICE —
by its resolved path hash and by a ``st_dev:st_ino`` alias of the repo
root — with every record appended to both files and consultation
merging their union. The path key alone was an identity seam: moving
or bind-mounting the repo to a new path landed consultation on a
fresh key, which read as an ABSENT ledger (the migration window), so
a binary recorded as build-produced regained absent-suppression
authority by re-scanning from a different path. The inode alias
survives renames, moves within a filesystem, and bind mounts — for as
long as the device number itself is stable (``st_dev`` is not durable
across reboots on btrfs subvolumes, overlayfs and other
anonymous-device filesystems; alias loss alone is safe because every
record also lives in the path-key file). It is a
fail-closed-only widening: a copied repo (``cp -r``) gets fresh
inodes and keeps only the path key's reach (same identity loss as
today), and a recycled inode can at worst attribute ANOTHER repo's
build-produced hashes to this one — withholding authority it would
otherwise grant, never granting any. That location is
RAPTOR-owned: traced builds run sandboxed with write grants limited to
the repo tree and the per-call staging workspace, and run output dirs
— which less-trusted code CAN write — are never under it. The ledger
therefore needs no MAC stamp: its integrity rides on the same
placement contract that protects the per-purpose MAC key files
themselves (:mod:`core.security.mac_key` keeps keys in this very
tree), and a MAC could not defend the one attack placement does
(selective deletion of entries restores authority; a key reachable by
whoever could edit the ledger would mint valid stamps anyway).

Failure policy: capture failures are loud and RECORDED — a
``capture-incomplete`` marker makes the ledger unverifiable. An
unverifiable / corrupt / unreadable ledger fail-closes SUPPRESSION
(auto-detected candidates are treated as unproven and demoted) but
never errors the run. An absent ledger means no traced build has been
captured for the repo and behaviour is unchanged — the honest
migration window: binaries planted by builds that ran before this
feature landed are invisible to it.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)

#: Ledger record schema version. Readers refuse records from a NEWER
#: schema (fail-closed: an unknown shape cannot be verified).
LEDGER_SCHEMA = 1

#: Hard cap on ``build-binary`` entries per repo ledger. Entries are
#: deduped by hash, so the cap only binds when traced builds have
#: produced that many DISTINCT binary contents. Too low and a large
#: legitimate build tree (per-test binaries, many rebuild cycles)
#: trips the overflow marker, permanently withholding auto-detect
#: suppression for the repo (loud, remediable via --binary /
#: /project binary add, but a nuisance). Too high and a hostile build
#: can grow a RAPTOR-owned file without bound (~200 bytes/entry, so
#: 4096 ≈ 1 MB). Pinned by a regression test either way.
LEDGER_ENTRY_CAP = 4096

#: Cap on candidate files hashed per snapshot. The walk itself is
#: depth- and dir-bounded (auto-detect's universe), but a hostile repo
#: can pre-stage arbitrarily many ELF-magic files. Too low and a
#: legitimate build tree overflows into capture-incomplete (fail-closed
#: but noisy); too high and the pre-build snapshot hashes attacker
#: volume on RAPTOR's dime. 1024 is ~128x auto-detect's result cap (8).
#: Pinned by a regression test either way.
SNAPSHOT_FILE_CAP = 1024

#: Per-file hash budget. A hostile repo can pre-stage a huge sparse
#: +x ELF-magic file; hashing it in the pre-build snapshot would stall
#: the run (the file never ran through any build). Oversized files are
#: SKIPPED at capture and FLAGGED as unverifiable at consultation, so
#: the skip can never launder authority — symmetric fail-closed. Too
#: low rejects real fat-DWARF binaries from the consult path (they
#: then need an explicit --binary); too high re-opens the stall. 1 GiB
#: covers virtually every debug binary. Pinned by a regression test.
MAX_HASH_BYTES = 1 << 30

#: Read budget for the ledger file itself. A conforming ledger never
#: exceeds the entry cap times a generous line size; anything larger
#: was not written by this module and reads as unverifiable.
_MAX_LEDGER_BYTES = LEDGER_ENTRY_CAP * 1024

_KIND_BINARY = "build-binary"
_KIND_INCOMPLETE = "capture-incomplete"

# Serialises in-process writers (parallel per-language traced builds
# append concurrently). Cross-process writers rely on O_APPEND; a torn
# interleave parses as a malformed line, which reads fail-closed.
_write_lock = threading.Lock()


@dataclass(frozen=True)
class LedgerView:
    """Read-time view of one repo's ledger.

    ``status``:
      * ``"absent"`` — no ledger exists; no traced build has been
        captured for this repo (migration window: pre-feature plants
        are invisible). Current behaviour applies.
      * ``"ok"`` — ``hashes`` is the complete build-produced content
        set.
      * ``"unverifiable"`` — the ledger exists but cannot vouch for
        completeness (corrupt, unreadable, foreign-owned, overflowed,
        or carrying a capture-incomplete marker). Consumers must treat
        every non-operator-asserted candidate as unproven: no
        suppression authority, never an error.
    """

    status: Literal["absent", "ok", "unverifiable"]
    hashes: frozenset[str] = field(default_factory=frozenset)
    reason: str | None = None


def _ledger_dir() -> Path:
    # The XDG basedir spec requires IGNORING relative XDG_DATA_HOME
    # values. Honoring one would scatter cwd-relative ledgers: capture
    # writes under the orchestrator's cwd while consultation from any
    # other cwd reads "absent" — the record silently splits and the
    # feature stops working, plus a stray tree appears wherever the
    # process happens to run.
    xdg = os.environ.get("XDG_DATA_HOME")
    base = (Path(xdg) if xdg and os.path.isabs(xdg)
            else Path.home() / ".local" / "share")
    return base / "raptor" / "build-ledger"


def ledger_path(repo: Path | str) -> Path:
    """The PRIMARY per-repo ledger file (keyed by resolved repo path
    hash). Writers and readers use :func:`ledger_paths` — both keys —
    this accessor names the path-key file only."""
    from core.hash import sha256_string
    key = sha256_string(str(Path(repo).resolve()))
    return _ledger_dir() / f"{key}.jsonl"


def ledger_paths(repo: Path | str) -> list[Path]:
    """Every ledger file keyed to *repo*: the resolved-path key plus,
    when the repo root is statable, the ``st_dev:st_ino`` alias key
    (see the module docstring's identity doctrine). Records append to
    ALL of these; consultation merges their union. Order is stable:
    path key first."""
    resolved = Path(repo).resolve()
    paths = [ledger_path(resolved)]
    try:
        st = os.stat(resolved)
    except OSError:
        # Unstatable repo root: the alias identity is unavailable, the
        # path key alone applies (pre-alias behaviour).
        return paths
    from core.hash import sha256_string
    alias = _ledger_dir() / (
        f"{sha256_string(f'dev-ino:{st.st_dev}:{st.st_ino}')}.jsonl")
    if alias != paths[0]:
        paths.append(alias)
    return paths


def _hash_capped(path: Path) -> str | None:
    """sha256 of *path*, or ``None`` when it vanished, is unreadable,
    or exceeds :data:`MAX_HASH_BYTES` (see the cap's rationale)."""
    from core.hash import sha256_file
    try:
        if os.stat(path).st_size > MAX_HASH_BYTES:
            return None
        return sha256_file(path)
    except OSError:
        return None


def snapshot_repo_binaries(repo: Path | str) -> dict[str, str] | None:
    """Hash every binary in auto-detect's candidate universe.

    Returns ``{path: sha256}``; ``None`` when the universe cannot be
    enumerated or exceeds :data:`SNAPSHOT_FILE_CAP` — the caller's
    post-build arm then records a capture-incomplete marker
    (fail-closed). Individual files that vanish mid-walk, refuse the
    read, or exceed the per-file budget are skipped: consultation
    independently flags any candidate it cannot hash, so a skip can
    never launder authority. Never raises.
    """
    try:
        from core.analysis.binary_oracle_autodetect import (
            elf_candidate_paths,
        )
        candidates = elf_candidate_paths(Path(repo))
        if candidates is None:
            return None
        if len(candidates) > SNAPSHOT_FILE_CAP:
            logger.warning(
                "build-ledger: %d binary candidates under %s exceed the "
                "snapshot cap (%d) — build-output capture is incomplete "
                "for this repo", len(candidates), repo, SNAPSHOT_FILE_CAP,
            )
            return None
        out: dict[str, str] = {}
        for p in candidates:
            digest = _hash_capped(p)
            if digest is not None:
                out[str(p)] = digest
        return out
    except Exception:  # noqa: BLE001 — capture must never fail the run
        logger.warning(
            "build-ledger: pre/post build snapshot failed for %s",
            repo, exc_info=True,
        )
        return None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _untracked_pre_carriers(
    repo: Path | str, paths: list[Path],
) -> list[Path]:
    """The subset of *paths* that are git-UNTRACKED in *repo* — the
    only pre-build carriers whose content hashes may be exempted from
    ledger recording.

    Delegates to the binary oracle's provenance filter
    (:func:`core.analysis.binary_oracle_cli._filter_locally_built` —
    the single doctrine source: committed content never earns
    suppression authority, so a repo committing a crafted ELF whose
    build step copies it to an untracked path must not keep authority
    via the pre-build exemption). Shares that filter's conservative
    split: not-a-repo, no git, sandbox refusal, and every other
    failure classify ALL paths as tracked — returning ``[]``, so
    nothing is exempt and everything records (safe over-capture;
    auto-detect withholds authority from those same candidates for the
    same reason). Never raises.
    """
    if not paths:
        return []
    try:
        from core.analysis.binary_oracle_cli import _filter_locally_built
        untracked, _tracked = _filter_locally_built(
            Path(repo), list(paths))
        return untracked
    except Exception:  # noqa: BLE001 — provenance unverifiable reads as nothing-exempt
        logger.warning(
            "build-ledger: pre-build provenance partition failed for "
            "%s — no pre-build exemptions granted", repo, exc_info=True,
        )
        return []


def _exempt_pre_hashes(
    repo: Path | str, pre: dict[str, str] | None,
) -> set[str]:
    """Content hashes exempt from recording because an UNTRACKED
    pre-build carrier already held them. A hash whose only pre-build
    carriers are git-tracked paths stays recordable: the tracked copy
    never had suppression authority, so its content must not inherit
    any by riding through the build to an untracked path."""
    pre_map = pre or {}
    if not pre_map:
        return set()
    untracked = {
        str(p) for p in _untracked_pre_carriers(
            repo, [Path(p) for p in pre_map])
    }
    return {
        digest for p, digest in pre_map.items() if p in untracked
    }


def _append_lines(path: Path, records: list[dict[str, object]]) -> bool:
    """Append *records* as JSONL in one O_APPEND write. 0700 dir /
    0600 file, O_NOFOLLOW — same placement posture as the per-purpose
    key files that share this tree. Returns False (loudly) on any
    failure; the write side has no safe fallback beyond saying so.
    """
    payload = "".join(
        json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n"
        for r in records
    ).encode("utf-8")
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(
            path,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        try:
            view = memoryview(payload)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)
        return True
    except OSError as exc:
        logger.warning(
            "build-ledger: could not record traced-build output for "
            "this repo (%s) — the next run cannot distinguish "
            "build-produced binaries from operator builds", exc,
        )
        return False


def _append_all(
    paths: list[Path], records: list[dict[str, object]],
) -> bool:
    """Append *records* to every key file. No short-circuit: a failed
    append on one key must not skip the other (the union merge at read
    time absorbs a torn pair). True only when all appends landed."""
    results = [_append_lines(p, records) for p in paths]
    return all(results)


def record_build_delta(
    repo: Path | str,
    pre: dict[str, str] | None,
    post: dict[str, str] | None,
) -> int:
    """Append the content DELTA a traced build produced to the ledger.

    *pre* / *post* are :func:`snapshot_repo_binaries` results taken
    around the build. A post-build hash is exempt from recording only
    when an UNTRACKED pre-build carrier already held it
    (:func:`_exempt_pre_hashes`): a pre-build hash carried solely by
    git-tracked paths records anyway, so a repo committing a crafted
    ELF that its build step copies to an untracked path cannot launder
    absent-suppression authority through the pre-build snapshot.
    ``pre is None`` (pre-build inventory failed) over-captures: every
    post-build hash is treated as build-produced — the safe direction,
    remediable by an explicit operator assertion. ``post is None``
    (post-build inventory failed) records a capture-incomplete marker:
    the ledger can no longer vouch for what the build wrote, so
    consultation fail-closes for this repo. Appends dedupe per key
    FILE, so each file stays a self-contained record of the repo's
    build-produced contents even when the other key already carries
    them. Returns the number of distinct NEW build-produced contents
    (a backfill of an already-known hash into a key file that lacked
    it counts zero). Never raises.
    """
    try:
        # Every record lands in BOTH key files (path + dev:ino alias)
        # so consultation from a moved/bind-mounted path still sees
        # it. The two appends are not atomic; a torn pair only makes
        # one file a subset of the other, and the union merge at read
        # time absorbs that.
        paths = ledger_paths(repo)
        with _write_lock:
            if post is None:
                _append_all(paths, [{
                    "v": LEDGER_SCHEMA, "kind": _KIND_INCOMPLETE,
                    "reason": "post-build binary inventory failed or "
                              "exceeded the snapshot cap",
                    "ts": _utc_now(),
                }])
                logger.warning(
                    "build-ledger: post-build inventory unavailable for "
                    "%s — ledger marked capture-incomplete; auto-detected "
                    "binaries lose absent-suppression authority for this "
                    "repo (assert trust with --binary / /project binary "
                    "add)", repo,
                )
                return 0
            # Exemptions are provenance-gated, not mere pre-presence:
            # see _exempt_pre_hashes. Computed by a never-raising
            # helper — a raise here would land in the outer handler
            # and skip recording entirely (fail-open).
            pre_hashes = _exempt_pre_hashes(repo, pre)
            existing = load_build_ledger(repo)
            if existing.status == "unverifiable":
                # Already fail-closed for this repo; appending more
                # entries could not restore verifiability but WOULD
                # grow the file without bound across runs.
                logger.warning(
                    "build-ledger: ledger for %s is unverifiable (%s) — "
                    "traced-build delta not recorded; suppression stays "
                    "withheld for auto-detected binaries",
                    repo, existing.reason,
                )
                return 0
            # Candidate build-produced contents from this run's
            # post-build inventory (deduped within the run; the first
            # carrier path wins the record's path field).
            candidates: dict[str, str] = {}
            for p, digest in sorted(post.items()):
                if digest in pre_hashes:
                    continue
                candidates.setdefault(digest, p)
            new = {d: p for d, p in candidates.items()
                   if d not in existing.hashes}
            if len(existing.hashes) + len(new) > LEDGER_ENTRY_CAP:
                # Dropping entries silently would fail-open (an
                # unrecorded planted binary keeps authority); the
                # overflow marker fail-closes the whole repo instead.
                _append_all(paths, [{
                    "v": LEDGER_SCHEMA, "kind": _KIND_INCOMPLETE,
                    "reason": f"entry cap ({LEDGER_ENTRY_CAP}) exceeded",
                    "ts": _utc_now(),
                }])
                logger.warning(
                    "build-ledger: entry cap (%d) exceeded for %s — "
                    "ledger marked capture-incomplete; auto-detected "
                    "binaries lose absent-suppression authority for "
                    "this repo", LEDGER_ENTRY_CAP, repo,
                )
                return 0
            ts = _utc_now()
            # Dedupe per DESTINATION file, never against the merged
            # union: each key file must stay self-contained. A hash
            # the alias file carries but the path file lacks (repo
            # moved, then deterministically rebuilt) must still land
            # in the path file — deduping against the union would
            # skip it, and a later alias-identity loss (device
            # renumber across reboots, recycled inode) would consult
            # the incomplete path file alone and hand the recorded
            # build-produced binary absent-suppression authority back
            # (fail-open).
            ok = True
            appended = 0
            for path in paths:
                have = _load_ledger_file(path).hashes
                residue = [
                    {"v": LEDGER_SCHEMA, "kind": _KIND_BINARY,
                     "sha256": digest, "path": p, "ts": ts}
                    for digest, p in candidates.items()
                    if digest not in have
                ]
                if not residue:
                    continue
                if _append_lines(path, residue):
                    appended += len(residue)
                else:
                    ok = False
            if not appended or not ok:
                # _append_lines warned loudly on any failure.
                return 0
            if new:
                logger.info(
                    "build-ledger: recorded %d traced-build binary "
                    "content(s) for %s", len(new), repo,
                )
            else:
                logger.info(
                    "build-ledger: backfilled %d ledger record(s) for "
                    "%s into a key file that lacked them (repo "
                    "identity previously split)", appended, repo,
                )
            return len(new)
    except Exception:  # noqa: BLE001 — capture must never fail the run
        logger.warning(
            "build-ledger: recording traced-build output failed for %s",
            repo, exc_info=True,
        )
        return 0


def _unverifiable(reason: str) -> LedgerView:
    return LedgerView(status="unverifiable", reason=reason)


def load_build_ledger(repo: Path | str) -> LedgerView:
    """Load one repo's ledger across BOTH key files (path + dev:ino
    alias), merged: either file unverifiable → ``unverifiable``,
    naming the offending file; otherwise the union of their hashes;
    ``absent`` only when neither file exists. Never raises; every
    failure shape maps to the fail-closed ``unverifiable`` status
    (see :class:`LedgerView`)."""
    try:
        paths = ledger_paths(repo)
    except Exception:  # noqa: BLE001 — resolution failure reads as absence
        # When no home directory resolves (HOME unset and no passwd
        # entry — systemd DynamicUser-style runners), there is no
        # location this install could ever have written a ledger to:
        # that is ledger ABSENCE, not a corrupt ledger. Mapping it to
        # unverifiable would demote every auto-detected binary in
        # environments where capture simply cannot operate. The
        # orchestrator's environment is operator-controlled, so a
        # scanned target cannot steer onto this branch.
        logger.warning(
            "build-ledger: ledger path resolution failed for %s; "
            "treating the ledger as absent (traced-build capture is "
            "inoperative in this environment)", repo, exc_info=True,
        )
        return LedgerView(status="absent")
    hashes: set[str] = set()
    seen_ok = False
    for path in paths:
        view = _load_ledger_file(path)
        if view.status == "unverifiable":
            return _unverifiable(f"{view.reason} [{path}]")
        if view.status == "ok":
            seen_ok = True
            hashes.update(view.hashes)
    if not seen_ok:
        return LedgerView(status="absent")
    return LedgerView(status="ok", hashes=frozenset(hashes))


def _load_ledger_file(path: Path) -> LedgerView:
    """Load ONE key file; same status semantics as
    :func:`load_build_ledger` but unmerged and without naming the
    file in the reason (the caller does)."""
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return LedgerView(status="absent")
    except OSError as exc:
        return _unverifiable(f"open refused ({exc})")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return _unverifiable("not a regular file")
        if st.st_uid != os.geteuid():
            return _unverifiable("foreign owner")
        if stat.S_IMODE(st.st_mode) & 0o022:
            return _unverifiable("group/other-writable")
        if st.st_size > _MAX_LEDGER_BYTES:
            return _unverifiable("oversized ledger file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
    except OSError as exc:
        return _unverifiable(f"read failed ({exc})")
    finally:
        os.close(fd)
    hashes: set[str] = set()
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            return _unverifiable("malformed ledger line")
        if not isinstance(rec, dict) or rec.get("v") != LEDGER_SCHEMA:
            return _unverifiable("unknown ledger record schema")
        kind = rec.get("kind")
        if kind == _KIND_INCOMPLETE:
            reason = rec.get("reason")
            return _unverifiable(
                str(reason) if isinstance(reason, str) and reason
                else "capture-incomplete marker",
            )
        if kind != _KIND_BINARY:
            return _unverifiable("unknown ledger record kind")
        digest = rec.get("sha256")
        if (not isinstance(digest, str) or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)):
            return _unverifiable("malformed sha256 in ledger record")
        hashes.add(digest)
    return LedgerView(status="ok", hashes=frozenset(hashes))


def build_produced_candidates(
    repo: Path | str, candidates: list[Path],
) -> tuple[list[Path], str | None]:
    """Which *candidates* must NOT receive ``absent``-suppression
    authority, per this repo's ledger.

    Returns ``(flagged, reason)``: ``reason`` is ``None`` when flags
    came from individual content-hash matches, else the ledger-level
    cause (unverifiable ledger → every candidate flagged). An absent
    ledger flags nothing (migration window). A candidate that cannot
    be hashed (unreadable, oversized — see :data:`MAX_HASH_BYTES`) is
    flagged as unproven. Never raises.
    """
    if not candidates:
        return [], None
    try:
        view = load_build_ledger(repo)
    except Exception:  # noqa: BLE001 — consultation reads fail-closed
        logger.warning(
            "build-ledger: consultation failed for %s", repo,
            exc_info=True,
        )
        return list(candidates), "ledger consultation failed"
    if view.status == "absent":
        return [], None
    if view.status == "unverifiable":
        return list(candidates), (
            f"build ledger unverifiable ({view.reason})"
        )
    flagged: list[Path] = []
    for p in candidates:
        digest = _hash_capped(p)
        if digest is None or digest in view.hashes:
            flagged.append(p)
    return flagged, None


__all__ = [
    "LEDGER_ENTRY_CAP",
    "LEDGER_SCHEMA",
    "LedgerView",
    "MAX_HASH_BYTES",
    "SNAPSHOT_FILE_CAP",
    "build_produced_candidates",
    "ledger_path",
    "ledger_paths",
    "load_build_ledger",
    "record_build_delta",
    "snapshot_repo_binaries",
]
