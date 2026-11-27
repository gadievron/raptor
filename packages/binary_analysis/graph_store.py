"""SQLite graph memory for black-box binary analysis.

The graph is a private substrate. JSON artefacts remain the public contract,
but the database gives `/understand`, fuzzing, runtime observation and future
validation passes one shared place to query evidence without re-running every
extractor.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import logging
import os
import shutil
import sqlite3
import stat
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Self, TYPE_CHECKING
from urllib.parse import quote

from core.hash import sha256_file
from core.security import mac_key

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

logger = logging.getLogger(__name__)

GRAPH_FILENAME = "binary-graph.sqlite"
SCHEMA_VERSION = 2

# ── Store provenance (sidecar MAC over the db file content) ──────────
#
# Graph stores live under run output dirs — trees that sandboxed
# children and scanned-target build steps can often write. Trusted
# consumers (the binary-oracle edge index, the audit sink-edge bridge)
# steer verdicts off edges read from here, so a planted or rewritten
# sqlite file must not be taken at face value. Writers stamp the store
# at close/finalize time: an HMAC-SHA256 token over the db file's
# content hash, under a per-purpose key
# (``$XDG_DATA_HOME/raptor/graph-store-mac.key`` — never shared with
# any other subsystem's key, core.security.mac_key doctrine; the key
# lives outside every LLM-writable and sandbox-readable tree). A
# verified token proves the store was last finalized by code that
# could read that key file, nothing stronger; key confidentiality is
# the trust anchor.
#
# Failure policy is demote-never-error: no usable key → the store
# stays unstamped and trusted consumers SKIP it with a loud warning
# (edge enrichment is an upgrade, not a right). Display-only readers
# (the graph query CLIs, report rendering) stay unverified.

#: Sidecar filename suffix: ``binary-graph.sqlite.provenance.json``.
PROVENANCE_SUFFIX = ".provenance.json"

_PROVENANCE_KIND = "binary-graph-store"
_PROVENANCE_KEY_LEN = 32

# Sidecars are a three-field JSON object (<1 KiB); the bound keeps a
# planted oversize sidecar from being buffered. Generous headroom so a
# legitimate future field never trips it; verification fails closed
# (skip) above it either way.
_PROVENANCE_MAX_BYTES = 64 * 1024

_warned_key_paths: set[str] = set()


def _provenance_key_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "raptor" / "graph-store-mac.key"


def _warn_once_suspect_key(path: Path, reason: str, remedy: str) -> None:
    key = str(path)
    if key in _warned_key_paths:
        logger.debug(
            "graph-store provenance: suspect key %s (%s)", path, reason)
        return
    _warned_key_paths.add(key)
    logger.warning(
        "graph-store provenance: refusing key %s — %s. Binary graph "
        "stores will not mint or verify provenance (trusted consumers "
        "skip them) until this is fixed: %s",
        path, reason, remedy,
    )


def _read_existing_provenance_key(
    path: Path,
) -> bytes | mac_key.Refused | None:
    return mac_key.read_existing_key(
        path, key_len=_PROVENANCE_KEY_LEN, warn=_warn_once_suspect_key)


def _load_or_create_provenance_key() -> bytes | None:
    return mac_key.load_or_create_key(
        _provenance_key_path(), key_len=_PROVENANCE_KEY_LEN,
        warn=_warn_once_suspect_key,
        read_existing=_read_existing_provenance_key,
        recreate_hint="a fresh key is created on the next store stamp")


def provenance_key_usable() -> bool:
    """Whether this install can mint/verify graph-store tokens at all."""
    try:
        return bool(_load_or_create_provenance_key())
    except OSError:
        return False


def _provenance_canonical(fields: Mapping[str, object]) -> bytes:
    """Injective canonical encoding — key-sorted, length-prefixed —
    identical construction to witness/outcome-trail provenance's."""
    items = sorted((str(k), str(v)) for k, v in fields.items())
    out = bytearray()
    out += len(items).to_bytes(4, "big")
    for key, value in items:
        for part in (key.encode("utf-8"), value.encode("utf-8")):
            out += len(part).to_bytes(4, "big")
            out += part
    return bytes(out)


def _provenance_mint(fields: Mapping[str, object]) -> str | None:
    try:
        key = _load_or_create_provenance_key()
    except OSError:
        return None
    if not key:
        return None
    return hmac.new(
        key, _provenance_canonical(fields), hashlib.sha256).hexdigest()


def _provenance_verify(fields: Mapping[str, object], token: object) -> bool:
    if not token or not isinstance(token, str):
        return False
    try:
        expected = _provenance_mint(fields)
        if expected is None:
            return False
        return hmac.compare_digest(expected, token.strip().lower())
    except Exception:  # noqa: BLE001 — verification failure is the skip path, never an error
        return False


def provenance_path_for(path: Path) -> Path:
    """The provenance sidecar path for a graph store db file."""
    path = Path(path)
    return path.with_name(path.name + PROVENANCE_SUFFIX)


def _db_content_sha256(path: Path) -> str | None:
    """Streamed content hash of the db file, None when unreadable."""
    try:
        return sha256_file(Path(path))
    except OSError:
        return None


def _pending_journal(path: Path) -> bool:
    """Whether uncheckpointed journal content rides NEXT TO the db
    file. The content hash covers the db file alone, so a non-empty
    ``-wal``/``-journal`` sibling changes the store's EFFECTIVE
    content without changing the hash — a planted journal would be
    folded into the db by the next (trusted, unsandboxed) open. Such a
    store is unverified; a clean writer close checkpoints the WAL
    away, so legitimate finalized stores do not carry one."""
    path = Path(path)
    for suffix in ("-wal", "-journal"):
        sibling = path.with_name(path.name + suffix)
        try:
            if sibling.stat().st_size > 0:
                return True
        except OSError:
            continue
    return False


def _provenance_fields(db_sha256: str) -> dict[str, str]:
    return {"kind": _PROVENANCE_KIND, "db_sha256": db_sha256}


def stamp_graph_store(path: Path) -> None:
    """Stamp a graph store the caller has just finished writing.

    Called at every writer close/finalize seam
    (:meth:`BinaryGraphStore.close`, :func:`graph_connection` exit) —
    legitimate mutate-then-close cycles re-stamp. Best-effort and
    demote-never-error: an unreadable db, a pending journal (another
    connection still open — ITS close re-stamps), or no usable key
    leaves the store unstamped, and trusted consumers skip it.
    """
    path = Path(path)
    if not path.is_file():
        return
    if _pending_journal(path):
        return
    digest = _db_content_sha256(path)
    if not digest:
        return
    token = _provenance_mint(_provenance_fields(digest))
    if not token:
        return
    payload = {
        "kind": _PROVENANCE_KIND,
        "db_sha256": digest,
        "token": token,
    }
    try:
        from core.json.utils import save_json
        save_json(provenance_path_for(path), payload)
    except OSError:
        logger.debug(
            "graph-store provenance: sidecar write failed for %s",
            path, exc_info=True)


def _load_provenance_sidecar(path: Path) -> tuple[str, str] | None:
    """The (recorded db hash, token) pair from the store's sidecar,
    None when absent or malformed — the caller's skip path."""
    sidecar = provenance_path_for(path)
    if not sidecar.is_file():
        return None
    try:
        from core.json.utils import load_json
        payload = load_json(
            sidecar, strict=True, max_bytes=_PROVENANCE_MAX_BYTES)
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    recorded = payload.get("db_sha256")
    token = payload.get("token")
    if not isinstance(recorded, str) or not isinstance(token, str):
        return None
    return recorded, token


def verify_graph_store(path: Path) -> bool:
    """Whether the store at *path* carries a valid provenance stamp
    over its CURRENT content (and no uncheckpointed journal rides next
    to it). False for unstamped (legacy / foreign / planted) stores
    and on any verification failure — the caller's skip path, never an
    error.

    This is a point-in-time PREDICATE over the path: nothing stops the
    file from being swapped after it returns. Consumers that go on to
    READ edges and steer verdicts must use
    :func:`open_verified_graph_store` instead, which verifies and
    queries one private snapshot copy with no verify/open window."""
    path = Path(path)
    if not path.is_file():
        return False
    if _pending_journal(path):
        return False
    loaded = _load_provenance_sidecar(path)
    if loaded is None:
        return False
    recorded, token = loaded
    digest = _db_content_sha256(path)
    # The recorded hash must match the db's CURRENT content — the
    # token authenticates the recorded hash, the comparison binds it
    # to the bytes actually on disk.
    if not digest or recorded != digest:
        return False
    return _provenance_verify(_provenance_fields(digest), token)


# ── Verified snapshot open (TOCTOU-free consumer path) ───────────────
#
# verify_graph_store() hashes the file AT ITS PATH and then returns;
# any consumer that re-opens the same path afterwards races every
# other writer of the run dir — a sandboxed build child or planted
# artifact can swap the db (or drop a -wal sibling that a writable
# open would fold in) between the verify and the open. The fix is to
# never read the path twice: copy the db ONCE into a private 0700
# mkdtemp, hashing the same bytes being copied, verify the MAC over
# that hash, and serve every query from the copy via an
# ``immutable=1`` sqlite open (no locking, no journal consultation —
# a planted -wal/-shm next to the SOURCE is never copied and never
# consulted; a hash-matching db was stamped journal-free, so sibling
# journal files next to it can only be planted or stale and are
# correctly ignored rather than refused).

#: Scratch dir prefix for snapshot copies — registered in
#: core.run.tmp_reaper._DIR_PREFIXES so crashed runs' copies are
#: reaped (the census test there fails on unregistered prefixes).
_SNAPSHOT_DIR_PREFIX = "raptor-graph-verify-"

# Snapshot copy bound. Too low and legitimately large graph stores
# (hundreds of thousands of nodes/edges for big binaries reach tens
# of MB) silently lose edge enrichment; too high and a planted
# oversize file makes the trusted process copy+hash attacker-sized
# bytes before the MAC check can refuse them. Verified real-world
# stores sit well under 1 GiB; raise only with evidence of a
# legitimate store above the bound.
_SNAPSHOT_MAX_DB_BYTES = 1 << 30

_SNAPSHOT_COPY_CHUNK = 1 << 20


def _snapshot_copy_db(path: Path, dest: Path) -> str | None:
    """Copy the db file at *path* to *dest*, returning the sha256 of
    the bytes ACTUALLY COPIED (the hash the caller must verify — never
    re-hash the source). None on any refusal: symlink, non-regular
    file, over-bound size, or I/O failure."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None
        if info.st_size > _SNAPSHOT_MAX_DB_BYTES:
            return None
        hasher = hashlib.sha256()
        total = 0
        with dest.open("wb") as out:
            while True:
                chunk = os.read(fd, _SNAPSHOT_COPY_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                # Re-enforced cumulatively: the file can grow after
                # the fstat above while we read it.
                if total > _SNAPSHOT_MAX_DB_BYTES:
                    return None
                hasher.update(chunk)
                out.write(chunk)
        return hasher.hexdigest()
    except OSError:
        return None
    finally:
        os.close(fd)


def _open_snapshot_connection(copy_path: Path) -> sqlite3.Connection | None:
    """Immutable read connection over the verified private copy.
    ``immutable=1`` disables locking and journal lookups entirely —
    correct here because the copy lives in our own 0700 scratch dir
    and nothing else may write it."""
    try:
        conn = sqlite3.connect(
            f"file:{quote(str(copy_path))}?immutable=1", uri=True)
    except sqlite3.Error:
        return None
    try:
        conn.row_factory = sqlite3.Row
        current = int(conn.execute("PRAGMA user_version").fetchone()[0])
    except sqlite3.Error:
        with contextlib.suppress(sqlite3.Error):
            conn.close()
        return None
    if current > SCHEMA_VERSION:
        # Newer-schema stores are skipped like unverified ones: the
        # consumer degrades to fresh extraction, never errors.
        with contextlib.suppress(sqlite3.Error):
            conn.close()
        return None
    return conn


class VerifiedGraphSnapshot:
    """Query handle over a verified PRIVATE COPY of a graph store.

    Only ever constructed by :func:`open_verified_graph_store`; every
    query method reads the copy, so post-verification changes to the
    original path cannot reach consumers."""

    def __init__(self, source_path: Path, conn: sqlite3.Connection) -> None:
        self.source_path = Path(source_path)
        self._conn = conn

    def summary(self) -> dict[str, Any]:
        """:func:`graph_summary` over the verified copy."""
        return _summary_from_connection(self._conn, self.source_path)

    def edges(self, *, kind: str | None = None) -> list[dict[str, Any]]:
        """:func:`query_edges` over the verified copy."""
        return _edges_from_connection(self._conn, kind=kind)


@contextmanager
def open_verified_graph_store(
    path: Path,
) -> Iterator[VerifiedGraphSnapshot | None]:
    """Verify and open the graph store at *path* with no verify/open
    window: snapshot-copy, hash the copy, MAC-verify that hash, and
    serve queries from the copy only.

    Yields None when the store cannot be verified (unstamped, tampered,
    oversize, unreadable, newer schema) — the caller's skip path, never
    an error. The REQUIRED path for every consumer whose reads steer
    verdicts; see the module comment above ``_SNAPSHOT_DIR_PREFIX``.
    """
    path = Path(path)
    tmpdir: str | None = None
    conn: sqlite3.Connection | None = None
    try:
        try:
            loaded = _load_provenance_sidecar(path)
            if loaded is not None:
                recorded, token = loaded
                tmpdir = tempfile.mkdtemp(prefix=_SNAPSHOT_DIR_PREFIX)
                copy_path = Path(tmpdir) / GRAPH_FILENAME
                digest = _snapshot_copy_db(path, copy_path)
                if (
                    digest is not None
                    and digest == recorded
                    and _provenance_verify(
                        _provenance_fields(digest), token)
                ):
                    conn = _open_snapshot_connection(copy_path)
        except OSError:
            logger.debug(
                "graph-store snapshot: open failed for %s",
                path, exc_info=True)
            conn = None
        yield VerifiedGraphSnapshot(path, conn) if conn is not None else None
    finally:
        if conn is not None:
            with contextlib.suppress(sqlite3.Error):
                conn.close()
        if tmpdir is not None:
            shutil.rmtree(tmpdir, ignore_errors=True)


def _json(value: Any) -> str:
    return json.dumps(value if value is not None else {}, sort_keys=True, separators=(",", ":"), default=str)


def _hash(*parts: Any, length: int = 20) -> str:
    data = "::".join(str(part) for part in parts).encode("utf-8", "surrogateescape")
    return hashlib.sha256(data).hexdigest()[:length]


def stable_node_id(binary_sha256: str, kind: str, key: str) -> str:
    return f"node:{kind}:{_hash(binary_sha256, kind, key)}"


def stable_edge_id(binary_sha256: str, kind: str, src_id: str, dst_id: str) -> str:
    return f"edge:{kind}:{_hash(binary_sha256, kind, src_id, dst_id)}"


def graph_path_for_run(run_dir: Path) -> Path:
    return Path(run_dir) / "graph" / GRAPH_FILENAME


def open_graph(path: Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        # Switching journal mode needs a moment of exclusivity, and
        # SQLite can report busy here WITHOUT consulting the busy
        # handler while a concurrent open's migration (or an ingest
        # batch) holds the write lock — a raced open of a fresh store
        # failed outright on this pragma. Bounded retry; on sustained
        # contention keep the inherited mode (WAL is a performance
        # preference, not a correctness gate — the store's creator
        # sets it durably).
        for attempt in range(50):
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                break
            except sqlite3.OperationalError:
                if attempt == 49:
                    logger.warning(
                        "binary graph %s: journal_mode=WAL contended; "
                        "keeping inherited mode", path)
                    break
                time.sleep(0.02)
        conn.execute("PRAGMA synchronous=NORMAL")
        _migrate(conn)
    except BaseException:
        try:
            conn.close()
        except BaseException:
            pass  # Retain the setup refusal after attempting connection cleanup.
        raise
    return conn


def open_graph_readonly(path: Path) -> sqlite3.Connection:
    """Open an EXISTING store for queries without write ability.

    Query lanes must not be able to mutate the store — or its directory
    — they are pointed at: the writable open above creates the parent
    dir, switches the journal mode, and runs (version-stamping)
    migration, all WRITES. When the queried path comes from discovery
    over less-trusted trees, those writes would land in a directory an
    adversary chose. ``mode=ro`` makes sqlite refuse every write at
    open scope rather than by caller discipline; there is no mkdir, no
    journal-mode switch and no migration here. The newer-schema refusal
    is kept (a pure PRAGMA read). Older stores stay readable: the only
    historical upgrade (v1→v2) rebuilt auxiliary-table constraints and
    changed none of the queried tables or columns.
    """
    path = Path(path)
    try:
        conn = sqlite3.connect(f"file:{quote(str(path))}?mode=ro", uri=True)
    except sqlite3.OperationalError as exc:
        # The one way a read-only open loses to a plain writable
        # connect: a WAL store whose writer died before checkpointing,
        # sitting in an unwritable directory — sqlite needs to create
        # the -shm / recover the -wal and mode=ro forbids both. Name
        # the recovery path instead of a bare "unable to open".
        if path.with_name(path.name + "-wal").exists():
            msg = (f"cannot open {path} read-only: a write-ahead log "
                   f"({path.name}-wal) is pending recovery. Open the "
                   "store writable once to checkpoint it, or copy the "
                   "db and -wal files to writable storage first")
            raise RuntimeError(msg) from exc
        raise
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        current = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if current > SCHEMA_VERSION:
            msg = (f"binary graph schema version {current} is newer "
                   f"than this RAPTOR ({SCHEMA_VERSION})")
            raise RuntimeError(msg)
    except BaseException:
        try:
            conn.close()
        except BaseException:
            pass  # Retain the setup refusal after attempting connection cleanup.
        raise
    return conn


@contextmanager
def graph_read_connection(path: Path) -> Iterator[sqlite3.Connection]:
    conn = open_graph_readonly(path)
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def graph_connection(path: Path) -> Iterator[sqlite3.Connection]:
    conn = open_graph(path)
    failed = True
    try:
        yield conn
        conn.commit()
        failed = False
    except Exception:
        conn.rollback()
        raise
    finally:
        try:
            conn.close()
        except BaseException:
            if not failed:
                raise
        else:
            # Writer finalize seam: even a rolled-back cycle may have
            # changed on-disk bytes (migration, WAL checkpoint), so
            # re-stamp over whatever content the close left behind.
            stamp_graph_store(Path(path))


def _migrate(conn: sqlite3.Connection) -> None:
    current = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if current > SCHEMA_VERSION:
        msg = f"binary graph schema version {current} is newer than this RAPTOR ({SCHEMA_VERSION})"
        raise RuntimeError(msg)
    if current == SCHEMA_VERSION:
        # Up to date — nothing to stamp. Re-stamping here committed a
        # WRITE on every open, so every pure read lane (graph_summary,
        # query_edges, /binary report) contended as a writer against
        # in-flight ingest batches (busy_timeout, then "database is
        # locked").
        return
    if current == 0:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                id TEXT PRIMARY KEY,
                binary_sha256 TEXT NOT NULL,
                binary_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                producer_run TEXT NOT NULL,
                props_json TEXT NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS nodes (
                snapshot_id TEXT NOT NULL,
                id TEXT NOT NULL,
                kind TEXT NOT NULL,
                stable_key TEXT NOT NULL,
                name TEXT NOT NULL DEFAULT '',
                address TEXT NOT NULL DEFAULT '',
                props_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY(snapshot_id, id),
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS edges (
                snapshot_id TEXT NOT NULL,
                id TEXT NOT NULL,
                kind TEXT NOT NULL,
                src_id TEXT NOT NULL,
                dst_id TEXT NOT NULL,
                confidence TEXT NOT NULL DEFAULT '',
                props_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY(snapshot_id, id),
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS evidence (
                snapshot_id TEXT NOT NULL,
                id TEXT NOT NULL,
                kind TEXT NOT NULL,
                tier TEXT NOT NULL,
                confidence TEXT NOT NULL,
                reproducible INTEGER NOT NULL,
                source TEXT NOT NULL,
                tool TEXT NOT NULL,
                summary TEXT NOT NULL,
                props_json TEXT NOT NULL DEFAULT '{}',
                PRIMARY KEY(snapshot_id, id),
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS node_evidence (
                snapshot_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                PRIMARY KEY(snapshot_id, node_id, evidence_id),
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS edge_evidence (
                snapshot_id TEXT NOT NULL,
                edge_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                PRIMARY KEY(snapshot_id, edge_id, evidence_id),
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS artifacts (
                snapshot_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL DEFAULT '',
                PRIMARY KEY(snapshot_id, kind, path),
                FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_binary_nodes_kind ON nodes(snapshot_id, kind);
            CREATE INDEX IF NOT EXISTS idx_binary_edges_kind ON edges(snapshot_id, kind);
            CREATE INDEX IF NOT EXISTS idx_binary_evidence_tier ON evidence(snapshot_id, tier);
            """
        )
    elif current == 1:
        try:
            _upgrade_v1_to_v2(conn)
        except sqlite3.OperationalError:
            # Two processes raced the upgrade: the loser blocked on the
            # winner's BEGIN IMMEDIATE, then failed mid-script against
            # the already-rebuilt tables. Losing the race means someone
            # else migrated — verify and carry on.
            with contextlib.suppress(sqlite3.OperationalError):
                conn.rollback()
            now = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if now != SCHEMA_VERSION:
                raise
            return
    conn.execute(f"PRAGMA user_version={int(SCHEMA_VERSION)}")
    conn.execute(
        "INSERT OR REPLACE INTO metadata(key, value) VALUES (?, ?)",
        ("schema_version", str(SCHEMA_VERSION)),
    )


def _upgrade_v1_to_v2(conn: sqlite3.Connection) -> None:
    """v1 omitted the snapshot FK on node_evidence/edge_evidence/artifacts,
    so a snapshot REPLACE cascaded nodes/edges/evidence but orphaned these
    rows. SQLite cannot add a FK in place; rebuild each table and drop rows
    already orphaned.

    BEGIN IMMEDIATE takes the write lock up front so two processes
    racing the upgrade cannot interleave the rebuild; the version
    stamp commits atomically with it. The loser blocks on the lock
    (busy_timeout), then fails against the already-rebuilt tables —
    _migrate treats that as "someone else migrated" after re-reading
    user_version."""
    conn.executescript(
        """
        BEGIN IMMEDIATE;
        ALTER TABLE node_evidence RENAME TO node_evidence_v1;
        CREATE TABLE node_evidence (
            snapshot_id TEXT NOT NULL,
            node_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            PRIMARY KEY(snapshot_id, node_id, evidence_id),
            FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
        );
        INSERT INTO node_evidence(snapshot_id, node_id, evidence_id)
            SELECT snapshot_id, node_id, evidence_id FROM node_evidence_v1
            WHERE snapshot_id IN (SELECT id FROM snapshots);
        DROP TABLE node_evidence_v1;

        ALTER TABLE edge_evidence RENAME TO edge_evidence_v1;
        CREATE TABLE edge_evidence (
            snapshot_id TEXT NOT NULL,
            edge_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            PRIMARY KEY(snapshot_id, edge_id, evidence_id),
            FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
        );
        INSERT INTO edge_evidence(snapshot_id, edge_id, evidence_id)
            SELECT snapshot_id, edge_id, evidence_id FROM edge_evidence_v1
            WHERE snapshot_id IN (SELECT id FROM snapshots);
        DROP TABLE edge_evidence_v1;

        ALTER TABLE artifacts RENAME TO artifacts_v1;
        CREATE TABLE artifacts (
            snapshot_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            path TEXT NOT NULL,
            sha256 TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(snapshot_id, kind, path),
            FOREIGN KEY(snapshot_id) REFERENCES snapshots(id) ON DELETE CASCADE
        );
        INSERT INTO artifacts(snapshot_id, kind, path, sha256)
            SELECT snapshot_id, kind, path, sha256 FROM artifacts_v1
            WHERE snapshot_id IN (SELECT id FROM snapshots);
        DROP TABLE artifacts_v1;
        PRAGMA user_version=2;
        COMMIT;
        """
    )


class BinaryGraphStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._conn: sqlite3.Connection | None = None
        self._batch_depth: int = 0

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = open_graph(self.path)
        return self._conn

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        conn = self._get_conn()
        if self._batch_depth > 0:
            yield conn
            return
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    @contextmanager
    def batch(self) -> Iterator[BinaryGraphStore]:
        """Batch multiple operations into a single transaction.

        Defers per-operation commits until the batch exits, reducing
        overhead when ingesting many nodes/edges."""
        conn = self._get_conn()
        self._batch_depth += 1
        try:
            yield self
            if self._batch_depth == 1:
                conn.commit()
        except Exception:
            if self._batch_depth == 1:
                conn.rollback()
            raise
        finally:
            self._batch_depth -= 1

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
            # Writer finalize seam: every ingest producer routes
            # through this close (context-managed), so the store's
            # provenance stamp follows its final content. Guarded —
            # __del__ may run this during interpreter teardown, where
            # module globals are unreliable, and a stamp failure must
            # never mask the close.
            try:
                stamp_graph_store(self.path)
            except Exception:  # noqa: BLE001 — best-effort stamp; readers skip an unstamped store
                logger.debug(
                    "graph-store provenance: stamp failed for %s",
                    self.path, exc_info=True)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:  # noqa: BLE001, S110 — broad by design: __del__ may run during interpreter teardown, where object state and module globals are unreliable; a raise here only spams stderr
            pass

    def begin_snapshot(self, binary_sha256: str, binary_path: str, run_dir: Path, props: dict[str, Any] | None = None) -> str:
        snapshot_id = f"snap:{_hash(binary_sha256, str(Path(run_dir).resolve()))}"
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO snapshots
                (id, binary_sha256, binary_path, created_at, producer_run, props_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    binary_sha256,
                    binary_path,
                    datetime.now(timezone.utc).isoformat(),
                    str(Path(run_dir).resolve()),
                    _json(props or {}),
                ),
            )
        return snapshot_id

    def latest_snapshot_id(self) -> str | None:
        if not self.path.exists():
            return None
        with self._connection() as conn:
            # rowid tie-break: created_at is an ISO string, and two
            # snapshots minted in the same instant otherwise pick an
            # arbitrary winner — insertion order is the honest tie.
            row = conn.execute(
                "SELECT id FROM snapshots "
                "ORDER BY created_at DESC, rowid DESC LIMIT 1"
            ).fetchone()
            return str(row["id"]) if row else None

    def add_evidence(self, snapshot_id: str, record: Any) -> None:
        data = record.to_dict() if hasattr(record, "to_dict") else dict(record)
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO evidence
                (snapshot_id, id, kind, tier, confidence, reproducible, source, tool, summary, props_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    data["id"],
                    data["kind"],
                    data["tier"],
                    data["confidence"],
                    1 if data.get("reproducible") else 0,
                    data["source"],
                    data["tool"],
                    data["summary"],
                    _json(data),
                ),
            )

    def add_node(
        self,
        snapshot_id: str,
        binary_sha256: str,
        kind: str,
        key: str,
        *,
        name: str = "",
        address: str = "",
        props: dict[str, Any] | None = None,
        evidence_ids: list[str] | None = None,
    ) -> str:
        node_id = stable_node_id(binary_sha256, kind, key)
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO nodes
                (snapshot_id, id, kind, stable_key, name, address, props_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (snapshot_id, node_id, kind, key, name, address, _json(props or {})),
            )
            for evidence_id in evidence_ids or []:
                conn.execute(
                    "INSERT OR IGNORE INTO node_evidence(snapshot_id, node_id, evidence_id) VALUES (?, ?, ?)",
                    (snapshot_id, node_id, evidence_id),
                )
        return node_id

    def add_node_if_absent(
        self,
        snapshot_id: str,
        binary_sha256: str,
        kind: str,
        key: str,
        *,
        name: str = "",
        address: str = "",
        props: dict[str, Any] | None = None,
        evidence_ids: list[str] | None = None,
    ) -> str:
        """``add_node`` without the REPLACE: an existing
        (snapshot, id) row keeps its props.

        For enrichment producers attaching records to ANOTHER
        producer's snapshot — the hunt referencing the map's function
        nodes must not wipe the map's props_json (add_node's INSERT OR
        REPLACE would). Evidence links still attach either way.
        """
        node_id = stable_node_id(binary_sha256, kind, key)
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO nodes
                (snapshot_id, id, kind, stable_key, name, address, props_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (snapshot_id, node_id, kind, key, name, address, _json(props or {})),
            )
            for evidence_id in evidence_ids or []:
                conn.execute(
                    "INSERT OR IGNORE INTO node_evidence(snapshot_id, node_id, evidence_id) VALUES (?, ?, ?)",
                    (snapshot_id, node_id, evidence_id),
                )
        return node_id

    def add_edge(
        self,
        snapshot_id: str,
        binary_sha256: str,
        kind: str,
        src_id: str,
        dst_id: str,
        *,
        confidence: str = "",
        props: dict[str, Any] | None = None,
        evidence_ids: list[str] | None = None,
    ) -> str:
        edge_id = stable_edge_id(binary_sha256, kind, src_id, dst_id)
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO edges
                (snapshot_id, id, kind, src_id, dst_id, confidence, props_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (snapshot_id, edge_id, kind, src_id, dst_id, confidence, _json(props or {})),
            )
            for evidence_id in evidence_ids or []:
                conn.execute(
                    "INSERT OR IGNORE INTO edge_evidence(snapshot_id, edge_id, evidence_id) VALUES (?, ?, ?)",
                    (snapshot_id, edge_id, evidence_id),
                )
        return edge_id

    def add_artifact(self, snapshot_id: str, kind: str, path: Path) -> None:
        # Streamed hash chokepoint — never read_bytes() a whole
        # artifact (decompilation corpora reach hundreds of MB).
        try:
            digest = sha256_file(Path(path))
        except OSError:
            digest = ""
        with self._connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO artifacts(snapshot_id, kind, path, sha256) VALUES (?, ?, ?, ?)",
                (snapshot_id, kind, str(Path(path).resolve()), digest),
            )


def _summary_from_connection(
    conn: sqlite3.Connection, path: Path,
) -> dict[str, Any]:
    latest = conn.execute("SELECT * FROM snapshots ORDER BY created_at DESC LIMIT 1").fetchone()
    if latest is None:
        return {"exists": True, "path": str(path), "nodes": {}, "edges": {}, "evidence": {}}
    snapshot_id = latest["id"]
    nodes = {
        row["kind"]: row["count"]
        for row in conn.execute(
            "SELECT kind, COUNT(*) AS count FROM nodes WHERE snapshot_id=? GROUP BY kind",
            (snapshot_id,),
        )
    }
    edges = {
        row["kind"]: row["count"]
        for row in conn.execute(
            "SELECT kind, COUNT(*) AS count FROM edges WHERE snapshot_id=? GROUP BY kind",
            (snapshot_id,),
        )
    }
    evidence = {
        row["tier"]: row["count"]
        for row in conn.execute(
            "SELECT tier, COUNT(*) AS count FROM evidence WHERE snapshot_id=? GROUP BY tier",
            (snapshot_id,),
        )
    }
    return {
        "exists": True,
        "path": str(path),
        "latest_snapshot": dict(latest),
        "nodes": nodes,
        "edges": edges,
        "evidence": evidence,
    }


def graph_summary(path: Path) -> dict[str, Any]:
    if not Path(path).exists():
        return {"exists": False, "path": str(path)}
    with graph_read_connection(path) as conn:
        return _summary_from_connection(conn, Path(path))


def _edges_from_connection(
    conn: sqlite3.Connection, *, kind: str | None = None,
) -> list[dict[str, Any]]:
    latest = conn.execute("SELECT id FROM snapshots ORDER BY created_at DESC LIMIT 1").fetchone()
    if latest is None:
        return []
    params: list[Any] = [latest["id"]]
    where = "WHERE e.snapshot_id=?"
    if kind:
        where += " AND e.kind=?"
        params.append(kind)
    rows = conn.execute(
        f"""
        SELECT e.*, s.name AS src_name, s.kind AS src_kind,
               d.name AS dst_name, d.kind AS dst_kind
        FROM edges e
        JOIN nodes s ON s.snapshot_id=e.snapshot_id AND s.id=e.src_id
        JOIN nodes d ON d.snapshot_id=e.snapshot_id AND d.id=e.dst_id
        {where}
        ORDER BY e.kind, s.name, d.name
        """,
        tuple(params),
    ).fetchall()
    return [
        {
            "id": row["id"],
            "kind": row["kind"],
            "source": {"id": row["src_id"], "kind": row["src_kind"], "name": row["src_name"]},
            "target": {"id": row["dst_id"], "kind": row["dst_kind"], "name": row["dst_name"]},
            "confidence": row["confidence"],
            "props": json.loads(row["props_json"] or "{}"),
        }
        for row in rows
    ]


def query_edges(path: Path, *, kind: str | None = None) -> list[dict[str, Any]]:
    if not Path(path).exists():
        return []
    with graph_read_connection(path) as conn:
        return _edges_from_connection(conn, kind=kind)


def query_evidence(path: Path, *, tier: str | None = None) -> list[dict[str, Any]]:
    if not Path(path).exists():
        return []
    with graph_read_connection(path) as conn:
        latest = conn.execute("SELECT id FROM snapshots ORDER BY created_at DESC LIMIT 1").fetchone()
        if latest is None:
            return []
        params: list[Any] = [latest["id"]]
        where = "WHERE snapshot_id=?"
        if tier:
            where += " AND tier=?"
            params.append(tier)
        rows = conn.execute(
            f"""
            SELECT id, kind, tier, confidence, reproducible, source, tool, summary, props_json
            FROM evidence
            {where}
            ORDER BY tier, kind, id
            """,
            tuple(params),
        ).fetchall()
        return [
            {
                "id": row["id"],
                "kind": row["kind"],
                "tier": row["tier"],
                "confidence": row["confidence"],
                "reproducible": bool(row["reproducible"]),
                "source": row["source"],
                "tool": row["tool"],
                "summary": row["summary"],
                "props": json.loads(row["props_json"] or "{}"),
            }
            for row in rows
        ]


__all__ = [
    "GRAPH_FILENAME",
    "PROVENANCE_SUFFIX",
    "BinaryGraphStore",
    "VerifiedGraphSnapshot",
    "graph_path_for_run",
    "graph_read_connection",
    "graph_summary",
    "open_graph",
    "open_graph_readonly",
    "open_verified_graph_store",
    "provenance_key_usable",
    "provenance_path_for",
    "query_edges",
    "query_evidence",
    "stable_edge_id",
    "stable_node_id",
    "stamp_graph_store",
    "verify_graph_store",
]
