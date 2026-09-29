"""CodeQL database provisioning for standalone /audit runs.

Standalone ``/audit`` historically took ``--codeql-db`` verbatim and
did nothing else — no discovery, no building — so runs without the
flag carried ``codeql_db_path: null`` and the CodeQL channel skipped
every hypothesis, silently. This module closes that gap in priority
order:

1. **Discover** databases the shared content-addressed cache already
   holds for this exact tree (``DatabaseManager.get_cached_database``
   keys on git commit + dirty-tree digest, so staleness is handled by
   construction; ``/codeql`` and ``/agentic`` populate the same
   cache).
2. **Build** missing databases in a background thread overlapping the
   audit's prep stages — but only for languages whose extraction runs
   no target build commands (extractor-only languages, and the
   buildless ``--build-mode=none`` compiled languages the CLI
   supports). Languages whose extraction would execute repo build
   logic (CodeQL autobuild) build only under the operator's ``build``
   trust marker / traced-build consent.
3. **Degrade loudly** otherwise: every language left without a
   database is recorded with the flag or marker that would provide
   one, written to ``codeql-provision.json`` and surfaced in the
   report — the channel must never again skip without saying so.

An explicit ``--codeql-db`` suppresses provisioning entirely (the
operator's declaration wins), and the ``codeql_enabled`` tuning
kill-switch is honoured.
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from core.json import load_json, save_json

logger = logging.getLogger(__name__)

STATUS_FILENAME = "codeql-provision.json"
_MAX_STATUS_BYTES = 1024 * 1024

# How long the orchestrator's prep stage waits for the background DB
# build before continuing without it. Too short and every first run
# on a mid-sized target pays the build without ever using the result
# (it lands in the shared cache for the NEXT run, but this run's
# channel stays down); too long and one slow extraction stalls the
# whole review loop behind prep. The build itself stays bounded by
# the database manager's own timeouts either way, and an abandoned
# build keeps running to completion so the cache still gains the
# database for subsequent runs (unless the process exits first — see
# the daemon-thread note at the build site).
BUILD_AWAIT_S = 900

# Await poll interval: short enough that SIGTERM and the environment
# guard interrupt the join within a couple of seconds (the salvage
# path must not sit behind a blocking multi-minute result() call),
# long enough not to spin.
_AWAIT_POLL_S = 2.0

# Wall-budget margin kept clear of the run deadline when clamping the
# await: the post-await stages (pre-sweep, review, salvage) need room
# to conclude gracefully inside a supervisor bound.
_AWAIT_DEADLINE_MARGIN_S = 60.0


@dataclass
class CodeqlSkip:
    """A language provisioning refused to build, with its remedy."""

    language: str
    reason: str
    remedy: str

    def to_dict(self) -> dict[str, str]:
        return {
            "language": self.language,
            "reason": self.reason,
            "remedy": self.remedy,
        }


@dataclass
class CodeqlProvision:
    """Outcome of run-start database provisioning."""

    db_paths: list[str] = field(default_factory=list)
    building_languages: list[str] = field(default_factory=list)
    build_future: Future | None = None
    skipped: list[CodeqlSkip] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "discovered": list(self.db_paths),
            "building": list(self.building_languages),
            "skipped": [s.to_dict() for s in self.skipped],
        }

    def write_status(self, out_dir: Path) -> None:
        """Persist the provisioning outcome (best-effort)."""
        try:
            save_json(Path(out_dir) / STATUS_FILENAME, self.to_dict())
        except Exception:  # noqa: BLE001 — status is telemetry, never fatal
            logger.debug("codeql provision status write failed", exc_info=True)


def load_provision_status(out_dir: Path) -> dict[str, Any] | None:
    """Read ``codeql-provision.json`` from a run directory."""
    path = Path(out_dir) / STATUS_FILENAME
    if not path.is_file():
        return None
    data = load_json(path, max_bytes=_MAX_STATUS_BYTES)
    return data if isinstance(data, dict) else None


def _update_status(out_dir: Path | None, **fields: Any) -> None:
    if out_dir is None:
        return
    try:
        data = load_provision_status(out_dir) or {}
        data.update(fields)
        save_json(Path(out_dir) / STATUS_FILENAME, data)
    except Exception:  # noqa: BLE001
        logger.debug("codeql provision status update failed", exc_info=True)


def discover_codeql_dbs(target_path: Path) -> list[str]:
    """Discovery-only probe of the shared cache (no builds, no trust).

    Used by resume to cheaply re-fill databases for the same tree:
    the cache key (commit + dirty-tree digest) carries the freshness
    check, so a hit here is valid for the tree as it stands now.
    Best-effort — errors return an empty list.
    """
    try:
        from core.config import RaptorConfig
        if not RaptorConfig.CODEQL_ENABLED:
            return []
        from packages.codeql.database_manager import DatabaseManager
        from packages.codeql.language_detector import LanguageDetector

        manager = DatabaseManager()
        detector = LanguageDetector(Path(target_path))
        detected = detector.filter_codeql_supported(
            detector.detect_languages(),
        )
        found: list[str] = []
        for language in sorted(detected):
            cached = manager.get_cached_database(
                Path(target_path), language,
            )
            if cached is not None:
                found.append(str(cached))
        return found
    except Exception:  # noqa: BLE001 — discovery is best-effort
        logger.debug("codeql discovery probe failed", exc_info=True)
        return []


def validate_db_paths(paths: list[str] | None) -> list[str]:
    """Drop stamped database paths that no longer exist on disk (or
    lost their structural marker) — a resumed segment must not aim
    the channel at an evicted cache entry. Content freshness rode the
    cache key when the path was discovered; explicit operator paths
    are structural-checked only."""
    valid: list[str] = []
    for p in paths or []:
        db = Path(p)
        if db.is_dir() and (db / "codeql-database.yml").is_file():
            valid.append(str(db))
        else:
            logger.warning(
                "codeql database from the run config no longer valid "
                "on disk — dropped: %s", p,
            )
    return valid


def stamp_run_config_dbs(out_dir: Path, paths: list[str]) -> None:
    """Merge database paths into the persisted run config, so a
    resumed segment sees databases the background build delivered
    after the config was first written. Best-effort."""
    if not paths:
        return
    try:
        from core.audit.resume import load_run_config, save_run_config

        cfg = load_run_config(Path(out_dir))
        if not isinstance(cfg, dict):
            return
        merged = list(dict.fromkeys(
            [*(cfg.get("codeql_db_paths") or []), *paths],
        ))
        cfg["codeql_db_paths"] = merged
        cfg["codeql_db_path"] = merged[0]
        save_run_config(Path(out_dir), cfg)
    except Exception:  # noqa: BLE001 — stamping is best-effort
        logger.debug("codeql run-config stamp failed", exc_info=True)


def provision_codeql_dbs(
    target_path: Path,
    *,
    out_dir: Path | None = None,
    traced_build: bool | None = None,
) -> CodeqlProvision:
    """Discover or build CodeQL databases for *target_path*.

    Returns immediately: cache hits land in ``db_paths``; builds run
    in a daemon background thread whose future yields the new
    database paths (await with :func:`await_provisioned_dbs`).
    ``traced_build`` is the tri-state per-run consent (``None``
    defers to the project's ``build`` trust marker). Best-effort
    throughout — provisioning must never fail the audit.
    """
    provision = CodeqlProvision()
    target_path = Path(target_path)

    from core.config import RaptorConfig
    if not RaptorConfig.CODEQL_ENABLED:
        provision.skipped.append(CodeqlSkip(
            language="*",
            reason="codeql disabled in tuning.json (codeql_enabled=false)",
            remedy="set codeql_enabled=true in tuning.json",
        ))
        return provision

    if not target_path.is_dir():
        # A non-directory target (binary chains hand the artifact
        # path straight through) has no source tree to detect
        # languages in or build a database from — a predictable
        # state, not a detection failure worth a traceback in the
        # run log. Persisted so the report sees the skip; the other
        # early returns above predate status writing and keep their
        # stdout-only contract.
        provision.skipped.append(CodeqlSkip(
            language="*",
            reason="target is not a directory — no source tree for "
                   "CodeQL (binary targets use the decompiler "
                   "Semgrep sweep)",
            remedy="pass --codeql-db <path> if a database built from "
                   "the matching source tree exists",
        ))
        if out_dir is not None:
            provision.write_status(out_dir)
        return provision

    try:
        from packages.codeql.database_manager import (
            AUTOBUILD_LANGUAGES,
            DatabaseManager,
        )
        from packages.codeql.language_detector import LanguageDetector
    except ImportError:
        provision.skipped.append(CodeqlSkip(
            language="*",
            reason="codeql package not importable",
            remedy="pass --codeql-db <path> to supply a database",
        ))
        return provision

    try:
        manager = DatabaseManager()
    except RuntimeError as exc:
        provision.skipped.append(CodeqlSkip(
            language="*",
            reason=str(exc),
            remedy="install the CodeQL CLI (or set CODEQL_CLI), or "
                   "pass --codeql-db <path>",
        ))
        return provision

    try:
        detector = LanguageDetector(target_path)
        detected = detector.filter_codeql_supported(
            detector.detect_languages(),
        )
    except Exception:  # noqa: BLE001 — detection is best-effort
        logger.warning(
            "codeql provisioning: language detection failed", exc_info=True,
        )
        return provision
    if not detected:
        return provision

    from core.project.trust import resolve_build_execution
    # run_dir=out_dir: building executes repo-influenced code, so the
    # marker grant follows the RUN PIN's project when the caller has a
    # run directory in hand — never the ambient session's project.
    build_trusted = resolve_build_execution(
        traced_build, target_path=target_path, run_dir=out_dir,
    )

    to_build: list[str] = []
    traced_languages: set[str] = set()
    for language in sorted(detected):
        try:
            # TTL/TOCTOU residue: the cache probe validates age and
            # structure NOW; the pre-sweep consumes the path minutes
            # later, and a concurrent cleanup could evict it in
            # between. The consumers already degrade per-call on a
            # missing/invalid database (the run continues without the
            # channel), so the race costs receipts, never correctness.
            cached = manager.get_cached_database(target_path, language)
        except Exception:  # noqa: BLE001
            logger.debug(
                "codeql cache probe failed for %s", language, exc_info=True,
            )
            cached = None
        if cached is not None:
            provision.db_paths.append(str(cached))
            continue
        if language not in AUTOBUILD_LANGUAGES:
            # Extractor-only language: `database create` runs no
            # target build logic at all.
            to_build.append(language)
            continue
        supported, detail = manager.supports_buildless(language)
        if supported and not build_trusted:
            # Buildless (--build-mode=none) extraction also runs no
            # target build commands — the manager applies it by
            # default for these languages.
            to_build.append(language)
            continue
        if build_trusted:
            to_build.append(language)
            traced_languages.add(language)
            continue
        provision.skipped.append(CodeqlSkip(
            language=language,
            reason=(
                f"extraction for {language} would execute the "
                f"target's build logic"
                + (f" ({detail})" if detail else "")
            ),
            remedy="pass --codeql-db <path>, or authorise the build "
                   "with `/project trust build`",
        ))

    if provision.db_paths:
        logger.info(
            "codeql provisioning: reusing %d cached database(s): %s",
            len(provision.db_paths), ", ".join(provision.db_paths),
        )
    for skip in provision.skipped:
        logger.warning(
            "codeql provisioning: no database for %s — %s (%s)",
            skip.language, skip.reason, skip.remedy,
        )

    if to_build:
        provision.building_languages = list(to_build)
        logger.info(
            "codeql provisioning: building database(s) for %s in the "
            "background (overlaps prep; results cache for later runs)",
            ", ".join(to_build),
        )

        def _build() -> list[str]:
            results = manager.create_databases_parallel(
                target_path,
                {language: None for language in to_build},
                audit_run_dir=out_dir,
                traced_languages=traced_languages or None,
            )
            built: list[str] = []
            for language, res in sorted(results.items()):
                if res.success and res.database_path is not None:
                    built.append(str(res.database_path))
                else:
                    logger.warning(
                        "codeql provisioning: build failed for %s: %s",
                        language, "; ".join(res.errors or ["unknown"]),
                    )
            return built

        # Daemon thread, manual future: a pool thread would be
        # JOINED at interpreter exit, holding a fast-failing run
        # hostage to the whole build. The daemon thread is abandoned
        # at exit instead — the sandboxed build subprocess is reaped
        # with the process (death-pipe/killpg), so nothing leaks; the
        # cost is that only runs which outlive the build (the normal
        # case — reviews run for much longer) get the cache write for
        # the next run. Atomic staging→canonical promotion means an
        # abandoned build never corrupts the cache.
        future: Future = Future()

        def _runner() -> None:
            try:
                future.set_result(_build())
            except BaseException as exc:  # noqa: BLE001 — carried to await
                future.set_exception(exc)

        threading.Thread(
            target=_runner, name="codeql-provision", daemon=True,
        ).start()
        provision.build_future = future

    if out_dir is not None:
        provision.write_status(out_dir)
    return provision


def await_provisioned_dbs(
    build_future: Future | None,
    *,
    out_dir: Path | None = None,
    timeout_s: float = BUILD_AWAIT_S,
    deadline_monotonic: float | None = None,
    should_abort: Callable[[], bool] | None = None,
) -> list[str]:
    """Bounded join on the background build; returns new DB paths.

    Poll loop, never one blocking wait: each short ``result()``
    timeout re-checks ``should_abort`` (SIGTERM / environment guard —
    the salvage path must not sit behind a multi-minute join) and the
    total wait is clamped to ``min(timeout_s, remaining wall budget −
    salvage margin)`` when *deadline_monotonic* is given. On any early
    stop the build keeps running (it lands in the shared cache for
    the next run) and this run continues without the database — the
    outcome is recorded in ``codeql-provision.json`` either way.
    """
    if build_future is None:
        return []
    effective_s = float(timeout_s)
    if deadline_monotonic is not None:
        remaining = (
            deadline_monotonic - time.monotonic()
            - _AWAIT_DEADLINE_MARGIN_S
        )
        effective_s = min(effective_s, max(0.0, remaining))
    start = time.monotonic()
    while True:
        if should_abort is not None and should_abort():
            logger.warning(
                "codeql provisioning: build wait interrupted "
                "(shutdown requested) — continuing without CodeQL",
            )
            _update_status(
                out_dir, build_aborted=True, build_wait_stopped="abort",
            )
            return []
        remaining_wait = effective_s - (time.monotonic() - start)
        if remaining_wait <= 0:
            logger.warning(
                "codeql provisioning: background build still running "
                "after %.0fs wait budget — continuing without CodeQL "
                "for this run (the build finishes into the shared "
                "cache for the next run)",
                effective_s,
            )
            _update_status(
                out_dir, build_timed_out=True,
                build_wait_stopped="deadline",
            )
            return []
        try:
            built = build_future.result(
                timeout=min(_AWAIT_POLL_S, remaining_wait),
            )
            break
        except (TimeoutError, FuturesTimeoutError):
            # Python < 3.11 raises the concurrent.futures class,
            # which is NOT the builtin TimeoutError there.
            continue
        except Exception:  # noqa: BLE001 — provisioning never fails the run
            logger.warning(
                "codeql provisioning: background build failed",
                exc_info=True,
            )
            _update_status(out_dir, build_failed=True)
            return []
    _update_status(out_dir, built=built)
    if built:
        logger.info(
            "codeql provisioning: %d database(s) built: %s",
            len(built), ", ".join(built),
        )
    return built
