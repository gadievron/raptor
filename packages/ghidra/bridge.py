"""Ghidra bridge — import, enrich, and round-trip orchestration."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from .detect import (
    pyghidra_available,
    validate_project,
)
from .model import REDatabase
from .session import GhidraSession, GhidraSessionError

logger = logging.getLogger(__name__)

AUTO_NAMED_WARN_THRESHOLD = 0.80


class GhidraBridge:
    """Orchestrates Ghidra project import, enrichment, and round-trip.

    Uses PyGhidra for in-process JVM access (no subprocess spawning).

    Usage::

        bridge = GhidraBridge(gpr_path)
        db = bridge.import_project()           # trust mode
        db = bridge.import_and_enrich(binary)  # enrich mode
        bridge.export_enrichments(db, out_gpr) # round-trip
    """

    def __init__(self, gpr_path: Path, *, program_name: Optional[str] = None):
        self.gpr_path = Path(gpr_path)
        self.program_name = program_name
        self._session: Optional[GhidraSession] = None
        self._validate_project()

    def _validate_project(self) -> None:
        """Validate the .gpr file structure (no Ghidra install needed)."""
        err = validate_project(self.gpr_path)
        if err:
            raise GhidraSessionError(f"invalid Ghidra project: {err}")

    def _ensure_pyghidra(self) -> None:
        """Check that pyghidra is available."""
        if not pyghidra_available():
            raise GhidraSessionError(
                "pyghidra not installed — "
                "install via: pip install pyghidra"
            )

    def _get_session(self) -> GhidraSession:
        """Get or create the persistent session."""
        if self._session is not None:
            return self._session
        self._ensure_pyghidra()
        session = GhidraSession()
        session.open(self.gpr_path, program_name=self.program_name)
        self._session = session
        return session

    def import_project(
        self,
        output_dir: Path,
        *,
        decompile: bool = False,
    ) -> REDatabase:
        """Import a Ghidra project into an REDatabase (trust mode).

        Opens the project via PyGhidra and exports all data directly
        through the Ghidra API.

        Args:
            output_dir: Directory for output files.
            decompile: If True, decompile every function (slow).
                Default False — import metadata only.

        Returns:
            The populated REDatabase.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        from .detect import prefer_in_process
        if prefer_in_process():
            session = self._get_session()
            db = session.export(decompile=decompile)
        else:
            # Default: the sandboxed analyzeHeadless subprocess — the
            # JVM parses an attacker-controlled project database, so
            # it runs network-denied with scoped writes. The export
            # script produces the same JSON, parsed into an
            # REDatabase here.
            from .headless import export_project
            from .parser import parse_export
            export_json = output_dir / "ghidra-export.json"
            export_project(
                self.gpr_path,
                export_json,
                program_name=self.program_name,
                decompile=decompile,
            )
            db = parse_export(export_json)

        if db.auto_named_ratio > AUTO_NAMED_WARN_THRESHOLD:
            pct = int(db.auto_named_ratio * 100)
            logger.warning(
                "Ghidra project is %d%% auto-named functions — "
                "consider --enrich to fill gaps with r2",
                pct,
            )

        self._write_re_database(db, output_dir)
        return db

    def decompile_function(
        self,
        name_or_addr,
        *,
        timeout: int = 30,
    ) -> Optional[str]:
        """Decompile a single function on demand.

        Args:
            name_or_addr: Function name (str) or entry address (int).
            timeout: Maximum seconds for decompilation.

        Returns:
            Decompiled C code, or None if not found / decompilation failed.
        """
        session = self._get_session()
        return session.decompile_function(name_or_addr, timeout=timeout)

    def import_and_enrich(
        self,
        output_dir: Path,
        *,
        binary_path: Optional[Path] = None,
    ) -> REDatabase:
        """Import Ghidra data and enrich with r2 analysis.

        Runs the Ghidra export first (primary), then runs r2 against
        the binary and merges the results.  Ghidra wins on conflicts.

        Args:
            output_dir: Directory for output files.
            binary_path: Path to the raw binary for r2 analysis.
                If None, attempts to extract the path from the Ghidra
                project metadata.

        Returns:
            The merged REDatabase.
        """
        ghidra_db = self.import_project(output_dir)

        bin_path = binary_path
        if bin_path is None and ghidra_db.binary_path:
            candidate = Path(ghidra_db.binary_path)
            # A relative metadata path is relative to the project, not
            # to whatever the process CWD happens to be — anchor it at
            # the .gpr's directory so a bundled sibling binary is found
            # (and the CWD is never probed for attacker-chosen names).
            if not candidate.is_absolute():
                candidate = self.gpr_path.parent / candidate
            # The metadata path is a free string inside the (attacker-
            # controlled) project — honour it only when it points at a
            # file shipped alongside the project itself, never at
            # arbitrary local paths the project author chose.
            try:
                contained = candidate.resolve().is_relative_to(
                    self.gpr_path.parent.resolve()
                )
            except OSError:
                contained = False
            if contained and candidate.is_file():
                logger.info(
                    "enrich: using binary_path from Ghidra metadata: %s",
                    candidate,
                )
                bin_path = candidate
            elif candidate.is_file():
                logger.warning(
                    "enrich: ignoring project-metadata binary path "
                    "outside the project directory (%s) — pass "
                    "--binary to use it explicitly", candidate,
                )

        if bin_path is None:
            logger.warning(
                "enrich mode: no binary path available — "
                "returning Ghidra-only data. Pass --binary to enable "
                "r2 enrichment."
            )
            return ghidra_db

        r2_db = self._run_r2(bin_path, output_dir)
        if r2_db is None:
            logger.warning("r2 analysis failed — returning Ghidra-only data")
            return ghidra_db

        merged = ghidra_db.merge(r2_db)

        new_funcs = len(merged.functions) - len(ghidra_db.functions)
        new_xrefs = len(merged.xrefs) - len(ghidra_db.xrefs)
        logger.info(
            "enrich: r2 added %d new functions, %d new xrefs",
            new_funcs, new_xrefs,
        )

        self._write_re_database(merged, output_dir)
        return merged

    def export_enrichments(
        self,
        db: Optional[REDatabase],
        output_gpr: Path,
        *,
        findings: Optional[list] = None,
    ) -> Path:
        """Export RAPTOR findings back into a Ghidra project copy.

        Uses PyGhidra transactions when available, else the sandboxed
        analyzeHeadless import script.

        Args:
            db: The REDatabase (possibly enriched). Optional — it only
                contributes r2-discovered new functions; findings keyed
                by function name resolve inside Ghidra, so callers
                without a loaded database pass None instead of paying
                an import invocation for it.
            output_gpr: Where to write the enriched ``.gpr`` copy.
            findings: Optional list of RAPTOR findings to import as
                comments and bookmarks. Entries carry ``address`` or a
                ``function`` name (resolved in-program).

        Returns:
            The output ``.gpr`` path.
        """
        from .project_util import prepare_working_copy

        output_dir = output_gpr.parent
        output_dir.mkdir(parents=True, exist_ok=True)

        work_gpr = prepare_working_copy(self.gpr_path, output_dir)
        enrichments = self._build_enrichments(db, findings)

        enrichments_json = output_dir / "ghidra-enrichments.json"
        with open(enrichments_json, "w") as f:
            json.dump(enrichments, f, indent=2)

        from .detect import prefer_in_process
        if prefer_in_process():
            self._apply_enrichments_pyghidra(work_gpr, enrichments)
        else:
            # Default: the sandboxed analyzeHeadless import script
            # applies the same enrichments JSON.
            from .headless import import_enrichments
            import_enrichments(
                self.gpr_path, enrichments_json, work_gpr,
                program_name=self.program_name,
                copy_prepared=True,
            )
        logger.info("enrichments applied to %s", work_gpr)
        return work_gpr

    def _apply_enrichments_pyghidra(
        self,
        gpr_path: Path,
        enrichments: dict,
    ) -> None:
        """Apply enrichments to a Ghidra project via PyGhidra transactions."""
        from .detect import get_project_name
        # The ghidra.* namespace only exists once the JVM is up —
        # open_project alone does not start it.
        GhidraSession.ensure_jvm()
        from pyghidra.api import consume_program, open_project

        project_name = get_project_name(gpr_path)
        project = open_project(str(gpr_path.parent), project_name)

        root = project.getProjectData().getRootFolder()
        files = list(root.getFiles())
        if not files:
            project.close()
            raise GhidraSessionError(
                f"cannot apply enrichments: project {project_name} "
                f"contains no programs"
            )

        program, consumer = consume_program(project, f"/{files[0].getName()}")

        try:
            tx = program.startTransaction("RAPTOR enrichments")
            try:
                n_comments = self._apply_comments(program, enrichments)
                n_bookmarks = self._apply_bookmarks(program, enrichments)
                n_functions = self._apply_functions(program, enrichments)
                program.endTransaction(tx, True)
                # Ghidra persists DomainObject changes only on an
                # explicit save — releasing without one silently
                # discards the whole transaction.
                from pyghidra.api import task_monitor
                program.save("RAPTOR enrichments", task_monitor())
                logger.info(
                    "applied %d comments, %d bookmarks, %d functions",
                    n_comments, n_bookmarks, n_functions,
                )
            except Exception:
                program.endTransaction(tx, False)
                raise
        finally:
            program.release(consumer)
            project.close()

    @staticmethod
    def _resolve_entry_address(program, entry: dict):
        """Resolve an enrichment entry to a Ghidra Address, or None.

        Entries carry an explicit ``address`` or a ``function`` name
        resolved against the program's own function index (mirrors
        ImportRaptor.java's toAddress).
        """
        addr = entry.get("address")
        if addr is not None and addr >= 0:
            space = program.getAddressFactory().getDefaultAddressSpace()
            resolved = space.getAddress(addr)
            # A stale or wrong-base address that hits no code unit
            # falls through to name resolution.
            if program.getListing().getCodeUnitAt(resolved) is not None:
                return resolved
        name = entry.get("function") or ""
        if name:
            matches = program.getListing().getGlobalFunctions(name)
            if len(matches) > 1:
                logger.info(
                    "function name %r matches %d definitions — using "
                    "the first", name, len(matches),
                )
            if matches:
                return matches[0].getEntryPoint()
        return None

    @staticmethod
    def _apply_comments(program, enrichments: dict) -> int:
        comment_types = _get_comment_type_map()
        listing = program.getListing()

        count = 0
        for entry in enrichments.get("comments", []):
            addr = GhidraBridge._resolve_entry_address(program, entry)
            if addr is None:
                continue
            cu = listing.getCodeUnitAt(addr)
            if cu is None:
                continue
            ct = comment_types.get(entry.get("kind", "eol"))
            if ct is None:
                continue
            existing = cu.getComment(ct)
            text = entry["text"]
            if existing:
                if text in str(existing):
                    continue
                text = str(existing) + "\n" + text
            cu.setComment(ct, text)
            count += 1
        return count

    @staticmethod
    def _apply_bookmarks(program, enrichments: dict) -> int:
        bm = program.getBookmarkManager()

        count = 0
        for entry in enrichments.get("bookmarks", []):
            addr = GhidraBridge._resolve_entry_address(program, entry)
            if addr is None:
                continue
            btype = entry.get("type", "RAPTOR")
            category = entry.get("category", "Finding")
            comment = entry.get("comment", "")
            bm.setBookmark(addr, btype, category, comment)
            count += 1
        return count

    @staticmethod
    def _apply_functions(program, enrichments: dict) -> int:
        from ghidra.program.model.symbol import SourceType

        fm = program.getFunctionManager()
        af = program.getAddressFactory()
        space = af.getDefaultAddressSpace()

        count = 0
        for entry in enrichments.get("new_functions", []):
            addr = space.getAddress(entry["address"])
            existing = fm.getFunctionAt(addr)
            if existing is not None:
                continue
            try:
                func = fm.createFunction(
                    entry.get("name", "raptor_%x" % entry["address"]),
                    addr,
                    None,
                    SourceType.USER_DEFINED,
                )
                if func:
                    count += 1
            except Exception:  # noqa: BLE001
                logger.debug(
                    "failed to create function at 0x%x", entry["address"],
                    exc_info=True,
                )
        return count

    def close(self) -> None:
        """Close the session and release resources."""
        if self._session is not None:
            self._session.close()
            self._session = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _run_r2(self, binary_path: Path, output_dir: Path) -> Optional[REDatabase]:
        """Run r2 analysis and return an REDatabase, or None on failure."""
        try:
            from .r2_import import import_binary_r2
            return import_binary_r2(binary_path)
        except Exception:
            logger.debug("r2 analysis failed", exc_info=True)
            return None

    def _build_enrichments(
        self,
        db: Optional[REDatabase],
        findings: Optional[list] = None,
    ) -> dict:
        """Build the enrichments JSON for the Ghidra import."""
        enrichments: dict = {
            "comments": [],
            "bookmarks": [],
            "new_functions": [],
        }

        for func in (db.functions if db else []):
            if func.source_tool != "ghidra":
                enrichments["new_functions"].append({
                    "name": func.name,
                    "address": func.address,
                    "source": func.source_tool,
                })

        for finding in (findings or []):
            addr = finding.get("address")
            func_name = finding.get("function") or ""
            if addr is None and not func_name:
                continue
            # Carry both keys: a stale/wrong-base address falls back
            # to name resolution inside the apply step.
            key = {}
            if addr is not None:
                key["address"] = addr
            if func_name:
                key["function"] = func_name
            enrichments["comments"].append({
                **key,
                "kind": "plate",
                "text": "RAPTOR: %s" % finding.get("summary", "finding"),
            })
            # Only findings that carry a severity earn a bookmark
            # (annotation entries with informational statuses get the
            # plate comment only).
            if finding.get("severity"):
                enrichments["bookmarks"].append({
                    **key,
                    "type": "RAPTOR",
                    "category": finding["severity"],
                    "comment": finding.get("summary", ""),
                })

        return enrichments

    def _write_re_database(self, db: REDatabase, output_dir: Path) -> None:
        """Write the REDatabase to disk as ``re-database.json``.

        Stamps the analysed binary's content hash into the metadata so
        cache reuse can verify the database belongs to the binary it
        is being used for.
        """
        doc = db.to_dict()
        try:
            bp = Path(db.binary_path or "")
            if bp.is_file():
                from core.hash import sha256_file
                doc.setdefault("metadata", {})["binary_sha256"] = (
                    sha256_file(bp)
                )
        except OSError:
            logger.debug("could not hash %s", db.binary_path, exc_info=True)
        out_path = output_dir / "re-database.json"
        # Atomic replace: attach graduated this file from one-shot
        # import output to long-lived shared state that concurrent
        # runs read lock-free — a truncate-in-place write gives a
        # reader the empty window and the run negative-caches "no
        # Ghidra context" for its whole lifetime.
        from core.json import save_json
        save_json(out_path, doc)
        logger.info("wrote %s (%d functions)", out_path, len(db.functions))


def _get_comment_type_map() -> dict:
    """Return comment kind string -> Ghidra constant map."""
    try:
        from ghidra.program.model.listing import CommentType
        return {
            "eol": CommentType.EOL,
            "plate": CommentType.PLATE,
            "pre": CommentType.PRE,
            "post": CommentType.POST,
        }
    except ImportError:
        from ghidra.program.model.listing import CodeUnit
        return {
            "eol": CodeUnit.EOL_COMMENT,
            "plate": CodeUnit.PLATE_COMMENT,
            "pre": CodeUnit.PRE_COMMENT,
            "post": CodeUnit.POST_COMMENT,
        }
