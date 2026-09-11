"""In-process Ghidra session via PyGhidra.

Embeds the Ghidra JVM in-process (via JPype) for direct API access.
Replaces the analyzeHeadless subprocess approach — faster startup,
persistent project handles, and on-demand per-function decompilation.

Requires ``pyghidra`` (bundled with Ghidra 12+, or ``pip install pyghidra``).
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Optional

from .detect import get_project_name
from .project_util import prepare_working_copy

from .model import (
    REComment,
    REDatabase,
    REFunction,
    RESegment,
    REType,
    REXref,
)

logger = logging.getLogger(__name__)


class GhidraSessionError(Exception):
    """Raised when a session operation fails."""


class GhidraSession:
    """Persistent in-process Ghidra session.

    Starts the JVM once (per-process singleton), opens a Ghidra project,
    and provides direct API access for export, decompilation, and queries.

    Usage::

        with GhidraSession() as session:
            session.open(Path("saprouter.gpr"))
            db = session.export()
            code = session.decompile_function("processRoute")
    """

    _jvm_started = False
    _jvm_lock = threading.Lock()

    def __init__(self):
        self._project = None
        self._program = None
        self._consumer = None
        self._work_dir = None
        self._decomp = None
        self._func_index: Optional[dict[str, object]] = None

    @classmethod
    def ensure_jvm(cls) -> None:
        """Start the Ghidra JVM if not already running.

        If ``GHIDRA_INSTALL_DIR`` is not set, derives it from the
        ``analyzeHeadless`` path on ``PATH`` (it lives under
        ``$GHIDRA_INSTALL_DIR/support/``).
        """
        if cls._jvm_started:
            return
        with cls._jvm_lock:
            if cls._jvm_started:
                return
            cls._ensure_jvm_locked()

    @classmethod
    def _ensure_jvm_locked(cls) -> None:
        import os
        if not os.environ.get("GHIDRA_INSTALL_DIR"):
            install_dir = cls._find_install_dir()
            if install_dir:
                os.environ["GHIDRA_INSTALL_DIR"] = str(install_dir)
                logger.info("auto-detected GHIDRA_INSTALL_DIR: %s", install_dir)
            else:
                raise GhidraSessionError(
                    "GHIDRA_INSTALL_DIR not set and analyzeHeadless not "
                    "found on PATH — set GHIDRA_INSTALL_DIR or install Ghidra"
                )
        try:
            import pyghidra
            if not pyghidra.api.started():
                pyghidra.start()
            cls._jvm_started = True
        except Exception as e:
            raise GhidraSessionError(f"failed to start Ghidra JVM: {e}") from e

    @staticmethod
    def _find_install_dir() -> Optional[Path]:
        """Derive GHIDRA_INSTALL_DIR from analyzeHeadless on PATH."""
        binary = shutil.which("analyzeHeadless")
        if not binary:
            return None
        real = Path(binary).resolve()
        if real.parent.name == "support":
            return real.parent.parent
        return None

    def open(
        self,
        gpr_path: Path,
        *,
        program_name: Optional[str] = None,
    ) -> None:
        """Open an existing Ghidra project.

        Creates a working copy so the original project is never modified.
        PyGhidra's ``open_project`` upgrades the on-disk database format
        and resets ownership, so a copy is required for read-only imports.

        Args:
            gpr_path: Path to the ``.gpr`` file.
            program_name: Specific program within the project.
                If None, opens the first (or only) program.
        """
        self.ensure_jvm()
        gpr_path = Path(gpr_path)

        work_dir = tempfile.mkdtemp(prefix="raptor-ghidra-")
        try:
            work_gpr = prepare_working_copy(gpr_path, Path(work_dir))
            project_dir = work_gpr.parent
            project_name_str = get_project_name(work_gpr)

            from pyghidra.api import open_project, consume_program
            try:
                self._project = open_project(str(project_dir), project_name_str)
            except Exception as e:
                raise GhidraSessionError(
                    f"failed to open project {project_name_str}: {e}"
                ) from e

            target_program = program_name.strip("/") if program_name else None
            if not target_program:
                programs = self.list_programs()
                if not programs:
                    raise GhidraSessionError(
                        f"project {project_name_str} contains no programs"
                    )
                target_program = programs[0]
                if len(programs) > 1:
                    logger.info(
                        "multi-program project: %s — opening %s",
                        ", ".join(programs),
                        target_program,
                    )

            try:
                self._program, self._consumer = consume_program(
                    self._project, f"/{target_program}"
                )
            except Exception as e:
                raise GhidraSessionError(
                    f"failed to open program {target_program}: {e}"
                ) from e

            self._work_dir = work_dir
        except BaseException:
            if self._project is not None:
                try:
                    self._project.close()
                except Exception:  # noqa: BLE001 — teardown best-effort
                    pass
                self._project = None
            shutil.rmtree(work_dir, ignore_errors=True)
            raise

        logger.info(
            "opened %s/%s (%s)",
            project_name_str,
            target_program,
            self._program.getLanguage().getLanguageDescription().getProcessor(),
        )

    def list_programs(self) -> list[str]:
        """List program paths in the open project (project-root
        relative, so subfolder programs appear as ``sub/dir/prog``).

        Filters to actual imported programs (DomainFile objects whose
        content class is ProgramDB or similar), excluding data type
        archives and other non-program files.
        """
        if not self._project:
            return []

        def walk(folder, prefix=""):
            files = [(prefix + str(f.getName()), f)
                     for f in folder.getFiles()]
            for sub in folder.getFolders():
                files.extend(walk(sub, prefix + str(sub.getName()) + "/"))
            return files

        entries = walk(self._project.getProjectData().getRootFolder())
        names = [path for path, f in entries
                 if "Program" in str(f.getContentType())]
        if not names:
            names = [path for path, _ in entries]
        # Depth-first sort: root programs before subfolder programs,
        # so the [0] default keeps the pre-subfolder-support choice
        # (and matches the server worker's root-files-first default).
        return sorted(names, key=lambda n: (n.count("/"), n))

    def export(self, *, decompile: bool = False) -> REDatabase:
        """Export the open program to an REDatabase.

        Args:
            decompile: If True, decompile every function (slow).

        Returns:
            Populated REDatabase.
        """
        self._require_program()
        program = self._program

        functions = self._export_functions(program, decompile)
        logger.info("exported %d functions", len(functions))

        xrefs = self._export_xrefs(program)
        logger.info("exported %d xrefs", len(xrefs))

        types = self._export_types(program)
        comments = self._export_comments(program)
        logger.info("exported %d comments", len(comments))

        segments = self._export_segments(program)
        imports = self._export_imports(program)
        exports = self._export_exports(program)
        strings = self._export_strings(program)
        bookmarks = self._export_bookmarks(program)

        arch = (
            str(program.getLanguage().getLanguageDescription().getProcessor())
            + "/"
            + str(program.getLanguage().getLanguageDescription().getSize())
        )

        metadata = {
            "program_name": str(program.getName()),
            "language_id": str(program.getLanguageID()),
            "compiler_spec": str(
                program.getCompilerSpec().getCompilerSpecID()
            ),
            "image_base": int(program.getImageBase().getOffset()),
        }
        ghidra_ver = program.getMetadata().get("Ghidra Version")
        if ghidra_ver:
            metadata["ghidra_version"] = str(ghidra_ver)

        db = REDatabase(
            source_tool="ghidra",
            binary_path=str(program.getExecutablePath()),
            architecture=arch,
            functions=functions,
            xrefs=xrefs,
            types=types,
            comments=comments,
            segments=segments,
            imports=imports,
            exports=exports,
            strings=strings,
            bookmarks=bookmarks,
            metadata=metadata,
        )

        # Ghidra's IMPORTED source type conflates debug-info and symbol
        # table names; split the provisional tag with a section probe
        # when the original binary is reachable (best-effort — same as
        # the headless-export parse seam).
        try:
            from core.analysis.binary_provenance import refine_import_provenance
            refine_import_provenance(db)
        except Exception:
            logger.debug("import-provenance refinement failed", exc_info=True)

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
            Decompiled C code, or None if not found / failed.
        """
        self._require_program()
        func = self._find_function(name_or_addr)
        if func is None:
            return None
        if func.isExternal() or func.isThunk():
            return None
        return self._decompile_one(func, timeout)

    def close(self) -> None:
        """Release all resources."""
        self._func_index = None

        if self._decomp is not None:
            try:
                self._decomp.dispose()
            except Exception:
                pass
            self._decomp = None

        if self._program is not None and self._consumer is not None:
            try:
                self._program.release(self._consumer)
            except Exception:
                pass
            self._program = None
            self._consumer = None

        if self._project is not None:
            try:
                self._project.close()
            except Exception:
                pass
            self._project = None

        if self._work_dir is not None:
            try:
                shutil.rmtree(self._work_dir, ignore_errors=True)
            except Exception:
                pass
            self._work_dir = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- internal helpers -----------------------------------------------

    def _require_program(self) -> None:
        if self._program is None:
            raise GhidraSessionError("no program open — call open() first")

    def _build_func_index(self) -> dict[str, object]:
        """Build a name -> function index for O(1) lookups."""
        if self._func_index is not None:
            return self._func_index
        idx: dict[str, object] = {}
        fm = self._program.getFunctionManager()
        it = fm.getFunctions(True)
        while it.hasNext():
            func = it.next()
            idx[str(func.getName())] = func
        self._func_index = idx
        return idx

    def _find_function(self, name_or_addr):
        """Look up a function by name or address."""
        fm = self._program.getFunctionManager()
        if isinstance(name_or_addr, int):
            af = self._program.getAddressFactory()
            addr = af.getDefaultAddressSpace().getAddress(name_or_addr)
            return fm.getFunctionAt(addr)
        idx = self._build_func_index()
        return idx.get(name_or_addr)

    def _get_decomp(self):
        """Get or create the decompiler interface."""
        if self._decomp is None:
            from ghidra.app.decompiler import DecompInterface
            self._decomp = DecompInterface()
            self._decomp.openProgram(self._program)
        return self._decomp

    def _decompile_one(self, func, timeout: int = 30) -> Optional[str]:
        """Decompile a single Ghidra Function object."""
        decomp = self._get_decomp()
        from pyghidra.api import task_monitor
        monitor = task_monitor(timeout)
        try:
            result = decomp.decompileFunction(func, timeout, monitor)
            if result is not None and result.decompileCompleted():
                df = result.getDecompiledFunction()
                if df is not None:
                    c = df.getC()
                    if c is not None:
                        return str(c)
        except Exception:
            logger.debug("decompilation failed for %s", func.getName(), exc_info=True)
        return None

    def _export_functions(self, program, decompile: bool) -> list[REFunction]:
        from ghidra.program.model.symbol import SourceType

        from .model import looks_tool_synthetic
        from .parser import _function_name_provenance

        # Mirror of the headless exporter's symbol-source mapping: the
        # raw source type is what mints the name-provenance tag, and a
        # placeholder-looking name must flag auto-named regardless of
        # what the symbol claims (forged/stripped-then-repacked names).
        source_names = {
            SourceType.DEFAULT: "default",
            SourceType.ANALYSIS: "analysis",
            SourceType.IMPORTED: "imported",
            SourceType.USER_DEFINED: "user_defined",
        }

        functions = []
        fm = program.getFunctionManager()
        it = fm.getFunctions(True)
        while it.hasNext():
            func = it.next()
            entry = func.getEntryPoint()
            name = str(func.getName())

            sym_source = func.getSymbol().getSource()
            source_name = source_names.get(sym_source, str(sym_source))
            is_auto = (
                sym_source == SourceType.ANALYSIS
                or looks_tool_synthetic(name)
            )

            sig = None
            try:
                proto = func.getSignature().getPrototypeString()
                if proto:
                    sig = str(proto)
            except Exception:
                pass

            cc = None
            try:
                conv = func.getCallingConvention()
                if conv:
                    cc = str(conv.getName())
            except Exception:
                pass

            decomp_text = None
            if decompile and not func.isExternal() and not func.isThunk():
                decomp_text = self._decompile_one(func)

            functions.append(REFunction(
                name=name,
                address=int(entry.getOffset()),
                size=int(func.getBody().getNumAddresses()),
                signature=sig,
                calling_convention=cc,
                is_auto_named=is_auto,
                is_thunk=bool(func.isThunk()),
                is_external=bool(func.isExternal()),
                decompilation=decomp_text,
                source_tool="ghidra",
                name_provenance=_function_name_provenance(
                    {"symbol_source": source_name}, name, is_auto,
                ),
            ))
        return functions

    def _export_xrefs(self, program) -> list[REXref]:
        """Export cross-references using source-address iterators.

        Uses getReferenceSourceIterator on each function body to skip
        addresses with no outgoing refs, rather than walking every
        address and calling getReferencesFrom on each.
        """
        xrefs = []
        seen = set()
        rm = program.getReferenceManager()
        fm = program.getFunctionManager()

        it = fm.getFunctions(True)
        while it.hasNext():
            func = it.next()
            body = func.getBody()
            src_it = rm.getReferenceSourceIterator(body, True)
            while src_it.hasNext():
                addr = src_it.next()
                refs = rm.getReferencesFrom(addr)
                for ref in refs:
                    to_addr = ref.getToAddress()
                    if to_addr is None or not to_addr.isMemoryAddress():
                        continue
                    kind = "call" if ref.getReferenceType().isCall() else "data"
                    key = (int(addr.getOffset()), int(to_addr.getOffset()), kind)
                    if key not in seen:
                        seen.add(key)
                        xrefs.append(REXref(
                            from_addr=key[0],
                            to_addr=key[1],
                            kind=kind,
                            source_tool="ghidra",
                        ))
        return xrefs

    def _export_types(self, program) -> list[REType]:
        from ghidra.program.model.data import (
            EnumDataType,
            FunctionDefinition,
            Structure,
            TypeDef,
        )

        types = []
        dtm = program.getDataTypeManager()
        it = dtm.getAllDataTypes()
        while it.hasNext():
            dt = it.next()

            if isinstance(dt, Structure):
                fields = []
                for comp in dt.getComponents():
                    fields.append({
                        "name": str(comp.getFieldName() or ""),
                        "offset": int(comp.getOffset()),
                        "type": str(comp.getDataType().getName()),
                        "size": int(comp.getLength()),
                    })
                types.append(REType(
                    name=str(dt.getName()),
                    kind="struct",
                    size=int(dt.getLength()),
                    fields=fields,
                    source_tool="ghidra",
                ))
            elif isinstance(dt, EnumDataType):
                types.append(REType(
                    name=str(dt.getName()),
                    kind="enum",
                    size=int(dt.getLength()),
                    source_tool="ghidra",
                ))
            elif isinstance(dt, TypeDef):
                types.append(REType(
                    name=str(dt.getName()),
                    kind="typedef",
                    size=int(dt.getLength()),
                    source_tool="ghidra",
                ))
            elif isinstance(dt, FunctionDefinition):
                types.append(REType(
                    name=str(dt.getName()),
                    kind="function_sig",
                    source_tool="ghidra",
                ))
        return types

    def _export_comments(self, program) -> list[REComment]:
        """Export comments using per-type address iterators.

        Iterates only addresses that actually have comments for each
        comment type, rather than walking all code units. Dramatically
        faster on projects with many defined data items but few comments.
        """
        comment_types = self._get_comment_types()
        comments = []
        listing = program.getListing()
        fm = program.getFunctionManager()
        addr_set = program.getMemory()

        for ct, kind_name in comment_types:
            try:
                addr_it = listing.getCommentAddressIterator(ct, addr_set, True)
            except (AttributeError, TypeError):
                # Fallback for Ghidra versions without this method
                addr_it = None

            if addr_it is not None:
                while addr_it.hasNext():
                    addr = addr_it.next()
                    text = listing.getComment(ct, addr)
                    if text is not None:
                        func = fm.getFunctionContaining(addr)
                        func_name = str(func.getName()) if func else None
                        comments.append(REComment(
                            address=int(addr.getOffset()),
                            function=func_name,
                            kind=kind_name,
                            text=str(text),
                            source_tool="ghidra",
                        ))
            else:
                it = listing.getCodeUnits(True)
                while it.hasNext():
                    cu = it.next()
                    text = cu.getComment(ct)
                    if text is not None:
                        addr = cu.getAddress()
                        func = fm.getFunctionContaining(addr)
                        func_name = str(func.getName()) if func else None
                        comments.append(REComment(
                            address=int(addr.getOffset()),
                            function=func_name,
                            kind=kind_name,
                            text=str(text),
                            source_tool="ghidra",
                        ))
        return comments

    def _get_comment_types(self):
        """Return (CommentType, name) pairs, handling Ghidra 11 vs 12 API."""
        try:
            from ghidra.program.model.listing import CommentType
            return [
                (CommentType.EOL, "eol"),
                (CommentType.PLATE, "plate"),
                (CommentType.PRE, "pre"),
                (CommentType.POST, "post"),
            ]
        except ImportError:
            from ghidra.program.model.listing import CodeUnit
            return [
                (CodeUnit.EOL_COMMENT, "eol"),
                (CodeUnit.PLATE_COMMENT, "plate"),
                (CodeUnit.PRE_COMMENT, "pre"),
                (CodeUnit.POST_COMMENT, "post"),
            ]

    def _export_segments(self, program) -> list[RESegment]:
        """Export memory segments.

        Note: ``end`` is the last address IN the block (inclusive),
        matching Ghidra's ``MemoryBlock.getEnd()`` semantics. Consumers
        needing exclusive-end should add 1.
        """
        segments = []
        for block in program.getMemory().getBlocks():
            perms = (
                ("r" if block.isRead() else "-")
                + ("w" if block.isWrite() else "-")
                + ("x" if block.isExecute() else "-")
            )
            segments.append(RESegment(
                name=str(block.getName()),
                start=int(block.getStart().getOffset()),
                end=int(block.getEnd().getOffset()),
                permissions=perms,
            ))
        return segments

    def _export_imports(self, program) -> list[dict]:
        from ghidra.program.model.symbol import ExternalLocation

        imports = []
        st = program.getSymbolTable()
        it = st.getExternalSymbols()
        while it.hasNext():
            sym = it.next()
            imp: dict = {"name": str(sym.getName())}
            try:
                refs = sym.getReferences()
                if len(refs) > 0:
                    imp["address"] = int(refs[0].getFromAddress().getOffset())
            except Exception:
                pass
            try:
                obj = sym.getObject()
                if isinstance(obj, ExternalLocation):
                    lib = obj.getLibraryName()
                    if lib:
                        imp["library"] = str(lib)
            except Exception:
                pass
            imports.append(imp)
        return imports

    def _export_exports(self, program) -> list[dict]:
        exports = []
        st = program.getSymbolTable()
        it = st.getSymbolIterator(True)
        while it.hasNext():
            sym = it.next()
            if sym.isExternalEntryPoint():
                exports.append({
                    "name": str(sym.getName()),
                    "address": int(sym.getAddress().getOffset()),
                })
        return exports

    def _export_strings(self, program) -> list[dict]:
        from ghidra.program.model.data import AbstractStringDataType

        strings = []
        listing = program.getListing()
        it = listing.getDefinedData(True)
        while it.hasNext():
            data = it.next()
            dt = data.getDataType()
            if isinstance(dt, AbstractStringDataType):
                try:
                    strings.append({
                        "address": int(data.getAddress().getOffset()),
                        "value": str(data.getDefaultValueRepresentation()),
                    })
                except Exception:
                    pass
        return strings

    def _export_bookmarks(self, program) -> list[dict]:
        bookmarks = []
        bm = program.getBookmarkManager()
        it = bm.getBookmarksIterator()
        while it.hasNext():
            b = it.next()
            bookmarks.append({
                "address": int(b.getAddress().getOffset()),
                "category": str(b.getCategory()),
                "comment": str(b.getComment()),
                "type": str(b.getTypeString()),
            })
        return bookmarks
