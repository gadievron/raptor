"""Sandboxed pyghidra worker — the persistent Ghidra server's child.

Runs INSIDE ``core.sandbox.run`` (network denied, reads restricted,
writes scoped): boots the JVM once, opens one project working copy,
and serves requests over a unix domain socket as JSON lines. This is
what makes a long-lived pyghidra safe on attacker-controlled projects
— the equivalent in-process session would run unsandboxed.

Self-contained by design: no RAPTOR imports (the sandbox read set
stays minimal — interpreter, pyghidra, Ghidra install, work dir).

Protocol (one JSON object per line, response mirrors ``id``):
  {"id": 1, "op": "ping"}
  {"id": 2, "op": "open", "gpr": "/work/copy.gpr", "program": null}
  {"id": 3, "op": "list"}
  {"id": 4, "op": "export", "out": "/work/export.json"}
  {"id": 5, "op": "decompile", "function": "main", "timeout": 30}
  {"id": 6, "op": "apply", "enrichments": {...}}
  {"id": 7, "op": "shutdown"}

Responses: {"id": N, "ok": true, ...} or {"id": N, "ok": false,
"error": "..."}. The worker exits on "shutdown", on socket EOF, or
when idle past --idle-timeout.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import traceback

#: Hard per-op wall-clock caps. A pyghidra call that outlives its cap
#: is stuck in native JVM code — Python cannot interrupt it, so the
#: watchdog answers the request with an error and kills the process;
#: the parent detects the dropped connection and can boot a fresh
#: worker instead of parking the slot until the lifetime cap. Every
#: cap sits BELOW the client's corresponding socket timeout (300s
#: default; decompile timeout+30) so the client receives the clean
#: watchdog error instead of a desynchronized-stream timeout.
_OP_DEADLINE_S = {
    "ping": 45,
    "list": 45,
    "open": 240,
    "export": 240,
    "apply": 240,
    "decompile": 240,  # a request timeout raises this to timeout+15
}
_WATCHDOG_EXIT_CODE = 70


def _log(msg: str) -> None:
    print(f"[ghidra-worker] {msg}", file=sys.stderr, flush=True)


class _Session:
    """One open Ghidra project (pyghidra), reused across requests."""

    def __init__(self) -> None:
        self.project = None
        self.program = None
        self._consumer = None
        self._flat = None

    @staticmethod
    def _walk_programs(folder, prefix: str = "") -> list:
        """Program paths relative to the project root — subfolder
        programs included (``sub/dir/prog``), root files bare."""
        out = [prefix + str(f.getName()) for f in folder.getFiles()]
        for sub in folder.getFolders():
            out.extend(_Session._walk_programs(
                sub, prefix + str(sub.getName()) + "/",
            ))
        return out

    def open(self, gpr: str, program_name: str | None) -> dict:
        import pyghidra
        if not pyghidra.api.started():
            pyghidra.start()
        from pathlib import Path

        from pyghidra.api import consume_program, open_project

        gpr_path = Path(gpr)
        self.project = open_project(
            str(gpr_path.parent), gpr_path.stem,
        )
        root = self.project.getProjectData().getRootFolder()
        files = self._walk_programs(root)
        if not files:
            raise RuntimeError("project contains no programs")
        target = (program_name or files[0]).strip("/")
        self.program, self._consumer = consume_program(
            self.project, f"/{target}",
        )
        return {"programs": files, "opened": target}

    def list_programs(self) -> dict:
        if self.project is None:
            raise RuntimeError("no project open")
        root = self.project.getProjectData().getRootFolder()
        return {"programs": self._walk_programs(root)}

    def decompile(self, function: str | int, timeout: int) -> dict:
        program = self._require_program()
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        listing = program.getListing()
        func = None
        if isinstance(function, int):
            space = program.getAddressFactory().getDefaultAddressSpace()
            func = listing.getFunctionContaining(
                space.getAddress(function),
            )
        else:
            matches = listing.getGlobalFunctions(function)
            if matches:
                func = matches[0]
        if func is None:
            raise RuntimeError(f"function not found: {function}")

        ifc = DecompInterface()
        try:
            ifc.openProgram(program)
            res = ifc.decompileFunction(
                func, timeout, ConsoleTaskMonitor(),
            )
            if not res.decompileCompleted():
                raise RuntimeError(
                    f"decompilation failed: {res.getErrorMessage()}"
                )
            return {"code": res.getDecompiledFunction().getC()}
        finally:
            ifc.dispose()

    def export(self, out: str) -> dict:
        """Minimal structured export: function summaries only.

        Full-fidelity export (xrefs, types, comments, decompilation)
        goes through ExportRaptor.java / the import pipeline; the
        server's primary consumers are decompile/apply, where JVM
        reuse pays.
        """
        program = self._require_program()
        listing = program.getListing()
        functions = []
        it = listing.getFunctions(True)
        for func in it:
            entry = {
                "name": str(func.getName()),
                "address": int(func.getEntryPoint().getOffset()),
                "size": int(func.getBody().getNumAddresses()),
                "is_thunk": bool(func.isThunk()),
                "is_external": bool(func.isExternal()),
                "source_tool": "ghidra",
            }
            functions.append(entry)
        doc = {
            "source_tool": "ghidra",
            "binary_path": str(program.getExecutablePath()),
            "architecture": str(
                program.getLanguage().getProcessor()
            ),
            "functions": functions,
        }
        with open(out, "w") as f:
            json.dump(doc, f)
        return {"functions": len(functions), "out": out}

    def apply_enrichments(self, enrichments: dict) -> dict:
        program = self._require_program()
        from ghidra.program.model.listing import CodeUnit
        try:
            from ghidra.program.model.listing import CommentType
            ct_map = {
                "eol": CommentType.EOL,
                "plate": CommentType.PLATE,
                "pre": CommentType.PRE,
                "post": CommentType.POST,
            }
        except ImportError:
            ct_map = {
                "eol": CodeUnit.EOL_COMMENT,
                "plate": CodeUnit.PLATE_COMMENT,
                "pre": CodeUnit.PRE_COMMENT,
                "post": CodeUnit.POST_COMMENT,
            }

        listing = program.getListing()
        space = program.getAddressFactory().getDefaultAddressSpace()

        def resolve(entry):
            addr = entry.get("address")
            if addr is not None and addr >= 0:
                resolved = space.getAddress(addr)
                if listing.getCodeUnitAt(resolved) is not None:
                    return resolved
            name = entry.get("function") or ""
            if name:
                matches = listing.getGlobalFunctions(name)
                if matches:
                    return matches[0].getEntryPoint()
            return None

        n_comments = n_bookmarks = 0
        tx = program.startTransaction("RAPTOR enrichments")
        try:
            for entry in enrichments.get("comments", []):
                addr = resolve(entry)
                if addr is None:
                    continue
                cu = listing.getCodeUnitAt(addr)
                if cu is None:
                    continue
                ct = ct_map.get(entry.get("kind", "eol"))
                if ct is None:
                    continue
                text = entry["text"]
                existing = cu.getComment(ct)
                if existing:
                    if text in str(existing):
                        continue
                    text = str(existing) + "\n" + text
                cu.setComment(ct, text)
                n_comments += 1
            bm = program.getBookmarkManager()
            for entry in enrichments.get("bookmarks", []):
                addr = resolve(entry)
                if addr is None:
                    continue
                bm.setBookmark(
                    addr,
                    entry.get("type", "RAPTOR"),
                    entry.get("category", "Finding"),
                    entry.get("comment", ""),
                )
                n_bookmarks += 1
            program.endTransaction(tx, True)
        except BaseException:
            program.endTransaction(tx, False)
            raise
        from pyghidra.api import task_monitor
        self.program.save("RAPTOR enrichments", task_monitor())
        return {"comments": n_comments, "bookmarks": n_bookmarks}

    def _require_program(self):
        if self.program is None:
            raise RuntimeError("no project open — send an 'open' first")
        return self.program

    def close(self) -> None:
        if self.program is not None and self._consumer is not None:
            try:
                self.program.release(self._consumer)
            except Exception:
                pass
        if self.project is not None:
            try:
                self.project.close()
            except Exception:
                pass
        self.program = self.project = self._consumer = None


def _handle(session: _Session, req: dict) -> dict:
    op = req.get("op")
    if op == "ping":
        return {"pong": True}
    if op == "open":
        return session.open(req["gpr"], req.get("program"))
    if op == "list":
        return session.list_programs()
    if op == "decompile":
        return session.decompile(
            req["function"], int(req.get("timeout", 30)),
        )
    if op == "export":
        return session.export(req["out"])
    if op == "apply":
        return session.apply_enrichments(req["enrichments"])
    raise RuntimeError(f"unknown op: {op}")


class _OpHung(Exception):
    """An op outlived its hard deadline inside native JVM code."""


class _HandlerThread:
    """ONE persistent worker thread running every op.

    A thread-per-op design would attach each new Python thread to the
    JVM (JPype auto-attach — a known leak vector over thousands of
    decompiles) and would boot the JVM on whichever thread ran the
    first ``open``. One long-lived handler thread keeps a single JVM
    attachment and a consistent boot thread; the main thread owns the
    socket and applies the deadline. After a hang the wedged thread is
    unrecoverable — the caller kills the process, so the queue never
    needs draining.
    """

    def __init__(self, session: _Session) -> None:
        import queue
        self._session = session
        self._requests: "queue.Queue" = queue.Queue()
        self._thread = threading.Thread(
            target=self._loop, name="ghidra-op-handler", daemon=True,
        )
        self._thread.start()

    def _loop(self) -> None:
        while True:
            req, box, done = self._requests.get()
            try:
                box["result"] = _handle(self._session, req)
            except BaseException as e:  # noqa: BLE001 — one error channel
                box["error"] = e
            finally:
                done.set()

    def run(self, req: dict) -> dict:
        """Run one op under its hard deadline; raise _OpHung past it."""
        op = str(req.get("op") or "")
        deadline = _OP_DEADLINE_S.get(op, 240)
        if op == "decompile":
            deadline = int(req.get("timeout", 30)) + 15
        box: dict = {}
        done = threading.Event()
        self._requests.put((req, box, done))
        if not done.wait(deadline):
            raise _OpHung(
                f"op '{op}' exceeded {deadline}s hard deadline"
            )
        if "error" in box:
            raise box["error"]
        return box["result"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("socket_path")
    parser.add_argument("--idle-timeout", type=int, default=3600)
    args = parser.parse_args()

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(args.socket_path)
    srv.listen(1)
    srv.settimeout(args.idle_timeout)
    _log(f"listening on {args.socket_path}")

    session = _Session()
    handler = _HandlerThread(session)
    try:
        while True:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                _log("idle timeout — exiting")
                return 0
            # An accepted socket is blocking regardless of the
            # listener's timeout — an idle-but-connected (or wedged)
            # parent would otherwise hold this JVM worker alive
            # forever. The same idle budget applies per read.
            conn.settimeout(args.idle_timeout)
            try:
                with conn, conn.makefile("rwb") as stream:
                    for line in stream:
                        try:
                            req = json.loads(line)
                        except json.JSONDecodeError as e:
                            resp = {"id": None, "ok": False,
                                    "error": f"bad request: {e}"}
                            stream.write(
                                (json.dumps(resp) + "\n").encode())
                            stream.flush()
                            continue
                        if req.get("op") == "shutdown":
                            resp = {"id": req.get("id"), "ok": True,
                                    "bye": True}
                            stream.write(
                                (json.dumps(resp) + "\n").encode())
                            stream.flush()
                            return 0
                        try:
                            result = handler.run(req)
                            resp = {"id": req.get("id"), "ok": True,
                                    **result}
                        except _OpHung as e:
                            # Answer, then die: the wedged JVM thread
                            # cannot be cancelled, so a fresh worker is
                            # the only recoverable state. The parent sees
                            # the connection drop and may restart.
                            _log(f"watchdog: {e} — exiting")
                            resp = {"id": req.get("id"), "ok": False,
                                    "error": f"worker watchdog: {e}",
                                    "worker_exiting": True}
                            try:
                                stream.write(
                                    (json.dumps(resp) + "\n").encode())
                                stream.flush()
                            except (OSError, ValueError):
                                # ValueError: write on a closed makefile.
                                pass
                            os._exit(_WATCHDOG_EXIT_CODE)
                        except BaseException as e:  # noqa: BLE001 — one channel
                            _log(traceback.format_exc())
                            resp = {"id": req.get("id"), "ok": False,
                                    "error": f"{type(e).__name__}: {e}"}
                        stream.write((json.dumps(resp) + "\n").encode())
                        stream.flush()
            except socket.timeout:
                _log("idle timeout on connection — exiting")
                return 0
    finally:
        session.close()


if __name__ == "__main__":
    sys.exit(main())
