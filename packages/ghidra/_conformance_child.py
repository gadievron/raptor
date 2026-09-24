"""Sandboxed child for decomp-tree tree-sitter conformance scans.

Executed as a NAMED script by path (``python -B <this file>
<tree-root>``) under ``core.sandbox.run`` — never in the parent
process: decomp-tree content is decompiled from the analysed binary,
so parsing it is exactly the class of hostile-bytes work the sandbox
exists for (a tree-sitter parser bug on crafted pseudo-C must not
own the audit process). Same named-script rationale as
:mod:`core.audit._json_child`: an on-disk script inside the RAPTOR
tree is attributable and auditable where an inline ``python -c`` blob
is not.

Protocol: ``argv[1]`` is the tree root; the JSON report leaves on
stdout — ``{"available": bool, "reason": str, "files": {name:
{"ok": bool, "reason": str}}}``. Import resolution self-anchors on
``__file__`` (the sanctioned pattern for path-executed scripts):
the sandbox deliberately strips ``RAPTOR_DIR`` from every child env
(a framework-identity tell to the target), so parent and child are
tied to the same tree by construction instead. ``sys.path[0]`` is
REPLACED so this package directory can never shadow stdlib modules.
"""

import json
import sys
from pathlib import Path as _Path

#: Per-file read ceiling. The emitter already bounds the WHOLE tree,
#: but one function block can legitimately dominate a file; above
#: this a file is reported as failed-for-measurement rather than
#: parsed (honest denominator), never silently skipped.
MAX_FILE_BYTES = 32 * 1024 * 1024
#: File-count ceiling — matches the parent's enumeration bound.
MAX_FILES = 4096


def scan_tree(root_path: str) -> dict:
    """Parse every tree file with tree-sitter C; per-file verdicts.

    ``ok`` means the parse produced a tree with no ERROR nodes
    (``root_node.has_error`` is false). Importable for direct tests;
    the sandbox wrapper in :mod:`packages.ghidra.decomp_conformance`
    is the production entry.
    """
    from pathlib import Path
    root = Path(root_path)
    try:
        from core.inventory.extractors import _ts_parser_for
        parser = _ts_parser_for("c")
    except Exception as exc:  # noqa: BLE001 — availability is the verdict
        return {"available": False,
                "reason": f"tree-sitter unavailable: {exc}",
                "files": {}}
    if parser is None:
        return {"available": False,
                "reason": "tree-sitter C grammar unavailable",
                "files": {}}

    names = sorted(p.name for p in root.glob("*.c") if p.is_file())
    if (root / "types.h").is_file():
        names.append("types.h")
    truncated = len(names) > MAX_FILES
    files: dict = {}
    for name in names[:MAX_FILES]:
        path = root / name
        try:
            size = path.stat().st_size
            if size > MAX_FILE_BYTES:
                files[name] = {
                    "ok": False,
                    "reason": f"over the {MAX_FILE_BYTES}-byte "
                              "per-file measurement cap",
                }
                continue
            src = path.read_bytes()
        except OSError as exc:
            files[name] = {"ok": False, "reason": f"unreadable: {exc}"}
            continue
        try:
            tree = parser.parse(src)
        except Exception as exc:  # noqa: BLE001 — a parser crash is the datum
            files[name] = {"ok": False,
                           "reason": f"tree-sitter parse raised: {exc}"}
            continue
        if tree is None or tree.root_node is None:
            files[name] = {"ok": False, "reason": "no parse tree"}
        elif tree.root_node.has_error:
            files[name] = {"ok": False,
                           "reason": "parse errors present "
                                     "(ERROR/MISSING nodes)"}
        else:
            files[name] = {"ok": True, "reason": ""}
    out = {"available": True, "reason": "", "files": files}
    if truncated:
        out["truncated"] = True
    return out


def main() -> None:
    sys.path[:1] = [str(_Path(__file__).resolve().parents[2])]
    sys.stdout.write(json.dumps(scan_tree(sys.argv[1]), default=str))


if __name__ == "__main__":
    main()
