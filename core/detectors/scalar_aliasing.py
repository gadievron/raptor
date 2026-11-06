"""Conservative C scalar-access proofs over a frozen compiler-parsed view.

Only straight-line functions with initialized builtin scalar objects and
unescaped local pointer aliases are supported. Casts are not accesses. Unknown
syntax, branches, calls, qualifiers, typedefs and attributes refuse the whole
function; absence of a proof never establishes safety.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import tempfile
from typing import Any

from core.atomic_fs import write_bytes_atomically
from core.run.scratch import scratch_dir
from core.source import read_text_capped, split_lines

from .budget import WorkBudget

RULE_ID = "raptor.compiler.incompatible-scalar-access"
_INTEGER_TYPES = frozenset({"short", "unsigned short", "int", "unsigned int",
                            "long", "unsigned long", "long long", "unsigned long long"})
_FLOAT_TYPES = frozenset({"float", "double", "long double"})
_SCALARS = _INTEGER_TYPES | _FLOAT_TYPES
_MAX_SOURCE_BYTES = 1024 * 1024
_MAX_AST_BYTES = 8 * 1024 * 1024
_MAX_NODES = 50000


class _Unsupported(ValueError):
    pass


@dataclass(frozen=True)
class _Object:
    ctype: str
    name: str


@dataclass(frozen=True)
class _Pointer:
    pointee: str
    obj: _Object
    cast: tuple[int, int] | None = None
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Place:
    ctype: str
    obj: _Object
    pointer: _Pointer | None = None


@dataclass(frozen=True)
class _Scalar:
    ctype: str


def _type(node):
    info = node.get("type", {})
    if not isinstance(info, dict) or set(info) != {"qualType"}:
        raise _Unsupported("non-builtin or qualified type")
    return info["qualType"]


def _name(node):
    name = node.get("name", "")
    if not isinstance(name, str) or not name or len(name) > 256:
        raise _Unsupported("identifier cap")
    return name


def _scalar_type(node):
    ctype = _type(node)
    if ctype not in _SCALARS:
        raise _Unsupported("non-scalar type")
    return ctype


def _offset(node, end=False):
    value = node.get("range", {}).get("end" if end else "begin", {}).get("offset")
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _Unsupported("missing physical offset")
    return value


class _Function:
    def __init__(self, node):
        self.node = node
        self.variables: dict[str, _Place | _Pointer] = {}
        self.proofs: list[dict[str, Any]] = []

    def access(self, place, node):
        if not isinstance(place, _Place):
            raise _Unsupported("unknown access")
        # Corresponding signed and unsigned integer types may alias.
        if place.ctype.removeprefix("unsigned ") == place.obj.ctype.removeprefix("unsigned "):
            return
        if place.pointer is None or place.pointer.cast is None:
            raise _Unsupported("unknown pointer provenance")
        self.proofs.append({
            "offset": _offset(node), "cast": place.pointer.cast,
            "object": place.obj.name, "declared_type": place.obj.ctype,
            "access_type": place.ctype, "function": _name(self.node),
            "identifiers": [place.obj.name, *place.pointer.aliases],
        })

    def expression(self, node, depth=0):
        if depth > 64:
            raise _Unsupported("expression depth cap")
        kind, children = node.get("kind"), node.get("inner", [])
        if kind in ("IntegerLiteral", "FloatingLiteral"):
            return _Scalar(_scalar_type(node))
        if kind == "DeclRefExpr":
            key = node.get("referencedDecl", {}).get("id")
            if key not in self.variables:
                raise _Unsupported("non-local object")
            return self.variables[key]
        if kind == "ParenExpr" and len(children) == 1:
            return self.expression(children[0], depth + 1)
        if kind in ("ImplicitCastExpr", "CStyleCastExpr") and len(children) == 1:
            value = self.expression(children[0], depth + 1)
            cast = node.get("castKind")
            if kind == "ImplicitCastExpr" and cast == "LValueToRValue":
                if isinstance(value, _Place):
                    self.access(value, node)
                    return _Scalar(_scalar_type(node))
                if isinstance(value, _Pointer) and _type(node) == value.pointee + " *":
                    return value
                raise _Unsupported("unknown lvalue conversion")
            target = _type(node)
            if isinstance(value, _Pointer) and cast in ("BitCast", "NoOp"):
                if not target.endswith(" *") or target[:-2] not in _SCALARS:
                    raise _Unsupported("non-builtin pointer cast")
                return _Pointer(target[:-2], value.obj, (_offset(node), _offset(node, True)), value.aliases)
            if isinstance(value, _Scalar) and target in _SCALARS and cast in (
                "NoOp", "IntegralCast", "IntegralToFloating",
            ):
                return _Scalar(target)
            raise _Unsupported("unsupported conversion")
        if kind == "UnaryOperator" and len(children) == 1:
            opcode = node.get("opcode")
            value = self.expression(children[0], depth + 1)
            if opcode == "&" and isinstance(value, _Place) and value.pointer is None:
                return _Pointer(value.ctype, value.obj)
            if opcode == "*" and isinstance(value, _Pointer):
                # Forming an lvalue does not load it: only LValueToRValue or a
                # supported assignment calls access(). This excludes &* / sizeof.
                return _Place(value.pointee, value.obj, value)
            if opcode in ("+", "-") and isinstance(value, _Scalar):
                return _Scalar(_scalar_type(node))
        raise _Unsupported("unsupported expression")

    def run(self):
        children = self.node.get("inner", [])
        bodies = [n for n in children if n.get("kind") == "CompoundStmt"]
        if len(bodies) != 1:
            return []
        for node in children:
            kind = node.get("kind")
            if kind == "ParmVarDecl":
                if node.get("inner"):
                    raise _Unsupported("parameter attributes")
                obj = _Object(_scalar_type(node), _name(node))
                self.variables[node["id"]] = _Place(obj.ctype, obj)
            elif kind != "CompoundStmt":
                raise _Unsupported("function attributes")
        for stmt in bodies[0].get("inner", []):
            kind, nodes = stmt.get("kind"), stmt.get("inner", [])
            if kind == "DeclStmt":
                for decl in nodes:
                    init = decl.get("inner", [])
                    if decl.get("kind") != "VarDecl" or len(init) != 1 or decl.get("storageClass"):
                        raise _Unsupported("unsupported declaration")
                    value = self.expression(init[0])
                    ctype = _type(decl)
                    if isinstance(value, _Pointer) and ctype == value.pointee + " *":
                        if len(value.aliases) >= 16:
                            raise _Unsupported("pointer alias chain cap")
                        self.variables[decl["id"]] = _Pointer(value.pointee, value.obj, value.cast,
                                                             (*value.aliases, _name(decl)))
                    elif isinstance(value, _Scalar) and ctype in _SCALARS:
                        self.variables[decl["id"]] = _Place(ctype, _Object(ctype, _name(decl)))
                    else:
                        raise _Unsupported("unknown initializer")
            elif kind == "ReturnStmt" and len(nodes) <= 1:
                if nodes:
                    value = self.expression(nodes[0])
                    if isinstance(value, _Place):
                        raise _Unsupported("unconverted return lvalue")
                break  # Never inspect statements after a return.
            elif kind == "BinaryOperator" and stmt.get("opcode") == "=" and len(nodes) == 2:
                value = self.expression(nodes[1])
                place = self.expression(nodes[0])
                if (isinstance(value, _Pointer) and isinstance(place, _Pointer)
                        and nodes[0].get("kind") == "DeclRefExpr"
                        and value.pointee == place.pointee):
                    reference = nodes[0]["referencedDecl"]
                    aliases = tuple(dict.fromkeys((*value.aliases, _name(reference))))
                    if len(aliases) > 16:
                        raise _Unsupported("pointer alias chain cap")
                    # Replace this variable's immutable pointer value only;
                    # aliases copied earlier retain their original provenance.
                    self.variables[reference["id"]] = _Pointer(value.pointee, value.obj, value.cast, aliases)
                elif isinstance(value, _Scalar) and isinstance(place, _Place) and place.pointer is not None:
                    self.access(place, nodes[0])
                else:
                    raise _Unsupported("unsupported assignment")
            else:
                raise _Unsupported("non-straight-line function")
        return self.proofs


def scalar_access_proofs(ast: Any, source: bytes) -> list[dict[str, Any]]:
    """Return narrow language-level access proofs, never a clean verdict."""
    if len(source) > _MAX_SOURCE_BYTES or not isinstance(ast, dict):
        raise _Unsupported("source/AST cap")
    pending = [(ast, 0)]
    count = 0
    proofs: list[dict[str, Any]] = []
    functions: list[dict[str, Any]] = []
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > _MAX_NODES or depth > 128 or not isinstance(node, dict):
            raise _Unsupported("AST shape/cap")
        children = node.get("inner", [])
        if not isinstance(children, list):
            raise _Unsupported("AST children")
        # Every queued child will consume a node. Refuse a known overflow
        # before allocating one pending tuple per child of a wide AST node.
        if count + len(pending) + len(children) > _MAX_NODES:
            raise _Unsupported("AST shape/cap")
        if node.get("kind") == "FunctionDecl":
            functions.append(node)
        pending.extend((child, depth + 1) for child in children)
    for node in functions:
        try:
            found = _Function(node).run()
            for proof in found:
                start, end = proof["cast"]
                offset = proof["offset"]
                if not (0 <= start <= end < len(source) and 0 <= offset < len(source)):
                    raise _Unsupported("offset outside source")
            proofs.extend(found)
        except (_Unsupported, KeyError, TypeError, AttributeError, RecursionError):
            pass
        if len(proofs) > 256:
            raise _Unsupported("scalar access proof cap")
    # Only proof locations need line numbers. Count disjoint byte spans in
    # offset order rather than retaining an integer for every source newline.
    locations = sorted({offset for proof in proofs
                        for offset in (*proof["cast"], proof["offset"])})
    lines: dict[int, int] = {}
    cursor = 0
    line = 1
    for offset in locations:
        line += source.count(b"\n", cursor, offset + 1)
        cursor = offset + 1
        lines[offset] = line
    for proof in proofs:
        start, end = proof.pop("cast")
        offset = proof.pop("offset")
        proof.update(line=lines[offset], cast_start=lines[start], cast_end=lines[end])
    return proofs


@dataclass
class AliasingResult:
    complete: bool = False
    proofs: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def corroborate_aliasing(target: Path, tu: str, candidates: list[dict[str, Any]], *,
                        gcc: str | None, clang: str | None, sandbox_run,
                        budget: WorkBudget, setup=None, include_dirs_memo=None,
                        scratch_root: str | None = None, preprocessor: tuple[str, ...] | None = None) -> AliasingResult:
    """Preprocess once with GCC, parse once with Clang; neither runs target code."""
    from core.audit.preprocessor_view import expand_translation_unit
    from core.audit.compiler_sweep import _l2_file_scan
    from core.audit._util import safe_join
    from core.audit.source_view import sanitized_view

    result = AliasingResult()
    if not gcc or not clang or Path(tu).suffix != ".c":
        result.limitations.append("scalar aliasing corroboration requires GCC, Clang and a C translation unit")
        return result
    try:
        with scratch_dir("scalar_aliasing_", dir=scratch_root) as scratch:
            view = expand_translation_unit(
                target_path=target, file_path=tu, out_dir=scratch,
                preprocessor=preprocessor or (gcc, "-fanalyzer", "-fstrict-aliasing", "-Wstrict-aliasing=1", "-E", "-x", "c"),
                timeout=budget.remaining(), setup=setup, include_dirs_memo=include_dirs_memo,
            )
            source = view.text.encode("utf-8")
            def alias_exception(text, filename):
                if not any(token in text for token in ("optimize", "may_alias")):
                    return False
                code = sanitized_view(text, filename)
                return any(token in code for token in ("optimize", "may_alias"))
            if (not view.ok or len(source) > _MAX_SOURCE_BYTES
                    or alias_exception(view.text, tu)
                    or any(line.lstrip().startswith("#") for line in split_lines(view.text))):
                raise _Unsupported("preprocessed view unavailable, over cap, or contains directives")
            # Marker names are target-controlled. Retain every entered source
            # file (even a header emitting only #line), then refuse raw location
            # redirects rather than using them as proof attribution.
            if not view.source_files or len(view.source_files) > 64:
                raise _Unsupported("source provenance cap")
            remaining = _MAX_SOURCE_BYTES
            for name in view.source_files:
                original = safe_join(target, name)
                raw = read_text_capped(original, max_chars=min(remaining, 256 * 1024)) if original else None
                if raw is None or raw[1]:
                    raise _Unsupported("source provenance unavailable")
                remaining -= len(raw[0])
                scan = _l2_file_scan(raw[0])
                if remaining < 0 or scan.witness or scan.linemarkers:
                    raise _Unsupported("source redirects or suppression")
                if alias_exception(raw[0], name):
                    raise _Unsupported("compiler-specific aliasing exception")
            path = scratch / "view.c"
            write_bytes_atomically(path, source)
            with tempfile.TemporaryFile(dir=scratch) as output, tempfile.TemporaryFile(dir=scratch) as errors:
                proc = budget.runner(sandbox_run)(
                    [clang, "-fsyntax-only", "-x", "c", "-Xclang", "-ast-dump=json", str(path)],
                    block_network=True, target=str(scratch), output=str(scratch), cwd=str(scratch),
                    stdout=output, stderr=errors, timeout=30, caller_label="compiler-aliasing",
                    limits={"memory_mb": 1024, "max_file_mb": 8, "cpu_seconds": 30},
                )
                output.seek(0)
                payload = output.read(_MAX_AST_BYTES + 1)
            if proc.returncode != 0 or len(payload) > _MAX_AST_BYTES:
                raise _Unsupported("Clang AST failed or exceeded its output cap")
            proofs = scalar_access_proofs(json.loads(payload), source)
            candidate_points = {(c["file"], c["line"]) for c in candidates}
            for proof in proofs:
                origin = view.origin_of(proof["line"])
                if origin is None:
                    continue
                # A cast can span lines; bound this attribution work too.
                if proof["cast_end"] - proof["cast_start"] > 16:
                    continue
                cast_origins = {view.origin_of(line) for line in range(proof["cast_start"], proof["cast_end"] + 1)}
                matched = {point for point in cast_origins if point is not None
                           and point in candidate_points and point[0] == origin[0]}
                for point in sorted(matched):
                    if len(result.proofs) >= 256:
                        raise _Unsupported("attributed scalar proof cap")
                    public_proof = {key: value for key, value in proof.items()
                                    if key not in ("cast_start", "cast_end")}
                    result.proofs.append({**public_proof, "file": origin[0], "line": origin[1],
                                          "candidate_line": point[1]})
        result.complete = True
    except Exception as exc:  # a failed corroborator cannot erase raw candidates
        result.proofs.clear()
        detail = str(exc) if isinstance(exc, _Unsupported) else type(exc).__name__
        result.limitations.append(f"scalar aliasing corroboration unavailable: {detail}")
    return result
