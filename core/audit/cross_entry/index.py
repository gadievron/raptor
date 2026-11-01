"""Typed access extraction with explicit uncertainty and bounded graph edges.

This is declaration-based resolution, not a C compiler or points-to solver.
Missing grammars and ambiguous declarations remain coverage gaps.
"""
from __future__ import annotations

import hashlib
import posixpath
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

from .model import Access, AccessIndex, Call, Function, Limits, Relation, digest


def walk(node: Any) -> Iterable[Any]:
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.named_children))


def text(node: Any, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace") if node is not None else ""


def declared_name(node: Any) -> Any:
    while node is not None:
        if node.type in {"identifier", "field_identifier", "type_identifier", "qualified_identifier"}:
            return node
        child = node.child_by_field_name("declarator")
        if child is None and node.type == "parenthesized_declarator" and len(node.named_children) == 1:
            child = node.named_children[0]
        node = child
    return None


def path(node: Any, src: bytes) -> tuple[str, str]:
    if node is None:
        return "", ""
    if node.type == "identifier":
        return text(node, src), ""
    if node.type == "field_expression":
        root, tail = path(node.child_by_field_name("argument"), src)
        member = text(node.child_by_field_name("field"), src)
        return root, ".".join(x for x in (tail, member) if x)
    if node.type in {"pointer_expression", "parenthesized_expression", "cast_expression", "subscript_expression"}:
        inner = node.child_by_field_name("argument") or node.child_by_field_name("value")
        if inner is None and node.named_children:
            inner = node.named_children[0]
        root, tail = path(inner, src)
        if node.type == "subscript_expression":
            tail += "[*]"
        return root, tail
    return "", ""


@dataclass
class Binding:
    name: str
    id: str
    type_id: str
    resolution: str
    start: int
    scope_start: int
    scope_end: int
    origin: str
    indirect: bool = False


class Types:
    def __init__(self, trees: dict[str, tuple[Any, bytes]], include_edges=None):
        self.tags: dict[str, list[tuple[str, int]]] = defaultdict(list)
        self.aliases: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self.visible: dict[str,set[str]] = {}
        includes: dict[str,set[str]] = defaultdict(set)
        for fp,(_,src) in trees.items():
            for name in re.findall(r'^\s*#\s*include\s*[<"]([^>"\n]+)[>"]',src.decode(errors="replace"),re.MULTILINE):
                options = [posixpath.normpath(posixpath.join(posixpath.dirname(fp),name)),name,"include/"+name]
                selected = (include_edges or {}).get(fp,{}).get(name)
                matches = [selected] if selected in trees else [p for p in options if p in trees]
                if matches:
                    includes[fp].add(matches[0])
        for fp in trees:
            seen = {fp}
            todo = [fp]
            while todo:
                current = todo.pop()
                for header in includes[current]-seen:
                    seen.add(header)
                    todo.append(header)
            self.visible[fp] = seen
        for fp, (tree, src) in trees.items():
            for n in walk(tree.root_node):
                if n.type in {"struct_specifier", "union_specifier", "class_specifier"}:
                    name = text(n.child_by_field_name("name"), src)
                    if name and n.child_by_field_name("body") is not None:
                        tag = n.type.split("_")[0] + " " + name
                        self.tags[tag].append((fp, n.start_byte))
                if n.type == "type_definition":
                    typ = text(n.child_by_field_name("type"), src).split("{")[0].strip()
                    for d in n.children_by_field_name("declarator"):
                        name = declared_name(d)
                        if name:
                            self.aliases[text(name, src)].append((fp, typ))

    def resolve(self, node: Any, fp: str, src: bytes) -> tuple[str, str]:
        typ = text(node, src).split("{")[0].strip()
        visited = set()
        while typ in self.aliases and typ not in visited:
            visited.add(typ)
            choices = [(f,t) for f,t in self.aliases[typ] if f in self.visible[fp]]
            local = [t for f, t in choices if f == fp]
            options = set(local or [t for _, t in choices])
            if len(options) != 1:
                return f"{fp}:unresolved:{typ}", "unresolved"
            typ = options.pop()
        if not typ.startswith(("struct ", "union ", "class ")) and fp.endswith((".cpp",".cc",".cxx",".hpp",".hh",".hxx")):
            candidates = [tag for tag in ("struct "+typ,"class "+typ,"union "+typ)
                          if any(f in self.visible[fp] for f,_ in self.tags.get(tag,[]))]
            if len(candidates) == 1:
                typ = candidates[0]
        if not typ.startswith(("struct ", "union ", "class ")):
            return f"{fp}:unresolved:{typ or '?'}", "unresolved"
        defs = [d for d in self.tags.get(typ, []) if d[0] in self.visible[fp]]
        local_defs = [d for d in defs if d[0] == fp]
        matches = local_defs or defs
        if len(matches) == 1:
            file, offset = matches[0]
            return f"{file}:{offset}:{typ}", "resolved"
        if not matches:
            # Explicit tag known, declaration identity unavailable. This is a
            # useful candidate group, never proof of type or object equality.
            return f"unresolved-tag:{typ}", "partial"
        return f"{fp}:ambiguous:{typ}", "unresolved"


def _bindings(fn: Any, fid: str, fp: str, src: bytes, types: Types) -> list[Binding]:
    bindings = []
    declarator = fn.child_by_field_name("declarator")
    signature = next((n for n in walk(declarator) if n.type == "function_declarator"),None)
    parameters = signature.child_by_field_name("parameters") if signature is not None else None
    for n in walk(fn):
        if n.type not in {"parameter_declaration", "declaration"}:
            continue
        # Nested callback parameters do not bind names in this function.
        if n.type == "parameter_declaration":
            if n.parent != parameters:
                continue
        typ, resolution = types.resolve(n.child_by_field_name("type"), fp, src)
        scope = n.parent
        while scope is not None and scope.type not in {"compound_statement", "function_definition", "for_statement"}:
            scope = scope.parent
        if scope is None:
            scope = fn
        for dec in n.children_by_field_name("declarator"):
            name_node = declared_name(dec)
            if name_node is None:
                continue
            name = text(name_node, src)
            value = dec.child_by_field_name("value")
            origin = text(value, src) or (f"parameter:{name}" if n.type == "parameter_declaration"
                                         else f"local:{fid}:{name_node.start_byte}")
            bindings.append(Binding(name, f"{fid}@{name_node.start_byte}", typ, resolution,
                                    name_node.start_byte, scope.start_byte, scope.end_byte, origin,
                                    any(c.type in {"pointer_declarator","reference_declarator","array_declarator"} for c in walk(dec))))
    return bindings


def _binding(bindings: list[Binding], name: str, pos: int) -> Binding | None:
    matches = [b for b in bindings if b.name == name and b.start <= pos and b.scope_start <= pos < b.scope_end]
    return max(matches, key=lambda b: (b.scope_start, b.start)) if matches else None


def _operation(node: Any, src: bytes) -> tuple[str, str]:
    cur = node
    indirect = False
    while cur.parent is not None and cur.parent.type in {"parenthesized_expression", "subscript_expression", "pointer_expression"}:
        if cur.parent.type == "pointer_expression" and text(cur.parent,src).lstrip().startswith("&"):
            return "address_escape", ""
        indirect |= cur.parent.type in {"subscript_expression","pointer_expression"}
        cur = cur.parent
    parent = cur.parent
    if parent is not None and parent.type == "update_expression":
        return "read_modify_write", ""
    if parent is not None and parent.type == "assignment_expression":
        lhs = parent.child_by_field_name("left")
        if lhs == cur:
            op = text(parent.child_by_field_name("operator"), src)
            operation = "indirect_write" if indirect and op == "=" else "direct_write" if op == "=" else "read_modify_write"
            return operation, text(parent.child_by_field_name("right"), src)
    if parent is not None and parent.type == "pointer_expression" and text(parent, src).lstrip().startswith("&"):
        return "address_escape", ""
    while parent is not None and parent.type not in {"compound_statement", "expression_statement", "return_statement"}:
        if parent.type == "argument_list":
            return "helper_argument", ""
        parent = parent.parent
    return "read", ""


def build_access_index(source_texts: dict[str, str], *, limits: Limits | None = None,
                       entry_points: Iterable[str] = (), include_edges=None) -> AccessIndex:
    from core.audit.callsite_consistency import parse_source_cached
    from core.audit.field_census import _classify_rhs_text
    from core.audit.ops_struct import extract_ops_registrations

    limits = limits or Limits()
    result = AccessIndex()
    start = time.monotonic()
    trees: dict[str, tuple[Any, bytes]] = {}
    used = 0
    for i, fp in enumerate(sorted(source_texts)):
        source = source_texts[fp]
        src = source.encode("utf-8", errors="replace")
        result.source_hashes[fp] = hashlib.sha256(src).hexdigest()
        if i >= limits.max_files or used + len(src) > limits.max_bytes or time.monotonic() - start > limits.scan_seconds:
            result.coverage["skipped"].append({"file": fp, "reason": "scan_budget"})
            continue
        used += len(src)
        tree, lang = parse_source_cached(fp, source)
        if tree is None or lang not in {"c", "cpp"}:
            result.coverage["skipped"].append({"file": fp, "reason": "unsupported_parser"})
            continue
        if tree.root_node.has_error:
            result.coverage["unresolved"].append({"file": fp, "reason": "parse_errors"})
        trees[fp] = tree, src
        result.coverage["files_scanned"].append(fp)

    types = Types(trees,include_edges)
    for fp,(tree,src) in trees.items():
        for n in walk(tree.root_node):
            if n.type in {"struct_specifier","union_specifier","class_specifier"} and n.child_by_field_name("body") is not None:
                tag = n.type.split("_")[0]+" "+text(n.child_by_field_name("name"),src)
                key = f"{fp}:{n.start_byte}:{tag}"
                result.declarations[key] = {"file":fp,"line":n.start_point[0]+1,"source":text(n,src)}
    globals_by_file: dict[str,list[Binding]] = defaultdict(list)
    header_globals: list[tuple[str,Binding]] = []
    for fp,(tree,src) in trees.items():
        for declaration in tree.root_node.named_children:
            if declaration.type != "declaration":
                continue
            if any(n.type == "function_declarator" for n in walk(declaration)):
                continue
            typ,resolution = types.resolve(declaration.child_by_field_name("type"),fp,src)
            static = any(n.type == "storage_class_specifier" and text(n,src) == "static" for n in declaration.children)
            for dec in declaration.children_by_field_name("declarator"):
                name = declared_name(dec)
                if name is None:
                    continue
                spelling = text(name,src)
                binding = Binding(spelling,f"global:{fp if static else 'external'}:{spelling}",typ,resolution,
                                  0,0,len(src),f"global:{fp if static else 'external'}:{spelling}",
                                  any(c.type in {"pointer_declarator","reference_declarator","array_declarator"} for c in walk(dec)))
                globals_by_file[fp].append(binding)
                result.declarations[binding.id] = {"file":fp,"line":declaration.start_point[0]+1,"source":text(declaration,src)}
                if fp.endswith((".h",".hpp",".hh")):
                    header_globals.append((fp,binding))
    by_name: dict[str, list[str]] = defaultdict(list)
    contexts = {}
    for fp, (tree, src) in trees.items():
        for fn in walk(tree.root_node):
            if fn.type != "function_definition":
                continue
            if time.monotonic()-start > limits.scan_seconds:
                result.coverage["truncated"].append("extraction_time_budget")
                break
            if len(result.functions) >= limits.max_functions:
                result.coverage["truncated"].append("function_budget")
                break
            declarator = fn.child_by_field_name("declarator")
            name = text(declared_name(declarator), src)
            if not name:
                continue
            fid = f"{fp}:{name}@{fn.start_byte}"
            visible_globals = []
            for header,b in header_globals:
                if header not in types.visible[fp] or header == fp:
                    continue
                bid = b.id if b.id.startswith("global:external:") else f"{b.id}:tu:{fp}"
                visible_globals.append(Binding(b.name,bid,b.type_id,b.resolution,0,0,len(src),bid,b.indirect))
                result.declarations[bid] = result.declarations[b.id]
            bindings = visible_globals + globals_by_file[fp] + _bindings(fn, fid, fp, src, types)
            body = text(fn, src)
            params = [b.name for b in bindings if b.origin.startswith("parameter:")]
            result.functions[fid] = Function(fid, fp, name, fn.start_point[0]+1,
                fn.end_point[0]+1, fn.start_byte, fn.end_byte, hashlib.sha256(body.encode()).hexdigest(),
                body, any(c.type == "storage_class_specifier" and text(c,src) == "static" for c in fn.children), params)
            by_name[name].append(fid)
            contexts[fid] = (fn,bindings)
            for node in walk(fn.child_by_field_name("body")):
                if time.monotonic()-start > limits.scan_seconds:
                    result.coverage["truncated"].append("extraction_time_budget")
                    break
                if len(result.accesses) >= limits.max_sites:
                    result.coverage["truncated"].append("site_budget")
                    break
                if node.type == "call_expression":
                    callee = text(node.child_by_field_name("function"), src)
                    args = node.child_by_field_name("arguments")
                    arguments = list(args.named_children) if args is not None else []
                    result.calls.append(Call(fid, callee, [text(a, src) for a in arguments], node.start_point[0]+1,
                                             start_byte=node.start_byte,end_byte=node.end_byte,
                                             argument_kinds=[a.type for a in arguments]))
                    # Whole-object arguments/escapes must survive even when no
                    # field_expression occurs (memset/free/replacement helpers).
                    for arg in arguments:
                        root, member = path(arg, src)
                        b = _binding(bindings, root, arg.start_byte)
                        if b and not member and (b.indirect or b.resolution != "unresolved" or text(arg,src).lstrip().startswith("&")):
                            if len(result.accesses) >= limits.max_sites:
                                result.coverage["truncated"].append("site_budget")
                                break
                            result.accesses.append(Access(f"{fid}:{arg.start_byte}:object",fid,fp,
                                arg.start_point[0]+1,arg.start_byte,arg.end_byte,b.type_id,b.id,"*",
                                "unresolved_effect",text(arg,src),resolution=b.resolution,object_origin=b.origin))
                    continue
                if node.type != "field_expression":
                    continue
                # Extract the complete outer field path once.
                if node.parent is not None and node.parent.type == "field_expression" and node.parent.child_by_field_name("argument") == node:
                    continue
                root, member = path(node, src)
                b = _binding(bindings, root, node.start_byte)
                op, rhs = _operation(node, src)
                result.accesses.append(Access(f"{fid}:{node.start_byte}",fid,fp,node.start_point[0]+1,
                    node.start_byte,node.end_byte,b.type_id if b else f"{fp}:unbound:{root}",
                    b.id if b else "",member,op,text(node,src),rhs,_classify_rhs_text(rhs,params) if rhs else "unknown",
                    b.resolution if b else "unresolved",b.origin if b else ""))

    def resolve(name: str, fp: str) -> list[str]:
        matches = by_name.get(name, [])
        local = [f for f in matches if result.functions[f].file == fp]
        headers = [f for f in matches if result.functions[f].file in types.visible.get(fp,set())]
        return local or headers or [f for f in matches if not result.functions[f].static]

    for call in result.calls:
        shadow = _binding(contexts[call.caller][1],call.name,call.start_byte)
        call.targets = [] if shadow else resolve(call.name, result.functions[call.caller].file)
        if len(call.targets) == 1:
            result.relations.append(Relation(call.caller,call.targets[0],"call",f"{result.functions[call.caller].file}:{call.line}","resolved"))
            target = result.functions[call.targets[0]]
            for argument,parameter in zip(call.arguments,target.params):
                result.relations.append(Relation(f"{call.caller}:{argument}",f"{target.id}:parameter:{parameter}",
                                                 "argument_binding",f"{result.functions[call.caller].file}:{call.line}","syntax"))
        else:
            result.coverage["unresolved"].append({"caller":call.caller,"symbol":call.name,"line":call.line,
                                                   "reason":"ambiguous_call" if call.targets else "unknown_call"})
    for fp, (tree, src) in trees.items():
        for reg in extract_ops_registrations(src.decode(errors="replace"), fp):
            targets = resolve(reg["function"], fp)
            if len(targets) == 1:
                result.entries.setdefault(targets[0], []).append(reg)
            else:
                result.coverage["unresolved"].append({"file":fp,"symbol":reg["function"],"reason":"unresolved_registration"})
    for key in sorted(set(entry_points)):
        for f in result.functions.values():
            if key == f"{f.file}:{f.name}":
                result.entries.setdefault(f.id, []).append({"source":"context_map"})

    from .dispatch import index_dispatch
    index_dispatch(result,trees,types,contexts,resolve,limits)

    # Typed expressions on both sides of an assignment nominate resource
    # transfers across types. These edges assert syntax, not points-to proof.
    expressions: dict[tuple[str, str], list[Access]] = defaultdict(list)
    for a in result.accesses:
        expressions[a.function, a.expression].append(a)
    for a in result.accesses:
        if not a.rhs:
            continue
        for b in expressions.get((a.function, a.rhs), []):
            if b.id != a.id:
                result.relations.append(Relation(a.type_id+":"+a.member_path,b.type_id+":"+b.member_path,
                                                 "resource_assignment",a.id))
    result.coverage["truncated"] = sorted(set(result.coverage["truncated"]))
    for typ in sorted({a.type_id for a in result.accesses if a.resolution != "resolved"}):
        result.coverage["unresolved"].append({"type_id":typ,"reason":"type_identity_unresolved"})
    result.coverage["complete"] = not any(result.coverage[k] for k in ("skipped","unresolved","truncated"))
    result.fingerprint = digest({"version":2,"sources":result.source_hashes,"limits":limits.content_settings(),
                                 "include_edges":include_edges,
                                 "entries":result.entries,"coverage":result.coverage})
    return result
