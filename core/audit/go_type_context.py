"""Bounded Go type declarations and their source documentation for review."""

from __future__ import annotations

from heapq import nsmallest
from pathlib import Path
import re

from core.source import read_bytes_capped
from core.source.lines import split_lines


_MAX_FILES = 20
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_TOTAL_BYTES = 4 * 1024 * 1024
_MAX_TYPE_LINES = 50
_MAX_TYPE_CHARS = 2400
_PREDECLARED = frozenset("""any bool byte comparable complex64 complex128 error
float32 float64 int int8 int16 int32 int64 rune string uint uint8 uint16
uint32 uint64 uintptr""".split())


def _type_names(tree, data: bytes) -> list[str]:
    local_parameters = set()
    for declaration in tree.root_node.named_children:
        parameters = declaration.child_by_field_name("type_parameters")
        if parameters is not None:
            for parameter in parameters.named_children:
                for child in parameter.named_children:
                    if child.type in ("identifier", "type_identifier"):
                        local_parameters.add(data[child.start_byte:child.end_byte].decode("utf-8", "replace"))
        receiver = declaration.child_by_field_name("receiver")
        pending = [receiver] if receiver is not None else []
        while pending:
            node = pending.pop()
            if node.type == "type_arguments":
                arguments = list(node.named_children)
                while arguments:
                    child = arguments.pop()
                    if child.type == "type_identifier":
                        local_parameters.add(data[child.start_byte:child.end_byte].decode("utf-8", "replace"))
                    arguments.extend(child.named_children)
            pending.extend(node.named_children)
    names = []
    stack = [tree.root_node]
    visited = 0
    while stack and visited < 8192:
        node = stack.pop()
        visited += 1
        if node.type == "qualified_type":
            continue  # A same-named local type is not an imported type.
        if node.type == "type_identifier":
            name = data[node.start_byte:node.end_byte].decode("utf-8", "replace")
            if name not in _PREDECLARED and name not in local_parameters and name not in names:
                names.append(name)
        stack.extend(reversed(node.named_children))
    return names


def _package(tree, data: bytes) -> str | None:
    for node in tree.root_node.named_children:
        if node.type == "package_clause" and node.named_children:
            package = node.named_children[-1]
            return data[package.start_byte:package.end_byte].decode("utf-8", "replace")
    return None


def _definitions(tree, data: bytes, text: str) -> dict[str, tuple[dict, list[str]]]:
    lines = split_lines(text)
    definitions: dict[str, tuple[dict, list[str]]] = {}
    for declaration in tree.root_node.named_children:
        if declaration.type != "type_declaration":
            continue
        specs = [node for node in declaration.named_children if node.type in ("type_spec", "type_alias")]
        for node in specs:
            name_node = node.child_by_field_name("name")
            if name_node is None or node.has_error:
                continue
            name = data[name_node.start_byte:name_node.end_byte].decode("utf-8", "replace")
            excerpt_node = declaration if len(specs) == 1 else node
            first = excerpt_node.start_point.row
            last = excerpt_node.end_point.row
            for _ in range(8):
                if first <= 0 or not lines[first - 1].lstrip().startswith("//"):
                    break
                first -= 1
            end = min(last + 1, first + _MAX_TYPE_LINES)
            excerpt = "\n".join(lines[first:end])
            truncated = end < last + 1 or len(excerpt) > _MAX_TYPE_CHARS
            if truncated:
                marker = "\n// [type context truncated]"
                excerpt = (excerpt[:max(0, _MAX_TYPE_CHARS - len(marker))] + marker)[:_MAX_TYPE_CHARS]
            references = []
            underlying = node.child_by_field_name("type")
            if underlying is not None and underlying.type in ("type_identifier", "pointer_type", "generic_type"):
                stack = [underlying]
                while stack:
                    child = stack.pop()
                    if child.type == "qualified_type":
                        continue
                    if child.type == "type_identifier":
                        reference = data[child.start_byte:child.end_byte].decode("utf-8", "replace")
                        if reference not in _PREDECLARED:
                            references.append(reference)
                    stack.extend(reversed(child.named_children))
            definitions[name] = ({"name": name, "line": first + 1, "source": excerpt}, references)
    return definitions


def resolve_go_types(target_path: Path, file_path: str, metadata: dict, source: str,
                     max_types: int = 5) -> list[dict]:
    """Resolve local, same-package types; declarations remain hint context.

    Receiver types take priority. Named aliases can add their underlying
    declaration. Imported types, test-only siblings, unreadable files and
    unavailable grammars are conservatively omitted. No names or expected
    behavior come from evaluation data.
    """
    if max_types <= 0 or _MAX_FILES <= 0:
        return []
    from .callsite_consistency import parse_source_cached
    from .context import _safe_path

    anchor = _safe_path(target_path, file_path)
    if anchor is None:
        return []
    tree, language = parse_source_cached(file_path, source)
    if tree is None or language != "go":
        return []
    names = _type_names(tree, source.encode("utf-8", "replace"))
    owner = metadata.get("class_name", "")
    match = re.fullmatch(r"\*?([\w]+)(?:\[.*\])?", owner) if isinstance(owner, str) else None
    if match and match[1] not in _PREDECLARED:
        names = list(dict.fromkeys([match[1]] + names))
    if not names:
        return []

    def candidates():
        yield anchor
        siblings = (path for path in anchor.parent.glob("*.go")
                    if path != anchor and not path.name.endswith("_test.go"))
        yield from nsmallest(_MAX_FILES - 1, siblings, key=lambda p: p.name)

    remaining = _MAX_TOTAL_BYTES
    definitions: dict[str, tuple[dict, list[str]]] = {}
    package = None
    seen = set()
    results = []
    for candidate in candidates():
        if remaining <= 0:
            break
        path = _safe_path(target_path, str(candidate))
        if path is None:
            continue
        got = read_bytes_capped(path, min(remaining, _MAX_FILE_BYTES))
        if got is None:
            continue
        raw, truncated = got
        remaining -= len(raw)
        if truncated:
            continue
        text = raw.decode("utf-8", "replace")
        parsed, language = parse_source_cached(str(path), text)
        if parsed is None or language != "go":
            continue
        current_package = _package(parsed, text.encode("utf-8", "replace"))
        if candidate == anchor:
            package = current_package
        if package is None or current_package != package:
            continue
        for name, (definition, references) in _definitions(parsed, text.encode("utf-8", "replace"), text).items():
            definitions.setdefault(name, (definition | {"file": str(path.relative_to(target_path.resolve()))}, references))
        for name in names:
            if name in seen or name not in definitions:
                continue
            definition, references = definitions[name]
            results.append(definition)
            seen.add(name)
            names.extend(reference for reference in references if reference not in names)
            if len(results) >= max_types:
                return results
        if all(name in seen for name in names):
            break
    return results
