"""Line-preserving kernel syntax adaptation for definition boundaries only.

This view is never used as evidence for a bug or as the pinned source/hash.
Recognized compiler annotations and statement macros confuse the C grammar;
unknown or malformed syntax is retained so normal parse refusal still applies.
"""
from __future__ import annotations

import re
from typing import Any

_ANNOTATION = re.compile(r"\b(?:__always_inline|__sched|__user)\b")
_MACRO = re.compile(r"\b(?:list_for_each_entry_safe|list_for_each_entry|perf_event_groups_for_each|scoped_cond_guard|scoped_guard|container_of|__aligned)\s*\(")
_TAG_TYPE = re.compile(r"\s*(?:struct|union|enum)\s+[A-Za-z_]\w*\s*", re.ASCII)
_ALIGNMENT = re.compile(r"\s*(?:0[xX][0-9a-fA-F]+|[0-9]+|[A-Za-z_]\w*)\s*", re.ASCII)


def _blank(chars: list[str], start: int, end: int, prefix: str = "") -> None:
    for index in range(start, end):
        if chars[index] not in "\r\n":
            chars[index] = " "
    # Call identifiers and the first type token have enough same-line
    # space for the short replacement; never overwrite a line separator.
    for index, char in enumerate(prefix, start):
        if index >= end or chars[index] in "\r\n":
            raise ValueError("kernel syntax replacement crossed a source line")
        chars[index] = char


def _identifier_boundary(view: str, start: int, end: int) -> bool:
    adjacent = view[start - 1:start] if start else ""
    adjacent += view[end:end + 1]
    # C identifiers can contain non-ASCII continuation characters that
    # Python regex word boundaries do not classify identically.
    return all(char.isascii() and not (char.isalnum() or char == "_") for char in adjacent)


def _arguments(view: str, opening: int, budget: int) -> tuple[int, list[tuple[int, int]]] | None:
    stack = [")"]
    starts = opening + 1
    parts: list[tuple[int, int]] = []
    for index in range(opening + 1, min(len(view), opening + 1 + budget)):
        char = view[index]
        if char in "([{":
            stack.append({"(": ")", "[": "]", "{": "}"}[char])
        elif char in ")]}":
            if char != stack.pop():
                return None
            if not stack:
                return index + 1, [*parts, (starts, index)]
        elif char == "," and len(stack) == 1:
            parts.append((starts, index))
            starts = index + 1
    return None


def _valid_arguments(parser: Any, chars: list[str], parts: list[tuple[int, int]], action: int = -1) -> bool:
    statements = []
    for index, (start, end) in enumerate(parts):
        value = "".join(chars[start:end])
        if not value.strip():
            return False
        statements.append(value + ";" if index == action else "(void)(" + value + ");")
    probe = parser.parse(("void __raptor_pin_probe(void){" + "\n".join(statements) + "}").encode())
    return probe is not None and not probe.root_node.has_error


def kernel_parse_view(text: str, parser: Any) -> str:
    """Adapt a closed kernel syntax subset while keeping source line numbers.

    Arguments are balanced and parsed before a control macro is replaced.
    Consequently a recognized name cannot hide malformed arguments or body
    statements. Preprocessor directives, strings and comments are untouched.
    """
    from core.audit.source_view import _C_FAMILY_SPECS, _strip_c_family

    code = list(_strip_c_family(text, _C_FAMILY_SPECS["c"]))
    offset = 0
    continuation = False
    for line in text.splitlines(keepends=True):
        end = offset + len(line)
        directive = continuation or "".join(code[offset:end]).lstrip().startswith("#")
        if directive:
            _blank(code, offset, end)
        continuation = directive and line.rstrip("\r\n \t\v\f").endswith("\\")
        offset = end
    view = "".join(code)
    chars = list(text)
    for match in _ANNOTATION.finditer(view):
        if _identifier_boundary(view, match.start(), match.end()):
            _blank(chars, match.start(), match.end())
    calls = []
    budget = 4 * len(view)
    for match in _MACRO.finditer(view):
        name = view[match.start():match.end()].split("(", 1)[0].strip()
        if not _identifier_boundary(view, match.start(), match.start() + len(name)):
            continue
        arguments = _arguments(view, match.end() - 1, budget)
        if arguments is None:
            return text
        end, parts = arguments
        budget -= end - (match.end() - 1)
        calls.append((name, match.start(), end, parts))
    # Type-valued arguments and declaration annotations are handled first
    # so they can also appear within a control macro's expression arguments.
    for name, start, end, parts in calls:
        if name == "container_of" and len(parts) == 3:
            left, right = parts[1]
            if _TAG_TYPE.fullmatch(view[left:right]) and _valid_arguments(parser, chars, [parts[0], parts[2]]):
                token = next(index for index in range(left, right) if not view[index].isspace())
                _blank(chars, token, right, "0")
        elif name == "__aligned" and len(parts) == 1:
            left, right = parts[0]
            if _ALIGNMENT.fullmatch(view[left:right]):
                _blank(chars, start, end)
    for name, start, end, parts in calls:
        arity = {"list_for_each_entry": 3, "list_for_each_entry_safe": 4, "perf_event_groups_for_each": 2}.get(name)
        if arity is not None and len(parts) == arity and _valid_arguments(parser, chars, parts):
            _blank(chars, start, end, "if(1)")
        elif name == "scoped_guard" and len(parts) >= 2 and _valid_arguments(parser, chars, parts):
            _blank(chars, start, end, "if(1)")
        elif name == "scoped_cond_guard" and len(parts) >= 3 and _valid_arguments(parser, chars, parts, action=1):
            _blank(chars, start, end, "if(1)")
    return "".join(chars)
