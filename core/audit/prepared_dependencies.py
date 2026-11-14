"""Bounded declarations from one compiler-generated dependency rule.

These spellings establish neither dependency completeness nor filesystem,
currentness or measured-build authority. The capture owner must validate the
paths against its owned namespace and retain the actual compiler operation.
"""

from __future__ import annotations

import re


class DependencyOutputUnavailable(ValueError):
    """The single-rule compiler output cannot be consumed without ambiguity."""


def parse_dependency_output(raw: bytes, *, expected_target: str,
                            max_bytes: int, max_dependencies: int) -> tuple[str, ...]:
    """Parse a strict single-target ``-M -MT`` output, without interpreting Make.

    The target must be a capture-owned simple identifier. Prerequisites retain
    their exact decoded path spellings; there is no path normalisation or IO.
    Escaped whitespace, hash, colon and backslash, doubled dollars and physical
    line continuations are supported. Variables, extra rules, order-only rules
    and unsupported Make syntax refuse the entire result. The count budget
    applies before deduplication, including repeated prerequisites.
    """
    if (type(max_bytes) is not int or max_bytes < 1
            or type(max_dependencies) is not int or max_dependencies < 1):
        raise DependencyOutputUnavailable("invalid_dependency_budget")
    if (not isinstance(expected_target, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", expected_target) is None):
        raise DependencyOutputUnavailable("invalid_expected_target")
    if type(raw) is not bytes or len(raw) > max_bytes:
        raise DependencyOutputUnavailable("dependency_byte_budget")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise DependencyOutputUnavailable("dependency_encoding") from exc
    text = text.replace("\r\n", "\n")
    if any((ord(char) < 32 and char not in "\t\n") or ord(char) == 127 for char in text):
        raise DependencyOutputUnavailable("dependency_control_character")
    target_parts: list[str] = []
    dependencies: list[str] = []
    token: list[str] = []
    separator = False
    finished = False

    def finish_token() -> None:
        if not token:
            return
        value = "".join(token)
        token.clear()
        if separator:
            if len(dependencies) >= max_dependencies:
                raise DependencyOutputUnavailable("dependency_count_budget")
            dependencies.append(value)
        else:
            target_parts.append(value)
            if len(target_parts) > 1:
                raise DependencyOutputUnavailable("multiple_dependency_targets")

    index = 0
    while index < len(text):
        char = text[index]
        if char == "#":
            end = text.find("\n", index)
            if end >= 0 and text[index:end].endswith("\\"):
                raise DependencyOutputUnavailable("dependency_comment_continuation")
            index = len(text) if end < 0 else end
            continue
        if char in " \t\n":
            finish_token()
            if char == "\n" and separator:
                finished = True
            elif char == "\n" and target_parts:
                raise DependencyOutputUnavailable("dependency_rule_unavailable")
            index += 1
            continue
        if finished:
            raise DependencyOutputUnavailable("multiple_dependency_rules")
        if char == "\\":
            index += 1
            if index == len(text):
                raise DependencyOutputUnavailable("truncated_dependency_escape")
            escaped = text[index]
            if escaped == "\n":
                finish_token()
            elif escaped in " \t#:\\":
                token.append(escaped)
            else:
                raise DependencyOutputUnavailable("unsupported_dependency_escape")
        elif char == "$":
            index += 1
            if index == len(text) or text[index] != "$":
                raise DependencyOutputUnavailable("dependency_variable_expansion")
            token.append("$")
        elif char == ":":
            if separator:
                raise DependencyOutputUnavailable("extra_dependency_separator")
            finish_token()
            if target_parts != [expected_target]:
                raise DependencyOutputUnavailable("dependency_target_mismatch")
            separator = True
        elif char in ";|=*?[]%":
            raise DependencyOutputUnavailable("unsupported_dependency_syntax")
        else:
            token.append(char)
        index += 1
    finish_token()
    if not separator or not dependencies:
        raise DependencyOutputUnavailable("dependency_rule_unavailable")
    return tuple(dict.fromkeys(dependencies))
