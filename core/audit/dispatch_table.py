"""Dispatch-table capability displacement detection.

Finds permission checks that only appear in setup/init functions
while dispatch-table members (per-operation entry points) skip them.

The key insight: functions registered in ops tables (file_operations,
proto_ops, route decorators, ioctl switches) are *definitionally*
per-operation.  When a subsystem's capability checks appear only
outside these dispatch members, the check is temporally displaced —
the permission was verified at setup time but operations run later,
potentially under different credentials.

This is approach A from the design: dispatch-table membership is a
mechanical signal (a grep, not a heuristic), not a name-based
lifecycle classification.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

_OPS_TABLE_PATTERNS = [
    # C kernel: struct file_operations, proto_ops, etc.
    re.compile(
        r"\.\s*(?:read|write|open|release|ioctl|unlocked_ioctl|poll|mmap"
        r"|recvmsg|sendmsg|connect|accept|bind|listen|setsockopt|getsockopt"
        r"|show|store|probe|remove|suspend|resume"
        r"|ndo_open|ndo_stop|ndo_start_xmit"
        r")\s*=\s*(\w+)",
    ),
    # C: explicit function pointer table assignment
    re.compile(
        r"\.(?:cmd_func|handler|callback|dispatch|execute|process"
        r"|do_ioctl|compat_ioctl)\s*=\s*(\w+)",
    ),
]

_IOCTL_CASE_RE = re.compile(
    r"case\s+\w+\s*:.*?(?:return\s+)?(\w+)\s*\(",
)

_CAPABILITY_PATTERNS = [
    # Linux kernel
    re.compile(r"\bcapable\s*\(\s*(CAP_\w+)\s*\)"),
    re.compile(r"\bns_capable\s*\([^,]+,\s*(CAP_\w+)\s*\)"),
    re.compile(r"\bhas_capability\s*\([^,]+,\s*(CAP_\w+)\s*\)"),
    # Generic permission/auth checks
    re.compile(r"\bcheck_permission\s*\(\s*[\"'](\w+)[\"']\s*\)"),
    re.compile(r"\brequire_capability\s*\(\s*([\w.]+)\s*\)"),
    # POSIX
    re.compile(r"\bprctl\s*\(\s*(PR_CAP\w+)"),
]


@dataclass
class DispatchMember:
    """A function registered in an ops/dispatch table."""
    name: str
    file: str
    table_field: str = ""


@dataclass
class CapabilityDisplacement:
    """A capability check that appears only outside dispatch members."""
    capability: str
    check_functions: list = field(default_factory=list)
    dispatch_members_without: list = field(default_factory=list)
    file: str = ""

    @property
    def description(self) -> str:
        checkers = ", ".join(self.check_functions[:3])
        missing = ", ".join(self.dispatch_members_without[:3])
        n_missing = len(self.dispatch_members_without)
        suffix = f" (+{n_missing - 3} more)" if n_missing > 3 else ""
        return (
            f"{self.capability} checked in {checkers} "
            f"but not in dispatch member(s) {missing}{suffix}"
        )


def find_dispatch_members(
    gaps: Sequence[dict[str, Any]],
) -> dict[str, list[DispatchMember]]:
    """Find functions registered in ops/dispatch tables.

    Scans all gaps for struct ops assignments and ioctl case
    dispatch patterns.  Returns a dict keyed by file path.
    """
    members_by_file: dict[str, list[DispatchMember]] = {}

    file_sources: dict[str, str] = {}
    func_files: dict[str, str] = {}
    for gap in gaps:
        f = gap.get("file", "")
        name = gap.get("name", "")
        source = gap.get("source", "")
        if f and name:
            func_files[name] = f
        if f and source:
            file_sources[f] = file_sources.get(f, "") + "\n" + source

    all_func_names = set(func_files.keys())

    for file_path, full_source in file_sources.items():
        members: list[DispatchMember] = []
        seen: set[str] = set()

        for pat in _OPS_TABLE_PATTERNS:
            for m in pat.finditer(full_source):
                name = m.group(1)
                if name in all_func_names and name not in seen:
                    seen.add(name)
                    members.append(DispatchMember(
                        name=name,
                        file=func_files.get(name, file_path),
                        table_field=m.group(0).split("=")[0].strip().lstrip(".").strip(),
                    ))

        for m in _IOCTL_CASE_RE.finditer(full_source):
            name = m.group(1)
            if name in all_func_names and name not in seen:
                seen.add(name)
                members.append(DispatchMember(
                    name=name,
                    file=func_files.get(name, file_path),
                    table_field="ioctl_case",
                ))

        if members:
            members_by_file[file_path] = members

    return members_by_file


@dataclass
class DispatchTableRecord:
    """One dispatch table in the shape the peer-group resolver's L2
    layer consumes (``handlers`` values are the member functions)."""

    file: str
    function: str
    handlers: dict[str, str] = field(default_factory=dict)


def build_dispatch_tables(
    gaps: Sequence[dict[str, Any]],
) -> list[DispatchTableRecord]:
    """Producer for ``resolve_peer_groups(dispatch_tables=…)`` (L2).

    The resolver's L2 layer previously had no producer at the prep
    call site — dispatch-site peer groups never formed. One record
    per file with registered members; the table field (``.read =``,
    ``ioctl_case``) keys each handler.
    """
    tables: list[DispatchTableRecord] = []
    for file_path, members in sorted(find_dispatch_members(gaps).items()):
        handlers: dict[str, str] = {}
        for m in members:
            key = m.table_field or m.name
            candidate = key
            suffix = 2
            while candidate in handlers:
                candidate = f"{key}#{suffix}"
                suffix += 1
            handlers[candidate] = m.name
        if len(handlers) >= 2:
            tables.append(DispatchTableRecord(
                file=file_path,
                function=PurePosixPath(file_path).stem,
                handlers=handlers,
            ))
    return tables


def find_capability_checks(
    gaps: Sequence[dict[str, Any]],
) -> dict[str, dict[str, list[str]]]:
    """Find capability/permission checks per function.

    Returns {file: {function_name: [capability, ...]}}.
    """
    result: dict[str, dict[str, list[str]]] = {}

    for gap in gaps:
        f = gap.get("file", "")
        name = gap.get("name", "")
        source = gap.get("source", "")
        if not (f and name and source):
            continue

        caps: list[str] = []
        for pat in _CAPABILITY_PATTERNS:
            for m in pat.finditer(source):
                cap = m.group(1)
                if cap not in caps:
                    caps.append(cap)

        if caps:
            result.setdefault(f, {})[name] = caps

    return result


def check_capability_displacement(
    gaps: Sequence[dict[str, Any]],
    *,
    min_dispatch_members: int = 2,
) -> list[CapabilityDisplacement]:
    """Detect temporally displaced capability checks.

    A capability is "displaced" when:
    1. It is checked in at least one function in the file
    2. That function is NOT a dispatch-table member
    3. At least one dispatch-table member in the same file
       does NOT check it (and none of the dispatch members do)

    Returns a list of displacements found.
    """
    dispatch_by_file = find_dispatch_members(gaps)
    caps_by_file = find_capability_checks(gaps)

    results: list[CapabilityDisplacement] = []

    for file_path, members in dispatch_by_file.items():
        if len(members) < min_dispatch_members:
            continue

        file_caps = caps_by_file.get(file_path, {})
        if not file_caps:
            continue

        member_names = {m.name for m in members}

        non_member_caps: dict[str, list[str]] = {}
        for func_name, caps in file_caps.items():
            if func_name not in member_names:
                for cap in caps:
                    non_member_caps.setdefault(cap, []).append(func_name)

        if not non_member_caps:
            continue

        member_caps: dict[str, set[str]] = {}
        for func_name, caps in file_caps.items():
            if func_name in member_names:
                for cap in caps:
                    member_caps.setdefault(cap, set()).add(func_name)

        for cap, checker_funcs in non_member_caps.items():
            members_with_cap = member_caps.get(cap, set())
            members_without = [
                m.name for m in members if m.name not in members_with_cap
            ]
            if not members_without:
                continue
            if members_with_cap:
                # Some dispatch members DO check — not a displacement,
                # just inconsistent (existing negative-space handles this)
                continue

            results.append(CapabilityDisplacement(
                capability=cap,
                check_functions=checker_funcs,
                dispatch_members_without=members_without,
                file=file_path,
            ))

    return results


def format_displacement_context(
    displacements: list[CapabilityDisplacement],
) -> str | None:
    """Format displacements for injection into the LLM review context."""
    if not displacements:
        return None

    parts = ["[Capability displacement analysis]"]
    for d in displacements:
        parts.append(f"  - {d.description}")
    return "\n".join(parts)
