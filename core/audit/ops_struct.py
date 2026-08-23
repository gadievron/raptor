"""Extract function-pointer registrations from C struct initialisers.

Functions assigned via designated initialisers in ops-struct tables
(e.g. `.output = esp_output_head`) are reachable via indirect calls
but have no direct callers in a static call graph.  This module
identifies them so the reachability gate does not suppress findings.
"""

import re

_STRUCT_INIT_RE = re.compile(
    r"(?:static\s+)?(?:const\s+)?struct\s+(\w+)\s+\w+\s*=\s*\{"
)
_FIELD_ASSIGN_RE = re.compile(r"\.\s*(\w+)\s*=\s*(\w+)\s*,?\s*$")

_NON_FUNC_VALUES = frozenset({
    "NULL", "0", "1", "true", "false", "TRUE", "FALSE",
})


def extract_ops_registrations(
    source: str,
    file_path: str,
) -> list[dict[str, str]]:
    """Extract function-pointer registrations from struct initialisers.

    Returns a list of dicts with keys: struct_type, field, function, file.
    """
    registrations: list[dict[str, str]] = []
    in_initialiser = False
    struct_type = ""
    depth = 0

    for line in source.splitlines():
        stripped = line.strip()

        if not in_initialiser:
            m = _STRUCT_INIT_RE.match(stripped)
            if m:
                in_initialiser = True
                struct_type = m.group(1)
                depth = stripped.count("{") - stripped.count("}")
                continue
        else:
            depth += stripped.count("{") - stripped.count("}")
            if depth <= 0:
                in_initialiser = False
                struct_type = ""
                continue

            if depth > 1:
                continue

            m = _FIELD_ASSIGN_RE.match(stripped)
            if m:
                value = m.group(2)
                if value in _NON_FUNC_VALUES:
                    continue
                if value.isupper() and "_" in value:
                    continue
                registrations.append({
                    "struct_type": struct_type,
                    "field": m.group(1),
                    "function": value,
                    "file": file_path,
                })

    return registrations


def collect_ops_entry_points(
    source_texts: dict[str, str],
) -> set[str]:
    """Scan all source files for ops-struct registrations.

    Returns a set of "file:function" keys suitable for merging into
    the entry_points set.
    """
    entry_points: set[str] = set()
    for fp, src in source_texts.items():
        if not any(fp.endswith(ext) for ext in (".c", ".h", ".cpp", ".cc")):
            continue
        for reg in extract_ops_registrations(src, fp):
            entry_points.add(f"{fp}:{reg['function']}")
    return entry_points
