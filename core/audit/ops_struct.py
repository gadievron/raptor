"""Extract function-pointer registrations from C struct initialisers.

Functions assigned via designated initialisers in ops-struct tables
(e.g. `.output = esp_output_head`) are reachable via indirect calls
but have no direct callers in a static call graph.  This module
identifies them so the reachability gate does not suppress findings.
"""

import re

#: Declaration line; the opening `{` may sit on the NEXT line
#: (`= \n {`), so it is optional here and tracked as pending.
_STRUCT_INIT_RE = re.compile(
    r"(?:static\s+)?(?:const\s+)?struct\s+(\w+)\s+\w+\s*=\s*(\{)?\s*$"
    r"|(?:static\s+)?(?:const\s+)?struct\s+(\w+)\s+\w+\s*=\s*\{"
)
#: One designated member. Deliberately NOT end-anchored and scanned
#: with finditer: the `$`-anchored single-member form missed `&func`
#: references, several members on one line, trailing comments, and
#: any member sharing the initialiser's closing line — each miss
#: silently dropped an indirect entry point from the reachability
#: exemption.
_FIELD_ASSIGN_RE = re.compile(r"\.\s*(\w+)\s*=\s*&?\s*([A-Za-z_]\w*)")

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
    pending_type = ""
    depth = 0

    def _scan_members(text: str) -> None:
        for fm in _FIELD_ASSIGN_RE.finditer(text):
            value = fm.group(2)
            if value in _NON_FUNC_VALUES:
                continue
            if value.isupper() and "_" in value:
                continue
            registrations.append({
                "struct_type": struct_type,
                "field": fm.group(1),
                "function": value,
                "file": file_path,
            })

    for line in source.splitlines():
        stripped = line.strip()

        if not in_initialiser:
            if pending_type:
                if stripped.startswith("{"):
                    in_initialiser = True
                    struct_type = pending_type
                    pending_type = ""
                    depth = stripped.count("{") - stripped.count("}")
                    _scan_members(stripped)
                    if depth <= 0:
                        in_initialiser = False
                        struct_type = ""
                    continue
                if stripped:
                    pending_type = ""
            m = _STRUCT_INIT_RE.match(stripped)
            if m:
                stype = m.group(1) or m.group(3) or ""
                if m.group(2) or m.group(3):
                    # `= {` on the declaration line (possibly with
                    # members, possibly closed on the same line).
                    in_initialiser = True
                    struct_type = stype
                    depth = stripped.count("{") - stripped.count("}")
                    _scan_members(stripped)
                    if depth <= 0:
                        in_initialiser = False
                        struct_type = ""
                else:
                    pending_type = stype
                continue
        else:
            # Scan BEFORE the depth update so a member on the
            # initialiser's closing line (`.last = final_fn };`) is
            # not skipped. Lines entered above depth 1 (inside a
            # nested initialiser spanning lines) stay skipped.
            if depth == 1:
                _scan_members(stripped)
            depth += stripped.count("{") - stripped.count("}")
            if depth <= 0:
                in_initialiser = False
                struct_type = ""

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
