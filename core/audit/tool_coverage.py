"""Maps vulnerability classes to the mechanical tools that can detect them.

Used by the gate-resolution pass to distinguish:
- "Tool covers this class + tool silent" → clean (disconfirmed)
- "No tool covers this class" → dark (tool-blind, needs human review)

When the coverage map is incomplete, the function defaults to dark —
failing in the conservative direction.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# CWE → tools that can mechanically detect that class.
#
# "prefilter" = RAPTOR's regex-based structural checks (fast, always on).
# "semgrep"   = Semgrep rules (taint mode when CodeQL is degraded).
# "codeql"    = CodeQL dataflow queries.
# "joern"     = Joern CPG queries.
# "coccinelle"= Coccinelle semantic patches.
# "smt"       = SMT solver (bounds feasibility).
#
# A class is "covered" if at least one tool in the set is available.
# Classes absent from this map are treated as uncovered (→ dark).
# ---------------------------------------------------------------------------

_CWE_TOOL_MAP: dict[str, frozenset[str]] = {
    # Memory corruption
    "CWE-120": frozenset({"prefilter", "codeql", "coccinelle"}),  # buffer overflow
    "CWE-122": frozenset({"prefilter", "codeql", "coccinelle"}),  # heap overflow
    "CWE-787": frozenset({"prefilter", "codeql", "coccinelle"}),  # OOB write
    "CWE-125": frozenset({"prefilter", "codeql"}),                # OOB read
    "CWE-416": frozenset({"prefilter", "codeql"}),                # use after free
    "CWE-415": frozenset({"prefilter", "codeql"}),                # double free
    "CWE-134": frozenset({"prefilter", "codeql", "coccinelle"}),  # format string
    "CWE-190": frozenset({"prefilter", "smt", "codeql"}),         # integer overflow
    "CWE-191": frozenset({"prefilter", "smt"}),                   # integer underflow
    "CWE-193": frozenset({"prefilter", "smt"}),                   # off-by-one
    "CWE-476": frozenset({"codeql", "coccinelle"}),               # null deref
    "CWE-362": frozenset({"coccinelle"}),                         # race condition
    "CWE-667": frozenset({"coccinelle"}),                         # improper locking

    # Injection
    "CWE-78":  frozenset({"prefilter", "semgrep", "codeql", "joern"}),  # OS command
    "CWE-77":  frozenset({"prefilter", "semgrep", "codeql", "joern"}),  # command injection
    "CWE-88":  frozenset({"prefilter", "semgrep", "codeql"}),           # argument injection
    "CWE-79":  frozenset({"prefilter", "semgrep", "codeql"}),           # XSS
    "CWE-89":  frozenset({"prefilter", "semgrep", "codeql", "joern"}),  # SQL injection
    "CWE-94":  frozenset({"prefilter", "semgrep", "codeql"}),           # code injection
    "CWE-95":  frozenset({"prefilter", "semgrep"}),                     # eval injection
    "CWE-917": frozenset({"semgrep", "codeql"}),                        # expression injection

    # Path / file
    "CWE-22":  frozenset({"prefilter", "semgrep", "codeql"}),     # path traversal
    "CWE-23":  frozenset({"prefilter", "semgrep", "codeql"}),     # relative path traversal
    "CWE-73":  frozenset({"prefilter", "semgrep"}),               # ext-controlled filename
    "CWE-367": frozenset({"prefilter"}),                          # TOCTOU

    # Deserialization / data handling
    "CWE-502": frozenset({"prefilter", "semgrep"}),               # deserialization
    "CWE-611": frozenset({"semgrep", "codeql"}),                  # XXE
    "CWE-776": frozenset({"semgrep"}),                            # XML entity expansion

    # Auth / crypto
    "CWE-798": frozenset({"semgrep"}),                            # hardcoded credentials
    "CWE-327": frozenset({"semgrep"}),                            # broken crypto
    "CWE-330": frozenset({"semgrep"}),                            # insufficient randomness
    "CWE-295": frozenset({"semgrep"}),                            # improper cert validation

    # SSRF / open redirect
    "CWE-918": frozenset({"semgrep", "codeql"}),                  # SSRF
    "CWE-601": frozenset({"semgrep", "codeql"}),                  # open redirect

    # ReDoS / prompt injection
    "CWE-1333": frozenset({"prefilter"}),                         # ReDoS
    "CWE-1336": frozenset({"prefilter"}),                         # prompt injection
}

# Mechanism keywords → CWEs. Used when the LLM provides a mechanism
# string instead of (or in addition to) a CWE number.
_MECHANISM_CWE_MAP: dict[str, list[str]] = {
    "buffer overflow":     ["CWE-120", "CWE-122", "CWE-787"],
    "heap overflow":       ["CWE-122", "CWE-787"],
    "stack overflow":      ["CWE-120", "CWE-787"],
    "out of bounds":       ["CWE-125", "CWE-787"],
    "oob write":           ["CWE-787"],
    "oob read":            ["CWE-125"],
    "use after free":      ["CWE-416"],
    "use-after-free":      ["CWE-416"],
    "double free":         ["CWE-415"],
    "format string":       ["CWE-134"],
    "integer overflow":    ["CWE-190"],
    "integer underflow":   ["CWE-191"],
    "off-by-one":          ["CWE-193"],
    "null pointer":        ["CWE-476"],
    "null dereference":    ["CWE-476"],
    "command injection":   ["CWE-78", "CWE-77"],
    "os command":          ["CWE-78"],
    "argument injection":  ["CWE-88"],
    "sql injection":       ["CWE-89"],
    "xss":                 ["CWE-79"],
    "cross-site scripting": ["CWE-79"],
    "code injection":      ["CWE-94"],
    "codeql injection":    ["CWE-94"],
    "eval injection":      ["CWE-95"],
    "path traversal":      ["CWE-22", "CWE-23"],
    "directory traversal": ["CWE-22"],
    "toctou":              ["CWE-367"],
    # "race condition" maps to CWE-362 (concurrent execution / lock
    # races, coccinelle-only coverage), NOT CWE-367: the prefilter's
    # TOCTOU check only detects access()/stat()-then-open patterns, so
    # mapping generic races to CWE-367 would mark every race hypothesis
    # tool-covered (prefilter is always live) and resolve genuine lock
    # races to clean-when-silent instead of dark. TOCTOU keeps its own
    # keyword above.
    "race condition":      ["CWE-362"],
    "deserialization":     ["CWE-502"],
    "pickle":              ["CWE-502"],
    "yaml load":           ["CWE-502"],
    "xxe":                 ["CWE-611"],
    "xml external":        ["CWE-611"],
    "ssrf":                ["CWE-918"],
    "open redirect":       ["CWE-601"],
    "hardcoded credential": ["CWE-798"],
    "hardcoded password":  ["CWE-798"],
    "redos":               ["CWE-1333"],
    "catastrophic backtracking": ["CWE-1333"],
    "regex denial":        ["CWE-1333"],
    "regular expression denial": ["CWE-1333"],
    "prompt injection":    ["CWE-1336"],
    "indirect prompt injection": ["CWE-1336"],
    "llm injection":       ["CWE-1336"],
    "wrong operator":      ["CWE-480"],
    "assignment in conditional": ["CWE-480"],
    "use of incorrect operator": ["CWE-480"],
    "assignment instead of comparison": ["CWE-481"],
}

_CWE_PATTERN = re.compile(r"CWE-(\d+)", re.IGNORECASE)


def _extract_cwes(
    cwe_field: str,
    mechanism: str = "",
    hypothesis: str = "",
) -> list[str]:
    """Extract CWE IDs from review output fields.

    Checks (in order): explicit CWE field, mechanism keywords,
    hypothesis keywords.
    """
    cwes: list[str] = []

    for m in _CWE_PATTERN.finditer(cwe_field or ""):
        cwes.append(f"CWE-{m.group(1)}")

    combined = f"{mechanism} {hypothesis}".lower()
    for keyword, mapped_cwes in _MECHANISM_CWE_MAP.items():
        if keyword in combined:
            cwes.extend(mapped_cwes)

    seen: set[str] = set()
    deduped: list[str] = []
    for c in cwes:
        if c not in seen:
            seen.add(c)
            deduped.append(c)
    return deduped


# Chain step types / evidence namespaces → the coverage map's tool
# vocabulary. Joern sub-channels and the coccinelle flow templates all
# count as their parent tool; a SARIF-cache hit means a semgrep scan
# ran over the file.
_CHANNEL_ALIASES: dict[str, str] = {
    "coccinelle_flow": "coccinelle",
    "joern_guard": "joern",
    "joern_flow": "joern",
    "cross_function": "joern",
    "sarif_cache": "semgrep",
}


def normalize_ran_channels(raw) -> set[str]:
    """Normalize a dispatched-tool record to the coverage map vocabulary.

    Accepts chain step types (``joern_guard``), namespaced receipts
    (``semgrep:rule-id``), or plain tool names. Unknown entries pass
    through unchanged — they simply never intersect the map.
    """
    out: set[str] = set()
    for entry in raw or ():
        name = str(entry).strip().lower()
        if not name:
            continue
        name = name.split(":", 1)[0]
        out.add(_CHANNEL_ALIASES.get(name, name))
    return out


def is_class_covered(
    cwe_field: str,
    mechanism: str,
    hypothesis: str,
    available_tools: dict[str, bool],
    *,
    ran_tools=None,
) -> bool:
    """Check if a tool that can detect the claimed class actually RAN.

    "Covered" means a mapped channel executed for this function —
    an installed-but-never-dispatched tool is NOT coverage. Treating
    installation as coverage let the gate-resolution pass convert
    correct hypotheses to ``clean`` on the claim that "a tool could
    have found it but didn't", when in fact no tool ever looked.

    ``ran_tools`` is the function's dispatched-tool record (chain step
    types, evidence receipts, or a SARIF-cache file hit), normalized
    via :func:`normalize_ran_channels`. Tools marked unavailable in
    ``available_tools`` are discarded from the ran set (a stale
    dispatch record cannot claim coverage for a dead tool).

    Returns False (conservative — triggers dark classification) when:
    - No CWEs could be extracted
    - All extracted CWEs are unmapped (not in _CWE_TOOL_MAP)
    - No mapped tool for any extracted CWE actually ran
    """
    cwes = _extract_cwes(cwe_field, mechanism, hypothesis)
    if not cwes:
        return False

    ran = normalize_ran_channels(ran_tools)
    if not ran:
        return False

    unavailable = {
        t for t, avail in (available_tools or {}).items() if not avail
    }
    ran -= unavailable

    for cwe in cwes:
        tools_for_cwe = _CWE_TOOL_MAP.get(cwe)
        if tools_for_cwe and tools_for_cwe & ran:
            return True

    return False
