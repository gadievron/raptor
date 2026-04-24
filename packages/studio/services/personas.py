"""Load raptor's expert personas and map them to findings.

Raptor ships 9–10 expert personas at ``$RAPTOR_HOME/tiers/personas/*.md``.
Each persona is a markdown brief that Claude Code loads on-demand to take
on a specialist perspective. See docs/CLAUDE_CODE_USAGE.md for the binding
to raptor packages.

This service lets the UI surface the right persona(s) for a given finding
— so an expanded stack_overflow finding suggests the Binary Exploitation
Specialist and Crash Analyst, while a command_injection finding suggests
the Penetration Tester and Security Researcher.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterable

from packages.studio.config import RAPTOR_HOME


# Curated metadata: label, use-case, which vuln categories trigger it.
# Keys match persona filenames (stem, without .md).
PERSONA_META: dict[str, dict] = {
    "exploit_developer": {
        "label": "Exploit Developer",
        "handle": "Mark Dowd",
        "use_when": "Generate a compilable, working PoC for a confirmed vulnerability.",
        "component": "llm_analysis/agent.py",
    },
    "crash_analyst": {
        "label": "Crash Analyst",
        "handle": "Charlie Miller · Halvar Flake",
        "use_when": "Triage and classify a memory-corruption crash.",
        "component": "llm_analysis/crash_agent.py",
    },
    "security_researcher": {
        "label": "Security Researcher",
        "handle": "",
        "use_when": "Deep vulnerability validation, false-positive detection.",
        "component": "llm_analysis/agent.py",
    },
    "offensive_security_researcher": {
        "label": "Offensive Security Researcher",
        "handle": "",
        "use_when": "Red-team perspective on realistic exploitability.",
        "component": "llm_analysis/agent.py",
    },
    "patch_engineer": {
        "label": "Patch Engineer",
        "handle": "",
        "use_when": "Produce a production-ready secure patch for a confirmed bug.",
        "component": "llm_analysis/agent.py",
    },
    "penetration_tester": {
        "label": "Penetration Tester",
        "handle": "",
        "use_when": "Craft realistic attack payloads for web-class vulnerabilities.",
        "component": "web/fuzzer.py",
    },
    "fuzzing_strategist": {
        "label": "Fuzzing Strategist",
        "handle": "",
        "use_when": "Design corpora and triage fuzzing output.",
        "component": "autonomous/dialogue.py",
    },
    "binary_exploitation_specialist": {
        "label": "Binary Exploitation Specialist",
        "handle": "",
        "use_when": "ROP, heap, and memory-corruption exploit development.",
        "component": "llm_analysis/crash_agent.py",
    },
    "codeql_analyst": {
        "label": "CodeQL Dataflow Analyst",
        "handle": "",
        "use_when": "Write custom CodeQL queries and validate dataflow paths.",
        "component": "codeql/dataflow_validator.py",
    },
    "codeql_finding_analyst": {
        "label": "CodeQL Finding Analyst",
        "handle": "Mark Dowd methodology",
        "use_when": "Triage CodeQL findings and identify false positives.",
        "component": "codeql/autonomous_analyzer.py",
    },
}


# Vuln-type categories used by personas_for_finding.
MEMORY_CORRUPTION_TYPES = frozenset({
    "buffer_overflow", "stack_overflow", "heap_overflow",
    "use_after_free", "uaf", "double_free",
    "format_string", "integer_overflow", "type_confusion",
    "null_deref", "null_pointer_dereference",
    "memory_corruption", "heap_corruption", "stack_corruption",
})
WEB_TYPES = frozenset({
    "xss", "cross_site_scripting", "sql_injection", "sqli",
    "command_injection", "path_traversal", "directory_traversal",
    "ssrf", "csrf", "xxe", "lfi", "rfi", "idor",
    "auth_bypass", "authentication_bypass", "broken_access_control",
    "deserialization", "open_redirect",
})


@dataclass
class Persona:
    key: str
    label: str
    handle: str
    use_when: str
    component: str
    content: str = ""
    source_path: Path | None = None

    @property
    def is_loaded(self) -> bool:
        return bool(self.content)


def _norm_type(t: str | None) -> str:
    if not t:
        return ""
    return t.lower().replace(" ", "_").replace("-", "_")


@lru_cache(maxsize=1)
def _load_all() -> dict[str, Persona]:
    """Scan the personas directory and return {key: Persona}."""
    out: dict[str, Persona] = {}
    base = RAPTOR_HOME / "tiers" / "personas"
    for key, meta in PERSONA_META.items():
        path = base / f"{key}.md"
        content = ""
        if path.is_file():
            try:
                content = path.read_text()
            except OSError:
                content = ""
        out[key] = Persona(
            key=key,
            label=meta["label"],
            handle=meta["handle"],
            use_when=meta["use_when"],
            component=meta["component"],
            content=content,
            source_path=path if path.is_file() else None,
        )
    return out


def all_personas() -> list[Persona]:
    return list(_load_all().values())


def get_persona(key: str) -> Persona | None:
    return _load_all().get(key)


def personas_for_finding(finding: dict) -> list[Persona]:
    """Return relevant personas for a finding, ranked most-specific first."""
    vuln = _norm_type(finding.get("vuln_type") or finding.get("type") or "")
    tool = (finding.get("tool") or "").lower()
    fs = (finding.get("final_status") or finding.get("status") or "").lower()
    has_binary_feasibility = isinstance(finding.get("feasibility"), dict)
    origin_file = str(finding.get("file") or "").lower()

    # (persona_key, relevance_score) — higher wins
    scored: list[tuple[str, int]] = []

    if vuln in MEMORY_CORRUPTION_TYPES or has_binary_feasibility:
        scored.append(("binary_exploitation_specialist", 10))
        scored.append(("crash_analyst", 8))
        if has_binary_feasibility:
            scored.append(("exploit_developer", 7))

    if vuln in WEB_TYPES:
        scored.append(("penetration_tester", 10))

    if tool == "codeql":
        scored.append(("codeql_finding_analyst", 9))
        scored.append(("codeql_analyst", 6))

    # Exploit Developer for any confirmed-exploitable finding
    if fs in ("exploitable", "likely_exploitable", "confirmed"):
        scored.append(("exploit_developer", 8 if vuln in MEMORY_CORRUPTION_TYPES else 6))
        scored.append(("patch_engineer", 5))

    # C/C++ file hint pulls in memory-corruption specialists
    if origin_file.endswith((".c", ".cpp", ".cc", ".h", ".hpp")):
        scored.append(("binary_exploitation_specialist", 4))

    # Fuzzing crash artifacts (heuristic: filename looks like crash dump)
    if "crash" in origin_file or origin_file.startswith("afl_output"):
        scored.append(("fuzzing_strategist", 8))
        scored.append(("crash_analyst", 6))

    # Always include Security Researcher as baseline validator
    scored.append(("security_researcher", 3))

    # Deduplicate keeping max score
    best: dict[str, int] = {}
    for key, score in scored:
        best[key] = max(best.get(key, 0), score)

    registry = _load_all()
    ordered = sorted(best.items(), key=lambda kv: (-kv[1], kv[0]))
    return [registry[k] for k, _ in ordered if k in registry][:4]


def clear_cache():
    """For tests — forget the cached persona file contents."""
    _load_all.cache_clear()
