#!/usr/bin/env python3
"""
RAPTOR Frida Methodology Engine

Exploitation-focused methodology for dynamic analysis.
Not app-specific - works on any target.

Methodology layers:
1. Attack Surface Discovery - What inputs/outputs exist?
2. Primitive Hunting - What exploitation primitives are present?
3. Coverage Tracking - What have we exercised?
4. Depth Analysis - Deep dive on interesting areas
"""

from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum


class ExploitPrimitive(Enum):
    """Categories of exploitation primitives to hunt for."""

    # Memory corruption
    HEAP_OPERATIONS = "heap_ops"          # malloc/free/realloc patterns
    BUFFER_OPERATIONS = "buffer_ops"      # memcpy/strcpy/sprintf
    FORMAT_STRINGS = "format_strings"     # printf family with user data

    # Authentication/Authorization
    CREDENTIAL_HANDLING = "credentials"   # passwords, tokens, keys
    SESSION_MANAGEMENT = "sessions"       # cookies, session IDs
    PRIVILEGE_OPERATIONS = "privileges"   # setuid, capability changes

    # Data flow
    NETWORK_IO = "network"                # send/recv/connect
    FILE_IO = "file_io"                   # open/read/write
    IPC = "ipc"                           # pipes, sockets, shared memory

    # Crypto
    CRYPTO_OPERATIONS = "crypto"          # encrypt/decrypt/hash
    KEY_MATERIAL = "keys"                 # key generation, storage
    RANDOM = "random"                     # PRNG usage

    # System interaction
    PROCESS_CONTROL = "process"           # fork/exec/system
    ENVIRONMENT = "environment"           # getenv, config reads


@dataclass
class MethodologyPhase:
    """A phase in the analysis methodology."""
    name: str
    goal: str
    primitives: List[ExploitPrimitive]
    depth: int  # 1=surface, 2=moderate, 3=deep


# Standard methodology phases
METHODOLOGY_PHASES = {
    "recon": MethodologyPhase(
        name="Reconnaissance",
        goal="Discover attack surface and entry points",
        primitives=[
            ExploitPrimitive.NETWORK_IO,
            ExploitPrimitive.FILE_IO,
            ExploitPrimitive.IPC,
            ExploitPrimitive.ENVIRONMENT,
        ],
        depth=1
    ),
    "auth": MethodologyPhase(
        name="Authentication Analysis",
        goal="Find credential handling and auth bypass opportunities",
        primitives=[
            ExploitPrimitive.CREDENTIAL_HANDLING,
            ExploitPrimitive.SESSION_MANAGEMENT,
            ExploitPrimitive.CRYPTO_OPERATIONS,
            ExploitPrimitive.KEY_MATERIAL,
        ],
        depth=2
    ),
    "memory": MethodologyPhase(
        name="Memory Safety",
        goal="Find memory corruption primitives",
        primitives=[
            ExploitPrimitive.HEAP_OPERATIONS,
            ExploitPrimitive.BUFFER_OPERATIONS,
            ExploitPrimitive.FORMAT_STRINGS,
        ],
        depth=2
    ),
    "execution": MethodologyPhase(
        name="Code Execution",
        goal="Find command injection and code execution paths",
        primitives=[
            ExploitPrimitive.PROCESS_CONTROL,
            ExploitPrimitive.ENVIRONMENT,
        ],
        depth=3
    ),
}


# Primitive → Hook mappings (OS-agnostic function families)
PRIMITIVE_HOOKS = {
    ExploitPrimitive.HEAP_OPERATIONS: {
        "functions": ["malloc", "free", "realloc", "calloc", "mmap", "munmap"],
        "analysis": "track_allocation_patterns",
        "signals": ["double-free", "use-after-free", "heap-overflow"],
    },
    ExploitPrimitive.BUFFER_OPERATIONS: {
        "functions": ["memcpy", "memmove", "strcpy", "strncpy", "strcat",
                      "sprintf", "snprintf", "gets", "fgets"],
        "analysis": "check_bounds",
        "signals": ["buffer-overflow", "stack-overflow"],
    },
    ExploitPrimitive.FORMAT_STRINGS: {
        "functions": ["printf", "fprintf", "sprintf", "snprintf", "syslog"],
        "analysis": "check_format_string_source",
        "signals": ["format-string-vuln"],
    },
    ExploitPrimitive.CREDENTIAL_HANDLING: {
        "functions": ["write", "send", "SSL_write"],  # outbound
        "patterns": ["password", "passwd", "secret", "token", "bearer",
                     "authorization", "api_key", "apikey", "auth"],
        "analysis": "scan_for_credentials",
        "signals": ["credential-leak", "hardcoded-secret"],
    },
    ExploitPrimitive.SESSION_MANAGEMENT: {
        "functions": ["write", "send", "recv", "read"],
        "patterns": ["session", "cookie", "jwt", "sid"],
        "analysis": "track_session_data",
        "signals": ["session-fixation", "session-leak"],
    },
    ExploitPrimitive.NETWORK_IO: {
        "functions": ["connect", "send", "recv", "sendto", "recvfrom",
                      "write", "read", "SSL_write", "SSL_read"],
        "analysis": "track_network_flow",
        "signals": ["unencrypted-traffic", "sensitive-data-transit"],
    },
    ExploitPrimitive.FILE_IO: {
        "functions": ["open", "fopen", "read", "write", "unlink", "rename"],
        "analysis": "track_file_access",
        "signals": ["sensitive-file-access", "path-traversal", "symlink-race"],
    },
    ExploitPrimitive.CRYPTO_OPERATIONS: {
        "functions": ["EVP_EncryptInit", "EVP_DecryptInit", "CCCrypt",
                      "SecKeyEncrypt", "SecKeyDecrypt"],
        "analysis": "check_crypto_params",
        "signals": ["weak-crypto", "ecb-mode", "static-iv"],
    },
    ExploitPrimitive.KEY_MATERIAL: {
        "functions": ["RAND_bytes", "SecRandomCopyBytes", "getrandom"],
        "patterns": ["key", "secret", "private"],
        "analysis": "track_key_usage",
        "signals": ["weak-random", "key-reuse"],
    },
    ExploitPrimitive.PROCESS_CONTROL: {
        "functions": ["system", "popen", "exec", "execve", "fork",
                      "posix_spawn"],
        "analysis": "check_command_injection",
        "signals": ["command-injection", "arbitrary-exec"],
    },
    ExploitPrimitive.ENVIRONMENT: {
        "functions": ["getenv", "setenv", "putenv"],
        "analysis": "track_env_usage",
        "signals": ["env-injection", "path-manipulation"],
    },
}


def get_hooks_for_phase(phase_name: str) -> Dict[str, Any]:
    """
    Get hook specifications for a methodology phase.

    Returns dict with:
    - functions: list of functions to hook
    - patterns: data patterns to watch for
    - signals: what findings indicate
    """
    if phase_name not in METHODOLOGY_PHASES:
        phase_name = "recon"  # default

    phase = METHODOLOGY_PHASES[phase_name]
    result = {
        "phase": phase.name,
        "goal": phase.goal,
        "depth": phase.depth,
        "functions": [],
        "patterns": [],
        "signals": [],
    }

    for primitive in phase.primitives:
        hook_spec = PRIMITIVE_HOOKS.get(primitive, {})
        result["functions"].extend(hook_spec.get("functions", []))
        result["patterns"].extend(hook_spec.get("patterns", []))
        result["signals"].extend(hook_spec.get("signals", []))

    # Deduplicate
    result["functions"] = list(set(result["functions"]))
    result["patterns"] = list(set(result["patterns"]))
    result["signals"] = list(set(result["signals"]))

    return result


def get_hooks_for_goal(goal: str) -> Dict[str, Any]:
    """
    Analyze a goal string and determine appropriate methodology.

    Args:
        goal: Natural language security goal

    Returns:
        Hook specification based on inferred methodology
    """
    goal_lower = goal.lower()

    # Map goal keywords to phases
    phase_keywords = {
        "recon": ["discover", "map", "surface", "enumerate", "find entry"],
        "auth": ["auth", "credential", "password", "login", "session",
                 "token", "bypass", "privilege"],
        "memory": ["memory", "buffer", "overflow", "heap", "corruption",
                   "crash", "fuzzing"],
        "execution": ["execute", "injection", "command", "rce", "shell",
                      "code execution"],
    }

    # Score each phase
    scores = {}
    for phase, keywords in phase_keywords.items():
        scores[phase] = sum(1 for kw in keywords if kw in goal_lower)

    # Pick highest scoring phase, default to recon
    best_phase = max(scores, key=scores.get) if max(scores.values()) > 0 else "recon"

    return get_hooks_for_phase(best_phase)


def generate_methodology_prompt(goal: str, target_type: str = "binary") -> str:
    """
    Generate LLM prompt based on methodology, not app-specific knowledge.

    Args:
        goal: Security objective
        target_type: binary, gui_app, service, etc.

    Returns:
        Prompt for LLM to generate hooks
    """
    hook_spec = get_hooks_for_goal(goal)

    return f"""
You are generating Frida hooks for exploitation-focused security analysis.

METHODOLOGY: {hook_spec['phase']}
PHASE GOAL: {hook_spec['goal']}
ANALYSIS DEPTH: {hook_spec['depth']}/3

USER GOAL: {goal}
TARGET TYPE: {target_type}

EXPLOITATION PRIMITIVES TO HUNT:
Functions to hook: {', '.join(hook_spec['functions'][:15])}
Data patterns to detect: {', '.join(hook_spec['patterns'])}
Signals indicating vulnerabilities: {', '.join(hook_spec['signals'])}

REQUIREMENTS:
1. Generate hooks that work on ANY target (no app-specific assumptions)
2. Focus on EXPLOITATION POTENTIAL, not just logging
3. Extract data that could be weaponized:
   - Credentials, keys, tokens → credential theft
   - Buffer sizes vs data sizes → overflow potential
   - Command strings → injection points
   - File paths → traversal/race conditions
4. Rate findings by exploitability (critical/high/medium/low/info)
5. Track coverage: log when we hit interesting code paths

EXPLOITATION MINDSET:
- What can be stolen? (credentials, keys, PII)
- What can be corrupted? (memory, files, state)
- What can be controlled? (execution flow, data)
- What can be bypassed? (auth, validation, checks)

Use these helpers (already defined):
- findSymbol(name, preferredModule) - resolve function
- sendFinding(title, severity, details, data) - report finding
- log(msg, level) - debug logging

Generate ONLY the JavaScript hook code. Focus on methodology, not specific apps.
"""


# Coverage tracking
class CoverageTracker:
    """Track what exploitation primitives have been exercised."""

    def __init__(self):
        self.hit_functions: Dict[str, int] = {}
        self.hit_primitives: Dict[ExploitPrimitive, int] = {}
        self.findings_by_signal: Dict[str, List] = {}

    def record_hit(self, function: str, primitive: ExploitPrimitive):
        """Record that a function/primitive was exercised."""
        self.hit_functions[function] = self.hit_functions.get(function, 0) + 1
        self.hit_primitives[primitive] = self.hit_primitives.get(primitive, 0) + 1

    def get_coverage_report(self) -> Dict[str, Any]:
        """Get coverage statistics."""
        total_primitives = len(ExploitPrimitive)
        hit_primitives = len(self.hit_primitives)

        return {
            "primitive_coverage": f"{hit_primitives}/{total_primitives}",
            "functions_exercised": len(self.hit_functions),
            "total_hits": sum(self.hit_functions.values()),
            "primitives_hit": list(self.hit_primitives.keys()),
            "primitives_missed": [
                p for p in ExploitPrimitive
                if p not in self.hit_primitives
            ],
        }


# Depth analysis triggers
DEPTH_TRIGGERS = {
    # Finding type → what to analyze deeper
    "credential-leak": ["trace call stack", "find credential source"],
    "buffer-overflow": ["calculate overflow size", "check exploitability"],
    "command-injection": ["trace input source", "check sanitization"],
    "format-string-vuln": ["check stack layout", "calculate offset"],
    "weak-crypto": ["extract algorithm params", "assess impact"],
}


def get_depth_analysis(finding_type: str) -> List[str]:
    """Get deeper analysis steps for a finding type."""
    return DEPTH_TRIGGERS.get(finding_type, ["manual review recommended"])
