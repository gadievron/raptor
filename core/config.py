#!/usr/bin/env python3
"""
RAPTOR Centralized Configuration Module

This module provides centralized configuration management for the RAPTOR framework,
including paths, timeouts, limits, and baseline settings.
"""

import os
from pathlib import Path
from typing import Dict, List, Tuple


class RaptorConfig:
    """Centralized configuration for RAPTOR framework."""

    # Version
    VERSION = "3.0.0"

    # Tool dependencies for startup checks
    # severity: "required" = feature unavailable, "degrades" = feature limited
    # group: tools in same group need at least one present
    TOOL_DEPS = {
        "afl++":    {"binary": "afl-fuzz",  "severity": "required", "affects": "/fuzz"},
        "codeql":   {"binary": "codeql",    "group": "scanner",     "affects": "/codeql, /agentic"},
        "gdb":      {"binary": "gdb",       "severity": "required", "affects": "/crash-analysis, /fuzz"},
        "rr":       {"binary": "rr",        "severity": "degrades", "affects": "/crash-analysis"},
        "semgrep":  {"binary": "semgrep",   "group": "scanner",     "affects": "/scan, /agentic"},
    }

    TOOL_GROUPS = {
        "scanner": {"min_required": 1, "affects": "/scan, /agentic"},
    }

    # Path Configuration
    # core/config.py -> repo root
    REPO_ROOT = Path(__file__).resolve().parents[1]
    ENGINE_DIR = REPO_ROOT / "engine"
    MCP_DIR = REPO_ROOT / "mcp"
    AGENTS_DIR = MCP_DIR / "agents"
    TOOLS_DIR = MCP_DIR / "tools"
    BASE_OUT_DIR = REPO_ROOT / "out"
    SEMGREP_RULES_DIR = ENGINE_DIR / "semgrep" / "rules"
    SEMGREP_REGISTRY_CACHE_DIR = SEMGREP_RULES_DIR / "registry-cache"
    SCHEMAS_DIR = ENGINE_DIR / "schemas"

    # CodeQL Configuration
    CODEQL_DB_DIR = REPO_ROOT / "codeql_dbs"
    CODEQL_QUERIES_DIR = ENGINE_DIR / "codeql" / "queries"
    CODEQL_SUITES_DIR = ENGINE_DIR / "codeql" / "suites"

    # Timeout Configuration (seconds)
    DEFAULT_TIMEOUT = 1800          # 30 minutes
    SEMGREP_TIMEOUT = 900            # 15 minutes (scan over local rule dirs)
    SEMGREP_PACK_TIMEOUT = 300       # 5 minutes (registry pack: fetch + scan)
    SEMGREP_RULE_TIMEOUT = 120       # 2 minutes per rule
    CODEQL_TIMEOUT = 1800            # 30 minutes (database creation)
    CODEQL_ANALYZE_TIMEOUT = 2400    # 40 minutes (query execution)
    GIT_CLONE_TIMEOUT = 600          # 10 minutes
    LLM_TIMEOUT = 120                # 2 minutes per LLM call
    SUBPROCESS_POLL_INTERVAL = 1     # 1 second

    # Resource Limits
    RESOURCE_READ_LIMIT = 5 * 1024 * 1024   # 5 MiB
    MAX_TAIL_BYTES = 2000                    # bytes of stdout/stderr in results
    HASH_CHUNK_SIZE = 1024 * 1024            # 1 MiB chunks for file hashing
    MAX_FILE_SIZE_FOR_HASH = 100 * 1024 * 1024  # 100 MiB max file size for hashing

    # Parallel Processing
    MAX_SEMGREP_WORKERS = 4          # Parallel Semgrep scans
    MAX_CODEQL_WORKERS = 2           # Parallel CodeQL scans

    # CodeQL Resource Configuration
    CODEQL_RAM_MB = 8192             # RAM for CodeQL analysis (8GB)
    CODEQL_THREADS = 0               # 0 = use all available CPUs
    CODEQL_MAX_PATHS = 4             # Max dataflow paths per query
    CODEQL_DB_CACHE_DAYS = 7         # Keep databases for 7 days
    CODEQL_DB_AUTO_CLEANUP = True    # Automatically cleanup old databases

    # Baseline Semgrep Packs (always included)
    BASELINE_SEMGREP_PACKS: List[Tuple[str, str]] = [
        ("semgrep_security_audit", "p/security-audit"),
        ("semgrep_owasp_top_10", "p/owasp-top-ten"),
        ("semgrep_secrets", "p/secrets"),
    ]

    # Mapping of policy groups to their corresponding semgrep registry packs
    # Format: {local_dir_name: (pack_name, pack_identifier)}
    POLICY_GROUP_TO_SEMGREP_PACK: Dict[str, Tuple[str, str]] = {
        # Only packs that exist on semgrep.dev and are cached in registry-cache/
        # deserialisation, filesystem, logging: no registry pack exists, local rules only
        # crypto: p/crypto and category/crypto both 404 — local rules only
        # ssrf: p/ssrf 404 and no local rules dir — no coverage until custom rules are added
        "secrets": ("semgrep_secrets", "p/secrets"),
        "injection": ("semgrep_injection", "p/command-injection"),
        "auth": ("semgrep_auth", "p/jwt"),
        "flows": ("semgrep_dataflow", "p/default"),
        "sinks": ("semgrep_sinks", "p/xss"),
        "best-practices": ("semgrep_best_practices", "p/default"),
    }

    # Default Policy Configuration
    DEFAULT_POLICY_VERSION = "v1"
    DEFAULT_POLICY_GROUPS = "all"

    # Environment Variables
    ENV_OUT_DIR = "RAPTOR_OUT_DIR"
    ENV_JOB_ID = "RAPTOR_JOB_ID"
    ENV_LLM_CMD = "RAPTOR_LLM_CMD"

    # LLM Provider Configuration
    OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

    # Proxy variables to strip for security
    PROXY_ENV_VARS = [
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "no_proxy",
    ]

    # Environment variables that can be exploited for command injection
    # when consumed by tools that shell-evaluate their values.
    # Ref: Phoenix Security CWE-78 disclosure (2026-03-31, VULN-01)
    # TODO: Replace blocklist with a minimal allowlist (PATH, HOME, LANG,
    # tool-specific vars). Needs testing of what semgrep, codeql, git, gdb,
    # afl-fuzz each require.
    DANGEROUS_ENV_VARS = [
        "TERMINAL",        # Shell-evaluated by command lookup utilities
        "BROWSER",         # Shell-evaluated by open/xdg-open
        "PAGER",           # Shell-evaluated by less/more invocation
        "VISUAL",          # Shell-evaluated by editor invocation
        "EDITOR",          # Shell-evaluated by editor invocation
        "IFS",             # Changes shell word splitting — classic injection vector
        "CDPATH",          # Alters cd behaviour, can redirect working directory
        "BASH_ENV",        # Executed by bash on startup in non-interactive mode
        "ENV",             # Executed by sh/dash on startup
        "PROMPT_COMMAND",  # Executed before every bash prompt (if child is interactive)
        "LD_PRELOAD",      # Injects shared libraries into child processes
        "LD_LIBRARY_PATH", # Redirects shared library resolution
        "PYTHONSTARTUP",   # Executed by Python on startup
        "PERL5OPT",        # Injects Perl command-line options
        "RUBYOPT",         # Injects Ruby command-line options
        "NODE_OPTIONS",    # Injects Node.js command-line options
        # Note: TERM is NOT stripped — it's read as a string (terminfo lookup),
        # not shell-evaluated. Stripping it breaks colour output in git/grep/etc.
    ]

    # Git Configuration
    GIT_ENV_VARS = {
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "true",
    }

    # MCP Server Configuration
    MCP_VERSION = "0.6.0"
    MCP_JOB_DIR = BASE_OUT_DIR / "jobs"

    # Logging Configuration
    LOG_DIR = BASE_OUT_DIR / "logs"
    LOG_FORMAT_CONSOLE = "[%(levelname)s] %(message)s"
    LOG_FORMAT_FILE = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    @classmethod
    def get_semgrep_config(cls, pack_id: str) -> str:
        """Return local cached path for a registry pack if available, else the registry ID.

        Naming: p/secrets -> c.p.secrets.json (mirrors semgrep.dev /c/p/ URL path).
        Falls back to the registry identifier so online scans still work.
        """
        cache_file = cls.SEMGREP_REGISTRY_CACHE_DIR / ("c." + pack_id.replace("/", ".") + ".json")
        if cache_file.exists():
            return str(cache_file)
        return pack_id

    @staticmethod
    def get_out_dir() -> Path:
        """
        Resolve the output directory, honoring RAPTOR_OUT_DIR environment variable.

        Warns if the output directory is a system path that could be dangerous.

        Returns:
            Path: Resolved output directory path
        """
        base = os.environ.get(RaptorConfig.ENV_OUT_DIR)
        if not base:
            return RaptorConfig.BASE_OUT_DIR
        resolved = Path(base).resolve()
        forbidden = ("/etc", "/usr", "/bin", "/sbin", "/boot", "/dev", "/proc", "/sys")
        for prefix in forbidden:
            if str(resolved).startswith(prefix):
                import logging
                logging.getLogger(__name__).warning(
                    f"RAPTOR_OUT_DIR points to system path {resolved} — this is likely a misconfiguration"
                )
                break
        return resolved

    @staticmethod
    def get_job_out_dir(job_id: str) -> Path:
        """
        Get the output directory for a specific job.

        Args:
            job_id: Unique job identifier

        Returns:
            Path: Job-specific output directory
        """
        return RaptorConfig.MCP_JOB_DIR / job_id

    @staticmethod
    def get_safe_env() -> dict:
        """
        Create a safe environment dict with proxy variables removed.

        Returns:
            dict: Environment variables with security-sensitive vars removed
        """
        env = os.environ.copy()
        for var in RaptorConfig.PROXY_ENV_VARS:
            env.pop(var, None)
        for var in RaptorConfig.DANGEROUS_ENV_VARS:
            env.pop(var, None)
        env["PYTHONUNBUFFERED"] = "1"
        return env

    @staticmethod
    def get_git_env() -> dict:
        """
        Create environment for safe git operations.

        Returns:
            dict: Environment configured for secure git operations
        """
        env = RaptorConfig.get_safe_env()
        env.update(RaptorConfig.GIT_ENV_VARS)
        return env

    @staticmethod
    def ensure_directories() -> None:
        """Create all required directories if they don't exist."""
        directories = [
            RaptorConfig.BASE_OUT_DIR,
            RaptorConfig.MCP_JOB_DIR,
            RaptorConfig.LOG_DIR,
            RaptorConfig.SCHEMAS_DIR,
            RaptorConfig.CODEQL_DB_DIR,
            RaptorConfig.CODEQL_SUITES_DIR,
        ]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)


# Convenience aliases for backward compatibility
def get_out_dir() -> Path:
    """Backward compatible function for getting output directory."""
    return RaptorConfig.get_out_dir()
