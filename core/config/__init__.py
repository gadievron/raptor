#!/usr/bin/env python3
"""
RAPTOR Centralized Configuration Module

This module provides centralized configuration management for the RAPTOR framework,
including paths, timeouts, limits, and baseline settings.
"""

import os
from pathlib import Path
from typing import Dict, List, Tuple


class classproperty:  # noqa: N801
    """Descriptor that works like @property but on the class itself."""

    def __init__(self, func):
        self.fget = func

    def __get__(self, obj, cls):
        return self.fget(cls)


class RaptorConfig:
    """Centralized configuration for RAPTOR framework.

    This class is a NAMESPACE — every public member is a class
    attribute or @classmethod. Pre-fix RaptorConfig had no
    `__init__` guard, so ``RaptorConfig()`` silently returned
    a usable instance. Two surprises that fell out of that:

      * ``cfg = RaptorConfig(); cfg.SOMETHING = 42`` set the
        attribute on the INSTANCE, while every internal site
        reads `RaptorConfig.SOMETHING` (the class attribute) —
        so the override silently no-ops with no error. Operators
        debugging a "my override isn't taking effect" issue had
        no signal that the override sites were reading past the
        instance.
      * Test fixtures that did ``cfg = RaptorConfig()`` to scope
        a `patch.object(cfg, "X", ...)` similarly mutated the
        instance, leaving production code unaffected.

    Block instantiation explicitly so the misuse fails fast at
    the call site instead of producing a phantom instance.
    """

    def __init__(self) -> None:
        raise TypeError(
            "RaptorConfig is a class-level configuration namespace; "
            "do NOT instantiate. Access members as RaptorConfig.X (or "
            "patch via patch.object(RaptorConfig, ...) in tests)."
        )

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
    # core/config/__init__.py -> repo root (two parents up: ``__init__.py``
    # → ``config/`` → ``core/`` → repo root). Was ``parents[1]`` when
    # this lived as the flat ``core/config.py``; the package conversion
    # added one directory level.
    REPO_ROOT = Path(__file__).resolve().parents[2]
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

    # Additional CodeQL pack roots searched by IRIS Tier 1 discovery
    # alongside the default `~/.codeql/packages/codeql/` location. Each
    # entry is a directory containing one or more `<lang>-queries/`
    # subdirectories matching the standard CodeQL pack layout. Listed
    # roots take precedence over the default on (lang, CWE) collisions
    # so RAPTOR-shipped packs can override stdlib queries.
    #
    # Default includes the in-repo raptor-python-queries pack so
    # LocalFlowSource-based queries (covering CLI sources like sys.argv
    # that the stdlib RemoteFlowSource model excludes) are picked up
    # without operator configuration.
    EXTRA_CODEQL_PACK_ROOTS: List[Path] = [
        REPO_ROOT / "packages" / "llm_analysis" / "codeql_packs",
    ]

    # IRIS Tier 1 master kill-switch. When False, all four consumers
    # (`/agentic --validate-dataflow`, `/exploit` pre-flight gate,
    # `/codeql analyze_iris_packs`, `/validate` Stage B gate) skip the
    # Tier 1 dataflow check entirely. Designed for the unlikely-but-
    # possible case where Tier 1 produces unwanted output on a given
    # target — e.g. excessive coverage-gap warnings on a stale DB,
    # an operator wanting to bypass refute downgrades temporarily, or
    # debugging a Tier 1 vs Tier 2 disagreement. Defaults to True so
    # the free signal is on by default everywhere.
    #
    # Per-consumer CLI flags can override this at run scope:
    #   /codeql --no-iris-tier1
    #   /agentic --no-validate-dataflow      (existing flag, broader)
    # /exploit and /validate inherit through `tier1_check_finding`.
    IRIS_TIER1_ENABLED: bool = True

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

    # Parallel Processing and CodeQL Resources — driven by tuning.json
    # Import is deferred to property access to avoid circular imports.

    @staticmethod
    def _tuning():
        from core.tuning import get_tuning
        return get_tuning()

    @classproperty
    def MAX_SEMGREP_WORKERS(cls):
        return cls._tuning().max_semgrep_workers

    @classproperty
    def MAX_CODEQL_WORKERS(cls):
        return cls._tuning().max_codeql_workers

    @classproperty
    def CODEQL_RAM_MB(cls):
        return cls._tuning().codeql_ram_mb

    @classproperty
    def CODEQL_THREADS(cls):
        return cls._tuning().codeql_threads

    # CodeQL DB cache: grace period before _evict_stale_canonical evicts
    # a canonical that has no metadata yet. The promote sequence has a
    # gap between os.rename(staging, canonical) and save_metadata
    # (covers _count_database_files + get_codeql_version subprocess +
    # save_metadata atomic write). Grace period must exceed worst-case
    # gap to avoid evicting in-flight writers' just-promoted canonicals.
    # 60s is well above measured gap (~1s in normal conditions); orphan
    # canonicals from crashed writers self-heal once their mtime
    # crosses this threshold.
    CODEQL_DB_MISSING_METADATA_GRACE = 60   # seconds
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

    # LLM Provider Configuration.
    #
    # OLLAMA_HOST reads the env var on every access so a runtime
    # change (test setup that sets OLLAMA_HOST after importing a
    # consumer; an operator sourcing a shell rc after RAPTOR is
    # already imported) is picked up. Pre-fix it was evaluated once
    # at class definition time:
    #
    #     OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    #
    # Any later env-var change was silently ignored — consumers
    # held the stale `http://localhost:11434` default even when
    # OLLAMA_HOST was set immediately after. Tests that set the env
    # then imported the consumer module saw the wrong value with no
    # diagnostic.
    #
    # Implement as a descriptor so both `RaptorConfig.OLLAMA_HOST`
    # (class access; the existing call pattern across `core/llm/`)
    # and `RaptorConfig().OLLAMA_HOST` (instance access; rare but
    # supported) re-read the env var on every access. `__get__` is
    # invoked for both class and instance reads.
    class _OllamaHostDescriptor:
        def __get__(self, obj, objtype=None):
            return os.getenv("OLLAMA_HOST", "http://localhost:11434")

    OLLAMA_HOST = _OllamaHostDescriptor()

    # Proxy variables to strip for security
    PROXY_ENV_VARS = [
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
        "http_proxy", "https_proxy", "no_proxy",
    ]

    # ----- Env allowlist (primary) and blocklist (belt + braces) -----
    #
    # get_safe_env() sanitises a subprocess env by:
    #   1. keeping only names in SAFE_ENV_ALLOWLIST or matching a
    #      SAFE_ENV_PREFIX. Everything else is dropped — future unknown
    #      injection vectors (a new GCONV_PATH-style var in next glibc,
    #      a new tool that auto-loads via env) don't flow through unless
    #      we explicitly allowlist them.
    #   2. overlaying DANGEROUS_ENV_VARS as a second strip. Belt + braces:
    #      if the allowlist accidentally admits something bad (e.g. we add
    #      `SSH_*` to prefixes and then realise SSH_ASKPASS is exec-capable),
    #      the blocklist still catches it. The blocklist also remains the
    #      authoritative list for untrusted-repo-content scanning (.envrc /
    #      Dockerfile ENV / CI config env sections).
    #
    # Callers that explicitly pass env= to subprocess.run / sandbox().run()
    # bypass both filters — their env is used verbatim.
    SAFE_ENV_ALLOWLIST = frozenset({
        # Tool lookup — sandboxed children need this to find gcc, python,
        # etc. PATH hijack of RAPTOR-owned setup binaries (unshare,
        # prlimit, sh, mount, mkdir) is handled separately by resolving
        # to absolute paths at setup time (see core/sandbox/probes.py).
        "PATH",
        # Identity
        "USER", "LOGNAME", "HOSTNAME",
        # Home and session — many tools need HOME for ~/.config; stripping
        # breaks far too much. Redirect-via-malicious-HOME is a real but
        # accepted residual risk (see sandbox threat model).
        "HOME", "SHELL", "PWD", "OLDPWD",
        # XDG base dirs — modern tools expect these. Same residual redirect
        # risk as HOME; accepted.
        "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
        "XDG_RUNTIME_DIR", "XDG_SESSION_ID", "XDG_SESSION_TYPE",
        # Locale — without LANG/LC_* set, glibc uses POSIX locale and many
        # tools break on non-ASCII input. grep complains, python may emit
        # UnicodeWarning, perl prints a banner, etc.
        "LANG", "LANGUAGE", "LC_ALL",
        # Terminal — vi/less/git/python all consult TERM. COLORTERM for
        # colour support detection.
        "TERM", "COLORTERM",
        # Time zone — date/time-handling tools use TZ.
        "TZ",
        # Display — X11. Rarely set in headless RAPTOR runs but harmless.
        "DISPLAY",
        # Non-interactive apt / dpkg. Legitimate tool flag, not exploitable.
        "DEBIAN_FRONTEND",
        # Python runtime flag we set ourselves.
        "PYTHONUNBUFFERED",
        # Trust markers — libexec/ scripts inspect these to verify they
        # were invoked from a trusted parent (bin/raptor, bin/cve-diff,
        # or Claude Code). Pure boolean flags; not shell-interpreted.
        # Must propagate through get_safe_env() because the sandbox
        # spawns its own libexec scripts (raptor-pid1-shim,
        # raptor-run-sandboxed) using this env.
        "_RAPTOR_TRUSTED", "CLAUDECODE",
        # RAPTOR runtime config that downstream subprocesses must
        # honour for the operator's intent to take effect:
        #   RAPTOR_OUT_DIR  output dir override (without this in the
        #                    allowlist, libexec/raptor-run-lifecycle
        #                    re-resolves out dir without the override
        #                    and writes to BASE_OUT_DIR — operator's
        #                    setting is silently lost across the
        #                    subprocess boundary).
        #   RAPTOR_DIR      installation root; libexec scripts derive
        #                    paths from it.
        # Both are validated by get_out_dir() (refuses system paths)
        # so an attacker setting them gains nothing beyond what they
        # already had with same-UID write access to ~/raptor-out.
        "RAPTOR_OUT_DIR", "RAPTOR_DIR",
    })

    # Name prefixes — any variable whose name starts with one of these is
    # kept, treated as a family allowlist. Keep the list minimal.
    SAFE_ENV_PREFIXES = (
        "LC_",          # locale sub-variables (LC_CTYPE, LC_COLLATE, etc.)
    )

    # Environment variables that can be exploited for command injection or
    # runtime code injection when consumed by tools that auto-load config /
    # shell-evaluate / import from them.
    # Ref: Phoenix Security CWE-78 disclosure (2026-03-31, VULN-01).
    #
    # Since the allowlist (SAFE_ENV_ALLOWLIST) is now the primary subprocess
    # defense, every entry here is *redundant* for the sanitise-os.environ
    # path: none of these names are in the allowlist, so get_safe_env()
    # would drop them regardless. The list is kept because it still does
    # real work elsewhere:
    #   1. packages/codeql/database_manager.py — layers build-system-
    #      reported env vars on top of get_safe_env(), filtered through
    #      this blocklist to stop a malicious repo from re-injecting
    #      LD_PRELOAD / PYTHONUSERBASE / etc. via its build metadata.
    #   2. Future repo-content scanning — `.envrc`, `Dockerfile` ENV lines,
    #      CI workflow env sections can all set dangerous vars; this list
    #      is the authoritative reference for what to flag.
    #   3. Belt + braces inside get_safe_env() — if the allowlist is ever
    #      widened (e.g., a new `SSH_*` prefix) the overlay still strips
    #      the specific known-bad names.
    DANGEROUS_ENV_VARS = [
        # Shell/tool-eval vectors
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
        # Loader/library-path redirection
        "LD_PRELOAD",      # Injects shared libraries into child processes
        "LD_LIBRARY_PATH", # Redirects shared library resolution
        "LD_AUDIT",        # Loads auditing modules into the dynamic linker
        "LD_DEBUG",        # Loader debug output — info leak (maps, symbols)
        "LD_PROFILE",      # Loader profiling — writes profile data, side-channel
        "LD_SHOW_AUXV",    # Prints auxv including randomised addresses
        # glibc data-module hijack (survives AT_SECURE on setuid binaries)
        "GCONV_PATH",      # iconv gconv-modules path — loads attacker .so on iconv use
        "LOCPATH",         # Locale data path — loads attacker locale modules
        "NLSPATH",         # Message catalog path — reads attacker-controlled data
        "HOSTALIASES",     # Static hostname→IP file — redirects DNS resolution
        "RES_OPTIONS",     # Resolver options — can influence DNS behaviour
        "LOCALDOMAIN",     # DNS search domain — name-resolution hijack
        # malloc tuning — MALLOC_CHECK_ can make valgrind-style bugs crash,
        # MALLOC_PERTURB_ can alter free()'d memory content, MALLOC_ARENA_MAX
        # can destabilise threaded allocators. Not escapes, but unexpected.
        "MALLOC_CHECK_",
        "MALLOC_PERTURB_",
        "MALLOC_ARENA_MAX",
        "MALLOC_MMAP_THRESHOLD_",
        "MALLOC_TRIM_THRESHOLD_",
        # Tempfile redirection — can cause tools to write outside expected dirs
        "TMPDIR",          # Used by Python tempfile, many shell tools
        # Runtime-specific startup/import redirection
        "PYTHONSTARTUP",   # Executed by Python on startup
        "PYTHONPATH",      # Redirects Python module import path
        "PYTHONHOME",      # Redirects Python standard library location
        "PYTHONINSPECT",   # Drops Python into an interactive prompt after script
        "PERL5OPT",        # Injects Perl command-line options
        "PERLLIB",         # Redirects Perl @INC library path
        "PERL5LIB",        # Same as PERLLIB but higher precedence
        "RUBYOPT",         # Injects Ruby command-line options
        "RUBYLIB",         # Redirects Ruby $LOAD_PATH
        "NODE_OPTIONS",    # Injects Node.js command-line options
        "NODE_PATH",       # Redirects Node.js module resolution
        "JAVA_TOOL_OPTIONS",   # JVM silently prepends this to every invocation
                               # — lets attacker inject -javaagent:... into
                               # any Java process (e.g. CodeQL) and load
                               # arbitrary code at JVM startup.
        "_JAVA_OPTIONS",       # Older variant of JAVA_TOOL_OPTIONS, same hazard.
        "OPENSSL_CONF",        # OpenSSL reads this config file. .conf files
                               # can load ENGINEs (arbitrary .so files) via
                               # the `engines` section — arbitrary code exec
                               # for any process that initialises OpenSSL.
        "PYTHONUSERBASE",      # Verified: arbitrary Python code exec at
                               # interpreter startup via .pth files in
                               # $PYTHONUSERBASE/lib/pythonX.Y/site-packages/.
                               # .pth files beginning with "import " are
                               # exec'd by site.py before any user code runs.
        "VIRTUAL_ENV",         # When set, Python's `site.py` and
                               # various tools (semgrep, pip)
                               # adjust import paths to prefer
                               # `$VIRTUAL_ENV/lib/...` first.
                               # Inheriting the parent's VIRTUAL_ENV
                               # into a subprocess that targets a
                               # DIFFERENT interpreter (system
                               # python, vendored binary) makes the
                               # subprocess silently load packages
                               # from the wrong venv — wrong
                               # versions, broken native deps, or
                               # hostile site-packages content if
                               # the venv was attacker-controlled.
                               # `packages/static-analysis/scanner.py`
                               # was already stripping it locally;
                               # promote here so all callers get
                               # the same guarantee from
                               # `get_safe_env()`.
        "GIT_CONFIG_GLOBAL",   # Overrides ~/.gitconfig path. A malicious
                               # config provides aliases that map to `!sh`
                               # commands, core.editor that execs arbitrary
                               # binaries on commit, credential.helper that
                               # runs on every fetch/push, etc. Any tool
                               # that invokes git picks these up.
        "GIT_CONFIG_SYSTEM",   # Overrides /etc/gitconfig path — same hazard
                               # as GIT_CONFIG_GLOBAL at the system layer.
        "GIT_CONFIG",          # Used by `git config -f FILE` internally but
                               # also respected when set as env — same
                               # injection surface.
        "GIT_SSH_COMMAND",     # Verified: git invokes this for every ssh-
                               # based remote operation (clone/fetch/push
                               # over ssh://). Direct arbitrary command exec.
        "GIT_SSH",             # Older variant of GIT_SSH_COMMAND — same
                               # exec path for git's ssh transport.
        "SSH_ASKPASS",         # Verified: ssh runs this program to prompt
                               # for passwords when no tty is attached.
                               # Any sandboxed tool that invokes ssh (git-
                               # over-ssh, rsync, scp, ansible) triggers it.
                               # Direct arbitrary command exec.
        "PYTHONBREAKPOINT",    # Verified: redirects Python's breakpoint()
                               # builtin to an arbitrary import path. Runs
                               # when code calls breakpoint() — uncommon in
                               # production but real attack surface if any
                               # sandboxed Python tool does.
        "KUBECONFIG",          # Kubernetes config file path. A malicious
                               # kubeconfig's `users[].user.exec` directive
                               # invokes an arbitrary command to obtain
                               # credentials — any kubectl invocation with
                               # a hijacked KUBECONFIG = arbitrary exec.
        # TLS trust / config redirection — weaken or subvert cryptographic
        # operations. Require MITM network position or traffic capture to
        # exploit, but zero legitimate use for the tools RAPTOR runs.
        "GNUTLS_SYSTEM_PRIORITY_FILE",  # GnuTLS cipher priority override
                                        # — can force weak ciphers.
        "NODE_EXTRA_CA_CERTS",          # Node.js extra trusted CA bundle
                                        # — MITM prerequisite.
        "SSLKEYLOGFILE",                # TLS libraries log session keys
                                        # — captured traffic decryptable.
        # Kerberos — config file can redirect to attacker KDC, cache can
        # seed an attacker principal into the process. Low relevance on
        # non-Kerberos hosts; belt and braces.
        "KRB5_CONFIG",
        "KRB5CCNAME",
        # Additional language/tool config that can load attacker-controlled
        # code when the tool runs under a caller-supplied env=. Allowlist-
        # first means these aren't passed to subprocess env normally; the
        # blocklist catches them if a caller supplies them explicitly.
        "CLASSPATH",           # Java: adds attacker .jar to classpath →
                               # arbitrary class loaded at JVM startup via
                               # Class-Path manifest or explicit-main invocation.
        "MAVEN_OPTS",          # Maven-invoked JVM flags. Same -javaagent
                               # / -Djava.security.policy injection as
                               # JAVA_TOOL_OPTIONS but via a different env var.
        "GRADLE_OPTS",         # Same for gradle.
        "CARGO_HOME",          # Rust: points cargo at an attacker config dir
                               # (config.toml can set linker wrapper, build.rs
                               # can execute arbitrary code).
        "GEM_HOME",            # Ruby: search path for gems. A malicious gem
                               # dir loaded on `require` runs at require time.
        "GEM_PATH",            # Ruby: additional gem search paths.
        "BUNDLE_GEMFILE",      # Bundler: pointer to Gemfile. Attacker Gemfile
                               # + Gemfile.lock can run code via post-install
                               # hooks.
        "PHPRC",               # PHP: alternative php.ini. php.ini `extension=`
                               # loads arbitrary .so files at PHP startup.
        "PHP_INI_SCAN_DIR",    # PHP: additional ini scan dir — same vector.
        "GIT_EXEC_PATH",       # Git: substitutes git-<cmd> helpers. Attacker
                               # dir with executable `git-checkout` replaces
                               # the real one for every `git checkout` call.
        "GIT_TEMPLATE_DIR",    # Git: attacker template used by `git init`.
                               # Per-repo hook executables picked up by future
                               # git operations on the init'd repo.
        "EMACSLOADPATH",       # Emacs: additional load path. If any tool
                               # invokes emacs (--batch, etc.), .el files from
                               # the attacker dir auto-load.
        "DOCKER_CONFIG",       # Docker CLI config dir. credsStore /
                               # credHelpers entries invoke arbitrary binaries
                               # named `docker-credential-<helper>` on login.
        "DOCKER_HOST",         # Docker daemon socket. An attacker URL lets
                               # a sandboxed child push images / run
                               # containers against a forged API.
        # TLS trust weakening. Not code-exec on their own but let an MITM
        # position actually intercept our traffic (e.g. if a child does
        # the TLS and the attacker planted a CA cert).
        "REQUESTS_CA_BUNDLE",  # Python `requests` trust anchor override.
        "CURL_CA_BUNDLE",      # curl trust anchor override.
        "SSL_CERT_FILE",       # OpenSSL-based tools' trust anchor override.
        "SSL_CERT_DIR",        # OpenSSL-based tools' trust anchor dir.
        # Allocator config — both glibc and jemalloc honour these env
        # vars. They can enable allocator features (verbose stats,
        # core dumps on detected corruption, profiling output paths)
        # that an attacker can use to (a) leak memory contents into
        # log files at predictable paths, (b) cause core dumps that
        # may contain credentials, (c) redirect heap profile output
        # to attacker-writable paths.
        "MALLOC_CONF",         # jemalloc configuration string.
        "JE_MALLOC_CONF",      # alternate jemalloc env var (some builds).
        "MALLOC_CHECK_",       # glibc heap consistency check; high values
                               # write to stderr → log injection.
        "MALLOC_PERTURB_",     # glibc fill-pattern; not security-critical
                               # alone but lets an attacker influence
                               # uninitialised-memory disclosure ABI.
        # Note: TERM is NOT stripped — it's read as a string (terminfo lookup),
        # not shell-evaluated. Stripping it breaks colour output in git/grep/etc.
    ]

    # Git Configuration
    #
    # GIT_CONFIG_GLOBAL=/dev/null and GIT_CONFIG_SYSTEM=/dev/null force git
    # to ignore the operator's ~/.gitconfig and /etc/gitconfig respectively
    # for every invocation that uses this env. Without these, a malicious
    # gitconfig (alias = !sh, core.editor = arbitrary binary, credential.helper
    # firing on every fetch) loaded out-of-band would still influence git's
    # behaviour even though the env doesn't carry GIT_CONFIG_GLOBAL itself.
    # The blocklist in get_safe_env() only clears caller-supplied overrides;
    # the user's *default* config is read from $HOME, which we don't strip.
    # GIT_CONFIG_NOSYSTEM=1 belt-and-braces in case /dev/null isn't honoured
    # on the platform (e.g. some Windows builds).
    GIT_ENV_VARS = {
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "true",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
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

        Refuses system paths that could be dangerous. Pre-fix this
        WARNED but still returned the resolved path — the operator's
        next `mkdir(out_dir, ...)` then created or polluted system
        directories. Refuse outright with ValueError so the caller
        sees the misconfiguration immediately and can correct
        RAPTOR_OUT_DIR before any filesystem damage.

        Match prefixes on path-component boundary so `/usr-local-foo`
        doesn't false-match the `/usr` rule.

        Returns:
            Path: Resolved output directory path

        Raises:
            ValueError: when RAPTOR_OUT_DIR points at a system prefix.
        """
        base = os.environ.get(RaptorConfig.ENV_OUT_DIR)
        if not base:
            return RaptorConfig.BASE_OUT_DIR
        resolved = Path(base).resolve()
        forbidden = ("/etc", "/usr", "/bin", "/sbin", "/boot", "/dev", "/proc", "/sys")
        resolved_str = str(resolved)
        for prefix in forbidden:
            # Component-boundary match: equals or starts with `prefix/`.
            if resolved_str == prefix or resolved_str.startswith(prefix + "/"):
                raise ValueError(
                    f"RAPTOR_OUT_DIR={resolved!r} resolves under system "
                    f"path {prefix!r}. Refusing to create output there. "
                    f"Set RAPTOR_OUT_DIR to a path under your home or a "
                    f"dedicated work directory."
                )
        # Validate the parent exists. `mkdir(parents=True)` would
        # silently create a deep directory tree under what may be a
        # typo (`RAPTOR_OUT_DIR=/home/raptr/out` — note the missing
        # `o` in `raptor`), leaving orphaned directories scattered
        # across the filesystem and potentially under another user's
        # `$HOME`. Surface the typo to the operator early — better a
        # clear error at config time than silent creation of a wrong-
        # pathed output tree that shows up as "where did my run go?"
        # an hour later.
        if not resolved.exists() and not resolved.parent.exists():
            raise ValueError(
                f"RAPTOR_OUT_DIR={resolved!r} parent directory "
                f"{str(resolved.parent)!r} does not exist. Refusing to "
                f"create a deep tree under what may be a typo. Create "
                f"the parent first or fix the path."
            )
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
    def get_safe_env(*, preserve_proxy: bool = False) -> dict:
        """Return a sanitised copy of os.environ for subprocess use.

        Two-stage filter:
          1. Allowlist (SAFE_ENV_ALLOWLIST + SAFE_ENV_PREFIXES) — primary.
             Only names that match are kept. Everything else drops, so
             future unknown injection vectors (new runtime auto-load env
             vars, new tools that consult ambient state) cannot flow
             through unless we explicitly add them.
          2. Blocklist (DANGEROUS_ENV_VARS + PROXY_ENV_VARS) — overlay.
             Belt + braces against an accidentally-over-broad allowlist
             prefix. By default also strips proxy vars (HTTP_PROXY,
             HTTPS_PROXY, NO_PROXY) — most subprocesses (codeql build,
             fuzzing harness, gdb) shouldn't be making outbound HTTP
             on the operator's behalf, and a proxy that was set for
             interactive use can leak through.

        ``preserve_proxy=True`` keeps the proxy vars in the returned
        env. Use only for subprocesses that legitimately need to
        proxy outbound HTTP — typically the egress wrapper, the
        sandbox proxy itself, or LLM clients that need to honour
        an operator's HTTPS_PROXY setting. The dangerous-env-var
        strip still applies.

        Callers who need a specific extra var (JAVA_HOME for a Java tool,
        a custom CA bundle, etc.) should add it to the returned dict
        explicitly after calling get_safe_env(), or pass their own env=
        to subprocess.run() to bypass this filter entirely.
        """
        from core.security.env_sanitisation import strip_env_vars
        allowlist = RaptorConfig.SAFE_ENV_ALLOWLIST
        prefixes = RaptorConfig.SAFE_ENV_PREFIXES
        env = {}
        for name, value in os.environ.items():
            if name in allowlist or name.startswith(prefixes):
                env[name] = value
        # Belt + braces: strip anything dangerous that somehow made it
        # through (either allowlisted explicitly or matching a prefix).
        if not preserve_proxy:
            env = strip_env_vars(env, RaptorConfig.PROXY_ENV_VARS)
        env = strip_env_vars(env, RaptorConfig.DANGEROUS_ENV_VARS)
        env["PYTHONUNBUFFERED"] = "1"
        return env

    # LLM provider API-key env vars.  These are intentionally NOT in
    # SAFE_ENV_ALLOWLIST — untrusted-code subprocesses (CodeQL builds,
    # fuzz harnesses) must never see credentials.  get_llm_env() layers
    # them on top of get_safe_env() for our own LLM-calling scripts.
    LLM_API_KEY_VARS = (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "MISTRAL_API_KEY",
        # Below: providers RAPTOR doesn't call directly today, but
        # whose keys legitimately need to flow through if the
        # operator wires up a custom dispatcher / aggregator. Pre-fix
        # the missing entries meant `get_llm_env()` stripped these
        # for our analysis scripts even when they were the only
        # configured provider.
        "GOOGLE_API_KEY",       # alternate Gemini env name
        "GROQ_API_KEY",         # aggregator + family stem (batch 067)
        "TOGETHER_API_KEY",     # aggregator
        "OPENROUTER_API_KEY",   # aggregator
        "FIREWORKS_API_KEY",    # aggregator
        "DEEPINFRA_API_KEY",    # aggregator
        "PERPLEXITY_API_KEY",   # aggregator
        "REPLICATE_API_TOKEN",  # aggregator (uses _TOKEN suffix)
        "COHERE_API_KEY",       # cohere family (batch 067)
        # AWS / GCP / Azure cloud providers when used as LLM gateways
        # (Bedrock, Vertex AI, Azure OpenAI). Operators routing
        # through these need credentials to flow through.
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "GOOGLE_APPLICATION_CREDENTIALS",  # GCP service account JSON path
    )

    @staticmethod
    def get_llm_env() -> dict:
        """Return get_safe_env() plus any LLM API keys present in the
        real environment.

        Use this for spawning RAPTOR's own analysis scripts that may call
        LLM providers.  Do NOT use for untrusted-code subprocesses.
        """
        env = RaptorConfig.get_safe_env()
        for var in RaptorConfig.LLM_API_KEY_VARS:
            val = os.environ.get(var)
            if val:
                env[var] = val
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
