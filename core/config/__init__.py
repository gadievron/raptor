"""
RAPTOR Centralized Configuration Module

This module provides centralized configuration management for the RAPTOR framework,
including paths, timeouts, limits, and baseline settings.
"""

import os
from pathlib import Path
from typing import ClassVar

# Imported at module level DELIBERATELY (stdlib-only leaf module, no
# cycle risk): get_safe_env() runs inside post-fork sandbox children
# (_spawn.run_sandboxed's env=None default), where a lazy first-time
# import would need filesystem reads the child's Landlock read
# allowlist does not grant — the child died ModuleNotFoundError
# whenever the parent process had not already imported the module.
from core.security.env_sanitisation import normalise_proxy_url, strip_env_vars
from core.security.rule_of_two import is_ci


class classproperty:
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
    #
    # ``VERSION`` is the baked release constant: it is stamped to the clean
    # release number in the tag/archive at release time (see
    # ``.github/workflows/release.yml``) and is what a release archive — which
    # has no ``.git`` to derive from — reports.
    #
    # ``effective_version()`` is what the running tool should report/display.
    # In a git checkout it derives the true position relative to the last
    # release tag (e.g. ``3.0.0-1786-g7fcf38ea``) so a clone that is many
    # commits past a release never masquerades as that clean release. It falls
    # back to ``VERSION`` when there is no usable git checkout (archive,
    # exported copy, git absent).
    VERSION = "3.0.0"

    @classmethod
    def effective_version(cls) -> str:
        """Runtime version: ``git describe`` in a checkout, else ``VERSION``."""
        import subprocess
        from pathlib import Path

        repo = Path(__file__).resolve().parents[2]
        if not (repo / ".git").exists():
            return cls.VERSION
        try:
            proc = subprocess.run(
                ["git", "-C", str(repo), "describe",
                 "--tags", "--dirty=-local", "--always"],
                capture_output=True, text=True, timeout=2,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return cls.VERSION
        desc = proc.stdout.strip()
        if proc.returncode != 0 or not desc:
            return cls.VERSION
        return desc.lstrip("v")

    # Tool dependencies for startup checks
    # severity: "required" = feature unavailable, "degrades" = feature limited
    # group: tools in same group need at least one present
    #
    # Version-display convention (startup banner + doctor): a tool's
    # version is shown IF AND ONLY IF RAPTOR gates behaviour on that
    # version; presence-only otherwise. The version-gated set today:
    #   * python  — 3.10+ floor (PEP 604 unions at import time)
    #   * z3      — SMT feature coverage varies by release
    #   * semgrep — rule semantics vary across releases; CI pins one
    #   * joern   — MIN_JOERN_VERSION floor (packages/joern/prereqs.py)
    #   * gcc     — -fanalyzer corroboration needs gcc >= 10
    # Do NOT add versions for anything else — the probes cost startup
    # time and the number carries no decision weight without a gate.
    # Probe implementations live in core/startup/init.py
    # (check_tools / _check_analyzer_capabilities); keep that module
    # and this list in sync when a new version gate lands.
    TOOL_DEPS: ClassVar[dict] = {
        "afl++":        {"binary": "afl-fuzz",  "severity": "required", "affects": "/fuzz"},
        "codeql":       {"binary": "codeql",    "group": "scanner",     "affects": "/codeql, /agentic"},
        # Coccinelle (spatch) is required for source_intel's verdict-
        # active axes (1-7). Without spatch, source_intel falls back
        # to UNCERTAIN on most findings — informational-only axes
        # (axis 1 alias scan, axis 6 build flags, axis 8 validation-
        # after-overflow) still work via pure-Python paths.
        # ``affects`` is operator-facing — names user commands ("/codeql,
        # /agentic"), not internal subsystem axes. ``source_intel`` /
        # ``verdict-active`` mean nothing to an operator reading /doctor.
        "coccinelle":   {"binary": "spatch",    "severity": "degrades", "affects": "/codeql, /agentic (C/C++ semantic-patch verification)"},
        "gdb":          {"binary": "gdb",       "severity": "required", "affects": "/crash-analysis, /fuzz"},
        "joern":        {"binary": "joern",     "severity": "degrades", "affects": "/audit (inter-procedural taint analysis)"},
        "rr":           {"binary": "rr",        "severity": "degrades", "affects": "/crash-analysis"},
        "semgrep":      {"binary": "semgrep",   "group": "scanner",     "affects": "/scan, /agentic"},
        # Dynamic analysis tools
        "frida":        {"binary": "frida",       "severity": "degrades", "affects": "/frida, dynamic analysis, /fuzz harness probe"},
        "frida-trace":  {"binary": "frida-trace", "severity": "degrades", "affects": "dynamic tracing"},
        # Binary-oracle reachability and /audit's binary-evidence
        # channel read ELF symbols/DWARF via binutils (readelf, nm,
        # objdump, c++filt). readelf is the presence proxy — the
        # suite ships as one package on every distro.
        "binutils":     {"binary": "readelf",     "severity": "degrades", "affects": "/agentic, /codeql, /validate (binary-oracle reachability)"},
        # r2 drives --binary-edges call-graph extraction
        # (core/analysis/binary_oracle_edges.py) and /audit's binary
        # corroboration (core/audit/capabilities.py).
        "radare2":      {"binary": "r2",          "severity": "degrades", "affects": "/agentic, /codeql (--binary-edges), /audit (binary evidence)"},
        # Perlasm generated-asm inventory (core/inventory/perlasm.py):
        # without perl, detected generators become loud coverage gaps
        # instead of enumerable generated kernels.
        "perl":         {"binary": "perl",        "severity": "degrades", "affects": "/scan, /agentic, /audit (perlasm generated-asm inventory)"},
        # SMT feasibility engine — a Python module, not a binary
        # (checked via importlib.util.find_spec). Consumers guard the
        # import and degrade: /audit path-feasibility, /codeql dataflow
        # validation, and exploit_feasibility one-gadget checks fall
        # back to LLM-only / unknown verdicts without it. ``pip`` names
        # the PyPI distribution (module name differs).
        "z3":           {"module": "z3", "pip": "z3-solver", "severity": "degrades", "affects": "/audit, /codeql, /exploit (SMT feasibility)"},
    }

    TOOL_GROUPS: ClassVar[dict] = {
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
    EXTRA_CODEQL_PACK_ROOTS: ClassVar[list[Path]] = [
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

    # Curated in-repo CodeQL query packs (CODEQL_QUERIES_DIR/<lang>/)
    # kill-switch. When False, `QueryRunner.analyze_curated_packs`
    # skips the curated pass entirely. Defaults to True so the
    # hand-written queries run alongside the standard suites.
    # Per-run CLI override: `/codeql --no-curated-queries`.
    CODEQL_CURATED_ENABLED: bool = True

    # Learned-models measurement pass on the /codeql agent: emit the
    # project's tool-corroborated IRIS taint specs as a models-as-data
    # extension pack and run the baseline-vs-augmented measurement over
    # a small per-language query set. Augmented-only findings join the
    # report as candidates (provenance=learned-model); suppression is
    # measurement-only — nothing is dropped. Per-run CLI override:
    # `/codeql --no-learned-models`.
    CODEQL_LEARNED_MODELS_ENABLED: bool = True

    # Mechanical Java source-wrapper summaries: same-tree helper
    # methods whose return provably carries servlet-request data
    # (core/analysis/java_source_summaries) are emitted as
    # models-as-data sourceModel rows and threaded into the standard
    # java suite via --additional-packs. Additive detection only.
    CODEQL_SOURCE_SUMMARIES_ENABLED: bool = True

    # Record-only sanitizer-cut post-pass over scan SARIF findings
    # (core/analysis/sanitizer_cut_postpass.py): value-bound gate
    # verdicts are written to suppressions.jsonl as evidence
    # (dropped: false) so the recall harness's warm scorer can measure
    # the projected FP rate. Never mutates, demotes, or drops a
    # finding. Per-run CLI override: `--no-sanitizer-cut-postpass`.
    SANITIZER_CUT_POSTPASS_ENABLED: bool = True

    # Sanitizer-cut ENFORCEMENT (corpus-earned 2026-08-19, operator-
    # approved — see the attested sanitizer_dominated entry in
    # core/analysis/reach_witness.py and
    # measured enforcement evidence): full-proof suppress
    # verdicts drop their findings from the combined SARIF, with
    # dropped: true records in suppressions.jsonl. Per-tool SARIFs stay
    # unfiltered (forensic record). Per-run CLI override:
    # `--no-sanitizer-cut-enforce` (reverts to record-only evidence).
    SANITIZER_CUT_ENFORCE_ENABLED: bool = True

    # Config-resolved additive findings (scan stage, Java): selector
    # calls (MessageDigest/Cipher/SecureRandom.getInstance) whose
    # argument resolves through the strict properties-file resolver to
    # a known-weak algorithm emit a NEW finding with
    # provenance=config-resolved. Detection only — the stage never
    # suppresses, and a resolution failure emits nothing. Per-run CLI
    # override: `--no-config-resolved`.
    CONFIG_RESOLVED_ENABLED: bool = True

    # Threat models passed to `codeql database analyze` on the STANDARD
    # suite pass (`--threat-model=<name>` per entry, additive to the
    # always-on `default`/remote model). `local` enables the
    # environment / commandargs / stdin / file / database source kinds
    # on stock queries — the same source classes RAPTOR's in-repo IRIS
    # packs model by hand (the IRIS pass stays: its verdicts feed the
    # refute-downgrade path). Version-gated in the runner: CLIs older
    # than CODEQL_THREAT_MODEL_MIN_VERSION never see the flag. The flag
    # is a no-op for query packs / languages without threat-model
    # support (CLI-documented behavior), so passing it is safe.
    # Kill-switch: CODEQL_THREAT_MODELS_ENABLED = False.
    # Per-run CLI overrides: `/codeql --threat-models <csv>` and
    # `/codeql --no-threat-models`.
    CODEQL_THREAT_MODELS_ENABLED: bool = True
    CODEQL_THREAT_MODELS: ClassVar[tuple] = ("local",)

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
    def CODEQL_ENABLED(cls):
        """Persistent CodeQL toggle from ``tuning.json``.

        When False, ``/agentic`` no longer injects ``--codeql`` by
        default. CLI flags still override: ``--codeql`` forces ON,
        ``--no-codeql`` forces OFF, regardless of this config.
        """
        return cls._tuning().codeql_enabled

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
    BASELINE_SEMGREP_PACKS: ClassVar[list[tuple[str, str]]] = [
        ("semgrep_security_audit", "p/security-audit"),
        ("semgrep_owasp_top_10", "p/owasp-top-ten"),
        ("semgrep_secrets", "p/secrets"),
    ]

    # Mapping of policy groups to their corresponding semgrep registry packs
    # Format: {local_dir_name: (pack_name, pack_identifier)}
    POLICY_GROUP_TO_SEMGREP_PACK: ClassVar[dict[str, tuple[str, str]]] = {
        # Only packs that exist on semgrep.dev and are cached in registry-cache/
        # deserialisation, filesystem, logging: no registry pack exists, local rules only
        # crypto: p/crypto and category/crypto both 404 — local rules only
        # ssrf: p/ssrf 404; local coverage via POLICY_GROUP_RULE_FILES
        "secrets": ("semgrep_secrets", "p/secrets"),
        "injection": ("semgrep_injection", "p/command-injection"),
        "auth": ("semgrep_auth", "p/jwt"),
        "flows": ("semgrep_dataflow", "p/default"),
        "sinks": ("semgrep_sinks", "p/xss"),
        "best-practices": ("semgrep_best_practices", "p/default"),
    }

    # Policy groups whose in-repo rules live in a single file inside
    # another group's directory rather than a directory of their own.
    # Selecting the group scans exactly that file; the emitted rule ids
    # are identical to a directory scan of the parent group (semgrep
    # derives ids from the rule FILE's path), so `--policy-groups
    # ssrf,sinks` dedups cleanly. No registry pack exists for these.
    POLICY_GROUP_RULE_FILES: ClassVar[dict[str, Path]] = {
        "ssrf": SEMGREP_RULES_DIR / "sinks" / "ssrf.yaml",
    }

    # Default Policy Configuration
    DEFAULT_POLICY_VERSION = "v1"
    DEFAULT_POLICY_GROUPS = "all"

    # Environment Variables
    ENV_OUT_DIR = "RAPTOR_OUT_DIR"
    # Operator override for target classification
    # (auto|library|hybrid|application) consulted by
    # core.inventory.library_detection.resolve_library_mode when the
    # programmatic setting is "auto". The escape hatch for when
    # auto-detection misclassifies a target (e.g. asserting 'hybrid' on a
    # lib+CLI whose manifest only exposes the library side).
    ENV_TARGET_KIND = "RAPTOR_TARGET_KIND"

    # Operator-supplied debug binaries for the current target — triggers
    # binary-oracle enrichment of the inventory (DWARF-joined per-function
    # classification). Mutated by the ``--binary`` CLI flag (repeatable)
    # at process start; read by ``build_inventory`` at the end of the
    # build. Empty tuple = no enrichment.
    #
    # MULTIPLE binaries are the common case for ``--target-kind=hybrid``
    # (a target that ships BOTH a library AND an application — npm
    # package with main+bin, Python package with console_scripts,
    # a C library that also ships a CLI). The classifier runs against
    # each binary independently; the per-source-function results are
    # combined with alive-in-any-wins semantics, so a function is only
    # ``absent`` when EVERY declared binary lacks it. Picking the wrong
    # single binary stops being a footgun.
    #
    # Follows the same in-process-ambient pattern as ``DEFAULT_TIMEOUT``
    # — no env var (binary_oracle hasn't yet shown a need to cross
    # subprocess boundaries; revisit if /validate or another helper grows
    # one).
    BINARY_ORACLE_PATHS: tuple[str, ...] = ()

    # Inc 2b Tier 1: when True, extract direct call edges from each
    # binary in BINARY_ORACLE_PATHS (via r2) and annotate inventory
    # items with binary-found callers. Affirmative reachability
    # evidence — a function with binary-confirmed callers gets the
    # ``binary_call_edge`` REACHABLE verdict via reach_witness.
    # Opt-in because r2 ``aaa`` is slow (~10-30s per binary on
    # typical sizes); operators turn it on when they care about
    # source-graph false-deads on indirect / fn-pointer call sites.
    BINARY_ORACLE_EDGES: bool = False

    # Perlasm generated-asm inventory (core/inventory/perlasm.py):
    # detect perlasm generators structurally, run them under the
    # strict sandbox profile (fail-closed), and inventory the emitted
    # assembly as ``asm-generated`` records. Default-on because the
    # pass is zero-cost on repos without perlasm generators and
    # fail-closed everywhere else (no strict sandbox => loud coverage
    # gap, no execution). ``RAPTOR_NO_PERLASM=1`` is the env
    # kill-switch for a single run.
    PERLASM_INVENTORY: bool = True

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
    # Implement as a descriptor so `RaptorConfig.OLLAMA_HOST` (class
    # access; the existing call pattern across `core/llm/`) re-reads
    # the env var on every access — a plain class attribute would
    # freeze the value at import time. Instance access is impossible
    # by design: RaptorConfig.__init__ raises TypeError (class-level
    # namespace, never instantiated), so the descriptor only ever
    # serves class reads.
    class _OllamaHostDescriptor:
        def __get__(self, obj, objtype=None):
            return os.getenv("OLLAMA_HOST", "http://localhost:11434")

    OLLAMA_HOST = _OllamaHostDescriptor()

    # Proxy variables to strip for security
    PROXY_ENV_VARS: ClassVar[list] = [
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
        "http_proxy", "https_proxy", "no_proxy", "all_proxy",
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
        # raptor-run-sandboxed) using this env. Untrusted TARGETS do
        # not see them: run_untrusted()/run_untrusted_networked()
        # strip both from the target-bound env (strip_trust_markers
        # in core/sandbox/context.py), and the pid1 shim strips them
        # before exec on the unshare path. RAPTOR's own Claude Code
        # skill dispatches opt out via keep_trust_markers=True (see
        # run_untrusted_networked) — those children drive libexec/
        # helpers on the operator-approved run and need the marker.
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
        #   RAPTOR_TARGET_KIND  operator's target-classification override
        #                    (auto|library|hybrid|application). Must survive
        #                    the subprocess boundary so an inventory rebuilt in
        #                    a child honours the operator's intent. Only ever
        #                    read as an enum (any other value → auto); no
        #                    injection surface.
        "RAPTOR_TARGET_KIND",
    })

    # CI markers ride the allowlist: RAPTOR's own interactivity gate
    # (core.security.rule_of_two.is_interactive) runs inside children
    # whose env this scrub produced — stripping every CI marker made
    # the gate judge a pseudo-TTY CI runner as a human, silently
    # opening the weakened-defenses consent path in CI. Pure boolean
    # flags, no injection surface; one source of truth in
    # rule_of_two so the lists cannot drift. (Deferred import: keeps
    # the class body free of a module-level core.security dependency
    # while still evaluating exactly once at class-definition time.)
    from core.security.rule_of_two import ci_env_vars as _ci_env_vars
    SAFE_ENV_ALLOWLIST = SAFE_ENV_ALLOWLIST | frozenset(_ci_env_vars())
    del _ci_env_vars

    # Name prefixes — any variable whose name starts with one of these is
    # kept, treated as a family allowlist. Keep the list minimal.
    SAFE_ENV_PREFIXES = (
        "LC_",          # locale sub-variables (LC_CTYPE, LC_COLLATE, etc.)
    )

    # Exploit-feasibility knobs that may cross the scrub boundary:
    # numeric budgets and shared-toggle booleans only — no injection
    # surface, and the loader runs inside scrub-spawned children where
    # dropping them silently discarded the operator's settings.
    #
    # Deliberately NOT a RAPTOR_EF_ prefix family: the rest of the
    # namespace is exec-path class. RAPTOR_EF_{CHECKSEC,ROPGADGET,
    # ONE_GADGET}_PATH name binaries the analysis EXECUTES,
    # RAPTOR_EF_CONFIG names a JSON that can set those same paths, and
    # RAPTOR_EF_CACHE_DIR redirects writes — the EDITOR/PAGER threat
    # class this scrub exists to strip. Those work only in the
    # operator's direct (unscrubbed) session environment.
    SAFE_ENV_ALLOWLIST = SAFE_ENV_ALLOWLIST | frozenset({
        "RAPTOR_EF_TIMEOUT_FAST", "RAPTOR_EF_TIMEOUT_NORMAL",
        "RAPTOR_EF_TIMEOUT_MEDIUM", "RAPTOR_EF_TIMEOUT_SLOW",
        "RAPTOR_EF_TIMEOUT_VERY_SLOW", "RAPTOR_EF_TIMEOUT_MAX",
        "RAPTOR_EF_ENABLE_CACHING", "RAPTOR_EF_ROP_CACHE_SIZE",
        "RAPTOR_EF_MAX_GADGETS", "RAPTOR_EF_VERIFY_FORMAT_N",
        "RAPTOR_EF_VERBOSE",
    })

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
    DANGEROUS_ENV_VARS = frozenset([
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
        # macOS dyld equivalents — no-ops on Linux, critical on macOS
        "DYLD_INSERT_LIBRARIES",      # macOS equivalent of LD_PRELOAD
        "DYLD_LIBRARY_PATH",          # macOS equivalent of LD_LIBRARY_PATH
        "DYLD_FALLBACK_LIBRARY_PATH", # macOS fallback library resolution
        "DYLD_FRAMEWORK_PATH",        # macOS framework injection
        # glibc data-module hijack (survives AT_SECURE on setuid binaries)
        "GCONV_PATH",      # iconv gconv-modules path — loads attacker .so on iconv use
        "LOCPATH",         # Locale data path — loads attacker locale modules
        "NLSPATH",         # Message catalog path — reads attacker-controlled data
        "HOSTALIASES",     # Static hostname→IP file — redirects DNS resolution
        "RES_OPTIONS",     # Resolver options — can influence DNS behaviour
        "LOCALDOMAIN",     # DNS search domain — name-resolution hijack
        # malloc tuning — MALLOC_CHECK_ can make valgrind-style bugs crash
        # (and high values write to stderr → log injection),
        # MALLOC_PERTURB_ can alter free()'d memory content (letting an
        # attacker influence uninitialised-memory disclosure ABI),
        # MALLOC_ARENA_MAX can destabilise threaded allocators. Not
        # escapes, but unexpected. Sole entries — keep the allocator
        # family together here (the jemalloc pair lives with the other
        # allocator-config vars below).
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
        # Allocator config — jemalloc honours these env vars. They can
        # enable allocator features (verbose stats, core dumps on
        # detected corruption, profiling output paths) that an
        # attacker can use to (a) leak memory contents into log files
        # at predictable paths, (b) cause core dumps that may contain
        # credentials, (c) redirect heap profile output to attacker-
        # writable paths. The glibc MALLOC_* family is listed once,
        # with the malloc-tuning group above.
        "MALLOC_CONF",         # jemalloc configuration string.
        "JE_MALLOC_CONF",      # alternate jemalloc env var (some builds).
        # Note: TERM is NOT stripped — it's read as a string (terminfo lookup),
        # not shell-evaluated. Stripping it breaks colour output in git/grep/etc.
    ])

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
    GIT_ENV_VARS: ClassVar[dict] = {
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
        # Check BOTH the lexically-normalised input and the symlink-
        # resolved path. On macOS /etc, /var and /tmp are symlinks into
        # /private, so a literal RAPTOR_OUT_DIR=/etc resolves to
        # /private/etc and would slip past a resolved-only check — catch
        # the operator-typed system path via os.path.normpath too. The
        # resolved check still guards against a symlink that points into
        # a (Linux-named) system directory.
        candidates = (os.path.normpath(base), str(resolved))
        for path_str in candidates:
            for prefix in forbidden:
                # Component-boundary match: equals or starts with `prefix/`.
                if path_str == prefix or path_str.startswith(prefix + "/"):
                    raise ValueError(
                        f"RAPTOR_OUT_DIR={base!r} resolves under system "
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
    def get_safe_env(
        *,
        preserve_proxy: bool = False,
        include_python_user_base: bool = False,
    ) -> dict:
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

        ``include_python_user_base=True`` (F102) re-admits the
        ``PYTHONUSERBASE`` variable from the original os.environ
        AFTER the dangerous-env-vars strip. Use only at scanner
        invocation sites that legitimately depend on a
        ``pip install --user`` tool (e.g. semgrep). The variable is
        a real RCE vector via .pth files (see DANGEROUS_ENV_VARS
        comment at PYTHONUSERBASE) and stays stripped by default;
        but if the operator deliberately installed the scanner under
        ``~/.local`` with a non-default ``PYTHONUSERBASE`` set, the
        subprocess fails ``ModuleNotFoundError`` without this opt-in.
        Mirrors the ``preserve_proxy`` opt-in pattern.

        Callers who need a specific extra var (JAVA_HOME for a Java tool,
        a custom CA bundle, etc.) should add it to the returned dict
        explicitly after calling get_safe_env(), or pass their own env=
        to subprocess.run() to bypass this filter entirely.
        """
        allowlist = RaptorConfig.SAFE_ENV_ALLOWLIST
        prefixes = RaptorConfig.SAFE_ENV_PREFIXES
        env = {}
        for name, value in os.environ.items():
            if name in allowlist or name.startswith(prefixes):
                env[name] = value
        # Belt + braces: strip anything dangerous that somehow made it
        # through (either allowlisted explicitly or matching a prefix).
        env = strip_env_vars(env, RaptorConfig.DANGEROUS_ENV_VARS)
        # Stamp the parent's CI verdict so the interactivity gate in
        # children never depends on which vendor markers survived the
        # scrub (allowlist churn must not be able to reopen the
        # CI-with-pseudo-TTY bypass). RAPTOR_CI is itself a recognised
        # marker in core.security.rule_of_two.
        if is_ci():
            env["RAPTOR_CI"] = "1"
        if preserve_proxy:
            for pv in RaptorConfig.PROXY_ENV_VARS:
                val = os.environ.get(pv)
                if val is not None:
                    # URL-shaped values are normalised (trailing slash
                    # breaks strict parsers like the JVM's HttpHost);
                    # NO_PROXY is a host list and passes through.
                    if not pv.upper().startswith("NO_"):
                        val = normalise_proxy_url(val)
                    env[pv] = val
        # F102: restore PYTHONUSERBASE AFTER the dangerous-var strip
        # for callers that opted in (e.g. semgrep scanner spawn).
        # Take the value verbatim from os.environ — do NOT invent
        # one if the operator didn't set it.
        if include_python_user_base:
            _userbase = os.environ.get("PYTHONUSERBASE")
            if _userbase is not None:
                env["PYTHONUSERBASE"] = _userbase
        env["PYTHONUNBUFFERED"] = "1"
        # Git config isolation for EVERY subprocess (inert for non-git
        # tools). Without this, any internal or sandboxed git invocation
        # reads the operator's ~/.gitconfig and /etc/gitconfig: a
        # commit.gpgsign=true there routes `git commit` through
        # gpg-agent/keyboxd (unix-socket IPC that network-denied
        # sandboxes block — observed as non-deterministic "failed to
        # write commit object"), log.showSignature invokes gpg on
        # reads, core.fsmonitor spawns watchers, credential.helper
        # fires on fetches. Applied AFTER the dangerous-var strip so
        # OUR values win over any operator/caller-supplied override.
        # Deliberate trade: operator gitconfig http.proxy /
        # url.insteadOf / credential.helper no longer influence
        # internal git — proxying flows through the env vars
        # (preserve_proxy) instead. Sites that predate this chokepoint
        # via get_git_env() are unaffected (same values).
        env.update(RaptorConfig.GIT_ENV_VARS)
        # RAPTOR_DIR is allowlisted above so children can derive tool
        # paths — but the AMBIENT value may point at a different
        # checkout (multi-checkout operators). Pin it to THIS tree so
        # RAPTOR's own Python children never import another tree's
        # modules (see pin_raptor_dir).
        pin_raptor_dir(env)
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
        "ORCAROUTER_API_KEY",   # aggregator
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
        # Bedrock's AWS-recommended bearer credential. A selection
        # signal AND a secret: children that resolve models locally
        # (mode scripts, the audit pipeline) starve on Bedrock entry
        # resolution without it. Same posture as the AWS access keys
        # above — LLM children only, never untrusted subprocesses.
        "AWS_BEARER_TOKEN_BEDROCK",
    )

    # LLM transport/backend ROUTING env vars — selection flags and
    # names, not secrets (credentials stay in LLM_API_KEY_VARS; the
    # profile-based AWS chain reads the actual keys from the profile
    # files that AWS_PROFILE / AWS_SHARED_CREDENTIALS_FILE merely
    # name). Intentionally NOT in SAFE_ENV_ALLOWLIST: untrusted-code
    # subprocesses have no business knowing the operator's LLM
    # topology, and RAPTOR's own LLM children get them layered on by
    # get_llm_env() / spawn_worker(). Without this family, every
    # spawned LLM child lost the operator's backend selection:
    # a minimal {"provider": "bedrock"} models.json entry could not
    # backfill surface/model from the Claude Code install
    # (_cc_bedrock_topology reads CLAUDE_CODE_USE_BEDROCK), the
    # dispatcher's SigV4 chain lost its profile/region pins, and the
    # claudecode fallback's `claude -p` child silently flipped from
    # the operator's Bedrock backend to the direct API — where a
    # Bedrock-shaped model id is a guaranteed HTTP 400.
    LLM_ROUTING_ENV_VARS = (
        # Claude Code backend selection — read by core.llm.config
        # (_cc_bedrock_topology backfill), core.llm.cc_adapter
        # (cc_subprocess_env AWS gate), core.llm.cc_proxy_hosts
        # (egress profile), core.llm.cc_probe (cache signature), and
        # by the `claude` CLI itself in grandchildren.
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_MANTLE",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
        # Anthropic model mapping / endpoint — the CC-topology model
        # backfill (gated on CLAUDE_CODE_USE_BEDROCK) and the `claude`
        # CLI's own session-default resolution. The direct-API SDK
        # path never reads ANTHROPIC_MODEL (verified: the only
        # in-repo functional read is inside _cc_bedrock_topology,
        # which returns early unless CLAUDE_CODE_USE_BEDROCK is set),
        # so carrying it cannot re-route direct-API children.
        "ANTHROPIC_MODEL",
        "ANTHROPIC_SMALL_FAST_MODEL",
        "ANTHROPIC_BASE_URL",
        # AWS signing-chain names — profile/region/config-file
        # LOCATIONS, not credentials. Read by the dispatcher's SigV4
        # auth chain, detection.bedrock_sigv4_intent, and egress
        # host derivation. Needed: a child that cannot see them
        # resolves a different (usually empty) signing chain than
        # the parent that selected the provider.
        "AWS_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        # Nice-to-have (nonstandard installs only): honour custom
        # shared-credentials/config locations so botocore's chain in
        # the child matches the parent's.
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CONFIG_FILE",
    )

    # RAPTOR's own LLM operator knobs, carried as prefix families
    # (same pattern as cc_adapter's _CC_BACKEND_ENV_PREFIXES: new
    # knobs in these namespaces keep working without call-site
    # churn). RAPTOR_BEDROCK_* are the explicit Bedrock opt-in
    # signals (MODEL / PROFILE / REGION / API) plus operational knobs
    # (MAX_WORKERS / PREFLIGHT_CACHE); RAPTOR_CC_* are the claudecode
    # transport knobs (MODEL / PIN_MODEL / EFFORT / FALLBACK_MODEL /
    # BUDGET_USD / PROBE_CACHE). NOT RAPTOR_LLM_: the dispatcher
    # route (RAPTOR_LLM_SOCKET + RAPTOR_LLM_TOKEN_FD) is per-child
    # state that only spawn_worker may set — a blanket-inherited
    # socket path without its token FD is a broken route.
    LLM_ROUTING_ENV_PREFIXES = (
        "RAPTOR_BEDROCK_",
        "RAPTOR_CC_",
    )

    @staticmethod
    def llm_routing_env() -> dict:
        """The LLM routing family present in the real environment.

        Names and selection flags only — no credentials (those are
        ``LLM_API_KEY_VARS``, layered separately by ``get_llm_env``).
        Overlay this onto a sanitised base env at every seam that
        spawns one of RAPTOR's OWN LLM-calling children
        (``get_llm_env`` does it automatically; ``spawn_worker``
        applies it to its default baseline). Never overlay onto an
        env destined for untrusted target code.
        """
        env = {}
        for var in RaptorConfig.LLM_ROUTING_ENV_VARS:
            val = os.environ.get(var)
            if val:
                env[var] = val
        for name, val in os.environ.items():
            if name.startswith(RaptorConfig.LLM_ROUTING_ENV_PREFIXES) and val:
                env[name] = val
        return env

    @staticmethod
    def get_llm_env(
        *,
        include_python_user_base: bool = False,
    ) -> dict:
        """Return get_safe_env() plus any LLM API keys and the LLM
        transport-routing family present in the real environment.

        Use this for spawning RAPTOR's own analysis scripts that may call
        LLM providers.  Do NOT use for untrusted-code subprocesses.

        ``include_python_user_base=True`` (F102b) forwards the opt-in
        to the underlying ``get_safe_env()`` so PYTHONUSERBASE is
        preserved on the returned env. Use at canonical-operator
        spawn sites (``raptor.py:_run_script``) whose child script
        in turn opts into the F102 restoration (e.g.
        ``raptor_agentic.py``'s semgrep spawn at line 757). Without
        this forwarding, the parent strips PYTHONUSERBASE before the
        child can restore it, and the F102 fix is orphaned for
        ``python raptor.py <mode>`` invocations. Mirrors the existing
        ``include_python_user_base`` opt-in on ``get_safe_env`` —
        same default-False, opt-in pattern as ``preserve_proxy``.

        Proxy vars are ALWAYS preserved here (``preserve_proxy=True``
        on the underlying ``get_safe_env``). Rationale: this env is
        exclusively for RAPTOR's own analysis scripts — trusted code
        that hosts the sandbox egress proxy, spawns ``claude`` CLI
        children, and makes provider SDK calls, all of which resolve
        their upstream route from the process environment at runtime
        (``core/sandbox/proxy.py`` autodetect,
        ``egress.operator_proxy_env()``,
        ``get_safe_env(preserve_proxy=True)``). Stripping the
        operator's launch-time proxy here starves every one of those
        mechanisms one level down and breaks all outbound HTTP on
        mandatory-egress-proxy hosts. The hostile-repo threat that
        motivates the default strip does not apply: these children
        never execute target-repo code with this env.
        """
        env = RaptorConfig.get_safe_env(
            preserve_proxy=True,
            include_python_user_base=include_python_user_base,
        )
        for var in RaptorConfig.LLM_API_KEY_VARS:
            val = os.environ.get(var)
            if val:
                env[var] = val
        # Transport/backend routing family (CLAUDE_CODE_USE_*,
        # ANTHROPIC_MODEL, AWS profile/region names, RAPTOR_BEDROCK_*/
        # RAPTOR_CC_* knobs). Applied AFTER get_safe_env so the
        # documented LLM-env additions never depend on allowlist
        # ordering; none of the names are in DANGEROUS_ENV_VARS, and
        # RAPTOR_DIR pinning (inside get_safe_env) is untouched —
        # the family shares no names with the pinned var.
        env.update(RaptorConfig.llm_routing_env())
        return env

    @staticmethod
    def strip_llm_env_vars(env: dict) -> dict:
        """Remove LLM credentials, the transport-routing family, and
        the dispatcher route pair from *env*; returns *env*.

        For RAPTOR's own NON-LLM helper children that are spawned
        from full-environ copies rather than ``get_safe_env()``
        (the SMT/Z3 probe children: they must mirror the parent's
        interpreter environment to unpickle and run RAPTOR verbs,
        so they can't take the safe-env baseline — but they make no
        LLM calls and have no business holding keys, backend
        selection, or a broken half-route).
        """
        drop = set(RaptorConfig.LLM_API_KEY_VARS)
        drop.update(RaptorConfig.LLM_ROUTING_ENV_VARS)
        drop.update(("RAPTOR_LLM_SOCKET", "RAPTOR_LLM_TOKEN_FD"))
        prefixes = RaptorConfig.LLM_ROUTING_ENV_PREFIXES
        for name in [k for k in env
                     if k in drop or k.startswith(prefixes)]:
            del env[name]
        return env

    @staticmethod
    def get_git_env() -> dict:
        """Environment for safe git operations — thin alias.

        ``get_safe_env()`` already applies ``GIT_ENV_VARS`` for every
        subprocess (git-config isolation is part of the baseline), so
        this is deliberately a pure passthrough with no second overlay:
        one source of truth, nothing to diverge. Kept as a named entry
        point because call sites read better as "give me the git env"
        and predate the chokepoint.

        Returns:
            dict: Environment configured for secure git operations
        """
        return RaptorConfig.get_safe_env()

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


# Ambient RAPTOR_DIR values whose override has already been announced
# (one line per distinct value per process, not one per spawn — a
# single audit run spawns dozens of SMT/Z3 children).
_RAPTOR_DIR_OVERRIDE_NOTICED: set = set()


def pin_raptor_dir(env) -> dict:
    """Hard-set ``RAPTOR_DIR`` in *env* to THIS tree's root; return *env*.

    ``RAPTOR_DIR`` tells RAPTOR's own Python children which tree to
    import ``core.*`` from (the mandated child bootstrap is
    ``sys.path.insert(0, os.environ['RAPTOR_DIR'])``). The ambient
    value is whatever the launching shell exported — operators running
    multiple checkouts routinely have it pointing at a DIFFERENT tree,
    and a child that inherits it silently imports the other tree's
    modules (observed: every SMT probe of an audit run exited 1 with
    ``TypeError: _run_smt_verb_inner() got an unexpected keyword
    argument`` because the child imported a stale checkout's
    ``core.audit.sweep``). Children of THIS process must import THIS
    tree, so the value is SET — never ``setdefault``'d — with a
    one-line notice the first time a differing ambient value is
    replaced: running multiple checkouts is normal; silently importing
    the wrong tree's modules is not.
    """
    import logging

    own = str(RaptorConfig.REPO_ROOT)
    ambient = env.get("RAPTOR_DIR")
    if ambient and ambient != own and ambient not in _RAPTOR_DIR_OVERRIDE_NOTICED:
        differs = True
        try:
            differs = Path(ambient).resolve() != RaptorConfig.REPO_ROOT
        except OSError:
            pass
        if differs:
            _RAPTOR_DIR_OVERRIDE_NOTICED.add(ambient)
            logging.getLogger(__name__).info(
                "RAPTOR_DIR override: ambient value %s points at a "
                "different checkout — children of this process import "
                "from %s",
                ambient, own,
            )
    env["RAPTOR_DIR"] = own
    return env


def pin_raptor_dir_in_environ() -> None:
    """Pin ``os.environ['RAPTOR_DIR']`` to this tree's root.

    Launcher-side chokepoint (libexec preambles, e2e scripts): every
    child that inherits ``os.environ`` afterwards — including the
    ``python3 -c`` SMT/Z3 probe children — imports this tree.
    """
    pin_raptor_dir(os.environ)


# Canonical boolean-toggle spellings. One parser for every operator
# on/off env var so the accepted spellings don't drift per reader
# (pre-fix: SAGE_FORCE_CPU treated "0" as enabling, RAPTOR_SAGE_AFL_PRIOR
# ignored "off", CVE_DIFF_DISABLE_RULES ignored "true").
_ENV_FLAG_TRUTHY = frozenset({"1", "true", "yes", "on"})
_ENV_FLAG_FALSY = frozenset({"0", "false", "no", "off"})


def env_flag(name: str, default: bool) -> bool:
    """Parse the boolean environment toggle *name*.

    Canonical spellings, case-insensitive, surrounding whitespace
    ignored: truthy = ``1``/``true``/``yes``/``on``, falsy =
    ``0``/``false``/``no``/``off``. Unset or empty returns *default*.
    Any other value warns (so a typo like ``SAGE_FORCE_CPU=ture``
    doesn't silently pick the default) and returns *default*.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if not value:
        return default
    if value in _ENV_FLAG_TRUTHY:
        return True
    if value in _ENV_FLAG_FALSY:
        return False
    import logging

    logging.getLogger(__name__).warning(
        "%s=%r is not a recognised boolean toggle "
        "(1/true/yes/on or 0/false/no/off); using default %s",
        name, raw, default,
    )
    return default


# Convenience aliases for backward compatibility
def get_out_dir() -> Path:
    """Backward compatible function for getting output directory."""
    return RaptorConfig.get_out_dir()
