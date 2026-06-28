"""Strip hostile env vars before subprocess calls.

Operator machines may carry attacker-influenced or accidental env values
(HTTPS_PROXY pointing at a local debugger, LD_PRELOAD from a development
tool). When cve-env shells out to git / docker / gh, those vars cross
the subprocess boundary unless we strip them. This is the analog of the
``proxies={"http": "", "https": ""}`` setting for ``requests``: defuse
implicit env-based redirection.

Pattern: default-strip with opt-in retention via ``keep``. Inverse of a
denylist on the child — we only let the child see what we explicitly
preserved.
"""

from __future__ import annotations

import os

# Env vars that subprocess children should NOT inherit by default. Each
# group documents its threat shape:
#
# Python interpreter / loader: PYTHONPATH points at attacker code; a
# child python in our subprocess chain (git's hooks, docker's buildkit
# extensions, gh's plugins) would import from there.
#
# Native loader: LD_PRELOAD / DYLD_INSERT_LIBRARIES inject code into
# every dynamically-linked binary the subprocess runs.
#
# Git command channel: GIT_SSH_COMMAND replaces git's ssh transport with
# attacker's command; GIT_PROXY_COMMAND does the same for the proxy.
#
# Network proxy: HTTPS_PROXY / HTTP_PROXY / ALL_PROXY redirect
# git/docker/gh outbound traffic through attacker MITM.
_DANGEROUS_ENV_VARS: frozenset[str] = frozenset(
    {
        # Python loader / interpreter.
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        # Native loader hijacks.
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        # Git command-channel hijacks.
        "GIT_SSH_COMMAND",
        "GIT_SSH",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG",
        "GIT_TEMPLATE_DIR",
        "GIT_EXEC_PATH",
        "GIT_PROXY_COMMAND",
        "GIT_TRACE",
        # Git config / path overrides — let attacker-controlled env rewrite
        # git's behaviour entirely.
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_SSH",
        "GIT_TEMPLATE_DIR",
        "GIT_WORK_TREE",
        "GIT_DIR",
        # Network proxy redirects (uppercase).
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        # Lowercase forms — some tools honor only the lowercase variant
        # (curl checks both; older clients may check only one).
        "https_proxy",
        "http_proxy",
        "all_proxy",
        # Proxy bypass — attacker excludes their MITM from NO_PROXY so
        # legitimate traffic routes to them.
        "NO_PROXY",
        "no_proxy",
        # Shell startup injection: BASH_ENV / ENV are sourced by
        # non-interactive shells (our subprocess children).
        "BASH_ENV",
        "ENV",
        "PROMPT_COMMAND",
        "CDPATH",
        # Node.js: NODE_OPTIONS injects flags (--require=evil.js);
        # NODE_EXTRA_CA_CERTS pins a rogue CA.
        "NODE_OPTIONS",
        "NODE_EXTRA_CA_CERTS",
        "NODE_PATH",
        # Java: tool agents / startup options inject code via JVMTI.
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JAVA_OPTIONS",
        # OpenSSL: rogue config or engine .so hijacks TLS globally.
        "OPENSSL_CONF",
        "OPENSSL_ENGINES",
        # Editor / pager (can shell-evaluate).
        "TERMINAL",
        "BROWSER",
        "PAGER",
        "VISUAL",
        "EDITOR",
        # TLS trust-store overrides (MITM via planted CA).
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "SSLKEYLOGFILE",
        # Allocator hijacks.
        "MALLOC_CONF",
        # Docker client: DOCKER_HOST redirects to attacker daemon;
        # DOCKER_CONFIG / DOCKER_CERT_PATH / DOCKER_TLS_VERIFY alter
        # credential resolution / TLS trust.
        "DOCKER_HOST",
        "DOCKER_CONFIG",
        "DOCKER_CERT_PATH",
        "DOCKER_TLS_VERIFY",
        # Docker Compose: override compose file or project scope.
        "COMPOSE_FILE",
        "COMPOSE_PROJECT_NAME",
        # SSH: agent / askpass hijacks.
        "SSH_ASKPASS",
        "SSH_AUTH_SOCK",
        # Kubernetes: KUBECONFIG redirects kubectl to attacker cluster.
        "KUBECONFIG",
        # glibc locale / iconv: GCONV_PATH loads arbitrary .so via
        # iconv_open; LOCPATH / NLSPATH load attacker locale data.
        "GCONV_PATH",
        "LOCPATH",
        "NLSPATH",
        # DNS override: HOSTALIASES rewrites name resolution.
        "HOSTALIASES",
        # Temp dir hijacks: attacker-controlled TMPDIR can intercept
        # predictable temp paths used by build tools.
        "TMPDIR",
        "TEMP",
        "TMP",
        # Rust toolchain: CARGO_HOME / RUSTUP_HOME redirect binary lookups.
        "CARGO_HOME",
        "RUSTUP_HOME",
        # Ruby: GEM_HOME / GEM_PATH / BUNDLE_PATH hijack gem resolution;
        # RUBYLIB / RUBYOPT inject code.
        "GEM_HOME",
        "GEM_PATH",
        "BUNDLE_PATH",
        "RUBYLIB",
        "RUBYOPT",
        # PHP: PHPRC / PHP_INI_SCAN_DIR load attacker php.ini.
        "PHPRC",
        "PHP_INI_SCAN_DIR",
        # Java build: CLASSPATH / MAVEN_OPTS / GRADLE_USER_HOME.
        "CLASSPATH",
        "MAVEN_OPTS",
        "GRADLE_USER_HOME",
        # Python venvs: VIRTUAL_ENV / CONDA_PREFIX alter sys.prefix
        # resolution in child python processes.
        "VIRTUAL_ENV",
        "CONDA_PREFIX",
        "CONDA_DEFAULT_ENV",
        # Perl: PERL5LIB / PERL5OPT / PERLLIB inject code.
        "PERL5LIB",
        "PERL5OPT",
        "PERLLIB",
        # Go: GOPATH / GOROOT redirect module / toolchain resolution.
        "GOPATH",
        "GOROOT",
    }
)

# Prefix patterns: env vars matching any of these prefixes are stripped
# even if not in the exact-match set above.  BASH_FUNC_* exports
# serialised shell functions that bash auto-imports — attacker can
# override coreutils (e.g. BASH_FUNC_ls%% ).
_DANGEROUS_ENV_PREFIXES: tuple[str, ...] = (
    "BASH_FUNC_",
)


def safe_subprocess_env(*, keep: frozenset[str] = frozenset()) -> dict[str, str]:
    """Return ``os.environ`` minus the dangerous vars, except those in ``keep``.

    Pass the result as ``env=`` to ``subprocess.run`` / ``Popen``::

        subprocess.run(["git", "clone", url, dst], env=safe_subprocess_env())

    The ``keep`` parameter lets a caller opt back in to a specific
    dangerous var when it's required for a legitimate reason (e.g., a
    test harness that needs ``LD_LIBRARY_PATH`` to find a bundled
    shared library). Use sparingly and document why at each call site.

    Note vs ``requests``: for ``requests``-based HTTP calls, prefer
    ``proxies={"http": "", "https": ""}`` — that disables ``requests``'s
    env-based proxy resolution at the library level.
    ``safe_subprocess_env()`` is for shelled-out commands.
    """
    env = os.environ.copy()
    for k in _DANGEROUS_ENV_VARS - keep:
        env.pop(k, None)
    # Strip prefix-matched vars (e.g. BASH_FUNC_*) unless explicitly kept.
    for k in list(env):
        if k in keep:
            continue
        if any(k.startswith(p) for p in _DANGEROUS_ENV_PREFIXES):
            del env[k]
    return env
