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
        "GIT_EXEC_PATH",
        "GIT_PROXY_COMMAND",
        "GIT_TRACE",
        # Network proxy redirects (uppercase).
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        # Lowercase forms — some tools honor only the lowercase variant
        # (curl checks both; older clients may check only one).
        "https_proxy",
        "http_proxy",
        "all_proxy",
    }
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
    return env
