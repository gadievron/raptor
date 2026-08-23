"""Environment-variable sanitisation helpers.

RAPTOR strips known-dangerous environment variables (runtime code-exec
vectors like `LD_PRELOAD` / `BASH_ENV` / `PYTHONUSERBASE` / `GIT_SSH_COMMAND`,
proxy overrides like `HTTPS_PROXY`) at multiple layers:

  1. `core.config.RaptorConfig.get_safe_env()` — builds a sanitised
     subprocess env from the parent's `os.environ`, applying the
     allowlist and then the blocklist overlay.
  2. `core.sandbox.context.sandbox().run()` — when a caller supplies
     their own `env=` (bypassing get_safe_env), the blocklist is still
     applied so a caller bug can't leak a code-exec vector through.

Both paths do the same dict-level work. This module centralises the
two primitives so future callers (new subprocess-spawning code, new
blocklists) get one canonical vocabulary.
"""

from collections.abc import Iterable


def normalise_proxy_url(value: str) -> str:
    """Normalise a proxy URL taken from HTTP(S)_PROXY / ALL_PROXY.

    Strips surrounding whitespace and any trailing slashes. The
    convention allows a bare trailing slash ("http://proxy:3128/") and
    permissive clients accept it, but strict parsers reject it — the
    observed case is the JVM's HttpHost (CodeQL's pack downloader dies
    with "Invalid HTTP host" when the env value carries the slash).
    Normalising once at ingestion means every child process, JVM or
    not, sees a value in the strictest accepted form. NO_PROXY values
    are host lists, not URLs — never route them through this.
    """
    return value.strip().rstrip("/")


def strip_env_vars(env: dict, names: Iterable[str]) -> dict:
    """Return a copy of `env` with every key in `names` removed.

    Preserves dict insertion order for keys that remain. Accepts any
    iterable of names — list, tuple, set, frozenset — and converts it
    to a frozenset once for O(1) membership checks.
    """
    blocklist = frozenset(names)
    return {k: v for k, v in env.items() if k not in blocklist}


def intersect_env_vars(env: dict, names: Iterable[str]) -> list:
    """Return the sorted list of keys from `env` that appear in `names`.

    Audit / logging companion to `strip_env_vars`. Use this before
    stripping to name what was removed (callers often want to
    `logger.warning` the specific variables so the operator can tell
    whether their own env was buggy vs. a third-party-set var).
    Sorted output keeps log lines stable across runs.
    """
    blocklist = frozenset(names)
    return sorted(k for k in env if k in blocklist)
