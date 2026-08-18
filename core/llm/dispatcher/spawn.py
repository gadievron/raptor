"""Spawn helper that wires the dispatcher into ``subprocess.Popen``.

Allocates a worker token via the dispatcher, passes the token's
read-end FD into the child, and sets the corresponding env vars.
The child receives:

  * ``RAPTOR_LLM_SOCKET`` — UDS path of the dispatcher.
  * ``RAPTOR_LLM_TOKEN_FD`` — file descriptor number to read the
    token from.

Credential posture: the dispatcher injects API keys at request time
from its in-memory secret store, so the worker does not NEED keys in
its environment — but whether it HAS them is the caller's choice of
``env``. With ``env=None`` (or an explicit ``get_safe_env()``) the
worker is keyless. The canonical LLM-purposed caller,
``raptor.py:_run_script``, deliberately passes
``RaptorConfig.get_llm_env()`` — provider keys flow into those
children as a fallback for the env-direct path (see the
``_get_or_start_dispatcher`` docstring there). This helper adds the
socket/token plumbing; it does not strip keys from a caller-supplied
env.
"""

from __future__ import annotations

import subprocess
from collections.abc import Mapping, Sequence

from .server import LLMDispatcher


def spawn_worker(
    dispatcher: LLMDispatcher,
    cmd: Sequence[str],
    *,
    label: str,
    env: Mapping[str, str] | None = None,
    pass_fds: Sequence[int] = (),
    **popen_kwargs,
) -> subprocess.Popen:
    """Spawn ``cmd`` with credential isolation wired up.

    ``env`` is the base environment for the child, passed through
    verbatim — ``RaptorConfig.get_safe_env()`` for keyless workers,
    ``RaptorConfig.get_llm_env()`` where the caller wants provider
    keys available as an env-direct fallback (``raptor.py:_run_script``
    does this). The helper adds ``RAPTOR_LLM_SOCKET`` and
    ``RAPTOR_LLM_TOKEN_FD`` on top. Other ``Popen`` kwargs flow
    through unchanged.

    ``label`` shows up in the dispatcher's audit log so it's possible
    to correlate dispatched calls back to the originating subprocess.

    Returns the ``Popen`` object — caller is responsible for waiting
    on it. The token's read-end FD is owned by the child after spawn;
    this side closes it immediately to avoid keeping it alive past the
    child's lifetime.
    """
    socket_path, token_fd = dispatcher.allocate_worker(label=label)

    # When env=None, fall back to RaptorConfig.get_safe_env() rather
    # than {}. A literally-empty env strips PATH, HOME, LANG, etc. —
    # most child binaries fail catastrophically without them (wrapper
    # binaries re-exec via PATH, Python text-mode I/O picks weird
    # encodings without LANG, process-local config-file resolution
    # explodes without HOME).
    #
    # Mirrors core/sandbox/context.py:890-906 — same treatment of
    # env=None, same rationale: env=None means "default behaviour"
    # (safe baseline shell env minus secrets), not "literally empty".
    # The dispatcher's whole point is credential isolation — API keys
    # are injected per-request from the in-memory secret store, not
    # passed via env — so get_safe_env() is the right baseline.
    # preserve_proxy: workers are RAPTOR's own scripts; non-LLM
    # outbound traffic (registry fetches, git) and any `claude` CLI
    # grandchild resolve the upstream proxy from the worker's env.
    if env is not None:
        base_env = dict(env)
    else:
        from core.config import RaptorConfig
        base_env = RaptorConfig.get_safe_env(preserve_proxy=True)
        # Transport-routing family (CLAUDE_CODE_USE_*, ANTHROPIC_MODEL,
        # AWS profile/region NAMES, RAPTOR_BEDROCK_*/RAPTOR_CC_*) —
        # workers resolve their models.json entries locally, and a
        # minimal Bedrock entry backfills surface/model from these.
        # Names and flags only: credential isolation is preserved
        # (the dispatcher still injects the actual secrets at request
        # time from its in-memory store).
        base_env.update(RaptorConfig.llm_routing_env())
    base_env["RAPTOR_LLM_SOCKET"] = socket_path
    base_env["RAPTOR_LLM_TOKEN_FD"] = str(token_fd)

    import os
    try:
        proc = subprocess.Popen(
            list(cmd),
            env=base_env,
            pass_fds=tuple({token_fd, *pass_fds}),
            **popen_kwargs,
        )
    except BaseException:
        # Popen failure (missing worker binary, exec-permission
        # error) — without this, the token pipe's read FD stranded
        # in the parent for the process lifetime.
        try:
            os.close(token_fd)
        except OSError:
            pass
        raise
    # Once Popen has handed the FD to the child, the parent's copy
    # serves no purpose and only delays the pipe's EOF if left open.
    try:
        os.close(token_fd)
    except OSError:
        pass
    return proc
