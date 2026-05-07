"""Spawn helper that wires the dispatcher into ``subprocess.Popen``.

Allocates a worker token via the dispatcher, passes the token's
read-end FD into the child, and sets the corresponding env vars.
The child receives:

  * ``RAPTOR_LLM_SOCKET`` — UDS path of the dispatcher.
  * ``RAPTOR_LLM_TOKEN_FD`` — file descriptor number to read the
    token from.

The worker's environment intentionally does NOT contain any LLM
provider API keys. The dispatcher injects them at request time
from its in-memory secret store.
"""

from __future__ import annotations

import subprocess
from typing import Mapping, Optional, Sequence

from .server import LLMDispatcher


def spawn_worker(
    dispatcher: LLMDispatcher,
    cmd: Sequence[str],
    *,
    label: str,
    env: Optional[Mapping[str, str]] = None,
    pass_fds: Sequence[int] = (),
    **popen_kwargs,
) -> subprocess.Popen:
    """Spawn ``cmd`` with credential isolation wired up.

    ``env`` is the base environment for the child (typically
    ``RaptorConfig.get_safe_env()`` so no API keys leak in). The
    helper adds ``RAPTOR_LLM_SOCKET`` and ``RAPTOR_LLM_TOKEN_FD`` on
    top. Other ``Popen`` kwargs flow through unchanged.

    ``label`` shows up in the dispatcher's audit log so it's possible
    to correlate dispatched calls back to the originating subprocess.

    Returns the ``Popen`` object — caller is responsible for waiting
    on it. The token's read-end FD is owned by the child after spawn;
    this side closes it immediately to avoid keeping it alive past the
    child's lifetime.
    """
    socket_path, token_fd = dispatcher.allocate_worker(label=label)

    base_env = dict(env) if env is not None else {}
    base_env["RAPTOR_LLM_SOCKET"] = socket_path
    base_env["RAPTOR_LLM_TOKEN_FD"] = str(token_fd)

    proc = subprocess.Popen(
        list(cmd),
        env=base_env,
        pass_fds=tuple(set([token_fd, *pass_fds])),
        **popen_kwargs,
    )
    # Once Popen has handed the FD to the child, the parent's copy
    # serves no purpose and only delays the pipe's EOF if left open.
    import os
    try:
        os.close(token_fd)
    except OSError:
        pass
    return proc
