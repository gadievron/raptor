"""Resolve the container's first-use launcher before entering a sandbox."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess


def resolve_bootstrap(cli: str | None, *, install: bool = True) -> str | None:
    """Ordinary installations pass through; bootstrap errors abort the caller."""
    if not cli or Path(os.path.realpath(cli)).name != "raptor-codeql-bootstrap":
        return cli
    from core.config import RaptorConfig

    env = RaptorConfig.get_safe_env(preserve_proxy=True)
    try:
        result = subprocess.run(
            [cli, "--raptor-resolve" if install else "--raptor-resolve-existing"],
            stdout=subprocess.PIPE, stderr=None if install else subprocess.PIPE, text=True,
            check=True, timeout=1200, env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        if not install:
            return None
        raise RuntimeError("CodeQL first-use installation failed; run codeql --raptor-install for diagnostics") from exc
    path = result.stdout.strip()
    if (not os.path.isabs(path) or not os.path.isfile(path)
            or not os.access(path, os.X_OK)
            or Path(os.path.realpath(path)).name == "raptor-codeql-bootstrap"):
        if not install:
            return None
        raise RuntimeError("CodeQL installer did not return an executable distribution path")
    return path
