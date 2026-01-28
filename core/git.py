#!/usr/bin/env python3
"""Git utilities for repository operations."""

import os
import re
from pathlib import Path
from typing import Dict, Any, Optional

from core.config import RaptorConfig
from core.logging import get_logger
from core.exec import run

logger = get_logger()


def get_safe_git_env() -> Dict[str, str]:
    """Return environment variables for safe git operations."""
    return RaptorConfig.get_git_env()


def validate_repo_url(url: str) -> bool:
    """Validate repository URL against allowed patterns."""
    allowed_patterns = [
        r'^https://github\.com/[\w\-]+/[\w.\-]+/?$',
        r'^https://gitlab\.com/[\w\-]+/[\w.\-]+/?$',
        r'^git@github\.com:[\w\-]+/[\w.\-]+\.git$',
        r'^git@gitlab\.com:[\w\-]+/[\w.\-]+\.git$',
    ]

    return any(re.match(pattern, url) for pattern in allowed_patterns)


def clone_repository(url: str, target: Path, depth: Optional[int] = 1) -> bool:
    """
    Clone a git repository safely.

    Args:
        url: Repository URL (must pass validation)
        target: Target directory for clone
        depth: Clone depth (1 for shallow, None for full)

    Returns:
        True if clone succeeded

    Raises:
        ValueError: If URL fails validation
        RuntimeError: If clone fails
    """
    # Validate URL
    if not validate_repo_url(url):
        logger.log_security_event(
            "invalid_repo_url",
            f"Rejected potentially unsafe repository URL: {url}"
        )
        raise ValueError(f"Invalid or untrusted repository URL: {url}")

    env = get_safe_git_env()

    cmd = ["git", "clone"]
    if depth is not None:
        cmd.extend(["--depth", str(depth), "--no-tags"])
    cmd.extend([url, str(target)])

    logger.info(f"Cloning repository: {url}")
    rc, so, se = run(
        cmd,
        timeout=RaptorConfig.GIT_CLONE_TIMEOUT,
        env=env,
    )
    if rc != 0:
        raise RuntimeError(f"git clone failed: {se.strip() or so.strip()}")

    logger.info(f"Repository cloned successfully to {target}")
    return True
