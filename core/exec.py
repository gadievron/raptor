#!/usr/bin/env python3
"""Command execution utilities.

Provides safe, consistent command execution across RAPTOR packages.
All functions use list-based arguments (never shell=True) for security.
"""

import os
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from core.config import RaptorConfig
from core.logging import get_logger

logger = get_logger()


def run(cmd, cwd=None, timeout=RaptorConfig.DEFAULT_TIMEOUT, env=None):
    """Execute a command and return results."""
    # Convert Path objects to strings for compatibility
    cwd_str = str(cwd) if isinstance(cwd, Path) else cwd
    
    p = subprocess.run(
        cmd,
        cwd=cwd_str,
        env=env or os.environ.copy(),
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    return p.returncode, p.stdout, p.stderr
