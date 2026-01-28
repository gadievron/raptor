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


def run(
    cmd,
    cwd=None,
    timeout: Optional[int] = None,
    env: Optional[dict] = None,
    description: Optional[str] = None
) -> Tuple[int, str, str]:
    """
    Execute a command and return results.
    
    Args:
        cmd: Command and arguments as a list (never use shell=True)
        cwd: Working directory for command execution (Path or str)
        timeout: Command timeout in seconds (default from config)
        env: Environment variables dict (merged with os.environ)
        description: Optional description for logging
        
    Returns:
        Tuple of (returncode, stdout, stderr)
        
    Raises:
        subprocess.TimeoutExpired: If command exceeds timeout
        Exception: For other execution errors
        
    Security:
        - Always uses list-based arguments (prevents shell injection)
        - Never uses shell=True
        - Environment variables are explicitly controlled
    """
    if timeout is None:
        timeout = RaptorConfig.DEFAULT_TIMEOUT
    
    if description:
        logger.info(f"Running: {description}")
    
    # Merge environment variables
    exec_env = os.environ.copy()
    if env:
        exec_env.update(env)
    
    # Convert cwd to string if Path object
    cwd_str = str(cwd) if cwd else None
    
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd_str,
            env=exec_env,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
        
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        raise
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        raise
