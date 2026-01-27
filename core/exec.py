#!/usr/bin/env python3
"""Command execution utilities.

Provides safe, consistent command execution across RAPTOR packages.
All functions use list-based arguments (never shell=True) for security.
"""

import os
import subprocess
import threading
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


def run_streaming(
    cmd: List[str],
    cwd=None,
    timeout: Optional[int] = None,
    env: Optional[dict] = None,
    description: Optional[str] = None,
    print_output: bool = True
) -> Tuple[int, str, str]:
    """
    Run a command and stream output in real-time while also capturing it.
    
    This is useful for long-running commands where you want to show progress
    to the user but still capture the full output for processing.
    
    Args:
        cmd: Command and arguments as a list (never use shell=True)
        cwd: Working directory for command execution (Path or str)
        timeout: Command timeout in seconds (default 1800s for long-running)
        env: Environment variables dict (merged with os.environ)
        description: Optional description for logging
        print_output: Whether to print output in real-time (default True)
        
    Returns:
        Tuple of (returncode, stdout, stderr)
        
    Raises:
        subprocess.TimeoutExpired: If command exceeds timeout
        Exception: For other execution errors
    """
    if timeout is None:
        timeout = 1800  # Default 30 minutes for long-running commands
    
    if description:
        logger.info(f"Running: {description}")
        if print_output:
            print(f"\n[*] {description}...")
    
    # Merge environment variables
    exec_env = os.environ.copy()
    if env:
        exec_env.update(env)
    
    def stream_output(pipe, storage, prefix=""):
        """Read from pipe line by line and print while storing."""
        try:
            for line in iter(pipe.readline, ''):
                if line:
                    storage.append(line)
                    if print_output:
                        print(f"{prefix}{line.rstrip()}", flush=True)
        except Exception:
            pass
        finally:
            pipe.close()
    
    # Convert cwd to string if Path object
    cwd_str = str(cwd) if cwd else None
    
    process = None
    try:
        process = subprocess.Popen(
            cmd,
            cwd=cwd_str,
            env=exec_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
            universal_newlines=True
        )
        
        stdout_lines = []
        stderr_lines = []
        
        # Create threads to read stdout and stderr concurrently
        stdout_thread = threading.Thread(
            target=stream_output,
            args=(process.stdout, stdout_lines)
        )
        stderr_thread = threading.Thread(
            target=stream_output,
            args=(process.stderr, stderr_lines)
        )
        
        # Start reading threads
        stdout_thread.start()
        stderr_thread.start()
        
        # Wait for process to complete
        process.wait(timeout=timeout)
        
        # Wait for all output to be read
        stdout_thread.join()
        stderr_thread.join()
        
        stdout = ''.join(stdout_lines)
        stderr = ''.join(stderr_lines)
        
        return process.returncode, stdout, stderr
        
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        if process:
            process.kill()
        raise
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        if process:
            try:
                process.kill()
            except Exception:
                pass
        raise
