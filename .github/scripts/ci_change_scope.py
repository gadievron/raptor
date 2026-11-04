"""Obtain complete Git changes for CI; unknown history never means no changes."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path


def changed_paths(repo: Path, base: str, head: str = 'HEAD') -> list[str] | None:
    if not re.fullmatch(r'[0-9a-fA-F]{40,64}', base or '') or set(base) == {'0'}:
        return None
    try:
        exists = subprocess.run(['git', 'cat-file', '-e', base + '^{commit}'], cwd=repo,
                                capture_output=True, timeout=10)
        if exists.returncode:
            subprocess.run(['git', 'fetch', '--no-tags', '--depth=1', 'origin', base],
                           cwd=repo, check=True, capture_output=True, timeout=30)
        result = subprocess.run(['git', 'diff', '--no-renames', '--name-only', '-z',
                                 base, head, '--'], cwd=repo, check=True,
                                capture_output=True, timeout=30)
        return [p.decode('utf-8', errors='surrogateescape')
                for p in result.stdout.split(b'\0') if p]
    except (OSError, subprocess.SubprocessError):
        return None
