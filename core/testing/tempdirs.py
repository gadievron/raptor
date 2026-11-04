"""Fresh test state directories without pytest's numbered-directory scans."""
from __future__ import annotations

from pathlib import Path
from tempfile import mkdtemp
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest


def isolated_test_dir(factory: pytest.TempPathFactory, prefix: str) -> Path:
    """Create private per-test state beneath the worker's retained basetemp.

    Numbered mktemp scans all siblings on every allocation. Autouse fixtures
    multiply that cost across large suites and also slow ordinary tmp_path
    allocations by filling their shared parent. Keep state under one parent
    and let mkdtemp choose an unused name without listing existing entries.
    """
    parent = factory.getbasetemp() / 'isolated-state'
    parent.mkdir(mode=0o700, exist_ok=True)
    return Path(mkdtemp(prefix=f'{prefix}-', dir=parent))
