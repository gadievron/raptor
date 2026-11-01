"""Capabilities for real installation-protection checks."""
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.fixture(scope="session")
def require_install_mounts():
    if sys.platform != "linux":
        reason = "Linux namespaces are required"
    else:
        helper = Path(__file__).resolve().parents[1] / '_install_namespace.py'
        probe = subprocess.run([sys.executable, '-I', str(helper), '--probe'],
                               capture_output=True, text=True, timeout=5)
        if probe.returncode == 0:
            return
        reason = "native namespace preflight failed: " + probe.stderr.strip()
    if os.environ.get("RAPTOR_INSTALL_PROTECTION_ACCEPTANCE") == "1":
        pytest.fail(reason)
    pytest.skip(reason)
