"""PBKDF2 iteration checks preserve Python keyword argument semantics."""
from __future__ import annotations

import inspect
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from core.audit.tests._live_transport import run_pinned_subprocess

_RULE = Path(__file__).resolve().parents[1] / "rules/crypto/weak-kdf-iterations.yaml"
pytestmark = [pytest.mark.slow, pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed")]


def test_pbkdf2_iteration_argument_forms(tmp_path):
    # Introspection verifies the actual installed API; no fixture is executed.
    parameter = inspect.signature(hashlib.pbkdf2_hmac).parameters["iterations"]
    assert parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    cases = [
        ('hashlib.pbkdf2_hmac("sha256", pw, salt, 1)', True),
        ('hashlib.pbkdf2_hmac("sha256", pw, salt, 99999, 32)', True),
        ('hashlib.pbkdf2_hmac("sha256", pw, salt, iterations=99999)', True),
        ('hashlib.pbkdf2_hmac(hash_name="sha256", password=pw, salt=salt, iterations=99999)', True),
        ('hashlib.pbkdf2_hmac(iterations=99999, salt=salt, password=pw, hash_name="sha256")', True),
        ('hashlib.pbkdf2_hmac("sha256", pw, salt, dklen=32, iterations=99999)', True),
        ('h.pbkdf2_hmac("sha256", pw, salt, iterations=99999)', True),
        ('derive("sha256", pw, salt, iterations=99999)', True),
        ('hashlib.pbkdf2_hmac("sha256", pw, salt, 100000)', False),
        ('hashlib.pbkdf2_hmac("sha256", pw, salt, iterations=100000)', False),
        ('hashlib.pbkdf2_hmac(hash_name="sha256", password=pw, salt=salt, iterations=100_000)', False),
        ('hashlib.pbkdf2_hmac("sha256", pw, salt, iterations=100001)', False),
        ('other.pbkdf2_hmac("sha256", pw, salt, iterations=1)', False),
        ('hashlib.scrypt(pw, salt=salt, n=1024, r=8, p=1)', False),
    ]
    lines = ["import hashlib", "import hashlib as h",
             "from hashlib import pbkdf2_hmac as derive", "import other"]
    expected = set()
    for number, (expression, reports) in enumerate(cases):
        lines.extend([f"def case_{number}(pw, salt):", f"    return {expression}"])
        if reports:
            expected.add(len(lines))
    target = tmp_path / "owned.py"
    target.write_text("\n".join(lines) + "\n")
    proc = run_pinned_subprocess(
        ["semgrep", "scan", "--config", str(_RULE), "--metrics", "off",
         "--disable-version-check", "--jobs", "1", "--json", str(target)],
        timeout=60, context="PBKDF2 iteration keyword parity", skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(path).name for path in data["paths"]["scanned"]} == {target.name}
    actual = {row["start"]["line"] for row in data["results"]
              if row["check_id"].endswith("raptor.crypto.pbkdf2.low-iterations.python")}
    assert actual == expected
