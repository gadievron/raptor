"""Native argument and import identity for Python RSA/DSA key-size rules."""
from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from core.audit.tests._live_transport import run_pinned_subprocess
from core.config import RaptorConfig

_RULE = Path(__file__).resolve().parents[1] / "rules/crypto/weak-asym-keysize.yaml"
pytestmark = [pytest.mark.slow, pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed")]


def test_asymmetric_key_python_argument_identity(tmp_path):
    # API signatures were verified from library source. These fixtures are
    # parsed by Semgrep only: no crypto dependency import or key generation.
    lines = [
        "from cryptography.hazmat.primitives.asymmetric import rsa, dsa",
        "from Crypto.PublicKey import RSA, DSA",
        "from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as rsa_key",
        "from cryptography.hazmat.primitives.asymmetric.dsa import generate_private_key as dsa_key",
    ]
    cases = [
        ("rsa.generate_private_key(public_exponent=65537,key_size=1024)", "rsa"),
        ("rsa.generate_private_key(65537,1024)", "rsa"),
        ("rsa.generate_private_key(65537,key_size=1024)", "rsa"),
        ("rsa_key(65537,1024)", "rsa"),
        ("dsa.generate_private_key(key_size=1024)", "dsa"),
        ("dsa.generate_private_key(1024)", "dsa"),
        ("dsa_key(1024)", "dsa"),
        ("RSA.generate(1024)", "rsa"),
        ("RSA.generate(bits=1024)", "rsa"),
        ("DSA.generate(1024)", "dsa"),
        ("DSA.generate(bits=1024)", "dsa"),
        ("rsa.generate_private_key(65537,2048)", None),
        ("rsa.generate_private_key(public_exponent=65537,key_size=2048)", None),
        ("dsa.generate_private_key(2048)", None),
        ("dsa.generate_private_key(key_size=2048)", None),
        ("RSA.generate(bits=2048)", None),
        ("DSA.generate(bits=2048)", None),
    ]
    expected = set()
    for number, (expression, kind) in enumerate(cases):
        lines.extend([f"def case_{number}():", f"    return {expression}"])
        if kind:
            expected.add(("owned.py", len(lines), kind))
    target = tmp_path / "owned.py"
    target.write_text("\n".join(lines) + "\n")
    other = tmp_path / "other.py"
    other.write_text(
        "from other import rsa, dsa\n"
        "rsa.generate_private_key(public_exponent=65537,key_size=1024)\n"
        "dsa.generate_private_key(key_size=1024)\n")
    proc = run_pinned_subprocess(
        ["semgrep", "scan", "--config", str(_RULE), "--metrics", "off",
         "--disable-version-check", "--jobs", "1", "--json", str(target), str(other)],
        timeout=60, context="Python RSA/DSA argument and import identity",
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(path).name for path in data["paths"]["scanned"]} == {target.name, other.name}
    actual = {(Path(row["path"]).name, row["start"]["line"],
               row["check_id"].split("raptor.crypto.")[-1].split(".")[0])
              for row in data["results"]}
    assert actual == expected
