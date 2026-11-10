"""Native standard-library identity controls; fixture hashes are not executed."""

import shutil
import pytest
from pathlib import Path
import json
from core.audit.tests._live_transport import run_pinned_subprocess
from core.config import RaptorConfig


pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed"),
]


def test_password_hash_hashlib_import_identity(tmp_path):
    report = tmp_path
    target = report / "owned"
    target.mkdir(exist_ok=True)
    prefix = ""
    cases = {
        "direct": ("import hashlib\nhashlib.sha256(password)\n", True),
        "alias": ("import hashlib as hashes\nhashes.sha256(password)\n", True),
        "named": ("from hashlib import sha256\nsha256(password)\n", True),
        "named_alias": (
            "from hashlib import sha256 as digest\ndigest(password)\n",
            True,
        ),
        "encoded": ("import hashlib\nhashlib.sha256(password.encode())\n", True),
        "unrelated": (
            "from owned_unrelated import hashlib\nhashlib.sha256(password)\n",
            False,
        ),
        "unrelated_named": (
            "from owned_unrelated import sha256\nsha256(password)\n",
            False,
        ),
        "non_password": ("import hashlib\nhashlib.sha256(document)\n", False),
        "policy": ("import hashlib\nhashlib.sha256(password_policy)\n", False),
    }
    expected = set()
    for name, (source, reports) in cases.items():
        filename = name + ".py"
        (target / filename).write_text(prefix + source)
        if reports:
            expected.add(filename)
    result = run_pinned_subprocess(
        [
            "semgrep",
            "scan",
            "--config",
            str(
                Path(__file__).resolve().parents[1]
                / "rules/crypto/insecure-password-hash.yaml"
            ),
            "--metrics",
            "off",
            "--disable-version-check",
            "--jobs",
            "1",
            "--json",
            *map(str, sorted(target.iterdir())),
        ],
        timeout=60,
        context="Owned inert Python password hash import identity baseline",
        env=RaptorConfig.get_safe_env(),
        skip_signals=(9,),
    )
    (report / "stdout.json").write_text(result.stdout)
    (report / "stderr.log").write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(p).name for p in data["paths"]["scanned"]} == {
        p.name for p in target.iterdir()
    }
    actual = {
        Path(row["path"]).name
        for row in data["results"]
        if row["check_id"].endswith("raptor.crypto.password.weak-hash.python")
    }
    (report / "summary.json").write_text(
        json.dumps(
            {
                "expected": sorted(expected),
                "actual": sorted(actual),
                "missing": sorted(expected - actual),
                "unexpected": sorted(actual - expected),
                "version": data.get("version"),
                "scope": "Canonical identity and advertised argument detection only; no fixture hash operation executed",
            },
            indent=2,
        )
    )
    assert actual == expected
    assert len(data["results"]) == len(expected)
