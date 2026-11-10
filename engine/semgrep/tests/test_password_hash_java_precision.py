"""Native JCA source identity controls; no digest/provider execution."""

import shutil
import pytest
import json
from pathlib import Path
from core.audit.tests._live_transport import run_pinned_subprocess
from core.config import RaptorConfig

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed"),
]


def test_password_hash_jca_import_identity(tmp_path):
    report = tmp_path
    target = report / "owned"
    target.mkdir(exist_ok=True)
    cases = {
        "direct": (
            'import java.security.MessageDigest;\nclass Owned { byte[] digest(String password) throws Exception { return MessageDigest.getInstance("SHA-256").digest(password.getBytes()); } }\n',
            True,
        ),
        "qualified": (
            'class Owned { byte[] digest(String password) throws Exception { return java.security.MessageDigest.getInstance("SHA-256").digest(password.getBytes()); } }\n',
            True,
        ),
        "unrelated": (
            'import owned_unrelated.MessageDigest;\nclass Owned { byte[] digest(String password) throws Exception { return MessageDigest.getInstance("SHA-256").digest(password.getBytes()); } }\n',
            False,
        ),
        "non_password": (
            'import java.security.MessageDigest;\nclass Owned { byte[] digest(String document) throws Exception { return MessageDigest.getInstance("SHA-256").digest(document.getBytes()); } }\n',
            False,
        ),
    }
    expected = set()
    for name, (source, reports) in cases.items():
        filename = name + ".java"
        (target / filename).write_text(source)
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
        context="Owned inert password hash import identity",
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
    rows = [
        row
        for row in data["results"]
        if row["check_id"].endswith("raptor.crypto.password.weak-hash.java")
    ]
    actual = {Path(row["path"]).name for row in rows}
    (report / "summary.json").write_text(
        json.dumps(
            {
                "expected": sorted(expected),
                "actual": sorted(actual),
                "missing": sorted(expected - actual),
                "unexpected": sorted(actual - expected),
                "rows": len(rows),
                "version": data.get("version"),
                "scope": "Inert Java import/API syntax; no digest/provider operation executed",
            },
            indent=2,
        )
    )
    assert actual == expected
    assert len(rows) == len(expected)
