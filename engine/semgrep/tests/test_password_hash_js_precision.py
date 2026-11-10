"""Native module identity controls; no hashing operations executed."""

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


def test_password_hash_node_import_identity(tmp_path):
    report = tmp_path
    target = report / "owned"
    target.mkdir(exist_ok=True)
    cases = {
        "default": (
            'import crypto from "crypto";\ncrypto.createHash("sha256").update(password);\n',
            True,
        ),
        "namespace": (
            'import * as hashes from "node:crypto";\nhashes.createHash("sha256").update(password);\n',
            True,
        ),
        "require": (
            'const hashes = require("crypto");\nhashes.createHash("sha256").update(password);\n',
            True,
        ),
        "named": (
            'import { createHash } from "crypto";\ncreateHash("sha256").update(password);\n',
            True,
        ),
        "named_alias": (
            'import { createHash as digest } from "node:crypto";\ndigest("sha256").update(password);\n',
            True,
        ),
        "node_default": (
            'import crypto from "node:crypto";\ncrypto.createHash("sha256").update(password);\n',
            True,
        ),
        "unrelated": (
            'import crypto from "owned-unrelated";\ncrypto.createHash("sha256").update(password);\n',
            False,
        ),
        "non_password": (
            'import crypto from "crypto";\ncrypto.createHash("sha256").update(document);\n',
            False,
        ),
    }
    expected = set()
    for suffix in ["js", "ts"]:
        for name, (source, reports) in cases.items():
            filename = name + "." + suffix
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
        if row["check_id"].endswith("raptor.crypto.password.weak-hash.js")
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
                "scope": "Inert import/API syntax; no hashing or password operation executed",
            },
            indent=2,
        )
    )
    assert actual == expected
    assert len(rows) == len(expected)
