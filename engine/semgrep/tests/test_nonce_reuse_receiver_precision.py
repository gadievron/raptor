"""Inert native receiver-write controls; no AEAD execution."""

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


def test_nonce_reuse_receiver_reassignment(tmp_path):
    report = tmp_path
    target = report / "owned"
    target.mkdir(exist_ok=True)
    prefix = "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
    cases = {
        "same": (
            "c = AESGCM(key)\nc.encrypt(nonce, data, None)\nc.encrypt(nonce, other_data, None)\n",
            {4},
        ),
        "rebound": (
            "c = AESGCM(key)\nc.encrypt(nonce, data, None)\nc = AESGCM(other_key)\nc.encrypt(nonce, other_data, None)\n",
            set(),
        ),
        "nonce_changed": (
            "c = AESGCM(key)\nc.encrypt(nonce, data, None)\nnonce = other_nonce\nc.encrypt(nonce, other_data, None)\n",
            set(),
        ),
        "fresh_pair": (
            "c = AESGCM(key)\nc.encrypt(nonce, data, None)\nc = AESGCM(other_key)\nc.encrypt(nonce, other_data, None)\nc.encrypt(nonce, more_data, None)\n",
            {6},
        ),
        "early_pair": (
            "c = AESGCM(key)\nc.encrypt(nonce, data, None)\nc.encrypt(nonce, other_data, None)\nc = AESGCM(other_key)\nc.encrypt(nonce, more_data, None)\n",
            {4},
        ),
        "unrelated_write": (
            "c = AESGCM(key)\nc.encrypt(nonce, data, None)\nother = object()\nc.encrypt(nonce, other_data, None)\n",
            {5},
        ),
    }
    expected = set()
    for name, (body, lines) in cases.items():
        (target / (name + ".py")).write_text(prefix + body)
        expected.update((name + ".py", line) for line in lines)
    result = run_pinned_subprocess(
        [
            "semgrep",
            "scan",
            "--config",
            str(
                Path(__file__).resolve().parents[1]
                / "rules/crypto/reused-nonce-heuristic.yaml"
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
        context="Owned inert nonce reuse receiver stability",
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
        if row["check_id"].endswith("raptor.crypto.nonce.reuse.two-calls.python")
    ]
    actual = {(Path(row["path"]).name, row["end"]["line"]) for row in rows}
    (report / "summary.json").write_text(
        json.dumps(
            {
                "expected": sorted(expected),
                "actual": sorted(actual),
                "missing": sorted(expected - actual),
                "unexpected": sorted(actual - expected),
                "rows": len(rows),
                "version": data.get("version"),
                "scope": "Inert source receiver-write controls; no AEAD construction or encryption executed",
            },
            indent=2,
        )
    )
    assert actual == expected
    assert len(rows) == len(expected)
