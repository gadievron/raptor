"""Native API identity controls; no cipher construction or encryption."""

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


def test_pycryptodome_nonce_imports_and_arguments(tmp_path):
    report = tmp_path
    target = report / "owned"
    target.mkdir(exist_ok=True)
    prefix = ""
    cases = {
        "direct": (
            'from Crypto.Cipher import AES\nAES.new(key, AES.MODE_GCM, nonce=b"0" * 12)\n',
            True,
        ),
        "alias": (
            'from Crypto.Cipher import AES as Box\nBox.new(key, Box.MODE_GCM, nonce=b"0" * 12)\n',
            True,
        ),
        "qualified": (
            'import Crypto.Cipher.AES\nCrypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_GCM, nonce=b"0" * 12)\n',
            True,
        ),
        "keyword_mode": (
            'from Crypto.Cipher import AES\nAES.new(key=key, mode=AES.MODE_GCM, nonce=b"0" * 12)\n',
            True,
        ),
        "cbc_keyword": (
            'from Crypto.Cipher import AES\nAES.new(key=key, mode=AES.MODE_CBC, iv=b"0" * 16)\n',
            True,
        ),
        "cbc_positional": (
            'from Crypto.Cipher import AES\nAES.new(key, AES.MODE_CBC, b"0" * 16)\n',
            True,
        ),
        "unrelated": (
            'from owned_unrelated import AES\nAES.new(key, AES.MODE_GCM, nonce=b"0" * 12)\n',
            False,
        ),
        "unrelated_iv": (
            'from owned_unrelated import AES\nAES.new(key, mode, iv=b"0" * 16)\n',
            False,
        ),
        "dynamic": (
            "from Crypto.Cipher import AES\nAES.new(key, AES.MODE_GCM, nonce=nonce)\n",
            False,
        ),
        "literal_data": (
            'from Crypto.Cipher import AES\nAES.new(b"literal key", AES.MODE_GCM, nonce=nonce)\n',
            False,
        ),
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
                / "rules/crypto/insecure-iv-or-nonce.yaml"
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
        context="Owned inert PyCryptodome nonce identity baseline",
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
        if row["check_id"].endswith("raptor.crypto.iv.literal.pycryptodome.python")
    }
    (report / "summary.json").write_text(
        json.dumps(
            {
                "expected": sorted(expected),
                "actual": sorted(actual),
                "missing": sorted(expected - actual),
                "unexpected": sorted(actual - expected),
                "version": data.get("version"),
                "scope": "Canonical identity and advertised argument detection only; no constructors or encryption executed",
            },
            indent=2,
        )
    )
    assert actual == expected
    assert len(data["results"]) == len(expected)
