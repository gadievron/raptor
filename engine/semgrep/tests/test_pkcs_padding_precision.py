"""Native Cipher API identity controls; source fixtures are never executed."""

import json
import shutil
from pathlib import Path

import pytest

from core.audit.tests._live_transport import run_pinned_subprocess
from core.config import RaptorConfig

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed"),
]

_JVM_CASES = {
    "bare.java": (
        "import javax.crypto.Cipher;\n"
        'class Owned { void check() throws Exception { Cipher.getInstance("RSA"); } '
        "}\n",
        True,
    ),
    "bare.kt": (
        'import javax.crypto.Cipher\nfun check() { Cipher.getInstance("RSA") }\n',
        True,
    ),
    "canonical.java": (
        "import javax.crypto.Cipher;\n"
        "class Owned { void check() throws Exception { "
        'Cipher.getInstance("RSA/ECB/PKCS1Padding"); } }\n',
        True,
    ),
    "canonical.kt": (
        "import javax.crypto.Cipher\n"
        'fun check() { Cipher.getInstance("RSA/ECB/PKCS1Padding") }\n',
        True,
    ),
    "provider.java": (
        "import javax.crypto.Cipher;\n"
        "class Owned { void check() throws Exception { "
        'Cipher.getInstance("rsa/ecb/pkcs1padding", "OwnedProvider"); } }\n',
        True,
    ),
    "provider.kt": (
        "import javax.crypto.Cipher\n"
        'fun check() { Cipher.getInstance("rsa/ecb/pkcs1padding", "OwnedProvider") '
        "}\n",
        True,
    ),
    "qualified.java": (
        "class Owned { void check() throws Exception { "
        'javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding"); } }\n',
        True,
    ),
    "qualified.kt": (
        'fun check() { javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding") }\n',
        True,
    ),
    "strong.java": (
        "import javax.crypto.Cipher;\n"
        "class Owned { void check() throws Exception { "
        'Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"); } }\n',
        False,
    ),
    "strong.kt": (
        "import javax.crypto.Cipher\n"
        'fun check() { Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding") }\n',
        False,
    ),
    "unrelated.java": (
        "import application.Cipher;\n"
        "class Owned { void check() throws Exception { "
        'Cipher.getInstance("RSA/ECB/PKCS1Padding"); } }\n',
        False,
    ),
    "unrelated.kt": (
        "import application.Cipher\n"
        'fun check() { Cipher.getInstance("RSA/ECB/PKCS1Padding") }\n',
        False,
    ),
}

_PYTHON_CASES = {
    "cipher_alias.py": (
        "from Crypto.Cipher import PKCS1_v1_5 as cipher\ncipher.new(key)\n",
        True,
    ),
    "cipher_module.py": (
        "from Crypto.Cipher import PKCS1_v1_5\nPKCS1_v1_5.new(key)\n",
        True,
    ),
    "cipher_new_alias.py": (
        "from Crypto.Cipher.PKCS1_v1_5 import new as make\nmake(key)\n",
        True,
    ),
    "cipher_qualified.py": (
        "import Crypto.Cipher.PKCS1_v1_5\nCrypto.Cipher.PKCS1_v1_5.new(key)\n",
        True,
    ),
    "local.py": (
        "class PKCS1_v1_5:\n"
        "    @staticmethod\n"
        "    def new(key):\n"
        "        return key\n"
        "PKCS1_v1_5.new(key)\n",
        False,
    ),
    "signature.py": (
        "from Crypto.Signature import PKCS1_v1_5\nPKCS1_v1_5.new(key)\n",
        False,
    ),
    "signature_alias.py": (
        "from Crypto.Signature import PKCS1_v1_5 as signature\nsignature.new(key)\n",
        False,
    ),
    "signature_new_alias.py": (
        "from Crypto.Signature.PKCS1_v1_5 import new as make\nmake(key)\n",
        False,
    ),
    "unrelated.py": (
        "from application import PKCS1_v1_5\nPKCS1_v1_5.new(key)\n",
        False,
    ),
}


def _scan_owned_pkcs_cases(tmp_path, cases, rule_id):
    target = tmp_path / "owned"
    target.mkdir()
    expected = set()
    for name, (source, reports) in cases.items():
        (target / name).write_text(source)
        if reports:
            expected.add(name)
    result = run_pinned_subprocess(
        [
            "semgrep",
            "scan",
            "--config",
            str(
                Path(__file__).resolve().parents[1]
                / "rules/crypto/pkcs1v15-padding.yaml"
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
        context="Owned inert PKCS API identity",
        env=RaptorConfig.get_safe_env(),
        skip_signals=(9,),
    )
    (tmp_path / "stdout.json").write_text(result.stdout)
    (tmp_path / "stderr.log").write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(p).name for p in data["paths"]["scanned"]} == set(cases)
    rows = [row for row in data["results"] if row["check_id"].endswith(rule_id)]
    actual = {Path(row["path"]).name for row in rows}
    assert actual == expected
    assert len(rows) == len(expected)


def test_pkcs_jvm_import_identity(tmp_path):
    _scan_owned_pkcs_cases(
        tmp_path, _JVM_CASES, "raptor.crypto.rsa.pkcs1v15-encrypt.java"
    )


def test_pkcs_python_import_identity(tmp_path):
    _scan_owned_pkcs_cases(
        tmp_path, _PYTHON_CASES, "raptor.crypto.rsa.pkcs1v15-encrypt.python"
    )


_GO_API_SOURCE = 'package owned\nimport "crypto/rsa"\nfunc inspect(private *rsa.PrivateKey, public *rsa.PublicKey, ciphertext, message, key, hashed, signature []byte) {\n    rsa.DecryptPKCS1v15(nil, private, ciphertext)\n    rsa.DecryptPKCS1v15SessionKey(nil, private, ciphertext, key)\n    rsa.EncryptPKCS1v15(nil, public, message)\n    rsa.EncryptOAEP(nil, nil, public, message, nil)\n    rsa.SignPKCS1v15(nil, private, 0, hashed)\n    rsa.VerifyPKCS1v15(public, 0, hashed, signature)\n}\n'


def test_go_pkcs_diagnostic_requires_protocol_review(tmp_path):
    report = tmp_path
    target = report / "owned.go"
    target.write_text(_GO_API_SOURCE)
    result = run_pinned_subprocess(
        [
            "semgrep",
            "scan",
            "--config",
            str(
                Path(__file__).resolve().parents[1]
                / "rules/crypto/pkcs1v15-padding.yaml"
            ),
            "--metrics",
            "off",
            "--disable-version-check",
            "--jobs",
            "1",
            "--json",
            str(target),
        ],
        timeout=60,
        context="Owned inert Go PKCS diagnostic",
        env=RaptorConfig.get_safe_env(),
        skip_signals=(9,),
    )
    (report / "stdout.json").write_text(result.stdout)
    (report / "stderr.log").write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(p).name for p in data["paths"]["scanned"]} == {"owned.go"}
    rows = [
        x
        for x in data["results"]
        if x["check_id"].endswith("raptor.crypto.rsa.pkcs1v15.go")
    ]
    signatures = [
        x
        for x in data["results"]
        if x["check_id"].endswith("raptor.crypto.rsa.pkcs1v15-sign.go")
    ]
    (report / "summary.json").write_text(
        json.dumps(
            {
                "lines": [x["start"]["line"] for x in rows],
                "messages": [x["extra"]["message"] for x in rows],
                "signature_lines": [x["start"]["line"] for x in signatures],
                "version": data.get("version"),
                "scope": "Inert Go API syntax, no cryptographic/target execution",
            },
            indent=2,
        )
        + "\n"
    )
    assert sorted(x["start"]["line"] for x in rows) == [4, 5, 6]
    assert [x["start"]["line"] for x in signatures] == [8]
    for row in rows:
        message = row["extra"]["message"]
        assert "review candidate" in message.lower()
        assert "DecryptPKCS1v15SessionKey" in message and "protocol" in message.lower()
