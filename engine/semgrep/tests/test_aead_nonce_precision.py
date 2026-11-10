"""Native detector controls; no AEAD constructors or encryption executed."""
from pathlib import Path
import json
from core.audit.tests._live_transport import run_pinned_subprocess
from core.config import RaptorConfig
import shutil
import pytest

pytestmark = [pytest.mark.slow, pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")]


def test_aead_nonce_constructor_identity(tmp_path):
    target = tmp_path / "owned"
    target.mkdir(exist_ok=True)
    cases = {
        "direct": ('from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nAESGCM(key).encrypt(b"0" * 12, data, None)\n', True),
        "alias": ('from cryptography.hazmat.primitives.ciphers.aead import AESGCM as Box\nBox(key).encrypt(b"0" * 12, data, None)\n', True),
        "qualified": ('import cryptography.hazmat.primitives.ciphers.aead\ncryptography.hazmat.primitives.ciphers.aead.AESGCM(key).encrypt(b"0" * 12, data, None)\n', True),
        "two_step": ('from cryptography.hazmat.primitives.ciphers.aead import AESGCM\na = AESGCM(key)\na.encrypt(b"0" * 12, data, None)\n', True),
        "two_step_alias": ('from cryptography.hazmat.primitives.ciphers.aead import AESGCM as Box\na = Box(key)\na.encrypt(b"0" * 12, data, None)\n', True),
        "other": ('from owned_unrelated import AESGCM\nAESGCM(key).encrypt(b"0" * 12, data, None)\n', False),
        "other_two_step": ('from owned_unrelated import AESGCM\na = AESGCM(key)\na.encrypt(b"0" * 12, data, None)\n', False),
        "dynamic": ('from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nAESGCM(key).encrypt(nonce, data, None)\n', False),
    }
    for name in ("AESGCM", "ChaCha20Poly1305", "AESCCM", "AESOCB3"):
        prefix = f"from cryptography.hazmat.primitives.ciphers.aead import {name}\n"
        cases[f"{name}_inline"] = (prefix + f'{name}(key).encrypt(b"0" * 12, data, None)\n', True)
        cases[f"{name}_stored"] = (prefix + f'a = {name}(key)\na.encrypt(b"0" * 12, data, None)\n', True)
    expected = set()
    for name, (source, reports) in cases.items():
        filename=name+".py"
        (target/filename).write_text(source)
        if reports:
            expected.add(filename)
    result = run_pinned_subprocess(
        ["semgrep","scan","--config",str(Path(__file__).resolve().parents[1]/"rules/crypto/insecure-iv-or-nonce.yaml"),"--metrics","off","--disable-version-check","--jobs","1","--json",*map(str,sorted(target.iterdir()))],
        timeout=60,context="Owned inert AEAD constructor identity baseline",
        env=RaptorConfig.get_safe_env(),skip_signals=(9,),
    )
    assert result.returncode==0,result.stderr
    data=json.loads(result.stdout)
    assert not data.get("errors"),data.get("errors")
    assert {Path(p).name for p in data["paths"]["scanned"]}=={p.name for p in target.iterdir()}
    actual={Path(row["path"]).name for row in data["results"] if row["check_id"].endswith("raptor.crypto.nonce.literal.python")}
    assert actual==expected
    assert len(data["results"])==len(expected)
    assert all(row["check_id"].endswith("raptor.crypto.nonce.literal.python") for row in data["results"])
    assert all(row["extra"]["message"].startswith("Candidate:") for row in data["results"])


def test_aead_direct_reassignment_ends_constructor_origin(tmp_path):
    rule = Path(__file__).resolve().parents[1] / "rules/crypto/insecure-iv-or-nonce.yaml"
    target = tmp_path / "receivers"
    target.mkdir()
    expected = set()
    cases = {
        "retained": ('    a = {name}(key)\n    a.encrypt(b"0" * 12, data, None)\n', 6),
        "rebound": ('    a = {name}(key)\n    a = Echo()\n    a.encrypt(b"0" * 12, data, None)\n', None),
        "unknown": ('    a = {name}(key)\n    a = other\n    a.encrypt(b"0" * 12, data, None)\n', None),
        "fresh": ('    a = {name}(key)\n    a = {name}(other)\n    a.encrypt(b"0" * 12, data, None)\n', 7),
        "early": ('    a = {name}(key)\n    a.encrypt(b"0" * 12, data, None)\n    a = Echo()\n    a.encrypt(b"0" * 12, data, None)\n', 6),
    }
    for name in ("AESGCM", "ChaCha20Poly1305", "AESCCM", "AESOCB3"):
        prefix = (
            f"from cryptography.hazmat.primitives.ciphers.aead import {name}\n"
            "class Echo:\n    def encrypt(self, nonce, data, associated_data): return nonce\n"
            "def owned(key, data, other):\n"
        )
        for case, (body, line) in cases.items():
            filename = f"{name}_{case}.py"
            (target / filename).write_text(prefix + body.format(name=name))
            if line is not None:
                expected.add((filename, line))
    result = run_pinned_subprocess(
        ["semgrep", "scan", "--config", str(rule), "--metrics", "off",
         "--disable-version-check", "--jobs", "1", "--json", *map(str, sorted(target.iterdir()))],
        timeout=60, context="Owned inert AEAD receiver reassignment controls",
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(p).name for p in data["paths"]["scanned"]} == {p.name for p in target.iterdir()}
    actual = {(Path(row["path"]).name, row["end"]["line"]) for row in data["results"]}
    assert actual == expected
    assert len(data["results"]) == len(expected)
