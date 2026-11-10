"""Native block-mode controls scan owned source without executing ciphers."""
from pathlib import Path
import json
from core.audit.tests._live_transport import run_pinned_subprocess
from core.config import RaptorConfig
import shutil
import pytest

pytestmark = [pytest.mark.slow, pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")]


def test_block_mode_python_argument_and_import_identity(tmp_path):
    target = tmp_path / "owned"
    target.mkdir(exist_ok=True)
    cases = {
        "aes_positional": ('from Crypto.Cipher import AES\nAES.new(key, AES.MODE_ECB)\n', True),
        "aes_mode_keyword": ('from Crypto.Cipher import AES\nAES.new(key, mode=AES.MODE_ECB)\n', True),
        "aes_keywords": ('from Crypto.Cipher import AES\nAES.new(key=key, mode=AES.MODE_ECB)\n', True),
        "aes_alias": ('import Crypto.Cipher.AES as block\nblock.new(key, block.MODE_ECB)\n', True),
        "modes_namespace": ('from cryptography.hazmat.primitives.ciphers import modes\nmodes.ECB()\n', True),
        "modes_direct": ('from cryptography.hazmat.primitives.ciphers.modes import ECB\nECB()\n', True),
        "modes_alias": ('from cryptography.hazmat.primitives.ciphers.modes import ECB as block_mode\nblock_mode()\n', True),
        "other_modes": ('from owned_unrelated import modes\nmodes.ECB()\n', False),
        "other_aes": ('from owned_unrelated import AES\nAES.new(key, AES.MODE_ECB)\n', False),
        "aes_gcm": ('from Crypto.Cipher import AES\nAES.new(key, AES.MODE_GCM)\n', False),
        "modes_cbc": ('from cryptography.hazmat.primitives.ciphers import modes\nmodes.CBC(iv)\n', False),
    }
    expected = set()
    for name, (source, reports) in cases.items():
        filename = name + ".py"
        (target / filename).write_text(source)
        if reports:
            expected.add(filename)
    result = run_pinned_subprocess(
        ["semgrep", "scan", "--config", str(Path(__file__).resolve().parents[1]/"rules/crypto/weak-block-modes.yaml"), "--metrics", "off", "--disable-version-check", "--jobs", "1", "--json", *map(str, sorted(target.iterdir()))],
        timeout=60, context="Owned inert Python block mode import and argument review",
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(p).name for p in data["paths"]["scanned"]} == {p.name for p in target.iterdir()}
    actual = {Path(row["path"]).name for row in data["results"] if row["check_id"].endswith("raptor.crypto.aes.ecb.python")}
    assert actual == expected
    assert len(data["results"]) == len(expected)
