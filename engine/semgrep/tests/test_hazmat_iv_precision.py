"""Native source-only constructor identity and literal-parameter controls."""
from pathlib import Path
import json
from core.audit.tests._live_transport import run_pinned_subprocess
from core.config import RaptorConfig
import shutil
import pytest

pytestmark = [pytest.mark.slow, pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")]


def test_hazmat_iv_imports_and_keyword_arguments(tmp_path):
    target = tmp_path / "owned"
    target.mkdir(exist_ok=True)
    cases = {
        "namespace": ('from cryptography.hazmat.primitives.ciphers import modes\nmodes.CBC(b"0" * 16)\n', True),
        "module_alias": ('import cryptography.hazmat.primitives.ciphers.modes as m\nm.CBC(b"0" * 16)\n', True),
        "direct": ('from cryptography.hazmat.primitives.ciphers.modes import CBC\nCBC(b"0" * 16)\n', True),
        "direct_alias": ('from cryptography.hazmat.primitives.ciphers.modes import CBC as BlockMode\nBlockMode(b"0" * 16)\n', True),
        "qualified": ('import cryptography.hazmat.primitives.ciphers.modes\ncryptography.hazmat.primitives.ciphers.modes.CBC(b"0" * 16)\n', True),
        "keyword": ('from cryptography.hazmat.primitives.ciphers import modes\nmodes.CBC(initialization_vector=b"0" * 16)\n', True),
        "ctr_keyword": ('from cryptography.hazmat.primitives.ciphers.modes import CTR\nCTR(nonce=b"0" * 16)\n', True),
        "other": ('from owned_unrelated import modes\nmodes.CBC(b"0" * 16)\n', False),
        "other_direct": ('from owned_unrelated import CBC\nCBC(b"0" * 16)\n', False),
        "dynamic": ('from cryptography.hazmat.primitives.ciphers import modes\nmodes.CBC(iv)\n', False),
        "ecb": ('from cryptography.hazmat.primitives.ciphers import modes\nmodes.ECB()\n', False),
    }
    for mode, keyword in {
        "CBC":"initialization_vector", "GCM":"initialization_vector", "CTR":"nonce",
        "CFB":"initialization_vector", "CFB8":"initialization_vector",
        "OFB":"initialization_vector", "XTS":"tweak",
    }.items():
        prefix = "from cryptography.hazmat.primitives.ciphers import modes\n"
        cases[f"{mode}_positional"] = (prefix + f'modes.{mode}(b"0" * 16)\n', True)
        cases[f"{mode}_keyword"] = (prefix + f'modes.{mode}({keyword}=b"0" * 16)\n', True)
        cases[f"{mode}_dynamic"] = (prefix + f'modes.{mode}({keyword}=parameter)\n', False)
    for mode in ("CFB", "CFB8", "OFB"):
        prefix = "from cryptography.hazmat.decrepit.ciphers import modes\n"
        cases[f"decrepit_{mode}_namespace"] = (prefix + f'modes.{mode}(b"0" * 16)\n', True)
        cases[f"decrepit_{mode}_keyword"] = (prefix + f'modes.{mode}(initialization_vector=b"0" * 16)\n', True)
        cases[f"decrepit_{mode}_direct"] = (
            f"from cryptography.hazmat.decrepit.ciphers.modes import {mode}\n"
            + f'{mode}(b"0" * 16)\n', True,
        )
        cases[f"decrepit_{mode}_alias"] = (
            f"from cryptography.hazmat.decrepit.ciphers.modes import {mode} as LegacyMode\n"
            + 'LegacyMode(b"0" * 16)\n', True,
        )
        cases[f"decrepit_{mode}_dynamic"] = (prefix + f'modes.{mode}(parameter)\n', False)
    expected = set()
    for name, (source, reports) in cases.items():
        filename=name+".py"
        (target/filename).write_text(source)
        if reports:
            expected.add(filename)
    result = run_pinned_subprocess(
        ["semgrep","scan","--config",str(Path(__file__).resolve().parents[1]/"rules/crypto/insecure-iv-or-nonce.yaml"),"--metrics","off","--disable-version-check","--jobs","1","--json",*map(str,sorted(target.iterdir()))],
        timeout=60,context="Owned inert hazmat IV identity and keyword baseline",
        env=RaptorConfig.get_safe_env(),skip_signals=(9,),
    )
    assert result.returncode==0,result.stderr
    data=json.loads(result.stdout)
    assert not data.get("errors"),data.get("errors")
    assert {Path(p).name for p in data["paths"]["scanned"]}=={p.name for p in target.iterdir()}
    actual={Path(row["path"]).name for row in data["results"] if row["check_id"].endswith("raptor.crypto.iv.literal.hazmat-modes.python")}
    assert actual==expected
    assert len(data["results"])==len(expected)
    assert all(row["check_id"].endswith("raptor.crypto.iv.literal.hazmat-modes.python") for row in data["results"])
    assert all(row["extra"]["message"].startswith("Candidate:") for row in data["results"])
