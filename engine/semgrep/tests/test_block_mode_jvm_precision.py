"""Native JVM factory and case controls without JCA/provider execution."""
from pathlib import Path
import json
from core.audit.tests._live_transport import run_pinned_subprocess
from core.config import RaptorConfig
import shutil
import pytest

pytestmark = [pytest.mark.slow, pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")]


def test_block_mode_jvm_factory_identity_and_case(tmp_path):
    target = tmp_path / "owned"
    target.mkdir(exist_ok=True)
    explicit = "raptor.crypto.aes.ecb.java"
    default = "raptor.crypto.aes.default-ecb.java"
    expected = {}
    for extension in ("java", "kt"):
        cases = {
            "upper": ("javax.crypto.Cipher", 'Cipher.getInstance("AES/ECB/NoPadding")', explicit),
            "lower": ("javax.crypto.Cipher", 'Cipher.getInstance("aes/ecb/nopadding")', explicit),
            "qualified": (None, 'javax.crypto.Cipher.getInstance("AES/ECB/NoPadding")', explicit),
            "bare": ("javax.crypto.Cipher", 'Cipher.getInstance("AES")', default),
            "bare_lower": ("javax.crypto.Cipher", 'Cipher.getInstance("aes")', default),
            "gcm": ("javax.crypto.Cipher", 'Cipher.getInstance("AES/GCM/NoPadding")', None),
            "other": ("owned.unrelated.Cipher", 'Cipher.getInstance("AES/ECB/NoPadding")', None),
        }
        if extension == "java":
            cases["static_import"] = ("static javax.crypto.Cipher.getInstance", 'getInstance("AES/ECB/NoPadding")', explicit)
        else:
            cases["aliased_import"] = ("javax.crypto.Cipher as BlockCipher", 'BlockCipher.getInstance("AES/ECB/NoPadding")', explicit)
        for name, (import_name, call, rule_id) in cases.items():
            filename = name + "." + extension
            prefix = ("import " + import_name + (";" if extension == "java" else "") + "\n") if import_name else ""
            body = ("class Owned { Object f() throws Exception { return " + call + "; } }\n") if extension == "java" else ("fun owned() = " + call + "\n")
            (target / filename).write_text(prefix + body)
            if rule_id:
                expected[filename] = rule_id
    result = run_pinned_subprocess(
        ["semgrep", "scan", "--config", str(Path(__file__).resolve().parents[1]/"rules/crypto/weak-block-modes.yaml"), "--metrics", "off", "--disable-version-check", "--jobs", "1", "--json", *map(str, sorted(target.iterdir()))],
        timeout=60, context="Owned inert JVM block mode factory identity and case review",
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(p).name for p in data["paths"]["scanned"]} == {p.name for p in target.iterdir()}
    actual = {Path(row["path"]).name: "raptor." + row["check_id"].split("raptor.")[-1] for row in data["results"]}
    assert actual == expected
    assert len(data["results"]) == len(expected)
