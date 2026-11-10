"""Native language syntax and API identity for JVM/Go key-size rules."""
from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from core.audit.tests._live_transport import run_pinned_subprocess
from core.config import RaptorConfig

_RULE = Path(__file__).resolve().parents[1] / "rules/crypto/weak-asym-keysize.yaml"
pytestmark = [pytest.mark.slow, pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed")]


def test_asymmetric_jvm_go_language_identity(tmp_path):
    fixtures = {
        "Owned.java": (
            'import java.security.KeyPairGenerator;\nclass Owned {\n'
            'void rsa() throws Exception { KeyPairGenerator g=KeyPairGenerator.getInstance("RSA"); g.initialize(1024); }\n'
            'void dsa() throws Exception { KeyPairGenerator g=KeyPairGenerator.getInstance("DSA"); g.initialize(1024); }\n'
            'void qualified() throws Exception { java.security.KeyPairGenerator g=java.security.KeyPairGenerator.getInstance("RSA"); g.initialize(1024); }\n'
            'void strong() throws Exception { KeyPairGenerator g=KeyPairGenerator.getInstance("RSA"); g.initialize(2048); }\n}\n'
        ),
        "Other.java": (
            'import other.KeyPairGenerator;\nclass Other {\n'
            'void unrelated() { KeyPairGenerator g=KeyPairGenerator.getInstance("RSA"); g.initialize(1024); }\n'
            'void dsa() { KeyPairGenerator g=KeyPairGenerator.getInstance("DSA"); g.initialize(1024); }\n}\n'
        ),
        "owned.kt": (
            'import java.security.KeyPairGenerator\n'
            'import java.security.KeyPairGenerator as KPG\n'
            'fun rsa() { val g=KeyPairGenerator.getInstance("RSA"); g.initialize(1024) }\n'
            'fun dsa() { var g=KeyPairGenerator.getInstance("DSA"); g.initialize(1024) }\n'
            'fun alias() { val g=KPG.getInstance("RSA"); g.initialize(1024) }\n'
            'fun typed() { val g: KeyPairGenerator=KeyPairGenerator.getInstance("DSA"); g.initialize(1024) }\n'
            'fun qualified() { val g=java.security.KeyPairGenerator.getInstance("RSA"); g.initialize(1024) }\n'
            'fun strong() { val g=KeyPairGenerator.getInstance("RSA"); g.initialize(2048) }\n'
            'fun strongDsa() { var g=KeyPairGenerator.getInstance("DSA"); g.initialize(2048) }\n'
        ),
        "Other.kt": (
            'import other.KeyPairGenerator\n'
            'fun unrelated() { val g=KeyPairGenerator.getInstance("RSA"); g.initialize(1024) }\n'
        ),
        "owned.go": (
            'package owned\nimport "crypto/rsa"\nimport "crypto/rand"\n'
            'func weak() { rsa.GenerateKey(rand.Reader, 1024) }\n'
            'func strong() { rsa.GenerateKey(rand.Reader, 2048) }\n'
        ),
        "alias.go": (
            'package owned\nimport r "crypto/rsa"\nimport "crypto/rand"\n'
            'func weakAlias() { r.GenerateKey(rand.Reader, 1024) }\n'
        ),
        "other.go": (
            'package owned\nimport "owned/rsa"\n'
            'func unrelated() { rsa.GenerateKey(nil, 1024) }\n'
        ),
    }
    targets = []
    for name, source in fixtures.items():
        target = tmp_path / name
        target.write_text(source)
        targets.append(str(target))
    proc = run_pinned_subprocess(
        ["semgrep", "scan", "--config", str(_RULE), "--metrics", "off",
         "--disable-version-check", "--jobs", "1", "--json", *targets],
        timeout=60, context="JVM/Go asymmetric-key language and import identity",
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(path).name for path in data["paths"]["scanned"]} == set(fixtures)
    actual = {(Path(row["path"]).name, row["start"]["line"],
               row["check_id"].split("raptor.crypto.")[-1]) for row in data["results"]}
    expected = {("Owned.java", 3, "rsa.small-key.java"), ("Owned.java", 4, "dsa.small-key.java"),
                ("Owned.java", 5, "rsa.small-key.java"),
                ("owned.go", 4, "rsa.small-key.go"), ("alias.go", 4, "rsa.small-key.go")}
    expected |= {("owned.kt", line, "rsa.small-key.kotlin") for line in (3, 5, 7)}
    expected |= {("owned.kt", line, "dsa.small-key.kotlin") for line in (4, 6)}
    assert actual == expected
