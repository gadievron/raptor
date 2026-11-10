"""PBKDF2 iteration checks preserve Python keyword argument semantics."""
from __future__ import annotations

import inspect
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from core.audit.tests._live_transport import run_pinned_subprocess

_RULE = Path(__file__).resolve().parents[1] / "rules/crypto/weak-kdf-iterations.yaml"
pytestmark = [pytest.mark.slow, pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed")]


def test_pbkdf2_iteration_argument_forms(tmp_path):
    # Introspection verifies the actual installed API; no fixture is executed.
    parameter = inspect.signature(hashlib.pbkdf2_hmac).parameters["iterations"]
    assert parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    cases = [
        ('hashlib.pbkdf2_hmac("sha256", pw, salt, 1)', True),
        ('hashlib.pbkdf2_hmac("sha256", pw, salt, 99999, 32)', True),
        ('hashlib.pbkdf2_hmac("sha256", pw, salt, iterations=99999)', True),
        ('hashlib.pbkdf2_hmac(hash_name="sha256", password=pw, salt=salt, iterations=99999)', True),
        ('hashlib.pbkdf2_hmac(iterations=99999, salt=salt, password=pw, hash_name="sha256")', True),
        ('hashlib.pbkdf2_hmac("sha256", pw, salt, dklen=32, iterations=99999)', True),
        ('h.pbkdf2_hmac("sha256", pw, salt, iterations=99999)', True),
        ('derive("sha256", pw, salt, iterations=99999)', True),
        ('hashlib.pbkdf2_hmac("sha256", pw, salt, 100000)', False),
        ('hashlib.pbkdf2_hmac("sha256", pw, salt, iterations=100000)', False),
        ('hashlib.pbkdf2_hmac(hash_name="sha256", password=pw, salt=salt, iterations=100_000)', False),
        ('hashlib.pbkdf2_hmac("sha256", pw, salt, iterations=100001)', False),
        ('other.pbkdf2_hmac("sha256", pw, salt, iterations=1)', False),
        ('hashlib.scrypt(pw, salt=salt, n=1024, r=8, p=1)', False),
    ]
    lines = ["import hashlib", "import hashlib as h",
             "from hashlib import pbkdf2_hmac as derive", "import other"]
    expected = set()
    for number, (expression, reports) in enumerate(cases):
        lines.extend([f"def case_{number}(pw, salt):", f"    return {expression}"])
        if reports:
            expected.add(len(lines))
    target = tmp_path / "owned.py"
    target.write_text("\n".join(lines) + "\n")
    proc = run_pinned_subprocess(
        ["semgrep", "scan", "--config", str(_RULE), "--metrics", "off",
         "--disable-version-check", "--jobs", "1", "--json", str(target)],
        timeout=60, context="PBKDF2 iteration keyword parity", skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(path).name for path in data["paths"]["scanned"]} == {target.name}
    actual = {row["start"]["line"] for row in data["results"]
              if row["check_id"].endswith("raptor.crypto.pbkdf2.low-iterations.python")}
    assert actual == expected



def test_pbkdf2_jvm_constructor_forms(tmp_path):
    java = (
        'import javax.crypto.spec.PBEKeySpec;\nclass Owned {\n'
        'PBEKeySpec low(char[] pw, byte[] salt) { return new PBEKeySpec(pw,salt,99999,256); }\n'
        'PBEKeySpec qualified(char[] pw, byte[] salt) { return new javax.crypto.spec.PBEKeySpec(pw,salt,99999,256); }\n'
        'PBEKeySpec boundary(char[] pw, byte[] salt) { return new PBEKeySpec(pw,salt,100000,256); }\n'
        'static Object PBEKeySpec(char[] pw, byte[] salt, int iters, int bits) { return null; }\n'
        'Object unrelated(char[] pw, byte[] salt) { return PBEKeySpec(pw,salt,99999,256); }\n}\n'
    )
    kotlin = (
        'import javax.crypto.spec.PBEKeySpec\n'
        'import javax.crypto.spec.PBEKeySpec as KeySpec\n'
        'fun low(pw: CharArray, salt: ByteArray) = PBEKeySpec(pw,salt,99999,256)\n'
        'fun qualified(pw: CharArray, salt: ByteArray) = javax.crypto.spec.PBEKeySpec(pw,salt,99999,256)\n'
        'fun alias(pw: CharArray, salt: ByteArray) = KeySpec(pw,salt,99999,256)\n'
        'fun boundary(pw: CharArray, salt: ByteArray) = PBEKeySpec(pw,salt,100000,256)\n'
        'object Other { fun PBEKeySpec(pw: CharArray,salt: ByteArray,iters: Int,bits: Int) = "unrelated" }\n'
        'fun unrelated(pw: CharArray, salt: ByteArray) = Other.PBEKeySpec(pw,salt,99999,256)\n'
        'fun shadowed(pw: CharArray, salt: ByteArray, PBEKeySpec: (CharArray, ByteArray, Int, Int) -> String) = PBEKeySpec(pw,salt,99999,256)\n'
    )
    unrelated_java = (
        'import other.PBEKeySpec;\nclass OwnedOther {\n'
        'Object unrelated(char[] pw, byte[] salt) { return new PBEKeySpec(pw,salt,99999,256); }\n}\n'
    )
    (tmp_path / "other").mkdir()
    (tmp_path / "other/PBEKeySpec.java").write_text(
        'package other; public class PBEKeySpec { public PBEKeySpec('
        'char[] pw,byte[] salt,int iters,int bits) {} }')
    targets = [tmp_path / "Owned.java", tmp_path / "owned.kt", tmp_path / "OwnedOther.java"]
    for target, source in zip(targets, (java, kotlin, unrelated_java)):
        target.write_text(source)
    proc = run_pinned_subprocess(
        ["semgrep", "scan", "--config", str(_RULE), "--metrics", "off",
         "--disable-version-check", "--jobs", "1", "--json", *map(str, targets)],
        timeout=60, context="PBKDF2 Java/Kotlin constructor identity", skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(path).name for path in data["paths"]["scanned"]} == {p.name for p in targets}
    actual = {(Path(row["path"]).name, row["start"]["line"], row["check_id"].split("low-iterations.")[-1])
              for row in data["results"]}
    assert actual == {("Owned.java", 3, "java"), ("Owned.java", 4, "java"),
                      ("owned.kt", 3, "kotlin"), ("owned.kt", 4, "kotlin"),
                      ("owned.kt", 5, "kotlin")}
