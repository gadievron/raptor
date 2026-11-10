"""Native Java and Kotlin constructor identity for the PRNG candidate rule."""
from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from core.audit.tests._live_transport import run_pinned_subprocess
from core.config import RaptorConfig

_RULE = Path(__file__).resolve().parents[1] / "rules/crypto/weak-prng.yaml"
pytestmark = [pytest.mark.slow, pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed")]


def test_prng_jvm_constructor_identity(tmp_path):
    fixtures = {
        "Owned.java": (
            "import java.util.Random;\nclass Owned {\n"
            "Object imported() { return new Random(); }\n"
            "Object seeded() { return new Random(42); }\n"
            "Object qualified() { return new java.util.Random(42); }\n"
            "double math() { return Math.random(); }\n"
            "Object secure() { return new java.security.SecureRandom(); }\n}\n"
        ),
        "Other.java": (
            "import other.Random;\nclass Other {\n"
            "Object unrelated() { return new Random(); }\n"
            "Object seeded() { return new Random(42); }\n}\n"
        ),
        "owned.kt": (
            "import java.util.Random\nimport java.util.Random as JRandom\n"
            "fun imported() = Random()\n"
            "fun seeded() = Random(42)\n"
            "fun qualified() = java.util.Random(42)\n"
            "fun alias() = JRandom(42)\n"
            "fun math() = Math.random()\n"
            "fun secure() = java.security.SecureRandom()\n"
            "object Other { fun Random(seed: Int) = seed }\n"
            "fun unrelated() = Other.Random(42)\n"
            "fun shadowed(Random: (Int) -> Int) = Random(42)\n"
        ),
        "Other.kt": (
            "import other.Random\n"
            "fun unrelatedImported() = Random()\n"
        ),
    }
    # The unrelated API is owned fixture source, never an absent dependency
    # interpreted as a standard-library constructor.
    (tmp_path / "other").mkdir()
    (tmp_path / "other/Random.java").write_text(
        "package other; public class Random { public Random() {} public Random(int seed) {} }")
    targets = []
    for name, content in fixtures.items():
        target = tmp_path / name
        target.write_text(content)
        targets.append(str(target))
    proc = run_pinned_subprocess(
        ["semgrep", "scan", "--config", str(_RULE), "--metrics", "off",
         "--disable-version-check", "--jobs", "1", "--json", *targets],
        timeout=60, context="Java/Kotlin PRNG constructor identity",
        env=RaptorConfig.get_safe_env(), skip_signals=(9,),
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert not data.get("errors"), data.get("errors")
    assert {Path(path).name for path in data["paths"]["scanned"]} == set(fixtures)
    actual = {(Path(row["path"]).name, row["start"]["line"],
               row["check_id"].split("java-random.")[-1])
              for row in data["results"] if "raptor.crypto.prng.java-random." in row["check_id"]}
    expected = {("Owned.java", line, "java") for line in (3, 4, 5, 6)}
    expected |= {("owned.kt", line, "kotlin") for line in (3, 4, 5, 6, 7)}
    assert actual == expected
