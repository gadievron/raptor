"""Fixture and validity gates for the in-repo semgrep rules.

Two tiers:

1. **Universe gates** — derived mechanically from ``rules/**/*.yaml``
   (registry-cache excluded), never a hand-typed list: every rule
   file must pass ``semgrep --validate`` and every rule must carry
   CWE metadata for the coverage machinery.
2. **Fixture pairs** (``_CASES``) — rule files with a positive
   fixture (must fire) and a negative fixture (must stay silent),
   mirroring the engine/negative_controls discipline. ``_CASES``
   started as the taint-rules wave and is the burn-down frontier:
   rule files outside it meet only the universe bar, so new fixture
   pairs grow it toward the full universe.

The real semgrep binary adjudicates — skipped when not installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
_FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _rule_universe() -> list[Path]:
    """Every in-repo rule file — registry-cache holds fetched packs,
    not in-repo rules, and is excluded."""
    files = sorted(
        p
        for pattern in ("*.yaml", "*.yml")
        for p in _RULES_DIR.rglob(pattern)
        if "registry-cache" not in p.parts
    )
    # Non-vacuity floor: a moved rules dir must not turn the universe
    # gates into zero-case passes.
    assert len(files) >= 40, (
        f"only {len(files)} rule files derived — universe derivation "
        f"looks broken"
    )
    return files

# rule file → (positive fixtures that must fire, negative fixtures that
# must not). Fixture names double as the language matrix.
_CASES = {
    "sinks/ssrf-wrappers.yaml": (
        ["ssrf_wrappers_pos.java", "ssrf_wrappers_pos.js", "ssrf_wrappers_pos.py"],
        ["ssrf_wrappers_neg.java", "ssrf_wrappers_neg.js", "ssrf_wrappers_neg.py"],
    ),
    "deserialisation/unsafe-java-xml-yaml.yaml": (
        ["deser_java_pos.java"],
        ["deser_java_neg.java"],
    ),
    "deserialisation/unsafe-python-jsonpickle.yaml": (
        ["deser_python_pos.py"],
        ["deser_python_neg.py"],
    ),
    "web/prototype-pollution-implementation.yaml": (
        ["protopoll_impl_pos.js"],
        ["protopoll_impl_neg.js"],
    ),
    "java/trust-boundary.yaml": (
        ["trustbound_java_pos.java", "trustbound_java_map_pos.java"],
        ["trustbound_java_neg.java"],
    ),
    "injection/xss.yaml": (
        ["xss_java_pos.java", "xss_java_collection_pos.java",
         "xss_java_printf_pos.java"],
        ["xss_java_encoder_neg.java", "xss_java_collection_neg.java",
         "xss_java_printf_neg.java"],
    ),
    "injection/ldap-taint.yaml": (
        ["ldap_java_pos.java"],
        ["ldap_java_neg.java"],
    ),
    "injection/xpath-taint.yaml": (
        ["xpath_java_pos.java"],
        ["xpath_java_neg.java"],
    ),
    "crypto/weak-hash.yaml": (
        ["weakhash_java_pos.java"],
        ["weakhash_java_neg.java"],
    ),
    "injection/sql-taint.yaml": (
        ["sqli_java_pos.java", "sql_java_multival_pos.java"],
        ["sqli_java_param_neg.java"],
    ),
    "injection/command-taint-multi.yaml": (
        ["cmdi_exec_array_pos.java"],
        ["cmdi_exec_array_neg.java"],
    ),
    "injection/regex-dos.yaml": (
        ["redos_java_literal_pos.java", "redos_java_taint_pos.java"],
        ["redos_java_literal_neg.java", "redos_java_taint_neg.java"],
    ),
    "injection/sql-concat.yaml": (
        ["sqlconcat_pos.java", "sqlconcat_pos.py", "sqlconcat_pos.js",
         "sqlconcat_pos.php"],
        ["sqlconcat_neg.java", "sqlconcat_neg.py"],
    ),
    "logging/logs-secrets.yaml": (
        ["logsecrets_pos.py", "logsecrets_pos.java"],
        ["logsecrets_neg.py"],
    ),
    "go/go-security.yaml": (
        ["gotls_pos.go"],
        ["gotls_neg.go"],
    ),
    "php/crlf-injection.yaml": (
        ["crlf_socket_pos.php"],
        ["crlf_socket_neg.php"],
    ),
    "php/unsafe-reflection.yaml": (
        ["unsafe_reflection_pos.php"],
        ["unsafe_reflection_neg.php"],
    ),
    "php/argument-injection.yaml": (
        ["arg_injection_pos.php"],
        ["arg_injection_neg.php"],
    ),
    "php/attr-encoding.yaml": (
        ["attr_encoding_pos.php"],
        ["attr_encoding_neg.php"],
    ),
    "php/weak-prng-token.yaml": (
        ["weak_prng_token_pos.php"],
        ["weak_prng_token_neg.php"],
    ),
    "php/weak-password-hash.yaml": (
        ["weak_password_hash_pos.php"],
        ["weak_password_hash_neg.php"],
    ),
}

pytestmark = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep binary not installed"
)


def _run_semgrep(rule_file: Path, targets: list[Path]) -> dict:
    proc = subprocess.run(
        [
            "semgrep",
            "scan",
            "--config",
            str(rule_file),
            "--quiet",
            "--metrics",
            "off",
            "--json",
            *[str(t) for t in targets],
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 0, f"semgrep failed on {rule_file}: {proc.stderr[:500]}"
    return json.loads(proc.stdout)


def test_cases_are_within_the_universe():
    """Guards _CASES against silent staleness (renamed/moved files)."""
    universe = {p.relative_to(_RULES_DIR).as_posix() for p in _rule_universe()}
    stale = sorted(set(_CASES) - universe)
    assert not stale, f"_CASES entries not in rules/: {stale}"


def test_every_rule_file_validates(tmp_path: Path):
    """Whole-universe --validate in one invocation: an unparseable or
    schema-invalid rule file anywhere under rules/ fails here instead
    of erroring out mid-scan. The universe is copied so a populated
    registry-cache on an operator checkout cannot leak into the run.
    """
    universe = _rule_universe()
    stage = tmp_path / "rules"
    for rule_file in universe:
        dest = stage / rule_file.relative_to(_RULES_DIR)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(rule_file.read_bytes())
    proc = subprocess.run(
        ["semgrep", "scan", "--validate", "--config", str(stage),
         "--metrics", "off"],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, (
        f"--validate failed over {len(universe)} rule files:\n"
        f"{proc.stderr[-3000:]}"
    )


@pytest.mark.parametrize("rule_rel", sorted(_CASES))
def test_rule_file_is_valid(rule_rel: str):
    rule_file = _RULES_DIR / rule_rel
    assert rule_file.is_file(), rule_file
    proc = subprocess.run(
        ["semgrep", "scan", "--validate", "--config", str(rule_file),
         "--metrics", "off"],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 0, f"--validate failed: {proc.stderr[:500]}"


@pytest.mark.parametrize("rule_rel", sorted(_CASES))
def test_positive_fixtures_fire(rule_rel: str):
    positives, _ = _CASES[rule_rel]
    rule_file = _RULES_DIR / rule_rel
    for fixture in positives:
        target = _FIXTURES / fixture
        assert target.is_file(), target
        results = _run_semgrep(rule_file, [target])["results"]
        assert results, f"{rule_rel} produced no findings on {fixture}"


@pytest.mark.parametrize("rule_rel", sorted(_CASES))
def test_negative_fixtures_stay_silent(rule_rel: str):
    _, negatives = _CASES[rule_rel]
    rule_file = _RULES_DIR / rule_rel
    for fixture in negatives:
        target = _FIXTURES / fixture
        assert target.is_file(), target
        results = _run_semgrep(rule_file, [target])["results"]
        hits = [(r["check_id"], r["start"]["line"]) for r in results]
        assert not hits, f"{rule_rel} fired on clean fixture {fixture}: {hits}"


def test_php_rules_silent_on_c_targets(tmp_path: Path):
    """The php/ pack must neither fire nor load-error when a scan
    hands it C sources — the audit dispatch is language-gated, but a
    whole-tree /scan is not, so a C/C++ target sweeping rules/ must
    see the PHP rules stay inert."""
    c_file = tmp_path / "native.c"
    c_file.write_text(
        "#include <stdio.h>\n"
        "int main(int argc, char **argv) {\n"
        "    char buf[64];\n"
        '    snprintf(buf, sizeof buf, "%s", argv[1]);\n'
        '    printf("%s\\n", buf);\n'
        "    return 0;\n"
        "}\n"
    )
    php_rules = sorted((_RULES_DIR / "php").glob("*.yaml"))
    assert php_rules, "php rule pack missing"
    for rule_file in php_rules:
        data = _run_semgrep(rule_file, [c_file])
        assert not data["results"], f"{rule_file.name} fired on C source"


def test_every_rule_has_cwe_metadata():
    """Every rule in the universe must carry CWE metadata for the
    coverage machinery — enforced over the derived universe, not just
    the fixture-paired subset."""
    yaml = pytest.importorskip("yaml")
    missing = []
    for rule_file in _rule_universe():
        doc = yaml.safe_load(rule_file.read_text())
        rules = doc.get("rules") if isinstance(doc, dict) else None
        if not rules:
            missing.append(f"{rule_file}: no rules key")
            continue
        for rule in rules:
            if not rule.get("metadata", {}).get("cwe"):
                missing.append(f"{rule.get('id')} ({rule_file.name})")
    assert not missing, "rules with no cwe metadata:\n  " + "\n  ".join(missing)


# --- case-insensitive algorithm names (JCA / OpenSSL lookup) ----------------

# rule file → (fixture, expected firing lines). JCA getInstance and
# OpenSSL digest lookups are case-insensitive per spec, so every
# case-variant line is a fully working weak-crypto use; exact line
# sets keep each variant individually witnessed (a fires-at-least-once
# assertion would let single variants regress silently).
_CASE_FOLD_CASES = {
    "crypto/weak-hash.yaml": ("weakcrypto_case_pos.java", [6, 7, 8, 9]),
    "crypto/weak-symmetric-cipher.yaml": (
        "weakcrypto_case_pos.java", [12, 13, 14, 15],
    ),
    "crypto/pkcs1v15-padding.yaml": (
        "weakcrypto_case_pos.java", [18, 19],
    ),
    "crypto/weak-hash-extended.yaml": ("weakhash_case_pos.rb", [4, 5, 6]),
}


@pytest.mark.parametrize("rule_rel", sorted(_CASE_FOLD_CASES))
def test_weak_crypto_matches_case_insensitively(rule_rel: str):
    fixture, expected_lines = _CASE_FOLD_CASES[rule_rel]
    rule_file = _RULES_DIR / rule_rel
    target = _FIXTURES / fixture
    results = _run_semgrep(rule_file, [target])["results"]
    lines = sorted({r["start"]["line"] for r in results})
    assert lines == expected_lines, (
        f"{rule_rel} case-fold coverage drifted on {fixture}: "
        f"fired {lines}, expected {expected_lines}"
    )


@pytest.mark.parametrize(
    "rule_rel",
    ["crypto/weak-hash.yaml", "crypto/weak-symmetric-cipher.yaml",
     "crypto/pkcs1v15-padding.yaml"],
)
def test_weak_crypto_case_negatives_stay_silent(rule_rel: str):
    rule_file = _RULES_DIR / rule_rel
    target = _FIXTURES / "weakcrypto_case_neg.java"
    results = _run_semgrep(rule_file, [target])["results"]
    hits = [(r["check_id"], r["start"]["line"]) for r in results]
    assert not hits, f"{rule_rel} fired on clean fixture: {hits}"


def test_prototype_pollution_impl_exact_lines():
    """Exact-line pin for the deep-set + unguarded-merge rules: the
    Object.keys-iterating merge is individually witnessed (Object.keys
    is NOT a guard — JSON.parse yields an own __proto__ key that it
    enumerates), and the fires-at-least-once positive gate alone would
    let it regress silently."""
    rule_file = _RULES_DIR / "web/prototype-pollution-implementation.yaml"
    results = _run_semgrep(
        rule_file, [_FIXTURES / "protopoll_impl_pos.js"],
    )["results"]
    assert sorted({r["start"]["line"] for r in results}) == [1, 16, 23]
