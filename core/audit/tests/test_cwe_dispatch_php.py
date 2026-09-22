"""Dispatch coverage for the PHP web-audit families: CWE-93 (CRLF
injection into protocol streams), CWE-470 (unsafe reflection), CWE-88
(argument injection), CWE-116 (attribute-encoding residual), CWE-327
(weak password digest), CWE-338 (weak PRNG for security tokens).

These classes previously had no dispatch entry at all: on a pure-PHP
target every review hypothesis in them produced an empty chain, the
loud unmapped warning fired, and the claim was never mechanically
tested. Each class now carries a curated php-only semgrep rule as its
verifying leg, language-gated in the resolver so non-PHP dispatch
keeps the pre-entry behaviour exactly (empty chain, warning,
checker-synthesis seeding).

Chain-shape tests are hermetic. The adjudication tests run the real
semgrep binary through run_semgrep_sweep over synthetic snippets and
are skipped when it is not installed.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from core.audit.cwe_dispatch import (
    CWE_TO_TOOL_DISPATCH,
    _MISSING_SEMGREP_WARNED,
    infer_cwe_from_hypothesis,
    lookup,
    resolve_semgrep_rule_for_cwe,
    semgrep_rule_for_cwe,
)
from core.audit.orchestrator import (
    _cwe_fallback_chain,
    _hypothesis_to_tool_chain,
)

_RULES_DIR = (
    Path(__file__).resolve().parents[3] / "engine" / "semgrep" / "rules"
)

# cwe -> (rule name, vulnerable snippet, sanitized snippet). Snippets
# are synthetic; each pair differs only in the neutralization the
# rule's sanitizer/anchor logic must honour.
_PHP_FAMILIES: dict[str, tuple[str, str, str]] = {
    "CWE-93": (
        "php/crlf-injection.yaml",
        '<?php\nfunction f($h) {\n    $r = $_GET["rcpt"];\n'
        '    $s = fsockopen($h, 25);\n'
        '    fwrite($s, "RCPT TO:<" . $r . ">\\r\\n");\n}\n',
        '<?php\nfunction f($h) {\n'
        '    $r = str_replace(["\\r", "\\n"], "", $_GET["rcpt"]);\n'
        '    $s = fsockopen($h, 25);\n'
        '    fwrite($s, "RCPT TO:<" . $r . ">\\r\\n");\n}\n',
    ),
    "CWE-470": (
        "php/unsafe-reflection.yaml",
        '<?php\nfunction f() {\n    $fn = $_GET["action"];\n'
        '    $fn("payload");\n}\n',
        '<?php\nfunction f() {\n    $fn = $_GET["action"];\n'
        '    if (!in_array($fn, ["a", "b"], true)) { die("no"); }\n'
        '    $fn("payload");\n}\n',
    ),
    "CWE-88": (
        "php/argument-injection.yaml",
        '<?php\nfunction f() {\n    $d = $_GET["dir"];\n'
        '    exec("ls " . $d);\n}\n',
        '<?php\nfunction f() {\n    $d = escapeshellarg($_GET["dir"]);\n'
        '    exec("ls " . $d);\n}\n',
    ),
    "CWE-116": (
        "php/attr-encoding.yaml",
        '<?php\nfunction f() {\n'
        '    echo "<a href=\'" '
        '. htmlspecialchars($_GET["u"], ENT_COMPAT) . "\'>x</a>";\n}\n',
        '<?php\nfunction f() {\n'
        '    echo "<a href=\'" '
        '. htmlspecialchars($_GET["u"], ENT_QUOTES) . "\'>x</a>";\n}\n',
    ),
    "CWE-327": (
        "php/weak-password-hash.yaml",
        '<?php\nfunction f() {\n'
        '    $password_hash = md5($_POST["password"]);\n'
        '    return $password_hash;\n}\n',
        '<?php\nfunction f() {\n'
        '    $hash = password_hash($_POST["password"], PASSWORD_DEFAULT);\n'
        '    return $hash;\n}\n',
    ),
    "CWE-338": (
        "php/weak-prng-token.yaml",
        '<?php\nfunction f() {\n    $token = mt_rand();\n'
        '    return $token;\n}\n',
        '<?php\nfunction f() {\n    $token = bin2hex(random_bytes(32));\n'
        '    return $token;\n}\n',
    ),
}


class TestDispatchEntries:
    @pytest.mark.parametrize("cwe", sorted(_PHP_FAMILIES))
    def test_entry_exists_and_is_semgrep_owned(self, cwe: str):
        entry = lookup(cwe)
        assert entry is not None
        assert entry["semgrep"] == _PHP_FAMILIES[cwe][0]
        assert entry["semgrep_langs"] == ("php",)
        # Pure semgrep families: no other channel claims to
        # adjudicate them.
        assert entry["smt"] is None
        assert entry["cocci"] is None
        assert entry["joern"] is False
        assert entry["codeql"] is None

    @pytest.mark.parametrize("cwe", sorted(_PHP_FAMILIES))
    def test_rule_file_exists_on_disk(self, cwe: str):
        assert (_RULES_DIR / _PHP_FAMILIES[cwe][0]).is_file()

    def test_every_table_semgrep_reference_exists_on_disk(self):
        for cwe, entry in CWE_TO_TOOL_DISPATCH.items():
            name = entry.get("semgrep")
            if name:
                assert (_RULES_DIR / name).is_file(), (
                    f"{cwe} references missing semgrep rule {name}"
                )


class TestLanguageGate:
    @pytest.mark.parametrize("cwe", sorted(_PHP_FAMILIES))
    def test_resolves_for_php_targets_only(self, cwe: str):
        resolved = resolve_semgrep_rule_for_cwe(cwe, "src/index.php")
        assert resolved is not None
        assert Path(resolved).is_file()
        assert resolved.endswith(_PHP_FAMILIES[cwe][0])
        for other in ("main.c", "app.py", "lib.js", "pkg/mod.go", ""):
            assert resolve_semgrep_rule_for_cwe(cwe, other) is None

    @pytest.mark.parametrize("cwe", sorted(_PHP_FAMILIES))
    def test_php_chain_has_curated_semgrep_leg(self, cwe: str):
        chain = _cwe_fallback_chain(cwe, "", "src/index.php")
        semgrep_legs = [e for e in chain if e["type"] == "semgrep"]
        assert len(semgrep_legs) == 1
        assert semgrep_legs[0]["config"]["rule"].endswith(
            _PHP_FAMILIES[cwe][0],
        )
        # Curated rules carry their own precision — the dynamic-rule
        # gates (identifier consistency, negative control) must stay
        # off, which the sweep keys on the absence of "keyword".
        assert "keyword" not in semgrep_legs[0]["config"]

    def test_no_unmapped_warning_on_php_targets(self, monkeypatch):
        import core.audit.orchestrator as _orch

        warned: list[str] = []
        monkeypatch.setattr(
            _orch, "_warn_unmapped_cwe", lambda cwe: warned.append(cwe),
        )
        for cwe in sorted(_PHP_FAMILIES):
            chain = _hypothesis_to_tool_chain("", "src/index.php", cwe=cwe)
            assert chain, f"{cwe} must dispatch on a PHP target"
        assert warned == []

    def test_c_targets_keep_pre_entry_behaviour(self, monkeypatch):
        """Non-PHP dispatch for these classes must stay exactly as it
        was before the entries existed: empty chain, loud warning —
        whose message keeps suspicious verdicts eligible for on-demand
        checker synthesis."""
        import core.audit.orchestrator as _orch

        warned: list[str] = []
        monkeypatch.setattr(
            _orch, "_warn_unmapped_cwe", lambda cwe: warned.append(cwe),
        )
        for cwe in sorted(_PHP_FAMILIES):
            assert _cwe_fallback_chain(cwe, "", "main.c") == []
            assert _hypothesis_to_tool_chain("", "main.c", cwe=cwe) == []
        # Both empty-chain builds warn (the monkeypatched stub skips
        # the real once-per-process dedup) — the set is what matters.
        assert sorted(set(warned)) == sorted(_PHP_FAMILIES)

    def test_missing_rule_file_drops_leg(self, monkeypatch):
        monkeypatch.setitem(
            CWE_TO_TOOL_DISPATCH,
            "CWE-93",
            {
                "smt": None, "cocci": None, "joern": False,
                "codeql": None, "sinks": [],
                "semgrep": "php/does-not-exist.yaml",
                "semgrep_langs": ("php",),
            },
        )
        _MISSING_SEMGREP_WARNED.discard("php/does-not-exist.yaml")
        assert resolve_semgrep_rule_for_cwe("CWE-93", "a.php") is None
        assert semgrep_rule_for_cwe("CWE-93") == "php/does-not-exist.yaml"


class TestHypothesisInference:
    """The dispatch entries make these classes reachable from
    hypothesis text when a review leaves the cwe field empty
    (infer_cwe_from_hypothesis only returns classes with entries)."""

    def test_crlf_phrasings(self):
        assert infer_cwe_from_hypothesis(
            "crlf injection into the smtp command stream",
        ) == "CWE-93"
        assert infer_cwe_from_hypothesis(
            "the recipient is injected with embedded crlf",
        ) == "CWE-93"

    def test_argument_injection_phrasings(self):
        assert infer_cwe_from_hypothesis(
            "argument injection into the tar invocation",
        ) == "CWE-88"

    def test_unsafe_reflection_phrasings(self):
        assert infer_cwe_from_hypothesis(
            "unsafe reflection: request parameter selects the class",
        ) == "CWE-470"
        assert infer_cwe_from_hypothesis(
            "variable function call on user input",
        ) == "CWE-470"

    def test_existing_rows_keep_precedence(self):
        # First-match-wins: phrasings the earlier rows already claim
        # must keep routing there.
        assert infer_cwe_from_hypothesis(
            "shell command injection via backticks",
        ) == "CWE-78"
        assert infer_cwe_from_hypothesis(
            "sql injection in the search filter",
        ) == "CWE-89"


needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed",
)


@needs_semgrep
class TestLiveAdjudication:
    """The real semgrep binary adjudicates both directions through
    run_semgrep_sweep — the exact call the tool chain dispatches."""

    @pytest.mark.parametrize("cwe", sorted(_PHP_FAMILIES))
    def test_vulnerable_snippet_confirms(self, cwe: str, tmp_path: Path):
        from core.audit.sweep import run_semgrep_sweep

        _, vulnerable, _ = _PHP_FAMILIES[cwe]
        (tmp_path / "app.php").write_text(vulnerable)
        rule = resolve_semgrep_rule_for_cwe(cwe, "app.php")
        assert rule
        result = run_semgrep_sweep(
            target_path=tmp_path,
            file_path="app.php",
            function_name="f",
            rule_config=rule,
        )
        assert result.outcome == "confirmed", (
            f"{cwe}: {result.outcome} {result.errors}"
        )
        assert result.matches

    @pytest.mark.parametrize("cwe", sorted(_PHP_FAMILIES))
    def test_sanitized_snippet_refutes(self, cwe: str, tmp_path: Path):
        from core.audit.sweep import run_semgrep_sweep

        _, _, sanitized = _PHP_FAMILIES[cwe]
        (tmp_path / "app.php").write_text(sanitized)
        rule = resolve_semgrep_rule_for_cwe(cwe, "app.php")
        assert rule
        result = run_semgrep_sweep(
            target_path=tmp_path,
            file_path="app.php",
            function_name="f",
            rule_config=rule,
        )
        assert result.outcome == "refuted", (
            f"{cwe}: {result.outcome} {result.errors}"
        )
