"""Dispatch coverage for the PHP semgrep legs of the pre-existing web
families: CWE-502 (unserialize taint), CWE-79 (attribute-context XSS
subset), CWE-601 (open redirect), CWE-22 (include injection).

Unlike the php-only families (test_cwe_dispatch_php), these classes
already had dispatch entries — codeql + joern legs that dispatch on
every language. The change under test is additive and language-gated:
PHP targets gain a curated semgrep leg at the head of the chain, and
every other target's chain stays byte-identical to the entry without
the semgrep keys (pinned by the differential below).

Chain-shape tests are hermetic. The adjudication tests run the real
semgrep binary through run_semgrep_sweep and are skipped when it is
not installed.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from core.audit.cwe_dispatch import (
    CWE_TO_TOOL_DISPATCH,
    lookup,
    resolve_semgrep_rule_for_cwe,
)
from core.audit.orchestrator import _cwe_fallback_chain

_RULES_DIR = (
    Path(__file__).resolve().parents[3] / "engine" / "semgrep" / "rules"
)

# cwe -> (rule name, vulnerable snippet, sanitized snippet). Snippets
# are synthetic; each pair differs only in the neutralization the
# rule's sanitizer/anchor logic must honour.
_WEB_FAMILIES: dict[str, tuple[str, str, str]] = {
    "CWE-502": (
        "php/unserialize-taint.yaml",
        '<?php\nfunction f() {\n'
        '    $prefs = unserialize($_COOKIE["prefs"]);\n'
        '    return $prefs;\n}\n',
        '<?php\nfunction f() {\n'
        '    $prefs = unserialize($_COOKIE["prefs"],'
        ' ["allowed_classes" => false]);\n'
        '    return $prefs;\n}\n',
    ),
    "CWE-79": (
        "php/attr-xss.yaml",
        '<?php\nfunction f() {\n'
        '    echo "<font color=\'" . $_POST["color"] . "\'>x</font>";\n}\n',
        '<?php\nfunction f() {\n'
        '    echo "<font color=\'" '
        '. htmlspecialchars($_POST["color"], ENT_QUOTES)'
        ' . "\'>x</font>";\n}\n',
    ),
    "CWE-601": (
        "php/open-redirect.yaml",
        '<?php\nfunction f() {\n    $next = $_GET["next"];\n'
        '    header("Location: " . $next);\n}\n',
        '<?php\nfunction f() {\n    $next = $_GET["next"];\n'
        '    if (!in_array($next, ["/home.php", "/about.php"], true))'
        ' { $next = "/home.php"; }\n'
        '    header("Location: " . $next);\n}\n',
    ),
    "CWE-22": (
        "php/include-injection.yaml",
        '<?php\nfunction f() {\n    $page = $_GET["page"];\n'
        '    include "modules/" . $page . ".php";\n}\n',
        '<?php\nfunction f() {\n    $page = basename($_GET["page"]);\n'
        '    include "modules/" . $page . ".php";\n}\n',
    ),
}

_NON_PHP_PATHS = ("main.c", "main.cpp", "app.py", "lib.js", "pkg/mod.go",
                  "App.java", "a.rb", "")


class TestDispatchEntries:
    @pytest.mark.parametrize("cwe", sorted(_WEB_FAMILIES))
    def test_entry_gains_gated_semgrep_leg(self, cwe: str):
        entry = lookup(cwe)
        assert entry is not None
        assert entry["semgrep"] == _WEB_FAMILIES[cwe][0]
        assert entry["semgrep_langs"] == ("php",)
        # NOT the php-only shape: the pre-existing multi-language
        # legs stay exactly as they were.
        assert entry["joern"] is True
        assert entry["codeql"], cwe
        assert entry["sinks"], cwe
        # No per-language routing: one rule, one gate.
        assert "semgrep_by_lang" not in entry

    @pytest.mark.parametrize("cwe", sorted(_WEB_FAMILIES))
    def test_rule_file_exists_on_disk(self, cwe: str):
        assert (_RULES_DIR / _WEB_FAMILIES[cwe][0]).is_file()


class TestLanguageGate:
    @pytest.mark.parametrize("cwe", sorted(_WEB_FAMILIES))
    def test_resolves_for_php_targets_only(self, cwe: str):
        for php_path in ("src/index.php", "view.phtml"):
            resolved = resolve_semgrep_rule_for_cwe(cwe, php_path)
            assert resolved is not None
            assert Path(resolved).is_file()
            assert resolved.endswith(_WEB_FAMILIES[cwe][0])
        for other in _NON_PHP_PATHS:
            assert resolve_semgrep_rule_for_cwe(cwe, other) is None

    @pytest.mark.parametrize("cwe", sorted(_WEB_FAMILIES))
    def test_probed_php_admits_the_leg(self, cwe: str):
        # Unknown extension + inventory language hint: the
        # content-probed sweep path (--scan-unknown-extensions)
        # honours the same gate.
        resolved = resolve_semgrep_rule_for_cwe(
            cwe, "plugin.mod", language="php",
        )
        assert resolved is not None
        assert resolved.endswith(_WEB_FAMILIES[cwe][0])
        assert resolve_semgrep_rule_for_cwe(
            cwe, "plugin.mod", language="rust",
        ) is None

    @pytest.mark.parametrize("cwe", sorted(_WEB_FAMILIES))
    def test_php_chain_is_baseline_plus_semgrep_head(self, cwe: str):
        chain = _cwe_fallback_chain(cwe, "", "src/index.php")
        assert chain[0]["type"] == "semgrep"
        assert chain[0]["config"]["rule"].endswith(_WEB_FAMILIES[cwe][0])
        # Curated rules carry their own precision — the dynamic-rule
        # gates (identifier consistency, negative control) must stay
        # off, which the sweep keys on the absence of "keyword".
        assert "keyword" not in chain[0]["config"]
        # Exactly one semgrep leg, prepended to the baseline chain.
        baseline = self._chain_without_semgrep_keys(cwe, "src/index.php")
        assert chain[1:] == baseline
        assert [e["type"] for e in chain].count("semgrep") == 1

    @staticmethod
    def _chain_without_semgrep_keys(cwe: str, path: str):
        entry = dict(CWE_TO_TOOL_DISPATCH[cwe])
        entry.pop("semgrep", None)
        entry.pop("semgrep_langs", None)
        original = CWE_TO_TOOL_DISPATCH[cwe]
        CWE_TO_TOOL_DISPATCH[cwe] = entry
        try:
            return _cwe_fallback_chain(cwe, "", path)
        finally:
            CWE_TO_TOOL_DISPATCH[cwe] = original

    @pytest.mark.parametrize("cwe", sorted(_WEB_FAMILIES))
    def test_non_php_chains_byte_identical(self, cwe: str):
        """The differential: for every non-PHP target the chain built
        from the real table equals the chain built from the entry
        stripped of its semgrep keys — the semgrep leg is the ONLY
        delta the wiring introduces, and only on PHP targets."""
        for path in _NON_PHP_PATHS:
            with_keys = _cwe_fallback_chain(cwe, "", path)
            without = self._chain_without_semgrep_keys(cwe, path)
            assert with_keys == without, (cwe, path)
            assert all(e["type"] != "semgrep" for e in with_keys)

    def test_sibling_class_untouched(self):
        # CWE-23 (relative path traversal) shares CWE-22's sink
        # vocabulary but gets no semgrep leg — the include-injection
        # rule is scoped to CWE-22 alone.
        entry = lookup("CWE-23")
        assert entry is not None
        assert entry.get("semgrep") is None
        assert resolve_semgrep_rule_for_cwe(
            "CWE-23", "src/index.php",
        ) is None


needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed",
)


@needs_semgrep
class TestLiveAdjudication:
    """The real semgrep binary adjudicates both directions through
    run_semgrep_sweep — the exact call the tool chain dispatches."""

    @pytest.mark.parametrize("cwe", sorted(_WEB_FAMILIES))
    def test_vulnerable_snippet_confirms(self, cwe: str, tmp_path: Path):
        from core.audit.sweep import run_semgrep_sweep

        _, vulnerable, _ = _WEB_FAMILIES[cwe]
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

    @pytest.mark.parametrize("cwe", sorted(_WEB_FAMILIES))
    def test_sanitized_snippet_refutes(self, cwe: str, tmp_path: Path):
        from core.audit.sweep import run_semgrep_sweep

        _, _, sanitized = _WEB_FAMILIES[cwe]
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
