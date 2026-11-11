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

import os
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
        # adjudicate them. Exception: CWE-116 carries joern legs for
        # its C/C++ sub-shapes, language-gated to c/cpp (joern_langs)
        # — the PHP chain shape stays semgrep-only, pinned in
        # test_php_chain_shape_unchanged below.
        assert entry["smt"] is None
        assert entry["cocci"] is None
        if cwe == "CWE-116":
            assert entry["joern"] is True
            assert entry["joern_langs"] == ("c", "cpp")
        else:
            assert entry["joern"] is False
        assert entry["codeql"] is None

    def test_php_chain_shape_unchanged(self):
        """The PHP chain for every family keeps its original shape —
        exactly one semgrep leg, nothing else. The C/C++ legs the
        encoding families gained are language-gated and must never
        leak into PHP dispatch."""
        for cwe in sorted(_PHP_FAMILIES):
            chain = _cwe_fallback_chain(cwe, "", "src/index.php")
            assert [e["type"] for e in chain] == ["semgrep"], cwe

    @pytest.mark.parametrize("cwe", sorted(_PHP_FAMILIES))
    def test_rule_file_exists_on_disk(self, cwe: str):
        assert (_RULES_DIR / _PHP_FAMILIES[cwe][0]).is_file()

    @pytest.mark.parametrize("cwe", ["CWE-88", "CWE-93", "CWE-116", "CWE-327", "CWE-338"])
    def test_narrow_php_rules_cannot_refute_the_whole_class(self, cwe: str):
        from core.audit.sweep import is_confirm_only_rule

        rule = resolve_semgrep_rule_for_cwe(cwe, "index.php")
        assert rule is not None
        assert is_confirm_only_rule(rule)

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
        # CWE-93/116 route C/C++ targets to their own curated rules
        # (semgrep_by_lang, pinned in test_cwe_dispatch_encoding);
        # every other language stays leg-free for all families.
        others = ("app.py", "lib.js", "pkg/mod.go", "")
        if cwe not in ("CWE-93", "CWE-116"):
            others = ("main.c", *others)
        for other in others:
            assert resolve_semgrep_rule_for_cwe(cwe, other) is None

    def test_phtml_resolves_but_skipped_legacy_suffixes_do_not(self):
        """.phtml is in semgrep's php target selection, so the leg
        must dispatch there. .php5/.php4/.php3 are NOT (the installed
        engine skips them for php-language rules — see the live pin
        below), so they must stay generic: a php mapping would both
        regress the generic-keyed dynamic rules that DO scan those
        files and record a semgrep dispatch for a scan that examined
        nothing."""
        from core.audit.hypothesis_mapping import semgrep_language_for

        assert semgrep_language_for("view.phtml") == "php"
        assert resolve_semgrep_rule_for_cwe("CWE-93", "view.phtml")
        for path in ("admin.php5", "old.php4", "lib.php3"):
            assert semgrep_language_for(path) == "generic"
            assert resolve_semgrep_rule_for_cwe("CWE-93", path) is None

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
        """Non-PHP dispatch for the php-only classes must stay exactly
        as it was before the entries existed: empty chain, loud
        warning — whose message keeps suspicious verdicts eligible for
        on-demand checker synthesis. CWE-93/116 carry their own C/C++
        legs now and are pinned in test_cwe_dispatch_encoding."""
        import core.audit.orchestrator as _orch

        php_only = sorted(set(_PHP_FAMILIES) - {"CWE-93", "CWE-116"})
        warned: list[str] = []
        monkeypatch.setattr(
            _orch, "_warn_unmapped_cwe", lambda cwe: warned.append(cwe),
        )
        for cwe in php_only:
            assert _cwe_fallback_chain(cwe, "", "main.c") == []
            assert _hypothesis_to_tool_chain("", "main.c", cwe=cwe) == []
        # Both empty-chain builds warn (the monkeypatched stub skips
        # the real once-per-process dedup) — the set is what matters.
        assert sorted(set(warned)) == php_only

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


# Real Semgrep execution belongs to the slow tool lane.
@pytest.mark.slow
@needs_semgrep
class TestLiveAdjudication:
    """Native confirms and class-appropriate silence through the dispatched sweep."""

    @pytest.mark.parametrize("cwe", sorted(_PHP_FAMILIES))
    def test_vulnerable_snippet_confirms(self, cwe: str, tmp_path: Path):
        from core.audit.tests._live_transport import (
            run_semgrep_sweep_guarded,
        )

        _, vulnerable, _ = _PHP_FAMILIES[cwe]
        (tmp_path / "app.php").write_text(vulnerable)
        rule = resolve_semgrep_rule_for_cwe(cwe, "app.php")
        assert rule
        result = run_semgrep_sweep_guarded(
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
        from core.audit.tests._live_transport import (
            run_semgrep_sweep_guarded,
        )

        _, _, sanitized = _PHP_FAMILIES[cwe]
        (tmp_path / "app.php").write_text(sanitized)
        rule = resolve_semgrep_rule_for_cwe(cwe, "app.php")
        assert rule
        result = run_semgrep_sweep_guarded(
            target_path=tmp_path,
            file_path="app.php",
            function_name="f",
            rule_config=rule,
        )
        if cwe in {"CWE-88", "CWE-93", "CWE-116", "CWE-327", "CWE-338"}:
            # These curated shapes do not cover their entire CWE classes.
            assert result.outcome == "inconclusive", (
                f"{cwe}: {result.outcome} {result.errors}"
            )
            assert "confirm-only" in (result.details or {}).get("reason", "")
        else:
            assert result.outcome == "refuted", (
                f"{cwe}: {result.outcome} {result.errors}"
            )

    def test_attribute_encoding_miss_on_indirect_flow_stays_inconclusive(self, tmp_path: Path):
        from core.audit.tests._live_transport import run_semgrep_sweep_guarded

        (tmp_path / "app.php").write_text(
            '<?php\nfunction f() {\n'
            '  $value = htmlspecialchars($_GET["x"], ENT_COMPAT);\n'
            '  echo "<a title=\'" . $value . "\'>x</a>";\n}\n'
        )
        rule = resolve_semgrep_rule_for_cwe("CWE-116", "app.php")
        assert rule
        result = run_semgrep_sweep_guarded(
            target_path=tmp_path, file_path="app.php", function_name="f", rule_config=rule,
        )
        assert result.outcome == "inconclusive", result.errors
        assert not result.matches
        assert "confirm-only" in (result.details or {}).get("reason", "")

    @pytest.mark.parametrize("body", [
        'echo "<input value=" . htmlspecialchars($_GET["x"], ENT_QUOTES) . ">";',
        '$value = htmlentities($_POST["x"]); echo "<input value=" . $value . ">";',
    ], ids=["direct", "alias"])
    def test_encoded_request_in_unquoted_attribute_confirms(self, body: str, tmp_path: Path):
        from core.analysis.rule_versions import version_tuple
        from core.audit.tests._live_transport import run_semgrep_sweep_guarded
        from packages.semgrep.runner import version

        installed = version_tuple(version())
        if installed is not None and installed < (1, 47, 0):
            pytest.skip("unquoted conditional-taint rule requires Semgrep >= 1.47.0")
        (tmp_path / "app.php").write_text('<?php\nfunction f() {\n  ' + body + '\n}\n')
        rule = resolve_semgrep_rule_for_cwe("CWE-116", "app.php")
        assert rule
        result = run_semgrep_sweep_guarded(
            target_path=tmp_path, file_path="app.php", function_name="f", rule_config=rule,
        )
        assert result.outcome == "confirmed", result.errors
        assert result.matches

    @pytest.mark.parametrize("body, expected", [
        ('echo "<a title=\'" . "prefix-" . $_GET["x"] . "\'>";', "confirmed"),
        ('echo "<a title=\'" . "fixed" . "\'>" . $_GET["body"];', "inconclusive"),
    ], ids=["request-inside-attribute", "request-after-attribute"])
    def test_raw_attribute_context_does_not_borrow_body_taint(
        self, body: str, expected: str, tmp_path: Path,
    ):
        from core.audit.tests._live_transport import run_semgrep_sweep_guarded

        (tmp_path / "app.php").write_text('<?php\nfunction f() {\n  ' + body + '\n}\n')
        rule = resolve_semgrep_rule_for_cwe("CWE-79", "app.php")
        assert rule
        result = run_semgrep_sweep_guarded(
            target_path=tmp_path, file_path="app.php", function_name="f", rule_config=rule,
        )
        assert result.outcome == expected, result.errors
        assert bool(result.matches) == (expected == "confirmed")

    @pytest.mark.parametrize("cwe, body", [
        ("CWE-327", '$raw=$_POST["password"]; return md5($raw);'),
        ("CWE-338", '$r=mt_rand(); $csrf_token=$r; return $csrf_token;'),
    ], ids=["neutral-password-alias", "neutral-prng-alias"])
    def test_crypto_name_misses_stay_inconclusive(self, cwe: str, body: str, tmp_path: Path):
        from core.audit.tests._live_transport import run_semgrep_sweep_guarded

        (tmp_path / "app.php").write_text('<?php\nfunction f() {\n  ' + body + '\n}\n')
        rule = resolve_semgrep_rule_for_cwe(cwe, "app.php")
        assert rule
        result = run_semgrep_sweep_guarded(
            target_path=tmp_path, file_path="app.php", function_name="f", rule_config=rule,
        )
        assert result.outcome == "inconclusive", result.errors
        assert not result.matches
        assert "confirm-only" in (result.details or {}).get("reason", "")

    @pytest.mark.parametrize("cwe, body, finding", [
        ("CWE-327", 'Foo::$password_hash=\\HASH("MD5", $input);', True),
        ("CWE-338", 'Foo::$csrf_token=\\MT_RAND();', True),
        ("CWE-327", 'return md5("password_reset_template");', False),
        ("CWE-338", '$token_key="cache"; $values[$token_key]=rand();', False),
    ], ids=["password-static-store", "prng-static-store", "noncredential-text", "dynamic-key"])
    def test_crypto_builtin_and_name_context(
        self, cwe: str, body: str, finding: bool, tmp_path: Path,
    ):
        from core.audit.tests._live_transport import run_semgrep_sweep_guarded

        (tmp_path / "app.php").write_text('<?php\nfunction f() {\n  ' + body + '\n}\n')
        rule = resolve_semgrep_rule_for_cwe(cwe, "app.php")
        assert rule
        result = run_semgrep_sweep_guarded(
            target_path=tmp_path, file_path="app.php", function_name="f", rule_config=rule,
        )
        assert result.outcome == ("confirmed" if finding else "inconclusive"), result.errors
        assert bool(result.matches) == finding

    @pytest.mark.parametrize("cwe, body, finding", [
        ("CWE-88", '$out=[$_GET["x"]]; exec("/usr/bin/true", $out);', False),
        ("CWE-88", '\\SYSTEM($_GET["x"]);', True),
        ("CWE-88", 'popen("/usr/bin/true", $_GET["mode"]);', False),
        ("CWE-93", '$s=fsockopen($_GET["host"],25); fwrite($s,"PING");', False),
        ("CWE-93", '$s=\\FSOCKOPEN("localhost",25); \\FWRITE($s,$_GET["x"]);', True),
        ("CWE-93", 'socket_write($socket,"PING",$_GET["length"]);', False),
    ], ids=["command-output", "qualified-command", "popen-mode", "socket-host",
            "qualified-payload", "socket-length"])
    def test_command_and_protocol_argument_roles(
        self, cwe: str, body: str, finding: bool, tmp_path: Path,
    ):
        from core.audit.tests._live_transport import run_semgrep_sweep_guarded

        (tmp_path / "app.php").write_text('<?php\nfunction f($socket) {\n  ' + body + '\n}\n')
        rule = resolve_semgrep_rule_for_cwe(cwe, "app.php")
        assert rule
        result = run_semgrep_sweep_guarded(
            target_path=tmp_path, file_path="app.php", function_name="f", rule_config=rule,
        )
        assert result.outcome == ("confirmed" if finding else "inconclusive"), result.errors
        assert bool(result.matches) == finding

    @pytest.mark.parametrize("cwe, body", [
        ("CWE-88", 'exec("tool " . escapeshellarg($_GET["argument"]));'),
        ("CWE-93", 'header("X-Note: " . $_GET["value"]);'),
    ], ids=["program-option-parsing", "response-header-channel"])
    def test_command_and_protocol_partial_scope_stays_inconclusive(
        self, cwe: str, body: str, tmp_path: Path,
    ):
        from core.audit.tests._live_transport import run_semgrep_sweep_guarded

        (tmp_path / "app.php").write_text('<?php\nfunction f() {\n  ' + body + '\n}\n')
        rule = resolve_semgrep_rule_for_cwe(cwe, "app.php")
        assert rule
        result = run_semgrep_sweep_guarded(
            target_path=tmp_path, file_path="app.php", function_name="f", rule_config=rule,
        )
        assert result.outcome == "inconclusive", result.errors
        assert not result.matches
        assert "confirm-only" in (result.details or {}).get("reason", "")

    def test_semgrep_php_target_selection_pin(self, tmp_path: Path):
        """Live pin of the engine's ACTUAL selection for language:php
        rules: .phtml is scanned, .php5/.php4/.php3 are not — the
        extension map's php rows depend on this. If a future semgrep
        starts scanning a legacy suffix, this fails and the suffix
        can be promoted to the php mapping."""
        import json

        from core.audit.tests._live_transport import run_pinned_subprocess

        rule = tmp_path / "probe.yaml"
        rule.write_text(
            "rules:\n"
            "  - id: probe\n"
            "    languages: [php]\n"
            "    severity: INFO\n"
            "    message: probe\n"
            "    pattern: mt_rand()\n",
        )
        targets = []
        for ext in ("phtml", "php5", "php4", "php3"):
            target = tmp_path / f"f.{ext}"
            target.write_text("<?php\n$x = mt_rand();\n")
            targets.append(str(target))
        # PYTHONPATH dropped like the runtime spawn path does: the CI
        # preflight dependency simulation hides modules via a stub
        # PYTHONPATH, which must not leak into the semgrep child.
        env = {k: v for k, v in os.environ.items()
               if k not in {"PYTHONPATH", "SEMGREP_APP_TOKEN"}}
        # Direct engine pins need their own settings/log isolation too.
        env.update({
            "SEMGREP_SETTINGS_FILE": str(tmp_path / "semgrep-settings.yml"),
            "SEMGREP_LOG_FILE": str(tmp_path / "semgrep.log"),
            "SEMGREP_ENABLE_VERSION_CHECK": "0",
        })
        proc = run_pinned_subprocess(
            ["semgrep", "scan", "--config", str(rule), "--metrics",
             "off", "--json", "--quiet", *targets],
            timeout=180,
            env=env,
            context="semgrep php target-selection pin",
        )
        assert proc.returncode == 0, proc.stderr[:500]
        scanned = {
            Path(p).name
            for p in json.loads(proc.stdout).get("paths", {}).get(
                "scanned", [],
            )
        }
        assert "f.phtml" in scanned
        assert not scanned & {"f.php5", "f.php4", "f.php3"}, scanned
