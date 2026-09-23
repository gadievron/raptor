"""Content-probed languages reach the executed semgrep sweep.

The inventory content-probes files whose extension says nothing (a PHP
plugin "module" file leads with its open tag) and records the language
on the checklist. The executed sweep must consume that hint: semgrep's
own extension-based target selection silently SKIPS such a file for a
language-keyed rule (``paths.scanned`` stays empty — pinned live
below), so without ``--scan-unknown-extensions`` the scanned-witness
gate capped every sweep there at inconclusive and a content-probed
file could never earn a tool-confirmed outcome in either direction.

Both language gates stay honest: the dispatch resolver admits the
curated leg only when the probe names one of the rule's declared
languages, and the sweep emits the flag only when the rule's own
``languages:`` key names the probed language — so a probed non-PHP
file is never scanned as php, and mapped extensions never consult the
hint (differential pins below).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from core.audit.cwe_dispatch import resolve_semgrep_rule_for_cwe
from core.audit.hypothesis_mapping import semgrep_probed_language
from core.audit.orchestrator import _hypothesis_to_tool_chain
from core.audit.sweep import _rule_languages_include, run_semgrep_sweep

_VULNERABLE_MOD = (
    "<?php\n"
    "global $app_config;\n"
    "$dir = $_POST['dir'];\n"
    "exec(\"ls \" . $dir);\n"
)
_SANITIZED_MOD = (
    "<?php\n"
    "global $app_config;\n"
    "$dir = escapeshellarg($_POST['dir']);\n"
    "exec(\"ls \" . $dir);\n"
)
# Unknown extension, C content: must never be scanned as php.
_C_CONTENT = (
    "#include <stdlib.h>\n"
    "int main(void) { return system(\"ls\"); }\n"
)


class TestSemgrepProbedLanguage:
    def test_probed_unknown_extension(self):
        assert semgrep_probed_language("modules/check.mod", "php") == "php"

    def test_case_folds(self):
        assert semgrep_probed_language("modules/check.mod", "PHP") == "php"

    def test_extensionless_shebang_probe(self):
        assert semgrep_probed_language("bin/deploy", "python") == "python"

    def test_mapped_extension_ignores_hint(self):
        # The extension table stays authoritative — a hint can never
        # change behaviour on an ordinary target.
        assert semgrep_probed_language("index.php", "php") is None
        assert semgrep_probed_language("main.c", "php") is None

    def test_no_hint(self):
        assert semgrep_probed_language("modules/check.mod", None) is None
        assert semgrep_probed_language("modules/check.mod", "") is None

    def test_language_without_semgrep_key(self):
        # perl/shell/asm have no semgrep language key to scan as.
        assert semgrep_probed_language("cgi/form.mod", "perl") is None
        assert semgrep_probed_language("scripts/run", "shell") is None


class TestResolverConsumesHint:
    def test_probed_php_admits_curated_leg(self):
        resolved = resolve_semgrep_rule_for_cwe(
            "CWE-88", "modules/check.mod", language="php",
        )
        assert resolved is not None
        assert resolved.endswith("php/argument-injection.yaml")

    def test_no_hint_keeps_drop(self):
        assert resolve_semgrep_rule_for_cwe(
            "CWE-88", "modules/check.mod",
        ) is None

    def test_non_matching_probe_keeps_drop(self):
        # A probed C file must not receive the php leg.
        assert resolve_semgrep_rule_for_cwe(
            "CWE-88", "gen/table.mod", language="c",
        ) is None

    def test_mapped_extension_unchanged_by_hint(self):
        with_hint = resolve_semgrep_rule_for_cwe(
            "CWE-88", "src/index.php", language="php",
        )
        without = resolve_semgrep_rule_for_cwe("CWE-88", "src/index.php")
        assert with_hint == without
        assert resolve_semgrep_rule_for_cwe(
            "CWE-88", "main.c", language="php",
        ) is None  # extension mapped to c: the hint never overrides

    def test_chain_builder_threads_hint(self):
        chain = _hypothesis_to_tool_chain(
            "", "modules/check.mod", cwe="CWE-88", language="php",
        )
        semgrep_legs = [e for e in chain if e["type"] == "semgrep"]
        assert len(semgrep_legs) == 1
        assert semgrep_legs[0]["config"]["rule"].endswith(
            "php/argument-injection.yaml",
        )
        # Without the hint the leg stays dropped (empty hypothesis:
        # no dynamic keyword leg either).
        bare = _hypothesis_to_tool_chain("", "modules/check.mod", cwe="CWE-88")
        assert [e for e in bare if e["type"] == "semgrep"] == []


class TestRuleLanguagesInclude:
    def test_inline_list(self, tmp_path: Path):
        rule = tmp_path / "r.yaml"
        rule.write_text("rules:\n  - id: x\n    languages: [php, hack]\n")
        assert _rule_languages_include(str(rule), "php")
        assert not _rule_languages_include(str(rule), "c")

    def test_block_list(self, tmp_path: Path):
        rule = tmp_path / "r.yaml"
        rule.write_text(
            "rules:\n  - id: x\n    languages:\n      - php\n      - hack\n",
        )
        assert _rule_languages_include(str(rule), "php")
        assert not _rule_languages_include(str(rule), "c")

    def test_pack_identifier_fails_closed(self):
        assert not _rule_languages_include("p/security-audit", "php")

    def test_missing_file_fails_closed(self, tmp_path: Path):
        assert not _rule_languages_include(str(tmp_path / "gone.yaml"), "php")

    def test_block_scalar_text_does_not_license(self, tmp_path: Path):
        # Real YAML parse: "languages: [php]" quoted inside a
        # block-scalar message body must not license the flag.
        rule = tmp_path / "r.yaml"
        rule.write_text(
            "rules:\n"
            "  - id: x\n"
            "    languages: [generic]\n"
            "    severity: WARNING\n"
            "    pattern-regex: 'exec'\n"
            "    message: |\n"
            "      prose quoting\n"
            "      languages: [php]\n"
            "      must not count\n",
        )
        assert not _rule_languages_include(str(rule), "php")
        assert _rule_languages_include(str(rule), "generic")

    def test_unparseable_yaml_fails_closed(self, tmp_path: Path):
        rule = tmp_path / "r.yaml"
        rule.write_text("rules: [::: not yaml\n\t{{{\n")
        assert not _rule_languages_include(str(rule), "php")


class TestFlagEmission:
    """The flag reaches the runner exactly when the probe and the
    rule agree — hermetic via an injected runner module."""

    def _sweep(self, tmp_path, monkeypatch, *, file_name, language):
        import packages.semgrep.runner as runner_mod
        from packages.semgrep.models import SemgrepResult

        (tmp_path / file_name).write_text(_VULNERABLE_MOD)
        rule = tmp_path / "rule.yaml"
        rule.write_text(
            "rules:\n  - id: x\n    pattern-regex: 'exec'\n"
            "    message: m\n    languages: [php]\n    severity: WARNING\n",
        )
        seen: dict = {}

        def _fake_run_rule(target, config, **kw):
            seen["extra_args"] = kw.get("extra_args")
            return SemgrepResult(
                name="x", config=config, target=str(target), returncode=0,
            )

        monkeypatch.setattr(runner_mod, "is_available", lambda: True)
        monkeypatch.setattr(runner_mod, "run_rule", _fake_run_rule)
        run_semgrep_sweep(
            target_path=tmp_path,
            file_path=file_name,
            function_name="f",
            rule_config=str(rule),
            language=language,
        )
        return seen["extra_args"]

    def test_probed_match_emits_flag(self, tmp_path, monkeypatch):
        assert self._sweep(
            tmp_path, monkeypatch, file_name="check.mod", language="php",
        ) == ["--scan-unknown-extensions"]

    def test_no_hint_no_flag(self, tmp_path, monkeypatch):
        assert self._sweep(
            tmp_path, monkeypatch, file_name="check.mod", language=None,
        ) is None

    def test_rule_language_mismatch_no_flag(self, tmp_path, monkeypatch):
        # A probed-c file with a php rule: the flag would make semgrep
        # scan the file AS php — refused.
        assert self._sweep(
            tmp_path, monkeypatch, file_name="table.gen", language="c",
        ) is None

    def test_mapped_extension_no_flag(self, tmp_path, monkeypatch):
        # Differential guarantee: ordinary targets run the identical
        # command even when a hint is supplied.
        assert self._sweep(
            tmp_path, monkeypatch, file_name="index.php", language="php",
        ) is None


class TestRefinementDispatch:
    """The checker-refinement suggested-rule dispatch threads the same
    inventory hint as the main tool-chain lane."""

    class _Config:
        def __init__(self, target_path, inventory=None):
            self.target_path = target_path
            self.inventory = inventory

    @staticmethod
    def _inventory(path: str, language: str) -> dict:
        return {
            "files": [{"path": path, "language": language, "items": []}],
        }

    def _dispatch(self, tmp_path, monkeypatch, *, file_name, inventory):
        import core.audit.sweep as sweep_mod
        from core.audit.refinement import _dispatch_semgrep
        from core.audit.sweep import SweepResult

        (tmp_path / file_name).write_text(_VULNERABLE_MOD)
        captured: dict = {}

        def _fake(**kw):
            captured.update(kw)
            return SweepResult(
                tool="semgrep", file_path=kw["file_path"],
                function_name=kw["function_name"], outcome="refuted",
            )

        monkeypatch.setattr(sweep_mod, "run_semgrep_sweep", _fake)
        out = _dispatch_semgrep(
            "rule.yaml", None,
            {"file": file_name, "function": "f"},
            self._Config(tmp_path, inventory),
        )
        assert out is not None
        return captured

    def test_probed_language_reaches_sweep(self, tmp_path, monkeypatch):
        captured = self._dispatch(
            tmp_path, monkeypatch, file_name="check.mod",
            inventory=self._inventory("check.mod", "php"),
        )
        assert captured["language"] == "php"

    def test_no_inventory_passes_none(self, tmp_path, monkeypatch):
        captured = self._dispatch(
            tmp_path, monkeypatch, file_name="check.mod", inventory=None,
        )
        assert captured["language"] is None


needs_semgrep = pytest.mark.skipif(
    shutil.which("semgrep") is None, reason="semgrep not installed",
)


@needs_semgrep
class TestLiveProbedTarget:
    """Live pins against the installed engine — the exact executed
    path (run_semgrep_sweep → packages.semgrep.runner.run_rule)."""

    def _rule(self):
        rule = resolve_semgrep_rule_for_cwe(
            "CWE-88", "check.mod", language="php",
        )
        assert rule
        return rule

    def test_engine_skips_unknown_extension_without_flag(
        self, tmp_path: Path,
    ):
        """Live pin of the motivating engine behaviour: a php-language
        rule handed an explicit unknown-extension target scans NOTHING
        without --scan-unknown-extensions, and scans it with the flag.
        If a future semgrep starts selecting such targets unaided, this
        fails and the flag plumbing can be retired."""
        import json
        import os
        import subprocess

        target = tmp_path / "check.mod"
        target.write_text(_VULNERABLE_MOD)
        base = [
            "semgrep", "scan", "--config", self._rule(), "--metrics",
            "off", "--json", "--quiet", str(target),
        ]
        # PYTHONPATH dropped like the runtime spawn path does: the CI
        # preflight dependency simulation hides modules via a stub
        # PYTHONPATH, which must not leak into the semgrep child.
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        proc = subprocess.run(
            base, capture_output=True, text=True, timeout=180, check=False,
            env=env,
        )
        assert proc.returncode == 0, proc.stderr[:500]
        assert json.loads(proc.stdout)["paths"]["scanned"] == []
        proc = subprocess.run(
            base[:-1] + ["--scan-unknown-extensions", str(target)],
            capture_output=True, text=True, timeout=180, check=False,
            env=env,
        )
        assert proc.returncode == 0, proc.stderr[:500]
        scanned = json.loads(proc.stdout)["paths"]["scanned"]
        assert [Path(p).name for p in scanned] == ["check.mod"]

    def test_probed_vulnerable_mod_confirms(self, tmp_path: Path):
        (tmp_path / "check.mod").write_text(_VULNERABLE_MOD)
        result = run_semgrep_sweep(
            target_path=tmp_path,
            file_path="check.mod",
            function_name="interstitial:2-4",
            rule_config=self._rule(),
            language="php",
        )
        assert result.outcome == "confirmed", (result.outcome, result.errors)
        assert result.matches

    def test_probed_sanitized_mod_refutes_with_witness(
        self, tmp_path: Path,
    ):
        """The promotion trigger: paths.scanned now witnesses the
        probed file, so a clean scan is a licensed refutation (was
        capped at inconclusive — no witness — before the hint)."""
        (tmp_path / "check.mod").write_text(_SANITIZED_MOD)
        result = run_semgrep_sweep(
            target_path=tmp_path,
            file_path="check.mod",
            function_name="interstitial:2-4",
            rule_config=self._rule(),
            language="php",
        )
        assert result.outcome == "refuted", (result.outcome, result.errors)
        substrate = (result.details or {}).get("substrate") or {}
        assert substrate.get("covered") is True
        assert substrate.get("tier") == "scanned-witness"

    def test_no_hint_stays_inconclusive(self, tmp_path: Path):
        # Degradation pin: without the inventory hint the engine still
        # skips the file and the witness gate caps at inconclusive —
        # never a false refutation.
        (tmp_path / "check.mod").write_text(_VULNERABLE_MOD)
        result = run_semgrep_sweep(
            target_path=tmp_path,
            file_path="check.mod",
            function_name="interstitial:2-4",
            rule_config=self._rule(),
        )
        assert result.outcome == "inconclusive", (
            result.outcome, result.errors,
        )

    def test_c_content_never_scanned_as_php(self, tmp_path: Path):
        # Two-direction: an unknown-extension C file (probed language
        # c) with a php rule is not scanned as php — no flag, no scan,
        # inconclusive rather than a cross-language match.
        (tmp_path / "table.gen").write_text(_C_CONTENT)
        result = run_semgrep_sweep(
            target_path=tmp_path,
            file_path="table.gen",
            function_name="main",
            rule_config=self._rule(),
            language="c",
        )
        assert result.outcome == "inconclusive", (
            result.outcome, result.errors,
        )
        assert not result.matches

    def test_partial_parse_never_refutes(self, tmp_path: Path):
        # A syntax error planted next to the vulnerable statement:
        # semgrep partially parses the file (it still appears in
        # paths.scanned) and finds nothing in the unparsed region. A
        # partially-parsed scan analysed nothing there — the sweep
        # must yield error/inconclusive in BOTH the probed and the
        # mapped direction, never a licensed refutation.
        broken = (
            "<?php\n"
            "function f( {{{ ((( \n"
            "$dir = $_POST['dir'];\n"
            "exec(\"ls \" . $dir);\n"
        )
        (tmp_path / "check.mod").write_text(broken)
        (tmp_path / "app.php").write_text(broken)
        for file_name, language in (("check.mod", "php"), ("app.php", None)):
            result = run_semgrep_sweep(
                target_path=tmp_path,
                file_path=file_name,
                function_name="f",
                rule_config=self._rule(),
                language=language,
            )
            assert result.outcome in ("error", "inconclusive"), (
                file_name, result.outcome, result.errors,
            )

    def test_refinement_dispatch_confirms_probed_file(
        self, tmp_path: Path,
    ):
        # The suggested-rule re-run adjudicates the probed file like
        # the main lane; without the inventory it degrades to the
        # pre-hint inconclusive, and mapped extensions are unchanged
        # either way.
        from core.audit.refinement import _dispatch_semgrep

        (tmp_path / "check.mod").write_text(_VULNERABLE_MOD)
        (tmp_path / "app.php").write_text(_VULNERABLE_MOD)
        inventory = {
            "files": [
                {"path": "check.mod", "language": "php", "items": []},
                {"path": "app.php", "language": "php", "items": []},
            ],
        }
        cfg_inv = TestRefinementDispatch._Config(tmp_path, inventory)
        cfg_bare = TestRefinementDispatch._Config(tmp_path, None)
        rule = self._rule()

        def _run(cfg, file_name):
            out = _dispatch_semgrep(
                rule, None, {"file": file_name, "function": "f"}, cfg,
            )
            assert out is not None
            return out["result"]

        assert _run(cfg_inv, "check.mod").startswith("confirmed")
        assert _run(cfg_bare, "check.mod").startswith("inconclusive")
        assert _run(cfg_inv, "app.php").startswith("confirmed")
        assert _run(cfg_bare, "app.php").startswith("confirmed")

    def test_mapped_extension_differential(self, tmp_path: Path):
        # No behaviour change for normal-extension targets: the same
        # content under .php adjudicates identically with and without
        # the hint.
        (tmp_path / "app.php").write_text(_VULNERABLE_MOD)
        outcomes = []
        for language in (None, "php"):
            result = run_semgrep_sweep(
                target_path=tmp_path,
                file_path="app.php",
                function_name="interstitial:2-4",
                rule_config=self._rule(),
                language=language,
            )
            outcomes.append((result.outcome, len(result.matches)))
        assert outcomes[0] == outcomes[1] == ("confirmed", 1)
