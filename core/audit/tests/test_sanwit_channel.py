"""Channel wiring: verdict discipline, evidence grading, substrate
registration, chain-builder hooks, and the orchestrator leg.

Hermetic: interpreter resolution and probe execution are stubbed at
the module seams (`core.audit.sanwit._execute`) — no PHP, no docker,
no sandbox. The live matrix lives in test_sanwit_live.py.
"""

from __future__ import annotations

import base64
import json
import os
import re
import threading
from types import SimpleNamespace

import pytest

import core.audit.sanwit._execute as sanwit_execute
from core.audit.sanwit import (
    SANWIT_CWES,
    SanwitResult,
    is_detection_rule_id,
    is_sanwit_hypothesis,
    mentioned_sanitizers,
    resolve_context,
    run_sanwit_check,
    sanwit_cwe_applicable,
)
from core.audit.sanwit._execute import (
    ExecOutcome,
    PhpRuntime,
    RuntimeUnavailable,
)

_SRC_SHELL = (
    "function g($x) {\n"
    '    $cmd = "prog " . escapeshellcmd($x) . " -v";\n'
    "    system($cmd);\n"
    "}"
)
_HYP_SHELL = (
    "argument injection despite escapeshellcmd — a space survives "
    "into a new argv word"
)

_RUNTIME = PhpRuntime(tier="native", version="8.3.0", php_path="/usr/bin/php")


def _fake_probe_response(probe_src: str, payloads_json: str, transform):
    """Authenticated fake: echoes each payload through *transform*."""
    token = re.search(r'"sanwit_token" => "([0-9a-f]+)"', probe_src)
    assert token, "probe must embed the execution token"
    payloads = json.loads(payloads_json)["payloads"]
    outputs = {
        pid: base64.b64encode(transform(p).encode()).decode()
        for pid, p in payloads.items()
    }
    return json.dumps({
        "sanwit_token": token.group(1),
        "php_version": "8.3.0",
        "outputs": outputs,
        "errors": {},
        "truncated": {},
    })


def _stub_execution(monkeypatch, transform=lambda p: p, mutate=None):
    monkeypatch.setattr(
        sanwit_execute, "resolve_php_runtime", lambda refresh=False: _RUNTIME,
    )

    def fake_execute(runtime, probe_src, payloads_json, audit_run_dir=None):
        stdout = _fake_probe_response(probe_src, payloads_json, transform)
        if mutate is not None:
            stdout = mutate(stdout)
        return ExecOutcome(ok=True, stdout=stdout)

    monkeypatch.setattr(sanwit_execute, "execute_probe", fake_execute)


def _run(monkeypatch=None, **kwargs):
    defaults = {
        "target_path": "/nonexistent",
        "file_path": "web/a.php",
        "function_name": "g",
        "hypothesis": _HYP_SHELL,
        "source": _SRC_SHELL,
        "cwe": "CWE-88",
    }
    defaults.update(kwargs)
    target = defaults.pop("target_path")
    file_path = defaults.pop("file_path")
    function = defaults.pop("function_name")
    hypothesis = defaults.pop("hypothesis")
    return run_sanwit_check(
        target, file_path, function, hypothesis, **defaults,
    )


class TestVerdictMapping:
    def test_breakout_confirms_with_exhibits(self, monkeypatch):
        _stub_execution(monkeypatch)  # identity chain: everything survives
        res = _run()
        assert res.outcome == "confirmed"
        assert res.verdict == "insufficient"
        assert res.rule_id == "sanwit:insufficient:shell-command"
        assert res.exhibits and len(res.exhibits) <= 4
        first = res.exhibits[0]
        assert first["payload"] and first["output"] and first["detail"]
        assert res.chain == ["escapeshellcmd({DATA})"]
        assert res.interpreter["version"] == "8.3.0"

    def test_neutralized_corpus_is_inconclusive_never_clean(
        self, monkeypatch,
    ):
        _stub_execution(monkeypatch, transform=lambda p: "inert")
        res = _run()
        assert res.outcome == "inconclusive"
        assert res.verdict == "sufficient"
        assert res.rule_id == "sanwit:sufficient:shell-command"
        assert "corpus-bounded" in res.reason
        assert "not a clean verdict" in res.reason

    def test_channel_never_emits_refuted(self, monkeypatch):
        for transform in (lambda p: p, lambda p: "inert"):
            _stub_execution(monkeypatch, transform=transform)
            assert _run().outcome != "refuted"

    def test_payload_error_poisons_sufficiency(self, monkeypatch):
        def mutate(stdout):
            doc = json.loads(stdout)
            first = next(iter(doc["outputs"]))
            del doc["outputs"][first]
            doc["errors"][first] = "chain produced NULL"
            for pid in doc["outputs"]:
                doc["outputs"][pid] = base64.b64encode(b"inert").decode()
            return json.dumps(doc)

        _stub_execution(monkeypatch, mutate=mutate)
        res = _run()
        assert res.outcome == "error"
        assert "indeterminate" in res.reason

    def test_breakout_stands_despite_other_payload_errors(
        self, monkeypatch,
    ):
        def mutate(stdout):
            doc = json.loads(stdout)
            first = next(iter(doc["outputs"]))
            del doc["outputs"][first]
            doc["errors"][first] = "chain produced NULL"
            return json.dumps(doc)

        _stub_execution(monkeypatch, mutate=mutate)  # identity otherwise
        res = _run()
        assert res.outcome == "confirmed"
        assert res.errors  # the indeterminate payload is recorded

    def test_truncated_output_is_indeterminate(self, monkeypatch):
        def mutate(stdout):
            doc = json.loads(stdout)
            for pid in doc["outputs"]:
                doc["outputs"][pid] = base64.b64encode(b"inert").decode()
                doc["truncated"][pid] = True
            return json.dumps(doc)

        _stub_execution(monkeypatch, mutate=mutate)
        res = _run()
        assert res.outcome == "error"

    def test_unauthenticated_output_is_error_never_a_verdict(
        self, monkeypatch,
    ):
        def mutate(stdout):
            doc = json.loads(stdout)
            doc["sanwit_token"] = "0" * 16
            return json.dumps(doc)

        _stub_execution(monkeypatch, mutate=mutate)
        res = _run()
        assert res.outcome == "error"
        assert "token" in res.reason

    def test_interpreter_absent_is_stated(self, monkeypatch):
        monkeypatch.setattr(
            sanwit_execute, "resolve_php_runtime",
            lambda refresh=False: RuntimeUnavailable(
                reason="php interpreter unavailable: php-cli not on "
                       "PATH; docker not on PATH",
            ),
        )
        res = _run()
        assert res.outcome == "skipped"
        assert res.verdict == "not-executable"
        assert "unavailable" in res.reason
        # Capability absence still records what was extracted.
        assert res.chain

    def test_sandbox_floor_is_stated(self, monkeypatch):
        monkeypatch.setattr(
            sanwit_execute, "resolve_php_runtime",
            lambda refresh=False: _RUNTIME,
        )
        monkeypatch.setattr(
            sanwit_execute, "execute_probe",
            lambda *a, **k: ExecOutcome(
                ok=False, floor_refusal=True,
                reason="containment floor mount-ns required",
            ),
        )
        res = _run()
        assert res.outcome == "skipped"
        assert "sandbox floor" in res.reason

    def test_extraction_refusal_is_skipped_with_reason(self, monkeypatch):
        _stub_execution(monkeypatch)
        res = _run(source="function g($x) { echo $x; }")
        assert res.outcome == "skipped"
        assert res.reason.startswith("extraction refused:")

    def test_ambiguous_context_is_skipped_with_candidates(
        self, monkeypatch,
    ):
        _stub_execution(monkeypatch)
        res = _run(
            hypothesis=(
                "XSS despite htmlspecialchars in the attribute"
            ),
            source=(
                "function f($x) {\n"
                "    $v = htmlspecialchars($x);\n"
                "    echo $v;\n"
                "}"
            ),
            cwe="CWE-79",
        )
        assert res.outcome == "skipped"
        assert "quote kind" in res.reason

    def test_exhibits_are_escaped(self, monkeypatch):
        _stub_execution(monkeypatch, transform=lambda p: p + "\x1b]0;t\x07")
        res = _run()
        assert res.outcome == "confirmed"
        for exhibit in res.exhibits:
            assert "\x1b" not in exhibit["output"]
            assert "\\x1b" in exhibit["output"]

    def test_receipt_dict_shape(self, monkeypatch):
        _stub_execution(monkeypatch)
        d = _run().to_dict()
        for key in ("tool", "outcome", "verdict", "rule_id", "reason",
                    "context_id", "family", "chain", "interpreter",
                    "corpus_size", "exhibits"):
            assert key in d, key
        assert d["tool"] == "sanwit"


class TestClassifiers:
    def test_hypothesis_classifier_two_directions(self):
        assert is_sanwit_hypothesis(
            "escapeshellcmd does not quote argument boundaries",
        )
        assert is_sanwit_hypothesis(
            "XSS despite htmlspecialchars: single-quoted attribute "
            "breakout",
        )
        # No family sanitizer named — extraction could not anchor.
        assert not is_sanwit_hypothesis(
            "argument injection through unquoted interpolation",
        )
        # Sanitizer named with no insufficiency direction.
        assert not is_sanwit_hypothesis(
            "input is sanitized with htmlspecialchars and validated",
        )
        assert not is_sanwit_hypothesis("buffer overflow in memcpy")

    def test_cwe_applicability_requires_named_sanitizer(self):
        assert sanwit_cwe_applicable("CWE-88", "despite escapeshellcmd")
        assert sanwit_cwe_applicable("88", "despite escapeshellcmd")
        assert not sanwit_cwe_applicable("CWE-88", "argument injection")
        assert not sanwit_cwe_applicable(
            "CWE-120", "despite escapeshellcmd",
        )
        assert SANWIT_CWES == frozenset(
            {"CWE-78", "CWE-77", "CWE-88", "CWE-79", "CWE-116"},
        )

    def test_mentioned_sanitizers(self):
        assert mentioned_sanitizers(
            "Escapeshellcmd then HTMLSPECIALCHARS",
        ) == ("escapeshellcmd", "htmlspecialchars")

    def test_context_pinning(self):
        ctx, _ = resolve_context("despite escapeshellcmd", "CWE-88")
        assert ctx.context_id == "shell-command"
        ctx, _ = resolve_context(
            "escapeshellarg output lands inside a single-quoted part "
            "of the command", "CWE-78",
        )
        assert ctx.context_id == "shell-squote"
        ctx, _ = resolve_context(
            "htmlspecialchars without ENT_QUOTES leaves the attribute "
            "breakable", "CWE-79",
        )
        assert ctx.context_id == "html-attr-squote"
        ctx, _ = resolve_context(
            "htmlspecialchars bypass in element content", "CWE-79",
        )
        assert ctx.context_id == "html-text"
        ctx, why = resolve_context("XSS despite htmlspecialchars", "CWE-79")
        assert ctx is None and "not determinable" in why

    def test_sanitizer_describing_quote_phrase_never_pins_squote(self):
        """Hypotheses describe escapeshellarg's OWN quoting with
        single-quote phrasing; pinning shell-squote on that would
        auto-confirm a false insufficiency on every escapeshellarg
        function (its output always carries quotes)."""
        for hyp in (
            "escapeshellarg wraps the value in single quotes but the "
            "quoting can be bypassed",
            "escapeshellarg only adds single quotes around the input",
            "single-quote handling in escapeshellarg is insufficient",
        ):
            ctx, why = resolve_context(hyp, "CWE-78")
            assert ctx is None, hyp
            assert "sink embedding" in why
            assert "shell-command" in why  # candidates named

    def test_sink_attached_quote_phrases_still_pin(self):
        for hyp, expected in (
            ("quote breakout: escapeshellarg output is embedded in a "
             "single-quoted part of the command", "shell-squote"),
            ("escapeshellcmd output is concatenated into a "
             "double-quoted segment of the command", "shell-dquote"),
            ("escapeshellarg output lands inside single-quoted "
             "context in the built command", "shell-squote"),
        ):
            ctx, why = resolve_context(hyp, "CWE-78")
            assert ctx is not None, (hyp, why)
            assert ctx.context_id == expected

    def test_hybrid_behavior_verb_overrides_embedding_verb(self):
        """The quotes described are the sanitizer's own even when an
        embedding verb follows in the same clause — pinning would
        re-open the auto-confirm."""
        ctx, why = resolve_context(
            "escapeshellarg wraps the input so it lands inside "
            "single quotes", "CWE-78",
        )
        assert ctx is None
        assert "sanitizer-behaviour" in why
        assert "shell-command" in why  # candidates named
        # Genuine sink-clause phrasing (no behaviour verb governing
        # the quote phrase) still pins.
        ctx, why = resolve_context(
            "argument injection despite escapeshellarg — the command "
            "argument lands inside single quotes in the built string",
            "CWE-78",
        )
        assert ctx is not None, why
        assert ctx.context_id == "shell-squote"

    def test_participial_value_description_still_pins(self):
        # A hyphen-attached participle ("escapeshellarg-escaped
        # value") identifies the VALUE, not a behaviour claim — the
        # phrase is genuine sink embedding and keeps its pin.
        ctx, why = resolve_context(
            "the escapeshellarg-escaped value lands inside single "
            "quotes in the command",
            "CWE-78",
        )
        assert ctx is not None, why
        assert ctx.context_id == "shell-squote"

    def test_sanitizer_describing_html_quote_phrase_refuses(self):
        # "leaves single quotes unescaped" describes the sanitizer;
        # without an attribute/element context there is no sink pin.
        ctx, why = resolve_context(
            "htmlspecialchars leaves single quotes unescaped", "CWE-79",
        )
        assert ctx is None
        assert "candidates" in why


class TestEvidenceGrading:
    def test_every_sanwit_stamp_is_detection_grade(self):
        assert is_detection_rule_id("sanwit:insufficient:shell-command")
        assert is_detection_rule_id("sanwit:sufficient:html-text")
        assert not is_detection_rule_id("semgrep:rule")

    def test_stamp_never_qualifies_alone(self):
        from core.audit.evidence_grade import is_tool_evidence

        assert not is_tool_evidence("sanwit:insufficient:shell-command")
        assert not is_tool_evidence("sanwit:sufficient:html-text")

    def test_two_detection_namespaces_aggregate(self):
        from core.audit.evidence_grade import is_tool_evidence

        assert is_tool_evidence(
            "sanwit:insufficient:shell-command+joern:live",
        )

    def test_not_promotion_grade(self):
        from core.audit.orchestrator import _promotion_grade_receipt

        assert not _promotion_grade_receipt(
            "sanwit:insufficient:shell-command",
        )

    def test_receipt_map_prose_reaches_real_stamps(self):
        from core.audit.evidence_grade import _RECEIPT_MAP

        assert "sanwit" in _RECEIPT_MAP
        # The lookup is exact-part-then-bare-namespace: every key in
        # the map must be reachable by a REAL stamp — a two-segment
        # prose row for three-segment rule ids would be a dead key.
        for key in _RECEIPT_MAP:
            if key.startswith("sanwit:"):
                raise AssertionError(
                    f"unreachable sanwit receipt-map key {key!r} — "
                    "rule ids are three-segment; only the bare "
                    "namespace row renders"
                )


class TestSubstrateRegistration:
    def test_registered_file_scope(self):
        from core.audit.substrate import registered_scope

        assert registered_scope("sanwit") == "file"

    def test_php_covered_others_not(self, tmp_path):
        from core.audit.substrate import file_substrate_coverage

        (tmp_path / "a.php").write_text("<?php\n")
        (tmp_path / "b.c").write_text("int main(void){}\n")
        cov = file_substrate_coverage(
            "sanwit", target_path=tmp_path, file_path="a.php",
        )
        assert cov.covered is True
        cov = file_substrate_coverage(
            "sanwit", target_path=tmp_path, file_path="b.c",
        )
        assert cov.covered is False


class TestCoverageDiscipline:
    def test_sanwit_absent_from_clean_when_silent_map(self):
        """The channel must never license silence->clean: it is not a
        coverage-map tool, so a dispatched sanwit row cannot resolve
        a class clean."""
        from core.audit.tool_coverage import _CWE_TOOL_MAP

        for tools in _CWE_TOOL_MAP.values():
            assert "sanwit" not in tools

    def test_not_early_exit_skippable(self):
        from core.audit.orchestrator import _EARLY_EXIT_SKIPPABLE_TYPES

        assert "sanwit" not in _EARLY_EXIT_SKIPPABLE_TYPES


class TestChainBuilders:
    def test_keyword_hook_appends_leg(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain

        chain = _hypothesis_to_tool_chain(
            "escapeshellcmd does not neutralize argument boundaries",
            "web/a.php",
        )
        assert {"type": "sanwit", "config": {}} in chain

    def test_cwe_hook_appends_leg(self):
        from core.audit.orchestrator import _cwe_fallback_chain

        chain = _cwe_fallback_chain(
            "CWE-88", "despite escapeshellcmd", "web/a.php",
        )
        assert {"type": "sanwit", "config": {}} in chain

    def test_no_leg_without_named_sanitizer(self):
        from core.audit.orchestrator import (
            _cwe_fallback_chain,
            _hypothesis_to_tool_chain,
        )

        chain = _hypothesis_to_tool_chain(
            "argument injection through the download path", "web/a.php",
            cwe="CWE-88",
        )
        assert {"type": "sanwit", "config": {}} not in chain
        chain = _cwe_fallback_chain("CWE-88", "argument injection", "a.php")
        assert {"type": "sanwit", "config": {}} not in chain

    def test_language_gate_drops_leg_on_non_php_files(self):
        """A sanitizer-named hypothesis on a non-PHP file must not
        grow a leg: the leg's existence feeds the empty-dispatch
        synthesis routing, which must stay unchanged off-PHP."""
        from core.audit.orchestrator import (
            _cwe_fallback_chain,
            _hypothesis_to_tool_chain,
        )

        hyp = "escapeshellcmd does not neutralize argument boundaries"
        chain = _hypothesis_to_tool_chain(hyp, "src/shell.c")
        assert {"type": "sanwit", "config": {}} not in chain
        chain = _cwe_fallback_chain(
            "CWE-88", "despite escapeshellcmd", "src/shell.c",
        )
        assert {"type": "sanwit", "config": {}} not in chain

    def test_language_gate_two_directions(self):
        from core.audit.sanwit import sanwit_language_permitted

        assert sanwit_language_permitted("web/a.php")
        assert not sanwit_language_permitted("src/a.c")
        assert not sanwit_language_permitted("")  # fail closed
        # Content-probed unmapped extension.
        assert sanwit_language_permitted("plugins/mod", language="php")
        assert not sanwit_language_permitted("plugins/mod", language="c")


class _Cfg:
    """Minimal OrchestratorConfig stand-in for _run_tool_chain."""

    def __init__(self, target, out_dir=None):
        self.target_path = target
        self.out_dir = out_dir
        self.codeql_db_path = None
        self.project_sinks = None
        self.tool_chain_early_exit = True


class TestOrchestratorLeg:
    def _canned(self, outcome, rule_id, verdict, reason="r"):
        return SanwitResult(
            tool="sanwit", file_path="web/a.php", function_name="g",
            outcome=outcome, verdict=verdict, rule_id=rule_id,
            reason=reason,
        )

    def _dispatch(self, tmp_path, monkeypatch, result, file_path="web/a.php"):
        import core.audit.sanwit as sanwit_mod
        from core.audit.orchestrator import _run_tool_chain

        (tmp_path / "web").mkdir(exist_ok=True)
        (tmp_path / "web" / "a.php").write_text("<?php function g(){}\n")
        (tmp_path / "web" / "b.c").write_text("int g(void){}\n")
        out_dir = tmp_path / "out"
        out_dir.mkdir(exist_ok=True)
        calls = []

        def fake_check(*args, **kwargs):
            calls.append((args, kwargs))
            return result

        monkeypatch.setattr(sanwit_mod, "run_sanwit_check", fake_check)
        confirmed = _run_tool_chain(
            [{"type": "sanwit", "config": {}}],
            config=_Cfg(tmp_path, out_dir),
            file_path=file_path,
            function_name="g",
            source="function g($x) {}",
            hypothesis=_HYP_SHELL,
            line_start=1,
            cwe="CWE-88",
        )
        return confirmed, calls, out_dir

    def test_confirmed_receipt_and_audit_log(self, tmp_path, monkeypatch):
        confirmed, calls, out_dir = self._dispatch(
            tmp_path, monkeypatch,
            self._canned(
                "confirmed", "sanwit:insufficient:shell-command",
                "insufficient",
            ),
        )
        assert confirmed == ["sanwit:insufficient:shell-command"]
        assert len(calls) == 1
        log = (out_dir / ".audit-log.jsonl").read_text()
        rows = [json.loads(line) for line in log.splitlines()]
        receipt = next(
            r for r in rows if r.get("action") == "sanwit_check"
        )
        assert receipt["verdict"] == "insufficient"
        assert receipt["rule_id"] == "sanwit:insufficient:shell-command"

    def test_sufficient_never_confirms(self, tmp_path, monkeypatch):
        confirmed, calls, _ = self._dispatch(
            tmp_path, monkeypatch,
            self._canned(
                "inconclusive", "sanwit:sufficient:shell-command",
                "sufficient",
            ),
        )
        assert confirmed == []
        assert len(calls) == 1

    def test_skipped_lands_in_skip_record(self, tmp_path, monkeypatch):
        import core.audit.sanwit as sanwit_mod
        from core.audit.orchestrator import _run_tool_chain

        (tmp_path / "web").mkdir(exist_ok=True)
        (tmp_path / "web" / "a.php").write_text("<?php function g(){}\n")
        monkeypatch.setattr(
            sanwit_mod, "run_sanwit_check",
            lambda *a, **k: self._canned(
                "skipped", "sanwit:not-executable", "not-executable",
            ),
        )
        skipped = set()
        confirmed = _run_tool_chain(
            [{"type": "sanwit", "config": {}}],
            config=_Cfg(tmp_path),
            file_path="web/a.php",
            function_name="g",
            source="function g($x) {}",
            hypothesis=_HYP_SHELL,
            line_start=1,
            skipped_types=skipped,
        )
        assert confirmed == []
        assert "sanwit" in skipped

    def test_substrate_gate_skips_non_php_pre_dispatch(
        self, tmp_path, monkeypatch,
    ):
        confirmed, calls, _ = self._dispatch(
            tmp_path, monkeypatch,
            self._canned(
                "confirmed", "sanwit:insufficient:shell-command",
                "insufficient",
            ),
            file_path="web/b.c",
        )
        assert confirmed == []
        assert calls == []  # never dispatched — substrate skip


class TestFileBindingHazard:
    """Namespace / use-function shadowing: unqualified builtin names
    (functions AND constants) can bind namespace-locally, so the
    probe's global binding would diverge from the target's — refuse."""

    _NS_SRC = (
        "<?php\n"
        "namespace App;\n"
        "const ENT_QUOTES = \\ENT_NOQUOTES;\n"
        "function htmlspecialchars(string $s, int $f = 0): string {\n"
        "    return $s;\n"
        "}\n"
    )
    _FN_SRC = (
        "function f($x) {\n"
        "    $v = htmlspecialchars($x, ENT_QUOTES);\n"
        "    echo \"<a title='$v'>\";\n"
        "}"
    )
    _HYP = (
        "XSS despite htmlspecialchars: single-quoted attribute breakout"
    )

    def _run_on(self, tmp_path, monkeypatch, head: str):
        _stub_execution(monkeypatch)
        (tmp_path / "web").mkdir(exist_ok=True)
        (tmp_path / "web" / "a.php").write_text(head + self._FN_SRC)
        return run_sanwit_check(
            tmp_path, "web/a.php", "f", self._HYP,
            source=self._FN_SRC, cwe="CWE-79",
        )

    def test_namespaced_file_refuses(self, tmp_path, monkeypatch):
        res = self._run_on(tmp_path, monkeypatch, self._NS_SRC)
        assert res.outcome == "skipped"
        assert "namespace" in res.reason

    def test_use_function_import_refuses(self, tmp_path, monkeypatch):
        res = self._run_on(
            tmp_path, monkeypatch,
            "<?php\nuse function App\\htmlspecialchars;\n",
        )
        assert res.outcome == "skipped"
        assert "use function" in res.reason

    def test_plain_global_file_proceeds(self, tmp_path, monkeypatch):
        res = self._run_on(tmp_path, monkeypatch, "<?php\n")
        assert res.outcome == "confirmed"  # identity stub: breakout

    def test_unreadable_file_proceeds_source_only(self, monkeypatch):
        _stub_execution(monkeypatch)
        res = run_sanwit_check(
            "/nonexistent", "web/a.php", "f", self._HYP,
            source=self._FN_SRC, cwe="CWE-79",
        )
        assert res.outcome == "confirmed"

    def test_comment_padding_cannot_hide_the_namespace(
        self, tmp_path, monkeypatch,
    ):
        # A fixed-size head read was defeated by ~72KB of comments
        # pushing the declaration past the head — the code-aware scan
        # skips ANY amount of comment padding.
        padding = "<?php\n/*\n" + ("x" * 76 + "\n") * 950 + "*/\n"
        head = padding + (
            "namespace App;\n"
            "const ENT_QUOTES = \\ENT_NOQUOTES;\n"
            "function htmlspecialchars(string $s, int $f = 0): string "
            "{ return $s; }\n"
        )
        assert len(head) > 64 * 1024  # beyond the old head read
        res = self._run_on(tmp_path, monkeypatch, head)
        assert res.outcome == "skipped"
        assert "namespace" in res.reason

    def test_over_budget_file_refuses_fail_closed(
        self, tmp_path, monkeypatch,
    ):
        from core.audit.sanwit import _BINDING_SCAN_BUDGET

        head = "<?php\n/*\n" + "x" * (_BINDING_SCAN_BUDGET + 10) + "\n*/\n"
        res = self._run_on(tmp_path, monkeypatch, head)
        assert res.outcome == "skipped"
        assert "binding-scan budget" in res.reason

    def test_use_const_import_refuses(self, tmp_path, monkeypatch):
        res = self._run_on(
            tmp_path, monkeypatch,
            "<?php\nuse const App\\ENT_QUOTES;\n",
        )
        assert res.outcome == "skipped"
        assert "use" in res.reason

    def test_mixed_case_declarations_refuse(self, tmp_path, monkeypatch):
        # PHP keywords are case-insensitive: `NameSpace App;` and
        # `USE FUNCTION strrev as htmlspecialchars;` are legal
        # shadowing spellings.
        res = self._run_on(
            tmp_path, monkeypatch, "<?php\nNameSpace App;\n",
        )
        assert res.outcome == "skipped"
        assert "namespace" in res.reason
        res = self._run_on(
            tmp_path, monkeypatch,
            "<?php\nUSE FUNCTION strrev as htmlspecialchars;\n",
        )
        assert res.outcome == "skipped"
        assert "use" in res.reason

    def test_mixed_case_inside_data_stays_inert(
        self, tmp_path, monkeypatch,
    ):
        res = self._run_on(
            tmp_path, monkeypatch,
            "<?php\n$s = 'NameSpace App;';\n// USE FUNCTION x\\y;\n",
        )
        assert res.outcome == "confirmed"

    def test_declarations_inside_data_are_inert(
        self, tmp_path, monkeypatch,
    ):
        # 'namespace'/'use function' text inside comments, string
        # literals, heredoc bodies, or the HTML prologue is data.
        head = (
            "<p>namespace App;</p>\n"
            "<?php\n"
            "// namespace App;\n"
            "$doc = 'use function foo\\bar;';\n"
            "$t = <<<EOT\nnamespace App;\nuse function x\\y;\nEOT;\n"
            '$u = "namespace App;";\n'
        )
        res = self._run_on(tmp_path, monkeypatch, head)
        assert res.outcome == "confirmed"

    @pytest.mark.skipif(
        not hasattr(os, "mkfifo"), reason="no mkfifo on this platform",
    )
    def test_fifo_target_degrades_source_only_without_blocking(
        self, tmp_path, monkeypatch,
    ):
        # A planted FIFO at the target path must land in the same
        # source-only arm as an unreadable file — and must not block
        # the scan (a raw open() on a reader-less FIFO hangs; the
        # bounded-read seam refuses non-regular files at the fd).
        _stub_execution(monkeypatch)
        (tmp_path / "web").mkdir(exist_ok=True)
        os.mkfifo(tmp_path / "web" / "a.php")
        box: dict[str, SanwitResult] = {}

        def run() -> None:
            box["res"] = run_sanwit_check(
                tmp_path, "web/a.php", "f", self._HYP,
                source=self._FN_SRC, cwe="CWE-79",
            )

        t = threading.Thread(target=run, daemon=True)
        t.start()
        t.join(timeout=20)
        assert not t.is_alive(), "binding scan blocked on a FIFO"
        assert box["res"].outcome == "confirmed"  # source-only mode

    def test_symlink_escape_is_not_scanned(self, tmp_path, monkeypatch):
        # The target-relative path symlinks OUT of the target root:
        # containment refuses the read and the check degrades to
        # source-only (the resolve-prefix spelling before the seam
        # behaved the same way — pinned here so it stays put).
        _stub_execution(monkeypatch)
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "evil.php").write_text("<?php\nnamespace App;\n")
        root = tmp_path / "root"
        (root / "web").mkdir(parents=True)
        (root / "web" / "a.php").symlink_to(outside / "evil.php")
        res = run_sanwit_check(
            root, "web/a.php", "f", self._HYP,
            source=self._FN_SRC, cwe="CWE-79",
        )
        assert res.outcome == "confirmed"  # escaped content never read

    def test_inroot_symlink_still_scanned(self, tmp_path, monkeypatch):
        # In-root symlinks keep working: containment resolves them,
        # and the resolved file's declarations still refuse.
        _stub_execution(monkeypatch)
        (tmp_path / "web").mkdir(exist_ok=True)
        (tmp_path / "web" / "real.php").write_text(
            self._NS_SRC + self._FN_SRC,
        )
        (tmp_path / "web" / "a.php").symlink_to(
            tmp_path / "web" / "real.php",
        )
        res = run_sanwit_check(
            tmp_path, "web/a.php", "f", self._HYP,
            source=self._FN_SRC, cwe="CWE-79",
        )
        assert res.outcome == "skipped"
        assert "namespace" in res.reason


class TestExtractionCache:
    def test_precheck_and_leg_share_one_extraction(self):
        # sanwit_can_adjudicate (chain-builder precheck) and
        # run_sanwit_check both extract; the memo makes the second
        # call free — same frozen object, one parse of the source.
        from core.audit.sanwit import _extract_cached

        _extract_cached.cache_clear()
        r1 = _extract_cached(_SRC_SHELL, ("escapeshellcmd",))
        r2 = _extract_cached(_SRC_SHELL, ("escapeshellcmd",))
        assert r1 is r2
        assert _extract_cached.cache_info().hits == 1


class TestCanAdjudicate:
    def test_mirrors_the_refusal_ladder(self, tmp_path, monkeypatch):
        from core.audit.sanwit import sanwit_can_adjudicate

        monkeypatch.setattr(
            sanwit_execute, "resolve_php_runtime",
            lambda refresh=False: _RUNTIME,
        )
        # Executable shape → True.
        assert sanwit_can_adjudicate(
            tmp_path, "web/a.php", _HYP_SHELL,
            source=_SRC_SHELL, cwe="CWE-88",
        )
        # Extraction refusal → False.
        assert not sanwit_can_adjudicate(
            tmp_path, "web/a.php", _HYP_SHELL,
            source="function g($x) { echo $x; }", cwe="CWE-88",
        )
        # Context refusal → False.
        assert not sanwit_can_adjudicate(
            tmp_path, "web/a.php", "XSS despite htmlspecialchars",
            source=_SRC_SHELL, cwe="CWE-79",
        )
        # Interpreter absent → False.
        monkeypatch.setattr(
            sanwit_execute, "resolve_php_runtime",
            lambda refresh=False: RuntimeUnavailable(reason="none"),
        )
        assert not sanwit_can_adjudicate(
            tmp_path, "web/a.php", _HYP_SHELL,
            source=_SRC_SHELL, cwe="CWE-88",
        )


class TestSynthesisRoutingRestored:
    """A sanwit leg counts as dispatch only when it actually runs: a
    chain whose every leg declined to look must route to the
    empty-dispatch synthesis lane exactly like an empty chain."""

    def _drive(self, tmp_path, monkeypatch, *, chain, run_stub,
               refuting=False, can_adjudicate=None):
        import core.audit.orchestrator as orch
        from core.audit.orchestrator import (
            OrchestratorConfig,
            OrchestratorResult,
            ReviewOutcome,
            _promote_suspicious_one,
        )

        outcome = ReviewOutcome(
            file="web/a.php", function="g", status="suspicious",
            body="looks off", hypothesis=_HYP_SHELL, line=2,
        )
        outcome.review_result = {"hypothesis": _HYP_SHELL}
        if refuting:
            outcome.review_result["adversarial_verdict"] = "refuted"
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.suspicious = 1
        out = tmp_path / "out"
        out.mkdir(exist_ok=True)
        config = OrchestratorConfig(target_path=tmp_path, out_dir=out)

        monkeypatch.setattr(
            orch, "_hypothesis_to_tool_chain", lambda *a, **k: chain,
        )
        monkeypatch.setattr(orch, "_run_tool_chain", run_stub)
        monkeypatch.setattr(
            orch, "_has_refuting_counter", lambda o: refuting,
        )
        monkeypatch.setattr(
            orch, "_read_raw_source", lambda *a, **k: "function g(){}",
        )
        monkeypatch.setattr(
            orch, "run_prefilter",
            lambda *a, **k: SimpleNamespace(hits=[]),
        )
        monkeypatch.setattr(
            orch, "_correlated_mech_detector_tool",
            lambda *a, **k: None,
        )
        if can_adjudicate is not None:
            import core.audit.sanwit as sanwit_mod

            monkeypatch.setattr(
                sanwit_mod, "sanwit_can_adjudicate",
                lambda *a, **k: can_adjudicate,
            )
        synthesized = []
        monkeypatch.setattr(
            orch, "_synthesize_unmapped_suspicious",
            lambda *a, **k: synthesized.append(a),
        )
        _promote_suspicious_one(result, config, 0, outcome)
        return synthesized

    def test_all_skipped_chain_routes_to_synthesis(
        self, tmp_path, monkeypatch,
    ):
        def run_stub(chain, **kwargs):
            kwargs["skipped_types"].add("sanwit")
            return []

        synthesized = self._drive(
            tmp_path, monkeypatch,
            chain=[{"type": "sanwit", "config": {}}],
            run_stub=run_stub,
        )
        assert len(synthesized) == 1

    def test_ran_but_silent_chain_does_not_route(
        self, tmp_path, monkeypatch,
    ):
        # The leg RAN (inconclusive, nothing skipped): dispatch
        # happened, no synthesis re-route.
        synthesized = self._drive(
            tmp_path, monkeypatch,
            chain=[{"type": "sanwit", "config": {}}],
            run_stub=lambda chain, **kwargs: [],
        )
        assert synthesized == []

    def test_all_errored_chain_routes_to_synthesis(
        self, tmp_path, monkeypatch,
    ):
        # A grammar-admitted chain that ERRORS at runtime (planted
        # invalid literal regex) adjudicated nothing — landing it in
        # error accounting must not swallow the empty-dispatch
        # synthesis route.
        def run_stub(chain, **kwargs):
            kwargs["errored_types"].add("sanwit")
            return []

        synthesized = self._drive(
            tmp_path, monkeypatch,
            chain=[{"type": "sanwit", "config": {}}],
            run_stub=run_stub,
        )
        assert len(synthesized) == 1

    def test_error_plus_another_leg_ran_does_not_route(
        self, tmp_path, monkeypatch,
    ):
        # Another leg actually adjudicated (ran, stayed silent):
        # its silence is evidence — no re-route.
        def run_stub(chain, **kwargs):
            kwargs["errored_types"].add("sanwit")
            return []

        synthesized = self._drive(
            tmp_path, monkeypatch,
            chain=[
                {"type": "sanwit", "config": {}},
                {"type": "smt", "config": {"verb": "x"}},
            ],
            run_stub=run_stub,
        )
        assert synthesized == []

    def test_skip_and_error_mix_routes(self, tmp_path, monkeypatch):
        def run_stub(chain, **kwargs):
            kwargs["skipped_types"].add("sanwit")
            kwargs["errored_types"].add("smt")
            return []

        synthesized = self._drive(
            tmp_path, monkeypatch,
            chain=[
                {"type": "sanwit", "config": {}},
                {"type": "smt", "config": {"verb": "x"}},
            ],
            run_stub=run_stub,
        )
        assert len(synthesized) == 1

    def test_refuting_counter_sanwit_only_chain_routes_when_refusing(
        self, tmp_path, monkeypatch,
    ):
        synthesized = self._drive(
            tmp_path, monkeypatch,
            chain=[{"type": "sanwit", "config": {}}],
            run_stub=lambda chain, **kwargs: [],
            refuting=True,
            can_adjudicate=False,
        )
        assert len(synthesized) == 1

    def test_refuting_counter_sanwit_chain_skips_when_it_can_run(
        self, tmp_path, monkeypatch,
    ):
        synthesized = self._drive(
            tmp_path, monkeypatch,
            chain=[{"type": "sanwit", "config": {}}],
            run_stub=lambda chain, **kwargs: [],
            refuting=True,
            can_adjudicate=True,
        )
        assert synthesized == []


class TestDockerCaptureBounds:
    def test_fsize_ulimit_in_container_args(self):
        args = sanwit_execute._docker_base_args("/usr/bin/docker", "/s")
        joined = " ".join(args)
        assert "--ulimit" in args
        assert f"fsize={sanwit_execute._DOCKER_FSIZE_LIMIT}" in joined
        assert "--network=none" in args

    def _shim_runtime(self, tmp_path, script: str):
        # A docker-client stand-in: the capture loop's subject is the
        # HOST-side client process (the container's rlimits cannot
        # bound its stdout pipe), so a shim exercises the real
        # behaviour hermetically. The shim honours --cidfile (writes
        # a fake cid, as the real client does) and records the
        # cid-based `rm -f` cleanup invocation into a marker file.
        marker = tmp_path / "cleanup-marker"
        shim = tmp_path / "docker-shim"
        shim.write_text(
            "#!/bin/sh\n"
            f'if [ "$1" = "kill" ]; then exit 0; fi\n'
            f'if [ "$1" = "rm" ]; then echo "$3" > "{marker}"; exit 0; fi\n'
            'prev=""\n'
            'for a in "$@"; do\n'
            '  [ "$prev" = "--cidfile" ] && printf '
            "'a1b2c3d4e5f6' > \"$a\"\n"
            '  prev="$a"\n'
            "done\n"
            + script + "\n"
        )
        shim.chmod(0o755)
        script_dir = tmp_path / "s"
        script_dir.mkdir(exist_ok=True)
        probe = script_dir / "probe.php"
        payloads = script_dir / "payloads.json"
        probe.write_text("<?php\n")
        payloads.write_text("{}")
        runtime = PhpRuntime(
            tier="docker", version="8.3.0",
            docker_path=str(shim), image="pinned",
        )
        return runtime, script_dir, probe, payloads, marker

    def test_oversized_stdout_is_indeterminate_bounded_and_cleaned(
        self, tmp_path,
    ):
        # 8 MiB flood: accumulation stops at cap+1, the client is
        # terminated while the pipes keep DRAINING (a blocked attach
        # would stop SIGTERM from ever reaching the container), and
        # the cid-based daemon-side cleanup runs — the bound is the
        # CAP and the drain grace, not timeout x throughput.
        import time as _time

        runtime, sdir, probe, payloads, marker = self._shim_runtime(
            tmp_path,
            "head -c 8388608 /dev/zero | tr '\\0' 'A'",
        )
        t0 = _time.monotonic()
        out = sanwit_execute._execute_docker(
            runtime, sdir, probe, payloads,
        )
        elapsed = _time.monotonic() - t0
        assert not out.ok
        assert "exceeded" in out.reason
        assert "cap" in out.reason
        assert elapsed < sanwit_execute.DOCKER_TIMEOUT_S / 2, (
            "flood termination must be drain-bounded, not "
            "timeout-bounded"
        )
        # The daemon-side rm -f ran with the recorded cid.
        assert marker.read_text().strip() == "a1b2c3d4e5f6"

    def test_small_stdout_passes_through_with_cleanup_belt(
        self, tmp_path,
    ):
        runtime, sdir, probe, payloads, marker = self._shim_runtime(
            tmp_path, "printf 'hello-json'",
        )
        out = sanwit_execute._execute_docker(
            runtime, sdir, probe, payloads,
        )
        assert out.ok
        assert out.stdout == "hello-json"
        # The cleanup belt is unconditional (idempotent on the
        # normal path — the real client's --rm has already fired).
        assert marker.exists()

    def test_nonzero_exit_carries_stderr_tail(self, tmp_path):
        runtime, sdir, probe, payloads, _ = self._shim_runtime(
            tmp_path, "echo boom-detail 1>&2; exit 7",
        )
        out = sanwit_execute._execute_docker(
            runtime, sdir, probe, payloads,
        )
        assert not out.ok
        assert "probe exited 7" in out.reason
        assert "boom-detail" in out.reason

    def test_probe_path_has_the_cleanup_belt(self, tmp_path):
        # The version probe can SIGKILL a slow client on timeout and
        # leak the container the same way — same cid discipline.
        marker = tmp_path / "cleanup-marker"
        shim = tmp_path / "docker-shim"
        shim.write_text(
            "#!/bin/sh\n"
            f'if [ "$1" = "kill" ]; then exit 0; fi\n'
            f'if [ "$1" = "rm" ]; then echo "$3" > "{marker}"; exit 0; fi\n'
            'prev=""\n'
            'for a in "$@"; do\n'
            '  [ "$prev" = "--cidfile" ] && printf '
            "'a1b2c3d4e5f6' > \"$a\"\n"
            '  prev="$a"\n'
            "done\n"
            "printf '8.3.0'\n"
        )
        shim.chmod(0o755)
        version, why = sanwit_execute._probe_docker(str(shim))
        assert version == "8.3.0", why
        assert marker.read_text().strip() == "a1b2c3d4e5f6"

    def test_cleanup_requires_a_wellformed_cid(self, tmp_path):
        calls = tmp_path / "calls"
        fake_docker = tmp_path / "fake-docker"
        fake_docker.write_text(
            f"#!/bin/sh\necho called >> \"{calls}\"\n",
        )
        fake_docker.chmod(0o755)
        bad = tmp_path / "cid"
        bad.write_text("../../etc; rm -rf /\n")
        sanwit_execute._cleanup_container(str(fake_docker), str(bad))
        assert not calls.exists()  # malformed cid: no invocation
        bad.write_text("a1b2c3d4e5f6\n")
        sanwit_execute._cleanup_container(str(fake_docker), str(bad))
        assert calls.exists()

    def test_cleanup_refuses_an_oversized_cidfile(self, tmp_path):
        # All-hex but far beyond any cid spelling: the bounded read
        # marks it truncated and the belt treats it like a missing
        # file — the hex PREFIX must never be forwarded to docker.
        calls = tmp_path / "calls"
        fake_docker = tmp_path / "fake-docker"
        fake_docker.write_text(
            f"#!/bin/sh\necho called >> \"{calls}\"\n",
        )
        fake_docker.chmod(0o755)
        bad = tmp_path / "cid"
        bad.write_text("a" * (sanwit_execute._CIDFILE_CAP + 64))
        sanwit_execute._cleanup_container(str(fake_docker), str(bad))
        assert not calls.exists()

    @pytest.mark.skipif(
        not hasattr(os, "mkfifo"), reason="no mkfifo on this platform",
    )
    def test_cleanup_refuses_a_nonregular_cidfile_promptly(
        self, tmp_path,
    ):
        # A FIFO where the cidfile should be: the bounded-read seam
        # refuses at the fd instead of blocking the cleanup belt on
        # a reader-less open.
        calls = tmp_path / "calls"
        fake_docker = tmp_path / "fake-docker"
        fake_docker.write_text(
            f"#!/bin/sh\necho called >> \"{calls}\"\n",
        )
        fake_docker.chmod(0o755)
        fifo = tmp_path / "cid"
        os.mkfifo(fifo)
        t = threading.Thread(
            target=sanwit_execute._cleanup_container,
            args=(str(fake_docker), str(fifo)),
            daemon=True,
        )
        t.start()
        t.join(timeout=20)
        assert not t.is_alive(), "cleanup belt blocked on a FIFO"
        assert not calls.exists()


class TestOrphanContainment:
    """A SIGKILL'd parent runs NO exit path: the cidfile belt and
    --rm both die with it, and an orphaned container (observed: a
    flood probe burning a core for 75+ minutes) survives until
    something else acts. Two independent legs pin the recovery: the
    container-side wall clock (self-termination without any host
    help) and the labelled dead-owner sweep (next witness run reaps
    by verified-pid identity)."""

    def test_owner_labels_and_wall_clock_in_args(self):
        args = sanwit_execute._docker_base_args("/usr/bin/docker", "/s")
        pid, start = sanwit_execute._owner_identity()
        assert f"{sanwit_execute._CHANNEL_LABEL}=1" in args
        assert f"{sanwit_execute._OWNER_PID_LABEL}={pid}" in args
        assert f"{sanwit_execute._OWNER_START_LABEL}={start}" in args
        # The wrapper heads the in-container command (right after
        # the image) so EVERY witness container self-terminates: a
        # resident sh (busybox timeout as PID 1 cannot kill; ash
        # exec-optimizes without the status capture) runs timeout
        # over the caller-appended "$@" positionals.
        img = args.index(sanwit_execute.DOCKER_IMAGE)
        assert args[img + 1:img + 3] == ["sh", "-c"]
        program = args[img + 3]
        bound = sanwit_execute._CONTAINER_WALL_CLOCK_S
        assert program.startswith(f'timeout -s KILL {bound} "$@"')
        assert "; st=$?" in program  # keeps sh resident (no exec-opt)
        assert args[img + 4] == "sh"  # $0; the command follows as $@
        assert args[img + 4] == args[-1]
        # Two directions: the unattended belt must exist, but the
        # attended parent deadline must keep winning the race.
        assert bound > sanwit_execute.DOCKER_TIMEOUT_S

    def test_self_starttime_is_verifiable(self):
        # The starttime read is the shared PID-reuse discriminator
        # (core.project.sessions.proc_starttime), not a local copy.
        start = sanwit_execute.proc_starttime(os.getpid())
        assert start is not None and start.isdigit()
        pid, owner_start = sanwit_execute._owner_identity()
        assert (pid, owner_start) == (os.getpid(), start)

        from core.project.sessions import proc_starttime as canonical

        assert sanwit_execute.proc_starttime is canonical

    def _sweep_shim(
        self,
        tmp_path,
        containers: dict[str, str],
        extra_ps_lines: list[str] | None = None,
        legacy_rows: list[str] | None = None,
    ):
        """Daemon-faithful fake docker: an id-format ``ps`` prints
        the container ids (plus any raw injected lines); any OTHER
        ``ps`` format is answered like the real Go-template renderer
        — *legacy_rows* verbatim, label VALUES unescaped — so a
        regression back to row parsing meets the injection, not a
        silent empty list. ``inspect <cid>`` prints that container's
        own label JSON; anything else is recorded."""
        calls = tmp_path / "calls"
        ps_ids = tmp_path / "ps-ids"
        lines = list(containers) + list(extra_ps_lines or [])
        ps_ids.write_text("".join(line + "\n" for line in lines))
        ps_rows = tmp_path / "ps-rows"
        ps_rows.write_text(
            "".join(row + "\n" for row in (legacy_rows or [])))
        for cid, labels_json in containers.items():
            (tmp_path / f"inspect-{cid[:16]}").write_text(labels_json)
        shim = tmp_path / "docker-shim"
        shim.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "ps" ]; then\n'
            '  if [ "$7" = "{{.ID}}" ]; then\n'
            f'    cat "{ps_ids}"\n'
            "  else\n"
            f'    cat "{ps_rows}"\n'
            "  fi\n"
            "  exit 0\n"
            "fi\n"
            'if [ "$1" = "inspect" ]; then\n'
            f'  f="{tmp_path}/inspect-$(printf %.16s "$4")"\n'
            '  if [ -f "$f" ]; then cat "$f"; exit 0; fi\n'
            "  exit 1\n"
            "fi\n"
            f'echo "$@" >> "{calls}"\n'
        )
        shim.chmod(0o755)
        return shim, calls

    @staticmethod
    def _labels(pid: str, start: str) -> str:
        return json.dumps({
            sanwit_execute._CHANNEL_LABEL: "1",
            sanwit_execute._OWNER_PID_LABEL: pid,
            sanwit_execute._OWNER_START_LABEL: start,
        })

    def _run_sweep(self, monkeypatch, shim):
        monkeypatch.setattr(sanwit_execute, "_SWEEP_DONE", False)
        sanwit_execute._sweep_dead_owner_containers(str(shim))

    def _dead_pid(self) -> str:
        import subprocess as sp
        import sys as _sys

        # A pid with POSITIVE death evidence: a real child that has
        # exited. Even if the pid is recycled before the sweep, the
        # fabricated starttime cannot match — both branches are
        # death evidence.
        child = sp.run(
            [_sys.executable, "-c", "import os; print(os.getpid())"],
            capture_output=True, text=True, check=True,
        )
        return child.stdout.strip()

    def test_sweep_reaps_only_positively_dead_owners(
        self, tmp_path, monkeypatch,
    ):
        dead_pid = self._dead_pid()
        live_pid = os.getpid()
        live_start = sanwit_execute.proc_starttime(live_pid)
        init_start = sanwit_execute.proc_starttime(1)
        containers = {
            "a" * 64: self._labels(dead_pid, "123456"),   # -> reap
            "b" * 64: self._labels(str(live_pid), str(live_start)),
            "d" * 64: self._labels(dead_pid, "0"),   # unverifiable
            "e" * 64: self._labels("notapid", "123"),  # malformed
            "f" * 64: json.dumps({"com.example": "x"}),  # foreign
        }
        if init_start is not None:
            # A live pid whose starttime CANNOT match the label: the
            # labelled owner's pid was recycled — death evidence.
            containers["c" * 64] = self._labels("1", f"{init_start}9")
        shim, calls = self._sweep_shim(
            tmp_path, containers, extra_ps_lines=["ZZZ", ""],
        )
        self._run_sweep(monkeypatch, shim)
        got = calls.read_text() if calls.exists() else ""
        assert f"kill {'a' * 64}" in got
        assert f"rm -f {'a' * 64}" in got
        if init_start is not None:
            assert f"rm -f {'c' * 64}" in got
        for skipped in ("b", "d", "e", "f"):
            assert skipped * 64 not in got
        assert "ZZZ" not in got

    def test_injected_label_values_cannot_forge_a_victim_row(
        self, tmp_path, monkeypatch,
    ):
        # The executed injection shape: a hostile owner.start value
        # embedding a newline/tab-forged row that names a foreign
        # victim cid. The listing never prints label values (ids
        # only) and the identity decision reads the candidate's OWN
        # inspect labels, so the forged text is inert data: the
        # victim is untouched, and the hostile container itself is
        # skipped (its start value is not a verifiable identity).
        victim = "9" * 64
        hostile = "a" * 64
        dead_pid = self._dead_pid()
        forged = f"0\n{victim}\t{dead_pid}\t123456"
        containers = {
            hostile: self._labels(dead_pid, forged),
            victim: json.dumps({"com.example.app": "web"}),
        }
        # What the Go-template renderer would print for a row-format
        # listing: the forged value verbatim — a regression back to
        # row parsing meets exactly the executed attack.
        legacy = [f"{hostile}\t{dead_pid}\t{forged}"]
        shim, calls = self._sweep_shim(
            tmp_path, containers, legacy_rows=legacy,
        )
        self._run_sweep(monkeypatch, shim)
        got = calls.read_text() if calls.exists() else ""
        assert victim not in got  # the falsified claim, now pinned
        assert hostile not in got  # unverifiable start -> left alone

    def test_forged_plain_row_fails_the_inspect_gate(
        self, tmp_path, monkeypatch,
    ):
        # Even a tab/newline-free forged listing line naming a
        # foreign cid (e.g. a compromised listing path) dies at the
        # authoritative per-container label read: the victim's own
        # labels do not carry the family marker.
        victim = "9" * 64
        containers = {
            victim: json.dumps({"com.example.app": "web"}),
        }
        shim, calls = self._sweep_shim(tmp_path, containers)
        self._run_sweep(monkeypatch, shim)
        assert not calls.exists()

    def test_sweep_leaves_a_live_verified_owner_alone(
        self, tmp_path, monkeypatch,
    ):
        # pid 1 with its REAL starttime: alive and identity-verified
        # (not our own pid, so this exercises the liveness branch,
        # not the own-pid skip).
        init_start = sanwit_execute.proc_starttime(1)
        if init_start is None:
            pytest.skip("no readable /proc/1/stat on this host")
        containers = {"f" * 64: self._labels("1", str(init_start))}
        shim, calls = self._sweep_shim(tmp_path, containers)
        self._run_sweep(monkeypatch, shim)
        assert not calls.exists()

    def test_sweep_budget_bounds_the_stall(self, tmp_path, monkeypatch):
        # Two directions: with the budget floored the sweep stops
        # before processing ANY row (a wedged daemon cannot stall
        # the witness past the budget + one in-flight call); the
        # default budget processes the same row (the reap tests
        # above are the accepting direction at scale).
        containers = {"a" * 64: self._labels(self._dead_pid(), "123456")}
        shim, calls = self._sweep_shim(tmp_path, containers)
        monkeypatch.setattr(sanwit_execute, "_SWEEP_BUDGET_S", -1)
        self._run_sweep(monkeypatch, shim)
        assert not calls.exists()  # no row processed past the budget

    def test_oversized_label_map_is_skipped(self, tmp_path, monkeypatch):
        # A hostile image shipping a megabyte label map is "not
        # ours" — fail toward not-reaping.
        big = json.dumps({
            sanwit_execute._CHANNEL_LABEL: "1",
            sanwit_execute._OWNER_PID_LABEL: self._dead_pid(),
            sanwit_execute._OWNER_START_LABEL: "123456",
            "com.example.pad": "x" * sanwit_execute._SWEEP_INSPECT_CAP,
        })
        containers = {"a" * 64: big}
        shim, calls = self._sweep_shim(tmp_path, containers)
        self._run_sweep(monkeypatch, shim)
        assert not calls.exists()

    def test_sweep_runs_once_per_process(self, tmp_path, monkeypatch):
        count = tmp_path / "count"
        shim = tmp_path / "docker-shim"
        shim.write_text(
            "#!/bin/sh\n"
            f'echo x >> "{count}"\n'
            "exit 0\n"
        )
        shim.chmod(0o755)
        monkeypatch.setattr(sanwit_execute, "_SWEEP_DONE", False)
        sanwit_execute._sweep_dead_owner_containers(str(shim))
        sanwit_execute._sweep_dead_owner_containers(str(shim))
        assert count.read_text().count("x") == 1

    def test_sweep_survives_a_broken_daemon(self, tmp_path, monkeypatch):
        shim = tmp_path / "docker-shim"
        shim.write_text("#!/bin/sh\nexit 1\n")
        shim.chmod(0o755)
        self._run_sweep(monkeypatch, shim)  # must not raise
        missing = tmp_path / "no-such-docker"
        monkeypatch.setattr(sanwit_execute, "_SWEEP_DONE", False)
        sanwit_execute._sweep_dead_owner_containers(str(missing))


class TestChildEnv:
    """Every witness spawn's environment comes from the shared
    fail-closed helper with target-facing markers stripped: the
    native tier's interpreter executes target-derived chain code,
    and no witness child consumes RAPTOR runtime variables."""

    def test_markers_and_dangerous_vars_stripped(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", "/opt/raptor")
        monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
        env = sanwit_execute._safe_env()
        assert not any(
            k.startswith(("RAPTOR_", "_RAPTOR")) for k in env
        )
        assert "LD_PRELOAD" not in env
        assert "PATH" in env  # two-direction: children still launch

    def test_fail_closed_when_core_config_is_broken(self, monkeypatch):
        # The re-rolled ladder this replaced raised through the
        # cleanup belt when core.config could not import; the shared
        # helper degrades to a minimal allowlist — never the
        # parent-inherit sentinel, never the raw parent env.
        import sys as _sys

        monkeypatch.setenv("SUPER_SECRET_API_KEY", "hunter2")
        monkeypatch.setitem(_sys.modules, "core.config", None)
        env = sanwit_execute._safe_env()
        assert env is not None
        assert "SUPER_SECRET_API_KEY" not in env
        assert "PATH" in env


class TestNativeExecutionSeam:
    def test_dark_verify_helper_names_exist(self):
        """Drift fence: the native tier reuses the dark_verify script-
        witness machinery via private same-subsystem imports — a
        rename there must fail HERE, not at first native dispatch."""
        from core.audit.dark_verify import _execute as dv

        for name in (
            "_import_sandbox_run", "_sandbox_run_capped",
            "_sandbox_exec_path", "_toolchain_read_paths",
        ):
            assert callable(getattr(dv, name)), name

    def test_native_fails_closed_without_sandbox(self, monkeypatch):
        import core.audit.dark_verify._execute as dv

        monkeypatch.setattr(dv, "_import_sandbox_run", lambda: None)
        out = sanwit_execute.execute_probe(
            _RUNTIME, "<?php\n", '{"payloads": {}}',
        )
        assert not out.ok
        assert "refused" in out.reason


class TestSandboxPolicy:
    def test_php_tool_policy_registered(self):
        from core.audit.sandbox_policy import get_sandbox_profile

        policy = get_sandbox_profile("php")
        assert policy is not None
        assert policy.profile == "full"
        assert policy.network_deny


@pytest.fixture(autouse=True)
def _reset_runtime_cache():
    sanwit_execute._reset_runtime_cache()
    yield
    sanwit_execute._reset_runtime_cache()
