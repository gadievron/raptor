"""Tests for core.orchestration.joern_scan — the /agentic Joern phase.

Everything here runs without a Joern installation: the decision
function takes injected availability booleans, the SARIF converters
take in-memory TaintFlow objects / marker transcripts, and the phase
entry point is only exercised for its degraded (no-session) paths.
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.orchestration.joern_scan import (
    _STRUCTURAL_QUERY_COUNT,
    STRUCTURAL_RULES,
    _read_target_line,
    _resolve_sink_name,
    _structural_results,
    _taint_results,
    _taint_rule_for,
    joern_scan_decision,
)
from core.sarif import emit
from packages.joern.models import FlowStep, TaintFlow


def _flow(steps: list[FlowStep], *, source_method: str = "handler",
          source_param: str = "char *buf",
          sink_call: str = "") -> TaintFlow:
    return TaintFlow(source_method=source_method,
                     source_param=source_param,
                     sink_call=sink_call, sink_arg_idx=1, steps=steps)


def _step(file: str, line: int, code: str,
          function: str = "handler") -> FlowStep:
    return FlowStep(file=file, function=function, line=line,
                    code=code, variable="")


class TestDecision(unittest.TestCase):
    """joern_scan_decision precedence matrix (availability injected)."""

    def _decide(self, **kw):
        base = dict(requested=False, disabled=False, skip_scan=False,
                    openant_only=False, target_path=Path("/nonexistent"),
                    codeql_covered_languages=frozenset(),
                    joern_available=True,
                    has_joern_sources=True, language="c")
        base.update(kw)
        return joern_scan_decision(**base)

    def test_disabled_wins_over_everything(self):
        d = self._decide(disabled=True, requested=True)
        self.assertFalse(d.run)
        self.assertIn("--no-joern-scan", d.reason)

    def test_skip_scan_blocks_even_explicit_request(self):
        d = self._decide(skip_scan=True, requested=True)
        self.assertFalse(d.run)
        self.assertTrue(d.requested)
        self.assertIn("imported SARIF", d.reason)

    def test_openant_only_blocks(self):
        d = self._decide(openant_only=True)
        self.assertFalse(d.run)
        self.assertIn("--openant-only", d.reason)

    def test_requested_runs_regardless_of_language_and_codeql(self):
        d = self._decide(requested=True, has_joern_sources=False,
                         language="ruby",
                         codeql_covered_languages=frozenset({"cpp"}))
        self.assertTrue(d.run)
        self.assertTrue(d.requested)

    def test_requested_but_unavailable_is_loud_block(self):
        d = self._decide(requested=True, joern_available=False)
        self.assertFalse(d.run)
        self.assertTrue(d.requested)
        self.assertIn("not", d.reason)

    def test_unavailable_blocks_auto(self):
        d = self._decide(joern_available=False)
        self.assertFalse(d.run)
        self.assertFalse(d.requested)

    def test_unprofiled_target_skips_auto(self):
        d = self._decide(has_joern_sources=False)
        self.assertFalse(d.run)
        self.assertIn("no sources with a curated Joern profile",
                      d.reason)

    def test_codeql_coverage_skips_auto(self):
        d = self._decide(
            codeql_covered_languages=frozenset({"cpp"}))
        self.assertFalse(d.run)
        self.assertIn("CodeQL", d.reason)

    def test_auto_enables_on_uncovered_c_target(self):
        d = self._decide()
        self.assertTrue(d.run)
        self.assertIn("auto-enabled", d.reason)

    def test_every_earned_language_auto_enables_uncovered(self):
        from core.orchestration.joern_scan import (
            _AUTO_ENABLE_LANGUAGES,
            _CODEQL_LANGUAGE_FOR,
        )
        for lang in sorted(_AUTO_ENABLE_LANGUAGES):
            with self.subTest(language=lang):
                self.assertIn(lang, _CODEQL_LANGUAGE_FOR)
                d = self._decide(language=lang)
                self.assertTrue(d.run)
                self.assertIn(lang, d.reason)

    def test_covering_codeql_analysis_suppresses_each_language(self):
        """Kotlin is covered by CodeQL's java analysis, TypeScript by
        javascript — the mapping, not the raw name, decides."""
        from core.orchestration.joern_scan import (
            _AUTO_ENABLE_LANGUAGES,
            _CODEQL_LANGUAGE_FOR,
        )
        for lang in sorted(_AUTO_ENABLE_LANGUAGES):
            with self.subTest(language=lang):
                covered = frozenset({_CODEQL_LANGUAGE_FOR[lang]})
                d = self._decide(language=lang,
                                 codeql_covered_languages=covered)
                self.assertFalse(d.run)
                self.assertIn("CodeQL", d.reason)

    def test_kotlin_suppressed_by_java_coverage_not_kotlin_key(self):
        d = self._decide(language="kotlin",
                         codeql_covered_languages=frozenset({"java"}))
        self.assertFalse(d.run)
        d = self._decide(language="kotlin",
                         codeql_covered_languages=frozenset({"kotlin"}))
        self.assertTrue(d.run)

    def test_unrelated_codeql_coverage_does_not_suppress(self):
        d = self._decide(language="c",
                         codeql_covered_languages=frozenset(
                             {"python", "javascript"}))
        self.assertTrue(d.run)

    def test_unearned_language_skips_auto(self):
        d = self._decide(language="ruby")
        self.assertFalse(d.run)
        self.assertIn("auto-enable not earned for ruby", d.reason)

    def test_empty_language_skips_auto(self):
        d = self._decide(language="")
        self.assertFalse(d.run)
        self.assertIn("unknown", d.reason)

    def test_openant_only_beats_explicit_request(self):
        d = self._decide(openant_only=True, requested=True)
        self.assertFalse(d.run)
        self.assertTrue(d.requested)
        self.assertIn("--openant-only", d.reason)

    def test_live_availability_probe_is_consulted(self):
        from unittest.mock import patch
        import packages.joern.prereqs as prereqs
        with patch.object(prereqs, "is_available", return_value=False):
            d = self._decide(joern_available=None)
        self.assertFalse(d.run)
        self.assertIn("not installed", d.reason)

    def test_live_sources_probe_is_consulted(self):
        from unittest.mock import patch
        import core.audit.joern_backend as backend
        with patch.object(backend, "target_has_c_sources",
                          return_value=False) as c_probe, \
             patch.object(backend, "target_has_joern_sources",
                          return_value=False) as joern_probe:
            d = self._decide(has_joern_sources=None)
        self.assertFalse(d.run)
        self.assertIn("no sources with a curated Joern profile",
                      d.reason)
        c_probe.assert_called_once()
        joern_probe.assert_called_once()

    def test_live_language_probe_is_consulted(self):
        """The dominant-language census routes auto-enable; the
        detect_language python fallback on an unprofiled tree is
        unreachable because the sources gate runs first."""
        from unittest.mock import patch
        import packages.joern.lang_config as lang_config
        with patch.object(lang_config, "detect_language",
                          return_value="go") as probe:
            d = self._decide(language=None)
        self.assertTrue(d.run)
        self.assertIn("go target", d.reason)
        probe.assert_called_once()


class TestTaintCategorisation(unittest.TestCase):
    def test_known_sinks_map_to_cwe_rules(self):
        cases = {
            "system": ("joern-taint-command-injection", "CWE-78"),
            "memcpy": ("joern-taint-buffer-write", "CWE-120"),
            "printf": ("joern-taint-format-string", "CWE-134"),
            "fopen": ("joern-taint-path-injection", "CWE-73"),
        }
        for sink, (rule_id, cwe) in cases.items():
            got_rule, _, got_cwe = _taint_rule_for(sink)
            self.assertEqual(got_rule, rule_id)
            self.assertEqual(got_cwe, cwe)

    def test_unknown_sink_falls_back_without_cwe(self):
        rule_id, _, cwe = _taint_rule_for("frobnicate")
        self.assertEqual(rule_id, "joern-taint-dangerous-sink")
        self.assertIsNone(cwe)

    def test_sink_name_from_flow_field_when_present(self):
        flow = _flow([_step("a.c", 5, "x")], sink_call="system")
        self.assertEqual(
            _resolve_sink_name(flow, Path("/nonexistent"), "a.c", 5),
            "system")

    def test_sink_name_recovered_from_step_code(self):
        # reachableByFlows paths end at the sink ARGUMENT node, so
        # sink_call is empty; the call text rides an earlier step.
        flow = _flow([
            _step("a.c", 3, "buf"),
            _step("a.c", 9, "memcpy(dst, buf, n)"),
            _step("a.c", 9, "n"),
        ])
        self.assertEqual(
            _resolve_sink_name(flow, Path("/nonexistent"), "a.c", 9),
            "memcpy")

    def test_sink_name_recovered_from_target_line(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "a.c").write_text(
                "int f(char *s) {\n  system(s);\n  return 0;\n}\n")
            flow = _flow([_step("a.c", 1, "s"), _step("a.c", 2, "s")])
            self.assertEqual(
                _resolve_sink_name(flow, target, "a.c", 2), "system")

    def test_unresolvable_sink_name_is_empty(self):
        flow = _flow([_step("a.c", 2, "s")])
        self.assertEqual(
            _resolve_sink_name(flow, Path("/nonexistent"), "a.c", 2), "")

    def test_sink_name_cache_is_used(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "a.c").write_text("system(s);\n")
            cache: dict = {}
            flow = _flow([_step("a.c", 1, "s")])
            first = _resolve_sink_name(flow, target, "a.c", 1,
                                       cache=cache)
            # A poisoned cache entry proves the second call short-circuits.
            cache[("a.c", 1)] = "memcpy"
            second = _resolve_sink_name(flow, target, "a.c", 1,
                                        cache=cache)
        self.assertEqual(first, "system")
        self.assertEqual(second, "memcpy")


class TestReadTargetLine(unittest.TestCase):
    """Hostile-repo hardening of the sink-line fallback read."""

    def test_reads_the_requested_line(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "a.c").write_text("one\ntwo\nsystem(x);\n")
            self.assertEqual(_read_target_line(target, "a.c", 3),
                             "system(x);")

    def test_symlink_escaping_target_is_refused(self):
        with TemporaryDirectory() as tmp, TemporaryDirectory() as out:
            target = Path(tmp)
            secret = Path(out) / "secret.c"
            secret.write_text("system(stolen);\n")
            (target / "link.c").symlink_to(secret)
            # Lexically "link.c" is contained; resolution escapes.
            self.assertEqual(_read_target_line(target, "link.c", 1), "")

    def test_in_target_symlink_resolves_to_contained_file(self):
        # confine() resolves symlinks before the containment check: a
        # link whose real file stays inside the target is contained
        # content and reads fine (the escaping link is refused above).
        # O_NOFOLLOW still guards the already-resolved final component
        # against a post-check swap.
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "real.c").write_text("system(x);\n")
            (target / "link.c").symlink_to(target / "real.c")
            self.assertEqual(
                _read_target_line(target, "link.c", 1), "system(x);")

    def test_fifo_is_refused_without_blocking(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            os.mkfifo(target / "pipe.c")
            self.assertEqual(_read_target_line(target, "pipe.c", 1), "")

    def test_nul_bearing_uri_is_refused(self):
        with TemporaryDirectory() as tmp:
            self.assertEqual(
                _read_target_line(Path(tmp), "a\x00b.c", 1), "")

    def test_huge_single_line_is_bounded(self):
        from core.orchestration import joern_scan
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "a.c").write_text("x" * (2 * joern_scan._SINK_READ_CHUNK)
                                        + "\nsystem(s);\n")
            text = _read_target_line(target, "a.c", 1)
            self.assertEqual(len(text), joern_scan._SINK_LINE_CAP)
            # The sink on line 2 is still reachable past the long line.
            self.assertEqual(_read_target_line(target, "a.c", 2),
                             "system(s);")

    def test_line_beyond_read_cap_gives_empty(self):
        from unittest.mock import patch
        from core.orchestration import joern_scan
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "a.c").write_text("pad\n" * 64 + "system(s);\n")
            with patch.object(joern_scan, "_SINK_READ_CAP_BYTES", 16):
                self.assertEqual(_read_target_line(target, "a.c", 65), "")


class TestTaintResults(unittest.TestCase):
    def _convert(self, flows, target):
        rules = emit.RuleIndex()
        errors: list[str] = []
        results = _taint_results(flows, target, rules, errors)
        return results, rules, errors

    def test_flow_becomes_result_with_codeflow(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "a.c").write_text("x\n" * 20)
            flow = _flow([
                _step("a.c", 3, "char *buf"),
                _step("a.c", 9, "strcpy(dst, buf)"),
            ])
            results, rules, errors = self._convert([flow], target)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res["ruleId"], "joern-taint-buffer-write")
        loc = res["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "a.c")
        self.assertEqual(loc["region"]["startLine"], 9)
        flow_locs = res["codeFlows"][0]["threadFlows"][0]["locations"]
        self.assertEqual(len(flow_locs), 2)
        labels = [loc_entry["location"]["message"]["text"]
                  for loc_entry in flow_locs]
        self.assertEqual(labels, ["source", "sink"])
        rule = next(r for r in rules.rules()
                    if r["id"] == "joern-taint-buffer-write")
        self.assertEqual(rule["properties"]["cwe"], "CWE-120")

    def test_out_of_root_sink_is_dropped(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            flow = _flow([
                _step("a.c", 3, "buf"),
                _step("/usr/include/string.h", 40, "strcpy(d, s)"),
            ])
            results, _, _ = self._convert([flow], target)
        self.assertEqual(results, [])

    def test_escaping_relative_sink_is_dropped(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            flow = _flow([_step("../outside.c", 3, "strcpy(d, s)")])
            results, _, _ = self._convert([flow], target)
        self.assertEqual(results, [])

    def test_zero_line_sink_is_dropped(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            flow = _flow([_step("a.c", 0, "strcpy(d, s)")])
            results, _, _ = self._convert([flow], target)
        self.assertEqual(results, [])

    def test_duplicate_flows_dedup_to_one_result(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            steps = [_step("a.c", 3, "buf"),
                     _step("a.c", 9, "strcpy(dst, buf)")]
            results, _, _ = self._convert(
                [_flow(list(steps)), _flow(list(steps))], target)
        self.assertEqual(len(results), 1)

    def test_single_resolvable_step_gets_no_codeflow(self):
        # SARIF threadFlows need >= 2 locations to be meaningful; a
        # flow whose only in-root step is the sink keeps the result
        # but drops the codeFlow.
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            flow = _flow([
                _step("/usr/include/x.h", 5, "buf"),
                _step("a.c", 9, "strcpy(dst, buf)"),
            ])
            results, _, _ = self._convert([flow], target)
        self.assertEqual(len(results), 1)
        self.assertNotIn("codeFlows", results[0])

    def test_result_cap_appends_error(self):
        from core.orchestration import joern_scan
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            flows = [
                _flow([_step("a.c", i + 1, "strcpy(dst, buf)")],
                      source_method=f"f{i}")
                for i in range(joern_scan._MAX_TAINT_RESULTS + 5)
            ]
            rules = emit.RuleIndex()
            errors: list[str] = []
            results = _taint_results(flows, target, rules, errors)
        self.assertEqual(len(results), joern_scan._MAX_TAINT_RESULTS)
        self.assertTrue(any("capped" in e for e in errors))


class TestStructuralResults(unittest.TestCase):
    def _convert(self, raw, target):
        rules = emit.RuleIndex()
        errors: list[str] = []
        failed: list[str] = []
        results = _structural_results(raw, target, rules, errors, failed)
        return results, rules, errors, failed

    @staticmethod
    def _done(queries: int = _STRUCTURAL_QUERY_COUNT,
              failed: int = 0) -> str:
        return (f'JOERN_SCAN_DONE:{{"queries":{queries},'
                f'"failed":{failed}}}')

    def test_hit_record_becomes_result(self):
        raw = ('JOERN_SCANHIT:{"query":"file-operation-race",'
               '"file":"a.c","line":12,"function":"toctou",'
               '"code":"open(path, 0)"}\n' + self._done())
        with TemporaryDirectory() as tmp:
            results, rules, errors, failed = self._convert(raw, Path(tmp))
        self.assertEqual(errors, [])
        self.assertEqual(failed, [])
        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res["ruleId"], "joern-file-operation-race")
        self.assertIn("toctou", res["message"]["text"])
        rule = next(r for r in rules.rules()
                    if r["id"] == "joern-file-operation-race")
        self.assertEqual(rule["properties"]["cwe"], "CWE-367")

    def test_missing_done_sentinel_is_degraded_not_clean(self):
        raw = ('JOERN_SCANHIT:{"query":"strlen-truncation",'
               '"file":"a.c","line":3,"function":"f","code":"int n"}')
        with TemporaryDirectory() as tmp:
            _, _, errors, _ = self._convert(raw, Path(tmp))
        self.assertTrue(any("did not complete" in e for e in errors))

    def test_query_count_drift_is_an_error(self):
        with TemporaryDirectory() as tmp:
            _, _, errors, _ = self._convert(
                self._done(queries=_STRUCTURAL_QUERY_COUNT - 1),
                Path(tmp))
        self.assertTrue(any("drift" in e for e in errors))

    def test_scanerr_record_marks_query_failed(self):
        raw = ('JOERN_SCANERR:{"query":"free-returned-value",'
               '"error":"boom"}\n' + self._done(failed=1))
        with TemporaryDirectory() as tmp:
            _, _, errors, failed = self._convert(raw, Path(tmp))
        self.assertEqual(failed, ["free-returned-value"])
        self.assertTrue(any("boom" in e for e in errors))

    def test_unknown_query_name_is_drift_error_not_result(self):
        raw = ('JOERN_SCANHIT:{"query":"made-up-query","file":"a.c",'
               '"line":3,"function":"f","code":"x"}\n' + self._done())
        with TemporaryDirectory() as tmp:
            results, _, errors, _ = self._convert(raw, Path(tmp))
        self.assertEqual(results, [])
        self.assertTrue(any("unknown structural query" in e
                            for e in errors))

    def test_out_of_root_hit_is_dropped(self):
        raw = ('JOERN_SCANHIT:{"query":"strlen-truncation",'
               '"file":"../../etc/passwd","line":3,"function":"f",'
               '"code":"x"}\n' + self._done())
        with TemporaryDirectory() as tmp:
            results, _, _, _ = self._convert(raw, Path(tmp))
        self.assertEqual(results, [])

    def test_hostile_line_value_is_dropped(self):
        raw = ('JOERN_SCANHIT:{"query":"strlen-truncation",'
               '"file":"a.c","line":"NaN","function":"f","code":"x"}\n'
               + self._done())
        with TemporaryDirectory() as tmp:
            results, _, _, _ = self._convert(raw, Path(tmp))
        self.assertEqual(results, [])

    def test_overflowing_line_value_is_dropped_not_fatal(self):
        # JSON 1e400 parses to float('inf'); int() then raises
        # OverflowError, which must not kill the whole phase.
        raw = ('JOERN_SCANHIT:{"query":"strlen-truncation",'
               '"file":"a.c","line":1e400,"function":"f","code":"x"}\n'
               + self._done())
        with TemporaryDirectory() as tmp:
            results, _, _, _ = self._convert(raw, Path(tmp))
        self.assertEqual(results, [])

    def test_duplicate_hits_dedup(self):
        hit = ('JOERN_SCANHIT:{"query":"strlen-truncation",'
               '"file":"a.c","line":3,"function":"f","code":"x"}')
        raw = f"{hit}\n{hit}\n" + self._done()
        with TemporaryDirectory() as tmp:
            results, _, _, _ = self._convert(raw, Path(tmp))
        self.assertEqual(len(results), 1)

    def test_rule_table_covers_script_query_names(self):
        # Every query the shipped script emits must be in the table —
        # a rename on either side otherwise silently drops hits (the
        # unknown-name path flags it at runtime; this catches it in CI).
        script = (Path(__file__).resolve().parents[3]
                  / "packages" / "joern" / "queries" / "structural_c.sc")
        text = script.read_text(encoding="utf-8")
        for query in STRUCTURAL_RULES:
            self.assertIn(f'runStructural("{query}")', text)
        self.assertEqual(
            text.count('runStructural("'), _STRUCTURAL_QUERY_COUNT)
        # Reverse direction: with every table key present in the
        # script and both cardinalities pinned, table keys and script
        # queries are exactly the same set — a script query added
        # without rule metadata can no longer slip through as a
        # runtime unknown-name warning.
        self.assertEqual(len(STRUCTURAL_RULES), _STRUCTURAL_QUERY_COUNT)
        # The completion sentinel's hardcoded count must track too —
        # otherwise a consistently-added query passes CI and then
        # emits a drift error on every run.
        self.assertIn(f'"queries":{_STRUCTURAL_QUERY_COUNT},', text)


def _stub_result(raw_output: str = "", flows: list | None = None,
                 errors: list | None = None):
    from types import SimpleNamespace
    return SimpleNamespace(raw_output=raw_output, flows=flows or [],
                           errors=errors or [])


class TestPhaseWithStubServer(unittest.TestCase):
    """Phase behaviour against a stubbed resident server."""

    def _run_phase(self, tmp: str, *, language: str,
                   structural_raw: str):
        from contextlib import contextmanager
        from unittest.mock import MagicMock, patch

        import packages.joern as joern_pkg
        import packages.joern.lang_config as lang_config
        from core.orchestration.joern_scan import run_joern_scan_phase

        srv = MagicMock()
        srv.run_tiered_sweep.return_value = _stub_result()
        srv.query_script.return_value = _stub_result(structural_raw)

        @contextmanager
        def _session(*args, **kwargs):
            yield srv

        target = Path(tmp) / "repo"
        target.mkdir()
        (target / "a.cc").write_text("int main() { return 0; }\n")
        out_dir = Path(tmp) / "out" / "run"
        out_dir.mkdir(parents=True)
        with patch.object(joern_pkg, "joern_session", _session), \
                patch.object(lang_config, "detect_language",
                             return_value=language):
            outcome = run_joern_scan_phase(target, out_dir)
        return outcome, srv

    def test_learned_flow_semantics_installed_before_sweep(self):
        # The scan phase must apply the same IRIS-learned sanitiser
        # kill rows the audit backend installs, BEFORE the sweep runs
        # (rows bind at query build time), and surface the row count.
        from unittest.mock import MagicMock, patch

        import core.audit.joern_backend as backend

        sweep_calls_at_install_time: list[int] = []

        def _install(srv_arg, *args, **kwargs):
            sweep_calls_at_install_time.append(
                srv_arg.run_tiered_sweep.call_count)
            return 3

        install = MagicMock(side_effect=_install)
        with TemporaryDirectory() as tmp:
            with patch.object(backend, "install_flow_semantics",
                              install):
                outcome, srv = self._run_phase(
                    tmp, language="java", structural_raw="")
        install.assert_called_once()
        self.assertIs(install.call_args.args[0], srv)
        self.assertEqual(sweep_calls_at_install_time, [0])
        self.assertEqual(outcome.semantics_rows, 3)
        self.assertEqual(outcome.metrics()["semantics_rows"], 3)

    def test_semantics_install_failure_never_costs_the_sweep(self):
        from unittest.mock import patch

        import core.audit.joern_backend as backend

        with TemporaryDirectory() as tmp:
            with patch.object(backend, "install_flow_semantics",
                              side_effect=RuntimeError("store broken")):
                outcome, srv = self._run_phase(
                    tmp, language="java", structural_raw="")
        srv.run_tiered_sweep.assert_called_once()
        self.assertEqual(outcome.semantics_rows, 0)

    def test_cpp_target_runs_structural_queries(self):
        done = (f'JOERN_SCAN_DONE:{{"queries":'
                f'{_STRUCTURAL_QUERY_COUNT},"failed":0}}')
        with TemporaryDirectory() as tmp:
            outcome, srv = self._run_phase(
                tmp, language="cpp", structural_raw=done)
        srv.query_script.assert_called_once()
        self.assertFalse(outcome.degraded)
        self.assertEqual(outcome.errors, [])

    def test_non_native_language_skips_structural_queries(self):
        with TemporaryDirectory() as tmp:
            outcome, srv = self._run_phase(
                tmp, language="java", structural_raw="")
        srv.query_script.assert_not_called()
        self.assertFalse(outcome.degraded)

    def test_missing_sentinel_marks_outcome_degraded(self):
        # The vacuity guard's error must surface in metrics as a
        # degraded run, not just as warning text.
        with TemporaryDirectory() as tmp:
            outcome, _ = self._run_phase(
                tmp, language="c", structural_raw="")
        self.assertTrue(outcome.degraded)
        self.assertTrue(outcome.metrics()["degraded"])
        self.assertTrue(any("did not complete" in e
                            for e in outcome.errors))


class TestPhaseDegraded(unittest.TestCase):
    def test_no_session_degrades_without_raising(self):
        import packages.joern as joern_pkg
        from unittest.mock import patch
        from contextlib import contextmanager

        from core.orchestration.joern_scan import run_joern_scan_phase

        @contextmanager
        def _no_session(*args, **kwargs):
            yield None

        with TemporaryDirectory() as tmp:
            target = Path(tmp) / "repo"
            target.mkdir()
            (target / "a.c").write_text("int main(void){return 0;}\n")
            out_dir = Path(tmp) / "out" / "run"
            out_dir.mkdir(parents=True)
            with patch.object(joern_pkg, "joern_session", _no_session):
                outcome = run_joern_scan_phase(target, out_dir)
        self.assertTrue(outcome.degraded)
        self.assertIsNone(outcome.sarif_path)
        self.assertEqual(outcome.finding_count, 0)
        self.assertTrue(any("session unavailable" in e
                            for e in outcome.errors))
        metrics = outcome.metrics()
        self.assertTrue(metrics["degraded"])
        self.assertIsNone(metrics["sarif"])


if __name__ == "__main__":
    unittest.main()
