"""Degradation contracts when tree-sitter is absent (bare CI shape).

The grammar wheels are optional dependencies. The behaviour-level
tests for the consistency dimensions and the Go/Java fail-open legs
skip on grammar-less hosts (`requires_ts`) because those capabilities
have no honest fallback — but the DEGRADATION itself is a contract,
and this file pins it hermetically so it stays tested on every host:

* every consistency dimension detector returns an empty result — no
  findings invented from line shapes, no exception;
* the prepass still completes and emits its artifact/telemetry shell;
* the Go/Java analyzers return ``None`` (their documented "parser
  unavailable" signal) and every verify-channel caller converts that
  into the enumerated ``language-unsupported`` inconclusive — never a
  TypeError on the None.

Absence is simulated through the same seams a grammar-less import
computes: the module-level ``_TS_AVAILABLE`` flags and
``fail_open_lang._ts_parser`` returning ``None``.
"""

from __future__ import annotations

import textwrap

import pytest

from core.testing import force_census_regex_fallback

_C_FIXTURE = {
    "src/writers.c": textwrap.dedent("""\
        int writer_a(const char *p) {
            int fd = open(p, O_WRONLY|O_CREAT|O_NOFOLLOW, 0600);
            return fd;
        }

        int writer_dev(const char *p) {
            int fd = open(p, O_WRONLY|O_CREAT, 0600);
            return fd;
        }
    """),
}


@pytest.fixture
def _no_tree_sitter(monkeypatch):
    """Flip every availability seam a grammar-less host would see."""
    import core.audit.consistency_dimensions as dims
    import core.audit.fail_open_lang as lang

    force_census_regex_fallback(monkeypatch)
    monkeypatch.setattr(dims, "_TS_AVAILABLE", False)
    monkeypatch.setattr(lang, "_ts_parser", lambda language: None)


class TestDimensionDetectorsDegradeEmpty:
    def test_flag_mode_empty(self, _no_tree_sitter):
        from core.audit.consistency_dimensions import (
            detect_flag_mode_deviations,
        )
        assert detect_flag_mode_deviations(_C_FIXTURE) == []

    def test_argument_shape_empty(self, _no_tree_sitter):
        from core.audit.consistency_dimensions import (
            detect_argument_shape_deviations,
        )
        assert detect_argument_shape_deviations(_C_FIXTURE) == []

    def test_cleanup_empty(self, _no_tree_sitter):
        from core.audit.consistency_dimensions import (
            detect_cleanup_deviations,
        )
        assert detect_cleanup_deviations(_C_FIXTURE, []) == []

    def test_interface_empty(self, _no_tree_sitter):
        from core.audit.consistency_dimensions import (
            detect_interface_deviations,
        )
        assert detect_interface_deviations(_C_FIXTURE, None) == []

    def test_ordering_empty(self, _no_tree_sitter):
        from core.audit.consistency_dimensions import (
            detect_ordering_deviations,
        )
        assert detect_ordering_deviations(_C_FIXTURE) == []

    def test_sanitize_sink_empty(self, _no_tree_sitter):
        from core.audit.consistency_dimensions import (
            detect_sanitize_sink_deviations,
        )
        assert detect_sanitize_sink_deviations(
            _C_FIXTURE,
            {"write_out": {"category": "html"}},
            frozenset({"escape_html"}),
        ) == []

    def test_guard_presence_empty(self, _no_tree_sitter):
        from core.audit.consistency_dimensions import (
            detect_guard_presence_deviations,
        )
        assert detect_guard_presence_deviations(_C_FIXTURE) == []

    def test_clone_drift_empty(self, _no_tree_sitter):
        from core.audit.clone_drift import detect_clone_drift
        assert detect_clone_drift(_C_FIXTURE) == []


class TestPrepassDegradesGracefully:
    def test_prepass_completes_with_telemetry(
        self, _no_tree_sitter, tmp_path,
    ):
        from core.audit.consistency_prepass import run_consistency_prepass
        res = run_consistency_prepass(_C_FIXTURE, out_dir=tmp_path)
        # Shape contract only: the prepass must complete and hand back
        # its telemetry shell; parser-backed dimensions simply find
        # nothing on a grammar-less host.
        assert isinstance(res, dict)
        assert "telemetry" in res


class TestFailOpenAnalyzersReturnNone:
    _GO = "package main\n\nfunc run() {\n    doWork()\n}\n"
    _JAVA = (
        "class A {\n"
        "    void f() {\n"
        "        try { g(); } catch (Exception e) { }\n"
        "    }\n"
        "}\n"
    )

    def test_java_handlers_none(self, _no_tree_sitter):
        from core.audit.fail_open_lang import java_handlers
        assert java_handlers(self._JAVA, "A.java") is None

    def test_go_recover_handlers_none(self, _no_tree_sitter):
        from core.audit.fail_open_lang import go_recover_handlers
        assert go_recover_handlers(self._GO, "m.go") is None

    def test_go_discard_sites_none(self, _no_tree_sitter):
        from core.audit.fail_open_lang import go_discard_sites
        assert go_discard_sites(self._GO, "m.go", "doWork") is None

    def test_go_function_span_none(self, _no_tree_sitter):
        from core.audit.fail_open_lang import go_function_span
        assert go_function_span(self._GO, "run") is None


class TestFailOpenVerdictIsLanguageUnsupported:
    """The verify channel converts analyzer-None into the enumerated
    inconclusive — the TypeError-on-None class of failure must never
    reach the caller."""

    def _check(self, tmp_path, rel, source, function, hypothesis):
        from core.audit.fail_open_verify import run_fail_open_check
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(source)
        return run_fail_open_check(tmp_path, rel, function, hypothesis)

    def test_java_inconclusive(self, _no_tree_sitter, tmp_path):
        from core.audit.fail_open_verify import (
            REASON_LANGUAGE_UNSUPPORTED,
        )
        res = self._check(
            tmp_path, "A.java",
            "class A {\n"
            "    boolean check() {\n"
            "        try { return verify(); }\n"
            "        catch (Exception e) { return true; }\n"
            "    }\n"
            "}\n",
            "check",
            "the broad catch in check() returns true — fail open",
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_LANGUAGE_UNSUPPORTED)

    def test_go_recover_inconclusive(self, _no_tree_sitter, tmp_path):
        from core.audit.fail_open_verify import (
            REASON_LANGUAGE_UNSUPPORTED,
        )
        res = self._check(
            tmp_path, "m.go",
            "package main\n\n"
            "func serve() {\n"
            "    defer func() {\n"
            "        if r := recover(); r != nil {\n"
            "            log.Print(r)\n"
            "        }\n"
            "    }()\n"
            "    handle()\n"
            "}\n",
            "serve",
            "the deferred recover() swallows the panic and continues",
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_LANGUAGE_UNSUPPORTED)
