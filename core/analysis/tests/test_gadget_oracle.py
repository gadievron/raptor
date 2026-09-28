"""PHP gadget-chain oracle: flow pins, census honesty, availability
bases, channel verdict discipline, and the untrusted-artifact query.

Fixtures are synthetic PHP trees written to tmp_path. Parse-dependent
classes are grammar-guarded (tree-sitter-php); the capability-absent
contract tests are hermetic (they stub the parser cache) and run
everywhere — grammar absence must be a recorded gap, never a silent
pass.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

import core.analysis.gadget_oracle as go
from core.analysis.gadget_oracle import (
    ABSENCE_EARNS_SUPPRESSION,
    ABSENCE_RECORD_VERDICT,
    CENSUS_UNKNOWN_QUALIFIER,
    REASON_GRAMMAR_UNAVAILABLE,
    REASON_LANGUAGE_UNSUPPORTED,
    REASON_NO_GADGETS_COMPLETE,
    REASON_NO_GADGETS_DEGRADED,
    REASON_NO_SURFACE_COMPLETE,
    REASON_TARGET_UNUSABLE,
    RULE_ABSENCE,
    RULE_CHAIN,
    RULE_CHAIN_CONDITIONAL,
    RULE_NO_SURFACE,
    TIER_NO_CHAINS_FOUND,
    TIER_NO_GADGET_SURFACE,
    TIER_NONE,
    absence_earns_suppression,
    absence_tier,
    census_qualifier,
    gadget_facts_for_file,
    gadget_language_permitted,
    gadget_oracle_applicable,
    is_detection_rule_id,
    is_gadget_hypothesis,
    load_gadget_report,
    php_grammar_available,
    report_matches_target,
    run_gadget_oracle_check,
    save_gadget_report,
    scan_tree,
)

_GRAMMAR = pytest.mark.skipif(
    not php_grammar_available(),
    reason="tree-sitter-php not installed",
)


@pytest.fixture(autouse=True)
def _fresh_memo():
    go.reset_scan_memo()
    yield
    go.reset_scan_memo()


@pytest.fixture
def _no_grammar(monkeypatch):
    """Hermetic capability-absent seam: the probed parser is None."""
    monkeypatch.setattr(go, "_PARSER_CACHE", [None])


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "target"
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    root.mkdir(exist_ok=True)
    return root


_DESTRUCT_UNLINK = """<?php
class TempLogger {
    public $path;
    function __destruct() {
        unlink($this->path);
    }
}
"""

# Mutant: the sink argument is a constant — no property flow.
_DESTRUCT_CONSTANT = """<?php
class TempLogger {
    public $path;
    function __destruct() {
        unlink("/tmp/fixed-name");
    }
}
"""

# Mutant: same flow, but in a regular method — no magic trigger.
_REGULAR_METHOD = """<?php
class TempLogger {
    public $path;
    function cleanup() {
        unlink($this->path);
    }
}
"""

_TOSTRING_SQL_ONEHOP = """<?php
class Renderer {
    public $tpl;
    public function __toString() {
        return $this->render($this->tpl);
    }
    private function render($t) {
        $sql = "SELECT body FROM tpl WHERE name = '" . $t . "'";
        return $this->db->query($sql);
    }
}
"""

# Mutant: the helper is called with a constant — the param-rooted
# sink must not bind.
_TOSTRING_SQL_CONSTANT_ARG = """<?php
class Renderer {
    public $tpl;
    public function __toString() {
        return $this->render("fixed");
    }
    private function render($t) {
        $sql = "SELECT body FROM tpl WHERE name = '" . $t . "'";
        return $this->db->query($sql);
    }
}
"""

# Two hops (magic -> h1 -> h2 -> sink): beyond the documented depth.
_TWO_HOP = """<?php
class Deep {
    public $x;
    function __destruct() {
        $this->h1($this->x);
    }
    private function h1($a) {
        $this->h2($a);
    }
    private function h2($b) {
        unlink($b);
    }
}
"""

_NO_GADGET = """<?php
class Safe {
    public $label;
    function __wakeup() {
        $x = "constant";
        unlink("/tmp/fixed-name");
    }
    function __toString() {
        return "safe";
    }
}
$obj = unserialize($_COOKIE['session']);
"""

_PARSE_BROKEN = """<?php
class Broken {
    function __destruct( {
        unlink($this->x
"""


@_GRAMMAR
class TestChainPins:
    def test_destruct_unlink_chain_found(self, tmp_path):
        root = _tree(tmp_path, {"logger.php": _DESTRUCT_UNLINK})
        report = scan_tree(root)
        chains = report["chains"]
        assert len(chains) == 1
        c = chains[0]
        assert c["class"] == "TempLogger"
        assert c["magic_method"] == "__destruct"
        assert c["trigger"] == "unserialize"
        assert c["property_path"] == "path"
        assert c["sink"]["category"] == "file"
        assert c["sink"]["callee"] == "unlink"
        assert c["steps"] == []
        assert "trigger_requires" not in c

    def test_mutant_constant_arg_no_chain(self, tmp_path):
        root = _tree(tmp_path, {"logger.php": _DESTRUCT_CONSTANT})
        assert scan_tree(root)["chains"] == []

    def test_mutant_regular_method_no_chain(self, tmp_path):
        root = _tree(tmp_path, {"logger.php": _REGULAR_METHOD})
        assert scan_tree(root)["chains"] == []

    def test_tostring_sql_one_hop(self, tmp_path):
        root = _tree(tmp_path, {"r.php": _TOSTRING_SQL_ONEHOP})
        chains = scan_tree(root)["chains"]
        assert len(chains) == 1
        c = chains[0]
        assert c["magic_method"] == "__toString"
        assert c["trigger"] == "conditional"
        assert "string-conversion" in c["trigger_requires"]
        assert c["steps"] and c["steps"][0]["method"] == "render"
        assert c["sink"]["category"] == "sql"

    def test_mutant_constant_call_arg_no_chain(self, tmp_path):
        root = _tree(tmp_path, {"r.php": _TOSTRING_SQL_CONSTANT_ARG})
        assert scan_tree(root)["chains"] == []

    def test_depth_limit_two_hops_not_found(self, tmp_path):
        """The documented depth is one same-class hop — a two-hop
        chain must NOT be found (the report says so via
        analysis_depth), while its one-hop control IS found."""
        root = _tree(tmp_path, {"deep.php": _TWO_HOP})
        report = scan_tree(root)
        assert report["chains"] == []
        assert ("one same-class"
                in report["analysis_depth"]["property_flow"])
        control = _TWO_HOP.replace("$this->h2($a);", "unlink($a);")
        root2 = _tree(tmp_path / "c", {"deep.php": control})
        assert len(scan_tree(root2)["chains"]) == 1

    def test_callable_include_echo_exec_sinks(self, tmp_path):
        src = """<?php
class Multi {
    public $cb; public $inc; public $msg; public $code;
    function __wakeup() {
        call_user_func($this->cb, "x");
        include($this->inc);
        eval($this->code);
    }
    function __toString() {
        echo $this->msg;
        return "";
    }
}
"""
        root = _tree(tmp_path, {"m.php": src})
        chains = scan_tree(root)["chains"]
        cats = {(c["sink"]["category"], c["sink"]["callee"])
                for c in chains}
        assert ("exec", "call_user_func") in cats
        assert ("include", "include") in cats
        assert ("exec", "eval") in cats
        assert ("echo", "echo") in cats

    def test_mutant_constant_callable_no_chain(self, tmp_path):
        src = """<?php
class Multi {
    function __wakeup() {
        call_user_func("fixed_fn", $this->arg);
    }
}
"""
        root = _tree(tmp_path, {"m.php": src})
        assert scan_tree(root)["chains"] == []


@_GRAMMAR
class TestUnserializeSites:
    def test_request_derived_site(self, tmp_path):
        root = _tree(tmp_path, {
            "h.php": "<?php $o = unserialize($_COOKIE['s']);\n"})
        sites = scan_tree(root)["unserialize_sites"]
        assert len(sites) == 1
        assert sites[0]["file"] == "h.php"
        assert sites[0]["request_derived"] is True

    def test_local_var_site_not_request_derived(self, tmp_path):
        root = _tree(tmp_path, {
            "h.php": "<?php $o = unserialize($blob);\n"})
        sites = scan_tree(root)["unserialize_sites"]
        assert len(sites) == 1
        assert sites[0]["request_derived"] is False


@_GRAMMAR
class TestAbsenceAndCensus:
    def test_no_gadget_tree_complete_census(self, tmp_path):
        root = _tree(tmp_path, {"safe.php": _NO_GADGET})
        report = scan_tree(root)
        assert report["chains"] == []
        assert report["census"]["complete"] is True
        assert report["census"]["parsed_clean"] == 1
        assert "COMPLETE" in census_qualifier(report)

    def test_mutant_added_gadget_flips_absence(self, tmp_path):
        root = _tree(tmp_path, {
            "safe.php": _NO_GADGET,
            "lib/logger.php": _DESTRUCT_UNLINK,
        })
        report = scan_tree(root)
        assert len(report["chains"]) == 1
        assert report["census"]["complete"] is True

    def test_parse_broken_degrades_census(self, tmp_path):
        root = _tree(tmp_path, {
            "safe.php": _NO_GADGET,
            "broken.php": _PARSE_BROKEN,
        })
        report = scan_tree(root)
        census = report["census"]
        assert census["complete"] is False
        assert "parse-errors" in census["incomplete_reasons"]
        assert ("broken.php"
                in report["census_detail"]["parse_error_files"])
        assert "INCOMPLETE" in census_qualifier(report)

    def test_mutant_fixed_file_restores_completeness(self, tmp_path):
        fixed = "<?php\nclass Broken {\n  function x() {}\n}\n"
        root = _tree(tmp_path, {
            "safe.php": _NO_GADGET, "broken.php": fixed})
        assert scan_tree(root)["census"]["complete"] is True

    def test_php_like_unscanned_breaks_completeness(self, tmp_path):
        root = _tree(tmp_path, {
            "safe.php": _NO_GADGET,
            "module.inc": _DESTRUCT_UNLINK,
        })
        report = scan_tree(root)
        census = report["census"]
        assert census["complete"] is False
        assert "php-like-unscanned" in census["incomplete_reasons"]
        assert ("module.inc"
                in report["census_detail"]["php_like_unscanned_files"])
        # The hidden gadget was NOT found — exactly why completeness
        # must break.
        assert report["chains"] == []

    def test_mutant_renamed_inc_is_scanned(self, tmp_path):
        root = _tree(tmp_path, {
            "safe.php": _NO_GADGET,
            "module.php": _DESTRUCT_UNLINK,
        })
        report = scan_tree(root)
        assert report["census"]["complete"] is True
        assert len(report["chains"]) == 1

    def test_non_php_files_do_not_break_census(self, tmp_path):
        root = _tree(tmp_path, {
            "safe.php": _NO_GADGET,
            "README.md": "# docs\n",
            "style.css": "body {}\n",
        })
        assert scan_tree(root)["census"]["complete"] is True


@_GRAMMAR
class TestAvailability:
    def test_not_established_without_any_basis(self, tmp_path):
        root = _tree(tmp_path, {
            "lib/logger.php": _DESTRUCT_UNLINK,
            "h.php": "<?php $o = unserialize($_GET['s']);\n",
        })
        chain = scan_tree(root)["chains"][0]
        assert chain["availability"] == "not_established"

    def test_same_file_basis_wins(self, tmp_path):
        root = _tree(tmp_path, {
            "app.php": (_DESTRUCT_UNLINK
                        + "$o = unserialize($_GET['s']);\n"),
        })
        chain = scan_tree(root)["chains"][0]
        assert chain["availability"] == "same_file"

    def test_autoload_registration_basis(self, tmp_path):
        root = _tree(tmp_path, {
            "lib/logger.php": _DESTRUCT_UNLINK,
            "boot.php": "<?php spl_autoload_register('my_loader');\n",
        })
        report = scan_tree(root)
        assert report["autoload"]["registered"] is True
        assert (report["chains"][0]["availability"]
                == "autoload_registered")

    def test_include_graph_basis(self, tmp_path):
        root = _tree(tmp_path, {"lib/logger.php": _DESTRUCT_UNLINK})
        ig = {"files": {"lib/logger.php": {"includer_count": 2}}}
        chain = scan_tree(root, include_graph=ig)["chains"][0]
        assert chain["availability"] == "included_somewhere"

    def test_include_graph_without_entry_stays_unestablished(
            self, tmp_path):
        root = _tree(tmp_path, {"lib/logger.php": _DESTRUCT_UNLINK})
        ig = {"files": {"other.php": {"includer_count": 3}}}
        chain = scan_tree(root, include_graph=ig)["chains"][0]
        assert chain["availability"] == "not_established"


class TestCapabilityAbsent:
    """Hermetic: grammar absence is a recorded gap, never a silent
    pass — these run on hosts without tree-sitter-php too."""

    def test_scan_records_capability_gap(self, tmp_path, _no_grammar):
        root = _tree(tmp_path, {"a.php": _DESTRUCT_UNLINK})
        report = scan_tree(root)
        assert report["capability"]["tree_sitter_php"] is False
        assert report["census"]["complete"] is False
        assert (REASON_GRAMMAR_UNAVAILABLE
                in report["census"]["incomplete_reasons"])
        assert report["chains"] == []

    def test_channel_skips_with_reason(self, tmp_path, _no_grammar):
        root = _tree(tmp_path, {"a.php": _DESTRUCT_UNLINK})
        ev = run_gadget_oracle_check(root, "a.php", "f", "gadget chain")
        assert ev.outcome == "skipped"
        assert ev.reason == REASON_GRAMMAR_UNAVAILABLE

    def test_qualifier_never_reads_complete(self, tmp_path, _no_grammar):
        root = _tree(tmp_path, {"a.php": _DESTRUCT_UNLINK})
        q = census_qualifier(scan_tree(root))
        assert "COMPLETE" not in q or "INCOMPLETE" in q

    def test_reset_parser_cache_forgets_probe(self, _no_grammar):
        # Cached absence is authoritative until reset...
        assert php_grammar_available() is False
        # ...and the reset seam returns the cache to unprobed, so the
        # next call re-probes the host for real.
        go.reset_parser_cache()
        assert go._PARSER_CACHE == []


class TestChannelGates:
    def test_non_php_file_skipped(self, tmp_path):
        ev = run_gadget_oracle_check(
            tmp_path, "src/a.c", "f", "gadget chain")
        assert ev.outcome == "skipped"
        assert ev.reason == REASON_LANGUAGE_UNSUPPORTED

    @_GRAMMAR
    def test_unusable_target_skipped(self, tmp_path):
        ev = run_gadget_oracle_check(
            tmp_path / "missing", "a.php", "f", "gadget chain")
        assert ev.outcome == "skipped"
        assert ev.reason == REASON_TARGET_UNUSABLE

    def test_language_gate_two_directions(self):
        assert gadget_language_permitted("web/a.php")
        assert not gadget_language_permitted("src/a.c")
        assert not gadget_language_permitted("")  # fail closed
        # Content-probed unmapped extension (inventory hint).
        assert gadget_language_permitted("plugins/mod", language="php")
        assert not gadget_language_permitted("plugins/mod", language="c")


@_GRAMMAR
class TestChannelVerdicts:
    def test_chain_confirms_with_detection_stamp(self, tmp_path):
        root = _tree(tmp_path, {"logger.php": _DESTRUCT_UNLINK})
        ev = run_gadget_oracle_check(
            root, "logger.php", "f", "object injection gadget")
        assert ev.outcome == "confirmed"
        assert ev.rule_id == RULE_CHAIN
        assert is_detection_rule_id(ev.rule_id)
        assert ev.chains and ev.chains[0]["class"] == "TempLogger"
        assert "TempLogger" in ev.reason
        assert "verify" in ev.reason.lower()

    def test_conditional_only_chain_uses_conditional_stamp(
            self, tmp_path):
        root = _tree(tmp_path, {"r.php": _TOSTRING_SQL_ONEHOP})
        ev = run_gadget_oracle_check(
            root, "r.php", "f", "gadget chain")
        assert ev.outcome == "confirmed"
        assert ev.rule_id == RULE_CHAIN_CONDITIONAL

    def test_surfaced_absence_stays_inconclusive(self, tmp_path):
        # POP surface exists (a __destruct) — the depth-limited
        # absence claim never refutes, byte-identical to the
        # pre-promotion verdict.
        root = _tree(tmp_path, {"safe.php": _NO_GADGET})
        ev = run_gadget_oracle_check(
            root, "safe.php", "f", "no gadgets in tree")
        assert ev.outcome == "inconclusive"
        assert ev.rule_id == RULE_ABSENCE
        assert ev.reason == REASON_NO_GADGETS_COMPLETE
        assert ev.census["complete"] is True
        assert ev.qualifier

    def test_zero_surface_complete_census_refutes(self, tmp_path):
        # The one earned refutation: complete census, zero POP
        # trigger surface anywhere in the tree.
        root = _tree(tmp_path, {"f.php": _PROCEDURAL_ONLY})
        ev = run_gadget_oracle_check(
            root, "f.php", "handle", "no gadgets in tree")
        assert ev.outcome == "refuted"
        assert ev.rule_id == RULE_NO_SURFACE
        assert ev.reason == REASON_NO_SURFACE_COMPLETE
        assert ev.absence_tier == TIER_NO_GADGET_SURFACE
        assert ev.census["complete"] is True

    def test_degraded_absence_reason(self, tmp_path):
        root = _tree(tmp_path, {
            "safe.php": _NO_GADGET, "broken.php": _PARSE_BROKEN})
        ev = run_gadget_oracle_check(
            root, "safe.php", "f", "no gadgets in tree")
        assert ev.outcome == "inconclusive"
        assert ev.reason == REASON_NO_GADGETS_DEGRADED

    def test_absence_writes_record_only_suppression_row(self, tmp_path):
        root = _tree(tmp_path, {"safe.php": _NO_GADGET})
        out = tmp_path / "out"
        out.mkdir()
        ev = run_gadget_oracle_check(
            root, "safe.php", "handler", "no gadgets in tree",
            output_dir=out,
        )
        assert ev.outcome == "inconclusive"
        rows = [
            json.loads(line) for line in
            (out / "suppressions.jsonl").read_text().splitlines()
        ]
        assert len(rows) == 1
        row = rows[0]
        assert row["verdict"] == ABSENCE_RECORD_VERDICT
        assert row["dropped"] is False   # record-only, nothing dropped
        assert row["earns_suppression"] is False
        assert row["file_path"] == "safe.php"
        assert row["census"]["complete"] is True

    def test_chain_outcome_writes_no_suppression_row(self, tmp_path):
        root = _tree(tmp_path, {"logger.php": _DESTRUCT_UNLINK})
        out = tmp_path / "out"
        out.mkdir()
        run_gadget_oracle_check(
            root, "logger.php", "f", "gadget", output_dir=out)
        assert not (out / "suppressions.jsonl").exists()

    def test_artifact_written_to_output_dir(self, tmp_path):
        root = _tree(tmp_path, {"logger.php": _DESTRUCT_UNLINK})
        out = tmp_path / "out"
        out.mkdir()
        run_gadget_oracle_check(
            root, "logger.php", "f", "gadget", output_dir=out)
        report = load_gadget_report(out)
        assert report is not None
        assert report_matches_target(report, root)
        assert len(report["chains"]) == 1

    def test_scan_memoized_per_target(self, tmp_path, monkeypatch):
        root = _tree(tmp_path, {"logger.php": _DESTRUCT_UNLINK})
        calls = []
        real = go.scan_tree

        def counting(target, **kw):
            calls.append(target)
            return real(target, **kw)

        monkeypatch.setattr(go, "scan_tree", counting)
        run_gadget_oracle_check(root, "logger.php", "f", "gadget")
        run_gadget_oracle_check(root, "logger.php", "g", "gadget")
        assert len(calls) == 1

    def test_absence_promotion_is_corpus_earned(self):
        # Flipped on the measured corpora (0 false absences for the
        # zero-surface tier); authority still flows only through
        # absence_earns_suppression, never this constant alone.
        assert ABSENCE_EARNS_SUPPRESSION is True


class TestDetectionGrade:
    def test_every_stamp_is_detection_grade(self):
        assert is_detection_rule_id(RULE_CHAIN)
        assert is_detection_rule_id(RULE_CHAIN_CONDITIONAL)
        assert is_detection_rule_id(RULE_ABSENCE)
        assert not is_detection_rule_id("semgrep:rule")

    def test_applicability_predicates(self):
        assert gadget_oracle_applicable("CWE-502")
        assert gadget_oracle_applicable("cwe-502")
        assert gadget_oracle_applicable("502")
        assert not gadget_oracle_applicable("CWE-89")
        assert not gadget_oracle_applicable("")

    def test_hypothesis_predicate_two_directions(self):
        assert is_gadget_hypothesis("no magic-method gadgets in tree")
        assert is_gadget_hypothesis("POP chain via __destruct")
        assert is_gadget_hypothesis("object injection at unserialize")
        assert not is_gadget_hypothesis("buffer overflow in memcpy")
        assert not is_gadget_hypothesis("")


class TestArtifactQuery:
    """The one re-validating read path over run-dir (untrusted) JSON."""

    def _report(self, **overrides):
        base = {
            "tier": "hint",
            "target_path": "/tmp/x",
            "census": {"complete": True, "php_files": 3,
                       "parsed_clean": 3, "incomplete_reasons": []},
            "chains": [{
                "class": "A", "file": "lib/a.php",
                "magic_method": "__destruct", "line": 4,
                "trigger": "unserialize", "steps": [],
                "property_path": "p",
                "sink": {"category": "file", "callee": "unlink",
                         "line": 5, "excerpt": "unlink($this->p)"},
                "availability": "same_file",
            }],
            "unserialize_sites": [
                {"file": "h.php", "line": 2, "request_derived": True,
                 "excerpt": "($_GET['x'])"},
            ],
        }
        base.update(overrides)
        return base

    def test_facts_always_carry_qualifier(self):
        facts = gadget_facts_for_file(self._report(), "h.php")
        assert facts is not None
        assert facts["qualifier"]
        assert facts["chains_total"] == 1
        assert facts["unserialize_sites_in_file"][0]["line"] == 2
        # Chains not in this file still render as tree-level context.
        assert facts["chains_elsewhere"][0]["class"] == "A"

    def test_file_scoped_chains(self):
        facts = gadget_facts_for_file(self._report(), "lib/a.php")
        assert facts["chains_in_file"][0]["sink_callee"] == "unlink"
        assert facts["chains_elsewhere"] == []

    def test_missing_census_refuses(self):
        report = self._report()
        del report["census"]
        assert gadget_facts_for_file(report, "h.php") is None

    def test_invalid_census_renders_unknown_qualifier(self):
        report = self._report(census={"complete": "yes"})
        assert census_qualifier(report) == CENSUS_UNKNOWN_QUALIFIER

    def test_tampered_fields_are_coerced_and_bounded(self):
        report = self._report(chains=[{
            "class": "X" * 10_000, "file": "lib/a.php",
            "magic_method": True, "line": "nope",
            "trigger": "weird", "steps": "not-a-list",
            "property_path": {"a": 1},
            "sink": {"category": 7, "callee": "e" * 9000,
                     "line": True, "excerpt": "\x1b]0;pwn\x07" * 500},
            "availability": None,
        }])
        facts = gadget_facts_for_file(report, "lib/a.php")
        c = facts["chains_in_file"][0]
        assert len(c["class"]) <= 256
        assert c["line"] == 0
        assert c["trigger"] == "conditional"
        assert c["steps"] == []
        assert len(c["sink_excerpt"]) <= 200
        assert c["sink_line"] == 0

    def test_non_dict_report_refuses(self):
        assert gadget_facts_for_file(["not", "a", "dict"], "x") is None

    def test_one_target_rule_fail_closed(self, tmp_path):
        report = self._report(target_path=str(tmp_path))
        assert report_matches_target(report, tmp_path)
        assert not report_matches_target(report, tmp_path / "other")
        assert not report_matches_target(report, None)
        assert not report_matches_target({"target_path": ""}, tmp_path)
        assert not report_matches_target({}, tmp_path)

    def test_save_load_roundtrip(self, tmp_path):
        report = self._report()
        save_gadget_report(tmp_path, report)
        loaded = load_gadget_report(tmp_path)
        assert loaded is not None
        assert loaded["chains"][0]["class"] == "A"

    def test_load_follows_checklist_symlink(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir()
        save_gadget_report(real, self._report())
        (real / "checklist.json").write_text("{}")
        rundir = tmp_path / "run"
        rundir.mkdir()
        (rundir / "checklist.json").symlink_to(real / "checklist.json")
        loaded = load_gadget_report(rundir)
        assert loaded is not None

    def test_load_missing_returns_none(self, tmp_path):
        assert load_gadget_report(tmp_path) is None


# PHP resolves function/method/class names case-insensitively and a
# leading backslash is an explicit global reference — byte-exact
# matching would let `__DESTRUCT()` / `SYSTEM()` / `\system()`
# gadgets evade the oracle entirely.
_UPPERCASE_GADGET = """<?php
class CaseGadget {
    public $cmd;
    function __DESTRUCT() {
        SYSTEM(SPRINTF("%s", $this->cmd));
    }
}
$x = UNSERIALIZE($_COOKIE['s']);
SPL_AUTOLOAD_REGISTER(function ($c) {});
"""

_QUALIFIED_GADGET = """<?php
class NsGadget {
    public $cmd;
    function __destruct() {
        \\system($this->cmd);
    }
}
"""

# Namespaced function: a DIFFERENT symbol, never the global sink.
_NAMESPACED_NOT_SINK = """<?php
class NsSafe {
    public $cmd;
    function __destruct() {
        App\\Util\\system($this->cmd);
    }
}
"""

_MIXED_CASE_HOP = """<?php
class Hop {
    public $tpl;
    public function __toString() {
        return $this->RENDER($this->tpl);
    }
    private function render($t) {
        return $this->db->QUERY("SELECT x WHERE n = '" . $t . "'");
    }
}
"""

_TRAIT_GADGET = """<?php
trait Evil {
    public function __destruct() {
        system($this->cmd);
    }
}
class TraitGadget {
    use EVIL;
    public $cmd;
}
"""

# The class's own magic method takes precedence over the trait's.
_TRAIT_PRECEDENCE = """<?php
trait Evil {
    public function __destruct() {
        system($this->cmd);
    }
}
class OwnWins {
    use Evil;
    public $cmd;
    public function __destruct() {
        $x = "quiet";
    }
}
"""

_TRAIT_CROSS_FILE = """<?php
class UsesElsewhere {
    use MissingTrait;
    public $cmd;
}
"""


@_GRAMMAR
class TestCaseAndNameResolution:
    def test_uppercase_magic_sink_propagator_found(self, tmp_path):
        root = _tree(tmp_path, {"g.php": _UPPERCASE_GADGET})
        report = scan_tree(root)
        chains = report["chains"]
        assert len(chains) == 1
        c = chains[0]
        assert c["magic_method"] == "__destruct"
        assert c["sink"]["category"] == "exec"
        assert c["sink"]["callee"] == "system"
        assert c["property_path"] == "cmd"
        # Uppercase unserialize()/spl_autoload_register() count too.
        assert report["unserialize_sites"][0]["request_derived"] is True
        assert report["autoload"]["registered"] is True
        assert report["magic_method_census"]["by_method"] == {
            "__destruct": 1}

    def test_leading_backslash_global_sink_found(self, tmp_path):
        root = _tree(tmp_path, {"g.php": _QUALIFIED_GADGET})
        chains = scan_tree(root)["chains"]
        assert len(chains) == 1
        assert chains[0]["sink"]["callee"] == "system"

    def test_namespaced_function_is_not_the_global_sink(self, tmp_path):
        root = _tree(tmp_path, {"g.php": _NAMESPACED_NOT_SINK})
        assert scan_tree(root)["chains"] == []

    def test_mixed_case_hop_and_sql_method(self, tmp_path):
        root = _tree(tmp_path, {"g.php": _MIXED_CASE_HOP})
        chains = scan_tree(root)["chains"]
        assert len(chains) == 1
        c = chains[0]
        assert c["magic_method"] == "__toString"
        assert c["sink"]["category"] == "sql"


@_GRAMMAR
class TestTraits:
    def test_same_file_trait_gadget_found(self, tmp_path):
        # `use EVIL;` — trait names resolve case-insensitively too.
        root = _tree(tmp_path, {"g.php": _TRAIT_GADGET})
        report = scan_tree(root)
        chains = report["chains"]
        assert len(chains) == 1
        assert chains[0]["class"] == "TraitGadget"
        assert chains[0]["magic_method"] == "__destruct"
        assert report["census"]["complete"] is True
        assert report["census"]["unresolved_trait_count"] == 0
        # Merged trait method joins the magic census.
        assert report["magic_method_census"]["by_method"] == {
            "__destruct": 1}

    def test_class_method_wins_over_trait(self, tmp_path):
        root = _tree(tmp_path, {"g.php": _TRAIT_PRECEDENCE})
        assert scan_tree(root)["chains"] == []

    def test_cross_file_trait_breaks_census(self, tmp_path):
        root = _tree(tmp_path, {"g.php": _TRAIT_CROSS_FILE})
        census = scan_tree(root)["census"]
        assert census["complete"] is False
        assert "unresolved-traits" in census["incomplete_reasons"]
        assert census["unresolved_trait_count"] == 1


# ── POP trigger-surface census + absence tiers ───────────────────────

_CONSTRUCT_ONLY = """<?php
class Plain {
    public $x;
    public function __construct($x) {
        $this->x = $x;
    }
    public function run() {
        return strlen($this->x);
    }
}
"""

_INVOKE_ONLY = """<?php
class Callback {
    public $fn;
    public function __invoke($arg) {
        return $arg;
    }
}
"""

_SERIALIZABLE_IMPL = """<?php
class Legacy implements Serializable {
    public $cmd;
    public function serialize() { return ""; }
    public function unserialize($data) {
        system($this->cmd);
    }
}
"""

_ANON_DESTRUCT = """<?php
$handler = new class {
    public $path;
    public function __destruct() {
        unlink($this->path);
    }
};
"""

_EVAL_SITE = """<?php
function boot($blob) {
    eval($blob);
}
"""

_PROCEDURAL_ONLY = """<?php
function handle($input) {
    return htmlspecialchars($input);
}
handle($_GET['x']);
"""

_INTERFACE_ONLY = """<?php
interface Storage {
    public function fetch($key);
    public function store($key, $value);
}
"""


@_GRAMMAR
class TestPopSurfaceCensus:
    def test_gadget_tree_counts_surface(self, tmp_path):
        root = _tree(tmp_path, {"logger.php": _DESTRUCT_UNLINK})
        surface = scan_tree(root)["pop_surface"]
        assert surface["by_method"] == {"__destruct": 1}
        assert surface["total_methods"] == 1
        assert surface["serializable_impls"] == 0
        assert surface["dynamic_definition_sites"] == 0
        assert surface["anonymous_class_methods"] == 0

    def test_construct_is_not_pop_surface(self, tmp_path):
        # Pins that the census is the POP set, not a naive
        # ``__``-prefix match: constructors never run on unserialize.
        root = _tree(tmp_path, {"plain.php": _CONSTRUCT_ONLY})
        report = scan_tree(root)
        assert report["pop_surface"]["total_methods"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_case_variant_magic_counts_casefolded(self, tmp_path):
        root = _tree(tmp_path, {"g.php": _UPPERCASE_GADGET})
        surface = scan_tree(root)["pop_surface"]
        assert surface["by_method"] == {"__destruct": 1}

    def test_trait_declared_surface_counts(self, tmp_path):
        root = _tree(tmp_path, {"g.php": _TRAIT_GADGET})
        surface = scan_tree(root)["pop_surface"]
        assert surface["by_method"] == {"__destruct": 1}

    def test_cross_file_trait_user_still_censuses_trait_side(
            self, tmp_path):
        # The trait body is elsewhere — census incomplete, tier none —
        # but the surface counters themselves stay honest (zero here).
        root = _tree(tmp_path, {"g.php": _TRAIT_CROSS_FILE})
        report = scan_tree(root)
        assert report["pop_surface"]["total_methods"] == 0
        assert report["absence_tier"] == TIER_NONE

    def test_anonymous_class_destruct_counts(self, tmp_path):
        root = _tree(tmp_path, {"h.php": _ANON_DESTRUCT})
        report = scan_tree(root)
        surface = report["pop_surface"]
        assert surface["by_method"] == {"__destruct": 1}
        assert surface["anonymous_class_methods"] == 1
        # The chain search does not model anonymous classes — the
        # surface census is exactly what stops a false zero-surface
        # claim here.
        assert report["chains"] == []
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_serializable_impl_counts_and_blocks(self, tmp_path):
        root = _tree(tmp_path, {"l.php": _SERIALIZABLE_IMPL})
        report = scan_tree(root)
        assert report["pop_surface"]["serializable_impls"] == 1
        # ``unserialize($data)`` + Serializable is real POP surface the
        # magic-method search never models: the tier MUST NOT read
        # no_gadget_surface.
        assert report["chains"] == []
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_serializable_qualified_variants_count(self, tmp_path):
        for i, clause in enumerate(
                ("\\Serializable", "App\\Serializable")):
            src = (f"<?php\nclass V{i} implements {clause} {{\n"
                   f"    public function serialize() {{ return ''; }}\n"
                   f"    public function unserialize($d) {{}}\n}}\n")
            root = _tree(tmp_path / str(i), {"v.php": src})
            report = scan_tree(root)
            assert report["pop_surface"]["serializable_impls"] == 1, clause
            assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_unrelated_interface_not_counted(self, tmp_path):
        src = ("<?php\nclass W implements Countable {\n"
               "    public function count() { return 0; }\n}\n")
        root = _tree(tmp_path, {"w.php": src})
        report = scan_tree(root)
        assert report["pop_surface"]["serializable_impls"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_eval_site_counts_and_blocks(self, tmp_path):
        root = _tree(tmp_path, {"boot.php": _EVAL_SITE})
        report = scan_tree(root)
        assert report["pop_surface"]["dynamic_definition_sites"] == 1
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_string_assert_counts_boolean_assert_does_not(
            self, tmp_path):
        root = _tree(tmp_path, {
            "s.php": "<?php assert('class Z {} true');\n"})
        assert (scan_tree(root)["pop_surface"]
                ["dynamic_definition_sites"] == 1)
        root2 = _tree(tmp_path / "b", {
            "b.php": "<?php assert($cond);\n"})
        report2 = scan_tree(root2)
        assert (report2["pop_surface"]["dynamic_definition_sites"]
                == 0)
        assert report2["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_invoke_only_surface_blocks_tier(self, tmp_path):
        # __invoke is surface the chain search does not model: chains
        # stay empty, but the promotable tier must NOT fire.
        root = _tree(tmp_path, {"c.php": _INVOKE_ONLY})
        report = scan_tree(root)
        assert report["chains"] == []
        assert report["pop_surface"]["by_method"] == {"__invoke": 1}
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND


@_GRAMMAR
class TestDeclaredSerializablePairCensus:
    """A declared ``serialize()``/``unserialize()`` pair is trigger
    surface even when THIS file's implements clause never spells
    ``Serializable``: ``unserialize()`` of a ``C:``-format payload
    calls ``->unserialize($payload)`` on any class that is
    ``instanceof Serializable`` at runtime, and the binding can ride
    an import alias, an in-tree interface that extends Serializable,
    or an interface shipped outside the tree entirely. Counting the
    declared pair is the fail-closed direction; resolving interface
    chains to prove a class is NOT Serializable would be the
    fail-open one. Each evasion shape below was execution-verified:
    the payload runs the pair on the PHP engine while the implements
    clause census alone sees nothing.
    """

    def test_import_alias_implements_blocks_tier(self, tmp_path):
        src = ("<?php\n"
               "use Serializable as Srl;\n"
               "class Cache implements Srl {\n"
               "    public function serialize() { return ''; }\n"
               "    public function unserialize($d) { system($d); }\n"
               "}\n")
        report = scan_tree(_tree(tmp_path, {"g.php": src}))
        by_method = report["pop_surface"]["by_method"]
        assert by_method.get("serialize") == 1
        assert by_method.get("unserialize") == 1
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_in_tree_interface_indirection_blocks_tier(self, tmp_path):
        src = ("<?php\n"
               "interface Store extends Serializable {}\n"
               "class Cache implements Store {\n"
               "    public function serialize() { return ''; }\n"
               "    public function unserialize($d) { system($d); }\n"
               "}\n")
        report = scan_tree(_tree(tmp_path, {"g.php": src}))
        by_method = report["pop_surface"]["by_method"]
        assert by_method.get("serialize") == 1
        assert by_method.get("unserialize") == 1
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_out_of_tree_interface_blocks_tier(self, tmp_path):
        # The interface lives outside the scanned tree — an autoloader
        # pulls it in at runtime. Nothing in-tree spells Serializable;
        # only the declared pair census can see this shape.
        src = ("<?php\n"
               "class Cache implements \\Vendor\\Store {\n"
               "    public function serialize() { return ''; }\n"
               "    public function unserialize($d) { system($d); }\n"
               "}\n")
        report = scan_tree(_tree(tmp_path, {"g.php": src}))
        by_method = report["pop_surface"]["by_method"]
        assert by_method.get("serialize") == 1
        assert by_method.get("unserialize") == 1
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_direct_implements_control_still_counted(self, tmp_path):
        # Control: the direct spelling keeps its implements-clause
        # census alongside the declared-pair counts.
        src = ("<?php\n"
               "class Cache implements \\Serializable {\n"
               "    public function serialize() { return ''; }\n"
               "    public function unserialize($d) { system($d); }\n"
               "}\n")
        report = scan_tree(_tree(tmp_path, {"g.php": src}))
        surface = report["pop_surface"]
        assert surface["serializable_impls"] == 1
        assert surface["by_method"].get("unserialize") == 1
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_unrelated_method_names_keep_promotable_tier(
            self, tmp_path):
        # Two-direction guard: methods named neither serialize nor
        # unserialize (including the near-name deserialize) must not
        # be newly counted as surface.
        src = ("<?php\n"
               "class Codec {\n"
               "    public function encode($d) { return json_encode($d); }\n"
               "    public function deserialize($d) { return json_decode($d); }\n"
               "}\n")
        report = scan_tree(_tree(tmp_path, {"c.php": src}))
        assert report["pop_surface"]["total_methods"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE


@_GRAMMAR
class TestAbsenceTierOnScans:
    def test_true_negative_procedural_tree_fires(self, tmp_path):
        root = _tree(tmp_path, {"f.php": _PROCEDURAL_ONLY})
        assert scan_tree(root)["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_true_negative_interface_only_fires(self, tmp_path):
        root = _tree(tmp_path, {"i.php": _INTERFACE_ONLY})
        assert scan_tree(root)["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_zero_php_tree_no_tier(self, tmp_path):
        # No PHP anywhere: the census is "complete" over nothing, so
        # the absence claim is vacuous — a mis-pointed target path
        # must never clamp findings filed under other paths.
        root = _tree(tmp_path, {"README.md": "docs only\n"})
        report = scan_tree(root)
        assert report["census"]["php_files"] == 0
        assert report["census"]["complete"] is True
        assert report["absence_tier"] == TIER_NONE
        assert absence_earns_suppression(report) is False

    def test_empty_tree_no_tier(self, tmp_path):
        root = _tree(tmp_path, {})
        assert scan_tree(root)["absence_tier"] == TIER_NONE

    def test_chains_present_tier_none(self, tmp_path):
        root = _tree(tmp_path, {"logger.php": _DESTRUCT_UNLINK})
        assert scan_tree(root)["absence_tier"] == TIER_NONE

    def test_surface_no_chains_tier_documents_boundary(self, tmp_path):
        root = _tree(tmp_path, {"safe.php": _NO_GADGET})
        report = scan_tree(root)
        assert report["chains"] == []
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_degraded_census_tier_none(self, tmp_path):
        root = _tree(tmp_path, {
            "f.php": _PROCEDURAL_ONLY, "hidden.inc": _DESTRUCT_UNLINK})
        report = scan_tree(root)
        assert report["census"]["complete"] is False
        assert report["absence_tier"] == TIER_NONE

    def test_unusable_target_tier_none(self, tmp_path):
        assert (scan_tree(tmp_path / "missing")["absence_tier"]
                == TIER_NONE)

    def test_qualifier_surfaces_the_tier(self, tmp_path):
        root = _tree(tmp_path, {"f.php": _PROCEDURAL_ONLY})
        q = census_qualifier(scan_tree(root))
        assert "no_gadget_surface" in q
        root2 = _tree(tmp_path / "s", {"safe.php": _NO_GADGET})
        q2 = census_qualifier(scan_tree(root2))
        assert "no_chains_found" in q2
        assert "never suppression-grade" in q2


_SPL_CLOSURE_AUTOLOAD = """<?php
spl_autoload_register(function ($class) {
    require __DIR__ . '/lib/' . $class . '.php';
});
$obj = unserialize($_GET['payload']);
"""

_LEGACY_AUTOLOAD = """<?php
function __autoload($class) {
    include __DIR__ . '/classes/' . $class . '.php';
}
$obj = unserialize($_COOKIE['session']);
"""


@_GRAMMAR
class TestAutoloadCensusBlocksTier:
    """Autoload-family registration is reachable attack surface for a
    deserialization finding: unserialize() resolves the attacker-chosen
    class name through the registered loader BEFORE any object method
    is consulted.  Registration in the tree must therefore demote the
    promotable tier to the boundary tier — for every mechanism PHP
    offers (spl_autoload_register, legacy ``function __autoload``, and
    the ``unserialize_callback_func`` INI hook)."""

    def test_spl_register_blocks_promotable_tier(self, tmp_path):
        root = _tree(tmp_path, {"entry.php": _SPL_CLOSURE_AUTOLOAD})
        report = scan_tree(root)
        assert report["census"]["complete"] is True
        assert report["chains"] == []
        assert report["autoload"]["registered"] is True
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "spl_autoload_register")
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND
        assert absence_earns_suppression(report) is False

    def test_legacy_autoload_function_blocks(self, tmp_path):
        root = _tree(tmp_path, {"entry.php": _LEGACY_AUTOLOAD})
        report = scan_tree(root)
        assert report["autoload"]["registered"] is True
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "__autoload")
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_unserialize_callback_ini_set_blocks(self, tmp_path):
        root = _tree(tmp_path, {"entry.php": (
            "<?php\n"
            "ini_set('unserialize_callback_func', 'my_loader');\n"
            "$obj = unserialize($_GET['x']);\n"
        )})
        report = scan_tree(root)
        assert report["autoload"]["registered"] is True
        site = report["autoload"]["sites"][0]
        assert site["mechanism"] == "unserialize_callback_func"
        assert site["line"] == 2
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_ini_alter_alias_blocks(self, tmp_path):
        root = _tree(tmp_path, {"entry.php": (
            "<?php\n"
            'ini_alter("unserialize_callback_func", "loader");\n'
        )})
        report = scan_tree(root)
        assert report["autoload"]["registered"] is True
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "unserialize_callback_func")
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_case_variant_callee_blocks(self, tmp_path):
        # PHP function names are case-insensitive: INI_SET() is the
        # same builtin.
        root = _tree(tmp_path, {"entry.php": (
            "<?php\n"
            "INI_SET('unserialize_callback_func', 'loader');\n"
        )})
        report = scan_tree(root)
        assert report["autoload"]["registered"] is True
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_dynamic_ini_key_fails_closed(self, tmp_path):
        # The census cannot see through a computed key — a dynamic
        # first argument is treated as a registration (over-count is
        # a demotion, never a false absence).
        root = _tree(tmp_path, {"entry.php": (
            "<?php\n"
            "$key = 'unserialize_callback' . '_func';\n"
            "ini_set($key, 'loader');\n"
        )})
        report = scan_tree(root)
        assert report["autoload"]["registered"] is True
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "ini-dynamic-key")
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_other_literal_ini_key_still_earns(self, tmp_path):
        # Literal-key discrimination: a benign setting is not an
        # autoload registration.
        root = _tree(tmp_path, {"entry.php": (
            "<?php\n"
            "ini_set('memory_limit', '256M');\n"
            "echo strlen($_GET['x']);\n"
        )})
        report = scan_tree(root)
        assert report["autoload"]["registered"] is False
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_zero_argument_ini_set_still_earns(self, tmp_path):
        # ini_set() with no arguments is an ArgumentCountError at
        # runtime — nothing is registered.
        root = _tree(tmp_path, {"entry.php": (
            "<?php\nini_set();\n"
        )})
        report = scan_tree(root)
        assert report["autoload"]["registered"] is False
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_qualifier_names_the_autoload_demotion(self, tmp_path):
        root = _tree(tmp_path, {"entry.php": _SPL_CLOSURE_AUTOLOAD})
        q = census_qualifier(scan_tree(root))
        assert "no_chains_found" in q


@_GRAMMAR
class TestDynamicCalleeFailsClosed:
    """A call whose callee is not a statically named function can
    invoke ANY function at runtime — ``spl_autoload_register``
    included — so the census records it as a fail-closed registration
    fact (mechanism ``dynamic-callee``), mirroring the
    dynamic-ini-key precedent.  Demotion-only: the fact can only
    withhold the promotable tier, never mint a chain or a verdict."""

    def _report(self, tmp_path: Path, code: str) -> dict:
        return scan_tree(_tree(tmp_path, {"entry.php": code}))

    def _assert_fails_closed(self, report: dict) -> None:
        assert report["census"]["complete"] is True
        assert report["autoload"]["registered"] is True
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "dynamic-callee")
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND
        assert absence_earns_suppression(report) is False

    def test_variable_function_fails_closed(self, tmp_path):
        self._assert_fails_closed(self._report(tmp_path, (
            "<?php\n"
            "$f = 'spl_autoload_register';\n"
            "$f(function ($c) { require __DIR__.'/'.$c.'.php'; });\n"
            "unserialize($_GET['x']);\n"
        )))

    def test_concat_built_name_fails_closed(self, tmp_path):
        # The callee-shape fact must catch this launder on its own
        # (pinned first in the sites list); the concat-fold mention
        # backstop ALSO sees the fully-literal assembly now, but the
        # dynamic-callee fact may never depend on it.
        self._assert_fails_closed(self._report(tmp_path, (
            "<?php\n"
            "$f = 'spl_autoload_' . 'register';\n"
            "$f(function ($c) { require __DIR__.'/'.$c.'.php'; });\n"
        )))

    def test_parenthesized_literal_callee_fails_closed(self, tmp_path):
        self._assert_fails_closed(self._report(tmp_path, (
            "<?php\n"
            "('spl_autoload_register')(function ($c) { require $c; });\n"
        )))

    def test_string_literal_callee_fails_closed(self, tmp_path):
        self._assert_fails_closed(self._report(tmp_path, (
            "<?php\n"
            "'spl_autoload_register'(function ($c) { require $c; });\n"
        )))

    def test_variable_ini_set_fails_closed(self, tmp_path):
        self._assert_fails_closed(self._report(tmp_path, (
            "<?php\n"
            "$g = 'ini_set';\n"
            "$g('unserialize_callback_func', 'loader_fn');\n"
        )))

    def test_benign_dynamic_call_still_demotes(self, tmp_path):
        # Chosen over-block: the census cannot know what $f holds, so
        # ANY dynamic callee withholds the promotable tier. The cost
        # is measured on the corpus, not assumed away.
        self._assert_fails_closed(self._report(tmp_path, (
            "<?php\n$f = 'strlen';\necho $f('x');\n"
        )))

    def test_namespaced_static_call_records_nothing(self, tmp_path):
        # ``App\helper()`` names one function statically — a
        # DIFFERENT symbol from the global family, so precision is
        # preserved for qualified static calls.
        report = self._report(tmp_path, (
            "<?php\nApp\\Boot\\helper('x');\n\\App\\Boot\\helper('y');\n"
        ))
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_relative_name_in_global_namespace_is_the_global(
            self, tmp_path):
        # ``namespace\spl_autoload_register(...)`` outside any
        # namespace IS the global function, spelled explicitly.
        report = self._report(tmp_path, (
            "<?php\n"
            "namespace\\spl_autoload_register(function ($c) {});\n"
        ))
        assert report["autoload"]["registered"] is True
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "spl_autoload_register")

    def test_relative_name_inside_namespace_records_nothing(
            self, tmp_path):
        # Inside ``namespace App`` the same spelling means
        # ``App\spl_autoload_register`` — a different symbol.
        report = self._report(tmp_path, (
            "<?php\nnamespace App;\n"
            "namespace\\spl_autoload_register(function ($c) {});\n"
        ))
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE


@_GRAMMAR
class TestCallableStringDispatch:
    """``call_user_func``/``call_user_func_array`` with a LITERAL
    string target are censused as the named call itself (callable
    strings always resolve fully-qualified, never through imports or
    the file's namespace); a non-literal target is a fail-closed
    dynamic callee."""

    def _report(self, tmp_path: Path, code: str) -> dict:
        return scan_tree(_tree(tmp_path, {"entry.php": code}))

    def test_cuf_literal_spl_registers(self, tmp_path):
        report = self._report(tmp_path, (
            "<?php\n"
            "call_user_func('spl_autoload_register',"
            " function ($c) {});\n"
        ))
        assert report["autoload"]["registered"] is True
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "spl_autoload_register")
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_cufa_literal_spl_registers(self, tmp_path):
        report = self._report(tmp_path, (
            "<?php\n"
            "call_user_func_array('spl_autoload_register',"
            " [function ($c) {}]);\n"
        ))
        assert report["autoload"]["registered"] is True
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "spl_autoload_register")

    def test_cuf_leading_backslash_target_registers(self, tmp_path):
        report = self._report(tmp_path, (
            "<?php\n"
            "call_user_func('\\\\spl_autoload_register',"
            " function ($c) {});\n"
        ))
        assert report["autoload"]["registered"] is True

    def test_cuf_case_variant_target_registers(self, tmp_path):
        # Callable strings resolve case-insensitively like any PHP
        # function name.
        report = self._report(tmp_path, (
            "<?php\n"
            "CALL_USER_FUNC('SPL_Autoload_Register',"
            " function ($c) {});\n"
        ))
        assert report["autoload"]["registered"] is True

    def test_cuf_escape_decoded_target_registers(self, tmp_path):
        # Double-quoted "\x72" is a real 'r' after PHP escape
        # decoding — the literal census must see the decoded name.
        report = self._report(tmp_path, (
            "<?php\n"
            "call_user_func(\"spl_autoload_\\x72egister\","
            " function ($c) {});\n"
        ))
        assert report["autoload"]["registered"] is True
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "spl_autoload_register")

    def test_cuf_ini_set_literal_key_registers(self, tmp_path):
        report = self._report(tmp_path, (
            "<?php\n"
            "call_user_func('ini_set',"
            " 'unserialize_callback_func', 'loader');\n"
        ))
        assert report["autoload"]["registered"] is True
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "unserialize_callback_func")

    def test_cuf_ini_set_dynamic_key_fails_closed(self, tmp_path):
        report = self._report(tmp_path, (
            "<?php\ncall_user_func('ini_set', $key, 'loader');\n"
        ))
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "ini-dynamic-key")

    def test_cufa_ini_set_fails_closed(self, tmp_path):
        # The key rides in a runtime array — unknowable, so the
        # dynamic-key rule applies.
        report = self._report(tmp_path, (
            "<?php\ncall_user_func_array('ini_set', $args);\n"
        ))
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "ini-dynamic-key")

    def test_cuf_dynamic_target_fails_closed(self, tmp_path):
        report = self._report(tmp_path, (
            "<?php\ncall_user_func($cb, 1);\n"
        ))
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "dynamic-callee")
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_cufa_dynamic_target_fails_closed(self, tmp_path):
        report = self._report(tmp_path, (
            "<?php\ncall_user_func_array($cb, [1]);\n"
        ))
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "dynamic-callee")

    def test_cuf_array_callable_fails_closed(self, tmp_path):
        report = self._report(tmp_path, (
            "<?php\ncall_user_func([$obj, 'method']);\n"
        ))
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "dynamic-callee")

    def test_nested_cuf_dispatch_resolves(self, tmp_path):
        report = self._report(tmp_path, (
            "<?php\n"
            "call_user_func('call_user_func',"
            " 'spl_autoload_register', function ($c) {});\n"
        ))
        assert report["autoload"]["registered"] is True
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "spl_autoload_register")

    def test_cuf_dispatch_depth_bounded(self, tmp_path):
        # A machine-built dispatch chain fails closed at the bound
        # instead of choosing the census's recursion depth.
        chain = ", ".join(["'call_user_func'"] * 20)
        report = self._report(tmp_path, (
            f"<?php\ncall_user_func({chain}, 'strlen', 'x');\n"
        ))
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "dynamic-callee")

    def test_cuf_zero_arguments_records_nothing(self, tmp_path):
        # ArgumentCountError at runtime — nothing is called.
        report = self._report(tmp_path, (
            "<?php\ncall_user_func();\n"
        ))
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_cuf_benign_literal_target_still_earns(self, tmp_path):
        # Precision pin: a literal target names exactly ONE function;
        # a benign, un-forwardable one must not cost the promotable
        # tier. Deliberately pinned on names that cannot invoke a
        # further callable — what a FORWARDER target would forward is
        # the family-literal-mention backstop's concern (see
        # TestFamilyLiteralMentionBackstop).
        report = self._report(tmp_path, (
            "<?php\n"
            "call_user_func('strlen', $x);\n"
            "call_user_func_array('strtoupper', [$s]);\n"
        ))
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_cuf_namespaced_target_records_nothing(self, tmp_path):
        # 'App\loader' / 'Cls::method' are DIFFERENT symbols; their
        # bodies, when in tree, are censused where they are declared.
        report = self._report(tmp_path, (
            "<?php\n"
            "call_user_func('App\\\\loader', 'x');\n"
            "call_user_func('Cls::method');\n"
        ))
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_cuf_unserialize_records_site(self, tmp_path):
        report = self._report(tmp_path, (
            "<?php\ncall_user_func('unserialize', $_GET['x']);\n"
        ))
        assert len(report["unserialize_sites"]) == 1
        assert report["unserialize_sites"][0]["request_derived"] is True

    def test_cuf_string_assert_counts(self, tmp_path):
        report = self._report(tmp_path, (
            "<?php\ncall_user_func('assert', 'do_thing()');\n"
        ))
        assert report["pop_surface"]["dynamic_definition_sites"] == 1

    def test_cuf_variable_assert_not_counted(self, tmp_path):
        # Mirrors the direct rule: only the string FORM is
        # eval-equivalent evidence.
        report = self._report(tmp_path, (
            "<?php\ncall_user_func('assert', $x);\n"
        ))
        assert report["pop_surface"]["dynamic_definition_sites"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_cufa_assert_not_counted(self, tmp_path):
        # Opaque arguments mirror the direct dynamic-argument rule.
        report = self._report(tmp_path, (
            "<?php\ncall_user_func_array('assert', $args);\n"
        ))
        assert report["pop_surface"]["dynamic_definition_sites"] == 0

    def test_cuf_preg_replace_literal_e_counts(self, tmp_path):
        report = self._report(tmp_path, (
            "<?php\n"
            "call_user_func('preg_replace', '/x/e', 'run()', $s);\n"
        ))
        assert report["pop_surface"]["dynamic_definition_sites"] == 1

    def test_cuf_create_function_counts(self, tmp_path):
        report = self._report(tmp_path, (
            "<?php\n"
            "call_user_func('create_function', '', 'return 1;');\n"
        ))
        assert report["pop_surface"]["dynamic_definition_sites"] == 1


@_GRAMMAR
class TestFamilyLiteralMentionBackstop:
    """A census family name spelled as an intact string literal
    ANYWHERE in the tree — or as a fully-literal concat chain that
    folds to the name — blocks the promotable tier (mechanism
    ``family-literal-mention``): PHP's callable-forwarding builtins
    (``array_map``, ``register_shutdown_function``, ...) and user
    forwarders can invoke any string that reaches them, a stored
    literal reaches them from any position (an argument, a variable,
    a default parameter value, a return, an initializer), and
    enumerating forwarders or carrying positions is an allowlist
    that rots. Fail-closed by design — the documented trade is that
    benign family-name string DATA also costs the tier."""

    def _report(self, tmp_path: Path, code: str) -> dict:
        return scan_tree(_tree(tmp_path, {"entry.php": code}))

    def _assert_blocked(self, report: dict) -> None:
        assert report["autoload"]["registered"] is True
        assert ("family-literal-mention"
                in [s["mechanism"]
                    for s in report["autoload"]["sites"]])
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_arraymap_family_argument_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\narray_map('spl_autoload_register', [$cb]);\n"
        )))

    def test_arraywalk_family_argument_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\narray_walk($cbs, 'spl_autoload_register');\n"
        )))

    def test_arrayfilter_family_argument_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\narray_filter($xs, 'unserialize');\n"
        )))

    def test_shutdown_family_argument_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n"
            "register_shutdown_function('spl_autoload_register',"
            " $cb);\n"
        )))

    def test_iterator_apply_family_argument_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\niterator_apply($it, 'call_user_func', [$f]);\n"
        )))

    def test_user_forwarder_family_argument_blocks(self, tmp_path):
        # No builtin allowlist: an in-tree (or out-of-tree) wrapper
        # can forward the string to a real invocation.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\nmy_dispatch('spl_autoload_register');\n"
        )))

    def test_cuf_forwarder_dispatch_blocks(self, tmp_path):
        # The dispatch resolves 'array_map' (not a censused name) and
        # consumes only THAT literal; the family name it would
        # forward stays visible to the backstop.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n"
            "call_user_func('array_map',"
            " 'spl_autoload_register', $xs);\n"
        )))

    def test_iniset_family_argument_blocks(self, tmp_path):
        # 'ini_set' is itself census family: forwarded with an
        # attacker-useful key it registers the unserialize callback.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\narray_map('ini_set', $keys, $values);\n"
        )))

    def test_leading_backslash_argument_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\narray_map('\\\\spl_autoload_register', [$cb]);\n"
        )))

    def test_case_variant_argument_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\narray_map('SPL_Autoload_Register', [$cb]);\n"
        )))

    def test_escape_decoded_argument_blocks(self, tmp_path):
        # Double-quoted "\x72" is a real 'r' after PHP escape
        # decoding — the backstop must see the decoded name.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n"
            "array_map(\"spl_autoload_\\x72egister\", [$cb]);\n"
        )))

    def test_array_wrapped_argument_blocks(self, tmp_path):
        # A family name inside an array argument (a cufa argument
        # bundle, a config list) is still forwardable.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\nregister_hooks(['spl_autoload_register', $cb]);\n"
        )))

    def test_concat_operand_argument_blocks(self, tmp_path):
        # A literal OPERAND equal to the family name blocks: with a
        # dynamic other operand the assembled value can be exactly
        # the family name at runtime.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\nforward($p . 'spl_autoload_register');\n"
        )))

    def test_method_call_argument_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n$reg->add('spl_autoload_register');\n"
        )))

    def test_nullsafe_call_argument_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n$reg?->add('spl_autoload_register');\n"
        )))

    def test_static_call_argument_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\nRegistry::add('spl_autoload_register');\n"
        )))

    def test_constructor_argument_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n$r = new Registrar('spl_autoload_register');\n"
        )))

    def test_nowdoc_argument_blocks(self, tmp_path):
        # Nowdoc is a string literal too — a callable can be spelled
        # with it.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\nforward(<<<'EOT'\nspl_autoload_register\nEOT);\n"
        )))

    def test_heredoc_argument_blocks(self, tmp_path):
        # A heredoc without interpolation is fully literal. The
        # zero-indent closer is the pre-7.3 spelling: nothing is
        # stripped, and this pin holds the no-indent behavior fixed
        # while the flexible-syntax pins below exercise stripping.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\nforward(<<<EOT\nspl_autoload_register\nEOT);\n"
        )))

    # ── flexible (indented-closer) heredoc/nowdoc: PHP 7.3+ strips
    # the closing marker's indentation from every body line at
    # compile time, so the runtime value is the DEDENTED body. The
    # census must compute that same value: joining the body verbatim
    # computes an indented string that never equals a family name,
    # and the tree earns while the registration executes — the false
    # absence these pins hold shut (execution-verified against the
    # PHP engine). ──

    def test_indented_heredoc_whole_name_blocks(self, tmp_path):
        # The whole family name in ONE indented heredoc — no concat.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n$cb = <<<EOT\n    spl_autoload_register\n"
            "    EOT;\narray_map($cb, ['probe_loader']);\n"
        )))

    def test_indented_nowdoc_whole_name_blocks(self, tmp_path):
        # Nowdoc bodies dedent identically (only escape decoding
        # differs between the two forms).
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n$cb = <<<'EOT'\n    spl_autoload_register\n"
            "    EOT;\narray_map($cb, ['probe_loader']);\n"
        )))

    def test_indented_heredoc_concat_operand_blocks(self, tmp_path):
        # Pure-literal concat with an indented heredoc RIGHT
        # operand: the chain fold reads the same leaf-content
        # helper, so the dedented fragment must join to the name
        # there too.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n$cb = 'spl_' . <<<EOT\n    autoload_register\n"
            "    EOT;\narray_map($cb, ['probe_loader']);\n"
        )))

    def test_indented_nowdoc_concat_operand_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n$cb = 'spl_' . <<<'EOT'\n    autoload_register\n"
            "    EOT;\narray_map($cb, ['probe_loader']);\n"
        )))

    def test_tab_indented_heredoc_whole_name_blocks(self, tmp_path):
        # PHP requires the body to repeat the closer's indentation
        # with the SAME characters — a tab-indented closer strips a
        # tab-indented body.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n$cb = <<<EOT\n\t\tspl_autoload_register\n"
            "\t\tEOT;\narray_map($cb, ['probe_loader']);\n"
        )))

    def test_indented_heredoc_escape_fragment_blocks(self, tmp_path):
        # Stripping happens on the source line; escape decoding
        # still applies to the remainder ('  spl' + \x5f +
        # 'autoload_register' dedents and decodes to the name).
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n$cb = <<<EOT\n  spl\\x5fautoload_register\n"
            "  EOT;\narray_map($cb, ['probe_loader']);\n"
        )))

    def test_indented_heredoc_non_family_value_still_earns(
            self, tmp_path):
        # No over-block: the DEDENTED value is the thing matched,
        # and a non-family value costs nothing (stripping must not
        # manufacture matches or registrations).
        report = self._report(tmp_path, (
            "<?php\n$cb = <<<EOT\n    helper_function\n"
            "    EOT;\narray_map($cb, ['x']);\n"
        ))
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_under_indented_heredoc_body_fails_closed(self, tmp_path):
        # A non-whitespace body line with LESS indentation than the
        # closer is a PHP compile error ("invalid body indentation
        # level"), but tree-sitter tolerates the shape — the
        # recovery cannot compute a trustworthy value, so the census
        # fails closed as a registration rather than earning.
        report = self._report(tmp_path, (
            "<?php\n$cb = <<<EOT\n  spl_autoload_register\n"
            "    EOT;\narray_map($cb, ['probe_loader']);\n"
        ))
        assert report["autoload"]["registered"] is True
        assert ("malformed-heredoc-indent"
                in [s["mechanism"]
                    for s in report["autoload"]["sites"]])
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_under_indented_heredoc_concat_operand_fails_closed(
            self, tmp_path):
        # The same malformed body as a chain OPERAND: the fold
        # treats it as never-matching, the unmatched chain descends,
        # and the mention arm's visit to the heredoc node itself
        # records the fail-closed registration — both consumers of
        # the shared leaf-content helper stay covered.
        report = self._report(tmp_path, (
            "<?php\n$cb = 'spl_' . <<<EOT\n a\n    EOT;\n"
        ))
        assert report["autoload"]["registered"] is True
        assert ("malformed-heredoc-indent"
                in [s["mechanism"]
                    for s in report["autoload"]["sites"]])
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_cr_only_line_endings_never_earn(self, tmp_path):
        # PHP accepts bare-CR line endings and EXECUTES this
        # registration (execution-verified against the engine): the
        # engine dedents the body to the intact family name exactly
        # as it does under \n endings. The recovery here is
        # newline-anchored TWICE (the closer-indent scan and the
        # body-token line-head check both demand a literal \n), so
        # a one-sided "support \r" edit to either check alone would
        # recover the indent, skip the body strip, compute an
        # indented value, match nothing — and EARN on an executing
        # tree. INVARIANT (never relax): this tree must not earn
        # the promotable tier.
        report = self._report(tmp_path, (
            "<?php\r$cb = <<<EOT\r    spl_autoload_register\r"
            "    EOT;\rarray_map($cb, ['probe_loader']);\r"
        ))
        assert report["absence_tier"] != TIER_NO_GADGET_SURFACE
        assert report["autoload"]["registered"] is True
        # Today-pin: the CR shape currently fails closed as a
        # malformed-heredoc-indent registration. A change that
        # instead dedents CR-terminated lines correctly must swap
        # this mechanism for family-literal-mention — every
        # outcome except earning is acceptable above.
        assert ("malformed-heredoc-indent"
                in [s["mechanism"]
                    for s in report["autoload"]["sites"]])
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    @pytest.mark.parametrize("prefix", ["b", "B"])
    def test_binary_string_heredoc_prefix_fails_closed(
            self, tmp_path, prefix):
        # b<<<EOT / B<<<EOT (binary-string heredoc) is valid PHP
        # that EXECUTES the registration (execution-verified
        # against the engine) but a shape the grammar cannot parse:
        # the file censuses as a parse error, completeness breaks,
        # and the tier is withheld TREE-WIDE. INVARIANT (never
        # relax): this tree must not earn the promotable tier.
        report = self._report(tmp_path, (
            f"<?php\n$cb = {prefix}<<<EOT\n"
            "    spl_autoload_register\n"
            "    EOT;\narray_map($cb, ['probe_loader']);\n"
        ))
        assert report["absence_tier"] != TIER_NO_GADGET_SURFACE
        # Today-pin: the protection is the parse-errors
        # completeness gate, file-level fail-closed. A grammar
        # upgrade that starts HALF-parsing the construct (the file
        # parses, the heredoc value stays invisible) flips
        # census-complete to True and must trade these lines for a
        # value-level verdict (family-literal-mention block) —
        # every outcome except earning is acceptable above.
        assert report["census"]["complete"] is False
        assert ("parse-errors"
                in report["census"]["incomplete_reasons"])
        assert report["absence_tier"] == TIER_NONE

    def test_whitespace_only_line_dedents_like_php(self, tmp_path):
        # PHP exempts whitespace-only body lines from the
        # indentation requirement (a shorter-than-indent blank line
        # strips whole) — such a line must not read as malformed,
        # and the surrounding value still computes exactly.
        report = self._report(tmp_path, (
            "<?php\n$cb = <<<EOT\n  keep_me\n \n  also_kept\n"
            "  EOT;\narray_map($cb, ['x']);\n"
        ))
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_namespaced_literal_argument_does_not_block(
            self, tmp_path):
        # 'App\loader' and 'Cls::method' are DIFFERENT symbols,
        # never the global family.
        report = self._report(tmp_path, (
            "<?php\n"
            "array_map('App\\\\spl_autoload_register', $xs);\n"
            "array_map('Cls::method', $xs);\n"
        ))
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_benign_literal_arguments_still_earn(self, tmp_path):
        # Whole-value match only: a benign builtin name and a prose
        # string CONTAINING a family word must not cost the tier.
        report = self._report(tmp_path, (
            "<?php\n"
            "array_map('trim', $xs);\n"
            "$log->write('nothing to assert here');\n"
        ))
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_closure_body_family_literal_blocks(self, tmp_path):
        # A closure body is executable code like any other: a family
        # name it returns (or stores) escapes to whoever calls the
        # closure, so the mention is position-independent here too.
        # The over-block direction is deliberate — a comparison
        # against the word 'assert' costs the promotable tier, the
        # same trade already accepted for benign argument data.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n"
            "array_filter($xs,"
            " function ($x) { return $x !== 'assert'; });\n"
        )))
        self._assert_blocked(self._report(tmp_path, (
            "<?php\nusort($ys, fn ($a, $b) => $a <=> 'eval');\n"
        )))

    def test_consumed_dispatch_target_not_double_reported(
            self, tmp_path):
        # The precise dispatch already censused the literal target —
        # exactly one site, under the precise mechanism.
        report = self._report(tmp_path, (
            "<?php\n"
            "call_user_func('spl_autoload_register',"
            " function ($c) {});\n"
        ))
        assert len(report["autoload"]["sites"]) == 1
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "spl_autoload_register")

    def test_nested_dispatch_targets_not_double_reported(
            self, tmp_path):
        # Every hop the dispatch resolved is consumed — including
        # the intermediate 'call_user_func' literal.
        report = self._report(tmp_path, (
            "<?php\n"
            "call_user_func('call_user_func',"
            " 'spl_autoload_register', function ($c) {});\n"
        ))
        assert len(report["autoload"]["sites"]) == 1
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "spl_autoload_register")

    def test_nested_call_argument_not_double_reported(self, tmp_path):
        # The literal is checked at its OWN walker visit, exactly
        # once — being inside two calls' argument subtrees must not
        # yield two facts.
        report = self._report(tmp_path, (
            "<?php\nouter(inner('unserialize'));\n"
        ))
        sites = report["autoload"]["sites"]
        assert [s["mechanism"] for s in sites] == [
            "family-literal-mention"]

    # ── position independence: literals OUTSIDE argument lists ──
    # Every shape below stores the intact family name somewhere a
    # forwarder can pick it up; each was execution-verified to
    # register a live autoloader on the PHP engine.

    def test_default_parameter_value_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n"
            "function boot($cb = 'spl_autoload_register') {\n"
            "    array_map($cb, ['loader']);\n"
            "}\n"
            "boot();\n"
        )))

    def test_assignment_rhs_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n"
            "$cb = 'spl_autoload_register';\n"
            "array_map($cb, ['loader']);\n"
        )))

    def test_return_statement_literal_blocks(self, tmp_path):
        # The forwarding argument is a nested CALL, not even a
        # variable — only the position-independent mention sees the
        # stored name.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n"
            "function get_cb() { return 'spl_autoload_register'; }\n"
            "array_map(get_cb(), ['loader']);\n"
        )))

    def test_array_default_parameter_static_method_blocks(
            self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n"
            "class Cfg {\n"
            "    public static function cbs(\n"
            "            $cbs = ['spl_autoload_register']) {\n"
            "        return $cbs;\n"
            "    }\n"
            "}\n"
            "$cbs = Cfg::cbs();\n"
            "array_map($cbs[0], ['loader']);\n"
        )))

    def test_property_initializer_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n"
            "class Reg { public $cb = 'spl_autoload_register'; }\n"
        )))

    def test_const_initializer_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\nconst CB = 'spl_autoload_register';\n"
        )))

    def test_class_const_initializer_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n"
            "class Reg { const CB = 'spl_autoload_register'; }\n"
        )))

    def test_toplevel_array_literal_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n$hooks = ['boot' => 'spl_autoload_register'];\n"
        )))

    def test_anonymous_class_ctor_argument_blocks(self, tmp_path):
        # tree-sitter-php nests the argument list under the
        # anonymous_class child, not the creation expression — a
        # per-call scan missed it; the whole-tree walk cannot.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n"
            "$o = new class('spl_autoload_register') {\n"
            "    public function __construct(public $cb) {}\n"
            "};\n"
        )))

    def test_anonymous_class_extends_ctor_argument_blocks(
            self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n"
            "class Base {}\n"
            "$o = new class('spl_autoload_register') extends Base {\n"
            "    public function __construct(public $cb) {}\n"
            "};\n"
        )))

    def test_anonymous_class_implements_ctor_argument_blocks(
            self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n"
            "interface Iface {}\n"
            "$o = new class('spl_autoload_register')"
            " implements Iface {\n"
            "    public function __construct(public $cb) {}\n"
            "};\n"
        )))

    def test_attribute_argument_blocks(self, tmp_path):
        # An attribute value executes only through a reflecting
        # invoker, but the stored literal escapes the tree exactly
        # like any other stored callable string: fail closed.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n"
            "#[Handler('spl_autoload_register')]\n"
            "class C {}\n"
        )))

    # ── compile-time literal concatenation ──
    # PHP folds adjacent literal concat at COMPILE time, so the
    # split spelling is byte-for-byte the intact name to the engine.

    def test_split_concat_argument_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n"
            "array_map('spl_autoload' . '_register', ['loader']);\n"
        )))

    def test_split_concat_nested_parenthesized_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n"
            "forward((('spl_' . 'autoload') . '_register'));\n"
        )))

    def test_split_concat_escape_decoded_blocks(self, tmp_path):
        # Operands decode per PHP quoting rules BEFORE joining.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n"
            "forward('spl_autoload' . \"_regist\\x65r\");\n"
        )))

    def test_split_concat_assignment_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n$f = 'spl_autoload' . '_register';\n"
        )))

    def test_split_concat_heredoc_operand_blocks(self, tmp_path):
        self._assert_blocked(self._report(tmp_path, (
            "<?php\nforward(<<<EOT\nspl_autoload\nEOT . '_register');\n"
        )))

    def test_matched_fold_reports_single_site(self, tmp_path):
        # The matched chain's operand literals are not visited
        # separately — one fact for one assembled name.
        report = self._report(tmp_path, (
            "<?php\nforward('spl_autoload' . '_register');\n"
        ))
        assert [s["mechanism"]
                for s in report["autoload"]["sites"]] == [
            "family-literal-mention"]

    def test_nonmatching_fold_still_earns(self, tmp_path):
        # A fully-literal chain folding to a NON-family value, with
        # no family-name operand, costs nothing.
        report = self._report(tmp_path, (
            "<?php\nforward('spl_autoload_' . 'helper');\n"
        ))
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_multi_segment_fold_does_not_block(self, tmp_path):
        # The folded value resolves like any literal: a multi-segment
        # name is a DIFFERENT symbol. Operands chosen so no single
        # operand is a family name either — a family-name OPERAND
        # blocks regardless of the fold (the shipped over-block, see
        # test_concat_operand_argument_blocks).
        report = self._report(tmp_path, (
            "<?php\nforward('Foo\\\\uns' . 'erialize');\n"
        ))
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_family_operand_in_multi_segment_fold_blocks(
            self, tmp_path):
        # r8-shipped semantics retained: the intact family-name
        # OPERAND costs the tier even when the assembled value is a
        # different (multi-segment) symbol — fail-closed.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\nforward('Foo\\\\' . 'unserialize');\n"
        )))

    # ── guards: what must KEEP earning ──

    def test_multi_segment_literal_positions_do_not_block(
            self, tmp_path):
        # 'Foo\unserialize' / 'Cls::method' name DIFFERENT symbols in
        # every position — storage is no more suspicious than an
        # argument was.
        report = self._report(tmp_path, (
            "<?php\n"
            "$x = 'Foo\\\\unserialize';\n"
            "const Y = 'App\\\\spl_autoload_register';\n"
            "function f($p = 'Cls::method') {}\n"
        ))
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_benign_literals_outside_arguments_still_earn(
            self, tmp_path):
        # Whole-value match only, in every position: benign names
        # and prose CONTAINING a family word cost nothing.
        report = self._report(tmp_path, (
            "<?php\n"
            "$s = 'nothing to assert here';\n"
            "const GREETING = 'evaluate';\n"
            "function f($p = 'trim') { return 'unserialized'; }\n"
        ))
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_interpolated_string_does_not_block(self, tmp_path):
        # Interpolation with a variable is genuinely runtime-
        # assembled — unknowable statically, the documented residual.
        report = self._report(tmp_path, (
            "<?php\n$cb = \"spl_autoload_$suffix\";\n"
        ))
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_concat_with_variable_operand_no_family_literal_earns(
            self, tmp_path):
        # A dynamic operand makes the fold unknowable; with no
        # family-name operand either, nothing blocks.
        report = self._report(tmp_path, (
            "<?php\n$cb = $prefix . '_register';\n"
        ))
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_interior_subchain_fold_blocks(self, tmp_path):
        # The WHOLE chain folds to a non-family value, but one
        # interior sub-chain folds to the intact name: the chain's
        # single fold pass records every sub-chain's verdict, so the
        # interior match still costs the tier — fail-closed (the
        # runtime value only APPENDS to the name).
        self._assert_blocked(self._report(tmp_path, (
            "<?php\nforward('spl_autoload' . '_register' . 'x');\n"
        )))

    def test_family_subchain_next_to_dynamic_operand_blocks(
            self, tmp_path):
        # A dynamic operand keeps the WHOLE chain unfoldable, but
        # the pure-literal sub-chain beside it folds to the intact
        # name on its own — with an empty runtime suffix the
        # assembled value IS the name, so the sub-chain verdict must
        # block exactly like the intact-literal operand does.
        self._assert_blocked(self._report(tmp_path, (
            "<?php\n$f = 'spl_autoload' . '_register' . $suffix;\n"
        )))

    # ── documented residual: cross-statement fragment assembly ──
    # These trees EXECUTE a real registration (the fragments are
    # assembled at runtime — execution-verified against the PHP
    # engine), but the name never appears whole in one literal or
    # one pure-literal concat EXPRESSION: the census's declared
    # single-expression static-visibility boundary. Pinned as
    # EARNERS so the residual documented at
    # _census_family_literal_mention stays an explicit, visible
    # boundary — if a future engine (assignment/constant flow
    # tracking) starts catching these shapes, this pin flips and
    # the residual documentation must be re-scoped in the same
    # change.

    @pytest.mark.parametrize("code", [
        pytest.param(
            "<?php\n$s = 'spl_autoload';\n$s .= '_register';\n"
            "array_map($s, ['probe_loader']);\n",
            id="dotequals-append"),
        pytest.param(
            "<?php\n$a = 'spl_autoload';\n$b = '_register';\n"
            "array_map($a . $b, ['probe_loader']);\n",
            id="two-variable-concat"),
        pytest.param(
            "<?php\nconst FRAG_A = 'spl_autoload';\n"
            "const FRAG_B = '_register';\n"
            "array_map(FRAG_A . FRAG_B, ['probe_loader']);\n",
            id="const-fragment-concat"),
        pytest.param(
            "<?php\nclass Frag { const P = 'spl_autoload';"
            " const Q = '_register'; }\n"
            "array_map(Frag::P . Frag::Q, ['probe_loader']);\n",
            id="classconst-fragment-concat"),
        pytest.param(
            "<?php\narray_map(implode('', ['spl_autoload',"
            " '_register']), ['probe_loader']);\n",
            id="implode-builtin-assembly"),
    ])
    def test_cross_statement_fragment_assembly_is_documented_residual(
            self, tmp_path, code):
        report = self._report(tmp_path, code)
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    # ── grammar-edge shapes: pinned so a grammar bump cannot
    #    silently regress them ──

    @pytest.mark.parametrize("code", [
        pytest.param(
            "<?php\n"
            "array_map(callback: 'spl_autoload_register',"
            " array: $xs);\n",
            id="named-argument"),
        pytest.param(
            "<?php\n"
            "forward($x ? 'spl_autoload_register' : 'trim');\n",
            id="ternary-arm"),
        pytest.param(
            "<?php\nconfigure(['spl_autoload_register' => 1]);\n",
            id="array-key"),
        pytest.param(
            "<?php\n"
            "$cb = match($x) {\n"
            "    1 => 'spl_autoload_register',\n"
            "    default => 'trim',\n"
            "};\n",
            id="match-arm"),
        pytest.param(
            "<?php\nforward(\"spl_autoload_register\");\n",
            id="double-quoted-plain"),
    ])
    def test_grammar_edge_mention_blocks(self, tmp_path, code):
        self._assert_blocked(self._report(tmp_path, code))

    def test_first_class_callable_blocks(self, tmp_path):
        # ``spl_autoload_register(...)`` names the family function
        # statically — censused by callee identity, not the mention
        # backstop; pinned here so the shape stays covered.
        report = self._report(tmp_path, (
            "<?php\n$f = spl_autoload_register(...);\n"
        ))
        assert report["autoload"]["registered"] is True
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND


@_GRAMMAR
class TestFunctionImportAliases:
    """``use function`` imports are resolved for the call census: an
    aliased spelling of an autoload-family function is seen as what
    PHP calls; the rewrite never runs AWAY from a family spelling
    (a decoy import must not launder the name)."""

    def _report(self, tmp_path: Path, code: str) -> dict:
        return scan_tree(_tree(tmp_path, {"entry.php": code}))

    def test_aliased_spl_register_blocks(self, tmp_path):
        report = self._report(tmp_path, (
            "<?php\n"
            "use function spl_autoload_register as sar;\n"
            "sar(function ($c) { require __DIR__.'/'.$c.'.php'; });\n"
            "unserialize($_GET['x']);\n"
        ))
        assert report["autoload"]["registered"] is True
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "spl_autoload_register")
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND
        assert absence_earns_suppression(report) is False

    def test_aliased_ini_set_literal_key_blocks(self, tmp_path):
        report = self._report(tmp_path, (
            "<?php\n"
            "use function ini_set as cfg;\n"
            "cfg('unserialize_callback_func', 'loader');\n"
        ))
        assert (report["autoload"]["sites"][0]["mechanism"]
                == "unserialize_callback_func")

    def test_alias_to_foreign_function_records_nothing(self, tmp_path):
        # The import target is a namespaced function — never the
        # global family; the aliased call is a different symbol.
        report = self._report(tmp_path, (
            "<?php\n"
            "use function App\\Boot\\helper as sar;\n"
            "sar('x');\n"
        ))
        assert report["autoload"]["sites"] == []
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_family_named_alias_still_blocks(self, tmp_path):
        # Never rewrite AWAY: the spelled family name stays censused
        # even when an import claims it means something else
        # (over-block, the safe error for a suppression blocker).
        report = self._report(tmp_path, (
            "<?php\n"
            "use function App\\Boot\\helper as spl_autoload_register;\n"
            "spl_autoload_register(function ($c) {});\n"
        ))
        assert report["autoload"]["registered"] is True

    def test_alias_applies_from_declaration_onward(self, tmp_path):
        # PHP imports are position-sensitive: a call BEFORE the use
        # declaration resolves without the alias.
        report = self._report(tmp_path, (
            "<?php\n"
            "sar('x');\n"
            "use function spl_autoload_register as sar;\n"
        ))
        assert report["autoload"]["sites"] == []

    def test_alias_window_is_namespace_scoped(self, tmp_path):
        # An import in namespace A never rewrites a call in
        # namespace B.
        report = self._report(tmp_path, (
            "<?php\n"
            "namespace A {\n"
            "    use function spl_autoload_register as sar;\n"
            "}\n"
            "namespace B {\n"
            "    sar('x');\n"
            "}\n"
        ))
        assert report["autoload"]["sites"] == []

    def test_const_import_never_rewrites_calls(self, tmp_path):
        # ``use const`` binds constants, not callables — a global
        # const import spelling a family name must not feed the
        # call-name rewrite (PHP calls the undefined function
        # ``sar``, not spl_autoload_register).
        report = self._report(tmp_path, (
            "<?php\n"
            "use const spl_autoload_register as sar;\n"
            "sar(function ($c) {});\n"
        ))
        assert report["autoload"]["sites"] == []


class TestAbsenceTierPredicate:
    """Hermetic fail-closed pins on the pure tier predicate."""

    def _report(self, **overrides):
        base = {
            "census": {"complete": True, "php_files": 3},
            "chains": [],
            "pop_surface": {
                "by_method": {},
                "total_methods": 0,
                "serializable_impls": 0,
                "dynamic_definition_sites": 0,
                "anonymous_class_methods": 0,
            },
            "autoload": {"registered": False, "sites": []},
        }
        base.update(overrides)
        return base

    def test_zero_surface_complete_census_fires(self):
        assert absence_tier(self._report()) == TIER_NO_GADGET_SURFACE

    def test_autoload_registration_demotes(self):
        # unserialize() hands the attacker-chosen class name to the
        # registered loader BEFORE any object method is consulted —
        # a registered autoload mechanism is reachable attack surface
        # even in a tree with zero POP trigger methods.
        registered = self._report(
            autoload={"registered": True,
                      "sites": [{"file": "boot.php", "line": 2,
                                 "mechanism": "spl_autoload_register"}]},
        )
        assert absence_tier(registered) == TIER_NO_CHAINS_FOUND

    def test_fail_closed_on_malformed_autoload_record(self):
        # Reports predating the autoload census (no key at all) must
        # never earn the promotable tier — fail closed, not open.
        missing = self._report()
        del missing["autoload"]
        assert absence_tier(missing) == TIER_NONE
        assert absence_tier(self._report(autoload=None)) == TIER_NONE
        assert absence_tier(
            self._report(autoload=[("boot.php", 2)])) == TIER_NONE
        assert absence_tier(
            self._report(autoload={"sites": []})) == TIER_NONE
        assert absence_tier(
            self._report(autoload={"registered": "no",
                                   "sites": []})) == TIER_NONE
        assert absence_tier(
            self._report(autoload={"registered": 0,
                                   "sites": []})) == TIER_NONE

    def test_each_blocker_individually_demotes(self):
        surfaced = self._report()
        surfaced["pop_surface"]["by_method"] = {"__destruct": 1}
        assert absence_tier(surfaced) == TIER_NO_CHAINS_FOUND
        for key in ("serializable_impls", "dynamic_definition_sites",
                    "anonymous_class_methods"):
            r = self._report()
            r["pop_surface"][key] = 1
            assert absence_tier(r) == TIER_NO_CHAINS_FOUND, key

    def test_fail_closed_on_malformed_reports(self):
        assert absence_tier("not-a-dict") == TIER_NONE
        assert absence_tier({}) == TIER_NONE
        assert absence_tier(self._report(census=None)) == TIER_NONE
        assert absence_tier(
            self._report(census={"complete": "yes"})) == TIER_NONE
        assert absence_tier(
            self._report(census={"complete": False})) == TIER_NONE
        assert absence_tier(self._report(chains=None)) == TIER_NONE
        assert absence_tier(
            self._report(chains=[{"class": "A"}])) == TIER_NONE
        assert absence_tier(
            self._report(chains_truncated=True)) == TIER_NONE
        assert absence_tier(self._report(pop_surface=None)) == TIER_NONE
        no_by_method = self._report()
        del no_by_method["pop_surface"]["by_method"]
        assert absence_tier(no_by_method) == TIER_NONE
        bool_count = self._report()
        bool_count["pop_surface"]["by_method"] = {"__destruct": True}
        assert absence_tier(bool_count) == TIER_NONE
        negative = self._report()
        negative["pop_surface"]["serializable_impls"] = -1
        assert absence_tier(negative) == TIER_NONE
        missing_counter = self._report()
        del missing_counter["pop_surface"]["dynamic_definition_sites"]
        assert absence_tier(missing_counter) == TIER_NONE

    def test_inconsistent_autoload_record_fails_closed(self):
        # ``registered: false`` alongside a NON-EMPTY sites list is an
        # internally inconsistent record — an artifact edit, never a
        # live scan (which derives the boolean from the sites). The
        # tier must not trust the boolean over the contradiction.
        r = self._report(autoload={
            "registered": False,
            "sites": [{"file": "boot.php", "line": 2,
                       "mechanism": "spl_autoload_register"}],
        })
        assert absence_tier(r) == TIER_NONE

    def test_vacuous_empty_scan_fails_closed(self):
        # Zero PHP files: every counter is zero because nothing was
        # looked at — a vacuous absence is no claim at all.
        r = self._report(census={"complete": True, "php_files": 0})
        assert absence_tier(r) == TIER_NONE

    def test_malformed_php_file_count_fails_closed(self):
        for bad in (None, "3", True, -1):
            r = self._report(
                census={"complete": True, "php_files": bad})
            assert absence_tier(r) == TIER_NONE, repr(bad)
        missing = self._report(census={"complete": True})
        assert absence_tier(missing) == TIER_NONE


class TestAbsenceEarnsSuppression:
    """Hermetic two-direction pins on the suppression-authority
    helper: constant AND earned tier, nothing else."""

    _report = TestAbsenceTierPredicate._report

    def test_earned_tier_carries_authority(self):
        assert absence_earns_suppression(self._report()) is True

    def test_no_chains_found_never_earns(self):
        # The depth-limited claim is permanently hint-tier: any POP
        # surface (each counter individually) declines.
        surfaced = self._report()
        surfaced["pop_surface"]["by_method"] = {"__destruct": 1}
        assert absence_earns_suppression(surfaced) is False
        for key in ("serializable_impls", "dynamic_definition_sites",
                    "anonymous_class_methods"):
            r = self._report()
            r["pop_surface"][key] = 1
            assert absence_earns_suppression(r) is False, key

    def test_autoload_registration_never_earns(self):
        # Registration alone is enough: the loader runs on the
        # attacker-chosen class name at unserialize() time.
        registered = self._report(
            autoload={"registered": True,
                      "sites": [{"file": "b.php", "line": 1,
                                 "mechanism": "__autoload"}]},
        )
        assert absence_earns_suppression(registered) is False

    def test_malformed_reports_fail_closed(self):
        assert absence_earns_suppression("not-a-dict") is False
        assert absence_earns_suppression({}) is False
        assert absence_earns_suppression(
            self._report(census=None)) is False
        assert absence_earns_suppression(
            self._report(census={"complete": False})) is False
        assert absence_earns_suppression(
            self._report(census={"complete": "yes"})) is False
        assert absence_earns_suppression(
            self._report(chains=[{"class": "A"}])) is False
        assert absence_earns_suppression(
            self._report(chains_truncated=True)) is False
        assert absence_earns_suppression(
            self._report(pop_surface=None)) is False
        no_autoload = self._report()
        del no_autoload["autoload"]
        assert absence_earns_suppression(no_autoload) is False
        assert absence_earns_suppression(
            self._report(autoload={"registered": "yes",
                                   "sites": []})) is False
        assert absence_earns_suppression(
            self._report(autoload={
                "registered": False,
                "sites": [{"file": "b.php", "line": 1,
                           "mechanism": "spl_autoload_register"}],
            })) is False
        assert absence_earns_suppression(
            self._report(census={"complete": True,
                                 "php_files": 0})) is False

    def test_constant_off_disarms_even_the_earned_tier(
            self, monkeypatch):
        monkeypatch.setattr(go, "ABSENCE_EARNS_SUPPRESSION", False)
        report = self._report()
        assert go.absence_tier(report) == TIER_NO_GADGET_SURFACE
        assert go.absence_earns_suppression(report) is False


@_GRAMMAR
class TestChannelTierSurfacing:
    def test_absence_evidence_carries_tier(self, tmp_path):
        root = _tree(tmp_path, {"f.php": _PROCEDURAL_ONLY})
        ev = run_gadget_oracle_check(
            root, "f.php", "handle", "no gadgets in tree")
        assert ev.outcome == "refuted"
        assert ev.absence_tier == TIER_NO_GADGET_SURFACE
        assert ev.to_dict()["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_surfaced_absence_keeps_boundary_tier(self, tmp_path):
        root = _tree(tmp_path, {"safe.php": _NO_GADGET})
        ev = run_gadget_oracle_check(
            root, "safe.php", "f", "no gadgets in tree")
        assert ev.outcome == "inconclusive"
        assert ev.absence_tier == TIER_NO_CHAINS_FOUND

    def test_confirmed_evidence_tier_none(self, tmp_path):
        root = _tree(tmp_path, {"logger.php": _DESTRUCT_UNLINK})
        ev = run_gadget_oracle_check(
            root, "logger.php", "f", "gadget chain")
        assert ev.outcome == "confirmed"
        assert ev.absence_tier == TIER_NONE

    def test_suppression_row_records_tier(self, tmp_path):
        root = _tree(tmp_path, {"f.php": _PROCEDURAL_ONLY})
        out = tmp_path / "out"
        out.mkdir()
        run_gadget_oracle_check(
            root, "f.php", "handle", "no gadgets in tree",
            output_dir=out,
        )
        rows = [
            json.loads(line) for line in
            (out / "suppressions.jsonl").read_text().splitlines()
        ]
        assert rows[0]["absence_tier"] == TIER_NO_GADGET_SURFACE
        assert rows[0]["earns_suppression"] is True
        assert rows[0]["dropped"] is False


@_GRAMMAR
class TestChannelPerBlockerDeclines:
    """Every individual promotion blocker forces the channel back to
    the inconclusive verdict — the refutation fires ONLY on the
    zero-surface complete-census shape."""

    HYP = "no gadgets in tree"

    def _check(self, root):
        return run_gadget_oracle_check(root, "f.php", "f", self.HYP)

    def _assert_inconclusive(self, ev):
        assert ev.outcome == "inconclusive"
        assert ev.rule_id == RULE_ABSENCE
        assert ev.reason in (REASON_NO_GADGETS_COMPLETE,
                             REASON_NO_GADGETS_DEGRADED)

    @pytest.mark.parametrize("method", sorted(go.POP_SURFACE_METHODS))
    def test_each_pop_surface_method_blocks(self, tmp_path, method):
        src = (f"<?php\nclass Carrier {{\n"
               f"    public function {method}() {{}}\n}}\n")
        root = _tree(tmp_path, {"f.php": src})
        ev = self._check(root)
        self._assert_inconclusive(ev)
        assert ev.absence_tier == TIER_NO_CHAINS_FOUND
        assert ev.reason == REASON_NO_GADGETS_COMPLETE

    def test_serializable_impl_blocks(self, tmp_path):
        root = _tree(tmp_path, {"f.php": _SERIALIZABLE_IMPL})
        ev = self._check(root)
        self._assert_inconclusive(ev)
        assert ev.absence_tier == TIER_NO_CHAINS_FOUND

    def test_eval_site_blocks(self, tmp_path):
        root = _tree(tmp_path, {"f.php": _EVAL_SITE})
        ev = self._check(root)
        self._assert_inconclusive(ev)
        assert ev.absence_tier == TIER_NO_CHAINS_FOUND

    def test_string_assert_blocks(self, tmp_path):
        root = _tree(tmp_path, {
            "f.php": "<?php assert('class Z {} true');\n"})
        ev = self._check(root)
        self._assert_inconclusive(ev)
        assert ev.absence_tier == TIER_NO_CHAINS_FOUND

    def test_anonymous_class_method_blocks(self, tmp_path):
        root = _tree(tmp_path, {"f.php": _ANON_DESTRUCT})
        ev = self._check(root)
        self._assert_inconclusive(ev)
        assert ev.absence_tier == TIER_NO_CHAINS_FOUND

    def test_autoload_registration_blocks(self, tmp_path):
        # unserialize() runs the registered loader on the
        # attacker-chosen class name before any object method — the
        # channel must never refute a deserialization hypothesis
        # against a tree that registers one.
        root = _tree(tmp_path, {"f.php": _SPL_CLOSURE_AUTOLOAD})
        ev = self._check(root)
        self._assert_inconclusive(ev)
        assert ev.absence_tier == TIER_NO_CHAINS_FOUND
        assert ev.reason == REASON_NO_GADGETS_COMPLETE

    def test_unserialize_callback_ini_blocks(self, tmp_path):
        root = _tree(tmp_path, {"f.php": (
            "<?php\n"
            "ini_set('unserialize_callback_func', 'loader');\n"
        )})
        ev = self._check(root)
        self._assert_inconclusive(ev)
        assert ev.absence_tier == TIER_NO_CHAINS_FOUND

    def test_parse_error_blocks(self, tmp_path):
        root = _tree(tmp_path, {
            "f.php": _PROCEDURAL_ONLY, "b.php": _PARSE_BROKEN})
        ev = self._check(root)
        self._assert_inconclusive(ev)
        assert ev.reason == REASON_NO_GADGETS_DEGRADED
        assert "parse-errors" in ev.census["incomplete_reasons"]

    def test_php_like_unscanned_blocks(self, tmp_path):
        root = _tree(tmp_path, {
            "f.php": _PROCEDURAL_ONLY, "h.inc": _PROCEDURAL_ONLY})
        ev = self._check(root)
        self._assert_inconclusive(ev)
        assert ev.reason == REASON_NO_GADGETS_DEGRADED
        assert "php-like-unscanned" in ev.census["incomplete_reasons"]

    def test_unresolved_trait_blocks(self, tmp_path):
        root = _tree(tmp_path, {"f.php": _TRAIT_CROSS_FILE})
        ev = self._check(root)
        self._assert_inconclusive(ev)
        assert "unresolved-traits" in ev.census["incomplete_reasons"]

    def test_oversized_file_blocks(self, tmp_path):
        import os as _os
        root = _tree(tmp_path, {
            "f.php": _PROCEDURAL_ONLY, "big.php": "<?php\n"})
        _os.truncate(root / "big.php", go.MAX_FILE_BYTES + 1)
        ev = self._check(root)
        self._assert_inconclusive(ev)
        assert ev.reason == REASON_NO_GADGETS_DEGRADED
        assert "oversized-files" in ev.census["incomplete_reasons"]

    def test_chains_truncated_blocks(self, tmp_path, monkeypatch):
        # Hermetic: a search that hit its accumulation budget must
        # never refute, even with zero recorded surface.
        root = _tree(tmp_path, {"f.php": _PROCEDURAL_ONLY})
        real = go.scan_tree

        def truncating(target, **kw):
            report = real(target, **kw)
            report["chains_truncated"] = True
            return report

        monkeypatch.setattr(go, "scan_tree", truncating)
        ev = self._check(root)
        self._assert_inconclusive(ev)
        assert ev.reason == REASON_NO_GADGETS_COMPLETE


def _sink_burst(n: int) -> str:
    """A class whose __destruct calls n distinct one-hop helpers,
    each with its own property sink."""
    calls = "\n".join(f"        $this->h{i}();" for i in range(n))
    helpers = "\n".join(
        f"    private function h{i}() {{ system($this->c{i}); }}"
        for i in range(n))
    return ("<?php\nclass Burst {\n"
            "    public function __destruct() {\n"
            f"{calls}\n    }}\n{helpers}\n}}\n")


@_GRAMMAR
class TestHostileTreeBounds:
    def test_fifo_excluded_from_walk_and_counted(self, tmp_path):
        # A FIFO would block open() forever — only regular files are
        # walked; the skip is counted, never silent. Asserted on the
        # walker (fails fast without opening anything on regression).
        import os as _os
        if not hasattr(_os, "mkfifo"):
            pytest.skip("no mkfifo on this platform")
        root = _tree(tmp_path, {"ok.php": _NO_GADGET})
        _os.mkfifo(root / "trap.php")
        files, stats = go._iter_tree_files(root)
        assert [rel for rel, _ in files] == ["ok.php"]
        assert stats["special_skipped"] == 1

    def test_special_files_counted_not_completeness_breaking(
            self, tmp_path, monkeypatch):
        # Census propagation, hermetic (no real FIFO): special files
        # have no at-rest content, so they count WITHOUT flipping the
        # census incomplete.
        root = _tree(tmp_path, {"ok.php": _NO_GADGET})
        real = go._iter_tree_files

        def fake(r):
            files, stats = real(r)
            stats["special_skipped"] = 2
            return files, stats

        monkeypatch.setattr(go, "_iter_tree_files", fake)
        census = scan_tree(root)["census"]
        assert census["special_file_count"] == 2
        assert census["complete"] is True

    def test_symlinked_file_counted_breaks_census(self, tmp_path):
        outside = tmp_path / "outside.php"
        outside.write_text(_DESTRUCT_UNLINK)
        root = _tree(tmp_path, {"ok.php": _NO_GADGET})
        (root / "alias.php").symlink_to(outside)
        report = scan_tree(root)
        census = report["census"]
        assert census["symlink_skipped_count"] == 1
        assert census["complete"] is False
        assert "symlinks-skipped" in census["incomplete_reasons"]

    def test_symlinked_dir_counted_breaks_census(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "gadget.php").write_text(_DESTRUCT_UNLINK)
        root = _tree(tmp_path, {"ok.php": _NO_GADGET})
        (root / "src").symlink_to(outside, target_is_directory=True)
        census = scan_tree(root)["census"]
        assert census["symlink_skipped_count"] == 1
        assert census["complete"] is False
        assert "symlinks-skipped" in census["incomplete_reasons"]

    def test_no_symlinks_census_stays_complete(self, tmp_path):
        root = _tree(tmp_path, {"ok.php": _NO_GADGET})
        census = scan_tree(root)["census"]
        assert census["symlink_skipped_count"] == 0
        assert census["complete"] is True

    def test_calls_capped_per_method(self, tmp_path):
        # Over the cap: each same-class call fans out into chains, so
        # the record list is bounded (memory amplifier otherwise).
        n = go.MAX_CALLS_PER_METHOD + 4
        root = _tree(tmp_path, {"b.php": _sink_burst(n)})
        chains = scan_tree(root)["chains"]
        assert len(chains) == go.MAX_CALLS_PER_METHOD

    def test_calls_under_cap_all_recorded(self, tmp_path):
        n = go.MAX_CALLS_PER_METHOD - 4
        root = _tree(tmp_path, {"b.php": _sink_burst(n)})
        assert len(scan_tree(root)["chains"]) == n

    def test_chain_accumulation_stops_at_budget(
            self, tmp_path, monkeypatch):
        monkeypatch.setattr(go, "MAX_CHAINS", 3)
        root = _tree(tmp_path, {"b.php": _sink_burst(8)})
        report = scan_tree(root)
        assert len(report["chains"]) == 3
        assert report["chains_truncated"] is True

    def test_chains_under_budget_not_truncated(self, tmp_path):
        root = _tree(tmp_path, {"b.php": _sink_burst(4)})
        report = scan_tree(root)
        assert len(report["chains"]) == 4
        assert "chains_truncated" not in report

    def test_recursion_error_becomes_census_degradation(
            self, tmp_path, monkeypatch):
        # One pathologically deep file degrades to a parse error —
        # the scan (and any CLI above it) survives.
        def boom(method_node, src):
            raise RecursionError

        monkeypatch.setattr(go, "_analyze_method", boom)
        root = _tree(tmp_path, {"deep.php": _DESTRUCT_UNLINK})
        report = scan_tree(root)
        assert report["chains"] == []
        census = report["census"]
        assert census["parse_error_count"] == 1
        assert census["complete"] is False
        assert "parse-errors" in census["incomplete_reasons"]

    def test_probe_bound_declared_in_census_and_qualifier(
            self, tmp_path):
        root = _tree(tmp_path, {"ok.php": _NO_GADGET})
        report = scan_tree(root)
        assert (report["census"]["php_probe_bytes"]
                == go._PHP_PROBE_BYTES)
        assert "64 KiB" in census_qualifier(report)

    def test_php_tag_after_long_preamble_is_counted(self, tmp_path):
        # 8 KiB of HTML before the tag — beyond the old 4 KiB window,
        # within the declared one: MUST be censused.
        content = "<html>" + "x" * 8192 + "\n<?php class G {}\n"
        root = _tree(tmp_path, {"late.inc": content,
                                "ok.php": _NO_GADGET})
        census = scan_tree(root)["census"]
        assert census["php_like_unscanned_count"] == 1
        assert census["complete"] is False

    def test_php_tag_beyond_probe_bound_is_the_declared_miss(
            self, tmp_path):
        # Beyond the declared window the probe is honestly blind —
        # the bound rides in the census/qualifier instead of the
        # census silently claiming completeness about content it
        # never read. (Two-direction pin for the probe cap.)
        content = ("<html>" + "x" * (go._PHP_PROBE_BYTES + 128)
                   + "\n<?php class G {}\n")
        root = _tree(tmp_path, {"vlate.inc": content,
                                "ok.php": _NO_GADGET})
        report = scan_tree(root)
        assert report["census"]["php_like_unscanned_count"] == 0
        assert "KiB" in census_qualifier(report)

    def test_chain_assembly_spends_exactly_the_budget(self, tmp_path):
        # Direct pin on the assembly-side stop: the budget bounds what
        # gets BUILT, not just what a later slice keeps — on BOTH
        # chain shapes (direct property sinks and one-hop callees).
        facts = go.analyze_php_source(_sink_burst(8).encode())
        assert facts is not None and len(facts.classes) == 1
        built = go._chains_for_class(facts.classes[0], "b.php", 5)
        assert len(built) == 5
        direct = "<?php\nclass D { function __destruct() {\n" + "".join(
            f"system($this->c{i});\n" for i in range(8)) + "} }\n"
        facts2 = go.analyze_php_source(direct.encode())
        assert facts2 is not None and len(facts2.classes) == 1
        built2 = go._chains_for_class(facts2.classes[0], "d.php", 5)
        assert len(built2) == 5


_TRAIT_ALIAS_DESTRUCT = """<?php
trait Helper {
    public function cleanup() { system($this->cmd); }
}
class Evil {
    public $cmd;
    use Helper { cleanup as __destruct; }
}
"""

_TRAIT_ALIAS_CALL = """<?php
trait Helper {
    public function fire($m, $a) { system($this->cmd); }
}
class Evil {
    public $cmd;
    use Helper { fire as __call; }
}
"""


class TestNameIdentityRuleAgreement:
    """The chain fold's leaf summary re-implements the mention
    backstop's name-identity rule (ASCII lower + leading-backslash
    strip) in ``(bs, rest)`` form rather than sharing code — a
    future change to one normalisation could silently diverge the
    other. Pin the two rules to the SAME match verdict on every
    adversarial value class, so any divergence fails here loudly
    instead of shipping as a spelling one census arm sees and the
    other does not."""

    @pytest.mark.parametrize("value", [
        "spl_autoload_register",
        "SPL_AutoLoad_Register",
        "\\spl_autoload_register",
        "\\\\unserialize",
        "unserialize",
        "app\\unserialize",
        "spl_autoload_registerx",
        "x" * 64,
        "",
        "\\",
        "call_user_func",
        "Cls::method",
    ])
    def test_fold_leaf_and_mention_verdicts_agree(
            self, value: str) -> None:
        mention = (go._ascii_lower(value).lstrip("\\")
                   in go._CENSUS_CALL_NAMES)
        summary = go._chain_leaf_summary(value)
        fold = (summary is not None
                and summary[1] in go._CENSUS_CALL_NAMES)
        assert fold == mention


@_GRAMMAR
class TestConcatChainScaling:
    """The ``.``-chain census must stay LINEAR on machine-built
    chains: MAX_FILE_BYTES admits ~1.4M operands, so a per-node
    re-fold (quadratic) turns one planted file into a silent
    multi-hour CPU stall while the census still reports complete.
    Pinned with deterministic instrumentation — operand-content
    reads — never wall-clock, so the pin cannot flake with machine
    speed."""

    N_OPERANDS = 4000

    @staticmethod
    def _chain_src(operands: list[str]) -> bytes:
        return ("<?php\n$x = " + " . ".join(operands)
                + ";\n").encode()

    def test_unmatched_chain_operand_reads_are_linear(
            self, monkeypatch) -> None:
        calls = 0
        real = go._backstop_literal_content

        def counting(
                node: object, src: bytes,
        ) -> str | go._MalformedLiteral | None:
            nonlocal calls
            calls += 1
            return real(node, src)

        monkeypatch.setattr(go, "_backstop_literal_content", counting)
        facts = go.analyze_php_source(
            self._chain_src(["'aa'"] * self.N_OPERANDS))
        assert facts is not None and not facts.parse_errors
        assert facts.autoload_sites == []
        # Vacuity guard: every operand was read at least once — the
        # instrumentation saw the real walk, not a short-circuit.
        assert calls >= self.N_OPERANDS
        # Linear bound with slack: each operand is legitimately read
        # TWICE (once by the chain's single fold pass, once at its
        # own mention visit on the unmatched descent) plus a small
        # constant for non-operand nodes. Raising the bound toward
        # N**2/2 (~8M reads here) would re-admit the
        # per-interior-node re-fold this pins out; lowering it under
        # 2*N would outlaw the two legitimate reads per operand and
        # fail the correct implementation.
        assert calls <= 3 * self.N_OPERANDS + 64

    def test_matched_chain_at_scale_reports_single_site(self) -> None:
        # Empty-string operands keep the WHOLE fold equal to the
        # family name at any chain length — the matched chain
        # reports exactly once, at its topmost node.
        facts = go.analyze_php_source(self._chain_src(
            ["'spl_autoload'", "'_register'"]
            + ["''"] * self.N_OPERANDS))
        assert facts is not None and not facts.parse_errors
        assert ([m for _, m in facts.autoload_sites]
                == ["family-literal-mention"])

    def test_split_family_name_deep_in_long_chain_still_blocks(
            self) -> None:
        # A chain-length CAP is not an acceptable linearity fix: a
        # family name split past any cap would EARN — a fresh false
        # absence. The junk prefix keeps the WHOLE chain unmatched;
        # the name lives in one interior sub-chain whose verdict is
        # recorded on the same single fold pass.
        facts = go.analyze_php_source(self._chain_src(
            ["'aa'"] * self.N_OPERANDS
            + ["('spl_autoload' . '_register')"]))
        assert facts is not None and not facts.parse_errors
        assert ("family-literal-mention"
                in [m for _, m in facts.autoload_sites])


@_GRAMMAR
class TestTraitAliasSurface:
    """Trait-use adaptations mint magic methods no method_declaration
    ever declares — the census must count the ALIAS."""

    def test_alias_to_destruct_counts_as_surface(self, tmp_path):
        root = _tree(tmp_path, {"g.php": _TRAIT_ALIAS_DESTRUCT})
        report = scan_tree(root)
        assert report["pop_surface"]["by_method"] == {"__destruct": 1}
        # Live trigger surface exists: the promotable tier must not.
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_alias_to_call_counts_as_surface(self, tmp_path):
        root = _tree(tmp_path, {"g.php": _TRAIT_ALIAS_CALL})
        report = scan_tree(root)
        assert report["pop_surface"]["by_method"] == {"__call": 1}
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_alias_from_trait_method_reference_counts(self, tmp_path):
        src = ("<?php\ntrait A { public function go() {} }\n"
               "trait B { public function go() {} }\n"
               "class C {\n    use A, B {\n"
               "        A::go insteadof B;\n"
               "        B::go as __wakeup;\n    }\n}\n")
        root = _tree(tmp_path, {"c.php": src})
        report = scan_tree(root)
        assert report["pop_surface"]["by_method"] == {"__wakeup": 1}

    def test_alias_to_serializable_pair_counts(self, tmp_path):
        # The implements clause can live in another file: counting
        # the alias alone is the safe over-block.
        src = ("<?php\ntrait T { public function load($d) {} }\n"
               "class S { use T { load as unserialize; } }\n")
        root = _tree(tmp_path, {"s.php": src})
        report = scan_tree(root)
        assert report["pop_surface"]["by_method"] == {"unserialize": 1}
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_benign_alias_does_not_count(self, tmp_path):
        src = ("<?php\ntrait T { public function a() {} }\n"
               "class P { use T { a as b; } }\n")
        root = _tree(tmp_path, {"p.php": src})
        report = scan_tree(root)
        assert report["pop_surface"]["total_methods"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_visibility_only_adaptation_does_not_count(self, tmp_path):
        src = ("<?php\ntrait T { public function a() {} }\n"
               "class P { use T { a as protected; } }\n")
        root = _tree(tmp_path, {"p.php": src})
        report = scan_tree(root)
        assert report["pop_surface"]["total_methods"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE


@_GRAMMAR
class TestOpenTagVariants:
    """PHP's open tag is case-insensitive and the short form is live
    on compiled-default builds — the probe must catch both; the XML
    declaration must not count."""

    def test_uppercase_open_tag_breaks_completeness(self, tmp_path):
        root = _tree(tmp_path, {
            "entry.php": "<?php unserialize($_GET['x']);\n",
            "lib.inc": ("<?PHP class Evil { public $c;\n"
                        "function __destruct() { system($this->c); } }\n"),
        })
        report = scan_tree(root)
        assert report["census"]["php_like_unscanned_count"] == 1
        assert "php-like-unscanned" in (
            report["census"]["incomplete_reasons"])
        assert report["absence_tier"] == TIER_NONE

    def test_short_open_tag_breaks_completeness(self, tmp_path):
        root = _tree(tmp_path, {
            "entry.php": "<?php unserialize($_GET['x']);\n",
            "lib.inc": ("<? class Evil { public $c;\n"
                        "function __destruct() { system($this->c); } }\n"),
        })
        report = scan_tree(root)
        assert report["census"]["php_like_unscanned_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_xml_declaration_is_not_php_like(self, tmp_path):
        # Only a REAL XML declaration — ``<?xml`` + whitespace +
        # ``version`` — is exempt from the probe. Anything else
        # ``<?xml``-prefixed counts (see the smuggle test below).
        root = _tree(tmp_path, {
            "entry.php": "<?php unserialize($_GET['x']);\n",
            "feed.xml": "<?xml version=\"1.0\"?>\n<root/>\n",
            "conf.xml": ("<?xml   version=\"1.0\" "
                         "encoding=\"UTF-8\"?>\n<cfg/>\n"),
        })
        report = scan_tree(root)
        assert report["census"]["php_like_unscanned_count"] == 0
        assert report["census"]["complete"] is True
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_xml_open_tag_code_smuggle_counts(self, tmp_path):
        # ``<?xml;`` is LIVE short-tag PHP: the class declaration is
        # compile-hoisted even on 8.x, where the bare ``xml`` constant
        # only errors afterwards (and 7.x merely warns). A word
        # boundary after ``xml`` is NOT an XML declaration — only
        # ``<?xml`` + whitespace + ``version`` is.
        root = _tree(tmp_path, {
            "entry.php": "<?php unserialize($_GET['x']);\n",
            "payload.xml": ("<?xml;\nclass Evil { public $c;\n"
                            "function __destruct() "
                            "{ system($this->c); } }\n"),
        })
        report = scan_tree(root)
        assert report["census"]["php_like_unscanned_count"] == 1
        assert "php-like-unscanned" in (
            report["census"]["incomplete_reasons"])
        assert report["absence_tier"] == TIER_NONE

    def test_xml_stylesheet_pi_overcounts_fail_closed(self, tmp_path):
        # ``<?xml-stylesheet`` is a processing instruction, not a
        # declaration — and ``<?xml-stylesheet;`` is live PHP pre-8
        # (constant subtraction warns, it does not parse-error), so
        # the probe counts it. Over-counting withholds the tier: the
        # fail-closed direction.
        root = _tree(tmp_path, {
            "entry.php": "<?php unserialize($_GET['x']);\n",
            "styled.xml": ("<?xml version=\"1.0\"?>\n"
                           "<?xml-stylesheet href=\"a.xsl\"?>\n<r/>\n"),
        })
        report = scan_tree(root)
        assert report["census"]["php_like_unscanned_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_xml_prefixed_constant_still_counts(self, tmp_path):
        # <?xmlfoo is NOT an XML declaration (word boundary): short-
        # tag PHP starting with an xml-prefixed constant still counts.
        root = _tree(tmp_path, {
            "entry.php": "<?php unserialize($_GET['x']);\n",
            "odd.inc": "<?xmlfoo();\n",
        })
        report = scan_tree(root)
        assert report["census"]["php_like_unscanned_count"] == 1
        assert report["absence_tier"] == TIER_NONE


@_GRAMMAR
class TestUnresolvedParents:
    """An out-of-tree parent hands its child every inherited magic
    method — extends must resolve in tree (or to a PHP-internal base)
    or the completeness claim breaks."""

    def test_qualified_out_of_tree_parent_blocks(self, tmp_path):
        src = ("<?php\nclass SessionCache extends "
               "Vendor\\Framework\\BufferedHandler { public $c; }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert "unresolved-parents" in (
            report["census"]["incomplete_reasons"])
        assert ("vendor\\framework\\bufferedhandler"
                in report["census_detail"]["unresolved_parents"])
        assert report["absence_tier"] == TIER_NONE

    def test_bare_out_of_tree_parent_blocks(self, tmp_path):
        src = ("<?php\nclass SessionCache extends BufferedHandler "
               "{ public $c; }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_internal_base_classes_do_not_block(self, tmp_path):
        src = ("<?php\nclass MyError extends Exception { }\n"
               "class OtherError extends \\RuntimeException { }\n"
               "class Weird extends STDCLASS { }\n")
        root = _tree(tmp_path, {"e.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 0
        assert report["census"]["complete"] is True
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_in_tree_parent_resolves_across_files(self, tmp_path):
        root = _tree(tmp_path, {
            "parent.php": "<?php class BaseThing { }\n",
            "child.php": "<?php class Child extends basething { }\n",
        })
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_namespace_qualified_never_resolves_by_terminal_name(
            self, tmp_path):
        # Vendor\Exception is NOT the internal Exception, and it is
        # not the in-tree Exception either — qualified targets
        # resolve only against fully-qualified in-tree declarations,
        # never by terminal name and never via the internal-base
        # allowlist (fail closed).
        root = _tree(tmp_path, {
            "g.php": ("<?php\nclass E extends Vendor\\Exception "
                      "{ }\n"),
        })
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_interface_extends_is_exempt(self, tmp_path):
        # Interface methods carry no bodies in PHP — no trigger code
        # can ride in through an interface parent.
        root = _tree(tmp_path, {
            "i.php": ("<?php\ninterface Wide extends "
                      "Psr\\Container\\ContainerInterface { }\n"),
        })
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_anonymous_class_extends_counts(self, tmp_path):
        root = _tree(tmp_path, {
            "a.php": ("<?php\n$h = new class extends "
                      "Vendor\\Handler { };\n"),
        })
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert report["absence_tier"] == TIER_NONE


@_GRAMMAR
class TestNamespaceParentResolution:
    """Inside a namespace a bare class name resolves to the CURRENT
    namespace — PHP classes have NO global fallback. The internal-base
    allowlist therefore applies only to global-context bare names and
    leading-backslash references; a namespaced bare name resolves
    against in-tree declarations in that namespace or breaks the
    census."""

    def test_namespaced_bare_internal_name_blocks(self, tmp_path):
        # App\Exception, not the internal Exception: out of tree.
        src = ("<?php\nnamespace App;\n"
               "class C extends Exception { public $c; }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert "unresolved-parents" in (
            report["census"]["incomplete_reasons"])
        assert ("app\\exception"
                in report["census_detail"]["unresolved_parents"])
        assert report["absence_tier"] == TIER_NONE

    def test_namespaced_bare_resolves_in_same_namespace(
            self, tmp_path):
        src = ("<?php\nnamespace App;\n"
               "class Base { }\nclass C extends Base { }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_namespaced_bare_resolves_across_files(self, tmp_path):
        root = _tree(tmp_path, {
            "base.php": "<?php\nnamespace App;\nclass Base { }\n",
            "child.php": ("<?php\nnamespace App;\n"
                          "class C extends BASE { }\n"),
        })
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_cross_namespace_bare_name_does_not_resolve(
            self, tmp_path):
        root = _tree(tmp_path, {
            "base.php": "<?php\nnamespace A;\nclass Base { }\n",
            "child.php": ("<?php\nnamespace B;\n"
                          "class C extends Base { }\n"),
        })
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_braced_namespace_bare_internal_name_blocks(
            self, tmp_path):
        src = ("<?php\nnamespace App {\n"
               "    class C extends Exception { }\n}\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_braced_global_namespace_keeps_allowlist(self, tmp_path):
        src = ("<?php\nnamespace {\n"
               "    class C extends Exception { }\n}\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_second_unbraced_namespace_region_applies(self, tmp_path):
        # After a second unbraced namespace declaration, bare names
        # resolve against the SECOND namespace.
        src = ("<?php\nnamespace A;\nclass Base { }\n"
               "namespace B;\nclass C extends Base { }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_leading_backslash_internal_inside_namespace_allowed(
            self, tmp_path):
        # \Exception is explicitly global — the allowlist applies.
        src = ("<?php\nnamespace App;\n"
               "class C extends \\Exception { }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_relative_name_extends_resolves_and_blocks(self, tmp_path):
        # namespace\Local means <current namespace>\Local.
        ok = ("<?php\nnamespace App;\nclass Local { }\n"
              "class C extends namespace\\Local { }\n")
        root = _tree(tmp_path, {"g.php": ok})
        assert scan_tree(root)["census"][
            "unresolved_parent_count"] == 0
        go.reset_scan_memo()
        bad = ("<?php\nnamespace App;\n"
               "class C extends namespace\\Missing { }\n")
        root2 = _tree(tmp_path / "b", {"g.php": bad})
        report = scan_tree(root2)
        assert report["census"]["unresolved_parent_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_qualified_name_resolves_against_namespaced_declaration(
            self, tmp_path):
        # Declarations are tracked fully qualified, so a qualified
        # reference to an in-tree namespaced class resolves.
        root = _tree(tmp_path, {
            "base.php": "<?php\nnamespace App;\nclass Base { }\n",
            "child.php": "<?php\nclass C extends App\\Base { }\n",
        })
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE


@_GRAMMAR
class TestImportAliasParentResolution:
    """``use`` imports rebind bare names inside their own namespace
    block (declaration point onward) — an aliased parent resolves to
    the imported FQN (in-tree declarations only), never to the
    internal-base allowlist."""

    def test_explicit_alias_masking_internal_name_blocks(
            self, tmp_path):
        src = ("<?php\nuse OtherNS\\Evil as Exception;\n"
               "class C extends Exception { public $c; }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert "unresolved-parents" in (
            report["census"]["incomplete_reasons"])
        assert ("otherns\\evil"
                in report["census_detail"]["unresolved_parents"])
        assert report["absence_tier"] == TIER_NONE

    def test_implicit_alias_masks(self, tmp_path):
        src = ("<?php\nuse OtherNS\\Exception;\n"
               "class C extends Exception { }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert ("otherns\\exception"
                in report["census_detail"]["unresolved_parents"])
        assert report["absence_tier"] == TIER_NONE

    def test_group_use_alias_masks(self, tmp_path):
        src = ("<?php\nuse OtherNS\\{Evil as Exception};\n"
               "class C extends Exception { }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_group_use_implicit_alias_masks(self, tmp_path):
        src = ("<?php\nuse OtherNS\\{Exception, Other};\n"
               "class C extends Exception { }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_alias_resolving_to_in_tree_class_resolves(self, tmp_path):
        root = _tree(tmp_path, {
            "lib.php": "<?php\nnamespace Lib;\nclass Base { }\n",
            "c.php": ("<?php\nuse Lib\\Base as B;\n"
                      "class C extends B { }\n"),
        })
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_alias_applies_inside_namespace(self, tmp_path):
        # The alias wins over namespace prefixing.
        root = _tree(tmp_path, {
            "lib.php": "<?php\nnamespace Lib;\nclass Base { }\n",
            "c.php": ("<?php\nnamespace App;\nuse Lib\\Base;\n"
                      "class C extends Base { }\n"),
        })
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_function_and_const_imports_do_not_mask(self, tmp_path):
        # ``use function`` / ``use const`` never apply to class-name
        # resolution — they must not strip the allowlist path.
        src = ("<?php\nuse function OtherNS\\exception;\n"
               "use const OtherNS\\EXCEPTION;\n"
               "class C extends Exception { }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_group_function_import_does_not_mask(self, tmp_path):
        src = ("<?php\nuse OtherNS\\{function exception, "
               "const EXCEPTION};\n"
               "class C extends Exception { }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE


@_GRAMMAR
class TestTraitNamespaceResolution:
    """Trait ``use`` inside a class body resolves by the same
    namespace and import rules as ``extends`` — a bare name inside a
    namespace never grabs a same-file trait from ANOTHER namespace,
    and an import alias redirects resolution out of tree."""

    def test_cross_namespace_decoy_trait_does_not_resolve(
            self, tmp_path):
        # The benign A\T must not satisfy B\C's `use T;` — that
        # resolves to B\T, which is not declared anywhere.
        src = ("<?php\nnamespace A;\n"
               "trait T { public function helper() { } }\n"
               "namespace B;\nclass C { use T; }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_trait_count"] == 1
        assert "unresolved-traits" in (
            report["census"]["incomplete_reasons"])
        assert report["absence_tier"] == TIER_NONE

    def test_same_namespace_trait_resolves(self, tmp_path):
        src = ("<?php\nnamespace A;\n"
               "trait T { public function helper() { } }\n"
               "class C { use T; }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_trait_count"] == 0
        assert report["census"]["complete"] is True
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_import_aliased_trait_does_not_resolve_bare_decoy(
            self, tmp_path):
        # `use OtherNS\Evil as T;` redirects the class's `use T;`
        # out of tree — the same-file A\T decoy must not satisfy it.
        src = ("<?php\nnamespace A {\n"
               "    trait T { public function helper() { } }\n}\n"
               "namespace B {\n"
               "    use OtherNS\\Evil as T;\n"
               "    class C { use T; }\n}\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_trait_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_qualified_trait_use_resolves_in_tree(self, tmp_path):
        # Fully-qualified trait use resolves against the in-tree
        # declaration (and its methods merge).
        src = ("<?php\nnamespace A;\n"
               "trait T { public function helper() { } }\n"
               "namespace B;\nclass C { use \\A\\T; }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_trait_count"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_enum_trait_use_out_of_tree_counts(self, tmp_path):
        src = ("<?php\nenum Suit {\n    use MissingTrait;\n"
               "    case H;\n}\n")
        root = _tree(tmp_path, {"e.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_trait_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_enum_trait_use_in_tree_resolves(self, tmp_path):
        src = ("<?php\ntrait H { public function x() { } }\n"
               "enum Suit { use H; case A; }\n")
        root = _tree(tmp_path, {"e.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_trait_count"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_anonymous_class_trait_use_out_of_tree_counts(
            self, tmp_path):
        src = "<?php\n$x = new class { use MissingTrait; };\n"
        root = _tree(tmp_path, {"a.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_trait_count"] == 1
        assert report["absence_tier"] == TIER_NONE


class TestAsciiLower:
    """PHP name identity folds ASCII A-Z ONLY — ``str.lower()`` folds
    full Unicode and would conflate distinct PHP identifiers."""

    def test_folds_ascii_uppercase(self) -> None:
        assert go._ascii_lower("__DESTRUCT") == "__destruct"
        assert go._ascii_lower("A\\B\\Cls") == "a\\b\\cls"

    def test_kelvin_sign_not_folded(self) -> None:
        # U+212A KELVIN SIGN: str.lower() folds it to "k"; PHP treats
        # it as a distinct identifier byte sequence.
        assert go._ascii_lower("\u212a") == "\u212a"
        assert go._ascii_lower("\u212ahelper") == "\u212ahelper"

    def test_dotted_capital_i_not_folded(self) -> None:
        # U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE lowercases to
        # a TWO-codepoint sequence under str.lower().
        assert go._ascii_lower("İ") == "İ"

    def test_non_letter_ascii_untouched(self) -> None:
        assert go._ascii_lower("_x9$\\") == "_x9$\\"


@_GRAMMAR
class TestUnicodeNameIdentity:
    """Class/trait name matching is ASCII-case-insensitive ONLY — a
    Unicode letter that Python folds onto an ASCII letter names a
    DIFFERENT PHP class, which PHP autoloads out of tree."""

    def test_kelvin_parent_does_not_match_ascii_decoy(
            self, tmp_path: Path) -> None:
        # extends <U+212A>helper: str.lower() folds the parent onto
        # the in-tree ASCII Khelper; PHP autoloads the DISTINCT
        # Kelvin-named class.
        root = _tree(tmp_path, {
            "decoy.php": "<?php\nclass Khelper { }\n",
            "g.php": ("<?php\nclass Evil extends \u212ahelper "
                      "{ public $cmd; }\n"),
        })
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert "unresolved-parents" in (
            report["census"]["incomplete_reasons"])
        assert report["absence_tier"] == TIER_NONE

    def test_kelvin_trait_use_does_not_match_ascii_decoy(
            self, tmp_path: Path) -> None:
        src = ("<?php\ntrait Khelper { public function h() { } }\n"
               "class Evil { use \u212ahelper; public $cmd; }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_trait_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_ascii_case_variant_parent_still_resolves(
            self, tmp_path: Path) -> None:
        # PHP class names ARE case-insensitive over ASCII.
        root = _tree(tmp_path, {
            "lib.php": "<?php\nclass KHelper { }\n",
            "g.php": "<?php\nclass C extends kHELPER { }\n",
        })
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE


@_GRAMMAR
class TestAliasNamespaceScoping:
    """``use`` imports bind per namespace block, from the declaration
    point onward — never file-wide. An alias declared in one block
    must not resolve references in another block (PHP resolves those
    under THEIR OWN namespace and autoloads out of tree)."""

    def test_alias_does_not_leak_into_next_unbraced_namespace(
            self, tmp_path: Path) -> None:
        # Namespace A's alias must not satisfy namespace B's bare
        # `extends Exception` — PHP resolves that as B\Exception.
        root = _tree(tmp_path, {
            "decoy.php": "<?php\nnamespace Some;\nclass Benign { }\n",
            "g.php": ("<?php\nnamespace A;\n"
                      "use Some\\Benign as Exception;\n"
                      "namespace B;\n"
                      "class Evil extends Exception { public $cmd; }\n"),
        })
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert ("b\\exception"
                in report["census_detail"]["unresolved_parents"])
        assert report["absence_tier"] == TIER_NONE

    def test_alias_does_not_leak_into_next_braced_namespace(
            self, tmp_path: Path) -> None:
        root = _tree(tmp_path, {
            "decoy.php": "<?php\nnamespace Some;\nclass Benign { }\n",
            "g.php": ("<?php\nnamespace A {\n"
                      "    use Some\\Benign as Exception;\n}\n"
                      "namespace B {\n"
                      "    class Evil extends Exception "
                      "{ public $cmd; }\n}\n"),
        })
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert ("b\\exception"
                in report["census_detail"]["unresolved_parents"])
        assert report["absence_tier"] == TIER_NONE

    def test_alias_does_not_leak_across_trait_use_blocks(
            self, tmp_path: Path) -> None:
        # Same-file decoy trait: namespace A's alias must not resolve
        # namespace B's `use Helper;` — PHP resolves B\Helper.
        src = ("<?php\nnamespace Some;\n"
               "trait Benign { public function h() { } }\n"
               "namespace A;\n"
               "use Some\\Benign as Helper;\n"
               "namespace B;\n"
               "class Evil { use Helper; public $cmd; }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_trait_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_alias_does_not_apply_before_its_declaration(
            self, tmp_path: Path) -> None:
        # PHP applies an import from its declaration point onward —
        # a reference BEFORE the `use` resolves under the namespace
        # alone (here: the global VendorBase, out of tree).
        src = ("<?php\nnamespace Some {\n"
               "    class Benign { }\n}\n"
               "namespace {\n"
               "    class Probe extends VendorBase { public $cmd; }\n"
               "    use Some\\Benign as VendorBase;\n}\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert ("vendorbase"
                in report["census_detail"]["unresolved_parents"])
        assert report["absence_tier"] == TIER_NONE

    def test_alias_applies_from_declaration_to_block_end(
            self, tmp_path: Path) -> None:
        # Guard: within its own block, after its declaration, the
        # alias still resolves in-tree — even with a later block in
        # the same file.
        root = _tree(tmp_path, {
            "lib.php": "<?php\nnamespace Lib;\nclass Base { }\n",
            "g.php": ("<?php\nnamespace A;\n"
                      "use Lib\\Base as LocalBase;\n"
                      "class C extends LocalBase { }\n"
                      "namespace Z;\n"
                      "class Other { }\n"),
        })
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE


class TestWindowIndexSemantics:
    """Hermetic pins for the byte-window stabbing index — it must
    mirror the linear-scan rule it replaced exactly: among covering
    windows the greatest start wins, same-start ties go to the
    earliest-added window, windows are half-open ``[start, end)``,
    and a byte outside every window answers ``None``."""

    def test_innermost_latest_wins(self) -> None:
        idx = go._WindowIndex([(0, 100, "outer"), (10, 50, "inner")])
        assert idx.at(5) == "outer"
        assert idx.at(10) == "inner"
        assert idx.at(49) == "inner"
        assert idx.at(50) == "outer"
        assert idx.at(99) == "outer"

    def test_half_open_and_outside(self) -> None:
        idx = go._WindowIndex([(10, 20, "w")])
        assert idx.at(9) is None
        assert idx.at(10) == "w"
        assert idx.at(19) == "w"
        assert idx.at(20) is None
        assert idx.at(10_000) is None

    def test_same_start_tie_goes_to_earliest_added(self) -> None:
        idx = go._WindowIndex([(0, 30, "first"), (0, 60, "second")])
        assert idx.at(0) == "first"
        assert idx.at(29) == "first"
        assert idx.at(30) == "second"
        assert idx.at(60) is None

    def test_gap_between_windows_is_none(self) -> None:
        idx = go._WindowIndex([(0, 10, "a"), (20, 30, "b")])
        assert idx.at(9) == "a"
        assert idx.at(15) is None
        assert idx.at(20) == "b"

    def test_empty_window_never_covers(self) -> None:
        idx = go._WindowIndex([(5, 5, "zero")])
        assert idx.at(5) is None

    def test_empty_index(self) -> None:
        idx = go._WindowIndex([])
        assert idx.at(0) is None


class TestNameContextScale:
    """The name-resolution tables are queried once per reference, so
    lookups must stay near-constant as the tables grow. The replaced
    per-query linear scans made whole-file resolution quadratic: a
    machine-generated file with tens of thousands of imports and
    references cost minutes of wall time. Bounds are deliberately
    generous — the indexed run finishes in well under a second even
    on a loaded machine, while the quadratic shape needs over a
    minute — so they discriminate without wall-clock flakiness."""

    def test_alias_lookups_scale_to_import_walls(self) -> None:
        n = 60_000
        span = 10 * n
        ctx = go._NameContext()
        ctx.class_aliases.extend(
            (i, span, f"a{i}", f"ns\\c{i}") for i in range(n))
        t0 = time.monotonic()
        hits = sum(
            1 for i in range(n)
            if ctx.alias_for(f"a{i}", span - 1) == f"ns\\c{i}")
        elapsed = time.monotonic() - t0
        assert hits == n
        assert elapsed < 10.0

    def test_same_alias_window_pile_is_indexed(self) -> None:
        # All windows share one alias name: the innermost-latest rule
        # must hold at every probe, still without a per-query scan.
        n = 60_000
        ctx = go._NameContext()
        ctx.class_aliases.extend(
            (i, n + 1, "p", f"ns\\c{i}") for i in range(n))
        t0 = time.monotonic()
        ok = all(
            ctx.alias_for("p", b) == f"ns\\c{b}" for b in range(n))
        elapsed = time.monotonic() - t0
        assert ok
        assert ctx.alias_for("p", n) == f"ns\\c{n - 1}"
        assert ctx.alias_for("p", n + 1) is None
        assert elapsed < 10.0

    def test_namespace_lookups_scale(self) -> None:
        n = 60_000
        ctx = go._NameContext()
        ctx.regions.extend(
            (2 * i, 2 * i + 1, f"ns{i}") for i in range(n))
        t0 = time.monotonic()
        ok = all(
            ctx.namespace_at(2 * i) == f"ns{i}" for i in range(n))
        elapsed = time.monotonic() - t0
        assert ok
        assert ctx.namespace_at(2 * n) == ""
        assert ctx.namespace_at(1) == ""
        assert elapsed < 10.0


@_GRAMMAR
class TestConditionalDeclarationResolution:
    """Only unconditional top-level declarations (direct children of
    the program or of a namespace body) bind at PHP compile time — a
    class/trait inside an ``if`` body or a never-called function must
    never satisfy parent/trait resolution, while its trigger surface
    still over-counts (fail closed)."""

    def test_if_wrapped_decoy_class_does_not_resolve(
            self, tmp_path: Path) -> None:
        root = _tree(tmp_path, {
            "decoy.php": ("<?php\nif (PHP_VERSION_ID < 0) {\n"
                          "    class VendorBase { }\n}\n"),
            "g.php": ("<?php\nclass Evil extends VendorBase "
                      "{ public $cmd; }\n"),
        })
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert ("vendorbase"
                in report["census_detail"]["unresolved_parents"])
        assert report["absence_tier"] == TIER_NONE

    def test_function_nested_decoy_class_does_not_resolve(
            self, tmp_path: Path) -> None:
        root = _tree(tmp_path, {
            "decoy.php": ("<?php\nfunction never_called() {\n"
                          "    class VendorBase { }\n}\n"),
            "g.php": ("<?php\nclass Evil extends VendorBase "
                      "{ public $cmd; }\n"),
        })
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_if_wrapped_decoy_trait_does_not_resolve(
            self, tmp_path: Path) -> None:
        src = ("<?php\nif (PHP_VERSION_ID < 0) {\n"
               "    trait VendorTrait { public function h() { } }\n}\n"
               "class Evil { use VendorTrait; public $cmd; }\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["census"]["unresolved_trait_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_braced_namespace_toplevel_still_resolves(
            self, tmp_path: Path) -> None:
        # Guard: direct children of a namespace body keep resolution
        # authority (class parent and trait alike; trait resolution
        # is same-file by design, so all three live together).
        root = _tree(tmp_path, {
            "lib.php": ("<?php\nnamespace Lib {\n"
                        "    class Base { }\n"
                        "    trait Extra { public function h() { } }\n"
                        "    class C extends Base { use Extra; }\n"
                        "}\n"),
        })
        report = scan_tree(root)
        assert report["census"]["unresolved_parent_count"] == 0
        assert report["census"]["unresolved_trait_count"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_conditional_class_surface_still_counts(
            self, tmp_path: Path) -> None:
        # Over-count preserved: a magic method inside a conditional
        # class still blocks the promotable tier.
        src = ("<?php\nif (PHP_VERSION_ID < 0) {\n"
               "    class Maybe { public function __destruct() { } }\n"
               "}\n")
        root = _tree(tmp_path, {"g.php": src})
        report = scan_tree(root)
        assert report["pop_surface"]["by_method"]["__destruct"] == 1
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND


@_GRAMMAR
class TestWalkSkippedDirs:
    """Never-walked dirs are probed: PHP-like content inside one
    breaks completeness instead of silently vanishing."""

    def test_node_modules_gadget_blocks(self, tmp_path):
        root = _tree(tmp_path, {
            "entry.php": "<?php unserialize($_GET['x']);\n",
            "node_modules/pkg/gadget.php": (
                "<?php class Evil { public $c;\n"
                "function __destruct() { system($this->c); } }\n"),
        })
        report = scan_tree(root)
        assert report["census"]["walk_skipped_dirs_with_php_count"] == 1
        assert "walk-skipped-dirs" in (
            report["census"]["incomplete_reasons"])
        assert ("node_modules" in
                report["census_detail"]["walk_skipped_dirs_with_php"])
        assert report["absence_tier"] == TIER_NONE

    def test_git_dir_gadget_blocks(self, tmp_path):
        root = _tree(tmp_path, {
            "entry.php": "<?php unserialize($_GET['x']);\n",
            ".git/hooks/post-checkout.php": (
                "<?php class Evil { public $c;\n"
                "function __destruct() { system($this->c); } }\n"),
        })
        report = scan_tree(root)
        assert report["census"]["walk_skipped_dirs_with_php_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_php_free_skipped_dir_does_not_block(self, tmp_path):
        root = _tree(tmp_path, {
            "entry.php": "<?php unserialize($_GET['x']);\n",
            "node_modules/pkg/index.js": "console.log(1);\n",
            "node_modules/pkg/package.json": "{}\n",
        })
        report = scan_tree(root)
        assert report["census"]["walk_skipped_dirs_with_php_count"] == 0
        assert report["census"]["complete"] is True
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_binary_heads_in_git_do_not_false_positive(self, tmp_path):
        root = _tree(tmp_path, {
            "entry.php": "<?php unserialize($_GET['x']);\n",
        })
        objects = root / ".git" / "objects" / "aa"
        objects.mkdir(parents=True)
        # zlib-like binary head containing "<?" AND a NUL: the NUL
        # guard must reject it (PHP source cannot contain NUL).
        (objects / "bb0123").write_bytes(b"x\x9c<?\x00\xffgarbage")
        report = scan_tree(root)
        assert report["census"]["walk_skipped_dirs_with_php_count"] == 0
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_extensionless_short_tag_hook_blocks(self, tmp_path):
        root = _tree(tmp_path, {
            "entry.php": "<?php unserialize($_GET['x']);\n",
        })
        hooks = root / ".git" / "hooks"
        hooks.mkdir(parents=True)
        (hooks / "post-checkout").write_text(
            "<? system($_GET['c']);\n")
        report = scan_tree(root)
        assert report["census"]["walk_skipped_dirs_with_php_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_symlinks_do_not_burn_probe_budget(self, tmp_path):
        # Symlinks are never opened — they must not consume the
        # content-probe budget and shadow a real PHP-like file
        # sorted after them.
        root = _tree(tmp_path, {
            "entry.php": "<?php unserialize($_GET['x']);\n",
        })
        skipdir = root / "node_modules" / "pkg"
        skipdir.mkdir(parents=True)
        for i in range(go._SKIP_PROBE_MAX_CONTENT_FILES + 6):
            (skipdir / f"link{i:03d}").symlink_to(
                "/nonexistent-probe-target")
        (skipdir / "zz-hook").write_text("<? system($_GET['c']);\n")
        report = scan_tree(root)
        assert report["census"]["walk_skipped_dirs_with_php_count"] == 1
        assert report["absence_tier"] == TIER_NONE

    def test_inc_extension_in_skipped_dir_blocks_by_name(
            self, tmp_path):
        root = _tree(tmp_path, {
            "entry.php": "<?php unserialize($_GET['x']);\n",
            "node_modules/pkg/gadget.inc": (
                "<?php class Evil { function __destruct() {} }\n"),
        })
        report = scan_tree(root)
        assert report["census"]["walk_skipped_dirs_with_php_count"] == 1
        assert report["absence_tier"] == TIER_NONE


@_GRAMMAR
class TestDynamicDefinitionLegacyForms:
    """create_function bodies and /e-modified preg_replace patterns
    are eval-equivalent on the PHP versions that ship them."""

    def test_create_function_counts(self, tmp_path):
        src = ("<?php\ncreate_function('', 'class Evil { public $c; "
               "function __destruct() { system($this->c); } } "
               "return 1;');\n")
        root = _tree(tmp_path, {"d.php": src})
        report = scan_tree(root)
        assert (report["pop_surface"]["dynamic_definition_sites"]
                == 1)
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_preg_replace_e_modifier_counts(self, tmp_path):
        root = _tree(tmp_path, {
            "d.php": ("<?php\npreg_replace('/x/e', $_GET['r'], "
                      "$_GET['s']);\n"),
        })
        report = scan_tree(root)
        assert (report["pop_surface"]["dynamic_definition_sites"]
                == 1)
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_preg_replace_without_e_does_not_count(self, tmp_path):
        root = _tree(tmp_path, {
            "d.php": ("<?php\npreg_replace('/x/i', 'y', "
                      "$_GET['s']);\n"),
        })
        report = scan_tree(root)
        assert (report["pop_surface"]["dynamic_definition_sites"]
                == 0)
        assert report["absence_tier"] == TIER_NO_GADGET_SURFACE

    def test_preg_replace_dynamic_pattern_does_not_count(
            self, tmp_path):
        # A non-literal pattern is unknowable statically — the
        # eval/assert census covers the general dynamic-code shapes.
        root = _tree(tmp_path, {
            "d.php": "<?php\npreg_replace($p, 'y', $_GET['s']);\n",
        })
        report = scan_tree(root)
        assert (report["pop_surface"]["dynamic_definition_sites"]
                == 0)

    def test_preg_replace_e_via_double_quoted_escapes_counts(
            self, tmp_path):
        # "\x65" and "\145" both decode to 'e' inside double quotes —
        # the modifier check must see the DECODED pattern.
        root = _tree(tmp_path, {
            "a.php": ("<?php\npreg_replace(\"/x/\\x65\", $_GET['r'], "
                      "$_GET['s']);\n"),
            "b.php": ("<?php\npreg_replace(\"/y/\\145\", $_GET['r'], "
                      "$_GET['s']);\n"),
        })
        report = scan_tree(root)
        assert (report["pop_surface"]["dynamic_definition_sites"]
                == 2)
        assert report["absence_tier"] == TIER_NO_CHAINS_FOUND

    def test_preg_replace_single_quoted_escape_stays_literal(
            self, tmp_path):
        # Single quotes decode only \\ and \' — '\x65' stays four
        # raw chars, so the modifier run is not 'e'.
        root = _tree(tmp_path, {
            "a.php": ("<?php\npreg_replace('/x/\\x65', 'y', "
                      "$_GET['s']);\n"),
        })
        report = scan_tree(root)
        assert (report["pop_surface"]["dynamic_definition_sites"]
                == 0)

    def test_preg_e_bracket_delimiters(self):
        assert go._preg_pattern_has_e("{x}e") is True
        assert go._preg_pattern_has_e("(x)ie") is True
        assert go._preg_pattern_has_e("<x>m") is False
        assert go._preg_pattern_has_e("#x#e") is True
        assert go._preg_pattern_has_e("/x/E") is False  # PCRE is cased
        assert go._preg_pattern_has_e("") is False
        assert go._preg_pattern_has_e("ex") is False
