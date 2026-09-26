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
    REASON_TARGET_UNUSABLE,
    RULE_ABSENCE,
    RULE_CHAIN,
    RULE_CHAIN_CONDITIONAL,
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

    def test_absence_is_inconclusive_never_refuted(self, tmp_path):
        root = _tree(tmp_path, {"safe.php": _NO_GADGET})
        ev = run_gadget_oracle_check(
            root, "safe.php", "f", "no gadgets in tree")
        assert ev.outcome == "inconclusive"
        assert ev.rule_id == RULE_ABSENCE
        assert ev.reason == REASON_NO_GADGETS_COMPLETE
        assert ev.census["complete"] is True
        assert ev.qualifier

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

    def test_never_suppression_grade_in_this_increment(self):
        assert ABSENCE_EARNS_SUPPRESSION is False


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
