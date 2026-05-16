"""Tests for the CodeQL and SMT adapters.

CodeQL tests mock subprocess (real DB build is multi-minute and requires
a source tree). SMT tests use real Z3 calls when available — the adapter
is a thin wrapper over packages/codeql/smt_path_validator and exercising
the real path catches integration issues mocks would mask.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.hypothesis_validation.adapters import (
    CodeQLAdapter,
    SMTAdapter,
)
from packages.hypothesis_validation.adapters.codeql import (
    _parse_sarif,
    _qlpack_yaml,
)
from packages.hypothesis_validation.adapters.smt import _parse_conditions


# CodeQL ----------------------------------------------------------------------

class TestCodeQLAdapterBasics:
    def test_name(self):
        assert CodeQLAdapter().name == "codeql"

    def test_describe_languages_includes_c_and_python(self):
        cap = CodeQLAdapter().describe()
        assert "c" in cap.languages
        assert "python" in cap.languages
        assert cap.syntax_example.strip()

    def test_describe_render_includes_dataflow(self):
        text = CodeQLAdapter().describe().render_for_prompt()
        assert "dataflow" in text.lower() or "data flow" in text.lower()

    def test_unavailable_when_no_database(self):
        with patch("shutil.which", return_value="/usr/bin/codeql"):
            a = CodeQLAdapter()
            assert not a.is_available()

    def test_unavailable_when_no_binary(self, tmp_path):
        db = tmp_path / "db"
        db.mkdir()
        with patch("shutil.which", return_value=None):
            a = CodeQLAdapter(database_path=db)
            assert not a.is_available()

    def test_unavailable_when_database_missing(self, tmp_path):
        with patch("shutil.which", return_value="/usr/bin/codeql"):
            a = CodeQLAdapter(database_path=tmp_path / "nonexistent")
            assert not a.is_available()

    def test_available_when_db_and_binary_present(self, tmp_path):
        db = tmp_path / "db"
        db.mkdir()
        with patch("shutil.which", return_value="/usr/bin/codeql"):
            a = CodeQLAdapter(database_path=db)
            assert a.is_available()

    def test_set_database_updates_availability(self, tmp_path):
        with patch("shutil.which", return_value="/usr/bin/codeql"):
            a = CodeQLAdapter()
            assert not a.is_available()
            db = tmp_path / "db"
            db.mkdir()
            a.set_database(db)
            assert a.is_available()


class TestCodeQLAdapterRun:
    def _adapter(self, tmp_path):
        db = tmp_path / "db"
        db.mkdir()
        # sandbox=False so subprocess.run mocks work directly
        a = CodeQLAdapter(
            database_path=db, codeql_bin="/usr/bin/codeql", sandbox=False,
        )
        return a, db

    def test_run_no_binary(self, tmp_path):
        db = tmp_path / "db"
        db.mkdir()
        with patch("shutil.which", return_value=None):
            a = CodeQLAdapter(database_path=db, sandbox=False)
        ev = a.run("import cpp\nselect 1\n", tmp_path)
        assert not ev.success
        assert "not installed" in ev.error

    def test_run_no_database(self, tmp_path):
        a = CodeQLAdapter(codeql_bin="/usr/bin/codeql", sandbox=False)
        ev = a.run("import cpp\nselect 1\n", tmp_path)
        assert not ev.success
        assert "no CodeQL database" in ev.error

    def test_run_database_missing(self, tmp_path):
        a = CodeQLAdapter(
            database_path=tmp_path / "nonexistent",
            codeql_bin="/usr/bin/codeql",
            sandbox=False,
        )
        ev = a.run("import cpp\nselect 1\n", tmp_path)
        assert not ev.success
        assert "not found" in ev.error

    def test_run_empty_rule(self, tmp_path):
        a, db = self._adapter(tmp_path)
        ev = a.run("", tmp_path)
        assert not ev.success
        assert "empty" in ev.error.lower()

    def test_run_subprocess_success(self, tmp_path):
        a, db = self._adapter(tmp_path)
        sarif = json.dumps({
            "runs": [{
                "results": [{
                    "ruleId": "raptor/x",
                    "message": {"text": "tainted size"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/a.c"},
                            "region": {"startLine": 42},
                        },
                    }],
                }],
            }],
        })

        def fake_run(cmd, **kwargs):
            # Find --output= arg, write SARIF there
            for arg in cmd:
                if arg.startswith("--output="):
                    Path(arg.split("=", 1)[1]).write_text(sarif)
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            ev = a.run("import cpp\nselect 1\n", tmp_path)
        assert ev.success
        assert len(ev.matches) == 1
        assert ev.matches[0]["file"] == "src/a.c"
        assert ev.matches[0]["line"] == 42
        assert "1 match" in ev.summary

    def test_run_subprocess_no_matches(self, tmp_path):
        a, db = self._adapter(tmp_path)

        def fake_run(cmd, **kwargs):
            for arg in cmd:
                if arg.startswith("--output="):
                    Path(arg.split("=", 1)[1]).write_text(
                        json.dumps({"runs": [{"results": []}]})
                    )
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            ev = a.run("import cpp\nselect 1\n", tmp_path)
        assert ev.success
        assert ev.matches == []
        assert "no matches" in ev.summary

    def test_run_subprocess_error(self, tmp_path):
        a, db = self._adapter(tmp_path)
        with patch("subprocess.run", return_value=MagicMock(
            returncode=1, stdout="", stderr="syntax error in query",
        )):
            ev = a.run("not valid ql", tmp_path)
        assert not ev.success
        assert "syntax error" in ev.error

    def test_run_subprocess_timeout(self, tmp_path):
        a, db = self._adapter(tmp_path)
        with patch("subprocess.run",
                   side_effect=__import__("subprocess").TimeoutExpired("codeql", 60)):
            ev = a.run("import cpp\nselect 1\n", tmp_path, timeout=60)
        assert not ev.success
        assert "timeout" in ev.error.lower()

    def test_run_subprocess_oserror(self, tmp_path):
        a, db = self._adapter(tmp_path)
        with patch("subprocess.run", side_effect=OSError("boom")):
            ev = a.run("import cpp\nselect 1\n", tmp_path)
        assert not ev.success
        assert "boom" in ev.error

    def test_run_no_sarif_produced(self, tmp_path):
        a, db = self._adapter(tmp_path)
        # subprocess returns 0 but no SARIF written
        with patch("subprocess.run", return_value=MagicMock(
            returncode=0, stdout="", stderr="",
        )):
            ev = a.run("import cpp\nselect 1\n", tmp_path)
        assert not ev.success


class TestQlPackYaml:
    def test_default_lang_is_cpp(self):
        yaml = _qlpack_yaml("/* no imports */\n")
        assert "codeql/cpp-all" in yaml

    def test_detects_python(self):
        yaml = _qlpack_yaml("import python\nselect 1\n")
        assert "codeql/python-all" in yaml

    def test_detects_java(self):
        yaml = _qlpack_yaml("import java\n")
        assert "codeql/java-all" in yaml

    def test_unknown_language_falls_back_to_cpp(self):
        yaml = _qlpack_yaml("import futurelang\n")
        assert "codeql/cpp-all" in yaml


class TestParseSarif:
    def test_empty_file(self, tmp_path):
        p = tmp_path / "x.sarif"
        p.write_text(json.dumps({"runs": []}))
        assert _parse_sarif(p) == []

    def test_missing_file(self, tmp_path):
        assert _parse_sarif(tmp_path / "nonexistent") == []

    def test_invalid_json(self, tmp_path):
        p = tmp_path / "x.sarif"
        p.write_text("not json")
        assert _parse_sarif(p) == []

    def test_basic_parse(self, tmp_path):
        p = tmp_path / "x.sarif"
        p.write_text(json.dumps({
            "runs": [{
                "results": [{
                    "ruleId": "r1",
                    "message": {"text": "msg"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "a.c"},
                            "region": {"startLine": 5},
                        },
                    }],
                }],
            }],
        }))
        m = _parse_sarif(p)
        assert len(m) == 1
        assert m[0]["file"] == "a.c"
        assert m[0]["line"] == 5
        assert m[0]["rule"] == "r1"


# SMT -------------------------------------------------------------------------

class TestSMTAdapterBasics:
    def test_name(self):
        assert SMTAdapter().name == "smt"

    def test_describe(self):
        cap = SMTAdapter().describe()
        text = cap.render_for_prompt()
        assert "feasibility" in text.lower() or "satisfiab" in text.lower()
        assert cap.languages == []  # language-agnostic


class TestParseConditions:
    def test_empty(self):
        assert _parse_conditions("") == []

    def test_blank_lines_ignored(self):
        c = _parse_conditions("\n\n\n")
        assert c == []

    def test_comments_ignored(self):
        c = _parse_conditions("# this is a comment\nsize > 0\n# another\n")
        assert len(c) == 1
        assert c[0].text == "size > 0"

    def test_negation_prefix(self):
        c = _parse_conditions("! size == 0\nsize > 0\n")
        assert len(c) == 2
        assert c[0].negated
        assert c[0].text == "size == 0"
        assert not c[1].negated

    def test_negation_with_no_text_skipped(self):
        c = _parse_conditions("!\n!  \n")
        assert c == []

    def test_step_indices_preserved(self):
        c = _parse_conditions("size > 0\nlen < 1024\n")
        # step_index reflects position in input
        indices = [cond.step_index for cond in c]
        assert indices == sorted(indices)


# Real Z3 integration tests — skipped when z3-solver not installed.

@pytest.mark.skipif(
    not SMTAdapter().is_available(),
    reason="z3-solver not installed",
)
class TestSMTAdapterIntegration:
    def test_unavailable_path(self):
        # When Z3 is available, this class runs. We exercise the real solver below.
        adapter = SMTAdapter()
        assert adapter.is_available()

    def test_satisfiable(self, tmp_path):
        a = SMTAdapter()
        ev = a.run("size > 0\nsize < 1024\n", tmp_path)
        assert ev.success
        assert "sat" in ev.summary
        # At least one witness in the model
        assert any(m.get("variable") == "size" for m in ev.matches)

    def test_unsatisfiable(self, tmp_path):
        a = SMTAdapter()
        # x cannot be both 0 and not 0
        ev = a.run("x == 0\nx != 0\n", tmp_path)
        assert ev.success
        assert "unsat" in ev.summary
        assert ev.matches == []

    def test_empty_rule_fails(self, tmp_path):
        a = SMTAdapter()
        ev = a.run("", tmp_path)
        assert not ev.success
        assert "no parseable conditions" in ev.error

    def test_only_comments_fails(self, tmp_path):
        a = SMTAdapter()
        ev = a.run("# just a comment\n", tmp_path)
        assert not ev.success

    def test_mixed_valid_and_invalid(self, tmp_path):
        a = SMTAdapter()
        # The first condition is fine; the second has unsupported syntax —
        # smt_path_validator buckets that as "unknown" but the first still
        # solves. The adapter should still report sat.
        ev = a.run("size > 0\nptr->field == 1\n", tmp_path)
        # At minimum: doesn't crash. May return sat (unparseable conditions
        # are dropped to unknown) or unknown depending on solver behaviour.
        assert ev.success or "unknown" in (ev.error or "").lower()


class TestSMTAdapterUnavailable:
    """Tests that work even when Z3 is absent."""

    def test_run_when_unavailable(self, tmp_path):
        a = SMTAdapter()
        with patch.object(a, "is_available", return_value=False):
            ev = a.run("size > 0\n", tmp_path)
        assert not ev.success
        assert "z3" in ev.error.lower()

    def test_run_with_empty_rule_fails_fast(self, tmp_path):
        a = SMTAdapter()
        with patch.object(a, "is_available", return_value=True):
            ev = a.run("", tmp_path)
        assert not ev.success
