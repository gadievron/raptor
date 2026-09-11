"""Tests for the CodeQL and SMT adapters.

CodeQL tests mock subprocess (real DB build is multi-minute and requires
a source tree). SMT tests use real Z3 calls when available — the adapter
is a thin wrapper over packages/codeql/smt_path_validator and exercising
the real path catches integration issues mocks would mask.
"""

import json
import logging
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

    def test_run_corrupt_sarif_is_tool_failure(self, tmp_path):
        """A written-but-unreadable SARIF is success=False, never a
        default-refuted zero-match success."""
        a, db = self._adapter(tmp_path)

        def fake_run(cmd, **kwargs):
            for arg in cmd:
                if arg.startswith("--output="):
                    Path(arg.split("=", 1)[1]).write_text("{corrupt")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            ev = a.run("import cpp\nselect 1\n", tmp_path)
        assert not ev.success
        assert "unreadable" in ev.error
        assert ev.matches == []

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


class TestCodeQLBatchPreconditionMessages:
    """run_prebuilt_queries_batch emits the same three distinct
    precondition messages as run() / run_prebuilt_query instead of one
    generic "codeql/database unavailable" string."""

    def test_no_cli_message_matches_siblings(self, tmp_path):
        db = tmp_path / "db"
        db.mkdir()
        with patch("shutil.which", return_value=None):
            a = CodeQLAdapter(database_path=db)
        results = a.run_prebuilt_queries_batch([Path("/pack/q.ql")])
        assert set(results) == {"/pack/q.ql"}
        ev = results["/pack/q.ql"]
        assert not ev.success
        assert ev.error == "codeql CLI is not installed"

    def test_no_database_configured_message_matches_siblings(self):
        a = CodeQLAdapter(codeql_bin="/usr/bin/codeql")
        results = a.run_prebuilt_queries_batch([Path("/pack/q.ql")])
        ev = results["/pack/q.ql"]
        assert not ev.success
        assert ev.error == "no CodeQL database configured (set_database() first)"

    def test_database_missing_message_matches_siblings(self, tmp_path):
        missing = tmp_path / "nonexistent-db"
        a = CodeQLAdapter(database_path=missing, codeql_bin="/usr/bin/codeql")
        results = a.run_prebuilt_queries_batch([Path("/pack/q.ql")])
        ev = results["/pack/q.ql"]
        assert not ev.success
        assert ev.error == f"CodeQL database not found: {missing}"

    def test_generic_message_no_longer_used(self, tmp_path):
        a = CodeQLAdapter(
            database_path=tmp_path / "nope", codeql_bin="/usr/bin/codeql",
        )
        results = a.run_prebuilt_queries_batch([Path("/pack/q.ql")])
        assert "codeql/database unavailable" not in results["/pack/q.ql"].error

    def test_empty_batch_returns_empty_dict(self, tmp_path):
        a = CodeQLAdapter(
            database_path=tmp_path / "nope", codeql_bin="/usr/bin/codeql",
        )
        assert a.run_prebuilt_queries_batch([]) == {}


class TestRunInlinePackInstallLogging:
    def test_pack_install_failure_logs_warning(self, tmp_path, caplog):
        """A failing inline `codeql pack install` in run() must emit a
        warning (matching the _ensure_pack_installed contract) instead
        of silently swallowing the exception."""
        db = tmp_path / "db"
        db.mkdir()
        a = CodeQLAdapter(
            database_path=db,
            codeql_bin=str(tmp_path / "no-such-codeql"),
            sandbox=False,
        )
        with caplog.at_level(
            logging.WARNING,
            logger="packages.hypothesis_validation.adapters.codeql",
        ):
            ev = a.run(
                "import cpp\nfrom Function f select f",
                target=db,
                env={"PATH": "/usr/bin"},
            )
        # The analyze step still fails loudly on its own.
        assert not ev.success
        assert "failed to invoke codeql" in ev.error
        # And the install failure is now observable in the log.
        assert any(
            "codeql pack install" in rec.getMessage() for rec in caplog.records
        )


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

    def test_missing_file_is_parse_failure(self, tmp_path):
        # None (tool failure), never [] — an unreadable SARIF must not
        # grade as a refuted "no matches".
        assert _parse_sarif(tmp_path / "nonexistent") is None

    def test_invalid_json_is_parse_failure(self, tmp_path):
        p = tmp_path / "x.sarif"
        p.write_text("not json")
        assert _parse_sarif(p) is None

    def test_hostile_start_line_is_parse_failure(self, tmp_path):
        # Extraction is inside the MUST-NOT-raise guard: a non-numeric
        # startLine reports a parse failure instead of raising.
        p = tmp_path / "x.sarif"
        p.write_text(json.dumps({
            "runs": [{
                "results": [{
                    "ruleId": "r1",
                    "message": {"text": "msg"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "a.c"},
                            "region": {"startLine": "NaN-ish"},
                        },
                    }],
                }],
            }],
        }))
        assert _parse_sarif(p) is None

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

    def test_mixed_valid_and_invalid_is_tool_failure(self, tmp_path):
        a = SMTAdapter()
        # The first condition is fine; the second has unsupported syntax
        # and gets dropped to "unknown". sat over the surviving subset is
        # NOT proof the full path is feasible, so the adapter must report
        # a tool failure naming the dropped condition rather than clean
        # confirming evidence over a near-empty check.
        ev = a.run("size > 0\nptr->field == 1\n", tmp_path)
        assert not ev.success
        assert "unparseable" in ev.error
        assert "ptr->field" in ev.error

    def test_fully_parsed_sat_still_confirms(self, tmp_path):
        # Companion direction: when EVERY condition parses, sat evidence
        # stays clean witness evidence — the partial-set failure above
        # must not swallow legitimate results.
        a = SMTAdapter()
        ev = a.run("size > 0\nsize < 1024\n", tmp_path)
        assert ev.success
        assert "sat" in ev.summary
        assert ev.matches

    def test_unsat_with_dropped_conditions_stays_sound(self, tmp_path):
        # unsat over a subset implies unsat over the whole set, so a
        # dropped condition must not degrade an unsat result to failure —
        # only annotate it.
        a = SMTAdapter()
        ev = a.run("x == 0\nx != 0\nptr->field == 1\n", tmp_path)
        assert ev.success
        assert "unsat" in ev.summary
        assert "excluded" in ev.summary
        assert ev.matches == []


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


class TestParseSarifBudget:
    def test_oversize_sarif_is_parse_failure(self, tmp_path: Path) -> None:
        """A SARIF over the bounded loader's cap is a tool failure
        (None), never an empty refutation. Sparse truncate: the stat
        gate fires before any read."""
        import os

        p = tmp_path / "x.sarif"
        p.write_text(json.dumps({"runs": []}))
        os.truncate(p, 100 * 1024 * 1024 + 1)
        assert _parse_sarif(p) is None


class TestPrebuiltSarifParseFailure:
    """run_prebuilt_query / run_prebuilt_queries_batch must convert a
    SARIF parse failure into failure evidence exactly like run() does —
    _parse_sarif returns None on unreadable output and the adapters
    MUST NOT raise (len(None) / iterating None are TypeErrors)."""

    def _adapter(self, tmp_path: Path) -> tuple[CodeQLAdapter, Path]:
        db = tmp_path / "db"
        db.mkdir()
        a = CodeQLAdapter(
            database_path=db, codeql_bin="/usr/bin/codeql", sandbox=False,
        )
        return a, db

    def _query(self, tmp_path: Path, name: str = "q.ql",
               qid: str | None = None) -> Path:
        q = tmp_path / name
        q.parent.mkdir(parents=True, exist_ok=True)
        header = f"/**\n * @id {qid}\n */\n" if qid else ""
        q.write_text(header + "import cpp\nselect 1\n")
        return q

    @staticmethod
    def _fake_run_writing(text: str):
        def fake_run(cmd, **kwargs):
            for arg in cmd:
                if arg.startswith("--output="):
                    Path(arg.split("=", 1)[1]).write_text(text)
            return MagicMock(returncode=0, stdout="", stderr="")
        return fake_run

    def test_prebuilt_corrupt_sarif_is_tool_failure(self, tmp_path):
        a, db = self._adapter(tmp_path)
        q = self._query(tmp_path)
        with patch("subprocess.run",
                   side_effect=self._fake_run_writing("{corrupt")):
            ev = a.run_prebuilt_query(q, tmp_path)
        assert not ev.success
        assert "unreadable" in ev.error
        assert ev.matches == []

    def test_prebuilt_valid_sarif_still_succeeds(self, tmp_path):
        a, db = self._adapter(tmp_path)
        q = self._query(tmp_path)
        sarif = json.dumps({"runs": [{"results": []}]})
        with patch("subprocess.run",
                   side_effect=self._fake_run_writing(sarif)):
            ev = a.run_prebuilt_query(q, tmp_path)
        assert ev.success
        assert "no matches" in ev.summary

    def test_batch_corrupt_sarif_is_tool_failure_for_every_query(self, tmp_path):
        a, db = self._adapter(tmp_path)
        q1 = self._query(tmp_path, "a/q1.ql")
        q2 = self._query(tmp_path, "b/q2.ql")
        with patch("subprocess.run",
                   side_effect=self._fake_run_writing("{corrupt")):
            results = a.run_prebuilt_queries_batch([q1, q2])
        assert set(results) == {str(q1), str(q2)}
        for ev in results.values():
            assert not ev.success
            assert "unreadable" in ev.error


class TestBatchAttribution:
    """Batch SARIF results map back to their originating query via
    @id / filename stem. Results that map to no known query must not
    vanish silently (the owning query would read as a clean refutable
    "no matches"), and a stem shared by two queries must not credit
    everything to whichever registered first."""

    def _adapter(self, tmp_path: Path) -> CodeQLAdapter:
        db = tmp_path / "db"
        db.mkdir(exist_ok=True)
        return CodeQLAdapter(
            database_path=db, codeql_bin="/usr/bin/codeql", sandbox=False,
        )

    def _query(self, tmp_path: Path, rel: str, qid: str | None = None) -> Path:
        q = tmp_path / rel
        q.parent.mkdir(parents=True, exist_ok=True)
        header = f"/**\n * @id {qid}\n */\n" if qid else ""
        q.write_text(header + "import cpp\nselect 1\n")
        return q

    @staticmethod
    def _sarif_with(rule_ids: list[str]) -> str:
        return json.dumps({
            "runs": [{
                "results": [
                    {
                        "ruleId": rid,
                        "message": {"text": f"hit for {rid}"},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/a.c"},
                                "region": {"startLine": 1},
                            },
                        }],
                    }
                    for rid in rule_ids
                ],
            }],
        })

    @staticmethod
    def _fake_run_writing(text: str):
        def fake_run(cmd, **kwargs):
            for arg in cmd:
                if arg.startswith("--output="):
                    Path(arg.split("=", 1)[1]).write_text(text)
            return MagicMock(returncode=0, stdout="", stderr="")
        return fake_run

    def test_unattributed_results_degrade_zero_match_queries(self, tmp_path):
        a = self._adapter(tmp_path)
        q1 = self._query(tmp_path, "a/first.ql", qid="raptor/first")
        q2 = self._query(tmp_path, "b/second.ql", qid="raptor/second")
        sarif = self._sarif_with(["raptor/first", "vendor/unknown-rule"])
        with patch("subprocess.run",
                   side_effect=self._fake_run_writing(sarif)):
            results = a.run_prebuilt_queries_batch([q1, q2])
        # The attributable match reaches its query.
        assert results[str(q1)].success
        assert len(results[str(q1)].matches) == 1
        # The zero-match query cannot claim a clean "no matches" while
        # an unattributed result exists — any of them could be its own.
        assert not results[str(q2)].success
        assert "could not be attributed" in results[str(q2)].error

    def test_fully_attributed_batch_keeps_clean_no_matches(self, tmp_path):
        # Direction guard: with every result attributed, a query with
        # zero matches keeps its refutation-capable clean result.
        a = self._adapter(tmp_path)
        q1 = self._query(tmp_path, "a/first.ql", qid="raptor/first")
        q2 = self._query(tmp_path, "b/second.ql", qid="raptor/second")
        sarif = self._sarif_with(["raptor/first"])
        with patch("subprocess.run",
                   side_effect=self._fake_run_writing(sarif)):
            results = a.run_prebuilt_queries_batch([q1, q2])
        assert results[str(q1)].success
        assert len(results[str(q1)].matches) == 1
        assert results[str(q2)].success
        assert results[str(q2)].matches == []
        assert "no matches" in results[str(q2)].summary

    def test_stem_collision_not_credited_to_first_query(self, tmp_path):
        # Two queries share the stem "q" and declare no @id; a result
        # with ruleId "q" is genuinely ambiguous. Crediting it to the
        # first-registered query would fabricate its evidence AND hand
        # the second a false refutation — both must degrade instead.
        a = self._adapter(tmp_path)
        q1 = self._query(tmp_path, "a/q.ql")
        q2 = self._query(tmp_path, "b/q.ql")
        sarif = self._sarif_with(["q"])
        with patch("subprocess.run",
                   side_effect=self._fake_run_writing(sarif)):
            results = a.run_prebuilt_queries_batch([q1, q2])
        assert results[str(q1)].matches == []
        assert not results[str(q1)].success
        assert not results[str(q2)].success


class TestEnsurePackInstalledCaching:
    """A failed `codeql pack install` must not be cached as installed —
    the cache would suppress the retry that could succeed once the
    operator fixes the environment."""

    def _pack(self, tmp_path: Path) -> tuple[Path, Path]:
        pack = tmp_path / "pack"
        pack.mkdir()
        (pack / "qlpack.yml").write_text("name: raptor/test-pack\n")
        q = pack / "q.ql"
        q.write_text("import cpp\nselect 1\n")
        return pack, q

    def test_failed_install_is_retried(self, tmp_path):
        from packages.hypothesis_validation.adapters.codeql import (
            _INSTALLED_PACK_DIRS,
            _ensure_pack_installed,
        )
        pack, q = self._pack(tmp_path)
        calls: list[list] = []

        def failing_runner(cmd, **kwargs):
            calls.append(cmd)
            return MagicMock(returncode=1, stdout="", stderr="registry unreachable")

        try:
            _ensure_pack_installed(q, "codeql", failing_runner, {})
            assert len(calls) == 1
            # Second call retries instead of hitting a poisoned cache.
            _ensure_pack_installed(q, "codeql", failing_runner, {})
            assert len(calls) == 2
        finally:
            _INSTALLED_PACK_DIRS.discard(pack.resolve())
            _INSTALLED_PACK_DIRS.discard(pack)

    def test_successful_install_is_cached(self, tmp_path):
        from packages.hypothesis_validation.adapters.codeql import (
            _INSTALLED_PACK_DIRS,
            _ensure_pack_installed,
        )
        pack, q = self._pack(tmp_path)
        calls: list[list] = []

        def ok_runner(cmd, **kwargs):
            calls.append(cmd)
            return MagicMock(returncode=0, stdout="", stderr="")

        try:
            _ensure_pack_installed(q, "codeql", ok_runner, {})
            _ensure_pack_installed(q, "codeql", ok_runner, {})
            assert len(calls) == 1
        finally:
            _INSTALLED_PACK_DIRS.discard(pack.resolve())
            _INSTALLED_PACK_DIRS.discard(pack)


@pytest.mark.skipif(
    not SMTAdapter().is_available(),
    reason="z3-solver not installed",
)
class TestSMTUnsatConclusiveFlag:
    """unsat is a definitive proof despite the empty match list — the
    evidence must carry empty_matches_conclusive so the verdict ladder
    can honour a confirmed reading of an infeasibility-phrased
    hypothesis, while sat evidence must NOT carry the flag."""

    def test_unsat_sets_flag(self, tmp_path):
        a = SMTAdapter()
        ev = a.run("x == 0\nx != 0\n", tmp_path)
        assert ev.success
        assert ev.matches == []
        assert ev.empty_matches_conclusive is True

    def test_sat_does_not_set_flag(self, tmp_path):
        a = SMTAdapter()
        ev = a.run("size > 0\nsize < 1024\n", tmp_path)
        assert ev.success
        assert ev.empty_matches_conclusive is False

    def test_unsat_summary_names_both_readings(self, tmp_path):
        # The evaluating LLM maps the proof onto the hypothesis's
        # phrasing from the summary text.
        a = SMTAdapter()
        ev = a.run("x == 0\nx != 0\n", tmp_path)
        assert "refutes" in ev.summary
        assert "confirms" in ev.summary
