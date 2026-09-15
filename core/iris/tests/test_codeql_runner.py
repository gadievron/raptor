"""Tests for the IRIS CodeQL runner's SARIF parsing and spec keying."""

from __future__ import annotations

import json
import os
from pathlib import Path

from core.evidence import EvidenceTier
from core.iris.codeql_runner import _match_to_spec_keys, _parse_sarif_matches
from core.iris.specs import TaintSpec, compile_codeql_config, spec_message_token
from core.iris.store import _spec_key


def _write_sarif(path: Path) -> None:
    path.write_text(json.dumps({
        "runs": [{
            "results": [{
                "ruleId": "r1",
                "message": {"text": "flow into sink"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "a.c"},
                        "region": {"startLine": 7},
                    },
                }],
            }],
        }],
    }))


def test_parse_sarif_matches_normal(tmp_path: Path) -> None:
    p = tmp_path / "out.sarif"
    _write_sarif(p)
    matches = _parse_sarif_matches(p)
    assert matches == [{
        "file": "a.c", "line": 7,
        "message": "flow into sink", "rule_id": "r1",
    }]


def test_parse_sarif_matches_missing_file(tmp_path: Path) -> None:
    assert _parse_sarif_matches(tmp_path / "absent.sarif") == []


def test_parse_sarif_matches_oversize_refused(tmp_path: Path) -> None:
    """A SARIF over the bounded loader's cap degrades to no matches;
    the stat gate fires before any read (sparse truncate)."""
    p = tmp_path / "out.sarif"
    _write_sarif(p)
    os.truncate(p, 100 * 1024 * 1024 + 1)
    assert _parse_sarif_matches(p) == []


def test_match_key_uses_store_spec_key_format() -> None:
    """The runner's keys feed refine._promote_confirmed and
    store._drop_refuted, which both match on store._spec_key's format.
    A locally-formatted key silently matches NOTHING: no spec is ever
    promoted, no scorecard outcome recorded, and a CodeQL confirmation
    cannot cancel a Joern refutation."""
    spec = TaintSpec(function="read_pkt", file="src/net.c", role="source")
    keys = _match_to_spec_keys(
        {"message": f"flow found [src={spec_message_token(spec)}]"},
        [spec],
    )
    assert keys == [_spec_key(spec)]


def test_match_key_empty_when_no_spec_matches() -> None:
    spec = TaintSpec(function="read_pkt", file="src/net.c", role="source")
    assert _match_to_spec_keys({"message": "unrelated flow"}, [spec]) == []


# ------------------------------------------------------------------
# Query-message ↔ match-back join contract
# ------------------------------------------------------------------
#
# The join only works if the GENERATED query's result messages carry
# the per-spec join token — a fixed message string means
# confirmed_keys is always empty and CodeQL-backed XREF_BACKED
# promotion never fires; a free-text NAME search over the message
# false-confirms specs named after message boilerplate.


def _src() -> TaintSpec:
    return TaintSpec(function="read_input", file="io.c", role="source")


def _snk() -> TaintSpec:
    return TaintSpec(function="exec_cmd", file="cmd.c", role="sink")


def _path_msg(src: TaintSpec, snk: TaintSpec) -> str:
    # message.text as CodeQL renders the generated select: the $@
    # placeholder becomes a [label](N) link carrying srcName; the
    # sink name and the [src= sink=] token suffix are concatenated.
    return (
        f"IRIS: tainted data from [{src.function}](1) reaches "
        f"project-specific sink {snk.function} "
        f"[src={spec_message_token(src)} sink={spec_message_token(snk)}]"
    )


def test_path_query_binds_spec_tokens_into_message() -> None:
    src, snk = _src(), _snk()
    query = compile_codeql_config([src, snk])
    # Per-endpoint join tokens are bound beside the hasName()
    # constraint and concatenated into the message; the human-readable
    # name rides along as the $@ link label.
    assert f'srcKey = "{spec_message_token(src)}"' in query
    assert f'snkKey = "{spec_message_token(snk)}"' in query
    assert '" [src=" + srcKey + " sink=" + snkKey + "]"' in query
    assert "source.getNode(), srcName" in query


def test_sink_only_query_binds_spec_token_into_message() -> None:
    snk = _snk()
    query = compile_codeql_config([snk])
    assert f'snkKey = "{spec_message_token(snk)}"' in query
    assert '" [sink=" + snkKey + "]"' in query


def test_matching_result_confirms_both_endpoints_and_promotes() -> None:
    """End-to-end join: a result row whose message the generated query
    would produce → both endpoint keys confirmed → promotion fires."""
    from core.iris.refine import RefinementFeedback, _promote_confirmed

    src, snk = _src(), _snk()
    keys = _match_to_spec_keys({"message": _path_msg(src, snk)}, [src, snk])
    assert set(keys) == {_spec_key(src), _spec_key(snk)}

    promoted = _promote_confirmed(
        [src, snk], RefinementFeedback(confirmed_keys=keys),
    )
    assert all(
        s.evidence_tier == EvidenceTier.XREF_BACKED for s in promoted
    )


def test_non_matching_result_confirms_nothing() -> None:
    keys = _match_to_spec_keys(
        {"message": "IRIS: tainted data from [other_fn](1) reaches "
                    "project-specific sink another_fn"},
        [_src(), _snk()],
    )
    assert keys == []


def test_boilerplate_named_spec_not_false_confirmed() -> None:
    """Spec function names are LLM-derived from the studied repo —
    a spec named after query-message boilerplate ('data', 'sink',
    'IRIS', 'Argument') must NOT be confirmed by every result."""
    src, snk = _src(), _snk()
    boilerplate = [
        TaintSpec(function=w, file="x.c", role="sink")
        for w in ("data", "sink", "IRIS", "from", "reaches",
                  "project", "tainted", "specific", "Argument")
    ]
    keys = _match_to_spec_keys(
        {"message": _path_msg(src, snk)}, [src, snk, *boilerplate],
    )
    assert set(keys) == {_spec_key(src), _spec_key(snk)}


def test_same_name_specs_do_not_cross_bleed() -> None:
    """The token hashes (file, function, role): a same-named spec in
    a different file/role must not inherit the confirmation."""
    snk = _snk()
    twin_other_file = TaintSpec(
        function="exec_cmd", file="other.c", role="sink")
    twin_other_role = TaintSpec(
        function="exec_cmd", file="cmd.c", role="sanitiser")
    msg = (f"Argument to IRIS-identified project sink exec_cmd "
           f"[sink={spec_message_token(snk)}]")
    keys = _match_to_spec_keys(
        {"message": msg}, [snk, twin_other_file, twin_other_role],
    )
    assert keys == [_spec_key(snk)]


# ---------------------------------------------------------------------------
# make_codeql_tool_runner construction path
# ---------------------------------------------------------------------------
# The unit-level spec join above is only reachable if the runner can be
# BUILT. Pre-fix, construction called a QueryRunner.is_available()
# method that has never existed: with codeql installed it crashed with
# AttributeError, without it QueryRunner() raised RuntimeError — either
# way the caller's broad except buried it and the CodeQL-backed
# XREF_BACKED confirmation lane stayed dead end-to-end on every host.


def test_tool_runner_none_when_codeql_unavailable(tmp_path, monkeypatch):
    import packages.codeql

    from core.iris.codeql_runner import make_codeql_tool_runner
    monkeypatch.setattr(packages.codeql, "is_available", lambda: False)
    db = tmp_path / "db"
    db.mkdir()
    assert make_codeql_tool_runner(db, tmp_path) is None


def test_tool_runner_none_when_constructor_raises(tmp_path, monkeypatch):
    import packages.codeql
    import packages.codeql.query_runner as qr

    from core.iris.codeql_runner import make_codeql_tool_runner
    monkeypatch.setattr(packages.codeql, "is_available", lambda: True)

    class _Boom:
        def __init__(self) -> None:
            raise RuntimeError("CodeQL CLI not found")

    monkeypatch.setattr(qr, "QueryRunner", _Boom)
    db = tmp_path / "db"
    db.mkdir()
    assert make_codeql_tool_runner(db, tmp_path) is None


def _stub_cli(tmp_path, monkeypatch) -> None:
    stub = tmp_path / "bin" / "codeql"
    stub.parent.mkdir(exist_ok=True)
    stub.write_text("#!/bin/sh\nexit 0\n")
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", str(stub.parent))
    monkeypatch.delenv("CODEQL_CLI", raising=False)


def _stub_db(tmp_path, language: str = "cpp") -> Path:
    db = tmp_path / "db"
    db.mkdir(exist_ok=True)
    (db / "codeql-database.yml").write_text(
        f"primaryLanguage: {language}\n",
    )
    return db


def test_tool_runner_constructs_with_stub_cli(tmp_path, monkeypatch):
    """End-to-end construction smoke: a stub codeql on PATH must yield
    a CALLABLE runner (the lane exists), not a crash and not None."""
    from core.iris.codeql_runner import make_codeql_tool_runner
    _stub_cli(tmp_path, monkeypatch)
    db = _stub_db(tmp_path)
    runner = make_codeql_tool_runner(db, tmp_path)
    assert callable(runner)


def test_tool_runner_none_when_db_missing(tmp_path, monkeypatch):
    from core.iris.codeql_runner import make_codeql_tool_runner
    _stub_cli(tmp_path, monkeypatch)
    assert make_codeql_tool_runner(tmp_path / "nodb", tmp_path) is None


# ---------------------------------------------------------------------------
# Language resolution
# ---------------------------------------------------------------------------
# The sole production caller passes no language, so the factory's
# default IS the language policy. A hardcoded `language="cpp"` default
# meant every non-cpp database got a cpp-library query and every
# analyze failed — the language must come from the database itself.


def test_tool_runner_probes_db_language(tmp_path, monkeypatch):
    """No language argument → the database's primaryLanguage decides
    which language's query the runner generates."""
    from core.iris.codeql_runner import make_codeql_tool_runner
    from core.iris.specs import TaintSpec

    _stub_cli(tmp_path, monkeypatch)
    db = _stub_db(tmp_path, language="java")

    captured: dict = {}

    import packages.codeql.query_runner as qr

    class _Recorder:
        def run_local_pack(self, lang, db_, pack_dir, out_dir, **kwargs):
            captured["language"] = lang
            captured["kwargs"] = kwargs
            captured["query"] = (Path(pack_dir) / "IrisSpecs.ql").read_text()
            return qr.QueryResult(
                success=False, language=lang, database_path=db_,
                sarif_path=None, findings_count=0, duration_seconds=0.0,
                errors=["stub"], suite_name="raptor-iris-refine",
            )

    monkeypatch.setattr(qr, "QueryRunner", lambda: _Recorder())
    runner = make_codeql_tool_runner(db, tmp_path)
    assert runner is not None
    runner([
        TaintSpec(function="readIn", file="A.java", role="source"),
        TaintSpec(function="runIt", file="B.java", role="sink"),
    ])
    assert captured["language"] == "java"
    assert "import semmle.code.java.dataflow.DataFlow" in captured["query"]


def test_tool_runner_passes_vendored_roots_offline(tmp_path, monkeypatch):
    """A cached vendored stdlib root must reach the analyze as
    --additional-packs with the install skipped — under block_network
    that root is the only way the temp pack's `*` dep can resolve."""
    from core.iris.codeql_runner import make_codeql_tool_runner
    from core.iris.specs import TaintSpec

    _stub_cli(tmp_path, monkeypatch)
    db = _stub_db(tmp_path, language="cpp")
    vendored = tmp_path / "vendored" / "codeql"
    vendored.mkdir(parents=True)

    captured: dict = {}

    import packages.codeql.query_runner as qr

    class _Recorder:
        def run_local_pack(self, lang, db_, pack_dir, out_dir, **kwargs):
            captured["kwargs"] = kwargs
            return qr.QueryResult(
                success=False, language=lang, database_path=db_,
                sarif_path=None, findings_count=0, duration_seconds=0.0,
                errors=["stub"], suite_name="raptor-iris-refine",
            )

    monkeypatch.setattr(qr, "QueryRunner", lambda: _Recorder())
    monkeypatch.setattr(
        qr, "vendored_stdlib_roots", lambda _lang: [vendored],
    )
    runner = make_codeql_tool_runner(db, tmp_path)
    runner([TaintSpec(function="f", file="a.c", role="sink")])
    assert captured["kwargs"]["extra_analyze_args"] == (
        f"--additional-packs={vendored}",
    )
    assert captured["kwargs"]["skip_install"] is True


def test_tool_runner_none_when_db_language_unknown(tmp_path, monkeypatch):
    """A database whose language cannot be determined gets NO runner —
    a guessed language means a query for the wrong library."""
    from core.iris.codeql_runner import make_codeql_tool_runner
    _stub_cli(tmp_path, monkeypatch)
    db = tmp_path / "opaque-database-dir"
    db.mkdir()
    assert make_codeql_tool_runner(db, tmp_path) is None


def test_tool_runner_none_when_db_language_unsupported(tmp_path, monkeypatch):
    from core.iris.codeql_runner import make_codeql_tool_runner
    _stub_cli(tmp_path, monkeypatch)
    db = _stub_db(tmp_path, language="swift")
    assert make_codeql_tool_runner(db, tmp_path) is None


def test_tool_runner_explicit_language_wins(tmp_path, monkeypatch):
    """An explicit language bypasses the probe (caller asserts
    knowledge); an explicit UNSUPPORTED language still refuses."""
    from core.iris.codeql_runner import make_codeql_tool_runner
    _stub_cli(tmp_path, monkeypatch)
    db = tmp_path / "db"
    db.mkdir()  # no metadata at all
    assert callable(make_codeql_tool_runner(db, tmp_path, language="ruby"))
    assert make_codeql_tool_runner(db, tmp_path, language="rust") is None
