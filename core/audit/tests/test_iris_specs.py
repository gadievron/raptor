"""Tests for core.audit.iris_specs — IRIS-pattern taint spec synthesis."""

import json

from core.audit.iris_specs import (
    TaintSpec,
    _escape_codeql,
    _escape_scala,
    compile_codeql_config,
    compile_joern_config,
    identify_candidates,
    parse_spec_response,
    specs_from_json,
    specs_to_json,
)
from core.evidence import EvidenceTier
from core.iris.specs import _escape_codeql as _iris_escape_codeql
from core.iris.specs import _escape_scala as _iris_escape_scala


class TestIdentifyCandidates:
    def test_empty_gaps(self):
        assert identify_candidates([]) == []

    def test_security_name_match(self):
        gaps = [
            {"file": "auth.py", "name": "authenticate_user"},
            {"file": "util.py", "name": "format_string"},
        ]
        candidates = identify_candidates(gaps)
        assert len(candidates) == 1
        assert candidates[0].function == "authenticate_user"
        assert candidates[0].has_security_name

    def test_taint_chain_callee(self):
        gaps = [
            {"file": "transform.py", "name": "apply_template"},
        ]
        candidates = identify_candidates(
            gaps,
            taint_chain_callees={"transform.py:apply_template"},
        )
        assert len(candidates) == 1
        assert candidates[0].callee_of_taint_chain

    def test_stock_sinks_excluded(self):
        gaps = [
            {"file": "lib.c", "name": "memcpy"},
        ]
        candidates = identify_candidates(
            gaps,
            taint_chain_callees={"lib.c:memcpy"},
            stock_sinks={"lib.c:memcpy"},
        )
        assert len(candidates) == 0

    def test_multiple_reasons(self):
        gaps = [
            {"file": "input.py", "name": "validate_input"},
        ]
        candidates = identify_candidates(
            gaps,
            taint_chain_callees={"input.py:validate_input"},
        )
        assert len(candidates) == 1
        assert candidates[0].callee_of_taint_chain
        assert candidates[0].has_security_name


class TestParseSpecResponse:
    def test_single_json_line(self):
        raw = '{"function": "sanitize_html", "file": "util.py", "role": "sanitiser", "taint_classes": ["xss"], "params_affected": [0], "return_tainted": true, "confidence": 0.9}'
        specs = parse_spec_response(raw)
        assert len(specs) == 1
        assert specs[0].function == "sanitize_html"
        assert specs[0].role == "sanitiser"
        assert specs[0].taint_classes == ["xss"]

    def test_sanitizer_normalised(self):
        raw = '{"function": "f", "file": "a.py", "role": "sanitizer"}'
        specs = parse_spec_response(raw)
        assert specs[0].role == "sanitiser"

    def test_json_array(self):
        raw = json.dumps([
            {"function": "f1", "file": "a.py", "role": "source"},
            {"function": "f2", "file": "b.py", "role": "sink"},
        ])
        specs = parse_spec_response(raw)
        assert len(specs) == 2

    def test_markdown_fenced(self):
        raw = "```json\n" + '{"function": "f", "file": "a.py", "role": "source"}' + "\n```"
        specs = parse_spec_response(raw)
        assert len(specs) == 1

    def test_invalid_role_skipped(self):
        raw = '{"function": "f", "file": "a.py", "role": "unknown"}'
        specs = parse_spec_response(raw)
        assert len(specs) == 0

    def test_malformed_json_tolerant(self):
        raw = "not json at all"
        specs = parse_spec_response(raw)
        assert len(specs) == 0

    def test_mixed_valid_invalid(self):
        raw = (
            '{"function": "f1", "file": "a.py", "role": "source"}\n'
            'not json\n'
            '{"function": "f2", "file": "b.py", "role": "sink"}\n'
        )
        specs = parse_spec_response(raw)
        assert len(specs) == 2


class TestCompileJoernConfig:
    def test_empty_specs(self):
        result = compile_joern_config([])
        assert "IRIS" in result

    def test_sources_pattern(self):
        specs = [
            TaintSpec(function="read_input", file="io.c", role="source"),
        ]
        result = compile_joern_config(specs)
        assert "projectSources" in result
        assert "read_input" in result

    def test_sinks_pattern(self):
        specs = [
            TaintSpec(function="exec_cmd", file="shell.c", role="sink"),
        ]
        result = compile_joern_config(specs)
        assert "projectSinks" in result
        assert "exec_cmd" in result

    def test_sanitisers_pattern(self):
        specs = [
            TaintSpec(function="escape_html", file="util.c", role="sanitiser"),
        ]
        result = compile_joern_config(specs)
        assert "projectSanitisers" in result

    def test_mixed_roles(self):
        specs = [
            TaintSpec(function="read_input", file="io.c", role="source"),
            TaintSpec(function="exec_cmd", file="shell.c", role="sink"),
            TaintSpec(function="escape", file="util.c", role="sanitiser"),
        ]
        result = compile_joern_config(specs)
        assert "projectSources" in result
        assert "projectSinks" in result
        assert "projectSanitisers" in result

    def test_special_chars_escaped(self):
        specs = [
            TaintSpec(function="obj.method", file="a.py", role="source"),
        ]
        result = compile_joern_config(specs)
        # Regex-escaped, then Scala-string-escaped: the dot arrives as
        # a double backslash + dot inside the generated literal.
        assert "obj\\\\.method" in result


# Function names that exercise every escaping hazard: regex metachars,
# quotes, backslashes, and control characters.
_SAMPLE_NAMES = [
    "plain_name",
    "obj.method",
    "price$",
    'we"ird\\name',
    "a\\b",
    'quote"only',
    "regex[meta](chars)+*?",
    "new\nline",
]


class TestEscapeScalaParity:
    """_escape_scala matches the hardened core.iris.specs escaper — a
    ``"`` or ``\\`` in a function name must not break out of the Scala
    string literal it is embedded in."""

    def test_matches_hardened_sibling(self):
        for name in _SAMPLE_NAMES:
            assert _escape_scala(name) == _iris_escape_scala(name), name

    def test_quote_escaped(self):
        out = _escape_scala('a"b')
        assert '"' not in out.replace('\\"', "")

    def test_backslash_escaped(self):
        # One source backslash → regex-escaped, then string-escaped:
        # four backslashes inside the Scala double-quoted literal.
        assert _escape_scala("a\\b") == "a\\\\\\\\b"

    def test_regex_dot_escaped(self):
        assert _escape_scala("obj.method") == "obj\\\\.method"

    def test_plain_name_untouched(self):
        assert _escape_scala("read_input") == "read_input"


class TestEscapeCodeqlParity:
    def test_matches_hardened_sibling(self):
        for name in _SAMPLE_NAMES:
            assert _escape_codeql(name) == _iris_escape_codeql(name), name

    def test_control_chars_stripped(self):
        assert _escape_codeql("a\nb\rc\0d") == "abcd"

    def test_quote_and_backslash_escaped(self):
        assert _escape_codeql('we"ird\\name') == 'we\\"ird\\\\name'


class TestCompiledConfigsSafe:
    def test_joern_pattern_has_no_bare_quote(self):
        specs = [TaintSpec(function='ev"il', file="a.py", role="source")]
        out = compile_joern_config(specs)
        line = next(
            ln for ln in out.splitlines() if "projectSources" in ln
        )
        inner = line.split('cpg.call.name("', 1)[1].rsplit('")', 1)[0]
        assert '"' not in inner.replace('\\"', "")

    def test_codeql_name_has_no_bare_quote(self):
        specs = [TaintSpec(function='ev"il', file="a.c", role="sink")]
        out = compile_codeql_config(specs)
        assert 'hasName("ev\\"il")' in out


class TestSpecSerialization:
    def test_roundtrip(self):
        specs = [
            TaintSpec(
                function="sanitize", file="util.py",
                role="sanitiser", taint_classes=["xss"],
                params_affected=[0], return_tainted=True,
                confidence=0.9,
            ),
        ]
        raw = specs_to_json(specs)
        loaded = specs_from_json(raw)
        assert len(loaded) == 1
        assert loaded[0].function == "sanitize"
        assert loaded[0].role == "sanitiser"
        assert loaded[0].taint_classes == ["xss"]
        assert loaded[0].confidence == 0.9
        assert loaded[0].evidence_tier == EvidenceTier.HEURISTIC

    def test_empty(self):
        assert specs_from_json("[]") == []

    def test_malformed_json(self):
        assert specs_from_json("not json") == []

    def test_to_dict(self):
        spec = TaintSpec(
            function="f", file="a.py", role="source",
            confidence=0.8,
        )
        d = spec.to_dict()
        assert d["function"] == "f"
        assert d["role"] == "source"
        assert d["evidence_tier"] == "heuristic"


class TestSpecsFromJsonShape:
    def test_non_list_json_returns_empty(self):
        assert specs_from_json('{"function": "f"}') == []
        assert specs_from_json('"just a string"') == []

    def test_list_json_still_parses(self):
        raw = (
            '[{"function": "f", "file": "a.py", "role": "source", '
            '"taint_classes": [], "params_affected": [], '
            '"return_tainted": true, "confidence": 0.9, '
            '"evidence_tier": "heuristic"}]'
        )
        specs = specs_from_json(raw)
        assert len(specs) == 1
        assert specs[0].function == "f"
        assert specs[0].return_tainted is True
