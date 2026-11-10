"""Unexpanded effects cannot lend a faithful C/C++ CFG to proof consumers."""
import pytest
from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
from core.analysis.sanitizer_cut import evaluate_finding
from core.run.gaps import record_analysis_gap as _real_record_gap

pytest.importorskip("tree_sitter_c")
pytest.importorskip("tree_sitter_cpp")

HEADER = "extern char *g_shell_quote(const char *);\nextern void consume(const char *);\n"


@pytest.fixture(autouse=True)
def gap_transport(monkeypatch):
    records = []
    def record(*_args, **kwargs):
        records.append(kwargs)
        return False
    monkeypatch.setattr("core.run.gaps.record_analysis_gap", record)
    return records


def _source(definitions, middle="    CHANGE;\n", before=""):
    return (definitions + HEADER + "void handle(char *raw, int flag) {\n" + before +
            "    char *safe = g_shell_quote(raw);\n" + middle + "    consume(safe);\n}\n")


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("definitions,middle", [
    ("#define CHANGE safe = raw\n", "    CHANGE;\n"),
    ("#define CHANGE safe[0] = raw[0]\n", "    CHANGE;\n"),
    ("#define CHANGE NEXT\n#define NEXT safe = raw\n", "    CHANGE;\n"),
    ("#de\\\nfine CHANGE safe = raw\n", "    CHANGE;\n"),
    ("#define CHANGE safe = raw\n", "    CHA\\\nNGE;\n"),
], ids=["assignment", "byte-write", "alias-chain", "directive-splice", "identifier-splice"])
def test_effect_macros_make_the_proof_cfg_unavailable(language, definitions, middle, gap_transport):
    source = _source(definitions, middle)
    cfg = build_cpp_intraproc_cfg(source, "handle", language=language)
    observed = None
    if cfg is not None:
        sink = next(node for node in cfg.nodes() if "consume" in node.calls)
        observed = evaluate_finding(cfg, [cfg.entry_node], sink, cwe="CWE-78", language=language,
                                    source_symbols={"raw"}, sink_arg="safe").verdict
    assert cfg is None, f"unexpanded source yielded proof verdict={observed}"
    assert gap_transport[-1]["reason"] == "cpp_preprocessing_unverified"


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_control_macro_cannot_be_checked_only_on_the_unexpanded_sink_path(language):
    source = ("#define GO goto target\n" + HEADER + "void handle(char *raw, int flag) {\n"
              "    char *safe = raw;\n    if (flag) { GO; return; }\n"
              "    safe = g_shell_quote(raw);\ntarget: consume(safe);\n}\n")
    assert build_cpp_intraproc_cfg(source, "handle", language=language) is None


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_keyword_macro_names_are_not_skipped(language):
    source = _source("#define return safe = raw; return\n", "    if (flag) { return; }\n")
    assert build_cpp_intraproc_cfg(source, "handle", language=language) is None


@pytest.mark.parametrize("language", ["c", "cpp"])
@pytest.mark.parametrize("middle", ["", "    /* CHANGE */\n", '    const char *note = "CHANGE";\n'])
def test_unused_definitions_and_literal_mentions_preserve_a_cfg(language, middle):
    source = _source("#define CHANGE safe = raw\n", middle)
    assert build_cpp_intraproc_cfg(source, "handle", language=language) is not None


def test_raw_string_mention_is_not_a_macro_reference():
    source = _source("#define CHANGE safe = raw\n", '    const char *note = R"tag(CHANGE)tag";\n')
    assert build_cpp_intraproc_cfg(source, "handle", language="cpp") is not None


def test_definition_inside_unused_raw_string_is_not_a_directive():
    source = 'const char *note = R"tag(\n#define CHANGE safe = raw\n)tag";\n' + _source("", "")
    assert build_cpp_intraproc_cfg(source, "handle", language="cpp") is not None


@pytest.mark.parametrize("language", ["c", "cpp"])
def test_function_scoped_conditional_preprocessing_is_unverified(language):
    source = _source("", "#if FEATURE\n    safe = raw;\n#endif\n")
    assert build_cpp_intraproc_cfg(source, "handle", language=language) is None


def test_gap_transport_failure_cannot_restore_a_cfg(monkeypatch):
    def unavailable(*_args, **_kwargs):
        raise OSError("owned diagnostic transport failure")
    monkeypatch.setattr("core.run.gaps.record_analysis_gap", unavailable)
    assert build_cpp_intraproc_cfg(_source("#define CHANGE safe = raw\n"), "handle") is None


@pytest.mark.parametrize("definition", ["#define g_shell_quote(x) (x)\n", "#define g_shell_quote replacement\n"])
@pytest.mark.parametrize("language,expression,before", [
    ("c", "g_shell_quote(raw)", ""), ("cpp", "g_shell_quote(raw)", ""),
    ("cpp", "::g_shell_quote(raw)", ""),
    ("cpp", "g_shell_quote(raw)", "    using ::g_shell_quote;\n"),
])
def test_macro_callee_refusal_precedes_identity_selection(definition, language, expression, before):
    source = _source("", "", before).replace(HEADER, HEADER + definition, 1)
    source = source.replace("safe = g_shell_quote(raw)", f"safe = {expression}")
    assert build_cpp_intraproc_cfg(source, "handle", language=language) is None


def test_utf8_prefix_does_not_shift_macro_reference_span():
    source = "/* π before function */\n" + _source("#define CHANGE safe = raw\n")
    assert build_cpp_intraproc_cfg(source, "handle") is None


def test_local_unused_macro_definition_is_not_an_expansion():
    source = _source("", "", before="#define UNUSED safe = raw\n")
    assert build_cpp_intraproc_cfg(source, "handle") is not None


def test_literal_valued_macros_still_need_preprocessing_evidence():
    source = _source("#define LIMIT 4\n", "    if (flag > LIMIT) { return; }\n")
    assert build_cpp_intraproc_cfg(source, "handle") is None


def test_identifier_encoding_is_conservatively_unverified():
    source = _source("#define Μ safe = raw\n", "    Μ;\n")
    assert build_cpp_intraproc_cfg(source, "handle", language="cpp") is None


def test_real_gap_writer_persists_the_unavailable_reason(tmp_path, monkeypatch):
    from core.run import gaps
    monkeypatch.setattr(gaps, "_gap_count", 0)
    monkeypatch.setattr(gaps, "_suppressed", 0)
    monkeypatch.setattr(gaps, "_pending", [])
    monkeypatch.setattr(gaps, "_seen_digests", set())
    monkeypatch.setattr(gaps, "record_analysis_gap", lambda **kwargs: _real_record_gap(tmp_path, **kwargs))
    path = tmp_path / "owned.c"
    path.write_text(_source("#define CHANGE safe = raw\n"))
    assert build_cpp_intraproc_cfg(path, "handle") is None
    record, = gaps.load_gaps(tmp_path)
    assert record["reason"] == "cpp_preprocessing_unverified"
    assert record["tool"] == "cfg_builder_cpp"
    assert record["function"] == "handle"
    assert record["file_path"] == str(path)
