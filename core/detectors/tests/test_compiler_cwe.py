"""Reporting classifications must not depend on family/taxonomy ordering."""
import json

import pytest

from core.detectors.compiler_families import compiler_reported_cwe, diagnostic_cwe, compiler_applicable


@pytest.mark.parametrize("message, expected", [
    ("Potential leak of memory pointed to by 'p'", "CWE-401"),
    ("Use of memory after it is freed", "CWE-416"),
    ("Attempt to free released memory", "CWE-415"),
    ("unknown allocation issue", None),
    ("use-after-free followed by a leak", None),
    ("", None),
])
def test_shared_clang_checker_needs_unambiguous_message(message, expected):
    assert diagnostic_cwe("unix.Malloc", message) == expected


def test_call_checker_is_not_always_null_dereference():
    assert diagnostic_cwe("core.CallAndMessage", "Called function pointer is null") == "CWE-476"
    assert diagnostic_cwe("core.CallAndMessage", "1st argument is an uninitialized value") is None


@pytest.mark.parametrize("rule, expected", [
    ("-Wanalyzer-infinite-loop", "CWE-835"),
    ("-Wloop-analysis", "CWE-834"),
    ("-Wanalyzer-out-of-bounds", "CWE-119"),
    ("-Wstringop-overread", "CWE-125"),
    ("-Wstringop-overflow=2", "CWE-120"),
])
def test_fallback_does_not_choose_first_family_alias(rule, expected):
    assert diagnostic_cwe(rule) == expected


@pytest.mark.parametrize("invalid", [True, False, 0, -1, 12.5, "not a CWE", "CWE-0", "CWE-１２５", [], {}, "1" * 100])
def test_bad_native_classification_cannot_override_known_family(invalid):
    assert diagnostic_cwe("-Wanalyzer-use-after-free", reported=invalid) == "CWE-416"


def test_native_classification_and_new_reported_families():
    assert diagnostic_cwe("-Wanalyzer-out-of-bounds", reported="CWE-00126") == "CWE-126"
    assert compiler_applicable("CWE-119") and compiler_applicable("CWE-126")


def test_both_gcc_metadata_formats_and_indexed_taxonomy():
    assert compiler_reported_cwe({"metadata": {"cwe": 126}}) == "CWE-126"
    assert compiler_reported_cwe({"taxa": [{"id": "126", "toolComponent": {"name": "cwe"}}]}) == "CWE-126"
    run = {"taxonomies": [{"name": "CWE", "taxa": [{"id": "126"}]}]}
    assert compiler_reported_cwe({"taxa": [{"index": 0, "toolComponent": {"index": 0}}]}, run) == "CWE-126"
    assert compiler_reported_cwe({"taxa": [{"id": "126", "toolComponent": {"name": "other"}}]}) is None


def test_multiple_cwes_are_not_decided_by_taxonomy_order():
    taxa = [{"id": value, "toolComponent": {"name": "cwe"}} for value in ("125", "787")]
    assert compiler_reported_cwe({"taxa": taxa}) is None
    assert compiler_reported_cwe({"taxa": list(reversed(taxa))}) is None


def test_native_classification_survives_both_compiler_parsers(tmp_path):
    from core.audit.compiler_sweep import _parse_gcc_json, _parse_gcc_sarif
    legacy = {"option": "-Wanalyzer-out-of-bounds", "kind": "warning", "message": "read",
              "locations": [{"caret": {"file": "a.c", "line": 1}}], "metadata": {"cwe": 126}}
    assert _parse_gcc_json(json.dumps([legacy]))[0]["cwe"] == "CWE-126"
    modern = {"ruleId": "-Wanalyzer-out-of-bounds", "message": {"text": "read"},
              "taxa": [{"id": "126", "toolComponent": {"name": "cwe"}}]}
    path = tmp_path / "gcc.sarif"
    path.write_text(json.dumps({"runs": [{"results": [modern]}]}))
    assert _parse_gcc_sarif(path)[0]["cwe"] == "CWE-126"


def test_conflicting_taxonomy_name_and_index_are_not_trusted():
    run = {"taxonomies": [{"name": "other", "taxa": [{"id": "126"}]}]}
    assert compiler_reported_cwe({"taxa": [{"id": "126", "toolComponent": {"name": "CWE", "index": 0}}]}, run) is None


def test_cpp_new_delete_leak_has_its_own_supported_checker():
    assert diagnostic_cwe("cplusplus.NewDeleteLeaks", "Potential leak of memory pointed to by 'p'") == "CWE-401"


@pytest.mark.parametrize('reference', [
    {'ruleIndex': 0}, {'rule': {'index': 0}},
    {'rule': {'id': '-Wanalyzer-use-after-free'}},
])
def test_compiler_sarif_rule_references_preserve_classification_and_default_level(tmp_path, reference):
    from core.audit.compiler_sweep import _parse_gcc_sarif
    rule = {'id': '-Wanalyzer-use-after-free', 'defaultConfiguration': {'level': 'error'}}
    result = {'message': {'text': 'use after free'}, **reference}
    report = tmp_path / 'gcc.sarif'
    report.write_text(json.dumps({'runs': [{'tool': {'driver': {'name': 'gcc', 'rules': [rule]}},
                                          'results': [result]}]}))
    diagnostic = _parse_gcc_sarif(report)[0]
    assert diagnostic['id'] == rule['id'] and diagnostic['kind'] == 'error'
    assert diagnostic_cwe(diagnostic['id'], diagnostic['message']) == 'CWE-416'


def test_compiler_sarif_resolution_is_run_local_and_explicit_level_wins(tmp_path):
    from core.audit.compiler_sweep import _parse_gcc_sarif
    runs = [{'tool': {'driver': {'rules': [
        {'id': name, 'defaultConfiguration': {'level': 'error'}}]}},
        'results': [{'ruleIndex': 0, 'level': 'warning', 'message': {'text': 'diagnostic'}}]}
        for name in ('-Wanalyzer-use-after-free', '-Wanalyzer-double-free')]
    report = tmp_path / 'gcc.sarif'
    report.write_text(json.dumps({'runs': runs}))
    diagnostics = _parse_gcc_sarif(report)
    assert [row['id'] for row in diagnostics] == ['-Wanalyzer-use-after-free', '-Wanalyzer-double-free']
    assert [row['kind'] for row in diagnostics] == ['warning', 'warning']


@pytest.mark.parametrize('reference, rules, expected_id', [
    ({'ruleIndex': True}, [{'id': 'one'}], ''),
    ({'ruleIndex': 99}, [{'id': 'one'}], ''),
    ({'rule': {'id': 'one'}}, [{'id': 'one'}, {'id': 'one'}], ''),
    ({'ruleId': 'other', 'ruleIndex': 0}, [{'id': 'one'}], 'other'),
])
def test_invalid_compiler_rule_references_cannot_borrow_descriptor_metadata(tmp_path, reference, rules, expected_id):
    from core.audit.compiler_sweep import _parse_gcc_sarif
    for rule in rules:
        rule['defaultConfiguration'] = {'level': 'error'}
    report = tmp_path / 'gcc.sarif'
    report.write_text(json.dumps({'runs': [{'tool': {'driver': {'rules': rules}},
        'results': [{'message': {'text': 'diagnostic'}, **reference}]}]}))
    diagnostic = _parse_gcc_sarif(report)[0]
    assert diagnostic['id'] == expected_id and diagnostic['kind'] == ''


def test_compiler_sarif_indexes_rules_once_only_when_needed(tmp_path, monkeypatch):
    from core.audit import compiler_sweep as compiler
    original = compiler.ResultRuleResolver
    builds = []

    class MeasuredResolver(original):
        def __init__(self, run):
            builds.append(run)
            super().__init__(run)

    monkeypatch.setattr(compiler, 'ResultRuleResolver', MeasuredResolver)
    report = tmp_path / 'gcc.sarif'
    run = {'tool': {'driver': {'rules': [{'id': '-Wanalyzer-use-after-free'}]}}, 'results': [
        {'ruleId': '-Wanalyzer-use-after-free', 'level': 'warning', 'message': {'text': 'diagnostic'}}
        for _ in range(100)]}
    report.write_text(json.dumps({'runs': [run]}))
    assert len(compiler._parse_gcc_sarif(report)) == 100 and not builds
    for row in run['results']:
        row.pop('ruleId')
        row['ruleIndex'] = 0
    report.write_text(json.dumps({'runs': [run]}))
    assert len(compiler._parse_gcc_sarif(report)) == 100 and len(builds) == 1


@pytest.mark.parametrize('index', [False, True, -2, 99, '0', 0.0])
def test_inline_cwe_id_does_not_bypass_invalid_taxon_index(index):
    run = {'taxonomies': [{'name': 'CWE', 'taxa': [{'id': '126'}, {'id': '126'}]}]}
    reference = {'id': '126', 'index': index, 'toolComponent': {'index': 0}}
    assert compiler_reported_cwe({'taxa': [reference]}, run) is None


@pytest.mark.parametrize('reference, taxonomy', [
    ({'id': '787', 'index': 0}, {'name': 'CWE', 'taxa': [{'id': '126'}]}),
    ({'id': '126', 'index': 0, 'guid': 'wrong'},
     {'name': 'CWE', 'taxa': [{'id': '126', 'guid': 'right'}]}),
    ({'id': '126', 'index': 0}, {'name': 'CWE', 'taxa': [{'id': '126', 'index': 1}]}),
])
def test_conflicting_taxon_metadata_cannot_override_family(reference, taxonomy):
    reference['toolComponent'] = {'index': 0}
    reported = compiler_reported_cwe({'taxa': [reference]}, {'taxonomies': [taxonomy]})
    assert reported is None
    assert diagnostic_cwe('-Wanalyzer-out-of-bounds', reported=reported) == 'CWE-119'


@pytest.mark.parametrize('run', [None, {}, {'taxonomies': []}])
def test_taxonomy_reference_requires_context_even_with_inline_cwe_name(run):
    reference = {'id': '126', 'toolComponent': {'name': 'CWE', 'index': 0}}
    assert compiler_reported_cwe({'taxa': [reference]}, run) is None


def test_taxonomy_guid_must_agree_with_indexed_component():
    run = {'taxonomies': [{'name': 'CWE', 'guid': 'right', 'taxa': [{'id': '126'}]}]}
    reference = {'id': '126', 'toolComponent': {'name': 'CWE', 'guid': 'wrong', 'index': 0}}
    assert compiler_reported_cwe({'taxa': [reference]}, run) is None
    reference['toolComponent']['guid'] = 'right'
    assert compiler_reported_cwe({'taxa': [reference]}, run) == 'CWE-126'


@pytest.mark.parametrize('index', [None, -1, 0])
def test_matching_and_inline_taxa_remain_supported(index):
    run = {'taxonomies': [{'name': 'CWE', 'taxa': [{'id': '126', 'guid': 'same'}]}]}
    reference = {'id': '126', 'toolComponent': {'name': 'CWE', 'index': 0}}
    if index is not None:
        reference['index'] = index
    if index == 0:
        reference['guid'] = 'same'
    assert compiler_reported_cwe({'taxa': [reference]}, run) == 'CWE-126'


def test_bad_sarif_cwe_reference_keeps_diagnostic_and_valid_native_metadata(tmp_path):
    from core.audit.compiler_sweep import _parse_gcc_sarif
    reference = {'id': '787', 'index': 0, 'toolComponent': {'index': 0}}
    run = {'taxonomies': [{'name': 'CWE', 'taxa': [{'id': '126'}]}], 'results': [{
        'ruleId': '-Wanalyzer-out-of-bounds', 'message': {'text': 'keep diagnostic'}, 'taxa': [reference]}]}
    report = tmp_path / 'compiler.sarif'
    report.write_text(json.dumps({'runs': [run]}))
    diagnostic = _parse_gcc_sarif(report)[0]
    assert diagnostic['id'] == '-Wanalyzer-out-of-bounds' and diagnostic['message'] == 'keep diagnostic'
    assert 'cwe' not in diagnostic
    assert compiler_reported_cwe({'metadata': {'cwe': 126}, 'taxa': [reference]}, run) == 'CWE-126'
