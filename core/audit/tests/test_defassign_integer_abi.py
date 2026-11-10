"""Definite-assignment SMT proofs require the owning target integer frame."""

import json
from types import SimpleNamespace

import pytest

from core.audit import defassign as da
from core.audit.defassign import check_definite_assignment
from core.audit.refutation import _ProbeContext, _probe_definite_assignment, rescue_self_refuted
from core.audit.integer_abi import integer_abi_key, integer_abi_record


LONG_SOURCE = ('int find_slot(long Value){int slot;'
               'if(Value == 0xffffffff){if(Value<0)return slot;}return 0;}')


@pytest.fixture(autouse=True)
def native_dependencies():
    pytest.importorskip('z3')
    pytest.importorskip('tree_sitter_c')


@pytest.mark.parametrize('abi,proven', [
    (None, False), ('unknown', False), ('invalid', False),
    ('llp64', False), ('ilp32', False), ('lp64', True), ('ilp64', True),
])
def test_long_obligation_uses_the_selected_target(abi, proven):
    result = check_definite_assignment(LONG_SOURCE, 'slot', integer_abi=abi)
    assert result.proven is proven, result.to_dict()
    if proven:
        assert result.method == 'structural+smt'
        assert result.integer_abi == integer_abi_record(abi)
        assert result.smt_paths_discharged > 0
        exported = result.to_dict()
        exported['integer_abi']['long_bits'] = 8
        assert result.integer_abi['long_bits'] == 64
    else:
        assert result.method != 'structural+smt'


@pytest.mark.parametrize('abi,proven', [('i16', False), ('ilp32', True)])
def test_target_int_width_is_not_borrowed_from_the_host(abi, proven):
    source = ('int Read(int Value){int slot;'
              'if(Value == 0xffff){if(Value<0)return slot;}return 0;}')
    result = check_definite_assignment(source, 'slot', integer_abi=abi)
    assert result.proven is proven, result.to_dict()


@pytest.mark.parametrize('abi', ['lp64', 'llp64'])
def test_wider_decimal_literal_cannot_be_truncated_into_the_parameter_frame(abi):
    source = ('int Read(unsigned Value){int slot;'
              'if(Value==0){if(Value > -2147483648)return slot;}return 0;}')
    assert 0 > -2147483648
    result = check_definite_assignment(source, 'slot', integer_abi=abi)
    assert not result.proven, result.to_dict()


@pytest.mark.parametrize('outer,inner,proven', [
    ('int', 'long', False),
    ('long', 'int', True),
])
def test_body_prototype_parameters_cannot_replace_entry_parameter_types(outer, inner, proven):
    source = ('int Read(' + outer + ' Value){int Helper(' + inner + ' Value);int slot;'
              'if(Value == 0xffffffff){if(Value<0)return slot;}return 0;}')
    result = check_definite_assignment(source, 'slot', integer_abi='lp64')
    assert result.proven is proven, result.to_dict()


@pytest.mark.parametrize('binding', ['int Value=-1;', 'enum {Value=-1};'])
def test_local_binding_cannot_borrow_the_outer_parameter_type(binding):
    source = ('int Read(long Value){int slot;{' + binding
              + 'if(Value==0xffffffff){if(Value<0)return slot;}}return 0;}')
    assert (-1) % (1 << 32) == 0xffffffff and -1 < 0
    assert not check_definite_assignment(source, 'slot', integer_abi='lp64').proven


@pytest.mark.parametrize('effect,postcondition', [
    ('((Value))=1;', 'Value>0'),
    ('(Value)++;', 'Value==0'),
    ('Set(&((Value)));', 'Value>0'),
])
def test_parenthesised_writes_and_address_escapes_decline_parameter_credit(effect, postcondition):
    source = ('int Read(int Value){void Set(int*);int slot;if(Value<0){'
              + effect + 'if(' + postcondition + ')return slot;}return 0;}')
    assert not check_definite_assignment(source, 'slot', integer_abi='lp64').proven


@pytest.mark.parametrize('parameter', [
    'uint64_t Value', 'size_t Value', 'volatile long Value',
    'long Value __attribute__((mode(SI)))',
])
def test_aliases_and_type_changing_parameter_qualifiers_decline(parameter):
    source = ('int Read(' + parameter + '){int slot;'
              'if(Value == 0xffffffff){if(Value<0)return slot;}return 0;}')
    assert not check_definite_assignment(source, 'slot', integer_abi='lp64').proven


@pytest.mark.parametrize('source', [
    ('int Read(unsigned long Value){int slot;'
     'if(Value==0){if(Value==(0xffffffff+1))return slot;}return 0;}'),
    ('int Read(unsigned long Count){int slot;'
     'if(Count==1){if((0xffffffff<<Count)==0xfffffffe)return slot;}return 0;}'),
])
def test_unbound_intermediate_types_cannot_refute_a_defined_c_path(source):
    assert (0xffffffff + 1) % (1 << 32) == 0
    assert (0xffffffff << 1) % (1 << 32) == 0xfffffffe
    result = check_definite_assignment(source, 'slot', integer_abi='lp64')
    assert not result.proven, result.to_dict()


def test_unsigned_atomic_comparison_remains_available():
    source = 'int Read(unsigned long Value){int slot;if(Value<0)return slot;return 0;}'
    result = check_definite_assignment(source, 'slot', integer_abi='llp64')
    assert result.proven and result.method == 'structural+smt'
    assert result.integer_abi == integer_abi_record('llp64')


def test_structural_proofs_do_not_require_a_target_layout():
    result = check_definite_assignment('int Read(void){int slot=1;return slot;}', 'slot')
    assert result.proven and result.method == 'structural'
    assert result.integer_abi is None


@pytest.mark.parametrize('abi,dominates', [(None, False), ('llp64', False), ('lp64', True)])
def test_active_detector_floor_receives_target_abi_and_durable_provenance(tmp_path, abi, dominates):
    from core.audit.refutation import rescue_self_refuted
    from core.audit.tests.test_defassign_gate import _Config, _Outcome, _hyp, _receipt, _records, _write_target

    target = _write_target(tmp_path, LONG_SOURCE)
    config = _Config(target_path=target, out_dir=tmp_path / 'out', integer_abi=abi)
    outcome = _Outcome(hypotheses=[_hyp()])
    result = rescue_self_refuted(outcome, source=LONG_SOURCE,
                                detector_findings=[_receipt()], config=config)
    assert (result is None) is dominates
    records = _records(config.out_dir)
    if dominates:
        assert len(records) == 1 and records[0]['refuter_gate'] == 'definite_assignment'
        reason = records[0]['reason']
        assert integer_abi_key(abi) in reason
        stored, _ = json.JSONDecoder().raw_decode(reason.split('; SMT target integer ABI ', 1)[1])
        assert stored == integer_abi_record(abi)
    else:
        assert result.demote_to == 'suspicious'
        assert not any(r.get('refuter_gate') == 'definite_assignment' for r in records)


def test_prior_abi_less_dominance_history_cannot_replace_a_current_proof(tmp_path):
    from core.audit.refutation import rescue_self_refuted
    from core.audit.tests.test_defassign_gate import _Config, _Outcome, _hyp, _receipt, _write_target

    target = _write_target(tmp_path, LONG_SOURCE)
    out = tmp_path / 'out'
    out.mkdir()
    old = {'verdict': 'refuter_dominates_receipt', 'refuter_gate': 'definite_assignment',
           'refuter_grade': 'proof', 'reason': 'old unqualified integer proof'}
    (out / 'suppressions.jsonl').write_text(json.dumps(old) + '\n')
    config = _Config(target_path=target, out_dir=out)
    result = rescue_self_refuted(_Outcome(hypotheses=[_hyp()]), source=LONG_SOURCE,
                                detector_findings=[_receipt()], config=config)
    assert result is not None and result.demote_to == 'suspicious'


def test_full_custom_layout_provenance_survives_the_fact_summary_cap(tmp_path):
    from core.audit.refutation import rescue_self_refuted
    from core.audit.tests.test_defassign_gate import _Config, _Outcome, _hyp, _receipt, _records, _write_target

    abi = integer_abi_record('lp64')
    abi['name'] = 'q' * 80
    target = _write_target(tmp_path, LONG_SOURCE)
    config = _Config(target_path=target, out_dir=tmp_path / 'out', integer_abi=abi)
    result = rescue_self_refuted(_Outcome(hypotheses=[_hyp()]), source=LONG_SOURCE,
                                detector_findings=[_receipt()], config=config)
    assert result is None
    reason = _records(config.out_dir)[0]['reason']
    assert len(reason) > 400 and integer_abi_key(abi) in reason
    stored, _ = json.JSONDecoder().raw_decode(reason.split('; SMT target integer ABI ', 1)[1])
    assert stored == abi


@pytest.mark.parametrize('abi,dominates', [('lp64', True), ('llp64', False)])
def test_post_loop_probe_context_receives_the_same_layout(tmp_path, abi, dominates):
    from core.audit.receipt_resolution import _receipt_corroborated_hypothesis
    from core.audit.tests.test_defassign_gate import _Config, _Outcome, _hyp, _records, _write_target

    target = _write_target(tmp_path, LONG_SOURCE)
    config = _Config(target_path=target, out_dir=tmp_path / 'out', integer_abi=abi)
    receipt = {'check_type': 'uninitialized_return', 'evidence': 'find_slot() call may return an uninitialized value'}
    result = _receipt_corroborated_hypothesis(
        _Outcome(hypotheses=[_hyp(conf='low')]), [receipt], config=config, source=LONG_SOURCE)
    assert (result is None) is dominates
    records = _records(config.out_dir)
    if dominates:
        assert len(records) == 1
        assert records[0]['floor_gate'] == 'receipt_corroborated_hypothesis'
        assert integer_abi_key(abi) in records[0]['reason']
    else:
        assert result.demote_to == 'suspicious'
        assert records == []


WIDTH_SENSITIVE = "int f(long a){int v; if(a == 0xffffffff){if(a < 0) return v;} return 0;}"


CONTRADICTION = "int f(int a){int v; if(a > 5) v=1; if(a > 5) return v; return 0;}"


@pytest.mark.parametrize("abi", [None, "unknown", {"name": "incomplete"}])
def test_unadmitted_layout_cannot_supply_a_source_proof(abi):
    result = da.check_definite_assignment(WIDTH_SENSITIVE, "v", integer_abi=abi)
    assert not result.proven, result.reason
    assert result.integer_abi is None and result.smt_paths_discharged == 0


@pytest.mark.parametrize("abi,expected", [("ilp32", False), ("llp64", False), ("lp64", True)])
def test_atomic_long_guard_uses_target_width(abi, expected):
    result = da.check_definite_assignment(WIDTH_SENSITIVE, "v", integer_abi=abi)
    assert result.proven is expected, result.reason
    if expected:
        assert result.method == "structural+smt"
        assert result.to_dict()["integer_abi"] == integer_abi_record(abi)


@pytest.mark.parametrize("abi", ["i16", "ilp32", "lp64", "ilp64"])
def test_known_builtin_formal_contradiction_retains_its_layout(abi):
    result = da.check_definite_assignment(CONTRADICTION, "v", integer_abi=abi)
    assert result.proven and result.method == "structural+smt", result.reason
    assert result.integer_abi == integer_abi_record(abi)


@pytest.mark.parametrize("spelling", ["size_t", "uint32_t", "int64_t", "volatile int"])
def test_aliases_and_unstable_formals_do_not_borrow_builtin_widths(spelling):
    source = CONTRADICTION.replace("int a", spelling + " a")
    result = da.check_definite_assignment(source, "v", integer_abi="lp64")
    assert not result.proven, result.reason


def test_structural_assignment_needs_no_integer_layout():
    result = da.check_definite_assignment("int f(void){int v=1; return v;}", "v")
    assert result.proven and result.method == "structural"
    assert result.integer_abi is None


def test_source_probe_passes_layout_and_records_it(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.c").write_text(WIDTH_SENSITIVE)
    outcome = SimpleNamespace(file="app.c")
    hypothesis = {"mechanism": "Variable v may be returned uninitialized"}
    receipt = {"description": "Variable 'v' may be returned uninitialized"}
    def probe(abi):
        return _probe_definite_assignment(outcome, hypothesis, _ProbeContext(
            source=WIDTH_SENSITIVE, target_path=target, repo_trusted=True,
            detector_finding=receipt, integer_abi=abi,
        ))
    assert probe(None) is None
    assert probe("ilp32") is None
    result = probe("lp64")
    assert result is not None and result.refuter_grade == "proof"
    assert '"long_bits":64' in result.reason
    assert '"name":"lp64"' in result.reason


@pytest.mark.parametrize("abi,dominates", [(None, False), ("llp64", False), ("lp64", True)])
def test_config_layout_reaches_the_actual_receipt_floor(tmp_path, abi, dominates):
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.c").write_text(WIDTH_SENSITIVE)
    out = tmp_path / "out"
    hypothesis = {"mechanism": "Variable v may be returned uninitialized",
                  "confidence": "refuted", "counter": "Every branch assigns v"}
    outcome = SimpleNamespace(file="app.c", function="f", line=1, status="clean",
                              body="", hypothesis="", hypotheses=[hypothesis],
                              evidence_tool="", review_result=None)
    receipt = {"detector": "cocci:uninitialized_return", "file": "app.c",
               "function": "f", "line": 1,
               "description": "Variable 'v' may be returned uninitialized"}
    config = SimpleNamespace(target_path=target, out_dir=out, repo_trusted=True, integer_abi=abi)
    result = rescue_self_refuted(outcome, config=config, source=WIDTH_SENSITIVE,
                                detector_findings=[receipt])
    if dominates:
        assert result is None
        records = [json.loads(line) for line in (out / "suppressions.jsonl").read_text().splitlines()]
        assert len(records) == 1 and records[0]["verdict"] == "refuter_dominates_receipt"
        assert '"long_bits":64' in records[0]["reason"]
    else:
        assert result is not None and result.demote_to == "suspicious"


LEGACY_ARITHMETIC_WIDTH_SENSITIVE = 'int f(unsigned long a){int v; if(a <= 0xffffffff){if(a + 1 > a) v=1; return v;} return 0;}'


@pytest.mark.parametrize("abi", ["ilp32", "llp64", "lp64", "ilp64"])
def test_arithmetic_width_obligation_retains_the_typed_source_refusal(abi):
    result = da.check_definite_assignment(LEGACY_ARITHMETIC_WIDTH_SENSITIVE, "v", integer_abi=abi)
    assert not result.proven and result.method != "structural+smt", result.to_dict()
