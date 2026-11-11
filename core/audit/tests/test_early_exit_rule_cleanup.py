"""Generated rule lifetime under actual constructor ordering and inert memo results."""
import builtins
import os
from types import SimpleNamespace

from core.audit import hypothesis_mapping, orchestrator
from core.audit.sweep import SweepResult
from core.run.scratch import write_temp_text
from core.testing.module_views import module_function_view


def _early_exit_case(tmp_path, *, marker=True, cleanup_error=False):
    source = tmp_path / 'owned.c'
    original = 'int owned(void) { return 0; }\n'
    source.write_text(original)
    rules = tmp_path / 'rules'
    rules.mkdir()
    generated = []
    calls = []
    retired = []

    def unlink_owned(path):
        assert path in {str(p) for p in generated}
        retired.append(path)
        os.unlink(path)
        if cleanup_error:
            raise OSError('after owned generated rule unlink')

    owned_os = SimpleNamespace(**vars(os))
    owned_os.unlink = unlink_owned

    def write_owned(text, *, prefix, suffix):
        path = write_temp_text(text, prefix=prefix, suffix=suffix, dir=rules)
        generated.append(path)
        return path

    scratch = SimpleNamespace(write_temp_text=write_owned)

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name == 'core.run.scratch':
            return scratch
        return builtins.__import__(name, globals, locals, fromlist, level)

    def memo(config, tool, request, invoke):
        assert tool in {'compiler', 'smt'}, 'unexpected non-skipped entry in qualification'
        calls.append(tool)
        # Parent-control fixture only: never invoke the backend callback.
        return SweepResult(
            tool=tool, file_path='owned.c', function_name='owned',
            outcome='confirmed' if tool == 'compiler' else 'inconclusive',
            rule_id='compiler:analyzer' if tool == 'compiler' else 'smt:owned',
            matches=[{'line': 1}] if tool == 'compiler' else [],
        )

    def inactive_channel(tool):
        def run(**kwargs):
            calls.append(tool)
            return SweepResult(
                tool=tool, file_path='owned.c', function_name='owned',
                outcome='inconclusive', rule_id=tool + ':owned',
            )
        return run

    sweep_view = SimpleNamespace(
        run_proto_length_sweep=inactive_channel('proto_length'),
        run_struct_field_sweep=inactive_channel('struct_field'),
    )

    def import_runner(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == 'sweep':
            return sweep_view
        return builtins.__import__(name, globals, locals, fromlist, level)

    mapping = module_function_view(hypothesis_mapping, import_hook=import_local)
    private = module_function_view(orchestrator, bindings={
        '_hypothesis_to_semgrep_rule_keyed': mapping.hypothesis_to_semgrep_rule_keyed,
        'os': owned_os,
        '_memoized_sweep_step': memo,
        '_UNMAPPED_CWES_LOGGED': set(),
        '_line_end_cache': {},
        '_ghidra_re_context': lambda *args: (None, None),
    }, import_hook=import_runner)
    config = orchestrator.OrchestratorConfig(target_path=tmp_path, out_dir=None)
    assert config.llm_budget_client is None
    skipped = set()
    errored = set()
    try:
        chain = private._hypothesis_to_tool_chain('buffer overflow', 'owned.c', 'CWE-120')
        assert chain[0]['type'] == 'compiler'
        assert {e['type'] for e in chain} <= {
            'compiler', 'smt', 'semgrep', 'coccinelle', 'joern', 'joern_guard', 'joern_flow', 'symbolic',
            'codeql', 'struct_field', 'proto_length',
        }
        assert len(generated) == 1
        if not marker:
            entries = [e for e in chain if e['type'] == 'semgrep']
            assert len(entries) == 1
            entries[0]['config'].pop('keyword')
        assert private._promotion_grade_receipt('compiler:analyzer')
        result = private._run_tool_chain(
            chain, config=config, file_path='owned.c', function_name='owned',
            source=None, hypothesis='buffer overflow',
            early_exit_check=private._promotion_grade_receipt, skipped_types=skipped,
            errored_types=errored, cwe='CWE-120',
        )
        assert result == ['compiler:analyzer']
        assert 'semgrep' in skipped
        assert not errored
        assert 'compiler' in calls
        assert 'semgrep' not in calls
        assert source.read_text() == original
        if marker:
            assert retired == [str(generated[0])]
            assert not generated[0].exists(), 'early-exit chain retained an unexecuted generated rule'
        else:
            assert retired == []
            assert generated[0].exists()

    finally:
        for path in generated:
            path.unlink(missing_ok=True)



def test_early_exit_retires_unexecuted_generated_rule(tmp_path):
    _early_exit_case(tmp_path)


def test_early_exit_preserves_ordinary_cleanup_error_policy(tmp_path):
    _early_exit_case(tmp_path, cleanup_error=True)


def test_early_exit_preserves_borrowed_generated_looking_rule(tmp_path):
    _early_exit_case(tmp_path, marker=False)
