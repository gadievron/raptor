"""Source-refusal control with an owned disposable rule, no tool execution."""
import os
from types import SimpleNamespace

from core.audit import orchestrator
from core.run.scratch import write_temp_text
from core.testing.module_views import module_function_view


def _source_refusal_case(tmp_path, *, marker=True, cleanup_error=False, tool="semgrep"):
    source = tmp_path / 'owned.php'
    current = '<?php function owned() { return 1; }\n'
    source.write_text(current)
    rule = write_temp_text('rules: []\n', prefix='audit_sweep_', suffix='.yaml', dir=tmp_path)
    identity = rule.stat()
    skipped = set()
    retired = []

    def unlink_owned(path):
        assert path == str(rule)
        now = rule.stat()
        assert (now.st_dev, now.st_ino) == (identity.st_dev, identity.st_ino)
        retired.append(path)
        os.unlink(rule)
        if cleanup_error:
            raise OSError('after owned unlink')

    owned_os = SimpleNamespace(**vars(os))
    owned_os.unlink = unlink_owned
    entry = {'type': tool, 'config': {'rule': str(rule)}}
    if marker:
        entry['config']['keyword'] = 'owned'

    def forbidden(*args, **kwargs):
        raise AssertionError('source refusal must not execute any tool or memo callback')

    private = module_function_view(orchestrator, bindings={
        'os': owned_os,
        '_memoized_sweep_step': forbidden,
        'run_semgrep_sweep': forbidden,
    })
    try:
        result = private._run_tool_chain(
            [entry],
            config=SimpleNamespace(target_path=tmp_path, out_dir=None),
            file_path='owned.php', function_name='owned',
            source='<?php function owned() { return 0; }\n',
            hypothesis='owned source-refusal control', skipped_types=skipped,
        )
        assert result == []
        assert skipped == {tool}
        assert len(result.outcomes) == 1
        assert result.outcomes[0].verdict == 'inconclusive'
        assert source.read_text() == current
        if rule.exists():
            now = rule.stat()
            assert (now.st_dev, now.st_ino) == (identity.st_dev, identity.st_ino)
        if marker and tool == 'semgrep':
            assert retired == [str(rule)]
            assert not rule.exists(), 'source refusal left an unexecuted generated rule'
        else:
            assert retired == []
            assert rule.exists()
            assert rule.read_text() == 'rules: []\n'

    finally:
        rule.unlink(missing_ok=True)



def test_source_refusal_retires_unexecuted_generated_rule(tmp_path):
    _source_refusal_case(tmp_path)


def test_source_refusal_preserves_ordinary_cleanup_error_policy(tmp_path):
    _source_refusal_case(tmp_path, cleanup_error=True)


def test_source_refusal_preserves_borrowed_generated_looking_path(tmp_path):
    _source_refusal_case(tmp_path, marker=False)


def test_source_refusal_preserves_other_tool_rule_path(tmp_path):
    _source_refusal_case(tmp_path, tool='coccinelle')
