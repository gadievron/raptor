"""Chain construction only acquires generated rules it can transfer."""
import builtins
from types import SimpleNamespace

from core.audit import hypothesis_mapping, orchestrator
from core.run.scratch import write_temp_text
from core.testing.module_views import module_function_view


def _owned_chain_builder(tmp_path):
    generated = []

    def write_owned(text, *, prefix, suffix):
        path = write_temp_text(text, prefix=prefix, suffix=suffix, dir=tmp_path)
        generated.append(path)
        return path

    scratch = SimpleNamespace(write_temp_text=write_owned)

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name == 'core.run.scratch':
            return scratch
        return builtins.__import__(name, globals, locals, fromlist, level)

    mapping = module_function_view(hypothesis_mapping, import_hook=import_local)
    private = module_function_view(orchestrator, bindings={
        '_hypothesis_to_semgrep_rule_keyed': mapping.hypothesis_to_semgrep_rule_keyed,
    })
    return private, generated


def test_curated_chain_does_not_orphan_generated_rule(tmp_path):
    private, generated = _owned_chain_builder(tmp_path)
    try:
        chain = private._hypothesis_to_tool_chain('xss', 'owned.php', 'CWE-79')
        semgrep = [entry for entry in chain if entry['type'] == 'semgrep']
        assert len(semgrep) == 1
        assert semgrep[0]['config']['rule'].endswith('php/attr-xss.yaml')
        assert not generated, 'generated rule acquired without an entry to own it'
        assert list(tmp_path.iterdir()) == []
    finally:
        # The failing baseline leaves only test-owned paths; retire them here.
        for path in generated:
            path.unlink(missing_ok=True)


def test_generated_rule_transfers_when_no_curated_entry(tmp_path):
    private, generated = _owned_chain_builder(tmp_path)
    try:
        chain = private._hypothesis_to_tool_chain('xss', 'owned.php')
        semgrep = [entry for entry in chain if entry['type'] == 'semgrep']
        assert len(semgrep) == len(generated) == 1
        assert semgrep[0]['config'] == {'rule': str(generated[0]), 'keyword': 'xss'}
        assert generated[0].is_file()
        assert 'rules:' in generated[0].read_text()
    finally:
        for path in generated:
            path.unlink(missing_ok=True)


def test_language_rejected_curated_rule_keeps_generated_fallback(tmp_path):
    private, generated = _owned_chain_builder(tmp_path)
    try:
        chain = private._hypothesis_to_tool_chain('xss', 'owned.c', 'CWE-79')
        semgrep = [entry for entry in chain if entry['type'] == 'semgrep']
        assert len(semgrep) == len(generated) == 1
        assert semgrep[0]['config'] == {'rule': str(generated[0]), 'keyword': 'xss'}
        assert generated[0].is_file()
    finally:
        for path in generated:
            path.unlink(missing_ok=True)


def test_unmatched_text_acquires_no_rule(tmp_path):
    private, generated = _owned_chain_builder(tmp_path)
    chain = private._hypothesis_to_tool_chain('no matching keyword', 'owned.php')
    assert not [entry for entry in chain if entry['type'] == 'semgrep']
    assert generated == []
    assert list(tmp_path.iterdir()) == []
