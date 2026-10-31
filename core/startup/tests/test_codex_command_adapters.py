"""Contracts for generated adapters and the shared source of procedures."""
import importlib.util
from pathlib import Path
import re
import shutil
import tomllib

import yaml

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location('sync_codex_commands', ROOT / '.codex/sync_commands.py')
SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNC)


def test_generated_adapters_current_and_source_links_resolve():
    assert SYNC.sync(ROOT) == ([], [])
    sources = list((ROOT / '.claude/commands').glob('*.md'))
    assert sources
    assert not (ROOT / '.agents/skills').is_symlink()
    for source in sources:
        wrapper = ROOT / '.agents/skills' / source.stem / 'SKILL.md'
        text = wrapper.read_text()
        metadata = yaml.safe_load(text.split('---', 2)[1])
        assert metadata['name'] == wrapper.parent.name
        assert metadata['description']
        for reference in re.findall(r'\]\(([^)]+)\)', text):
            assert (wrapper.parent / reference).is_file(), reference


def test_check_detects_new_commands_and_metadata_changes_without_writing(tmp_path):
    for name in ('.claude/commands', '.claude/agents', '.claude/skills', '.codex/agents'):
        shutil.copytree(ROOT / name, tmp_path / name)
    command = tmp_path / '.claude/commands/scan.md'
    command.write_text(command.read_text().replace('description:', 'description: Updated ', 1))
    new = tmp_path / '.claude/commands/new-example.md'
    new.write_text('---\ndescription: New workflow\n---\nRead the target.\n')
    stale, obsolete = SYNC.sync(tmp_path)
    assert not obsolete
    assert Path('.agents/skills/scan/SKILL.md') in stale
    assert Path('.agents/skills/new-example/SKILL.md') in stale
    assert not (tmp_path / '.agents/skills/new-example').exists()


def test_regeneration_preserves_native_agent_configuration(tmp_path):
    for name in ('.claude/commands', '.claude/agents', '.codex/agents'):
        shutil.copytree(ROOT / name, tmp_path / name)
    path = next((tmp_path / '.codex/agents').glob('*.toml'))
    original = path.read_text() + '\nmodel = "example-model"\n'
    path.write_text(original)
    before = tomllib.loads(original)
    SYNC.sync(tmp_path, write=True)
    after = tomllib.loads(path.read_text())
    assert {k: v for k, v in before.items() if k != 'developer_instructions'} == {
        k: v for k, v in after.items() if k != 'developer_instructions'}
    assert SYNC.sync(tmp_path) == ([], [])


def test_short_names_preserve_shared_methodologies_and_claude_adapters(tmp_path):
    for name in ('.claude/commands', '.claude/agents', '.claude/skills', '.codex/agents'):
        shutil.copytree(ROOT / name, tmp_path / name)
    shared = tmp_path / '.claude/skills'
    before = {p.relative_to(shared): p.read_bytes() for p in shared.rglob('*') if p.is_file()}
    (tmp_path / '.agents').mkdir()
    (tmp_path / '.agents/skills').symlink_to('../.claude/skills', target_is_directory=True)
    SYNC.sync(tmp_path, write=True)
    assert not (tmp_path / '.agents/skills').is_symlink()
    assert (tmp_path / '.agents/skills/code-understanding').is_symlink()
    assert (tmp_path / '.agents/skills/crash-analysis/gcov-coverage').is_symlink()
    for name in ('audit', 'frida', 'scan', 'commands'):
        wrapper = tmp_path / '.agents/skills' / name / 'SKILL.md'
        assert not wrapper.parent.is_symlink()
        assert yaml.safe_load(wrapper.read_text().split('---', 2)[1])['name'] == name
    assert before == {p.relative_to(shared): p.read_bytes() for p in shared.rglob('*') if p.is_file()}
    assert SYNC.sync(tmp_path) == ([], [])


def test_regeneration_preserves_unmanaged_native_instructions(tmp_path):
    for name in ('.claude/commands', '.claude/agents', '.codex/agents'):
        shutil.copytree(ROOT / name, tmp_path / name)
    path = next((tmp_path / '.codex/agents').glob('*.toml'))
    original = path.read_text().replace(SYNC.MARKER, 'Operator-maintained role instructions')
    path.write_text(original)
    SYNC.sync(tmp_path, write=True)
    assert path.read_text() == original
    assert SYNC.sync(tmp_path) == ([], [])


def test_codex_generated_adapters_never_enter_claude_skill_discovery():
    """A current Codex adapter tree must not hide stale Claude-discovered copies."""
    contaminated = [str(path.relative_to(ROOT))
                    for path in (ROOT / '.claude/skills').rglob('SKILL.md')
                    if SYNC.MARKER in path.read_text()]
    assert not contaminated, f'Codex adapters in Claude skill discovery: {contaminated}'
