"""Owned fixtures exercise small parser adapters without installed vendors."""
import subprocess

import pytest


from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize('adapter', ['autodetect', 'capabilities', 'addr2line', 'ebpf', 'ghidra', 'scanner', 'objdump'])
def test_small_parser_adapter_reaches_sandbox(tmp_path, monkeypatch, adapter):
    from core import sandbox
    import shutil
    binary = tmp_path / 'owned'
    binary.write_bytes(b'\x7fELF' + b'\0' * 64)
    monkeypatch.setattr(shutil, 'which', lambda name, **kwargs: '/usr/bin/' + name)
    seen = []
    def run(command, **options):
        seen.append(options)
        assert options.get('target'), 'parser has no filesystem scope'
        assert options['capture_output'] is True
        if adapter != 'ebpf':
            assert options['block_network'] is True
        if adapter == 'ebpf':
            assert options['output'] == options['target']
        if adapter == 'ghidra':
            assert options['restrict_reads'] is True
        if adapter == 'scanner':
            assert options['fake_home'] is True
        stdout = '.debug_info\nDW_TAG_compile_unit\n' if adapter in ('autodetect', 'capabilities') else 'owned.c:9\n'
        return subprocess.CompletedProcess(command, 0, stdout, '')
    monkeypatch.setattr(sandbox, 'run', run)
    if adapter == 'autodetect':
        from core.analysis.binary_oracle_autodetect import _has_dwarf
        assert _has_dwarf(binary)
    elif adapter == 'capabilities':
        from core.audit.capabilities import _has_dwarf
        assert _has_dwarf(binary)
    elif adapter == 'addr2line':
        from core.orchestration.frida_validation_bridge import _addr2line_batch
        assert _addr2line_batch(binary, [16]) == {16: 'owned.c:9'}
    elif adapter == 'ghidra':
        from packages.ghidra import headless, ebpf_probe
        monkeypatch.setattr(headless, '_find_headless', lambda: '/usr/bin/analyzeHeadless')
        monkeypatch.setattr(headless, '_install_read_paths', lambda *a: [str(tmp_path)])
        ebpf_probe.ghidra_decode([], tmp_path / 'work')
    elif adapter == 'objdump':
        from packages.ghidra.objdump_import import _run_binutil
        assert _run_binutil(['/usr/bin/objdump', '-d', str(binary)], binary).returncode == 0
    elif adapter == 'scanner':
        import importlib
        module = importlib.import_module('packages.static-analysis.scanner')
        assert module.run(['/usr/bin/semgrep', '--version'], target=str(tmp_path),
                          output=str(tmp_path), fake_home=True)[0] == 0
    else:
        from packages.binary_analysis.corpus_profile import _run_bpf_objdump
        assert _run_bpf_objdump('/usr/bin/llvm-objdump', b'\x95' + b'\0' * 7)
    assert len(seen) == 1


def test_corpus_workload_dispatches_owned_build_through_sandbox(tmp_path, monkeypatch):
    from core import git, sandbox
    from core.inventory.binary_oracle_corpora import zstd_holdout as driver
    seen = []
    monkeypatch.setattr(git, 'clone_repository', lambda *a, **k: True)
    monkeypatch.setattr(git, 'get_safe_git_env', lambda: {})
    patch_module_attribute(monkeypatch, driver, 'subprocess', 'run', lambda *a, **k: subprocess.CompletedProcess(a, 0))
    monkeypatch.setattr(driver, 'run_build_step', lambda *a, **k: None)
    build = tmp_path / 'build-o0'
    def run(command, **options):
        assert options['target'] == str(build)
        assert options['output'] == str(build / 'workload')
        assert options['writable_paths'] == [str(build)]
        assert options['block_network'] is True
        assert options['check'] is True
        seen.append(command)
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(sandbox, 'run', run)
    driver._build_fresh(tmp_path / 'tag', build, tmp_path / 'build-o2')
    assert len(seen) > 1
