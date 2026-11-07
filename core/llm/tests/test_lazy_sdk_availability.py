"""Metadata discovery stays cheap; selected SDKs still undergo real imports."""
import os
from pathlib import Path
import subprocess
import sys

import pytest

from core.llm import detection

ROOT = Path(__file__).resolve().parents[3]


def test_offline_resolution_does_not_import_unselected_sdks(tmp_path):
    script = r'''
import os, sys, importlib.abc
sys.path.insert(0, os.environ['RAPTOR_DIR'])
seen = []
class NoSDK(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in {'openai', 'anthropic', 'google.genai', 'botocore'}:
            seen.append(fullname)
            raise ImportError('SDK import blocked by test')
sys.meta_path.insert(0, NoSDK())
from core.llm.config import _get_default_primary_model
_get_default_primary_model(offline=True)
assert seen == [], seen
'''
    env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
           'HOME': str(tmp_path), 'RAPTOR_DIR': str(ROOT),
           'PYTHONDONTWRITEBYTECODE': '1'}
    result = subprocess.run([sys.executable, '-I', '-c', script],
                            cwd=tmp_path, env=env, text=True,
                            capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('flag,module', list(detection._SDK_IMPORTS.items()))
@pytest.mark.parametrize('available', [True, False])
def test_lazy_flags_validate_real_import_once(monkeypatch, flag, module, available):
    import importlib
    calls = []
    monkeypatch.setattr(detection, '_SDK_AVAILABILITY', {})
    monkeypatch.delitem(vars(detection), flag, raising=False)

    def probe(name):
        assert name == module
        calls.append(name)
        if not available:
            raise ImportError('broken SDK installation')
        return object()

    monkeypatch.setattr(importlib, 'import_module', probe)
    assert getattr(detection, flag) is available
    assert getattr(detection, flag) is available
    assert calls == [module]
    monkeypatch.setitem(vars(detection), flag, not available)
    assert detection._sdk_available(flag) is (not available)
    assert calls == [module]


def test_missing_selected_sdk_is_not_advertised(monkeypatch):
    import importlib
    from core.llm import config
    monkeypatch.setenv('OPENAI_API_KEY', 'test-only-key')
    monkeypatch.setattr(detection, '_SDK_AVAILABILITY', {})
    monkeypatch.delitem(vars(detection), 'OPENAI_SDK_AVAILABLE', raising=False)

    def missing(name):
        assert name == 'openai'
        raise ImportError('broken SDK installation')

    monkeypatch.setattr(importlib, 'import_module', missing)
    assert config._build_openai_compat_config('openai') is None
    assert config.OPENAI_SDK_AVAILABLE is False


def test_availability_names_remain_discoverable_without_sdk_probes(monkeypatch):
    from core.llm import config
    monkeypatch.setattr(detection, '_SDK_AVAILABILITY', {})
    assert set(detection._SDK_IMPORTS) <= set(dir(detection))
    assert set(detection._SDK_IMPORTS) <= set(detection.__all__)
    assert 'OPENAI_SDK_AVAILABLE' in dir(config)
    assert 'OPENAI_SDK_AVAILABLE' in config.__all__
    assert detection._SDK_AVAILABILITY == {}
