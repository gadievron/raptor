"""Non-LLM metadata must not initialize the broker source inventory."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]


def test_metadata_configuration_and_filters_do_not_import_broker_registry():
    program = '''
import os, sys
sys.path.insert(0, sys.argv[1])
sys.modules['core.llm.model_brokers'] = None
from core.config import RaptorConfig
os.environ['LC_BROKER_API_KEY'] = 'not-a-real-key'
os.environ['LC_BROKER_API_TOKEN'] = 'not-a-real-token'
safe = RaptorConfig.get_safe_env()
assert 'LC_BROKER_API_KEY' not in safe
assert 'LC_BROKER_API_TOKEN' not in safe
filtered = RaptorConfig.strip_llm_env_vars({'OPENAI_API_KEY': 'not-a-real-key', 'PATH': '/usr/bin'})
assert 'OPENAI_API_KEY' not in filtered
assert filtered['PATH'] == '/usr/bin'
assert sys.modules['core.llm.model_brokers'] is None
'''
    result = subprocess.run([sys.executable, '-I', '-c', program, str(ROOT)],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr


def test_non_llm_helpers_preserve_application_api_credentials():
    from core.config import RaptorConfig
    result = RaptorConfig.strip_llm_env_vars({
        'NVD_API_KEY': 'application-credential', 'OPENAI_API_KEY': 'llm-credential',
    })
    assert result['NVD_API_KEY'] == 'application-credential'
    assert 'OPENAI_API_KEY' not in result


def test_explicit_credential_namespace_overrides_are_still_stripped(monkeypatch):
    from core.config import RaptorConfig
    monkeypatch.setattr(RaptorConfig, 'LLM_API_KEY_VARS', ('LC_CUSTOM_AUTH',))
    monkeypatch.setenv('LC_CUSTOM_AUTH', 'not-a-real-credential')
    assert 'LC_CUSTOM_AUTH' not in RaptorConfig.get_safe_env()
    assert 'LC_CUSTOM_AUTH' not in RaptorConfig.strip_llm_env_vars({'LC_CUSTOM_AUTH': 'value'})
