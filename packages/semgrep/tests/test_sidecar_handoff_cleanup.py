"""Scanner sidecar allocation owns its filename through stream setup failures."""
from pathlib import Path
import tempfile

import pytest

from core.run import scratch
from core.testing.module_bindings import patch_module_attribute
from packages.semgrep import runner


@pytest.mark.parametrize('stage', ['write', 'close'])
@pytest.mark.parametrize('error_type', [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_sidecar_stream_failure_reclaims_file_before_dispatch(tmp_path, monkeypatch, stage, error_type):
    monkeypatch.setattr(runner, 'is_available', lambda: True)
    monkeypatch.setattr(runner, 'scope_isolation_available', lambda: True)
    monkeypatch.setattr('core.config.RaptorConfig.SEMGREP_OFFLINE', False)
    original = tempfile.NamedTemporaryFile
    failure = error_type('owned sidecar stream failure')
    allocated = []

    class Stream:
        def __init__(self, stream):
            self.stream = stream
            self.failed = False
            allocated.append(self)

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

        def write(self, value):
            if stage == 'write':
                self.failed = True
                raise failure
            return self.stream.write(value)

        def close(self):
            self.stream.close()
            if stage == 'close' and not self.failed:
                self.failed = True
                raise failure

    def create(*args, **kwargs):
        return Stream(original(*args, **{**kwargs, 'dir': tmp_path}))

    def forbidden(*args, **kwargs):
        pytest.fail('sidecar setup failure reached tool execution')

    patch_module_attribute(monkeypatch, scratch, 'tempfile', 'NamedTemporaryFile', create)
    with pytest.raises(error_type) as caught:
        runner.run_rule(tmp_path, 'local-rule.yaml', subprocess_runner=forbidden)
    assert caught.value is failure
    assert len(allocated) == 1
    assert allocated[0].failed
    assert allocated[0].stream.closed
    assert not Path(allocated[0].name).exists()
