"""Build wrapper allocation owns its filename through stream setup failures."""
from pathlib import Path
import tempfile

import pytest

from core.run import scratch
from core.testing.module_bindings import patch_module_attribute
from packages.codeql.tests import test_traced_build_wrapper_location as cases


@pytest.mark.parametrize('stage', ['write', 'close'])
@pytest.mark.parametrize('error_type', [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_wrapper_stream_failure_reclaims_file_before_dispatch(tmp_path, monkeypatch, stage, error_type):
    manager = cases.db_manager.__wrapped__(tmp_path)
    original = tempfile.NamedTemporaryFile
    failure = error_type('owned wrapper stream failure')
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

    patch_module_attribute(monkeypatch, scratch, 'tempfile', 'NamedTemporaryFile', create)
    with pytest.raises(error_type) as caught:
        cases._run_traced_create(manager, tmp_path)
    assert caught.value is failure
    assert len(allocated) == 1
    assert allocated[0].failed
    assert allocated[0].stream.closed
    assert not Path(allocated[0].name).exists()
