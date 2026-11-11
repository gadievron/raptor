"""Native owned-trail readback cancellation is not an ordinary refusal."""
import errno
import json
import os
from types import SimpleNamespace

import pytest

from core.audit import refutation
from core.testing.module_views import module_function_view


@pytest.mark.parametrize('failure', [None, OSError, TypeError, KeyboardInterrupt, SystemExit, GeneratorExit])
@pytest.mark.parametrize('close_error', [False, True])
def test_witness_readback_native_cleanup(tmp_path, failure, close_error):
    primary = failure('after native witness trail read') if failure else None
    resources = []

    class Stream:
        def __init__(self, stream):
            self.stream = stream
            self.fd = stream.fileno()
            self.reads = self.seeks = self.closes = 0

        def __enter__(self):
            self.stream.__enter__()
            return self

        def seek(self, offset):
            self.seeks += 1
            return self.stream.seek(offset)

        def read(self):
            data = self.stream.read()
            rows = [json.loads(line) for line in data.splitlines()]
            assert len(rows) == 1
            assert rows[0]['finding_id'] == 'audit-refutation:owned.c:f:1'
            assert rows[0]['verdict'] == 'in_function_witness_corroborates_dismissal'
            assert rows[0]['dropped'] is False
            self.reads += 1
            if primary is not None:
                raise primary
            return data

        def __exit__(self, *args):
            self.closes += 1
            self.stream.__exit__(*args)
            if close_error:
                raise OSError('after native witness trail close')

    def open_owned(path, mode):
        stream = refutation.open_regular(path, mode)
        assert stream is not None
        wrapped = Stream(stream)
        resources.append(wrapped)
        return wrapped

    view = module_function_view(refutation, bindings={'open_regular': open_owned})
    caught = None
    result = None
    try:
        try:
            result = view._record_witness_discharge(
                SimpleNamespace(file='owned.c', function='f', line=1), tmp_path,
                mechanism='owned readback fixture', corroboration=['owned fixture'],
            )
        except BaseException as exc:
            caught = exc
        assert len(resources) == 1
        resource = resources[0]
        assert resource.seeks == resource.reads == resource.closes == 1
        assert resource.stream.closed
        with pytest.raises(OSError) as retired:
            os.fstat(resource.fd)
        assert retired.value.errno == errno.EBADF
        assert (tmp_path / 'suppressions.jsonl').is_file()
        if failure in (KeyboardInterrupt, SystemExit, GeneratorExit):
            assert caught is primary
        else:
            assert caught is None
            assert result is (failure is None and not close_error)
    finally:
        for resource in resources:
            if not resource.stream.closed:
                resource.stream.close()
