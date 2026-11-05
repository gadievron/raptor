"""Cancellation between I/O and bookkeeping cannot lose resynchronization."""
import json
import os
import sys

import pytest

from core.sandbox import evidence


class Cancelled(BaseException):
    pass


def test_cancel_after_short_write_keeps_recovery_pending(tmp_path, monkeypatch):
    handle = evidence.EvidenceFile.open(tmp_path, 'events.jsonl')
    original_write = os.write
    original_trace = sys.gettrace()
    writes = []
    interrupted = False

    def short_once(fd, data):
        writes.append(bytes(data))
        return original_write(fd, data[:5] if len(writes) == 1 else data)

    def cancel_after_return(frame, event, arg):
        nonlocal interrupted
        if (frame.f_code is evidence.EvidenceFile.write_line.__code__
                and event == 'line' and 'written' in frame.f_locals
                and not interrupted):
            interrupted = True
            raise Cancelled('after write, before bookkeeping')
        return cancel_after_return

    try:
        monkeypatch.setattr(os, 'write', short_once)
        try:
            sys.settrace(cancel_after_return)
            with pytest.raises(Cancelled, match='before bookkeeping'):
                handle.write_record({'first': 'incomplete'})
        finally:
            sys.settrace(original_trace)
        assert interrupted
        assert handle.write_record({'second': 'preserved'})
        assert json.loads(handle.path.read_bytes().splitlines()[-1]) == {'second': 'preserved'}
        assert writes[1].startswith(b'\n')
        assert len(writes) == 2
    finally:
        sys.settrace(original_trace)
        handle.close()
