"""Direct rule-language reader ownership without scanner execution."""
import errno
import os

import pytest
from pathlib import Path
from core.audit import sweep as source


@pytest.mark.parametrize("body_kind", ["healthy", "cancel", "io", "unexpected"])
@pytest.mark.parametrize("close_kind", ["healthy", "io", "cancel"])
def test_rule_language_reader_precedence(tmp_path, monkeypatch, body_kind, close_kind):
    path = tmp_path / "owned.yaml"
    content = "rules:\n  - id: owned\n    languages: [php]\n"
    path.write_text(content)
    primary = {"healthy": None, "cancel": KeyboardInterrupt("owned rule read interruption"),
               "io": OSError("owned rule read failure"),
               "unexpected": TypeError("owned unexpected read error")}[body_kind]
    cleanup = {"healthy": None, "io": OSError("owned close aftereffect"),
               "cancel": KeyboardInterrupt("owned close cancellation")}[close_kind]
    streams = []
    original_path = source.Path

    class Observed:
        def __init__(self, stream):
            self.stream = stream
            self.fd = stream.fileno()
            self.reads = self.closes = 0

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            self.closes += 1
            self.stream.__exit__(*args)
            if cleanup is not None:
                raise cleanup

        def read(self, size):
            self.reads += 1
            assert size == source._RULE_LANGS_MAX_BYTES
            assert self.stream.read(size) == content
            if primary is not None:
                raise primary
            return content

    class ObservedPath(type(Path())):
        def open(self, *args, **kwargs):
            stream = super().open(*args, **kwargs)
            wrapped = Observed(stream)
            streams.append(wrapped)
            return wrapped

    observed = None
    result = None
    try:
        try:
            with monkeypatch.context() as scope:
                scope.setattr(source, "Path", ObservedPath)
                result = source._rule_languages_include(str(path), "php")
        except BaseException as error:
            observed = error
        assert source.Path is original_path
        assert len(streams) == 1 and streams[0].reads == 1
        assert streams[0].closes == 1 and streams[0].stream.closed
        try:
            os.fstat(streams[0].fd)
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            raise AssertionError("owned descriptor remained live")
        assert path.read_text() == content
        expected = primary if primary is not None else cleanup
        if isinstance(expected, OSError):
            assert observed is None and result is False
        elif expected is not None:
            assert observed is expected and result is None
        else:
            assert observed is None and result is True
    finally:
        for wrapped in streams:
            if not wrapped.stream.closed:
                wrapped.stream.close()
