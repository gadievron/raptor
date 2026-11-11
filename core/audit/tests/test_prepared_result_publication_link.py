"""Retained-result names are revalidated after the anchored read."""
import errno
import os
from types import SimpleNamespace

import pytest

from core.audit import prepared_result_retention as module
from core.audit.sweep import SweepResult
from core.testing.module_views import module_function_view
from .test_prepared_claim_context import case  # noqa: F401 -- imported pytest fixture
from .test_prepared_claim_pipeline import pipeline_case  # noqa: F401 -- imported pytest fixture


@pytest.mark.parametrize("changed", ["file-missing", "file-replaced", "directory-replaced", "directory-link"])
def test_publication_refuses_result_name_changed_during_native_read(tmp_path, changed):
    result = SweepResult(tool="smt", file_path="unit.c", function_name="Read",
                         outcome="inconclusive", rule_id="smt:check-overflow",
                         raw_output="retained existing result", details={"existing": True})
    reference = module.retain_smt_result(tmp_path, result)
    path = tmp_path / reference
    original = path.read_bytes()
    reads, opened, live = [], [], set()
    native_open, native_read, native_close = os.open, os.read, os.close

    def open_fd(*args, **kwargs):
        fd = native_open(*args, **kwargs)
        opened.append(fd)
        live.add(fd)
        return fd

    def close_fd(fd):
        native_close(fd)
        live.remove(fd)

    def read(fd, size):
        chunk = native_read(fd, size)
        if chunk and not reads:
            reads.append(fd)
            if changed.startswith("file"):
                path.unlink()
                if changed == "file-replaced":
                    path.write_bytes(original)
            else:
                saved = tmp_path / "saved-results"
                path.parent.rename(saved)
                if changed == "directory-link":
                    path.parent.symlink_to(saved, target_is_directory=True)
                else:
                    path.parent.mkdir()
                    path.write_bytes(original)
        return chunk

    private_os = SimpleNamespace(**{**vars(os), "open": open_fd, "read": read, "close": close_fd})
    view = module_function_view(module, bindings={"os": private_os})
    try:
        matched = view.retained_smt_result_matches(tmp_path, reference, result)
        assert reads and not live
        for fd in set(opened):
            with pytest.raises(OSError) as caught:
                os.fstat(fd)
            assert caught.value.errno == errno.EBADF
        assert os.open is native_open and os.read is native_read and os.close is native_close
        if changed != "file-missing":
            assert path.read_bytes() == original
        assert matched is False
    finally:
        for fd in live:
            native_close(fd)


def test_shadow_withdraws_fact_when_result_directory_changes_during_read(pipeline_case, monkeypatch):  # noqa: F811 -- imported fixture
    from .test_prepared_claim_pipeline import publish, run

    c = pipeline_case
    _, first = run(c)
    assert first["claims"][0]["supported_obligations"] == ["entry-arithmetic-out-of-range"]
    reference = first["preparation_availability"][0]["fact_event"]["raw_reference"]
    original = (c.out / reference).read_bytes()
    reads = []
    native_read = os.read

    def read(fd, size):
        chunk = native_read(fd, size)
        if chunk and not reads:
            reads.append(fd)
            directory = c.out / module.RESULT_DIRECTORY
            directory.rename(c.out / "saved-results")
            directory.mkdir()
        return chunk

    private_os = SimpleNamespace(**{**vars(os), "read": read})
    view = module_function_view(module, bindings={"os": private_os})
    monkeypatch.setattr(module, "retained_smt_result_matches", view.retained_smt_result_matches)
    shadow = publish(c)
    assert reads and len(c.calls) == 1
    assert (c.out / "saved-results" / reference.split("/")[1]).read_bytes() == original
    assert shadow["claims"][0]["supported_obligations"] == []
    assert shadow["preparation_availability"][0]["fact_event"] is None
    assert shadow["authoritative"] is False
    assert os.read is native_read
