"""Rule preparation failures close the already-created sandbox scratch."""

import pytest
from packages.code_understanding.dispatch import hunt_cocci_dispatch as dispatch
from core.run import scratch


@pytest.mark.parametrize("error", [OSError("disk full"), KeyboardInterrupt()])
def test_rule_write_failure_closes_sandbox_scratch(tmp_path, monkeypatch, error):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "f.c").write_text("int f() {}")
    allocated = tmp_path / "scratch"
    allocated.mkdir()
    monkeypatch.setattr(dispatch, "spatch_is_available", lambda: True)
    monkeypatch.setattr(
        dispatch, "translate_pattern_to_cocci_rule", lambda *a, **kw: "@@\n@@\nfoo();"
    )
    monkeypatch.setattr(dispatch, "_make_locked_sandbox_runner", lambda *a: object())
    monkeypatch.setattr(scratch.tempfile, "mkdtemp", lambda **kw: str(allocated))

    def failed_write(*args, **kw):
        raise error

    monkeypatch.setattr(scratch.tempfile, "NamedTemporaryFile", failed_write)
    if isinstance(error, OSError):
        result = dispatch.cocci_hunt_dispatch(None, "find foo", str(repo))
        assert "error" in result[0]
    else:
        with pytest.raises(type(error)):
            dispatch.cocci_hunt_dispatch(None, "find foo", str(repo))
    assert not allocated.exists()
