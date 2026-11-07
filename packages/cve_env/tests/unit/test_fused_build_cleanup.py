"""An automatic context remains owned until a build succeeds."""

from types import SimpleNamespace
import pytest
from cve_env.agent import tools


from core.testing.module_bindings import patch_module_attribute


@pytest.mark.parametrize("error", [OSError("disk full"), KeyboardInterrupt()])
@pytest.mark.parametrize("automatic", [True, False])
def test_fused_build_exception_respects_context_ownership(
    tmp_path, monkeypatch, error, automatic
):
    context = tmp_path / "context"
    context.mkdir()
    (context / "Dockerfile").write_text("partial data")
    patch_module_attribute(monkeypatch, tools, 'tempfile', "mkdtemp", lambda **kw: str(context))

    def fail(**kw):
        raise error

    monkeypatch.setattr(tools._docker_build, "docker_build", fail)
    args = {} if automatic else {"context_dir": str(context)}
    with pytest.raises(type(error)):
        tools._maybe_fuse_build({"ok": True, "dockerfile_text": "FROM scratch"}, args)
    assert context.exists() is (not automatic)


def test_successful_fused_build_keeps_automatic_context(tmp_path, monkeypatch):
    context = tmp_path / "context"
    context.mkdir()
    patch_module_attribute(monkeypatch, tools, 'tempfile', "mkdtemp", lambda **kw: str(context))
    result = SimpleNamespace(
        ok=True,
        image_tag="image",
        exit_code=0,
        reason="",
        reason_class="ok",
        stderr_tail="",
        suggested_patch="",
        next_step_hint="",
    )
    monkeypatch.setattr(tools._docker_build, "docker_build", lambda **kw: result)
    payload = tools._maybe_fuse_build(
        {"ok": True, "dockerfile_text": "FROM scratch"}, {}
    )
    assert payload["context_dir"] == str(context)
    assert context.exists()
