"""Cleanup failures must not strand later resources or hide the first error."""

from types import SimpleNamespace

import pytest

from core.env import handle as handles
from core.env import provision as pv
from core.env.spec import EnvironmentSpec, RunSpec, SourceSpec
from core.testing.restricted_tree import restricted_tree


@pytest.fixture
def resources(tmp_path, monkeypatch):
    work = tmp_path / "owned"
    work.mkdir()
    live = {work}
    calls = []
    for kind in ("containers", "networks", "images"):
        monkeypatch.setattr(
            pv, "remove_labeled_" + kind, lambda *a, kind=kind: calls.append(kind)
        )
    monkeypatch.setattr(
        pv,
        "keepalive_unregister",
        lambda path: (calls.append("unregister"), live.discard(path)),
    )
    handle = SimpleNamespace(teardown=lambda: calls.append("handle"))
    env = pv.Environment(
        spec=None,
        handle=handle,
        image_ref="image",
        provision_id="owned-id",
        owned_workdir=work,
    )
    return SimpleNamespace(work=work, live=live, calls=calls, handle=handle, env=env)


@pytest.mark.parametrize(
    "fault", ["handle", "containers", "networks", "images", "unregister"]
)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_teardown_attempts_every_resource_after_failure(
    resources, monkeypatch, fault, error
):
    sentinel = error("original failure")

    def fail(*args):
        resources.calls.append(fault)
        if fault == "unregister":
            resources.live.discard(resources.work)
        raise sentinel

    if fault == "handle":
        monkeypatch.setattr(resources.handle, "teardown", fail)
    elif fault == "unregister":
        monkeypatch.setattr(pv, "keepalive_unregister", fail)
    else:
        monkeypatch.setattr(pv, "remove_labeled_" + fault, fail)
    with pytest.raises(error) as caught:
        resources.env.teardown()
    assert caught.value is sentinel
    assert resources.calls == [
        "handle",
        "containers",
        "networks",
        "images",
        "unregister",
    ]
    assert not resources.work.exists()
    assert not resources.live


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
@pytest.mark.parametrize("owner", ["environment", "sandbox"])
def test_teardown_reclaims_restricted_owned_trees(resources, mode, owner):
    with restricted_tree(resources.work / "rootfs", mode) as rootfs:
        if owner == "environment":
            resources.env.teardown()
        else:
            handle = handles.SandboxHandle.__new__(handles.SandboxHandle)
            handle.rootfs = rootfs
            handle._torn_down = False
            handle.teardown()
        assert not rootfs.exists()


@pytest.mark.parametrize("owner", ["environment", "sandbox"])
def test_failed_tree_removal_is_reported_and_can_be_retried(
    resources, monkeypatch, owner
):
    if owner == "environment":
        target = resources.env
        module = pv
    else:
        target = handles.SandboxHandle.__new__(handles.SandboxHandle)
        target.rootfs = resources.work
        target._torn_down = False
        module = handles
    with monkeypatch.context() as fault:
        fault.setattr(module, "rmtree_hardened", lambda path: False, raising=False)
        with pytest.raises(OSError):
            target.teardown()
    assert resources.work.exists()
    target.teardown()
    assert not resources.work.exists()


@pytest.fixture
def provision_setup(resources, monkeypatch):
    spec = EnvironmentSpec(
        name="test",
        version="1",
        source=SourceSpec(kind="image", image_ref="image"),
        run=RunSpec(surface="http", port=80),
    )
    monkeypatch.setattr(pv.tempfile, "mkdtemp", lambda **kwargs: str(resources.work))
    monkeypatch.setattr(pv, "keepalive_register", resources.live.add)
    return spec


@pytest.mark.parametrize("fault", ["containers", "networks", "images"])
@pytest.mark.parametrize("original", [TypeError, KeyboardInterrupt])
def test_provision_preserves_original_exception_after_cleanup_failure(
    resources, provision_setup, monkeypatch, fault, original
):
    sentinel = original("provision failed")

    def step(*args, **kwargs):
        (kwargs["work"] / "partial").write_text("payload")
        raise sentinel

    def fail(*args):
        resources.calls.append(fault)
        raise OSError("cleanup failed")

    monkeypatch.setattr(pv, "_provision_steps", step)
    monkeypatch.setattr(pv, "remove_labeled_" + fault, fail)
    with pytest.raises(original) as caught:
        pv.provision(provision_setup)
    assert caught.value is sentinel
    assert set(resources.calls) == {"containers", "networks", "images", "unregister"}
    assert not resources.work.exists()
    assert not resources.live


@pytest.mark.parametrize("fault", ["containers", "networks", "images"])
def test_structured_provision_failure_survives_cleanup_error(
    resources, provision_setup, monkeypatch, fault
):
    def fail(*args):
        resources.calls.append(fault)
        raise OSError("cleanup failed")

    def step(*args, **kwargs):
        return kwargs["fail"](reason="launch_failed", detail="original detail")

    monkeypatch.setattr(pv, "_provision_steps", step)
    monkeypatch.setattr(pv, "remove_labeled_" + fault, fail)
    outcome = pv.provision(provision_setup)
    assert not outcome.ok
    assert outcome.reason == "launch_failed"
    assert outcome.detail == "original detail"
    assert not resources.work.exists()
    assert not resources.live


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_registration_failure_still_releases_owned_allocation(
    resources, provision_setup, monkeypatch, error
):
    sentinel = error("registration failed")

    def register(path):
        resources.live.add(path)
        raise sentinel

    monkeypatch.setattr(pv, "keepalive_register", register)
    with pytest.raises(error) as caught:
        pv.provision(provision_setup)
    assert caught.value is sentinel
    assert not resources.work.exists()
    assert not resources.live


def test_teardown_preserves_first_of_multiple_errors(resources, monkeypatch):
    first = OSError("runtime stop failed")

    def handle():
        resources.calls.append("handle")
        raise first

    def containers(*args):
        resources.calls.append("containers")
        raise ValueError("container cleanup failed")

    monkeypatch.setattr(resources.handle, "teardown", handle)
    monkeypatch.setattr(pv, "remove_labeled_containers", containers)
    with pytest.raises(OSError) as caught:
        resources.env.teardown()
    assert caught.value is first
    assert not resources.work.exists()
    assert "images" in resources.calls


@pytest.mark.parametrize("fault", ["containers", "networks", "images"])
def test_cleanup_errors_never_remove_caller_owned_workdir(
    resources, provision_setup, monkeypatch, fault
):
    payload = resources.work / "operator-data"
    payload.write_text("keep")

    def step(*args, **kwargs):
        raise TypeError("original provision error")

    def fail(*args):
        resources.calls.append(fault)
        raise OSError("cleanup failed")

    monkeypatch.setattr(pv, "_provision_steps", step)
    monkeypatch.setattr(pv, "remove_labeled_" + fault, fail)
    with pytest.raises(TypeError, match="original provision error"):
        pv.provision(provision_setup, workdir=resources.work)
    assert payload.read_text() == "keep"
    assert resources.work in resources.live
    assert "unregister" not in resources.calls


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
def test_provision_failure_reclaims_restricted_partial_workdir(
    resources, provision_setup, monkeypatch, mode
):
    def step(*args, **kwargs):
        return kwargs["fail"](reason="launch_failed", detail="original detail")

    monkeypatch.setattr(pv, "_provision_steps", step)
    with restricted_tree(resources.work / "rootfs", mode):
        result = pv.provision(provision_setup)
        assert not result.ok
        assert not resources.work.exists()
        assert not resources.live


@pytest.mark.parametrize("owner", ["environment", "sandbox"])
def test_cleanup_refuses_replaced_symlink_root(resources, tmp_path, owner):
    outside = tmp_path / "operator-data"
    outside.mkdir(mode=0o750)
    payload = outside / "payload"
    payload.write_text("keep")
    mode = outside.stat().st_mode
    resources.work.rename(tmp_path / "old-work")
    resources.work.symlink_to(outside, target_is_directory=True)
    if owner == "environment":
        target = resources.env
    else:
        target = handles.SandboxHandle.__new__(handles.SandboxHandle)
        target.rootfs = resources.work
        target._torn_down = False
    with pytest.raises(OSError):
        target.teardown()
    assert payload.read_text() == "keep"
    assert outside.stat().st_mode == mode
    assert resources.work.is_symlink()


def test_failed_workdir_cleanup_preserves_provision_failure_and_releases_keepalive(
    resources, provision_setup, monkeypatch
):
    def step(*args, **kwargs):
        return kwargs["fail"](reason="export_failed", detail="original export error")

    monkeypatch.setattr(pv, "_provision_steps", step)
    monkeypatch.setattr(pv, "rmtree_hardened", lambda path: False)
    result = pv.provision(provision_setup)
    assert not result.ok
    assert result.reason == "export_failed"
    assert result.detail == "original export error"
    assert resources.work.exists()
    assert not resources.live


@pytest.mark.parametrize("owner", ["environment", "sandbox"])
def test_successful_cleanup_does_not_claim_a_later_directory_at_same_path(
    resources, owner
):
    if owner == "environment":
        target = resources.env
    else:
        target = handles.SandboxHandle.__new__(handles.SandboxHandle)
        target.rootfs = resources.work
        target._torn_down = False
    target.teardown()
    resources.work.mkdir()
    payload = resources.work / "operator-data"
    payload.write_text("keep")
    target.teardown()
    assert payload.read_text() == "keep"


def test_workdir_ownership_is_released_even_if_runtime_cleanup_failed(
    resources, monkeypatch
):
    def fail():
        raise OSError("runtime stop failed")

    with monkeypatch.context() as fault:
        fault.setattr(resources.handle, "teardown", fail)
        with pytest.raises(OSError):
            resources.env.teardown()
    assert resources.env.owned_workdir is None
    resources.work.mkdir()
    payload = resources.work / "operator-data"
    payload.write_text("keep")
    resources.env.teardown()
    assert payload.read_text() == "keep"
