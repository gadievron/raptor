"""Registry fixture teardown owns launch producers without changing policy."""

import os
from pathlib import Path

import pytest

from core.security import env_sanitisation, launch_scratch
from core.testing.state_isolation import pin_user_state_dirs

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX launcher scratch authority")


@pytest.mark.parametrize("finish", ["normal", "error", "interrupt", "close"])
def test_real_restore_does_not_outlive_registry_owner(tmp_path, monkeypatch, finish):
    root = tmp_path / f"raptor-{os.geteuid()}" / f"session-{os.getpid()}-123"
    root.mkdir(parents=True, mode=0o700)
    metadata = launch_scratch.create(root)
    token = launch_scratch.issue(tmp_path / "authorities", metadata, os.getpid())
    monkeypatch.setenv("_RAPTOR_SCRATCH_AUTH", token)
    monkeypatch.setattr(launch_scratch, "_restored", False)
    monkeypatch.setattr(launch_scratch, "_metadata_path", None)
    monkeypatch.setattr(env_sanitisation, "_subprocess_tmpdir", None)
    before = dict(os.environ)

    def lifecycle():
        with pytest.MonkeyPatch.context() as owner:
            pin_user_state_dirs(owner, tmp_path / "registry")
            launch_scratch.restore()
            assert launch_scratch._restored
            assert Path(env_sanitisation._subprocess_tmpdir).is_dir()
            changed = os.environ["_RAPTOR_SCRATCH_AUTH"] != token
            assert changed, "the native delegation producer was not reached"
            yield

    scope = lifecycle()
    next(scope)
    if finish == "normal":
        with pytest.raises(StopIteration):
            next(scope)
    elif finish == "close":
        scope.close()
    else:
        error = RuntimeError if finish == "error" else KeyboardInterrupt
        with pytest.raises(error):
            scope.throw(error("fixture consumer failed"))
    restored = dict(os.environ) == before
    assert restored, "fixture left borrowed environment changed"
    assert launch_scratch._restored is False
    assert launch_scratch._metadata_path is None
    assert env_sanitisation._subprocess_tmpdir is None
    # The fixture restores references; it does not revoke the caller's launch.
    authorized_metadata, _ = launch_scratch._restore_authorized(token)
    assert authorized_metadata == metadata


@pytest.mark.parametrize("initial", [None, "", "retired-authorization"])
def test_registry_owner_preserves_missing_empty_and_stale_values(tmp_path, monkeypatch, initial):
    name = "_RAPTOR_SCRATCH_AUTH"
    monkeypatch.setenv(name, "")
    if initial is None:
        monkeypatch.delenv(name)
    else:
        monkeypatch.setenv(name, initial)
    before = dict(os.environ)
    restored = launch_scratch._restored
    metadata = launch_scratch._metadata_path
    scratch = env_sanitisation._subprocess_tmpdir
    with pytest.MonkeyPatch.context() as owner:
        pin_user_state_dirs(owner, tmp_path / "registry")
        unchanged = os.environ.get(name) == initial
        assert unchanged, "registry pin silently changed launch policy"
        os.environ[name] = "producer-replacement"
        launch_scratch._restored = not restored
        launch_scratch._metadata_path = tmp_path / "retired-metadata"
        env_sanitisation._subprocess_tmpdir = str(tmp_path / "retired-scratch")
    unchanged = dict(os.environ) == before
    assert unchanged, "registry pin did not restore the borrowed environment"
    assert launch_scratch._restored is restored
    assert launch_scratch._metadata_path is metadata
    assert env_sanitisation._subprocess_tmpdir is scratch


def test_fixture_does_not_turn_retired_authority_into_standalone_success(tmp_path):
    import shutil

    root = tmp_path / f"raptor-{os.geteuid()}" / f"session-{os.getpid()}-123"
    root.mkdir(parents=True, mode=0o700)
    metadata = launch_scratch.create(root)
    retired = launch_scratch.issue(tmp_path / "authorities", metadata, os.getpid())
    shutil.rmtree(root)
    before = dict(os.environ)
    with pytest.MonkeyPatch.context() as owner:
        pin_user_state_dirs(owner, tmp_path / "registry")
        owner.setenv("_RAPTOR_SCRATCH_AUTH", retired)
        owner.setattr(launch_scratch, "_restored", False)
        with pytest.raises(PermissionError, match="authorization is unavailable or stale"):
            launch_scratch.restore()
    unchanged = dict(os.environ) == before
    assert unchanged, "refusal path changed the caller's launch state"
