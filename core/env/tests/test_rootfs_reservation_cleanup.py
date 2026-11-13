"""An owned empty reservation must not replace its setup failure."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.env import build


@pytest.fixture
def reservation(tmp_path, monkeypatch):
    keep = tmp_path / 'owned-reservation'
    state = SimpleNamespace(keep=keep, primary=None, cleanup=None,
                            identity=None, stats=0, removals=0, dispatches=0)

    class OwnedPath(type(Path())):
        def lstat(self, *args, **kwargs):
            result = super().lstat(*args, **kwargs)
            if self == keep:
                state.stats += 1
                state.identity = (result.st_dev, result.st_ino)
                if state.primary is not None:
                    raise state.primary
            return result

        def rmdir(self):
            assert self == keep
            current = Path(self).lstat()
            assert (current.st_dev, current.st_ino) == state.identity
            super().rmdir()
            state.removals += 1
            if state.cleanup is not None:
                raise state.cleanup

    def forbidden(*args, **kwargs):
        state.dispatches += 1
        pytest.fail('reservation setup failure must precede scratch/build dispatch')

    monkeypatch.setattr(build, 'Path', OwnedPath)
    monkeypatch.setattr(build, '_containerized_build', forbidden)
    monkeypatch.setattr(build, 'scratch_dir', forbidden)
    state.run = lambda: build.containerized_build(
        tmp_path, 'unused inert command', out_dir=tmp_path / 'out', keep_rootfs=keep,
    )
    try:
        yield state
    finally:
        assert state.dispatches == 0
        if keep.exists():
            assert not list(keep.iterdir())
            keep.rmdir()


@pytest.mark.parametrize('primary_type', [KeyboardInterrupt, SystemExit, RuntimeError])
@pytest.mark.parametrize('cleanup_type', [MemoryError, SystemExit, OSError])
def test_setup_primary_survives_consumed_reservation_cleanup(reservation, primary_type, cleanup_type):
    reservation.primary = primary_type('after native owned reservation lstat')
    reservation.cleanup = cleanup_type('after native owned empty reservation removal')
    with pytest.raises(primary_type) as caught:
        reservation.run()
    assert caught.value is reservation.primary
    assert reservation.stats == reservation.removals == 1
    assert reservation.identity is not None and not reservation.keep.exists()
