"""Restricted-tree setup failures reclaim owned native filesystem state."""

from contextlib import ExitStack, contextmanager
from types import FunctionType
import stat

import pytest
from core.atomic_fs import rmtree_hardened
from core.testing.restricted_tree import restricted_tree


@pytest.mark.parametrize("stage", ["mkdir", "write", "chmod"])
@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_setup_refusal_reclaims_owned_tree(stage, after, error, tmp_path):
    failure = error("owned restricted-tree setup refusal")
    entered, reached = [], []

    class FaultPath(type(tmp_path)):
        def mkdir(self, *args, **kwargs):
            if stage == "mkdir" and self.name == "nested" and not reached:
                reached.append(stage)
                if after:
                    super().mkdir(*args, **kwargs)
                raise failure
            return super().mkdir(*args, **kwargs)

        def write_bytes(self, data):
            if stage == "write" and self.name == "payload":
                reached.append(stage)
                if after:
                    super().write_bytes(data)
                raise failure
            return super().write_bytes(data)

        def chmod(self, mode, *args, **kwargs):
            if stage == "chmod" and self.name == "locked":
                reached.append(stage)
                if after:
                    super().chmod(mode, *args, **kwargs)
                    assert stat.S_IMODE(self.stat().st_mode) == mode
                raise failure
            return super().chmod(mode, *args, **kwargs)

    root = FaultPath(tmp_path / "owned")
    sibling = tmp_path / "borrowed"
    sibling.write_bytes(b"preserve")
    try:
        with pytest.raises(error) as caught:
            with ExitStack() as scope:
                scope.enter_context(restricted_tree(root))
                entered.append(True)
        assert caught.value is failure
        assert reached == [stage]
        assert not entered
        assert not root.exists()
        assert sibling.read_bytes() == b"preserve"
    finally:
        assert rmtree_hardened(root)
        assert sibling.read_bytes() == b"preserve"


@pytest.mark.parametrize("mode", [0o000, 0o500, 0o555])
@pytest.mark.parametrize("error", [None, OSError, KeyboardInterrupt, SystemExit])
def test_body_keeps_native_tree_and_original_error(mode, error, tmp_path):
    root = tmp_path / "owned"
    failure = error("owned restricted-tree body") if error else None

    def invoke():
        with restricted_tree(root, mode) as actual:
            assert actual is root
            assert stat.S_IMODE((root / "locked").stat().st_mode) == mode
            if failure:
                raise failure

    try:
        if error:
            with pytest.raises(error) as caught:
                invoke()
            assert caught.value is failure
        else:
            invoke()
        assert not root.exists()
    finally:
        assert rmtree_hardened(root)


@pytest.mark.parametrize("during_setup", [False, True])
def test_cleanup_cancellation_still_propagates(during_setup, tmp_path):
    primary = KeyboardInterrupt("owned primary")
    cancellation = SystemExit("owned cleanup cancellation")
    seen = []
    root = tmp_path / "owned"

    class FaultPath(type(tmp_path)):
        def chmod(self, *args, **kwargs):
            super().chmod(*args, **kwargs)
            raise primary

    if during_setup:
        root = FaultPath(root)

    def cleanup(path):
        seen.append(path)
        raise cancellation

    generator = restricted_tree.__wrapped__
    scope = contextmanager(
        FunctionType(
            generator.__code__,
            dict(generator.__globals__, rmtree_hardened=cleanup),
            generator.__name__,
            generator.__defaults__,
            generator.__closure__,
        )
    )
    try:
        with pytest.raises(SystemExit) as caught:
            with scope(root):
                raise primary
        assert caught.value is cancellation
        assert seen == [root]
    finally:
        assert rmtree_hardened(root)
