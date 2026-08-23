"""SandboxHost output-directory isolation from the target tree.

Pre-fix, ``SandboxHost.start`` and ``one_shot_call`` defaulted
``output`` to the TARGET path, making the untrusted target tree a
writable bind inside the sandbox — a spawned target could rewrite the
scanned repo (demonstrated live: ``spawn(["sh", "-c", "echo OWNED >
<target>/file"])`` mutated the file on the host).

Now:
- the default output is a private mkdtemp, removed when the session
  ends (``close()`` / one-shot return, success and failure paths);
- an explicit ``output`` that resolves (realpath, so symlinks count)
  to the target is refused with a clear error.
"""

from __future__ import annotations

import json
import os
import struct
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from core.sandbox.host import HostRPCError, SandboxHost, one_shot_call

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Linux-only sandbox internals",
)


class _RunRecorder:
    """Stands in for core.sandbox.run; captures kwargs and reports
    whether the output dir existed at spawn time."""

    def __init__(self) -> None:
        self.kwargs: dict | None = None
        self.output_existed = False

    def __call__(self, argv, **kwargs):
        self.kwargs = kwargs
        self.output_existed = os.path.isdir(kwargs["output"])
        # One-shot mode: answer with a valid frame echoing the rid so
        # the response parses; persistent mode ignores the result
        # because the startup ping times out first.
        rid = None
        if kwargs.get("input"):
            (length,) = struct.unpack("!I", kwargs["input"][:4])
            rid = json.loads(kwargs["input"][4:4 + length]).get("rid")
        body = json.dumps({"ok": True, "pong": True, "rid": rid}).encode()

        class _Result:
            returncode = 0
            stdout = struct.pack("!I", len(body)) + body
            stderr = b""

        return _Result()


class TestDefaultOutputIsPrivate:

    def test_start_default_output_not_target(self):
        recorder = _RunRecorder()
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            with patch("core.sandbox.run", recorder):
                # The fake never answers the RPC ping, so start()
                # fails after capturing the spawn kwargs — enough to
                # pin the output-resolution and cleanup behaviour.
                with pytest.raises(HostRPCError):
                    SandboxHost.start(target=target, startup_timeout=0.5)
            assert recorder.kwargs is not None
            out = recorder.kwargs["output"]
            assert os.path.realpath(out) != os.path.realpath(str(target)), (
                "default output must never be the target tree"
            )
            assert recorder.output_existed, (
                "default output dir must exist at spawn time"
            )
            # Failure path cleaned the private scratch dir up.
            assert not os.path.exists(out)

    def test_close_removes_default_output(self):
        recorder = _RunRecorder()
        with TemporaryDirectory() as tmp:
            with patch("core.sandbox.run", recorder):
                with pytest.raises(HostRPCError):
                    SandboxHost.start(target=Path(tmp), startup_timeout=0.5)
            # start() already closed on ping failure; the scratch dir
            # must not leak. (Success-path close() is pinned by the
            # integration test below.)
            assert not os.path.exists(recorder.kwargs["output"])

    def test_explicit_output_untouched(self):
        recorder = _RunRecorder()
        with TemporaryDirectory() as tmp, TemporaryDirectory() as out:
            with patch("core.sandbox.run", recorder):
                with pytest.raises(HostRPCError):
                    SandboxHost.start(target=Path(tmp), output=Path(out),
                                      startup_timeout=0.5)
            assert recorder.kwargs["output"] == out
            assert os.path.isdir(out), (
                "caller-provided output dirs are never removed"
            )

    def test_one_shot_default_output_not_target(self):
        recorder = _RunRecorder()
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            with patch("core.sandbox.run", recorder):
                resp = one_shot_call(cmd="ping", payload={}, target=target)
            assert resp == {"ok": True, "pong": True}
            out = recorder.kwargs["output"]
            assert os.path.realpath(out) != os.path.realpath(str(target))
            assert recorder.output_existed
            assert not os.path.exists(out), (
                "one-shot scratch output must be removed after the call"
            )


class TestOutputEqualsTargetRefused:

    def test_start_refuses_output_equal_target(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            with patch("core.sandbox.run", _RunRecorder()) as fake:
                with pytest.raises(ValueError, match="distinct output"):
                    SandboxHost.start(target=target, output=target)
                assert fake.kwargs is None, "refusal must precede any spawn"

    def test_start_refuses_symlink_to_target(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp) / "repo"
            target.mkdir()
            link = Path(tmp) / "out-link"
            link.symlink_to(target)
            with patch("core.sandbox.run", _RunRecorder()):
                with pytest.raises(ValueError, match="distinct output"):
                    SandboxHost.start(target=target, output=link)

    def test_one_shot_refuses_output_equal_target(self):
        with TemporaryDirectory() as tmp:
            target = Path(tmp)
            with patch("core.sandbox.run", _RunRecorder()) as fake:
                with pytest.raises(ValueError, match="distinct output"):
                    one_shot_call(cmd="ping", payload={},
                                  target=target, output=target)
                assert fake.kwargs is None


@pytest.mark.integration
class TestTargetReadOnlyE2E:
    """Inverts the live PoC through the real sandbox.

    The target is created OUTSIDE /tmp: the sandbox's /tmp write
    baseline is a separate, separately-tracked exposure that keeps
    /tmp-resident trees writable regardless of the output binding.
    This test pins what the output-default fix owns — that the target
    tree itself is no longer bound writable via ``output``.
    """

    def test_spawned_target_cannot_rewrite_target_tree(self):
        home = Path.home()
        if not os.access(home, os.W_OK):
            pytest.skip("needs a writable non-/tmp scratch location")
        with TemporaryDirectory(dir=home, prefix=".raptor-test-") as tmp:
            target = Path(tmp)
            src = target / "scanned-source.c"
            src.write_text("int main(){}\n")
            host = SandboxHost.start(target=target, startup_timeout=60.0)
            owned_output = host._owned_output
            try:
                res = host.spawn(
                    ["sh", "-c", f"echo OWNED > {target}/scanned-source.c"],
                    timeout=30.0,
                )
                assert res["returncode"] != 0, (
                    "write into the target tree unexpectedly succeeded"
                )
            finally:
                host.close()
            assert src.read_text() == "int main(){}\n", (
                "target tree was mutated through the default output bind"
            )
            assert owned_output and not os.path.exists(owned_output), (
                "close() must remove the default-output scratch dir"
            )
