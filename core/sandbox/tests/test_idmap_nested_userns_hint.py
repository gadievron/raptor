"""The nested-userns hint on id-map setup failures is diagnostic-only.

``_run_newuidmap`` appends an explanatory suffix to its RuntimeError
when the refusal happened inside a self-owned (nested) user namespace,
where "fix the host" advice would mislead. Two directions pinned here:
the suffix appears exactly when the detector says nested, and the
detector itself never fires on the ordinary unprivileged host posture
(no EPERM marker, root invoker, unopenable /proc/1/ns/user).
"""

from __future__ import annotations

import os
import sys

import pytest

from core.sandbox import _spawn

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Linux-only sandbox internals (user-namespace id maps)",
)

_NESTED_MARKER = "unprivileged nested user namespace"


class TestDetector:
    def test_no_eperm_marker_is_never_nested(self) -> None:
        # Any other newuidmap failure (usage error, missing subuid
        # entry) must not draw the nested-userns explanation.
        assert _spawn._idmap_denied_in_self_owned_userns(
            "newuidmap: uid range [0-1) not allowed") is False

    def test_root_invoker_is_never_nested(self, monkeypatch) -> None:
        # Root owns the init userns: owner==uid holds trivially there,
        # so the detector must not classify root as nested.
        monkeypatch.setattr(os, "getuid", lambda: 0)
        assert _spawn._idmap_denied_in_self_owned_userns(
            "newuidmap: write to uid_map failed: Operation not "
            "permitted") is False

    def test_unopenable_pid1_ns_is_not_nested(self, monkeypatch) -> None:
        # The ordinary unprivileged host posture: pid 1's ns/user is
        # not openable — that refusal IS the foreign-init evidence.
        def _deny(*_a, **_k):
            raise PermissionError("Operation not permitted")
        monkeypatch.setattr(os, "open", _deny)
        assert _spawn._idmap_denied_in_self_owned_userns(
            "newuidmap: write to uid_map failed: Operation not "
            "permitted") is False

    def test_self_owned_pid1_ns_with_eperm_is_nested(
        self, monkeypatch,
    ) -> None:
        # Construct the nested posture with mocks: pid 1's ns/user
        # opens, and NS_GET_OWNER_UID reports the invoker's own uid.
        import fcntl
        real_open = os.open

        def _fake_open(path, flags, *a, **k):
            if path == "/proc/1/ns/user":
                return real_open("/dev/null", os.O_RDONLY)
            return real_open(path, flags, *a, **k)

        def _fake_ioctl(fd, req, buf, mutate=True):
            buf[0] = os.getuid()
            return 0

        monkeypatch.setattr(os, "open", _fake_open)
        monkeypatch.setattr(fcntl, "ioctl", _fake_ioctl)
        assert _spawn._idmap_denied_in_self_owned_userns(
            "newuidmap: write to uid_map failed: Operation not "
            "permitted") is True


class TestMessageSuffix:
    def _fail_newuidmap(self, monkeypatch, nested: bool) -> str:
        monkeypatch.setattr(
            _spawn, "_idmap_denied_in_self_owned_userns",
            lambda stderr: nested)
        with pytest.raises(RuntimeError) as exc:
            _spawn._run_newuidmap(
                os.getpid(), "/bin/false", ["0", "1000", "1"])
        return str(exc.value)

    def test_nested_refusal_names_the_cause(self, monkeypatch) -> None:
        msg = self._fail_newuidmap(monkeypatch, nested=True)
        assert _NESTED_MARKER in msg
        assert "/bin/false" in msg  # base message keeps its shape

    def test_host_refusal_message_unchanged(self, monkeypatch) -> None:
        msg = self._fail_newuidmap(monkeypatch, nested=False)
        assert _NESTED_MARKER not in msg
        assert "failed" in msg and "/bin/false" in msg
