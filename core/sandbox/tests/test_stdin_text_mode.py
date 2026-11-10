"""The legacy subprocess text-mode alias reaches native dispatch."""
import subprocess
import sys

import pytest

from core.sandbox import sandbox
from core.sandbox.tests.capability import requires_landlock, requires_mount, requires_userns


@pytest.mark.slow
@pytest.mark.linux_native
@pytest.mark.skipif(sys.platform != "linux", reason="Linux native namespace delivery")
@requires_landlock
@requires_mount
@requires_userns
@pytest.mark.parametrize("alias,explicit", [(True, None), (True, True),
                                           (False, None), (False, False)],
                         ids=["alias-text", "both-text", "alias-bytes", "both-bytes"])
def test_legacy_text_alias_preserves_native_result_type(tmp_path, alias, explicit):
    target, output = tmp_path / "target", tmp_path / "output"
    target.mkdir()
    output.mkdir()
    flags = {"universal_newlines": alias}
    if explicit is not None:
        flags["text"] = explicit
    payload = "owned witness" if alias else b"owned witness"
    with sandbox(profile="strict", target=str(target), output=str(output)) as run:
        actual = run(["/bin/cat"], input=payload, capture_output=True,
                     check=True, timeout=15, **flags)
    assert actual.returncode == 0, actual.stderr
    assert actual.stdout == payload
    assert type(actual.stdout) is type(payload)
    assert actual.sandbox_info["mount_ns_active"] is True


@pytest.mark.parametrize("alias,explicit", [(True, False), (False, True)],
                         ids=["alias-text-conflict", "alias-bytes-conflict"])
def test_conflicting_aliases_fail_before_dispatch(alias, explicit):
    # The nonexistent executable distinguishes validation from a dispatched
    # command without creating a process or relying on a mocked executor.
    with sandbox(profile="none") as run:
        with pytest.raises(subprocess.SubprocessError, match="Cannot disambiguate"):
            run(["/nonexistent-owned-text-mode-control"], text=explicit,
                universal_newlines=alias)
