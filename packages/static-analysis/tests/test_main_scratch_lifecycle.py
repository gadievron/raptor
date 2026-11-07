"""CLI allocation is protected before startup logs and clone work can fail."""

import importlib
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

from core.atomic_fs import rmtree_hardened
from core.run import parent_liveness, scratch
from core.testing.module_bindings import patch_module_attribute
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture
def scan_case(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / "user")
    monkeypatch.delenv(parent_liveness.WATCHDOG_ENV, raising=False)
    roots = []
    allocate = scratch.tempfile.mkdtemp
    def create(*a, **kw):
        assert kw.get("dir") is None
        kw["dir"] = tmp_path
        result = allocate(*a, **kw)
        roots.append(Path(result))
        return result
    patch_module_attribute(monkeypatch, scratch, "tempfile", "mkdtemp", create)
    # The launcher's sys.path insertion belongs to this test's private list.
    with patch.object(sys, "path", sys.path.copy()):
        scanner = importlib.import_module("packages.static-analysis.scanner")
        yield scanner, roots


@pytest.mark.parametrize("keep", [False, True], ids=["cleanup", "operator-kept"])
@pytest.mark.parametrize("phase", ["log", "clone"])
@pytest.mark.parametrize("error", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_cli_workspace_owned_before_fallible_startup(scan_case, monkeypatch, keep, phase, error):
    scanner, roots = scan_case
    args = ["scanner", "--repo", "https://example.invalid/repository"]
    if keep:
        args.append("--keep")
    monkeypatch.setattr(sys, "argv", args)
    observed = []
    primary = error("startup fault")
    def fail():
        assert len(roots) == 1
        root = roots[0]
        assert str(root) in scratch._keepalive_paths
        (root / "partial").write_bytes(b"temporary")
        child = root / "restricted"
        child.mkdir()
        (child / "cache").write_bytes(b"temporary")
        child.chmod(0)
        observed.append(root)
        raise primary
    if phase == "clone":
        def clone(*a, **kw):
            fail()
        monkeypatch.setattr(scanner, "clone_repository", clone)
    else:
        original = scanner.logger
        class Logger:
            def info(self, *a, **kw):
                fail()
            def __getattr__(self, name):
                return getattr(original, name)
        monkeypatch.setattr(scanner, "logger", Logger())
    try:
        with pytest.raises(error) as caught:
            scanner.main()
        assert caught.value is primary
        assert observed == roots
        assert roots[0].exists() == keep
        assert str(roots[0]) not in scratch._keepalive_paths
    finally:
        for root in roots:
            assert rmtree_hardened(root), f"test-owned retained workspace leaked: {root}"
