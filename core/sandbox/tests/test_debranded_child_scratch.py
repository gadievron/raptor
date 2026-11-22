"""Child-visible sandbox dirs are minted OUTSIDE the branded temp family.

Under the ``bin/raptor`` launcher ``tempfile.gettempdir()`` is the
per-session ``TMPDIR`` — ``<base>/raptor-<euid>/session-<pid>-<rand>/tmp``
— so a bare ``mkdtemp()`` inherits the framework name, the euid and the
session pid as path components. Two sandbox dirs hand their exact paths
to the sandboxed child:

- the private scratch (``.scr-``): the restricted Landlock-only posture
  steers the child's ``TMPDIR``/``TEMP``/``TMP`` at the full path — one
  ``getenv`` would disclose the branding to hostile code;
- the persona home (``.fp-``): its files are bind-mounted over
  ``/proc/cpuinfo`` and friends in the mount-ns child, and the mountinfo
  root field of each bind shows the full SOURCE path — to the very
  process the persona exists to hide the host identity from.

Both must therefore be minted at the de-branded base (the family
component stripped). The mountless mid-call demotion twin of the
scratch is pinned by test_context_demoted_scratch_retirement.py, which
drives all three mint routes through a steered tempfile view; the
end-to-end child's-eye view is in test_ll_private_scratch.py.
"""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

import core.run.tmp_reaper as _reaper_mod
from core.sandbox.tests.capability import requires_landlock
from core.testing.module_bindings import patch_module_attribute

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="both postures under test are Linux substrates",
)

# A family no real path carries: under a launcher-nested run pytest's
# tmp_path itself lies inside the REAL raptor-<euid> family, so
# stripping the real family would cut ABOVE tmp_path and mint at the
# real system base — non-hermetic and asserting the wrong parent.
_FAKE_EUID = os.geteuid() + 54321
_FAMILY = f"raptor-{_FAKE_EUID}"


@pytest.fixture(autouse=True)
def _owned_family(monkeypatch):
    """Steer the helper's euid-derived family default onto the fake
    family through tmp_reaper's private os view, so only the component
    this file builds is ever stripped."""
    patch_module_attribute(monkeypatch, _reaper_mod, "os", "geteuid",
                           lambda: _FAKE_EUID)


def _branded_tempdir(tmp_path):
    """A launcher-session-shaped temp dir under the test's private base."""
    branded = tmp_path / _FAMILY / "session-1-2" / "tmp"
    branded.mkdir(parents=True)
    return branded


def _tracking_mkdtemp(minted, prefix_tag):
    real_mkdtemp = tempfile.mkdtemp

    def _track(*args, **kw):
        d = real_mkdtemp(*args, **kw)
        # Capture both positional and keyword prefix forms (see
        # test_fingerprint_context.py: TemporaryDirectory passes
        # positionally).
        prefix = kw.get("prefix")
        if prefix is None and len(args) >= 2:
            prefix = args[1]
        if prefix and str(prefix).startswith(prefix_tag):
            minted.append(d)
        return d

    return _track


@requires_landlock
def test_private_scratch_minted_at_debranded_base(monkeypatch, tmp_path):
    """Site: the restricted Landlock-only posture's context scratch.
    The child reads this exact path back from TMPDIR."""
    from core.sandbox import sandbox

    branded = _branded_tempdir(tmp_path)
    minted = []
    monkeypatch.setattr(tempfile, "mkdtemp", _tracking_mkdtemp(minted, ".scr-"))
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(branded))
    with patch("core.sandbox.context.check_net_available",
               return_value=False), \
         patch("core.sandbox.context.check_mount_available",
               return_value=False):
        with sandbox(target=str(tmp_path), output=str(tmp_path),
                     block_network=False, restrict_reads=True):
            assert len(minted) == 1, (
                f"expected one private scratch, got {minted}"
            )
            scratch = Path(minted[0])
            assert scratch.parent == tmp_path, (
                f"child-visible scratch minted at {scratch.parent}, not "
                f"the de-branded base {tmp_path}"
            )
            assert _FAMILY not in scratch.parts
    assert not os.path.exists(minted[0]), (
        "de-branded private scratch must still be removed at context exit"
    )


@requires_landlock
def test_persona_tmpdir_minted_at_debranded_base(monkeypatch, tmp_path):
    """Site: the fingerprint persona home. apply_overlay bind-mounts its
    files in the mount-ns child; mountinfo shows the source path."""
    import core.sandbox._spawn as _sp
    import core.sandbox.context as ctx
    import core.sandbox.fingerprint as _fp
    from core.sandbox import sandbox

    # Pin the persona availability gate (same set as the persona
    # lifecycle tests in test_fingerprint_context.py) — nothing spawns.
    monkeypatch.setattr(ctx, "check_mount_available", lambda: True)
    monkeypatch.setattr(_sp, "mount_ns_available", lambda: True)
    monkeypatch.setattr(_fp, "is_supported", lambda: True)

    branded = _branded_tempdir(tmp_path)
    minted = []
    monkeypatch.setattr(tempfile, "mkdtemp", _tracking_mkdtemp(minted, ".fp-"))
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(branded))
    with sandbox(target=str(tmp_path), output=str(tmp_path),
                 sanitise_host_fingerprint=True):
        assert len(minted) == 1, (
            f"expected one persona tmpdir, got {minted}"
        )
        persona_home = Path(minted[0])
        assert persona_home.parent == tmp_path, (
            f"persona home minted at {persona_home.parent}, not the "
            f"de-branded base {tmp_path}"
        )
        assert _FAMILY not in persona_home.parts
    assert not os.path.exists(minted[0]), (
        "de-branded persona home must still be removed at context exit"
    )


@requires_landlock
def test_unbranded_tempdir_is_used_directly(monkeypatch, tmp_path):
    """Without the family component the base passes through unchanged —
    the bare-shell / already-de-branded shape loses nothing."""
    from core.sandbox import sandbox

    minted = []
    monkeypatch.setattr(tempfile, "mkdtemp", _tracking_mkdtemp(minted, ".scr-"))
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    with patch("core.sandbox.context.check_net_available",
               return_value=False), \
         patch("core.sandbox.context.check_mount_available",
               return_value=False):
        with sandbox(target=str(tmp_path), output=str(tmp_path),
                     block_network=False, restrict_reads=True):
            assert len(minted) == 1
            assert Path(minted[0]).parent == tmp_path
