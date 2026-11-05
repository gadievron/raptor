"""Sweep-driver logging: every record emits exactly once, level-prefixed.

The stress-sweep driver used to install its own bare root console
handler via ``logging.basicConfig``; RAPTOR's logging bootstrap then
stacked its canonical ``[LEVEL] message`` handler at the first lazy
pipeline import, and every log line printed twice (bare + prefixed)
for the entire sweep. Duplication is per-HANDLER emission of a single
LogRecord — caplog counts records, not writes — so the pin runs a
subprocess and counts actual stderr lines.
"""

from __future__ import annotations

import subprocess
import sys

from core.testing.logging_state import isolated_cli_logging
from pathlib import Path

_REPO_ROOT = str(Path(__file__).resolve().parents[4])

_DRIVER = """
import sys
sys.path.insert(0, {root!r})
from pathlib import Path
from packages.sca.calibration.stress import configure_sweep_logging
configure_sweep_logging(Path({home!r}) / "debug.log")
# The duplication only manifested once the pipeline's lazy import
# attached RAPTOR's root handler mid-run; import it explicitly so the
# assertion covers the stacked-handler window.
import packages.sca.pipeline  # noqa: F401
import logging
logging.getLogger("packages.sca.osv").info("sca.osv: sentinel-emission-xyz")
"""


def test_sweep_logging_single_prefixed_emission(tmp_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, "-c",
         _DRIVER.format(root=_REPO_ROOT, home=str(tmp_path))],
        capture_output=True, text=True, timeout=120,
        env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin",
             "RAPTOR_DIR": _REPO_ROOT},
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    hits = [l for l in proc.stderr.splitlines()
            if "sentinel-emission-xyz" in l]
    # Exactly once, and in the level-prefixed keeper form.
    assert len(hits) == 1, proc.stderr[-2000:]
    assert hits[0] == "[INFO] sca.osv: sentinel-emission-xyz"
    # The debug file still received the record in its own shape.
    debug = (tmp_path / "debug.log").read_text()
    assert "sentinel-emission-xyz" in debug
    assert "INFO packages.sca.osv" in debug


@isolated_cli_logging()
def test_sweep_logging_installs_one_console_handler(
    tmp_path: Path,
) -> None:
    """In-process invariant: one console StreamHandler on root, in
    the canonical prefixed format, plus the DEBUG file handler."""
    import importlib
    import logging

    from packages.sca.calibration.stress import configure_sweep_logging
    configure_sweep_logging(tmp_path / "debug.log")
    importlib.import_module("packages.sca.pipeline")
    root = logging.getLogger()
    # pytest attaches its own LogCaptureHandlers to root, so count by
    # identity: exactly one handler carrying RAPTOR's root-console
    # sentinel, and no bare-format console handler (the duplication
    # culprit was a '%(message)s' StreamHandler from basicConfig).
    sentinels = [
        h for h in root.handlers
        if getattr(h, "_raptor_root_handler", False)
    ]
    assert len(sentinels) == 1
    assert sentinels[0].formatter._fmt == "[%(levelname)s] %(message)s"
    bare = [
        h for h in root.handlers
        if isinstance(h, logging.StreamHandler)
        and not isinstance(h, logging.FileHandler)
        and getattr(h, "formatter", None) is not None
        and h.formatter._fmt == "%(message)s"
    ]
    assert bare == []
    files = [h for h in root.handlers if isinstance(h, logging.FileHandler)]
    assert any(
        Path(getattr(h, "baseFilename", "")) == tmp_path / "debug.log"
        for h in files
    )
