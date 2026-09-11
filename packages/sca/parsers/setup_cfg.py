"""``setup.cfg`` parser — declarative setuptools metadata (INI).

Reads the dependency-bearing keys of the ``[options]`` family:

    [options]
    install_requires =
        requests>=2.0
        packaging
    setup_requires =
        setuptools-scm

    [options.extras_require]
    dev =
        pytest>=7

Each value is a newline- (or ``;``-) separated list of PEP 508
requirement lines, so per-line parsing is delegated to the
requirements.txt parser's line handler — one grammar, no drift.

Discovery has always classified ``setup.cfg`` as a PyPI manifest;
before this parser existed the file was silently dropped at
dispatch (0 deps, no warning).
"""

from __future__ import annotations

import configparser
import logging
from typing import TYPE_CHECKING

from ..models import Dependency
from . import _safe_read, register

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

ECOSYSTEM = "PyPI"

# (option key, scope) inside ``[options]``.
_OPTION_KEYS: tuple[tuple[str, str], ...] = (
    ("install_requires", "main"),
    ("setup_requires", "build"),
    ("tests_require", "test"),
)


@register(filenames=["setup.cfg"])
def parse(path: Path) -> list[Dependency]:
    text = _safe_read.read_bounded(path, follow_symlinks=False)
    if text is None:
        # ``read_bounded`` already logged the underlying reason.
        return []
    # ``interpolation=None``: setup.cfg values legitimately contain
    # ``%`` (version pins like ``foo==1.0%2Blocal`` are rare but the
    # default BasicInterpolation would raise on any stray ``%``).
    cfg = configparser.ConfigParser(interpolation=None)
    try:
        cfg.read_string(text)
    except configparser.Error as e:
        logger.warning(
            "sca.parsers.setup_cfg: INI parse failed for %s: %s", path, e,
        )
        return []

    from .requirements import _AVAILABLE, _parse_requirement_line
    if not _AVAILABLE:
        logger.warning(
            "sca.parsers.setup_cfg: skipping %s — 'packaging' not installed",
            path,
        )
        return []

    deps: list[Dependency] = []

    def _extend(raw_value: str, scope: str) -> None:
        for line in _split_requirement_list(raw_value):
            d = _parse_requirement_line(
                line, declared_in=path, editable=False,
            )
            if d is not None:
                d.scope = scope
                deps.append(d)

    if cfg.has_section("options"):
        for key, scope in _OPTION_KEYS:
            value = cfg.get("options", key, fallback=None)
            if value:
                _extend(value, scope)
    if cfg.has_section("options.extras_require"):
        for _extra, value in cfg.items("options.extras_require"):
            if value:
                _extend(value, "optional")
    return deps


def _split_requirement_list(value: str) -> list[str]:
    """Split a setuptools dangling-list value into requirement lines.

    setuptools accepts newline-separated entries (the common shape)
    and semicolon-joined single-line lists are NOT split — ``;``
    introduces a PEP 508 environment marker, which belongs to the
    requirement.
    """
    return [ln.strip() for ln in value.splitlines() if ln.strip()]


__all__ = ["parse"]
