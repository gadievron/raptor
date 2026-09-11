"""``setup.py`` visibility stub — legacy setuptools build script.

``setup.py`` is executable Python; its dependency lists routinely
come from variables, file reads, or conditionals, so there is no
faithful static parser and SCA deliberately does not execute target
code. Discovery classifies the file as a PyPI manifest, and before
this stub existed the dispatch silently returned 0 deps — a
setup.py-only project looked "clean" with no trace of WHY.

This stub makes the drop visible instead of pretending coverage:

  * When the script contains no dependency-bearing keyword
    (``install_requires`` / ``setup_requires`` / ``extras_require``
    / ``tests_require``) there is nothing being dropped — the
    common PEP 517 shim ``setup()`` — so it returns ``[]`` quietly.
  * When such a keyword IS present, real dependencies are being
    skipped: the stub emits a warning in the canonical
    ``<kind> parse failed for <path>: <reason>`` shape so
    ``capture_parse_failures`` lifts it into the run report's
    parse-failure counter. Operators are pointed at setup.cfg /
    pyproject.toml, both of which have real parsers.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from ..models import Dependency
from . import _safe_read, register

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# Keywords whose presence means the script declares dependencies we
# cannot extract statically.
_DEP_KEYWORD_RE = re.compile(
    r"\b(?:install_requires|setup_requires|extras_require|tests_require)\b"
)


@register(filenames=["setup.py"])
def parse(path: Path) -> list[Dependency]:
    text = _safe_read.read_bounded(path, follow_symlinks=False)
    if text is None:
        # ``read_bounded`` already logged the underlying reason.
        return []
    if _DEP_KEYWORD_RE.search(text):
        logger.warning(
            "sca.parsers.setup_py: manifest parse failed for %s: "
            "setup.py declares dependency keywords but static extraction "
            "is unsupported (executable build script; SCA never runs "
            "target code) — dependencies not extracted. Declare them in "
            "setup.cfg or pyproject.toml for coverage.",
            path,
        )
    return []


__all__ = ["parse"]
