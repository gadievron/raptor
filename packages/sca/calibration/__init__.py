"""Risk-score calibration corpus — ground truth + project samples
for validating the ``risk_components`` weights in
:mod:`packages.sca.risk`.

See ``docs/calibration.md`` for the full design (sources,
licensing, validation methodology). This package owns the build
pipeline; outputs land in ``packages/sca/data/calibration/`` and
ship under RAPTOR's MIT license (with per-file source-attribution
blocks for sources that require it).

Public entry points:
  * :func:`build_corpus` — refresh ground-truth signals from
    public sources. Network-dependent.
  * :func:`validate_corpus` — compute Spearman correlation +
    top-N precision against the corpus's project samples; emit
    a quarterly validation report.
"""

from .build import build_corpus
from .project_samples import collect_project_samples
from .validate import validate_corpus

__all__ = [
    "build_corpus",
    "collect_project_samples",
    "validate_corpus",
]
