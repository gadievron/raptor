"""True-positive harvest flywheel.

Systematises the harvest of a run's confirmed true positives into
(a) detection-rule CANDIDATES and (b) private corpus label records.
Mechanical harvest, human-gated promotion: nothing this package emits
changes a verdict, enables a rule, or publishes a label — candidates
land in a run-local directory for maintainer review, and label
emission is provenance-gated per finding (default: not labelable).

Operator CLI: ``libexec/raptor-tp-harvest <run-dir>``.
"""

from core.tp_harvest.records import (
    HARVEST_STATUSES,
    HarvestRecord,
    build_record,
    classify_finding,
)

__all__ = [
    "HARVEST_STATUSES",
    "HarvestRecord",
    "build_record",
    "classify_finding",
]
