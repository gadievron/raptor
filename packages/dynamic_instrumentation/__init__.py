"""RAPTOR dynamic instrumentation (Frida).

Spawn-and-instrument support for ``/frida``: function tracing and Stalker
basic-block coverage that feeds the existing drcov → CoverageStore pipeline.
Backend-agnostic package name so a second backend could slot in behind the
same API.

Public surface::

    from packages.dynamic_instrumentation.api import (
        trace_functions, collect_coverage, is_available,
    )
    from packages.dynamic_instrumentation.capability import probe
"""

from .api import collect_coverage, is_available, trace_functions
from .capability import probe

__all__ = ["trace_functions", "collect_coverage", "is_available", "probe"]
