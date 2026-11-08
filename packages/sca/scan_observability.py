"""Per-run completion accounting and lightweight stage telemetry."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import sys
from time import perf_counter


class MeasuredProgress:
    """Delegate presentation while measuring wall time between stage starts."""

    def __init__(self, progress):
        self.progress = progress
        self.timings = {}
        self.current = None
        self.started = perf_counter()
        self.stage_started = self.started

    def __getattr__(self, name):
        return getattr(self.progress, name)

    def _finish(self):
        now = perf_counter()
        if self.current is not None:
            self.timings[self.current] = self.timings.get(self.current, 0) + now - self.stage_started
        self.stage_started = now

    def stage(self, name, *args, **kwargs):
        self._finish()
        self.current = name
        return self.progress.stage(name, *args, **kwargs)

    def end(self, *args, **kwargs):
        self._finish()
        self.current = None
        return self.progress.end(*args, **kwargs)


def query_accounting(dependencies, client, results):
    from .sbom_inventory.advisory_coverage import _receipt
    available = {row.dep_key for row in results}
    counts, reasons = Counter(), Counter()
    for dep in dependencies:
        row = _receipt(dep, client, available)
        counts[row["status"]] += 1
        if row["reason"]:
            reasons[row["reason"]] += 1
    return {"total": len(dependencies), "checked": counts["checked"],
            "unavailable": counts["unavailable"], "unavailable_reasons": dict(reasons)}


def completion_summary(*, coverage, parse_failures, health, progress, receipt):
    rss = None
    try:
        import resource
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if sys.platform != "darwin":
            rss *= 1024
    except ImportError:
        pass
    return {"format": "raptor-sca-scan-summary", "schema_version": 1,
            "status": "partial" if health or parse_failures or coverage["unavailable"] else "complete",
            "generated_at": datetime.now(timezone.utc).isoformat(), "advisory_queries": coverage,
            "assessment_scope": "Parsed/imported package inventory and recorded scan-health gaps; not complete source, file, runtime or upstream advisory coverage.",
            "parse_failures": len(parse_failures), "scan_health_findings": len(health),
            "limitations": [row["detail"] for row in health],
            "receipt_generated_at": receipt["generated_at"], "advisory_source": receipt["advisory_source"],
            "elapsed_seconds": round(perf_counter() - progress.started, 6),
            "stage_seconds": {key: round(value, 6) for key, value in progress.timings.items()},
            "process_peak_rss_bytes": rss,
            "memory_scope": "Process lifetime high-water mark, including earlier or concurrent work; not an isolated scan peak."}



def failure_summary(error):
    """No completed coverage claim; arbitrary exception text stays out of JSON."""
    return {"format": "raptor-sca-scan-summary", "schema_version": 1, "status": "failed",
            "generated_at": datetime.now(timezone.utc).isoformat(), "error_type": type(error).__name__,
            "assessment_scope": "Analysis did not complete; no complete coverage assessment is available."}
