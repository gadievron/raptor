"""Positive scan-query receipts, bound to the exact emitted SBOM and findings."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import math

from core.hash import sha256_file
from core.json import save_json
from ..distro import advisory_dependency
from ..osv import primary_query_supported
from .source import Source, SHA256

MAX_QUERY_RECORDS = 100_000


@dataclass
class AdvisoryCoverage:
    sources: dict
    queries: list
    truncated: bool
    limitations: list
    generated_at: str | None = None
    scanner: dict = field(default_factory=dict)
    advisory_source: dict = field(default_factory=dict)
    format: str = "raptor-sca-advisory-coverage"
    schema_version: int = 1


def _coordinates(dep):
    return {"ecosystem": dep.ecosystem, "name": dep.name, "version": dep.version}


def query_key(row):
    return tuple(row.get(key) or "" for key in ("ecosystem", "name", "version", "purl"))


def _receipt(dep, osv, available):
    row = dict(_coordinates(dep), purl=dep.purl or "", query=None, status="unavailable", reason="")
    try:
        query = advisory_dependency(dep)
        row["query"] = _coordinates(query)
        if not dep.version:
            row["reason"] = "no resolved installed version"
        elif not primary_query_supported(query.ecosystem):
            row["reason"] = "dedicated source fallback does not establish primary package-query coverage"
        elif dep.key() not in available:
            row["reason"] = "no advisory query result recorded"
        elif osv.lookup_failed(dep.key()) or dep.key() in osv.coverage_gaps:
            row["reason"] = osv.coverage_gaps.get(dep.key(), "advisory lookup unavailable")
        else:
            row["status"] = "checked"
    except ValueError as error:
        row["reason"] = str(error)
    return row


def write_coverage(path, dependencies, osv, results, artifacts):
    """Stream-hash self-produced outputs; never retain their complete bytes."""
    available = {row.dep_key for row in results}
    from core.config import RaptorConfig
    db = getattr(osv, "_offline_db", None)
    snapshot = db.snapshot_metadata() if db is not None else None
    document = AdvisoryCoverage(
        generated_at=datetime.now(timezone.utc).isoformat(),
        scanner={"name": "raptor-sca", "version": RaptorConfig.VERSION},
        advisory_source={"provider": "OSV", "mode": "offline_database" if db is not None else "cache_only" if getattr(osv, "_offline", False) else "network_and_cache",
                         "cache_ttl_seconds": getattr(osv, "_query_ttl", None), "snapshot": snapshot,
                         "upstream_revision": None, "limitation": "Receipt time is not advisory publication or cache-entry time; no upstream revision is authenticated."},
        sources={name: sha256_file(file) for name, file in artifacts.items()},
        queries=[_receipt(dep, osv, available) for dep in dependencies[:MAX_QUERY_RECORDS]],
        truncated=len(dependencies) > MAX_QUERY_RECORDS,
        limitations=["Records query availability, not advisory-database completeness or build provenance.",
                     "Hashes bind local artifacts for consistency; this is not a signed attestation."],
    )
    save_json(path, asdict(document), stream=True)
    return asdict(document)


def read_coverage(path, inventory_sha, findings_sha, *, max_age_hours=None, now=None):
    """Return a query index or an explicit unavailability reason."""
    try:
        with Source(path) as source:
            data, digest = source.read_json()
        if (data.get("format") != "raptor-sca-advisory-coverage" or type(data.get("schema_version")) is not int
                or data["schema_version"] != 1):
            raise ValueError("unsupported advisory coverage format")
        if max_age_hours is not None:
            if not math.isfinite(max_age_hours) or max_age_hours <= 0:
                raise ValueError("coverage maximum age must be a finite positive number")
            value = data.get("generated_at")
            if not isinstance(value, str):
                raise ValueError("coverage receipt has no timestamp; rerun the scan")
            stamp = datetime.fromisoformat(value)
            if stamp.tzinfo is None:
                raise ValueError("coverage timestamp must include a timezone")
            age = ((now or datetime.now(timezone.utc)) - stamp).total_seconds()
            if age < -300 or age > max_age_hours * 3600:
                raise ValueError("coverage receipt is stale or has a future timestamp; rerun the scan")
        sources = data.get("sources")
        if not isinstance(sources, dict) or any(not isinstance(value, str) or not SHA256.fullmatch(value) for value in sources.values()):
            raise ValueError("invalid advisory coverage fingerprints")
        if (sources.get("findings.json") != findings_sha or inventory_sha not in
                {sources.get("sbom.cdx.json"), sources.get("sbom.spdx.json")}):
            raise ValueError("coverage does not match the supplied SBOM and findings")
        rows = data.get("queries")
        if not isinstance(rows, list) or len(rows) > MAX_QUERY_RECORDS:
            raise ValueError("invalid advisory query inventory")
        indexed = {}
        for row in rows:
            if (not isinstance(row, dict) or any(not isinstance(row.get(key), str) for key in ("ecosystem", "name", "purl", "reason"))
                    or row.get("version") is not None and not isinstance(row["version"], str)
                    or row.get("status") not in {"checked", "unavailable"}):
                raise ValueError("invalid advisory query receipt")
            query = row.get("query")
            if row["status"] == "checked" and (not isinstance(query, dict) or any(
                    not isinstance(query.get(key), str) or not query[key] for key in ("ecosystem", "name", "version"))):
                raise ValueError("checked receipt has no concrete query identity")
            key = query_key(row)
            if key in indexed:
                raise ValueError("duplicate advisory query receipts")
            indexed[key] = row
        return indexed, digest, []
    except (OSError, ValueError, TypeError, KeyError) as error:
        return {}, None, [str(error)]
