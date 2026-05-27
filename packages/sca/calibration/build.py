"""Build the calibration corpus from public ground-truth sources.

Runs each enabled fetcher (KEV, EPSS, exploit-evidence) and writes
JSON artefacts to ``packages/sca/data/calibration/``. Each output
file carries a top-level ``_source`` block documenting:

  * ``license`` — the source's data license (Public Domain /
    Apache-2.0 / CC-BY-4.0)
  * ``url`` — canonical source URL
  * ``fetched_at`` — UTC timestamp of the run
  * ``provenance`` — short prose for the ATTRIBUTION.md cross-reference

The build is idempotent + diff-friendly: re-running on unchanged
sources produces byte-identical output (sorted keys, stable
ordering). The CI workflow opens an auto-PR only when something
actually changed.

License compliance:

  * Tier 1 sources (KEV / NVD / EPSS / OSV / GHSA) are embedded
    verbatim — all are MIT-redistribution-compatible. CC-BY-4.0
    sources (GHSA) carry per-file attribution blocks.
  * Tier 2 sources (Exploit-DB / Metasploit) are reduced to
    boolean signals + reference URLs only. We never ship exploit
    content; only public facts about its existence.
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# Output directory — relative to repo root in production; tests pass
# their own ``out_dir``.
DEFAULT_OUT_DIR = Path("packages/sca/data/calibration")


@dataclass(frozen=True)
class BuildResult:
    """Per-source build status. The CI workflow surfaces these in
    the auto-PR body so reviewers see what changed."""

    source: str
    written: bool        # True iff the file changed
    error: Optional[str] # populated on fetch failure (workflow logs)
    record_count: int


def _build_one_source(source: str, out_dir: Path, http: Any) -> BuildResult:
    """Run one source's fetcher, never raising — failures (and unknown
    sources) come back as a ``BuildResult`` with ``error`` set.

    The dispatch table is built here (not at module level) because the
    ``_build_*`` functions are defined further down the module.
    """
    builders = {
        "kev": _build_kev,
        "epss": _build_epss,
        "exploitdb": _build_exploitdb,
        "metasploit": _build_metasploit,
        "github_poc": _build_github_poc,
        "osv_evidence": _build_osv_evidence,
        "vulnrichment": _build_vulnrichment,
    }
    fn = builders.get(source)
    if fn is None:
        return BuildResult(source=source, written=False,
                           error=f"unknown source {source!r}", record_count=0)
    try:
        return fn(out_dir, http)
    except Exception as e:                              # noqa: BLE001
        # Defensive: an individual source breaking shouldn't abort the rest.
        logger.warning("sca.calibration: %s build failed: %s", source, e,
                       exc_info=True)
        return BuildResult(source=source, written=False,
                           error=str(e), record_count=0)


def build_corpus(
    *,
    out_dir: Optional[Path] = None,
    http: Optional[Any] = None,
    sources: Optional[List[str]] = None,
    jobs: int = 0,
) -> List[BuildResult]:
    """Refresh the calibration corpus.

    ``sources`` filters which fetchers run. Default is all known
    sources. Each source is independent — one failure doesn't abort
    the rest; the BuildResult list reports per-source status (always in
    input order, regardless of completion order).

    Sources are fetched in parallel by default (``jobs=0`` → one thread per
    source, capped): each is an independent bulk download to a distinct host
    and writes its own file, so they overlap cleanly and share the one
    keep-alive HTTP pool. ``jobs=1`` forces sequential.

    The function never raises on individual source failures —
    captures them in BuildResult.error so the CI workflow can keep
    going. Programmer errors (bad arguments, unwriteable out_dir)
    still raise.
    """
    if out_dir is None:
        out_dir = DEFAULT_OUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    if http is None:
        from core.http import default_client
        http = default_client()

    if sources is None:
        sources = ["kev", "epss", "exploitdb", "metasploit",
                   "github_poc", "osv_evidence", "vulnrichment"]

    if jobs <= 0:
        jobs = min(len(sources), 8) or 1

    results: List[Optional[BuildResult]] = [None] * len(sources)
    if jobs <= 1 or len(sources) <= 1:
        for i, source in enumerate(sources):
            results[i] = _build_one_source(source, out_dir, http)
    else:
        with ThreadPoolExecutor(max_workers=jobs) as pool:
            fut_to_idx = {
                pool.submit(_build_one_source, source, out_dir, http): i
                for i, source in enumerate(sources)
            }
            for fut in as_completed(fut_to_idx):
                results[fut_to_idx[fut]] = fut.result()
    return [r for r in results if r is not None]


# ---------------------------------------------------------------------------
# Per-source builders
# ---------------------------------------------------------------------------


def _build_kev(out_dir: Path, http: Any) -> BuildResult:
    """Fetch the CISA KEV JSON dump and write a flat CVE-keyed
    signal file. Public Domain — embed verbatim."""
    KEV_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )
    data = http.get_json(KEV_URL)
    signals: Dict[str, Dict[str, Any]] = {}
    for entry in data.get("vulnerabilities", []):
        cve = entry.get("cveID")
        if not cve:
            continue
        signals[cve] = {
            "kev": True,
            "date_added": entry.get("dateAdded"),
            "vendor": entry.get("vendorProject"),
            "product": entry.get("product"),
            "ransomware_use": (
                entry.get("knownRansomwareCampaignUse") == "Known"
            ),
        }
    output = {
        "_source": {
            "name": "CISA KEV",
            "url": KEV_URL,
            "license": "Public Domain (US Government work)",
            "fetched_at": _utcnow(),
            "provenance": (
                "CISA Known Exploited Vulnerabilities Catalog. "
                "Public Domain; embedded verbatim."
            ),
        },
        "signals": dict(sorted(signals.items())),
    }
    return _write_if_changed(
        out_dir / "kev_signals.json", output, source="kev",
        record_count=len(signals),
    )


# Exploit-DB index CSV. Fetched by BOTH _build_exploitdb and
# _build_github_poc (the latter re-parses it for github.com PoC URLs),
# so it lives here as a single source of truth. The ``HEAD`` ref
# resolves to the repo's default branch at request time (GitLab raw
# honours HEAD), so a branch rename upstream can't 404 us.
_EDB_CSV_URL = (
    "https://gitlab.com/exploit-database/exploitdb/-/raw/HEAD/"
    "files_exploits.csv"
)


def _build_exploitdb(out_dir: Path, http: Any) -> BuildResult:
    """Fetch the Exploit-DB index CSV and emit a CVE-keyed
    boolean-signal file.

    **Strict licensing posture:** Exploit-DB's license is
    research/personal-use, NOT redistribution. We download the
    public INDEX (which is metadata about public exploits — the
    fact that an exploit exists for CVE-X) and emit ONLY:

      * ``has_exploitdb_entry: bool``
      * ``edb_ids: [int, ...]`` (entry IDs, public references)

    We never store exploit BODIES, payloads, shellcode, or any
    exploit content. The Tier 2 license-check
    (:mod:`packages.sca.calibration._license_check`) enforces this
    at commit time by rejecting field names like ``body`` /
    ``shellcode`` / ``exploit_code`` anywhere in the corpus.

    Source: ``files_exploits.csv`` from the upstream
    ``exploit-database/exploitdb`` GitLab mirror. The CSV columns
    include ``codes`` which carries CVE references.
    """
    import csv
    import io

    raw = http.get_bytes(_EDB_CSV_URL, max_bytes=64 * 1024 * 1024)
    text = raw.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    cve_to_ids: Dict[str, List[int]] = {}
    rows_seen = 0
    for row in reader:
        rows_seen += 1
        edb_id_raw = row.get("id")
        codes_raw = row.get("codes") or ""
        if not edb_id_raw:
            continue
        try:
            edb_id = int(edb_id_raw)
        except (TypeError, ValueError):
            continue
        # ``codes`` is semicolon-separated; entries that map to a
        # CVE look like ``CVE-2021-44228``. Filter to CVE refs
        # only (other codes include OSVDB ids).
        for code in codes_raw.split(";"):
            code = code.strip()
            if code.startswith("CVE-"):
                cve_to_ids.setdefault(code, []).append(edb_id)
    signals = {
        cve: {
            "has_exploitdb_entry": True,
            "edb_ids": sorted(set(ids)),
        }
        for cve, ids in cve_to_ids.items()
    }
    output = {
        "_source": {
            "name": "Exploit-DB index",
            "url": _EDB_CSV_URL,
            "license": (
                "Exploit-DB content is research/personal-use only. "
                "We embed ONLY boolean signals + entry-ID references "
                "(public observable facts). No exploit content stored."
            ),
            "fetched_at": _utcnow(),
            "provenance": (
                "Exploit-Database files_exploits.csv index. We map "
                "CVE references in the ``codes`` column to entry "
                "IDs; no exploit bodies are read or stored."
            ),
            "rows_scanned": rows_seen,
        },
        "signals": dict(sorted(signals.items())),
    }
    return _write_if_changed(
        out_dir / "exploitdb_signals.json", output,
        source="exploitdb", record_count=len(signals),
    )


def _build_metasploit(out_dir: Path, http: Any) -> BuildResult:
    """Fetch the Metasploit Framework module metadata index and
    emit a CVE-keyed boolean-signal file.

    **Strict licensing posture:** the MSF Framework codebase is
    BSD-3-Clause. We could embed it freely, but we choose not to:
    the corpus only needs the FACT that a module exists per CVE.
    Storing module names + CVE refs is sufficient for calibration
    (signal: "exploitation has been weaponised") without
    redistributing the framework's data.

    Source: ``modules_metadata_base.json`` from the upstream
    ``rapid7/metasploit-framework`` GitHub repo. JSON keyed by
    module path; each module has a ``references`` list with
    ``CVE-...`` entries.
    """
    # ``HEAD`` resolves to the repo's default branch at request time
    # (raw.githubusercontent honours it), so a master→main rename
    # upstream can't 404 this fetch.
    MSF_URL = (
        "https://raw.githubusercontent.com/rapid7/metasploit-framework/"
        "HEAD/db/modules_metadata_base.json"
    )
    data = http.get_json(MSF_URL)
    if not isinstance(data, dict):
        raise RuntimeError(
            f"unexpected MSF index shape: {type(data).__name__}"
        )
    cve_to_modules: Dict[str, List[str]] = {}
    for module_path, meta in data.items():
        if not isinstance(meta, dict):
            continue
        refs = meta.get("references") or []
        if not isinstance(refs, list):
            continue
        for ref in refs:
            cve_id = _msf_ref_to_cve(ref)
            if cve_id is None:
                continue
            cve_to_modules.setdefault(cve_id, []).append(module_path)
    signals = {
        cve: {
            "has_msf_module": True,
            "module_paths": sorted(set(mods)),
        }
        for cve, mods in cve_to_modules.items()
    }
    output = {
        "_source": {
            "name": "Metasploit Framework module metadata",
            "url": MSF_URL,
            "license": (
                "Metasploit Framework is BSD-3-Clause. We embed only "
                "module-path references + booleans (a public fact "
                "about the framework's contents); no MSF code is "
                "stored."
            ),
            "fetched_at": _utcnow(),
            "provenance": (
                "rapid7/metasploit-framework "
                "modules_metadata_base.json. We extract the "
                "CVE→module-path mapping; framework code itself is "
                "not redistributed."
            ),
            "modules_scanned": len(data),
        },
        "signals": dict(sorted(signals.items())),
    }
    return _write_if_changed(
        out_dir / "metasploit_signals.json", output,
        source="metasploit", record_count=len(signals),
    )


def _build_github_poc(out_dir: Path, http: Any) -> BuildResult:
    """Extract github.com PoC URLs from the Exploit-DB index.

    Many EDB entries link to a GitHub repo (the original PoC
    publication) via the ``source_url`` or ``application_url``
    columns. We re-parse the EDB CSV (a single network fetch
    we do anyway for the EDB build) and emit a Tier-3
    boolean+URLs signal per CVE.

    Why a separate signal: KEV says "exploited in the wild",
    EDB says "an exploit entry exists in our DB", MSF says
    "a Metasploit module exists". A GitHub PoC URL is a fourth
    independent signal: "a public PoC repo is one click away
    on GitHub". Operators triaging triage further when they can
    inspect the actual PoC code.

    Strict licensing: we ONLY store the URL — the URL itself
    is a public observable fact (the existence of a repo).
    No PoC code is fetched or stored.
    """
    import csv
    import io

    raw = http.get_bytes(_EDB_CSV_URL, max_bytes=64 * 1024 * 1024)
    text = raw.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    cve_to_urls: Dict[str, List[str]] = {}
    rows_seen = 0
    for row in reader:
        rows_seen += 1
        codes_raw = row.get("codes") or ""
        if "CVE-" not in codes_raw:
            continue
        cves = [c.strip() for c in codes_raw.split(";")
                 if c.strip().startswith("CVE-")]
        if not cves:
            continue
        urls: List[str] = []
        for col in ("source_url", "application_url"):
            url = (row.get(col) or "").strip()
            if _is_github_poc_url(url):
                urls.append(url)
        if not urls:
            continue
        for cve in cves:
            cve_to_urls.setdefault(cve, []).extend(urls)
    signals = {
        cve: {
            "has_github_poc": True,
            "github_poc_urls": sorted(set(urls)),
        }
        for cve, urls in cve_to_urls.items()
    }
    output = {
        "_source": {
            "name": "GitHub PoC URLs (derived from Exploit-DB index)",
            "url": _EDB_CSV_URL,
            "license": (
                "Derived signal: presence + public URL only. "
                "Source URLs are public observable facts; the "
                "PoC code itself is NOT fetched or stored."
            ),
            "fetched_at": _utcnow(),
            "provenance": (
                "Parses the Exploit-Database files_exploits.csv "
                "``source_url`` / ``application_url`` columns for "
                "github.com URLs. Same network fetch as the EDB "
                "build."
            ),
            "rows_scanned": rows_seen,
        },
        "signals": dict(sorted(signals.items())),
    }
    return _write_if_changed(
        out_dir / "github_poc_signals.json", output,
        source="github_poc", record_count=len(signals),
    )


def _is_github_poc_url(url: str) -> bool:
    """Match ``https://github.com/<owner>/<repo>(/...)?`` shape.

    Filters out the EDB self-references and non-github URLs.
    Doesn't try to verify the repo *is* a PoC repo — operators
    inspecting the URL can decide.
    """
    if not url:
        return False
    return url.startswith(("https://github.com/", "http://github.com/"))


def _msf_ref_to_cve(ref: Any) -> Optional[str]:
    """MSF references arrive in two shapes:

      * String: ``"CVE-2021-44228"`` or ``"OSVDB-12345"``
      * Object: ``{"type": "CVE", "ref": "2021-44228"}``

    Return a normalised CVE-id string or None for non-CVE refs.
    """
    if isinstance(ref, str):
        if ref.startswith("CVE-"):
            return ref
        return None
    if isinstance(ref, dict):
        if ref.get("type") == "CVE":
            cve_num = ref.get("ref") or ""
            if cve_num and not cve_num.startswith("CVE-"):
                cve_num = f"CVE-{cve_num}"
            return cve_num or None
    return None


# EPSS feed (FIRST.org). We page to completeness rather than capping
# at a single response: ``_EPSS_PAGE_SIZE`` rows per call, following
# the API's ``offset``/``total`` envelope. ``_EPSS_MAX_PAGES`` is a
# defensive ceiling so a misbehaving API can't loop forever.
_EPSS_BASE_URL = "https://api.first.org/data/v1/epss?epss-gt=0.05"
_EPSS_PAGE_SIZE = 10000
_EPSS_MAX_PAGES = 100


def _build_epss(out_dir: Path, http: Any) -> BuildResult:
    """Fetch the daily EPSS scores CSV and emit a sorted JSON of
    ``{cve_id: {epss, percentile, fetched_date}}``.

    EPSS is FIRST.org's free-for-any-use feed. We page through the
    FIRST API for every CVE with EPSS ≥ 0.05, following the
    ``offset``/``total`` envelope to completeness — a single capped
    ``limit`` silently dropped the tail once the matching set grew
    past one page.
    """
    signals: Dict[str, Dict[str, Any]] = {}
    offset = 0
    total: Optional[int] = None
    pages = 0
    while pages < _EPSS_MAX_PAGES:
        pages += 1
        url = f"{_EPSS_BASE_URL}&limit={_EPSS_PAGE_SIZE}&offset={offset}"
        data = http.get_json(url)
        rows = data.get("data") or []
        for entry in rows:
            cve = entry.get("cve")
            if not cve:
                continue
            # Reject entries missing epss / percentile entirely —
            # coercing missing fields to 0.0 would silently inflate
            # the corpus with no-data rows that look like "0% EPSS".
            if entry.get("epss") is None or entry.get("percentile") is None:
                continue
            try:
                score = float(entry["epss"])
                percentile = float(entry["percentile"])
            except (TypeError, ValueError):
                continue
            signals[cve] = {
                "epss": score,
                "percentile": percentile,
                "as_of": entry.get("date"),
            }
        if total is None:
            total = data.get("total")
        offset += len(rows)
        # Last page: a short/empty page, or we've covered the
        # server-reported total.
        if len(rows) < _EPSS_PAGE_SIZE:
            break
        if total is not None and offset >= total:
            break
    else:
        # Page ceiling hit without a natural stop — surface it rather
        # than silently truncating the corpus.
        logger.warning(
            "sca.calibration: EPSS fetch hit the %d-page ceiling "
            "(offset=%d, total=%s) — corpus may be truncated",
            _EPSS_MAX_PAGES, offset, total,
        )
    output = {
        "_source": {
            "name": "FIRST.org EPSS",
            "url": "https://www.first.org/epss/",
            "license": "Free for any use (FIRST.org)",
            "fetched_at": _utcnow(),
            "provenance": (
                "Exploit Prediction Scoring System — FIRST.org. "
                "Filtered to CVEs with EPSS ≥ 0.05 to keep the "
                "corpus tractable."
            ),
        },
        "signals": dict(sorted(signals.items())),
    }
    return _write_if_changed(
        out_dir / "epss_signals.json", output, source="epss",
        record_count=len(signals),
    )


def _build_osv_evidence(out_dir: Path, http: Any) -> BuildResult:
    """Walk OSV records for every CVE present in the
    ``project_samples/`` corpus and emit a CVE-keyed signal of
    ``EVIDENCE`` references that point to known exploit-hosting
    domains.

    OSV aggregates references from upstream advisory sources (GHSA,
    CVE.org, NVD) and tags each by type. ``EVIDENCE`` is a broad
    type — it marks URLs ranging from packetstormsecurity exploit
    code to Snyk/Hackerone advisories to Twitter posts. The first
    pass at this builder accepted every EVIDENCE ref; that nuked
    Spearman ρ on the corpus by labelling 553 findings ``exploited``
    based on advisory presence rather than exploit availability,
    diluting the same definition KEV/EDB/MSF/PoC carry.

    The fix: filter EVIDENCE URLs by host. Only count refs whose
    host is in :data:`_OSV_EVIDENCE_EXPLOIT_HOSTS` — exploit
    archives + bug-bounty PoC sites + the full-disclosure mailing
    list. Advisory-only hosts (snyk.io, hackerone.com, nvd.nist.gov,
    vendor blogs) are dropped because their presence indicates
    public KNOWLEDGE, not public EXPLOIT.

    For high-impact CVEs (Log4Shell, Struts2) this still surfaces
    packetstormsecurity / exploit-db / GitHub gist links — a fifth
    independent ground-truth source beyond KEV / EDB / MSF / GH-PoC,
    with particular value for ecosystems where EDB/MSF/PoC coverage
    is sparse (Rust / .NET / PHP).

    **Scope:** corpus-only. OSV doesn't expose a CVE listing
    endpoint, so the universe of queryable CVEs is bounded by what
    our scans actually surface. Walking the existing 27k-entry
    signal union would be 27k OSV calls (~45 min); walking the
    corpus's surfaced CVEs is typically ~150-500 calls.

    **Empty result is acceptable:** if no project_samples directory
    exists yet (fresh checkout, pre-collect), record_count=0 and
    the signal file emits an empty signals block — the validator
    handles missing files gracefully.
    """
    OSV_BASE = "https://api.osv.dev/v1"
    samples_dir = out_dir / "project_samples"

    cve_set: set = set()
    cves_with_any_evidence_ref = 0
    cves_with_exploit_host_url = 0
    if samples_dir.is_dir():
        for sample_path in samples_dir.rglob("*.json"):
            try:
                data = json.loads(sample_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for finding in data.get("findings", []):
                if not isinstance(finding, dict):
                    continue
                advisory = finding.get("advisory") or {}
                if not isinstance(advisory, dict):
                    continue
                for key in ("aliases", "cves"):
                    for c in (advisory.get(key) or []):
                        if isinstance(c, str) and c.startswith("CVE-"):
                            cve_set.add(c)
                cve = advisory.get("cve_id")
                if isinstance(cve, str) and cve.startswith("CVE-"):
                    cve_set.add(cve)

    signals: Dict[str, Dict[str, Any]] = {}
    queried = 0
    for cve in sorted(cve_set):
        try:
            data = http.get_json(f"{OSV_BASE}/vulns/{cve}")
        except Exception:                                   # noqa: BLE001
            # Per-CVE failures (404, 5xx, timeout) shouldn't abort
            # the whole build. Missing CVEs in OSV simply don't get
            # an EVIDENCE signal.
            continue
        queried += 1
        if not isinstance(data, dict):
            continue
        all_evidence_urls: List[str] = []
        exploit_host_urls: List[str] = []
        for ref in (data.get("references") or []):
            if not isinstance(ref, dict):
                continue
            if ref.get("type") != "EVIDENCE":
                continue
            url = ref.get("url")
            if not isinstance(url, str):
                continue
            all_evidence_urls.append(url)
            if _is_exploit_host_url(url):
                exploit_host_urls.append(url)
        if all_evidence_urls:
            cves_with_any_evidence_ref += 1
        if exploit_host_urls:
            cves_with_exploit_host_url += 1
            signals[cve] = {
                "has_osv_evidence": True,
                "evidence_urls": sorted(set(exploit_host_urls)),
            }
    output = {
        "_source": {
            "name": "OSV EVIDENCE references (corpus-scoped)",
            "url": f"{OSV_BASE}/vulns/{{id}}",
            "license": (
                "Derived signal: presence + URL only. Source URLs "
                "are public observable facts; evidence content is "
                "NOT fetched or stored."
            ),
            "fetched_at": _utcnow(),
            "provenance": (
                "Walks every CVE referenced in project_samples/ "
                "findings, queries OSV /vulns/{id}, and extracts "
                "references where type=='EVIDENCE'. Corpus-scoped "
                "because OSV exposes no CVE-listing endpoint; the "
                "universe is bounded by what our scans actually "
                "surface."
            ),
            "cves_queried": queried,
            "cves_in_corpus": len(cve_set),
            "cves_with_any_evidence_ref": cves_with_any_evidence_ref,
            "cves_with_exploit_host_url": cves_with_exploit_host_url,
            "exploit_host_allowlist": sorted(_OSV_EVIDENCE_EXPLOIT_HOSTS),
        },
        "signals": dict(sorted(signals.items())),
    }
    return _write_if_changed(
        out_dir / "osv_evidence_signals.json", output,
        source="osv_evidence", record_count=len(signals),
    )


# Hosts where an EVIDENCE-tagged URL is an "exploit-publication"
# signal — exploit archives, bug-bounty PoC sites, full-disclosure
# mailing lists. Advisory-only hosts (snyk.io / hackerone.com /
# vendor blogs) are deliberately excluded: their presence indicates
# public knowledge of a vulnerability, not public availability of
# an exploit. We already capture vulnerability-knowledge via OSV's
# core advisory graph; this signal is specifically for "exploit
# code is one click away".
_OSV_EVIDENCE_EXPLOIT_HOSTS = frozenset({
    "exploit-db.com",
    "packetstormsecurity.com",
    "packetstormsecurity.org",
    "0day.today",
    "huntr.dev",
    "gist.github.com",
    "seclists.org",
})


def _is_exploit_host_url(url: str) -> bool:
    """True when the URL's host (case-insensitive, ``www.`` stripped)
    is in the exploit-publication allowlist."""
    if not isinstance(url, str) or not url:
        return False
    try:
        from urllib.parse import urlparse
        host = urlparse(url).netloc.lower()
    except Exception:                                       # noqa: BLE001
        return False
    if host.startswith("www."):
        host = host[4:]
    return host in _OSV_EVIDENCE_EXPLOIT_HOSTS


# Decompression-bomb defence for the Vulnrichment tarball walk
# (:func:`_build_vulnrichment`). ``get_bytes`` bounds the
# *compressed* download, but the gzip + tar layers below can expand
# without limit. We cap total decompressed bytes at
# ``len(compressed) * _DECOMP_RATIO`` (floored at ``_DECOMP_FLOOR``).
# JSON text gzips ~4-15x, so 50x sits far above any honest ratio yet
# trips the 1000x+ expansion that defines a bomb. Anchoring the
# ceiling to the bytes we actually fetched means it auto-scales as the
# corpus grows — there is no absolute size to re-tune.
_DECOMP_RATIO = 50
_DECOMP_FLOOR = 64 * 1024 * 1024
# Bounds the in-memory read of any single member so a forged-huge
# header size can't balloon memory before the stream-level guard
# fires. Most CVE-JSON-5 records are tens of KB, but CISA-ADP
# enrichment of mega-vendor CVEs is genuinely large — e.g.
# CVE-2024-20399 (Cisco NX-OS) is ~9.7 MB of affected-product matrix
# and carries an active-exploitation SSVC signal we must not drop.
# 64 MB keeps a wide margin over observed records while still bounding
# a single read; the stream-level ratio cap is the real bomb guard.
_PER_RECORD_CAP = 64 * 1024 * 1024


class _CappedReader:
    """Wrap a (decompressed) stream and trip once cumulative bytes
    read exceed ``cap``.

    Wrapping the gzip layer — rather than only bounding each extracted
    record — catches a decompression bomb hidden in ANY tar member,
    including ones the caller filters out: a streaming ``tarfile`` must
    still read through their decompressed data to reach the next
    header. Only ``read`` is needed for ``tarfile`` stream mode
    (``r|``); the wrapped object is closed by its own ``with`` block.
    """

    def __init__(self, inner: Any, cap: int) -> None:
        self._inner = inner
        self._cap = cap
        self._seen = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._inner.read(size)
        self._seen += len(chunk)
        if self._seen > self._cap:
            raise RuntimeError(
                "vulnrichment tarball decompressed beyond "
                f"{self._cap} bytes — possible decompression bomb"
            )
        return chunk


def _build_vulnrichment(out_dir: Path, http: Any) -> BuildResult:
    """Fetch the CISA Vulnrichment repository tarball, walk every
    CVE-*.json record, and emit a CVE-keyed signal file for any
    entry with SSVC ``Exploitation`` of ``poc`` or ``active``.

    Vulnrichment is one of the cleanest cross-eco exploitation
    signals — CC0 1.0 public domain, vendor-neutral (US Government
    work, the cisagov organization), and covers ~60% of CVEs in
    ecosystems where the existing five signal sources (KEV / EDB /
    MSF / GitHub-PoC / OSV-Evidence) return ~0% coverage (Cargo /
    NuGet / Packagist). See ``project_sca_post_ship_deferred.md``
    for the trigger-driven research that selected this source.

    SSVC values are normalised to lowercase. We deliberately drop
    ``none`` entries — they carry no exploit signal and would
    bloat the file by ~3x without adding any signal. Operators
    needing the full ``none`` set should query
    ``core.cve.vulnrichment.VulnrichmentClient`` at runtime.

    The tarball is ~60 MB compressed / ~280 MB extracted. We
    stream the archive members through ``tarfile`` without
    extracting to disk; only the per-CVE SSVC fields are kept in
    memory. ``max_bytes`` ceiling (300 MB) is a defence against
    a tarball that grew unexpectedly — operators can lift the
    cap by re-fetching outside the build if needed.
    """
    import gzip
    import io
    import tarfile

    # ``HEAD`` resolves to the repo's default branch at request time
    # (CISA publishes to ``develop``, not ``main``); codeload honours
    # it, so a future default-branch rename can't 404 this fetch.
    VULNRICHMENT_TARBALL = (
        "https://codeload.github.com/cisagov/vulnrichment/tar.gz/HEAD"
    )
    raw = http.get_bytes(
        VULNRICHMENT_TARBALL, max_bytes=300 * 1024 * 1024,
    )
    # Bound total decompression so a bomb hidden anywhere in the
    # tarball can't OOM the runner (see ``_CappedReader``).
    max_decompressed = max(_DECOMP_FLOOR, len(raw) * _DECOMP_RATIO)
    signals: Dict[str, Dict[str, Any]] = {}
    files_scanned = 0
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
        capped = _CappedReader(gz, max_decompressed)
        with tarfile.open(fileobj=capped, mode="r|") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                name = member.name
                if not name.endswith(".json"):
                    continue
                base = name.rsplit("/", 1)[-1]
                if not base.startswith("CVE-"):
                    continue
                files_scanned += 1
                f = tar.extractfile(member)
                if f is None:
                    continue
                # Bound the per-member read: a real CVE record is tiny,
                # so a member that reads past the cap is not a genuine
                # entry — skip it rather than buffer an arbitrary size.
                blob = f.read(_PER_RECORD_CAP + 1)
                if len(blob) > _PER_RECORD_CAP:
                    logger.warning(
                        "sca.calibration: vulnrichment member %s exceeds "
                        "%d bytes — skipping (not a genuine CVE record)",
                        name, _PER_RECORD_CAP,
                    )
                    continue
                try:
                    record = json.loads(blob)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                decision = _vulnrichment_extract_ssvc(record)
                if decision is None:
                    continue
                exploitation = decision["exploitation"]
                if exploitation not in ("poc", "active"):
                    # ``none`` carries no exploit signal — skip.
                    # Future versions may also keep ``none``
                    # entries for completeness; today the
                    # ground-truth file is the union-of-signals
                    # set, so a non-signal entry is a no-op.
                    continue
                cve_id = (
                    record.get("cveMetadata", {}).get("cveId") or ""
                ).upper()
                if not cve_id.startswith("CVE-"):
                    continue
                signals[cve_id] = {
                    "ssvc_exploitation": exploitation,
                    "ssvc_automatable": decision.get("automatable"),
                    "ssvc_technical_impact": decision.get(
                        "technical_impact",
                    ),
                }
    output = {
        "_source": {
            "name": "CISA Vulnrichment (SSVC Exploitation)",
            "url": VULNRICHMENT_TARBALL,
            "license": "CC0 1.0 Universal (Public Domain)",
            "fetched_at": _utcnow(),
            "provenance": (
                "CISA Vulnrichment SSVC scorecards filtered to "
                "entries with Exploitation=poc or =active. "
                "Skips ``none`` entries; a missing CVE means "
                "either no SSVC scorecard yet OR SSVC=none "
                "(query VulnrichmentClient at runtime for the "
                "full picture)."
            ),
            "files_scanned": files_scanned,
        },
        "signals": dict(sorted(signals.items())),
    }
    return _write_if_changed(
        out_dir / "vulnrichment_signals.json", output,
        source="vulnrichment", record_count=len(signals),
    )


def _vulnrichment_extract_ssvc(record: Any) -> Optional[Dict[str, Any]]:
    """Pluck SSVC fields out of a CVE-JSON-5 record's CISA-ADP
    container. Returns ``{"exploitation", "automatable",
    "technical_impact"}`` or ``None`` if the entry lacks an SSVC
    scorecard.

    Defensive: any unexpected shape → ``None``. Mirrors
    :func:`core.cve.vulnrichment._decode_ssvc` so a future schema
    change touches both. (Both kept independent for now to avoid
    a build-time import of the runtime client.)
    """
    if not isinstance(record, dict):
        return None
    containers = record.get("containers")
    if not isinstance(containers, dict):
        return None
    adp = containers.get("adp")
    if not isinstance(adp, list):
        return None
    for entry in adp:
        if not isinstance(entry, dict):
            continue
        provider = (
            (entry.get("providerMetadata") or {}).get("shortName") or ""
        )
        if "CISA-ADP" not in provider:
            continue
        for metric in entry.get("metrics") or []:
            if not isinstance(metric, dict):
                continue
            content = (metric.get("other") or {}).get("content") or {}
            options = content.get("options")
            if not isinstance(options, list):
                continue
            exploitation = None
            automatable = None
            technical_impact = None
            for opt in options:
                if not isinstance(opt, dict):
                    continue
                if "Exploitation" in opt:
                    exploitation = str(opt["Exploitation"]).lower()
                if "Automatable" in opt:
                    automatable = str(opt["Automatable"]).lower()
                if "Technical Impact" in opt:
                    technical_impact = (
                        str(opt["Technical Impact"]).lower()
                    )
            if exploitation in ("none", "poc", "active"):
                return {
                    "exploitation": exploitation,
                    "automatable": automatable,
                    "technical_impact": technical_impact,
                }
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> str:
    """ISO-8601 UTC timestamp without microseconds — stable string
    for diff-friendliness."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_if_changed(
    path: Path, data: Dict[str, Any], *, source: str,
    record_count: int,
) -> BuildResult:
    """Write ``data`` to ``path`` only when content differs.

    Diff is computed against the file's current bytes (with
    ``_source.fetched_at`` masked to current run time so the
    timestamp churn doesn't trigger spurious diffs). Returns a
    BuildResult with ``written`` reflecting whether disk changed.
    """
    new_bytes = json.dumps(
        data, indent=2, sort_keys=True, ensure_ascii=False,
    ).encode("utf-8") + b"\n"
    if path.exists():
        try:
            existing = path.read_bytes()
        except OSError:
            existing = b""
        if _bytes_equal_excluding_timestamp(existing, new_bytes):
            return BuildResult(
                source=source, written=False, error=None,
                record_count=record_count,
            )
    path.write_bytes(new_bytes)
    return BuildResult(
        source=source, written=True, error=None,
        record_count=record_count,
    )


def _bytes_equal_excluding_timestamp(a: bytes, b: bytes) -> bool:
    """Compare two corpus JSON blobs ignoring ``_source.fetched_at``.

    Without this the corpus would re-write every run (timestamp
    differs even when source content didn't change), churning the
    git history. Match-on-content semantics.
    """
    try:
        da = json.loads(a)
        db = json.loads(b)
    except (json.JSONDecodeError, ValueError):
        return False
    for d in (da, db):
        if isinstance(d, dict) and "_source" in d:
            d["_source"] = {
                k: v for k, v in d["_source"].items()
                if k != "fetched_at"
            }
    return da == db


__all__ = ["BuildResult", "build_corpus"]
