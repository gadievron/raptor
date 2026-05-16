"""Per-CVE signal layer: EPSS, KEV.

Shared substrate for any consumer that needs to enrich findings with
CVE-keyed risk signals — SCA's vulnerable-dependency findings, but
also ``/agentic`` ranking, ``/validate`` severity adjustment,
``/exploit`` prioritisation, and SARIF / report badges. All clients
take an injected :class:`core.http.HttpClient` and
:class:`core.json.JsonCache` so consumers control the egress policy
(allowlist via ``EgressClient``) and cache lifetime per their needs.

The signal layer is deliberately scope-limited to PUBLIC CVE-keyed
data. Corpus-backed signals (Exploit-DB, Metasploit, GitHub PoC
indices) live elsewhere — they have data-distribution licensing
constraints that don't fit a generic core utility. SCA's
``exploit_evidence`` module bundles its calibration corpus and
stays in ``packages/sca`` for that reason.

OSV.dev is also out of scope here: ``packages/osv`` already
provides the shared OSV client / parser / verdict types.
``core/cve`` is for the per-CVE attribute layer (is this CVE in
KEV? what's its EPSS score?), not for advisory aggregation.
"""

from core.cve.epss import EPSS_URL, EpssClient
from core.cve.kev import KEV_URL, KevClient

__all__ = ["EpssClient", "EPSS_URL", "KevClient", "KEV_URL"]
