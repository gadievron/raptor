"""2-method pointer consensus.

For a given CVE, run two independent fix-commit-finding methods and
report whether they agree on a `(slug, sha)` pointer. The pipeline's
acquire+diff stages turn the chosen pointer into source code; this
module measures whether independent sources attest to that pointer.

The two methods (highest-signal pointer sources):

  1. **OSV references**  — `osv_raw`'s ``references[].url`` matching
     ``github.com/<owner>/<repo>/commit/<sha>`` + kernel.org shortlinks.
  2. **NVD Patch-tagged** — `nvd_raw`'s ``references[]`` with
     ``tags=["Patch"]`` containing GitHub or kernel commit URLs.

Earlier versions ran 5 methods (GHSA alias / distro tracker / GitHub
commit search). They were dropped from the consensus tally because the
3 added methods rarely *disagreed* with the top 2 — they mostly
provided redundant agreement, not independent evidence. They remain
available as agent tools for *discovery*; they just don't contribute
to the ship-time consensus signal.

This is **pointer-level consensus**, not source-level: each method
outputs a pointer to where the fix should be, and we tally whether
they agree. Source code itself comes from the existing `extract_diff`
pipeline (or `extract_via_api` fallback), run once against the
agent's chosen pointer.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from cve_diff.core.url_re import (
    GITHUB_COMMIT_URL_RE,
    KERNEL_SHA_URL_RE,
    LINUX_UPSTREAM_SLUG,
    normalize_slug,
)


@dataclass(frozen=True, slots=True)
class MethodResult:
    """Output of one method runner."""
    name: str
    found: bool
    slug: str = ""
    sha: str = ""
    detail: str = ""  # source URL or note explaining why no result

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "found": self.found,
            "slug": self.slug,
            "sha": self.sha,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class ConsensusReport:
    """Aggregate of 2 methods' findings."""
    cve_id: str
    methods: tuple[MethodResult, ...]  # always 2
    consensus_slug: str  # "" if no consensus
    consensus_sha: str   # "" if no consensus
    agreement_count: int  # how many methods voted for the consensus pick

    @property
    def attempted_count(self) -> int:
        return sum(1 for m in self.methods if m.found)

    def matches_pipeline_pick(self, picked_slug: str, picked_sha: str) -> bool:
        """Did the agent's submission match the consensus?"""
        if not self.consensus_slug:
            return False
        ps = normalize_slug(picked_slug or "")
        return (
            ps == self.consensus_slug
            and (picked_sha or "").lower().startswith(self.consensus_sha[:12].lower())
        )

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "methods": [m.to_dict() for m in self.methods],
            "consensus_slug": self.consensus_slug,
            "consensus_sha": self.consensus_sha,
            "agreement_count": self.agreement_count,
            "attempted_count": self.attempted_count,
        }


def _extract_pair_from_url(url: str) -> tuple[str, str] | None:
    """Return (slug, sha) from a GitHub commit URL or kernel shortlink."""
    m = GITHUB_COMMIT_URL_RE.search(url or "")
    if m:
        return normalize_slug(m.group(1)), m.group(2).lower()
    km = KERNEL_SHA_URL_RE.search(url or "")
    if km:
        return LINUX_UPSTREAM_SLUG.lower(), km.group(1).lower()
    return None


# ------------------------------------------------------------------ method 1
def _osv_references(cve_id: str) -> MethodResult:
    """Method 1: scan OSV's references[].url for github commits."""
    from tools.oracle.osv_oracle import _fetch_osv  # reuse existing fetcher
    payload = _fetch_osv(cve_id)
    if payload is None:
        return MethodResult("OSV references", False, detail="OSV 404 / network failure")
    for ref in payload.get("references") or []:
        pair = _extract_pair_from_url((ref.get("url") or "").strip())
        if pair:
            slug, sha = pair
            return MethodResult("OSV references", True, slug=slug, sha=sha,
                                detail=ref.get("url", ""))
    # Fall back to affected[].ranges[].events[].fixed
    for aff in payload.get("affected") or []:
        for rng in aff.get("ranges") or []:
            if (rng.get("type") or "").upper() != "GIT":
                continue
            from cve_diff.core.url_re import extract_github_slug
            slug = extract_github_slug(rng.get("repo") or "") or ""
            for ev in rng.get("events") or []:
                sha = (ev.get("fixed") or "").lower()
                if slug and sha and sha != "0":
                    return MethodResult("OSV references", True, slug=slug, sha=sha,
                                        detail=f"affected.ranges (repo={slug})")
    return MethodResult("OSV references", False, detail="no commit URLs in references / ranges")


# ------------------------------------------------------------------ method 2
def _nvd_patch_tagged(cve_id: str) -> MethodResult:
    """Method 2: scan NVD's references[] with tags=['Patch']."""
    from cve_diff.discovery.nvd import NvdDiscoverer
    nvd = NvdDiscoverer()
    payload = nvd.get_payload(cve_id)
    if payload is None:
        return MethodResult("NVD Patch-tagged", False, detail="NVD 404 / network failure")
    for vuln in payload.get("vulnerabilities") or []:
        cve = vuln.get("cve") or {}
        for ref in cve.get("references") or []:
            tags = ref.get("tags") or []
            if "Patch" not in tags:
                continue
            pair = _extract_pair_from_url((ref.get("url") or "").strip())
            if pair:
                slug, sha = pair
                return MethodResult("NVD Patch-tagged", True, slug=slug, sha=sha,
                                    detail=ref.get("url", ""))
    return MethodResult("NVD Patch-tagged", False, detail="no Patch-tagged commit refs")


# ------------------------------------------------------------------ orchestrator
def run_consensus(cve_id: str) -> ConsensusReport:
    """Run both methods, aggregate by canonical (slug, sha[:12]) key."""
    methods: tuple[MethodResult, ...] = (
        _osv_references(cve_id),
        _nvd_patch_tagged(cve_id),
    )

    # Aggregate by (canonical_slug, sha[:12]). Methods that didn't find
    # anything contribute nothing; agreement requires both votes.
    counts: Counter[tuple[str, str]] = Counter()
    full_sha: dict[tuple[str, str], str] = {}
    for m in methods:
        if not m.found or not m.slug or not m.sha:
            continue
        key = (m.slug.lower(), m.sha[:12].lower())
        counts[key] += 1
        # Keep the longest SHA we've seen (different methods may publish
        # different abbreviation lengths).
        if len(m.sha) > len(full_sha.get(key, "")):
            full_sha[key] = m.sha

    if not counts:
        return ConsensusReport(cve_id=cve_id, methods=methods,
                               consensus_slug="", consensus_sha="",
                               agreement_count=0)
    top_key, top_count = counts.most_common(1)[0]
    if top_count < 2:
        # Only one method found a pointer — no cross-source agreement,
        # but expose the single pointer for downstream display.
        return ConsensusReport(cve_id=cve_id, methods=methods,
                               consensus_slug="", consensus_sha="",
                               agreement_count=top_count)
    return ConsensusReport(
        cve_id=cve_id,
        methods=methods,
        consensus_slug=top_key[0],
        consensus_sha=full_sha[top_key],
        agreement_count=top_count,
    )


def render_markdown(report: ConsensusReport) -> str:
    """Format a `ConsensusReport` as a Markdown section."""
    lines: list[str] = []
    lines.append("## Consensus from 2 methods")
    lines.append("")
    lines.append("| Method | Found | Slug / SHA | Note |")
    lines.append("|---|:-:|---|---|")
    for m in report.methods:
        if m.found:
            lines.append(
                f"| {m.name} | ✓ | {m.slug} / {m.sha[:12]} | "
                f"{(m.detail or '')[:80]} |"
            )
        else:
            lines.append(f"| {m.name} | — | — | {(m.detail or '')[:80]} |")
    lines.append("")
    if report.agreement_count >= 2:
        lines.append(
            f"**Both methods agree on "
            f"`{report.consensus_slug}/{report.consensus_sha[:12]}`.**"
        )
    elif report.attempted_count == 0:
        lines.append("**No method found a fix-commit pointer for this CVE.**")
    else:
        lines.append(
            f"**No consensus** — {report.attempted_count} of 2 method(s) "
            f"found a pointer; the other did not."
        )
    return "\n".join(lines)
