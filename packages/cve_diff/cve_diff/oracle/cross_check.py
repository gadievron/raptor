"""Oracle cross-check CLI.

Reads a `cve-diff bench` ``summary.json`` and, for each CVE:
- If PASS: parse the matching ``<cve_id>.osv.json`` in the same
  directory to extract our picked (slug, sha), then call the OSV
  oracle and NVD fallback.
- If FAIL: pass empty (slug, sha) to the oracle so we surface
  false-refusals (CVEs we labeled UnsupportedSource / DiscoveryError
  that OSV/NVD actually have commit data for).

Writes:
- ``<output_dir>/oracle_verdicts.jsonl`` — one JSON line per CVE
- ``<output_dir>/oracle_summary.md`` — aggregate breakdown + top
  examples per verdict

Usage:
    .venv/bin/python -m cve_diff.oracle.cross_check \\
        --summary /tmp/bench200/summary.json \\
        --output-dir /tmp/bench200/oracle/
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

from core.http.urllib_backend import UrllibClient
from packages.nvd import NvdClient
from packages.nvd.verify import verify as _nvd_verify
from packages.osv import OsvClient
from packages.osv.verdicts import OracleVerdict, Verdict
from packages.osv.verify import verify as _osv_verify


@functools.lru_cache(maxsize=1)
def _osv_client() -> OsvClient:
    return OsvClient(http=UrllibClient(user_agent="cve-diff-cross-check/0.1"))


@functools.lru_cache(maxsize=1)
def _nvd_client() -> NvdClient:
    return NvdClient()

_GH_COMMIT_URL = re.compile(
    r"https?://github\.com/([^/]+/[^/#?\s.]+)/commit/([a-f0-9]{7,40})",
    re.IGNORECASE,
)


def _load_pick_from_osv_file(summary_dir: Path, cve_id: str) -> tuple[str, str]:
    """Return (slug, sha) from the per-CVE OSV JSON, or ('', '')."""
    path = summary_dir / f"{cve_id}.osv.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "", ""
    for ref in data.get("references") or []:
        url = (ref.get("url") or "")
        m = _GH_COMMIT_URL.search(url)
        if m:
            slug = m.group(1)
            if slug.endswith(".git"):
                slug = slug[:-4]
            return slug, m.group(2)
    # Fallback: the repo field + the first fixed event.
    for aff in data.get("affected") or []:
        for rng in aff.get("ranges") or []:
            repo = rng.get("repo") or ""
            m = re.match(r"https?://github\.com/([^/]+/[^/#?\s.]+)", repo)
            slug = ""
            if m:
                slug = m.group(1)
                if slug.endswith(".git"):
                    slug = slug[:-4]
            for ev in rng.get("events") or []:
                sha = ev.get("fixed") or ""
                if slug and sha:
                    return slug, sha
    return "", ""


def _verify_one(cve_id: str, picked_slug: str, picked_sha: str) -> OracleVerdict:
    """Ask OSV; if ORPHAN, fall back to NVD."""
    v = _osv_verify(cve_id, picked_slug, picked_sha, client=_osv_client())
    if v.verdict != Verdict.ORPHAN:
        return v
    nv = _nvd_verify(cve_id, picked_slug, picked_sha, client=_nvd_client())
    if nv.verdict != Verdict.ORPHAN:
        return nv
    # Both orphans — return the first with combined note.
    return OracleVerdict(
        cve_id=cve_id, picked_slug=picked_slug, picked_sha=picked_sha,
        verdict=Verdict.ORPHAN, source="none",
        notes="OSV + NVD both have no commit data",
    )


def _classify_bench_status(r: dict) -> str:
    if r.get("ok"):
        return "PASS"
    err = r.get("error") or ""
    if "UnsupportedSource" in err:
        return "UNSUPPORTED"
    if "DiscoveryError" in err:
        return "DISCOVERY_ERROR"
    if "AcquisitionError" in err:
        return "ACQUISITION_ERROR"
    if "AnalysisError" in err:
        return "ANALYSIS_ERROR"
    return "OTHER_FAIL"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--summary", required=True, help="Path to bench summary.json")
    p.add_argument("--output-dir", required=True, help="Where to write verdicts + markdown")
    p.add_argument("--limit", type=int, default=0, help="Stop after N CVEs (0 = all)")
    args = p.parse_args()

    summary_path = Path(args.summary)
    summary_dir = summary_path.parent
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    results = summary.get("results") or []
    if args.limit > 0:
        results = results[: args.limit]

    verdicts_by_status: dict[str, list[OracleVerdict]] = {}
    verdicts_flat: list[tuple[str, OracleVerdict]] = []
    jsonl_path = out_dir / "oracle_verdicts.jsonl"

    print(f"Cross-checking {len(results)} CVEs from {summary_path} → {out_dir}", file=sys.stderr)
    # Write to a `.tmp` file then atomically rename to the final
    # path. Pre-fix the writer wrote directly to `oracle_verdicts.jsonl`
    # — if the oracle was interrupted (Ctrl-C, OOM kill, parent
    # process exit) mid-run, the partial file looked legitimate to
    # downstream consumers (file exists, parses as JSONL up to
    # truncation point) but was missing the tail of CVE verdicts.
    # Re-running the oracle then double-counted the already-written
    # head of the previous run if the consumer didn't notice.
    #
    # Atomic temp-then-rename pattern: writer flushes + fsyncs
    # before rename so the on-disk content is durable; rename is
    # atomic at the filesystem-metadata layer. Consumer sees either
    # the OLD complete file or the NEW complete file, never a
    # truncated transition.
    #
    # Per-iteration `fh.flush()` is intentional checkpoint behaviour
    # — operator can `tail -f oracle_verdicts.jsonl.tmp` to watch
    # progress in real time on large runs (1000+ CVEs take 30+ min).
    tmp_path = jsonl_path.with_suffix(jsonl_path.suffix + ".tmp")
    with tmp_path.open("w", encoding="utf-8") as fh:
        for i, r in enumerate(results, 1):
            cve_id = r.get("cve_id", "UNKNOWN")
            status = _classify_bench_status(r)
            if status == "PASS":
                picked_slug, picked_sha = _load_pick_from_osv_file(summary_dir, cve_id)
            else:
                picked_slug, picked_sha = "", ""
            v = _verify_one(cve_id, picked_slug, picked_sha)
            verdicts_by_status.setdefault(status, []).append(v)
            verdicts_flat.append((status, v))
            fh.write(json.dumps({"bench_status": status, **v.to_dict()}) + "\n")
            fh.flush()  # checkpoint — see comment above
            if i % 20 == 0:
                print(f"  … {i}/{len(results)}", file=sys.stderr)
        # fsync before rename so the data pages are on disk before
        # the rename's metadata change becomes visible.
        try:
            os.fsync(fh.fileno())
        except OSError:
            pass
    os.replace(str(tmp_path), str(jsonl_path))

    # Aggregate markdown.
    # `errors="replace"` so a stray surrogate or other non-roundtripable
    # codepoint (rare but possible — CVE descriptions sometimes carry
    # half-decoded UTF-16 from upstream feeds; LLM-generated content
    # can hold lone surrogates from token-truncation artefacts) gets
    # written as the replacement char `?` instead of raising
    # UnicodeEncodeError. Pre-fix the strict-default behaviour
    # crashed the oracle run mid-write — operator saw partial
    # JSONL written with NO oracle_summary.md, blamed an oracle
    # bug rather than the upstream feed encoding issue.
    md = _render_markdown(summary_path.name, results, verdicts_by_status)
    (out_dir / "oracle_summary.md").write_text(md, encoding="utf-8", errors="replace")

    # Headline to stderr
    pass_results = verdicts_by_status.get("PASS", [])
    ver = sum(1 for v in pass_results if v.verdict == Verdict.MATCH_EXACT)
    rng = sum(1 for v in pass_results if v.verdict == Verdict.MATCH_RANGE)
    mirror = sum(1 for v in pass_results if v.verdict == Verdict.MIRROR_DIFFERENT_SLUG)
    disp = sum(1 for v in pass_results if v.verdict == Verdict.DISPUTE)
    orph = sum(1 for v in pass_results if v.verdict == Verdict.ORPHAN)
    hall = sum(1 for v in pass_results if v.verdict == Verdict.LIKELY_HALLUCINATION)
    print(
        f"\nPASS breakdown: exact={ver} range={rng} mirror={mirror} "
        f"dispute={disp} orphan={orph} hallucination={hall}",
        file=sys.stderr,
    )
    return 0


def _render_markdown(summary_name: str, results: list[dict],
                     by_status: dict[str, list[OracleVerdict]]) -> str:
    lines: list[str] = []
    lines.append(f"# Oracle verification — `{summary_name}`\n")
    lines.append(f"Total CVEs: {len(results)}\n")
    lines.append("## Breakdown by bench-status × oracle-verdict\n")
    lines.append("| bench status | oracle verdict | count |")
    lines.append("|---|---|---:|")
    for status, vs in sorted(by_status.items()):
        counter: Counter[str] = Counter()
        for v in vs:
            counter[v.verdict.value] += 1
        for verdict, c in counter.most_common():
            lines.append(f"| {status} | {verdict} | {c} |")

    # Per-status sections with notable examples.
    for status, vs in sorted(by_status.items()):
        lines.append(f"\n## {status} ({len(vs)} CVEs)\n")
        by_v: dict[Verdict, list[OracleVerdict]] = {}
        for v in vs:
            by_v.setdefault(v.verdict, []).append(v)
        for verdict in sorted(by_v.keys(), key=lambda x: x.value):
            examples = by_v[verdict]
            lines.append(f"### {verdict.value} ({len(examples)})")
            # Show up to 5 examples.
            for ex in examples[:5]:
                lines.append(
                    f"- **{ex.cve_id}** (src={ex.source}): "
                    f"picked=`{ex.picked_slug}@{ex.picked_sha[:12] if ex.picked_sha else ''}`, "
                    f"expected={list(ex.expected_slugs)[:3]} / {[s[:12] for s in ex.expected_shas[:3]]}"
                    + (f". {ex.notes}" if ex.notes else "")
                )
            if len(examples) > 5:
                lines.append(f"- … and {len(examples) - 5} more")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
