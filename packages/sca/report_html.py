"""HTML report — self-contained alternative to ``report.md``.

Same severity-sorted, finding-grouped shape as the markdown
report, rendered as a single HTML file with embedded CSS — no
external assets, no JavaScript, no markdown-to-HTML library
dependency. Suitable for CI artefact uploads, compliance
attachments, and any consumer that wants browser-renderable
output.

Public entry: :func:`render_html_report` — same signature as
:func:`packages.sca.report.render_markdown_report`. Pipeline
emits both formats when ``--html`` is passed.
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Optional, Sequence

from .findings import severity_rank
from .models import (
    HygieneFinding,
    SupplyChainFinding,
    VulnFinding,
)


_SEV_LABEL = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Info",
    # ``none`` = CVSS rated 0.0 (rare). Rendered with a distinct
    # label so operators don't read the bare word "None" as a
    # placeholder / bug.
    "none": "None (CVSS 0.0)",
}

# Severity-keyed colours. Permissive palette — readable on light
# AND dark backgrounds via OS preference (the embedded CSS uses
# ``prefers-color-scheme`` to adapt).
_SEV_BG = {
    "critical": "#7f1d1d", "high": "#9a3412", "medium": "#854d0e",
    "low": "#1e40af", "info": "#374151",
}


def render_html_report(
    *,
    target: Path,
    deps_analysed: int,
    vuln_findings: Sequence[VulnFinding],
    hygiene_findings: Sequence[HygieneFinding],
    supply_chain_findings: Sequence[SupplyChainFinding] = (),
    license_findings: Sequence = (),
    cache_hits: Optional[int] = None,
    cache_misses: Optional[int] = None,
    cache_evictions: Optional[int] = None,
    generated_at: Optional[datetime] = None,
) -> str:
    """Return the full report as a single HTML string."""
    generated_at = generated_at or datetime.now(timezone.utc)
    sorted_vulns = sorted(
        vuln_findings,
        key=lambda f: (-severity_rank(f.severity),
                       not f.in_kev,
                       -(f.epss or 0.0),
                       f.dependency.name),
    )
    sorted_hygiene = sorted(
        hygiene_findings,
        key=lambda f: (-severity_rank(f.severity), f.kind, f.dependency.name),
    )
    sorted_supply = sorted(
        supply_chain_findings,
        key=lambda f: (-severity_rank(f.severity), f.kind, f.dependency.name),
    )
    sorted_license = sorted(
        license_findings,
        key=lambda f: (-severity_rank(f.severity), f.kind, f.dependency.name),
    )

    # Auto-populate the ecosystem dropdown from the actual deps
    # in the report (rather than hard-coding the 8 known
    # ecosystems) so the dropdown only shows what the operator
    # has to triage.
    ecosystems = sorted({
        f.dependency.ecosystem
        for f in (*sorted_vulns, *sorted_supply,
                   *sorted_license, *sorted_hygiene)
    })
    parts = [
        _doctype(),
        _head(target),
        "<body>",
        _h1(target, generated_at),
        _summary_section(
            deps_analysed=deps_analysed,
            vuln_findings=sorted_vulns,
            hygiene_findings=sorted_hygiene,
            supply_chain_findings=sorted_supply,
            license_findings=sorted_license,
            cache_hits=cache_hits, cache_misses=cache_misses,
            cache_evictions=cache_evictions,
        ),
        _filter_bar(ecosystems),
    ]
    if sorted_vulns:
        parts.append(_vuln_section(sorted_vulns))
    if sorted_supply:
        parts.append(_kinded_section(
            sorted_supply, header="Supply-chain findings",
            kind_attr="kind",
        ))
    if sorted_license:
        parts.append(_license_section(sorted_license))
    if sorted_hygiene:
        parts.append(_kinded_section(
            sorted_hygiene, header="Hygiene findings",
            kind_attr="kind",
        ))
    if (not sorted_vulns and not sorted_hygiene
            and not sorted_supply and not sorted_license):
        parts.append(
            "<section><h2>Findings</h2><p>No vulnerabilities, "
            "hygiene, supply-chain, or license issues detected for "
            "the analysed dependency set.</p></section>"
        )
    parts.append(_FILTER_SCRIPT)
    parts.append("</body></html>")
    return "\n".join(parts)


def write_html_report(path: Path, content: str) -> None:
    from ._atomic import atomic_write_text
    atomic_write_text(path, content)


# ---------------------------------------------------------------------------
# Document scaffolding
# ---------------------------------------------------------------------------


def _doctype() -> str:
    return "<!DOCTYPE html>\n<html lang=\"en\">"


def _head(target: Path) -> str:
    title = escape(f"SCA Report — {target}")
    return (
        "<head>"
        '<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{title}</title>"
        f"<style>{_CSS}</style>"
        "</head>"
    )


def _h1(target: Path, generated_at: datetime) -> str:
    return (
        f"<h1>SCA Report — <code>{escape(str(target))}</code></h1>"
        f"<p class=\"meta\">Generated: "
        f"{generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>"
    )


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------


def _summary_section(
    *,
    deps_analysed: int,
    vuln_findings: Sequence[VulnFinding],
    hygiene_findings: Sequence[HygieneFinding],
    supply_chain_findings: Sequence[SupplyChainFinding],
    license_findings: Sequence,
    cache_hits: Optional[int],
    cache_misses: Optional[int],
    cache_evictions: Optional[int] = None,
) -> str:
    from collections import Counter
    severity_counts: Counter = Counter()
    kev_count = 0
    suppressed_count = 0
    for f in vuln_findings:
        if f.suppressed:
            suppressed_count += 1
            continue
        severity_counts[f.severity] += 1
        if f.in_kev:
            kev_count += 1
    for collection in (supply_chain_findings, hygiene_findings,
                        license_findings):
        for f in collection:
            if getattr(f, "suppressed", False):
                suppressed_count += 1
                continue
            severity_counts[f.severity] += 1

    rows = []
    for sev in ("critical", "high", "medium", "low", "info"):
        if severity_counts.get(sev):
            rows.append(
                f"<tr><td><span class=\"sev sev-{sev}\">"
                f"{escape(_SEV_LABEL[sev])}</span></td>"
                f"<td>{severity_counts[sev]}</td></tr>"
            )
    if not rows:
        rows.append("<tr><td>(none)</td><td>0</td></tr>")

    counts = [
        ("Dependencies analysed", deps_analysed),
        ("Vulnerable findings", len(vuln_findings)),
        ("KEV-listed", kev_count),
        ("Supply-chain findings", len(supply_chain_findings)),
        ("Hygiene findings", len(hygiene_findings)),
    ]
    if license_findings:
        counts.append(("License findings", len(license_findings)))
    if suppressed_count:
        counts.append(("Suppressed", suppressed_count))
    if cache_hits is not None and cache_misses is not None:
        total = cache_hits + cache_misses
        rate = (cache_hits * 100 // total) if total else 0
        cache_label = f"{cache_hits} hits / {cache_misses} misses ({rate}%)"
        if cache_evictions is not None and cache_evictions > 0:
            # See report.py — surface evictions only when LRU fired.
            cache_label += f", {cache_evictions} memo evictions"
        counts.append(("Advisory cache", cache_label))

    counts_html = "".join(
        f"<dt>{escape(k)}</dt><dd>{escape(str(v))}</dd>"
        for k, v in counts
    )
    return (
        "<section><h2>Summary</h2>"
        "<table class=\"sev-table\">"
        "<thead><tr><th>Severity</th><th>Count</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        f"<dl class=\"counts\">{counts_html}</dl>"
        "</section>"
    )


def _vuln_section(findings: Sequence[VulnFinding]) -> str:
    parts = ["<section><h2>Vulnerable dependencies</h2>"]
    for f in findings:
        parts.append(_vuln_card(f))
    parts.append("</section>")
    return "".join(parts)


def _vuln_card(f: VulnFinding) -> str:
    dep = f.dependency
    primary = f.advisories[0] if f.advisories else None
    # data-* attributes feed the interactive filter bar (see
    # ``_filter_bar`` / ``_FILTER_SCRIPT``). Each card exposes the
    # discriminators the operator filters on; ``data-search`` is a
    # pre-lowercased haystack so the JS filter doesn't have to
    # call ``.toLowerCase()`` on every keystroke.
    search_bits = [
        dep.name, dep.version or "",
        primary.osv_id if primary else "",
        primary.summary if primary else "",
    ]
    if primary and primary.aliases:
        search_bits.extend(primary.aliases)
    haystack = " ".join(s for s in search_bits if s).lower()
    parts = [
        f"<article class=\"finding sev-{f.severity}\""
        f" data-severity=\"{f.severity}\""
        f" data-kev=\"{'1' if f.in_kev else '0'}\""
        f" data-suppressed=\"{'1' if f.suppressed else '0'}\""
        f" data-ecosystem=\"{escape(dep.ecosystem)}\""
        f" data-search=\"{escape(haystack)}\">"
        f"<h3><span class=\"sev sev-{f.severity}\">"
        f"{escape(_SEV_LABEL.get(f.severity, f.severity.title()))}"
        f"</span> {escape(dep.name)} {escape(dep.version or '*')}"
    ]
    if f.fixed_version:
        parts.append(
            f" → <em>fix:</em> <code>{escape(f.fixed_version)}</code>"
        )
    if f.suppressed:
        reason = f.suppression_reason or "no reason"
        parts.append(
            f" <small class=\"suppressed\">suppressed: "
            f"{escape(reason)}</small>"
        )
    parts.append("</h3><ul>")
    if primary is not None:
        aliases = ", ".join(escape(a) for a in primary.aliases[:3]) \
            if primary.aliases else "—"
        parts.append(
            f"<li><strong>Advisory:</strong> "
            f"<code>{escape(primary.osv_id)}</code> "
            f"<small>(aliases: {aliases})</small></li>"
        )
        if primary.summary:
            parts.append(f"<li>{escape(primary.summary)}</li>")
    badges: list = []
    if f.in_kev:
        badges.append("<span class=\"badge kev\">KEV</span>")
    if f.epss is not None and f.epss > 0:
        badges.append(
            f"<span class=\"badge epss\">EPSS {f.epss:.2f}</span>"
        )
    if f.cvss_score is not None:
        badges.append(
            f"<span class=\"badge cvss\">CVSS {f.cvss_score}</span>"
        )
    if badges:
        parts.append(f"<li>{' '.join(badges)}</li>")
    ev = getattr(f, "exploit_evidence", None)
    if ev is not None and ev.has_any:
        if ev.edb_ids:
            edb_links = ", ".join(
                f"<a href=\"https://www.exploit-db.com/exploits/{i}\">{i}</a>"
                for i in ev.edb_ids[:3]
            )
            extra = (f" (+{len(ev.edb_ids) - 3} more)"
                      if len(ev.edb_ids) > 3 else "")
            parts.append(
                f"<li><strong>Exploit-DB:</strong> {edb_links}{extra}</li>"
            )
        if ev.msf_modules:
            mods = ", ".join(
                f"<code>{escape(m)}</code>" for m in ev.msf_modules[:2]
            )
            extra = (f" (+{len(ev.msf_modules) - 2} more)"
                      if len(ev.msf_modules) > 2 else "")
            parts.append(
                f"<li><strong>Metasploit:</strong> {mods}{extra}</li>"
            )
        if ev.github_poc_urls:
            poc_links = ", ".join(
                f"<a href=\"{escape(u)}\">{escape(u)}</a>"
                for u in ev.github_poc_urls[:2]
            )
            extra = (f" (+{len(ev.github_poc_urls) - 2} more)"
                      if len(ev.github_poc_urls) > 2 else "")
            parts.append(
                f"<li><strong>GitHub PoC:</strong> {poc_links}{extra}</li>"
            )
    parts.append(
        f"<li><small>Source: <code>{escape(str(dep.declared_in))}"
        f"</code> · scope: {escape(dep.scope)} · "
        f"pin: {escape(dep.pin_style.value)}</small></li>"
    )
    parts.append("</ul></article>")
    return "".join(parts)


def _kinded_section(findings, *, header: str, kind_attr: str) -> str:
    """Render hygiene / supply-chain findings (single-line each)."""
    parts = [f"<section><h2>{escape(header)}</h2><ul class=\"kinded\">"]
    for f in findings:
        kind = getattr(f, kind_attr, "")
        dep = f.dependency
        detail = getattr(f, "detail", "")
        sup = "1" if getattr(f, "suppressed", False) else "0"
        haystack = (f"{dep.name} {dep.version or ''} "
                     f"{kind} {detail}").lower()
        parts.append(
            f"<li class=\"finding sev-{f.severity}\""
            f" data-severity=\"{f.severity}\""
            f" data-kev=\"0\""
            f" data-suppressed=\"{sup}\""
            f" data-ecosystem=\"{escape(dep.ecosystem)}\""
            f" data-search=\"{escape(haystack)}\">"
            f"<span class=\"sev sev-{f.severity}\">"
            f"{escape(_SEV_LABEL.get(f.severity, f.severity.title()))}"
            f"</span> "
            f"<code>{escape(kind)}</code> "
            f"<strong>{escape(dep.ecosystem)}:{escape(dep.name)}</strong> — "
            f"{escape(detail)}</li>"
        )
    parts.append("</ul></section>")
    return "".join(parts)


def _license_section(findings) -> str:
    parts = ["<section><h2>License findings</h2><ul class=\"kinded\">"]
    for f in findings:
        dep = f.dependency
        spdx = getattr(f, "spdx", None) or "(none)"
        kind = getattr(f, "kind", "")
        kind_label = {
            "license_denied": "Denied",
            "license_warned": "Warned",
            "license_unknown": "Unknown",
            "license_incompatible": "Incompatible",
        }.get(kind, kind or "?")
        sup = "1" if getattr(f, "suppressed", False) else "0"
        haystack = (f"{dep.name} {dep.version or ''} "
                     f"{kind_label} {spdx}").lower()
        parts.append(
            f"<li class=\"finding sev-{f.severity}\""
            f" data-severity=\"{f.severity}\""
            f" data-kev=\"0\""
            f" data-suppressed=\"{sup}\""
            f" data-ecosystem=\"{escape(dep.ecosystem)}\""
            f" data-search=\"{escape(haystack)}\">"
            f"<span class=\"sev sev-{f.severity}\">"
            f"{escape(_SEV_LABEL.get(f.severity, f.severity.title()))}"
            f"</span> <code>{escape(kind_label)}</code> "
            f"<strong>{escape(dep.ecosystem)}:{escape(dep.name)}</strong> "
            f"<code>{escape(spdx)}</code></li>"
        )
    parts.append("</ul></section>")
    return "".join(parts)


# ---------------------------------------------------------------------------
# Interactive filter bar (vanilla JS, no deps)
# ---------------------------------------------------------------------------


def _filter_bar(ecosystems: Sequence[str]) -> str:
    """Render the sticky filter bar. ``ecosystems`` populates the
    dropdown — only ecosystems present in the report appear,
    keeping the UI tight on single-ecosystem repos.

    The HTML emits a ``role="region"`` + ``aria-label`` so the
    bar is announced clearly by screen readers."""
    eco_options = "".join(
        f'<option value="{escape(e)}">{escape(e)}</option>'
        for e in ecosystems
    )
    return (
        '<section id="filters" class="filter-bar"'
        ' role="region" aria-label="Finding filters">'
        '<label>Min severity '
        '<select name="severity">'
        '<option value="">All</option>'
        '<option value="critical">Critical</option>'
        '<option value="high">High+</option>'
        '<option value="medium">Medium+</option>'
        '<option value="low">Low+</option>'
        '<option value="info">Info+</option>'
        '</select></label>'
        '<label><input type="checkbox" name="kev"> KEV only</label>'
        '<label><input type="checkbox" name="hidesup" checked>'
        ' Hide suppressed</label>'
        '<label>Ecosystem '
        '<select name="ecosystem">'
        '<option value="">All</option>'
        f'{eco_options}'
        '</select></label>'
        '<label>Search '
        '<input type="search" name="q" placeholder="name / CVE / summary">'
        '</label>'
        '<span id="filter-counter" class="filter-counter"></span>'
        '</section>'
    )


# ``data-*`` attributes on each finding card feed the filter
# logic. The script is intentionally vanilla JS with no
# dependencies — the report.html artefact must stay a
# single self-contained file (no CDN fetches, no module
# imports).
_FILTER_SCRIPT = """<script>
(function () {
  // ``none`` covers CVSS=0.0 advisories — pinned at rank 0 so the
  // "Info+" filter hides them and the "All" filter shows them.
  var ranks = {critical: 5, high: 4, medium: 3, low: 2, info: 1,
                none: 0};
  var bar = document.getElementById('filters');
  if (!bar) return;
  var counter = document.getElementById('filter-counter');
  var cards = document.querySelectorAll('article.finding, li.finding');

  function read(name) {
    var el = bar.querySelector('[name="' + name + '"]');
    if (!el) return '';
    if (el.type === 'checkbox') return el.checked;
    return el.value;
  }

  function applyFilters() {
    var sev = read('severity');
    var kev = read('kev');
    var hidesup = read('hidesup');
    var eco = read('ecosystem');
    var q = (read('q') || '').toLowerCase();
    var minRank = sev ? ranks[sev] : 0;
    var visible = 0;
    cards.forEach(function (c) {
      var r = ranks[c.dataset.severity] || 0;
      var show = r >= minRank;
      if (kev && c.dataset.kev !== '1') show = false;
      if (hidesup && c.dataset.suppressed === '1') show = false;
      if (eco && c.dataset.ecosystem !== eco) show = false;
      if (q && c.dataset.search.indexOf(q) === -1) show = false;
      c.style.display = show ? '' : 'none';
      if (show) visible++;
    });
    if (counter) {
      counter.textContent = visible + ' / ' + cards.length + ' visible';
    }
    // Hide whole sections whose findings are all filtered out so
    // the operator doesn't scroll past empty headings.
    document.querySelectorAll('section').forEach(function (s) {
      if (s.id === 'filters') return;
      var children = s.querySelectorAll('article.finding, li.finding');
      if (children.length === 0) return;  // summary section
      var anyVisible = false;
      children.forEach(function (c) {
        if (c.style.display !== 'none') anyVisible = true;
      });
      s.style.display = anyVisible ? '' : 'none';
    });
  }

  bar.querySelectorAll('input, select').forEach(function (el) {
    el.addEventListener('input', applyFilters);
    el.addEventListener('change', applyFilters);
  });
  applyFilters();
})();
</script>"""


# ---------------------------------------------------------------------------
# Embedded CSS
# ---------------------------------------------------------------------------

# Single source of truth for visual styling. Inlined into the
# <head> so the report is fully self-contained (no external CSS
# fetch). Adapts to the reader's OS dark/light preference via
# ``prefers-color-scheme``.
_CSS = """
:root { color-scheme: light dark; }
body {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  max-width: 64rem; margin: 1rem auto; padding: 0 1rem;
  line-height: 1.5;
}
h1 { font-size: 1.6rem; margin-bottom: 0.25rem; }
h1 code { font-size: 0.85em; font-weight: normal; }
.meta { color: #666; margin-top: 0; font-size: 0.9em; }
h2 {
  font-size: 1.2rem; margin-top: 2rem;
  border-bottom: 1px solid #e5e5e5; padding-bottom: 0.25rem;
}
h3 { font-size: 1rem; margin: 1rem 0 0.25rem; }
section { margin-bottom: 1.5rem; }
table.sev-table {
  border-collapse: collapse; margin: 0.5rem 0;
}
table.sev-table th, table.sev-table td {
  padding: 0.25rem 0.75rem; border: 1px solid #e5e5e5;
  text-align: left;
}
dl.counts { display: grid; grid-template-columns: max-content 1fr;
            gap: 0.25rem 1rem; margin: 0.5rem 0; }
dl.counts dt { font-weight: 600; color: #666; }
dl.counts dd { margin: 0; font-variant-numeric: tabular-nums; }
.sev {
  display: inline-block; padding: 0.1em 0.5em;
  border-radius: 0.25em; color: white; font-weight: 600;
  font-size: 0.85em;
}
.sev-critical { background: #7f1d1d; }
.sev-high     { background: #9a3412; }
.sev-medium   { background: #854d0e; }
.sev-low      { background: #1e40af; }
.sev-info     { background: #374151; }
/* CVSS rated 0.0 (rare; OSV occasionally ships ``severity=none``
   advisories for compatibility-flag CVEs). Same grey as info —
   triage-neutral. Without this rule, severity=none cards rendered
   as un-styled white-on-white text in dark mode. */
.sev-none     { background: #525252; }
article.finding {
  border-left: 3px solid #888; padding-left: 0.75rem;
  margin-bottom: 1rem;
}
article.finding.sev-critical { border-color: #7f1d1d; }
article.finding.sev-high     { border-color: #9a3412; }
article.finding.sev-medium   { border-color: #854d0e; }
article.finding ul { margin: 0; padding-left: 1.25rem; }
article.finding li { margin: 0.1rem 0; }
.badge {
  display: inline-block; padding: 0.05em 0.4em;
  border-radius: 0.25em; font-size: 0.8em; font-weight: 600;
  border: 1px solid currentColor; margin-right: 0.25rem;
}
.badge.kev { color: #b91c1c; border-color: #b91c1c; }
.badge.epss { color: #6b21a8; border-color: #6b21a8; }
.badge.cvss { color: #1f2937; border-color: #1f2937; }
ul.kinded { list-style: none; padding-left: 0; }
ul.kinded li { padding: 0.25rem 0; border-bottom: 1px solid #f0f0f0; }
code { background: rgba(127,127,127,0.1); padding: 0 0.2em;
       border-radius: 0.2em; font-size: 0.9em; }
small.suppressed { color: #888; font-style: italic; }
@media (prefers-color-scheme: dark) {
  body { background: #1a1a1a; color: #e5e5e5; }
  .meta { color: #aaa; }
  h2 { border-bottom-color: #444; }
  table.sev-table th, table.sev-table td { border-color: #444; }
  dl.counts dt { color: #aaa; }
  ul.kinded li { border-bottom-color: #2a2a2a; }
  .badge.cvss { color: #d4d4d4; border-color: #d4d4d4; }
  .filter-bar {
    background: #222; border-color: #444;
  }
  .filter-bar input, .filter-bar select {
    background: #1a1a1a; color: #e5e5e5; border-color: #555;
  }
  .filter-counter { color: #aaa; }
}

/* Sticky filter bar — stays in view as the operator scrolls
   through long reports so they can refine without scrolling
   back to the top. */
.filter-bar {
  position: sticky; top: 0;
  background: #fafafa; border: 1px solid #e5e5e5;
  padding: 0.5rem 0.75rem; border-radius: 4px;
  margin: 1rem 0;
  display: flex; flex-wrap: wrap; gap: 0.75rem 1.25rem;
  align-items: center;
  z-index: 10;
  font-size: 0.9em;
}
.filter-bar label { display: inline-flex; gap: 0.4rem;
  align-items: center; margin: 0; }
.filter-bar input[type="search"] { width: 16rem; max-width: 100%; }
.filter-bar input, .filter-bar select {
  padding: 0.15rem 0.4rem; border: 1px solid #ccc;
  border-radius: 3px; font-size: inherit;
}
.filter-counter { color: #666; margin-left: auto;
  font-variant-numeric: tabular-nums; }
"""


__all__ = ["render_html_report", "write_html_report"]
