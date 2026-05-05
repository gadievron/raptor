"""
Markdown renderer for a `DiffBundle`. Human-readable counterpart to the
OSV JSON. Phase 1 keeps it tight: header, repo + commits + diff stats,
fenced-code diff body. Root-cause / variants sections will be appended
in later phases.
"""

from __future__ import annotations

from cve_diff.analysis.analyzer import RootCause
from cve_diff.core.models import DiffBundle

DIFF_BODY_LIMIT_BYTES = 256 * 1024


_DISCOVER_TOOLS: frozenset[str] = frozenset({
    "osv_raw", "osv_expand_aliases", "nvd_raw", "deterministic_hints",
    "gh_search_repos", "gh_search_commits", "gh_commit_detail",
    "gh_list_commits_by_path", "gh_compare", "git_ls_remote",
    "gitlab_commit", "cgit_fetch", "fetch_distro_advisory",
    "oracle_check", "check_diff_shape", "http_fetch",
})
_VERIFY_TOOLS: frozenset[str] = frozenset({
    "gh_commit_detail", "gitlab_commit", "cgit_fetch",
})

# Group tool names by intent so the per-tool flow reads as a high-level
# strategy ("Look up known data" / "Verify candidate" / etc.) rather
# than a raw 17-tool log. Adjacent same-intent calls collapse into one
# numbered step in the rendered output.
_TOOL_INTENT: dict[str, str] = {
    "deterministic_hints": "lookup",
    "osv_raw": "lookup",
    "osv_expand_aliases": "lookup",
    "nvd_raw": "lookup",
    "fetch_distro_advisory": "lookup",
    "gh_commit_detail": "verify",
    "cgit_fetch": "verify",
    "gitlab_commit": "verify",
    "gh_search_repos": "search",
    "gh_search_commits": "search",
    "gh_list_commits_by_path": "search",
    "gh_compare": "search",
    "git_ls_remote": "search",
    "http_fetch": "search",
    "check_diff_shape": "shape",
    "oracle_check": "oracle",
    "submit_result": "submit",
}

# Human-readable label per intent. The order of the dict is the order
# steps usually appear (read top to bottom for canonical strategy).
_INTENT_LABEL: dict[str, str] = {
    "lookup": "Look up known data",
    "search": "Search for candidates",
    "verify": "Verify candidate",
    "shape": "Check diff shape",
    "oracle": "Cross-check via oracle",
    "submit": "Submit result",
    "other": "Other",
}


def _summarise_args(name: str, args: dict) -> str:
    """One-line, human-friendly args summary used in the strategy steps."""
    if not isinstance(args, dict):
        return ""
    if name in ("gh_commit_detail", "cgit_fetch", "gitlab_commit", "check_diff_shape"):
        slug = args.get("slug", "")
        sha = (args.get("sha") or "")[:12]
        if slug and sha:
            return f"{slug} @ {sha}"
        return slug or sha or ""
    if name in ("gh_search_repos", "gh_search_commits"):
        q = args.get("query", "")
        return f'"{q[:50]}{"…" if len(q) > 50 else ""}"'
    if name == "gh_list_commits_by_path":
        return args.get("path", "")
    if name == "http_fetch":
        url = args.get("url", "")
        # Keep host + path tail for readability
        return url[:60] + ("…" if len(url) > 60 else "")
    if name == "git_ls_remote":
        return args.get("url", "")[:60]
    if name == "submit_result":
        outcome = args.get("outcome", "?")
        sha = (args.get("fix_commit") or "")[:12]
        return f"{outcome}" + (f" · {sha}" if sha else "")
    return ""


def _intent_steps(jsonl_lines: list[str]) -> list[dict]:
    """Walk the tool-call jsonl and collapse adjacent same-intent calls
    into "strategy steps". Each step is a dict with keys:
        intent     one of _INTENT_LABEL keys
        tools      list[(tool_name, summarised_args)]
        n          tool count in this step
    """
    import json as _json
    steps: list[dict] = []
    current: dict | None = None
    for line in jsonl_lines:
        try:
            d = _json.loads(line)
        except (ValueError, TypeError):
            continue
        name = d.get("tool", "?")
        args = d.get("args") or {}
        intent = _TOOL_INTENT.get(name, "other")
        summary = _summarise_args(name, args)
        if current and current["intent"] == intent:
            current["tools"].append((name, summary))
            current["n"] += 1
        else:
            current = {"intent": intent, "tools": [(name, summary)], "n": 1}
            steps.append(current)
    return steps


def _render_intent_step(step: dict) -> str:
    """Render one strategy step — bullet line under DISCOVER."""
    intent = step["intent"]
    label = _INTENT_LABEL.get(intent, "Other")
    tool_summaries: list[str] = []
    for name, summary in step["tools"]:
        if summary:
            tool_summaries.append(f"`{name}`({summary})")
        else:
            tool_summaries.append(f"`{name}`")
    return f"- **{label}** ({step['n']}× call{'s' if step['n'] != 1 else ''}): " + ", ".join(tool_summaries)


def render_flow(cve_id: str, jsonl_lines: list[str], *,
                ok: bool, error_class: str | None,
                stage_signals: dict | None = None,
                stage_status: dict | None = None) -> str:
    """Render a per-CVE pipeline trace.

    **All 5 stage headers ALWAYS render** — PASS or FAIL. This is a
    user-stated requirement (2026-05-01): on a FAIL the user wants to
    see WHERE in the pipeline things broke, not just "it broke."

    UX: 5 pipeline stages headlined with status + method picked.
    DISCOVER groups the agent's tool calls into intent-labelled
    strategy steps. Stages 2-5 are populated from ``stage_signals``
    when the pipeline reached them (PASS); FAIL paths show ✗ on the
    stage that broke and ``(not reached)`` on subsequent stages.

    ``stage_signals`` (optional dict): per-stage rich detail (PASS
    only). Keys: ``acquire`` / ``resolve`` / ``diff`` / ``render``.
    See callers in ``cli/main.py``.

    ``stage_status`` (optional dict): per-stage outcome regardless of
    PASS/FAIL. Keys: ``discover`` / ``acquire`` / ``resolve`` / ``diff``
    / ``render``. Each value is ``{"status": "ok"|"fail", "reason": str}``.
    Missing keys → ``(not reached)``. The renderer needs this on FAIL
    paths to draw stage 2-5 headers correctly.
    """
    out: list[str] = [f"# {cve_id} — pipeline trace", ""]
    if not jsonl_lines:
        out.append("_(no tool calls were captured)_")
        return "\n".join(out) + "\n"

    # Headline outcome
    out.append("## Outcome")
    if ok:
        out.append("")
        out.append("**✓ PASS**")
    else:
        out.append("")
        out.append(f"**✗ FAIL** · `{error_class or 'unknown'}` — see `{cve_id}.md` for the rationale.")
    out.append("")

    stage_status = stage_status or {}

    # ---- Stage 1: DISCOVER ----
    steps = _intent_steps(jsonl_lines)
    n_calls = sum(s["n"] for s in steps)
    # Status precedence: explicit stage_status > overall ok flag.
    discover_st = (stage_status.get("discover") or {}).get("status")
    if discover_st == "fail" or (discover_st is None and not ok):
        discover_glyph = "✗"
    else:
        discover_glyph = "✓"
    out.append(f"## Stage 1 — DISCOVER {discover_glyph}")
    out.append("")
    out.append(f"_Agent's strategy ({n_calls} tool call{'s' if n_calls != 1 else ''}):_")
    out.append("")
    for step in steps:
        out.append(_render_intent_step(step))
    out.append("")

    # ---- Stages 2-5: ALWAYS rendered ----
    # Status for each stage is derived from stage_status; on PASS, the
    # absence of a stage_status entry is treated as ✓ (the pipeline
    # reached and produced stage_signals — that's a successful run).
    # On FAIL, the absence is "(not reached)".

    def _stage_glyph(stage_key: str) -> str:
        """Pick ✓/✗/⊘ based on status, falling back to PASS/FAIL of the
        whole pipeline. ``⊘`` here is rendered textually as ``(not
        reached)`` in the body — the header still shows a marker for
        scannability."""
        st = (stage_status.get(stage_key) or {}).get("status")
        if st == "ok":
            return "✓"
        if st == "fail":
            return "✗"
        # No explicit status — infer from overall outcome + presence
        # of rich signals (means the stage produced data → reached).
        if ok and stage_signals and stage_key in stage_signals:
            return "✓"
        return "⊘"  # not reached

    # Stage 2: ACQUIRE
    g = _stage_glyph("acquire")
    out.append(f"## Stage 2 — ACQUIRE {g}")
    out.append("")
    if g == "⊘":
        out.append("_(not reached)_")
    elif g == "✗":
        reason = (stage_status.get("acquire") or {}).get("reason") or "?"
        out.append(f"**Failed:** {reason}")
    else:
        acq = (stage_signals or {}).get("acquire") or {}
        layer = acq.get("layer", "?")
        elapsed = acq.get("elapsed_s")
        elapsed_str = f", {elapsed}s" if elapsed is not None else ""
        out.append(f"**Method:** `{layer}`{elapsed_str}")
    out.append("")

    # Stage 3: RESOLVE
    g = _stage_glyph("resolve")
    out.append(f"## Stage 3 — RESOLVE {g}")
    out.append("")
    if g == "⊘":
        out.append("_(not reached)_")
    elif g == "✗":
        reason = (stage_status.get("resolve") or {}).get("reason") or "?"
        out.append(f"**Failed:** {reason}")
    else:
        res = (stage_signals or {}).get("resolve") or {}
        before = res.get("before", "?")
        after = res.get("after", "?")
        out.append(f"- **Before (fix^):** `{before}`")
        out.append(f"- **After (fix):**  `{after}`")
    out.append("")

    # Stage 4: DIFF
    g = _stage_glyph("diff")
    out.append(f"## Stage 4 — DIFF {g}")
    out.append("")
    if g == "⊘":
        out.append("_(not reached)_")
    elif g == "✗":
        reason = (stage_status.get("diff") or {}).get("reason") or "?"
        out.append(f"**Failed:** {reason}")
    else:
        df = (stage_signals or {}).get("diff") or {}
        out.extend(_render_stage4_sources(df))
    out.append("")

    # Stage 5: RENDER
    g = _stage_glyph("render")
    out.append(f"## Stage 5 — RENDER {g}")
    out.append("")
    if g == "⊘":
        out.append("_(not reached)_")
    elif g == "✗":
        reason = (stage_status.get("render") or {}).get("reason") or "?"
        out.append(f"**Failed:** {reason}")
    else:
        rd = (stage_signals or {}).get("render") or {}
        cons = rd.get("consensus_count")
        out.append("**Outputs:** OSV Schema 1.6.0, per-CVE Markdown, flow log")
        if cons is not None:
            out.append(f"**Pointer consensus:** {cons}/2 method(s) agreed (OSV refs + NVD Patch-tag)")
    out.append("")
    return "\n".join(out)


# Verdict glyphs for the Stage 4 agreement line. Same vocabulary as the
# per-CVE markdown table (`_render_extraction_agreement`) so the on-disk
# report and the trace use the same labels.
_VERDICT_GLYPHS = {
    "agree": "✓ agree",
    "partial": "⚠ partial",
    "disagree": "✗ disagree",
}


_METHOD_LABELS = {
    "clone": "Clone",
    "github_api": "GitHub API",
    "gitlab_api": "GitLab API",
    "patch_url": "Patch URL",
}


def _label_for(method: str) -> str:
    return _METHOD_LABELS.get(method, method)


def _ref_hint(method: str, slug: str | None, sha: str | None) -> str:
    """Replay-style endpoint hint for each method, so the user can
    re-run the same fetch by hand."""
    if method == "clone":
        return "`git diff fix^..fix`"
    if not slug or not sha:
        return f"`{method}`"
    if method == "github_api":
        return f"`/repos/{slug}/commits/{sha}`"
    if method == "gitlab_api":
        return f"`/projects/{slug}/repository/commits/{sha}`"
    if method == "patch_url":
        # Forge-aware hint: GitHub uses `<slug>/commit/<sha>.patch`,
        # cgit uses the `?id=<sha>&format=patch` query.
        from core.url_patterns import is_kernel_org_url
        s = (slug or "").lower()
        # Hostname-anchored ``kernel.org`` check (closes the
        # incomplete-substring CodeQL footgun); ``cgit`` stays as a
        # path-token substring since it's forge software, not a host.
        if is_kernel_org_url(slug or "") or "cgit" in s:
            return f"`{slug}/commit/?id={sha}&format=patch`"
        return f"`{slug}/commit/{sha}.patch`"
    return f"`{slug} @ {sha}`"


def _render_stage4_sources(df: dict) -> list[str]:
    """Render Stage 4's per-source breakdown.

    Iterates over ``agreement.sources`` (N entries) plus a verdict line.
    Always prints the clone row. When the agreement dict is absent (no
    second source available), shows clone + a single ``skipped`` row.

    User's primary success metric: at a glance, see how many independent
    extractors looked at the same commit and whether they agreed.
    """
    shape = df.get("shape", "?")
    nfiles_clone = df.get("files_changed", 0)
    nbytes_clone = df.get("diff_bytes", 0)
    agreement = df.get("extraction_agreement")
    slug = df.get("slug")
    sha = df.get("sha")

    rows: list[str] = ["**Sources:**", ""]

    # No second source at all → the historical "skipped" path.
    if not agreement:
        rows.append(
            f"- **Clone** (`git diff fix^..fix`): "
            f"{nfiles_clone} file{'s' if nfiles_clone != 1 else ''}, "
            f"{nbytes_clone:,} bytes — shape `{shape}`"
        )
        rows.append(f"- **API**: skipped ({_single_source_reason(slug)})")
        rows.append("")
        rows.append("**Verdict:** single source (cannot cross-check)")
        return rows

    # N-source path — render every source from agreement["sources"].
    sources: list[dict] = list(agreement.get("sources") or [])
    for src in sources:
        name = src.get("name") or "?"
        files = src.get("files") or 0
        nbytes = src.get("bytes") or 0
        label = _label_for(name)
        ref = _ref_hint(name, slug, sha)
        suffix = f" — shape `{shape}`" if name == "clone" else ""
        rows.append(
            f"- **{label}** ({ref}): "
            f"{files} file{'s' if files != 1 else ''}, "
            f"{nbytes:,} bytes{suffix}"
        )

    # The JSON-API path is unavailable on cgit forges. Surface that
    # explicitly so a user reading "2 sources" knows it's because the
    # forge has no JSON API, not because we forgot to call it.
    src_names = {s.get("name") for s in sources}
    if "patch_url" in src_names and "github_api" not in src_names \
            and "gitlab_api" not in src_names:
        rows.append(f"- **API**: skipped ({_single_source_reason(slug)})")

    rows.append("")
    rows.append(_render_verdict_line(agreement))
    return rows


def _render_verdict_line(agreement: dict) -> str:
    """Build the Stage 4 ``Verdict:`` line for an N-source agreement."""
    verdict = agreement.get("verdict") or "?"
    sources = agreement.get("sources") or []
    n = len(sources)
    pairwise = agreement.get("pairwise") or {}
    outliers = agreement.get("outliers") or []

    if verdict == "agree":
        return f"**Verdict:** ✓ {n}/{n} agree — all sources match"
    if verdict == "majority_agree":
        # 2/3 form: name the outlier(s) so the user knows where to look.
        outlier_names = ", ".join(_label_for(o) for o in outliers) or "?"
        return (
            f"**Verdict:** ⚠ {n - len(outliers)}/{n} agree — "
            f"{outlier_names} differs"
        )
    if verdict == "partial":
        # Mixed — fall back to listing pairwise verdicts.
        return f"**Verdict:** ⚠ partial — pairwise: {pairwise}"
    if verdict == "disagree":
        return f"**Verdict:** ✗ disagree — no two sources match"
    # 2-source fall-through (raw `agree`/`partial`/`disagree` from
    # the pair check)
    glyph = _VERDICT_GLYPHS.get(verdict, verdict)
    return f"**Verdict:** {glyph}"


def _single_source_reason(slug: str | None) -> str:
    """Human-readable reason for why no API extractor ran.

    The forge dispatcher in ``extract_via_gitlab_api.extract_for_agreement``
    routes by URL host. Anything not matching GitHub/GitLab returns None.
    We pick a label from the slug; if it's empty, we just say
    ``no second extractor for this forge``.
    """
    if not slug:
        return "no second extractor available"
    from core.url_patterns import is_kernel_org_url
    s = slug.lower()
    # Hostname-anchored ``kernel.org`` check (closes the
    # incomplete-substring CodeQL footgun); ``cgit`` /
    # ``googlesource`` stay as path-token substrings — both are
    # forge-software identifiers, not hostnames.
    if is_kernel_org_url(slug) or "cgit" in s:
        return "cgit forge — no second extractor available"
    if "googlesource" in s:
        return "googlesource forge — no second extractor available"
    return "no second extractor for this forge"


def render_failure(cve_id: str, error_class: str, error_text: str) -> str:
    """Render a per-CVE markdown for a CVE that did NOT produce a fix
    (any non-PASS outcome: UnsupportedSource / no_evidence / budget_*
    / AnalysisError / repeated_tool_call / etc.).

    The agent's rationale (when present) lives inside ``error_text``
    after the surrender-reason marker. We strip the wrapping prefix
    to make the rationale the report's headline content. Helps users
    understand WHY a CVE was refused without diving into ``summary.json``.
    """
    rationale = _strip_surrender_prefix(error_text)
    classification = _humanize_class(error_class)
    return (
        f"# {cve_id}\n\n"
        f"**Outcome:** {classification}\n\n"
        f"**Class:** `{error_class}`\n\n"
        f"## Why no fix was extracted\n\n"
        f"{rationale}\n"
    )


def _strip_surrender_prefix(error_text: str) -> str:
    """Remove ``DiscoveryError: <CVE>: agent surrendered (<reason>):``
    or ``UnsupportedSource: <CVE>:`` boilerplate so the rationale
    reads as the headline. Best-effort; falls back to the raw text."""
    s = (error_text or "").strip()
    # DiscoveryError surrender form
    marker = "agent surrendered ("
    if marker in s:
        try:
            after = s.split("):", 1)[1].strip()
            if after:
                return after
        except IndexError:
            pass
    # Typed exception with CVE-id prefix: "ClassName: CVE-X: rest"
    parts = s.split(":", 2)
    if len(parts) == 3 and parts[1].strip().startswith("CVE-"):
        return parts[2].strip()
    return s or "(no rationale recorded)"


def _humanize_class(error_class: str) -> str:
    return {
        "UnsupportedSource": "Out of scope (closed-source vendor)",
        "no_evidence": "No public commit reference",
        "budget_cost_usd": "Budget cap reached",
        "budget_iterations": "Iteration cap reached",
        "budget_tokens": "Token cap reached",
        "budget_s": "Wall-clock cap reached",
        "AnalysisError": "Diff invariant rejected the agent's pick",
        "AcquisitionError": "Repository / commit unavailable",
        "DiscoveryError": "Discovery failed",
        "repeated_tool_call": "Agent repeated the same tool call",
        "sha_not_found_in_repo": "Submitted SHA not on the named repo",
        "submit_unverified_sha": "Agent submitted a SHA without verifying it via gh_commit_detail",
        "PerCveTimeout": "Per-CVE wall-clock timeout",
        "llm_error": "Anthropic API failure after retries",
    }.get(error_class, error_class)


def _commit_url(repository_url: str, sha: str) -> str:
    base = repository_url.removesuffix(".git").rstrip("/")
    return f"{base}/commit/{sha}"


def _md_safe(s: str) -> str:
    """Escape characters that break markdown link/inline-code rendering.

    `(`/`)` close link targets; backticks close inline-code; angle
    brackets are interpreted as autolinks. Renderer-supplied URLs and
    repo names should pass through this before landing in `[txt](url)`
    or `` `txt` `` constructs.
    """
    return (
        str(s)
        .replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("(", "%28")
        .replace(")", "%29")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _neutralize_diff_fence(diff_text: str) -> str:
    """Insert zero-width space inside fence-closing backtick runs.

    A diff that contains ```` ``` ```` somewhere closes the surrounding
    ```` ```diff ```` block early and turns the rest of the diff into
    raw markdown — link/image injection from upstream commit content.
    Inserting U+200B between any three consecutive backticks defangs the
    fence without changing the visible characters in monospace render.
    """
    return diff_text.replace("```", "`​`​`")


def render(bundle: DiffBundle, root_cause: RootCause | None = None) -> str:
    repo = bundle.repo_ref.repository_url
    fix_url = _md_safe(_commit_url(repo, bundle.commit_after))
    intro_url = _md_safe(_commit_url(repo, bundle.commit_before))
    repo_safe = _md_safe(repo)

    diff_body = bundle.diff_text
    truncated_note = ""
    if len(diff_body) > DIFF_BODY_LIMIT_BYTES:
        diff_body = diff_body[:DIFF_BODY_LIMIT_BYTES]
        truncated_note = (
            f"\n\n_…diff truncated at {DIFF_BODY_LIMIT_BYTES} bytes "
            f"(full size {bundle.bytes_size} bytes)._"
        )

    rc_block = _render_root_cause(root_cause) if root_cause else ""

    shape_warning = ""
    if bundle.shape != "source":
        shape_warning = (
            f"\n> **Diff shape: `{bundle.shape}`.** The changed files are "
            f"release notes / packaging metadata only. This repo is likely a "
            f"downstream mirror rather than the upstream fix source.\n"
        )

    files_block = _render_files(bundle)
    consensus_block = _render_consensus(bundle)
    extraction_block = _render_extraction_agreement(bundle)

    return (
        f"# {bundle.cve_id}\n\n"
        f"**Repository:** {repo_safe}\n\n"
        f"**Introduced:** [`{bundle.commit_before}`]({intro_url})\n\n"
        f"**Fixed:** [`{bundle.commit_after}`]({fix_url})\n\n"
        f"**Files changed:** {bundle.files_changed}  \n"
        f"**Diff size:** {bundle.bytes_size:,} bytes  \n"
        f"**Canonical score:** {bundle.repo_ref.canonical_score}\n"
        f"{shape_warning}\n"
        f"{extraction_block}"
        f"{consensus_block}"
        f"{rc_block}"
        f"{files_block}"
        f"## Diff\n\n"
        f"```diff\n"
        f"{_neutralize_diff_fence(diff_body)}\n"
        f"```"
        f"{truncated_note}\n"
    )


def _render_extraction_agreement(bundle: DiffBundle) -> str:
    """Render the N-source extraction-content cross-check block.

    The schema changed in 2026 to ``{verdict, sources: [...], pairwise,
    outliers}``. Iterate ``sources`` (one row per extractor) instead of
    the old hard-coded clone-vs-API two-row layout (which read keys
    that no longer exist and silently rendered "?" / 0 every time).
    """
    a = bundle.extraction_agreement
    if not a:
        return ""
    verdict = a.get("verdict", "")
    icon = {
        "agree": "✓",
        "majority_agree": "≈",
        "partial": "≈",
        "disagree": "✗",
        "single_source": "—",
    }.get(verdict, "?")
    sources = a.get("sources") or []
    if not sources:
        return ""
    rows = [
        "## Extraction sources\n",
        "| Method | Files | Bytes |",
        "|---|---:|---:|",
    ]
    for s in sources:
        name = s.get("name", "?")
        files = s.get("files", "?")
        bytes_ = s.get("bytes", 0)
        rows.append(f"| {name} | {files} | {bytes_:,} |")
    extras = []
    pw = a.get("pairwise") or {}
    if pw:
        pw_text = ", ".join(f"`{k}`={v}" for k, v in pw.items())
        extras.append(f"Pairwise: {pw_text}.")
    outliers = a.get("outliers") or []
    if outliers:
        extras.append(f"Outlier sources: {', '.join(outliers)}.")
    rows.append("")
    rows.append(f"**Agreement:** {icon} `{verdict}`. " + " ".join(extras))
    rows.append("")
    return "\n".join(rows) + "\n"


def _render_consensus(bundle: DiffBundle) -> str:
    """Render the 2-method pointer-consensus table when present."""
    c = bundle.consensus
    if not c:
        return ""
    lines = ["## Consensus from 2 methods\n"]
    lines.append("| Method | Found | Slug / SHA | Note |")
    lines.append("|---|:-:|---|---|")
    for m in c.get("methods") or []:
        if m.get("found"):
            lines.append(
                f"| {m['name']} | ✓ | `{m['slug']}/{m['sha'][:12]}` | "
                f"{(m.get('detail') or '')[:80]} |"
            )
        else:
            lines.append(
                f"| {m['name']} | — | — | {(m.get('detail') or '')[:80]} |"
            )
    lines.append("")
    n_agree = c.get("agreement_count", 0)
    if n_agree >= 2:
        lines.append(
            f"**Both methods agree on "
            f"`{c.get('consensus_slug', '')}/{c.get('consensus_sha', '')[:12]}`."
            f"** Pipeline picked: "
            f"`{bundle.repo_ref.repository_url}` @ `{bundle.commit_after[:12]}`. "
            + ("✓ matches consensus." if _matches(c, bundle) else "⚠ differs from consensus.")
        )
    elif (c.get("attempted_count", 0) == 0):
        lines.append("**No method found a fix-commit pointer for this CVE** — "
                     "the agent's pick was not externally attested. Manual review recommended.")
    else:
        lines.append(f"**No consensus** — {c.get('attempted_count', 0)} of 2 method(s) "
                     f"found a pointer; the other did not.")
    lines.append("")
    return "\n".join(lines) + "\n"


def _matches(c: dict, bundle: DiffBundle) -> bool:
    cs = (c.get("consensus_slug") or "").lower()
    chs = (c.get("consensus_sha") or "").lower()[:12]
    if not cs or not chs:
        return False
    # Pipeline's chosen slug is in repo_ref.repository_url (as github URL).
    repo = bundle.repo_ref.repository_url.lower()
    if cs not in repo:
        return False
    return bundle.commit_after.lower().startswith(chs)


def _render_files(bundle: DiffBundle) -> str:
    """One-line summary per changed file + a test/production split."""
    if not bundle.files:
        return ""
    n_test = sum(1 for f in bundle.files if f.is_test)
    n_prod = len(bundle.files) - n_test
    lines = [f"## Files ({n_prod} production / {n_test} test)\n"]
    for f in bundle.files:
        badge = "test" if f.is_test else "src"
        lines.append(f"- `{f.path}` ({f.hunks_count} hunk{'' if f.hunks_count == 1 else 's'}) — {badge}")
    lines.append("")
    return "\n".join(lines) + "\n"


def _render_root_cause(rc: RootCause) -> str:
    bullets = "\n".join(f"- {step}" for step in rc.why_chain) or "- _(none)_"
    funcs = ", ".join(f"`{f}`" for f in rc.affected_functions) or "_(none listed)_"
    return (
        f"## Root cause\n\n"
        f"**CWE:** {rc.cwe_id} — {rc.vulnerability_type}  \n"
        f"**Confidence:** {rc.confidence:.2f}  \n"
        f"**Model:** {rc.model_id}\n\n"
        f"{rc.summary}\n\n"
        f"**Why chain:**\n{bullets}\n\n"
        f"**Affected functions:** {funcs}\n\n"
    )
