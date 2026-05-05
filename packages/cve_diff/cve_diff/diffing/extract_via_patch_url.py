"""Third diff source: fetch the forge's raw ``<sha>.patch`` URL.

Non-git, non-API-JSON. Three forges expose a unified-diff endpoint:

  GitHub:  ``https://github.com/<slug>/commit/<sha>.patch``
  GitLab:  ``https://gitlab.com/<slug>/-/commit/<sha>.patch``
  cgit:    ``<base>/commit/?id=<sha>&format=patch``

This is the forge's own ``git format-patch`` output served as static
text — distinct from both the clone (git CLI) and the API JSON
(parsed-file + synthesized) paths. It can disagree with the API JSON
on whitespace, line endings, binary truncation, or path normalization,
so it adds real triangulation rather than just confidence.

Crucially, this is the **first second-source coverage for cgit**
(kernel.org). Before this module, cgit-hosted CVEs had only the clone
as a single source — the agreement signal was unavailable.

Best-effort: any failure (404, timeout, parse error) returns ``None``.
The auxiliary check must never abort the pipeline.
"""
from __future__ import annotations

import functools
import re

from core.http import HttpError
from core.http.urllib_backend import UrllibClient

from cve_diff.core.models import CommitSha, DiffBundle, FileChange, RepoRef
from cve_diff.core.path_classifier import is_test_path
from core.url_patterns import extract_github_slug
from cve_diff.diffing import shape_dynamic
from cve_diff.diffing.extract_via_gitlab_api import _gitlab_host_and_slug

_TIMEOUT_S = 10
_USER_AGENT = "cve-diff/0.1 (+https://github.com/cve-diff)"
_MAX_BYTES = 5_000_000  # 5MB cap on patch body


@functools.lru_cache(maxsize=1)
def _client() -> "EgressClient":
    """Allowlisted egress client (curated forge hosts only).

    Pre-2026-05-04 this returned a bare UrllibClient with no host
    allowlist. Combined with the substring-based forge selector that
    accepted any URL containing ``/cgit/`` or ``git.savannah``, an
    attacker-influenced CVE record could fetch from arbitrary HTTP
    servers — SSRF amplifier. Now we share the agent tool layer's
    allowlist (`_AGENT_FORGE_HOSTS`); any host not in it is refused
    at CONNECT.
    """
    from core.http.egress_backend import EgressClient
    from cve_diff.agent.tools import _AGENT_FORGE_HOSTS
    return EgressClient(allowed_hosts=_AGENT_FORGE_HOSTS, user_agent=_USER_AGENT)


def _patch_url_for(ref: RepoRef) -> str | None:
    """Map a ``RepoRef`` to its forge's raw ``.patch`` URL, or None.

    Order: GitHub → GitLab (gitlab.com or self-hosted) → cgit-style
    (anything containing ``/cgit/`` or with a kernel.org path layout).
    Unknown forges return None — the caller marks the third source as
    unavailable.
    """
    url = (ref.repository_url or "").strip()
    sha = (ref.fix_commit or "").strip()
    if not url or not sha:
        return None

    # GitHub
    slug = extract_github_slug(url)
    if slug:
        return f"https://github.com/{slug}/commit/{sha}.patch"

    # GitLab (gitlab.com + self-hosted). ``_gitlab_host_and_slug``
    # returns ``host`` with the protocol included (e.g. ``https://gitlab.com``).
    host, gl_slug = _gitlab_host_and_slug(url)
    if host and gl_slug:
        return f"{host}/{gl_slug}/-/commit/{sha}.patch"

    # cgit-style: kernel.org and similar. The URL pattern is
    # `<base>/commit/?id=<sha>&format=patch`. We strip a trailing `.git`
    # / trailing slash and append the cgit query.
    #
    # ``is_kernel_org_url`` is hostname-anchored so a ``kernel.org``
    # substring inside an attacker-supplied path can't match. The
    # ``/cgit/`` and ``git.savannah`` checks remain substring-based —
    # ``cgit`` is a path token (forge software, not a host) and
    # ``git.savannah.gnu.org`` shows up in two slightly different host
    # forms across NVD records, so a strict hostname check would miss
    # legitimate variants.
    from core.url_patterns import is_kernel_org_url
    low = url.lower()
    if is_kernel_org_url(url) or "/cgit/" in low or "git.savannah" in low:
        base = url.rstrip("/")
        if base.endswith(".git"):
            base = base[:-4]
        return f"{base}/commit/?id={sha}&format=patch"

    return None


# ``diff --git a/<before> b/<after>`` — captures the post-fix path.
_DIFF_GIT_RE = re.compile(r"^diff --git a/.+? b/(.+)$")
# ``@@ -A,B +C,D @@ context`` — used to count hunks per file.
_HUNK_RE = re.compile(r"^@@ ")


def _parse_unified_diff(text: str) -> list[tuple[str, int]]:
    """Walk a unified-diff body and return ``[(path, hunk_count), ...]``.

    Keys on the post-fix path (the ``b/`` side). Files with zero hunks
    are still recorded (a pure rename would have zero ``@@`` lines but
    is still a file change).
    """
    out: list[tuple[str, int]] = []
    current: str | None = None
    hunks = 0
    for raw_line in text.splitlines():
        m = _DIFF_GIT_RE.match(raw_line)
        if m:
            if current is not None:
                out.append((current, hunks))
            current = m.group(1).strip()
            hunks = 0
        elif _HUNK_RE.match(raw_line) and current is not None:
            hunks += 1
    if current is not None:
        out.append((current, hunks))
    return out


def extract_via_patch_url(cve_id: str, ref: RepoRef) -> DiffBundle | None:
    """Fetch the forge's ``.patch`` URL and return a ``DiffBundle``.

    Returns ``None`` for: unsupported forge, HTTP non-200, network
    failure, or empty/unparseable body. The caller (``extract_for_agreement``)
    treats absence as "third-source unavailable" — the verdict adapts.
    """
    url = _patch_url_for(ref)
    if url is None:
        return None
    try:
        resp = _client().request(
            "GET", url, timeout=_TIMEOUT_S, retries=0,
        )
    except HttpError:
        return None
    if resp.status != 200:
        return None
    # Cap on raw bytes (not codepoints). The previous `len(body) >
    # _MAX_BYTES` ran AFTER UTF-8 decode, so a 5M-codepoint string of
    # mostly-multibyte chars could be 15-20 MB of underlying bytes;
    # the in-memory body is also held in full before the cap. Cap
    # bytes-side first.
    raw = resp.body[:_MAX_BYTES]
    body = raw.decode("utf-8", errors="replace")
    if not body or not body.strip():
        return None

    parsed = _parse_unified_diff(body)
    if not parsed:
        return None
    file_names = [p for p, _ in parsed]
    files = tuple(
        FileChange(
            path=p,
            is_test=is_test_path(p),
            hunks_count=hc,
            before_source=None,
            after_source=None,
        )
        for p, hc in parsed
    )

    slug = extract_github_slug(ref.repository_url or "")

    def _no_languages_fetch(_slug: str):
        # Best-effort: the patch URL path may be running against a forge
        # that doesn't expose a languages endpoint. shape_dynamic falls
        # back to its offline classifier.
        return None

    shape = shape_dynamic.classify(
        file_names,
        slug=slug or "",
        fetch=_no_languages_fetch,
    )

    # ``commit_before`` would normally be the parent SHA, but a
    # ``.patch`` URL response carries the diff body (and the commit's
    # own SHA via the ``From <sha>`` header) without exposing the
    # parent. Pre-2026-05-02 this slot held ``<sha>^`` — git's
    # revspec for "parent of sha". That works for ``git diff
    # <sha>^..<sha>`` (the extractor doesn't re-run git diff for
    # patch-url-sourced bundles anyway — diff_text comes straight
    # from the patch body), but it breaks downstream display:
    # ``report/markdown.py``'s ``_commit_url(<sha>^)`` emits
    # ``https://forge/.../commit/<sha>^`` which 404s, and
    # ``report/osv_schema.py``'s ``diff_against`` field carries the
    # bogus revspec into the OSV record. Setting it equal to
    # ``commit_after`` keeps the ``CommitSha`` NewType contract
    # honest (it's an actual SHA) and signals "parent unknown" to
    # any consumer that compares the two.
    fix_sha = (ref.fix_commit or "").lower()
    return DiffBundle(
        cve_id=cve_id,
        repo_ref=ref,
        commit_before=CommitSha(fix_sha),
        commit_after=CommitSha(fix_sha),
        diff_text=body,
        files_changed=len(file_names),
        bytes_size=len(body.encode("utf-8")),
        shape=shape,
        files=files,
    )


