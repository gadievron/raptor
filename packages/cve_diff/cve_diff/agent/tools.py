"""
Tool surface exposed to the agentic-first discover loop.

Each tool is a small, self-contained function returning a string. Errors
become JSON-in-string so the loop never has to handle exceptions from
tool dispatch.

Design notes:
- No scorer, no gating. The agent sees raw data and decides.
- GitHub calls go through ``cve_diff.infra.github_client`` to share the
  5000 req/h token bucket with the rest of the pipeline.
- OSV + NVD calls are direct (OSV has no shared cache; NVD reuses the
  disk-cached ``NvdDiscoverer._get_payload`` to avoid 429 storms under
  ``ProcessPoolExecutor`` workers).
- Every outbound HTTP call has a timeout and a response-size cap.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable

import requests

from cve_diff.discovery.nvd import NvdDiscoverer
from cve_diff.infra import github_client

_TIMEOUT_S = 10.0
_MAX_BYTES = 32 * 1024
_USER_AGENT = "cve-diff-agent/0.1"
_OSV_BASE = "https://api.osv.dev/v1"
_GH_API = "https://api.github.com"
# GitHub retry budget: 3 attempts on 429 / 5xx, 1s base exponential
# backoff. 4xx other than 429 fail fast (likely client-side bug).
# Mirrors the NVD pattern at cve_diff/discovery/nvd.py:137-171.
_GH_RETRY_MAX = 3
_GH_RETRY_BASE_S = 1.0
# Re-export under the historical underscore-prefixed names so existing
# call sites (including out-of-tree oracle/) keep working. Canonical
# definitions live in cve_diff.core.url_re.
from cve_diff.core.url_re import (  # noqa: E402
    GITHUB_COMMIT_URL_RE as _GITHUB_COMMIT_URL_RE,
    KERNEL_SHA_URL_RE as _KERNEL_SHA_URL_RE,
    LINUX_UPSTREAM_SLUG as _LINUX_UPSTREAM_SLUG,
)

_nvd = NvdDiscoverer()


@dataclass(frozen=True, slots=True)
class Tool:
    """A single agent-callable tool. ``impl`` returns a string."""
    name: str
    description: str
    parameters: dict[str, Any]
    impl: Callable[..., str]

    def anthropic_schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters,
        }


def _err(msg: str) -> str:
    return json.dumps({"error": msg[:300]})


def _gh_get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any] | list | None:
    if not github_client._bucket().try_acquire():
        return None
    delay = _GH_RETRY_BASE_S
    for attempt in range(_GH_RETRY_MAX + 1):
        try:
            resp = requests.get(
                f"{_GH_API}{path}",
                params=params or {},
                headers=github_client._headers(),
                timeout=_TIMEOUT_S,
            )
        except requests.RequestException:
            return None
        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError:
                return None
        # 429: rate-limited. Respect Retry-After when GitHub provides it.
        if resp.status_code == 429 and attempt < _GH_RETRY_MAX:
            retry_after = resp.headers.get("Retry-After", "")
            try:
                wait_s = max(float(retry_after), delay) if retry_after else delay
            except ValueError:
                wait_s = delay
            time.sleep(wait_s)
            delay *= 2
            continue
        # 5xx: transient server error.
        if 500 <= resp.status_code < 600 and attempt < _GH_RETRY_MAX:
            time.sleep(delay)
            delay *= 2
            continue
        return None
    return None


# ---------------------------------------------------------------- OSV + NVD

def _osv_raw_impl(cve_id: str) -> str:
    if not cve_id:
        return _err("cve_id required")
    try:
        resp = requests.get(f"{_OSV_BASE}/vulns/{cve_id}", timeout=_TIMEOUT_S)
    except requests.RequestException as exc:
        return _err(f"network: {exc}")
    if resp.status_code == 404:
        return json.dumps({"not_found": True, "cve_id": cve_id})
    if resp.status_code != 200:
        return _err(f"http {resp.status_code}")
    try:
        return json.dumps(resp.json())[:_MAX_BYTES]
    except ValueError:
        return _err("non-json")


def _nvd_raw_impl(cve_id: str) -> str:
    if not cve_id:
        return _err("cve_id required")
    payload = _nvd.get_payload(cve_id)
    if payload is None:
        return json.dumps({"not_found": True, "cve_id": cve_id})
    return json.dumps(payload)[:_MAX_BYTES]


def _osv_expand_aliases_impl(identifier: str) -> str:
    """Follow OSV aliases. One hop — returns a list of {id, source} the agent
    can then fetch via ``osv_raw``. Useful for CVE↔GHSA/DSA/USN bridging."""
    if not identifier:
        return _err("identifier required")
    try:
        resp = requests.get(f"{_OSV_BASE}/vulns/{identifier}", timeout=_TIMEOUT_S)
    except requests.RequestException as exc:
        return _err(f"network: {exc}")
    if resp.status_code != 200:
        return json.dumps({"aliases": []})
    try:
        data = resp.json()
    except ValueError:
        return _err("non-json")
    aliases = list(data.get("aliases") or [])
    return json.dumps({"aliases": aliases, "primary_id": data.get("id")})


def _deterministic_hints_impl(cve_id: str) -> str:
    """Thin OSV+NVD extractor. Returns github slug + commit SHA candidates
    parsed from references, with provenance. No scoring — the agent decides."""
    if not cve_id:
        return _err("cve_id required")
    hints: list[dict[str, str]] = []
    # OSV
    try:
        resp = requests.get(f"{_OSV_BASE}/vulns/{cve_id}", timeout=_TIMEOUT_S)
        if resp.status_code == 200:
            data = resp.json()
            for ref in data.get("references") or []:
                url = ref.get("url") or ""
                m = _GITHUB_COMMIT_URL_RE.search(url)
                if m:
                    hints.append({"slug": m.group(1), "sha": m.group(2), "source": "osv_reference"})
                    continue
                km = _KERNEL_SHA_URL_RE.search(url)
                if km:
                    hints.append({"slug": _LINUX_UPSTREAM_SLUG, "sha": km.group(1), "source": "osv_kernel_shortlink"})
            for aff in data.get("affected") or []:
                for rng in aff.get("ranges") or []:
                    if (rng.get("type") or "").upper() != "GIT":
                        continue
                    repo = rng.get("repo") or ""
                    repo_slug = ""
                    m = re.match(r"https?://github\.com/([^/]+/[^/.\s]+)", repo)
                    if m:
                        repo_slug = m.group(1)
                    for ev in rng.get("events") or []:
                        sha = ev.get("fixed") or ""
                        if sha and repo_slug:
                            hints.append({"slug": repo_slug, "sha": sha, "source": "osv_affected_fixed"})
    except requests.RequestException:
        pass
    # NVD
    nvd_payload = _nvd.get_payload(cve_id)
    if nvd_payload:
        for vuln in nvd_payload.get("vulnerabilities") or []:
            cve = vuln.get("cve") or {}
            for ref in cve.get("references") or []:
                url = ref.get("url") or ""
                m = _GITHUB_COMMIT_URL_RE.search(url)
                if m:
                    hints.append({"slug": m.group(1), "sha": m.group(2), "source": "nvd_reference"})
                    continue
                km = _KERNEL_SHA_URL_RE.search(url)
                if km:
                    hints.append({"slug": _LINUX_UPSTREAM_SLUG, "sha": km.group(1), "source": "nvd_kernel_shortlink"})
    # De-dupe on (slug, sha) preserving first-seen
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, str]] = []
    for h in hints:
        key = (h["slug"].lower(), h["sha"].lower())
        if key not in seen:
            seen.add(key)
            unique.append(h)
    return json.dumps({"hints": unique[:20]})


# ---------------------------------------------------------------- GitHub search / commits

def _gh_search_impl(kind: str, query: str) -> str:
    if not query or not query.strip():
        return _err("query required")
    data = _gh_get(f"/search/{kind}", {"q": query[:256], "per_page": 20})
    if data is None:
        return _err("rate_limited or http error")
    items = (data.get("items") or []) if isinstance(data, dict) else []
    slim: list[dict[str, Any]] = []
    for it in items[:20]:
        if kind == "repositories":
            slim.append({
                "slug": it.get("full_name", ""),
                "description": (it.get("description") or "")[:200],
                "stars": it.get("stargazers_count", 0),
                "language": it.get("language") or "",
                "archived": it.get("archived", False),
                "created_at": it.get("created_at", ""),
            })
        else:  # commits
            repo = (it.get("repository") or {}).get("full_name", "")
            commit = it.get("commit") or {}
            msg = (commit.get("message") or "")[:200]
            slim.append({
                "slug": repo,
                "sha": it.get("sha", ""),
                "message": msg,
            })
    return json.dumps({"items": slim})


def _gh_search_repos_impl(query: str) -> str:
    return _gh_search_impl("repositories", query)


def _gh_search_commits_impl(query: str) -> str:
    return _gh_search_impl("commits", query)


def _gh_commit_detail_impl(slug: str, sha: str) -> str:
    if not slug or not sha:
        return _err("slug and sha required")
    data = github_client.get_commit(slug, sha)
    if data is None:
        return _err("not found / rate limited")
    commit = data.get("commit") or {}
    files = github_client.get_commit_files(slug, sha) or []
    return json.dumps({
        "slug": slug,
        "sha": sha,
        "message": (commit.get("message") or "")[:1000],
        "files": files[:20],
        "files_total": len(files),
        "parents": [p.get("sha", "") for p in (data.get("parents") or []) if isinstance(p, dict)],
    })


def _gh_list_commits_by_path_impl(slug: str, path: str, since: str = "", until: str = "") -> str:
    if not slug or not path:
        return _err("slug and path required")
    params: dict[str, Any] = {"path": path, "per_page": 20}
    if since:
        params["since"] = since
    if until:
        params["until"] = until
    data = _gh_get(f"/repos/{slug}/commits", params)
    if data is None or not isinstance(data, list):
        return _err("rate_limited or http error")
    commits = [
        {
            "sha": c.get("sha", ""),
            "message": ((c.get("commit") or {}).get("message") or "")[:200],
            "date": (((c.get("commit") or {}).get("committer") or {})).get("date", ""),
        }
        for c in data[:20]
    ]
    return json.dumps({"commits": commits})


def _gh_compare_impl(slug: str, base: str, head: str) -> str:
    if not slug or not base or not head:
        return _err("slug, base, head required")
    data = _gh_get(f"/repos/{slug}/compare/{base}...{head}")
    if data is None or not isinstance(data, dict):
        return _err("rate_limited or http error")
    files = [f.get("filename", "") for f in (data.get("files") or [])][:20]
    return json.dumps({
        "status": data.get("status", ""),
        "ahead_by": data.get("ahead_by", 0),
        "behind_by": data.get("behind_by", 0),
        "files": files,
    })


# ---------------------------------------------------------------- Non-GitHub forges

def _git_ls_remote_impl(url: str) -> str:
    if not url or not re.match(r"^https?://", url):
        return _err("http(s) url required")
    try:
        proc = subprocess.run(
            ["git", "ls-remote", "--heads", "--tags", url],
            capture_output=True, text=True, timeout=20,
        )
    except subprocess.TimeoutExpired:
        return _err("timeout")
    except OSError as exc:
        return _err(f"git: {exc}")
    if proc.returncode != 0:
        return _err(f"git ls-remote failed: {proc.stderr.strip()[:200]}")
    refs = [line.split("\t") for line in proc.stdout.strip().splitlines() if "\t" in line][:50]
    return json.dumps({"refs": [{"sha": r[0], "ref": r[1]} for r in refs]})


def _gitlab_commit_impl(host: str, slug: str, sha: str) -> str:
    if not host or not slug or not sha:
        return _err("host, slug, sha required")
    host = host.rstrip("/")
    project = requests.utils.quote(slug, safe="")
    url = f"{host}/api/v4/projects/{project}/repository/commits/{sha}"
    try:
        resp = requests.get(url, timeout=_TIMEOUT_S, headers={"User-Agent": _USER_AGENT})
    except requests.RequestException as exc:
        return _err(f"network: {exc}")
    if resp.status_code != 200:
        return _err(f"http {resp.status_code}")
    try:
        data = resp.json()
    except ValueError:
        return _err("non-json")
    return json.dumps({
        "id": data.get("id", ""),
        "short_id": data.get("short_id", ""),
        "title": (data.get("title") or "")[:200],
        "message": (data.get("message") or "")[:1000],
        "parent_ids": data.get("parent_ids") or [],
        "created_at": data.get("created_at", ""),
    })


def _cgit_fetch_impl(host: str, slug: str, sha: str) -> str:
    if not host or not slug or not sha:
        return _err("host, slug, sha required")
    host = host.rstrip("/")
    url = f"{host}/{slug}/commit/?id={sha}"
    try:
        resp = requests.get(url, timeout=_TIMEOUT_S, headers={"User-Agent": _USER_AGENT})
    except requests.RequestException as exc:
        return _err(f"network: {exc}")
    if resp.status_code != 200:
        return _err(f"http {resp.status_code}")
    return json.dumps({"url": url, "body": resp.text[:_MAX_BYTES]})


_distro = None


def _fetch_distro_advisory_impl(cve_id: str = "") -> str:
    """Fetch Debian/Ubuntu/Red Hat security-tracker records in parallel.

    Returns per-distro status + references plus extracted ``(slug, sha)``
    candidates from any GitHub or kernel.org URLs in those references.
    """
    if not cve_id:
        return _err("cve_id required")
    global _distro
    if _distro is None:
        from cve_diff.discovery.distro_cache import DistroFetcher
        _distro = DistroFetcher()
    results = _distro.fetch_all(cve_id)
    candidates: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for distro_name, data in results.items():
        if "error" in data:
            continue
        for url in data.get("references") or []:
            m = _GITHUB_COMMIT_URL_RE.search(url or "")
            if m:
                slug, sha = m.group(1).lower(), m.group(2).lower()
                if (slug, sha) not in seen:
                    seen.add((slug, sha))
                    candidates.append({"slug": slug, "sha": sha, "distro": distro_name, "via": url})
                continue
            km = _KERNEL_SHA_URL_RE.search(url or "")
            if km:
                sha = km.group(1).lower()
                slug = _LINUX_UPSTREAM_SLUG.lower()
                if (slug, sha) not in seen:
                    seen.add((slug, sha))
                    candidates.append({"slug": slug, "sha": sha, "distro": distro_name, "via": url})
    return json.dumps({"candidates": candidates, "distro_status": results})[:_MAX_BYTES * 8]


def _oracle_check_impl(cve_id: str = "", slug: str = "", sha: str = "") -> str:
    """Cross-check a candidate ``(slug, sha)`` against OSV/NVD/GHSA aliases.

    Wraps ``tools/oracle/cross_check._verify_one``: tries OSV first
    (with GHSA alias-following), falls back to NVD on ORPHAN. Returns
    the structured verdict the agent can use to confirm or revise its
    pick before submitting.

    Verdict semantics:
      * ``match_exact`` / ``match_range`` / ``mirror_different_slug`` —
        candidate is correct; safe to submit.
      * ``dispute`` — oracle has the same slug but a different sha;
        consider switching to one of ``expected_shas``.
      * ``likely_hallucination`` — oracle has commit data but our
        ``(slug, sha)`` is not among them; switch to one of
        ``expected_slugs`` / ``expected_shas`` (typical: project-mirror
        or project-absorption mismatch).
      * ``orphan`` — oracle has no data; advisory only, not a
        prescription to refuse. Submit if ``gh_commit_detail`` confirms.
    """
    if not cve_id or not slug or not sha:
        return _err("cve_id, slug, sha all required")
    try:
        from tools.oracle.cross_check import _verify_one
    except ImportError as exc:
        return _err(f"oracle unavailable: {exc}")
    try:
        verdict = _verify_one(cve_id, slug, sha)
    except Exception as exc:  # noqa: BLE001
        return _err(f"{type(exc).__name__}: {exc}"[:200])
    return json.dumps(verdict.to_dict())


def _check_diff_shape_impl(slug: str, sha: str) -> str:
    """Predict the shape (source / packaging_only / notes_only) of a
    candidate's diff *before* submitting.

    Reuses ``shape_dynamic.classify`` — the same classifier the pipeline
    runs post-extraction to reject non-source picks via ``AnalysisError``.
    Letting the agent self-check pre-submit avoids wasting the bench on
    invariant-rejected picks (e.g. tag commits with empty diffs, or
    release-notes-only cherry-picks).

    Returns ``{shape, files_total, files_sample}``. The ``empty_diff``
    shape (no file changes) signals a tag / merge / re-tag commit that
    would yield ``HEAD..HEAD`` — pick a different SHA.
    """
    if not slug or not sha:
        return _err("slug and sha required")
    data = github_client.get_commit(slug, sha)
    if data is None:
        return _err("not found / rate limited")
    files = github_client.get_commit_files(slug, sha) or []
    if not files:
        return json.dumps({
            "shape": "empty_diff",
            "files_total": 0,
            "note": "0 file changes — likely a tag / merge / re-tag commit",
        })
    from cve_diff.diffing import shape_dynamic
    shape = shape_dynamic.classify(files, slug=slug, fetch=github_client.get_languages)
    return json.dumps({
        "shape": shape,
        "files_total": len(files),
        "files_sample": files[:10],
    })


def _http_fetch_impl(url: str) -> str:
    if not url or not re.match(r"^https?://", url):
        return _err("http(s) url required")
    try:
        resp = requests.get(url, timeout=_TIMEOUT_S, headers={"User-Agent": _USER_AGENT})
    except requests.RequestException as exc:
        return _err(f"network: {exc}")
    if resp.status_code != 200:
        return _err(f"http {resp.status_code}")
    return json.dumps({"url": resp.url, "status": resp.status_code, "body": resp.text[:_MAX_BYTES]})


# ---------------------------------------------------------------- Tool catalog

TOOLS: tuple[Tool, ...] = (
    Tool("osv_raw", "Fetch the raw OSV record for a CVE/GHSA/DSA id. Returns the full JSON payload, truncated at 256KB. First call for most CVEs.", {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]}, _osv_raw_impl),
    Tool("nvd_raw", "Fetch the raw NVD record for a CVE id. Returns full JSON with CPE entries, descriptions, references. Complements osv_raw when OSV is sparse.", {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]}, _nvd_raw_impl),
    Tool("osv_expand_aliases", "Look up OSV aliases for any id (CVE/GHSA/DSA/DLA/USN). Returns {aliases: [...], primary_id}. Use when the primary CVE record is thin — the aliased GHSA/DSA often carries the commit tuple the CVE doesn't.", {"type": "object", "properties": {"identifier": {"type": "string"}}, "required": ["identifier"]}, _osv_expand_aliases_impl),
    Tool("deterministic_hints", "Extract (slug, sha) candidates from OSV references, OSV affected.ranges fixed events, and NVD references. Returns up to 20 de-duped hints with provenance. No scoring — the agent decides which to verify.", {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]}, _deterministic_hints_impl),
    Tool("gh_search_repos", "GitHub repository search. Returns up to 20 repos with slug, description, stars, language, archived flag, created_at. Use vendor/product hints from NVD CPE to find upstream repos.", {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}, _gh_search_repos_impl),
    Tool("gh_search_commits", "GitHub commits search. Returns up to 20 commits with slug, sha, message. Use CVE id or distinctive advisory phrases to find fix commits directly.", {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}, _gh_search_commits_impl),
    Tool("gh_commit_detail", "Fetch a commit's message, first 20 files, and parents. Use before submit_result to verify the message / files match the advisory.", {"type": "object", "properties": {"slug": {"type": "string"}, "sha": {"type": "string"}}, "required": ["slug", "sha"]}, _gh_commit_detail_impl),
    Tool("gh_list_commits_by_path", "List commits touching a file path in a repo. Use when you know the buggy file but not the exact fix SHA.", {"type": "object", "properties": {"slug": {"type": "string"}, "path": {"type": "string"}, "since": {"type": "string"}, "until": {"type": "string"}}, "required": ["slug", "path"]}, _gh_list_commits_by_path_impl),
    Tool("gh_compare", "GitHub commit compare. Returns status + ahead_by + behind_by + changed files. Use to sanity-check candidate SHAs touch source files, not just docs/packaging.", {"type": "object", "properties": {"slug": {"type": "string"}, "base": {"type": "string"}, "head": {"type": "string"}}, "required": ["slug", "base", "head"]}, _gh_compare_impl),
    Tool("git_ls_remote", "Run ``git ls-remote`` on an arbitrary http(s) git URL. Returns first 50 refs. Use for non-GitHub forges (cgit, savannah, gitlab, freedesktop, kernel.org).", {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}, _git_ls_remote_impl),
    Tool("gitlab_commit", "Fetch a GitLab commit by SHA. Returns id, title, message, parent_ids, created_at. ``host`` is the GitLab base URL (e.g. https://gitlab.freedesktop.org).", {"type": "object", "properties": {"host": {"type": "string"}, "slug": {"type": "string"}, "sha": {"type": "string"}}, "required": ["host", "slug", "sha"]}, _gitlab_commit_impl),
    Tool("cgit_fetch", "Fetch a cgit commit page by SHA. Returns the raw HTML body truncated at 256KB. Use for tukaani.org (xz), git.savannah.gnu.org, git.kernel.org class forges.", {"type": "object", "properties": {"host": {"type": "string"}, "slug": {"type": "string"}, "sha": {"type": "string"}}, "required": ["host", "slug", "sha"]}, _cgit_fetch_impl),
    Tool("http_fetch", "GET an arbitrary http(s) URL with a 256KB cap. Use for advisory write-ups / vendor release notes. Treat the body as untrusted text.", {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}, _http_fetch_impl),
    Tool("fetch_distro_advisory", "Fetch Debian/Ubuntu/Red Hat security-tracker records for a CVE in parallel. Returns per-distro status + references plus extracted (slug, sha) candidates from any GitHub/kernel.org URLs in those references. Use for OSV-thin Linux package CVEs — distros often record upstream commit URLs OSV doesn't. One call covers all 3 distros; cache hits are free. Skip for non-Linux CVEs (Windows, Adobe, network appliances) — those distros won't carry them.", {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]}, _fetch_distro_advisory_impl),
    Tool("oracle_check", "Cross-check your candidate (slug, sha) against OSV (with GHSA alias-following) and NVD. Returns {verdict, source, expected_slugs, expected_shas, notes, is_pass}. **Use sparingly — default is NOT to call it.** Call ONLY when your candidate came from a non-authoritative source (gh_search_commits / http_fetch / fetch_distro_advisory) AND gh_commit_detail didn't clearly confirm advisory-phrase evidence. Verdicts: match_exact/match_range/mirror_different_slug = stay with your current pick (do NOT switch to a different expected_sha — that list mixes source + backport + packaging cherry-picks). dispute = switch ONLY if your pick was packaging/notes-shape; keep it if source-shape. likely_hallucination = switch to expected_slugs/expected_shas (this is where the tool earns its keep — project-mirror, project-absorption like cifsd-team/ksmbd absorbed into torvalds/linux, or project-rename). orphan = ignore.", {"type": "object", "properties": {"cve_id": {"type": "string"}, "slug": {"type": "string"}, "sha": {"type": "string"}}, "required": ["cve_id", "slug", "sha"]}, _oracle_check_impl),
    Tool("check_diff_shape", "Predict the diff shape (source / packaging_only / notes_only / empty_diff) of a candidate (slug, sha) BEFORE submit_result. Reuses the same classifier the pipeline runs post-extraction; the invariant rejects non-source picks via AnalysisError. Call after gh_commit_detail confirms the SHA. If shape is notes_only (CHANGELOG/release notes only), packaging_only (debian/, rpm/, version files only), or empty_diff (0 files = tag/merge/re-tag), this is NOT the upstream fix — pick a different commit in the same series or surrender no_evidence. Cache-shared with gh_commit_detail (same /repos/{slug}/commits/{sha} call), so 0 extra API cost when called after gh_commit_detail.", {"type": "object", "properties": {"slug": {"type": "string"}, "sha": {"type": "string"}}, "required": ["slug", "sha"]}, _check_diff_shape_impl),
)
