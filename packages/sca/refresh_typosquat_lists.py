"""Refresh the bundled "popular packages" lists used by the typosquat
detector + the curated python_module_map.json.

Per design §940 / §817 / §854, these data files are refreshed weekly by
a cron-driven auto-PR (``.github/workflows/refresh-sca-data.yml``).
This module is the script that workflow runs.

Per-ecosystem source endpoints (all unauthenticated):

  - **PyPI** — hugovk's ``top-pypi-packages`` JSON: a daily-updated
    rolling list of the most-downloaded PyPI packages over the
    last 30 days. Maintained as a community resource since 2017;
    used by ruff, uv, and other tools.
  - **npm** — anvaka's ``npmrank`` index: top npm packages by
    "depended-upon count" (more attack-relevant than raw downloads;
    a typosquat targets packages OTHERS will accidentally pull in).
  - **crates.io** — the registry's own ``/api/v1/crates`` endpoint
    sorted by downloads.
  - **Packagist** — ``/explore/popular.json`` paginated by popularity.

Ecosystems WITHOUT a clean public popularity API
(RubyGems, Maven Central, NuGet, Go modules, Homebrew, Debian) are
left to their existing hand-curated lists. Future PRs can add
fetchers as suitable upstream sources surface; for now those
ecosystems' typosquat detection runs against smaller bundled lists.

The script is idempotent: running it on an unchanged upstream
produces an unchanged output file (sorted, stable JSON shape). The
auto-PR workflow only opens a PR when ``git status`` reports a
diff after the run.

Failure modes:
  - Per-ecosystem source down → log warning, leave that file alone.
  - All sources down → no file changes; the workflow's auto-PR step
    detects no diff and exits cleanly.
  - Output target unwritable → log error, exit 1 so the workflow
    surfaces the failure.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from core.http import HttpClient
from core.http.urllib_backend import UrllibClient

logger = logging.getLogger(__name__)

# Default top-N. The design specifies 5000 per ecosystem; we let the
# CLI override (smaller values for local dev, larger for the cron run).
_DEFAULT_TOP_N = 5000

# Where the bundled lists live.
_DATA_DIR = Path(__file__).resolve().parent / "data"


# ---------------------------------------------------------------------------
# Per-ecosystem fetchers
# ---------------------------------------------------------------------------
#
# Each fetcher returns a sorted ``list[str]`` of canonical package names.
# Fetchers raise on hard failure (the orchestrator catches and logs); a
# successful return with an empty list means "source returned nothing
# parseable" and is treated as a soft failure (existing list left alone).

_HUGOVK_TOP_PYPI = (
    "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.json"
)
_ANVAKA_NPM_RANK = (
    "https://anvaka.github.io/npmrank/online/npmrank.json"
)
_CRATES_API = "https://crates.io/api/v1/crates"
_PACKAGIST_POPULAR = "https://packagist.org/explore/popular.json"


def fetch_pypi(http: HttpClient, top_n: int) -> List[str]:
    data = http.get_json(_HUGOVK_TOP_PYPI, retries=2)
    rows = data.get("rows") or data.get("packages") or []
    names: List[str] = []
    for r in rows[:top_n]:
        # hugovk format: ``{"project": "requests", "download_count": ...}``
        # in older snapshots; ``{"name": ...}`` in newer.
        n = r.get("project") or r.get("name")
        if isinstance(n, str) and n:
            names.append(n.lower())
    return sorted(set(names))


def fetch_npm(http: HttpClient, top_n: int) -> List[str]:
    data = http.get_json(_ANVAKA_NPM_RANK, retries=2)
    # The anvaka npmrank format is a dict: ``{name: rank, ...}`` where
    # lower rank = more popular. Sort and take the top N.
    if not isinstance(data, dict):
        return []
    ranked = sorted(data.items(), key=lambda kv: kv[1])
    return sorted({n for n, _ in ranked[:top_n]
                    if isinstance(n, str) and n})


def fetch_crates(
    http: HttpClient, top_n: int, *, per_page: int = 100,
) -> List[str]:
    """crates.io paginates ``per_page`` (max 100) per request. Fetch
    enough pages to fill ``top_n``. The API is unauthenticated but
    rate-limited; honour rate limits via ``retries=`` (the proxy +
    backoff path handles 429 transparently). ``per_page`` is a
    parameter so tests can exercise pagination with small fixtures.
    """
    names: List[str] = []
    pages = (top_n + per_page - 1) // per_page
    for page in range(1, pages + 1):
        url = (f"{_CRATES_API}?sort=downloads"
               f"&per_page={per_page}&page={page}")
        try:
            data = http.get_json(url, retries=2)
        except Exception as e:                  # noqa: BLE001
            logger.warning("crates.io page %d failed: %s", page, e)
            break
        crates = data.get("crates") or []
        if not crates:
            break
        for c in crates:
            n = c.get("name") or c.get("id")
            if isinstance(n, str):
                names.append(n.lower())
        if len(crates) < per_page:
            break
    return sorted(set(names))[:top_n]


def fetch_packagist(http: HttpClient, top_n: int) -> List[str]:
    """Packagist's popular endpoint is paginated; ``page=N`` query param."""
    names: List[str] = []
    page = 1
    while len(names) < top_n:
        url = f"{_PACKAGIST_POPULAR}?page={page}"
        try:
            data = http.get_json(url, retries=2)
        except Exception as e:                  # noqa: BLE001
            logger.warning("packagist page %d failed: %s", page, e)
            break
        packages = data.get("packages") or []
        if not packages:
            break
        for p in packages:
            n = p.get("name")
            if isinstance(n, str):
                names.append(n.lower())
        # Packagist returns 'next' in the response when more pages exist.
        if not data.get("next"):
            break
        page += 1
        if page > 200:               # safety: 200 pages × 12/pg ≈ 2400
            break
    return sorted(set(names))[:top_n]


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

# Maps the bundled-file name to its fetcher. The file name matches what
# typosquat.py loads via ``packages/sca/data/popular/<eco>.json``.
_FETCHERS: Dict[str, Tuple[str, Callable[[HttpClient, int], List[str]]]] = {
    # bundle filename → (display name, fetcher)
    # Filenames must match the ecosystem strings in parsers/ so the
    # typosquat detector's ``_load_popular(ecosystem)`` finds them.
    "PyPI.json":      ("PyPI",      fetch_pypi),
    "npm.json":       ("npm",       fetch_npm),
    "Cargo.json":     ("Cargo",     fetch_crates),
    "Packagist.json": ("Packagist", fetch_packagist),
}


def refresh_all(
    http: HttpClient,
    *,
    top_n: int = _DEFAULT_TOP_N,
    only: Optional[List[str]] = None,
    data_dir: Path = _DATA_DIR,
) -> Dict[str, str]:
    """Fetch every supported ecosystem and write the result to
    ``data_dir/popular/<file>``. Returns ``{file: status}`` per
    fetcher: ``"updated"`` / ``"unchanged"`` / ``"skipped"`` /
    ``"failed: <msg>"``.
    """
    popular_dir = data_dir / "popular"
    popular_dir.mkdir(parents=True, exist_ok=True)
    out: Dict[str, str] = {}
    for fname, (display, fetch) in _FETCHERS.items():
        if only is not None and display not in only:
            out[fname] = "skipped"
            continue
        try:
            # nosemgrep: sinks.raptor.web.ssrf.dynamic-url
            # ``fetch`` callables hardcode their URLs (top of file
            # ``_FETCHERS`` dict points each fname to a specific
            # function with a literal URL). Not SSRF.
            names = fetch(http, top_n)
        except Exception as e:                  # noqa: BLE001
            logger.warning("%s fetch failed: %s", display, e)
            out[fname] = f"failed: {type(e).__name__}: {e}"
            continue
        if not names:
            out[fname] = "failed: empty result"
            continue
        target = popular_dir / fname
        new_blob = json.dumps(names, indent=2) + "\n"
        if target.exists() and target.read_text(encoding="utf-8") == new_blob:
            out[fname] = "unchanged"
            continue
        target.write_text(new_blob, encoding="utf-8")
        out[fname] = "updated"
        logger.info("refreshed %s (%d entries)", target, len(names))
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="refresh_typosquat_lists",
        description=(
            "Refresh packages/sca/data/popular/<eco>.json from upstream "
            "popularity feeds. Run by .github/workflows/refresh-sca-data.yml."
        ),
    )
    p.add_argument(
        "--top-n", type=int, default=_DEFAULT_TOP_N,
        help=f"max names per ecosystem (default {_DEFAULT_TOP_N})",
    )
    p.add_argument(
        "--only", action="append", default=None,
        metavar="ECO",
        help="restrict to one or more ecosystems "
             "(PyPI, npm, Cargo, Packagist). Repeatable.",
    )
    p.add_argument(
        "--data-dir", type=Path, default=_DATA_DIR,
        help=f"data directory root (default {_DATA_DIR})",
    )
    p.add_argument("-v", "--verbose", action="count", default=0)
    args = p.parse_args(argv if argv is not None else sys.argv[1:])

    logging.basicConfig(
        level=logging.WARNING - 10 * min(args.verbose, 2),
        format="%(levelname)s %(name)s: %(message)s",
    )

    # The refresh script doesn't go through the SCA egress-allowlisted
    # client because the popularity feeds aren't on the SCA allowlist
    # (they're cron-only, not part of the analyse path). UrllibClient is
    # the right tool — uncontended outbound HTTPS.
    http = UrllibClient()
    results = refresh_all(http, top_n=args.top_n, only=args.only,
                           data_dir=args.data_dir)
    for fname, status in sorted(results.items()):
        print(f"  {fname:20s}  {status}")
    failed = [k for k, v in results.items() if v.startswith("failed:")]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
