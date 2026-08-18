"""Harvest parser/decoder API names from CVE-fix history into a data pack.

The function taxonomy's ``PARSER_FUNCS`` category ("high-CVE-density
parser entry points" — the fuzz-prioritisation signal for source-less
binary targets, where the study loop cannot learn vocabulary) used to be
a hand-grown ~45-name catalog. This module is the harvest-to-pack
capability that replaces hand-curation: it walks security-fix history
and records which public parser-API functions security fixes actually
land in, with provenance, into
``core/function_taxonomy/data/packs/parser_apis.json``.

Inputs (either, per :class:`HarvestSource`):

* ``repo_dir`` — a local git clone of a parsing library. Commits whose
  message references a CVE id are walked; the enclosing-function names
  from each fix diff's hunk headers are extracted and filtered to the
  library's public-API name patterns.
* ``diff_dir`` — a directory of recorded fix diffs (``*.diff`` /
  ``*.patch`` — e.g. `/cve-diff` run artifacts copied side-by-side).
  CVE ids are taken from each filename, or from a ``<name>.json``
  sidecar with a ``cve_id`` field.

Only hunk-header context functions count (the functions a fix
*modified*), only in C-family files, and only names matching the
source's ``api_patterns`` (the library's exported-namespace shape, e.g.
``^XML_`` for expat) — internal static helpers carry no signal for
import-table matching on binaries.

Merging is ADDITIVE ONLY: an existing pack entry is never removed by a
harvest (shrinkage would silently regress every consumer); harvests add
names and corroborate existing entries with CVE provenance. The
``legacy-catalog`` provenance marks entries inherited from the
pre-migration hardcoded list.

Git invocations use the strict read-only argv
(:func:`core.git.clone.safe_git_readonly_command`) — an untrusted
clone's config/hooks never execute. Partial (``--filter=blob:none``)
clones need the promisor transport re-enabled for ``git show``; that is
an explicit operator opt-in (``allow_promisor_fetch=True`` /
``--allow-promisor-fetch``), which drops to the non-strict safe argv
and preserves proxy env for the lazy blob fetch.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from core.git.clone import (
    get_safe_git_env,
    safe_git_command,
    safe_git_readonly_command,
)

#: Shipped pack location (the taxonomy loads it at import).
PACK_PATH = (
    Path(__file__).resolve().parents[1]
    / "function_taxonomy" / "data" / "packs" / "parser_apis.json"
)

#: Default harvest-source config (libraries + clone URLs + API shapes).
DEFAULT_SOURCES_PATH = (
    Path(__file__).resolve().parent / "data" / "parser_pack_sources.json"
)

PACK_SCHEMA = 1

PROVENANCE_LEGACY = "legacy-catalog"
PROVENANCE_CVE_FIX = "cve-fix-diff"

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
# `diff --git a/<path> b/<path>` — tracks which file a hunk belongs to.
_DIFF_FILE_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)")
# Unified hunk header; group(1) is git's enclosing-context line.
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@ ?(.*)$")
# Last `name(` in the context line = the enclosing function.
_CONTEXT_FUNC_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")

_C_FAMILY_EXTS = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh")

_GIT_TIMEOUT = 60


@dataclass(frozen=True)
class HarvestSource:
    """One parsing library to harvest."""

    library: str
    api_patterns: tuple[str, ...]
    repo_dir: str | None = None
    diff_dir: str | None = None
    clone_url: str | None = None  # documentation / operator convenience

    def compiled_patterns(self) -> list[re.Pattern[str]]:
        return [re.compile(p) for p in self.api_patterns]


@dataclass
class HarvestResult:
    """Names harvested for one library: name → sorted CVE ids."""

    library: str
    names: dict[str, set[str]] = field(default_factory=dict)
    commits_walked: int = 0
    errors: list[str] = field(default_factory=list)

    def add(self, name: str, cves: set[str]) -> None:
        self.names.setdefault(name, set()).update(cves)


def load_sources(path: Path) -> list[HarvestSource]:
    """Load a harvest-source config: ``{"sources": [{...}, ...]}``."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    sources = []
    for item in raw.get("sources", []):
        library = item.get("library")
        patterns = tuple(
            p for p in item.get("api_patterns", []) if isinstance(p, str)
        )
        if not (isinstance(library, str) and library and patterns):
            raise ValueError(
                f"source entry needs 'library' + 'api_patterns': {item!r}"
            )
        sources.append(HarvestSource(
            library=library,
            api_patterns=patterns,
            repo_dir=item.get("repo_dir"),
            diff_dir=item.get("diff_dir"),
            clone_url=item.get("clone_url"),
        ))
    return sources


# =====================================================================
# Diff parsing
# =====================================================================


def extract_fix_functions(diff_text: str) -> set[str]:
    """Enclosing-function names from a unified diff's hunk headers,
    restricted to C-family files."""
    names: set[str] = set()
    in_c_file = False
    for line in diff_text.splitlines():
        file_match = _DIFF_FILE_RE.match(line)
        if file_match:
            in_c_file = file_match.group(2).lower().endswith(_C_FAMILY_EXTS)
            continue
        if not in_c_file:
            continue
        hunk = _HUNK_RE.match(line)
        if not hunk:
            continue
        context = hunk.group(1)
        candidates = _CONTEXT_FUNC_RE.findall(context)
        if candidates:
            names.add(candidates[-1])
    return names


def _filter_api_names(
    names: set[str], patterns: list[re.Pattern[str]],
) -> set[str]:
    return {
        n for n in names
        if _IDENT_RE.match(n) and any(p.search(n) for p in patterns)
    }


# =====================================================================
# Git-repo harvesting
# =====================================================================


def _run_git(
    args: list[str], *, allow_promisor_fetch: bool = False,
) -> subprocess.CompletedProcess:
    if allow_promisor_fetch:
        argv = safe_git_command(*args)
        env = get_safe_git_env(preserve_proxy=True)
    else:
        argv = safe_git_readonly_command(*args)
        env = get_safe_git_env()
    return subprocess.run(
        argv, capture_output=True, text=True, errors="replace",
        timeout=_GIT_TIMEOUT, env=env, check=False,
    )


def harvest_git_repo(
    source: HarvestSource,
    *,
    max_commits: int = 2000,
    allow_promisor_fetch: bool = False,
) -> HarvestResult:
    """Walk CVE-referencing commits of a local clone and extract the
    public parser-API functions their fix diffs touch."""
    result = HarvestResult(library=source.library)
    assert source.repo_dir is not None
    repo = str(Path(source.repo_dir).resolve())
    patterns = source.compiled_patterns()

    listing = _run_git([
        "-C", repo, "log", "--grep=CVE-", "-i",
        f"--max-count={max_commits}", "--format=%H",
    ])
    if listing.returncode != 0:
        result.errors.append(
            f"git log failed: {listing.stderr.strip()[:300]}"
        )
        return result

    for sha in listing.stdout.split():
        message = _run_git(
            ["-C", repo, "show", "-s", "--format=%B", sha],
            allow_promisor_fetch=allow_promisor_fetch,
        )
        if message.returncode != 0:
            result.errors.append(f"{sha[:12]}: message read failed")
            continue
        cves = {c.upper() for c in _CVE_RE.findall(message.stdout)}
        if not cves:
            continue
        diff = _run_git(
            ["-C", repo, "show", "--format=", "--no-color", sha],
            allow_promisor_fetch=allow_promisor_fetch,
        )
        if diff.returncode != 0:
            result.errors.append(
                f"{sha[:12]}: diff read failed "
                f"(partial clone? see --allow-promisor-fetch)"
            )
            continue
        result.commits_walked += 1
        for name in _filter_api_names(
            extract_fix_functions(diff.stdout), patterns,
        ):
            result.add(name, cves)
    return result


# =====================================================================
# Recorded-diff harvesting (offline; /cve-diff artifacts)
# =====================================================================


def harvest_diff_dir(source: HarvestSource) -> HarvestResult:
    """Extract parser-API functions from recorded fix diffs.

    CVE ids come from the diff filename or a ``<stem>.json`` sidecar
    carrying ``cve_id`` — a diff without either is still harvested,
    with empty CVE provenance.
    """
    result = HarvestResult(library=source.library)
    assert source.diff_dir is not None
    root = Path(source.diff_dir)
    patterns = source.compiled_patterns()

    diff_paths = sorted(
        p for pattern in ("*.diff", "*.patch")
        for p in root.glob(pattern)
    )
    for path in diff_paths:
        cves = {c.upper() for c in _CVE_RE.findall(path.name)}
        sidecar = path.with_suffix(".json")
        if sidecar.is_file():
            try:
                meta = json.loads(sidecar.read_text(encoding="utf-8"))
                cve_id = meta.get("cve_id", "")
                cves |= {c.upper() for c in _CVE_RE.findall(str(cve_id))}
            except (OSError, ValueError):
                result.errors.append(f"{sidecar.name}: unreadable sidecar")
        try:
            diff_text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            result.errors.append(f"{path.name}: {e}")
            continue
        result.commits_walked += 1
        for name in _filter_api_names(
            extract_fix_functions(diff_text), patterns,
        ):
            result.add(name, cves)
    return result


def harvest(
    source: HarvestSource,
    *,
    max_commits: int = 2000,
    allow_promisor_fetch: bool = False,
) -> HarvestResult:
    """Dispatch to the repo or diff-dir harvester for one source."""
    if source.repo_dir:
        return harvest_git_repo(
            source, max_commits=max_commits,
            allow_promisor_fetch=allow_promisor_fetch,
        )
    if source.diff_dir:
        return harvest_diff_dir(source)
    result = HarvestResult(library=source.library)
    result.errors.append("source has neither repo_dir nor diff_dir")
    return result


# =====================================================================
# Pack merge / serialisation
# =====================================================================


def load_pack(path: Path) -> dict:
    """Load a parser_apis pack, or an empty skeleton when absent."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    raw.setdefault("pack", "parser_apis")
    raw.setdefault("schema", PACK_SCHEMA)
    entries = raw.get("entries")
    raw["entries"] = entries if isinstance(entries, list) else []
    return raw


def merge_results(pack: dict, results: list[HarvestResult]) -> dict:
    """Merge harvest results into a pack — additive only.

    Existing entries are never removed (regenerate-for-shrinkage is
    forbidden: consumers union this pack into ``PARSER_FUNCS``).
    A harvested name matching an existing entry corroborates it —
    provenance gains ``cve-fix-diff`` and the CVE list unions.
    """
    by_name: dict[str, dict] = {}
    for entry in pack.get("entries", []):
        name = entry.get("name")
        if isinstance(name, str) and _IDENT_RE.match(name):
            by_name[name] = {
                "name": name,
                "library": str(entry.get("library", "")),
                "provenance": sorted(
                    {str(p) for p in entry.get("provenance", [])}
                ),
                "cves": sorted({str(c) for c in entry.get("cves", [])}),
            }

    for result in results:
        for name, cves in result.names.items():
            entry = by_name.get(name)
            if entry is None:
                entry = by_name[name] = {
                    "name": name,
                    "library": result.library,
                    "provenance": [],
                    "cves": [],
                }
            entry["provenance"] = sorted(
                set(entry["provenance"]) | {PROVENANCE_CVE_FIX}
            )
            entry["cves"] = sorted(set(entry["cves"]) | cves)

    merged = dict(pack)
    merged["entries"] = sorted(
        by_name.values(), key=lambda e: (e["library"], e["name"]),
    )
    return merged


def dumps_pack(pack: dict) -> str:
    return json.dumps(pack, indent=1, sort_keys=True) + "\n"


def write_pack(pack: dict, path: Path) -> None:
    """Atomic write (tempfile + rename, same-dir)."""
    import os
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=path.name + ".", suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(dumps_pack(pack))
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


# =====================================================================
# CLI
# =====================================================================


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="raptor-parser-pack-harvest",
        description=(
            "Harvest parser/decoder API names from CVE-fix history "
            "into the parser_apis data pack."
        ),
    )
    parser.add_argument(
        "--sources", type=Path, default=DEFAULT_SOURCES_PATH,
        help="harvest-source config JSON (default: shipped config)",
    )
    parser.add_argument(
        "--clone-root", type=Path, default=None,
        help=(
            "directory holding one clone per source library "
            "(<clone-root>/<library>); fills repo_dir for sources "
            "that don't set one"
        ),
    )
    parser.add_argument(
        "--pack", type=Path, default=PACK_PATH,
        help="pack file to merge into (default: shipped pack)",
    )
    parser.add_argument(
        "--max-commits", type=int, default=2000,
        help="per-repo bound on CVE-referencing commits walked",
    )
    parser.add_argument(
        "--allow-promisor-fetch", action="store_true",
        help=(
            "re-enable git transport for `git show` so partial "
            "(--filter=blob:none) clones can lazily fetch blobs; "
            "only for operator-made clones"
        ),
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="print the merged pack to stdout instead of writing",
    )
    args = parser.parse_args(argv)

    try:
        sources = load_sources(args.sources)
    except (OSError, ValueError) as e:
        print(f"error: cannot load sources: {e}", file=sys.stderr)
        return 2

    results: list[HarvestResult] = []
    for source in sources:
        if source.repo_dir is None and source.diff_dir is None:
            if args.clone_root is not None:
                candidate = args.clone_root / source.library
                if (candidate / ".git").exists():
                    source = HarvestSource(
                        library=source.library,
                        api_patterns=source.api_patterns,
                        repo_dir=str(candidate),
                        clone_url=source.clone_url,
                    )
                else:
                    print(
                        f"  {source.library}: no clone at {candidate}; "
                        f"skipped", file=sys.stderr,
                    )
                    continue
            else:
                print(
                    f"  {source.library}: no repo_dir/diff_dir and no "
                    f"--clone-root; skipped", file=sys.stderr,
                )
                continue
        result = harvest(
            source, max_commits=args.max_commits,
            allow_promisor_fetch=args.allow_promisor_fetch,
        )
        results.append(result)
        print(
            f"  {result.library}: {result.commits_walked} fix commits, "
            f"{len(result.names)} API names"
            + (f", {len(result.errors)} errors" if result.errors else ""),
            file=sys.stderr,
        )
        for err in result.errors[:5]:
            print(f"    ! {err}", file=sys.stderr)

    pack = load_pack(args.pack)
    before = {e["name"] for e in pack["entries"]}
    merged = merge_results(pack, results)
    after = {e["name"] for e in merged["entries"]}
    corroborated = sum(
        1 for e in merged["entries"]
        if PROVENANCE_CVE_FIX in e["provenance"]
        and e["name"] in before
    )
    print(
        f"pack: {len(before)} -> {len(after)} entries "
        f"(+{len(after - before)} new, {corroborated} with CVE provenance "
        f"among pre-existing)", file=sys.stderr,
    )

    if args.dry_run:
        print(dumps_pack(merged), end="")
        return 0
    write_pack(merged, args.pack)
    print(f"wrote {args.pack}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
