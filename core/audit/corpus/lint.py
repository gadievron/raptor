"""Label linter for the /audit calibration corpus.

Usage:
    python3 -m core.audit.corpus.lint [paths...] [options]

Two modes:

``--mode schema`` (default)
    Load every label and check field sanity, plus
    ``expected_rule_hits`` staleness: every pinned rule id must exist
    in the discovered rule inventory (shipped + graduated, via
    ``rule_eval``'s discovery; engines without a rules checkout are
    skipped per-engine).  No network, no fixtures, no engine
    execution — safe as an always-on CI gate.

``--mode pins``
    Verify each label's source pin against the pinned tree: file
    exists, line range in bounds, ``span_sha`` matches (when
    present), and the function name appears within the pinned span.
    Trees are resolved from the fixtures dir (only when the checkout
    is at the pinned ref), from the linter's sparse cache, or — with
    ``--fetch-missing`` — by fetching just the labelled files at the
    pinned ref (see ``sources.fetch_files``).

Per-label pin outcomes:

- ``ok``           pin verifies against the pinned tree
- ``relocatable``  the span or function still exists in the file (or
                   the file under a known prefix) but not at the
                   pinned location — a suggested re-pin is printed
- ``missing``      the function is absent from the pinned file (and,
                   with ``--tree-search``, from the whole tree), or
                   the pinned ref is no longer fetchable upstream
- ``no-fixture``   no tree available to verify against (warn, not
                   fail, unless ``--require-fixtures``)

``--stamp`` backfills ``span_sha`` into label files whose pin
verified ``ok`` (atomic rewrite, key order preserved).  A failing
label is never stamped.

Exit codes:
    0  clean
    1  usage / infrastructure error (bad path, unreadable label dir)
    2  lint failures (schema errors; any relocatable/missing pin;
       no-fixture under --require-fixtures)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Sequence

from core.json import load_json

from .label import FunctionLabel, compute_span_sha, load_label
from .sources import FIXTURES_DIR

LABELS_DIR = Path(__file__).parent / "labels"

# One .label.json is a small hand-written record.
_MAX_LABEL_BYTES = 8 * 1024 * 1024

# Default sparse-fetch cache for pin verification (repo@ref-keyed
# subdirectories) — separate from the full fixture trees so a lint
# fetch never disturbs a runner checkout.
DEFAULT_CACHE_DIR = Path("out/audit-corpus-lint-cache")

EXIT_OK = 0
EXIT_INFRA = 1
EXIT_LINT = 2

PIN_OK = "ok"
PIN_RELOCATABLE = "relocatable"
PIN_MISSING = "missing"
PIN_NO_FIXTURE = "no-fixture"

# Prefixes probed when a label's file is missing from the tree root —
# mirrors the runner's probe (some repos pin src/-relative paths; see
# the symlinks field in sources.json).
_PREFIX_PROBES = ("src",)

# Suffixes searched by --tree-search.
_SOURCE_EXTS = frozenset({
    ".c", ".h", ".py", ".go", ".rs", ".js", ".ts",
    ".java", ".cpp", ".cc", ".cxx", ".rb", ".swift",
})

# Cap on the sliding-window span_sha relocation search: files beyond
# this many lines get the (cheaper) name-based relocation only.
_RELOCATE_HASH_LINE_CAP = 200_000


@dataclass
class PinCheck:
    """Result of verifying one label's source pin."""

    label: FunctionLabel
    path: Path | None
    outcome: str
    detail: str = ""
    # Suggested re-pin (relocatable only).
    suggested_file: str = ""
    suggested_start: int = 0
    suggested_end: int = 0
    # Span hash of the pinned range in the verified tree (ok only) —
    # what --stamp writes.
    current_span_sha: str = ""
    # The pinned span sits entirely inside a statically-dead
    # preprocessor arm (#if 0 / #elif 0).  The pin itself verifies —
    # raw text is raw text — but the inventory excludes the function,
    # so the runner scores it dormant (receipt
    # ``inventory:preprocessor_dead``) rather than reviewing it.
    preprocessor_dead: bool = False


def _function_name(label: FunctionLabel) -> str:
    """Bare function name — same derivation as the runner."""
    name = label.function_id.rsplit(":", 1)[-1]
    return name.rsplit(".", 1)[-1]


def _name_re(name: str) -> re.Pattern:
    return re.compile(
        rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])",
    )


# -------------------------------------------------------------------
# Label loading (per-file error collection)
# -------------------------------------------------------------------

def collect_label_files(paths: Sequence[Path]) -> list[Path]:
    """Expand *paths* (files or directories) into label files."""
    files: list[Path] = []
    for p in paths:
        if p.is_dir():
            files.extend(sorted(p.rglob("*.label.json")))
        else:
            files.append(p)
    return files


def load_labels(
    files: Sequence[Path],
) -> tuple[list[tuple[Path, FunctionLabel]], list[str]]:
    """Load labels, collecting per-file errors instead of raising.

    ``load_all_labels`` raises on the first bad file; the linter wants
    the full report.  Duplicate ``function_id`` values across the
    loaded set are errors (results and checkpoints key on it).
    """
    loaded: list[tuple[Path, FunctionLabel]] = []
    errors: list[str] = []
    seen: dict[str, Path] = {}
    for f in files:
        try:
            label = load_label(f)
        except (ValueError, KeyError, TypeError) as exc:
            errors.append(f"{f}: {exc}")
            continue
        except json.JSONDecodeError as exc:
            errors.append(f"{f}: invalid JSON: {exc}")
            continue
        except OSError as exc:
            errors.append(f"{f}: unreadable: {exc}")
            continue
        prev = seen.get(label.function_id)
        if prev is not None:
            errors.append(
                f"{f}: duplicate function_id {label.function_id!r} "
                f"(already labelled in {prev})"
            )
            continue
        seen[label.function_id] = f
        loaded.append((f, label))
    return loaded, errors


def schema_check(pairs: Sequence[tuple[Path, FunctionLabel]]) -> list[str]:
    """Field sanity beyond what the dataclass validators enforce."""
    errors: list[str] = []
    for path, label in pairs:
        src = label.source

        def err(msg: str, path=path, label=label) -> None:
            errors.append(f"{path}: {label.function_id}: {msg}")

        if ":" not in label.function_id:
            err("function_id must be '<file>:<name>'")
        elif label.function_id.rsplit(":", 1)[0] != src.file:
            err(
                f"function_id file part "
                f"{label.function_id.rsplit(':', 1)[0]!r} != "
                f"source.file {src.file!r}"
            )
        if not _function_name(label):
            err("function_id has an empty function name")
        if not src.repo:
            err("source.repo is empty")
        if not src.sha:
            err("source.sha is empty")
        if not src.file:
            err("source.file is empty")
        elif Path(src.file).is_absolute() or ".." in Path(src.file).parts:
            err(f"source.file {src.file!r} must be repo-relative")
        if src.line_start < 1:
            err(f"line_start {src.line_start} must be >= 1")
        if src.line_end < src.line_start:
            err(
                f"line_end {src.line_end} < line_start {src.line_start}"
            )
        if not label.rationale.strip():
            err("rationale is empty")
        if not label.labeler.strip():
            err("labeler is empty")
        if not label.labeled_at.strip():
            err("labeled_at is empty")
    return errors


def expected_rule_hits_check(
    pairs: Sequence[tuple[Path, FunctionLabel]],
) -> list[str]:
    """Dangling ``expected_rule_hits`` staleness check.

    Every rule id a label pins must exist in the discovered rule
    inventory — shipped plus graduated, enumerated through
    ``rule_eval``'s discovery (never a parallel hardcoded list) — or
    the pin can never bind and the label silently degrades to a
    coverage gap. Inventory enumeration only; no engine executes.

    Graceful skips, per engine: an engine whose rule dirs are absent
    (CI without a rules checkout) or whose name is outside
    ``rule_eval.ENGINES`` (the field deliberately allows pinning rule
    sets this checkout doesn't ship) contributes no errors.
    """
    pinned: dict[str, list[tuple[Path, FunctionLabel, str]]] = {}
    for path, label in pairs:
        for engine, rule_ids in (label.expected_rule_hits or {}).items():
            for rule_id in rule_ids:
                pinned.setdefault(engine, []).append(
                    (path, label, rule_id),
                )
    if not pinned:
        # No pins anywhere: skip discovery entirely (keeps the
        # default lint path import-light and cheap).
        return []

    from . import rule_eval

    engines = sorted(set(pinned) & set(rule_eval.ENGINES))
    rules, _discovery_errors = rule_eval.discover_rules(engines)
    graduated, _grad_errors = rule_eval.discover_graduated_rules(
        engines, rule_eval.find_engine_rules_base(None),
    )
    known: dict[str, set] = {}
    for rule in [*rules, *graduated]:
        known.setdefault(rule.engine, set()).add(rule.rule_id)

    errors: list[str] = []
    for engine, entries in sorted(pinned.items()):
        ids = known.get(engine)
        if not ids:
            # Engine dirs absent (or foreign engine name): nothing to
            # check against — skip, never fail.
            continue
        for path, label, rule_id in entries:
            if rule_id not in ids:
                errors.append(
                    f"{path}: {label.function_id}: expected_rule_hits "
                    f"names unknown {engine} rule {rule_id!r} — not in "
                    f"the shipped or graduated inventory (renamed or "
                    f"removed rule?)"
                )
    return errors


# -------------------------------------------------------------------
# Tree resolution (fixtures, sparse cache, --fetch-missing)
# -------------------------------------------------------------------

def _git_output(repo: Path, *args: str) -> str:
    from .sources import _run_git

    result = _run_git(["-C", str(repo), *args], timeout_s=60)
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def _checkout_matches(repo: Path, sha: str) -> bool:
    """True when *repo*'s HEAD is the commit *sha* resolves to."""
    head = _git_output(repo, "rev-parse", "HEAD")
    if not head:
        return False
    if all(c in "0123456789abcdef" for c in sha) and len(sha) >= 7:
        return head.startswith(sha)
    resolved = _git_output(repo, "rev-parse", f"{sha}^{{commit}}")
    return bool(resolved) and resolved == head


def resolve_trees(
    labels: Sequence[FunctionLabel],
    *,
    fixtures_dir: Path = FIXTURES_DIR,
    cache_dir: Path | None = None,
    fetch_missing: bool = False,
) -> dict[tuple[str, str], tuple[Path | None, str]]:
    """Resolve a verification tree per ``(repo, sha)`` pin target.

    Returns ``{(repo, sha): (tree_or_None, detail)}``.  A fixture tree
    is used only when its checkout matches the pinned ref (a fixture
    at another ref cannot verify this pin).  ``detail`` values whose
    tree is None:

    - ``"unfetchable:<why>"`` — the remote answered but the pinned
      ref is gone (history rewrite / tag deletion).  Callers score
      the pin ``missing``.
    - anything else — no tree available (no fixture, offline, repo
      not in sources.json).  Callers score ``no-fixture``.
    """
    wanted: dict[tuple[str, str], list[str]] = {}
    for label in labels:
        key = (label.source.repo, label.source.sha)
        files = wanted.setdefault(key, [])
        if label.source.file not in files:
            files.append(label.source.file)

    resolved: dict[tuple[str, str], tuple[Path | None, str]] = {}
    registry = None
    for (repo, sha), files in wanted.items():
        fixture = fixtures_dir / repo
        if fixture.is_dir():
            if not (fixture / ".git").exists():
                # Tarball-style fixture: usable, but the ref cannot be
                # verified — mirror the runner's behaviour and say so.
                resolved[(repo, sha)] = (
                    fixture, "ref unverified (fixture is not a git "
                    "checkout)",
                )
                continue
            if _checkout_matches(fixture, sha):
                resolved[(repo, sha)] = (fixture, "")
                continue
            detail = f"fixture {fixture} is checked out at another ref"
        else:
            detail = f"no fixture at {fixture}"

        cached = None
        if cache_dir is not None:
            cached = cache_dir / f"{repo}@{sha}"
            if (cached / ".git").exists() and _checkout_matches(
                cached, sha,
            ):
                resolved[(repo, sha)] = (cached, "sparse cache")
                continue

        if fetch_missing and cached is not None:
            from .sources import SourceFetchError, fetch_files

            if registry is None:
                from .sources import load_sources

                try:
                    registry = load_sources()
                except (ValueError, OSError) as exc:
                    registry = {}
                    detail = f"sources.json unreadable: {exc}"
            if repo not in registry:
                resolved[(repo, sha)] = (
                    None, f"{detail}; repo not in sources.json",
                )
                continue
            try:
                fetch_files(
                    repo, sha, files, cached, entry=registry[repo],
                )
                resolved[(repo, sha)] = (cached, "sparse cache")
                continue
            except SourceFetchError as exc:
                if exc.connectivity:
                    resolved[(repo, sha)] = (
                        None, f"remote unreachable: {exc}",
                    )
                else:
                    # The remote answered and refused the ref: the
                    # pinned commit/tag is gone upstream.
                    resolved[(repo, sha)] = (None, f"unfetchable:{exc}")
                continue

        resolved[(repo, sha)] = (None, detail)
    return resolved


# -------------------------------------------------------------------
# Pin verification
# -------------------------------------------------------------------

def _relocate_by_hash(
    lines: list[str], span_sha: str, span_len: int,
) -> int | None:
    """Find the 1-indexed start line where the stored span hash
    matches, or None."""
    from core.staleness import hash_spans_text

    n = len(lines)
    if span_len <= 0 or n < span_len or n > _RELOCATE_HASH_LINE_CAP:
        return None
    text = "\n".join(lines)
    spans = [(s, s + span_len - 1) for s in range(1, n - span_len + 2)]
    for start, h in zip(
        range(1, n - span_len + 2), hash_spans_text(text, spans),
    ):
        if h == span_sha:
            return start
    return None


def _relocate_by_name(
    lines: list[str], name: str, _span_len: int,
) -> int | None:
    """Best-effort 1-indexed start line for *name*'s definition."""
    pattern = _name_re(name)
    candidates = [
        i + 1 for i, line in enumerate(lines) if pattern.search(line)
    ]
    if not candidates:
        return None
    # Prefer a line that looks like a definition/declaration site
    # (name immediately followed by an open paren).
    call_like = re.compile(
        rf"(?<![A-Za-z0-9_]){re.escape(name)}\s*\(",
    )
    for cand in candidates:
        if call_like.search(lines[cand - 1]):
            return cand
    return candidates[0]


def _tree_search(tree: Path, name: str, limit: int = 3) -> list[str]:
    """Search *tree* for *name*; returns up to *limit* ``file:line``
    hits."""
    pattern = _name_re(name)
    hits: list[str] = []
    for root, dirs, files in os.walk(tree):
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".") and d not in (
                "vendor", "node_modules", "__pycache__",
            )
        ]
        for fname in sorted(files):
            if Path(fname).suffix not in _SOURCE_EXTS:
                continue
            fpath = Path(root) / fname
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines()):
                if pattern.search(line):
                    rel = fpath.relative_to(tree)
                    hits.append(f"{rel}:{i + 1}")
                    break
            if len(hits) >= limit:
                return hits
    return hits


# File suffixes the C preprocessor governs (mirrors the runner's set).
_CPP_SUFFIXES = frozenset({
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx",
})


def _span_preprocessor_dead(
    rel_file: str,
    lines: list[str],
    line_start: int,
    line_end: int,
) -> bool:
    """Whole pinned span inside a statically-dead preprocessor arm?

    Same literal-only detector the inventory's translation view uses
    (``#if 0`` / ``#elif 0`` — config-independent), so the lint note
    matches what the checklist will actually do. Best-effort: any
    probe failure means "not dead".
    """
    if Path(rel_file).suffix.lower() not in _CPP_SUFFIXES:
        return False
    try:
        from core.inventory.translation_view import (
            detect_preprocessor_dead_ranges,
        )
        ranges = detect_preprocessor_dead_ranges("\n".join(lines))
    except Exception:  # noqa: BLE001 — lint note only, never fatal
        return False
    return any(r0 <= line_start and line_end <= r1 for r0, r1 in ranges)


def _check_span(
    label: FunctionLabel,
    lines: list[str],
    rel_file: str,
    path: Path | None,
    *,
    tree: Path,
    tree_search: bool,
) -> PinCheck:
    """Verify the pinned range against *lines* of *rel_file*."""
    src = label.source
    name = _function_name(label)
    span_len = src.line_end - src.line_start + 1
    n = len(lines)
    in_bounds = 1 <= src.line_start <= src.line_end <= n

    if in_bounds:
        span_text = "\n".join(lines[src.line_start - 1:src.line_end])
        current = compute_span_sha(
            "\n".join(lines), src.line_start, src.line_end,
        )
        name_in_span = bool(_name_re(name).search(span_text))
        sha_ok = (not src.span_sha) or current == src.span_sha
        if sha_ok and name_in_span and rel_file == src.file:
            dead = _span_preprocessor_dead(
                rel_file, lines, src.line_start, src.line_end,
            )
            return PinCheck(
                label=label, path=path, outcome=PIN_OK,
                detail=(
                    "preprocessor-dead (#if 0 arm) — the inventory "
                    "excludes it; the runner scores dormant"
                    if dead else ""
                ),
                current_span_sha=current,
                preprocessor_dead=dead,
            )

    # Relocation: exact span by hash first, then the function name.
    if src.span_sha:
        start = _relocate_by_hash(lines, src.span_sha, span_len)
        if start is not None:
            return PinCheck(
                label=label, path=path, outcome=PIN_RELOCATABLE,
                detail=(
                    f"span found at {rel_file}:{start}-"
                    f"{start + span_len - 1} (pinned "
                    f"{src.line_start}-{src.line_end})"
                ),
                suggested_file=rel_file,
                suggested_start=start,
                suggested_end=start + span_len - 1,
            )
    start = _relocate_by_name(lines, name, span_len)
    if start is not None:
        end = min(start + span_len - 1, n)
        why = (
            "span content changed"
            if in_bounds and src.span_sha
            else (
                "name outside pinned range"
                if in_bounds
                else f"range {src.line_start}-{src.line_end} out of "
                     f"bounds ({n} lines)"
            )
        )
        return PinCheck(
            label=label, path=path, outcome=PIN_RELOCATABLE,
            detail=(
                f"{why}; {name!r} found at {rel_file}:{start} — "
                f"suggest {start}-{end}"
            ),
            suggested_file=rel_file,
            suggested_start=start,
            suggested_end=end,
        )

    detail = f"{name!r} absent from {rel_file}"
    if tree_search:
        hits = _tree_search(tree, name)
        if hits:
            detail += " — tree search found it in " + ", ".join(hits)
        else:
            detail += " and from the pinned tree"
    return PinCheck(
        label=label, path=path, outcome=PIN_MISSING, detail=detail,
    )


def verify_pin(
    label: FunctionLabel,
    tree: Path,
    *,
    path: Path | None = None,
    tree_search: bool = False,
) -> PinCheck:
    """Verify one label's pin against a resolved *tree*."""
    src_file = tree / label.source.file
    rel_file = label.source.file
    if not src_file.is_file():
        for prefix in _PREFIX_PROBES:
            cand = tree / prefix / label.source.file
            if cand.is_file():
                src_file = cand
                rel_file = f"{prefix}/{label.source.file}"
                break
        else:
            name = _function_name(label)
            detail = f"file {label.source.file} not found in tree"
            if tree_search:
                hits = _tree_search(tree, name)
                if hits:
                    detail += (
                        " — tree search found "
                        f"{name!r} in " + ", ".join(hits)
                    )
            return PinCheck(
                label=label, path=path, outcome=PIN_MISSING,
                detail=detail,
            )

    try:
        text = src_file.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return PinCheck(
            label=label, path=path, outcome=PIN_MISSING,
            detail=f"unreadable: {exc}",
        )
    return _check_span(
        label, text.splitlines(), rel_file, path,
        tree=tree, tree_search=tree_search,
    )


def verify_pins(
    pairs: Sequence[tuple[Path | None, FunctionLabel]],
    *,
    fixtures_dir: Path = FIXTURES_DIR,
    cache_dir: Path | None = None,
    fetch_missing: bool = False,
    tree_search: bool = False,
) -> list[PinCheck]:
    """Verify every label's pin.  Order matches *pairs*."""
    labels = [label for _, label in pairs]
    trees = resolve_trees(
        labels,
        fixtures_dir=fixtures_dir,
        cache_dir=cache_dir,
        fetch_missing=fetch_missing,
    )
    checks: list[PinCheck] = []
    for path, label in pairs:
        tree, detail = trees[(label.source.repo, label.source.sha)]
        if tree is None:
            if detail.startswith("unfetchable:"):
                checks.append(PinCheck(
                    label=label, path=path, outcome=PIN_MISSING,
                    detail=(
                        "pinned ref no longer fetchable upstream — "
                        + detail[len("unfetchable:"):]
                    ),
                ))
            else:
                checks.append(PinCheck(
                    label=label, path=path, outcome=PIN_NO_FIXTURE,
                    detail=detail,
                ))
            continue
        checks.append(verify_pin(
            label, tree, path=path, tree_search=tree_search,
        ))
    return checks


# -------------------------------------------------------------------
# Stamping
# -------------------------------------------------------------------

def stamp_labels(checks: Sequence[PinCheck]) -> list[Path]:
    """Backfill ``span_sha`` into label files whose pin verified ok.

    Atomic rewrite (tempfile + rename) preserving key order; the hash
    lands directly after ``line_end`` in the ``source`` object.  A
    label that did not verify is never stamped.
    """
    stamped: list[Path] = []
    for check in checks:
        if check.outcome != PIN_OK or not check.current_span_sha:
            continue
        if check.path is None:
            continue
        if check.label.source.span_sha == check.current_span_sha:
            continue  # already stamped
        raw = load_json(check.path, strict=True, max_bytes=_MAX_LABEL_BYTES)
        if raw is None:
            # Strict load_json still soft-returns None for a missing
            # file — a label that vanished mid-lint cannot be stamped.
            raise FileNotFoundError(check.path)
        source = raw.get("source", {})
        new_source = {}
        for key, val in source.items():
            if key == "span_sha":
                continue
            new_source[key] = val
            if key == "line_end":
                new_source["span_sha"] = check.current_span_sha
        if "span_sha" not in new_source:
            new_source["span_sha"] = check.current_span_sha
        raw["source"] = new_source
        fd, tmp_name = tempfile.mkstemp(
            dir=str(check.path.parent),
            prefix=check.path.name + ".",
        )
        try:
            with os.fdopen(fd, "w") as f:
                # ensure_ascii=False: labels are UTF-8 on disk; the
                # stamp must not rewrite prose into \uXXXX escapes.
                json.dump(raw, f, indent=4, ensure_ascii=False)
                f.write("\n")
            os.replace(tmp_name, check.path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
        stamped.append(check.path)
    return stamped


# -------------------------------------------------------------------
# Reporting
# -------------------------------------------------------------------

def pin_census(checks: Sequence[PinCheck]) -> dict[str, int]:
    census = {
        PIN_OK: 0, PIN_RELOCATABLE: 0, PIN_MISSING: 0, PIN_NO_FIXTURE: 0,
    }
    for check in checks:
        census[check.outcome] += 1
    return census


def format_pin_report(checks: Sequence[PinCheck]) -> str:
    lines = []
    for check in sorted(checks, key=lambda c: c.label.function_id):
        line = f"  {check.outcome:<12} {check.label.function_id}"
        if check.detail:
            line += f" — {check.detail}"
        lines.append(line)
    census = pin_census(checks)
    lines.append(
        f"Pin census: {census[PIN_OK]} ok, "
        f"{census[PIN_RELOCATABLE]} relocatable, "
        f"{census[PIN_MISSING]} missing, "
        f"{census[PIN_NO_FIXTURE]} no-fixture "
        f"({len(checks)} label(s))"
    )
    return "\n".join(lines)


# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m core.audit.corpus.lint",
        description="Lint /audit calibration-corpus labels",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "exit codes:\n"
            "  0  clean\n"
            "  1  usage / infrastructure error\n"
            "  2  lint failures (schema errors, drifted pins, or "
            "no-fixture\n"
            "     under --require-fixtures)"
        ),
    )
    parser.add_argument(
        "paths", nargs="*", type=Path,
        help="Label files or directories "
             "(default: the committed corpus labels)",
    )
    parser.add_argument(
        "--mode", choices=("schema", "pins"), default="schema",
        help="schema: field sanity only (default, no fixtures). "
             "pins: verify pins against the pinned trees",
    )
    parser.add_argument(
        "--fixtures-dir", type=Path, default=FIXTURES_DIR,
        help=f"Fixture tree root (default: {FIXTURES_DIR})",
    )
    parser.add_argument(
        "--cache-dir", type=Path, default=DEFAULT_CACHE_DIR,
        help="Sparse-fetch cache for pin verification "
             f"(default: {DEFAULT_CACHE_DIR})",
    )
    parser.add_argument(
        "--fetch-missing", action="store_true",
        help="Fetch only the labelled files at the pinned ref into "
             "the cache when no local tree can verify a pin",
    )
    parser.add_argument(
        "--stamp", action="store_true",
        help="Backfill span_sha into label files whose pin verified "
             "ok (pins mode only)",
    )
    parser.add_argument(
        "--tree-search", action="store_true",
        help="On a missing function, search the whole pinned tree "
             "for it",
    )
    parser.add_argument(
        "--require-fixtures", action="store_true",
        help="Treat no-fixture as a lint failure instead of a warning",
    )
    args = parser.parse_args(argv)

    # Default run with no labels present is a clean no-op: the labels
    # directory is populated locally, so a bare tree must lint green.
    if not args.paths and not any(LABELS_DIR.rglob("*.label.json")):
        print("lint: no labels present; nothing to lint")
        return EXIT_OK

    paths = args.paths or [LABELS_DIR]
    for p in paths:
        if not p.exists():
            print(f"lint: path not found: {p}", file=sys.stderr)
            return EXIT_INFRA

    files = collect_label_files(paths)
    if not files:
        print("lint: no .label.json files found", file=sys.stderr)
        return EXIT_INFRA

    pairs, schema_errors = load_labels(files)
    schema_errors.extend(schema_check(pairs))
    schema_errors.extend(expected_rule_hits_check(pairs))

    print(f"Loaded {len(pairs)} label(s) from {len(files)} file(s)")
    if schema_errors:
        print(f"{len(schema_errors)} schema error(s):", file=sys.stderr)
        for e in schema_errors:
            print(f"  {e}", file=sys.stderr)

    if args.mode == "schema":
        if schema_errors:
            return EXIT_LINT
        print("Schema lint clean.")
        return EXIT_OK

    # pins mode — schema errors gate before any fetch is attempted.
    if schema_errors:
        return EXIT_LINT

    checks = verify_pins(
        pairs,
        fixtures_dir=args.fixtures_dir,
        cache_dir=args.cache_dir,
        fetch_missing=args.fetch_missing,
        tree_search=args.tree_search,
    )
    print(format_pin_report(checks))

    if args.stamp:
        stamped = stamp_labels(checks)
        for p in stamped:
            print(f"  stamped span_sha: {p}")
        print(f"Stamped {len(stamped)} label file(s)")

    census = pin_census(checks)
    failures = census[PIN_RELOCATABLE] + census[PIN_MISSING]
    if args.require_fixtures:
        failures += census[PIN_NO_FIXTURE]
    elif census[PIN_NO_FIXTURE]:
        print(
            f"WARNING: {census[PIN_NO_FIXTURE]} label(s) could not be "
            f"verified (no fixture at the pinned ref) — not a failure "
            f"without --require-fixtures",
        )
    return EXIT_LINT if failures else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
