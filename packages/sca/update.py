"""``raptor-sca fix --cve-only`` — CVE-driven upgrade planner.

Reads a ``findings.json`` (or runs the analyse pipeline) and emits a
``proposed/`` directory of manifest rewrites that bump every vulnerable
dependency to the smallest fix version above the installed one.

Modes:

    --minimal     (default) smallest-bump-that-fixes
    --fix=<adv>   restrict to the specified advisory IDs (comma-separated)
    --allow-major allow rewrites that cross a major version boundary
    --pin-only    only rewrite manifests where the dep is currently pinned
                  (skip wildcard / caret / range entries)

Outputs (under ``--out``):

    proposed/<original-relative-path>   rewritten manifest
    changes.json                         structured (eco, name, old, new, file)
    changes.md                           human-readable summary

Per-ecosystem rewriters live in ``_rewrite_*`` functions below. All are
string-level (no AST) so they preserve operator formatting; complex
shapes the regex can't safely modify (Maven properties, computed npm
specifiers) are skipped with a logged note rather than silently
mangling the file.
"""

from __future__ import annotations

import argparse
import difflib
import json
import logging
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .versions import VersionError, compare as version_compare

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class UpgradeChange:
    """One concrete dep upgrade to apply to one manifest."""

    ecosystem: str
    name: str
    old_version: str
    new_version: str
    manifest: Path
    advisory_ids: Tuple[str, ...]
    skipped_reason: Optional[str] = None  # set when rewrite couldn't apply


def main(argv: Sequence[str]) -> int:
    from .cli import _configure_logging

    args = _parse_args(argv)
    _configure_logging(args.verbose)

    findings_rows = _load_findings(args)
    if findings_rows is None:
        return 2

    out_dir = _resolve_out_dir(args)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"raptor-sca fix --cve-only: cannot create output dir {out_dir}: {e}",
              file=sys.stderr)
        return 2

    advisory_filter = _parse_advisory_filter(args.fix)
    targets = _plan_targets(
        findings_rows,
        advisory_filter=advisory_filter,
        allow_major=args.allow_major,
    )
    if not targets:
        print("raptor-sca fix: no actionable upgrades — every vulnerable dep is "
              "either unfixed, already at the highest fix, or filtered out by "
              "--fix.", file=sys.stderr)
        return 0

    changes = _materialise_changes(
        targets,
        findings_rows,
        out_dir / "proposed",
        pin_only=args.pin_only,
    )

    # Per-change upgrade-compat risk signals (semver-major bumps,
    # dep-set churn). Cheap version-string heuristic always; the
    # network-gated dep-set diff fires only for online runs against
    # ecosystems we support (currently PyPI).
    compat_reports = _compute_compat_reports(
        changes, offline=args.offline,
        cache_root=Path(args.cache_root) if args.cache_root else None,
    )

    (out_dir / "changes.json").write_text(
        json.dumps(
            [_change_to_dict(c, compat_reports.get(_change_key(c)))
             for c in changes],
            indent=2,
        ),
        encoding="utf-8",
    )
    (out_dir / "changes.md").write_text(
        _render_changes_markdown(changes, compat_reports),
        encoding="utf-8",
    )

    applied = [c for c in changes if c.skipped_reason is None]
    skipped = [c for c in changes if c.skipped_reason is not None]
    extra = ""
    patch_path: Optional[Path] = None
    repo_root: Optional[Path] = None
    # ``--apply`` implies ``--git-patch``: you can't apply what wasn't
    # generated, and forcing operators to remember both flags is just
    # paperwork.
    want_patch = args.git_patch or args.apply
    if want_patch and applied:
        patch_path, repo_root = _emit_git_patch(applied, out_dir)
        if patch_path is not None:
            extra = (
                f"\nraptor-sca fix: upgrade.patch written to {patch_path}\n"
                f"          apply with: cd {repo_root} && "
                f"git apply {patch_path}"
            )
    print(f"raptor-sca fix: {len(applied)} change(s) applied, "
          f"{len(skipped)} skipped — proposed/ written to {out_dir}/proposed"
          + extra)

    if args.apply:
        from .patch_apply import apply_patch_to_target
        # Apply at the patch's repo root (computed by ``_emit_git_patch``
        # via .git-walk). When no patch was generated (no applicable
        # changes), the helper handles it as a graceful no-op.
        rc = apply_patch_to_target(
            repo_root if repo_root else Path.cwd(),
            patch_path,
            caller_label="raptor-sca fix --cve-only",
        )
        if rc != 0:
            return rc

    # ``--allow-cascade``: run the proposed manifest through the native
    # resolver to confirm it satisfies all peer constraints. Reports
    # success / conflict; when the resolver succeeds, the proposed
    # lockfile is captured alongside the manifest.
    if args.allow_cascade and applied:
        _run_cascade_validation(applied, out_dir)

    # ``--validate-against=<file>``: same shape as cascade but against
    # an externally-supplied manifest (Dependabot's PR).
    if args.validate_against:
        ext = Path(args.validate_against).resolve()
        _run_external_validation(ext, out_dir)

    # ``--format=pr-comment``: emit a separate GitHub-flavoured Markdown
    # rendering of the change set alongside changes.md.
    if args.format == "pr-comment":
        (out_dir / "changes.pr-comment.md").write_text(
            _render_pr_comment(changes), encoding="utf-8",
        )

    # ``--hash-pin``: optional second pass that walks .github/workflows
    # and replaces mutable refs with commit SHAs. Independent of the
    # CVE-driven plan above — even projects with no vuln findings can
    # benefit. Requires a target directory; with ``--findings`` only
    # we don't know where the workflows live.
    if args.hash_pin:
        from .hash_pin import hash_pin_workflows
        target_dir: Optional[Path] = None
        if args.target:
            target_dir = Path(args.target).resolve()
        else:
            # Fall back to a single common target if all findings agree.
            files = {Path(r["file"]).resolve()
                      for r in findings_rows
                      if isinstance(r.get("file"), str)}
            common = _common_target(files)
            target_dir = common
        if target_dir is None:
            print("raptor-sca fix: --hash-pin needs a target directory; "
                  "rerun with --target <repo>", file=sys.stderr)
        else:
            result = hash_pin_workflows(
                target_dir, write=args.hash_pin_write,
            )
            (out_dir / "hash-pin.json").write_text(
                json.dumps({
                    "changed_files": [str(p) for p in result.changed_files],
                    "changes": [
                        {"file": str(c.file), "line": c.line,
                          "action": c.action,
                          "old_ref": c.old_ref, "new_sha": c.new_sha}
                        for c in result.changes
                    ],
                    "skipped": [
                        {"file": str(f), "line": ln, "action": a,
                          "reason": r}
                        for f, ln, a, r in result.skipped
                    ],
                }, indent=2),
                encoding="utf-8",
            )
            verb = "rewrote" if args.hash_pin_write else "would rewrite"
            print(f"raptor-sca fix --cve-only --hash-pin: {verb} {len(result.changes)} "
                  f"ref(s) across {len(result.changed_files)} workflow file"
                  f"(s); {len(result.skipped)} skipped. Plan: "
                  f"{out_dir}/hash-pin.json")
    return 0


def _run_cascade_validation(
    applied: List["UpgradeChange"], out_dir: Path,
) -> None:
    """Per-ecosystem resolver pass over the proposed manifests.

    Groups applied changes by ecosystem; for each ecosystem, runs the
    matching resolver against the corresponding proposed manifest in
    ``out_dir/proposed``. Ecosystems are resolved in parallel via a
    thread pool — each resolver call sleeps on its sandbox subprocess,
    so threading buys real wallclock for polyglot upgrade plans
    (npm + PyPI + Go each ~5-10s; sequential = ~25s; parallel = the
    slowest one, ~10s). Same pattern as ``transitive._run_cascades_
    parallel``.

    Reports OK / conflict per ecosystem; the resolver's lockfile (when
    it produces one) is captured for follow-up consumers.
    """
    by_eco: Dict[str, List[UpgradeChange]] = defaultdict(list)
    for c in applied:
        by_eco[c.ecosystem].append(c)
    proposed_root = out_dir / "proposed"

    # Resolve eco_root per ecosystem first (sequential — pure path
    # manipulation, no I/O).
    work_items: List[Tuple[str, Path]] = []
    for eco, changes in by_eco.items():
        first_manifest = changes[0].manifest
        try:
            rel_parent = first_manifest.parent.relative_to(Path.cwd())
        except ValueError:
            rel_parent = Path(first_manifest.parent.name)
        eco_root = (proposed_root / rel_parent).resolve()
        if not eco_root.exists():
            eco_root = proposed_root
        work_items.append((eco, eco_root))

    summary = _validate_ecosystems_parallel(work_items, out_dir)

    (out_dir / "cascade.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8",
    )
    oks = sum(1 for s in summary if s["verdict"] == "ok")
    conflicts = sum(1 for s in summary if s["verdict"] == "conflict")
    print(f"raptor-sca fix --cve-only --allow-cascade: {oks} ecosystem(s) resolve "
          f"cleanly; {conflicts} have conflicts. Plan: "
          f"{out_dir}/cascade.json")


def _validate_ecosystems_parallel(
    work_items: List[Tuple[str, Path]], out_dir: Path,
) -> List[Dict[str, Any]]:
    """Dispatch resolver dry-run per ecosystem in parallel.

    Each thread calls one resolver subprocess inside its own sandbox
    session — no shared mutable state across threads. Returns
    summary rows in the SAME order as ``work_items`` (input order
    preservation makes diffs against the previous sequential output
    deterministic).

    Defensive: a buggy resolver subprocess that raises rather than
    returning a result fails just that ecosystem with verdict=
    "error"; other ecosystems still report. Matches the pattern in
    ``transitive._run_cascades_parallel``.
    """
    from concurrent.futures import ThreadPoolExecutor

    if not work_items:
        return []

    results: Dict[str, Dict[str, Any]] = {}
    with ThreadPoolExecutor(
        max_workers=max(1, len(work_items)),
        thread_name_prefix="sca-cascade-validate",
    ) as pool:
        futs = {
            pool.submit(_validate_one_ecosystem, eco, eco_root, out_dir): eco
            for eco, eco_root in work_items
        }
        for fut in futs:
            eco = futs[fut]
            try:
                results[eco] = fut.result()
            except Exception as e:                       # noqa: BLE001
                logger.warning(
                    "sca.update: cascade validation crashed for %s: %s",
                    eco, e,
                )
                results[eco] = {
                    "ecosystem": eco, "verdict": "error",
                    "reason": f"resolver thread crashed: {e}",
                }
    return [results[eco] for eco, _ in work_items]


def _validate_one_ecosystem(
    eco: str, eco_root: Path, out_dir: Path,
) -> Dict[str, Any]:
    """Per-ecosystem cascade body. Runs one resolver dry-run +
    captures its lockfile if present. Returns the summary row.
    """
    from .resolvers import get_resolver
    # Pass eco_root so multi-tool ecosystems (npm/yarn/pnpm,
    # pip/poetry, Maven/Gradle) pick the resolver matching the
    # project's actual lockfile/config.
    resolver = get_resolver(eco, project_dir=eco_root)
    if resolver is None:
        return {
            "ecosystem": eco, "verdict": "unsupported",
            "reason": "no resolver wrapper for ecosystem",
        }
    if not resolver.is_available():
        return {
            "ecosystem": eco, "verdict": "skipped",
            "reason": f"{eco} toolchain not in PATH",
        }
    result = resolver.dry_run(eco_root)
    row = {
        "ecosystem": eco,
        "verdict": "ok" if result.success else "conflict",
        "error": result.error,
    }
    if result.proposed_lockfile is not None:
        lockfile_dest = out_dir / f"cascade-{eco.lower()}.lock"
        try:
            lockfile_dest.write_bytes(result.proposed_lockfile)
        except OSError:
            pass
    return row


def _run_external_validation(manifest: Path, out_dir: Path) -> None:
    """Run the ecosystem's resolver against an externally-supplied
    manifest (e.g. Dependabot's PR). Detects the ecosystem from the
    filename."""
    from .resolvers import get_resolver
    eco = _detect_ecosystem_from_filename(manifest.name)
    if eco is None:
        print(f"raptor-sca fix --cve-only --validate-against: cannot detect ecosystem from "
              f"{manifest.name!r}; supported names: package.json, "
              f"requirements.txt, go.mod, Cargo.toml, ...", file=sys.stderr)
        return
    resolver = get_resolver(eco, project_dir=manifest.parent)
    if resolver is None:
        print(f"raptor-sca fix --cve-only --validate-against: no resolver wrapper for "
              f"{eco}", file=sys.stderr)
        return
    if not resolver.is_available():
        print(f"raptor-sca fix --cve-only --validate-against: {eco} toolchain not in PATH",
              file=sys.stderr)
        return
    result = resolver.dry_run(manifest.parent)
    (out_dir / "validate-against.json").write_text(
        json.dumps({
            "manifest": str(manifest),
            "ecosystem": eco,
            "verdict": "ok" if result.success else "conflict",
            "error": result.error,
        }, indent=2),
        encoding="utf-8",
    )
    verb = "validates" if result.success else "FAILS"
    print(f"raptor-sca fix --cve-only --validate-against: {manifest.name} {verb} via "
          f"{eco} resolver. Detail: {out_dir}/validate-against.json")


def _detect_ecosystem_from_filename(name: str) -> Optional[str]:
    if name == "package.json" or name == "package-lock.json":
        return "npm"
    if name.startswith("requirements") and name.endswith(".txt"):
        return "PyPI"
    if name == "pyproject.toml" or name == "Pipfile" or name == "poetry.lock":
        return "PyPI"
    if name == "go.mod" or name == "go.sum":
        return "Go"
    return None


def _render_pr_comment(changes: List["UpgradeChange"]) -> str:
    """GitHub-Markdown rendering of the change set, suitable for posting
    as a comment on a Dependabot PR.

    Uses collapsible <details> sections so the comment stays scannable
    when there are many changes.
    """
    applied = [c for c in changes if c.skipped_reason is None]
    skipped = [c for c in changes if c.skipped_reason is not None]
    out: List[str] = []
    out.append("## raptor-sca fix --cve-only — proposed plan")
    out.append("")
    out.append(f"- **{len(applied)} change(s) applied**")
    out.append(f"- {len(skipped)} skipped")
    out.append("")
    if applied:
        out.append("<details>")
        out.append("<summary>Applied changes</summary>")
        out.append("")
        out.append("| Ecosystem | Package | From | To | Advisories |")
        out.append("|---|---|---|---|---|")
        for c in applied:
            advs = ", ".join(c.advisory_ids) if c.advisory_ids else "—"
            out.append(
                f"| {c.ecosystem} | `{c.name}` | {c.old_version} | "
                f"{c.new_version} | {advs} |"
            )
        out.append("</details>")
        out.append("")
    if skipped:
        out.append("<details>")
        out.append("<summary>Skipped (with reason)</summary>")
        out.append("")
        for c in skipped:
            out.append(
                f"- `{c.ecosystem}:{c.name}` "
                f"({c.old_version} → {c.new_version}): "
                f"{c.skipped_reason}"
            )
        out.append("</details>")
    return "\n".join(out) + "\n"


def _common_target(files: set) -> Optional[Path]:
    """Best-effort common ancestor for hash-pin to find ``.github/``."""
    if not files:
        return None
    # Walk up from the first file; verify all others share the prefix.
    first = next(iter(files))
    cur = first.parent
    while cur != cur.parent:
        if all(cur in f.parents for f in files):
            return cur
        cur = cur.parent
    return None


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="raptor-sca fix --cve-only",
        description="CVE-driven upgrade planner.",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument(
        "--findings",
        help="findings.json from a prior `raptor-sca` run",
    )
    g.add_argument(
        "--target",
        help="run `raptor-sca <target>` to produce findings before planning",
    )
    p.add_argument("--out", help="output dir for proposed/ + changes.* "
                                 "(default: out/sca-fix-<UTC>/)")
    p.add_argument("--fix", help="comma-separated advisory IDs to fix; "
                                 "everything else is left alone")
    p.add_argument("--minimal", action="store_true", default=True,
                   help="(default) smallest fix above the installed version")
    p.add_argument("--allow-major", action="store_true",
                   help="allow upgrades that cross a major version boundary")
    p.add_argument("--pin-only", action="store_true",
                   help="only rewrite manifests where the dep is currently "
                        "pinned to an exact version")
    p.add_argument("--git-patch", action="store_true",
                   help="emit upgrade.patch alongside proposed/ — a "
                        "git-apply-compatible unified diff")
    p.add_argument("--apply", action="store_true",
                   help="after generating the patch, run ``git apply`` "
                        "to write the proposed manifest changes back to "
                        "the source tree. Implies --git-patch. Refuses "
                        "if the source tree isn't a git checkout (no "
                        "rollback path); the patch is still written so "
                        "operators can apply manually.")
    p.add_argument("--hash-pin", action="store_true",
                   help="resolve mutable git refs (e.g., GitHub Actions "
                        "``uses: org/action@v1``) to commit SHAs. "
                        "Mitigates the Trivy mutable-tag attack pattern. "
                        "Uses ``git ls-remote`` so it works without "
                        "GITHUB_TOKEN for public repos. Default: report "
                        "the rewrite plan; pass --hash-pin-write to "
                        "modify workflow files in place.")
    p.add_argument("--hash-pin-write", action="store_true",
                   help="with --hash-pin, write the pinned workflows "
                        "in place instead of just reporting the plan")
    p.add_argument("--allow-cascade", action="store_true",
                   help="when the proposed plan doesn't resolve cleanly, "
                        "invoke the language's native resolver "
                        "(npm/pip/go) and let it suggest additional "
                        "non-vulnerable peer bumps. Reports the cascade "
                        "as part of the plan; final resolution depends "
                        "on the resolver's verdict.")
    p.add_argument("--validate-against", metavar="MANIFEST",
                   help="validate an externally-supplied proposed "
                        "manifest (e.g. Dependabot's PR) by running the "
                        "ecosystem's resolver against it. Reports OK / "
                        "conflict / unresolvable + any findings the "
                        "proposed plan would introduce.")
    p.add_argument("--format", choices=["plain", "pr-comment"],
                   default="plain",
                   help="output format for the human-readable report. "
                        "``pr-comment`` emits GitHub-flavoured Markdown "
                        "with collapsible sections, suitable for posting "
                        "as a comment on a Dependabot PR.")
    p.add_argument("--offline", action="store_true",
                   help="when --target is used, run analyse with --offline")
    p.add_argument("--cache-root", help="cache root for analyse pre-pass")
    p.add_argument("--no-llm", action="store_true",
                   help="(accepted for orthogonality with `fix`; "
                        "this mode does not consult an LLM)")
    p.add_argument("-v", "--verbose", action="count", default=0)
    args = p.parse_args(argv)
    # ``--allow-cascade`` shells out to npm/pip/go which all need
    # network to query their registries (the sandbox routes them
    # through the egress proxy with a per-ecosystem allowlist).
    # ``--offline`` says "no network at the SCA level". Combining
    # them is operator confusion: the cascade resolver would always
    # fail to reach its registry. Reject up-front.
    if args.offline and args.allow_cascade:
        p.error("--offline and --allow-cascade are mutually exclusive: "
                "the cascade resolver shells out to npm/pip/go, all of "
                "which must reach their registry to resolve dependencies. "
                "Use one or the other.")
    return args


# ---------------------------------------------------------------------------
# Findings loading
# ---------------------------------------------------------------------------

def _load_findings(args: argparse.Namespace) -> Optional[List[Dict[str, Any]]]:
    if args.findings:
        path = Path(args.findings).resolve()
        if not path.exists():
            print(f"raptor-sca fix: findings file not found: {path}",
                  file=sys.stderr)
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"raptor-sca fix: cannot read {path}: {e}", file=sys.stderr)
            return None
        if not isinstance(data, list):
            print(f"raptor-sca fix: {path} is not a finding list",
                  file=sys.stderr)
            return None
        return data

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"raptor-sca fix --cve-only: target does not exist: {target}",
              file=sys.stderr)
        return None
    if not target.is_dir():
        print(f"raptor-sca fix --cve-only: target is not a directory: {target}",
              file=sys.stderr)
        return None

    # Run analyse internally, then read its findings.json.
    from .pipeline import RunOptions, run_sca
    pre_out = _resolve_out_dir(args, suffix="-prepass")
    pre_out.mkdir(parents=True, exist_ok=True)
    options = RunOptions(
        offline=args.offline,
        cache_root=Path(args.cache_root) if args.cache_root else None,
    )
    result = run_sca(target=target, output_dir=pre_out, options=options)
    return json.loads(result.findings_path.read_text(encoding="utf-8"))


def _resolve_out_dir(args: argparse.Namespace, *, suffix: str = "") -> Path:
    if args.out:
        base = Path(args.out).resolve()
        return base / suffix.lstrip("-") if suffix else base
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return Path("out") / f"sca-update-{ts}{suffix}"


def _parse_advisory_filter(value: Optional[str]) -> Optional[set]:
    if not value:
        return None
    return {tok.strip() for tok in value.split(",") if tok.strip()}


# ---------------------------------------------------------------------------
# Target selection
# ---------------------------------------------------------------------------

def _plan_targets(
    rows: List[Dict[str, Any]],
    *,
    advisory_filter: Optional[set],
    allow_major: bool,
) -> Dict[Tuple[str, str, str], "_PlanEntry"]:
    """Build ``(ecosystem, name, declared_in) → planned upgrade``.

    Same dep declared in two manifests gets two plan entries (one each)
    so they can land independently if the chosen target differs.
    """
    plans: Dict[Tuple[str, str, str], _PlanEntry] = {}
    for row in rows:
        if row.get("vuln_type") != "sca:vulnerable_dependency":
            continue
        sca = row.get("sca") or {}
        adv = sca.get("advisory") or {}
        adv_id = adv.get("id") if isinstance(adv, dict) else None
        aliases = adv.get("aliases") if isinstance(adv, dict) else []
        ids_for_filter = {adv_id, *(a for a in (aliases or [])
                                     if isinstance(a, str))} - {None}
        if advisory_filter is not None and not (
            ids_for_filter & advisory_filter
        ):
            continue
        ecosystem = sca.get("ecosystem")
        name = sca.get("name")
        installed = sca.get("version")
        fix = sca.get("fixed_version")
        manifest = row.get("file")
        if not (ecosystem and name and installed and fix and manifest):
            continue
        if not allow_major and _crosses_major(ecosystem, installed, fix):
            continue

        key = (ecosystem, name, manifest)
        entry = plans.get(key)
        if entry is None:
            plans[key] = _PlanEntry(
                ecosystem=ecosystem, name=name,
                installed=installed, target=fix,
                manifest=Path(manifest),
                advisory_ids=[adv_id] if adv_id else [],
            )
            continue
        # Multiple findings against the same (eco, name, manifest) →
        # pick the *highest* fix so the upgrade resolves them all.
        try:
            cmp = version_compare(ecosystem, fix, entry.target)
        except VersionError:
            cmp = 0
        if cmp > 0:
            entry.target = fix
        if adv_id and adv_id not in entry.advisory_ids:
            entry.advisory_ids.append(adv_id)
    return plans


@dataclass
class _PlanEntry:
    ecosystem: str
    name: str
    installed: str
    target: str
    manifest: Path
    advisory_ids: List[str]


def _crosses_major(ecosystem: str, installed: str, target: str) -> bool:
    """Heuristic: do the leading numeric segments differ?

    For ecosystems where the comparator understands "major" (semver,
    pep440), this is the right call. For unknown comparators we
    conservatively say no major crossing so upgrades aren't blocked
    silently.
    """
    inst_major = _leading_int(installed)
    tgt_major = _leading_int(target)
    if inst_major is None or tgt_major is None:
        return False
    return tgt_major != inst_major


def _leading_int(version: str) -> Optional[int]:
    m = re.match(r"^v?(\d+)", version.strip())
    if not m:
        return None
    return int(m.group(1))


# ---------------------------------------------------------------------------
# Manifest rewriters
# ---------------------------------------------------------------------------

def _materialise_changes(
    plans: Dict[Tuple[str, str, str], _PlanEntry],
    findings_rows: List[Dict[str, Any]],
    proposed_root: Path,
    *,
    pin_only: bool,
) -> List[UpgradeChange]:
    out: List[UpgradeChange] = []
    pin_styles = _pin_styles_by_finding(findings_rows)

    # Group plans by manifest so each file is only opened once.
    by_manifest: Dict[Path, List[_PlanEntry]] = defaultdict(list)
    for plan in plans.values():
        by_manifest[plan.manifest].append(plan)

    for manifest, plan_list in by_manifest.items():
        try:
            original = manifest.read_text(encoding="utf-8")
        except OSError as e:
            for plan in plan_list:
                out.append(_skip(plan, f"cannot read manifest: {e}"))
            continue

        text = original
        for plan in plan_list:
            pin_style = pin_styles.get(
                (plan.ecosystem, plan.name, str(manifest))
            )
            if pin_only and pin_style not in ("exact", None):
                out.append(_skip(plan, f"--pin-only set, current pin "
                                       f"is {pin_style!r}"))
                continue
            new_text, applied, reason = _rewrite_one(
                manifest, text, plan,
            )
            if applied:
                text = new_text
                out.append(UpgradeChange(
                    ecosystem=plan.ecosystem, name=plan.name,
                    old_version=plan.installed,
                    new_version=plan.target,
                    manifest=manifest,
                    advisory_ids=tuple(plan.advisory_ids),
                ))
            else:
                out.append(_skip(plan, reason or "rewriter found no match"))

        if text != original:
            try:
                rel = manifest.resolve().relative_to(Path.cwd())
            except ValueError:
                # Anchor on the manifest's name so absolute paths still
                # land somewhere sensible under proposed/.
                rel = Path(manifest.name)
            from ._atomic import atomic_write_text
            target = proposed_root / rel
            atomic_write_text(target, text)
    return out


def _pin_styles_by_finding(rows: List[Dict[str, Any]]) -> Dict[Tuple[str, str, str], str]:
    out: Dict[Tuple[str, str, str], str] = {}
    for row in rows:
        if row.get("vuln_type") != "sca:vulnerable_dependency":
            continue
        sca = row.get("sca") or {}
        key = (sca.get("ecosystem"), sca.get("name"), row.get("file"))
        if all(key) and "pin_style" in sca:
            out[key] = sca["pin_style"]      # type: ignore[index]
    return out


def _skip(plan: _PlanEntry, reason: str) -> UpgradeChange:
    return UpgradeChange(
        ecosystem=plan.ecosystem, name=plan.name,
        old_version=plan.installed, new_version=plan.target,
        manifest=plan.manifest,
        advisory_ids=tuple(plan.advisory_ids),
        skipped_reason=reason,
    )


def _rewrite_one(
    manifest: Path, text: str, plan: _PlanEntry,
) -> Tuple[str, bool, Optional[str]]:
    name = manifest.name
    suffix = manifest.suffix.lower()
    if name == "pom.xml":
        return _rewrite_pom_xml(text, plan)
    if name == "package.json":
        return _rewrite_package_json(text, plan)
    if name == "pyproject.toml":
        return _rewrite_pyproject_toml(text, plan)
    if name.startswith("requirements") and name.endswith(".txt"):
        return _rewrite_requirements_txt(text, plan)
    # NuGet write surfaces. Two file shapes — caller picks the
    # right one via ``plan.manifest`` (set by the planner to
    # match the dep's source-origin field).
    if name == "Directory.Packages.props":
        return _rewrite_via_registry(manifest, text, plan)
    if suffix in (".csproj", ".fsproj", ".vbproj"):
        return _rewrite_via_registry(manifest, text, plan)
    # Gradle write surface — libs.versions.toml. Inline
    # build.gradle / build.gradle.kts edits are NOT supported
    # by harden today (DSL rewrite is risky given Turing-complete
    # Groovy / Kotlin). The catalog covers modern projects which
    # is where most operator demand is.
    if name == "libs.versions.toml":
        return _rewrite_via_registry(manifest, text, plan)
    if _is_inline_install_file(manifest):
        return _rewrite_inline_install(text, plan)
    return text, False, f"no rewriter for {name}"


def _rewrite_via_registry(
    manifest: Path, text: str, plan: _PlanEntry,
) -> Tuple[str, bool, Optional[str]]:
    """Bridge to the ``packages/sca/rewriters/`` registry — used
    by NuGet CPM / csproj / Gradle catalog paths. The registry
    operates on file paths (it reads + atomic-writes the file
    itself), but ``_rewrite_one``'s contract is text-in / text-
    out + bool applied + reason. Adapt by:

      * Synthesise a single ``RewriteEdit`` from the plan.
      * Call the registry's dispatcher.
      * Read back the (possibly mutated) file content.

    For Gradle catalogs the locator needs a section prefix
    (``library:<alias>`` / ``version:<key>`` / ``plugin:<alias>``).
    Harden's plan doesn't carry source-origin metadata today;
    we default to ``library:<name>`` which covers the common
    case (catalog libraries with inline versions). version.ref-
    resolved entries fall through with ``not_found``; the bumper
    will route them correctly once it learns about the catalog
    layout (separate piece of work).
    """
    from .rewriters import RewriteEdit, rewrite as _rewrite

    if manifest.name == "libs.versions.toml":
        # Default locator: target the library entry directly.
        # When the catalog uses ``version.ref`` the rewriter
        # returns ``not_found``; an operator who hits this can
        # set the version.ref'd entry by hand or wait for the
        # bumper-side catalog routing.
        locator = f"library:{plan.name}"
    else:
        locator = plan.name

    edit = RewriteEdit(
        locator=locator,
        old_value=plan.installed,
        new_value=plan.target,
    )
    results = _rewrite(manifest, [edit])
    if not results:
        return text, False, f"no rewriter for {manifest.name}"
    r = results[0]
    if r.applied:
        # Reload the file content for the caller. The rewriter
        # already wrote atomically; this read is the canonical
        # post-state.
        try:
            new_text = manifest.read_text(encoding="utf-8")
        except OSError as e:
            return text, False, f"error: post-write read failed: {e}"
        return new_text, True, None
    return text, False, r.reason


def _is_inline_install_file(path: Path) -> bool:
    """True if this file is one whose ``RUN``/script lines we know how to
    rewrite via the inline-install path. Mirrors the discovery predicate
    in ``parsers/inline_installs.py``.
    """
    name = path.name
    if name in ("Dockerfile", "Containerfile"):
        return True
    if name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
        return True
    if path.suffix in (".dockerfile", ".sh", ".bash"):
        return True
    if name in ("devcontainer.json", ".devcontainer.json"):
        return True
    if path.suffix in (".yml", ".yaml"):
        parts = path.parts
        for j in range(len(parts) - 2):
            if parts[j] == ".github" and parts[j + 1] == "workflows":
                return True
    return False


# ----- pom.xml --------------------------------------------------------------

def _rewrite_pom_xml(
    text: str, plan: _PlanEntry,
) -> Tuple[str, bool, Optional[str]]:
    """Find the <dependency> block whose groupId+artifactId match and
    rewrite its <version>OLD</version> → <version>NEW</version>.

    Skipped (returns False) when the version uses a property reference
    (``${log4j.version}``) — properties are usually defined elsewhere
    in the file and we don't try to rewrite the property's value here.
    """
    if ":" not in plan.name:
        return text, False, "Maven coordinate missing groupId:artifactId"
    group, artifact = plan.name.split(":", 1)

    block_re = re.compile(
        r"(<(?:dependency|plugin|parent)\b[^>]*>"
        r"(?:(?!</(?:dependency|plugin|parent)>).)*?</(?:dependency|plugin|parent)>)",
        re.DOTALL,
    )
    out_text = text
    rewrote = False
    for m in block_re.finditer(text):
        block = m.group(1)
        if (f"<groupId>{group}</groupId>" not in block
                or f"<artifactId>{artifact}</artifactId>" not in block):
            continue
        if re.search(r"<version>\s*\$\{[^}]+\}\s*</version>", block):
            return text, False, ("Maven version uses a property reference; "
                                 "edit <properties> manually")
        new_block, n = re.subn(
            r"(<version>)\s*" + re.escape(plan.installed)
            + r"\s*(</version>)",
            rf"\g<1>{plan.target}\g<2>",
            block,
            count=1,
        )
        if n:
            out_text = out_text.replace(block, new_block, 1)
            rewrote = True
            break
    if not rewrote:
        return text, False, ("no <dependency>/<plugin> block matched "
                             f"{group}:{artifact}@{plan.installed}")
    return out_text, True, None


# ----- package.json ---------------------------------------------------------

def _rewrite_package_json(
    text: str, plan: _PlanEntry,
) -> Tuple[str, bool, Optional[str]]:
    """Replace the dep's spec preserving any leading ``^``/``~``/range
    operator the operator wrote.

    Operates on the raw text so trailing-newline / indentation
    conventions are preserved. The dep can live in any of
    ``dependencies`` / ``devDependencies`` / ``peerDependencies`` /
    ``optionalDependencies`` — we don't enforce which.
    """
    # Capture the value between the colon and the closing quote of the
    # spec. The `name` may need JSON-string escaping if it contains
    # special chars; for npm package names those are limited and
    # ``re.escape`` handles them.
    pat = re.compile(
        r'("' + re.escape(plan.name) + r'"\s*:\s*")'
        r"([^\"]*?)"
        r'(")'
    )
    rewrote = False
    new_text = text

    def _replace(m: re.Match) -> str:
        nonlocal rewrote
        prefix, current, suffix = m.group(1), m.group(2), m.group(3)
        new_spec = _bump_npm_spec(current, plan.installed, plan.target)
        if new_spec is None:
            return m.group(0)
        rewrote = True
        return f"{prefix}{new_spec}{suffix}"

    new_text, _ = pat.subn(_replace, text, count=1)
    if not rewrote:
        return text, False, "no matching spec found"
    return new_text, True, None


def _bump_npm_spec(current: str, installed: str, target: str) -> Optional[str]:
    """Compute the replacement spec.

    Preserves the operator's leading prefix (``^``, ``~``, ``>=``,
    blank). Returns ``None`` when the current spec is a tarball / git
    URL / npm-alias — those need manual review.
    """
    s = current.strip()
    if not s:
        return target
    if s.startswith(("git+", "git@", "git:", "github:", "bitbucket:",
                     "gitlab:", "gist:", "file:", "npm:")):
        return None
    if s.startswith(("http://", "https://")):
        return None
    if s in ("*", "x", "X", "latest"):
        return target
    for prefix in ("^", "~"):
        if s.startswith(prefix):
            return f"{prefix}{target}"
    if any(ch in s for ch in "<>=| "):
        # range / multi-bound — replace inline match if possible.
        return s.replace(installed, target) if installed in s else None
    return target


# ----- requirements.txt -----------------------------------------------------

def _rewrite_requirements_txt(
    text: str, plan: _PlanEntry,
) -> Tuple[str, bool, Optional[str]]:
    """Update the line(s) that pin ``name`` (PEP 503 normalised match)
    to the target version.

    Includes / pip flags / editable / URL specs are skipped. Commented
    lines (``# pkg==X``) are also rewritten when they pin a matching
    name+version — the leading ``#`` is preserved so the line stays
    commented, but the version is upgraded so an operator following
    the recipe gets the patched version.
    """
    norm = _normalise_pypi_name(plan.name)
    out_lines: List[str] = []
    rewrote = False
    for raw in text.splitlines(keepends=True):
        stripped = raw.strip()
        if (not stripped
                or stripped.startswith(("-r", "--requirement",
                                        "-c", "--constraint",
                                        "-e ", "--editable ",
                                        "--", "-i ", "-f "))):
            out_lines.append(raw)
            continue

        # Recognise commented lines and try the body for a match. The
        # leading ``#`` plus any following whitespace is captured so we
        # can put it back if we rewrite.
        comment_match = re.match(r"^(\s*#+\s*)(.*)$", stripped)
        if comment_match:
            comment_prefix = comment_match.group(1)
            body = comment_match.group(2).strip()
            if not body:
                out_lines.append(raw)
                continue
            line_value = re.split(r"\s+#", body, maxsplit=1)[0].strip()
        else:
            comment_prefix = ""
            line_value = re.split(r"\s+#", stripped, maxsplit=1)[0].strip()

        m = re.match(r"^([A-Za-z0-9_\-.]+)\s*([<>=!~]=?[^\s;]+)?", line_value)
        if not m:
            out_lines.append(raw)
            continue
        if _normalise_pypi_name(m.group(1)) != norm:
            out_lines.append(raw)
            continue
        if comment_prefix and not plan.installed:
            # Defensive: shouldn't happen — every plan has an installed
            # version. If somehow it doesn't, leave the line alone.
            out_lines.append(raw)
            continue
        # Preserve any range bounds (floor/ceiling) around the new exact
        # pin instead of collapsing them — they record the safe corridor
        # for future up/downgrades. Splicing on the match end keeps any
        # trailing PEP 508 marker (``; python_version >= ...``) intact.
        new_spec = _pypi_pin_preserving_bounds(m.group(2) or "", plan.target)
        new_inner = m.group(1) + new_spec + line_value[m.end():]
        new_line = f"{comment_prefix}{new_inner}" if comment_prefix else new_inner
        out_lines.append(raw.replace(stripped, new_line))
        rewrote = True
    if not rewrote:
        return text, False, "no matching line"
    return "".join(out_lines), True, None


def _normalise_pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------------------
# Inline install rewriter (Dockerfile / *.sh / .github/workflows/*.yml /
# devcontainer.json — anywhere a `pip install foo==X` line might live).
# ---------------------------------------------------------------------------

# Per-ecosystem regex for "an install command on this line." Matching
# means we'll consider substituting on the line; non-matching means we
# leave the line alone (don't accidentally rewrite a comment or a
# variable named like the dep).
_INLINE_INSTALL_CMD_RES = {
    "PyPI": re.compile(
        r"\b(?:python3?\s+-m\s+)?(?:pip3?|pipx|uv\s+pip)\s+install\b",
        re.IGNORECASE),
    "Debian": re.compile(r"\bapt(?:-get)?\s+install\b", re.IGNORECASE),
    "Red Hat": re.compile(r"\b(?:yum|dnf)\s+install\b", re.IGNORECASE),
    "Alpine": re.compile(r"\bapk\s+(?:add|install)\b", re.IGNORECASE),
    "npm": re.compile(
        r"\b(?:npm\s+(?:install|i|add)|yarn\s+add|pnpm\s+(?:add|install|i)"
        r"|npx|bunx|pnpm\s+dlx|yarn\s+dlx)\b",
        re.IGNORECASE),
    "Homebrew": re.compile(r"\bbrew\s+install\b", re.IGNORECASE),
    "Go": re.compile(r"\bgo\s+install\b", re.IGNORECASE),
    "Cargo": re.compile(r"\bcargo\s+install\b", re.IGNORECASE),
    "RubyGems": re.compile(r"\bgem\s+install\b", re.IGNORECASE),
    # ``dotnet add package <name> --version <X>`` /
    # ``nuget install <name> -Version <X>`` /
    # ``Install-Package <name> -Version <X>`` (PowerShell).
    "NuGet": re.compile(
        r"\b(?:dotnet\s+add\s+package|nuget\s+install|Install-Package)\b",
        re.IGNORECASE),
    # ``composer require <vendor/pkg>:<version>`` /
    # ``composer require <vendor/pkg>``.
    "Packagist": re.compile(r"\bcomposer\s+(?:require|update)\b",
                              re.IGNORECASE),
    # ``mvn install:install-file -DgroupId=… -DartifactId=… -Dversion=…``
    # is the canonical "install a JAR into a local repo" inline form.
    # ``mvn deploy:deploy-file`` uses the same -D switches and is
    # equally rewritable. Matched at the goal-name level so ad-hoc
    # variants (``./mvnw …``) still hit.
    "Maven": re.compile(
        r"\bmvn(?:w)?\s+(?:[-\w:]+\s+)*"
        r"(?:install:install-file|deploy:deploy-file)\b",
        re.IGNORECASE),
}


_INLINE_SHELL_SEP_RE = re.compile(r"&&|\|\||;|(?<!\|)\|(?!\|)")


def _inline_line_continues(raw: str) -> bool:
    """True if ``raw`` ends with a shell line-continuation ``\\``
    (ignoring the trailing newline / whitespace)."""
    return raw.rstrip().endswith("\\")


def _rewrite_inline_install(
    text: str, plan: _PlanEntry,
) -> Tuple[str, bool, Optional[str]]:
    """Rewrite the version of ``plan.name`` inside an inline-install file.

    Inline-install files are Dockerfile / Containerfile / ``*.sh`` /
    ``*.bash`` / ``.github/workflows/*.yml`` / ``devcontainer.json`` —
    anywhere ``pip install foo==X`` (or ``apt install foo=X``,
    ``npm install foo@X``, etc.) might live.

    Strategy:
      1. Walk the file physical line by line, tracking whether we are
         inside the *argument region* of a matching install command —
         a region that spans ``\\``-continuation lines, so a multi-line
         ``apt-get install -y \\`` … block with one package per line is
         covered, not just same-line installs.
      2. On a line carrying the install command, substitute within its
         same-line args. While inside the continued arg region, each
         package-on-its-own-line is substituted too.
      3. ``#`` comment lines inside a continuation are transparent
         (Docker strips them before the shell runs), so they neither
         terminate the region nor get rewritten. A shell separator
         (``&&`` / ``||`` / ``;`` / ``|``) ends the region — a new
         command starts there.
      4. Both pinned and unpinned forms are handled; an unpinned
         ``pip install pkg`` / continuation-line ``pkg`` is rewritten to
         the pinned form (``pkg==<target>`` / ``pkg=<target>`` /
         ``pkg@<target>`` per ecosystem).

    GHA YAML and devcontainer.json have richer structure (block
    scalars, JSON string fields) but ``run:`` block bodies and JSONC
    string values still parse correctly under line-level processing —
    the substitutions only fire on lines that contain an actual install
    command keyword or sit inside its continued args.
    """
    eco = plan.ecosystem
    cmd_re = _INLINE_INSTALL_CMD_RES.get(eco)
    if cmd_re is None:
        return text, False, (
            f"inline rewriter not yet wired for ecosystem {eco!r}"
        )

    sub_fn = _INLINE_SUB_FNS.get(eco)
    if sub_fn is None:
        return text, False, (
            f"inline rewriter has no substitution for {eco!r}"
        )

    out_lines: List[str] = []
    rewrote = False
    in_args = False   # inside a matching install command's continued args
    for raw in text.splitlines(keepends=True):
        m = cmd_re.search(raw)
        if m is not None:
            # Install command on this physical line: rewrite same-line args.
            prefix = raw[: m.end()]
            new_rest, hit = sub_fn(raw[m.end():], plan.name, plan.target)
            rewrote = rewrote or hit
            out_lines.append(prefix + new_rest)
            in_args = _inline_line_continues(raw)
            continue
        if in_args:
            if raw.lstrip().startswith("#"):
                # Docker strips ``#`` comment lines inside a RUN
                # continuation before the shell sees them, so they
                # neither carry a package nor break the continuation.
                out_lines.append(raw)
                continue
            sep = _INLINE_SHELL_SEP_RE.search(raw)
            if sep is not None:
                # A shell separator ends this install's args; a new
                # command starts. Only the portion before the separator
                # is still install args (usually just whitespace here).
                new_before, hit = sub_fn(
                    raw[: sep.start()], plan.name, plan.target)
                rewrote = rewrote or hit
                out_lines.append(new_before + raw[sep.start():])
                in_args = False
                continue
            # A package token on its own continuation line.
            new_line, hit = sub_fn(raw, plan.name, plan.target)
            rewrote = rewrote or hit
            out_lines.append(new_line)
            in_args = _inline_line_continues(raw)
            continue
        out_lines.append(raw)
    if not rewrote:
        return text, False, (
            f"name {plan.name!r} not found in inline {eco} installs"
        )
    return "".join(out_lines), True, None


_PYPI_CLAUSE_RE = re.compile(r"^\s*(===|==|>=|<=|~=|!=|>|<)\s*(.+?)\s*$")


def _pypi_pin_preserving_bounds(spec: str, target: str) -> str:
    """Return a PEP 440 specifier that pins to ``target`` while keeping
    any range bounds from ``spec`` as a record of the safe corridor.

    ``spec`` is the specifier text *after* the package name::

        >=2.0,<3.0  ->  >=2.0,==<target>,<3.0   (floor + ceiling kept)
        >=2.31.0    ->  >=2.31.0,==<target>      (downgrade floor kept)
        ==2.30.0    ->  ==<target>               (old exact pin replaced)
        ""/bare     ->  ==<target>

    Bounds (``>=`` ``>`` ``<`` ``<=`` ``!=``) are preserved; existing pin
    clauses (``==`` ``===`` ``~=``) are dropped and replaced by a single
    ``==<target>``. The floor lets a future ``degraded_safety`` downgrade
    know how far down is acceptable; the ceiling stops an auto-jump past
    a declared major. Assumes ``target`` satisfies the kept bounds —
    harden's selection honours the corridor (see ``_plan_one``).
    """
    lowers, uppers, excludes = [], [], []
    for part in spec.split(","):
        cm = _PYPI_CLAUSE_RE.match(part)
        if cm is None:
            continue
        op, ver = cm.group(1), cm.group(2)
        if op in (">=", ">"):
            lowers.append(f"{op}{ver}")
        elif op in ("<", "<="):
            uppers.append(f"{op}{ver}")
        elif op == "!=":
            excludes.append(f"{op}{ver}")
        # ==, ===, ~= are dropped — replaced by the ==target below.
    return ",".join(lowers + [f"=={target}"] + uppers + excludes)


def _inline_sub_pypi(
    text: str, name: str, new_version: str,
) -> Tuple[str, bool]:
    """``pip install foo==1.0`` / ``pip install 'foo>=2,<3'`` / ``foo``."""
    name_re = re.escape(name)
    # 1. Specifier form: ``pkg<spec>`` where <spec> is one or more
    #    comma-joined PEP 440 clauses. Capture the WHOLE spec so range
    #    bounds survive the pin (see _pypi_pin_preserving_bounds). ``,``
    #    is excluded from the version class so clauses split cleanly;
    #    ``;`` stays excluded to leave PEP 508 markers untouched.
    spec_re = re.compile(
        rf"(?<![A-Za-z0-9._-])({name_re})"
        # Horizontal whitespace only between clauses — ``\s`` would let
        # the trailing ``\s*`` swallow the line's newline into the spec.
        rf"((?:[ \t]*(?:===|==|>=|<=|~=|!=|>|<)[ \t]*[^\s\\;\"',]+[ \t]*,?)+)",
        re.IGNORECASE,
    )
    new_text, n = spec_re.subn(
        lambda m: m.group(1) + _pypi_pin_preserving_bounds(
            m.group(2), new_version),
        text, count=1,
    )
    if n > 0:
        return new_text, True
    # 2. Bare name (not part of another identifier or version-separated).
    bare = re.compile(
        rf"(?<![A-Za-z0-9._-])({name_re})(?![A-Za-z0-9._@/-])",
        re.IGNORECASE,
    )
    new_text, n = bare.subn(rf"\1=={new_version}", text)
    return (new_text, True) if n > 0 else (text, False)


def _inline_sub_eq_separated(
    text: str, name: str, new_version: str,
) -> Tuple[str, bool]:
    """Single-``=`` version separator (apt, apk)."""
    name_re = re.escape(name)
    pinned = re.compile(
        rf"(?<![A-Za-z0-9._-])({name_re})=([^\s\\,;\"']+)",
        re.IGNORECASE,
    )
    new_text, n = pinned.subn(rf"\1={new_version}", text)
    if n > 0:
        return new_text, True
    bare = re.compile(
        rf"(?<![A-Za-z0-9._-])({name_re})(?![A-Za-z0-9._@/=-])",
        re.IGNORECASE,
    )
    new_text, n = bare.subn(rf"\1={new_version}", text)
    return (new_text, True) if n > 0 else (text, False)


def _inline_sub_yum(
    text: str, name: str, new_version: str,
) -> Tuple[str, bool]:
    """RPM convention: ``pkg-version`` (version starts with a digit)."""
    name_re = re.escape(name)
    pinned = re.compile(
        rf"(?<![A-Za-z0-9._-])({name_re})-(\d[^\s\\,;\"']*)",
        re.IGNORECASE,
    )
    new_text, n = pinned.subn(rf"\1-{new_version}", text)
    if n > 0:
        return new_text, True
    bare = re.compile(
        rf"(?<![A-Za-z0-9._-])({name_re})(?![A-Za-z0-9._@/=-])",
        re.IGNORECASE,
    )
    new_text, n = bare.subn(rf"\1-{new_version}", text)
    return (new_text, True) if n > 0 else (text, False)


def _inline_sub_at_separated(
    text: str, name: str, new_version: str,
) -> Tuple[str, bool]:
    """``@``-separated version (npm scoped/plain, brew, Go modules).

    For scoped npm (``@anthropic-ai/claude-code@1.0``) the version
    separator is the LAST ``@``; the leading ``@scope/`` belongs to the
    name and must be preserved.
    """
    name_re = re.escape(name)
    pinned = re.compile(
        rf"(?<![A-Za-z0-9._-])({name_re})@([^\s\\,;\"']+)",
    )
    new_text, n = pinned.subn(rf"\1@{new_version}", text)
    if n > 0:
        return new_text, True
    bare = re.compile(
        rf"(?<![A-Za-z0-9._-])({name_re})(?![A-Za-z0-9._@/=-])",
    )
    new_text, n = bare.subn(rf"\1@{new_version}", text)
    return (new_text, True) if n > 0 else (text, False)


def _inline_sub_versioned_flag(
    text: str, name: str, new_version: str,
    *,
    version_flags: tuple,
) -> Tuple[str, bool]:
    """Multi-token version: ``cargo install ripgrep --version 14.1.0``.

    Three cases per command:
      1. Pkg name + existing ``--version <X>`` flag: replace the X token.
      2. Pkg name + no version flag: append ``--version <new>`` after
         the package name.
      3. Pkg name not present: no change.

    Operates on the rest-of-line text after the install-command match —
    so caller has already pinned us to a single command's args.
    """
    name_re = re.escape(name)
    # Case 1: ``<name> ... --version <X>`` (or ``-v <X>`` / ``--vers <X>``).
    # The flag may not be adjacent to the name; do a two-step scan.
    name_pattern = re.compile(
        rf"(?<![A-Za-z0-9._-])({name_re})(?![A-Za-z0-9._@/=-])",
        re.IGNORECASE,
    )
    if not name_pattern.search(text):
        return text, False
    # Look for an existing version flag anywhere in the args.
    flag_alt = "|".join(re.escape(f) for f in version_flags)
    flag_re = re.compile(
        rf"({flag_alt})\s+([^\s\\,;\"']+)",
    )
    m = flag_re.search(text)
    if m:
        # Replace the value token only.
        flag = m.group(1)
        return (
            text[:m.start()] + f"{flag} {new_version}" + text[m.end():],
            True,
        )
    # Case 2: append ``--version <new>`` after the package name.
    new_text = name_pattern.sub(
        rf"\1 --version {new_version}", text, count=1)
    return new_text, True


def _inline_sub_cargo(
    text: str, name: str, new_version: str,
) -> Tuple[str, bool]:
    return _inline_sub_versioned_flag(
        text, name, new_version,
        version_flags=("--version", "--vers"),
    )


def _inline_sub_gem(
    text: str, name: str, new_version: str,
) -> Tuple[str, bool]:
    return _inline_sub_versioned_flag(
        text, name, new_version,
        version_flags=("--version", "-v"),
    )


def _inline_sub_nuget(
    text: str, name: str, new_version: str,
) -> Tuple[str, bool]:
    """``dotnet add package Foo --version X`` /
    ``nuget install Foo -Version X`` /
    ``Install-Package Foo -Version X``."""
    return _inline_sub_versioned_flag(
        text, name, new_version,
        version_flags=("--version", "-Version", "-v"),
    )


def _inline_sub_composer(
    text: str, name: str, new_version: str,
) -> Tuple[str, bool]:
    """``composer require vendor/pkg:1.2.3`` — colon-separated.

    Composer doesn't pin via a separate ``--version`` flag; the version
    constraint is bundled into the package argument with a colon.
    """
    name_re = re.escape(name)
    pinned = re.compile(
        rf"(?<![A-Za-z0-9._-])({name_re}):([^\s\\,;\"']+)",
    )
    new_text, n = pinned.subn(rf"\1:{new_version}", text)
    if n > 0:
        return new_text, True
    bare = re.compile(
        rf"(?<![A-Za-z0-9._-])({name_re})(?![A-Za-z0-9._@/=:-])",
    )
    new_text, n = bare.subn(rf"\1:{new_version}", text)
    return (new_text, True) if n > 0 else (text, False)


def _inline_sub_maven(
    text: str, name: str, new_version: str,
) -> Tuple[str, bool]:
    """``mvn install:install-file -DgroupId=g -DartifactId=a -Dversion=X``.

    The OSV ecosystem uses ``groupId:artifactId`` as the dep name, so
    we split it and require BOTH ``-DgroupId=`` and ``-DartifactId=``
    to match before bumping ``-Dversion=``. Anything less risks
    rewriting an unrelated invocation that happens to share one
    coordinate.

    Single ``=`` between flag and value is the common convention; the
    space-separated form (``-Dversion 1.0``) is rare and not handled
    — operators using it can fall back to ``--git-patch`` and edit by
    hand.
    """
    if ":" not in name:
        return text, False
    group, artifact = name.split(":", 1)
    g_re = re.escape(group)
    a_re = re.escape(artifact)
    # Both -DgroupId and -DartifactId must be present in the args
    # block; quoting tolerated.
    has_group = re.search(
        rf'-DgroupId\s*=\s*["\']?{g_re}["\']?(?![A-Za-z0-9._-])',
        text)
    has_artifact = re.search(
        rf'-DartifactId\s*=\s*["\']?{a_re}["\']?(?![A-Za-z0-9._-])',
        text)
    if not (has_group and has_artifact):
        return text, False
    version_re = re.compile(
        r'(-Dversion\s*=\s*["\']?)([^\s\\,;"\']+)(["\']?)',
    )
    new_text, n = version_re.subn(
        rf'\g<1>{new_version}\g<3>', text, count=1,
    )
    return (new_text, True) if n > 0 else (text, False)


_INLINE_SUB_FNS: Dict[str, Any] = {
    "PyPI": _inline_sub_pypi,
    "Debian": _inline_sub_eq_separated,
    "Alpine": _inline_sub_eq_separated,
    "Red Hat": _inline_sub_yum,
    "npm": _inline_sub_at_separated,
    "Homebrew": _inline_sub_at_separated,
    "Go": _inline_sub_at_separated,
    "Cargo": _inline_sub_cargo,
    "RubyGems": _inline_sub_gem,
    "NuGet": _inline_sub_nuget,
    "Packagist": _inline_sub_composer,
    "Maven": _inline_sub_maven,
}


# ----- pyproject.toml -------------------------------------------------------

def _rewrite_pyproject_toml(
    text: str, plan: _PlanEntry,
) -> Tuple[str, bool, Optional[str]]:
    """Best-effort string-level rewrite covering PEP 621 dep lists and
    Poetry-style ``name = "spec"`` lines.

    Keeps the original spec prefix when present (``^``, ``~``); falls
    back to ``==target`` for hard pins.
    """
    norm = _normalise_pypi_name(plan.name)

    # 1. Poetry-flavoured ``name = "..."`` form.
    poetry_re = re.compile(
        r'^([ \t]*)("?)([A-Za-z0-9_\-.]+)\2\s*=\s*"([^"]*)"',
        re.MULTILINE,
    )
    poetry_hit = False

    def _poetry_sub(m: re.Match) -> str:
        nonlocal poetry_hit
        if _normalise_pypi_name(m.group(3)) != norm:
            return m.group(0)
        new_spec = _bump_npm_spec(m.group(4), plan.installed, plan.target)
        if new_spec is None:
            return m.group(0)
        poetry_hit = True
        return (f"{m.group(1)}{m.group(2)}{m.group(3)}{m.group(2)} "
                f'= "{new_spec}"')

    new_text = poetry_re.sub(_poetry_sub, text)

    # 2. PEP 621 list form: each entry is a quoted PEP 508 string.
    pep508_re = re.compile(r'"([A-Za-z0-9_\-.]+)\s*([<>=!~][^"]*)"')

    def _pep508_sub(m: re.Match) -> str:
        if _normalise_pypi_name(m.group(1)) != norm:
            return m.group(0)
        return f'"{m.group(1)}=={plan.target}"'

    new_text = pep508_re.sub(_pep508_sub, new_text)

    if new_text == text:
        return text, False, "no matching pyproject entry"
    return new_text, True, None


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------

def _find_repo_root(start: Path, *, max_walk: int = 20) -> Path:
    """Walk up looking for a ``.git`` entry; return that directory.

    Falls back to ``start`` after ``max_walk`` levels — enough to find
    a repo root in any sane layout without unbounded ascent.
    """
    cur = start
    for _ in range(max_walk):
        if (cur / ".git").exists():
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return start


def _emit_git_patch(
    applied: List[UpgradeChange], out_dir: Path,
) -> Tuple[Optional[Path], Optional[Path]]:
    """Write a git-apply-compatible unified diff for every applied
    change. Paths inside the patch are relative to the longest common
    ancestor of the touched manifests so ``git apply`` from that
    ancestor lands them correctly.

    Returns ``(patch_path, repo_root_for_apply)`` or ``(None, None)``
    when there's nothing patchable.
    """
    if not applied:
        return None, None

    # Gather (manifest_resolved, proposed_in_out_dir) pairs. Multiple
    # findings against the same manifest collapse to a single pair —
    # otherwise the same hunks would be emitted N times in the patch
    # and ``git apply`` would re-apply (or warn).
    pairs: List[Tuple[Path, Path]] = []
    seen_manifests: set = set()
    for change in applied:
        manifest = change.manifest.resolve()
        if manifest in seen_manifests:
            continue
        seen_manifests.add(manifest)
        try:
            rel = manifest.relative_to(Path.cwd())
        except ValueError:
            rel = Path(manifest.name)
        proposed = (out_dir / "proposed" / rel).resolve()
        if not proposed.exists():
            # Same fallback path the rewriter uses when the manifest
            # lives outside cwd (rare).
            proposed = (out_dir / "proposed" / manifest.name).resolve()
        if proposed.exists():
            pairs.append((manifest, proposed))

    if not pairs:
        return None, None

    # Find the right base for patch paths. ``git apply`` matches the
    # ``a/<path>`` and ``b/<path>`` segments against the index, so the
    # patch must be rooted at the repo root — not at the longest common
    # ancestor of the manifests, which may be a subdirectory. Walk up
    # from the LCP looking for a ``.git`` entry; fall back to the LCP
    # if no repo is found.
    lcp = Path(os.path.commonpath([str(p[0].parent) for p in pairs]))
    repo_root = _find_repo_root(lcp)

    diff_lines: List[str] = []
    for original, proposed in pairs:
        rel = original.relative_to(repo_root)
        try:
            old = original.read_text(encoding="utf-8").splitlines(keepends=True)
        except OSError:
            continue
        try:
            new = proposed.read_text(encoding="utf-8").splitlines(keepends=True)
        except OSError:
            continue
        # Header line (``diff --git a/x b/x``) makes ``git apply``
        # happy and shows up cleanly in code-review tooling.
        diff_lines.append(f"diff --git a/{rel} b/{rel}\n")
        diff_lines.extend(difflib.unified_diff(
            old, new,
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        ))
        if diff_lines and not diff_lines[-1].endswith("\n"):
            diff_lines.append("\n")

    if not diff_lines:
        return None, None
    patch_path = out_dir / "upgrade.patch"
    patch_path.write_text("".join(diff_lines), encoding="utf-8")
    return patch_path, repo_root


def _change_to_dict(
    c: UpgradeChange,
    compat: "Optional[Any]" = None,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "ecosystem": c.ecosystem,
        "name": c.name,
        "old_version": c.old_version,
        "new_version": c.new_version,
        "manifest": str(c.manifest),
        "advisory_ids": list(c.advisory_ids),
        "skipped_reason": c.skipped_reason,
    }
    if compat is not None and compat.risks:
        out["compat_risks"] = [
            {"kind": r.kind, "severity": r.severity, "detail": r.detail}
            for r in compat.risks
        ]
        out["compat_overall_severity"] = compat.overall_severity
    return out


def _change_key(c: UpgradeChange) -> Tuple[str, str, str, str]:
    """Stable identity for a change so multiple manifests bumping the
    same dep share the same compat report (the risk is per X→Y, not
    per file)."""
    return (c.ecosystem, c.name.lower(),
            c.old_version, c.new_version)


def _compute_compat_reports(
    changes: Iterable[UpgradeChange],
    *,
    offline: bool,
    cache_root: "Optional[Path]" = None,
) -> Dict[Tuple[str, str, str, str], "Any"]:
    """Run the api-compat heuristic over every applied change.

    Returns a map of ``_change_key(c) -> UpgradeCompatReport``.
    Pure version-string analysis (semver bump) is always available;
    requires_dist-diff is gated on having an HttpClient (skipped in
    ``--offline``). Only PyPI is wired today; other ecosystems pass
    through with empty reports.
    """
    from .api_compat import check_pypi_api_compat

    out: Dict[Tuple[str, str, str, str], Any] = {}
    seen_keys: set = set()
    http = None
    cache = None
    if not offline:
        try:
            from core.json import JsonCache

            from . import SCA_CACHE_ROOT, default_client
            http = default_client()
            cache = JsonCache(root=cache_root or SCA_CACHE_ROOT)
        except Exception:                             # noqa: BLE001
            logger.debug("api-compat: HttpClient setup failed; "
                         "running with semver heuristic only",
                         exc_info=True)
            http = None
            cache = None

    for c in changes:
        if c.skipped_reason is not None:
            continue
        key = _change_key(c)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        if c.ecosystem == "PyPI":
            out[key] = check_pypi_api_compat(
                c.name, c.old_version, c.new_version,
                http=http, cache=cache,
            )
        else:
            # Other ecosystems: only the version-string heuristic is
            # meaningful, but the per-ecosystem semver convention
            # differs (npm uses semver strictly; Maven doesn't; Cargo
            # does). Run the PyPI helper without HTTP — it computes
            # the semver risk from version strings alone, which IS
            # universally meaningful enough to surface.
            out[key] = check_pypi_api_compat(
                c.name, c.old_version, c.new_version,
                http=None, cache=None,
            )
    return out


def _render_changes_markdown(
    changes: Iterable[UpgradeChange],
    compat_reports: "Optional[Dict[Tuple[str, str, str, str], Any]]" = None,
) -> str:
    applied = [c for c in changes if c.skipped_reason is None]
    skipped = [c for c in changes if c.skipped_reason is not None]
    parts: List[str] = ["# raptor-sca fix --cve-only — proposed changes", ""]
    parts.append(f"- Applied: **{len(applied)}**")
    parts.append(f"- Skipped: **{len(skipped)}**")
    parts.append("")
    if applied:
        parts.append("## Applied")
        parts.append("")
        parts.append(
            "| Ecosystem | Name | Old → New | Manifest | Advisories | "
            "Compat |"
        )
        parts.append("|---|---|---|---|---|---|")
        for c in applied:
            compat_cell = "—"
            if compat_reports is not None:
                rep = compat_reports.get(_change_key(c))
                if rep is not None and rep.risks:
                    compat_cell = (
                        f"**{rep.overall_severity}** "
                        f"({len(rep.risks)} signal"
                        f"{'s' if len(rep.risks) > 1 else ''})"
                    )
            parts.append(
                f"| {c.ecosystem} | {c.name} | {c.old_version} → "
                f"{c.new_version} | `{c.manifest}` | "
                f"{', '.join(c.advisory_ids) or '—'} | {compat_cell} |"
            )
        parts.append("")
        # Detail block for any change with non-empty compat risks.
        risky = []
        if compat_reports is not None:
            seen = set()
            for c in applied:
                key = _change_key(c)
                if key in seen:
                    continue
                seen.add(key)
                rep = compat_reports.get(key)
                if rep is not None and rep.risks:
                    risky.append((c, rep))
        if risky:
            parts.append("### Upgrade-compat risk detail")
            parts.append("")
            parts.append(
                "Heuristic signals that an upgrade may break the build "
                "or surface compatibility regressions. Review release "
                "notes before merging changes flagged ``high``."
            )
            parts.append("")
            for c, rep in risky:
                parts.append(
                    f"**{c.ecosystem}:{c.name}** "
                    f"({c.old_version} → {c.new_version})"
                )
                for r in rep.risks:
                    parts.append(f"- _{r.severity}_ — {r.detail}")
                parts.append("")
    if skipped:
        parts.append("## Skipped")
        parts.append("")
        for c in skipped:
            parts.append(
                f"- **{c.ecosystem}:{c.name}** "
                f"({c.old_version} → {c.new_version}, `{c.manifest}`): "
                f"{c.skipped_reason}"
            )
        parts.append("")
    return "\n".join(parts)


__all__ = ["UpgradeChange", "main"]
