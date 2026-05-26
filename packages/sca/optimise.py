"""``raptor-sca fix`` — scan + fix CVEs + pin unpinned deps in one pass.

Superset of ``fix --cve-only``:

1. Runs the full analyse pipeline against the target.
2. Plans CVE-fix upgrades (same logic as ``fix --cve-only``).
3. Plans pinning for unpinned / loose-pinned deps that have no CVEs
   (hygiene-only).  Uses the lockfile-resolved version when available,
   otherwise the version string from the manifest.
4. Materialises all changes through the existing per-ecosystem rewriters.

The result is a ``proposed/`` tree of rewritten manifests where every
dep is pinned to an exact, CVE-free version — as close to "perfect" as
we can get without running language-native resolvers.

Outputs (under ``--out``):

    proposed/<relative-path>   rewritten manifests
    changes.json               structured change list
    changes.md                 human-readable summary
    findings.json              full analyse output (from prepass)
    report.md                  full analyse report (from prepass)
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .update import (
    UpgradeChange,
    _PlanEntry,
    _change_to_dict,
    _emit_git_patch,
    _materialise_changes,
    _plan_targets,
    _rewrite_one,
)

logger = logging.getLogger(__name__)


def main(argv: Sequence[str]) -> int:
    from .cli import _configure_logging

    args = _parse_args(argv)
    _configure_logging(args.verbose)

    if args.apply and args.out:
        print("raptor-sca fix: --apply and --out are mutually exclusive",
              file=sys.stderr)
        return 2

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"raptor-sca fix: target does not exist: {target}",
              file=sys.stderr)
        return 2
    if not target.is_dir():
        print(f"raptor-sca fix: target is not a directory: {target}",
              file=sys.stderr)
        return 2

    out_dir = _resolve_out_dir(args.out)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"raptor-sca fix: cannot create output dir {out_dir}: {e}",
              file=sys.stderr)
        return 2

    # ---- Phase 1: analyse ---------------------------------------------------
    from .pipeline import RunOptions, run_sca

    options = RunOptions(
        offline=args.offline,
        no_cache=args.no_cache,
        cache_root=Path(args.cache_root) if args.cache_root else None,
        enable_kev=True,
        enable_epss=True,
        enable_reachability=True,
        enable_supply_chain=True,
        # ``fix`` never uses the scan-phase LLM stages: triage just
        # ranks findings (we apply all of them regardless), and the
        # behavioural-review stages enrich findings we don't act on.
        # Always off here — saves ~7s LLM-client init + variable
        # per-finding cost on every scan.
        enable_llm_review=False,
        enable_triage=False,
        # ``--llm-inline-installs`` is opt-in: an LLM sweep over
        # Dockerfiles / shell / GHA workflow ``run:`` blocks to find
        # deps the mechanical parser missed. Only useful for ``fix``
        # when the operator suspects coverage gaps; off by default
        # because of the per-file LLM cost.
        enable_llm_inline_installs=(
            args.llm_inline_installs and not args.no_llm
        ),
        # Propagate ``--include-commented`` so commented-line
        # findings flow through to the planner + rewriter. The
        # rewriter preserves the ``#`` prefix; only the version
        # gets tightened.
        include_commented=args.include_commented,
    )
    try:
        result = run_sca(target=target, output_dir=out_dir, options=options)
    except Exception:
        logger.exception("raptor-sca fix: analyse prepass failed")
        return 3

    findings_rows: List[Dict[str, Any]] = json.loads(
        result.findings_path.read_text(encoding="utf-8"),
    )

    # ---- Phase 2: plan CVE fixes --------------------------------------------
    vuln_plans = _plan_targets(
        findings_rows,
        advisory_filter=None,
        allow_major=args.allow_major,
    )

    # Detect CVE fixes blocked by major-version boundary.
    major_blocked: Dict[Tuple[str, str, str], _PlanEntry] = {}
    if not args.allow_major:
        all_vuln = _plan_targets(
            findings_rows, advisory_filter=None, allow_major=True,
        )
        major_blocked = {
            k: v for k, v in all_vuln.items() if k not in vuln_plans
        }

    # ---- Phase 3: plan hygiene pins -----------------------------------------
    hygiene_plans = _plan_hygiene_pins(findings_rows, vuln_plans)

    # ---- Phase 3a: detect GHA-action-ref drift (independent of pins) -------
    has_gha_drift = any(
        isinstance(r, dict)
        and r.get("vuln_type") == "sca:supply_chain:gha_action_ref_drift"
        for r in findings_rows
    )
    do_hash_pin = has_gha_drift and not args.no_hash_pin

    if (not vuln_plans and not hygiene_plans and not major_blocked
            and not do_hash_pin):
        print("raptor-sca fix: nothing to do — all deps are pinned and "
              "CVE-free.", file=sys.stderr)
        return 0

    # ---- Phase 3b: LLM impact analysis for major-blocked CVEs -----------
    llm_approved: set = set()
    llm_verdicts: Dict[Tuple[str, str, str], Any] = {}
    if major_blocked and not args.no_llm:
        llm_approved, llm_verdicts = _analyze_major_bumps(
            major_blocked, vuln_plans, target,
        )

    # Default: plan only. --apply writes in-place, --out writes proposed/.
    if not args.apply and not args.out:
        _print_dry_run(vuln_plans, hygiene_plans, major_blocked,
                       llm_approved=llm_approved, llm_verdicts=llm_verdicts)
        if do_hash_pin:
            hp_summary = _run_hash_pin(target, out_dir, write=False)
            if hp_summary:
                print(hp_summary)
        # Exit 1 when CVEs remain unresolved (blocked by major version).
        # CI can use this to detect "needs attention".
        return 1 if major_blocked else 0

    if args.apply:
        proposed_root = out_dir / "_apply_staging"
    else:
        proposed_root = out_dir / "proposed"

    # ---- Phase 4: materialise all changes -----------------------------------
    import os
    saved_cwd = os.getcwd()
    os.chdir(str(target))
    all_plans = {**vuln_plans, **hygiene_plans}
    try:
        changes = _materialise_changes(
            all_plans,
            findings_rows,
            proposed_root,
            pin_only=False,
        )
    finally:
        os.chdir(saved_cwd)

    # Second pass: retry hygiene plans that _materialise_changes couldn't
    # apply (bare names with no version operator).
    hygiene_keys = set(hygiene_plans.keys())
    skipped_hygiene = [
        c for c in changes
        if c.skipped_reason is not None
        and (c.ecosystem, c.name, str(c.manifest)) in hygiene_keys
    ]
    if skipped_hygiene:
        retry_plans = {
            (c.ecosystem, c.name, str(c.manifest)): hygiene_plans[
                (c.ecosystem, c.name, str(c.manifest))
            ]
            for c in skipped_hygiene
        }
        retry_changes = _materialise_pin_changes(
            retry_plans, proposed_root, target=target,
        )
        retry_succeeded = {
            (c.ecosystem, c.name, str(c.manifest))
            for c in retry_changes
            if c.skipped_reason is None
        }
        changes = [
            c for c in changes
            if (c.ecosystem, c.name, str(c.manifest)) not in retry_succeeded
        ] + [c for c in retry_changes if c.skipped_reason is None]
        existing = {(c.ecosystem, c.name, str(c.manifest)) for c in changes}
        changes += [
            c for c in retry_changes
            if c.skipped_reason is not None
            and (c.ecosystem, c.name, str(c.manifest)) not in existing
        ]

    applied = [c for c in changes if c.skipped_reason is None]
    skipped = [c for c in changes if c.skipped_reason is not None]
    vuln_applied = [c for c in applied if c.advisory_ids]
    pin_applied = [c for c in applied if not c.advisory_ids]

    # --apply: copy staged files back over the originals.
    if args.apply and applied:
        _apply_in_place(proposed_root, target)
        import shutil
        shutil.rmtree(proposed_root, ignore_errors=True)

    (out_dir / "changes.json").write_text(
        json.dumps([_change_to_dict(c) for c in changes], indent=2),
        encoding="utf-8",
    )
    (out_dir / "changes.md").write_text(
        _render_optimise_markdown(changes), encoding="utf-8",
    )

    extra = ""
    if args.git_patch and applied:
        patch_path, repo_root = _emit_git_patch(applied, out_dir)
        if patch_path is not None:
            extra = (
                f"\nraptor-sca fix: upgrade.patch written to {patch_path}\n"
                f"             apply with: cd {repo_root} && "
                f"git apply {patch_path}"
            )

    if do_hash_pin:
        hp_summary = _run_hash_pin(target, out_dir, write=args.apply)
        if hp_summary:
            extra += "\n" + hp_summary

    if major_blocked:
        n = len(major_blocked)
        if llm_verdicts:
            print(f"\nraptor-sca fix: {n} CVE fix(es) need major-version bumps "
                  f"(LLM: breaking changes) — re-run with --allow-major "
                  f"to apply anyway", file=sys.stderr)
        else:
            print(f"\nraptor-sca fix: {n} CVE fix(es) need major-version bumps "
                  f"— re-run with --allow-major", file=sys.stderr)

    if args.apply:
        print(f"raptor-sca fix: {len(vuln_applied)} CVE fix(es), "
              f"{len(pin_applied)} pin(s) applied in-place, "
              f"{len(skipped)} skipped" + extra)
    else:
        print(f"raptor-sca fix: {len(vuln_applied)} CVE fix(es), "
              f"{len(pin_applied)} pin(s), "
              f"{len(skipped)} skipped — written to {proposed_root}"
              + extra)
    return 1 if major_blocked else 0


# ---------------------------------------------------------------------------
# Hygiene → pin planning
# ---------------------------------------------------------------------------

_HYGIENE_PIN_KINDS = frozenset({"unpinned_dependency", "loose_pin"})


def _plan_hygiene_pins(
    rows: List[Dict[str, Any]],
    vuln_plans: Dict[Tuple[str, str, str], _PlanEntry],
) -> Dict[Tuple[str, str, str], _PlanEntry]:
    """Plan exact-pin rewrites for deps with hygiene findings.

    Skips deps that already have a CVE-fix plan (those are handled by
    the vuln planner which picks a safe target version).  For the rest,
    the "target" is the version already installed — we're just tightening
    the pin style, not changing the version.

    Acts on three hygiene kinds from non-lockfile manifests:

      - ``unpinned_dependency`` — pin to current installed version
      - ``loose_pin`` — tighten range to current installed version
      - ``cross_manifest_inconsistency`` — find every manifest that
        pins this ``(ecosystem, name)``, pick the highest version
        among them, and pin all of them to that version. This makes
        ``fix`` actually reconcile the divergence; without this case
        operators would see the finding repeatedly without an
        automated path to clear it.
    """
    plans: Dict[Tuple[str, str, str], _PlanEntry] = {}

    # Pre-pass: build a (ecosystem, name) → [(manifest, version), …]
    # index across ALL findings. Cross-manifest reconciliation needs
    # this to enumerate every place the dep appears, not just the
    # one manifest the cross_manifest_inconsistency finding points at.
    all_dep_locations: Dict[Tuple[str, str], List[Tuple[str, str]]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        sca = row.get("sca") or {}
        eco = sca.get("ecosystem")
        nm = sca.get("name")
        ver = sca.get("version")
        mf = row.get("file")
        if not (eco and nm and ver and mf):
            continue
        if sca.get("is_lockfile"):
            continue
        all_dep_locations.setdefault((eco, nm), []).append((mf, ver))

    for row in rows:
        if not isinstance(row, dict):
            continue
        vt = row.get("vuln_type", "")
        kind = vt.removeprefix("sca:hygiene:")
        if kind not in _HYGIENE_PIN_KINDS and kind != "cross_manifest_inconsistency":
            continue

        sca = row.get("sca") or {}
        ecosystem = sca.get("ecosystem")
        name = sca.get("name")
        version = sca.get("version")
        manifest = row.get("file")

        if not (ecosystem and name and version and manifest):
            continue
        if sca.get("is_lockfile"):
            continue

        if kind == "cross_manifest_inconsistency":
            # Look up every manifest that pins this (eco, name); plan
            # an update to all of them, targeting the highest version
            # currently in use across the workspace.
            locations = all_dep_locations.get((ecosystem, name), [])
            if len(locations) < 2:
                # Defensive — finding shouldn't fire for single-manifest
                # cases, but if it does there's nothing to reconcile.
                continue
            target_version = _highest_version(
                v for (_, v) in locations
            ) or version
            for (loc_manifest, _loc_ver) in locations:
                key = (ecosystem, name, loc_manifest)
                if key in vuln_plans or key in plans:
                    continue
                plans[key] = _PlanEntry(
                    ecosystem=ecosystem,
                    name=name,
                    # ``installed`` is whatever this manifest pins
                    # today; the rewriter uses (installed → target).
                    installed=next(
                        (v for (m, v) in locations
                         if m == loc_manifest),
                        version,
                    ),
                    target=target_version,
                    manifest=Path(loc_manifest),
                    advisory_ids=[],
                )
            continue

        key = (ecosystem, name, manifest)
        if key in vuln_plans:
            continue
        if key in plans:
            continue

        plans[key] = _PlanEntry(
            ecosystem=ecosystem,
            name=name,
            installed=version,
            target=version,
            manifest=Path(manifest),
            advisory_ids=[],
        )

    # Cross-manifest CVE propagation: if a dep at the same
    # (ecosystem, name, installed_version) has a CVE-fix target in
    # another manifest, adopt it here too.  This handles the case
    # where offline/cache misses cause the vuln finding to appear for
    # one copy of the dep but not another.
    vuln_by_dep: Dict[Tuple[str, str, str], _PlanEntry] = {}
    for plan in vuln_plans.values():
        dep_key = (plan.ecosystem, plan.name, plan.installed)
        existing = vuln_by_dep.get(dep_key)
        if existing is None or plan.target > existing.target:
            vuln_by_dep[dep_key] = plan

    for key, plan in plans.items():
        dep_key = (plan.ecosystem, plan.name, plan.installed)
        vuln_match = vuln_by_dep.get(dep_key)
        if vuln_match is not None:
            plan.target = vuln_match.target
            plan.advisory_ids = list(vuln_match.advisory_ids)

    return plans


def _run_hash_pin(
    target: Path, out_dir: Path, *, write: bool,
) -> Optional[str]:
    """Rewrite ``.github/workflows/*.yml`` ``uses:`` refs to commit
    SHAs. Writes a ``hash-pin.json`` artefact alongside the run's
    other outputs. Returns a one-line human-readable summary, or
    ``None`` when there was nothing to do.

    Shared between plan-only / --apply / --out modes:
      - plan-only and ``--out``: ``write=False`` (rewrite plan only)
      - ``--apply``: ``write=True`` (in-place rewrite of workflow YAMLs)
    """
    from .hash_pin import hash_pin_workflows
    hp_result = hash_pin_workflows(target, write=write)
    (out_dir / "hash-pin.json").write_text(
        json.dumps({
            "changed_files": [str(p) for p in hp_result.changed_files],
            "changes": [
                {"file": str(c.file), "line": c.line,
                 "action": c.action,
                 "old_ref": c.old_ref, "new_sha": c.new_sha}
                for c in hp_result.changes
            ],
            "skipped": [
                {"file": str(f), "line": ln, "action": a, "reason": r}
                for f, ln, a, r in hp_result.skipped
            ],
        }, indent=2),
        encoding="utf-8",
    )
    if not hp_result.changes:
        return None
    verb = "rewrote" if write else "would rewrite"
    msg = (
        f"raptor-sca fix: {verb} {len(hp_result.changes)} "
        f"GHA action ref(s) across "
        f"{len(hp_result.changed_files)} workflow file(s)"
    )
    if hp_result.skipped:
        msg += f"; {len(hp_result.skipped)} skipped"
    msg += f". Plan: {out_dir}/hash-pin.json"
    return msg


def _highest_version(versions) -> Optional[str]:
    """Return the highest version string by PEP 440 ordering when
    available, falling back to lexicographic.

    Used for cross-manifest reconciliation — versions like ``2.31``,
    ``2.31.0``, ``2.33.1`` come from different manifest pins of the
    same dep and need a single canonical pick.
    """
    versions = [v for v in versions if v]
    if not versions:
        return None
    try:
        from packaging.version import Version, InvalidVersion
        try:
            parsed = sorted(versions, key=Version)
            return parsed[-1]
        except InvalidVersion:
            pass
    except ImportError:
        pass
    return sorted(versions)[-1]


# ---------------------------------------------------------------------------
# Materialise hygiene pin changes
# ---------------------------------------------------------------------------

def _materialise_pin_changes(
    plans: Dict[Tuple[str, str, str], _PlanEntry],
    proposed_root: Path,
    target: Optional[Path] = None,
) -> List[UpgradeChange]:
    """Materialise pin-tightening changes.

    Unlike CVE-fix materialisation (which replaces old→new version),
    pin-tightening may need to:
    - Add a version spec to a bare package name (``requests`` → ``requests==2.28.0``)
    - Replace a loose spec with an exact one (``~=2.28`` → ``==2.28.0``)
    - Strip npm prefixes (``^1.2.3`` → ``1.2.3``)

    The update-module rewriters handle the loose→exact case for most
    ecosystems, but miss bare names.  This function tries the standard
    rewriter first, then falls back to ecosystem-specific pin insertion.
    """
    out: List[UpgradeChange] = []

    by_manifest: Dict[Path, List[_PlanEntry]] = defaultdict(list)
    for plan in plans.values():
        by_manifest[plan.manifest].append(plan)

    for manifest, plan_list in by_manifest.items():
        # If the CVE phase already wrote a proposed copy, read that
        # instead so both sets of changes compose.
        base = target if target else Path.cwd()
        try:
            rel = manifest.resolve().relative_to(base)
        except ValueError:
            rel = Path(manifest.name)

        try:
            original = manifest.read_text(encoding="utf-8")
        except OSError as e:
            for plan in plan_list:
                out.append(UpgradeChange(
                    ecosystem=plan.ecosystem, name=plan.name,
                    old_version=plan.installed, new_version=plan.target,
                    manifest=plan.manifest, advisory_ids=(),
                    skipped_reason=f"cannot read manifest: {e}",
                ))
            continue

        text = original
        for plan in plan_list:
            new_text, applied, reason = _rewrite_one(manifest, text, plan)
            if not applied or new_text == text:
                new_text, applied, reason = _pin_bare_name(
                    manifest, text, plan,
                )
            if applied:
                text = new_text
                out.append(UpgradeChange(
                    ecosystem=plan.ecosystem, name=plan.name,
                    old_version=plan.installed, new_version=plan.target,
                    manifest=plan.manifest, advisory_ids=(),
                ))
            else:
                out.append(UpgradeChange(
                    ecosystem=plan.ecosystem, name=plan.name,
                    old_version=plan.installed, new_version=plan.target,
                    manifest=plan.manifest, advisory_ids=(),
                    skipped_reason=reason or "rewriter found no match",
                ))

        if text != original:
            from ._atomic import atomic_write_text
            dest = proposed_root / rel
            atomic_write_text(dest, text)

    return out


# ---------------------------------------------------------------------------
# Bare-name pinning (fallback when the standard rewriter misses)
# ---------------------------------------------------------------------------

def _normalise_pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pin_bare_name(
    manifest: Path, text: str, plan: _PlanEntry,
) -> Tuple[str, bool, Optional[str]]:
    """Insert an exact version pin for a bare (unversioned) dep name."""
    name = manifest.name

    if name.startswith("requirements") and name.endswith(".txt"):
        return _pin_bare_requirements(text, plan)
    if name == "package.json":
        return _pin_bare_package_json(text, plan)
    if name == "pyproject.toml":
        return _pin_bare_pyproject(text, plan)

    return text, False, f"no bare-name pinner for {name}"


def _pin_bare_requirements(
    text: str, plan: _PlanEntry,
) -> Tuple[str, bool, Optional[str]]:
    """Pin ``name`` (bare, no version) → ``name==target``."""
    norm = _normalise_pypi_name(plan.name)
    out_lines: List[str] = []
    rewrote = False
    for raw in text.splitlines(keepends=True):
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", "-")):
            out_lines.append(raw)
            continue
        # Split off inline comments, preserving them for re-assembly.
        comment_split = re.split(r"(\s+#)", stripped, maxsplit=1)
        line_value = comment_split[0].strip()
        comment_tail = "".join(comment_split[1:])  # separator + comment text

        m = re.match(r"^([A-Za-z0-9_\-.]+)\s*$", line_value)
        if m and _normalise_pypi_name(m.group(1)) == norm:
            pinned = f"{m.group(1)}=={plan.target}{comment_tail}"
            out_lines.append(raw.replace(stripped, pinned))
            rewrote = True
        else:
            out_lines.append(raw)
    if not rewrote:
        return text, False, "bare name not found on its own line"
    return "".join(out_lines), True, None


def _pin_bare_package_json(
    text: str, plan: _PlanEntry,
) -> Tuple[str, bool, Optional[str]]:
    """Pin ``"name": "*"`` or ``"name": ""`` → ``"name": "target"``."""
    pat = re.compile(
        r'("' + re.escape(plan.name) + r'"\s*:\s*")'
        r'([^"]*?)'
        r'(")'
    )
    rewrote = False

    def _replace(m: re.Match) -> str:
        nonlocal rewrote
        current = m.group(2).strip()
        if current in ("*", "x", "X", "latest", ""):
            rewrote = True
            return f"{m.group(1)}{plan.target}{m.group(3)}"
        return m.group(0)

    new_text = pat.sub(_replace, text, count=1)
    if not rewrote:
        return text, False, "no wildcard/empty spec found"
    return new_text, True, None


def _pin_bare_pyproject(
    text: str, plan: _PlanEntry,
) -> Tuple[str, bool, Optional[str]]:
    """Pin a bare dep name in pyproject.toml (PEP 621 or Poetry)."""
    norm = _normalise_pypi_name(plan.name)

    # PEP 621 list form: "name" or 'name' as a bare string in
    # [project.dependencies] or [project.optional-dependencies.*]
    out_lines: List[str] = []
    rewrote = False
    for raw in text.splitlines(keepends=True):
        stripped = raw.strip()
        m = re.match(
            r"""^(['"])([A-Za-z0-9_\-.]+)\s*(['"])\s*,?\s*$""",
            stripped,
        )
        if m and _normalise_pypi_name(m.group(2)) == norm:
            q = m.group(1)
            new_val = f"{q}{m.group(2)}=={plan.target}{q}"
            if stripped.endswith(","):
                new_val += ","
            out_lines.append(raw.replace(stripped, new_val))
            rewrote = True
        else:
            out_lines.append(raw)
    if rewrote:
        return "".join(out_lines), True, None
    return text, False, "bare name not found in pyproject.toml"


# ---------------------------------------------------------------------------
# LLM impact analysis for major-version-blocked CVE fixes
# ---------------------------------------------------------------------------

def _analyze_major_bumps(
    major_blocked: Dict[Tuple[str, str, str], _PlanEntry],
    vuln_plans: Dict[Tuple[str, str, str], _PlanEntry],
    target: Path,
) -> Tuple[set, Dict]:
    """Run LLM impact analysis on major-blocked CVE fixes.

    For each blocked dep, asks the LLM whether the major bump is safe
    given the project's actual call sites.  "safe" verdicts are moved
    from *major_blocked* into *vuln_plans* so they get applied.

    Returns ``(llm_approved_keys, remaining_verdicts)``.  Both are
    empty when no LLM is available — the caller falls back to
    mechanical-only mode.
    """
    from .llm import get_llm_client

    client = get_llm_client()
    if client is None:
        print("raptor-sca fix: no LLM provider configured; "
              "major-bump CVEs will be flagged for manual review",
              file=sys.stderr)
        return set(), {}

    from .llm.upgrade_impact_review import assess_upgrade_impact
    from .models import Confidence, Dependency, PinStyle

    n = len(major_blocked)
    print(f"raptor-sca fix: analysing {n} major-bump CVE(s) with LLM...",
          file=sys.stderr)

    approved: set = set()
    verdicts: Dict[Tuple[str, str, str], Any] = {}

    for key, plan in list(major_blocked.items()):
        dep = Dependency(
            ecosystem=plan.ecosystem,
            name=plan.name,
            version=plan.installed,
            declared_in=plan.manifest,
            scope="main",
            is_lockfile=False,
            pin_style=PinStyle.EXACT,
            direct=True,
            purl=f"pkg:{plan.ecosystem.lower()}/{plan.name}@{plan.installed}",
            parser_confidence=Confidence(level="medium"),
        )
        try:
            verdict = assess_upgrade_impact(client, dep, plan.target, target)
        except Exception:                       # noqa: BLE001
            logger.exception(
                "raptor-sca fix: LLM impact analysis failed for %s:%s "
                "→ %s; treating as needs-review",
                plan.ecosystem, plan.name, plan.target,
            )
            verdict = None
        if verdict is None:
            continue

        if verdict.verdict == "safe":
            vuln_plans[key] = major_blocked.pop(key)
            approved.add(key)
        else:
            verdicts[key] = verdict

    if approved:
        print(f"raptor-sca fix: {len(approved)} major-bump(s) LLM-approved as safe",
              file=sys.stderr)
    if verdicts:
        print(f"raptor-sca fix: {len(verdicts)} major-bump(s) need manual review",
              file=sys.stderr)

    return approved, verdicts


# ---------------------------------------------------------------------------
# Dry-run summary
# ---------------------------------------------------------------------------

def _print_dry_run(
    vuln_plans: Dict[Tuple[str, str, str], _PlanEntry],
    hygiene_plans: Dict[Tuple[str, str, str], _PlanEntry],
    major_blocked: Optional[Dict[Tuple[str, str, str], _PlanEntry]] = None,
    *,
    llm_approved: Optional[set] = None,
    llm_verdicts: Optional[Dict] = None,
) -> None:
    """Print what fix *would* do, grouped by manifest file."""
    all_plans = list(vuln_plans.values()) + list(hygiene_plans.values())
    vuln_keys = set(vuln_plans.keys())

    by_manifest: Dict[Path, List[_PlanEntry]] = defaultdict(list)
    for plan in all_plans:
        by_manifest[plan.manifest].append(plan)

    name_count: Dict[str, int] = defaultdict(int)
    for m in by_manifest:
        name_count[m.name] += 1

    n_vuln = len(vuln_plans)
    n_pin = len(hygiene_plans)
    total = n_vuln + n_pin
    print(f"raptor-sca fix: {total} change(s) planned "
          f"({n_vuln} CVE, {n_pin} pin)\n")

    for manifest in sorted(by_manifest):
        plans = sorted(by_manifest[manifest], key=lambda p: p.name)
        label = (str(manifest) if name_count[manifest.name] > 1
                 else manifest.name)
        print(f"  {label}")
        for plan in plans:
            key = (plan.ecosystem, plan.name, str(plan.manifest))
            if key in vuln_keys:
                ids = ", ".join(plan.advisory_ids)
                suffix = ""
                if llm_approved and key in llm_approved:
                    suffix = "  (LLM: safe to bump)"
                print(f"    {plan.name} {plan.installed} → {plan.target}  [{ids}]{suffix}")
            else:
                print(f"    {plan.name} → =={plan.target}")
        print()

    if major_blocked:
        print(f"  !! {len(major_blocked)} CVE fix(es) blocked "
              f"(require major version bump):\n")
        for plan in sorted(major_blocked.values(), key=lambda p: p.name):
            key = (plan.ecosystem, plan.name, str(plan.manifest))
            ids = ", ".join(plan.advisory_ids)
            print(f"    {plan.name} {plan.installed} → {plan.target}  "
                  f"[{ids}]")
            if llm_verdicts and key in llm_verdicts:
                v = llm_verdicts[key]
                label = v.verdict.replace("_", " ")
                print(f"      LLM: {label} ({v.confidence})")
                if v.summary:
                    print(f"      {v.summary}")
                for bc in v.breaking_changes[:3]:
                    print(f"        {bc.site}: {bc.what_breaks}")
        print("\n  Re-run with --allow-major to include these.\n")

    print("Run with --apply to modify files in-place, "
          "or --out <dir> to write proposed/ for review.")


def _apply_in_place(staged: Path, target: Path) -> None:
    """Copy staged rewrites back over the original manifests."""
    # Manifest writes into the user's tree go through atomic_write_text
    # so an interruption (Ctrl-C, OOM kill, disk full) can never leave
    # a torn or empty manifest behind. shutil.copy2 would not be atomic.
    from ._atomic import atomic_write_bytes
    for staged_file in staged.rglob("*"):
        if not staged_file.is_file():
            continue
        rel = staged_file.relative_to(staged)
        dest = target / rel
        atomic_write_bytes(dest, staged_file.read_bytes())


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------

def _render_optimise_markdown(changes: list[UpgradeChange]) -> str:
    applied = [c for c in changes if c.skipped_reason is None]
    skipped = [c for c in changes if c.skipped_reason is not None]
    vuln_applied = [c for c in applied if c.advisory_ids]
    pin_applied = [c for c in applied if not c.advisory_ids]

    parts: list[str] = ["# sca fix — proposed changes", ""]
    parts.append(f"- CVE fixes: **{len(vuln_applied)}**")
    parts.append(f"- Pins tightened: **{len(pin_applied)}**")
    parts.append(f"- Skipped: **{len(skipped)}**")
    parts.append("")

    if vuln_applied:
        parts.append("## CVE Fixes")
        parts.append("")
        parts.append("| Ecosystem | Name | Old | New | Advisories |")
        parts.append("|---|---|---|---|---|")
        for c in vuln_applied:
            parts.append(
                f"| {c.ecosystem} | {c.name} | {c.old_version} | "
                f"{c.new_version} | {', '.join(c.advisory_ids)} |"
            )
        parts.append("")

    if pin_applied:
        parts.append("## Pins Tightened")
        parts.append("")
        parts.append("| Ecosystem | Name | Pinned To | Manifest |")
        parts.append("|---|---|---|---|")
        for c in pin_applied:
            parts.append(
                f"| {c.ecosystem} | {c.name} | {c.new_version} | "
                f"`{c.manifest}` |"
            )
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


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="raptor-sca fix",
        description="Scan + fix CVEs + pin unpinned deps in one pass.",
        epilog="Modes: 'raptor-sca fix' (default) pins all deps + fixes CVEs. "
               "Use --cve-only to fix only CVEs without tightening pins. "
               "Use --harden to upgrade all deps to the latest safe version.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", help="path to the project to fix")
    p.add_argument("--apply", action="store_true",
                   help="modify manifest files in-place (default: show plan only)")
    p.add_argument("--out",
                   help="write proposed/ to this directory for review "
                        "(mutually exclusive with --apply)")
    p.add_argument("--allow-major", action="store_true",
                   help="allow CVE-fix upgrades that cross a major version")
    p.add_argument("--git-patch", action="store_true",
                   help="emit upgrade.patch alongside proposed/")
    p.add_argument("--offline", action="store_true",
                   help="skip all network calls; use cache only")
    p.add_argument("--no-llm", action="store_true",
                   help="skip LLM impact analysis on major-bump CVEs "
                        "(mechanical mode only). Also disables "
                        "--llm-inline-installs if both are set.")
    p.add_argument("--llm-inline-installs", action="store_true",
                   help="run an LLM pass over Dockerfile / shell / "
                        ".github/workflows ``run:`` blocks to find "
                        "deps the mechanical parser missed. Off by "
                        "default; pay-as-you-go LLM cost.")
    p.add_argument("--no-hash-pin", action="store_true",
                   help="skip hash-pinning .github/workflows actions "
                        "(default: rewrite mutable refs like @v6 to "
                        "commit SHAs when ``gha_action_ref_drift`` "
                        "findings are present)")
    p.add_argument("--no-cache", action="store_true",
                   help="bypass disk cache for this run")
    p.add_argument("--cache-root", help="override cache root")
    p.add_argument("--include-commented", action="store_true",
                   help="parse commented-out version-pinned lines "
                        "(e.g. ``# pkg>=1.0`` in requirements.txt) as "
                        "deps. Hygiene findings on commented entries "
                        "are downgraded to ``info`` (see findings.py), "
                        "and ``fix`` rewrites them while preserving the "
                        "leading ``#``. Useful for projects that document "
                        "optional installs in comment-form and want them "
                        "auto-pinned alongside active deps.")
    p.add_argument("-v", "--verbose", action="count", default=0)
    return p.parse_args(argv)


def _resolve_out_dir(explicit: Optional[str]) -> Path:
    if explicit:
        return Path(explicit).resolve()
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return Path("out") / f"sca-fix-{ts}"
