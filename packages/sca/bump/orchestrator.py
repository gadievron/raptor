"""Bumper orchestrator — walks opinion surfaces, proposes
target versions, evaluates verdicts, optionally applies edits.

Phase 2.d MVP covers ONE surface: Dockerfile ARG version pins.
Future surfaces (manifest deps, FROM image refs, GHA `uses:`,
Helm chart deps, git submodules) plug in via the same shape —
each adds a walker + an upstream-source lookup + a rewriter
registration.

Operator-facing flow:

  raptor-sca bump <target>
    → walks every Dockerfile under <target>
    → for each ARG pin with a known upstream source, fetches
      the latest stable version
    → for each proposed bump, runs ``evaluate_bump_supply_chain``
      + ``_compute_verdict`` to produce a Block / Review / Clean
      verdict
    → prints a verdict table (default)
    → optionally writes the changes (``--apply``)
    → optionally emits a proposed/ directory (``--out``) instead
      of in-place writes
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import List, Optional, Tuple

from ..models import SupplyChainFinding, VulnFinding
from ..parsers.inline_installs._arg_version_pins import (
    _BUILTIN_ARG_MAP,
    _ARG_RE,
)
from ..registries.npm import NpmClient
from ..registries.pypi import PyPIClient
from ..rewriters import RewriteEdit, RewriteResult, rewrite
from .evaluator import evaluate_bump_supply_chain
from .upstream_map import UpstreamSource, lookup_upstream
from .vuln_delta import evaluate_bump_vulns

logger = logging.getLogger(__name__)

# Verdict ladder constants (mirroring ``review.py``).
_VERDICT_CLEAN = 0
_VERDICT_REVIEW = 1
_VERDICT_BLOCK = 2

_VERDICT_LABEL = {
    _VERDICT_CLEAN: "Clean",
    _VERDICT_REVIEW: "Review",
    _VERDICT_BLOCK: "Block",
}


@dataclass(frozen=True)
class BumpCandidate:
    """One proposed bump: where it lives + what we'd change it to.

    ``kind`` discriminates the surface:
      * ``"arg"`` — Dockerfile ARG version pin.  ``locator`` is
        the ARG name (``SEMGREP_VERSION``); ``upstream`` is the
        ``UpstreamSource`` to query for the target.
      * ``"from_image"`` — Dockerfile FROM image ref.
        ``locator`` is ``"{registry}/{repository}"``; ``upstream``
        is None (the target comes from
        ``core.upstream_latest.oci_tags``).

    More kinds plug in by adding to this enum + a walker block in
    ``_enumerate_candidates``."""

    kind: str
    locator: str
    file: Path
    current_version: str
    target_version: str
    upstream: Optional[UpstreamSource] = None
    # Kind-specific metadata (e.g. SHA pair for SHA-pinned GHA
    # uses lines). The apply path forwards this to
    # ``RewriteEdit.extra`` so rewriters can read it.
    extra: Optional[dict] = None

    @property
    def arg_name(self) -> str:
        """Back-compat alias for ARG-pin candidates. Tests + the
        legacy JSON output read this; keep the name reachable
        without breaking the refactor."""
        return self.locator


@dataclass
class BumpResult:
    """Per-candidate outcome — what verdict we computed and
    whether we applied the rewrite."""

    candidate: BumpCandidate
    verdict: int
    verdict_label: str
    bump_supply_chain_findings: List[SupplyChainFinding]
    bump_vuln_findings: List[VulnFinding] = field(default_factory=list)
    error: Optional[str] = None
    rewrite_result: Optional[RewriteResult] = None


@dataclass
class BumpReport:
    """Aggregate report from a ``run_bump`` call."""

    target: Path
    candidates: List[BumpCandidate]
    results: List[BumpResult]
    skipped: List[Tuple[str, Path, str]] = field(default_factory=list)
    # ``(arg_name, file, reason)`` for ARGs we couldn't bump
    # (no upstream mapping, current version not parseable, etc.)


def run_bump(
    target: Path,
    *,
    http,
    pypi_client: Optional[PyPIClient] = None,
    npm_client: Optional[NpmClient] = None,
    osv_client=None,
    kev_client=None,
    epss_client=None,
    apply: bool = False,
    now: Optional[datetime] = None,
    cache=None,
    github_token: Optional[str] = None,
    policy=None,
) -> BumpReport:
    """Walk Dockerfiles under ``target``, propose ARG bumps,
    compute verdicts, optionally apply.

    ``apply=False`` is dry-run: candidates + verdicts only, no
    file writes. ``apply=True`` rewrites in place via the
    Dockerfile-ARG rewriter — only edits where the verdict is
    Clean are applied (Review and Block surface in the report
    but don't auto-apply, per the project's "suggest-only"
    posture documented in
    project_sca_dependabot_plus_plus.md).
    """
    now = now or datetime.now(timezone.utc)
    # Load operator policy from .raptor-sca-bump.yml (or use
    # default). The walker emits all candidates; policy-skips
    # are applied AFTER enumeration so the report can still
    # surface "N candidates skipped by policy" for audit.
    from .policy import load_policy
    policy = policy or load_policy(target)
    candidates, skipped = _enumerate_candidates(
        target, http=http, cache=cache, github_token=github_token,
        pypi_client=pypi_client,
    )
    # Apply policy ``skip:`` rules — these move candidates from
    # the candidates list into the skipped list with the
    # operator's stated reason.
    if policy.skip:
        kept: List[BumpCandidate] = []
        for cand in candidates:
            # Target-relative POSIX path for ``skip: - path:`` rules. The
            # walker enumerates absolute paths under the resolved target;
            # fall back to the raw path if it's somehow outside.
            try:
                rel_path = cand.file.resolve().relative_to(
                    target.resolve()).as_posix()
            except (ValueError, OSError):
                rel_path = cand.file.as_posix()
            rule = policy.is_skipped(
                kind=cand.kind, locator=cand.locator, path=rel_path,
            )
            if rule is not None:
                skipped.append((
                    cand.locator, cand.file,
                    f"policy skip: {rule.reason}"
                    if rule.reason
                    else "policy skip",
                ))
                continue
            kept.append(cand)
        candidates = kept
    # Discover the project's (arch, libc) platform matrix ONCE up
    # front; passed into each per-candidate evaluator so the
    # wheel-platform-compat detector can cross-check target wheels
    # against what the project's base images actually supply.
    from packages.sca.platform_matrix import discover_platform_matrix
    platform_matrix = discover_platform_matrix(target)

    # Lazy-construct the OCI client only when binary-capability-delta
    # is enabled by policy AND at least one candidate is image-shaped.
    # Building it eagerly would force the http dependency on operators
    # who never enable the feature.
    oci_client = None
    if policy.binary_capability_delta_enabled and any(
        c.kind in ("from_image", "yaml_image", "gha_uses")
        for c in candidates
    ):
        try:
            from core.oci.client import OciRegistryClient
            oci_client = OciRegistryClient(http=http)
        except Exception as e:                    # noqa: BLE001
            logger.warning(
                "sca.bump: binary_capability_delta enabled but OCI "
                "client construction failed: %s — feature degraded",
                e,
            )

    results: List[BumpResult] = []
    for cand in candidates:
        result = _evaluate_one(
            cand,
            pypi_client=pypi_client, npm_client=npm_client,
            osv_client=osv_client,
            kev_client=kev_client, epss_client=epss_client,
            platform_matrix=platform_matrix,
            now=now,
            rapid_release_days=policy.thresholds.rapid_release_days,
            oci_client=oci_client,
            http=http,
            binary_capability_delta_enabled=(
                policy.binary_capability_delta_enabled
            ),
        )
        # Policy override: ``block_on_major`` forces major-version
        # bumps to Block-tier so operators always review them.
        if (policy.thresholds.block_on_major
                and _is_major_bump(cand.current_version,
                                    cand.target_version)
                and result.verdict != _VERDICT_BLOCK):
            result.verdict = _VERDICT_BLOCK
            result.verdict_label = _VERDICT_LABEL[_VERDICT_BLOCK]
        # Policy override: ``block_on_minor_skew`` forces same-major
        # large-minor-jump bumps to Block. Catches the
        # ``python 3.9 → 3.14.5``-class of operationally large
        # bumps that semver labels "same major".
        if (policy.thresholds.block_on_minor_skew > 0
                and _is_minor_skew_bump(
                    cand.current_version, cand.target_version,
                    threshold=policy.thresholds.block_on_minor_skew,
                )
                and result.verdict != _VERDICT_BLOCK):
            result.verdict = _VERDICT_BLOCK
            result.verdict_label = _VERDICT_LABEL[_VERDICT_BLOCK]
        if apply and result.verdict == _VERDICT_CLEAN:
            if cand.kind == "git_submodule":
                # Submodule SHAs live in git's object database,
                # not a text file we can rewrite. Apply path
                # emits a manual-action instruction so operators
                # know what to run.
                sm_path = (cand.extra or {}).get("submodule_path", "?")
                result.rewrite_result = RewriteResult(
                    edit=RewriteEdit(
                        locator=cand.locator,
                        old_value=cand.current_version,
                        new_value=cand.target_version,
                        extra=cand.extra,
                    ),
                    applied=False,
                    reason=(
                        f"manual: run `git submodule update "
                        f"--remote --merge -- {sm_path}` "
                        f"then `git add {sm_path}`"
                    ),
                )
            else:
                edit = RewriteEdit(
                    locator=cand.locator,
                    old_value=cand.current_version,
                    new_value=cand.target_version,
                    extra=cand.extra,
                )
                rewrites = rewrite(cand.file, [edit])
                if rewrites:
                    result.rewrite_result = rewrites[0]
        results.append(result)
    return BumpReport(
        target=target,
        candidates=candidates,
        results=results,
        skipped=skipped,
    )


def _enumerate_candidates(
    target: Path,
    *,
    http,
    cache,
    github_token: Optional[str],
    pypi_client: Optional[PyPIClient] = None,
) -> Tuple[List[BumpCandidate], List[Tuple[str, Path, str]]]:
    """Find every (Dockerfile, ARG) pair under ``target`` with a
    built-in upstream-source mapping, query the upstream, and
    build a candidate list."""
    from core.upstream_latest.github_releases import (
        NoStableVersionsFound,
        UpstreamLookupError,
        latest_release,
        latest_tag,
    )
    candidates: List[BumpCandidate] = []
    skipped: List[Tuple[str, Path, str]] = []
    target = target.resolve()
    if not target.exists():
        return candidates, skipped
    dockerfiles = _find_dockerfiles(target)
    # Cache upstream lookups per (kind, coordinate) — multiple
    # Dockerfiles may pin the same tool.
    latest_cache: dict = {}
    for dockerfile in dockerfiles:
        try:
            text = dockerfile.read_text(encoding="utf-8")
        except OSError as e:
            logger.warning("sca.bump: read failed for %s: %s",
                            dockerfile, e)
            continue
        for line in text.splitlines():
            match = _ARG_RE.match(line)
            if match is None:
                continue
            arg_name = match.group(1)
            current = match.group(2).strip('"').strip("'")
            upstream = lookup_upstream(arg_name)
            if upstream is None:
                # No upstream source — silent skip (operator can
                # add via the inline-comment override path).
                continue
            cache_key = (upstream.kind, upstream.coordinate)
            if cache_key in latest_cache:
                target_version = latest_cache[cache_key]
            else:
                try:
                    if upstream.kind == "github_release":
                        raw = latest_release(
                            upstream.coordinate,
                            http=http, cache=cache,
                            github_token=github_token,
                        )
                    elif upstream.kind == "github_tag":
                        raw = latest_tag(
                            upstream.coordinate,
                            http=http, cache=cache,
                            github_token=github_token,
                        )
                    else:
                        raw = None
                except (UpstreamLookupError, NoStableVersionsFound) as e:
                    skipped.append(
                        (arg_name, dockerfile,
                         f"upstream lookup failed: {e}")
                    )
                    latest_cache[cache_key] = None
                    continue
                target_version = (raw or "").lstrip("v")
                latest_cache[cache_key] = target_version
            if not target_version:
                skipped.append(
                    (arg_name, dockerfile, "no upstream version")
                )
                continue
            if target_version == current:
                # Already at latest — not a bump candidate.
                continue
            candidates.append(BumpCandidate(
                kind="arg",
                locator=arg_name,
                file=dockerfile,
                current_version=current,
                target_version=target_version,
                upstream=upstream,
            ))

    # FROM image refs — bump candidates from ``FROM
    # <registry>/<repository>:<tag>`` lines. Tag must be clean-
    # semver shape (refuses ``python:latest``, ``python:3.12-
    # bookworm`` — variants aren't bump candidates without a
    # variant-tag map we don't have).
    for dockerfile in dockerfiles:
        try:
            text = dockerfile.read_text(encoding="utf-8")
        except OSError:
            continue
        from_candidates, from_skipped = _enumerate_from_image_candidates(
            text=text, dockerfile=dockerfile,
            http=http, cache=cache,
            from_cache=latest_cache,
        )
        candidates.extend(from_candidates)
        skipped.extend(from_skipped)

        # Inline ``RUN pip install <name>==<version>`` pins.
        # Same Dockerfile, different surface; rewriter is wired
        # through the dockerfile_from dispatcher via
        # ``extra["kind"] == "inline_install_pip"``.
        if pypi_client is not None:
            inline_candidates, inline_skipped = (
                _enumerate_inline_install_candidates(
                    dockerfile=dockerfile,
                    pypi_client=pypi_client,
                    inline_cache=latest_cache,
                )
            )
            candidates.extend(inline_candidates)
            skipped.extend(inline_skipped)

    # k8s / docker-compose / gitlab-ci ``image:`` refs — bump
    # candidates from existing OCI-eco Dependency parsers.
    # Reuses ``core/upstream_latest/oci_tags.latest_tag`` from
    # Phase 2.b for the upstream lookup.
    yaml_candidates, yaml_skipped = _enumerate_yaml_image_candidates(
        target, http=http, cache=cache,
        from_cache=latest_cache,
    )
    candidates.extend(yaml_candidates)
    skipped.extend(yaml_skipped)

    # Helm chart deps (``Chart.yaml`` ``dependencies:`` block).
    # Uses ``core/upstream_latest/helm_index`` for the index.yaml
    # lookup against each chart's declared repository URL.
    helm_candidates, helm_skipped = _enumerate_helm_chart_candidates(
        target, http=http, cache=cache,
        helm_cache=latest_cache,
    )
    candidates.extend(helm_candidates)
    skipped.extend(helm_skipped)

    # Git submodule pins (``.gitmodules`` + recorded SHA in the
    # parent repo's git index). The bumper identifies candidates
    # but ``--apply`` doesn't rewrite — submodule SHAs live in
    # git's object database, not a text file. Operators apply
    # manually via ``git submodule update --remote``.
    sub_candidates, sub_skipped = _enumerate_git_submodule_candidates(
        target, http=http, cache=cache,
        github_token=github_token,
        sub_cache=latest_cache,
    )
    candidates.extend(sub_candidates)
    skipped.extend(sub_skipped)

    # GitHub Actions ``uses:`` refs — bump candidates from
    # ``.github/workflows/*.yml`` files. Phase 3.b ships tag-
    # pinned support only; SHA-pinned refs (raptor's convention)
    # need a tag→SHA resolver and ship in 3.b.2.
    workflow_files = _find_gha_workflows(target)
    for wf in workflow_files:
        try:
            text = wf.read_text(encoding="utf-8")
        except OSError:
            continue
        gha_candidates, gha_skipped = _enumerate_gha_uses_candidates(
            text=text, workflow=wf,
            http=http, cache=cache,
            github_token=github_token,
            uses_cache=latest_cache,
        )
        candidates.extend(gha_candidates)
        skipped.extend(gha_skipped)
    return candidates, skipped


def _enumerate_inline_install_candidates(
    *,
    dockerfile: Path,
    pypi_client: PyPIClient,
    inline_cache: dict,
) -> Tuple[List[BumpCandidate], List[Tuple[str, Path, str]]]:
    """Walk ``RUN pip install <name>==<version>`` pins in a
    Dockerfile and emit candidates whose PyPI-latest stable
    version is higher than the pinned one.

    Coverage today is PyPI exact-pinned installs only. Other
    inline-install shapes have parsers in
    ``packages.sca.parsers.inline_installs`` (``apt-get install
    foo=1.0``, ``npm install -g foo@1.0``, ``gem install foo -v
    1.0``) but no bumper walker yet — each needs a different
    upstream-latest source. The PyPI walker arrived first because
    raptor's own devcontainer pins semgrep / claude-code / etc.
    inline via ``pip install``.

    Skipped silently:
      * Non-exact pin styles (``>=1.0``, ``~=2.0``, etc.) — bump
        semantics are different for ranges
      * Current version not stable-semver (``2.0.0b1``,
        ``1.0.dev123``) — operators on pre-release pins are
        making a deliberate choice
      * Already at latest

    Skipped with explanation (returned in the ``skipped`` list):
      * No stable versions on PyPI for the package
      * Upstream lookup failed (network / 404)
    """
    from core.upstream_latest._version_filter import (
        highest_stable, parse_stable,
    )
    from packages.sca.parsers.inline_installs import parse_dockerfile

    candidates: List[BumpCandidate] = []
    skipped: List[Tuple[str, Path, str]] = []

    try:
        deps = parse_dockerfile(dockerfile)
    except Exception as e:                                  # noqa: BLE001
        logger.debug(
            "inline_install walker: parse failed for %s: %s",
            dockerfile, e,
        )
        return candidates, skipped

    for dep in deps:
        if dep.ecosystem != "PyPI":
            continue
        if dep.version is None or not dep.version.strip():
            continue
        if dep.pin_style.value != "exact":
            continue
        current = dep.version
        if parse_stable(current) is None:
            # Pre-release / branch-shaped — leave alone.
            continue

        # Per-(name, ecosystem) cache so re-walking the same
        # Dockerfile (e.g. across multiple targets in a sweep)
        # doesn't re-query PyPI for the same package.
        cache_key = ("inline_install_pip", dep.name)
        if cache_key in inline_cache:
            target_version = inline_cache[cache_key]
        else:
            try:
                versions = pypi_client.list_versions(dep.name)
            except Exception as e:                          # noqa: BLE001
                skipped.append((
                    dep.name, dockerfile,
                    f"upstream lookup failed: {e}",
                ))
                continue
            target_version = highest_stable(versions or [])
            inline_cache[cache_key] = target_version

        if target_version is None:
            skipped.append((
                dep.name, dockerfile,
                "no stable versions on PyPI",
            ))
            continue
        if target_version == current:
            continue

        candidates.append(BumpCandidate(
            kind="inline_install_pip",
            locator=dep.name,
            file=dockerfile,
            current_version=current,
            target_version=target_version,
            upstream=UpstreamSource("pypi_meta", dep.name),
            extra={"kind": "inline_install_pip"},
        ))
    return candidates, skipped


def _enumerate_from_image_candidates(
    *,
    text: str,
    dockerfile: Path,
    http,
    cache,
    from_cache: dict,
) -> Tuple[List[BumpCandidate], List[Tuple[str, Path, str]]]:
    """Walk ``FROM`` instructions in ``text``; emit candidates
    for image refs with bumpable stable-semver tags.

    Skipped silently:
      * Digest-pinned FROM (``image@sha256:...``) — immutable
      * Multi-stage ``FROM x AS y`` where ``x`` references a
        previous stage by name (no registry component)
      * Tag is ``latest`` / branch-shaped / variant
        (``3.12-bookworm``)

    Skipped with explanation:
      * Upstream lookup fails (registry 404 / network / no
        stable tag at all)
    """
    from core.dockerfile.parser import parse_dockerfile
    from core.oci.image_ref import parse_image_ref
    from core.upstream_latest._version_filter import (
        parse_stable_with_variant,
    )
    from core.upstream_latest.github_releases import (
        NoStableVersionsFound,
        UpstreamLookupError,
    )
    from core.upstream_latest.oci_tags import latest_tag as oci_latest_tag

    candidates: List[BumpCandidate] = []
    skipped: List[Tuple[str, Path, str]] = []
    try:
        instructions = parse_dockerfile(text)
    except Exception:                # noqa: BLE001 — parsers must not crash
        logger.warning("sca.bump: Dockerfile parse failed for %s",
                        dockerfile, exc_info=True)
        return candidates, skipped
    # Track stage names from prior FROM lines so we can skip
    # ``FROM <stage>`` refs (those reuse a previous stage, not a
    # real image to bump).
    stage_names: set = set()
    for inst in instructions:
        if inst.directive != "FROM":
            continue
        args = inst.args.strip()
        # ``FROM image AS stage`` — record the stage name + bump
        # the image portion.
        as_split = args.split(" AS ", 1)
        if len(as_split) == 1:
            as_split = args.split(" as ", 1)
        image_ref_str = as_split[0].strip()
        if len(as_split) > 1:
            stage_names.add(as_split[1].strip())
        # Reusing a prior stage by name — not a bump target.
        if image_ref_str in stage_names:
            continue
        try:
            ref = parse_image_ref(image_ref_str)
        except Exception:            # noqa: BLE001
            skipped.append((
                image_ref_str, dockerfile,
                f"unparseable FROM ref: {image_ref_str}"
            ))
            continue
        # Digest-pinned → immutable, not a bump candidate.
        if ref.digest:
            continue
        if not ref.tag:
            continue
        # Tag must be clean stable semver to be bumpable. Variants
        # Tags fall into one of three shapes:
        #   * bare stable semver — ``3.12`` → bump to highest
        #     bare semver tag for the repo.
        #   * variant-suffixed semver — ``3.12-slim`` /
        #     ``3.12-slim-bookworm`` → bump to highest
        #     ``<semver>-<same-variant>`` tag (filter on the
        #     variant string, preserve it through the lookup).
        #   * anything else — aliases (``latest``), date tags,
        #     branch refs — skip with no proposal.
        parsed = parse_stable_with_variant(ref.tag)
        if parsed is None:
            continue
        _, variant = parsed
        locator = f"{ref.registry}/{ref.repository}"
        # Cache key includes the variant so different-variant
        # callsites against the same repo don't share answers.
        cache_key = ("oci_tag", locator, variant)
        if cache_key in from_cache:
            target_tag = from_cache[cache_key]
        else:
            try:
                target_tag = oci_latest_tag(
                    image_ref_str, http=http, cache=cache,
                    variant=variant,
                )
            except (UpstreamLookupError, NoStableVersionsFound) as e:
                skipped.append((
                    locator, dockerfile,
                    f"OCI tag lookup failed: {e}",
                ))
                from_cache[cache_key] = None
                continue
            from_cache[cache_key] = target_tag
        if not target_tag or target_tag == ref.tag:
            continue
        candidates.append(BumpCandidate(
            kind="from_image",
            locator=locator,
            file=dockerfile,
            current_version=ref.tag,
            target_version=target_tag,
            upstream=UpstreamSource("oci_tag", locator),
        ))
    return candidates, skipped


def _evaluate_one(
    cand: BumpCandidate,
    *,
    pypi_client: Optional[PyPIClient],
    npm_client: Optional[NpmClient],
    osv_client=None,
    kev_client=None,
    epss_client=None,
    platform_matrix=None,
    now: datetime,
    rapid_release_days: int = 30,
    oci_client=None,
    http=None,
    binary_capability_delta_enabled: bool = False,
) -> BumpResult:
    """Compute the verdict for one bump candidate.

    ARG-kind candidates with a ``_BUILTIN_ARG_MAP`` entry get the
    full bump-tier verdict (recent_publish via registry metadata,
    maintainer_change / install_hook for npm) PLUS the OSV
    vuln-delta check when ``osv_client`` is supplied. FROM-image-
    kind and ARG-kind without an eco-map fall through to Clean
    (no bump-tier signals available for OCI yet — operator review
    on the suggest-only PR is the gate).

    Inline-install PyPI candidates always go through the
    ``evaluate_bump_supply_chain`` path with ``ecosystem="PyPI"``
    + ``name = cand.locator``; their wheel-platform-compat check
    fires against ``platform_matrix`` when both are present.
    """
    eco_map = None
    if cand.kind == "arg":
        eco_map = _BUILTIN_ARG_MAP.get(cand.locator)
    elif cand.kind == "inline_install_pip":
        eco_map = ("PyPI", cand.locator)
    findings: List[SupplyChainFinding] = []
    new_vulns: List = []
    if eco_map is not None:
        ecosystem, package_name = eco_map
        try:
            findings = evaluate_bump_supply_chain(
                ecosystem=ecosystem, name=package_name,
                current_version=cand.current_version,
                target_version=cand.target_version,
                pypi_client=pypi_client, npm_client=npm_client,
                platform_matrix=platform_matrix,
                now=now,
                rapid_release_days=rapid_release_days,
            )
        except Exception as e:                # noqa: BLE001
            return BumpResult(
                candidate=cand,
                verdict=_VERDICT_REVIEW,    # err on the side of human-review
                verdict_label=_VERDICT_LABEL[_VERDICT_REVIEW],
                bump_supply_chain_findings=[],
                error=f"evaluator raised: {e}",
            )
        # OSV vuln-delta: catches "this bump would introduce a
        # CVE the current pin doesn't have". The verdict ladder
        # already escalates VulnFindings — KEV → Block, multiple-
        # critical → Block, etc.
        if osv_client is not None:
            try:
                new_vulns = evaluate_bump_vulns(
                    ecosystem=ecosystem, name=package_name,
                    current_version=cand.current_version,
                    target_version=cand.target_version,
                    osv_client=osv_client,
                    kev_client=kev_client, epss_client=epss_client,
                )
            except Exception as e:            # noqa: BLE001
                # Vuln delta is enrichment, not load-bearing —
                # don't fail the whole evaluation if it goes
                # sideways. Operator still gets the supply-chain
                # verdict + an error breadcrumb.
                logger.warning(
                    "sca.bump: vuln-delta evaluation failed for %s: %s",
                    cand.locator, e,
                )
    # Binary-capability-delta — opt-in fifth Tier-1 signal. Applies
    # to image-shaped candidates (FROM image, yaml image) and to
    # Docker-container GHA actions (gha_uses → resolve action.yml's
    # ``runs.image``). Pulls current + target main binaries via
    # core.oci, runs the capability diff; high-severity finding
    # when target adds exec or network capability current didn't.
    if (binary_capability_delta_enabled and oci_client is not None
            and cand.kind in (
                "from_image", "yaml_image", "gha_uses",
            )):
        bcd_finding = _binary_capability_delta_for_candidate(
            cand, oci_client=oci_client, http=http,
        )
        if bcd_finding is not None:
            findings.append(bcd_finding)

    from ..review import _compute_verdict
    verdict = _compute_verdict(
        vuln_findings=new_vulns,
        typo_findings=[],
        bump_supply_chain_findings=findings,
    )
    return BumpResult(
        candidate=cand,
        verdict=verdict,
        verdict_label=_VERDICT_LABEL.get(verdict, str(verdict)),
        bump_supply_chain_findings=findings,
        bump_vuln_findings=new_vulns,
    )


def _binary_capability_delta_for_candidate(
    cand: BumpCandidate, *, oci_client, http=None,
) -> Optional[SupplyChainFinding]:
    """Pull current + target main binaries from the candidate's
    image refs, run capability diff. Returns ``None`` on any
    routine failure (image unresolvable, binary not extractable,
    radare2 unavailable, no new capabilities).

    Candidate-kind mapping
    - ``from_image`` / ``yaml_image``: locator is
      ``"<registry>/<repository>"``; ref is ``"<locator>:<version>"``.
    - ``gha_uses``: locator is the GitHub repo
      ``"<owner>/<repo>"``; we fetch ``action.yml`` at the
      current + target refs and resolve ``runs.image`` to an OCI
      ref. Returns None for non-Docker actions (JS / composite)
      and for Dockerfile-based actions (no pre-built image).

    Both halves must resolve cleanly — if the action SWITCHED
    between Docker-flavoured and JS between versions, we can't
    capability-diff (different shapes) and bail.
    """
    from .binary_capability_delta import binary_capability_delta_finding
    from .image_binary_extract import fetch_image_binary

    ecosystem = "Container"
    if cand.kind == "gha_uses":
        ecosystem = "GHA"
        if http is None:
            logger.debug(
                "sca.bump.binary_capability_delta: no http client "
                "for gha_uses candidate %s", cand.locator,
            )
            return None
        current_ref, target_ref = _resolve_gha_image_refs(
            cand, http=http,
        )
        if current_ref is None or target_ref is None:
            return None
    else:
        current_ref = f"{cand.locator}:{cand.current_version}"
        target_ref = f"{cand.locator}:{cand.target_version}"

    current_bin = fetch_image_binary(
        current_ref, client=oci_client,
    )
    if current_bin is None:
        logger.debug(
            "sca.bump.binary_capability_delta: could not extract "
            "current binary from %s", current_ref,
        )
        return None
    target_bin = fetch_image_binary(
        target_ref, client=oci_client,
    )
    if target_bin is None:
        logger.debug(
            "sca.bump.binary_capability_delta: could not extract "
            "target binary from %s", target_ref,
        )
        return None
    return binary_capability_delta_finding(
        ecosystem=ecosystem,
        name=cand.locator,
        current_version=cand.current_version,
        target_version=cand.target_version,
        current_binary=current_bin,
        target_binary=target_bin,
    )


def _resolve_gha_image_refs(
    cand: BumpCandidate, *, http,
) -> Tuple[Optional[str], Optional[str]]:
    """Resolve current + target image refs for a ``gha_uses``
    candidate. Returns (None, None) for non-Docker actions or
    fetch failures."""
    from .gha_action_image import resolve_gha_action_image

    current = resolve_gha_action_image(
        cand.locator, cand.current_version, http=http,
    )
    if current is None:
        logger.debug(
            "sca.bump.binary_capability_delta: %s@%s is not a "
            "resolvable Docker-container action",
            cand.locator, cand.current_version,
        )
        return None, None
    target = resolve_gha_action_image(
        cand.locator, cand.target_version, http=http,
    )
    if target is None:
        logger.debug(
            "sca.bump.binary_capability_delta: %s@%s is not a "
            "resolvable Docker-container action",
            cand.locator, cand.target_version,
        )
        return None, None
    return current.image_ref, target.image_ref


def _enumerate_yaml_image_candidates(
    target: Path,
    *,
    http,
    cache,
    from_cache: dict,
) -> Tuple[List[BumpCandidate], List[Tuple[str, Path, str]]]:
    """Walk YAML ``image:`` refs in compose / gitlab-ci / k8s
    files via the existing SCA parsers. Each parser already
    extracts OCI ``Dependency`` rows with ``ecosystem="OCI"``;
    we convert each into a bump candidate by querying
    ``oci_tags`` for upstream-latest.

    Same filtering as FROM image candidates: skip digest-pinned
    (immutable), skip non-stable-semver tags (variants /
    aliases), skip at-latest.
    """
    from ..discovery import find_manifests
    from ..parsers import parse_manifest
    from core.upstream_latest._version_filter import parse_stable
    from core.upstream_latest.github_releases import (
        NoStableVersionsFound,
        UpstreamLookupError,
    )
    from core.upstream_latest.oci_tags import latest_tag as oci_latest_tag

    candidates: List[BumpCandidate] = []
    skipped: List[Tuple[str, Path, str]] = []
    # Reuse the parser dispatch to find OCI deps in YAML files.
    # ``find_manifests`` walks the target; ``parse_manifest``
    # dispatches per file shape.
    try:
        manifests = find_manifests(target)
    except Exception:                       # noqa: BLE001
        return candidates, skipped
    for manifest in manifests:
        # Only YAML manifest shapes; skip Dockerfiles (handled by
        # the FROM walker), GHA workflows (handled by uses
        # walker), package manifests (different concern).
        if manifest.path.suffix.lower() not in (".yml", ".yaml"):
            continue
        # Skip GHA workflows — different walker / surface.
        parts = manifest.path.parts
        is_gha = any(
            parts[i] == ".github" and parts[i + 1] == "workflows"
            for i in range(len(parts) - 2)
        )
        if is_gha:
            continue
        try:
            deps = parse_manifest(manifest)
        except Exception:                # noqa: BLE001
            continue
        for dep in deps:
            if dep.ecosystem != "OCI":
                continue
            current_tag = dep.version or ""
            # Skip if no tag (digest-only or malformed).
            if not current_tag:
                continue
            # Stable-semver filter (same as FROM walker).
            if parse_stable(current_tag) is None:
                continue
            # Compose / k8s / gitlab-ci parsers preserve the
            # image ref as-written (short form ``postgres``,
            # registry-qualified ``ghcr.io/foo/bar``). Canonicalize
            # through ``parse_image_ref`` so the locator we emit
            # matches the convention shared with the Dockerfile-
            # FROM walker (``{registry}/{repository}``).
            from core.oci.image_ref import parse_image_ref
            try:
                ref = parse_image_ref(f"{dep.name}:{current_tag}")
            except Exception:        # noqa: BLE001
                continue
            locator = f"{ref.registry}/{ref.repository}"
            cache_key = ("oci_tag", locator)
            if cache_key in from_cache:
                target_tag = from_cache[cache_key]
            else:
                try:
                    target_tag = oci_latest_tag(
                        locator, http=http, cache=cache,
                    )
                except (UpstreamLookupError, NoStableVersionsFound) as e:
                    skipped.append((
                        locator, manifest.path,
                        f"OCI tag lookup failed: {e}",
                    ))
                    from_cache[cache_key] = None
                    continue
                from_cache[cache_key] = target_tag
            if not target_tag or target_tag == current_tag:
                continue
            candidates.append(BumpCandidate(
                kind="yaml_image",
                locator=locator,
                file=manifest.path,
                current_version=current_tag,
                target_version=target_tag,
                upstream=UpstreamSource("oci_tag", locator),
            ))
    return candidates, skipped


def _enumerate_helm_chart_candidates(
    target: Path,
    *,
    http,
    cache,
    helm_cache: dict,
) -> Tuple[List[BumpCandidate], List[Tuple[str, Path, str]]]:
    """Walk ``Chart.yaml`` dependencies via the existing Helm
    parser. Each dep carries a Helm repo URL in
    ``source_extra['repository']``; we query that repo's
    ``index.yaml`` for the highest stable-semver version of the
    named chart.

    Skipped silently:
      * Deps without a repository URL (vendored deps; can't look
        up upstream)
      * Deps whose current version isn't stable-semver (variant /
        operator-internal pinning convention)

    Skipped with explanation:
      * Helm index fetch failures
      * Chart name not present in the repo's index
    """
    from ..discovery import find_manifests
    from ..parsers import parse_manifest
    from core.upstream_latest._version_filter import parse_stable
    from core.upstream_latest.github_releases import (
        NoStableVersionsFound, UpstreamLookupError,
    )
    from core.upstream_latest.helm_index import latest_chart_version

    candidates: List[BumpCandidate] = []
    skipped: List[Tuple[str, Path, str]] = []
    try:
        manifests = find_manifests(target)
    except Exception:                       # noqa: BLE001
        return candidates, skipped
    for manifest in manifests:
        if manifest.path.name != "Chart.yaml":
            continue
        try:
            deps = parse_manifest(manifest)
        except Exception:                  # noqa: BLE001
            continue
        for dep in deps:
            if dep.ecosystem != "Helm":
                continue
            current_version = dep.version or ""
            if not current_version:
                continue
            if parse_stable(current_version) is None:
                continue
            repo = (dep.source_extra or {}).get("repository") if dep.source_extra else None
            if not repo:
                # No upstream URL → can't look up. Silent skip.
                continue
            cache_key = ("helm_index", repo, dep.name)
            if cache_key in helm_cache:
                target_version = helm_cache[cache_key]
            else:
                try:
                    target_version = latest_chart_version(
                        repo, dep.name, http=http, cache=cache,
                    )
                except (UpstreamLookupError, NoStableVersionsFound) as e:
                    skipped.append((
                        f"{dep.name} ({repo})", manifest.path,
                        f"Helm index lookup failed: {e}",
                    ))
                    helm_cache[cache_key] = None
                    continue
                helm_cache[cache_key] = target_version
            if not target_version or target_version == current_version:
                continue
            candidates.append(BumpCandidate(
                kind="helm_chart",
                locator=dep.name,
                file=manifest.path,
                current_version=current_version,
                target_version=target_version,
                upstream=UpstreamSource("helm_index", dep.name),
                extra={"repository": repo},
            ))
    return candidates, skipped


def _enumerate_git_submodule_candidates(
    target: Path,
    *,
    http,
    cache,
    github_token: Optional[str],
    sub_cache: dict,
) -> Tuple[List[BumpCandidate], List[Tuple[str, Path, str]]]:
    """Walk ``.gitmodules`` submodules via the existing parser.
    For each GitHub-shaped submodule with a recorded current SHA,
    look up upstream-latest tag and resolve to a target SHA.

    Phase 3.e ships candidate emission only. The ``--apply`` path
    refuses to rewrite (submodule SHAs are in git's object
    database, not a text file); reviewers see the proposed SHA
    and the manual ``git submodule update --remote --
    <path>`` instruction.
    """
    from ..discovery import find_manifests
    from ..parsers import parse_manifest
    from core.upstream_latest.github_releases import (
        NoStableVersionsFound, UpstreamLookupError,
        latest_release, latest_tag, resolve_tag_to_sha,
    )

    candidates: List[BumpCandidate] = []
    skipped: List[Tuple[str, Path, str]] = []
    try:
        manifests = find_manifests(target)
    except Exception:                       # noqa: BLE001
        return candidates, skipped
    for manifest in manifests:
        if manifest.path.name != ".gitmodules":
            continue
        try:
            deps = parse_manifest(manifest)
        except Exception:                  # noqa: BLE001
            continue
        for dep in deps:
            # We only handle GitHub-hosted submodules in Phase 3.e
            # — other git hosts need different upstream-latest
            # mechanisms (git ls-remote against arbitrary URLs).
            if dep.ecosystem != "GitHub":
                continue
            current_sha = dep.version  # may be None (unresolved)
            if not current_sha or len(current_sha) != 40:
                # Unresolved or non-SHA pin — can't propose a bump
                # without a current anchor.
                continue
            repo = dep.name      # ``owner/repo`` for GitHub URLs
            cache_key = ("gha_uses", repo)
            if cache_key in sub_cache:
                target_tag = sub_cache[cache_key]
            else:
                try:
                    target_tag = latest_release(
                        repo, http=http, cache=cache,
                        github_token=github_token,
                    )
                except UpstreamLookupError:
                    try:
                        target_tag = latest_tag(
                            repo, http=http, cache=cache,
                            github_token=github_token,
                        )
                    except (UpstreamLookupError, NoStableVersionsFound) as e:
                        skipped.append((
                            repo, manifest.path,
                            f"submodule upstream lookup failed: {e}",
                        ))
                        sub_cache[cache_key] = None
                        continue
                sub_cache[cache_key] = target_tag
            if not target_tag:
                continue
            # Resolve target tag → SHA. Cache separately from the
            # tag-lookup (different OSV/GitHub endpoints).
            sha_cache_key = ("tag_to_sha", repo, target_tag)
            if sha_cache_key in sub_cache:
                target_sha = sub_cache[sha_cache_key]
            else:
                try:
                    target_sha = resolve_tag_to_sha(
                        repo, target_tag, http=http, cache=cache,
                        github_token=github_token,
                    )
                except UpstreamLookupError as e:
                    skipped.append((
                        repo, manifest.path,
                        f"submodule tag→SHA resolution failed: {e}",
                    ))
                    sub_cache[sha_cache_key] = None
                    continue
                sub_cache[sha_cache_key] = target_sha
            if not target_sha or target_sha == current_sha:
                continue
            sm_path = (dep.source_extra or {}).get("path", "")
            candidates.append(BumpCandidate(
                kind="git_submodule",
                locator=repo,
                file=manifest.path,
                current_version=current_sha,
                target_version=target_tag,    # human-readable tag
                upstream=UpstreamSource("git_remote", repo),
                extra={
                    "old_sha": current_sha,
                    "new_sha": target_sha,
                    "submodule_path": sm_path,
                },
            ))
    return candidates, skipped


_USES_RE = re.compile(
    r"^\s*(?:-\s+)?uses:\s*"             # optional YAML list marker
    r"(?P<repo>[\w.-]+/[\w.-]+)"        # owner/repo
    r"(?P<subpath>(?:/[\w./-]+)?)"       # optional sub-action path
    r"@"
    r"(?P<ref>[^\s#]+)"                   # ref (up to ws / comment)
)

# Phase 3.b.2 — SHA-pinned with ``# was vX`` comment. The comment
# carries the human-readable tag so the bumper can compute a new
# tag → new SHA on the same axis.
_USES_SHA_COMMENT_RE = re.compile(
    r"^\s*(?:-\s+)?uses:\s*"
    r"(?P<repo>[\w.-]+/[\w.-]+)"
    r"(?P<subpath>(?:/[\w./-]+)?)"
    r"@"
    r"(?P<sha>[a-f0-9]{40})"
    r"\s+#\s*was\s+"
    r"(?P<tag>[^\s#]+)"
)


def _enumerate_gha_uses_candidates(
    *,
    text: str,
    workflow: Path,
    http,
    cache,
    github_token: Optional[str],
    uses_cache: dict,
) -> Tuple[List[BumpCandidate], List[Tuple[str, Path, str]]]:
    """Walk ``uses:`` lines in a GHA workflow file; emit
    candidates for tag-pinned refs whose upstream has a newer
    stable tag.

    Skipped silently:
      * SHA-pinned refs (40-char hex) — Phase 3.b.2 territory
      * Branch-pinned refs (``@main``, ``@master``) — out of
        scope for auto-bumper
      * Refs that aren't clean stable-semver (handled via the
        github_releases.latest_release path which already
        filters pre-releases)

    Skipped with explanation:
      * Upstream lookup fails
    """
    from core.upstream_latest._version_filter import parse_stable
    from core.upstream_latest.github_releases import (
        UpstreamLookupError,
        resolve_tag_to_sha,
    )

    candidates: List[BumpCandidate] = []
    skipped: List[Tuple[str, Path, str]] = []
    for line in text.splitlines():
        # Phase 3.b.2: SHA-pinned with ``# was vX`` comment.
        # Detect first; if matched, propose new tag + new SHA.
        sha_match = _USES_SHA_COMMENT_RE.match(line)
        if sha_match is not None:
            repo = sha_match.group("repo")
            current_sha = sha_match.group("sha")
            current_tag = sha_match.group("tag")
            if parse_stable(current_tag) is None:
                # Comment tag isn't semver — operator's not using
                # the convention we recognize. Skip silently.
                continue
            target_tag = _lookup_latest_release_or_tag(
                repo, http=http, cache=cache,
                github_token=github_token,
                uses_cache=uses_cache,
                skipped=skipped, workflow=workflow,
            )
            if not target_tag:
                continue
            # Same-major-pin filter: ``# was v6`` and target
            # ``v6.2.1`` would surface as a noisy same-major
            # update (operator chose major-only). Skip those.
            if _same_major_pin(current_tag, target_tag):
                continue
            if current_tag == target_tag:
                continue
            # Resolve target tag → commit SHA. Cache per
            # (repo, target_tag) — multiple workflows often pin
            # the same actions to the same SHAs.
            sha_cache_key = ("tag_to_sha", repo, target_tag)
            if sha_cache_key in uses_cache:
                target_sha = uses_cache[sha_cache_key]
            else:
                try:
                    target_sha = resolve_tag_to_sha(
                        repo, target_tag, http=http, cache=cache,
                        github_token=github_token,
                    )
                except UpstreamLookupError as e:
                    skipped.append((
                        repo, workflow,
                        f"tag→SHA resolution failed: {e}",
                    ))
                    uses_cache[sha_cache_key] = None
                    continue
                uses_cache[sha_cache_key] = target_sha
            if not target_sha:
                continue
            candidates.append(BumpCandidate(
                kind="gha_uses",
                locator=repo,
                file=workflow,
                current_version=current_tag,
                target_version=target_tag,
                upstream=UpstreamSource("github_release", repo),
                extra={
                    "old_sha": current_sha,
                    "new_sha": target_sha,
                },
            ))
            continue
        match = _USES_RE.match(line)
        if match is None:
            continue
        repo = match.group("repo")
        ref = match.group("ref")
        # SHA-pinned without our # was vX comment → can't
        # safely bump (no human-readable anchor). Skip.
        if re.fullmatch(r"[a-f0-9]{40}", ref):
            continue
        # Branch-shaped → skip (auto-bumper doesn't surface
        # branch-to-tag transitions yet).
        if ref in ("main", "master", "develop") or "/" in ref:
            continue
        # Must be parseable as semver (``v4``, ``v4.1.0``, ``1.0``).
        # We use the relaxed `parse_stable` filter — accepts 1-4
        # part numeric + optional v-prefix.
        if parse_stable(ref) is None:
            continue
        target_ref = _lookup_latest_release_or_tag(
            repo, http=http, cache=cache,
            github_token=github_token,
            uses_cache=uses_cache,
            skipped=skipped, workflow=workflow,
        )
        if not target_ref:
            continue
        # Normalise both to compare like-shapes. If the current
        # ref is a major-only (``v4``) and the latest is full
        # (``v4.2.1``), we'd want to either:
        #   (a) propose ``v5`` once it exists (major-only roll)
        #   (b) propose the full version (specific roll)
        # Renovate uses (a); for our suggest-only flow (a) is
        # less noisy.
        if ref == target_ref:
            continue
        # If current ref is major-only and target's major is the
        # same, no candidate (we'd be proposing a same-major
        # specific roll, which renovate considers a no-op for
        # major-only pins).
        if _same_major_pin(ref, target_ref):
            continue
        candidates.append(BumpCandidate(
            kind="gha_uses",
            locator=repo,
            file=workflow,
            current_version=ref,
            target_version=target_ref,
            upstream=UpstreamSource("github_release", repo),
        ))
    return candidates, skipped


def _lookup_latest_release_or_tag(
    repo: str,
    *,
    http,
    cache,
    github_token: Optional[str],
    uses_cache: dict,
    skipped: List[Tuple[str, Path, str]],
    workflow: Path,
) -> Optional[str]:
    """Look up the latest stable upstream version for a GitHub
    repo. Tries ``/releases/latest`` first (proper GitHub
    Releases); falls back to ``/tags`` (projects that tag without
    releases). Caches per-repo via ``uses_cache``.

    Stability filter: GitHub's ``releases/latest`` endpoint
    returns whatever tag the publisher marked as the latest
    release, without enforcing stable-semver shape. For example,
    ``github/codeql-action`` publishes ``codeql-bundle-vX.Y.Z``
    bundle releases that don't match the ``v?N.N.N`` shape we
    expect for auto-bumping a ``v4`` → ``vN`` pin. This function
    validates the upstream-latest result through ``parse_stable``
    and falls through to the tag-listing path if the
    ``releases/latest`` tag doesn't pass the filter. If neither
    path produces a stable-semver tag, the repo is recorded as
    skipped with reason — operator sees the gap explicitly.
    """
    from core.upstream_latest._version_filter import parse_stable
    from core.upstream_latest.github_releases import (
        NoStableVersionsFound, UpstreamLookupError,
        latest_release, latest_tag,
    )
    cache_key = ("gha_uses", repo)
    if cache_key in uses_cache:
        return uses_cache[cache_key]
    target_ref = None
    try:
        candidate = latest_release(
            repo, http=http, cache=cache, github_token=github_token,
        )
    except UpstreamLookupError:
        candidate = None
    # Validate the /releases/latest result. Some projects publish
    # non-semver bundle tags (codeql-bundle-vX.Y.Z); we can't
    # substitute those for a vN pin shape, so fall through to
    # /tags which DOES filter to stable.
    if candidate is not None and parse_stable(candidate) is not None:
        target_ref = candidate
    else:
        try:
            target_ref = latest_tag(
                repo, http=http, cache=cache, github_token=github_token,
            )
        except (UpstreamLookupError, NoStableVersionsFound) as e:
            skipped.append((
                repo, workflow,
                (f"upstream lookup found non-semver release "
                 f"{candidate!r} and tag-listing also failed: {e}")
                if candidate is not None
                else f"upstream lookup failed: {e}",
            ))
            uses_cache[cache_key] = None
            return None
    uses_cache[cache_key] = target_ref
    return target_ref


def _is_major_bump(current: str, target: str) -> bool:
    """True if ``target`` is a major-equivalent jump from ``current``.
    Used by the ``block_on_major`` policy threshold.

    Two cases count as major-equivalent:

      1. **Different ``major``** at 1.x+ on either side
         (``v4 → v7.0.1``, ``11-jdk → 26-jdk``).

      2. **Different ``minor`` while both are still at major
         zero** (``0.84 → 0.103``). Per semver §4 pre-1.0
         versions provide NO stability guarantees; npm / Cargo /
         Composer compatibility solvers all default-cap at the
         minor for ``0.y.z`` ranges. RAPTOR mirrors that
         convention so operators using ``block_on_major: true``
         catch the ``openai 0.84 → 0.103``-class of pre-1.0
         API churn that's almost-always breaking.

    Variant suffixes (``-jdk``, ``-slim``, ``-alpine``) are
    stripped via ``parse_stable_with_variant``; ``oci_latest_tag``
    constrains target to same-variant-as-current so the variant
    string itself isn't part of the comparison.

    Conservative: if either version can't be parsed as
    stable-semver (``latest``, branch refs, date tags), returns
    False — don't force-block what we can't reason about."""
    from core.upstream_latest._version_filter import (
        parse_stable_with_variant,
    )
    cur = parse_stable_with_variant(current)
    tgt = parse_stable_with_variant(target)
    if cur is None or tgt is None:
        return False
    cur_tuple, _ = cur
    tgt_tuple, _ = tgt
    if not cur_tuple or not tgt_tuple:
        return False
    if cur_tuple[0] != tgt_tuple[0]:
        return True
    # Both same major. Pre-1.0 special case: when major is 0 on
    # both sides, compare minors instead — see docstring.
    if cur_tuple[0] == 0:
        cur_minor = cur_tuple[1] if len(cur_tuple) > 1 else 0
        tgt_minor = tgt_tuple[1] if len(tgt_tuple) > 1 else 0
        return cur_minor != tgt_minor
    return False


def _is_minor_skew_bump(
    current: str, target: str, *, threshold: int,
) -> bool:
    """True if ``target`` is a same-major bump with a minor-version
    delta ≥ ``threshold``. Used by the ``block_on_minor_skew``
    policy threshold to catch operationally-large jumps that strict
    semver labels "same major" (``python 3.9 → 3.14.5`` is a
    5-minor jump within major 3).

    Returns False when:
      * Either version can't be parsed as stable-semver
        (``latest``, branch refs).
      * The majors differ — that's ``_is_major_bump``'s job.
      * Either side is pre-1.0 — handled by ``_is_major_bump``'s
        zero-major rule, where every 0.x → 0.y is already
        major-equivalent.
      * Target's minor is not strictly greater than current's (a
        same-major downgrade or zero-skew rewrite).
    """
    from core.upstream_latest._version_filter import (
        parse_stable_with_variant,
    )
    cur = parse_stable_with_variant(current)
    tgt = parse_stable_with_variant(target)
    if cur is None or tgt is None:
        return False
    cur_tuple, _ = cur
    tgt_tuple, _ = tgt
    if not cur_tuple or not tgt_tuple:
        return False
    if cur_tuple[0] != tgt_tuple[0]:
        return False
    if cur_tuple[0] == 0:
        # Pre-1.0 belongs to ``_is_major_bump``'s zero-major rule.
        return False
    cur_minor = cur_tuple[1] if len(cur_tuple) > 1 else 0
    tgt_minor = tgt_tuple[1] if len(tgt_tuple) > 1 else 0
    return (tgt_minor - cur_minor) >= threshold


def _same_major_pin(current: str, target: str) -> bool:
    """True if ``current`` is a major-only pin (``v4``) and the
    target is in the same major (``v4.2.1``). Avoids proposing
    a major-only roll TO a specific version — operators using
    major-only pins explicitly chose that level."""
    from core.upstream_latest._version_filter import parse_stable
    cur = parse_stable(current)
    tgt = parse_stable(target)
    if cur is None or tgt is None:
        return False
    if len(cur) != 1:
        return False
    return cur[0] == tgt[0]


def _find_gha_workflows(target: Path) -> List[Path]:
    """Walk ``target/.github/workflows/`` for YAML files."""
    workflows_dir = target / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return []
    out: List[Path] = []
    for path in workflows_dir.iterdir():
        if path.is_file() and path.suffix in (".yml", ".yaml"):
            out.append(path)
    return sorted(out)


def _find_dockerfiles(target: Path) -> List[Path]:
    """Walk ``target`` for files the Dockerfile-ARG rewriter
    knows how to handle. Mirrors the inline-installs parser's
    discovery predicate so the bumper sees every ARG-bearing
    file that the rest of SCA does."""
    if target.is_file():
        return [target] if _is_dockerfile(target) else []
    out: List[Path] = []
    for path in target.rglob("*"):
        if path.is_file() and _is_dockerfile(path):
            out.append(path)
    return sorted(out)


def _is_dockerfile(path: Path) -> bool:
    name = path.name
    if name in ("Dockerfile", "Containerfile"):
        return True
    if name.startswith("Dockerfile.") or name.endswith(".Dockerfile"):
        return True
    if path.suffix == ".dockerfile":
        return True
    return False


def render_report(report: BumpReport) -> str:
    """Operator-readable table summarising the bump report.

    Format chosen for terminal-readability; the bumper CLI prints
    it to stdout. PR-comment rendering is a separate codepath
    (the existing ``diff --pr-comment`` machinery, when wired in
    a future commit)."""
    lines: List[str] = []
    lines.append(f"raptor-sca bump: target {report.target}")
    if not report.candidates and not report.skipped:
        lines.append("  no bump candidates found")
        return "\n".join(lines) + "\n"
    if report.candidates:
        lines.append("")
        lines.append(
            f"  {'Kind':<11} {'Locator':<35} "
            f"{'Current':<14} {'Target':<22} {'Verdict':<8} Result"
        )
        # Dedup the display by (kind, locator, current_version,
        # target_version). The underlying ``results`` list still
        # has one entry per file (so --apply iterates all files)
        # but the human-readable table folds identical proposals
        # into one row with a file-count suffix. Pre-fix on
        # raptor: 8 CODEQL_VERSION rows + 3 github/codeql-action
        # rows (one per file each); operators read it as noise.
        groups: "dict[tuple, List[BumpResult]]" = {}
        order: List[tuple] = []
        for r in report.results:
            key = (
                r.candidate.kind, r.candidate.locator,
                r.candidate.current_version, r.candidate.target_version,
            )
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(r)
        for key in order:
            group = groups[key]
            head = group[0]
            n_files = len(group)
            # ``Result`` field aggregates the per-file outcomes:
            # if all applied → "applied (N files)"; if mixed →
            # "applied N, skipped M"; if none applied → just
            # the dominant reason from the first.
            applied_count = sum(
                1 for r in group
                if r.rewrite_result is not None and r.rewrite_result.applied
            )
            if applied_count > 0:
                if applied_count == n_files:
                    result_label = (
                        f"applied ({n_files} file)"
                        if n_files == 1 else f"applied ({n_files} files)"
                    )
                else:
                    result_label = (
                        f"applied {applied_count}/{n_files}"
                    )
            elif head.rewrite_result is not None:
                result_label = f"skipped ({head.rewrite_result.reason})"
            elif head.error:
                result_label = f"error: {head.error}"
            else:
                result_label = "" if n_files == 1 else f"({n_files} files)"
            lines.append(
                f"  {head.candidate.kind:<11} "
                f"{head.candidate.locator:<35} "
                f"{head.candidate.current_version:<14} "
                f"{head.candidate.target_version:<22} "
                f"{head.verdict_label:<8} {result_label}"
            )
            # Surface the supply-chain findings inline so operators
            # know WHY a verdict isn't Clean. (One copy per group;
            # identical proposals would emit identical findings.)
            for sf in head.bump_supply_chain_findings:
                lines.append(f"      [{sf.severity}] {sf.kind}: {sf.detail}")
            # Surface newly-introduced CVEs (OSV vuln-delta) —
            # the strongest "do not auto-bump" signal we have.
            for vf in head.bump_vuln_findings:
                adv = vf.advisories[0] if vf.advisories else None
                cve = (adv.osv_id if adv else "?")
                kev_marker = " KEV" if vf.in_kev else ""
                lines.append(
                    f"      [{vf.severity}{kev_marker}] "
                    f"new-CVE {cve}: "
                    f"{(adv.summary[:90] if adv and adv.summary else '')}"
                )
    if report.skipped:
        lines.append("")
        lines.append("  Skipped:")
        for arg, path, reason in report.skipped:
            lines.append(
                f"    {arg} ({path.name}): {reason}"
            )
    return "\n".join(lines) + "\n"
