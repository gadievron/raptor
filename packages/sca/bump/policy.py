"""``.raptor-sca-bump.yml`` operator policy file.

The bumper's defaults are sensible but unconfigurable today.
Operators wanting different behaviour — tighter rapid-release
window, longer maintainer-cooldown, skip certain locators
entirely — supply a policy file at the project root:

    # .raptor-sca-bump.yml
    skip:
      - locator: actions/checkout
        reason: "vendored a fork; bumps managed separately"
      - kind: from_image
        locator: docker.io/library/postgres
        reason: "schema migration blocker — manual coord required"

    thresholds:
      rapid_release_days: 14    # tighter than the default 30
      block_on_major: true       # major-version bumps require human review

Schema:

* ``skip``: list of locator-match rules; each can match by
  ``kind`` (any/arg/from_image/yaml_image/gha_uses/helm_chart/
  git_submodule), ``locator`` (exact or wildcard via ``*``).
  Matching rules cause the candidate to NOT be emitted by
  the walker.
* ``thresholds.rapid_release_days``: override the
  ``recent_publish`` detector's window (default 30; smaller
  values are stricter).
* ``thresholds.block_on_major``: when True, candidates whose
  target's major version differs from current's are forced to
  Block-tier verdict (operator review required).

Loading is fail-soft: a missing or malformed policy file
yields the default (no skips, default thresholds). Operators
get a warning log on parse failures but the bumper continues."""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


_POLICY_FILE = ".raptor-sca-bump.yml"


@dataclass(frozen=True)
class SkipRule:
    """One entry in the ``skip:`` list."""

    kind: Optional[str] = None       # None → any kind matches
    locator: Optional[str] = None    # None → any locator matches; ``*``-glob ok
    reason: str = ""

    def matches(self, *, candidate_kind: str, candidate_locator: str) -> bool:
        if self.kind and self.kind != candidate_kind:
            return False
        if self.locator and not _locator_match(self.locator, candidate_locator):
            return False
        return True


@dataclass(frozen=True)
class Thresholds:
    """Numeric / boolean thresholds adjustable by the operator."""

    rapid_release_days: int = 30
    block_on_major: bool = False
    # OFF by default (0): no minor-skew gate.
    #
    # When > 0: force-Block any same-major bump whose target.minor
    # exceeds current.minor by ``block_on_minor_skew`` or more.
    # Catches the ``python 3.9 → 3.14.5``-class of bump where the
    # change is "same major" by strict semver but operationally
    # large (5 minor versions of Python = significant removed APIs).
    #
    # ``_is_major_bump`` already covers different-major + pre-1.0
    # minor jumps; this threshold catches the gap between "same
    # major" and "operationally major-equivalent".
    #
    # Suggested values:
    #   * ``2`` — very conservative, blocks any 2+ minor jump
    #   * ``5`` — pragmatic, blocks "big" jumps like 3.9→3.14
    #   * ``10`` — only blocks LTS-skipping-LTS-class jumps
    #
    # Only applies when ``current`` and ``target`` are both
    # parseable as semver with major ≥ 1 (pre-1.0 is handled by
    # ``_is_major_bump``'s zero-major rule); unparseable inputs
    # (``latest``, branch refs) skip the gate.
    block_on_minor_skew: int = 0


@dataclass
class BumpPolicy:
    """Loaded policy. Defaults yield "no override" behaviour."""

    skip: List[SkipRule] = field(default_factory=list)
    thresholds: Thresholds = field(default_factory=Thresholds)
    # OFF by default: binary-capability-delta requires radare2 +
    # r2pipe + network egress to pull layers + significant compute.
    # Operators opt in via ``binary_capability_delta: true`` in
    # ``.raptor-sca-bump.yml`` (or the corresponding CLI flag). When
    # enabled, FROM-image / yaml-image candidates get an extra signal
    # comparing current vs target binary capability surfaces.
    binary_capability_delta_enabled: bool = False

    def is_skipped(
        self, *, kind: str, locator: str,
    ) -> Optional[SkipRule]:
        """Return the first matching skip rule, or ``None``."""
        for rule in self.skip:
            if rule.matches(candidate_kind=kind, candidate_locator=locator):
                return rule
        return None


def load_policy(target: Path) -> BumpPolicy:
    """Load ``.raptor-sca-bump.yml`` from the target directory.

    Missing file → default policy (no skips, default thresholds).
    Malformed file → warning log + default policy. The bumper
    never crashes on a bad policy — operators get the default
    behaviour and a log entry to fix the file.
    """
    policy_path = target / _POLICY_FILE
    if not policy_path.exists():
        return BumpPolicy()
    try:
        text = policy_path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning(
            "sca.bump.policy: could not read %s: %s; using default",
            policy_path, e,
        )
        return BumpPolicy()
    try:
        import yaml          # type: ignore[import-untyped]
    except ImportError:
        logger.warning(
            "sca.bump.policy: PyYAML not installed; cannot parse "
            "%s — using default policy", policy_path,
        )
        return BumpPolicy()
    try:
        loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
        data = yaml.load(text, Loader=loader)
    except yaml.YAMLError as e:
        logger.warning(
            "sca.bump.policy: %s is malformed YAML: %s; using default",
            policy_path, e,
        )
        return BumpPolicy()
    if not isinstance(data, dict):
        logger.warning(
            "sca.bump.policy: %s top-level is not a mapping; "
            "using default", policy_path,
        )
        return BumpPolicy()

    skips: List[SkipRule] = []
    raw_skip = data.get("skip")
    if isinstance(raw_skip, list):
        for entry in raw_skip:
            if not isinstance(entry, dict):
                continue
            kind = entry.get("kind")
            locator = entry.get("locator")
            reason = entry.get("reason") or ""
            if not isinstance(kind, str) and kind is not None:
                continue
            if not isinstance(locator, str) and locator is not None:
                continue
            if kind is None and locator is None:
                # Empty rule would skip everything — refuse silently.
                continue
            skips.append(SkipRule(
                kind=kind, locator=locator,
                reason=str(reason),
            ))

    th = Thresholds()
    raw_th = data.get("thresholds")
    if isinstance(raw_th, dict):
        rrd = raw_th.get("rapid_release_days")
        bom = raw_th.get("block_on_major")
        bms = raw_th.get("block_on_minor_skew")
        if isinstance(rrd, int) and rrd > 0:
            th = Thresholds(
                rapid_release_days=rrd,
                block_on_major=th.block_on_major,
                block_on_minor_skew=th.block_on_minor_skew,
            )
        if isinstance(bom, bool):
            th = Thresholds(
                rapid_release_days=th.rapid_release_days,
                block_on_major=bom,
                block_on_minor_skew=th.block_on_minor_skew,
            )
        # ``block_on_minor_skew: 0`` is the documented "disabled"
        # value; treat 0 as a valid explicit-off rather than
        # ignoring it. Negative values are nonsensical (would
        # block-on-downgrade) — ignore those.
        if isinstance(bms, int) and bms >= 0:
            th = Thresholds(
                rapid_release_days=th.rapid_release_days,
                block_on_major=th.block_on_major,
                block_on_minor_skew=bms,
            )

    # ``binary_capability_delta`` is the top-level toggle name in
    # the YAML — keeping the YAML key short while the field name
    # stays explicit. False / missing yields the default (off).
    bcd_enabled = data.get("binary_capability_delta") is True

    return BumpPolicy(
        skip=skips, thresholds=th,
        binary_capability_delta_enabled=bcd_enabled,
    )


def _locator_match(pattern: str, locator: str) -> bool:
    """Match ``locator`` against an operator pattern. ``*`` and
    ``?`` are glob wildcards (via fnmatch). Plain strings match
    literally."""
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatchcase(locator, pattern)
    return pattern == locator
