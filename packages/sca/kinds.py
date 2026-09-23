"""Kind-namespace constants for the ``sca:*`` taxonomy.

Single home for the namespace strings that tag SCA output. Two distinct
uses share these prefixes:

* ``vuln_type`` — the row classifier in ``findings.json`` (see the
  package README's "Finding categories" table). Consumers dispatch on
  exact match (``VULNERABLE_DEPENDENCY``) or on a category prefix
  (``HYGIENE_PREFIX`` etc.).
* ``finding_id`` — the stable per-finding identity. Category prefixes
  are composed with dep coordinates
  (``f"{HYGIENE_PREFIX}{kind}:{eco}:{name}"``).

The values are an on-disk contract: findings.json rows, SARIF rule
ids, suppression files, and cross-run diff baselines all carry them.
Renaming a value is a schema change, not a refactor — existing
suppressions and baselines would silently stop matching.

Note the two supply-chain spellings: ``vuln_type`` uses
``sca:supply_chain:`` (with underscore) while most supply-chain
``finding_id`` values historically use ``sca:supplychain:`` (without).
Both are load-bearing on disk; do not "fix" one to match the other.
"""

from __future__ import annotations

# The tool-level namespace every SCA-owned tag lives under. Consumers
# use it to split SCA rows from other tools' rows in a merged list.
SCA_PREFIX = "sca:"

# ---------------------------------------------------------------------------
# vuln_type values / prefixes (also used as finding_id category prefixes)
# ---------------------------------------------------------------------------

VULNERABLE_DEPENDENCY = "sca:vulnerable_dependency"
HYGIENE_PREFIX = "sca:hygiene:"
SUPPLY_CHAIN_PREFIX = "sca:supply_chain:"
LICENSE_PREFIX = "sca:license:"
SCAN_HEALTH_PREFIX = "sca:scan_health:"

# Full vuln_type values that gates / planners dispatch on individually.
SUPPLY_CHAIN_IMAGE_CAPABILITY_DRIFT = (
    SUPPLY_CHAIN_PREFIX + "image_capability_drift"
)
SUPPLY_CHAIN_GHA_ACTION_REF_DRIFT = (
    SUPPLY_CHAIN_PREFIX + "gha_action_ref_drift"
)

# ---------------------------------------------------------------------------
# finding_id-only namespaces (never appear as a vuln_type)
# ---------------------------------------------------------------------------

# Vulnerable-dependency finding ids:
#   f"{VULN_ID_PREFIX}{eco}:{name}:{version}:{osv_id}"
VULN_ID_PREFIX = "sca:vuln:"

# Historical supply-chain finding-id spelling (no underscore) — see the
# module docstring. New supply-chain checks keep using it so ids stay
# consistent within the category.
SUPPLYCHAIN_ID_PREFIX = "sca:supplychain:"

# Scan-level (non-dep) finding ids, e.g. image capability drift keyed
# by image ref hash.
SCAN_ID_PREFIX = "sca:scan:"

# Version-bump risk evaluator finding ids (packages/sca/bump/).
BUMP_ID_PREFIX = "sca:bump:"

# ---------------------------------------------------------------------------
# Non-finding namespaces that share the tool prefix
# ---------------------------------------------------------------------------

# Scorecard decision-class for the major-bump LLM prefilter, keyed by
# ecosystem: f"{MAJOR_BUMP_DECISION_CLASS_PREFIX}{ecosystem}".
MAJOR_BUMP_DECISION_CLASS_PREFIX = "sca:major_bump:"

# RAPTOR-owned per-repo config files. These are NOT dependency
# manifests: the generic YAML surfaces (the kubernetes candidate
# router — which also feeds the image-ref walker) skip them so
# "ignored when untrusted" holds for the FILE, not just the
# suppression/license lane. Owners: suppressions.SUPPRESS_FILENAME,
# pipeline._LICENSE_POLICY_FILENAME (membership pinned by tests).
RAPTOR_CONFIG_FILENAMES = (
    ".raptor-sca-suppress.yml",
    ".raptor-sca-license-policy.yml",
)
