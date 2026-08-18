"""Leg-1 security-role classifier for the fail-open channel.

Binds a *role* to the guarded call/region of a fail-open hypothesis
("this ``except: pass`` wraps token verification"), with an explicit
evidence source and grade on every binding. The vocabulary policy is
tiered and structurally enforced:

* **Tier A — universal vocabulary** (hardcoded here): libc/POSIX
  security surfaces and language-stdlib security *module paths*.
  Properties of the platform, never of a target.
* **Tier B — framework hook mechanics** (hardcoded here): *how*
  security handlers register (decorator/registration/signature
  patterns), never per-project API name lists.
* **Tier C — target/library vocabulary** (never a shipped list):
  binds at run time from RAPTOR's learned-vocabulary surfaces —
  operator annotations, study domain models, IRIS/taint specs,
  discovered project sinks, discovered conventions. A small
  seed-exemplar set (single-digit, marked) exists only to bootstrap
  shape matching; coverage gaps are fixed in the learned-vocab
  plumbing, never by growing lists here.

Evidence-laundering firewall (mirrors
``evidence_grade.sanitize_llm_evidence_tool``): a role premise that is
only an uncorroborated LLM guess (heuristic-tier spec, naming stem,
lone seed match) is **detection-grade** — it can never single-handedly
turn an LLM hypothesis into tool-confirmed evidence. Registry-grade
sources (operator annotation, domain-model invariant, corroborated
spec tier, call-graph-derived sink, Tier A/B, established convention)
are promote-capable. Two independent detection-grade sources agreeing
upgrade to registry-grade, mirroring the aggregation posterior rule.

CI size-budget lint: :func:`registry_budget_violations` fails when any
registry or seed set exceeds its budget — "huge special-case list" is
structurally impossible, not just discouraged. Related registries with
different consumers/shapes: ``framework_model.FRAMEWORK_GUARANTEES``,
``negative_space._FRAMEWORK_PATTERNS`` (deliberate, documented debt —
a dedup-wave hoist candidate).
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Grades a role binding can carry (promotion rights, see module doc).
GRADE_REGISTRY = "registry"
GRADE_DETECTION = "detection"

# Size budgets — enforced by registry_budget_violations() and the
# TestVocabPolicy CI lint. Growing a registry past its budget must
# fail the build; the fix for coverage is learned vocab, not lists.
TIER_A_CATEGORY_CAP = 12
SEED_SET_CAP = 9


@dataclass(frozen=True)
class RoleAPI:
    """One Tier-A universal entry or Tier-C seed exemplar."""

    name: str               # "setuid" (tier A) | "EVP_VerifyFinal" (seed)
    role: str               # "privilege" | "crypto" | ...
    contract: str           # "tristate:1=ok,0=fail,-1=error" | "zero_ok"
                            # | "nonneg_ok" | "err_second" | ""
    langs: tuple[str, ...]
    tier: str               # "universal" | "seed_exemplar"


@dataclass(frozen=True)
class FrameworkHook:
    """Tier B — registration mechanics only, never API name lists."""

    framework: str          # "django" | "flask" | "fastapi" | ...
    role: str               # "auth" | "validation" | "session" | "csrf"
    pattern: str            # regex on decorator/registration/signature


# ── Tier A: universal vocabulary ────────────────────────────────────
# POSIX privilege / filesystem-isolation surface. Contracts are the
# documented return conventions ("zero_ok" = 0 on success, non-zero /
# -1 on failure).

TIER_A_UNIVERSAL: tuple[RoleAPI, ...] = (
    # Privilege drops — failure means the process KEEPS privilege.
    RoleAPI("setuid", "privilege", "zero_ok", ("c", "cpp"), "universal"),
    RoleAPI("setgid", "privilege", "zero_ok", ("c", "cpp"), "universal"),
    RoleAPI("seteuid", "privilege", "zero_ok", ("c", "cpp"), "universal"),
    RoleAPI("setegid", "privilege", "zero_ok", ("c", "cpp"), "universal"),
    RoleAPI("setresuid", "privilege", "zero_ok", ("c", "cpp"), "universal"),
    RoleAPI("setresgid", "privilege", "zero_ok", ("c", "cpp"), "universal"),
    RoleAPI("setgroups", "privilege", "zero_ok", ("c", "cpp"), "universal"),
    RoleAPI("initgroups", "privilege", "zero_ok", ("c", "cpp"), "universal"),
    # Filesystem isolation / access checks.
    RoleAPI("chroot", "fs_isolation", "zero_ok", ("c", "cpp"), "universal"),
    RoleAPI("access", "fs_isolation", "zero_ok", ("c", "cpp"), "universal"),
    RoleAPI("mlock", "memory_protection", "zero_ok", ("c", "cpp"),
            "universal"),
    RoleAPI("mlockall", "memory_protection", "zero_ok", ("c", "cpp"),
            "universal"),
)

# Language-stdlib security surfaces, matched by MODULE PATH prefix on
# dotted callees — not exhaustive function lists.
TIER_A_MODULE_PREFIXES: dict[str, str] = {
    "ssl.": "crypto",
    "hmac.": "crypto",
    "secrets.": "crypto",
    "hashlib.": "crypto",
    "crypto/": "crypto",        # Go crypto/* import path shape
    "java.security.": "crypto",
}

# Tier-A security-relevant flag/mode vocabulary — grading input for
# the consistency programme's flag/mode comparator (§3.7 / §5.1: this
# registry is the single Tier-A home; the comparator itself is
# vocabulary-free and detects ANY constant deviation — these entries
# only grade security relevance). Properties of the platform
# (POSIX open(2) flags, stdlib TLS kwargs), never of a target.
# Budget-linted like every other registry here.

@dataclass(frozen=True)
class SecurityFlag:
    """One universally security-relevant flag / keyword argument."""

    name: str       # "O_NOFOLLOW" | "verify" | "shell" | ...
    kind: str       # "bitmask_flag" | "kwarg_bool"
    role: str       # "fs_isolation" | "tls_verify" | "cmd_injection"
    safe_when: str  # "present" | "true" | "false"
    cwe: str        # graded CWE family for the dangerous direction


TIER_A_SECURITY_FLAGS: tuple[SecurityFlag, ...] = (
    SecurityFlag("O_NOFOLLOW", "bitmask_flag", "fs_isolation",
                 "present", "CWE-59"),
    SecurityFlag("O_EXCL", "bitmask_flag", "fs_isolation",
                 "present", "CWE-367"),
    SecurityFlag("O_CLOEXEC", "bitmask_flag", "fd_hygiene",
                 "present", "CWE-403"),
    SecurityFlag("MSG_NOSIGNAL", "bitmask_flag", "signal_safety",
                 "present", "CWE-248"),
    SecurityFlag("verify", "kwarg_bool", "tls_verify",
                 "true", "CWE-295"),
    SecurityFlag("check_hostname", "kwarg_bool", "tls_verify",
                 "true", "CWE-295"),
    SecurityFlag("shell", "kwarg_bool", "cmd_injection",
                 "false", "CWE-78"),
)


def security_flag_role(name: str) -> SecurityFlag | None:
    """Grade a flag token / kwarg name against the Tier-A vocabulary.

    Grading only — a miss means "ungraded lead", never "suppressed".
    """
    for entry in TIER_A_SECURITY_FLAGS:
        if entry.name == name:
            return entry
    return None


# ── Tier C seed exemplars ───────────────────────────────────────────
# SEED EXEMPLARS — pattern illustrators, not the operating mechanism.
# Present so the tri-state comparison-shape matcher has documented,
# testable instances; a seed match alone is detection-grade. Scaling
# is learned vocab (annotations / domain model / IRIS specs / sinks),
# NEVER growth of this list (SEED_SET_CAP enforced).

SEED_EXEMPLARS: tuple[RoleAPI, ...] = (
    # CVE-2008-5077: EVP_VerifyFinal returns 1=ok, 0=bad sig, -1=error;
    # truth-testing the result accepts -1 as a valid signature.
    RoleAPI("EVP_VerifyFinal", "crypto", "tristate:1=ok,0=fail,-1=error",
            ("c", "cpp"), "seed_exemplar"),
    # Same contract triple, EVP_DigestVerify* generation.
    RoleAPI("EVP_DigestVerifyFinal", "crypto",
            "tristate:1=ok,0=fail,-1=error", ("c", "cpp"), "seed_exemplar"),
    # X509_verify_cert: 1=ok, 0=fail, <0 internal error.
    RoleAPI("X509_verify_cert", "cert",
            "tristate:1=ok,0=fail,-1=error", ("c", "cpp"), "seed_exemplar"),
)

# ── Tier B: framework hook mechanics ────────────────────────────────
# Registration mechanics only — decorator / annotation / signature /
# implements-clause shapes, never per-project API name lists. Phase 1
# shipped the Python frameworks; phase 2 adds Spring/Jakarta
# filter+interceptor registration.

TIER_B_HOOK_CAP = 16

TIER_B_FRAMEWORK_HOOKS: tuple[FrameworkHook, ...] = (
    FrameworkHook(
        "flask", "auth",
        r"@(?:[A-Za-z_]\w*\.)?login_required\b"
        r"|@(?:[A-Za-z_]\w*\.)?before_request\b",
    ),
    FrameworkHook(
        "django", "auth",
        r"@(?:login_required|permission_required|user_passes_test)\b",
    ),
    FrameworkHook(
        "django", "session",
        r"def\s+process_(?:request|view|exception)\s*\(",
    ),
    FrameworkHook(
        "fastapi", "validation",
        r"\bDepends\s*\(|@(?:field_)?validator\b",
    ),
    # Spring method security (annotation mechanics) and filter /
    # interceptor registration (extends / implements / hook-method
    # signature mechanics).
    FrameworkHook(
        "spring", "auth",
        r"@(?:PreAuthorize|PostAuthorize|Secured)\b",
    ),
    FrameworkHook(
        "spring", "request_filter",
        r"\bextends\s+(?:OncePerRequestFilter|GenericFilterBean)\b"
        r"|\bimplements\s+HandlerInterceptor\b"
        r"|\bboolean\s+preHandle\s*\(",
    ),
    # Jakarta/javax servlet filters + JSR-250 authorization
    # annotations.
    FrameworkHook(
        "jakarta", "auth",
        r"@(?:RolesAllowed|DenyAll|ServletSecurity)\b",
    ),
    FrameworkHook(
        "jakarta", "request_filter",
        r"@WebFilter\b"
        r"|\bimplements\s+(?:jakarta\.servlet\.|javax\.servlet\.)?Filter\b"
        r"|\bvoid\s+doFilter\s*\(",
    ),
    # Go middleware mechanics: the net/http wrapper signature (shared
    # by chi and most router ecosystems) and gin's HandlerFunc type.
    # Plain `func(w, r)` request handlers deliberately do NOT match —
    # a handler is not a gate; the wrapper shape is.
    FrameworkHook(
        "go-net/http", "middleware",
        r"func\s*\w*\s*\(\s*\w+\s+http\.Handler\s*\)\s*http\.Handler",
    ),
    FrameworkHook(
        "gin", "middleware",
        r"\bgin\.HandlerFunc\b|func\s*\(\s*\w+\s+\*gin\.Context\s*\)",
    ),
)

# ── Naming heuristics (weakest tier; detection-grade only) ──────────
# Universal identifier stems; matching a *target* identifier against
# them is still only a guess about that target — hence detection-grade
# (mirrors taint_specs.classify_role_heuristic).

_NAMING_STEM_RE = re.compile(
    r"auth[nz]?|verify|validate|sanitiz|permission|perm(?:_|$)|acl"
    r"|crypt|sign|cert|session|token|csrf|origin|trust",
    re.IGNORECASE,
)

# Library-name prefixes that must never appear as Tier-A entries — the
# structural "no hardcoded project/library API lists" enforcement used
# by registry_budget_violations().
_LIBRARY_PREFIX_RE = re.compile(
    r"^(?:EVP_|BIO_|SSL_|X509_|PEM_|RSA_|EC_|BN_|jwt\.|django\.|flask\."
    r"|fastapi\.|spring\.|express\.)",
)

# Tri-state contract mined from domain-model contract prose
# ("returns 1 on success, 0 on failure, -1 on error").
_TRISTATE_PROSE_RE = re.compile(
    r"1\s*(?:=|on|for|means)?\s*(?:ok|success|valid).{0,60}"
    r"0\s*(?:=|on|for|means)?\s*(?:fail|invalid|bad).{0,60}"
    r"(?:-1|negative)\s*(?:=|on|for|means)?\s*(?:error|fault)",
    re.IGNORECASE | re.DOTALL,
)
_ZERO_OK_PROSE_RE = re.compile(
    r"returns?\s+(?:0|zero)\s+on\s+success", re.IGNORECASE,
)
_MUST_CHECK_PROSE_RE = re.compile(
    r"must\s+(?:be\s+)?check|return value must", re.IGNORECASE,
)

# Guard-ish semantics an invariant statement must express before it
# binds a role (an invariant merely *mentioning* a function is not a
# role assertion about it).
_GUARD_SEMANTICS_RE = re.compile(
    r"must\s+(?:succeed|verify|validate|pass|be\s+checked|hold)"
    r"|before\s+|only\s+(?:if|when|after)|fail|reject|deny"
    r"|verif|validat|authoriz|authenticat",
    re.IGNORECASE,
)

# Annotation statuses that assert a security role.
_ROLE_ANNOTATION_STATUSES = frozenset({
    "sink", "trust_boundary", "entry_point",
})

# IRIS/taint evidence tiers corroborated enough to be registry-grade.
_CORROBORATED_SPEC_TIERS = frozenset({
    "observed_runtime", "replayed_crash", "smt_proved",
    "xref_backed", "header_backed",
})


@dataclass
class RoleEvidence:
    """One role binding with source, provenance and promotion grade."""

    kind: str          # "auth" | "crypto" | "privilege" | "sanitiser" | ...
    source: str        # annotation | domain_model | iris_spec | taint_spec
                       # | sink_catalog | universal_registry
                       # | framework_registry | convention | naming
                       # | seed_exemplar
    matched: str       # the identifier / pattern that matched
    confidence: str    # high | medium | low
    provenance: str    # e.g. "iris_spec:xref_backed", "annotation",
                       # "tier_a:posix-privilege"
    grade: str         # GRADE_REGISTRY | GRADE_DETECTION
    contract: str = ""  # return contract when the source records one

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "kind": self.kind,
            "source": self.source,
            "matched": self.matched,
            "confidence": self.confidence,
            "provenance": self.provenance,
            "grade": self.grade,
        }
        if self.contract:
            d["contract"] = self.contract
        return d


@dataclass
class RoleContext:
    """Runtime learned-vocabulary surfaces available to the classifier.

    Every field is optional — the classifier degrades to Tier A/B +
    naming when a surface is absent. ``conventions`` carries runtime
    ``negative_space.SecurityConvention`` objects; ``wur_functions``
    carries harvested ``wur:<function>`` facts from source-intel.
    """

    out_dir: Path | None = None
    annotations_dir: Path | None = None
    inventory: dict[str, Any] | None = None
    conventions: list[Any] = field(default_factory=list)
    context_map: dict[str, Any] | None = None
    wur_functions: frozenset[str] = frozenset()


# ── registry budget lint ────────────────────────────────────────────


def registry_budget_violations() -> list[str]:
    """Structural vocabulary-policy lint (consumed by CI tests).

    Returns human-readable violations; an empty list means the
    registries honour the tier policy: Tier A per-category caps hold,
    seed sets stay single-digit, tiers are labelled correctly, and no
    Tier-A entry smuggles in a library API name.
    """
    violations: list[str] = []

    by_category: dict[str, int] = {}
    for entry in TIER_A_UNIVERSAL:
        if entry.tier != "universal":
            violations.append(
                f"TIER_A_UNIVERSAL entry {entry.name!r} has tier "
                f"{entry.tier!r} (must be 'universal')",
            )
        if _LIBRARY_PREFIX_RE.match(entry.name):
            violations.append(
                f"TIER_A_UNIVERSAL entry {entry.name!r} matches a known "
                "library prefix — library vocabulary is Tier C (learned)",
            )
        by_category[entry.role] = by_category.get(entry.role, 0) + 1
    for category, count in sorted(by_category.items()):
        if count > TIER_A_CATEGORY_CAP:
            violations.append(
                f"Tier-A category {category!r} has {count} entries "
                f"(cap {TIER_A_CATEGORY_CAP})",
            )
    if len(TIER_A_MODULE_PREFIXES) > TIER_A_CATEGORY_CAP:
        violations.append(
            f"TIER_A_MODULE_PREFIXES has {len(TIER_A_MODULE_PREFIXES)} "
            f"entries (cap {TIER_A_CATEGORY_CAP})",
        )

    flags_by_role: dict[str, int] = {}
    for flag in TIER_A_SECURITY_FLAGS:
        if _LIBRARY_PREFIX_RE.match(flag.name):
            violations.append(
                f"TIER_A_SECURITY_FLAGS entry {flag.name!r} matches a "
                "known library prefix — library vocabulary is Tier C "
                "(learned)",
            )
        if flag.kind not in ("bitmask_flag", "kwarg_bool"):
            violations.append(
                f"TIER_A_SECURITY_FLAGS entry {flag.name!r} has "
                f"unknown kind {flag.kind!r}",
            )
        flags_by_role[flag.role] = flags_by_role.get(flag.role, 0) + 1
    for role, count in sorted(flags_by_role.items()):
        if count > TIER_A_CATEGORY_CAP:
            violations.append(
                f"Tier-A flag role {role!r} has {count} entries "
                f"(cap {TIER_A_CATEGORY_CAP})",
            )

    seed_by_category: dict[str, int] = {}
    for entry in SEED_EXEMPLARS:
        if entry.tier != "seed_exemplar":
            violations.append(
                f"SEED_EXEMPLARS entry {entry.name!r} has tier "
                f"{entry.tier!r} (must be 'seed_exemplar')",
            )
        seed_by_category[entry.role] = seed_by_category.get(entry.role, 0) + 1
    for category, count in sorted(seed_by_category.items()):
        if count > SEED_SET_CAP:
            violations.append(
                f"seed-exemplar category {category!r} has {count} entries "
                f"(cap {SEED_SET_CAP})",
            )

    if len(TIER_B_FRAMEWORK_HOOKS) > TIER_B_HOOK_CAP:
        violations.append(
            f"TIER_B_FRAMEWORK_HOOKS has {len(TIER_B_FRAMEWORK_HOOKS)} "
            f"entries (cap {TIER_B_HOOK_CAP}) — hook mechanics are a "
            "bounded vocabulary; per-project names are Tier C (learned)",
        )
    for hook in TIER_B_FRAMEWORK_HOOKS:
        try:
            re.compile(hook.pattern)
        except re.error as exc:
            violations.append(
                f"TIER_B hook {hook.framework}/{hook.role} pattern does "
                f"not compile: {exc}",
            )

    return violations


# ── learned-vocab adapters (Tier C proper) ──────────────────────────


def _annotation_role(
    names: Sequence[str], file_path: str, ctx: RoleContext,
) -> RoleEvidence | None:
    """Operator annotations — the strongest learned source."""
    base = ctx.annotations_dir
    if base is None and ctx.out_dir is not None:
        candidate = Path(ctx.out_dir) / "annotations"
        base = candidate if candidate.is_dir() else None
    if base is None:
        return None
    try:
        from core.annotations.storage import read_file_annotations
        annotations = read_file_annotations(Path(base), file_path)
    except Exception:
        logger.debug("fail_open role: annotation read failed", exc_info=True)
        return None
    wanted = {n for n in names if n}
    for ann in annotations:
        status = (ann.metadata or {}).get("status", "")
        if status in _ROLE_ANNOTATION_STATUSES and ann.function in wanted:
            return RoleEvidence(
                kind=status,
                source="annotation",
                matched=ann.function,
                confidence="high",
                provenance="annotation",
                grade=GRADE_REGISTRY,
            )
    return None


def _contract_from_prose(prose: str) -> str:
    if not prose:
        return ""
    if _TRISTATE_PROSE_RE.search(prose):
        return "tristate:1=ok,0=fail,-1=error"
    if _ZERO_OK_PROSE_RE.search(prose):
        return "zero_ok"
    return ""


def _domain_model_role(
    names: Sequence[str], file_path: str, ctx: RoleContext,
) -> RoleEvidence | None:
    """Study domain model: guard-role invariants + per-function
    contracts, loaded through the bridge's cached accessors."""
    if ctx.out_dir is None:
        return None
    try:
        from core.concepts.audit_bridge import (
            _find_domain_model,
            _guard_in_scope,
        )
        model = _find_domain_model(Path(ctx.out_dir))
    except Exception:
        logger.debug("fail_open role: domain model load failed",
                     exc_info=True)
        return None
    if not model:
        return None

    wanted = [n for n in names if n]

    for inv in model.get("invariants") or []:
        if not isinstance(inv, dict):
            continue
        text = " ".join(
            str(inv.get(k) or "")
            for k in ("statement", "negation", "mechanical_rule", "id")
        )
        if not _GUARD_SEMANTICS_RE.search(text):
            continue
        if not _guard_in_scope(inv, file_path):
            continue
        for name in wanted:
            tail = name.rsplit(".", 1)[-1]
            if tail and re.search(rf"\b{re.escape(tail)}\b", text):
                return RoleEvidence(
                    kind="guard",
                    source="domain_model",
                    matched=name,
                    confidence="high",
                    provenance=f"domain_model:{inv.get('id', 'invariant')}",
                    grade=GRADE_REGISTRY,
                )

    for contract in model.get("contracts") or []:
        if not isinstance(contract, dict):
            continue
        fn = contract.get("function") or ""
        for name in wanted:
            if fn and fn == name.rsplit(".", 1)[-1]:
                prose = " ".join(
                    str(contract.get(k) or "")
                    for k in ("output_semantics", "implication", "when")
                )
                if not (_GUARD_SEMANTICS_RE.search(prose)
                        or _MUST_CHECK_PROSE_RE.search(prose)
                        or _contract_from_prose(prose)):
                    continue
                return RoleEvidence(
                    kind="guard",
                    source="domain_model",
                    matched=name,
                    confidence="high",
                    provenance="domain_model:contract",
                    grade=GRADE_REGISTRY,
                    contract=_contract_from_prose(prose),
                )
    return None


def _iris_spec_role(
    names: Sequence[str], file_path: str, ctx: RoleContext,
) -> RoleEvidence | None:
    """IRIS/taint specs — the spec's EvidenceTier is carried onto the
    receipt verbatim and decides the grade."""
    if ctx.out_dir is None:
        return None
    spec_path = Path(ctx.out_dir) / "iris-taint-specs.json"
    if not spec_path.is_file():
        return None
    try:
        from core.audit.iris_specs import specs_from_json
        specs = specs_from_json(spec_path.read_text(encoding="utf-8"))
    except Exception:
        logger.debug("fail_open role: iris spec load failed", exc_info=True)
        return None
    wanted = {n.rsplit(".", 1)[-1] for n in names if n}
    for spec in specs:
        role = getattr(spec, "role", "")
        if role not in ("sanitiser", "sink", "source"):
            continue
        if spec.function not in wanted:
            continue
        tier = getattr(spec, "evidence_tier", None)
        tier_value = getattr(tier, "value", str(tier or "heuristic"))
        grade = (
            GRADE_REGISTRY if tier_value in _CORROBORATED_SPEC_TIERS
            else GRADE_DETECTION
        )
        return RoleEvidence(
            kind=role,
            source="iris_spec",
            matched=spec.function,
            confidence="high" if grade == GRADE_REGISTRY else "low",
            provenance=f"iris_spec:{tier_value}",
            grade=grade,
        )
    return None


def _sink_catalog_role(
    names: Sequence[str], file_path: str, ctx: RoleContext,
) -> RoleEvidence | None:
    """Discovered project sinks (call-graph facts for wrapper /
    side_effect reasons; naming-reason sinks stay detection-grade)."""
    if ctx.out_dir is None:
        return None
    catalog = Path(ctx.out_dir) / "discovered-sinks.json"
    if not catalog.is_file():
        return None
    try:
        data = json.loads(catalog.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    wanted = {n.rsplit(".", 1)[-1] for n in names if n}
    for sink in data.get("discovered_sinks") or []:
        if not isinstance(sink, dict):
            continue
        fn = sink.get("function") or ""
        if fn not in wanted:
            continue
        reason = sink.get("reason") or ""
        grade = (
            GRADE_REGISTRY if reason in ("wrapper", "side_effect")
            else GRADE_DETECTION
        )
        return RoleEvidence(
            kind="sink",
            source="sink_catalog",
            matched=fn,
            confidence="high" if grade == GRADE_REGISTRY else "low",
            provenance=f"sink_catalog:{reason or 'unknown'}",
            grade=grade,
        )
    return None


def _convention_role(
    names: Sequence[str], enclosing_source: str, ctx: RoleContext,
) -> RoleEvidence | None:
    """Runtime SecurityConvention objects from discover_conventions
    (auth / validation concerns only)."""
    if not ctx.conventions:
        return None
    try:
        from core.audit.negative_space import MIN_CONVENTION_OCCURRENCES
    except ImportError:
        return None
    for conv in ctx.conventions:
        concern = getattr(conv, "concern", "")
        if not any(c in concern for c in ("auth", "validation")):
            continue
        if getattr(conv, "occurrences", 0) < MIN_CONVENTION_OCCURRENCES:
            continue
        pattern = getattr(conv, "pattern", "")
        if not pattern:
            continue
        try:
            conv_re = re.compile(pattern)
        except re.error:
            continue
        for name in names:
            if name and conv_re.search(name):
                return RoleEvidence(
                    kind=concern,
                    source="convention",
                    matched=name,
                    confidence="medium",
                    provenance=f"convention:{pattern}",
                    grade=GRADE_REGISTRY,
                )
        if enclosing_source and conv_re.search(enclosing_source):
            return RoleEvidence(
                kind=concern,
                source="convention",
                matched=pattern,
                confidence="medium",
                provenance=f"convention:{pattern}",
                grade=GRADE_REGISTRY,
            )
    return None


# ── static registry adapters (Tier A / B / seeds / naming) ──────────


def _tier_a_role(
    names: Sequence[str], language: str,
) -> RoleEvidence | None:
    for name in names:
        if not name:
            continue
        tail = name.rsplit(".", 1)[-1]
        for entry in TIER_A_UNIVERSAL:
            if language in entry.langs and tail == entry.name:
                return RoleEvidence(
                    kind=entry.role,
                    source="universal_registry",
                    matched=entry.name,
                    confidence="high",
                    provenance=f"tier_a:posix-{entry.role}",
                    grade=GRADE_REGISTRY,
                    contract=entry.contract,
                )
        for prefix, role in TIER_A_MODULE_PREFIXES.items():
            if name.startswith(prefix):
                return RoleEvidence(
                    kind=role,
                    source="universal_registry",
                    matched=name,
                    confidence="high",
                    provenance=f"tier_a:stdlib-module:{prefix}",
                    grade=GRADE_REGISTRY,
                )
    return None


def _tier_b_role(enclosing_source: str) -> RoleEvidence | None:
    if not enclosing_source:
        return None
    for hook in TIER_B_FRAMEWORK_HOOKS:
        m = re.search(hook.pattern, enclosing_source)
        if m:
            return RoleEvidence(
                kind=hook.role,
                source="framework_registry",
                matched=m.group(0).strip(),
                confidence="high",
                provenance=f"tier_b:{hook.framework}-hook-mechanics",
                grade=GRADE_REGISTRY,
            )
    return None


def _seed_exemplar_role(
    names: Sequence[str], language: str,
) -> RoleEvidence | None:
    for name in names:
        tail = name.rsplit(".", 1)[-1] if name else ""
        for entry in SEED_EXEMPLARS:
            if language in entry.langs and tail == entry.name:
                return RoleEvidence(
                    kind=entry.role,
                    source="seed_exemplar",
                    matched=entry.name,
                    confidence="low",
                    provenance=f"seed_exemplar:{entry.name}",
                    grade=GRADE_DETECTION,
                    contract=entry.contract,
                )
    return None


def _naming_role(names: Sequence[str]) -> RoleEvidence | None:
    for name in names:
        if not name:
            continue
        m = _NAMING_STEM_RE.search(name)
        if m:
            return RoleEvidence(
                kind="security_naming",
                source="naming",
                matched=name,
                confidence="low",
                provenance=f"naming:{m.group(0).lower()}",
                grade=GRADE_DETECTION,
            )
    return None


def lookup_contract(
    callee: str,
    *,
    language: str,
    context: RoleContext | None = None,
) -> str:
    """Return contract for ``callee`` from any source that records one.

    Consulted when the winning role evidence carries no contract (a
    domain-model *invariant* binds the role but the contract triple
    lives on the seed exemplar / Tier-A entry / domain-model
    *contract*). Order: domain-model contract prose, Tier-A registry,
    seed exemplars.
    """
    ctx = context or RoleContext()
    tail = callee.rsplit(".", 1)[-1] if callee else ""
    if not tail:
        return ""
    if ctx.out_dir is not None:
        try:
            from core.concepts.audit_bridge import _find_domain_model
            model = _find_domain_model(Path(ctx.out_dir)) or {}
        except Exception:
            logger.debug("fail_open contract: domain model load failed",
                         exc_info=True)
            model = {}
        for contract in model.get("contracts") or []:
            if isinstance(contract, dict) \
                    and contract.get("function") == tail:
                prose = " ".join(
                    str(contract.get(k) or "")
                    for k in ("output_semantics", "implication", "when")
                )
                mined = _contract_from_prose(prose)
                if mined:
                    return mined
    for entry in TIER_A_UNIVERSAL:
        if language in entry.langs and entry.name == tail:
            return entry.contract
    for entry in SEED_EXEMPLARS:
        if language in entry.langs and entry.name == tail:
            return entry.contract
    return ""


# ── entry point ─────────────────────────────────────────────────────


def bind_role(
    callee_names: Iterable[str],
    enclosing_function: str,
    file_path: str,
    *,
    language: str,
    context: RoleContext | None = None,
    enclosing_source: str = "",
) -> RoleEvidence | None:
    """Bind a security role to the guarded region.

    ``callee_names`` are the calls inside the guarded region (try body
    / flagged statement); ``enclosing_function`` participates as a
    candidate too (a swallow inside ``verify_token`` is role-bearing
    even when the callee is anonymous). Sources are consulted in
    evidence-precedence order, strongest first; the first registry-
    grade hit wins. Detection-grade hits are collected — two agreeing
    *independent* sources upgrade to registry grade (the aggregation
    posterior rule expressed at the role level).

    Returns ``None`` when no role binds at all — the channel then
    returns ``inconclusive("role-unbound")``, never confirmed.
    """
    ctx = context or RoleContext()
    names = [n for n in callee_names if n]
    if enclosing_function:
        names.append(enclosing_function)
    if not names:
        return None

    detection_hits: list[RoleEvidence] = []

    checks = (
        lambda: _annotation_role(names, file_path, ctx),
        lambda: _domain_model_role(names, file_path, ctx),
        lambda: _iris_spec_role(names, file_path, ctx),
        lambda: _tier_a_role(names, language),
        lambda: _sink_catalog_role(names, file_path, ctx),
        lambda: _tier_b_role(enclosing_source),
        lambda: _convention_role(names, enclosing_source, ctx),
        lambda: _seed_exemplar_role(names, language),
        lambda: _naming_role(names),
    )
    for check in checks:
        evidence = check()
        if evidence is None:
            continue
        if evidence.grade == GRADE_REGISTRY:
            return evidence
        if all(evidence.source != d.source for d in detection_hits):
            detection_hits.append(evidence)

    if not detection_hits:
        return None
    # Two independent detection-grade sources agree — upgrade to
    # registry grade (mirrors _aggregate_channel_confirmations'
    # two-independent-namespaces rule). Purely name-derived sources
    # (naming stem, seed exemplar) are NOT independent of each other —
    # both key on the same identifier string — so at least one of the
    # pair must be a learned artifact.
    name_derived = frozenset({"naming", "seed_exemplar"})
    if len(detection_hits) >= 2 and not all(
        d.source in name_derived for d in detection_hits[:2]
    ):
        first, second = detection_hits[0], detection_hits[1]
        return RoleEvidence(
            kind=first.kind,
            source=first.source,
            matched=first.matched,
            confidence="medium",
            provenance=(
                f"upgraded:{first.provenance}+{second.provenance}"
            ),
            grade=GRADE_REGISTRY,
            contract=first.contract or second.contract,
        )
    return detection_hits[0]
