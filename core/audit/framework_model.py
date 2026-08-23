"""Framework-aware sanitization knowledge for false-positive reduction.

Many web frameworks ship with built-in protections (parameterised queries,
auto-escaping templates, CSRF middleware) that structurally prevent certain
CWE classes.  When a finding targets a CWE that the detected framework
already mitigates, the finding is likely a false positive.

This module provides:
  - ``FrameworkGuarantee`` -- a data class describing one framework's
    built-in protection and which CWE classes it negates.
  - ``FRAMEWORK_GUARANTEES`` -- a static catalog of known protections
    across Django, Flask, Spring, Express, Go stdlib, Rails, and Rust sqlx.
  - ``framework_negates_cwe()`` -- detect the framework from source text
    and check whether a CWE is negated by a framework guarantee.
  - ``format_framework_context()`` -- render guarantees as LLM-consumable
    context strings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from re import Pattern
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass
class FrameworkGuarantee:
    """A single framework protection that negates one or more CWE classes."""

    framework: str
    """Short framework name, e.g. ``"django"``, ``"spring"``."""

    pattern: str
    """Function, decorator, or import pattern that activates the guarantee."""

    guarantees: str
    """Human-readable description of what the pattern guarantees."""

    negates_cwe: list[str] = field(default_factory=list)
    """CWE identifiers (e.g. ``"CWE-89"``) that this pattern prevents."""


# ---------------------------------------------------------------------------
# Static catalog
# ---------------------------------------------------------------------------

FRAMEWORK_GUARANTEES: list[FrameworkGuarantee] = [
    # ------------------------------------------------------------------
    # Django (Python)
    # ------------------------------------------------------------------
    FrameworkGuarantee(
        framework="django",
        pattern="ORM .filter()/.get()/.exclude()",
        guarantees="Django ORM parameterises queries; user input is never "
        "interpolated into SQL",
        negates_cwe=["CWE-89"],
    ),
    FrameworkGuarantee(
        framework="django",
        pattern="@csrf_protect / CsrfViewMiddleware",
        guarantees="Django CSRF middleware validates tokens on state-changing "
        "requests",
        negates_cwe=["CWE-352"],
    ),
    FrameworkGuarantee(
        framework="django",
        pattern="Template auto-escaping (default on)",
        guarantees="Django templates auto-escape variables; XSS prevented "
        "unless |safe or mark_safe is used",
        negates_cwe=["CWE-79"],
    ),
    FrameworkGuarantee(
        framework="django",
        pattern="FileResponse / sendfile",
        guarantees="FileResponse controls the response but does NOT "
        "sanitise the path -- user-controlled filenames still "
        "risk path traversal",
        negates_cwe=[],  # explicitly does NOT negate CWE-22
    ),
    # ------------------------------------------------------------------
    # Flask (Python)
    # ------------------------------------------------------------------
    FrameworkGuarantee(
        framework="flask",
        pattern="render_template() with Jinja2",
        guarantees="Jinja2 auto-escapes HTML by default; XSS prevented "
        "unless |safe filter is used",
        negates_cwe=["CWE-79"],
    ),
    FrameworkGuarantee(
        framework="flask",
        pattern="SQLAlchemy .filter() with bound params",
        guarantees="SQLAlchemy bound parameters prevent SQL injection",
        negates_cwe=["CWE-89"],
    ),
    # ------------------------------------------------------------------
    # Spring (Java)
    # ------------------------------------------------------------------
    FrameworkGuarantee(
        framework="spring",
        pattern="@Valid / @Validated on controller params",
        guarantees="Bean Validation annotations enforce input constraints "
        "before handler execution",
        negates_cwe=["CWE-20"],
    ),
    FrameworkGuarantee(
        framework="spring",
        pattern="JdbcTemplate with ? placeholders",
        guarantees="JdbcTemplate parameterises queries via PreparedStatement",
        negates_cwe=["CWE-89"],
    ),
    FrameworkGuarantee(
        framework="spring",
        pattern="@PreAuthorize",
        guarantees="Spring Security SpEL-based authorization check is "
        "present on the endpoint",
        negates_cwe=["CWE-862"],
    ),
    # ------------------------------------------------------------------
    # Express / Node.js
    # ------------------------------------------------------------------
    FrameworkGuarantee(
        framework="express",
        pattern="helmet() middleware",
        guarantees="Helmet sets security-related HTTP headers "
        "(X-Content-Type-Options, CSP, etc.)",
        negates_cwe=["CWE-693"],
    ),
    FrameworkGuarantee(
        framework="express",
        pattern="express-validator",
        guarantees="express-validator provides input validation and "
        "sanitisation middleware",
        negates_cwe=["CWE-20"],
    ),
    # ------------------------------------------------------------------
    # Go standard library
    # ------------------------------------------------------------------
    FrameworkGuarantee(
        framework="go",
        pattern="database/sql with ? / $1 placeholders",
        guarantees="database/sql parameterises queries via driver-level "
        "prepared statements",
        negates_cwe=["CWE-89"],
    ),
    FrameworkGuarantee(
        framework="go",
        pattern="html/template",
        guarantees="html/template auto-escapes values by context "
        "(HTML, JS, URL)",
        negates_cwe=["CWE-79"],
    ),
    # ------------------------------------------------------------------
    # Rails (Ruby)
    # ------------------------------------------------------------------
    FrameworkGuarantee(
        framework="rails",
        pattern="ActiveRecord .where() with placeholders",
        guarantees="ActiveRecord parameterises queries when using "
        "placeholder syntax",
        negates_cwe=["CWE-89"],
    ),
    FrameworkGuarantee(
        framework="rails",
        pattern="ERB default escaping / h()",
        guarantees="Rails 3+ auto-escapes ERB output; earlier versions "
        "use h() helper",
        negates_cwe=["CWE-79"],
    ),
    # ------------------------------------------------------------------
    # Rust
    # ------------------------------------------------------------------
    FrameworkGuarantee(
        framework="rust",
        pattern="sqlx query!() macro",
        guarantees="sqlx query!() macro is compile-time checked and "
        "parameterised",
        negates_cwe=["CWE-89"],
    ),
]


# ---------------------------------------------------------------------------
# Framework detection helpers
# ---------------------------------------------------------------------------

# Each entry: (framework_name, list_of_(compiled_regex, applicable_cwes) pairs)
# The regex is matched against the full source text.  If a match is found the
# framework is considered present and the associated CWEs are candidates for
# negation.

_FrameworkDetector = tuple[str, list[tuple[Pattern[str], list[str]]]]

_DETECTORS: list[_FrameworkDetector] = [
    (
        "django",
        [
            # ORM parameterised queries
            (
                re.compile(
                    r"(?:from\s+django\.|import\s+django)"
                    r"|\.objects\s*\.\s*(?:filter|get|exclude)\s*\(",
                ),
                ["CWE-89"],
            ),
            # CSRF protection
            (
                re.compile(
                    r"@csrf_protect"
                    r"|CsrfViewMiddleware"
                    r"|django\.middleware\.csrf",
                ),
                ["CWE-352"],
            ),
            # Template auto-escaping (detect Django template usage; the
            # guarantee is void when |safe or mark_safe appears)
            (
                re.compile(
                    r"(?:from\s+django\.template|render_to_string|render\s*\()"
                    r"(?!.*\|\s*safe)(?!.*mark_safe)",
                    re.DOTALL,
                ),
                ["CWE-79"],
            ),
        ],
    ),
    (
        "flask",
        [
            # Jinja2 auto-escaping via render_template
            (
                re.compile(
                    r"(?:from\s+flask\s+import|import\s+flask)"
                    r"|render_template\s*\(",
                ),
                ["CWE-79"],
            ),
            # SQLAlchemy bound parameters
            (
                re.compile(
                    r"(?:from\s+sqlalchemy|import\s+sqlalchemy)"
                    r"|\.filter\s*\(",
                ),
                ["CWE-89"],
            ),
        ],
    ),
    (
        "spring",
        [
            # Bean Validation
            (
                re.compile(r"@Valid\b|@Validated\b"),
                ["CWE-20"],
            ),
            # JdbcTemplate parameterised queries
            (
                re.compile(
                    r"JdbcTemplate"
                    r"|NamedParameterJdbcTemplate"
                    r"|\.query\s*\(.*\?",
                    re.DOTALL,
                ),
                ["CWE-89"],
            ),
            # Spring Security authorization
            (
                re.compile(r"@PreAuthorize\b|@Secured\b"),
                ["CWE-862"],
            ),
        ],
    ),
    (
        "express",
        [
            # Helmet security headers
            (
                re.compile(r"require\s*\(\s*['\"]helmet['\"]\s*\)|helmet\s*\("),
                ["CWE-693"],
            ),
            # express-validator
            (
                re.compile(
                    r"require\s*\(\s*['\"]express-validator['\"]\s*\)"
                    r"|from\s+['\"]express-validator['\"]",
                ),
                ["CWE-20"],
            ),
        ],
    ),
    (
        "go",
        [
            # database/sql parameterised queries
            (
                re.compile(
                    r"\"database/sql\""
                    r"|\.QueryRow\s*\(.*(?:\$\d|\?)"
                    r"|\.Query\s*\(.*(?:\$\d|\?)"
                    r"|\.Exec\s*\(.*(?:\$\d|\?)",
                    re.DOTALL,
                ),
                ["CWE-89"],
            ),
            # html/template auto-escaping
            (
                re.compile(r"\"html/template\""),
                ["CWE-79"],
            ),
        ],
    ),
    (
        "rails",
        [
            # ActiveRecord parameterised queries
            (
                re.compile(
                    r"ActiveRecord|\.where\s*\(.*\?"
                    r"|class\s+\w+\s*<\s*ApplicationRecord",
                    re.DOTALL,
                ),
                ["CWE-89"],
            ),
            # ERB escaping (default in Rails 3+)
            (
                re.compile(r"<%=.*%>|ActionView|\.html_safe"),
                ["CWE-79"],
            ),
        ],
    ),
    (
        "rust",
        [
            # sqlx compile-time checked queries
            (
                re.compile(r"sqlx::query!|sqlx::query_as!"),
                ["CWE-89"],
            ),
        ],
    ),
]

# Pre-index guarantees by (framework, cwe) for O(1) lookup.
_GUARANTEE_INDEX: dict[tuple[str, str], FrameworkGuarantee] = {}
for _g in FRAMEWORK_GUARANTEES:
    for _cwe in _g.negates_cwe:
        _GUARANTEE_INDEX[(_g.framework, _cwe)] = _g


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def framework_negates_cwe(
    file_path: str,
    source: str,
    cwe: str,
) -> FrameworkGuarantee | None:
    """Check whether a framework guarantee negates *cwe* in *source*.

    Detection is lightweight pattern matching on import statements,
    decorators, and method calls.  ``file_path`` is accepted for future
    extension (e.g. language inference from extension) but is currently
    unused beyond logging.

    Returns the matching ``FrameworkGuarantee`` if one is found, or
    ``None`` if no framework protection applies.
    """
    for framework_name, detectors in _DETECTORS:
        for pattern, covered_cwes in detectors:
            if cwe not in covered_cwes:
                continue
            if pattern.search(source):
                guarantee = _GUARANTEE_INDEX.get((framework_name, cwe))
                if guarantee is not None:
                    return guarantee
    return None


def format_framework_context(guarantees: Sequence[FrameworkGuarantee]) -> str:
    """Render a list of guarantees as LLM-consumable context.

    Example output::

        Framework conventions: Django ORM parameterises queries
        (CWE-89 mitigated by framework).
    """
    if not guarantees:
        return ""

    parts: list[str] = []
    for g in guarantees:
        cwes = ", ".join(g.negates_cwe) if g.negates_cwe else "none"
        parts.append(f"{g.framework.capitalize()} {g.pattern} -- "
                     f"{g.guarantees} ({cwes} mitigated by framework)")
    return "Framework conventions: " + "; ".join(parts) + "."
