"""Classify extracted guard conditions into security-relevant categories.

Categories:
  auth     — authentication/authorization checks
  bounds   — size/length/index bounds validation
  null     — null/nil/None/nullptr checks
  config   — configuration flags, debug modes, feature gates
  error    — error status checks (errno, result codes)
  type     — type checks, instanceof, type assertions
  resource — resource availability (file exists, connection open)
  unknown  — cannot classify
"""

from __future__ import annotations

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Category patterns — ordered by specificity (most specific first)
# ---------------------------------------------------------------------------

# Auth/authorization patterns
_AUTH_RE = re.compile(
    r"(?:"
    r"\b(?:is_?auth(?:enticated|orized)?|check_?(?:auth|permission|access|role)"
    r"|has_?(?:permission|role|access|privilege)|require_?(?:auth|login|role)"
    r"|verify_?(?:token|session|credentials?|access)"
    r"|login_?required|auth_?required|is_?(?:admin|superuser|root|owner)"
    r"|is_?logged_?in|ensure_?auth|can_?access|allowed|permitted"
    r"|is_?valid_?token|is_?valid_?session"
    r"|authenticate|authorize)\b"
    # Decorator-style
    r"|@(?:login_required|permission_required|auth_required"
    r"|jwt_required|token_required|requires_auth|protected"
    r"|authenticated|permissions_required|require_role)"
    # Common auth variable patterns
    r"|\b(?:user|session|token|credentials?)\.(?:is_?valid|is_?active"
    r"|authenticated|authorized|role|permissions?)\b"
    # Go/Java middleware patterns
    r"|\b(?:AuthMiddleware|RequireRole|RequireAuth"
    r"|ensureAuthenticated|isLoggedIn|requiresPermission)\b"
    r")",
    re.IGNORECASE,
)

# Bounds/size/length checks
_BOUNDS_RE = re.compile(
    r"(?:"
    # Length/size comparisons
    r"\b(?:len|length|size|count|num|n_?items|capacity)\s*[(<>=!]"
    r"|\b\w+\.(?:len(?:gth)?|size|count|capacity)\s*[(<>=!]"
    # Index/offset bounds
    r"|\b(?:idx?|index|offset|pos(?:ition)?|cursor)\s*(?:<|<=|>=|>)\s*"
    # limit/max/min comparisons
    r"|\b(?:max_?|min_?|limit|cap|bound|threshold|ceiling|floor)\w*\s*(?:[<>=!])"
    r"|\b\w+\s*(?:<|<=|>=|>)\s*(?:max_?|min_?|limit|cap|bound|threshold)\w*\b"
    # Array/buffer size
    r"|\b(?:buf(?:fer)?_?(?:len|size|sz)|arr(?:ay)?_?(?:len|size))\b"
    # sizeof comparisons
    r"|\bsizeof\s*\("
    # Range checks: 0 <= x < N
    r"|\b\d+\s*(?:<|<=)\s*\w+\s*(?:<|<=)\s*\d+"
    r")",
    re.IGNORECASE,
)

# Null/nil/None/nullptr checks
_NULL_RE = re.compile(
    r"(?:"
    r"\b(?:is\s+None|is\s+not\s+None|not\s+None)\b"
    r"|\b(?:nil|null|nullptr|NULL|Nil)\b"
    r"|\b\w+\s*(?:==|!=)\s*(?:nil|null|nullptr|NULL|None)\b"
    r"|\b(?:nil|null|nullptr|NULL|None)\s*(?:==|!=)\s*\w+"
    # C-style: if (!ptr) — require pointer-like identifiers
    r"|!\s*(?:p(?:tr)?|buf(?:fer)?|data|ctx|obj|handle|node|ref|mem|alloc|str|msg|dev|req|res|conn)\s*[)\s{]"
    # Optional chaining / unwrap
    r"|\?\."
    # Go: err != nil
    r"|\berr\s*!=\s*nil\b"
    r")",
    re.IGNORECASE,
)

# Configuration/debug/feature flags
_CONFIG_RE = re.compile(
    r"(?:"
    r"\b(?:debug|verbose|devel(?:opment)?|testing|test_?mode"
    r"|feature_?(?:flag|gate|enabled|toggle)|enabled?|disabled?"
    r"|config|setting|option|flag|env|environment"
    r"|production|staging|sandbox|dry_?run|mock"
    r"|allow_?unsafe|skip_?(?:auth|check|validation)"
    r"|unsafe_?mode|permissive|strict_?mode"
    r"|NDEBUG|DEBUG|_DEBUG)\b"
    # Environment variable checks
    r"|\b(?:os\.(?:environ|getenv)|process\.env|ENV)\b"
    # Common config patterns
    r"|\b(?:settings?|conf(?:ig)?)\s*[.\[]\s*['\"]"
    r")",
    re.IGNORECASE,
)

# Error status checks
_ERROR_RE = re.compile(
    r"(?:"
    r"\b(?:err(?:no|or)?|status|result|ret(?:val|urn_?code)?|rc|exit_?code"
    r"|e?code)\s*(?:==|!=|<|>|<=|>=)\s*"
    # Named error constants (case-sensitive: EACCES, STATUS_OK, ERR_FAIL)
    r"|(?-i:\b(?:E[A-Z]{2,}|STATUS_[A-Z_]+|ERROR_[A-Z_]+|ERR_[A-Z_]+)\b)"
    # Success/failure checks
    r"|\b(?:succeeded|failed|is_?(?:err(?:or)?|ok|success))\b"
    # Go error pattern
    r"|\berr\s*!=\s*nil\b"
    # HTTP status
    r"|\b(?:status_?code|http_?status)\s*(?:==|!=|<|>)"
    # Exception-related
    r"|\b(?:except|catch|rescue)\b"
    r")",
    re.IGNORECASE,
)

# Type checks
_TYPE_RE = re.compile(
    r"(?:"
    r"\binstanceof\b"
    r"|\bisinstance\s*\("
    r"|\btype\s*\(\s*\w+\s*\)\s*(?:==|!=|is)"
    r"|\btypeof\s+"
    r"|\btype_?(?:of|check|assert)\b"
    r"|\b\w+\s*\.\s*(?:is_?a\??|kind_?of\??|is_?type)\b"
    # Go type assertion/switch
    r"|\.\s*\(\s*[A-Z]\w+\s*\)"
    # Rust: matches!(x, Type::Variant)
    r"|\bmatches!\s*\("
    r")",
    re.IGNORECASE,
)

# Resource availability checks
_RESOURCE_RE = re.compile(
    r"(?:"
    r"\b(?:exists?|is_?file|is_?dir(?:ectory)?|is_?open|is_?closed"
    r"|is_?connected|is_?available|is_?ready|is_?alive|is_?running"
    r"|is_?writable|is_?readable|can_?(?:read|write|connect|open)"
    r"|file_?exists|path_?exists|access)\b"
    # File/socket operations that serve as guards
    r"|\b(?:stat|lstat|access|fstat)\s*\("
    # Connection checks
    r"|\b\w+\.(?:is_?open|is_?connected|is_?alive|ping)\b"
    r")",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Classification function
# ---------------------------------------------------------------------------

# Priority order: if a condition matches multiple categories, the first
# match wins. Order reflects security relevance.
_CLASSIFIERS = [
    ("auth", _AUTH_RE),
    ("bounds", _BOUNDS_RE),
    ("null", _NULL_RE),
    ("config", _CONFIG_RE),
    ("error", _ERROR_RE),
    ("type", _TYPE_RE),
    ("resource", _RESOURCE_RE),
]


def classify_condition(
    condition_text: str,
    language: Optional[str] = None,
) -> str:
    """Classify a guard condition text into a security-relevant category.

    Args:
        condition_text: The extracted condition expression text.
        language: Optional language hint (unused currently, reserved
            for language-specific disambiguation).

    Returns:
        Category string: auth|bounds|null|config|error|type|resource|unknown
    """
    if not condition_text:
        return "unknown"

    for category, pattern in _CLASSIFIERS:
        if pattern.search(condition_text):
            return category

    return "unknown"


def classify_conditions_batch(
    conditions: list,
    language: Optional[str] = None,
) -> list:
    """Classify a batch of condition texts. Returns parallel list of categories."""
    return [classify_condition(c, language) for c in conditions]
