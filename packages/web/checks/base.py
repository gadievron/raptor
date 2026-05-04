"""Base class and registry for ASVS-mapped security checks."""

from __future__ import annotations

import abc
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Callable, Dict, Iterable, List, Optional, Type

if TYPE_CHECKING:
    from packages.web.client import WebClient
    from packages.web.auth import AuthSession
    from core.llm.providers import LLMProvider


class CheckCategory(str, Enum):
    AUTHN       = "V2"    # Authentication
    SESSION     = "V3"    # Session Management
    ACCESS      = "V4"    # Access Control
    INJECTION   = "V5"    # Validation, Sanitization, Encoding
    TLS         = "V9"    # Communication Security
    INFORMATION = "V7"    # Error Handling and Logging
    API         = "V13"   # API and Web Service
    HEADERS     = "V14.4" # Security Headers
    CORS        = "V14.5" # HTTP Request Header Validation


@dataclass
class CheckResult:
    """Output from a single Check.run() call.

    passed=True means the check found no issue. Scanner collects only
    failed (passed=False) results as findings.
    """

    check_id: str
    check_name: str
    category: CheckCategory
    passed: bool
    severity: str       # critical | high | medium | low | informational
    confidence: str     # high | medium | low
    url: str
    evidence: str
    detail: str
    recommendation: str
    asvs_ref: str = ""
    requires_auth: bool = False


class Check(abc.ABC):
    """Abstract base for all security checks.

    Subclasses register with the module-level `registry` via the
    @registry.register() decorator. Constructor receives only the LLM
    provider (may be None). WebClient and AuthSession flow through run().
    """

    check_id: str = ""
    check_name: str = ""
    category: CheckCategory = CheckCategory.HEADERS
    requires_auth: bool = False

    def __init__(self, llm: Optional["LLMProvider"] = None) -> None:
        self.llm = llm

    @abc.abstractmethod
    def run(
        self,
        client: "WebClient",
        target_url: str,
        session: Optional["AuthSession"] = None,
        discovery: Optional[dict] = None,
    ) -> List[CheckResult]:
        """Execute the check. Return empty list when nothing is found."""
        ...

    def _llm_analyse(
        self,
        system: str,
        evidence_text: str,
        schema: dict,
    ) -> dict:
        """Run an enveloped LLM call. Returns {} when no LLM is available."""
        if not self.llm:
            return {}
        from core.security.prompt_defense_profiles import CONSERVATIVE
        from core.security.prompt_envelope import TaintedString, build_prompt

        slots = {"evidence": TaintedString(value=evidence_text, trust="untrusted")}
        bundle = build_prompt(
            system=system,
            profile=CONSERVATIVE,
            untrusted_blocks=(),
            slots=slots,
        )
        prompt = next((m.content for m in bundle.messages if m.role == "user"), "")
        system_prompt = next(
            (m.content for m in bundle.messages if m.role == "system"), None
        )
        try:
            result, _ = self.llm.generate_structured(
                prompt=prompt, schema=schema, system_prompt=system_prompt
            )
            return result or {}
        except Exception:
            return {}

    def _result(
        self,
        *,
        passed: bool,
        url: str,
        evidence: str,
        detail: str,
        recommendation: str,
        severity: str = "medium",
        confidence: str = "high",
        asvs_ref: str = "",
    ) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            check_name=self.check_name,
            category=self.category,
            passed=passed,
            severity=severity,
            confidence=confidence,
            url=url,
            evidence=evidence,
            detail=detail,
            recommendation=recommendation,
            asvs_ref=asvs_ref or f"ASVS 5.0 {self.check_id}",
            requires_auth=self.requires_auth,
        )


class CheckRegistry:
    """Global registry of all Check subclasses."""

    def __init__(self) -> None:
        self._checks: Dict[str, Type[Check]] = {}

    def register(
        self,
        category: CheckCategory,
        check_id: str,
        check_name: str = "",
        requires_auth: bool = False,
    ) -> Callable[[Type[Check]], Type[Check]]:
        def decorator(cls: Type[Check]) -> Type[Check]:
            cls.check_id = check_id
            cls.check_name = check_name or cls.__name__
            cls.category = category
            cls.requires_auth = requires_auth
            self._checks[check_id] = cls
            return cls
        return decorator

    def all(self) -> List[Type[Check]]:
        return list(self._checks.values())

    def for_categories(self, categories: Iterable[CheckCategory]) -> List[Type[Check]]:
        cats = set(categories)
        return [c for c in self._checks.values() if c.category in cats]

    def unauthenticated(self) -> List[Type[Check]]:
        return [c for c in self._checks.values() if not c.requires_auth]

    def authenticated(self) -> List[Type[Check]]:
        return [c for c in self._checks.values() if c.requires_auth]


registry = CheckRegistry()
