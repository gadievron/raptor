"""Web tool adapter catalogue.

The scanner core stays in Python, but live web work increasingly needs narrow
external helpers as well. This module keeps those tools honest: each adapter
declares what it does, what evidence it can produce, and how much operator
approval it needs before it can run.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass(frozen=True)
class WebToolAdapter:
    """One built-in or external web-testing capability."""

    id: str
    name: str
    role: str  # discovery | scanner | validator | browser
    risk: str  # passive | active | intrusive
    execution: str  # builtin | external | planned
    evidence_kinds: tuple[str, ...]
    validates: tuple[str, ...] = ()
    binary: Optional[str] = None
    parser_status: str = "structured"  # structured | text | planned
    notes: str = ""

    def to_dict(self, *, selected: bool = False) -> dict:
        available = True
        if self.binary:
            available = shutil.which(self.binary) is not None
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role,
            "risk": self.risk,
            "execution": self.execution,
            "evidence_kinds": list(self.evidence_kinds),
            "validates": list(self.validates),
            "binary": self.binary,
            "available": available,
            "selected": selected,
            "parser_status": self.parser_status,
            "notes": self.notes,
        }


_ADAPTERS: tuple[WebToolAdapter, ...] = (
    WebToolAdapter(
        id="raptor-http",
        name="RAPTOR HTTP client",
        role="scanner",
        risk="passive",
        execution="builtin",
        evidence_kinds=("http_request", "http_response", "redirect_chain"),
        notes="Same-origin request engine used by discovery, checks and fuzzing.",
    ),
    WebToolAdapter(
        id="raptor-crawler",
        name="RAPTOR crawler",
        role="discovery",
        risk="passive",
        execution="builtin",
        evidence_kinds=("endpoint", "form", "parameter", "api_surface"),
        notes="Bounded HTML and JSON crawl seeded from discovery results.",
    ),
    WebToolAdapter(
        id="raptor-web-oracle",
        name="RAPTOR web oracle",
        role="validator",
        risk="active",
        execution="builtin",
        evidence_kinds=("baseline_response", "attack_response", "response_diff", "oracle_signal"),
        validates=("sqli", "xss", "ssti", "command_injection", "path_traversal"),
        notes="Three-gate baseline/attack/diff oracle used for injection findings.",
    ),
    WebToolAdapter(
        id="ffuf",
        name="ffuf",
        role="discovery",
        risk="active",
        execution="external",
        evidence_kinds=("content_discovery",),
        binary="ffuf",
        parser_status="structured",
        notes="Opt-in content discovery. Requires an operator-supplied wordlist.",
    ),
    WebToolAdapter(
        id="nuclei",
        name="nuclei",
        role="validator",
        risk="active",
        execution="external",
        evidence_kinds=("template_match", "scanner_finding"),
        validates=("sqli", "xss", "ssti", "command_injection", "path_traversal", "other"),
        binary="nuclei",
        parser_status="structured",
        notes="Opt-in second-opinion validator. A no-match is not a refutation.",
    ),
    WebToolAdapter(
        id="dalfox",
        name="dalfox",
        role="validator",
        risk="active",
        execution="planned",
        evidence_kinds=("xss_probe",),
        validates=("xss",),
        binary="dalfox",
        parser_status="planned",
        notes="Reserved for browser-aware XSS confirmation once its parser lands.",
    ),
    WebToolAdapter(
        id="sqlmap",
        name="sqlmap",
        role="validator",
        risk="intrusive",
        execution="planned",
        evidence_kinds=("sqli_validation",),
        validates=("sqli",),
        binary="sqlmap",
        parser_status="planned",
        notes="Deliberately not executable yet; requires tighter per-finding approval controls.",
    ),
)


def all_web_tool_adapters() -> tuple[WebToolAdapter, ...]:
    return _ADAPTERS


def web_tool_adapter(tool_id: str) -> WebToolAdapter:
    for adapter in _ADAPTERS:
        if adapter.id == tool_id:
            return adapter
    raise KeyError(f"Unknown web tool adapter: {tool_id}")


def web_tool_adapter_report(selected: Iterable[str] = ()) -> list[dict]:
    selected_ids = set(selected)
    return [adapter.to_dict(selected=adapter.id in selected_ids) for adapter in _ADAPTERS]
