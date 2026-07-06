"""Opt-in external validation oracles for web findings.

External tools are useful as second opinions, not as a replacement for
RAPTOR's own web oracle. A validator match adds evidence. A no-match is only a
no-match; it never refutes a live finding by itself.
"""

from __future__ import annotations

import json
import shutil
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from core.logging import get_logger
from core.sandbox import run_untrusted
from core.security.redaction import redact_secrets
from packages.web.execution_policy import WebExecutionPolicy, WebPolicyError
from packages.web.models import WebFinding
from packages.web.tool_adapters import web_tool_adapter

logger = get_logger()


class ExternalValidatorRunner:
    """Run selected external web validators against existing findings."""

    def __init__(
        self,
        *,
        base_url: str,
        out_dir: Path,
        policy: WebExecutionPolicy,
        reveal_secrets: bool = False,
    ) -> None:
        self.base_url = base_url
        self.out_dir = out_dir
        self.policy = policy
        self.reveal_secrets = reveal_secrets

    def run(
        self,
        findings: Iterable[WebFinding],
        validators: Iterable[str],
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for validator_id in dict.fromkeys(validators):
            adapter = web_tool_adapter(validator_id)
            if adapter.role != "validator" or adapter.execution != "external":
                results.append({
                    "tool": validator_id,
                    "status": "skipped",
                    "reason": "adapter is not an executable external validator",
                })
                continue
            if validator_id == "nuclei":
                results.extend(self._run_nuclei(findings))
        return results

    def _run_nuclei(self, findings: Iterable[WebFinding]) -> list[dict[str, Any]]:
        adapter = web_tool_adapter("nuclei")
        binary_path = shutil.which(adapter.binary or "nuclei")
        if not binary_path:
            return [{
                "tool": "nuclei",
                "status": "unavailable",
                "reason": "nuclei binary not found on PATH",
            }]

        seen_urls: set[str] = set()
        results: list[dict[str, Any]] = []
        for finding in findings:
            target_url = finding.target_url or finding.url
            if target_url in seen_urls:
                continue
            seen_urls.add(target_url)
            try:
                self.policy.authorize(
                    tool_id="nuclei",
                    url=target_url,
                    risk=adapter.risk,
                    action="external_validator",
                )
            except WebPolicyError as exc:
                results.append({
                    "tool": "nuclei",
                    "target_url": self._redact(target_url),
                    "status": "denied",
                    "reason": str(exc),
                })
                continue

            results.append(self._nuclei_one(target_url, binary_path))
        return results

    def _nuclei_one(self, target_url: str, binary_path: str) -> dict[str, Any]:
        target_host = (urlparse(target_url).hostname or "").lower()
        target_id = sha256(target_url.encode("utf-8")).hexdigest()[:12]
        output_file = self.out_dir / "external-validators" / f"nuclei-{target_id}.jsonl"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            binary_path,
            "-u",
            target_url,
            "-jsonl",
            "-silent",
            "-no-color",
            "-severity",
            "medium,high,critical",
        ]
        logger.info("Running external validator nuclei against %s", self._redact(target_url))
        completed = run_untrusted(
            cmd,
            output=str(output_file.parent),
            use_egress_proxy=True,
            proxy_hosts=[target_host],
            tool_paths=[str(Path(binary_path).parent)],
            caller_label="web-validator-nuclei",
            timeout=300,
            capture_output=True,
            text=True,
        )
        stdout = completed.stdout or ""
        output_file.write_text(self._redact(stdout), encoding="utf-8")

        matches: list[dict[str, Any]] = []
        for line in stdout.splitlines():
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(raw, dict):
                continue
            info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
            matches.append({
                "template_id": raw.get("template-id"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "matched_at": self._redact(raw.get("matched-at") or raw.get("host") or target_url),
            })

        return {
            "tool": "nuclei",
            "target_url": self._redact(target_url),
            "status": "matched" if matches else "no_match",
            "returncode": completed.returncode,
            "evidence_kind": "template_match",
            "matches": matches,
            "output_file": str(output_file),
            "stderr": self._redact((completed.stderr or "").strip()),
            "note": "No-match is not a refutation of RAPTOR's own web oracle.",
        }

    def _redact(self, value: object) -> str:
        return redact_secrets(value, reveal_secrets=self.reveal_secrets)
