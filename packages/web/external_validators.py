"""Opt-in external validation oracles for web findings.

External tools are useful as second opinions, not as a replacement for
RAPTOR's own web oracle. A validator match adds evidence. A no-match is only a
no-match; it never refutes a live finding by itself.

Supply-chain posture: nuclei never fetches or auto-updates templates.
The runner requires an operator-provisioned, pinned templates directory
(provision once, verify its digest at provision time) and always passes
``-duc`` (disable update check). The egress proxy would fail-close any
fetch attempt anyway; pre-provisioning makes it a clean skip instead of
a mid-run stall. ``-ni`` is a hard default: out-of-band testing against
third-party OAST servers conflicts with RAPTOR's egress and metadata
posture, permanently.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from core.logging import get_logger
from core.sandbox import run_untrusted_networked
from core.security.redaction import redact_secrets
from packages.web.execution_policy import WebExecutionPolicy, WebPolicyError
from packages.web.models import WebFinding
from packages.web.tool_adapters import web_tool_adapter

logger = get_logger()

# Finding class -> nuclei template tags. Per-finding validation runs the
# templates that could actually corroborate the class, not a broad
# severity sweep that burns the request budget on irrelevant noise.
TAGS_BY_VULN_TYPE: dict[str, str] = {
    "sqli": "sqli",
    "xss": "xss",
    "ssti": "ssti",
    "command_injection": "rce",
    "path_traversal": "lfi,traversal",
}

# Matches ffuf's DEFAULT_GUARDED_RATE: nuclei's own defaults (-rl 150,
# -c 25) are far hotter than anything else RAPTOR points at a target.
DEFAULT_RATE_LIMIT = 50


@dataclass(frozen=True)
class NucleiConfig:
    """Operator-tunable knobs for the nuclei validator."""

    templates_dir: Path | None = None
    severity: str = "medium,high,critical"
    rate_limit: int = DEFAULT_RATE_LIMIT
    concurrency: int = 10
    bulk_size: int = 10
    timeout: int = 10
    retries: int = 1
    max_runtime: int = 600
    headers: tuple[str, ...] = ()
    binary: str = "nuclei"
    store_responses: bool = True


class ExternalValidatorRunner:
    """Run selected external web validators against existing findings."""

    def __init__(
        self,
        *,
        base_url: str,
        out_dir: Path,
        policy: WebExecutionPolicy,
        reveal_secrets: bool = False,
        nuclei_config: NucleiConfig | None = None,
    ) -> None:
        self.base_url = base_url
        self.out_dir = out_dir
        self.policy = policy
        self.reveal_secrets = reveal_secrets
        self.nuclei_config = nuclei_config or NucleiConfig()

    def run(
        self,
        findings: Iterable[WebFinding],
        validators: Iterable[str],
    ) -> list[dict[str, Any]]:
        findings = list(findings)
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

    # -- nuclei ---------------------------------------------------------

    def _run_nuclei(self, findings: list[WebFinding]) -> list[dict[str, Any]]:
        config = self.nuclei_config
        adapter = web_tool_adapter("nuclei")
        binary_path = shutil.which(config.binary or adapter.binary or "nuclei")
        if not binary_path:
            return [{
                "tool": "nuclei",
                "status": "unavailable",
                "reason": "nuclei binary not found on PATH",
            }]
        # Same realpath rule as the ffuf engine: the sandbox binds and
        # visibility checks operate on the RESOLVED path.
        binary_path = os.path.realpath(binary_path)

        if config.templates_dir is None or not Path(config.templates_dir).is_dir():
            return [{
                "tool": "nuclei",
                "status": "unavailable",
                "reason": (
                    "no pinned nuclei templates directory; provision a "
                    "digest-verified release and pass it explicitly — the "
                    "supply-chain posture forbids fetched/auto-updated "
                    "templates"
                ),
            }]
        templates_dir = Path(os.path.realpath(config.templates_dir))

        # Authorize each unique target; denied targets are recorded and
        # excluded from the batch — never silently dropped.
        results: list[dict[str, Any]] = []
        targets: dict[str, set[str]] = {}
        for finding in findings:
            target_url = finding.target_url or finding.url
            tags = TAGS_BY_VULN_TYPE.get(finding.vuln_type or "", "")
            if target_url in targets:
                if tags:
                    targets[target_url].update(tags.split(","))
                continue
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
            targets[target_url] = set(tags.split(",")) if tags else set()

        if not targets:
            return results

        results.extend(
            self._nuclei_batch(binary_path, templates_dir, targets)
        )
        return results

    def _nuclei_batch(
        self,
        binary_path: str,
        templates_dir: Path,
        targets: dict[str, set[str]],
    ) -> list[dict[str, Any]]:
        """One sandboxed nuclei invocation over all authorized targets."""
        config = self.nuclei_config
        run_dir = self.out_dir / "external-validators"
        run_dir.mkdir(parents=True, exist_ok=True)

        # Targets and credential headers ride 0600 files, never argv
        # (same /proc-cmdline channel the ffuf -config TOML closes).
        targets_file = self._write_private(
            run_dir / "nuclei-targets.txt", "\n".join(targets) + "\n"
        )
        headers_file: Path | None = None
        if config.headers:
            headers_file = self._write_private(
                run_dir / "nuclei-headers.txt", "\n".join(config.headers) + "\n"
            )

        tags = sorted({tag for tagset in targets.values() for tag in tagset if tag})
        cmd = [
            binary_path,
            "-l", str(targets_file),
            "-t", str(templates_dir),
            # Supply-chain / posture hard defaults. -dut (disallow
            # unsigned) is deliberately NOT passed: the pinned dir is
            # the operator's provenance gate, and RAPTOR-authored
            # replay templates are unsigned by construction.
            "-duc",
            "-ni",
            "-silent",
            "-jsonl",
            "-no-color",
            "-severity", config.severity,
            "-rl", str(config.rate_limit),
            "-c", str(config.concurrency),
            "-bs", str(config.bulk_size),
            "-timeout", str(config.timeout),
            "-retries", str(config.retries),
        ]
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        if headers_file is not None:
            cmd.extend(["-H", str(headers_file)])
        if config.store_responses:
            # Full request/response transcripts: the
            # evidence-or-it-didn't-happen artifact class.
            cmd.extend(["-sresp", "-srd", str(run_dir / "nuclei-responses")])
        if not any(self._is_private_host(url) for url in targets):
            # Keep templates from pivoting into RFC1918 space — but only
            # when the TARGET itself is not private (lab scans).
            cmd.append("-lna")

        proxy_hosts = sorted({
            (urlparse(url).hostname or "").lower() for url in targets
        } - {""})
        logger.info(
            "Running external validator nuclei against %d target(s), tags=%s",
            len(targets), ",".join(tags) or "-",
        )

        stdout = ""
        stderr = ""
        returncode: int | None = None
        timed_out = False
        try:
            completed = run_untrusted_networked(
                cmd,
                output=str(run_dir),
                readable_paths=[str(templates_dir), str(targets_file)]
                + ([str(headers_file)] if headers_file else []),
                proxy_hosts=proxy_hosts,
                fake_home=True,
                tool_paths=[str(Path(binary_path).parent)],
                caller_label="web-validator-nuclei",
                timeout=config.max_runtime,
                capture_output=True,
                text=True,
            )
            returncode = completed.returncode
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = self._as_text(exc.stdout)
            stderr = self._as_text(exc.stderr)
            logger.warning(
                "nuclei exceeded max runtime %ds; keeping partial output",
                config.max_runtime,
            )
        finally:
            if headers_file is not None and not self.reveal_secrets:
                headers_file.unlink(missing_ok=True)

        output_file = run_dir / "nuclei-results.jsonl"
        output_file.write_text(self._redact(stdout), encoding="utf-8")

        matches_by_target: dict[str, list[dict[str, Any]]] = {u: [] for u in targets}
        for line in stdout.splitlines():
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(raw, dict):
                continue
            info_raw = raw.get("info")
            info: dict[str, Any] = info_raw if isinstance(info_raw, dict) else {}
            matched_at = str(raw.get("matched-at") or raw.get("host") or "")
            record = {
                "template_id": raw.get("template-id"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "matched_at": self._redact(matched_at),
                "extracted_results": [
                    self._redact(item)
                    for item in (raw.get("extracted-results") or [])
                ],
                "curl_command": self._redact(raw.get("curl-command") or ""),
            }
            owner = self._attribute_target(matched_at, targets)
            matches_by_target.setdefault(owner, []).append(record)

        run_meta = {
            "binary": binary_path,
            "templates_dir": str(templates_dir),
            "returncode": returncode,
            "timed_out": timed_out,
            "tags": tags,
            "output_file": str(output_file),
            "stderr": self._redact(stderr.strip()),
        }
        results = []
        for target_url in targets:
            matches = matches_by_target.get(target_url, [])
            results.append({
                "tool": "nuclei",
                "target_url": self._redact(target_url),
                "status": "matched" if matches else "no_match",
                "evidence_kind": "template_match",
                "matches": matches,
                "run": run_meta,
                "note": "No-match is not a refutation of RAPTOR's own web oracle.",
            })
        return results

    # -- helpers --------------------------------------------------------

    def _attribute_target(self, matched_at: str, targets: dict[str, Any]) -> str:
        """Attribute a JSONL record to the batch target that produced it."""
        for target_url in targets:
            if matched_at.startswith(target_url):
                return target_url
        matched_host = (urlparse(matched_at).hostname or "").lower()
        for target_url in targets:
            if (urlparse(target_url).hostname or "").lower() == matched_host:
                return target_url
        return matched_at or "unattributed"

    @staticmethod
    def _write_private(path: Path, content: str) -> Path:
        """Fresh 0600 inode; refuses to follow a pre-planted symlink."""
        path.unlink(missing_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    @staticmethod
    def _is_private_host(url: str) -> bool:
        host = urlparse(url).hostname or ""
        if host in ("localhost",):
            return True
        try:
            return not ipaddress.ip_address(host).is_global
        except ValueError:
            return False

    @staticmethod
    def _as_text(raw: object) -> str:
        if isinstance(raw, bytes):
            return raw.decode("utf-8", errors="replace")
        return str(raw or "")

    def _redact(self, value: object) -> str:
        return redact_secrets(value, reveal_secrets=self.reveal_secrets)
