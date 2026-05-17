#!/usr/bin/env python3
"""Narrow ffuf integration for RAPTOR web scans.

The runner is intentionally small and opt-in: operators must provide a
wordlist, and RAPTOR constrains the ffuf URL template to the configured target
origin before spawning the external binary.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from core.logging import get_logger
from core.sandbox import run_untrusted
from core.security.redaction import redact_secrets

logger = get_logger()


@dataclass(frozen=True)
class FfufConfig:
    """Configuration for an explicit ffuf content-discovery run."""

    wordlist: Path
    path_template: str = "FUZZ"
    threads: int = 10
    rate: int | None = None
    timeout: int = 30
    max_runtime: int = 300
    report_limit: int = 50
    binary: str = "ffuf"
    auto_calibration: bool = True
    match_status: str | None = "200,204,301,302,307,401,403,405,500"
    filter_status: str | None = "404"
    filter_size: int | None = None


class FfufRunner:
    """Run ffuf against a single in-scope target origin."""

    def __init__(self, base_url: str, out_dir: Path, reveal_secrets: bool = False):
        self.base_url = base_url.rstrip("/")
        self.out_dir = out_dir
        self.reveal_secrets = reveal_secrets

    def _origin(self, url: str) -> tuple[str, str, int]:
        parsed = urlparse(url)
        default_port = 443 if parsed.scheme == "https" else 80
        return (
            parsed.scheme.lower(),
            (parsed.hostname or "").lower(),
            parsed.port or default_port,
        )

    def _redact(self, value: object) -> str:
        return redact_secrets(value, reveal_secrets=self.reveal_secrets)

    def build_url_template(self, path_template: str) -> str:
        """Build and scope-check the ffuf URL template.

        ffuf marks the replacement point with ``FUZZ``. Accepting a raw URL from
        the CLI without checking it would let a saved RAPTOR config or copied
        command accidentally aim ffuf at a different host. Treat the template
        like WebClient paths: relative paths are anchored to ``base_url``;
        absolute URLs are allowed only when their normalized origin matches.

        ``urljoin`` intentionally normalizes ``..`` segments before the origin
        check. That can move a relative template outside the base path while
        staying on the same origin; this integration scopes ffuf to the target
        host/origin rather than to a specific subpath.
        """
        if "FUZZ" not in path_template:
            raise ValueError("ffuf path template must include FUZZ")

        url_template = urljoin(self.base_url + "/", path_template)
        probe_url = url_template.replace("FUZZ", "raptor-scope-probe")
        if self._origin(probe_url) != self._origin(self.base_url):
            raise ValueError(
                "ffuf path template is outside configured target scope: "
                f"{self._redact(probe_url)}"
            )
        return url_template

    def build_command(self, config: FfufConfig, output_file: Path) -> list[str]:
        """Return argv for a safe, non-shell ffuf invocation."""
        if not config.wordlist.is_file():
            raise FileNotFoundError(f"ffuf wordlist not found: {config.wordlist}")
        if config.threads < 1:
            raise ValueError("ffuf threads must be >= 1")
        if config.rate is not None and config.rate < 1:
            raise ValueError("ffuf rate must be >= 1 when set")
        if config.timeout < 1:
            raise ValueError("ffuf timeout must be >= 1")
        if config.max_runtime < 1:
            raise ValueError("ffuf max runtime must be >= 1")
        if config.report_limit < 0:
            raise ValueError("ffuf report limit must be >= 0")
        if config.filter_size is not None and config.filter_size < 0:
            raise ValueError("ffuf filter size must be >= 0 when set")

        url_template = self.build_url_template(config.path_template)
        cmd = [
            config.binary,
            "-u",
            url_template,
            "-w",
            str(config.wordlist),
            "-of",
            "json",
            "-o",
            str(output_file),
            "-noninteractive",
            "-t",
            str(config.threads),
            "-timeout",
            str(config.timeout),
        ]
        if config.auto_calibration:
            cmd.append("-ac")
        if config.match_status:
            cmd.extend(["-mc", config.match_status])
        if config.filter_status:
            cmd.extend(["-fc", config.filter_status])
        if config.filter_size is not None:
            cmd.extend(["-fs", str(config.filter_size)])
        if config.rate is not None:
            cmd.extend(["-rate", str(config.rate)])
        return cmd

    def run(self, config: FfufConfig) -> dict[str, Any]:
        """Run ffuf in RAPTOR's sandbox and return a compact result summary.

        ffuf exits non-zero for several operational conditions (no matches,
        interrupted run, config error). RAPTOR keeps the raw JSON artifact when
        present and reports the return code instead of treating every non-zero
        as a scanner crash.
        """
        binary_path = shutil.which(config.binary)
        if binary_path is None:
            raise FileNotFoundError(
                f"ffuf binary not found on PATH: {config.binary}. "
                "Install ffuf or pass --ffuf-bin."
            )

        target_host = (urlparse(self.base_url).hostname or "").lower()
        if not target_host:
            raise ValueError("ffuf base URL must include a hostname")

        self.out_dir.mkdir(parents=True, exist_ok=True)
        output_file = self.out_dir / "ffuf_results.json"
        cmd = self.build_command(config, output_file)
        redacted_cmd = [self._redact(part) for part in cmd]
        logger.info(f"Running sandboxed ffuf: {' '.join(redacted_cmd)}")

        completed = run_untrusted(
            cmd,
            target=str(config.wordlist.parent),
            output=str(self.out_dir),
            readable_paths=[str(config.wordlist.parent)],
            use_egress_proxy=True,
            proxy_hosts=[target_host],
            tool_paths=[str(Path(binary_path).parent)],
            caller_label="web-ffuf",
            timeout=config.max_runtime,
            capture_output=True,
            text=True,
        )

        results: list[dict[str, Any]] = []
        if output_file.exists():
            try:
                parsed = json.loads(output_file.read_text(encoding="utf-8"))
                raw_results = parsed.get("results") or []
                if isinstance(raw_results, list):
                    results = [r for r in raw_results if isinstance(r, dict)]
            except json.JSONDecodeError as exc:
                logger.warning(f"Could not parse ffuf JSON output: {exc}")

        summarized_results = [self._summarize_result(r) for r in results[: config.report_limit]]
        return {
            "tool": "ffuf",
            "returncode": completed.returncode,
            "output_file": str(output_file),
            "result_count": len(results),
            "reported_result_count": len(summarized_results),
            "omitted_result_count": max(0, len(results) - len(summarized_results)),
            "results": summarized_results,
            "stderr": self._redact((completed.stderr or "").strip()),
        }

    def _summarize_result(self, result: dict[str, Any]) -> dict[str, Any]:
        """Keep ffuf report entries compact and secret-redacted."""
        return {
            "url": self._redact(result.get("url", "")),
            "status": result.get("status"),
            "length": result.get("length"),
            "words": result.get("words"),
            "lines": result.get("lines"),
        }
