"""
Bug Report Fetcher

Fetch and parse bug reports from various sources (URLs, local files).
"""

import re
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

import requests


@dataclass
class BugReport:
    """Structured representation of a bug report."""

    # Source information
    url: Optional[str] = None
    source_type: str = "unknown"  # github, gitlab, bugzilla, trac, generic

    # Bug details
    title: str = ""
    description: str = ""

    # Crash information
    stack_trace: Optional[str] = None
    crash_signal: Optional[str] = None
    crash_address: Optional[str] = None
    asan_report: Optional[str] = None

    # Reproduction
    reproduction_steps: List[str] = field(default_factory=list)
    reproduction_command: Optional[str] = None

    # Attachments
    attachments: List[Dict[str, str]] = field(default_factory=list)
    crasher_input_urls: List[str] = field(default_factory=list)

    # Raw content
    raw_content: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "url": self.url,
            "source_type": self.source_type,
            "title": self.title,
            "description": self.description,
            "stack_trace": self.stack_trace,
            "crash_signal": self.crash_signal,
            "crash_address": self.crash_address,
            "asan_report": self.asan_report,
            "reproduction_steps": self.reproduction_steps,
            "reproduction_command": self.reproduction_command,
            "attachments": self.attachments,
            "crasher_input_urls": self.crasher_input_urls,
        }


class BugFetcher:
    """Fetch and parse bug reports from URLs."""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "RAPTOR-CrashAnalysis/1.0"
        })

    def fetch(self, url: str) -> BugReport:
        """
        Fetch a bug report from a URL.

        Args:
            url: URL to the bug report

        Returns:
            BugReport with extracted information
        """
        report = BugReport(url=url)

        # Detect source type
        report.source_type = self._detect_source_type(url)

        # Fetch content
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            report.raw_content = response.text
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to fetch bug report: {e}")

        # Parse based on source type
        if report.source_type == "github":
            self._parse_github(report)
        elif report.source_type == "gitlab":
            self._parse_gitlab(report)
        elif report.source_type == "trac":
            self._parse_trac(report)
        else:
            self._parse_generic(report)

        # Extract crash-related information
        self._extract_crash_info(report)

        return report

    def _detect_source_type(self, url: str) -> str:
        """Detect the bug tracker type from URL."""
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        path = parsed.path.lower()

        if "github.com" in host:
            return "github"
        elif "gitlab" in host:
            return "gitlab"
        elif "bugzilla" in host or "bugs." in host:
            return "bugzilla"
        elif "trac" in host or "/ticket/" in path:
            return "trac"
        else:
            return "generic"

    def _parse_github(self, report: BugReport) -> None:
        """Parse GitHub issue page."""
        content = report.raw_content

        # Try to extract title from HTML
        title_match = re.search(r'<span[^>]*class="[^"]*js-issue-title[^"]*"[^>]*>([^<]+)</span>', content)
        if title_match:
            report.title = title_match.group(1).strip()

        # Extract issue body
        body_match = re.search(r'<td[^>]*class="[^"]*comment-body[^"]*"[^>]*>(.*?)</td>', content, re.DOTALL)
        if body_match:
            # Strip HTML tags for description
            body_html = body_match.group(1)
            report.description = re.sub(r'<[^>]+>', '', body_html).strip()

        # Look for attachment links
        attachment_matches = re.findall(r'href="([^"]+/files/[^"]+)"', content)
        for url in attachment_matches:
            if not url.startswith("http"):
                url = "https://github.com" + url
            report.attachments.append({"url": url, "type": "file"})

    def _parse_gitlab(self, report: BugReport) -> None:
        """Parse GitLab issue page."""
        content = report.raw_content

        # Extract title
        title_match = re.search(r'<h1[^>]*class="[^"]*title[^"]*"[^>]*>([^<]+)</h1>', content)
        if title_match:
            report.title = title_match.group(1).strip()

        # Extract description
        desc_match = re.search(r'<div[^>]*class="[^"]*description[^"]*"[^>]*>(.*?)</div>', content, re.DOTALL)
        if desc_match:
            report.description = re.sub(r'<[^>]+>', '', desc_match.group(1)).strip()

    def _parse_trac(self, report: BugReport) -> None:
        """Parse Trac ticket page."""
        content = report.raw_content

        # Extract title (summary)
        title_match = re.search(r'<h2[^>]*class="[^"]*summary[^"]*"[^>]*>([^<]+)</h2>', content)
        if not title_match:
            title_match = re.search(r'<span[^>]*class="[^"]*summary[^"]*"[^>]*>([^<]+)</span>', content)
        if title_match:
            report.title = title_match.group(1).strip()

        # Extract description
        desc_match = re.search(r'<div[^>]*class="[^"]*description[^"]*"[^>]*>(.*?)</div>', content, re.DOTALL)
        if desc_match:
            report.description = re.sub(r'<[^>]+>', '', desc_match.group(1)).strip()

        # Look for attachments
        attachment_matches = re.findall(r'href="(/attachment/ticket/[^"]+)"', content)
        for path in attachment_matches:
            parsed = urlparse(report.url)
            full_url = f"{parsed.scheme}://{parsed.netloc}{path}"
            report.attachments.append({"url": full_url, "type": "attachment"})

    def _parse_generic(self, report: BugReport) -> None:
        """Generic parsing for unknown bug trackers."""
        content = report.raw_content

        # Try to extract title from <title> tag
        title_match = re.search(r'<title>([^<]+)</title>', content, re.IGNORECASE)
        if title_match:
            report.title = title_match.group(1).strip()

        # Use full content as description (stripped of HTML)
        report.description = re.sub(r'<[^>]+>', ' ', content)
        report.description = re.sub(r'\s+', ' ', report.description).strip()

    def _extract_crash_info(self, report: BugReport) -> None:
        """Extract crash-related information from the bug report."""
        text = report.description + "\n" + report.raw_content

        # Extract ASAN report
        asan_match = re.search(
            r'(=+\d+=+ERROR: AddressSanitizer:.*?)(?=\n\n|\Z)',
            text,
            re.DOTALL
        )
        if asan_match:
            report.asan_report = asan_match.group(1).strip()

        # Extract stack trace
        stack_patterns = [
            # ASAN stack trace
            r'(#\d+\s+0x[0-9a-fA-F]+.*?)(?=\n\n|\Z)',
            # GDB backtrace
            r'(#\d+\s+.*?\(.*?\).*?)(?=\n\n|\Z)',
            # Generic crash trace
            r'((?:at\s+|in\s+).*?:\d+.*?)(?=\n\n|\Z)',
        ]

        for pattern in stack_patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                report.stack_trace = match.group(1).strip()
                break

        # Extract crash signal
        signal_match = re.search(
            r'(SIGSEGV|SIGABRT|SIGFPE|SIGBUS|SIGILL|SIGTRAP)',
            text,
            re.IGNORECASE
        )
        if signal_match:
            report.crash_signal = signal_match.group(1).upper()

        # Extract crash address
        addr_match = re.search(r'(?:at|address)\s*(0x[0-9a-fA-F]+)', text, re.IGNORECASE)
        if addr_match:
            report.crash_address = addr_match.group(1)

        # Extract reproduction command
        cmd_patterns = [
            r'```(?:bash|sh)?\s*\n([^\n]+)\s*\n```',
            r'\$\s+(.+)',
            r'(?:run|execute|command):\s*`([^`]+)`',
        ]

        for pattern in cmd_patterns:
            match = re.search(pattern, text)
            if match:
                cmd = match.group(1).strip()
                # Filter out obviously non-command content
                if len(cmd) < 500 and not cmd.startswith('#'):
                    report.reproduction_command = cmd
                    break

        # Look for crasher input URLs
        input_patterns = [
            r'(https?://[^\s]+\.(?:zip|tar|gz|bin|raw|poc|crash)[^\s]*)',
            r'(https?://[^\s]*(?:crash|poc|input|sample)[^\s]*)',
        ]

        for pattern in input_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            report.crasher_input_urls.extend(matches)

        # Deduplicate
        report.crasher_input_urls = list(set(report.crasher_input_urls))

    def download_attachments(self, report: BugReport, output_dir: Path) -> List[Path]:
        """
        Download attachments from a bug report.

        Args:
            report: BugReport with attachment URLs
            output_dir: Directory to save attachments

        Returns:
            List of paths to downloaded files
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        downloaded = []

        all_urls = [a["url"] for a in report.attachments] + report.crasher_input_urls

        for i, url in enumerate(all_urls):
            try:
                response = self.session.get(url, timeout=self.timeout)
                response.raise_for_status()

                # Determine filename
                filename = Path(urlparse(url).path).name
                if not filename:
                    filename = f"attachment_{i}"

                filepath = output_dir / filename
                filepath.write_bytes(response.content)
                downloaded.append(filepath)

            except requests.RequestException as e:
                print(f"Warning: Failed to download {url}: {e}")

        return downloaded


def load_local_crashes(crash_dir: Path) -> List[Dict[str, Any]]:
    """
    Load crashes from a local directory (e.g., AFL++ output).

    Args:
        crash_dir: Path to directory containing crash inputs

    Returns:
        List of crash info dictionaries
    """
    crash_dir = Path(crash_dir)
    crashes = []

    if not crash_dir.exists():
        raise FileNotFoundError(f"Crash directory not found: {crash_dir}")

    # AFL++ format: crashes are in crashes/ directory
    # libFuzzer format: crash-* files

    crash_files = []

    # Look for AFL++ crash files
    if (crash_dir / "crashes").exists():
        crash_files.extend((crash_dir / "crashes").glob("id:*"))

    # Look for libFuzzer crash files
    crash_files.extend(crash_dir.glob("crash-*"))

    # Generic: any file in the directory
    if not crash_files:
        crash_files.extend(crash_dir.glob("*"))

    for crash_file in crash_files:
        if crash_file.is_file():
            crashes.append({
                "path": crash_file,
                "size": crash_file.stat().st_size,
                "name": crash_file.name,
            })

    return crashes
