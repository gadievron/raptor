from __future__ import annotations

import pytest

from cve_diff.security.exceptions import SSRFError, ValidationError
from cve_diff.security.validators import (
    validate_commit_sha,
    validate_cve_id,
    validate_cvss_score,
    validate_path,
    validate_url,
)


class TestValidateCveId:
    @pytest.mark.parametrize(
        "cve",
        ["CVE-1999-0001", "CVE-2024-1086", "CVE-2024-1234567890"],
    )
    def test_accepts_valid(self, cve: str) -> None:
        assert validate_cve_id(cve) == cve

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "   ",
            " CVE-2024-1234",
            "cve-2024-1234",
            "CVE-24-1234",
            "CVE-2024-123",
            "CVE-2024-abcd",
            "CVE-2024-1234-5",
            "CVE-1998-0001",
            "CVE-2024-12345678901",
            "CVE-2024-1234; DROP TABLE cves;--",
            "CVE-2024-1234'",
            "CVE-2024-1234/../etc/passwd",
            "CVE-2024-1234\\x00",
        ],
    )
    def test_rejects_invalid(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            validate_cve_id(bad)

    def test_rejects_non_string(self) -> None:
        with pytest.raises(ValidationError):
            validate_cve_id(None)  # type: ignore[arg-type]
        with pytest.raises(ValidationError):
            validate_cve_id(12345)  # type: ignore[arg-type]


class TestValidateUrl:
    @pytest.mark.parametrize(
        "url",
        [
            "https://github.com/curl/curl",
            "http://example.com/path",
            "https://api.osv.dev/v1/vulns/CVE-2024-1086",
        ],
    )
    def test_accepts_public(self, url: str) -> None:
        assert validate_url(url) == url

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1",
            "http://localhost",
            "http://10.0.0.1",
            "http://192.168.1.1",
            "http://172.16.0.1",
            "http://169.254.169.254",
        ],
    )
    def test_ssrf_private_ranges(self, url: str) -> None:
        with pytest.raises(SSRFError):
            validate_url(url)

    def test_ssrf_octal_bypass(self) -> None:
        with pytest.raises(SSRFError):
            validate_url("http://0177.0.0.1/")

    def test_ssrf_hex_bypass(self) -> None:
        with pytest.raises(SSRFError):
            validate_url("http://0x7f000001/")

    def test_rejects_non_http(self) -> None:
        with pytest.raises(ValidationError):
            validate_url("ftp://example.com/")
        with pytest.raises(ValidationError):
            validate_url("file:///etc/passwd")

    def test_rejects_empty(self) -> None:
        with pytest.raises(ValidationError):
            validate_url("")

    def test_rejects_url_encoded_hostname(self) -> None:
        with pytest.raises(ValidationError):
            validate_url("http://127%2e0%2e0%2e1/")


class TestValidatePath:
    def test_accepts_relative(self) -> None:
        assert validate_path("dir/file.txt") == "dir/file.txt"

    @pytest.mark.parametrize(
        "bad",
        [
            "../etc/passwd",
            "/etc/passwd",
            "/sys/kernel",
            "/proc/self/environ",
            "C:\\Windows\\System32",
            "dir\\file.txt",
            "file\x00.exe",
            "%2e%2e/etc/passwd",
            "\u2024\u2024/etc/passwd",
            "a" * 1025,
            "",
        ],
    )
    def test_rejects_attacks(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            validate_path(bad)


class TestValidateCommitSha:
    @pytest.mark.parametrize(
        "sha",
        [
            "a1b2c3d",
            "a1b2c3d4",
            "a1b2c3d4e5f6789012345678901234567890abcd",
            "A1B2C3D4E5F6789012345678901234567890ABCD",
        ],
    )
    def test_accepts_valid(self, sha: str) -> None:
        assert validate_commit_sha(sha) == sha

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "abc",
            "a" * 41,
            "g" * 40,
            "a1b2c3d; rm -rf /",
            "a1b2c3d/../etc",
            "a1b2c3d e5f",
            " a1b2c3d",
        ],
    )
    def test_rejects_invalid(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            validate_commit_sha(bad)


class TestValidateCvssScore:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [("0.0", 0.0), ("7.5", 7.5), ("10.0", 10.0)],
    )
    def test_accepts_valid(self, raw: str, expected: float) -> None:
        assert validate_cvss_score(raw) == expected

    @pytest.mark.parametrize(
        "bad",
        ["-1.0", "11.0", "7.5e0", "7..5", "7", "7.50", "NaN", "abc", ""],
    )
    def test_rejects_invalid(self, bad: str) -> None:
        with pytest.raises(ValidationError):
            validate_cvss_score(bad)
