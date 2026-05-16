from __future__ import annotations

import pytest

from cve_diff.security.exceptions import ValidationError
from cve_diff.security.validators import validate_cve_id


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
