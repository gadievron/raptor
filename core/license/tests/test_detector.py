"""Tests for ``detect_target_license`` — the top-level-only license
classifier RAPTOR uses to surface licensing context at lifecycle
start (informational; not a gate)."""

from __future__ import annotations

import pytest

from core.license.detector import (
    TargetLicense,
    detect_target_license,
    format_license_summary,
)


# ---------------------------------------------------------------------------
# detect_target_license
# ---------------------------------------------------------------------------


class TestSpdxHeaderDetection:
    """SPDX-License-Identifier header is the highest-confidence signal."""

    def test_mit_spdx_header(self, tmp_path):
        (tmp_path / "LICENSE").write_text(
            "SPDX-License-Identifier: MIT\n\n"
            "Permission is hereby granted, free of charge, ...\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "MIT"
        assert lic.classification == "oss"
        assert lic.confidence == "high"
        assert lic.source_file == "LICENSE"

    def test_apache_spdx_header(self, tmp_path):
        (tmp_path / "LICENSE").write_text(
            "SPDX-License-Identifier: Apache-2.0\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "Apache-2.0"
        assert lic.classification == "oss"
        assert lic.confidence == "high"

    def test_gpl_spdx_header_treated_as_oss(self, tmp_path):
        # GPL is OSS for CodeQL terms — copyleft is a downstream
        # concern, not a licensing gate.
        (tmp_path / "LICENSE").write_text(
            "SPDX-License-Identifier: GPL-3.0-or-later\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.classification == "oss"

    def test_unknown_spdx_id_classified_proprietary(self, tmp_path):
        # SPDX header present but not in our OSS allowlist — could
        # be a custom commercial id, treat conservatively.
        (tmp_path / "LICENSE").write_text(
            "SPDX-License-Identifier: AcmeCorp-Internal-1.0\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.classification == "proprietary"
        assert lic.spdx_id == "AcmeCorp-Internal-1.0"
        assert lic.confidence == "high"


class TestCompoundSpdxHeader:
    """SPDX-License-Identifier with a compound expression
    (``MIT OR Apache-2.0``, ``GPL-3.0 WITH Classpath-exception-2.0``).
    Uses the shared compound-expression primitives in
    ``core/license/spdx.py``."""

    def test_or_all_oss(self, tmp_path):
        # Rust ecosystem convention. Both operands are OSS → whole
        # expression OSS.
        (tmp_path / "LICENSE").write_text(
            "SPDX-License-Identifier: MIT OR Apache-2.0\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.classification == "oss"
        assert lic.spdx_id == "MIT OR Apache-2.0"
        assert lic.confidence == "high"

    def test_or_any_non_oss_drops_to_proprietary(self, tmp_path):
        # OR of MIT and a custom commercial id → operator
        # explicitly offered EITHER; the custom id breaks OSS-
        # classification per the conservative rule.
        (tmp_path / "LICENSE").write_text(
            "SPDX-License-Identifier: MIT OR AcmeCorp-Internal-1.0\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.classification == "proprietary"
        assert "MIT" in lic.spdx_id
        assert "AcmeCorp-Internal-1.0" in lic.spdx_id

    def test_and_all_oss(self, tmp_path):
        (tmp_path / "LICENSE").write_text(
            "SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.classification == "oss"
        assert lic.spdx_id == "Apache-2.0 AND BSD-3-Clause"

    def test_with_exception_treats_principal_license(self, tmp_path):
        # ``X WITH Y`` means license X + exception Y. Y often isn't
        # a standalone SPDX license id (it's a clause name like
        # Classpath-exception-2.0). The principal X (GPL-3.0) IS
        # OSS, so the whole expression is OSS.
        (tmp_path / "LICENSE").write_text(
            "SPDX-License-Identifier: GPL-3.0 WITH Classpath-exception-2.0\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.classification == "oss"
        assert lic.spdx_id == "GPL-3.0 WITH Classpath-exception-2.0"

    def test_compound_takes_precedence_over_single(self, tmp_path):
        # Defends against the regex-precedence bug: the single-id
        # SPDX regex would otherwise match just ``MIT`` and silently
        # drop the ``OR Apache-2.0`` tail. Verify the full
        # expression survives in spdx_id.
        (tmp_path / "LICENSE").write_text(
            "SPDX-License-Identifier: MIT OR Apache-2.0\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "MIT OR Apache-2.0"  # not just "MIT"


class TestTextFingerprintDetection:
    """Medium-confidence fingerprints catch licenses without an
    SPDX header — most real-world LICENSE files predate the
    SPDX-Identifier convention."""

    def test_mit_text_fingerprint(self, tmp_path):
        (tmp_path / "LICENSE").write_text(
            "MIT License\n\n"
            "Permission is hereby granted, free of charge, to any "
            "person obtaining a copy of this software ...\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "MIT"
        assert lic.classification == "oss"
        assert lic.confidence == "medium"

    def test_apache_text_fingerprint(self, tmp_path):
        (tmp_path / "LICENSE").write_text(
            "                                 Apache License\n"
            "                           Version 2.0, January 2004\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "Apache-2.0"
        assert lic.classification == "oss"
        assert lic.confidence == "medium"

    def test_gpl_text_fingerprint(self, tmp_path):
        (tmp_path / "COPYING").write_text(
            "                    GNU GENERAL PUBLIC LICENSE\n"
            "                       Version 3, 29 June 2007\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "GPL-3.0"
        assert lic.classification == "oss"


class TestProprietaryDetection:
    """Common proprietary markers classify as proprietary even
    without an SPDX header."""

    def test_all_rights_reserved_phrase(self, tmp_path):
        (tmp_path / "LICENSE").write_text(
            "Copyright (c) 2026 AcmeCorp.\n"
            "All rights reserved.\n"
            "No part of this code may be reproduced ...\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.classification == "proprietary"
        assert lic.spdx_id is None

    def test_proprietary_keyword(self, tmp_path):
        (tmp_path / "LICENSE").write_text(
            "This is proprietary software of AcmeCorp.\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.classification == "proprietary"

    def test_confidential_keyword(self, tmp_path):
        (tmp_path / "LICENSE").write_text(
            "AcmeCorp Internal\nConfidential\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.classification == "proprietary"


class TestMissingAndUnknown:
    def test_no_license_file_returns_missing(self, tmp_path):
        # Empty tree → missing classification.
        lic = detect_target_license(tmp_path)
        assert lic.classification == "missing"
        assert lic.source_file is None
        assert lic.spdx_id is None

    def test_license_file_with_no_recognised_content(self, tmp_path):
        # File present but nothing in our fingerprint or marker sets.
        (tmp_path / "LICENSE").write_text(
            "Some random text that doesn't match anything we know.\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.classification == "unknown"
        assert lic.source_file == "LICENSE"

    def test_nonexistent_target_dir_returns_missing(self, tmp_path):
        lic = detect_target_license(tmp_path / "does-not-exist")
        assert lic.classification == "missing"


class TestFileNameCoverage:
    """The pattern set should catch real-world file-naming variants."""

    @pytest.mark.parametrize("filename", [
        "LICENSE",
        "LICENSE.txt",
        "LICENSE.md",
        "LICENSE.rst",
        "LICENCE",       # British
        "COPYING",
        "COPYING.txt",
        "license",       # lowercase variant
        "license.md",
    ])
    def test_filename_variants_recognised(self, tmp_path, filename):
        (tmp_path / filename).write_text(
            "SPDX-License-Identifier: MIT\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "MIT"

    def test_dual_license_files_picked_strongest(self, tmp_path):
        # Rust convention: LICENSE-MIT + LICENSE-APACHE side by side.
        (tmp_path / "LICENSE-MIT").write_text(
            "SPDX-License-Identifier: MIT\n",
        )
        (tmp_path / "LICENSE-APACHE").write_text(
            "                                 Apache License\n",  # fingerprint
        )
        lic = detect_target_license(tmp_path)
        # MIT wins on confidence (SPDX header beats text fingerprint).
        assert lic.spdx_id == "MIT"
        assert lic.classification == "oss"
        assert lic.confidence == "high"
        # Other license file is recorded.
        assert "license-apache" in (f.lower() for f in lic.additional_files)

    def test_only_readme_does_not_count(self, tmp_path):
        # README isn't a license filename — should fall through to
        # ''missing''.
        (tmp_path / "README.md").write_text(
            "SPDX-License-Identifier: MIT\n",
        )
        lic = detect_target_license(tmp_path)
        assert lic.classification == "missing"


class TestSecurityAndRobustness:
    def test_symlink_license_skipped(self, tmp_path):
        # Defensive: a symlink LICENSE → /etc/passwd shouldn't be
        # read. Top-level walk drops symlinks explicitly.
        import os
        os.symlink("/etc/passwd", tmp_path / "LICENSE")
        lic = detect_target_license(tmp_path)
        # No license file detected (symlink skipped).
        assert lic.classification == "missing"

    def test_oversized_license_file_reads_only_head(self, tmp_path):
        # A LICENSE file that prepends 100 lines of garbage then
        # includes the MIT preamble — we cap at 50 lines, so this
        # should classify as unknown (the preamble lives past the
        # cap).
        garbage = "x\n" * 100
        (tmp_path / "LICENSE").write_text(
            garbage
            + "Permission is hereby granted, free of charge, ...\n",
        )
        lic = detect_target_license(tmp_path)
        # Beyond the read cap → no fingerprint hit → unknown.
        assert lic.classification == "unknown"

    def test_binary_license_file_does_not_crash(self, tmp_path):
        # Bizarre but real: a LICENSE file that's actually binary
        # (operator pasted in a screenshot or similar). The reader
        # falls back to errors="replace" so we just get garbage
        # text → unknown classification, no crash.
        (tmp_path / "LICENSE").write_bytes(b"\x00\x01\x02\xff" * 100)
        lic = detect_target_license(tmp_path)
        assert lic.classification == "unknown"


# ---------------------------------------------------------------------------
# format_license_summary
# ---------------------------------------------------------------------------


class TestFormatSummary:
    """The terse operator-facing render. OSS = single info line, no
    warning. Proprietary / unknown / missing = warning when the
    caller indicates this run will actually invoke CodeQL (caller
    passes ``command=\"codeql\"``). The HOW (source file, confidence,
    additional files) is debug-level, not surfaced here."""

    def test_oss_renders_terse(self):
        lic = TargetLicense(
            spdx_id="MIT", classification="oss",
            source_file="LICENSE", confidence="high",
        )
        out = format_license_summary(lic, command="codeql")
        assert "MIT" in out
        # Terse: no source-file mention, no confidence tag.
        assert "LICENSE" not in out
        assert "⚠️" not in out  # OSS classification = no warning

    def test_oss_medium_confidence_still_terse(self):
        # The HOW (text-fingerprint vs SPDX header) is debug-level
        # now; the operator-facing line just shows the spdx id.
        lic = TargetLicense(
            spdx_id="MIT", classification="oss",
            source_file="LICENSE", confidence="medium",
        )
        out = format_license_summary(lic, command="scan")
        assert "heuristic" not in out.lower()

    def test_proprietary_warns_on_codeql_command(self):
        lic = TargetLicense(
            spdx_id=None, classification="proprietary",
            source_file="LICENSE", confidence="low",
        )
        out = format_license_summary(lic, command="codeql")
        assert "proprietary" in out.lower()
        assert "⚠️" in out
        assert "codeql" in out.lower()

    def test_proprietary_silent_on_non_codeql_command(self):
        # Caller passes the actual command — ``fuzz`` / ``web`` /
        # plain ``agentic`` (no --codeql) — and the warning stays
        # quiet. Only the terse info line fires.
        lic = TargetLicense(
            spdx_id=None, classification="proprietary",
            source_file="LICENSE", confidence="low",
        )
        out = format_license_summary(lic, command="fuzz")
        assert "proprietary" in out.lower()
        assert "⚠️" not in out

    def test_missing_warns_on_codeql_command(self):
        lic = TargetLicense(
            spdx_id=None, classification="missing",
            source_file=None, confidence="low",
        )
        out = format_license_summary(lic, command="codeql")
        assert "not detected" in out.lower()
        assert "⚠️" in out

    def test_unknown_warns_on_codeql_command(self):
        lic = TargetLicense(
            spdx_id=None, classification="unknown",
            source_file="LICENSE", confidence="low",
        )
        out = format_license_summary(lic, command="codeql")
        assert "undetermined" in out.lower()
        assert "⚠️" in out

    def test_terse_for_oss_does_not_list_additional_files(self):
        # Operator-facing line is terse — additional license files
        # are visible in ``lic.additional_files`` for callers that
        # want to render them, but the summary stays clean.
        lic = TargetLicense(
            spdx_id="MIT", classification="oss",
            source_file="LICENSE-MIT", confidence="high",
            additional_files=("LICENSE-APACHE",),
        )
        out = format_license_summary(lic, command="scan")
        assert "LICENSE-APACHE" not in out
        assert "MIT" in out
