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


class TestInTreeSymlinkLicenseFiles:
    """REUSE-compliant projects ship ``COPYING`` as a symlink
    into ``LICENSES/<SPDX>.txt`` (glib, NetworkManager, many
    GNOME-era projects). _find_license_files now accepts
    in-tree symlinks; out-of-tree ones still refused."""

    def test_copying_symlinked_to_in_tree_license(self, tmp_path):
        (tmp_path / "LICENSES").mkdir()
        (tmp_path / "LICENSES" / "LGPL-2.1-or-later.txt").write_text(
            "GNU LESSER GENERAL PUBLIC LICENSE\n"
            "Version 2.1\n"
        )
        (tmp_path / "COPYING").symlink_to(
            "LICENSES/LGPL-2.1-or-later.txt",
        )
        lic = detect_target_license(tmp_path)
        assert lic.classification == "oss"
        assert lic.spdx_id == "LGPL-2.1"

    def test_license_symlinked_outside_tree_refused(self, tmp_path):
        # Crafted-target defence: LICENSE → /etc/passwd-style
        # symlink to host fs. Must be refused so we don't read
        # host file contents and surface them as a license.
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "definitely-not-a-license.txt").write_text(
            "All Rights Reserved\n"
        )
        target = tmp_path / "target"
        target.mkdir()
        (target / "LICENSE").symlink_to(
            outside / "definitely-not-a-license.txt",
        )
        lic = detect_target_license(target)
        # Symlink out of tree refused; nothing left to detect.
        assert lic.classification == "missing"


class TestGplVersionDisambiguation:
    """GPL family + version detected from the preamble. Without
    this, every GPL/LGPL/AGPL file was classified as the family's
    "default" version (categorically GPL-3.0), which mis-labelled
    every GPL-2.0 project by a major version."""

    def test_gpl_version_2_classified_as_gpl_2_0(self, tmp_path):
        (tmp_path / "COPYING").write_text(
            "                  GNU GENERAL PUBLIC LICENSE\n"
            "                       Version 2, June 1991\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "GPL-2.0"

    def test_gpl_version_3_classified_as_gpl_3_0(self, tmp_path):
        (tmp_path / "COPYING").write_text(
            "                  GNU GENERAL PUBLIC LICENSE\n"
            "                  Version 3, 29 June 2007\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "GPL-3.0"

    def test_lgpl_version_2_1_kept_as_minor(self, tmp_path):
        # SPDX uses "LGPL-2.1" (with the .1) because 2.0 and 2.1
        # are substantively different licenses. Normalisation
        # rule: bare integer → .0; explicit minor → kept as-is.
        (tmp_path / "COPYING").write_text(
            "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 2.1\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "LGPL-2.1"

    def test_lgpl_version_3_classified_as_lgpl_3_0(self, tmp_path):
        (tmp_path / "COPYING").write_text(
            "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "LGPL-3.0"

    def test_agpl_version_3_classified_as_agpl_3_0(self, tmp_path):
        (tmp_path / "COPYING").write_text(
            "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "AGPL-3.0"


class TestBsd2VsBsd3Discrimination:
    """BSD-2 and BSD-3 share the same intro ("redistribution
    and use in source and binary forms"). BSD-3 = BSD-2 + the
    "Neither the name of" clause; presence of that clause
    promotes the result to BSD-3."""

    def test_bsd_3_clause_wins_when_neither_clause_present(self, tmp_path):
        # libslirp-shape file: BSD-3 because the "neither the name
        # of" clause is in the text. Pre-fix this got BSD-2 because
        # earliest-position picked the shared intro.
        (tmp_path / "LICENSE").write_text(
            "Redistribution and use in source and binary forms, "
            "with or without modification, are permitted provided "
            "that the following conditions are met:\n"
            "1. Redistributions of source code must retain ...\n"
            "2. Redistributions in binary form must reproduce ...\n"
            "3. Neither the name of the copyright holder nor "
            "the names of its contributors may be used to endorse\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "BSD-3-Clause"

    def test_bsd_2_clause_when_no_neither_clause(self, tmp_path):
        (tmp_path / "LICENSE").write_text(
            "Redistribution and use in source and binary forms, "
            "with or without modification, are permitted provided "
            "that the following conditions are met:\n"
            "1. Redistributions of source code must retain ...\n"
            "2. Redistributions in binary form must reproduce ...\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "BSD-2-Clause"


class TestPreRenamedLgplFingerprint:
    """Older GNOME-era projects (eds-data-server, others)
    ship COPYING with the pre-1999 name 'GNU LIBRARY GENERAL
    PUBLIC LICENSE' — same license, different title. Pin the
    fingerprint so these don't silently fall through to
    unknown."""

    def test_library_gpl_version_2_classified_as_lgpl_2_0(self, tmp_path):
        # "GNU LIBRARY GENERAL PUBLIC LICENSE Version 2" is
        # the canonical LGPL-2.0 — the very first LGPL,
        # before the 1999 rename to "Lesser" + version bump
        # to 2.1. Pin the version-detection so this doesn't
        # silently collapse to LGPL-2.1.
        (tmp_path / "COPYING").write_text(
            "GNU LIBRARY GENERAL PUBLIC LICENSE\n"
            "Version 2, June 1991\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.classification == "oss"
        assert lic.spdx_id == "LGPL-2.0"


class TestFingerprintPositionPriority:
    """Earliest fingerprint in the text wins, not registry
    order. Pre-fix _TEXT_FINGERPRINTS iterated in declaration
    order (MIT first), so a multi-license aggregation file
    that mentions MPL at the top but MIT later got classified
    as MIT — wrong. The earliest position is the operator-
    relevant signal: project's primary license is stated at
    the top; bundled-lib notices follow."""

    def test_earliest_match_wins_over_registry_order(self, tmp_path):
        # MPL preamble at line 1, MIT preamble at line 3.
        # Pre-fix: MIT wins (first in _TEXT_FINGERPRINTS).
        # Post-fix: MPL wins (earliest in text).
        (tmp_path / "LICENSE").write_text(
            "Mozilla Public License — this is the primary license.\n"
            "\n"
            "Bundled library: Permission is hereby granted, "
            "free of charge, to any person obtaining a copy.\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "MPL-2.0"

    def test_lgpl_preamble_not_misclassified_as_gpl(self, tmp_path):
        # LGPL boilerplate contains "GNU General Public License"
        # deeper in the text (LGPL incorporates GPL terms by
        # reference). Earliest-position correctly picks LGPL.
        # Pre-fix the registry-order iteration mis-classified
        # LGPL files as GPL-3.0.
        (tmp_path / "LICENSE").write_text(
            "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 2.1\n"
            "...this License incorporates the terms of the "
            "GNU General Public License...\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "LGPL-2.1"

    def test_agpl_preamble_not_misclassified_as_gpl(self, tmp_path):
        # Same shape: AGPL preamble contains references to GPL.
        (tmp_path / "LICENSE").write_text(
            "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3\n"
            "...derived from the GNU General Public License...\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "AGPL-3.0"

    def test_apache_notice_with_bundled_mpl_picks_apache(self, tmp_path):
        # Apache NOTICE files frequently start with the Apache
        # header then list third-party attributions including
        # Mozilla / MIT / etc. Earliest-position picks Apache.
        (tmp_path / "LICENSE").write_text(
            "Apache License Version 2.0\n\n"
            "Third-party notices:\n- foo: Mozilla Public License\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "Apache-2.0"

    def test_spdx_header_still_overrides_position(self, tmp_path):
        # The SPDX header takes precedence over fingerprint
        # matching regardless of position. Pin so a future
        # rework doesn't accidentally subordinate it.
        (tmp_path / "LICENSE").write_text(
            "Mozilla Public License preamble at top.\n"
            "SPDX-License-Identifier: MIT\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "MIT"

    def test_single_fingerprint_unchanged(self, tmp_path):
        # Sanity: file with only one fingerprint still works.
        (tmp_path / "LICENSE").write_text(
            "Permission is hereby granted, free of charge, "
            "to any person obtaining a copy of this software\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "MIT"


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


class TestIndirectionFollow:
    """Indirection-follow promotes ``classification=unknown``
    when the top-level LICENSE is a pointer to a real license
    file inside the target tree (Firefox, multi-license repos
    with ``LICENSES/*.txt`` layouts)."""

    def test_simple_text_indirection_follows(self, tmp_path):
        # LICENSE redirect → LICENSE.txt with real MIT body.
        (tmp_path / "LICENSE").write_text(
            "Please see the file LICENSE.txt for the licence.\n"
        )
        (tmp_path / "LICENSE.txt").write_text(
            "Permission is hereby granted, free of charge, "
            "to any person obtaining a copy of this software "
            "and associated documentation files (the Software)\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "MIT"
        assert lic.classification == "oss"
        # source_file is the relative path of the linked file,
        # not the original LICENSE pointer.
        assert lic.source_file == "LICENSE.txt"

    def test_nested_subdir_indirection_follows(self, tmp_path):
        # Multi-license layout: LICENSE → LICENSES/MIT.txt
        (tmp_path / "LICENSE").write_text(
            "license text is in LICENSES/MIT.txt\n"
        )
        (tmp_path / "LICENSES").mkdir()
        (tmp_path / "LICENSES" / "MIT.txt").write_text(
            "Permission is hereby granted, free of charge, "
            "to any person obtaining a copy of this software\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.spdx_id == "MIT"
        assert lic.source_file == "LICENSES/MIT.txt"

    def test_path_traversal_rejected(self, tmp_path):
        # Adversarial: LICENSE redirect points outside the
        # target tree via .. — defence must reject.
        (tmp_path / "target").mkdir()
        (tmp_path / "outside_license.txt").write_text(
            "MIT License\n\n"
            "Permission is hereby granted, free of charge\n"
        )
        (tmp_path / "target" / "LICENSE").write_text(
            "See ../outside_license.txt for terms\n"
        )
        lic = detect_target_license(tmp_path / "target")
        # Path traversal rejected → indirection didn't help →
        # stays unknown with the original LICENSE as source.
        assert lic.classification == "unknown"
        assert lic.source_file == "LICENSE"

    def test_symlinked_indirection_target_rejected(self, tmp_path):
        # Adversarial: LICENSE → real_link.txt → /etc/passwd
        # (symlink to host file). Symlink check refuses to
        # follow.
        (tmp_path / "LICENSE").write_text(
            "see real_link.txt for the terms\n"
        )
        (tmp_path / "real_link.txt").symlink_to(
            "/nonexistent/sensitive",
        )
        lic = detect_target_license(tmp_path)
        # Symlinked target refused; stays unknown.
        assert lic.classification == "unknown"
        assert lic.source_file == "LICENSE"

    def test_html_multi_license_aggregation_picks_primary(self, tmp_path):
        # The Firefox case: LICENSE → license.html which
        # contains MPL header + many bundled-lib license
        # notices. _classify_text picks the EARLIEST fingerprint
        # in the text, so the project's primary license (named
        # at the top of the HTML) wins over the bundled-lib
        # notices that appear later. Pre-fix the registry-order
        # fingerprint iteration matched MIT (which appeared
        # later, in the bundled-lib section) — wrong.
        (tmp_path / "LICENSE").write_text(
            "Please see the file legal/license.html for the "
            "copyright licensing conditions.\n"
        )
        (tmp_path / "legal").mkdir()
        (tmp_path / "legal" / "license.html").write_text(
            "<html><body>\n"
            "<h1>Project license: Mozilla Public License</h1>\n"
            "<p>This project is licensed under the MPL-2.0.</p>\n"
            "<h2>Bundled libraries</h2>\n"
            "<pre>Permission is hereby granted, free of charge, "
            "to any person obtaining a copy of this software</pre>\n"
            "</body></html>\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.classification == "oss"
        assert lic.spdx_id == "MPL-2.0"
        assert lic.source_file == "legal/license.html"

    def test_in_tree_symlink_pivot_blocked(self, tmp_path):
        # Adversarial: LICENSE redirect points to a file that's
        # actually a symlink to another in-tree file (e.g.
        # ``.env`` or any sensitive in-target file). Pre-fix the
        # is_symlink check fired AFTER .resolve() — always
        # returned False for the canonicalised target — so the
        # symlink-pivot succeeded and we read the pivoted file's
        # content for classification.
        (tmp_path / ".env").write_text(
            "API_KEY=secret-shouldnt-be-read\n"
            "All Rights Reserved — proprietary\n"
        )
        (tmp_path / "shim.txt").symlink_to(".env")
        (tmp_path / "LICENSE").write_text(
            "see the file shim.txt for the terms\n"
        )
        lic = detect_target_license(tmp_path)
        # Pivoted file NOT read; classification stays unknown.
        # If it WERE read, the proprietary marker would fire
        # and the result would be "proprietary" — pin against
        # that regression.
        assert lic.classification == "unknown"
        assert lic.source_file == "LICENSE"

    def test_absolute_path_ref_rejected(self, tmp_path):
        # Defence-in-depth: ref starting with `/` rejected at
        # the regex-blind-spot layer. relative_to(target_dir)
        # would also catch this, but the early reject keeps
        # the failure intent explicit.
        (tmp_path / "LICENSE").write_text(
            "see /etc/passwd.txt for the licence\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.classification == "unknown"

    def test_directory_enumeration_capped(self, tmp_path):
        # A hostile LICENSES/ with hundreds of children — the
        # cap caps enqueued children at _INDIRECTION_PATH_LIMIT
        # (8) so the BFS doesn't blow up.
        (tmp_path / "LICENSE").write_text(
            "see the LICENSES/ directory\n"
        )
        (tmp_path / "LICENSES").mkdir()
        # 50 files, only the first 8 should be enqueued.
        # Make them all classifiable so we know the cap
        # actually kicks in (otherwise non-classifiable
        # children would silently exhaust).
        for i in range(50):
            (tmp_path / "LICENSES" / f"f{i:02d}.txt").write_text(
                "MIT License\n\n"
                "Permission is hereby granted, free of charge\n"
            )
        lic = detect_target_license(tmp_path)
        # Should classify (cap doesn't prevent successful
        # detection on small dirs); main concern is the cap
        # doesn't break the legit case.
        assert lic.classification == "oss"
        assert lic.spdx_id == "MIT"

    def test_cycle_terminates(self, tmp_path):
        # A → B → A — the visited-set must prevent infinite
        # loops. Pin so a future refactor doesn't accidentally
        # drop the cycle-protection.
        (tmp_path / "LICENSE").write_text(
            "Some text. see A.txt for details\n"
        )
        (tmp_path / "A.txt").write_text(
            "More text. see B.txt for the licence\n"
        )
        (tmp_path / "B.txt").write_text(
            "Yet more text. see A.txt for the licence\n"
        )
        # No license-text fingerprint in any of them; the test
        # is that this RETURNS (no infinite loop) — the
        # classification stays unknown but the call completes.
        lic = detect_target_license(tmp_path)
        assert lic.classification == "unknown"

    def test_depth_limit_blocks_deep_chains(self, tmp_path):
        # _INDIRECTION_DEPTH_LIMIT=2 should prevent us
        # following 3+ hops. Pin that a 4-hop chain doesn't
        # reach the MIT text at the far end.
        (tmp_path / "LICENSE").write_text("see A.txt for the licence\n")
        (tmp_path / "A.txt").write_text("see B.txt for the licence\n")
        (tmp_path / "B.txt").write_text("see C.txt for the licence\n")
        (tmp_path / "C.txt").write_text("see D.txt for the licence\n")
        (tmp_path / "D.txt").write_text(
            "Permission is hereby granted, free of charge\n"
        )
        lic = detect_target_license(tmp_path)
        # MIT text is 4 hops deep — beyond the depth limit;
        # detector must NOT classify as MIT.
        assert lic.spdx_id != "MIT"
        assert lic.classification == "unknown"

    def test_directory_reference_enumerated(self, tmp_path):
        # Pattern: "see LICENSES/ directory" — should enumerate
        # files inside and classify each.
        (tmp_path / "LICENSE").write_text(
            "see the LICENSES/ directory for all licenses\n"
        )
        (tmp_path / "LICENSES").mkdir()
        (tmp_path / "LICENSES" / "MIT.txt").write_text(
            "Permission is hereby granted, free of charge, "
            "to any person obtaining a copy of this software\n"
        )
        lic = detect_target_license(tmp_path)
        assert lic.classification == "oss"
        assert lic.spdx_id == "MIT"


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
