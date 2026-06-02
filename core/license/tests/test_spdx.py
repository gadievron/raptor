"""Tests for ``core/license/spdx.py`` — the shared compound-SPDX
primitives consumed by SCA's policy engine + the target-license
detector."""

from __future__ import annotations

from core.license.spdx import (
    looks_like_spdx_expression,
    split_compound_expression,
)


class TestLooksLikeSpdxExpression:
    def test_or_compound(self):
        assert looks_like_spdx_expression("MIT OR Apache-2.0")

    def test_and_compound(self):
        assert looks_like_spdx_expression("Apache-2.0 AND BSD-3-Clause")

    def test_with_exception(self):
        assert looks_like_spdx_expression(
            "GPL-3.0 WITH Classpath-exception-2.0",
        )

    def test_single_id_rejected(self):
        # Single-id is valid SPDX but not a compound expression —
        # caller's single-id path handles those.
        assert not looks_like_spdx_expression("MIT")

    def test_freetext_rejected(self):
        assert not looks_like_spdx_expression("see LICENSE file")
        assert not looks_like_spdx_expression("Custom Commercial License")

    def test_whitespace_tolerated(self):
        assert looks_like_spdx_expression("  MIT OR Apache-2.0  ")

    def test_three_operand_chain(self):
        assert looks_like_spdx_expression(
            "MIT OR Apache-2.0 OR BSD-3-Clause",
        )


class TestSplitCompoundExpression:
    def test_or_split(self):
        assert split_compound_expression("MIT OR Apache-2.0") == [
            "MIT", "Apache-2.0",
        ]

    def test_with_split(self):
        # WITH attaches an exception to the preceding license — the
        # first operand is the principal license; callers using
        # this split should know that.
        assert split_compound_expression(
            "GPL-3.0 WITH Classpath-exception-2.0",
        ) == ["GPL-3.0", "Classpath-exception-2.0"]

    def test_and_split(self):
        assert split_compound_expression(
            "Apache-2.0 AND BSD-3-Clause",
        ) == ["Apache-2.0", "BSD-3-Clause"]

    def test_three_operand_chain(self):
        assert split_compound_expression(
            "MIT OR Apache-2.0 OR BSD-3-Clause",
        ) == ["MIT", "Apache-2.0", "BSD-3-Clause"]

    def test_single_id_returns_empty(self):
        # Single ids are not compound — caller falls back to
        # single-id handling.
        assert split_compound_expression("MIT") == []

    def test_freetext_returns_empty(self):
        assert split_compound_expression("see LICENSE file") == []


class TestSCAImportCompatibility:
    """SCA's ``_looks_like_spdx_expression`` alias must continue to
    work after the extraction. Locks in the call-site contract."""

    def test_sca_alias_is_shared_function(self):
        from packages.sca.license import _looks_like_spdx_expression
        assert _looks_like_spdx_expression is looks_like_spdx_expression
