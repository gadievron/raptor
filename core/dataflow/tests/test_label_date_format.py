"""Label date metadata must consume the full ASCII date string."""

import pytest

from core.dataflow.label import GroundTruth


def test_label_date_requires_full_ascii_format():
    def label(date):
        return GroundTruth(finding_id="fixture", verdict="true_positive", rationale="fixture",
                           labeler="fixture", labeled_at=date)

    for invalid in ("2026-11-13\n", "２０２６-１１-１３", "2026-1-13", " 2026-11-13",
                    None, False, 20261113, [], {}):
        with pytest.raises(ValueError, match="labeled_at"):
            label(invalid)
    for date in ("2026-11-13", "2024-02-29"):
        original = label(date)
        assert GroundTruth.from_json(original.to_json()).labeled_at == date
