"""Actual retained facts govern curated/project alias overlap."""

from dataclasses import replace

import pytest

from packages.source_intel.analyze import (
    AttributeEvidence, _extend_project_alias_observations,
)


def _known():
    return AttributeEvidence(
        kind="wur", function_name="owned", location=("owned.c", 3),
        match_source="known_alias", raw_match="__must_check",
    )


def test_matching_project_observation_retains_one_curated_fact():
    known = _known()
    observations = [known]
    project = replace(known, match_source="project_alias")
    _extend_project_alias_observations(observations, [project])
    assert observations == [known] and observations[0] is known


@pytest.mark.parametrize("change", [
    {"kind": "nonnull"}, {"function_name": "other"},
    {"location": ("other.c", 3)}, {"location": ("owned.c", 4)},
    {"raw_match": "OWNED_ALIAS"}, {"conditional_on": "CONFIG_OWNED"},
])
def test_distinct_fact_fields_are_not_deduplicated(change):
    known = _known()
    project = replace(known, match_source="project_alias", **change)
    observations = [known]
    _extend_project_alias_observations(observations, [project])
    assert observations == [known, project]


def test_missing_curated_fact_retains_project_fallback():
    project = replace(_known(), match_source="project_alias")
    observations = []
    _extend_project_alias_observations(observations, [project])
    assert observations == [project]


def test_literal_provenance_and_distinct_project_order_are_retained():
    literal = replace(_known(), match_source="literal")
    project = replace(_known(), match_source="project_alias")
    other = replace(project, function_name="other")
    observations = [literal]
    _extend_project_alias_observations(observations, [project, other])
    assert observations == [literal, project, other]


def test_no_project_observations_does_not_scan_existing_facts():
    class UnreadableFacts(list):
        def __iter__(self):
            pytest.fail("empty project result must not scan existing facts")

    observations = UnreadableFacts([_known()])
    _extend_project_alias_observations(observations, [])
    assert len(observations) == 1
