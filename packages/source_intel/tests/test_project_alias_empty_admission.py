"""No project-alias candidates means no target metadata admission."""

import importlib

import pytest

analyze = importlib.import_module("packages.source_intel.analyze")


@pytest.mark.parametrize("aliases", [
    (), (("wur", ()),), (("wur", ()), ("nonnull", ())),
], ids=["none", "one-empty-family", "two-empty-families"])
def test_empty_aliases_do_not_request_target_metadata(tmp_path, aliases):
    class MetadataForbidden(type(tmp_path)):
        def is_dir(self):
            pytest.fail("empty project aliases must not request target metadata")

    assert analyze._scan_project_alias_observations(MetadataForbidden(tmp_path), aliases) == []


def test_nonempty_aliases_retain_target_metadata_admission(tmp_path):
    requests = []

    class TrackedPath(type(tmp_path)):
        def is_dir(self):
            requests.append(str(self))
            return super().is_dir()

    target = TrackedPath(tmp_path / "missing")
    assert analyze._scan_project_alias_observations(target, (("wur", ("OWNED",)),)) == []
    assert requests == [str(target)]
