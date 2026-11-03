"""Broken Debian references must bind an unambiguous retained version."""
import pytest

from core.oci.common_licenses import corrected_common_reference


GFDL = """License: GFDL-1.3+-no-invariant
 Permission is granted under the terms of the
 GNU Free Documentation License, Version 1.3 or
 any later version.
 See /usr/share/common-licenses/GFDL-3.

"""


def test_gpl_version_spelling():
    assert corrected_common_reference("GPL-2.0", "") == "GPL-2"


def test_explicit_gfdl_grant_supplies_the_referenced_version():
    assert corrected_common_reference("GFDL-3", GFDL) == "GFDL-1.3"


@pytest.mark.parametrize("text", [
    "", GFDL.replace("Version 1.3", "Version 1.2"),
    GFDL.replace("License: GFDL-1.3", "License: GFDL-1.2"),
    GFDL.replace("License: GFDL-1.3+-no-invariant", "License: GFDL"),
    GFDL.replace("GFDL-3.", "GFDL-2."),
    GFDL.replace(" GNU Free", "\nLicense: other\n GNU Free"),
])
def test_missing_conflicting_or_unrelated_grants_stay_unresolved(text):
    assert corrected_common_reference("GFDL-3", text) is None


@pytest.mark.parametrize("name", ["GPL", "GPL-9", "GFDL", "GFDL-2", "../GPL-2"])
def test_other_references_are_not_guessed(name):
    assert corrected_common_reference(name, GFDL) is None
