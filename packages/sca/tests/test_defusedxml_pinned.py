"""Regression: defusedxml must be installed and active for SCA XML parsing.

`requirements.txt` pins defusedxml so SCA pom.xml / .csproj parsing
uses the safe parser. These tests fail loudly if a future install
accidentally drops the pin or if defusedxml's billion-laughs defense
regresses.
"""


def test_defusedxml_is_pinned_and_importable():
    """The dep must import cleanly — that's the structural pin check.

    We deliberately don't probe a specific consumer module
    (`packages.sca.agent`, `packages.sca.parsers.pom`, etc.) because
    the SCA refactor in feat/sca migrates the defusedxml import from
    the monolithic agent into per-ecosystem parsers. Testing the dep
    itself is shape-agnostic and stays correct across that change.
    """
    import defusedxml  # noqa: F401
    import defusedxml.ElementTree  # noqa: F401
    assert defusedxml.__version__, (
        "defusedxml imported but reports no version — install is broken."
    )


def test_defusedxml_rejects_billion_laughs():
    import defusedxml.ElementTree as DET
    from defusedxml import EntitiesForbidden

    payload = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE lolz ['
        b'<!ENTITY lol "lol">'
        b'<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">'
        b']>'
        b'<root>&lol2;</root>'
    )
    try:
        DET.fromstring(payload)
    except EntitiesForbidden:
        return
    raise AssertionError(
        "defusedxml.ElementTree.fromstring should have raised "
        "EntitiesForbidden on an entity-recursion payload."
    )


def test_well_formed_pom_still_parses():
    import defusedxml.ElementTree as DET

    pom = (
        b'<?xml version="1.0"?>'
        b'<project>'
        b'<dependencies>'
        b'<dependency>'
        b'<groupId>org.apache.commons</groupId>'
        b'<artifactId>commons-text</artifactId>'
        b'<version>1.9</version>'
        b'</dependency>'
        b'</dependencies>'
        b'</project>'
    )
    root = DET.fromstring(pom)
    deps = root.findall("dependencies/dependency")
    assert len(deps) == 1
    assert deps[0].find("artifactId").text == "commons-text"
