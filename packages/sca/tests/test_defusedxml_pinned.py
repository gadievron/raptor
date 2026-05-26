"""Regression: defusedxml must be installed and active in the SCA POM parser.

The dedicated POM parser at ``packages/sca/parsers/pom.py`` uses
defusedxml's ``ElementTree`` to read target-repo ``pom.xml`` files.
These tests fail loudly if a future install accidentally drops the
defusedxml pin or if its billion-laughs defense regresses.

(Pre-feat/sca, POM parsing lived inline in ``packages/sca/agent.py``
and the import flag was ``_DEFUSED_XML``. On feat/sca the parser
lives in its own module and the flag is ``_AVAILABLE``.)
"""

import importlib


def test_sca_pom_parser_uses_defusedxml():
    pom_parser = importlib.import_module("packages.sca.parsers.pom")
    assert pom_parser._AVAILABLE, (
        "packages.sca.parsers.pom fell back to xml.etree.ElementTree "
        "because defusedxml is not installed. Pin "
        "``defusedxml==0.7.1`` in requirements.txt — billion-laughs "
        "payloads (CWE-776) expand on the stdlib parser."
    )


def test_sca_nuget_parser_uses_defusedxml():
    """``.csproj`` / ``.fsproj`` / ``.vbproj`` files come from the
    target repo. Without defusedxml, an attacker-controlled XXE
    payload can exfil filesystem content or DoS the parser.
    Surfaced 2026-05-21 by semgrep dogfood — historically silently
    fell back to stdlib ``ElementTree``."""
    nuget_parser = importlib.import_module("packages.sca.parsers.nuget")
    assert nuget_parser._AVAILABLE, (
        "packages.sca.parsers.nuget fell back to stdlib ElementTree "
        "because defusedxml is not installed."
    )


def test_sca_license_pom_uses_defusedxml():
    """Maven POM fetched from Maven Central for license extraction.
    Trusted-network input, but defense-in-depth — refuse stdlib."""
    lic = importlib.import_module("packages.sca.license")
    assert lic._DEFUSEDXML_AVAILABLE, (
        "packages.sca.license fell back to stdlib for POM parsing."
    )


def test_sca_maven_registry_uses_defusedxml():
    """Maven Central POM parsed by the registry client. Same
    defense-in-depth reasoning."""
    mvn = importlib.import_module("packages.sca.registries.maven")
    assert mvn._DEFUSEDXML_AVAILABLE, (
        "packages.sca.registries.maven fell back to stdlib XML parser."
    )


def test_sca_nuget_registry_uses_defusedxml():
    """``.nuspec`` from NuGet registry. Same defense-in-depth
    reasoning."""
    ng = importlib.import_module("packages.sca.registries.nuget")
    assert ng._DEFUSEDXML_AVAILABLE, (
        "packages.sca.registries.nuget fell back to stdlib XML parser."
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
