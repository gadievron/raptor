"""Regression: defusedxml must be installed and active in the SCA agent.

`requirements.txt` pins defusedxml so `packages/sca/agent.py` parses
target-repo pom.xml with the safe parser. These tests fail loudly if a
future install accidentally drops the pin or if defusedxml's
billion-laughs defense regresses.
"""

import importlib


def test_sca_agent_uses_defusedxml():
    agent = importlib.import_module("packages.sca.agent")
    assert agent._DEFUSED_XML, (
        "packages.sca.agent fell back to xml.etree.ElementTree because "
        "defusedxml is not installed. Pin `defusedxml==0.7.1` in "
        "requirements.txt — billion-laughs payloads (CWE-776) expand on "
        "the stdlib parser."
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
