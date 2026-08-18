"""Negative control: "xxe" keyword family (Python).

defusedxml parsing only — entity resolution structurally disabled by
the library. No lxml parse call, no entity-resolution opt-in, no DTD
loading. The unsafe-shape pattern must not match any line of this
fixture.
"""

from defusedxml.ElementTree import fromstring as safe_fromstring


def parse_manifest(text):
    # defusedxml forbids entity expansion and external DTD fetches by
    # construction — the safe idiom the unsafe-shape pattern must not
    # match.
    return safe_fromstring(text)
