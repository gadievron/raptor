"""Classify native SBOM declaration gaps without loading package clients."""
import re


UNKNOWN_DECLARATION = re.compile(r"(?:^|[ (])(?:LicenseRef-)?(?:UNKNOWN|NOASSERTION|NONE|UNLICENSED)(?:$|[ )])", re.I)


def catalogue_declaration_missing(artifact: dict) -> bool:
    licences = artifact.get("licenses", [])
    if not isinstance(licences, list) or not licences:
        return True
    for licence in licences:
        if not isinstance(licence, dict):
            return True
        value = licence.get("spdxExpression") or licence.get("value")
        if not isinstance(value, str) or not value.strip() or UNKNOWN_DECLARATION.search(value):
            return True
    return False
