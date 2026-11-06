"""Memory-bounded inventory projections; retained records keep their existing validation."""
from __future__ import annotations

from ..sbom_import import _components, _references


def native_file(row):
    if not isinstance(row, dict):
        raise ValueError("invalid native file record")
    result = {key: row[key] for key in ("location", "digests", "unknowns") if key in row}
    metadata = row.get("metadata")
    if isinstance(metadata, dict):
        result["metadata"] = {key: metadata[key] for key in ("type", "linkDestination") if key in metadata}
    elif "metadata" in row:
        result["metadata"] = metadata
    return result


def native_package(row):
    if not isinstance(row, dict):
        raise ValueError("invalid native package record")
    result = {key: row[key] for key in ("id", "name", "version", "type", "purl", "licenses", "locations") if key in row}
    if "metadata" in row:
        metadata = row["metadata"]
        if isinstance(metadata, dict):
            result["metadata"] = {"files": metadata["files"]} if "files" in metadata else {}
        else:
            result["metadata"] = metadata
    return result


def discard(row):
    return None


class CycloneProjection:
    def __init__(self):
        self.refs = set()
        self.count = 0

    def observe(self, key, value):
        refs = _references(value)
        if refs & self.refs:
            raise ValueError("duplicate CycloneDX bom-ref")
        self.refs.update(refs)

    def component(self, row):
        rows = _components({"components": [row]})
        self.count += len(rows)
        if self.count > 100_000:
            raise ValueError("CycloneDX component count exceeds 100000")
        return self._compact(row)

    def _compact(self, row):
        children = row.get("components")
        if row.get("type") == "file":
            row = {key: row[key] for key in ("type", "name", "bom-ref") if key in row}
        else:
            row = dict(row)
        if children is not None:
            row["components"] = [self._compact(child) for child in children]
        return row


def spdx_file(row):
    if not isinstance(row, dict):
        raise ValueError("invalid SPDX file record")
    # Keep IDs, licence expressions and snippet/relationship anchors. The
    # importer validates them after all custom definitions are available.
    return {key: row[key] for key in ("SPDXID", "fileName", "licenseDeclared", "licenseConcluded",
                                     "licenseInfoFromFiles", "licenseInfoInFiles", "licenseInfoInSnippets", "hasFiles") if key in row}
