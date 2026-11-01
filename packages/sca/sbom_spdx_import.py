"""SPDX 2.3 JSON inventory and vulnerability-query projection.

The original document is preserved independently of package matching. This
adapter validates the structures it consumes; it is not a full SPDX validator.
External documents, source URLs and custom licence text are never fetched or
interpreted as instructions. Policy uses declared licences, not conclusions.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime
import re
from typing import TYPE_CHECKING

from .ecosystems import distro_base
from .models import Confidence, Dependency, PinStyle
from .sbom_import import ImportedBom, _component_to_dep

if TYPE_CHECKING:
    from pathlib import Path


_LOCAL_ID = re.compile(r"SPDXRef-[A-Za-z0-9.-]+")
_DOCUMENT_ID = re.compile(r"DocumentRef-[A-Za-z0-9.+-]+")
_LICENSE_REF = re.compile(r"(?:(DocumentRef-[A-Za-z0-9.+-]+):)?(LicenseRef-[A-Za-z0-9.-]+)")
_LICENSE_TOKEN = re.compile(r"(?:DocumentRef-[A-Za-z0-9.+-]+:)?[A-Za-z0-9][A-Za-z0-9.+-]*|[()]")
_DEPENDENCY_OF = {
    "DEPENDENCY_OF", "BUILD_DEPENDENCY_OF", "DEV_DEPENDENCY_OF",
    "OPTIONAL_DEPENDENCY_OF", "PROVIDED_DEPENDENCY_OF",
    "TEST_DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF",
}


def _objects(data: dict, field: str) -> list[dict]:
    value = data.get(field, [])
    if not isinstance(value, list) or any(not isinstance(v, dict) for v in value):
        raise ValueError(f"SPDX {field} must be an array of objects")
    return value


def _text(data: dict, field: str, *, required: bool = True) -> str | None:
    value = data.get(field)
    if value is None and not required and field not in data:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"SPDX {field} must be a nonempty string")
    return value


def _strings(data: dict, field: str) -> list[str]:
    value = data.get(field, [])
    if not isinstance(value, list) or any(not isinstance(v, str) or not v for v in value):
        raise ValueError(f"SPDX {field} must be an array of nonempty strings")
    return value


def _licence(value: str, licences: set[str], external: set[str]) -> None:
    """Check expression structure and resolve LicenseRef identifiers locally.

    This validates syntax, not membership in a particular SPDX licence list.
    Bound both expression length and nesting before policy evaluation.
    """
    if value in {"NONE", "NOASSERTION"}:
        return
    if len(value) > 4096:
        raise ValueError("SPDX licence expression exceeds 4096 characters")
    position, depth = 0, 0
    operand, simple, exception = True, False, False
    for match in _LICENSE_TOKEN.finditer(value):
        if value[position:match.start()].strip():
            raise ValueError("invalid SPDX licence expression")
        position = match.end()
        token = match[0]
        if token == "(":
            if not operand or exception:
                raise ValueError("invalid SPDX licence expression")
            depth += 1
            if depth > 10:
                raise ValueError("SPDX licence expression nesting exceeds 10")
        elif token == ")":
            if operand or depth == 0:
                raise ValueError("invalid SPDX licence expression")
            depth -= 1
            simple = False
        elif token in {"AND", "OR"}:
            if operand:
                raise ValueError("invalid SPDX licence expression")
            operand, simple = True, False
        elif token == "WITH":
            if operand or not simple:
                raise ValueError("invalid SPDX licence expression")
            operand, exception, simple = True, True, False
        else:
            if not operand or token in {"NONE", "NOASSERTION"}:
                raise ValueError("invalid SPDX licence expression")
            ref = _LICENSE_REF.fullmatch(token)
            if ":" in token and ref is None:
                raise ValueError("invalid SPDX external licence reference")
            if ref:
                if exception:
                    raise ValueError("LicenseRef cannot be an SPDX exception")
                if ref[1] and ref[1] not in external:
                    raise ValueError("undeclared SPDX external licence document")
                if not ref[1] and ref[2] not in licences:
                    raise ValueError("undefined SPDX LicenseRef")
            elif token.startswith("LicenseRef-") or token.startswith("DocumentRef-"):
                raise ValueError("invalid SPDX licence reference")
            simple = not exception
            operand, exception = False, False
    if value[position:].strip() or operand or depth:
        raise ValueError("invalid SPDX licence expression")


def _references(data: dict, items: list[dict]) -> tuple[set[str], set[str], set[str]]:
    known = {"SPDXRef-DOCUMENT"}
    for item in items:
        ref = _text(item, "SPDXID")
        if not _LOCAL_ID.fullmatch(ref) or ref in known:
            raise ValueError("invalid or duplicate SPDXID")
        known.add(ref)
    external: set[str] = set()
    for entry in _objects(data, "externalDocumentRefs"):
        ref = _text(entry, "externalDocumentId")
        if not _DOCUMENT_ID.fullmatch(ref) or ref in external:
            raise ValueError("invalid or duplicate SPDX external document ID")
        _text(entry, "spdxDocument")
        checksum = entry.get("checksum")
        if not isinstance(checksum, dict):
            raise ValueError("SPDX external document checksum must be an object")
        _text(checksum, "algorithm")
        _text(checksum, "checksumValue")
        external.add(ref)
    licences: set[str] = set()
    for entry in _objects(data, "hasExtractedLicensingInfos"):
        ref = _text(entry, "licenseId")
        if not re.fullmatch(r"LicenseRef-[A-Za-z0-9.-]+", ref) or ref in licences:
            raise ValueError("invalid or duplicate SPDX LicenseRef definition")
        _text(entry, "extractedText")
        licences.add(ref)
    return known, external, licences


def _depths(data: dict, known: set[str], external: set[str]) -> dict[str, int]:
    def endpoint(ref: str) -> bool:
        if ref in known:
            return True
        document, separator, local = ref.partition(":")
        if separator and document in external and _LOCAL_ID.fullmatch(local):
            return False
        raise ValueError("dangling or invalid SPDX element reference")

    roots = set()
    for ref in _strings(data, "documentDescribes"):
        if endpoint(ref):
            roots.add(ref)
    graph: dict[str, set[str]] = {}
    for relation in _objects(data, "relationships"):
        source = _text(relation, "spdxElementId")
        target = _text(relation, "relatedSpdxElement")
        kind = _text(relation, "relationshipType")
        endpoint(source)
        if target not in {"NONE", "NOASSERTION"}:
            endpoint(target)
        if kind == "DESCRIBES" and source == "SPDXRef-DOCUMENT" and target in known:
            roots.add(target)
        elif kind == "DESCRIBED_BY" and target == "SPDXRef-DOCUMENT" and source in known:
            roots.add(source)
        elif kind == "DEPENDS_ON":
            graph.setdefault(source, set()).add(target)
        elif kind in _DEPENDENCY_OF:
            graph.setdefault(target, set()).add(source)
    depths = dict.fromkeys(roots, 0)
    pending = deque(roots)
    while pending:
        current = pending.popleft()
        for child in graph.get(current, ()):
            if child in known and child not in depths:
                depths[child] = depths[current] + 1
                pending.append(child)
    return depths


def _read_spdx(data: dict, path: Path) -> ImportedBom:
    if data.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("unsupported SPDX version; expected SPDX-2.3 JSON")
    if data.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ValueError("SPDX document SPDXID must be SPDXRef-DOCUMENT")
    if data.get("dataLicense") != "CC0-1.0":
        raise ValueError("SPDX 2.3 dataLicense must be CC0-1.0")
    _text(data, "name")
    namespace = _text(data, "documentNamespace")
    if not re.match(r"[A-Za-z][A-Za-z0-9+.-]*:", namespace) or "#" in namespace or any(c.isspace() or ord(c) < 32 for c in namespace):
        raise ValueError("invalid SPDX documentNamespace")
    creation = data.get("creationInfo")
    if not isinstance(creation, dict):
        raise ValueError("SPDX creationInfo must be an object")
    created = _text(creation, "created")
    try:
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", created):
            raise ValueError("expected a UTC timestamp")
        datetime.fromisoformat(created)
    except ValueError as exc:
        raise ValueError("invalid SPDX creation timestamp") from exc
    if not _strings(creation, "creators"):
        raise ValueError("SPDX creationInfo requires creators")
    packages = _objects(data, "packages")
    files, snippets = _objects(data, "files"), _objects(data, "snippets")
    items = packages + files + snippets
    if len(items) > 100_000:
        raise ValueError("SPDX element count exceeds 100000")
    known, external, licences = _references(data, items)
    for file in files:
        _text(file, "fileName")
    file_ids = {f["SPDXID"] for f in files}
    for snippet in snippets:
        if _text(snippet, "snippetFromFile") not in file_ids:
            raise ValueError("dangling SPDX snippetFromFile reference")
    for item in items:
        for field in ("licenseDeclared", "licenseConcluded"):
            value = _text(item, field, required=False)
            if value is not None:
                _licence(value, licences, external)
        for field in ("licenseInfoFromFiles", "licenseInfoInFiles", "licenseInfoInSnippets"):
            for value in _strings(item, field):
                _licence(value, licences, external)
        for ref in _strings(item, "hasFiles"):
            if ref not in file_ids:
                raise ValueError("dangling SPDX hasFiles reference")
    depths = _depths(data, known, external)
    gaps: list[str] = []
    if external:
        gaps.append("external SPDX documents are retained but not fetched; their inventory and licence definitions are outside analysis coverage")
    if licences:
        gaps.append("custom SPDX licence definitions are retained; policy matches LicenseRef identifiers without interpreting their text")
    if files or snippets:
        gaps.append("SPDX files and snippets are retained; vulnerability matching and licence policy cover package declarations only")
    deps, inventory, refs = [], [], {}
    for package in packages:
        name = _text(package, "name")
        version = _text(package, "versionInfo", required=False)
        _text(package, "downloadLocation")
        if "filesAnalyzed" in package and type(package["filesAnalyzed"]) is not bool:
            raise ValueError("SPDX filesAnalyzed must be a boolean")
        declared = _text(package, "licenseDeclared", required=False)
        conclusion = _text(package, "licenseConcluded", required=False)
        declaration = declared if declared not in {None, "NONE", "NOASSERTION"} else None
        if conclusion not in {None, "NONE", "NOASSERTION", declared}:
            gaps.append(f"package {name}: distinct concluded licence retained; policy evaluates the declared licence only")
        purls = set()
        for ref in _objects(package, "externalRefs"):
            _text(ref, "referenceCategory")
            kind = _text(ref, "referenceType")
            locator = _text(ref, "referenceLocator")
            if kind in {"purl", "http://spdx.org/rdf/references/purl", "https://spdx.org/rdf/references/purl"}:
                if ref["referenceCategory"] != "PACKAGE-MANAGER":
                    raise ValueError("SPDX purl must use PACKAGE-MANAGER referenceCategory")
                purls.add(locator)
        if len(purls) > 1:
            raise ValueError("ambiguous SPDX package: multiple distinct purls")
        purl = next(iter(purls), "")
        comp = {"name": name, "purl": purl}
        if version is not None:
            comp["version"] = version
        if declaration:
            comp["licenses"] = [{"expression": declaration}]
        dep = _component_to_dep(comp, sbom_path=path)
        if dep is None:
            gaps.append(f"package {name}: no usable purl; retained in inventory, not vulnerability-matched")
            dep = Dependency(
                ecosystem="SBOM", name=name, version=version, declared_in=path,
                scope="main", is_lockfile=True, pin_style=PinStyle.UNKNOWN,
                direct=True, purl=purl, parser_confidence=Confidence("high", reason="SPDX inventory declaration"),
                declared_license=declaration,
                license_declarations=(declaration,) if declaration else (),
                source_kind="sbom_import",
            )
            inventory.append(dep)
        else:
            deps.append(dep)
            if distro_base(dep.ecosystem) is not None and package.get("primaryPackagePurpose") != "SOURCE":
                gaps.append(f"package {name}: distro matching uses supplied PURL coordinates; binary-to-source package correspondence is not established")
            refs.setdefault(dep.key(), []).append(package["SPDXID"])
            if not dep.version:
                gaps.append(f"package {name}: no resolved version; vulnerability coverage is incomplete")
        depth = depths.get(package["SPDXID"])
        dep.direct = depth is None or depth <= 1
        dep.transitive_depth = max(0, depth - 1) if depth is not None else None
        dep.parser_confidence = Confidence("high", numeric=0.95, reason="imported from SPDX SBOM")
        dep.source_extra = {
            "sbom_ref": package["SPDXID"],
            "sbom_directness": "graph" if depth is not None else "unknown",
            "spdx_license_declared": declared,
            "spdx_license_concluded": conclusion,
        }
    return ImportedBom(data, deps, gaps, refs, [p["SPDXID"] for p in packages], inventory, [], format="SPDX")
