"""Portable audit metadata, deliberately independent of any HTML presentation."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import urllib.parse

from core.oci.license_declarations import UNKNOWN_DECLARATION
from core.license.spdx import split_compound_expression
from .source import SHA256

FORMAT = "raptor-sbom-inventory"


@dataclass
class Notice:
    sha256: str
    path: str
    origin: str
    content_kind: str = "notice_candidate"
    layer_id: str = ""
    visibility: str = "not_recorded"


@dataclass
class Record:
    id: str
    name: str
    version: str
    kind: str
    purl: str = ""
    scope: str = "packages"
    declarations: list[str] = field(default_factory=list)
    notices: list[Notice] = field(default_factory=list)
    notice_status: str = "not_assessed"
    graph_supplied: bool = False
    parents: list[str] = field(default_factory=list)
    children: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)

    @property
    def declaration_missing(self):
        return not self.declarations or any(not value.strip() or UNKNOWN_DECLARATION.search(value)
                                            for value in self.declarations)

    @property
    def identity(self):
        # Keep package type, namespace, distro/architecture and subpath. A
        # scanner occurrence qualifier is not a cross-version identity.
        head, mark, fragment = self.purl.partition("#")
        base, _, query = head.partition("?")
        at = base.rfind("@")
        if at > base.rfind("/"):
            base = base[:at]
        qualifiers = urllib.parse.urlencode(sorted(
            (k, v.rsplit("@", 1)[0] if k == "upstream" and base.startswith(("pkg:deb/", "pkg:apk/")) else v)
            for k, v in urllib.parse.parse_qsl(query) if k != "package-id"))
        identity = base + ("?" + qualifiers if qualifiers else "") + (mark + fragment if mark else "")
        if self.scope == "source-candidates":
            return self.scope, self.evidence.get("tool", ""), self.evidence.get("source") or "", identity or (self.kind + ":" + self.name)
        return self.scope, identity or (self.kind + ":" + self.name)


@dataclass
class Inventory:
    source_format: str
    source_sha256: str
    subject: str = ""
    records: list[Record] = field(default_factory=list)
    file_count: int = 0
    coverage: dict | None = None
    notice_files: list[Notice] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    schema_version: int = 1
    format: str = FORMAT

    @property
    def notice_verification(self) -> str:
        """Transient readback state; keep format-1 snapshot fields unchanged."""
        return getattr(self, "_notice_verification", "not_recorded")

    @notice_verification.setter
    def notice_verification(self, value: str) -> None:
        self._notice_verification = value

    def to_dict(self):
        return asdict(self)

    def summary(self):
        packages = [p for p in self.records if p.scope == "packages"]
        candidates = [p for p in self.records if p.scope == "source-candidates"]
        assessed = [p for p in packages if p.notice_status != "not_assessed"]
        return {"packages": len(packages), "source_candidates": len(candidates),
                "subject_records": sum(p.scope == "subjects" for p in self.records),
                "file_records": self.file_count,
                "unresolved_declarations": sum(p.declaration_missing for p in packages),
                "notice_assessed_packages": len(assessed),
                "notice_gap_packages": sum(p.notice_status in {"missing", "invalid"} for p in assessed) if assessed else None,
                "source_candidate_notice_gaps": sum(p.notice_status in {"missing", "invalid"} for p in candidates),
                "retained_notice_records": len(self.notice_files)}


def from_snapshot(data):
    if data.get("format") != FORMAT or type(data.get("schema_version")) is not int or data.get("schema_version") != 1:
        raise ValueError("unsupported SBOM inventory snapshot")
    values = dict(data)
    values.pop("summary", None)
    values.pop("selection", None)
    rows = values.get("records")
    if not isinstance(rows, list) or len(rows) > 100_000:
        raise ValueError("invalid inventory inventory")
    values["records"] = [Record(**dict(row, notices=[Notice(**n) for n in row.get("notices", [])])) for row in rows]
    values["notice_files"] = [Notice(**n) for n in values.get("notice_files", [])]
    inventory = Inventory(**values)
    validate(inventory)
    return inventory


def validate(inventory):
    if not isinstance(inventory.source_sha256, str) or not SHA256.fullmatch(inventory.source_sha256):
        raise ValueError("invalid inventory input fingerprint")
    if not isinstance(inventory.source_format, str) or not isinstance(inventory.subject, str):
        raise ValueError("invalid inventory source identity")
    if type(inventory.file_count) is not int or inventory.file_count < 0:
        raise ValueError("invalid file inventory count")
    if not isinstance(inventory.diagnostics, list) or any(not isinstance(v, str) for v in inventory.diagnostics):
        raise ValueError("invalid inventory diagnostics")
    if inventory.notice_verification not in {"not_recorded", "verified", "not_verified", "failed"}:
        raise ValueError("invalid notice verification scope")
    if inventory.coverage is not None:
        if not isinstance(inventory.coverage, dict):
            raise ValueError("invalid recorded coverage")
        metrics = inventory.coverage.get("metrics")
        if metrics is not None and (not isinstance(metrics, dict) or any(
                v is not None and (type(v) is not int or v < 0) for v in metrics.values())):
            raise ValueError("invalid recorded coverage metrics")
    seen = set()
    for row in inventory.records:
        if (not all(isinstance(v, str) for v in (row.id, row.name, row.version, row.kind, row.purl))
                or not row.id or not row.name or (row.scope, row.id) in seen
                or row.scope not in {"packages", "source-candidates", "subjects"}
                or row.notice_status not in {"not_assessed", "captured", "missing", "invalid"}
                or not isinstance(row.declarations, list) or any(not isinstance(v, str) for v in row.declarations)
                or type(row.graph_supplied) is not bool
                or not isinstance(row.evidence, dict)):
            raise ValueError("invalid or duplicate audit package record")
        if any(not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs)
               for refs in (row.parents, row.children)):
            raise ValueError("invalid inventory dependency references")
        if row.notice_status == "captured" and not row.notices:
            raise ValueError("captured notice status has no notice")
        if row.scope == "source-candidates" and (not isinstance(row.evidence.get("tool", ""), str)
                or not isinstance(row.evidence.get("source") or "", str)):
            raise ValueError("invalid source-candidate identity")
        seen.add((row.scope, row.id))
    for notice in [n for p in inventory.records for n in p.notices] + inventory.notice_files:
        if (not isinstance(notice.sha256, str) or not SHA256.fullmatch(notice.sha256)
                or not all(isinstance(v, str) for v in (notice.path, notice.origin, notice.content_kind, notice.layer_id, notice.visibility))):
            raise ValueError("invalid retained notice reference")


def selected(inventory, *, license_id=None, package=None, scope=None):
    """Exact licence operands, without choosing an AND/OR licensing option."""
    def matches(row):
        if scope and row.scope != scope:
            return False
        if package and package not in {row.id, row.name, row.purl}:
            return False
        # Inspect operands, not arbitrary free-text mentions such as "not MIT".
        # Removing grouping only enumerates operands; the stored declaration
        # and its AND/OR choice remain unchanged.
        return not license_id or any(value.strip() == license_id or license_id in split_compound_expression(
            value.replace("(", " ").replace(")", " ")) for value in row.declarations)
    return [row for row in inventory.records if matches(row)]
