"""Saved conditional syntax projection, never verification evidence input.

Writer precondition: operator-owned run output directory, not target output.
Reader output is descriptive saved data; it does not authenticate the producer,
source snapshot, claim lineage, missing premises or freshness.
"""
import json
from pathlib import Path

from core.json import loads
from core.atomic_fs import write_bytes_atomically
from core.reporting.document import Block
from core.source import open_regular_beneath

FILENAME = "source-syntax-observations.json"
CONTRACT = "unsigned-member-narrow-alloc-wide-copy-v1"
FILES = ("protocol/parser.c", "protocol/message.c", "protocol/message.h")
REQUIRED_LIMITS = (
    "preprocessing-and-system-header-bindings", "fixed-width-typedef-semantics",
    "ABI-size_t-and-header-layout", "malloc-and-memcpy-library-bindings",
    "external-object-validity-and-aliasing", "allocation-success",
    "atomic-multi-file-build-snapshot", "claim-mechanism-verification",
)
ROLES = {"wide_record", "narrow_record", "caller", "callee", "prototype", "member_assignment",
         "source_bounds_guard", "direct_call", "nonzero_alloc_guard", "allocation",
         "allocation_success_guard", "copy", "return"}


def _hex(value, length):
    return type(value) is str and len(value) == length and all(c in "0123456789abcdef" for c in value)


def _saved_shape(row):
    expected = {"source_units", "spans", "member_type_spellings", "argument_roles", "declared_cwe",
                "class_admission", "claim_reference", "status", "contract", "authority",
                "source_verified", "unresolved"}
    if (set(row) != expected or row["authority"] is not False or row["source_verified"] is not False
            or row["status"] != "source_bound_conditional_observation" or row["contract"] != CONTRACT
            or row["member_type_spellings"] != ["uint32_t", "uint16_t"]):
        return False
    if row["argument_roles"] != ["narrow-member", "wire-plus-header", "wide-member"]:
        return False
    units, spans, unresolved = row["source_units"], row["spans"], row["unresolved"]
    if type(units) is not list or len(units) != 3 or type(spans) is not list or len(spans) != 13:
        return False
    sizes = {}
    for unit, file in zip(units, FILES):
        if (type(unit) is not list or len(unit) != 2 or type(unit[0]) is not str
                or unit[0] != file or type(unit[1]) is not dict):
            return False
        identity = unit[1]
        if set(identity) != {"sha256", "version"} or not _hex(identity["sha256"], 64):
            return False
        version = identity["version"]
        if (type(version) is not list or len(version) != 5
                or any(type(v) is not int or not -(1 << 127) < v < 1 << 127 for v in version)
                or version[0] < 0 or version[1] < 0 or not 1 <= version[2] <= 32768):
            return False
        sizes[file] = version[2]
    roles = set()
    locations = {}
    callee_roles = {"callee", "nonzero_alloc_guard", "allocation", "allocation_success_guard", "copy", "return"}
    for span in spans:
        if type(span) is not dict or set(span) != {"role", "file", "start_byte", "end_byte", "sha256"}:
            return False
        role = span["role"]
        if type(role) is not str or role not in ROLES or role in roles or span["file"] not in FILES:
            return False
        expected_file = FILES[2] if role == "prototype" else FILES[1] if role in callee_roles else FILES[0]
        if span["file"] != expected_file:
            return False
        if (type(span["start_byte"]) is not int or type(span["end_byte"]) is not int
                or not 0 <= span["start_byte"] < span["end_byte"] <= sizes[span["file"]]
                or not _hex(span["sha256"], 64)):
            return False
        roles.add(role)
        locations[role] = (span["start_byte"], span["end_byte"])
    for role in ("member_assignment", "source_bounds_guard", "direct_call"):
        if not locations["caller"][0] <= locations[role][0] < locations[role][1] <= locations["caller"][1]:
            return False
    for role in callee_roles - {"callee"}:
        if not locations["callee"][0] <= locations[role][0] < locations[role][1] <= locations["callee"][1]:
            return False
    for ordered in (("wide_record", "narrow_record", "caller"),
                    ("member_assignment", "source_bounds_guard", "direct_call"),
                    ("nonzero_alloc_guard", "allocation", "allocation_success_guard", "copy", "return")):
        if any(locations[first][1] > locations[second][0] for first, second in zip(ordered, ordered[1:])):
            return False
    if type(unresolved) is not list or not 1 <= len(unresolved) <= 16:
        return False
    if unresolved != list(REQUIRED_LIMITS):
        return False
    admission = row["class_admission"]
    if type(admission) is not str:
        return False
    if admission.startswith("unavailable:") and len(admission) <= 128:
        return row["declared_cwe"] is None and row["claim_reference"] is None
    reference = row["claim_reference"]
    return (admission == "declared-occurrence-only:not-mechanism-verification"
            and row["declared_cwe"] in ("CWE-190", "CWE-195", "CWE-680")
            and type(reference) is list and len(reference) == 2
            and all(_hex(value, 32) for value in reference))


def _project_typed(result):
    # Report-only readers do not import or initialize the source observer.
    from .member_copy_observation import MemberCopyObservation, ObservationUnavailable, SyntaxSpan
    from .refutation_source import SourceIdentity

    if type(result) is ObservationUnavailable:
        if type(result.reason) is not str or not 1 <= len(result.reason) <= 128:
            raise ValueError("unbounded refusal")
        return {"reason": result.reason}
    if type(result) is not MemberCopyObservation:
        raise TypeError("typed source observation required")
    if (result.authority is not False or result.source_verified is not False
            or type(result.status) is not str or result.status != "source_bound_conditional_observation"
            or type(result.contract) is not str or result.contract != CONTRACT):
        raise ValueError("conditional observation required")
    if (type(result.source_units) is not tuple or len(result.source_units) != 3
            or type(result.spans) is not tuple or len(result.spans) != 13
            or type(result.unresolved) is not tuple or len(result.unresolved) != len(REQUIRED_LIMITS)
            or any(type(label) is not str or len(label) > 128 for label in result.unresolved)
            or result.unresolved != REQUIRED_LIMITS):
        raise ValueError("bounded immutable fields required")
    units = []
    for unit in result.source_units:
        if type(unit) is not tuple or len(unit) != 2 or type(unit[0]) is not str:
            raise ValueError("invalid source unit")
        name, identity = unit
        if type(identity) is not SourceIdentity or type(identity.version) is not tuple:
            raise ValueError("source identity required")
        if len(identity.version) != 5 or not _hex(identity.sha256, 64):
            raise ValueError("invalid source identity")
        if any(type(v) is not int or not -(1 << 127) < v < 1 << 127 for v in identity.version):
            raise ValueError("invalid version")
        units.append([name, {"sha256": identity.sha256, "version": list(identity.version)}])
    spans = []
    for span in result.spans:
        if type(span) is not SyntaxSpan:
            raise ValueError("typed span required")
        if (type(span.role) is not str or len(span.role) > 64
                or type(span.file) is not str or len(span.file) > 64
                or type(span.start_byte) is not int or type(span.end_byte) is not int
                or not _hex(span.sha256, 64)):
            raise ValueError("invalid span fields")
        spans.append({"role": span.role, "file": span.file, "start_byte": span.start_byte,
                      "end_byte": span.end_byte, "sha256": span.sha256})
    if (type(result.member_type_spellings) is not tuple or len(result.member_type_spellings) != 2
            or type(result.argument_roles) is not tuple or len(result.argument_roles) != 3
            or type(result.class_admission) is not str or len(result.class_admission) > 128
            or any(type(value) is not str or len(value) > 64
                   for value in (*result.member_type_spellings, *result.argument_roles))
            or (result.declared_cwe is not None
                and (type(result.declared_cwe) is not str or len(result.declared_cwe) > 128))):
        raise ValueError("invalid descriptor fields")
    reference = result.claim_reference
    if reference is not None and (type(reference) is not tuple or len(reference) != 2
                                  or any(not _hex(v, 32) for v in reference)):
        raise ValueError("invalid declared reference")
    # Build only known built-in leaves; do not asdict/deepcopy arbitrary objects.
    row = {"source_units": units, "spans": spans,
           "member_type_spellings": list(result.member_type_spellings),
           "argument_roles": list(result.argument_roles), "declared_cwe": result.declared_cwe,
           "class_admission": result.class_admission,
           "claim_reference": list(reference) if reference is not None else None,
           "status": result.status, "contract": result.contract,
           "authority": False, "source_verified": False, "unresolved": list(REQUIRED_LIMITS)}
    if not _saved_shape(row):
        raise ValueError("unsupported source observation shape")
    return row


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def write_source_syntax_observation(out_dir: Path, result) -> None:
    """Publish once beneath an existing operator-owned root; never infer a target root."""
    record = {"schema_version": 1, "role": "saved_conditional_source_syntax",
              "authority": False, "source_verified": False, "history_complete": False,
              "contract": CONTRACT, "record": _project_typed(result)}
    raw = json.dumps(record, allow_nan=False, sort_keys=True).encode("utf-8")
    if len(raw) > 32768:
        raise ValueError("sidecar byte budget")
    write_bytes_atomically(out_dir / FILENAME, raw, root=out_dir, replace=False, mode=0o600)


def load_saved_source_syntax(out_dir: Path) -> dict | None:
    unavailable = {"mode": "unavailable", "authority": False, "source_verified": False}
    try:
        path = out_dir / FILENAME
        if not path.exists() and not path.is_symlink():
            return None
        stream = open_regular_beneath(out_dir, FILENAME, "rb")
        if stream is None:
            return unavailable
        with stream:
            raw = stream.read(32769)
        data = loads(raw, max_bytes=32768, object_pairs_hook=_unique)
        if (type(data) is not dict or set(data) != {"schema_version", "role", "authority", "source_verified",
                                                  "history_complete", "contract", "record"}
                or type(data.get("schema_version")) is not int
                or data["schema_version"] != 1 or data.get("contract") != CONTRACT
                or data.get("role") != "saved_conditional_source_syntax"
                or data.get("authority") is not False or data.get("source_verified") is not False
                or data.get("history_complete") is not False):
            return unavailable
        row = data.get("record")
        if type(row) is not dict:
            return unavailable
        if set(row) == {"reason"}:
            if type(row["reason"]) is not str or not 1 <= len(row["reason"]) <= 128:
                return unavailable
            return {**unavailable, "saved_refusal": True}
        if (row.get("authority") is not False or row.get("source_verified") is not False
                or row.get("status") != "source_bound_conditional_observation"
                or row.get("contract") != CONTRACT):
            return unavailable
        if not _saved_shape(row):
            return unavailable
        return {"mode": "saved", "authority": False, "source_verified": False,
                "producer_authenticated": False, "source_freshness": "unavailable",
                "history_complete": False,
                "recorded_files": 3, "recorded_spans": 13,
                "unresolved": list(REQUIRED_LIMITS),
                "meaning": "saved conditional syntax only; not evidence or assurance"}
    except Exception:  # Optional saved data must not replace the audit; cancellation propagates.
        return unavailable


def source_syntax_blocks(report: dict) -> list[Block]:
    """Render only fixed descriptive labels; saved fields grant no authority."""
    saved = report.get("source_syntax_observations")
    if saved is None:
        return []
    unavailable = [Block("paragraph", title="Saved source syntax unavailable", text=(
        "No consistent saved source-syntax projection is available. This does not establish "
        "that no analysis ran, that no defect exists, or that coverage is complete."))]
    if (type(saved) is not dict or saved.get("mode") != "saved"
            or saved.get("authority") is not False or saved.get("source_verified") is not False
            or saved.get("producer_authenticated") is not False
            or saved.get("source_freshness") != "unavailable"
            or saved.get("history_complete") is not False
            or type(saved.get("recorded_files")) is not int or saved["recorded_files"] != 3
            or type(saved.get("recorded_spans")) is not int or saved["recorded_spans"] != 13
            or saved.get("unresolved") != list(REQUIRED_LIMITS)):
        return unavailable
    return [Block("section", title="Saved conditional source syntax", children=[
        Block("paragraph", text=(
            "A saved projection describes three source files and thirteen syntax spans. "
            "The recorded member type spellings are uint32_t and uint16_t. "
            "This is conditional syntax data, not a verified defect, refutation, "
            "authenticated producer record, or proof of current source freshness. "
            "It does not change findings, verdicts, checker counts, or coverage.")),
        Block("table", columns=["Unresolved premise"], rows=[[label] for label in (
            "Preprocessing and system headers", "Fixed-width type definitions",
            "ABI, size_t and header layout", "Allocator and copy-function bindings",
            "External object validity and aliasing", "Successful allocation",
            "A coherent build snapshot", "Claim-mechanism verification",
        )]),
    ])]
