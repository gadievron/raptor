"""Parser-only source observations retain their unresolved authority boundary."""
import hashlib

import pytest

from core.audit import member_copy_observation as observation
from core.audit.claims import ClaimRevision
from core.inventory._ts_cache import ParseBudgetExceeded

FIXTURES = {'protocol/parser.c': '#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>\n\n#include "message.h"\n\nstruct raw_header {\n    uint32_t magic;\n    uint32_t length;\n    uint32_t type;\n};\n\nstruct parsed_msg {\n    uint16_t length;\n    uint16_t type;\n    uint8_t *payload;\n};\n\n/*\n * Parse a message header from the wire format.\n *\n * Reads the raw 32-bit fields and populates the parsed structure.\n * The caller is responsible for freeing the allocated payload.\n */\nint parse_header(const uint8_t *wire, size_t wire_len,\n                 struct parsed_msg *out)\n{\n    struct raw_header hdr;\n\n    if (wire_len < sizeof(hdr))\n        return -1;\n\n    memcpy(&hdr, wire, sizeof(hdr));\n\n    if (hdr.magic != 0x52415054)\n        return -1;\n\n    out->length = hdr.length;   /* uint32_t -> uint16_t */\n    out->type = hdr.type;\n\n    if (wire_len < sizeof(hdr) + hdr.length)\n        return -1;\n\n    out->payload = alloc_message(out->length,\n                                 wire + sizeof(hdr), hdr.length);\n    if (!out->payload)\n        return -1;\n\n    return 0;\n}\n', 'protocol/message.c': '#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>\n\n#include "message.h"\n\n/*\n * Allocate a message buffer and copy payload data into it.\n *\n * alloc_len: the number of bytes to allocate.\n * src:       pointer to the source data.\n * copy_len:  the number of bytes to copy from src.\n *\n * Returns a heap-allocated buffer, or NULL on allocation failure.\n * The caller must free the returned pointer.\n */\nuint8_t *alloc_message(uint16_t alloc_len,\n                       const uint8_t *src, uint32_t copy_len)\n{\n    uint8_t *buf;\n\n    if (alloc_len == 0)\n        return NULL;\n\n    buf = malloc(alloc_len);\n    if (!buf)\n        return NULL;\n\n    memcpy(buf, src, copy_len);\n\n    return buf;\n}\n', 'protocol/message.h': '#ifndef MESSAGE_H\n#define MESSAGE_H\n\n#include <stdint.h>\n#include <stdlib.h>\n\nuint8_t *alloc_message(uint16_t alloc_len,\n                       const uint8_t *src, uint32_t copy_len);\n\n#endif\n'}
FIXTURE_SHA256 = {'protocol/parser.c': '9423b58ca76c30183b01ead1b8a91f2a4ad4cd8a2451b12beb0d4e49d003a4ba', 'protocol/message.c': 'e8494aac6f9816090e9eebc6de4522caa3e32b35c045089e923f302a5e2a99a7', 'protocol/message.h': 'f8ef844fdd239f179656fd723e30075bd291c46927d8768d4022b0b84b89f38b'}
@pytest.fixture
def source_tree(tmp_path):
    for file, source in FIXTURES.items():
        path = tmp_path / file
        path.parent.mkdir(exist_ok=True)
        path.write_text(source)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == FIXTURE_SHA256[file]
    return tmp_path


def test_retained_three_file_shape_is_conditional(source_tree):
    result = observation.observe_member_copy(source_tree)
    assert isinstance(result, observation.MemberCopyObservation), result
    assert result.member_type_spellings == ("uint32_t", "uint16_t")
    assert not result.authority and not result.source_verified
    assert result.status == "source_bound_conditional_observation"
    assert result.declared_cwe is None and result.claim_reference is None
    assert result.class_admission == "unavailable:no-pipeline-revision"
    assert "ABI-size_t-and-header-layout" in result.unresolved
    assert "malloc-and-memcpy-library-bindings" in result.unresolved
    for file, identity in result.source_units:
        assert identity.sha256 == FIXTURE_SHA256[file]
    assert {span.role for span in result.spans} >= {"member_assignment", "direct_call", "allocation", "copy"}
    for span in result.spans:
        raw = (source_tree / span.file).read_bytes()
        assert hashlib.sha256(raw[span.start_byte:span.end_byte]).hexdigest() == span.sha256


@pytest.mark.parametrize("file,old,new", [
    ("parser.c", "struct raw_header hdr;", "struct Other hdr;"),
    ("parser.c", "uint32_t length;", "uint16_t length;"),
    ("parser.c", "uint16_t length;", "uint32_t length;"),
    ("parser.c", "alloc_message(out->length,", "alloc_message(hdr.length,"),
    ("parser.c", "wire + sizeof(hdr), hdr.length", "wire + sizeof(hdr), out->length"),
    ("message.c", "memcpy(buf, src, copy_len)", "memcpy(buf, src, alloc_len)"),
    ("parser.c", "if (wire_len < sizeof(hdr) + hdr.length)", "if (wire_len > sizeof(hdr) + hdr.length)"),
    ("parser.c", "out->type = hdr.type;", "out->type = hdr.type; out->length = hdr.type;"),
    ("parser.c", "out->type = hdr.type;", "out->type = hdr.type; escape(&out->length);"),
    ("parser.c", "alloc_message(out->length,", "(*alloc_message)(out->length,"),
    ("message.h", "uint16_t alloc_len", "uint32_t alloc_len"),
    ("message.c", "if (!buf)", "if (buf)"),
    ("message.c", "return buf;", "return src;"),
    ("message.c", "buf = malloc(alloc_len);", "buf = calloc(1, alloc_len);"),
    ("message.c", "memcpy(buf, src, copy_len);", "alias = buf; memcpy(alias, src, copy_len);"),
    ("parser.c", "struct raw_header {", "union raw_header {"),
    ("parser.c", "uint16_t length;", "uint16_t length : 8;"),
    ("parser.c", "uint16_t length;", "volatile uint16_t length;"),
    ("parser.c", "#include <stdint.h>", "#include \"other.h\""),
    ("message.h", "#endif", "#else\nint other;\n#endif"),
    ("parser.c", "return 0;", "return 0"),
], ids=["wrong-record-owner", "wide-width", "narrow-width", "allocation-arg", "copy-arg",
        "callee-copy-count", "bounds-guard", "overwrite", "escaping-helper", "indirect-call",
        "prototype", "allocation-success-guard", "returned-alias", "alternate-allocator",
        "buffer-alias", "union", "bitfield", "volatile", "alternate-include", "conditional-header",
        "parser-error"])
def test_changed_or_ambiguous_premises_refuse(source_tree, file, old, new):
    path = source_tree / "protocol" / file
    source = path.read_text()
    assert old in source
    path.write_text(source.replace(old, new, 1))
    assert isinstance(observation.observe_member_copy(source_tree), observation.ObservationUnavailable)


def test_duplicate_callee_definition_refuses(source_tree):
    path = source_tree / "protocol/message.c"
    path.write_text(path.read_text() + "\nuint8_t *alloc_message(uint16_t x,const uint8_t*y,uint32_t z){return 0;}\n")
    assert isinstance(observation.observe_member_copy(source_tree), observation.ObservationUnavailable)


def test_macro_ambiguity_refuses(source_tree):
    path = source_tree / "protocol/parser.c"
    path.write_text("#define malloc custom_alloc\n" + path.read_text())
    assert isinstance(observation.observe_member_copy(source_tree), observation.ObservationUnavailable)


def test_shared_field_name_in_another_record_cannot_donate_type(source_tree):
    path = source_tree / "protocol/parser.c"
    path.write_text(path.read_text().replace("struct raw_header hdr;", "struct Other hdr;")
                    .replace("struct raw_header {", "struct Other {"))
    assert isinstance(observation.observe_member_copy(source_tree), observation.ObservationUnavailable)


def test_duplicate_prototype_refuses(source_tree):
    path = source_tree / "protocol/message.h"
    path.write_text(path.read_text().replace("#endif", "uint8_t *alloc_message(uint16_t a,const uint8_t*b,uint32_t c);\n#endif"))
    assert isinstance(observation.observe_member_copy(source_tree), observation.ObservationUnavailable)


def test_guard_moved_after_copy_refuses(source_tree):
    path = source_tree / "protocol/message.c"
    source = path.read_text()
    guard = "    if (!buf)\n        return NULL;\n"
    assert guard in source
    path.write_text(source.replace(guard, "").replace("    return buf;", guard + "    return buf;"))
    assert isinstance(observation.observe_member_copy(source_tree), observation.ObservationUnavailable)


@pytest.mark.parametrize("budget", [{"max_file_bytes": True}, {"max_nodes": 0}, {"max_depth": 65}])
def test_invalid_or_expanded_budget_refuses(source_tree, budget):
    assert isinstance(observation.observe_member_copy(source_tree, **budget), observation.ObservationUnavailable)


def test_byte_budget_refuses_before_parser(source_tree, monkeypatch):
    def forbidden(_language):
        pytest.fail("byte-budget refusal must precede parser acquisition")
    monkeypatch.setattr(observation, "_ts_parser_for", forbidden)
    assert observation.observe_member_copy(source_tree, max_file_bytes=32).reason == "source-byte-budget"


def test_node_and_depth_budget_refuse(source_tree):
    assert observation.observe_member_copy(source_tree, max_nodes=1).reason == "parser-node-or-depth-budget"
    assert observation.observe_member_copy(source_tree, max_depth=1).reason == "parser-node-or-depth-budget"


def test_disabled_wall_budget_refuses_before_parser(source_tree, monkeypatch):
    monkeypatch.setattr(observation, "parse_budget_s", lambda: 0)
    monkeypatch.setattr(observation, "_ts_parser_for", lambda _: pytest.fail("disabled wall budget"))
    assert observation.observe_member_copy(source_tree).reason == "parser-wall-budget-unavailable"


def test_missing_parser_refuses(source_tree, monkeypatch):
    monkeypatch.setattr(observation, "_ts_parser_for", lambda _: None)
    assert observation.observe_member_copy(source_tree).reason == "parser-unavailable"


def test_parser_budget_exception_refuses(source_tree, monkeypatch):
    class Exhausted:
        timeout_micros = 1
        def parse(self, _raw):
            raise ParseBudgetExceeded("owned boundary")
    monkeypatch.setattr(observation, "_ts_parser_for", lambda _: Exhausted())
    assert observation.observe_member_copy(source_tree).reason == "parser-wall-budget"


def test_missing_native_budget_capability_refuses_before_parse(source_tree, monkeypatch):
    class Unbounded:
        def parse(self, _raw):
            pytest.fail("native parser budget is required")
    monkeypatch.setattr(observation, "_ts_parser_for", lambda _: Unbounded())
    assert observation.observe_member_copy(source_tree).reason == "parser-native-budget-unavailable"


def test_source_change_during_parse_invalidates_observation(source_tree, monkeypatch):
    parser = observation._ts_parser_for("c")
    assert parser is not None
    class Mutating:
        timeout_micros = parser.timeout_micros
        calls = 0
        def parse(self, raw):
            tree = parser.parse(raw)
            self.calls += 1
            if self.calls == 3:
                path = source_tree / "protocol/parser.c"
                path.write_text(path.read_text() + "\n")
            return tree
    monkeypatch.setattr(observation, "_ts_parser_for", lambda _: Mutating())
    assert observation.observe_member_copy(source_tree).reason == "source-changed"


def test_anchored_symlink_source_refuses(source_tree):
    path = source_tree / "protocol/parser.c"
    other = source_tree / "protocol/other.c"
    path.rename(other)
    path.symlink_to(other.name)
    assert isinstance(observation.observe_member_copy(source_tree), observation.ObservationUnavailable)


def revision(cwe="CWE-190", *, line=25, kind="unsigned-member-narrow-alloc-wide-copy-v1"):
    return ClaimRevision({"mechanism": "owned declared claim", "cwe": cwe, "mechanism_kind": kind},
                         pass_id="owned-test", file="protocol/parser.c", function="parse_header", line_start=line)


def test_explicit_revision_is_declared_occurrence_only(source_tree):
    claim = revision()
    result = observation.observe_member_copy(source_tree, claim_revision=claim)
    assert isinstance(result, observation.MemberCopyObservation)
    assert result.claim_reference == (claim.claim_id, claim.revision_id)
    assert result.declared_cwe == "CWE-190"
    assert result.class_admission == "declared-occurrence-only:not-mechanism-verification"
    assert not result.authority and not result.source_verified


@pytest.mark.parametrize("claim", [
    revision("CWE-190: Overflow; CWE-680: Buffer Overflow"),
    revision(["CWE-190", "CWE-680"]), revision(line=26), revision(kind=""),
    {"claim_id": "model-forged", "cwe": "CWE-190"},
], ids=["multi-id", "malformed-class", "other-occurrence", "missing-mechanism", "raw-dict"])
def test_ambiguous_or_unissued_claim_cannot_supply_class(source_tree, claim):
    result = observation.observe_member_copy(source_tree, claim_revision=claim)
    assert isinstance(result, observation.MemberCopyObservation)
    assert result.class_admission.startswith("unavailable:")
    assert result.declared_cwe is None and result.claim_reference is None
    assert not result.authority and not result.source_verified


def test_conditional_integer_model_is_separate_from_source_observation():
    result = observation.conditional_unsigned_copy_size(wide_bits=32, narrow_bits=16, count=65537)
    assert result.status == "conditional_size_mismatch"
    assert (result.allocated, result.copied) == (1, 65537)
    assert not result.authority and not result.source_verified
    assert observation.conditional_unsigned_copy_size(wide_bits=32, narrow_bits=16, count=65536).status.startswith("not_reached")
    assert observation.conditional_unsigned_copy_size(wide_bits=32, narrow_bits=16, count=8).status == "no_model_mismatch"


@pytest.mark.parametrize("values", [(True, 16, 1), (16, 32, 1), (65, 16, 1), (32, 16, -1), (32, 16, 1 << 32)])
def test_conditional_integer_model_refuses_unknown_inputs(values):
    wide, narrow, count = values
    assert observation.conditional_unsigned_copy_size(wide_bits=wide, narrow_bits=narrow, count=count).status == "unavailable"
