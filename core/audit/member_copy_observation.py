"""Bounded C member/alloc/copy syntax observations, without verdict authority.

The initial contract admits only the closed three-file protocol shape below.
Observed type spellings and calls are not resolved headers, ABI, libc bindings,
object validity, alias closure or an executed defect. No audit gate consumes
these observations as confirmation, refutation or claim-history equivalence.
"""
from dataclasses import dataclass, field
import hashlib

from core.source import open_regular_beneath
from core.inventory.extractors import _ts_parser_for
from core.inventory._ts_cache import ParseBudgetExceeded, parse_budget_s

from .claims import ClaimRevision
from .refutation_source import SourceIdentity, capture_source_identity

_FILES = ("protocol/parser.c", "protocol/message.c", "protocol/message.h")
_MECHANISM = "unsigned-member-narrow-alloc-wide-copy-v1"
_UNRESOLVED = (
    "preprocessing-and-system-header-bindings", "fixed-width-typedef-semantics",
    "ABI-size_t-and-header-layout", "malloc-and-memcpy-library-bindings",
    "external-object-validity-and-aliasing", "allocation-success",
    "atomic-multi-file-build-snapshot", "claim-mechanism-verification",
)


@dataclass(frozen=True)
class ObservationUnavailable:
    reason: str


@dataclass(frozen=True)
class SyntaxSpan:
    role: str
    file: str
    start_byte: int
    end_byte: int
    sha256: str


@dataclass(frozen=True)
class MemberCopyObservation:
    source_units: tuple[tuple[str, SourceIdentity], ...]
    spans: tuple[SyntaxSpan, ...]
    member_type_spellings: tuple[str, str]
    argument_roles: tuple[str, ...]
    declared_cwe: str | None
    class_admission: str
    claim_reference: tuple[str, str] | None
    status: str = field(default="source_bound_conditional_observation", init=False)
    contract: str = field(default=_MECHANISM, init=False)
    authority: bool = field(default=False, init=False)
    source_verified: bool = field(default=False, init=False)
    unresolved: tuple[str, ...] = field(default=_UNRESOLVED, init=False)


class _Refuse(ValueError):
    pass


def _text(node, raw):
    return raw[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""


def _tokens(node, raw):
    tokens = []
    stack = [node]
    while stack:
        item = stack.pop()
        if item.type == "comment":
            continue
        if item.children:
            stack.extend(reversed(item.children))
        else:
            text = _text(item, raw)
            if text and not text.isspace():
                tokens.append(text)
    return tokens


def _expect(node, raw, tokens, reason):
    if node is None or _tokens(node, raw) != tokens.split():
        raise _Refuse(reason)


def _named(node):
    return [child for child in node.named_children if child.type != "comment"]


def _check_tree(root, max_nodes, max_depth):
    if root.has_error:
        raise _Refuse("parser-error")
    stack = [(root, 0)]
    count = 0
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > max_nodes or depth > max_depth:
            raise _Refuse("parser-node-or-depth-budget")
        if node.is_missing or node.type == "ERROR":
            raise _Refuse("parser-error")
        stack.extend((child, depth + 1) for child in node.children)


def _include(node, raw, path):
    selected = node.child_by_field_name("path")
    if node.type != "preproc_include" or _text(selected, raw) != path:
        raise _Refuse("include-or-macro-ambiguity")
    # No trailing tokens or alternate preprocessor spelling admitted.
    if _tokens(node, raw) != ["#include", *_tokens(selected, raw)]:
        raise _Refuse("include-or-macro-ambiguity")


def _translation_units(trees, sources):
    caller, callee, header = (_named(tree.root_node) for tree in trees)
    if ([n.type for n in caller] != ["preproc_include"] * 4 + ["struct_specifier"] * 2
            + ["function_definition"]
            or [n.type for n in callee] != ["preproc_include"] * 4 + ["function_definition"]):
        raise _Refuse("translation-unit-shape-or-ambiguous-definition")
    for nodes, raw in ((caller, sources[0]), (callee, sources[1])):
        for node, path in zip(nodes[:4], ("<stdint.h>", "<stdlib.h>", "<string.h>", '"message.h"')):
            _include(node, raw, path)
    if len(header) != 1 or header[0].type != "preproc_ifdef":
        raise _Refuse("header-guard-or-macro-ambiguity")
    guard = header[0]
    if guard.children[0].type != "#ifndef" or guard.children[-1].type != "#endif":
        raise _Refuse("header-guard-or-macro-ambiguity")
    parts = _named(guard)
    if [n.type for n in parts] != ["identifier", "preproc_def", "preproc_include",
                                 "preproc_include", "declaration"]:
        raise _Refuse("header-guard-or-macro-ambiguity")
    _expect(parts[0], sources[2], "MESSAGE_H", "header-guard-or-macro-ambiguity")
    _expect(parts[1], sources[2], "#define MESSAGE_H", "header-guard-or-macro-ambiguity")
    _include(parts[2], sources[2], "<stdint.h>")
    _include(parts[3], sources[2], "<stdlib.h>")
    return caller[4], caller[5], caller[6], callee[4], parts[4]


def _observe_syntax(trees, sources):
    wide, narrow, caller, callee, prototype = _translation_units(trees, sources)
    _expect(wide, sources[0], "struct raw_header { uint32_t magic ; uint32_t length ; uint32_t type ; }",
            "record-owner-or-type-ambiguity")
    _expect(narrow, sources[0], "struct parsed_msg { uint16_t length ; uint16_t type ; uint8_t * payload ; }",
            "record-owner-or-type-ambiguity")
    _expect(caller.child_by_field_name("type"), sources[0], "int", "caller-type-mismatch")
    _expect(caller.child_by_field_name("declarator"), sources[0],
            "parse_header ( const uint8_t * wire , size_t wire_len , struct parsed_msg * out )",
            "caller-binding-mismatch")
    callee_decl = "* alloc_message ( uint16_t alloc_len , const uint8_t * src , uint32_t copy_len )"
    _expect(callee.child_by_field_name("type"), sources[1], "uint8_t", "callee-type-mismatch")
    _expect(callee.child_by_field_name("declarator"), sources[1], callee_decl,
            "callee-prototype-mismatch")
    _expect(prototype, sources[2], "uint8_t " + callee_decl + " ;", "callee-prototype-mismatch")
    cbody = caller.child_by_field_name("body")
    mbody = callee.child_by_field_name("body")
    statements = _named(cbody)
    if [n.type for n in statements] != ["declaration", "if_statement", "expression_statement",
                                        "if_statement", "expression_statement", "expression_statement",
                                        "if_statement", "expression_statement", "if_statement",
                                        "return_statement"]:
        raise _Refuse("caller-guard-or-mutation")
    magic = statements[3].child_by_field_name("condition")
    literals = []
    stack = [magic] if magic is not None else []
    while stack:
        node = stack.pop()
        if node.type == "number_literal":
            literals.append(_text(node, sources[0]))
        stack.extend(node.children)
    if len(literals) != 1:
        raise _Refuse("caller-guard-or-mutation")
    _expect(cbody, sources[0], """{
        struct raw_header hdr ;
        if ( wire_len < sizeof ( hdr ) ) return -1 ;
        memcpy ( & hdr , wire , sizeof ( hdr ) ) ;
        if ( hdr . magic != MAGIC ) return -1 ;
        out -> length = hdr . length ; out -> type = hdr . type ;
        if ( wire_len < sizeof ( hdr ) + hdr . length ) return -1 ;
        out -> payload = alloc_message ( out -> length , wire + sizeof ( hdr ) , hdr . length ) ;
        if ( ! out -> payload ) return -1 ; return 0 ; }
        """.replace("MAGIC", literals[0]), "caller-guard-arguments-or-mutation")
    if [n.type for n in _named(mbody)] != ["declaration", "if_statement", "expression_statement",
                                         "if_statement", "expression_statement", "return_statement"]:
        raise _Refuse("callee-guard-alias-or-mutation")
    _expect(mbody, sources[1], """{
        uint8_t * buf ; if ( alloc_len == 0 ) return NULL ;
        buf = malloc ( alloc_len ) ; if ( ! buf ) return NULL ;
        memcpy ( buf , src , copy_len ) ; return buf ; }
        """, "callee-guard-alias-or-mutation")
    return caller, (
        ("wide_record", _FILES[0], wide), ("narrow_record", _FILES[0], narrow),
        ("caller", _FILES[0], caller), ("callee", _FILES[1], callee),
        ("prototype", _FILES[2], prototype), ("member_assignment", _FILES[0], statements[4]),
        ("source_bounds_guard", _FILES[0], statements[6]), ("direct_call", _FILES[0], statements[7]),
        ("nonzero_alloc_guard", _FILES[1], _named(mbody)[1]),
        ("allocation", _FILES[1], _named(mbody)[2]),
        ("allocation_success_guard", _FILES[1], _named(mbody)[3]),
        ("copy", _FILES[1], _named(mbody)[4]), ("return", _FILES[1], _named(mbody)[5]),
    )


def _claim_selection(revision, line):
    if revision is None:
        return None, "unavailable:no-pipeline-revision", None
    if type(revision) is not ClaimRevision:
        return None, "unavailable:pipeline-revision-required", None
    material = revision.hypothesis
    text = material.get("mechanism")
    if not isinstance(text, str) or not revision.matches_occurrence(
            file=_FILES[0], function="parse_header", line_start=line, hypothesis=text):
        return None, "unavailable:claim-occurrence-mismatch", None
    cwe = material.get("cwe")
    if (type(cwe) is not str or cwe not in {"CWE-190", "CWE-195", "CWE-680"}
            or material.get("mechanism_kind") != _MECHANISM):
        return None, "unavailable:explicit-class-and-mechanism-required", None
    return cwe, "declared-occurrence-only:not-mechanism-verification", (revision.claim_id, revision.revision_id)


def observe_member_copy(root, *, claim_revision=None, max_file_bytes=32768,
                        max_nodes=4096, max_depth=64):
    """Observe only the admitted syntax shape under three anchored byte pins.

    Before/after identities detect changed source, not atomic multi-file/build
    capture. Parser wall budget is owned by the existing BoundedParser API;
    this function never changes its shared timeout or grants engine resources.
    """
    if any(type(value) is not int or value < 1 for value in (max_file_bytes, max_nodes, max_depth)):
        return ObservationUnavailable("invalid-budget")
    if max_file_bytes > 32768 or max_nodes > 4096 or max_depth > 64:
        return ObservationUnavailable("budget-outside-contract")
    captured = []
    for file in _FILES:
        identity = capture_source_identity(root, file)
        if identity is None:
            return ObservationUnavailable("source-unavailable")
        captured.append(identity)
    before = tuple(captured)
    try:
        sources = []
        for file, identity in zip(_FILES, before):
            stream = open_regular_beneath(root, file, "rb")
            if stream is None:
                raise _Refuse("anchored-source-unavailable")
            with stream:
                raw = stream.read(max_file_bytes + 1)
            if len(raw) > max_file_bytes:
                raise _Refuse("source-byte-budget")
            if hashlib.sha256(raw).hexdigest() != identity.sha256:
                raise _Refuse("source-changed")
            sources.append(raw)
        if parse_budget_s() <= 0:
            raise _Refuse("parser-wall-budget-unavailable")
        parser = _ts_parser_for("c")
        if parser is None:
            raise _Refuse("parser-unavailable")
        # BoundedParser forwards this read-only native capability. A configured
        # wall budget alone is insufficient on bindings lacking the native knob.
        timeout = getattr(parser, "timeout_micros", None)
        if type(timeout) is not int or timeout < 1:
            raise _Refuse("parser-native-budget-unavailable")
        trees = []
        for raw in sources:
            tree = parser.parse(raw)
            _check_tree(tree.root_node, max_nodes, max_depth)
            trees.append(tree)
        caller, selected = _observe_syntax(trees, sources)
        raw_by_file = dict(zip(_FILES, sources))
        spans = tuple(SyntaxSpan(role, file, node.start_byte, node.end_byte,
                                 hashlib.sha256(raw_by_file[file][node.start_byte:node.end_byte]).hexdigest())
                      for role, file, node in selected)
        cwe, admission, reference = _claim_selection(claim_revision, caller.start_point.row + 1)
        observation = MemberCopyObservation(tuple(zip(_FILES, before)), spans,
                                            ("uint32_t", "uint16_t"),
                                            ("narrow-member", "wire-plus-header", "wide-member"),
                                            cwe, admission, reference)
        if tuple(capture_source_identity(root, file) for file in _FILES) != before:
            raise _Refuse("source-changed")
        return observation
    except ParseBudgetExceeded:
        return ObservationUnavailable("parser-wall-budget")
    except _Refuse as error:
        return ObservationUnavailable(str(error))
    except (OSError, ValueError, RuntimeError):
        return ObservationUnavailable("source-or-parser-unavailable")


@dataclass(frozen=True)
class ConditionalCopySize:
    status: str
    allocated: int | None = None
    copied: int | None = None
    authority: bool = field(default=False, init=False)
    source_verified: bool = field(default=False, init=False)


def conditional_unsigned_copy_size(*, wide_bits, narrow_bits, count):
    """Separate finite model; no source observation or ABI premise is inferred."""
    if (any(type(value) is not int for value in (wide_bits, narrow_bits, count))
            or not 1 <= narrow_bits < wide_bits <= 64 or not 0 <= count < 1 << wide_bits):
        return ConditionalCopySize("unavailable")
    allocated = count % (1 << narrow_bits)
    if allocated == 0:
        return ConditionalCopySize("not_reached:nonzero-allocation-guard")
    return ConditionalCopySize("conditional_size_mismatch" if allocated < count else "no_model_mismatch",
                               allocated, count)
