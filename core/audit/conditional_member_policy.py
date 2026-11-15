"""UNAPPLIED candidate policy; primary-text checked, independent review pending.

These are conditions of a source-model implication, not admitted target facts.
No target edition, typedef, header, symbol binding or allocation is inferred.
"""
from enum import Enum

from .claim_support_contracts import ConclusionSignature

POLICY_ID = "c11-conditional-member-copy-effects"
POLICY_VERSION = "1"
PRIMARY = "https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf"
EDITION = "WG14 N1570 2011-04-12 (C11 committee draft)"
RULES = (
    ("unsigned-conversion", "6.3.1.3p1-2;6.5.16.1p2;6.5.2.2p7,9;6.5.2.3p3-4",
     "Assignment converts to the destination; unsigned conversion is modular."),
    ("exact-width-types", "7.20.1.1p2-3;7.20.2.1",
     "Provided uintN_t types have exact unsigned width; availability is optional."),
    ("symbolic-size", "6.5.3.4p2,4-5",
     "sizeof includes structure padding and yields size_t; its value is implementation-defined."),
    ("allocation-effect", "7.22.3p1;7.22.3.4p2-3",
     "Successful malloc supplies a disjoint object of the requested size; it may fail."),
    ("library-scope", "7.1.2p1,3-4;7.1.3p1-2;7.1.4p1",
     "Implementation header, macro and library applicability remain conditions."),
    ("copy-effect", "7.24.1p1-2;7.24.2.1p2",
     "memcpy uses its size_t count; overlap or access beyond the object is invalid."),
)


class Condition(Enum):
    C11 = "C11-ordinary-integer-semantics"
    UINT_TYPES = "standard-uint8_t-uint16_t-uint32_t-bindings"
    TRANSLATION = "captured-source-shape-not-altered-by-preprocessing"
    CALLEE = "direct-callee-resolves-to-captured-alloc_message"
    MALLOC = "malloc-has-reviewed-standard-object-size-effects"
    MEMCPY = "memcpy-has-reviewed-standard-count-effects"
    OBJECTS = "valid-live-readable-wire-and-writable-noninterfering-out"
    HEADER = "post-header-copy-magic-accepted-and-length-equals-65537"
    EXTENT = "wire-extent-and-wire_len-at-least-H-plus-65537"
    SIZE = "H-is-sizeof-hdr-positive-and-SIZE_MAX-at-least-H-plus-65537"
    SUCCESS = "malloc-one-byte-succeeds"
    DEFINED_PATH = "no-prior-undefined-behavior-or-concurrent-relevant-mutation"


STATEMENT = "Under the recorded conditions, unsigned member narrowing leads to a copy count exceeding the requested allocation size."
EFFECT_SCOPE = "conditional-source-model-pre-copy-size-relation"


def conclusion_signature(*, size_max_refinement=None):
    """Closed policy-owned condition kinds; no raw caller premise admission.

    A numeric refinement constrains this hypothetical model. It is NOT measured
    target ABI evidence. Unknown size remains the explicit symbolic condition.
    """
    if size_max_refinement is not None and (
            type(size_max_refinement) is not int or not 0 <= size_max_refinement < 1 << 128):
        raise ValueError("unsupported model size refinement")
    conditions = tuple(condition.value for condition in Condition)
    if size_max_refinement is not None:
        conditions += (f"model-only-SIZE_MAX:{size_max_refinement}",)
    return ConclusionSignature(STATEMENT, "conditional-size-mismatch", EFFECT_SCOPE, conditions)
