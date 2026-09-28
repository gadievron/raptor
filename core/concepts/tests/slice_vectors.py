"""Deterministic (model, file, function, source) vectors for the
domain-slice fingerprint equivalence suite.

Kept importable standalone (no pytest machinery) so the same
definitions can mint golden hashes against any tree — that is how the
goldens in test_slice_memo.py were produced, and how they are
regenerated after an INTENTIONAL prompt-content change.
"""
from __future__ import annotations

from typing import Any

_SRC_MATCH = (
    "int frame_checksum_verify(struct frame *f, char *buf, size_t len)\n"
    "{\n"
    "    if (crc_before_use(buf, len) != f->crc)\n"
    "        return -EINVAL;\n"
    "    spin_lock(&f->lock);\n"
    "    memcpy(f->scratch, buf, len);\n"
    "    frame_ref_get(f);\n"
    "    spin_unlock(&f->lock);\n"
    "    return frame_layout_parse(f, buf, len);\n"
    "}\n"
)

_SRC_PLAIN = (
    "static int helper(int x)\n"
    "{\n"
    "    return x * 3 + 1;\n"
    "}\n"
)


def _model_full() -> dict[str, Any]:
    return {
        "version": "1",
        "security_context": {
            "privilege_level": "kernel",
            "attack_surface": "unprivileged userspace via sendmsg",
            "isolation": "none",
            "trust_summary": "socket input reaches frame parsers unchecked",
        },
        "concepts": [
            {
                "id": "frame_layout",
                "description": "frames carry a crc_before_use header that "
                               "frame_checksum_verify must validate",
                "confidence": "corroborated",
                "evidence": [
                    {"type": "code_path", "file": "net/frame.c",
                     "item": "frame_checksum_verify",
                     "observation": "crc check"},
                ],
            },
            {
                "id": "queue_index_bound",
                "description": "queue indices are masked before table access",
                "confidence": "inferred",
                "evidence": [{"file": "net/queue.c", "item": "queue_push"}],
            },
        ],
        "invariants": [
            {
                "id": "crc_before_use",
                "concept": "frame_layout",
                "statement": "crc_before_use must pass before memcpy into "
                             "f->scratch",
                "negation": "unchecked frames corrupt scratch state",
                "confidence": "tested",
                "provenance": "extracted",
            },
            {
                "id": "derived_ref_balance",
                "statement": "frame_ref_get requires a matching frame_ref_put "
                             "on every path",
                "negation": "refcount leak pins frames forever",
                "confidence": "inferred",
                "provenance": "llm_prior",
            },
        ],
        "contracts": [
            {
                "function": "frame_checksum_verify",
                "file": "net/frame.c",
                "when": "called from softirq context",
                "input_semantics": "buf holds >= 4 bytes",
                "output_semantics": "0 on valid crc, -EINVAL otherwise",
                "implication": "callers may trust f->scratch afterwards",
                "confidence": "documented",
            },
            {
                "function": "frame_checksum_verify",
                "file": "drivers/other/frame.c",
                "input_semantics": "WRONG-FILE contract, must never serve",
                "confidence": "inferred",
            },
            {
                "function": "queue_push",
                "file": "net/queue.c",
                "state": "stale",
                "input_semantics": "stale contract, must never serve",
            },
        ],
        "bug_patterns": [
            {
                "id": "bp_memcpy_unchecked",
                "description": "memcpy with attacker length before crc check",
                "what_to_grep": r"memcpy\s*\(",
            },
            {
                "id": "bp_unrelated",
                "description": "double fetch on mmap'd control page",
                "what_to_grep": "second_fetch_of",
            },
        ],
        "paired_operations": [
            {"acquire": "spin_lock", "release": "spin_unlock",
             "kind": "lock", "note": "softirq safe"},
            {"acquire": "frame_ref_get", "release": "frame_ref_put",
             "kind": "refcount"},
        ],
        "key_files": ["net/frame.c"],
    }


def _model_security_only() -> dict[str, Any]:
    return {
        "security_context": {
            "privilege_level": "root daemon",
            "attack_surface": "local socket",
        },
        "concepts": [],
        "invariants": [],
        "contracts": [],
    }


def _model_empty() -> dict[str, Any]:
    return {"concepts": [], "invariants": [], "contracts": []}


def _model_drifted() -> dict[str, Any]:
    return {
        "security_context": {"privilege_level": "kernel"},
        "concepts": [
            "bare-string concept (non-dict, skipped)",
            {"description": "concept with no id at all",
             "confidence": "inferred"},
            {
                "id": "frame_layout",
                "description": "frame_checksum_verify guards frame_layout",
                "invariants": [
                    "inline bare-string invariant about frame_checksum_verify",
                    {"statement": "inline dict invariant",
                     "confidence": "tested"},
                    42,
                ],
                "evidence": ["net/frame.c:12 string-shaped evidence"],
            },
        ],
        "invariants": "corrupted",
        "contracts": [
            {
                "function": "frame_checksum_verify",
                "input_semantics": "file-less contract serves with caution",
            },
        ],
        "bug_patterns": [
            {"description": "pattern with empty hint", "what_to_grep": ""},
            "non-dict bug pattern",
        ],
    }


def _model_hostile_hints() -> dict[str, Any]:
    return {
        "concepts": [],
        "invariants": [],
        "contracts": [],
        "bug_patterns": [
            {"id": "bp_bad_regex", "description": "unbalanced paren hint",
             "what_to_grep": "(frame_checksum"},
            {"id": "bp_redos", "description": "nested quantifier hint",
             "what_to_grep": "(a+)+$"},
            {"id": "bp_too_long", "description": "over-length hint",
             "what_to_grep": "frame_" + "x" * 300},
            {"id": "bp_case", "description": "case-insensitive hit",
             "what_to_grep": "MEMCPY"},
        ],
    }


def _model_unicode() -> dict[str, Any]:
    return {
        "security_context": {
            "privilege_level": "kernel",
            "attack_surface": "réseau — non-ASCII surface name",
        },
        "concepts": [
            {
                "id": "frame_layout",
                "description": "frame_checksum_verify: caractères accentués "
                               "éè☃ in prose",
                "confidence": "inferred",
                "evidence": [{"file": "net/frame.c",
                              "item": "frame_checksum_verify"}],
            },
        ],
        "invariants": [
            {"id": "inv_u", "concept": "frame_layout",
             "statement": "frame_checksum_verify normalises ☃ first"},
        ],
        "contracts": [],
        "paired_operations": [
            {"acquire": "spin_lock", "release": "spin_unlock",
             "kind": "lock"},
        ],
    }


#: vector id -> (model builder name, file_path, function_name, source)
VECTORS: dict[str, tuple[str, str, str, str]] = {
    "full-match": ("_model_full", "net/frame.c",
                   "frame_checksum_verify", _SRC_MATCH),
    "full-match-deep-path": ("_model_full", "src/linux/net/frame.c",
                             "frame_checksum_verify", _SRC_MATCH),
    "full-sym-prefixed": ("_model_full", "net/frame.c",
                          "sym.frame_checksum_verify", _SRC_MATCH),
    "full-unrelated-fn": ("_model_full", "lib/other.c",
                          "helper", _SRC_PLAIN),
    "full-no-source": ("_model_full", "net/frame.c",
                       "frame_checksum_verify", ""),
    "security-only": ("_model_security_only", "auth.c",
                      "check_pw", _SRC_PLAIN),
    "empty-selection": ("_model_empty", "auth.c", "check_pw", _SRC_PLAIN),
    "drifted-match": ("_model_drifted", "net/frame.c",
                      "frame_checksum_verify", _SRC_MATCH),
    "drifted-no-source": ("_model_drifted", "net/frame.c",
                          "frame_checksum_verify", ""),
    "hostile-hints": ("_model_hostile_hints", "net/frame.c",
                      "frame_checksum_verify", _SRC_MATCH),
    "hostile-hints-no-source": ("_model_hostile_hints", "net/frame.c",
                                "frame_checksum_verify", ""),
    "unicode-paired": ("_model_unicode", "net/frame.c",
                       "frame_checksum_verify", _SRC_MATCH),
}


def build_model(name: str) -> dict[str, Any]:
    return globals()[name]()
