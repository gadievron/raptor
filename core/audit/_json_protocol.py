"""Bounded data-only transport for the two audited SMT worker entries."""
import json
import math

MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_REPLY_BYTES = 1024 * 1024
ALLOWED_ENTRIES = frozenset({
    'core.audit.condition_smt:_z3_dispatch_json',
    'core.audit.sweep:_run_smt_verb_inner_json',
})


def _check_tree(value):
    pending = [(value, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if depth > 32 or count > 100000:
            raise ValueError('JSON tree exceeds complexity budget')
        kind = type(node)
        if node is None or kind in (bool, int):
            continue
        if kind is float and math.isfinite(node):
            continue
        if kind is str and len(node) <= MAX_REQUEST_BYTES:
            continue
        if kind in (list, tuple):
            if len(node) > 100000:
                raise ValueError('JSON array exceeds budget')
            pending.extend((item, depth + 1) for item in node)
        elif kind is dict:
            if len(node) > 100000 or any(type(key) is not str for key in node):
                raise ValueError('invalid JSON object')
            pending.extend((item, depth + 1) for pair in node.items() for item in pair)
        else:
            raise ValueError('non-JSON value')


def encode(value, limit):
    _check_tree(value)
    payload = json.dumps(value, allow_nan=False, ensure_ascii=True).encode('ascii')
    if len(payload) > limit:
        raise ValueError('JSON record exceeds byte budget')
    return payload


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _nonfinite(value):
    raise ValueError('nonfinite JSON number')


def decode(payload, limit):
    if not isinstance(payload, bytes) or len(payload) > limit:
        raise ValueError('JSON record exceeds byte budget')
    value = json.loads(payload.decode('utf-8'), object_pairs_hook=_unique, parse_constant=_nonfinite)  # json-budget: byte length checked above; nesting/node budget checked below.
    _check_tree(value)
    return value
