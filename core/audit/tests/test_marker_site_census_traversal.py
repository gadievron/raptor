"""Marker census traversal and collection building preserve their full scope."""
from __future__ import annotations

import ast

import pytest

from core.audit.tests import _marker_sites as scanner
from core.audit.tests import _review_keys


@pytest.mark.parametrize("source", [
    'def run(body):\n    return "[a:" in transform(nested(body))\n',
    '@decorate(option=initial())\nclass Outer(base()):\n'
    '    async def run(self, value: hint() = default()):\n'
    '        async for item in source():\n            check(item)\n',
    'values = [render(item) for item in source() if item.startswith("[a:")]\n'
    'mapping = {key(): value() for item in values}\n'
    'items = {render(item) for item in values}\n',
    'MARKS: tuple[str, ...] = ("[a:", "[b:")\n'
    'for marker in MARKS:\n    outcome = marker in body\n'
    'value = f"{render(item):{width()}}"\n',
])
def test_candidate_buckets_match_stdlib_order_and_identity(source):
    tree = ast.parse(source)
    before = ast.dump(tree, include_attributes=True)
    nodes = list(ast.walk(tree))
    expected = (
        [node for node in nodes if isinstance(node, (ast.Assign, ast.AnnAssign))],
        [node for node in nodes if isinstance(node, (ast.For, ast.AsyncFor, ast.ListComp,
                                                   ast.SetComp, ast.GeneratorExp, ast.DictComp))],
        [node for node in nodes if isinstance(node, (ast.Compare, ast.Call))],
    )
    actual = scanner._candidate_nodes(tree)
    assert tuple([id(node) for node in bucket] for bucket in actual) == tuple(
        [id(node) for node in bucket] for bucket in expected)
    assert ast.dump(tree, include_attributes=True) == before


@pytest.mark.parametrize("kind", ["tuple", "list", "set", "dict"])
def test_collection_building_does_not_repeatedly_copy_accumulated_prefixes(kind):
    copied = 0

    class TrackedTuple(tuple):
        def __radd__(self, prefix):
            nonlocal copied
            copied += len(prefix)
            return tuple(prefix) + tuple(self)

    count = 128
    if kind == "dict":
        source = "{" + ",".join(f"'key{i}': piece" for i in range(count)) + "}"
        expected = tuple(value for i in range(count) for value in (f"key{i}", "[a:"))
    else:
        left, right = {"tuple": ("(", ")"), "list": ("[", "]"), "set": ("{", "}")}[kind]
        source = left + ",".join(["piece"] * count) + right
        expected = ("[a:",) * count
    node = ast.parse(source, mode="eval").body
    assert scanner._collection(node, {"piece": TrackedTuple(("[a:",))}) == expected
    # The old repeated tuple concatenation copies 8,128 prefix elements for
    # 128 sequence values. Permit linear work, independent of elapsed time.
    assert copied <= 2 * count, copied


def test_nested_collections_keep_order_duplicates_and_borrowed_values():
    part = ("[a:", "opaque", "[a:")
    extra = ("extra",)
    env = {"PART": part, "EXTRA": extra}
    node = ast.parse("{'key': [PART, ('[b:',)], **EXTRA}", mode="eval").body
    before = ast.dump(node, include_attributes=True)
    assert scanner._collection(node, env) == ("key", "[a:", "opaque", "[a:", "[b:", "extra")
    assert scanner._collection(ast.parse("PART", mode="eval").body, env) is part
    assert scanner._collection(ast.parse("constants.PART", mode="eval").body, env) is part
    assert env == {"PART": part, "EXTRA": extra}
    assert env["PART"] is part and env["EXTRA"] is extra
    assert ast.dump(node, include_attributes=True) == before


@pytest.mark.parametrize("normalised", [False, True])
def test_cross_file_constants_and_loop_consumers_keep_exact_sites(normalised):
    target = "body.casefold()" if normalised else "body"
    sources = {
        "a.py": 'MARKS: tuple[str, ...] = ("[a:", "[b:")\n'
                'def f(body):\n'
                f'    return any(marker in {target} for marker in MARKS)\n',
        "b.py": 'from a import MARKS\n'
                'def f(body):\n'
                '    for prefix in MARKS:\n'
                f'        if {target}.startswith(prefix): return True\n',
    }
    expected = [(rel, line, kind, marker)
                for rel, line, kind in (("a.py", 3, "in"), ("b.py", 4, "startswith"))
                for marker in ("[a:", "[b:")]
    sites, normed = scanner.scan(sources)
    assert sites == expected
    assert normed == (expected if normalised else [])


def test_shared_parse_cache_keeps_complete_trees_for_review_key_census(tmp_path):
    rel = "core/audit/example.py"
    source = 'def run(outcome, body):\n    outcome.review_result = {"flag": True}\n    return "[a:" in body\n'
    path = tmp_path / rel
    path.parent.mkdir(parents=True)
    path.write_text(source, encoding="utf-8")
    trees = {}
    sites, normed = scanner.scan({rel: source, "invalid.py": "def ("}, parsed_trees=trees)
    assert sites == [(rel, 3, "in", "[a:")]
    assert not normed
    assert set(trees) == {rel}
    assert ast.dump(trees[rel], include_attributes=True) == ast.dump(
        ast.parse(source), include_attributes=True)
    cached = _review_keys.scan_full(tmp_path, parsed_trees=trees)
    assert cached == _review_keys.scan_full(tmp_path)
    assert cached[1] == {("flag", rel, 2)}


def test_loop_bindings_shadow_constants_without_mutating_or_leaking_them():
    from collections import ChainMap

    global_value, local_value = ("[global:",), ("[local:",)
    global_constants = {"PART": global_value}
    local_constants = {"PART": local_value}
    env = ChainMap(local_constants, global_constants)
    nodes = list(ast.walk(ast.parse("for PART in ('[loop:',):\n    pass\nfor name in PART:\n    pass\n")))
    first = scanner._loop_env(nodes, env)
    second = scanner._loop_env(nodes, env)
    assert first["PART"] == first["name"] == ("[loop:",)
    first["name"] = ("changed",)
    assert second["name"] == ("[loop:",)
    assert global_constants == {"PART": global_value}
    assert local_constants == {"PART": local_value}
    assert global_constants["PART"] is global_value
    assert local_constants["PART"] is local_value


@pytest.mark.parametrize("failure", [RuntimeError, KeyboardInterrupt])
def test_failed_loop_binding_preserves_borrowed_constants(monkeypatch, failure):
    constants = {"PART": ("[a:",)}
    borrowed_value = constants["PART"]
    collect = scanner._collection
    nodes = list(ast.walk(ast.parse("for marker in PART:\n    pass\nfor later in unavailable():\n    pass\n")))

    def interrupted(node, env):
        if isinstance(node, ast.Call):
            raise failure("binding interrupted")
        return collect(node, env)

    monkeypatch.setattr(scanner, "_collection", interrupted)
    with pytest.raises(failure, match="binding interrupted"):
        scanner._loop_env(nodes, constants)
    assert constants == {"PART": borrowed_value}
    assert constants["PART"] is borrowed_value


@pytest.mark.parametrize("global_value", ["ordinary", "[global:"])
def test_local_constants_override_first_global_binding_only_locally(global_value):
    sources = {
        "first.py": f"TAG = {global_value!r}\n",
        "local.py": 'TAG = "[local:"\ndef f(body):\n    return TAG in body\n',
        "external.py": 'def f(body):\n    return TAG in body\n',
    }
    expected = [("local.py", 3, "in", "[local:")]
    if global_value.startswith("["):
        expected.append(("external.py", 2, "in", global_value))
    assert scanner.scan(sources) == (sorted(expected), [])


def test_loop_aliases_do_not_escape_their_source_file():
    sources = {
        "constants.py": 'MARKS = ("[a:",)\n',
        "loop.py": 'def f(body):\n    for marker in MARKS:\n        return marker in body\n',
        "other.py": 'def f(body):\n    return marker in body\n',
    }
    assert scanner.scan(sources) == ([("loop.py", 3, "in", "[a:")], [])
