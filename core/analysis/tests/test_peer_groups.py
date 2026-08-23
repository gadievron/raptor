"""Tests for core.analysis.peer_groups — layered peer group resolver."""

import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import MagicMock

from core.analysis.peer_groups import (
    _binary_co_callee_groups,
    _dispatch_site_groups,
    _domain_model_groups,
    _filter_co_callees,
    _func_directory,
    _joern_co_callee_groups,
    _largest_compatible_subset,
    _paired_operation_groups,
    _parse_joern_peers,
    _signatures_compatible,
    _type_cohort_groups,
    _verb_prefix_groups,
    resolve_peer_groups,
)

# Anchor probe subprocesses to the SAME tree these tests run from,
# passed as argv[1] (the test_fork_safe_warn*.py idiom). A bare
# ``python -c "from core... import"`` child resolves imports through
# its cwd, which is not guaranteed to be this repo root by the time
# the test runs (observed under shuffled order: cwd drift made the
# hash-seed probe die with ModuleNotFoundError: 'core').
_REPO_ROOT = str(Path(__file__).resolve().parents[3])


# ── Fixtures ──────────────────────────────────────────────────────────

def _func(name, file="src/handlers.c", line=1, metadata=None):
    d = {"name": name, "file": file, "line": line}
    if metadata:
        d["metadata"] = metadata
    return d


@dataclass(frozen=True)
class FakeBinaryCallEdge:
    caller: str
    callee: str
    binary_path: str = "/bin/test"


@dataclass
class FakeBinaryEdgeIndex:
    binary_path: str = "/bin/test"
    edges: list = field(default_factory=list)
    callees: set = field(default_factory=set)


@dataclass
class FakeDispatchTable:
    function: str
    file: str
    line: int = 1
    keys: list = field(default_factory=list)
    table_type: str = "dict"
    handlers: dict = field(default_factory=dict)


class FakeJoernResult:
    def __init__(self, raw_output="", errors=None):
        self.raw_output = raw_output
        self.errors = errors or []
        self.flows = []
        self.ok = not self.errors


# ── _parse_joern_peers ────────────────────────────────────────────────


class TestParseJoernPeers:
    def test_basic(self):
        raw = (
            "JOERN_PEERS:dispatch|src/main.c|handle_get,handle_post,handle_delete\n"
            "JOERN_PEERS:router|src/route.c|route_api,route_static\n"
        )
        result = _parse_joern_peers(raw)
        assert len(result) == 2
        assert result[0] == ("dispatch", "src/main.c",
                             ["handle_get", "handle_post", "handle_delete"])
        assert result[1] == ("router", "src/route.c",
                             ["route_api", "route_static"])

    def test_single_callee_dropped(self):
        raw = "JOERN_PEERS:main|main.c|init\n"
        assert _parse_joern_peers(raw) == []

    def test_empty(self):
        assert _parse_joern_peers("") == []
        assert _parse_joern_peers("unrelated output\n") == []


# ── _filter_co_callees ───────────────────────────────────────────────


class TestFilterCoCallees:
    def test_keeps_compatible(self):
        funcs = {
            "handle_get": _func("handle_get", metadata={
                "parameters": [("req", "Request")], "return_type": "Response",
            }),
            "handle_post": _func("handle_post", metadata={
                "parameters": [("req", "Request")], "return_type": "Response",
            }),
        }
        result = _filter_co_callees(["handle_get", "handle_post"], funcs)
        assert result == ["handle_get", "handle_post"]

    def test_filters_incompatible_arity(self):
        funcs = {
            "handle_get": _func("handle_get", metadata={
                "parameters": [("req", "Request")],
            }),
            "handle_post": _func("handle_post", metadata={
                "parameters": [("req", "Request")],
            }),
            "log_request": _func("log_request", metadata={
                "parameters": [("msg", "str"), ("level", "int"),
                               ("ctx", "Ctx"), ("ts", "int")],
            }),
        }
        result = _filter_co_callees(
            ["handle_get", "handle_post", "log_request"], funcs,
        )
        assert "handle_get" in result
        assert "handle_post" in result
        assert "log_request" not in result

    def test_no_metadata_permissive(self):
        funcs = {
            "a": _func("a"),
            "b": _func("b"),
        }
        result = _filter_co_callees(["a", "b"], funcs)
        assert result == ["a", "b"]

    def test_single_callee_passthrough(self):
        funcs = {"a": _func("a")}
        assert _filter_co_callees(["a"], funcs) == ["a"]

    def test_unknown_name_dropped(self):
        funcs = {"a": _func("a")}
        result = _filter_co_callees(["a", "unknown"], funcs)
        assert result == ["a"]


# ── _signatures_compatible ────────────────────────────────────────────


class TestSignaturesCompatible:
    def test_same_signature(self):
        a = _func("a", metadata={"parameters": [("x", "int")], "return_type": "int"})
        b = _func("b", metadata={"parameters": [("y", "int")], "return_type": "int"})
        assert _signatures_compatible(a, b)

    def test_different_first_param_type(self):
        a = _func("a", metadata={"parameters": [("x", "Request")]})
        b = _func("b", metadata={"parameters": [("x", "Timer")]})
        assert not _signatures_compatible(a, b)

    def test_arity_mismatch(self):
        a = _func("a", metadata={"parameters": [("x", "int")]})
        b = _func("b", metadata={"parameters": [("x", "int"), ("y", "int"), ("z", "int")]})
        assert not _signatures_compatible(a, b)

    def test_arity_within_tolerance(self):
        a = _func("a", metadata={"parameters": [("x", "int")]})
        b = _func("b", metadata={"parameters": [("x", "int"), ("y", "int")]})
        assert _signatures_compatible(a, b)

    def test_no_metadata_compatible(self):
        assert _signatures_compatible(_func("a"), _func("b"))

    def test_different_return_type(self):
        a = _func("a", metadata={"return_type": "Response"})
        b = _func("b", metadata={"return_type": "None"})
        assert not _signatures_compatible(a, b)

    def test_unannotated_compatible_with_annotated(self):
        a = _func("a", metadata={"parameters": [("x", None)]})
        b = _func("b", metadata={"parameters": [("x", "Request")]})
        assert _signatures_compatible(a, b)


# ── L0: Joern co-callee ──────────────────────────────────────────────


class TestJoernCoCalleeGroups:
    def test_basic(self):
        server = MagicMock()
        server.query.return_value = FakeJoernResult(
            raw_output="JOERN_PEERS:dispatch|src/main.c|handle_get,handle_post\n",
        )
        funcs = [_func("handle_get"), _func("handle_post")]
        groups = _joern_co_callee_groups(server, funcs)
        assert len(groups) == 1
        assert groups[0].group_id == "joern_co_callee:dispatch"
        names = {s.function for s in groups[0].siblings}
        assert names == {"handle_get", "handle_post"}

    def test_filters_unknown_functions(self):
        server = MagicMock()
        server.query.return_value = FakeJoernResult(
            raw_output="JOERN_PEERS:dispatch|main.c|handle_get,unknown_fn,handle_post\n",
        )
        funcs = [_func("handle_get"), _func("handle_post")]
        groups = _joern_co_callee_groups(server, funcs)
        assert len(groups) == 1
        names = {s.function for s in groups[0].siblings}
        assert names == {"handle_get", "handle_post"}

    def test_empty_on_error(self):
        server = MagicMock()
        server.query.return_value = FakeJoernResult(errors=["timeout"])
        assert _joern_co_callee_groups(server, [_func("a")]) == []

    def test_empty_on_exception(self):
        server = MagicMock()
        server.query.side_effect = RuntimeError("boom")
        assert _joern_co_callee_groups(server, [_func("a")]) == []

    def test_empty_functions(self):
        server = MagicMock()
        assert _joern_co_callee_groups(server, []) == []


# ── L1: Binary co-callee ─────────────────────────────────────────────


class TestBinaryCoCalleeGroups:
    def test_basic(self):
        idx = FakeBinaryEdgeIndex(edges=[
            FakeBinaryCallEdge("dispatch", "handle_get"),
            FakeBinaryCallEdge("dispatch", "handle_post"),
        ])
        funcs = [_func("handle_get"), _func("handle_post")]
        groups = _binary_co_callee_groups(idx, funcs)
        assert len(groups) == 1
        names = {s.function for s in groups[0].siblings}
        assert names == {"handle_get", "handle_post"}

    def test_single_callee_no_group(self):
        idx = FakeBinaryEdgeIndex(edges=[
            FakeBinaryCallEdge("main", "init"),
        ])
        funcs = [_func("init")]
        assert _binary_co_callee_groups(idx, funcs) == []

    def test_filters_to_known_functions(self):
        idx = FakeBinaryEdgeIndex(edges=[
            FakeBinaryCallEdge("dispatch", "handle_get"),
            FakeBinaryCallEdge("dispatch", "printf"),
            FakeBinaryCallEdge("dispatch", "handle_post"),
        ])
        funcs = [_func("handle_get"), _func("handle_post")]
        groups = _binary_co_callee_groups(idx, funcs)
        assert len(groups) == 1
        names = {s.function for s in groups[0].siblings}
        assert names == {"handle_get", "handle_post"}

    def test_empty_edges(self):
        idx = FakeBinaryEdgeIndex(edges=[])
        assert _binary_co_callee_groups(idx, [_func("a")]) == []

    def test_ambiguous_name_excluded_not_misbound(self):
        """Two remaining records sharing a name: the bare callee name
        is ambiguous — grouping must exclude it rather than bind the
        sibling (and the claim) to an arbitrary file's record."""
        idx = FakeBinaryEdgeIndex(edges=[
            FakeBinaryCallEdge("dispatch", "parse"),
            FakeBinaryCallEdge("dispatch", "handle_get"),
            FakeBinaryCallEdge("dispatch", "handle_post"),
        ])
        funcs = [
            _func("parse", file="src/a.c"),
            _func("parse", file="src/b.c"),
            _func("handle_get"),
            _func("handle_post"),
        ]
        groups = _binary_co_callee_groups(idx, funcs)
        assert len(groups) == 1
        names = {s.function for s in groups[0].siblings}
        assert names == {"handle_get", "handle_post"}
        assert "parse" not in names

    def test_unique_name_binds_to_its_own_file(self):
        idx = FakeBinaryEdgeIndex(edges=[
            FakeBinaryCallEdge("dispatch", "handle_get"),
            FakeBinaryCallEdge("dispatch", "handle_post"),
        ])
        funcs = [
            _func("handle_get", file="src/get.c", line=7),
            _func("handle_post", file="src/post.c", line=9),
        ]
        groups = _binary_co_callee_groups(idx, funcs)
        by_fn = {s.function: s for s in groups[0].siblings}
        assert by_fn["handle_get"].file == "src/get.c"
        assert by_fn["handle_post"].file == "src/post.c"


# ── L2: Dispatch-site ─────────────────────────────────────────────────


class TestDispatchSiteGroups:
    def test_basic(self):
        table = FakeDispatchTable(
            function="dispatch",
            file="src/main.c",
            keys=["get", "post"],
            handlers={"get": "handle_get", "post": "handle_post"},
        )
        funcs = [_func("handle_get"), _func("handle_post")]
        groups = _dispatch_site_groups([table], funcs)
        assert len(groups) == 1
        names = {s.function for s in groups[0].siblings}
        assert names == {"handle_get", "handle_post"}

    def test_no_handlers_no_group(self):
        table = FakeDispatchTable(
            function="dispatch", file="main.c",
            keys=["get", "post"], handlers={},
        )
        assert _dispatch_site_groups([table], [_func("a")]) == []

    def test_single_handler_no_group(self):
        table = FakeDispatchTable(
            function="dispatch", file="main.c",
            handlers={"get": "handle_get"},
        )
        funcs = [_func("handle_get")]
        assert _dispatch_site_groups([table], funcs) == []

    def test_handler_not_in_functions_dropped(self):
        table = FakeDispatchTable(
            function="dispatch", file="main.c",
            handlers={"get": "handle_get", "post": "handle_post"},
        )
        funcs = [_func("handle_get")]
        assert _dispatch_site_groups([table], funcs) == []


# ── L3: Domain model ─────────────────────────────────────────────────


class TestDomainModelGroups:
    def test_basic(self):
        model = {
            "concepts": [{
                "name": "rpc_handlers",
                "functions": ["handle_connect", "handle_data"],
            }],
        }
        funcs = [_func("handle_connect"), _func("handle_data")]
        groups = _domain_model_groups(model, funcs)
        assert len(groups) == 1
        assert groups[0].group_id == "domain:rpc_handlers"

    def test_members_field(self):
        model = {
            "concepts": [{
                "name": "codec",
                "members": [{"name": "encode_frame"}, {"name": "decode_frame"}],
            }],
        }
        funcs = [_func("encode_frame"), _func("decode_frame")]
        groups = _domain_model_groups(model, funcs)
        assert len(groups) == 1

    def test_no_concepts(self):
        assert _domain_model_groups({}, [_func("a")]) == []
        assert _domain_model_groups({"concepts": []}, [_func("a")]) == []

    def test_single_member_no_group(self):
        model = {"concepts": [{"name": "x", "functions": ["a"]}]}
        assert _domain_model_groups(model, [_func("a")]) == []


# ── L4: Type cohort ──────────────────────────────────────────────────


class TestTypeCohortGroups:
    def test_basic(self):
        idx = {
            "page": [("page_alloc", "writer"), ("page_free", "writer"),
                     ("page_map", "reader")],
        }
        funcs = [_func("page_alloc"), _func("page_free"), _func("page_map")]
        groups = _type_cohort_groups(idx, funcs)
        assert len(groups) == 1
        assert groups[0].group_id == "type_cohort:page"
        names = {s.function for s in groups[0].siblings}
        assert names == {"page_alloc", "page_free", "page_map"}

    def test_single_function_no_group(self):
        idx = {"page": [("page_alloc", "writer")]}
        assert _type_cohort_groups(idx, [_func("page_alloc")]) == []

    def test_none_index(self):
        assert _type_cohort_groups(None, [_func("a")]) == []

    def test_filters_to_known_functions(self):
        idx = {"page": [("page_alloc", "writer"), ("unknown", "reader"),
                        ("page_free", "writer")]}
        funcs = [_func("page_alloc"), _func("page_free")]
        groups = _type_cohort_groups(idx, funcs)
        assert len(groups) == 1
        names = {s.function for s in groups[0].siblings}
        assert names == {"page_alloc", "page_free"}

    def test_duplicate_roles_deduplicated(self):
        idx = {"page": [("page_alloc", "reader"), ("page_alloc", "writer"),
                        ("page_free", "reader")]}
        funcs = [_func("page_alloc"), _func("page_free")]
        groups = _type_cohort_groups(idx, funcs)
        assert len(groups) == 1
        sibling_names = [s.function for s in groups[0].siblings]
        assert sibling_names == ["page_alloc", "page_free"]


# ── L5: Verb-prefix + sig shape ──────────────────────────────────────


class TestVerbPrefixGroups:
    def test_basic_grouping(self):
        funcs = [
            _func("handle_get", file="src/api/handlers.c"),
            _func("handle_post", file="src/api/handlers.c"),
            _func("handle_delete", file="src/api/handlers.c"),
        ]
        groups = _verb_prefix_groups(funcs)
        assert len(groups) == 1
        names = {s.function for s in groups[0].siblings}
        assert names == {"handle_get", "handle_post", "handle_delete"}

    def test_directory_scoping(self):
        funcs = [
            _func("handle_get", file="src/api/handlers.c"),
            _func("handle_post", file="src/api/handlers.c"),
            _func("handle_click", file="src/ui/events.c"),
            _func("handle_scroll", file="src/ui/events.c"),
        ]
        groups = _verb_prefix_groups(funcs)
        assert len(groups) == 2
        dirs = {g.group_id.split(":")[1] for g in groups}
        assert "src/api" in dirs
        assert "src/ui" in dirs

    def test_single_function_no_group(self):
        funcs = [_func("handle_get", file="src/api/h.c")]
        assert _verb_prefix_groups(funcs) == []

    def test_signature_filtering(self):
        funcs = [
            _func("handle_get", file="src/h.c", metadata={
                "parameters": [("req", "Request")], "return_type": "Response",
            }),
            _func("handle_post", file="src/h.c", metadata={
                "parameters": [("req", "Request")], "return_type": "Response",
            }),
            _func("handle_shutdown", file="src/h.c", metadata={
                "parameters": [], "return_type": "None",
            }),
        ]
        groups = _verb_prefix_groups(funcs)
        assert len(groups) == 1
        names = {s.function for s in groups[0].siblings}
        assert "handle_get" in names
        assert "handle_post" in names
        assert "handle_shutdown" not in names

    def test_decorator_grouping(self):
        funcs = [
            _func("index", file="src/app.py", metadata={
                "attributes": ["app.route"],
            }),
            _func("login", file="src/app.py", metadata={
                "attributes": ["app.route"],
            }),
        ]
        groups = _verb_prefix_groups(funcs)
        assert len(groups) == 1
        assert "decorator" in groups[0].group_id

    def test_decorator_claimed_excluded_from_verb(self):
        funcs = [
            _func("handle_get", file="src/h.c", metadata={
                "attributes": ["api_handler"],
            }),
            _func("handle_post", file="src/h.c", metadata={
                "attributes": ["api_handler"],
            }),
            _func("handle_delete", file="src/h.c"),
        ]
        groups = _verb_prefix_groups(funcs)
        deco_groups = [g for g in groups if "decorator" in g.group_id]
        verb_groups = [g for g in groups if "verb" in g.group_id]
        assert len(deco_groups) == 1
        deco_names = {s.function for s in deco_groups[0].siblings}
        assert deco_names == {"handle_get", "handle_post"}
        # handle_delete alone in verb bucket → no group
        assert len(verb_groups) == 0

    def test_verb_prefix_group_carries_shared_context(self):
        groups = _verb_prefix_groups(
            [_func("parse_header"), _func("parse_body")]
        )
        assert len(groups) == 1
        group = groups[0]
        assert group.shared_context
        assert "parse" in group.shared_context

    def test_decorator_claim_does_not_cross_directories(self):
        funcs = [
            _func("handle_get", file="src/api/h.c", metadata={
                "attributes": ["api_handler"],
            }),
            _func("handle_post", file="src/api/h.c", metadata={
                "attributes": ["api_handler"],
            }),
            _func("handle_get", file="src/db/h.c"),
            _func("handle_post", file="src/db/h.c"),
        ]
        groups = _verb_prefix_groups(funcs)
        deco_groups = [g for g in groups if "decorator" in g.group_id]
        verb_groups = [g for g in groups if "verb" in g.group_id]
        assert len(deco_groups) == 1
        # db/ functions NOT decorator-claimed → still form a verb group
        db_verb = [g for g in verb_groups if "src/db" in g.group_id]
        assert len(db_verb) == 1
        db_names = {s.function for s in db_verb[0].siblings}
        assert db_names == {"handle_get", "handle_post"}


# ── L6: Paired operations ────────────────────────────────────────────


class TestPairedOperationGroups:
    def test_prefix_pair(self):
        funcs = [_func("encode_jwt"), _func("decode_jwt")]
        groups = _paired_operation_groups(funcs)
        assert len(groups) == 1
        names = {s.function for s in groups[0].siblings}
        assert names == {"encode_jwt", "decode_jwt"}

    def test_suffix_pair(self):
        funcs = [_func("session_lock"), _func("session_unlock")]
        groups = _paired_operation_groups(funcs)
        assert len(groups) == 1

    def test_no_partner(self):
        funcs = [_func("encode_jwt"), _func("encode_xml")]
        assert _paired_operation_groups(funcs) == []

    def test_cross_directory(self):
        funcs = [
            _func("alloc_context", file="src/core/ctx.c"),
            _func("free_context", file="src/cleanup/ctx.c"),
        ]
        groups = _paired_operation_groups(funcs)
        assert len(groups) == 1

    def test_multiple_pairs(self):
        funcs = [
            _func("encode_jwt"), _func("decode_jwt"),
            _func("lock_session"), _func("unlock_session"),
        ]
        groups = _paired_operation_groups(funcs)
        assert len(groups) == 2

    def test_get_set_pair(self):
        funcs = [_func("get_user"), _func("set_user")]
        groups = _paired_operation_groups(funcs)
        assert len(groups) == 1

    def test_get_put_pair(self):
        funcs = [_func("get_page"), _func("put_page")]
        groups = _paired_operation_groups(funcs)
        assert len(groups) == 1

    # Names crafted so two forward names collide on the same
    # lowercased stem ("blob") and contend for one reverse partner.
    COLLIDING = (
        "encode_Blob", "encode_blob", "decode_blob",
        "get_item", "put_item", "set_item",
        "lock_table", "unlock_table",
    )

    def test_stem_collision_winner_is_sorted_last_writer(self):
        groups = _paired_operation_groups(
            [_func(n) for n in self.COLLIDING]
        )
        pair_ids = {g.group_id for g in groups}
        # sorted() puts "encode_Blob" before "encode_blob"; the
        # last writer for stem "blob" is therefore "encode_blob".
        assert "pair:encode_blob:decode_blob" in pair_ids
        assert "pair:encode_Blob:decode_blob" not in pair_ids

    def test_pairing_stable_across_hash_seeds(self):
        # Set iteration order varies with PYTHONHASHSEED; the pairing
        # must not.
        snippet = (
            "import sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "from core.analysis.peer_groups import _paired_operation_groups\n"
            f"names = {list(self.COLLIDING)!r}\n"
            "fns = [{'name': n, 'file': 'src/mod.c', 'line': 1}"
            " for n in names]\n"
            "print(sorted(g.group_id for g in"
            " _paired_operation_groups(fns)))\n"
        )
        outputs = set()
        for seed in ("0", "1", "42"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            proc = subprocess.run(
                [sys.executable, "-c", snippet, _REPO_ROOT],
                capture_output=True, text=True, env=env, check=True,
            )
            outputs.add(proc.stdout.strip())
        assert len(outputs) == 1, outputs

    def test_first_claim_still_exclusive(self):
        # A name already claimed by an earlier pattern is not re-paired.
        groups = _paired_operation_groups(
            [_func("get_item"), _func("put_item"), _func("set_item")]
        )
        assert [g.group_id for g in groups] == ["pair:get_item:put_item"]


# ── resolve_peer_groups integration ───────────────────────────────────


class TestResolvePeerGroups:
    def test_empty(self):
        assert resolve_peer_groups([]) == []

    def test_verb_prefix_only(self):
        funcs = [
            _func("handle_get", file="src/h.c"),
            _func("handle_post", file="src/h.c"),
        ]
        groups = resolve_peer_groups(funcs)
        assert len(groups) >= 1

    def test_exclusive_claim(self):
        """L0 claims functions, L5 verb-prefix still runs independently."""
        server = MagicMock()
        server.query.return_value = FakeJoernResult(
            raw_output="JOERN_PEERS:dispatch|main.c|handle_get,handle_post\n",
        )
        funcs = [
            _func("handle_get", file="src/h.c"),
            _func("handle_post", file="src/h.c"),
            _func("handle_delete", file="src/h.c"),
        ]
        groups = resolve_peer_groups(funcs, joern_server=server)
        joern_groups = [g for g in groups if "joern" in g.group_id]
        assert len(joern_groups) == 1
        joern_names = {s.function for s in joern_groups[0].siblings}
        assert joern_names == {"handle_get", "handle_post"}
        # handle_delete is NOT in joern group, but L5 runs on all
        # functions independently — it may group all three by verb prefix
        # (L4-L6 are independent of claims)

    def test_paired_and_verb_coexist(self):
        """L5 and L6 are independent — a function can be in both."""
        funcs = [
            _func("get_user", file="src/h.c"),
            _func("set_user", file="src/h.c"),
            _func("get_page", file="src/h.c"),
        ]
        groups = resolve_peer_groups(funcs)
        pair_groups = [g for g in groups if "pair" in g.group_id]
        verb_groups = [g for g in groups if "verb" in g.group_id]
        assert len(pair_groups) >= 1
        # get_user should be in both a pair AND a verb group
        pair_names = set()
        for pg in pair_groups:
            for s in pg.siblings:
                pair_names.add(s.function)
        verb_names = set()
        for vg in verb_groups:
            for s in vg.siblings:
                verb_names.add(s.function)
        assert "get_user" in pair_names
        assert "get_user" in verb_names

    def test_type_cohort_independent(self):
        """L4 runs on ALL functions, not just unclaimed."""
        server = MagicMock()
        server.query.return_value = FakeJoernResult(
            raw_output="JOERN_PEERS:dispatch|main.c|handle_get,handle_post\n",
        )
        type_ref = {
            "Request": [("handle_get", "reader"), ("handle_post", "reader")],
        }
        funcs = [_func("handle_get"), _func("handle_post")]
        groups = resolve_peer_groups(
            funcs, joern_server=server, type_ref_index=type_ref,
        )
        joern_groups = [g for g in groups if "joern" in g.group_id]
        type_groups = [g for g in groups if "type_cohort" in g.group_id]
        assert len(joern_groups) == 1
        assert len(type_groups) == 1


# ── Helpers ───────────────────────────────────────────────────────────


class TestFuncDirectory:
    def test_normal(self):
        assert _func_directory({"file": "src/api/handlers.c"}) == "src/api"

    def test_root(self):
        assert _func_directory({"file": "main.c"}) == "."

    def test_empty(self):
        assert _func_directory({"file": ""}) == ""
        assert _func_directory({}) == ""


class TestLargestCompatibleSubset:
    def test_all_compatible(self):
        funcs = [_func("a"), _func("b"), _func("c")]
        assert len(_largest_compatible_subset(funcs)) == 3

    def test_filters_incompatible(self):
        funcs = [
            _func("a", metadata={"parameters": [("x", "int")]}),
            _func("b", metadata={"parameters": [("x", "int")]}),
            _func("c", metadata={"parameters": [("x", "str")]}),
        ]
        result = _largest_compatible_subset(funcs)
        names = {f["name"] for f in result}
        assert "a" in names
        assert "b" in names
        assert "c" not in names

    def test_single(self):
        assert len(_largest_compatible_subset([_func("a")])) == 1

    def test_empty(self):
        assert _largest_compatible_subset([]) == []


# ── Producers: binary_edge_index_from_inventory (L1) ─────────────────


def _bo_inventory(binaries):
    return {"binary_oracle": {"binaries": binaries}}


class TestBinaryEdgeIndexFromInventory:
    def _patch_cache(self, monkeypatch, mapping):
        """Route load_cached_edge_index through an in-memory cache."""
        import core.analysis.binary_oracle_edges as edges_mod

        def _fake_load(path):
            return mapping.get(str(path))

        monkeypatch.setattr(
            edges_mod, "load_cached_edge_index", _fake_load,
        )

    def test_none_inventory(self):
        from core.analysis.peer_groups import (
            binary_edge_index_from_inventory,
        )

        assert binary_edge_index_from_inventory(None) is None
        assert binary_edge_index_from_inventory({}) is None
        assert binary_edge_index_from_inventory(
            {"binary_oracle": {}}) is None

    def test_operator_opt_out(self, monkeypatch):
        """--no-binary-oracle wins even with eligible cached binaries."""
        from core.analysis.binary_oracle_edges import BinaryEdgeIndex
        from core.analysis.peer_groups import (
            binary_edge_index_from_inventory,
        )

        idx = BinaryEdgeIndex(binary_path="/b/app")
        idx.edges.append(FakeBinaryCallEdge("main", "h_get"))
        self._patch_cache(monkeypatch, {"/b/app": idx})
        inv = _bo_inventory(
            [{"path": "/b/app", "build_id": "aa", "tier": "full"}])
        assert binary_edge_index_from_inventory(
            inv, no_binary_oracle=True) is None

    def test_tier_gate_skips_symbol_only_and_unknown(self, monkeypatch):
        """Chokepoint tier gating: stripped / unknown-tier binaries
        never feed L1 — name-keyed joins from a stripped binary can't
        earn an exclusive-claim layer."""
        from core.analysis.binary_oracle_edges import BinaryEdgeIndex
        from core.analysis.peer_groups import (
            binary_edge_index_from_inventory,
        )

        idx = BinaryEdgeIndex(binary_path="/b/stripped")
        idx.edges.append(FakeBinaryCallEdge("main", "h_get"))
        self._patch_cache(
            monkeypatch, {"/b/stripped": idx, "/b/unknown": idx})
        inv = _bo_inventory([
            {"path": "/b/stripped", "build_id": "aa",
             "tier": "symbol_only"},
            {"path": "/b/unknown", "build_id": "bb", "tier": "unknown"},
        ])
        assert binary_edge_index_from_inventory(inv) is None

    def test_cache_miss_stays_empty(self, monkeypatch):
        """Cold cache -> None -> layer stays empty (equivalence pin).
        The producer never runs r2."""
        from core.analysis.peer_groups import (
            binary_edge_index_from_inventory,
        )

        self._patch_cache(monkeypatch, {})
        inv = _bo_inventory(
            [{"path": "/b/app", "build_id": "aa", "tier": "full"}])
        assert binary_edge_index_from_inventory(inv) is None

    def test_full_tier_cache_hit_merges_binaries(self, monkeypatch):
        from core.analysis.binary_oracle_edges import BinaryEdgeIndex
        from core.analysis.peer_groups import (
            binary_edge_index_from_inventory,
        )

        idx_a = BinaryEdgeIndex(binary_path="/b/app")
        idx_a.edges.append(FakeBinaryCallEdge("main", "h_get", "/b/app"))
        idx_a.callees.add("h_get")
        idx_b = BinaryEdgeIndex(binary_path="/b/lib")
        idx_b.edges.append(FakeBinaryCallEdge("main", "h_put", "/b/lib"))
        idx_b.callees.add("h_put")
        self._patch_cache(monkeypatch, {"/b/app": idx_a, "/b/lib": idx_b})
        inv = _bo_inventory([
            {"path": "/b/app", "build_id": "aa", "tier": "full"},
            {"path": "/b/lib", "build_id": "bb", "tier": "full"},
        ])
        merged = binary_edge_index_from_inventory(inv)
        assert merged is not None
        assert len(merged.edges) == 2
        assert merged.callees == {"h_get", "h_put"}

    def test_coverage_gain_l1_groups_where_l2_l6_cannot(self, monkeypatch):
        """Functions no other layer can group (no dispatch table, no
        verb prefix, no pair pattern) get grouped once the L1 producer
        supplies cached binary edges."""
        from core.analysis.binary_oracle_edges import BinaryEdgeIndex
        from core.analysis.peer_groups import (
            binary_edge_index_from_inventory,
        )

        funcs = [
            _func("frobnicate", file="src/a.c"),
            _func("quuxify", file="src/b.c"),
        ]
        # Without the L1 input: no groups at all.
        assert resolve_peer_groups(funcs) == []

        idx = BinaryEdgeIndex(binary_path="/b/app")
        idx.edges.append(
            FakeBinaryCallEdge("dispatch_all", "frobnicate", "/b/app"))
        idx.edges.append(
            FakeBinaryCallEdge("dispatch_all", "quuxify", "/b/app"))
        idx.callees.update({"frobnicate", "quuxify"})
        self._patch_cache(monkeypatch, {"/b/app": idx})
        inv = _bo_inventory(
            [{"path": "/b/app", "build_id": "aa", "tier": "full"}])

        edge_index = binary_edge_index_from_inventory(inv)
        groups = resolve_peer_groups(funcs, binary_edge_index=edge_index)
        assert len(groups) == 1
        assert groups[0].sibling_type == "co_callee"
        assert {s.function for s in groups[0].siblings} == {
            "frobnicate", "quuxify",
        }

    def test_equivalence_absent_input_byte_identical(self):
        """No binaries declared -> resolver output identical to a call
        that never mentions the layer."""
        funcs = [
            _func("handle_get", file="src/h.c"),
            _func("handle_put", file="src/h.c"),
            _func("encode_frame", file="src/codec.c"),
            _func("decode_frame", file="src/codec.c"),
        ]
        from core.analysis.peer_groups import (
            binary_edge_index_from_inventory,
        )

        produced = binary_edge_index_from_inventory({"files": []})
        assert produced is None
        baseline = resolve_peer_groups(funcs)
        wired = resolve_peer_groups(funcs, binary_edge_index=produced)
        assert [
            (g.group_id, g.sibling_type,
             [(s.file, s.function) for s in g.siblings])
            for g in baseline
        ] == [
            (g.group_id, g.sibling_type,
             [(s.file, s.function) for s in g.siblings])
            for g in wired
        ]


# ── Producers: type_ref_index_from_inventory (L4) ────────────────────


def _inv_file(path, language, items):
    return {"path": path, "language": language, "items": items}


def _inv_fn(name, *, params=None, return_type=None, signature=None):
    item = {"name": name, "kind": "function", "line_start": 1}
    meta = {}
    if params is not None:
        meta["parameters"] = params
    if return_type is not None:
        meta["return_type"] = return_type
    if meta:
        item["metadata"] = meta
    if signature is not None:
        item["signature"] = signature
    return item


class TestTypeRefIndexFromInventory:
    def test_none_without_type_info(self):
        from core.analysis.peer_groups import type_ref_index_from_inventory

        assert type_ref_index_from_inventory(None) is None
        assert type_ref_index_from_inventory({}) is None
        # untyped items -> nothing distinctive -> None
        inv = {"files": [_inv_file("a.py", "python", [
            _inv_fn("f"), _inv_fn("g"),
        ])]}
        assert type_ref_index_from_inventory(inv) is None

    def test_cohort_from_typed_params(self):
        from core.analysis.peer_groups import type_ref_index_from_inventory

        inv = {"files": [_inv_file("a.py", "python", [
            _inv_fn("login", params=[["ctx", "AuthContext"]]),
            _inv_fn("logout", params=[["ctx", "AuthContext"]]),
            _inv_fn("unrelated", params=[["n", "int"]]),
        ])]}
        idx = type_ref_index_from_inventory(inv)
        assert idx is not None
        assert set(idx) == {"AuthContext"}
        assert [fn for fn, _cls in idx["AuthContext"]] == ["login", "logout"]

    def test_primitives_never_form_cohorts(self):
        from core.analysis.peer_groups import type_ref_index_from_inventory

        inv = {"files": [_inv_file("a.py", "python", [
            _inv_fn("f", params=[["s", "str"], ["n", "int"]],
                    return_type="bool"),
            _inv_fn("g", params=[["s", "str"], ["n", "int"]],
                    return_type="bool"),
        ])]}
        assert type_ref_index_from_inventory(inv) is None

    def test_decorated_forms_normalise(self):
        """const ptr / Optional[...] / std::vector<...> all yield the
        distinctive core type."""
        from core.analysis.peer_groups import type_ref_index_from_inventory

        inv = {"files": [
            _inv_file("a.c", "c", [
                _inv_fn("c_reader",
                        params=[["r", "const request_ctx_t *"]]),
            ]),
            _inv_file("b.py", "python", [
                _inv_fn("py_reader",
                        params=[["r", "Optional[request_ctx_t]"]]),
            ]),
            _inv_file("c.cpp", "cpp", [
                _inv_fn("cpp_reader",
                        params=[["r", "std::vector<request_ctx_t>"]]),
            ]),
        ]}
        idx = type_ref_index_from_inventory(inv)
        assert idx is not None
        assert [fn for fn, _cls in idx["request_ctx_t"]] == [
            "c_reader", "cpp_reader", "py_reader",
        ]

    def test_return_type_counts(self):
        from core.analysis.peer_groups import type_ref_index_from_inventory

        inv = {"files": [_inv_file("a.py", "python", [
            _inv_fn("make_token", return_type="SessionToken"),
            _inv_fn("verify_token", params=[["t", "SessionToken"]]),
        ])]}
        idx = type_ref_index_from_inventory(inv)
        assert idx is not None
        entries = dict(idx["SessionToken"])
        assert entries == {"make_token": "return", "verify_token": "param"}

    def test_c_signature_fallback(self):
        """C items without parameter metadata mine the signature for
        _t / struct tokens (language-aware degradation)."""
        from core.analysis.peer_groups import type_ref_index_from_inventory

        inv = {"files": [_inv_file("net.c", "c", [
            _inv_fn("conn_open",
                    signature="int conn_open(conn_state_t *cs)"),
            _inv_fn("conn_close",
                    signature="void conn_close(struct conn_state *cs)"),
            _inv_fn("conn_reset",
                    signature="void conn_reset(conn_state_t *cs)"),
        ])]}
        idx = type_ref_index_from_inventory(inv)
        assert idx is not None
        assert [fn for fn, _cls in idx["conn_state_t"]] == [
            "conn_open", "conn_reset",
        ]
        # struct tag from the fallback regex
        assert "conn_state" in idx or "conn_state_t" in idx

    def test_bounded_cohort_size(self):
        """A type shared by half the codebase is not distinctive."""
        from core.analysis.peer_groups import type_ref_index_from_inventory

        items = [
            _inv_fn(f"f{i}", params=[["g", "GodObject"]])
            for i in range(30)
        ]
        inv = {"files": [_inv_file("a.py", "python", items)]}
        assert type_ref_index_from_inventory(inv) is None
        # under the cap it forms normally
        inv_small = {"files": [_inv_file("a.py", "python", items[:5])]}
        idx = type_ref_index_from_inventory(inv_small)
        assert idx is not None and len(idx["GodObject"]) == 5

    def test_bounded_total_types(self):
        from core.analysis.peer_groups import type_ref_index_from_inventory

        files = []
        for i in range(300):
            files.append(_inv_file(f"m{i}.py", "python", [
                _inv_fn(f"use_a_{i}", params=[["x", f"WidgetKind{i}"]]),
                _inv_fn(f"use_b_{i}", params=[["x", f"WidgetKind{i}"]]),
            ]))
        idx = type_ref_index_from_inventory({"files": files})
        assert idx is not None
        assert len(idx) == 200

    def test_coverage_gain_l4_groups_where_l5_l6_cannot(self):
        """Functions with unrelated names (no verb prefix, no pair)
        sharing a distinctive type get grouped once the L4 producer
        runs."""
        from core.analysis.peer_groups import type_ref_index_from_inventory

        funcs = [
            _func("frobnicate", file="src/a.py"),
            _func("quuxify", file="src/b.py"),
        ]
        assert resolve_peer_groups(funcs) == []

        inv = {"files": [
            _inv_file("src/a.py", "python", [
                _inv_fn("frobnicate", params=[["p", "PayloadEnvelope"]]),
            ]),
            _inv_file("src/b.py", "python", [
                _inv_fn("quuxify", params=[["p", "PayloadEnvelope"]]),
            ]),
        ]}
        idx = type_ref_index_from_inventory(inv)
        groups = resolve_peer_groups(funcs, type_ref_index=idx)
        assert len(groups) == 1
        assert groups[0].sibling_type == "type_cohort"
        assert groups[0].group_id == "type_cohort:PayloadEnvelope"
        assert {s.function for s in groups[0].siblings} == {
            "frobnicate", "quuxify",
        }

    def test_equivalence_absent_input_byte_identical(self):
        funcs = [
            _func("handle_get", file="src/h.c"),
            _func("handle_put", file="src/h.c"),
        ]
        from core.analysis.peer_groups import type_ref_index_from_inventory

        produced = type_ref_index_from_inventory({"files": []})
        assert produced is None
        baseline = resolve_peer_groups(funcs)
        wired = resolve_peer_groups(funcs, type_ref_index=produced)
        assert [
            (g.group_id, g.sibling_type,
             [(s.file, s.function) for s in g.siblings])
            for g in baseline
        ] == [
            (g.group_id, g.sibling_type,
             [(s.file, s.function) for s in g.siblings])
            for g in wired
        ]
