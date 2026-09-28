"""Tests for the L7 interface-slot census and peer-group layer.

Pins the census (ops-slot extraction reuse, override-set metadata
join, family cap), the layer's join contract (name resolution through
the ambiguity-excluding index, claim floor, seeded-random member cap,
escaping), the exclusive placement (L7 claims ahead of the co-callee
layers), and the cross-module string pins the interface dimension
depends on (group type admitted, claim floor = comparator floor).
"""

from __future__ import annotations

from core.analysis.interface_slots import (
    GROUP_TYPE_INTERFACE_SLOT,
    MAX_SLOT_FAMILIES,
    SlotFamily,
    SlotMember,
    interface_slot_families,
)
from core.analysis.peer_groups import (
    MAX_INTERFACE_SLOT_MEMBERS,
    MIN_INTERFACE_SLOT_MEMBERS,
    _interface_slot_groups,
    resolve_peer_groups,
)

# ── fixtures ──────────────────────────────────────────────────────────

_OPS_C = """\
static const struct proto_ops tcp_ops = {
    .send = tcp_send,
    .recv = tcp_recv,
};
static const struct proto_ops udp_ops = {
    .send = udp_send,
    .recv = udp_recv,
};
static const struct proto_ops raw_ops = {
    .send = raw_send,
    .recv = raw_recv,
};
"""


def _func(name, file="src/net.c", line=1):
    return {"name": name, "file": file, "line": line}


def _checklist_py(*classes, one_file=False):
    """``classes`` = (class_name, [bases], [method names]). Each
    class in its own file by default (the layout where override
    members keep distinct (file, name) identities)."""
    files = []
    items_shared = []
    line = 10
    for idx, (cls, bases, methods) in enumerate(classes):
        items = []
        for m in methods:
            items.append({
                "name": m,
                "kind": "function",
                "line_start": line,
                "metadata": {
                    "class_name": cls,
                    "class_attributes": list(bases),
                },
            })
            line += 10
        if one_file:
            items_shared.extend(items)
        else:
            files.append({"path": f"src/h{idx}.py", "items": items})
    if one_file:
        files = [{"path": "src/handlers.py", "items": items_shared}]
    return {"files": files}


# ── census: ops-slot families ─────────────────────────────────────────


class TestOpsSlotCensus:
    def test_slot_family_per_struct_field(self):
        fams = interface_slot_families({"src/net.c": _OPS_C})
        assert fams is not None
        keys = {(f.kind, f.key) for f in fams}
        assert ("ops_slot", "proto_ops.send") in keys
        assert ("ops_slot", "proto_ops.recv") in keys
        send = next(f for f in fams if f.key == "proto_ops.send")
        assert sorted(m.function for m in send.members) == [
            "raw_send", "tcp_send", "udp_send",
        ]

    def test_single_implementation_no_family(self):
        src = "struct a_ops x = {\n    .go = only_impl,\n};\n"
        assert interface_slot_families({"a.c": src}) is None

    def test_non_c_files_skipped(self):
        fams = interface_slot_families({"net.py": _OPS_C})
        assert fams is None

    def test_family_cap_marks_caps_hit(self):
        # One struct type per index, two members each — census-wide
        # family flood.
        parts = []
        for i in range(MAX_SLOT_FAMILIES + 5):
            parts.append(
                f"struct ops{i} a{i} = {{ .go = f{i}_a, }};\n"
                f"struct ops{i} b{i} = {{ .go = f{i}_b, }};\n"
            )
        fams = interface_slot_families({"flood.c": "".join(parts)})
        assert fams is not None
        assert len(fams) == MAX_SLOT_FAMILIES
        assert all(f.caps_hit for f in fams)


class TestDerivedFamilyCap:
    """Cap derived from census input scale: floor for small trees,
    linear growth with input files, absolute ceiling as backstop."""

    def test_small_tree_keeps_the_floor(self):
        from core.analysis.interface_slots import _derive_slot_family_cap
        assert _derive_slot_family_cap(0) == MAX_SLOT_FAMILIES
        assert _derive_slot_family_cap(1) == MAX_SLOT_FAMILIES
        # Right at the crossover the floor still binds.
        assert _derive_slot_family_cap(
            4 * MAX_SLOT_FAMILIES,
        ) == MAX_SLOT_FAMILIES

    def test_large_tree_derives_above_the_floor(self):
        from core.analysis.interface_slots import _derive_slot_family_cap
        assert _derive_slot_family_cap(4_000) == 1_000

    def test_ceiling_binds_at_kernel_scale(self):
        from core.analysis.interface_slots import (
            MAX_SLOT_FAMILIES_CEILING,
            _derive_slot_family_cap,
        )
        # A full kernel tree is tens of thousands of C files.
        assert _derive_slot_family_cap(40_000) == \
            MAX_SLOT_FAMILIES_CEILING
        assert _derive_slot_family_cap(10**9) == \
            MAX_SLOT_FAMILIES_CEILING

    def test_constants_read_at_call_time(self, monkeypatch):
        import core.analysis.interface_slots as isl
        monkeypatch.setattr(isl, "MAX_SLOT_FAMILIES", 2)
        monkeypatch.setattr(isl, "MAX_SLOT_FAMILIES_CEILING", 3)
        assert isl._derive_slot_family_cap(0) == 2
        assert isl._derive_slot_family_cap(100) == 3

    @staticmethod
    def _flood_texts(n_files: int) -> dict[str, str]:
        # One two-member family per file.
        return {
            f"f{i}.c": (
                f"struct ops{i} a{i} = {{ .go = f{i}_a, }};\n"
                f"struct ops{i} b{i} = {{ .go = f{i}_b, }};\n"
            )
            for i in range(n_files)
        }

    def test_scale_raises_cap_above_floor(self, monkeypatch):
        # Below the derived cap: at scale the derivation admits
        # families the bare floor would have dropped.
        import core.analysis.interface_slots as isl
        monkeypatch.setattr(isl, "MAX_SLOT_FAMILIES", 1)
        monkeypatch.setattr(isl, "_SLOT_FAMILY_FILES_PER_FAMILY", 1)
        fams = isl.interface_slot_families(self._flood_texts(3))
        assert fams is not None
        assert len(fams) == 3
        assert not any(f.caps_hit for f in fams)

    def test_ceiling_still_caps_with_marker(self, monkeypatch):
        # At the ceiling: truncation happens and is stamped in-band.
        import core.analysis.interface_slots as isl
        monkeypatch.setattr(isl, "MAX_SLOT_FAMILIES", 1)
        monkeypatch.setattr(isl, "_SLOT_FAMILY_FILES_PER_FAMILY", 1)
        monkeypatch.setattr(isl, "MAX_SLOT_FAMILIES_CEILING", 2)
        fams = isl.interface_slot_families(self._flood_texts(3))
        assert fams is not None
        assert len(fams) == 2
        assert all(f.caps_hit for f in fams)

    def test_checklist_files_count_toward_scale(self, monkeypatch):
        import core.analysis.interface_slots as isl
        monkeypatch.setattr(isl, "MAX_SLOT_FAMILIES", 1)
        monkeypatch.setattr(isl, "_SLOT_FAMILY_FILES_PER_FAMILY", 1)
        checklist = {"files": [{"path": f"p{i}.py"} for i in range(2)]}
        fams = isl.interface_slot_families(
            self._flood_texts(1), checklist,
        )
        # 1 source text + 2 checklist entries = cap 3 >= 1 family.
        assert fams is not None
        assert not any(f.caps_hit for f in fams)


# ── census: override-set families ─────────────────────────────────────


class TestOverrideCensus:
    def test_shared_base_forms_family(self):
        checklist = _checklist_py(
            ("TcpHandler", ["BaseHandler"], ["process"]),
            ("UdpHandler", ["BaseHandler"], ["process"]),
            ("RawHandler", ["BaseHandler"], ["process"]),
        )
        fams = interface_slot_families(None, checklist)
        assert fams is not None
        fam = next(f for f in fams if f.key == "BaseHandler.process")
        assert fam.kind == "override_set"
        assert len(fam.members) == 3
        assert sorted(m.file for m in fam.members) == [
            "src/h0.py", "src/h1.py", "src/h2.py",
        ]

    def test_same_file_overrides_collapse_never_misbind(self):
        # Same-named methods in ONE file share the pipeline's
        # (file, name) identity — they collapse to one member and the
        # family drops below the floor (under-claims, never
        # mis-binds; the docstring's collapse note).
        checklist = _checklist_py(
            ("TcpHandler", ["BaseHandler"], ["process"]),
            ("UdpHandler", ["BaseHandler"], ["process"]),
            one_file=True,
        )
        assert interface_slot_families(None, checklist) is None

    def test_dunders_excluded(self):
        checklist = _checklist_py(
            ("A", ["Base"], ["__init__"]),
            ("B", ["Base"], ["__init__"]),
        )
        assert interface_slot_families(None, checklist) is None

    def test_distinct_bases_do_not_family(self):
        checklist = _checklist_py(
            ("A", ["BaseX"], ["process"]),
            ("B", ["BaseY"], ["process"]),
        )
        assert interface_slot_families(None, checklist) is None

    def test_malformed_metadata_contributes_nothing(self):
        checklist = {"files": [{"path": "a.py", "items": [
            {"name": "f", "kind": "function",
             "metadata": {"class_name": 3, "class_attributes": "X"}},
            {"name": "g", "kind": "function", "metadata": "junk"},
            "junk",
        ]}]}
        assert interface_slot_families(None, checklist) is None


# ── layer: join contract ──────────────────────────────────────────────


def _fam(key="proto_ops.send", names=("tcp_send", "udp_send",
                                      "raw_send"), kind="ops_slot"):
    return SlotFamily(kind=kind, key=key, members=[
        SlotMember(function=n) for n in names
    ])


class TestInterfaceSlotLayer:
    def test_joins_by_name_and_emits_group(self):
        functions = [
            _func("tcp_send"), _func("udp_send"), _func("raw_send"),
        ]
        groups = _interface_slot_groups([_fam()], functions)
        assert len(groups) == 1
        g = groups[0]
        assert g.sibling_type == GROUP_TYPE_INTERFACE_SLOT
        assert g.group_id == "interface_slot:ops_slot:proto_ops.send"
        assert sorted(s.function for s in g.siblings) == [
            "raw_send", "tcp_send", "udp_send",
        ]

    def test_below_floor_family_neither_claims_nor_emits(self):
        functions = [_func("tcp_send"), _func("udp_send")]
        groups = _interface_slot_groups(
            [_fam(names=("tcp_send", "udp_send"))], functions,
        )
        assert groups == []

    def test_ambiguous_name_not_misbound(self):
        # Same bare name in two files: the name index excludes it, so
        # the family drops below the floor rather than binding to an
        # arbitrary record.
        functions = [
            _func("tcp_send", file="a.c"),
            _func("tcp_send", file="b.c"),
            _func("udp_send"), _func("raw_send"),
        ]
        groups = _interface_slot_groups([_fam()], functions)
        assert groups == []

    def test_file_keyed_member_joins_exactly(self):
        functions = [
            _func("process", file="src/handlers.py", line=10),
            _func("check", file="src/handlers.py", line=20),
            _func("audit", file="src/handlers.py", line=30),
        ]
        fam = SlotFamily(kind="override_set", key="Base.process",
                         members=[
                             SlotMember("process", "src/handlers.py", 10),
                             SlotMember("check", "src/handlers.py", 20),
                             SlotMember("audit", "src/handlers.py", 30),
                         ])
        groups = _interface_slot_groups([fam], functions)
        assert len(groups) == 1
        assert {s.line for s in groups[0].siblings} == {10, 20, 30}

    def test_member_cap_notes_and_bounds(self):
        n = MAX_INTERFACE_SLOT_MEMBERS + 8
        names = [f"impl_{i:03d}" for i in range(n)]
        functions = [_func(x) for x in names]
        groups = _interface_slot_groups(
            [_fam(names=tuple(names))], functions,
        )
        assert len(groups) == 1
        g = groups[0]
        assert len(g.siblings) == MAX_INTERFACE_SLOT_MEMBERS
        assert "group capped at" in g.shared_context

    def test_hostile_key_escaped(self):
        functions = [
            _func("tcp_send"), _func("udp_send"), _func("raw_send"),
        ]
        fam = _fam(key="evil\x1b[31mops.send")
        groups = _interface_slot_groups([fam], functions)
        assert len(groups) == 1
        assert "\x1b" not in groups[0].group_id
        assert "\x1b" not in groups[0].description
        assert "\\x1b" in groups[0].group_id


# ── resolver placement ────────────────────────────────────────────────


class TestResolverPlacement:
    def test_l7_claims_before_dispatch_layer(self):
        functions = [
            _func("tcp_send"), _func("udp_send"), _func("raw_send"),
        ]

        class _Table:
            function = "dispatch"
            file = "src/net.c"
            handlers = {
                "a": "tcp_send", "b": "udp_send", "c": "raw_send",
            }

        groups = resolve_peer_groups(
            functions,
            dispatch_tables=[_Table()],
            interface_slots=[_fam()],
        )
        types = [
            g.sibling_type if isinstance(g.sibling_type, str)
            else g.sibling_type.value
            for g in groups
        ]
        assert GROUP_TYPE_INTERFACE_SLOT in types
        # The dispatch layer saw nothing unclaimed — L7 claimed all
        # three implementations first.
        assert "dispatch_site" not in types

    def test_no_census_is_equivalence_pinned(self):
        functions = [
            _func("tcp_send"), _func("udp_send"), _func("raw_send"),
        ]
        with_none = resolve_peer_groups(functions, interface_slots=None)
        baseline = resolve_peer_groups(functions)
        assert [g.group_id for g in with_none] == [
            g.group_id for g in baseline
        ]


# ── cross-module pins ─────────────────────────────────────────────────


class TestCrossModulePins:
    def test_group_type_admitted_by_interface_dimension(self):
        from core.audit.consistency_dimensions import (
            _INTERFACE_GROUP_TYPES,
        )
        assert GROUP_TYPE_INTERFACE_SLOT in _INTERFACE_GROUP_TYPES

    def test_claim_floor_matches_the_comparator_floor(self):
        from core.audit.consistency_dimensions import (
            INTERFACE_MIN_GROUP,
        )
        assert MIN_INTERFACE_SLOT_MEMBERS == INTERFACE_MIN_GROUP
