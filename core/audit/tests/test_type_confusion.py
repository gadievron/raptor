"""Tests for core.audit.type_confusion — deser → virtual dispatch detection."""

from core.audit.type_confusion import (
    _build_type_index,
    _find_deser_sources,
    _find_virtual_dispatch_sites,
    detect_type_confusion,
)
from core.inventory.call_graph import CallSite, ClassDef, FileCallGraph


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cg(calls=None, classes=None):
    """Build a FileCallGraph with calls and optional ClassDef data."""
    sites = []
    for entry in (calls or []):
        if len(entry) == 3:
            caller, chain, line = entry
            sites.append(CallSite(line=line, chain=chain, caller=caller))
        elif len(entry) == 4:
            caller, chain, line, recv = entry
            sites.append(CallSite(
                line=line, chain=chain, caller=caller,
                receiver_type=recv,
            ))
    return FileCallGraph(calls=sites, classes=classes or [])


# ---------------------------------------------------------------------------
# Type index
# ---------------------------------------------------------------------------


class TestBuildTypeIndex:
    def test_single_inheritance(self):
        graphs = {
            "auth.py": _cg(classes=[
                ClassDef(name="Base", line=1, bases=[], methods=[("check", 5)]),
                ClassDef(name="Sub", line=20, bases=["Base"],
                         methods=[("check", 25), ("extra", 30)]),
            ]),
        }
        idx = _build_type_index(graphs)
        assert "Sub" in idx.parent_to_children["Base"]
        assert "check" in idx.class_methods["Base"]
        assert "check" in idx.class_methods["Sub"]
        assert "extra" in idx.class_methods["Sub"]

    def test_multi_level(self):
        graphs = {
            "a.py": _cg(classes=[
                ClassDef(name="A", line=1, bases=[], methods=[("m", 5)]),
                ClassDef(name="B", line=10, bases=["A"], methods=[]),
                ClassDef(name="C", line=20, bases=["B"], methods=[("m", 25)]),
            ]),
        }
        idx = _build_type_index(graphs)
        assert "B" in idx.parent_to_children["A"]
        assert "C" in idx.parent_to_children["B"]

    def test_dotted_base(self):
        graphs = {
            "a.py": _cg(classes=[
                ClassDef(name="Sub", line=1, bases=["some_module.Base"],
                         methods=[("m", 5)]),
            ]),
        }
        idx = _build_type_index(graphs)
        assert "Sub" in idx.parent_to_children["Base"]

    def test_empty_call_graphs(self):
        idx = _build_type_index({})
        assert not idx.parent_to_children
        assert not idx.class_methods

    def test_root_classes_excluded(self):
        graphs = {
            "a.py": _cg(classes=[
                ClassDef(name="MyError", line=1, bases=["Exception"],
                         methods=[("msg", 5)]),
                ClassDef(name="Foo", line=10, bases=["object"],
                         methods=[("run", 15)]),
            ]),
        }
        idx = _build_type_index(graphs)
        assert "Exception" not in idx.parent_to_children
        assert "object" not in idx.parent_to_children


# ---------------------------------------------------------------------------
# Deserialization source detection
# ---------------------------------------------------------------------------


class TestFindDeserSources:
    def test_pickle_loads(self):
        graphs = {
            "handler.py": _cg(calls=[
                ("process", ["pickle", "loads"], 10),
            ]),
        }
        sources = _find_deser_sources(graphs)
        assert len(sources) == 1
        assert sources[0] == ("handler.py", "process", "pickle.loads", 10)

    def test_json_parse(self):
        graphs = {
            "app.js": _cg(calls=[
                ("handleInput", ["JSON", "parse"], 5),
            ]),
        }
        sources = _find_deser_sources(graphs)
        assert len(sources) == 1
        assert sources[0][2] == "JSON.parse"

    def test_qualified_tail_match(self):
        graphs = {
            "app.java": _cg(calls=[
                ("read", ["stream", "ObjectInputStream", "readObject"], 20),
            ]),
        }
        sources = _find_deser_sources(graphs)
        assert len(sources) == 1
        assert sources[0][2] == "ObjectInputStream.readObject"

    def test_non_deser_not_matched(self):
        graphs = {
            "util.py": _cg(calls=[
                ("fetch", ["requests", "get"], 10),
                ("parse", ["json", "dumps"], 20),
            ]),
        }
        sources = _find_deser_sources(graphs)
        assert sources == []

    def test_empty_graphs(self):
        assert _find_deser_sources({}) == []


# ---------------------------------------------------------------------------
# Virtual dispatch site detection
# ---------------------------------------------------------------------------


class TestFindVirtualDispatchSites:
    def test_receiver_type_dispatch(self):
        graphs = {
            "handler.java": _cg(
                calls=[
                    ("process", ["validate"], 10, "BaseAuth"),
                ],
                classes=[
                    ClassDef(name="BaseAuth", line=1, bases=[],
                             methods=[("validate", 5)]),
                    ClassDef(name="PermissiveAuth", line=20,
                             bases=["BaseAuth"],
                             methods=[("validate", 25)]),
                ],
            ),
        }
        idx = _build_type_index(graphs)
        sites = _find_virtual_dispatch_sites(graphs, idx)
        assert len(sites) == 1
        assert sites[0][3] == "BaseAuth"
        assert sites[0][4] == "validate"
        assert "PermissiveAuth" in sites[0][5]

    def test_self_dispatch(self):
        graphs = {
            "auth.py": _cg(
                calls=[
                    ("check_auth", ["self", "validate"], 10),
                ],
                classes=[
                    ClassDef(name="BaseAuth", line=1, bases=[],
                             methods=[("check_auth", 3), ("validate", 5)]),
                    ClassDef(name="WeakAuth", line=20, bases=["BaseAuth"],
                             methods=[("validate", 25)]),
                ],
            ),
        }
        idx = _build_type_index(graphs)
        sites = _find_virtual_dispatch_sites(graphs, idx)
        assert len(sites) == 1
        assert sites[0][4] == "validate"
        assert "WeakAuth" in sites[0][5]

    def test_transitive_subtype_dispatch(self):
        """Base → Middle → Evil: only Evil overrides, must still be found."""
        graphs = {
            "auth.py": _cg(
                calls=[
                    ("process", ["validate"], 10, "Base"),
                ],
                classes=[
                    ClassDef(name="Base", line=1, bases=[],
                             methods=[("validate", 5)]),
                    ClassDef(name="Middle", line=20, bases=["Base"],
                             methods=[("helper", 25)]),
                    ClassDef(name="Evil", line=40, bases=["Middle"],
                             methods=[("validate", 45)]),
                ],
            ),
        }
        idx = _build_type_index(graphs)
        sites = _find_virtual_dispatch_sites(graphs, idx)
        assert len(sites) == 1
        assert "Evil" in sites[0][5]

    def test_self_dispatch_multi_class_same_method(self):
        """Two classes define same method in one file — both checked."""
        graphs = {
            "auth.py": _cg(
                calls=[
                    ("validate", ["self", "check"], 10),
                ],
                classes=[
                    ClassDef(name="AuthA", line=1, bases=[],
                             methods=[("validate", 3), ("check", 5)]),
                    ClassDef(name="AuthB", line=20, bases=[],
                             methods=[("validate", 23), ("check", 25)]),
                    ClassDef(name="WeakA", line=40, bases=["AuthA"],
                             methods=[("check", 45)]),
                ],
            ),
        }
        idx = _build_type_index(graphs)
        sites = _find_virtual_dispatch_sites(graphs, idx)
        assert len(sites) >= 1
        all_overriders = []
        for s in sites:
            all_overriders.extend(s[5])
        assert "WeakA" in all_overriders

    def test_no_override_no_site(self):
        graphs = {
            "auth.py": _cg(
                calls=[
                    ("process", ["validate"], 10, "BaseAuth"),
                ],
                classes=[
                    ClassDef(name="BaseAuth", line=1, bases=[],
                             methods=[("validate", 5)]),
                    ClassDef(name="Sub", line=20, bases=["BaseAuth"],
                             methods=[("other", 25)]),
                ],
            ),
        }
        idx = _build_type_index(graphs)
        sites = _find_virtual_dispatch_sites(graphs, idx)
        assert sites == []


# ---------------------------------------------------------------------------
# Full detector
# ---------------------------------------------------------------------------


class TestDetectTypeConfusion:
    def test_deser_to_dispatch_same_function(self):
        graphs = {
            "handler.py": _cg(
                calls=[
                    ("process", ["pickle", "loads"], 10),
                    ("process", ["self", "validate"], 20),
                ],
                classes=[
                    ClassDef(name="Handler", line=1, bases=[],
                             methods=[("process", 3), ("validate", 5)]),
                    ClassDef(name="UnsafeHandler", line=30,
                             bases=["Handler"],
                             methods=[("validate", 35)]),
                ],
            ),
        }
        findings = detect_type_confusion({}, graphs)
        assert len(findings) == 1
        assert findings[0].deser_source == "pickle.loads"
        assert findings[0].overridden_method == "validate"
        assert "UnsafeHandler" in findings[0].overriding_subtypes

    def test_deser_to_dispatch_cross_function(self):
        graphs = {
            "app.py": _cg(
                calls=[
                    ("load_data", ["yaml", "load"], 10),
                    ("load_data", ["process"], 15),
                    ("process", ["self", "validate"], 20),
                ],
                classes=[
                    ClassDef(name="App", line=1, bases=[],
                             methods=[("load_data", 3), ("process", 8),
                                      ("validate", 12)]),
                    ClassDef(name="WeakApp", line=40, bases=["App"],
                             methods=[("validate", 45)]),
                ],
            ),
        }
        findings = detect_type_confusion({}, graphs)
        assert len(findings) >= 1
        methods = {f.overridden_method for f in findings}
        assert "validate" in methods

    def test_describe_names_deser_origin(self):
        """In the transitive case the dispatch site is a different
        function from the deser site — describe() must name both so
        the taint origin can be located from the finding record."""
        graphs = {
            "app.py": _cg(
                calls=[
                    ("load_data", ["yaml", "load"], 10),
                    ("load_data", ["process"], 15),
                    ("process", ["self", "validate"], 20),
                ],
                classes=[
                    ClassDef(name="App", line=1, bases=[],
                             methods=[("load_data", 3), ("process", 8),
                                      ("validate", 12)]),
                    ClassDef(name="WeakApp", line=40, bases=["App"],
                             methods=[("validate", 45)]),
                ],
            ),
        }
        findings = detect_type_confusion({}, graphs)
        transitive = [f for f in findings if f.function != f.deser_function]
        assert transitive, f"expected a transitive finding: {findings}"
        desc = transitive[0].describe()
        assert "deserialised in load_data()" in desc
        assert "yaml.load" in desc
        assert "virtual dispatch of validate()" in desc
        assert "WeakApp" in desc

    def test_no_deser_no_finding(self):
        graphs = {
            "auth.py": _cg(
                calls=[
                    ("process", ["self", "validate"], 10),
                ],
                classes=[
                    ClassDef(name="Base", line=1, bases=[],
                             methods=[("process", 3), ("validate", 5)]),
                    ClassDef(name="Sub", line=20, bases=["Base"],
                             methods=[("validate", 25)]),
                ],
            ),
        }
        findings = detect_type_confusion({}, graphs)
        assert findings == []

    def test_no_hierarchy_no_finding(self):
        graphs = {
            "handler.py": _cg(
                calls=[
                    ("process", ["pickle", "loads"], 10),
                    ("process", ["validate"], 20),
                ],
                classes=[
                    ClassDef(name="Handler", line=1, bases=[],
                             methods=[("process", 3), ("validate", 5)]),
                ],
            ),
        }
        findings = detect_type_confusion({}, graphs)
        assert findings == []

    def test_transitive_deser_to_dispatch(self):
        """Base → Middle → Evil: deser + dispatch must find Evil."""
        graphs = {
            "handler.py": _cg(
                calls=[
                    ("process", ["pickle", "loads"], 10),
                    ("process", ["self", "validate"], 20),
                ],
                classes=[
                    ClassDef(name="Handler", line=1, bases=[],
                             methods=[("process", 3), ("validate", 5)]),
                    ClassDef(name="Middle", line=30, bases=["Handler"],
                             methods=[("helper", 35)]),
                    ClassDef(name="EvilHandler", line=50,
                             bases=["Middle"],
                             methods=[("validate", 55)]),
                ],
            ),
        }
        findings = detect_type_confusion({}, graphs)
        assert len(findings) >= 1
        all_subtypes = []
        for f in findings:
            all_subtypes.extend(f.overriding_subtypes)
        assert "EvilHandler" in all_subtypes

    def test_none_call_graphs(self):
        assert detect_type_confusion({}, None) == []

    def test_empty_call_graphs(self):
        assert detect_type_confusion({}, {}) == []


# ---------------------------------------------------------------------------
# Per-enclosing-class dedup
# ---------------------------------------------------------------------------


def _graphs_two_classes_same_method():
    """One file, two class hierarchies sharing method names.

    Both BaseA and BaseB define ``handler`` (the caller) and
    ``process`` (dispatched via self); each has one subtype
    overriding ``process``.
    """
    return {
        "m.py": _cg(
            calls=[
                ("handler", ["pickle", "loads"], 5),
                ("handler", ["self", "process"], 10),
            ],
            classes=[
                ClassDef(name="BaseA", line=1, bases=[],
                         methods=[("handler", 2), ("process", 3)]),
                ClassDef(name="BaseB", line=20, bases=[],
                         methods=[("handler", 21), ("process", 22)]),
                ClassDef(name="SubA", line=40, bases=["BaseA"],
                         methods=[("process", 41)]),
                ClassDef(name="SubB", line=50, bases=["BaseB"],
                         methods=[("process", 51)]),
            ],
        ),
    }


class TestPerClassDedup:
    """Two classes in one file defining the same method name yield
    per-class dispatch findings at the same call site (the dedup key
    carries the enclosing class), while true duplicates still dedup."""

    def test_both_enclosing_classes_emit_findings(self):
        findings = detect_type_confusion({}, _graphs_two_classes_same_method())
        assert len(findings) == 2
        base_types = {f.base_type for f in findings}
        assert base_types == {"BaseA", "BaseB"}
        for f in findings:
            assert f.file == "m.py"
            assert f.function == "handler"
            assert f.line == 10
            assert f.overridden_method == "process"
        by_base = {f.base_type: f for f in findings}
        assert by_base["BaseA"].overriding_subtypes == ["SubA"]
        assert by_base["BaseB"].overriding_subtypes == ["SubB"]

    def test_true_duplicates_still_dedup(self):
        graphs = _graphs_two_classes_same_method()
        # Duplicate the dispatch call site verbatim: same file, caller,
        # line, and enclosing classes — must not double the findings.
        graphs["m.py"].calls.append(
            CallSite(line=10, chain=["self", "process"], caller="handler"),
        )
        findings = detect_type_confusion({}, graphs)
        assert len(findings) == 2
        assert {f.base_type for f in findings} == {"BaseA", "BaseB"}

    def test_single_class_unaffected(self):
        graphs = {
            "s.py": _cg(
                calls=[
                    ("handler", ["pickle", "loads"], 3),
                    ("handler", ["self", "process"], 7),
                ],
                classes=[
                    ClassDef(name="Base", line=1, bases=[],
                             methods=[("handler", 2), ("process", 3)]),
                    ClassDef(name="Sub", line=20, bases=["Base"],
                             methods=[("process", 21)]),
                ],
            ),
        }
        findings = detect_type_confusion({}, graphs)
        assert len(findings) == 1
        assert findings[0].base_type == "Base"


# ---------------------------------------------------------------------------
# Safety contract compliance
# ---------------------------------------------------------------------------


class TestContractCompliance:
    def test_assert_boost_only_succeeds(self):
        from core.audit.safety_contract import assert_boost_only
        assert_boost_only("type_confusion")

    def test_suppress_evidence_raises(self):
        import pytest
        from core.audit.safety_contract import ContractViolation, SuppressEvidence
        with pytest.raises(ContractViolation):
            SuppressEvidence(
                source="type_confusion",
                verdict="no_confusion",
                reason="test",
            )

    def test_boost_evidence_allowed(self):
        from core.audit.safety_contract import BoostEvidence
        ev = BoostEvidence(
            source="type_confusion",
            action="add_finding",
            description="deser object reaches virtual dispatch",
        )
        assert ev.source == "type_confusion"
        assert ev.action == "add_finding"


# ---------------------------------------------------------------------------
# Adversarial blind spots
# ---------------------------------------------------------------------------


class TestBlindSpots:
    def test_no_findings_returns_empty_not_suppression(self):
        graphs = {
            "safe.py": _cg(
                calls=[("process", ["validate"], 10)],
                classes=[
                    ClassDef(name="Base", line=1, bases=[],
                             methods=[("validate", 5)]),
                ],
            ),
        }
        findings = detect_type_confusion({}, graphs)
        assert findings == []

    def test_name_collision_produces_noise_not_silence(self):
        graphs = {
            "a.py": _cg(
                calls=[
                    ("load", ["pickle", "loads"], 10),
                    ("load", ["self", "validate"], 20),
                ],
                classes=[
                    ClassDef(name="Base", line=1, bases=[],
                             methods=[("load", 3), ("validate", 5)]),
                ],
            ),
            "b.py": _cg(
                classes=[
                    ClassDef(name="Sub", line=1, bases=["Base"],
                             methods=[("validate", 10)]),
                ],
            ),
        }
        findings = detect_type_confusion({}, graphs)
        assert len(findings) >= 1

    def test_missing_receiver_type_falls_back(self):
        graphs = {
            "handler.py": _cg(
                calls=[
                    ("process", ["pickle", "loads"], 10),
                    ("process", ["self", "validate"], 20),
                ],
                classes=[
                    ClassDef(name="Handler", line=1, bases=[],
                             methods=[("process", 3), ("validate", 5)]),
                    ClassDef(name="UnsafeHandler", line=30,
                             bases=["Handler"],
                             methods=[("validate", 35)]),
                ],
            ),
        }
        findings = detect_type_confusion({}, graphs)
        assert len(findings) >= 1
        assert all(f.confidence == "medium" for f in findings)
