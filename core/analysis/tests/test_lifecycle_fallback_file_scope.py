"""Textual CFG fallback retains the requested read-site file boundary."""
from core.analysis.lifecycle_checker import check_all_fields, check_coverage_with_cfg
from core.analysis.lifecycle_model import Guard, ReadSite, StateField, WriteSite


def _field():
    return StateField(
        name="state", struct_type="Owned", invariant="requires ready",
        write_sites=[WriteSite("writer.c", 3, "write", frozenset({
            Guard("ready", "writer.c", 2),
        }))],
        read_sites=[
            ReadSite("a.c", 10, "read_a", frozenset()),
            ReadSite("b.c", 20, "read_b", frozenset()),
        ],
    )


def test_cfg_fallback_limits_findings_to_requested_file():
    findings = check_coverage_with_cfg(_field(), object(), cfg_file="a.c")
    assert [f.read_site.file for f in findings] == ["a.c"]


def test_all_fields_fallback_emits_each_site_once():
    findings = check_all_fields([_field()], cfgs={"a.c": object(), "b.c": object()})
    assert [(f.read_site.file, f.read_site.line) for f in findings] == [
        ("a.c", 10), ("b.c", 20),
    ]


def test_unscoped_fallback_keeps_all_sites():
    assert len(check_coverage_with_cfg(_field(), object())) == 2
