"""Textual guard receipts cannot equate case, literals or typed operations."""
import pytest

from core.analysis.lifecycle_checker import check_coverage, check_coverage_with_cfg
from core.analysis.lifecycle_model import Guard, ReadSite, StateField, WriteSite


def _field(write, read, *, write_polarity=True, read_polarity=True):
    return StateField(name="field", struct_type="State", invariant="guard required",
        write_sites=[WriteSite(file="owned.c", line=3, function="handle",
                     guards=frozenset({Guard(write, "owned.c", 2, polarity=write_polarity)}))],
        read_sites=[ReadSite(file="owned.c", line=7, function="handle",
                    guards=frozenset({Guard(read, "owned.c", 6, polarity=read_polarity)}))])


@pytest.mark.parametrize("write,read", [
    ("AUTH", "auth"), ('role == "ADMIN"', 'role == "admin"'),
    ('label == "a  b"', 'label == "a b"'),
    ("pointer", "pointer != NULL"), ("value", "value != 0"),
])
def test_distinct_guard_texts_do_not_close_coverage(write, read):
    findings = check_coverage(_field(write, read))
    assert len(findings) == 1
    assert write in findings[0].missing_guards


def test_identical_guard_and_polarity_retains_coverage():
    assert check_coverage(_field("AUTH", "AUTH")) == []


def test_native_cpp_coverage_preserves_required_false_arm():
    pytest.importorskip("tree_sitter_c")
    from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg

    source = "void handle(int auth) {\n if (auth) {\n  consume();\n }\n}\n"
    cfg = build_cpp_intraproc_cfg(source, "handle", language="c")
    assert cfg is not None
    field = _field("auth", "auth", write_polarity=False)
    field.read_sites[0] = ReadSite(file="owned.c", line=3, function="handle",
                                  guards=frozenset({Guard("auth", "owned.c", 2)}))
    assert len(check_coverage_with_cfg(field, cfg, cfg_file="owned.c")) == 1


def test_native_unknown_epoch_cannot_be_overridden_by_model_text():
    pytest.importorskip("tree_sitter_c")
    from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg

    source = "void handle(int auth) {\n if (auth) {\n  auth = 0;\n  consume();\n }\n}\n"
    cfg = build_cpp_intraproc_cfg(source, "handle", language="c")
    assert cfg is not None
    field = _field("auth", "auth")
    field.read_sites[0] = ReadSite(file="owned.c", line=4, function="handle",
                                  guards=frozenset({Guard("auth", "owned.c", 2)}))
    assert len(check_coverage_with_cfg(field, cfg, cfg_file="owned.c")) == 1


@pytest.mark.parametrize("polarity", [True, False])
def test_native_matching_arm_retains_coverage(polarity):
    pytest.importorskip("tree_sitter_c")
    from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
    from core.analysis.guard_bypass import check_guard_coverage

    middle = " if (auth) {\n  consume();\n }\n" if polarity else " if (auth) return;\n consume();\n"
    source = "void handle(int auth) {\n" + middle + "}\n"
    cfg = build_cpp_intraproc_cfg(source, "handle", language="c")
    assert cfg is not None
    assert check_guard_coverage(cfg, 3, "auth", required_polarity=polarity)
    assert not check_guard_coverage(cfg, 3, "auth", required_polarity=not polarity)


def test_legacy_source_guard_matching_remains_case_sensitive():
    from core.analysis.cfg_builder import build_python_cfg
    from core.analysis.guard_bypass import check_guard_coverage

    source = "def handle(auth):\n    if auth:\n        consume()\n"
    cfg = build_python_cfg(source, "handle")
    assert cfg is not None
    assert check_guard_coverage(cfg, 3, "auth")
    assert not check_guard_coverage(cfg, 3, "AUTH")


@pytest.mark.parametrize("bad", [0, "false", None])
def test_non_boolean_polarity_cannot_close_coverage(bad):
    from core.analysis.lifecycle_checker import _guard_covers

    assert not _guard_covers(Guard("auth", "owned.c", 1, polarity=bad),
                             Guard("auth", "owned.c", 1, polarity=False))


def test_empty_text_does_not_establish_a_guard():
    assert len(check_coverage(_field("", ""))) == 1
