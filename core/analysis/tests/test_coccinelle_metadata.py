"""Curated report-ID ownership is shared and cannot grant extra authority."""

from pathlib import Path
import io

import pytest

from core.analysis import coccinelle_metadata as metadata


def _rule(root: Path, name: str, role: str, *aliases: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{name}.cocci"
    path.write_text(f"// @role: {role}\n@r@\n" + "\n".join(
        f'payload = {{"rule": "{alias}"}}' for alias in aliases
    ))
    return path


@pytest.mark.parametrize("header,expected", [
    ("// @role: verification\n@r@\n", "verification"),
    ("\n// prose\n// @role: detection\n@r@\n", "detection"),
    ("// prose\n@r@\n// @role: verification\n", "detection"),
    ("// @role: other\n// @role: verification\n", "detection"),
    ("// @role: verification\n// @role: detection\n", "verification"),
    ("// prose\u2028// @role: verification\n", "detection"),
    ("// prose\r// @role: verification\r@r@\r", "verification"),
    ("\ufeff// @role: verification\n", "detection"),
], ids=["verification", "detection", "trailing", "unknown-first", "first-directive",
        "unicode-not-newline", "physical-cr", "bom-unchanged"])
def test_role_header_preserves_reader_contract(header, expected):
    assert metadata.role_from_header(io.StringIO(header, newline=None)) == expected


def test_role_header_is_not_limited_by_a_byte_prefix():
    header = "// long documentation\n" * 600 + "// @role: verification\n@r@\n"
    assert metadata.role_from_header(io.StringIO(header)) == "verification"


def test_literal_report_ids_share_the_runner_grammar():
    text = '''{"rule": "first.id"}\n{'rule' : 'second:variant-1'}'''
    assert metadata.emitted_rule_ids(text) == {"first.id", "second:variant-1"}


def test_aliases_inherit_owner_role_and_dynamic_rules_remain_distinct(tmp_path):
    _rule(tmp_path, "weak", "detection", "weak_variant")
    _rule(tmp_path, "strong", "verification", "strong_variant")
    for name in ("weak", "weak_variant"):
        assert metadata.curated_rule_role(name, tmp_path) == "detection"
    for name in ("strong", "strong_variant"):
        assert metadata.curated_rule_role(name, tmp_path) == "verification"
    assert metadata.curated_rule_role("hypothesis-generated", tmp_path) is None


@pytest.mark.parametrize("roles", [("verification", "verification"), ("verification", "detection")])
@pytest.mark.parametrize("collision", ["shared_variant", "first"])
def test_conflicting_ownership_is_detection_even_for_a_filename(tmp_path, roles, collision):
    _rule(tmp_path, "first", roles[0], collision)
    _rule(tmp_path, "second", roles[1], collision)
    assert metadata.curated_rule_role(collision, tmp_path) == "detection"


def test_complete_library_is_read_once_and_cached_by_root(tmp_path, monkeypatch):
    root = tmp_path / "one"
    other = tmp_path / "two"
    _rule(root, "owner", "verification", "report")
    _rule(other, "owner", "detection", "report")
    read = metadata.read_text_gated
    reads = []

    def observed(path, *args, **kwargs):
        reads.append(path)
        return read(path, *args, **kwargs)

    monkeypatch.setattr(metadata, "read_text_gated", observed)
    assert metadata.curated_rule_role("report", root) == "verification"
    assert metadata.curated_rule_role("owner", root) == "verification"
    assert metadata.curated_rule_role("unknown", root) is None
    assert metadata.curated_rule_role("report", other) == "detection"
    assert reads == [(root / "owner.cocci").resolve(), (other / "owner.cocci").resolve()]


def test_missing_library_is_conservative_and_retryable(tmp_path):
    root = tmp_path / "missing"
    assert metadata.curated_rule_role("unknown", root) == "detection"
    _rule(root, "owner", "verification", "report")
    assert metadata.curated_rule_role("report", root) == "verification"
    assert metadata.curated_rule_role("unknown", root) is None


@pytest.mark.parametrize("problem", ["encoding", "size", "directory", "symlink"])
def test_incomplete_or_unsafe_metadata_cannot_look_dynamic(tmp_path, monkeypatch, problem):
    root = tmp_path / "rules"
    path = _rule(root, "owner", "verification", "report")
    broken = root / "broken.cocci"
    if problem == "encoding":
        broken.write_bytes(b"\xff")
    elif problem == "size":
        monkeypatch.setattr(metadata, "RULE_MAX_BYTES", 128)
        broken.write_text("x" * 129)
    elif problem == "directory":
        broken.mkdir()
    else:
        outside = tmp_path / "outside"
        outside.write_text('// @role: verification\n{"rule": "forged"}\n')
        broken.symlink_to(outside)
    assert path.is_file()
    assert metadata.curated_rule_role("unknown", root) == "detection"
    assert metadata.curated_rule_role("report", root) == "detection"
    if problem == "directory":
        broken.rmdir()
    else:
        broken.unlink()
    assert metadata.curated_rule_role("report", root) == "verification"


@pytest.mark.parametrize("name", ["../outside", "/absolute", "with/slash", "with\\slash", "bad\x00id"])
def test_receipt_ids_do_not_become_filesystem_paths(tmp_path, name):
    _rule(tmp_path, "owner", "verification")
    assert metadata.curated_rule_role(name, tmp_path) == "detection"
