"""Regression tests for ``disguised_filename`` and
``large_obfuscated_artefact``."""

from __future__ import annotations

from pathlib import Path

from packages.sca.supply_chain.artefacts import scan_target


# ---------------------------------------------------------------------------
# disguised_filename
# ---------------------------------------------------------------------------

def test_png_extension_with_elf_content_flagged(tmp_path: Path) -> None:
    """`.png` whose first bytes are ELF — classic payload-disguise shape."""
    (tmp_path / "image.png").write_bytes(
        b"\x7fELF\x02\x01\x01" + b"\x00" * 200
    )
    findings = scan_target(tmp_path, [])
    kinds = [f.kind for f in findings]
    assert "disguised_filename" in kinds
    f = next(x for x in findings if x.kind == "disguised_filename")
    assert "ELF executable" in f.detail
    assert f.severity == "high"


def test_json_extension_with_zip_content_flagged(tmp_path: Path) -> None:
    """A `.json` file whose first bytes are PK (ZIP) is a hidden archive."""
    (tmp_path / "config.json").write_bytes(b"PK\x03\x04" + b"\x00" * 200)
    findings = scan_target(tmp_path, [])
    assert any(f.kind == "disguised_filename" for f in findings)


def test_txt_extension_with_shebang_flagged(tmp_path: Path) -> None:
    """A `.txt` file whose first bytes are `#!/bin/sh` is an executable
    in disguise."""
    (tmp_path / "notes.txt").write_text(
        "#!/bin/sh\necho pwned\n", encoding="utf-8",
    )
    findings = scan_target(tmp_path, [])
    assert any(f.kind == "disguised_filename" for f in findings)


def test_valid_png_not_flagged(tmp_path: Path) -> None:
    """A genuinely correct PNG file (full 8-byte magic) is not flagged."""
    (tmp_path / "logo.png").write_bytes(
        b"\x89PNG\r\n\x1a\n" + b"IHDR" * 100
    )
    findings = scan_target(tmp_path, [])
    assert all(f.kind != "disguised_filename" for f in findings)


def test_valid_json_not_flagged(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text('{"x": 1}', encoding="utf-8")
    findings = scan_target(tmp_path, [])
    assert all(f.kind != "disguised_filename" for f in findings)


def test_text_file_with_null_bytes_flagged(tmp_path: Path) -> None:
    """A `.py` file containing null bytes is binary in disguise."""
    (tmp_path / "evil.py").write_bytes(
        b"# innocent comment\n" + b"\x00" * 200
    )
    findings = scan_target(tmp_path, [])
    assert any(f.kind == "disguised_filename" for f in findings)


def test_extension_not_in_map_not_flagged(tmp_path: Path) -> None:
    """A `.dat` file's extension isn't in our magic map; we don't
    second-guess it."""
    (tmp_path / "blob.dat").write_bytes(b"\x7fELF\x02\x01\x01")
    findings = scan_target(tmp_path, [])
    assert all(f.kind != "disguised_filename" for f in findings)


def test_disguise_check_skips_vendored_dirs(tmp_path: Path) -> None:
    """node_modules legitimately contains binary blobs with text-ish
    extensions (e.g., a checked-in node binary). Skip it."""
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "config.json").write_bytes(
        b"PK\x03\x04" + b"\x00" * 100
    )
    findings = scan_target(tmp_path, [])
    assert findings == []


def test_disguise_check_skips_test_fixtures(tmp_path: Path) -> None:
    """Test trees routinely contain intentionally-misnamed files
    as detector fixtures. ``disguised_filename`` firing on them is
    noise that drowns out real hits — SCA's own fixtures at
    ``packages/sca/tests/fixtures/prompt_injections/*.txt`` (with
    shell-script content) are the canonical case. Skip the rule
    inside any ``tests/`` / ``test/`` / ``__tests__/`` / ``spec/``
    / ``e2e/`` tree. ``binary_in_tests`` still fires there because
    binary-in-test-fixtures IS a known attack pattern."""
    tests_dir = tmp_path / "tests" / "fixtures"
    tests_dir.mkdir(parents=True)
    (tests_dir / "evil.txt").write_text(
        "#!/bin/bash\nrm -rf /\n", encoding="utf-8",
    )
    findings = scan_target(tmp_path, [])
    assert not any(f.kind == "disguised_filename" for f in findings), (
        f"disguised_filename fired inside tests/: {findings}"
    )


# ---------------------------------------------------------------------------
# large_obfuscated_artefact
# ---------------------------------------------------------------------------

def test_minified_js_in_source_flagged(tmp_path: Path) -> None:
    """A 100KB+ .js file whose only line is 100K+ chars long looks
    minified — flag it (outside dist/)."""
    (tmp_path / "src").mkdir()
    payload = b"var _0x1234=function(a,b,c){" + b"a" * 200_000 + b"}"
    (tmp_path / "src" / "app.js").write_bytes(payload)
    findings = scan_target(tmp_path, [])
    assert any(f.kind == "large_obfuscated_artefact" for f in findings)


def test_minified_in_dist_not_flagged(tmp_path: Path) -> None:
    """The same payload inside dist/ is legitimate build output."""
    (tmp_path / "dist").mkdir()
    payload = b"var _0x1234=function(a,b,c){" + b"a" * 200_000 + b"}"
    (tmp_path / "dist" / "bundle.js").write_bytes(payload)
    findings = scan_target(tmp_path, [])
    assert all(f.kind != "large_obfuscated_artefact" for f in findings)


def test_normal_source_file_not_flagged(tmp_path: Path) -> None:
    """A 200KB human-readable .js file with normal line lengths and
    typical entropy is fine."""
    (tmp_path / "src").mkdir()
    body = "function fn(arg) { return arg + 1; }\n" * 5000
    (tmp_path / "src" / "big.js").write_text(body, encoding="utf-8")
    findings = scan_target(tmp_path, [])
    assert all(f.kind != "large_obfuscated_artefact" for f in findings)


def test_small_minified_file_not_flagged(tmp_path: Path) -> None:
    """Below the 100KB size threshold we don't bother with the entropy
    check — false-positive risk on tiny files."""
    (tmp_path / "src").mkdir()
    payload = b"var _0x=function(){" + b"a" * 50_000 + b"}"
    (tmp_path / "src" / "tiny.js").write_bytes(payload)
    findings = scan_target(tmp_path, [])
    assert all(f.kind != "large_obfuscated_artefact" for f in findings)


def test_minified_python_in_source_flagged(tmp_path: Path) -> None:
    """`.py` is also covered — packers generate giant single-line
    Python sometimes."""
    (tmp_path / "lib").mkdir()
    payload = (
        "exec(__import__('zlib').decompress("
        + ("b'" + "x" * 200_000 + "'") + "))"
    ).encode()
    (tmp_path / "lib" / "loader.py").write_bytes(payload)
    findings = scan_target(tmp_path, [])
    assert any(f.kind == "large_obfuscated_artefact" for f in findings)
