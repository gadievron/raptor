"""Tests for Rust crate-module-tree membership resolution.

``#[path = "…"]`` values come from the analysed (untrusted) sources, so
candidates resolving outside the repo root must never be probed, read, or
added to the reachable set — including via symlinks.
"""

from __future__ import annotations

import os

import pytest

from core.build.rust_modules import extract_rust_crate_modules

_CARGO = '[package]\nname = "x"\nversion = "0.1.0"\n'


def _crate(tmp_path, files):
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)


def _r(tmp_path, rel):
    return str((tmp_path / rel).resolve())


def test_none_without_cargo_toml(tmp_path):
    _crate(tmp_path, {"src/lib.rs": "pub fn a(){}\n"})
    assert extract_rust_crate_modules(tmp_path) is None  # not a crate → unknown


def test_reachable_modules_from_lib_root(tmp_path):
    _crate(tmp_path, {
        "Cargo.toml": _CARGO,
        "src/lib.rs": "mod util;\nmod net;\n",
        "src/util.rs": "",               # foo.rs form
        "src/net/mod.rs": "",            # foo/mod.rs form
        "src/orphan.rs": "",             # not declared anywhere
    })
    mods = extract_rust_crate_modules(tmp_path)
    assert _r(tmp_path, "src/lib.rs") in mods
    assert _r(tmp_path, "src/util.rs") in mods
    assert _r(tmp_path, "src/net/mod.rs") in mods
    assert _r(tmp_path, "src/orphan.rs") not in mods


def test_nested_mod_uses_stem_subdir(tmp_path):
    # A non-mod.rs module file foo.rs searches the foo/ subdirectory for its
    # own submodules (Rust 2018 layout).
    _crate(tmp_path, {
        "Cargo.toml": _CARGO,
        "src/main.rs": "mod foo;\n",
        "src/foo.rs": "mod bar;\n",
        "src/foo/bar.rs": "",
    })
    mods = extract_rust_crate_modules(tmp_path)
    assert _r(tmp_path, "src/foo/bar.rs") in mods


def test_path_attribute_override(tmp_path):
    _crate(tmp_path, {
        "Cargo.toml": _CARGO,
        "src/lib.rs": '#[path = "custom/thing.rs"]\nmod thing;\n',
        "src/custom/thing.rs": "",
    })
    mods = extract_rust_crate_modules(tmp_path)
    assert _r(tmp_path, "src/custom/thing.rs") in mods


def test_inline_mod_is_not_a_file(tmp_path):
    # `mod inner { … }` (no trailing ;) declares no file — must not be treated
    # as a file mod, and must not crash.
    _crate(tmp_path, {
        "Cargo.toml": _CARGO,
        "src/lib.rs": "mod inner { pub fn z(){} }\nmod real;\n",
        "src/real.rs": "",
    })
    mods = extract_rust_crate_modules(tmp_path)
    assert _r(tmp_path, "src/real.rs") in mods


def test_bin_and_examples_are_roots(tmp_path):
    _crate(tmp_path, {
        "Cargo.toml": _CARGO,
        "src/bin/tool.rs": "fn main(){}\n",
        "examples/demo.rs": "fn main(){}\n",
        "src/orphan.rs": "",          # no lib/main root reaches it
    })
    mods = extract_rust_crate_modules(tmp_path)
    assert _r(tmp_path, "src/bin/tool.rs") in mods
    assert _r(tmp_path, "examples/demo.rs") in mods
    assert _r(tmp_path, "src/orphan.rs") not in mods


def test_commented_mod_ignored(tmp_path):
    _crate(tmp_path, {
        "Cargo.toml": _CARGO,
        "src/lib.rs": "// mod ghost;\n/* mod ghost2; */\nmod real;\n",
        "src/real.rs": "",
        "src/ghost.rs": "",
    })
    mods = extract_rust_crate_modules(tmp_path)
    assert _r(tmp_path, "src/real.rs") in mods
    assert _r(tmp_path, "src/ghost.rs") not in mods


def test_absolute_path_attr_stays_out_of_reachable(tmp_path):
    # Absolute #[path] discards the join base entirely — must not leak the
    # out-of-tree file into the crate-membership set.
    outside = tmp_path / "outside" / "secret.rs"
    outside.parent.mkdir(parents=True)
    outside.write_text("mod pulled_in;\n")
    crate = tmp_path / "crate"
    _crate(crate, {
        "Cargo.toml": _CARGO,
        "src/lib.rs": f'#[path = "{outside}"]\nmod thing;\nmod real;\n',
        "src/real.rs": "",
    })
    mods = extract_rust_crate_modules(crate)
    assert str(outside.resolve()) not in mods
    assert _r(crate, "src/real.rs") in mods  # rest of the crate unaffected


def test_dotdot_path_attr_stays_out_of_reachable(tmp_path):
    outside = tmp_path / "outside" / "escape.rs"
    outside.parent.mkdir(parents=True)
    outside.write_text("")
    crate = tmp_path / "crate"
    _crate(crate, {
        "Cargo.toml": _CARGO,
        "src/lib.rs": '#[path = "../../outside/escape.rs"]\nmod esc;\n'
                      "mod real;\n",
        "src/real.rs": "",
    })
    mods = extract_rust_crate_modules(crate)
    assert str(outside.resolve()) not in mods
    assert _r(crate, "src/real.rs") in mods


def test_out_of_tree_file_mods_are_not_traversed(tmp_path):
    # An escaped file must not act as a springboard: mods it declares must
    # not be resolved (even ones that would land back inside the crate).
    outside = tmp_path / "outside" / "spring.rs"
    outside.parent.mkdir(parents=True)
    outside.write_text("mod victim;\n")
    crate = tmp_path / "crate"
    _crate(crate, {
        "Cargo.toml": _CARGO,
        "src/lib.rs": '#[path = "../../outside/spring.rs"]\nmod s;\n',
        "src/victim.rs": "",
    })
    mods = extract_rust_crate_modules(crate)
    assert mods is not None
    assert str(outside.resolve()) not in mods
    assert _r(crate, "src/victim.rs") not in mods


def test_symlink_escape_via_path_attr_rejected(tmp_path):
    # Confinement is symlink-aware: an in-repo #[path] target that is a link
    # pointing outside the root must be rejected, not read.
    outside = tmp_path / "outside" / "linked.rs"
    outside.parent.mkdir(parents=True)
    outside.write_text("")
    crate = tmp_path / "crate"
    _crate(crate, {
        "Cargo.toml": _CARGO,
        "src/lib.rs": '#[path = "linked.rs"]\nmod ln;\nmod real;\n',
        "src/real.rs": "",
    })
    os.symlink(outside, crate / "src" / "linked.rs")
    mods = extract_rust_crate_modules(crate)
    assert str(outside.resolve()) not in mods
    assert str((crate / "src" / "linked.rs")) not in {str(m) for m in mods}
    assert _r(crate, "src/real.rs") in mods


def test_symlink_escape_via_plain_mod_rejected(tmp_path):
    # Same mechanism without #[path]: mod NAME; whose file is a symlink out.
    outside = tmp_path / "outside" / "evil.rs"
    outside.parent.mkdir(parents=True)
    outside.write_text("")
    crate = tmp_path / "crate"
    _crate(crate, {
        "Cargo.toml": _CARGO,
        "src/lib.rs": "mod evil;\nmod real;\n",
        "src/real.rs": "",
    })
    os.symlink(outside, crate / "src" / "evil.rs")
    mods = extract_rust_crate_modules(crate)
    assert str(outside.resolve()) not in mods
    assert _r(crate, "src/real.rs") in mods


def test_symlinked_root_out_of_tree_is_skipped(tmp_path):
    # A crate root that resolves outside the repo is not read; with no other
    # roots the membership set is unknown (None), never an out-of-tree path.
    outside = tmp_path / "outside" / "lib.rs"
    outside.parent.mkdir(parents=True)
    outside.write_text("mod anything;\n")
    crate = tmp_path / "crate"
    _crate(crate, {"Cargo.toml": _CARGO})
    (crate / "src").mkdir()
    os.symlink(outside, crate / "src" / "lib.rs")
    assert extract_rust_crate_modules(crate) is None


def test_in_repo_path_attr_still_resolves(tmp_path):
    # Regression guard: legitimate relative #[path] inside the repo keeps
    # working after confinement, including subdir traversal within the root.
    crate = tmp_path / "crate"
    _crate(crate, {
        "Cargo.toml": _CARGO,
        "src/lib.rs": '#[path = "custom/thing.rs"]\nmod thing;\n',
        "src/custom/thing.rs": '#[path = "../deeper.rs"]\nmod deeper;\n',
        "src/deeper.rs": "",
    })
    mods = extract_rust_crate_modules(crate)
    assert _r(crate, "src/custom/thing.rs") in mods
    assert _r(crate, "src/deeper.rs") in mods


def test_all_reachable_paths_confined_to_root(tmp_path):
    # Property: every returned path lies under the resolved repo root, even
    # with hostile #[path] values mixed in.
    outside = tmp_path / "outside" / "x.rs"
    outside.parent.mkdir(parents=True)
    outside.write_text("")
    crate = tmp_path / "crate"
    _crate(crate, {
        "Cargo.toml": _CARGO,
        "src/lib.rs": (
            f'#[path = "{outside}"]\nmod a;\n'
            '#[path = "../../outside/x.rs"]\nmod b;\n'
            "mod real;\n"
        ),
        "src/real.rs": "",
    })
    root = str(crate.resolve())
    mods = extract_rust_crate_modules(crate)
    assert mods
    assert all(m.startswith(root + os.sep) for m in mods)


def test_nul_byte_path_attr_is_rejected_not_crash(tmp_path):
    crate = tmp_path / "crate"
    _crate(crate, {
        "Cargo.toml": _CARGO,
        "src/lib.rs": '#[path = "bad\x00name.rs"]\nmod bad;\nmod real;\n',
        "src/real.rs": "",
    })
    mods = extract_rust_crate_modules(crate)
    assert _r(crate, "src/real.rs") in mods


def test_oversize_rs_file_read_capped_not_loaded_whole(tmp_path, monkeypatch):
    # The walk runs in the unsandboxed parent over untrusted sources:
    # a planted huge .rs must be read through the capped chokepoint.
    # Decls before the cap survive; decls past it are dropped
    # (under-detection — membership stays sound).
    from core.build import rust_modules

    monkeypatch.setattr(rust_modules, "_MAX_RS_BYTES", 4096)
    (tmp_path / "Cargo.toml").write_text("[package]\nname='x'\n")
    src = tmp_path / "src"
    src.mkdir()
    filler = "// pad\n" * 1024  # > 4096 bytes
    (src / "lib.rs").write_text("mod early;\n" + filler + "mod late;\n")
    (src / "early.rs").write_text("")
    (src / "late.rs").write_text("")
    result = rust_modules.extract_rust_crate_modules(tmp_path)
    assert result is not None
    assert str((src / "early.rs").resolve()) in result
    assert str((src / "late.rs").resolve()) not in result


def test_reachable_cap_degrades_to_unknown(tmp_path, monkeypatch):
    # Past the reachable-file cap membership is UNKNOWN (None) — the
    # conservative direction: no module-based suppression rather than
    # a truncated (wrong) membership set.
    from core.build import rust_modules

    monkeypatch.setattr(rust_modules, "_MAX_REACHABLE_FILES", 2)
    (tmp_path / "Cargo.toml").write_text("[package]\nname='x'\n")
    src = tmp_path / "src"
    src.mkdir()
    (src / "lib.rs").write_text("mod a;\nmod b;\nmod c;\n")
    for name in "abc":
        (src / f"{name}.rs").write_text("")
    assert rust_modules.extract_rust_crate_modules(tmp_path) is None


# ---------------------------------------------------------------------------
# Code-view fidelity: the mod scan must see code the compiler sees and
# nothing it doesn't — strings are data, block comments nest, and the
# fallback scanner is linear on hostile input.
# ---------------------------------------------------------------------------

class TestCodeViewFidelity:
    def test_line_comment_inside_string_keeps_the_mod_edge(self, tmp_path):
        """`//` inside a string literal is data: a same-line ``mod``
        decl after it is compiled by rustc and must stay a member —
        the string-blind stripper marked real.rs build-excluded."""
        _crate(tmp_path, {
            "Cargo.toml": _CARGO,
            "src/lib.rs": 'const U: &str = "see https://x"; mod real;\n'
                          "mod plain;\n",
            "src/real.rs": "",
            "src/plain.rs": "",
        })
        mods = extract_rust_crate_modules(tmp_path)
        assert _r(tmp_path, "src/real.rs") in mods
        assert _r(tmp_path, "src/plain.rs") in mods

    def test_mod_inside_string_is_not_an_edge(self, tmp_path):
        _crate(tmp_path, {
            "Cargo.toml": _CARGO,
            "src/lib.rs": 'const S: &str = "mod fake;";\nmod real;\n',
            "src/fake.rs": "",
            "src/real.rs": "",
        })
        mods = extract_rust_crate_modules(tmp_path)
        assert _r(tmp_path, "src/real.rs") in mods
        assert _r(tmp_path, "src/fake.rs") not in mods

    def test_nested_block_comment_hides_its_mod(self, tmp_path):
        """Rust block comments NEST: the non-greedy `/* … */` stripper
        closed at the INNER terminator and leaked the still-commented
        ``mod hidden;`` back into the scan."""
        _crate(tmp_path, {
            "Cargo.toml": _CARGO,
            "src/lib.rs": "/* /* inner */ mod hidden; */\nmod real;\n",
            "src/hidden.rs": "",
            "src/real.rs": "",
        })
        mods = extract_rust_crate_modules(tmp_path)
        assert _r(tmp_path, "src/real.rs") in mods
        assert _r(tmp_path, "src/hidden.rs") not in mods


class TestFallbackScanner:
    """The linear scanner used when the shared lexer can't vouch a
    view (no grammar installed, or the file doesn't parse — every
    hostile shape lands here)."""

    def test_string_and_comment_awareness(self):
        from core.build.rust_modules import _strip_noncode
        src = (
            'const U: &str = "see https://x"; mod real;\n'
            'const S: &str = "mod fake;";\n'
            "/* /* inner */ mod hidden; */ mod after;\n"
            "// mod line_commented;\n"
            'const R: &str = r#"mod raw_fake; " still raw"#; mod raw_ok;\n'
            "const E: &str = \"esc \\\" mod esc_fake;\"; mod esc_ok;\n"
            "fn f<'a>(x: &'a str) {} mod lifetime_ok;\n"
            "const C: char = ','; mod char_ok;\n"
        )
        view = _strip_noncode(src)
        kept = {"real", "after", "raw_ok", "esc_ok", "lifetime_ok",
                "char_ok"}
        dropped = {"fake", "hidden", "line_commented", "raw_fake",
                   "esc_fake"}
        for name in kept:
            assert f"mod {name};" in view, name
        for name in dropped:
            assert f"mod {name};" not in view, name
        # Blanking preserves layout: newline count survives.
        assert view.count("\n") == src.count("\n")

    @pytest.mark.parametrize("shape", [
        # Closer-less: one find to EOF per opener run.
        "/*x" * (512 * 1024 // 3),
        # Far closer: a run of nested openers whose single closer
        # sits at EOF — a depth loop that recomputes its closer scan
        # per iteration re-scans toward it once per opener (measured
        # ×4 per size doubling, ~19 s at this size, ~310 s per file
        # at the 2 MiB cap).
        "/*x" * (512 * 1024 // 3) + "*/",
        # Balanced runs: the closer half makes an unmemoized loop
        # re-scan to EOF for the absent next opener once per closer
        # (the separators keep the delimiters from overlapping into
        # accidental locality).
        "/*x" * (256 * 1024 // 3) + "x*/" * (256 * 1024 // 3),
    ], ids=["closer-less", "far-closer", "balanced-runs"])
    def test_unclosed_comment_input_is_linear(self, shape):
        """The lazy-dotall stripper re-scanned to end-of-string once
        per `/*` — 3.8s at 64 KiB, ~an hour extrapolated at the 2 MiB
        per-file cap. The find-driven scanner memoizes its
        forward-only delimiter positions, so every shape above is
        linear (~40 ms measured); the bound below carries
        loaded-runner headroom yet sits orders of magnitude under
        the quadratic cost at this size."""
        import time
        from core.build.rust_modules import _strip_noncode
        t0 = time.monotonic()
        view = _strip_noncode(shape)
        elapsed = time.monotonic() - t0
        assert elapsed < 5.0, f"non-linear strip: {elapsed:.2f}s"
        # Two-direction: the whole span is comment — nothing survives.
        assert view.strip() == ""

    def test_c_and_raw_c_string_family(self):
        """Rust 1.77 C-string literals: the raw prefix family must be
        COMPLETE. A ``cr`` missing from the opener set half-matches
        as identifier + plain string, and the phantom string swallows
        the trailing code — dropping a real ``mod`` edge on a
        rustc-compiled file (the consumer's witness demotes findings
        in files without an edge, so the miss is suppress-direction).
        """
        from core.build.rust_modules import _strip_noncode
        # The real edge after a cr raw string survives; the interior
        # (with its unescaped quote) is blanked, not a string opener.
        view = _strip_noncode('const A: &CStr = cr#"a " b"#; mod real;')
        assert "mod real;" in view
        # Zero-hash cr string: raw semantics — backslash is data, not
        # an escape, so the first quote closes it.
        view = _strip_noncode('const A: &CStr = cr"x\\"; mod real2;')
        assert "mod real2;" in view
        # Plain c-string: escape-aware like a plain string.
        view = _strip_noncode(
            'const A: &CStr = c"mod fake; \\" still"; mod real3;')
        assert "mod real3;" in view
        assert "mod fake;" not in view
        # In-string decls stay non-edges across the raw family.
        for src in ('const S = cr#"mod fake;"#; mod ok;',
                    'const S = r#"mod fake;"#; mod ok;',
                    'const S = br#"mod fake;"#; mod ok;'):
            view = _strip_noncode(src)
            assert "mod ok;" in view, src
            assert "mod fake;" not in view, src

    def test_unclosed_string_blanks_to_eof_not_hang(self):
        from core.build.rust_modules import _strip_noncode
        view = _strip_noncode('const S: &str = "never closed... mod x;\n')
        assert "mod x;" not in view
