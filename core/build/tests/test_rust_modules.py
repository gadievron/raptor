"""Tests for Rust crate-module-tree membership resolution."""

from __future__ import annotations

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
