"""Tests for Rust crate-module-tree membership resolution.

``#[path = "…"]`` values come from the analysed (untrusted) sources, so
candidates resolving outside the repo root must never be probed, read, or
added to the reachable set — including via symlinks.
"""

from __future__ import annotations

import os

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
