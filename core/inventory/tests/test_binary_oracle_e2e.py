"""End-to-end integration tests for the binary-oracle arc.

These tests exercise the FULL path: build a real C project + binary,
run the enrich pipeline (auto-detect → classifier → chokepoint
accessor → reachability verdict → witness), and verify each layer
of the chain returns what downstream consumers expect.

Different from the unit tests, which mock the inventory + chokepoint
in isolation. These prove the layers compose correctly.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from core.inventory.binary_oracle import enrich_inventory_with_binary_oracle
from core.inventory.binary_oracle_autodetect import detect_binaries
from core.inventory.reach_audit import classify_reachability
from core.inventory.reach_chokepoint import check_suppress
from core.inventory.reach_witness import (
    STRUCTURALLY_SUPPRESSIBLE_KINDS,
    verdict_from_classification,
)
from core.inventory.reachability import binary_oracle_absent


@pytest.fixture(scope="module")
def _synthetic_target_built(tmp_path_factory):
    """Module-scoped: gcc-compile the synthetic dead-function project
    ONCE, share across every test in this file. Previously each test
    called ``_build_synthetic_target(tmp_path)`` and paid the gcc
    compile cost (~25s on CI cold-start) per test — 4 tests = 100s of
    redundant compile time. Now compiled once.

    Yields ``(project_root, binary_path, inventory_template)``. The
    inventory dict is a TEMPLATE — each test must deep-copy it via
    ``_fresh_inventory`` before mutating, otherwise mutations leak
    across tests.
    """
    work = tmp_path_factory.mktemp("synthetic_target")
    return _build_synthetic_target(work)


def _fresh_inventory(template: dict) -> dict:
    """Deep-copy the module-scoped inventory template so each test
    can mutate items[...].metadata etc. without cross-test leakage."""
    import copy
    return copy.deepcopy(template)


def _build_synthetic_target(tmp_path: Path) -> tuple[Path, Path, dict]:
    """Build a small C project with a deliberately-dead function.

    Returns (project_root, binary_path, inventory_dict). The binary
    is compiled with -O2 -ffunction-sections -fdata-sections +
    -Wl,--gc-sections so the dead function is genuinely DCE'd.

    Direct callers exist for tests that MUTATE the project dir
    (planted-binary, LTO-rebuild) — those can't share the
    module-fixture's read-only project. Most tests should use the
    ``_synthetic_target_built`` fixture instead.
    """
    project = tmp_path / "myproj"
    project.mkdir()
    src = project / "lib.c"
    # Build a wider source than the floor's min-match requirement (3
    # non-boilerplate names) so the floor doesn't reject a legitimate
    # binary just because the target is small. Real /agentic targets
    # have dozens-to-thousands of functions; this models that without
    # being huge.
    func_lines = []
    for i in range(10):
        func_lines.append(
            f"// Live: called from main.\n"
            f"int alive_helper_{i}(int x) {{ return x * {7 + i}; }}\n"
        )
    func_lines.append(
        "// Dead: never referenced anywhere — gc-sections strips it.\n"
        "int dead_helper(int x) { return x * 11; }\n"
    )
    func_lines.append(
        "int main(void) {\n"
        "  int r = 0;\n"
        + "".join(
            f"  r += alive_helper_{i}(r + {i});\n" for i in range(10)
        )
        + "  return r;\n"
        "}\n"
    )
    src.write_text("\n".join(func_lines))
    (project / "build").mkdir()
    binary = project / "build" / "myapp"
    subprocess.run([
        "gcc", "-O2", "-g",
        "-ffunction-sections", "-fdata-sections",
        "-Wl,--gc-sections",
        str(src), "-o", str(binary),
    ], check=True)
    items = []
    line = 2
    for i in range(10):
        items.append({"name": f"alive_helper_{i}",
                      "kind": "function", "line_start": line})
        line += 3
    items.append({"name": "dead_helper",
                  "kind": "function", "line_start": line})
    line += 3
    items.append({"name": "main", "kind": "function", "line_start": line})
    inventory = {
        "files": [{
            "path": "lib.c", "language": "c", "items": items,
        }],
    }
    return project, binary, inventory


def _dead_helper_line(inv: dict) -> int:
    for it in inv["files"][0]["items"]:
        if it["name"] == "dead_helper":
            return it["line_start"]
    raise AssertionError("dead_helper not in inventory")


def _alive_helper_line(inv: dict) -> int:
    for it in inv["files"][0]["items"]:
        if it["name"] == "alive_helper_0":
            return it["line_start"]
    raise AssertionError("alive_helper_0 not in inventory")


@pytest.mark.slow
def test_e2e_explicit_binary_flag_path(_synthetic_target_built) -> None:
    """The ``--binary`` explicit-path path: operator points at a
    binary; classifier finds the dead function absent and the
    chokepoint accessor confirms suppression eligibility."""
    project, binary, template = _synthetic_target_built
    inv = _fresh_inventory(template)
    counts = enrich_inventory_with_binary_oracle(inv, (binary,))
    assert counts["classified"] == 12
    items = {it["name"]: it for it in inv["files"][0]["items"]}

    # dead_helper → absent, tier=full
    dead = items["dead_helper"]["metadata"]["binary_oracle"]
    assert dead["classification"] == "absent", dead
    assert all(b["tier"] == "full" for b in dead["binaries"]), dead

    # alive_helper_0 → symbol_present (or inlined, depending on -O2)
    alive = items["alive_helper_0"]["metadata"]["binary_oracle"]
    assert alive["classification"] in ("symbol_present", "inlined"), alive

    dead_line = _dead_helper_line(inv)
    alive_line = _alive_helper_line(inv)
    # Chokepoint accessor confirms eligibility for the dead function.
    assert binary_oracle_absent(
        inv, "lib.c", "dead_helper", dead_line) is True
    assert binary_oracle_absent(
        inv, "lib.c", "alive_helper_0", alive_line) is False

    # And the reach_audit classifier returns the right verdict.
    verdict_dead = classify_reachability(
        inv, "lib.c", "dead_helper", dead_line, "lib")
    assert verdict_dead == "binary_oracle_absent"

    # Verdict resolves to a may_suppress=True witness.
    spec = verdict_from_classification(verdict_dead)
    assert spec.may_suppress(STRUCTURALLY_SUPPRESSIBLE_KINDS) is True


def test_e2e_autodetect_finds_binary(_synthetic_target_built) -> None:
    """The ``--binary-auto`` path: operator passes no explicit path;
    auto-detect walks the project tree and finds the binary under
    ``build/``."""
    project, binary, template = _synthetic_target_built
    inv = _fresh_inventory(template)
    detected = detect_binaries(project, "application")
    # The built binary lives at build/myapp.
    assert any(p.name == "myapp" for p in detected), detected
    # Same chokepoint behaviour as the explicit-path path.
    counts = enrich_inventory_with_binary_oracle(inv, tuple(detected))
    assert counts["classified"] == 12


def test_e2e_chokepoint_helper_full_flow(_synthetic_target_built) -> None:
    """The shared ``reach_chokepoint`` helper that both /agentic and
    /codeql use: from a finding-shaped input through to the suppression
    decision, all on a real binary's enrichment output."""
    project, binary, template = _synthetic_target_built
    inv = _fresh_inventory(template)
    enrich_inventory_with_binary_oracle(inv, (binary,))
    dead_line = _dead_helper_line(inv)
    alive_line = _alive_helper_line(inv)

    # Decision on the DEAD function — should suppress.
    decision = check_suppress(
        checklist=inv,
        file_path="lib.c", function_name="dead_helper", line=dead_line,
        repo_root=project,
    )
    assert decision is not None
    verdict, reason = decision
    assert verdict == "binary_oracle_absent"
    assert "dead_helper" in reason

    # Decision on the LIVE function — must NOT suppress.
    decision = check_suppress(
        checklist=inv,
        file_path="lib.c", function_name="alive_helper_0", line=alive_line,
        repo_root=project,
    )
    assert decision is None

    # manual_override on the dead function — must NOT suppress.
    decision = check_suppress(
        checklist=inv,
        file_path="lib.c", function_name="dead_helper", line=dead_line,
        repo_root=project,
        manual_override=True,
    )
    assert decision is None


def test_e2e_hostile_planted_binary_is_dropped(tmp_path: Path) -> None:
    """The hostile-ELF attack shape: a binary with completely
    unrelated symbols (planted in the target tree by an attacker)
    must be dropped by the source-coverage floor — NOT used to
    suppress every real finding via foreign-DWARF absent verdicts."""
    project, real_binary, inv = _build_synthetic_target(tmp_path)
    # Build a "planted" binary with completely different symbols.
    planted_src = tmp_path / "hostile.c"
    planted_src.write_text(
        "int hostile_payload(int x) { return x ^ 0xdeadbeef; }\n"
        "int main(void) { return hostile_payload(0); }\n"
    )
    planted_bin = project / "build" / "planted"
    subprocess.run(["gcc", "-O0", "-g", str(planted_src),
                    "-o", str(planted_bin)], check=True)

    # Enrich with ONLY the planted binary. Defense must fire: the
    # planted binary names alpha/beta/main from the source, none of
    # which the planted binary's DWARF knows about → drop with
    # warning, no inventory items annotated.
    counts = enrich_inventory_with_binary_oracle(inv, (planted_bin,))
    assert counts["classified"] == 0, (
        "planted binary should be dropped by the source-coverage "
        "floor — never annotate inventory with foreign-DWARF verdicts"
    )
    items = {it["name"]: it for it in inv["files"][0]["items"]}
    assert "binary_oracle" not in (items["dead_helper"].get("metadata") or {})

    # And in the REAL + planted case, the planted is dropped but the
    # real one still classifies. ``dead_helper`` ends up absent (real
    # binary stripped it), but the verdict comes ONLY from the real
    # binary — the planted contributes nothing.
    counts = enrich_inventory_with_binary_oracle(
        inv, (real_binary, planted_bin))
    assert counts["classified"] == 12
    items = {it["name"]: it for it in inv["files"][0]["items"]}
    dead = items["dead_helper"]["metadata"]["binary_oracle"]
    assert dead["classification"] == "absent"
    # Only ONE binary contributed (the real one); the planted was filtered.
    assert len(dead["binaries"]) == 1
    assert dead["binaries"][0]["path"].endswith("/build/myapp")


@pytest.mark.slow
def test_e2e_classifier_handles_lto_clone_suffix(tmp_path: Path) -> None:
    """Real-world LTO build: a function specialised by GCC ipa-cp or
    LTO emits as ``foo.lto_priv.0`` / ``foo.clone.0`` etc. The
    classifier's IPA suffix regex must strip these so source-name
    lookup still finds the function (otherwise it would FP as absent
    on real LTO targets — adversarial review P0-115)."""
    project = tmp_path / "lto_proj"
    project.mkdir()
    src = project / "lib.c"
    # Force a clone via __attribute__((target_clones)) — gcc emits
    # ``func.resolver`` and per-target ``func.arch_X`` symbols.
    src.write_text(
        "__attribute__((target_clones(\"default,sse4.2\")))\n"
        "int multiarch_helper(int x) { return x + 1; }\n"
        "int main(void) { return multiarch_helper(0); }\n"
    )
    binary = project / "app"
    try:
        subprocess.run(
            ["gcc", "-O2", "-g", str(src), "-o", str(binary)],
            check=True, capture_output=True,
        )
    except subprocess.CalledProcessError:
        pytest.skip("gcc rejects target_clones on this platform")

    inv = {"files": [{
        "path": "lib.c", "language": "c", "items": [
            {"name": "multiarch_helper", "kind": "function",
             "line_start": 2},
        ],
    }]}
    enrich_inventory_with_binary_oracle(inv, (binary,))
    item = inv["files"][0]["items"][0]
    bo = item["metadata"]["binary_oracle"]
    # ``multiarch_helper`` IS in the binary (multiple clones); should
    # classify as symbol_present (NOT absent) — proves the suffix
    # stripper found at least one of the clone symbols.
    assert bo["classification"] in ("symbol_present", "inlined"), bo
