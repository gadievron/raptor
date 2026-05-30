"""Rule-set integrity test — per design exit criterion.

Asserts:
  1. Every expected cocci rule exists in the shipped layout.
  2. Every shipped rule is parseable by spatch (no syntax errors).
  3. Every rule emits COCCIRESULT (else it's verdict-useless).

Pinned-set check: if a new rule lands, this test reminds you to
add it to the expected set. If a rule is renamed/removed, this
test catches it.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_RULES_ROOT = Path(__file__).resolve().parents[3] / "engine" / "coccinelle" / "source_intel"


# Pinned per-axis rule list. When a new rule lands here, update
# this set. Design called for ~38 rules total; this is honest
# current state (21 shipped, more to come per the design plan).
EXPECTED_RULES = {
    "allocation": {
        "double_free.cocci",
        "paired_free.cocci",
        "unchecked_alloc.cocci",
        "unchecked_alloc_local.cocci",
    },
    "attrs": {
        "attr_access.cocci",
        "attr_alloc_size.cocci",
        "attr_const.cocci",
        "attr_counted_by.cocci",
        "attr_deprecated.cocci",
        "attr_malloc.cocci",
        "attr_no_stack_protector.cocci",
        "attr_nodiscard.cocci",
        "attr_nonnull.cocci",
        "attr_noreturn.cocci",
        "attr_pure.cocci",
        "attr_returns_nonnull.cocci",
        "attr_warn_unused_result.cocci",
    },
    "compile_time": {
        "no_sanitize_attr.cocci",
    },
    "concurrency": {
        "lock_sites.cocci",
    },
    "hazards": {
        "deprecated_functions.cocci",
        "signed_alloc.cocci",
        "type_confusion_cast.cocci",
        "unsafe_temp_files.cocci",
    },
    "privilege": {
        "capability_check.cocci",
        "cred_manipulation.cocci",
        "lsm_hooks.cocci",
        "setuid_setgid.cocci",
        "user_boundary.cocci",
    },
    "proximity": {
        "abort_proximate.cocci",
        "lock_pairs.cocci",
        "null_guards.cocci",
        "refcount_pairs.cocci",
        "warn_class.cocci",
    },
    "variants": {
        "checked_alloc.cocci",
        "structural_fingerprint.cocci",
    },
}


def test_rules_root_exists():
    assert _RULES_ROOT.is_dir(), (
        f"rules root not found: {_RULES_ROOT}"
    )


def test_expected_axes_present():
    """All expected axis subdirs exist."""
    for axis in EXPECTED_RULES.keys():
        axis_dir = _RULES_ROOT / axis
        assert axis_dir.is_dir(), f"missing axis dir: {axis_dir}"


def test_no_unexpected_axis_dirs():
    """Catch a new axis dir landing without test update."""
    actual_axes = {
        p.name for p in _RULES_ROOT.iterdir() if p.is_dir()
    }
    expected_axes = set(EXPECTED_RULES.keys())
    unexpected = actual_axes - expected_axes
    assert not unexpected, (
        f"unexpected axis dirs found: {sorted(unexpected)} — "
        f"add to EXPECTED_RULES or remove the dirs"
    )


def test_each_axis_has_expected_rules():
    """Per-axis pinned set."""
    for axis, expected_rules in EXPECTED_RULES.items():
        axis_dir = _RULES_ROOT / axis
        actual_rules = {
            p.name for p in axis_dir.glob("*.cocci")
        }
        missing = expected_rules - actual_rules
        extra = actual_rules - expected_rules
        assert not missing, (
            f"axis {axis!r} missing rules: {sorted(missing)}"
        )
        assert not extra, (
            f"axis {axis!r} has unexpected rules: {sorted(extra)} "
            f"— add to EXPECTED_RULES or remove"
        )


def test_total_rule_count_matches():
    """Sanity: total rule count from inventory should match
    what we list in EXPECTED_RULES."""
    actual_total = sum(
        1 for _ in _RULES_ROOT.rglob("*.cocci")
    )
    expected_total = sum(len(r) for r in EXPECTED_RULES.values())
    assert actual_total == expected_total, (
        f"got {actual_total} cocci files, expected {expected_total}"
    )


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed",
)
def test_every_rule_parses(tmp_path):
    """spatch --parse-cocci shouldn't error on any shipped rule."""
    empty = tmp_path / "empty.c"
    empty.write_text("int main(void) { return 0; }\n")
    failed = []
    for rule in _RULES_ROOT.rglob("*.cocci"):
        proc = subprocess.run(
            [
                "spatch", "--sp-file", str(rule),
                "--very-quiet", "--no-includes",
                str(empty),
            ],
            capture_output=True, text=True, timeout=30,
        )
        # `--sp-file` parse errors surface as non-zero returncode
        # OR "parse error" / "syntax error" / "Fatal error" in stderr.
        err = (proc.stderr or "") + (proc.stdout or "")
        if proc.returncode != 0 and (
            "parse error" in err.lower()
            or "syntax error" in err.lower()
            or "fatal error" in err.lower()
        ):
            failed.append((rule.name, err[:300]))
    assert not failed, (
        "rules failed to parse:\n"
        + "\n".join(f"  {n}: {e}" for n, e in failed)
    )


def test_every_rule_emits_cocciresult():
    """Every shipped rule must produce COCCIRESULT lines (else it's
    verdict-useless — informational rules that emit nothing aren't
    consumed anywhere)."""
    no_emit = []
    for rule in _RULES_ROOT.rglob("*.cocci"):
        text = rule.read_text()
        if "COCCIRESULT" not in text:
            no_emit.append(rule.relative_to(_RULES_ROOT))
    assert not no_emit, (
        f"rules without COCCIRESULT emission: {sorted(map(str, no_emit))}"
    )
