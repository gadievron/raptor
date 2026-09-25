"""Mechanics tests for the live-WSL verification checklist.

Hermetic: probes are stubbed — nothing here touches WSL, the sandbox,
or the consent store.  What is pinned is the harness contract the CI
jobs rely on: registry integrity, status/kind coercion, exit-code
semantics (assert failures and probe errors redden the job; strict
mode reddens skipped asserts), JSON artifact shape, and summary
escaping of probe-derived bytes.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "wsl_verify_live.py"


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location("wsl_verify_live",
                                                  _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _item(mod, item_id: str, kind: str, probe, section: str = "facts"):
    return mod.Item(item_id, "test#1", section, kind, "stub item", probe)


def _run(mod, items):
    return mod.run_items(items, mod.Context())


# ---------------------------------------------------------------------------
# registry integrity
# ---------------------------------------------------------------------------

def test_registry_ids_unique(mod):
    ids = [item.item_id for item in mod.REGISTRY]
    assert len(ids) == len(set(ids))


def test_registry_sections_and_kinds_valid(mod):
    for item in mod.REGISTRY:
        assert item.section in mod.SECTIONS, item.item_id
        assert item.kind in (mod.KIND_RECORD, mod.KIND_ASSERT), item.item_id
        assert item.description, item.item_id
        assert callable(item.probe), item.item_id
        assert "#" in item.series_ref, item.item_id


def test_every_section_nonempty(mod):
    for section in mod.SECTIONS:
        assert any(i.section == section for i in mod.REGISTRY), section


def test_asserted_item_set_pinned(mod):
    """A silent assert→record downgrade must fail HERE, not surface as
    a quietly-weaker CI leg. Deliberate kind changes edit this pin."""
    asserted = {i.item_id for i in mod.REGISTRY
                if i.kind == mod.KIND_ASSERT}
    recorded = {i.item_id for i in mod.REGISTRY
                if i.kind == mod.KIND_RECORD}
    assert asserted == {
        "drvfs-case-insensitive", "drvfs-world-writable",
        "env-plus-marker", "flock-cross-distro", "floor-host-consent",
        "grant-non-tty", "grant-via-pty", "interop-escape-mount-ns",
        "interop-escape-ns-only", "interop-plumbing", "kernel-family",
        "landlock-absent", "live-ns-only-run", "machine-id",
        "mkfifo-on-drvfs", "mnt-target-exemption", "mount-ns-masks",
        "posture-banner", "refusal-names-ceremony",
        "rename-cross-client", "revoke", "run-wsl-regrant",
        "tmpdir-latch-drvfs", "tmpdir-latch-ext4", "unshare-mask-strip",
        "v9fs-magic-mnt", "wsl-detection", "wsl1-banner",
        "wsl1-disable-escape", "wsl1-flavour", "wsl1-refusal",
        "wsl2-flavour",
    }
    assert recorded == {
        "casefold-samples", "host-surfaces", "kernel-identity",
        "lsm-list", "marker-setup", "per-dir-case-sensitive",
        "perf-pmu", "pregrant-clean", "wsl1-f-types",
        "wsl1-kernel-identity",
    }
    assert len(asserted) == 32 and len(recorded) == 10
    assert len(mod.REGISTRY) == 42


# ---------------------------------------------------------------------------
# runner status handling
# ---------------------------------------------------------------------------

def test_assert_pass_and_fail_recorded(mod):
    items = [
        _item(mod, "a", mod.KIND_ASSERT,
              lambda _c: mod.ProbeResult(mod.STATUS_PASS, value=1,
                                         expected=1)),
        _item(mod, "b", mod.KIND_ASSERT,
              lambda _c: mod.ProbeResult(mod.STATUS_FAIL, value=2,
                                         expected=1)),
    ]
    results = _run(mod, items)
    assert results["a"]["status"] == mod.STATUS_PASS
    assert results["b"]["status"] == mod.STATUS_FAIL
    assert results["b"]["expected"] == 1


def test_probe_exception_becomes_error(mod):
    def boom(_ctx):
        raise RuntimeError("probe exploded")

    results = _run(mod, [_item(mod, "x", mod.KIND_ASSERT, boom)])
    assert results["x"]["status"] == mod.STATUS_ERROR
    assert "probe exploded" in results["x"]["detail"]


def test_probe_skip_becomes_skipped_with_reason(mod):
    def skip(_ctx):
        raise mod.ProbeSkip("no second distro")

    results = _run(mod, [_item(mod, "x", mod.KIND_ASSERT, skip)])
    assert results["x"]["status"] == mod.STATUS_SKIPPED
    assert "no second distro" in results["x"]["detail"]


def test_invalid_status_for_kind_coerced_to_error(mod):
    # A record item may not claim pass/fail; an assert item may not
    # claim recorded — the runner refuses the contract violation.
    rec = _item(mod, "r", mod.KIND_RECORD,
                lambda _c: mod.ProbeResult(mod.STATUS_PASS))
    asrt = _item(mod, "a", mod.KIND_ASSERT,
                 lambda _c: mod.ProbeResult(mod.STATUS_RECORDED))
    results = _run(mod, [rec, asrt])
    assert results["r"]["status"] == mod.STATUS_ERROR
    assert results["a"]["status"] == mod.STATUS_ERROR


def test_one_probe_fault_does_not_abort_the_walk(mod):
    def boom(_ctx):
        raise RuntimeError("boom")

    items = [
        _item(mod, "first", mod.KIND_ASSERT, boom),
        _item(mod, "second", mod.KIND_RECORD,
              lambda _c: mod.ProbeResult(mod.STATUS_RECORDED, value="ok")),
    ]
    results = _run(mod, items)
    assert results["second"]["status"] == mod.STATUS_RECORDED


# ---------------------------------------------------------------------------
# section verdict / strict semantics
# ---------------------------------------------------------------------------

def _results(mod, rows):
    return {
        f"i{n}": {"series_ref": "t#1", "kind": kind, "description": "d",
                  "status": status, "value": None, "expected": None,
                  "detail": ""}
        for n, (kind, status) in enumerate(rows)
    }


def test_ok_all_green(mod):
    rows = [(mod.KIND_ASSERT, mod.STATUS_PASS),
            (mod.KIND_RECORD, mod.STATUS_RECORDED)]
    assert mod.section_ok(_results(mod, rows), strict=False) is True
    assert mod.section_ok(_results(mod, rows), strict=True) is True


def test_assert_fail_reddens(mod):
    rows = [(mod.KIND_ASSERT, mod.STATUS_FAIL)]
    assert mod.section_ok(_results(mod, rows), strict=False) is False


def test_error_reddens_even_on_record_items(mod):
    rows = [(mod.KIND_RECORD, mod.STATUS_ERROR)]
    assert mod.section_ok(_results(mod, rows), strict=False) is False


def test_skipped_assert_passes_only_without_strict(mod):
    rows = [(mod.KIND_ASSERT, mod.STATUS_SKIPPED)]
    assert mod.section_ok(_results(mod, rows), strict=False) is True
    assert mod.section_ok(_results(mod, rows), strict=True) is False


def test_skipped_record_never_reddens(mod):
    rows = [(mod.KIND_RECORD, mod.STATUS_SKIPPED)]
    assert mod.section_ok(_results(mod, rows), strict=True) is True


# ---------------------------------------------------------------------------
# summary + artifact
# ---------------------------------------------------------------------------

def test_summary_escapes_probe_derived_bytes(mod):
    # OSC sequence + a bidi override — both must leave the summary as
    # escapes (the shared log_sanitisation contract).
    hostile = "value\x1b]0;pwned\x07‮end"
    results = _run(mod, [_item(
        mod, "h", mod.KIND_ASSERT,
        lambda _c: mod.ProbeResult(mod.STATUS_FAIL, value=hostile,
                                   expected="clean", detail=hostile))])
    text = mod.render_summary("facts", results)
    assert "\x1b" not in text
    assert "\x07" not in text
    assert "‮" not in text
    assert "\\x1b" in text
    assert "\\u202e" in text


def test_summary_bounds_long_values(mod):
    results = _run(mod, [_item(
        mod, "long", mod.KIND_ASSERT,
        lambda _c: mod.ProbeResult(mod.STATUS_FAIL, value="v" * 5000,
                                   expected=""))])
    text = mod.render_summary("facts", results)
    assert "...[+" in text  # the shared sanitiser's elision marker
    assert len(text) < 5000


def test_payload_shape_and_json_roundtrip(mod, tmp_path):
    items = [
        _item(mod, "a", mod.KIND_ASSERT,
              lambda _c: mod.ProbeResult(mod.STATUS_PASS, value=True,
                                         expected=True)),
        _item(mod, "b", mod.KIND_RECORD,
              lambda _c: mod.ProbeResult(mod.STATUS_RECORDED,
                                         value={"k": Path("/x")})),
    ]
    payload = mod.build_payload("facts", _run(mod, items), strict=True)
    assert payload["section"] == "facts"
    assert payload["ok"] is True
    assert set(payload["items"]) == {"a", "b"}
    assert "osrelease" in payload["host"]
    # default=str in the writer: non-JSON values (Path) must serialise.
    out = tmp_path / "artifact.json"
    out.write_text(json.dumps(payload, indent=2, default=str))
    assert json.loads(out.read_text())["items"]["b"]["value"]["k"] == "/x"


def test_main_exit_codes(mod, tmp_path, monkeypatch):
    # Route a stub registry through the real CLI: exit 0 on green,
    # exit 1 when an assert item fails.
    green = [_item(mod, "g", mod.KIND_ASSERT,
                   lambda _c: mod.ProbeResult(mod.STATUS_PASS))]
    red = [_item(mod, "r", mod.KIND_ASSERT,
                 lambda _c: mod.ProbeResult(mod.STATUS_FAIL))]
    out = tmp_path / "o.json"
    monkeypatch.setattr(mod, "REGISTRY", green)
    assert mod.main(["--section", "facts", "--json-out", str(out)]) == 0
    monkeypatch.setattr(mod, "REGISTRY", red)
    assert mod.main(["--section", "facts", "--json-out", str(out)]) == 1
    saved = json.loads(out.read_text())
    assert saved["ok"] is False


def test_main_strict_flag_carries_into_verdict(mod, tmp_path, monkeypatch):
    skipping = [_item(mod, "s", mod.KIND_ASSERT,
                      lambda _c: (_ for _ in ()).throw(
                          mod.ProbeSkip("prereq absent")))]
    out = tmp_path / "o.json"
    monkeypatch.setattr(mod, "REGISTRY", skipping)
    assert mod.main(["--section", "facts", "--json-out", str(out)]) == 0
    assert mod.main(["--section", "facts", "--json-out", str(out),
                     "--strict"]) == 1


# ---------------------------------------------------------------------------
# pure helpers
# ---------------------------------------------------------------------------

def test_interop_child_verdict(mod):
    assert mod._interop_child_verdict(
        "PE OSError 2\nCONNECT denied 2\nBINFMT_WRITE denied 13\n") is True
    assert mod._interop_child_verdict("PE out True\n") is False
    assert mod._interop_child_verdict("CONNECT ok /run/WSL/1\n") is False


def test_printable_passthrough(mod):
    assert mod._printable("plain ascii — ok") == "plain ascii — ok"
