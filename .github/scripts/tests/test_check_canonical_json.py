"""Detector-correctness tests for the canonical-JSON guardrail.

Pins both contractual behaviours of the gate:

  1. PASS on the real repo tree — every canonical site is either
     migrated to ``core.json.dumps_canonical`` or baselined with a
     note (``test_real_tree_is_clean``).
  2. FAIL on a deliberately-injected raw ``json.dumps`` inside a
     canonical module (``test_injected_raw_dumps_in_canonical_module_fails``).

Plus unit coverage of the two detector rules on synthetic trees.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "check_canonical_json.py"
_REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def det():
    spec = importlib.util.spec_from_file_location(
        "check_canonical_json", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _tree(tmp_path: Path, rel: str, body: str) -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return tmp_path


class TestRule1RawDumpsInCanonicalModule:
    def test_raw_dumps_in_canonical_module_flagged(
            self, det, tmp_path: Path) -> None:
        root = _tree(tmp_path, "core/coverage/journal_mac.py", (
            "import json\n"
            "def row_sha256(row):\n"
            "    return json.dumps(row, sort_keys=True)\n"
        ))
        keys = {det.finding_key(f) for f in det.scan_tree(root)}
        assert ("raw_dumps_in_canonical_module:"
                "core/coverage/journal_mac.py:row_sha256") in keys

    def test_aliased_and_local_imports_caught(
            self, det, tmp_path: Path) -> None:
        root = _tree(tmp_path, "core/coverage/journal_mac.py", (
            "def sneak(row):\n"
            "    import json as _j\n"
            "    return _j.dumps(row)\n"
            "def sneak2(row):\n"
            "    from json import dumps as d\n"
            "    return d(row)\n"
        ))
        keys = {det.finding_key(f) for f in det.scan_tree(root)}
        assert ("raw_dumps_in_canonical_module:"
                "core/coverage/journal_mac.py:sneak") in keys
        assert ("raw_dumps_in_canonical_module:"
                "core/coverage/journal_mac.py:sneak2") in keys

    def test_dumps_canonical_call_is_clean(
            self, det, tmp_path: Path) -> None:
        root = _tree(tmp_path, "core/coverage/journal_mac.py", (
            "from core.json.utils import dumps_canonical\n"
            "def row_sha256(row):\n"
            "    return dumps_canonical(row)\n"
        ))
        assert det.scan_tree(root) == []

    def test_non_canonical_module_not_rule1_flagged(
            self, det, tmp_path: Path) -> None:
        root = _tree(tmp_path, "core/some/display.py", (
            "import json\n"
            "def show(x):\n"
            "    print(json.dumps(x))\n"
        ))
        rules = {f["rule"] for f in det.scan_tree(root)}
        assert "raw_dumps_in_canonical_module" not in rules


class TestRule2DumpsFlowsToHash:
    def test_nested_dumps_in_hash_call_flagged(
            self, det, tmp_path: Path) -> None:
        root = _tree(tmp_path, "core/newmod.py", (
            "import hashlib, json\n"
            "def fingerprint(x):\n"
            "    return hashlib.sha256(\n"
            "        json.dumps(x, sort_keys=True).encode()).hexdigest()\n"
        ))
        keys = {det.finding_key(f) for f in det.scan_tree(root)}
        assert "dumps_flows_to_hash:core/newmod.py:fingerprint" in keys

    def test_flow_via_local_name_flagged(self, det, tmp_path: Path) -> None:
        root = _tree(tmp_path, "packages/p/newmod.py", (
            "import hashlib, json\n"
            "def fingerprint(x):\n"
            "    encoded = json.dumps(x, sort_keys=True)\n"
            "    payload = encoded.encode('utf-8')\n"
            "    return hashlib.sha256(payload).hexdigest()\n"
        ))
        keys = {det.finding_key(f) for f in det.scan_tree(root)}
        assert "dumps_flows_to_hash:packages/p/newmod.py:fingerprint" in keys

    def test_hmac_flow_flagged(self, det, tmp_path: Path) -> None:
        root = _tree(tmp_path, "core/newmod.py", (
            "import hmac, json\n"
            "def token(key, x):\n"
            "    msg = json.dumps(x).encode()\n"
            "    return hmac.new(key, msg, 'sha256').hexdigest()\n"
        ))
        keys = {det.finding_key(f) for f in det.scan_tree(root)}
        assert "dumps_flows_to_hash:core/newmod.py:token" in keys

    def test_display_dumps_without_hash_is_clean(
            self, det, tmp_path: Path) -> None:
        root = _tree(tmp_path, "core/newmod.py", (
            "import hashlib, json\n"
            "def show(x):\n"
            "    print(json.dumps(x))\n"
            "def unrelated(b: bytes):\n"
            "    return hashlib.sha256(b).hexdigest()\n"
        ))
        assert det.scan_tree(root) == []

    def test_taint_does_not_leak_across_functions(
            self, det, tmp_path: Path) -> None:
        root = _tree(tmp_path, "core/newmod.py", (
            "import hashlib, json\n"
            "def a(x):\n"
            "    encoded = json.dumps(x)\n"
            "    return encoded\n"
            "def b(encoded: bytes):\n"
            "    return hashlib.sha256(encoded).hexdigest()\n"
        ))
        assert det.scan_tree(root) == []


class TestBaselineSemantics:
    def test_baselined_finding_passes_and_stale_warns(
            self, det, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        root = _tree(tmp_path, "core/coverage/journal_mac.py", (
            "import json\n"
            "def row_sha256(row):\n"
            "    return json.dumps(row)\n"
        ))
        findings = det.scan_tree(root)
        keys = {det.finding_key(f) for f in findings}
        baseline = dict.fromkeys(
            keys | {"raw_dumps_in_canonical_module:core/gone.py:f"},
            {"note": "test"},
        )
        new = {k for k in keys if k not in baseline}
        stale = set(baseline) - keys
        assert not new
        assert stale == {"raw_dumps_in_canonical_module:core/gone.py:f"}

    def test_write_baseline_round_trip(
            self, det, tmp_path: Path) -> None:
        root = _tree(tmp_path, "core/coverage/journal_mac.py", (
            "import json\n"
            "def row_sha256(row):\n"
            "    return json.dumps(row)\n"
        ))
        findings = det.scan_tree(root)
        bl = tmp_path / "baseline.json"
        det.write_baseline(bl, findings)
        entries = json.loads(bl.read_text())["entries"]
        assert set(entries) == {det.finding_key(f) for f in findings}
        assert all("note" in v for v in entries.values())


class TestRealTreeContract:
    """The two behaviours that make the gate trustworthy on this repo."""

    def test_real_tree_is_clean(self, det) -> None:
        """Every canonical site in the real repo is migrated or
        baselined — the checker exits clean on the tree it ships in."""
        findings = det.scan_tree(_REPO_ROOT)
        baseline = det.load_baseline(
            _SCRIPT.parent / "canonical_json_baseline.json")
        new = {det.finding_key(f)
               for f in findings} - set(baseline)
        assert not new, f"unbaselined canonical-JSON findings: {sorted(new)}"

    def test_injected_raw_dumps_in_canonical_module_fails(
            self, det, tmp_path: Path) -> None:
        """A raw json.dumps injected into a canonical module is a NEW
        finding against the shipped baseline."""
        src = _REPO_ROOT / "core/coverage/journal_mac.py"
        body = src.read_text(encoding="utf-8") + (
            "\n\ndef _injected_bad_canonical(row):\n"
            "    import json as _j\n"
            "    return _j.dumps(row, sort_keys=True)\n"
        )
        root = _tree(tmp_path, "core/coverage/journal_mac.py", body)
        findings = det.scan_tree(root)
        baseline = det.load_baseline(
            _SCRIPT.parent / "canonical_json_baseline.json")
        new = {det.finding_key(f) for f in findings} - set(baseline)
        assert ("raw_dumps_in_canonical_module:"
                "core/coverage/journal_mac.py:_injected_bad_canonical"
                ) in new
