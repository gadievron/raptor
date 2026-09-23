"""_is_detection_only resolves the stock-rule root fail-closed.

The rule path was joined against ``os.environ.get("RAPTOR_DIR", ".")``
— a doctrine-violating CWD fallback: with RAPTOR_DIR unset (embedders,
bare pytest from another directory) the isfile check missed, and a
stock DETECTION-role rule read as a dynamic per-hypothesis rule —
i.e. promotion-grade (fail-open into the promotion gate).
"""

from __future__ import annotations

from pathlib import Path

from core.audit.orchestrator import _is_detection_only

_RAPTOR_DIR = str(Path(__file__).resolve().parents[3])


class TestDetectionRoleResolution:
    def test_unset_raptor_dir_fails_closed(self, monkeypatch, tmp_path):
        monkeypatch.delenv("RAPTOR_DIR", raising=False)
        monkeypatch.chdir(tmp_path)  # CWD carries no engine/ tree
        assert _is_detection_only("coccinelle:alloc_narrow_count") is True

    def test_stock_detection_rule_resolves_with_raptor_dir(
        self, monkeypatch, tmp_path,
    ):
        monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
        monkeypatch.chdir(tmp_path)  # resolution must not lean on CWD
        assert _is_detection_only("coccinelle:alloc_narrow_count") is True

    def test_dynamic_rule_still_promotes(self, monkeypatch):
        monkeypatch.setenv("RAPTOR_DIR", _RAPTOR_DIR)
        assert _is_detection_only(
            "coccinelle:hypothesis-generated-nonexistent-rule",
        ) is False
