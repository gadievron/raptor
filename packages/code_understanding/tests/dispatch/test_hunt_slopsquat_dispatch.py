"""Tests for the slopsquat dispatch backend for /understand --hunt.

The dispatch is offline and side-effect-free: it reuses the SCA manifest
parsers (pure Python, no binary, no network) and the pure-heuristic
slopsquat detector. So unlike the cocci tests — which must mock spatch —
these exercise the real SCA stack against tmp-dir fixtures, which is
higher fidelity. Only the "SCA not installed" path is simulated.

Coverage:
  * slopsquat-shaped dep (popular prefix + generic suffix) → variant
    with the file/line/function/snippet/confidence/tool shape the
    VariantAdapter consumes
  * clean repo (only popular deps) → []
  * repo with no manifests → []
  * non-existent / non-dir repo_path → error variant
  * SCA package not importable → error variant (not a crash)
  * SLOPSQUAT_MODEL sentinel exposes a stable model_name
  * _finding_to_variant: absolute manifest path → repo-relative file
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest


# parents[4] climbs:
#   [0] packages/code_understanding/tests/dispatch/  (this file's directory)
#   [1] packages/code_understanding/tests/
#   [2] packages/code_understanding/
#   [3] packages/
#   [4] <repo root>
_REPO_ROOT = str(Path(__file__).resolve().parents[4])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


from packages.code_understanding.dispatch import hunt_slopsquat_dispatch as mod  # noqa: E402


def _write_package_json(repo: Path, deps: dict) -> None:
    (repo / "package.json").write_text(
        json.dumps({"name": "fixture", "version": "1.0.0", "dependencies": deps})
    )


# ---------------------------------------------------------------------
# Dispatch entry-point
# ---------------------------------------------------------------------

def test_slopsquat_shape_dep_yields_variant(tmp_path: Path) -> None:
    # react-helper = popular prefix ("react") + generic suffix ("helper").
    _write_package_json(tmp_path, {"react": "^18.0.0", "react-helper": "^1.0.0"})

    variants = mod.slopsquat_hunt_dispatch(None, "ignored", str(tmp_path))

    assert len(variants) == 1
    v = variants[0]
    # Shape the VariantAdapter consumes.
    assert set(v) >= {"file", "line", "function", "snippet", "confidence", "tool"}
    assert v["file"] == "package.json"          # repo-relative manifest
    assert v["line"] == 0                         # dependency-level, no source line
    assert v["function"] == "npm:react-helper"
    assert v["tool"] == "sca-slopsquat"
    assert "slopsquat shape" in v["snippet"]
    assert "react" in v["snippet"]                # suspected imitated package
    assert isinstance(v["confidence"], str)


def test_clean_repo_only_popular_deps_yields_nothing(tmp_path: Path) -> None:
    _write_package_json(tmp_path, {"react": "^18.0.0", "express": "^4.0.0"})
    assert mod.slopsquat_hunt_dispatch(None, "x", str(tmp_path)) == []


def test_repo_with_no_manifests_yields_nothing(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("no manifests here")
    assert mod.slopsquat_hunt_dispatch(None, "x", str(tmp_path)) == []


def test_nonexistent_repo_returns_error_variant() -> None:
    out = mod.slopsquat_hunt_dispatch(None, "x", "/no/such/dir/xyz")
    assert len(out) == 1
    assert "error" in out[0]
    assert "not a directory" in out[0]["error"]


def test_file_path_as_repo_returns_error_variant(tmp_path: Path) -> None:
    f = tmp_path / "afile.txt"
    f.write_text("x")
    out = mod.slopsquat_hunt_dispatch(None, "x", str(f))
    assert len(out) == 1 and "error" in out[0]


def test_sca_not_importable_returns_error_variant(tmp_path: Path) -> None:
    _write_package_json(tmp_path, {"react-helper": "^1.0.0"})
    # Setting a module to None in sys.modules makes `import` of it raise
    # ImportError — simulates SCA not being installed alongside /understand.
    with mock.patch.dict(sys.modules, {"packages.sca.discovery": None}):
        out = mod.slopsquat_hunt_dispatch(None, "x", str(tmp_path))
    assert len(out) == 1
    assert "error" in out[0]
    assert "SCA package not importable" in out[0]["error"]


def test_scan_failure_returns_error_variant_not_crash(tmp_path: Path) -> None:
    _write_package_json(tmp_path, {"react-helper": "^1.0.0"})
    with mock.patch.object(mod, "Path", wraps=Path):
        # Force scan_deps to blow up after imports succeed.
        with mock.patch(
            "packages.sca.supply_chain.slopsquat.scan_deps",
            side_effect=RuntimeError("boom"),
        ):
            out = mod.slopsquat_hunt_dispatch(None, "x", str(tmp_path))
    assert len(out) == 1
    assert "error" in out[0]
    assert "slopsquat scan failed" in out[0]["error"]


# ---------------------------------------------------------------------
# Sentinel handle + mapping helper
# ---------------------------------------------------------------------

def test_sentinel_model_has_stable_name() -> None:
    assert mod.SLOPSQUAT_MODEL.model_name == mod.SLOPSQUAT_MODEL_NAME
    assert mod.SLOPSQUAT_MODEL_NAME == "sca-slopsquat"


def test_finding_to_variant_relativizes_absolute_manifest_path(tmp_path: Path) -> None:
    # Duck-typed stand-in for SlopsquatFinding — _finding_to_variant only
    # reads these attributes, so we avoid constructing the full dataclass.
    abs_manifest = tmp_path / "sub" / "package.json"
    finding = SimpleNamespace(
        dependency=SimpleNamespace(
            declared_in=abs_manifest, ecosystem="npm", name="react-helper",
        ),
        score=0.6,
        reasons=("popular_prefix_generic_suffix",),
        suspected_root="react",
        confidence=SimpleNamespace(level="low"),
    )
    v = mod._finding_to_variant(finding, tmp_path)
    assert v["file"] == str(Path("sub") / "package.json")  # repo-relative
    assert v["function"] == "npm:react-helper"
    assert v["confidence"] == "low"


def test_finding_to_variant_leaves_foreign_path_unchanged() -> None:
    # declared_in outside the repo → relative_to raises → left as-is.
    finding = SimpleNamespace(
        dependency=SimpleNamespace(
            declared_in=Path("/elsewhere/package.json"), ecosystem="npm", name="x-cli",
        ),
        score=0.5, reasons=("r",), suspected_root=None,
        confidence=SimpleNamespace(level="low"),
    )
    v = mod._finding_to_variant(finding, Path("/repo"))
    assert v["file"] == "/elsewhere/package.json"
    assert "resembles" not in v["snippet"]  # suspected_root None → no clause


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
