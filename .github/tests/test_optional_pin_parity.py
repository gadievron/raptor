import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXACT_PIN = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[^;\s]+)(?:;.*)?$"
)


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _commented_pins(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line.startswith("# "):
            continue
        match = EXACT_PIN.fullmatch(raw_line.removeprefix("# ").strip())
        if match:
            pins[_canonical_name(match["name"])] = match["version"]

    return pins


def _active_pins(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-r "):
            continue
        match = EXACT_PIN.fullmatch(line)
        if match:
            pins[_canonical_name(match["name"])] = match["version"]

    return pins


def _manifest_pins() -> dict[str, str]:
    manifest = json.loads(
        (ROOT / "containers" / "all-tools-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    return {
        _canonical_name(package["distribution"]): package["version"]
        for package in manifest["python_packages"]
    }


def test_all_tools_manifest_matches_canonical_optional_pins() -> None:
    canonical = _commented_pins(ROOT / "requirements.txt")
    manifest = _manifest_pins()

    assert {name: canonical[name] for name in ("angr", "frida")} == {
        name: manifest[name] for name in ("angr", "frida")
    }


def test_optional_lock_matches_canonical_optional_pins() -> None:
    canonical = _commented_pins(ROOT / "requirements.txt")
    optional = _active_pins(
        ROOT / ".devcontainer" / "requirements-all-optional.txt"
    )

    assert {name: canonical[name] for name in ("frida", "jsonschema")} == {
        name: optional[name] for name in ("frida", "jsonschema")
    }
