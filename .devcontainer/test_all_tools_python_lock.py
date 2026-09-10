import json
import re
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version


ROOT = Path(__file__).resolve().parents[1]
BASE_INPUT = ROOT / "containers" / "requirements-base.in"
BASE_LOCK = ROOT / "containers" / "requirements-base.lock"
ALL_TOOLS_INPUT = ROOT / "containers" / "requirements-all-tools.in"
ALL_TOOLS_LOCK = ROOT / "containers" / "requirements-all-tools.lock"
HASH = re.compile(r"^--hash=sha256:(?P<digest>[0-9a-f]{64})$")


def load_requirements(path: Path) -> tuple[dict[str, Requirement], set[str]]:
    requirements: dict[str, Requirement] = {}
    includes: set[str] = set()

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("-r "):
            includes.add(line.removeprefix("-r ").strip())
            continue

        requirement = Requirement(line)
        requirements[canonicalize_name(requirement.name)] = requirement

    return requirements, includes


def exact_version(requirements: dict[str, Requirement], name: str) -> Version:
    requirement = requirements[canonicalize_name(name)]
    specifiers = list(requirement.specifier)

    assert len(specifiers) == 1
    assert specifiers[0].operator == "=="
    return Version(specifiers[0].version)


def load_input_pin_sets(
    path: Path,
    seen: set[Path] | None = None,
) -> dict[str, set[Version]]:
    seen = set() if seen is None else seen
    path = path.resolve()
    if path in seen:
        return {}
    seen.add(path)

    requirements, includes = load_requirements(path)
    pins = {
        name: {exact_version(requirements, name)}
        for name in requirements
    }
    for include in includes:
        nested = load_input_pin_sets(path.parent / include, seen)
        for name, versions in nested.items():
            pins.setdefault(name, set()).update(versions)
    return pins


def load_hash_lock(path: Path) -> dict[str, tuple[Version, set[str]]]:
    locked: dict[str, tuple[Version, set[str]]] = {}
    current_name: str | None = None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not raw_line[0].isspace():
            requirement = Requirement(stripped.removesuffix("\\").strip())
            name = canonicalize_name(requirement.name)
            assert name not in locked
            locked[name] = (exact_version({name: requirement}, name), set())
            current_name = name
            continue

        hash_match = HASH.fullmatch(stripped.removesuffix("\\").strip())
        assert current_name is not None
        assert hash_match is not None, raw_line
        locked[current_name][1].add(hash_match["digest"])

    assert all(hashes for _, hashes in locked.values())
    return locked


def test_shared_constraints_lock_the_compatible_intersection() -> None:
    constraints, includes = load_requirements(
        ROOT / "containers" / "constraints-all-tools.txt"
    )

    assert not includes
    expected = {
        "google-api-core": "2.34.0",
        "googleapis-common-protos": "1.75.3",
        "grpcio": "1.83.1",
        "grpcio-status": "1.83.1",
        "jsonschema": "4.25.1",
        "opentelemetry-api": "1.37.0",
        "opentelemetry-exporter-otlp-proto-common": "1.37.0",
        "opentelemetry-exporter-otlp-proto-http": "1.37.0",
        "opentelemetry-instrumentation": "0.58b0",
        "opentelemetry-instrumentation-requests": "0.58b0",
        "opentelemetry-instrumentation-threading": "0.58b0",
        "opentelemetry-proto": "1.37.0",
        "opentelemetry-sdk": "1.37.0",
        "opentelemetry-semantic-conventions": "0.58b0",
        "opentelemetry-util-http": "0.58b0",
        "proto-plus": "1.28.4",
        "protobuf": "6.33.6",
        "rich": "14.3.4",
    }

    assert set(constraints) == set(expected)
    assert {
        name: str(exact_version(constraints, name)) for name in expected
    } == expected

    rich = exact_version(constraints, "rich")
    protobuf = exact_version(constraints, "protobuf")
    google_api_core = exact_version(constraints, "google-api-core")

    assert Version("13.7.0") <= rich < Version("15.0.0")
    assert Version("6.33.5") <= protobuf < Version("7.0.0")
    assert Version("2.28.0") <= google_api_core < Version("2.36.0")
    assert canonicalize_name("z3-solver") not in constraints


def test_all_tools_inputs_keep_required_exact_pins() -> None:
    runtime, runtime_includes = load_requirements(ROOT / "requirements.txt")
    development, development_includes = load_requirements(
        ROOT / "requirements-dev.txt"
    )
    grammars, grammar_includes = load_requirements(
        ROOT / "requirements-grammars.txt"
    )
    optional, optional_includes = load_requirements(
        ROOT / ".devcontainer" / "requirements-all-optional.txt"
    )
    all_tools, all_tools_includes = load_requirements(
        ROOT / "containers" / "requirements-all-tools.txt"
    )
    angr, angr_includes = load_requirements(
        ROOT / "containers" / "requirements-angr.txt"
    )
    atheris, atheris_includes = load_requirements(
        ROOT / "containers" / "requirements-atheris-amd64.txt"
    )

    assert not runtime_includes
    assert development_includes == {"requirements.txt"}
    assert not grammar_includes
    assert optional_includes == {"../requirements.txt"}
    assert all_tools_includes == {"../requirements-grammars.txt"}
    assert not angr_includes
    assert not atheris_includes

    assert str(exact_version(runtime, "instructor")) == "1.15.4"
    assert str(exact_version(development, "z3-solver")) == "4.15.4.0"
    assert set(grammars) == {
        "tree-sitter",
        "tree-sitter-c",
        "tree-sitter-c-sharp",
        "tree-sitter-cpp",
        "tree-sitter-go",
        "tree-sitter-java",
        "tree-sitter-javascript",
        "tree-sitter-kotlin",
        "tree-sitter-lua",
        "tree-sitter-php",
        "tree-sitter-python",
        "tree-sitter-ruby",
        "tree-sitter-rust",
        "tree-sitter-scala",
        "tree-sitter-swift",
        "tree-sitter-typescript",
    }
    for name in grammars:
        exact_version(grammars, name)

    expected_optional = {
        "frida": "17.17.0",
        "jsonschema": "4.25.1",
        "pyghidra": "3.1.0",
        "r2pipe": "1.9.8",
        "z3-solver": "4.15.4.0",
    }
    expected_all_tools = {
        "cvss": "3.6",
        "frida-tools": "14.10.4",
        "google-auth": "2.57.1",
        "google-cloud-bigquery": "3.45.0",
        "h2": "4.4.1",
        "orjson": "3.11.9",
        "pwntools": "4.15.0",
    }
    expected_angr = {
        "angr": "9.3.4",
        "z3-solver": "4.13.0.0",
    }

    assert {
        name: str(exact_version(optional, name)) for name in expected_optional
    } == expected_optional
    assert {
        name: str(exact_version(all_tools, name)) for name in expected_all_tools
    } == expected_all_tools
    assert {
        name: str(exact_version(angr, name)) for name in expected_angr
    } == expected_angr
    assert str(exact_version(atheris, "atheris")) == "3.1.0"


def test_lock_targets_semgrep_1_172() -> None:
    base_lock = load_hash_lock(BASE_LOCK)
    assert base_lock["semgrep"][0] == Version("1.172.0")


def test_generated_hash_locks_cover_the_complete_environments() -> None:
    base = load_hash_lock(BASE_LOCK)
    all_tools = load_hash_lock(ALL_TOOLS_LOCK)
    base_inputs = load_input_pin_sets(BASE_INPUT)
    all_tools_inputs = load_input_pin_sets(ALL_TOOLS_INPUT)

    assert len(base) == 129
    assert len(all_tools) == 213
    assert set(base) <= set(all_tools)

    assert all(len(versions) == 1 for versions in base_inputs.values())
    for name, versions in base_inputs.items():
        assert base[name][0] == next(iter(versions))

    conflicts = {
        name: versions
        for name, versions in all_tools_inputs.items()
        if len(versions) > 1
    }
    assert conflicts == {
        "z3-solver": {Version("4.13.0.0"), Version("4.15.4.0")}
    }
    for name, versions in all_tools_inputs.items():
        expected = (
            Version("4.13.0.0")
            if name == "z3-solver"
            else next(iter(versions))
        )
        assert all_tools[name][0] == expected

    assert base["z3-solver"][0] == Version("4.15.4.0")
    assert all_tools["z3-solver"][0] == Version("4.13.0.0")

    manifest = json.loads(
        (ROOT / "containers" / "all-tools-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    for package in manifest["python_packages"]:
        name = canonicalize_name(package["distribution"])
        assert all_tools[name][0] == Version(package["version"])


def test_lock_generation_is_pinned_to_python_314_amd64_snapshot() -> None:
    expected_options = (
        "--python-version 3.14",
        "--python-platform x86_64-manylinux_2_36",
        "--generate-hashes",
        "--exclude-newer 2026-09-09T00:00:00Z",
    )

    for path in (BASE_LOCK, ALL_TOOLS_LOCK):
        header = "\n".join(
            path.read_text(encoding="utf-8").splitlines()[:2]
        )
        for option in expected_options:
            assert option in header

    all_tools_header = "\n".join(
        ALL_TOOLS_LOCK.read_text(encoding="utf-8").splitlines()[:2]
    )
    assert "--overrides containers/requirements-angr.txt" in all_tools_header


def test_dockerfile_uses_only_complete_hash_locked_python_transactions() -> None:
    dockerfile = (ROOT / ".devcontainer" / "Dockerfile").read_text(encoding="utf-8")
    commands = re.findall(
        r"^RUN python3 -m pip install (?P<command>.*?)(?=\n\n)",
        dockerfile,
        re.MULTILINE | re.DOTALL,
    )

    assert len(commands) == 2
    assert {
        path
        for command in commands
        for path in re.findall(r"-r (/tmp/raptor/requirements-[^ \\\n]+)", command)
    } == {
        "/tmp/raptor/requirements-base.lock",
        "/tmp/raptor/requirements-all-tools.lock",
    }
    for command in commands:
        assert "--require-hashes" in command
        assert "--no-deps" in command

    devcontainer = (
        ROOT / ".devcontainer" / "devcontainer.json"
    ).read_text(encoding="utf-8")
    assert "postCreateCommand" not in devcontainer
    assert "pip install" not in devcontainer

    for ignore_file in (ROOT / ".dockerignore", ROOT / ".containerignore"):
        ignored = ignore_file.read_text(encoding="utf-8")
        assert "!/containers/requirements-base.lock" in ignored
        assert "!/containers/requirements-all-tools.lock" in ignored


def test_opentelemetry_families_stay_synchronized() -> None:
    constraints, _ = load_requirements(
        ROOT / "containers" / "constraints-all-tools.txt"
    )

    stable = {
        exact_version(constraints, name)
        for name in (
            "opentelemetry-api",
            "opentelemetry-exporter-otlp-proto-common",
            "opentelemetry-exporter-otlp-proto-http",
            "opentelemetry-proto",
            "opentelemetry-sdk",
        )
    }
    beta = {
        exact_version(constraints, name)
        for name in (
            "opentelemetry-instrumentation",
            "opentelemetry-instrumentation-requests",
            "opentelemetry-instrumentation-threading",
            "opentelemetry-semantic-conventions",
            "opentelemetry-util-http",
        )
    }

    assert stable == {Version("1.37.0")}
    assert beta == {Version("0.58b0")}
