#!/usr/bin/env python3

from __future__ import annotations

import argparse
import importlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


DEFAULT_MANIFEST = Path("/usr/local/share/raptor/all-tools-manifest.json")
PLAYWRIGHT_BROWSERS_PATH = Path("/opt/ms-playwright")
CARGO_FUZZ_SMOKE = Path("/usr/local/share/raptor/cargo-fuzz-smoke")
CARGO_FUZZ_VENDOR = Path("/usr/local/share/raptor/cargo-fuzz-vendor")
_HEX_DIGEST_LENGTHS = {
    "sha256": 64,
    "sha512": 128,
}
_REQUIRED_CLI_TOOLS = {
    "claude-code": (
        "Claude Code",
        "2.1.263",
        ["claude", "--version"],
        "2.1.263",
        [
            "node",
            "-p",
            "require('/opt/raptor/npm/base/node_modules/"
            "@anthropic-ai/claude-code/package.json').version",
        ],
    ),
    "copilot-cli": (
        "GitHub Copilot CLI",
        "1.0.83",
        [
            "/opt/raptor/npm/all-tools/node_modules/.bin/copilot",
            "--version",
        ],
        "1.0.83",
        [
            "node",
            "-p",
            "require('/opt/raptor/npm/all-tools/node_modules/"
            "@github/copilot/package.json').version",
        ],
    ),
    "yarn": (
        "Yarn",
        "1.22.22",
        ["yarn", "--version"],
        "1.22.22",
        [
            "node",
            "-p",
            "require('/opt/raptor/npm/base/node_modules/"
            "yarn/package.json').version",
        ],
    ),
    "pnpm": (
        "pnpm",
        "11.8.0",
        ["pnpm", "--version"],
        "11.8.0",
        [
            "node",
            "-p",
            "require('/opt/raptor/npm/base/node_modules/"
            "pnpm/package.json').version",
        ],
    ),
}
_REQUIRED_SNAPSHOT_TOOLS = {
    "semgrep": ("Semgrep", "1.172.0", ("semgrep",)),
    "java": ("Java runtime", "21.0.12.1", ("java",)),
    "javac": ("Java compiler", "21.0.12.1", ("javac",)),
    "ghidra": ("Ghidra", "12.1.3", ("ghidra", "analyzeHeadless")),
    "gradle": ("Gradle", "9.7.1", ("gradle",)),
    "joern": ("Joern", "4.0.622", ("joern", "joern-parse")),
    "gcloud": ("Google Cloud CLI", "583.0.0", ("gcloud",)),
    "ollama": ("Ollama", "0.33.3", ("ollama",)),
}
_JOERN_JAR_PREFIX = "io.joern.joern-cli-"
_CARGO_FUZZ_FIXTURE_LOCK_SHA256 = (
    "4baf46b199ba9c236d2ee3618e65ed30949ac240b112376a07543434c97e7b81"
)
_LIBFUZZER_SYS_VERSION = "0.4.13"
_LIBFUZZER_SYS_CHECKSUM = (
    "a9fd2f41a1cba099f79a0b6b6c35656cf7c03351a7bae8ff0f28f25270f929d2"
)
_VERSION_TOKEN_RE = re.compile(
    r"""
    (?<![A-Za-z0-9.])
    (?:(?:go|v)(?=\d))?
    (?P<version>
        \d
        (?=[A-Za-z0-9._+~-]*\.)
        [A-Za-z0-9._+~-]*
        [A-Za-z0-9]
    )
    (?!(?:[A-Za-z0-9_+~-]|\.(?=[A-Za-z0-9])))
    """,
    re.IGNORECASE | re.VERBOSE,
)


def normalize_arch(machine: str) -> str:
    return {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(machine.lower(), machine.lower())


def _normalized_version_tokens(text: str) -> list[str]:
    return [match.group("version") for match in _VERSION_TOKEN_RE.finditer(text)]


def version_output_matches(expected_version: str, output: str) -> bool:
    expected_match = _VERSION_TOKEN_RE.fullmatch(expected_version.strip())
    if expected_match is None:
        return False
    normalized_expected = expected_match.group("version")
    return normalized_expected in _normalized_version_tokens(output)


def version_probe_env(home: Path) -> dict[str, str]:
    env = runtime_probe_env()
    env.update(
        {
            "HOME": str(home),
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
        }
    )
    return env


def verify_command_version(
    expected_version: str,
    command: list[str],
    *,
    label: str | None = None,
) -> str | None:
    if not command:
        return "version command is empty"
    subject = label or command[0]
    with tempfile.TemporaryDirectory(prefix="raptor-version-probe-") as temp_dir:
        home = Path(temp_dir) / "home"
        home.mkdir()
        try:
            result = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
                stdin=subprocess.DEVNULL,
                env=version_probe_env(home),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"{subject} version check failed: {exc}"

    output = f"{result.stdout}\n{result.stderr}".strip()
    if result.returncode != 0:
        return (
            f"{subject} version check exited {result.returncode}: {output}"
        )
    if not version_output_matches(expected_version, output):
        return (
            f"{subject} version output does not contain exact "
            f"{expected_version}: {output}"
        )
    return None


def load_manifest(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    required_keys = {
        "schema_version",
        "snapshot_date",
        "supported_architectures",
        "tools",
        "python_packages",
        "required_python_imports",
        "required_binaries",
        "required_paths",
    }
    missing = sorted(required_keys - data.keys())
    if missing:
        raise ValueError(f"manifest missing keys: {', '.join(missing)}")
    if data["schema_version"] != 1:
        raise ValueError(f"unsupported manifest schema: {data['schema_version']}")
    if len(data["required_binaries"]) != len(set(data["required_binaries"])):
        raise ValueError("manifest contains duplicate required binaries")
    if not isinstance(data["tools"], dict):
        raise ValueError("manifest tools must be an object")
    for tool_name, tool in data["tools"].items():
        if not isinstance(tool, dict):
            raise ValueError(f"{tool_name} manifest entry must be an object")
        tool_version = tool.get("version")
        if not isinstance(tool_version, str) or not tool_version:
            raise ValueError(f"{tool_name} must define a non-empty version")
        command = tool.get("version_command")
        if (
            not isinstance(command, list)
            or not command
            or any(not isinstance(argument, str) or not argument for argument in command)
        ):
            raise ValueError(
                f"{tool_name} must define a non-empty version_command"
            )
    for tool_name, (
        display_name,
        expected_version,
        expected_command,
        expected_package_version,
        expected_package_command,
    ) in _REQUIRED_CLI_TOOLS.items():
        tool = data["tools"].get(tool_name)
        if tool is None:
            raise ValueError(f"manifest must define {display_name}")
        if tool.get("version") != expected_version:
            raise ValueError(f"{display_name} version must be {expected_version}")
        if tool.get("version_command") != expected_command:
            command_text = " ".join(expected_command)
            raise ValueError(
                f"{display_name} must be version-checked with `{command_text}`"
            )
        if tool.get("package_version") != expected_package_version:
            raise ValueError(
                f"{display_name} npm package version must be "
                f"{expected_package_version}"
            )
        if tool.get("package_version_command") != expected_package_command:
            command_text = " ".join(expected_package_command)
            raise ValueError(
                f"{display_name} npm package must be version-checked with "
                f"`{command_text}`"
            )
        required_binary = Path(expected_command[0]).name
        if required_binary not in data["required_binaries"]:
            raise ValueError(
                f"{display_name} binary `{required_binary}` must be required"
            )
    for tool_name, (
        display_name,
        expected_version,
        required_binaries,
    ) in _REQUIRED_SNAPSHOT_TOOLS.items():
        tool = data["tools"].get(tool_name)
        if tool is None:
            raise ValueError(f"manifest must define {display_name}")
        if tool.get("version") != expected_version:
            raise ValueError(f"{display_name} version must be {expected_version}")
        for binary in required_binaries:
            if binary not in data["required_binaries"]:
                raise ValueError(
                    f"{display_name} binary `{binary}` must be required"
                )
    codeql = data["tools"]["codeql"]
    if codeql["kind"] != "official-bundle":
        raise ValueError("CodeQL manifest entry must describe the official bundle")
    if (
        "github/codeql-action/releases/download/codeql-bundle-v2.26.4/"
        not in codeql["url"]
    ):
        raise ValueError("CodeQL manifest entry must use the official 2.26.4 bundle")
    if len(codeql["sha256"]) != 64:
        raise ValueError("CodeQL bundle must have a SHA-256 pin")

    packages = {package["distribution"]: package for package in data["python_packages"]}
    if len(packages) != len(data["python_packages"]):
        raise ValueError("manifest contains duplicate Python distributions")
    if packages.get("z3-solver", {}).get("version") != "4.13.0.0":
        raise ValueError("all-tools must use angr-compatible z3-solver 4.13.0.0")
    if packages.get("atheris", {}).get("architectures") != ["amd64"]:
        raise ValueError("Atheris must be explicitly limited to amd64")

    rr = data["tools"].get("rr")
    if rr is None:
        raise ValueError("manifest must define the Bookworm rr package")
    if rr.get("version") != "5.6.0":
        raise ValueError("rr upstream version must be 5.6.0")
    if rr.get("package") != "rr":
        raise ValueError("rr package name must be `rr`")
    if rr.get("package_version") != "5.6.0-3+b1":
        raise ValueError("rr Bookworm package version must be 5.6.0-3+b1")
    if rr.get("version_command") != ["rr", "--version"]:
        raise ValueError("rr must be version-checked with `rr --version`")
    if "rr" not in data["required_binaries"]:
        raise ValueError("rr must be a required all-tools binary")

    rust = data["tools"].get("rust")
    if rust is None:
        raise ValueError("manifest must define Rust")
    snapshot_date = data["snapshot_date"]
    if (
        not isinstance(snapshot_date, str)
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}", snapshot_date) is None
    ):
        raise ValueError("snapshot_date must use YYYY-MM-DD")
    expected_nightly = f"nightly-{snapshot_date}"
    if rust.get("nightly_toolchain") != expected_nightly:
        raise ValueError(
            f"Rust nightly toolchain must be date-pinned as {expected_nightly}"
        )
    nightly_version = rust.get("nightly_version")
    if (
        not isinstance(nightly_version, str)
        or re.fullmatch(
            r"\d+\.\d+\.\d+-nightly \([0-9a-f]{9} \d{4}-\d{2}-\d{2}\)",
            nightly_version,
        )
        is None
    ):
        raise ValueError("Rust nightly_version must record the exact nightly rustc")
    for required_path in (
        PLAYWRIGHT_BROWSERS_PATH,
        CARGO_FUZZ_SMOKE,
        CARGO_FUZZ_VENDOR,
    ):
        if str(required_path) not in data["required_paths"]:
            raise ValueError(f"manifest must require runtime path {required_path}")

    cargo_fuzz = data["tools"].get("cargo-fuzz")
    if cargo_fuzz is None:
        raise ValueError("manifest must define cargo-fuzz")
    for field in ("fixture_lock_sha256", "libfuzzer_sys_checksum"):
        digest = cargo_fuzz.get(field)
        if (
            not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            raise ValueError(
                f"cargo-fuzz {field} must be exactly 64 lowercase "
                "hexadecimal characters"
            )
    if cargo_fuzz.get("fixture_lock_sha256") != _CARGO_FUZZ_FIXTURE_LOCK_SHA256:
        raise ValueError("cargo-fuzz fixture lock SHA-256 is not the pinned digest")
    if cargo_fuzz.get("libfuzzer_sys_version") != _LIBFUZZER_SYS_VERSION:
        raise ValueError(
            f"cargo-fuzz fixture must pin libfuzzer-sys {_LIBFUZZER_SYS_VERSION}"
        )
    if cargo_fuzz.get("libfuzzer_sys_checksum") != _LIBFUZZER_SYS_CHECKSUM:
        raise ValueError(
            "cargo-fuzz fixture libfuzzer-sys checksum is not the pinned digest"
        )

    for tool_name, tool in data["tools"].items():
        for field, expected_length in _HEX_DIGEST_LENGTHS.items():
            if field not in tool:
                continue
            digest = tool[field]
            if (
                not isinstance(digest, str)
                or len(digest) != expected_length
                or re.fullmatch(r"[0-9a-f]+", digest) is None
            ):
                raise ValueError(
                    f"{tool_name} {field} must be exactly "
                    f"{expected_length} lowercase hexadecimal characters"
                )
    return data


def runtime_probe_env() -> dict[str, str]:
    allowed = (
        "HOME",
        "LANG",
        "LC_ALL",
        "LD_LIBRARY_PATH",
        "PATH",
        "PLAYWRIGHT_BROWSERS_PATH",
        "RUSTUP_HOME",
    )
    return {
        name: os.environ[name]
        for name in allowed
        if name in os.environ
    }


def verify_joern_runtime(manifest: dict) -> list[str]:
    joern = shutil.which("joern") or shutil.which("joern-cli")
    joern_parse = shutil.which("joern-parse")
    errors: list[str] = []

    if joern is None:
        errors.append("joern-cli not found on PATH")
    if joern_parse is None:
        errors.append("joern-parse not found on PATH")
    if errors:
        return errors

    joern_path = Path(joern).resolve()
    joern_parse_path = Path(joern_parse).resolve()
    for name, path in (("joern", joern_path), ("joern-parse", joern_parse_path)):
        if not path.is_file() or not os.access(path, os.X_OK):
            errors.append(f"{name} launcher is not executable: {path}")
    if errors:
        return errors

    if joern_path.parent != joern_parse_path.parent:
        return [
            "joern and joern-parse do not resolve to the same installation: "
            f"{joern_path.parent} != {joern_parse_path.parent}"
        ]

    jars = sorted(
        (joern_path.parent / "lib").glob(f"{_JOERN_JAR_PREFIX}*.jar")
    )
    if len(jars) != 1:
        return [
            "Joern installation must contain exactly one "
            f"{_JOERN_JAR_PREFIX}*.jar, found {len(jars)}"
        ]

    actual_version = jars[0].name[len(_JOERN_JAR_PREFIX) : -4]
    expected_version = manifest["tools"]["joern"]["version"]
    if actual_version != expected_version:
        return [
            f"Joern distribution version {actual_version} != {expected_version}"
        ]
    return []


def verify_playwright_runtime() -> list[str]:
    configured_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if configured_path != str(PLAYWRIGHT_BROWSERS_PATH):
        return [
            "PLAYWRIGHT_BROWSERS_PATH "
            f"{configured_path!r} != {str(PLAYWRIGHT_BROWSERS_PATH)!r}"
        ]
    if not PLAYWRIGHT_BROWSERS_PATH.is_dir():
        return [f"missing Playwright browser directory: {PLAYWRIGHT_BROWSERS_PATH}"]
    if not os.access(PLAYWRIGHT_BROWSERS_PATH, os.R_OK | os.X_OK):
        return [
            "Playwright browser directory is not readable/searchable by "
            f"runtime user: {PLAYWRIGHT_BROWSERS_PATH}"
        ]

    script = """
from playwright.sync_api import sync_playwright

with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page()
    page.set_content("<title>raptor-playwright-runtime</title>")
    assert page.title() == "raptor-playwright-runtime"
    browser.close()
"""
    with tempfile.TemporaryDirectory(prefix="raptor-playwright-runtime-") as temp_dir:
        home = Path(temp_dir) / "home"
        cache = Path(temp_dir) / "cache"
        home.mkdir()
        cache.mkdir()
        env = runtime_probe_env()
        env.update(
            {
                "HOME": str(home),
                "XDG_CACHE_HOME": str(cache),
            }
        )
        try:
            result = subprocess.run(
                [sys.executable, "-c", script],
                text=True,
                capture_output=True,
                check=False,
                timeout=90,
                stdin=subprocess.DEVNULL,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return [f"Playwright Chromium launch failed: {exc}"]
    if result.returncode != 0:
        output = f"{result.stdout}\n{result.stderr}".strip()
        return [
            f"Playwright Chromium launch exited {result.returncode}: {output}"
        ]
    return []


def verify_rust_runtime(manifest: dict) -> list[str]:
    rust = manifest["tools"]["rust"]
    nightly = rust["nightly_toolchain"]
    env = runtime_probe_env()

    try:
        stable_result = subprocess.run(
            ["rustc", "--version"],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
            stdin=subprocess.DEVNULL,
            env=env,
        )
        nightly_result = subprocess.run(
            ["rustup", "run", nightly, "rustc", "--version"],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
            stdin=subprocess.DEVNULL,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"Rust runtime toolchain check failed: {exc}"]

    errors: list[str] = []
    stable_output = f"{stable_result.stdout}\n{stable_result.stderr}".strip()
    if stable_result.returncode != 0:
        errors.append(
            f"stable rustc check exited {stable_result.returncode}: {stable_output}"
        )
    elif not stable_result.stdout.startswith(f"rustc {rust['version']} "):
        errors.append(
            f"default rustc is not stable {rust['version']}: {stable_output}"
        )

    nightly_output = f"{nightly_result.stdout}\n{nightly_result.stderr}".strip()
    expected_nightly = f"rustc {rust['nightly_version']}"
    if nightly_result.returncode != 0:
        errors.append(
            f"{nightly} rustc check exited {nightly_result.returncode}: "
            f"{nightly_output}"
        )
    elif nightly_result.stdout.strip() != expected_nightly:
        errors.append(
            f"{nightly} rustc identity {nightly_result.stdout.strip()!r} "
            f"!= {expected_nightly!r}"
        )
    return errors


def verify_cargo_fuzz_runtime(manifest: dict) -> list[str]:
    for required_path in (CARGO_FUZZ_SMOKE, CARGO_FUZZ_VENDOR):
        if not required_path.is_dir():
            return [f"missing cargo-fuzz runtime fixture: {required_path}"]
        if not os.access(required_path, os.R_OK | os.X_OK):
            return [
                f"cargo-fuzz runtime fixture is not readable/searchable: "
                f"{required_path}"
            ]

    rust = manifest["tools"]["rust"]
    with tempfile.TemporaryDirectory(prefix="raptor-cargo-fuzz-runtime-") as temp_dir:
        temp_path = Path(temp_dir)
        project = temp_path / "project"
        cargo_home = temp_path / "cargo-home"
        target_dir = temp_path / "target"
        home = temp_path / "home"
        rustc_args_log = temp_path / "rustc-args.log"
        rustc_version_log = temp_path / "rustc-version.log"
        rustc_wrapper = temp_path / "rustc-wrapper"

        shutil.copytree(CARGO_FUZZ_SMOKE, project)
        cargo_home.mkdir()
        target_dir.mkdir()
        home.mkdir()
        rustc_wrapper.write_text(
            """#!/bin/sh
set -eu
"$1" --version >> "$RAPTOR_RUSTC_VERSION_LOG"
printf '%s\\n' "$*" >> "$RAPTOR_RUSTC_ARGS_LOG"
exec "$@"
""",
            encoding="utf-8",
        )
        rustc_wrapper.chmod(0o755)

        env = runtime_probe_env()
        env.update(
            {
                "CARGO_BUILD_JOBS": "1",
                "CARGO_HOME": str(cargo_home),
                "CARGO_NET_OFFLINE": "true",
                "CARGO_TARGET_DIR": str(target_dir),
                "HOME": str(home),
                "RAPTOR_RUSTC_ARGS_LOG": str(rustc_args_log),
                "RAPTOR_RUSTC_VERSION_LOG": str(rustc_version_log),
                "RUSTC_WRAPPER": str(rustc_wrapper),
            }
        )
        try:
            result = subprocess.run(
                ["cargo-fuzz", "build", "--verbose", "smoke"],
                cwd=project,
                text=True,
                capture_output=True,
                check=False,
                timeout=300,
                stdin=subprocess.DEVNULL,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return [f"cargo-fuzz offline sanitizer build failed: {exc}"]

        output = f"{result.stdout}\n{result.stderr}".strip()
        if result.returncode != 0:
            return [
                f"cargo-fuzz offline sanitizer build exited "
                f"{result.returncode}: {output}"
            ]
        if not rustc_args_log.is_file():
            return ["cargo-fuzz build did not invoke rustc through the probe wrapper"]

        rustc_args = rustc_args_log.read_text(encoding="utf-8")
        if (
            re.search(
                r"-(?:C|Z)(?:\s*)sanitizer=address",
                rustc_args,
            )
            is None
        ):
            return [
                "cargo-fuzz build completed without an AddressSanitizer "
                "rustc invocation"
            ]

        rustc_versions = rustc_version_log.read_text(encoding="utf-8")
        expected_nightly = f"rustc {rust['nightly_version']}"
        if expected_nightly not in rustc_versions:
            return [
                f"cargo-fuzz did not compile with {rust['nightly_toolchain']}: "
                f"{rustc_versions.strip()}"
            ]

        fuzz_binaries = [
            path
            for path in target_dir.rglob("smoke")
            if path.is_file() and os.access(path, os.X_OK)
        ]
        if not fuzz_binaries:
            return ["cargo-fuzz build produced no executable smoke target"]
    return []


def verify_runtime_probes(manifest: dict) -> list[str]:
    errors: list[str] = []
    errors.extend(verify_joern_runtime(manifest))
    errors.extend(verify_playwright_runtime())
    errors.extend(verify_rust_runtime(manifest))
    errors.extend(verify_cargo_fuzz_runtime(manifest))
    return errors


def verify_installed(manifest: dict) -> list[str]:
    errors: list[str] = []
    arch = normalize_arch(platform.machine())
    if arch not in manifest["supported_architectures"]:
        return [f"unsupported all-tools architecture: {arch}"]

    for binary in manifest["required_binaries"]:
        if shutil.which(binary) is None:
            errors.append(f"missing binary: {binary}")

    for raw_path in manifest["required_paths"]:
        if not Path(raw_path).exists():
            errors.append(f"missing path: {raw_path}")

    for tool_name, tool in manifest["tools"].items():
        package_version = tool.get("package_version")
        if package_version:
            package_version_command = tool.get("package_version_command")
            package_name = tool.get("package", tool_name)
            command = package_version_command or [
                "dpkg-query",
                "-W",
                "-f=${Version}",
                package_name,
            ]
            try:
                package_result = subprocess.run(
                    command,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=30,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                errors.append(f"{tool_name} package version check failed: {exc}")
            else:
                actual_package_version = package_result.stdout.strip()
                if package_result.returncode != 0:
                    errors.append(
                        f"{tool_name} package version check exited "
                        f"{package_result.returncode}: "
                        f"{package_result.stderr.strip()}"
                    )
                elif actual_package_version != package_version:
                    errors.append(
                        f"{tool_name} package version "
                        f"{actual_package_version} != {package_version}"
                    )

        command = tool.get("version_command")
        if not command:
            continue
        version_error = verify_command_version(
            tool["version"],
            command,
            label=tool_name,
        )
        if version_error is not None:
            errors.append(version_error)

    try:
        r2_plugins = subprocess.run(
            ["r2", "-q", "-c", "Lc~ghidra", "/dev/null"],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append(f"r2ghidra plugin check failed: {exc}")
    else:
        if r2_plugins.returncode != 0 or "ghidra" not in r2_plugins.stdout.lower():
            errors.append("r2ghidra plugin is not available to radare2")

    for package in manifest["python_packages"]:
        architectures = package.get(
            "architectures", manifest["supported_architectures"]
        )
        if arch not in architectures:
            continue
        distribution = package["distribution"]
        expected_version = package["version"]
        try:
            actual_version = version(distribution)
        except PackageNotFoundError:
            errors.append(f"missing Python distribution: {distribution}")
            continue
        if actual_version != expected_version:
            errors.append(
                f"{distribution} version {actual_version} != {expected_version}"
            )
        for module in package["imports"]:
            try:
                importlib.import_module(module)
            except ImportError as exc:
                errors.append(f"cannot import {module}: {exc}")

    for module in manifest["required_python_imports"]:
        try:
            importlib.import_module(module)
        except ImportError as exc:
            errors.append(f"cannot import {module}: {exc}")

    pip_check = subprocess.run(
        [sys.executable, "-m", "pip", "check"],
        text=True,
        capture_output=True,
        check=False,
    )
    if pip_check.returncode != 0:
        errors.append(f"pip check failed: {pip_check.stdout}{pip_check.stderr}".strip())

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the RAPTOR all-tools image")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--manifest-only", action="store_true")
    mode.add_argument("--runtime-probes", action="store_true")
    parser.add_argument("--check-version", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if args.check_version is not None:
        if len(args.check_version) < 2:
            parser.error("--check-version requires VERSION COMMAND [ARG ...]")
        expected_version, *command = args.check_version
        error = verify_command_version(expected_version, command)
        if error is not None:
            print(f"executable verification: {error}", file=sys.stderr)
            return 1
        print(f"{command[0]} exact version {expected_version} verified")
        return 0

    try:
        manifest = load_manifest(args.manifest)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"all-tools manifest invalid: {exc}", file=sys.stderr)
        return 2

    if args.manifest_only:
        print(f"all-tools manifest {manifest['snapshot_date']} is valid")
        return 0

    if args.runtime_probes:
        errors = verify_runtime_probes(manifest)
        if errors:
            for error in errors:
                print(f"all-tools runtime probe: {error}", file=sys.stderr)
            return 1
        nightly = manifest["tools"]["rust"]["nightly_toolchain"]
        print(f"all-tools runtime probes verified with {nightly}")
        return 0

    errors = verify_installed(manifest)
    if errors:
        for error in errors:
            print(f"all-tools verification: {error}", file=sys.stderr)
        return 1

    print(f"all-tools snapshot {manifest['snapshot_date']} verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
