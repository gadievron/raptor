#!/usr/bin/env python3

"""
This script updates the dependencies inside the container files.

Sources:
  SEMGREP_VERSION     - https://github.com/semgrep/semgrep/releases (GitHub releases, pip install)
  CODEQL_VERSION      - https://github.com/github/codeql-cli-binaries/releases (GitHub releases)
  CLAUDE_CODE_VERSION - https://github.com/anthropics/claude-code/tags (GitHub tags, npm install)
"""

import json
import re
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

DOCKERFILES = [
    ".devcontainer/Dockerfile",
]

# Matches a stable semver tag, optionally v-prefixed (e.g. "v1.2.3" or "1.2.3").
# Pre-releases like "v1.2.3-rc.1" deliberately don't match — never auto-bump to one.
SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "devcontainer-updater",
        },
    )
    with urllib.request.urlopen(req) as resp:
        return resp.read()


def _github_latest_release(repo: str) -> str:
    """Return tag_name of the latest GitHub *release* for a repo (e.g. 'v2.25.3')."""
    data = json.loads(
        _fetch(f"https://api.github.com/repos/{repo}/releases/latest"))
    return data["tag_name"]


def _github_latest_tag(repo: str) -> str:
    """Return the highest stable-semver *tag* for a repo (e.g. 'v2.1.138').

    Use this when the project doesn't cut GitHub releases (or they lag the tags).
    Pre-release tags are filtered out so an alpha/rc never lands in a Dockerfile pin.
    """
    data = json.loads(
        _fetch(f"https://api.github.com/repos/{repo}/tags?per_page=100"))
    versions: list[tuple[tuple[int, int, int], str]] = []
    for entry in data:
        name = entry["name"]
        m = SEMVER_RE.match(name)
        if m is None:
            continue
        versions.append((tuple(int(g) for g in m.groups()), name))
    if not versions:
        raise RuntimeError(f"No stable semver tags found for {repo}")
    return max(versions)[1]


def get_latest_versions() -> dict[str, str]:
    """Fetch and return the latest version string for each tracked ARG.

    All three ARGs are stored as bare semver in the Dockerfile, so the leading
    'v' is stripped from every source.
    """
    return {
        "SEMGREP_VERSION": _github_latest_release("semgrep/semgrep").lstrip("v"),
        "CODEQL_VERSION": _github_latest_release("github/codeql-cli-binaries").lstrip("v"),
        "CLAUDE_CODE_VERSION": _github_latest_tag("anthropics/claude-code").lstrip("v"),
    }


def update_dockerfile(path: Path, latest: dict[str, str]) -> list[tuple[str, str, str]]:
    """
    Rewrite ARG version lines in a single Dockerfile.

    Only updates ARGs that are already present in the file; never adds new ones.
    Returns a list of (arg_name, old_version, new_version) for each change made.
    """
    content = path.read_text()
    changes: list[tuple[str, str, str]] = []

    for arg, new_version in latest.items():
        pattern = re.compile(rf"^(ARG {arg}=)(\S+)", re.MULTILINE)
        match = pattern.search(content)
        if match is None:
            continue  # ARG not present in this file — skip
        old_version = match.group(2)
        if old_version == new_version:
            continue  # already up to date
        content = pattern.sub(rf"\g<1>{new_version}", content)
        changes.append((arg, old_version, new_version))

    if changes:
        path.write_text(content)

    return changes


def main() -> None:
    print("Fetching latest versions...")
    latest = get_latest_versions()
    for arg, version in latest.items():
        print(f"  {arg}: {version}")

    print()
    any_changes = False

    for rel_path in DOCKERFILES:
        path = REPO_ROOT / rel_path
        if not path.exists():
            print(f"  SKIP {rel_path} (file not found)")
            continue

        changes = update_dockerfile(path, latest)
        if changes:
            any_changes = True
            for arg, old, new in changes:
                print(f"  {rel_path}: {arg}  {old} -> {new}")
        else:
            print(f"  {rel_path}: up to date")

    print()
    if any_changes:
        print(
            "Dockerfiles updated. Open a pull request and assign review to @some-natalie."
        )
    else:
        print("All dependencies are up to date. Close this issue.")


if __name__ == "__main__":
    main()
