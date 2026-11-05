"""Pin user instructions to a verified publication; run only in an isolated CI checkout."""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import fnmatch
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from dockerhub_scope import BUILD_INPUTS, copy_sources

IMAGE = "danielcuthbert/raptor"
STATE = ".github/published-image.json"
DOCS = ("README.md", "docs/installation.md")
MAX_BYTES = 2 * 1024 * 1024
IMAGE_REF = re.compile(r"(?<![\w/.-])(?:docker\.io/)?danielcuthbert/raptor(?::latest@sha256:[0-9a-f]{64}|@sha256:[0-9a-f]{64}|:latest)(?![\w:@.-])")


@dataclass(frozen=True)
class Publication:
    schema_version: int
    image: str
    digest: str
    source_commit: str
    image_inputs: str
    run_id: int
    run_attempt: int
    published_at: int
    run_url: str

    def validate(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1 or self.image != IMAGE:
            raise ValueError("unsupported publication record")
        for value, pattern in ((self.digest, r"sha256:[0-9a-f]{64}"),
                               (self.source_commit, r"[0-9a-f]{40}"),
                               (self.image_inputs, r"[0-9a-f]{64}")):
            if not isinstance(value, str) or not re.fullmatch(pattern, value):
                raise ValueError("invalid publication identity")
        if any(type(n) is not int or n <= 0 for n in (self.run_id, self.run_attempt, self.published_at)):
            raise ValueError("invalid publication ordering")
        if self.run_url != f"https://github.com/gadievron/raptor/actions/runs/{self.run_id}":
            raise ValueError("invalid publication run URL")


def bounded_text(path: Path) -> str:
    if path.is_symlink():
        raise ValueError("generated documentation must not be a symlink")
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("documentation input exceeds size limit")
    return data.decode("utf-8")


def pin_commands(text: str, digest: str) -> str:
    """Only Docker pull/run commands in Markdown fences use published images."""
    result = []
    fence = None
    active = False
    for line in text.splitlines(keepends=True):
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            active = False
        elif fence:
            if not active:
                active = bool(re.match(r"^\s*(?:\$\s*)?(?:sudo\s+)?docker\s+(?:pull|run)\b", line))
            if active:
                line = IMAGE_REF.sub(f"docker.io/{IMAGE}:latest@{digest}", line)
                active = line.rstrip().endswith(("\\", "`"))
        result.append(line)
    return "".join(result)


def check_build_inputs(root: Path) -> None:
    """Do not create a docs -> image -> docs rebuild cycle, even after COPY changes."""
    inputs = BUILD_INPUTS + copy_sources(bounded_text(root / ".devcontainer/Dockerfile"))
    for path in (*DOCS, STATE):
        for source in inputs:
            source = source.removeprefix("./").rstrip("/") or "."
            # Match ancestors as well as literal/globbed file inputs.
            if source == "." or any(fnmatch.fnmatchcase(parent, source)
                                    for parent in (path, *[p.as_posix() for p in Path(path).parents])):
                raise ValueError("published-image documentation overlaps image build inputs")


def update(root: Path, incoming: Publication) -> list[str]:
    from core.json import load_json, save_json

    incoming.validate()
    check_build_inputs(root)
    state = root / STATE
    if state.is_symlink():
        raise ValueError("publication record must not be a symlink")
    if state.exists():
        previous = Publication(**load_json(state, strict=True, max_bytes=64 * 1024))
        previous.validate()
        if previous.published_at > incoming.published_at:
            return []
        if previous.published_at == incoming.published_at and previous != incoming:
            raise ValueError("conflicting publications at the same timestamp")
    # Render everything before any writes, so malformed state/docs cannot leave a partial update.
    rendered = {name: pin_commands(bounded_text(root / name), incoming.digest) for name in DOCS}
    rendered[STATE] = json.dumps(asdict(incoming), indent=2) + "\n"
    changes = [name for name, text in rendered.items()
               if not (root / name).exists() or bounded_text(root / name) != text]
    for name in changes:
        if name == STATE:
            save_json(state, asdict(incoming))
        else:
            (root / name).write_text(rendered[name], encoding="utf-8")
    return changes


def git(root: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=root, env=env, check=True, timeout=60,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def sync_main(root: Path, incoming: Publication) -> None:
    """Normal fast-forward pushes only; regenerate on the latest main after a race."""
    incoming.validate()
    for attempt in range(3):
        git(root, "fetch", "--no-tags", "origin", "refs/heads/main")
        git(root, "checkout", "--detach", "FETCH_HEAD")
        changes = update(root, incoming)
        if not changes:
            return
        git(root, "add", "--", *changes)
        git(root, "-c", "user.name=github-actions[bot]",
            "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "-c", "commit.gpgsign=false", "commit", "-m", "docs: pin container instructions to the published image")
        # Workflow supplies request-scoped Git credentials in the environment.
        # They are never saved in .git/config, a remote URL or command arguments.
        try:
            git(root, "push", "origin", "HEAD:refs/heads/main")
            return
        except subprocess.CalledProcessError:
            if attempt == 2:
                raise RuntimeError("image published, but documentation push failed; inspect repository write permissions") from None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sync-main", action="store_true")
    args = parser.parse_args()
    incoming = Publication(1, IMAGE, os.environ["PUBLISHED_DIGEST"], os.environ["SOURCE_COMMIT"],
                           os.environ["IMAGE_INPUTS"], int(os.environ["GITHUB_RUN_ID"]),
                           int(os.environ["GITHUB_RUN_ATTEMPT"]), int(os.environ["PUBLISHED_AT"]),
                           f"https://github.com/gadievron/raptor/actions/runs/{os.environ['GITHUB_RUN_ID']}")
    root = Path(__file__).resolve().parents[2]
    if args.sync_main:
        sync_main(root, incoming)
    else:
        update(root, incoming)


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    main()
