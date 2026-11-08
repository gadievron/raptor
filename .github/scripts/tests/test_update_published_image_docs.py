"""Published instructions follow verified pushes without changing local-build commands."""
from dataclasses import asdict, replace
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

from core.testing.module_registry import module_registry_scope

SCRIPTS = Path(__file__).resolve().parents[1]
with patch.object(sys, "path", sys.path.copy()), module_registry_scope("update_published_image_docs") as modules:
    sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location("update_published_image_docs", SCRIPTS / "update_published_image_docs.py")
    module = importlib.util.module_from_spec(spec)
    modules[spec.name] = module
    spec.loader.exec_module(module)


@pytest.fixture(scope="module", autouse=True)
def _registered_helpers():
    with module_registry_scope(spec.name) as modules:
        modules[spec.name] = module
        yield


def publication(**changes):
    return replace(module.Publication(1, module.IMAGE, "sha256:" + "a" * 64,
                                     "b" * 40, "c" * 64, 123, 1, 1700000000,
                                     "https://github.com/gadievron/raptor/actions/runs/123"), **changes)


@pytest.fixture
def repo(tmp_path):
    (tmp_path / ".github").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / ".devcontainer").mkdir()
    (tmp_path / ".devcontainer/Dockerfile").write_text("FROM base\nCOPY pyproject.toml /tmp/\n")
    for name in module.DOCS:
        (tmp_path / name).write_text("```bash\ndocker pull docker.io/danielcuthbert/raptor:latest\n"
                                    "docker run -it \\\n  danielcuthbert/raptor:latest\n"
                                    "docker build -t raptor:local .\n```\n")
    return tmp_path


def test_updates_all_examples_and_records_exact_publication(repo):
    p = publication()
    assert set(module.update(repo, p)) == {*module.DOCS, module.STATE}
    for name in module.DOCS:
        text = (repo / name).read_text()
        assert text.count("docker.io/" + module.IMAGE + ":latest@" + p.digest) == 2
        assert "docker build -t raptor:local ." in text
    assert json.loads((repo / module.STATE).read_text()) == asdict(p)
    assert module.update(repo, p) == []


def test_only_prebuilt_commands_change():
    text = """prose danielcuthbert/raptor:latest
```bash
docker pull danielcuthbert/raptor:latest
sudo docker run --rm \\
  danielcuthbert/raptor:latest
docker build -t danielcuthbert/raptor:latest .
docker pull danielcuthbert/raptor:1.2.3
docker pull elsewhere/danielcuthbert/raptor:latest
```
~~~powershell
docker run --rm `
  docker.io/danielcuthbert/raptor:latest
~~~
"""
    updated = module.pin_commands(text, publication().digest)
    assert updated.count("@sha256:") == 3
    assert updated.count("docker.io/danielcuthbert/raptor:latest@sha256:") == 3
    assert module.pin_commands(updated, publication().digest) == updated
    newer = module.pin_commands(updated, "sha256:" + "d" * 64)
    assert newer.count(":latest@sha256:" + "d" * 64) == 3
    assert "prose danielcuthbert/raptor:latest" in updated
    assert "docker build -t danielcuthbert/raptor:latest ." in updated
    assert "docker pull danielcuthbert/raptor:1.2.3" in updated
    assert "docker pull elsewhere/danielcuthbert/raptor:latest" in updated


def test_stale_docs_rerun_cannot_replace_a_newer_publication(repo):
    newer = publication(digest="sha256:" + "d" * 64, published_at=1700000050)
    module.update(repo, newer)
    # Run IDs alone cannot order publications: an old build may be rerun later.
    assert module.update(repo, publication(run_id=999, run_url="https://github.com/gadievron/raptor/actions/runs/999")) == []
    assert json.loads((repo / module.STATE).read_text())["digest"] == newer.digest
    module.update(repo, publication(published_at=1700000100))
    assert json.loads((repo / module.STATE).read_text())["digest"] == publication().digest


@pytest.mark.parametrize("state", ['{broken', '{"schema_version":2}', '[]'])
def test_malformed_state_does_not_overwrite_docs(repo, state):
    (repo / module.STATE).write_text(state)
    before = [(repo / p).read_bytes() for p in module.DOCS]
    with pytest.raises((ValueError, TypeError)):
        module.update(repo, publication())
    assert [(repo / p).read_bytes() for p in module.DOCS] == before


@pytest.mark.parametrize("source", [".", "README.md", "docs/", "docs/*.md", ".github/published-image.json"])
def test_rejects_self_referential_build_inputs(repo, source):
    (repo / ".devcontainer/Dockerfile").write_text(f"FROM base\nCOPY {source} /tmp/\n")
    with pytest.raises(ValueError, match="overlaps"):
        module.update(repo, publication())
    assert not (repo / module.STATE).exists()


@pytest.mark.parametrize("changes", [dict(digest="latest"), dict(source_commit="main"),
                                     dict(published_at=0), dict(run_url="https://elsewhere.invalid")])
def test_invalid_publication_never_writes(repo, changes):
    with pytest.raises(ValueError):
        module.update(repo, publication(**changes))
    assert not (repo / module.STATE).exists()


def test_missing_later_document_does_not_leave_partial_update(repo):
    before = (repo / module.DOCS[0]).read_bytes()
    (repo / module.DOCS[1]).unlink()
    with pytest.raises(FileNotFoundError):
        module.update(repo, publication())
    assert (repo / module.DOCS[0]).read_bytes() == before
    assert not (repo / module.STATE).exists()


def command(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.PIPE, text=True).strip()


def commit(root, message):
    command(root, "add", ".")
    command(root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "-qm", message)


def test_push_race_preserves_new_main_changes_and_uses_fast_forward(repo, tmp_path_factory, monkeypatch):
    command(repo, "init", "-q", "-b", "main")
    commit(repo, "initial")
    remote = tmp_path_factory.mktemp("publication-remote")
    command(remote, "init", "--bare", "-q", "--initial-branch=main")
    command(repo, "remote", "add", "origin", str(remote))
    command(repo, "push", "-q", "origin", "main")
    other = tmp_path_factory.mktemp("publication-racer")
    command(other, "clone", "-q", str(remote), ".")
    original = module.git
    pushed = []

    def race(root, *args, **kwargs):
        if args[0] == "push":
            pushed.append(args)
            if len(pushed) == 1:
                (other / "README.md").write_text("Concurrent user edit\n" + (other / "README.md").read_text())
                commit(other, "concurrent change")
                command(other, "push", "-q", "origin", "main")
        return original(root, *args, **kwargs)

    monkeypatch.setattr(module, "git", race)
    module.sync_main(repo, publication())
    assert len(pushed) == 2
    assert all(args == ("push", "origin", "HEAD:refs/heads/main") for args in pushed)
    published_readme = command(remote, "show", "main:README.md")
    assert "Concurrent user edit" in published_readme
    assert publication().digest in published_readme
    before = command(remote, "rev-parse", "main")
    module.sync_main(repo, publication())
    assert command(remote, "rev-parse", "main") == before


@pytest.mark.parametrize("filename", ["test_update_published_image_docs.py", "test_ci_publish_scope.py"])
def test_test_collection_restores_import_state(filename):
    path_object = sys.path
    path_values = list(sys.path)
    missing = object()
    names = ("update_published_image_docs", "dockerhub_scope", "ci_change_scope")
    before = {name: sys.modules.get(name, missing) for name in names}
    loader = importlib.util.spec_from_file_location("publication_collection_probe", SCRIPTS / "tests" / filename)
    probe = importlib.util.module_from_spec(loader)
    loader.loader.exec_module(probe)
    assert sys.path is path_object
    assert sys.path == path_values
    assert all(sys.modules.get(name, missing) is value for name, value in before.items())


def test_developer_commands_follow_the_verified_publication(repo):
    developer = repo / "docs/developers.md"
    developer.write_text("```bash\ndocker pull docker.io/danielcuthbert/raptor:latest\n"
                         "docker run -it docker.io/danielcuthbert/raptor:latest\n```\n")
    current = publication()
    module.update(repo, current)
    assert developer.read_text().count(":latest@" + current.digest) == 2
    newer = publication(digest="sha256:" + "d" * 64, published_at=current.published_at + 1)
    module.update(repo, newer)
    assert developer.read_text().count(":latest@" + newer.digest) == 2
