"""validate_build_command version probes must never run inside the scanned repo.

Regression: the probe passed ``cwd=build_system.working_dir`` — a path
inside the untrusted target — to ``_run_trusted`` (explicitly
unsandboxed). Maven's launcher walks up from cwd to find a ``.mvn/``
directory and loads ``.mvn/jvm.config`` even for ``mvn --version``, so a
scanned repo shipping ``.mvn/jvm.config`` with
``-javaagent:<repo>/evil.jar`` executed attacker code with full operator
privileges on the default /codeql and /agentic flows, before any sandbox
engaged and before any build was attempted. yarn classic's ``yarn-path``
(from a ``.yarnrc`` found by the same upward walk) is the same class.

Fix: every probe runs from the filesystem root (``_PROBE_CWD``), whose
upward config walk terminates at root-owned paths. Argv is a RAPTOR
constant and env comes from get_safe_env(), so the probe carries no
attacker-controlled input at all.
"""

import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from core.build.build_detector import BuildDetector, BuildSystem

# Every build-system type validate_build_command has a probe for —
# enumerated from the source of truth, so a probe added to the map is
# AUTOMATICALLY covered by the neutral-cwd assertion (the maven
# incident was exactly a second tool re-opening a class the gradle
# probe had already been hardened against). The subset pin below keeps
# an accidental map shrink loud as well.
PROBED_TYPES = sorted(BuildDetector._VALIDATION_COMMANDS)

_KNOWN_MINIMUM = {
    "maven", "gradle", "ant", "npm", "yarn", "pnpm", "pip", "poetry",
    "gomod", "cmake", "make", "dotnet", "bundler",
}


def test_probe_map_covers_known_build_tool_families():
    assert _KNOWN_MINIMUM <= set(PROBED_TYPES)


def _build_system(build_type: str, working_dir: Path) -> BuildSystem:
    # "gradle build" (not "./gradlew ...") so the gradle entry takes the
    # system-gradle probe path like every other tool.
    return BuildSystem(
        type=build_type, command=f"{build_type} build", working_dir=working_dir,
        env_vars={}, confidence=0.9, detected_files=[],
    )


def _ok_probe():
    return mock.patch(
        "core.build.build_detector._run_trusted",
        return_value=SimpleNamespace(returncode=0),
    )


@pytest.mark.parametrize("build_type", PROBED_TYPES)
def test_probe_never_runs_with_repo_cwd(tmp_path, build_type):
    repo = tmp_path / "repo"
    repo.mkdir()
    bs = _build_system(build_type, repo)

    with _ok_probe() as run:
        assert BuildDetector(repo).validate_build_command(bs) is True

    cwd = run.call_args.kwargs["cwd"]
    assert cwd == os.sep
    resolved = Path(cwd).resolve()
    assert resolved != repo.resolve()
    assert not str(resolved).startswith(str(repo.resolve()))


def test_gradle_wrapper_java_probe_uses_neutral_cwd(tmp_path):
    gradlew = tmp_path / "gradlew"
    gradlew.write_text("#!/bin/sh\nexit 0\n")
    gradlew.chmod(0o755)
    bs = BuildSystem(
        type="gradle", command="./gradlew build -x test --no-daemon",
        working_dir=tmp_path, env_vars={}, confidence=0.9,
        detected_files=["build.gradle"],
    )

    with _ok_probe() as run:
        assert BuildDetector(tmp_path).validate_build_command(bs) is True

    assert run.call_args.args[0] == ["java", "-version"]
    assert run.call_args.kwargs["cwd"] == os.sep


def test_missing_working_dir_still_fails_before_probe(tmp_path):
    bs = _build_system("maven", tmp_path / "gone")

    with _ok_probe() as run:
        assert BuildDetector(tmp_path).validate_build_command(bs) is False

    run.assert_not_called()


def _malicious_maven_repo(tmp_path: Path) -> tuple[Path, Path]:
    """Fixture repo shipping the hostile `.mvn/jvm.config` + a canary path."""
    repo = tmp_path / "repo"
    (repo / ".mvn").mkdir(parents=True)
    (repo / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        "<modelVersion>4.0.0</modelVersion>"
        "<groupId>g</groupId><artifactId>a</artifactId>"
        "<version>1</version></project>\n"
    )
    canary = tmp_path / "canary-agent-executed"
    (repo / ".mvn" / "jvm.config").write_text(
        f"-javaagent:{repo}/evil.jar\n"
    )
    return repo, canary


def test_malicious_maven_config_not_consumed_by_probe(tmp_path, monkeypatch):
    """End-to-end through the real _run_trusted with a shim `mvn` on PATH.

    The shim emulates the Maven launcher's config discovery: walk up
    from cwd looking for `.mvn/jvm.config` and touch the canary when
    found (stand-in for the JVM executing the repo-shipped -javaagent).
    Post-fix the probe runs from the filesystem root, so the shim never
    sees the repo's `.mvn/` — the canary stays absent AND validation
    still succeeds (legitimate path: tool detected as available).
    """
    repo, canary = _malicious_maven_repo(tmp_path)

    shim_dir = tmp_path / "bin"
    shim_dir.mkdir()
    shim = shim_dir / "mvn"
    # Canary path baked in at generation time — get_safe_env() strips
    # test-set env vars, so the shim can't receive it via the env.
    shim.write_text(
        "#!/bin/sh\n"
        '# Emulate Maven launcher project-dir discovery from $PWD upward.\n'
        'd="$(pwd)"\n'
        "while :; do\n"
        f'  if [ -f "$d/.mvn/jvm.config" ]; then touch {canary}; break; fi\n'
        '  [ "$d" = "/" ] && break\n'
        '  d="$(dirname "$d")"\n'
        "done\n"
        'echo "Apache Maven 9.9.9 (shim)"\n'
        "exit 0\n"
    )
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shim_dir}{os.pathsep}{os.environ.get('PATH', '')}")

    # Non-vacuity control: prove the shim DOES detect the hostile config
    # when run with the repo as cwd (i.e. the pre-fix probe invocation
    # would have triggered it).
    subprocess.run([str(shim)], cwd=repo, check=True,
                   stdout=subprocess.DEVNULL, timeout=30)
    assert canary.exists(), "shim self-check failed — test would be vacuous"
    canary.unlink()

    bs = BuildSystem(
        type="maven",
        command="mvn clean compile -DskipTests -Dmaven.test.skip=true",
        working_dir=repo, env_vars={}, confidence=0.9,
        detected_files=["pom.xml"],
    )
    assert BuildDetector(repo).validate_build_command(bs) is True
    assert not canary.exists(), (
        "probe consumed the repo's .mvn/jvm.config — code-execution "
        "channel is open again"
    )


def test_probe_missing_tool_gracefully_unvalidated(tmp_path, monkeypatch):
    """Tool absent from PATH → validation returns False, no crash."""
    repo = tmp_path / "repo"
    repo.mkdir()
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))

    bs = _build_system("maven", repo)
    assert BuildDetector(repo).validate_build_command(bs) is False


@pytest.mark.skipif(shutil.which("mvn") is None, reason="mvn not installed")
def test_real_maven_probe_ignores_repo_jvm_config(tmp_path):
    """With real Maven installed: a hostile `.mvn/jvm.config` must not
    reach the probe's JVM.

    Uses an unrecognizable JVM option as the observable payload — the
    same channel the -javaagent attack rides. Pre-fix, `mvn --version`
    with cwd inside the repo consumed the config and died with
    "Unrecognized option" (proving arbitrary JVM args, agent loading
    included); post-fix the config is never read and the version probe
    succeeds.
    """
    repo = tmp_path / "repo"
    (repo / ".mvn").mkdir(parents=True)
    (repo / "pom.xml").write_text("<project/>\n")
    (repo / ".mvn" / "jvm.config").write_text("-Xbogus_raptor_probe_regression\n")

    bs = BuildSystem(
        type="maven",
        command="mvn clean compile -DskipTests -Dmaven.test.skip=true",
        working_dir=repo, env_vars={}, confidence=0.9,
        detected_files=["pom.xml"],
    )
    assert BuildDetector(repo).validate_build_command(bs, timeout=120) is True
