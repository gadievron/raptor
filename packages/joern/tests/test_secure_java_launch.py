"""Private argument files preserve trusted JVM options without argv secrets."""

import json

import pytest

from packages.joern.server import _private_java_command


def fixture(tmp_path, monkeypatch):
    root = tmp_path / "distribution"
    (root / "bin").mkdir(parents=True)
    (root / "lib").mkdir()
    (root / "conf").mkdir()
    launcher = root / "bin" / "bridge"
    launcher.write_text("declare -a app_mainclass=('example.Main')\n")
    workspace = tmp_path / "private"
    workspace.mkdir()
    monkeypatch.setattr("packages.joern.prereqs._java_path", lambda: "/trusted/java")
    return root, launcher, workspace


def test_configuration_precedes_admitted_heap_and_secret_never_enters_argv(tmp_path, monkeypatch):
    root, launcher, workspace = fixture(tmp_path, monkeypatch)
    (root / "conf" / "application.ini").write_text("# JVM settings\n-J-Xss4m\n-J-Xmx99g\n")
    command = _private_java_command(str(launcher), ["-J-Xmx512m"],
                                    ["--server-auth-password", "private secret"], str(workspace))
    assert command == ["/trusted/java", "@" + str(workspace / "server.args")]
    assert "private secret" not in " ".join(command)
    arguments = [json.loads(line) for line in (workspace / "server.args").read_text().splitlines()]
    assert arguments.index("-Xmx99g") < arguments.index("-Xmx512m")
    assert "-Xss4m" in arguments and arguments[-1] == "private secret"
    assert (workspace / "server.args").stat().st_mode & 0o777 == 0o600


def test_unsupported_launcher_configuration_is_not_silently_ignored(tmp_path, monkeypatch):
    root, launcher, workspace = fixture(tmp_path, monkeypatch)
    (root / "conf" / "application.ini").write_text("-main alternate.Main\n")
    with pytest.raises(RuntimeError, match="unsupported"):
        _private_java_command(str(launcher), [], [], str(workspace))
    assert not (workspace / "server.args").exists()


@pytest.mark.parametrize("source", [
    "declare -a app_mainclass=('example.Main'); unexpected-side-effect\n",
    "declare -a app_mainclass=('example.Main' 'second.Main')\n",
    "declare -a app_mainclass=('example.Main;sideEffect')\n",
    "app_mainclass=arbitrary\n",
])
def test_unsupported_launcher_shape_refuses_without_writing_argument_file(tmp_path, monkeypatch, source):
    _, launcher, workspace = fixture(tmp_path, monkeypatch)
    launcher.write_text(source)
    with pytest.raises(RuntimeError, match="supported secure Java entry point"):
        _private_java_command(str(launcher), [], [], str(workspace))
    assert not (workspace / "server.args").exists()


@pytest.mark.integration
@pytest.mark.parametrize("value", ["path with spaces", "single'and\"double quotes", r"back\slash'and\"quote"])
def test_environment_option_quoting_round_trips_through_real_java(tmp_path, value):
    import subprocess
    from core.config import RaptorConfig
    from packages.joern.prereqs import _java_path
    from packages.joern.server import _java_option_value
    java = _java_path()
    if java is None:
        pytest.skip("JDK required")
    source = tmp_path / "OptionProbe.java"
    source.write_text(
        "class OptionProbe { public static void main(String[] args) throws Exception { "
        "System.out.write(System.getProperty(\"raptor.option.path\").getBytes(\"UTF-8\")); } }")
    env = RaptorConfig.get_safe_env()
    env["_JAVA_OPTIONS"] = (
        f"-Xmx128m -Djava.io.tmpdir={_java_option_value(str(tmp_path))} "
        f"-Draptor.option.path={_java_option_value(value)}")
    result = subprocess.run([java, "--source", "11", str(source)], env=env,
                            capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.stdout == value.encode()
