"""Tests for packages.joern.prereqs."""

from __future__ import annotations

from unittest.mock import patch

import packages.joern.prereqs as prereqs


class TestIsAvailable:
    def test_returns_bool(self):
        result = prereqs.is_available()
        assert isinstance(result, bool)


class TestCheckPrereqs:
    def test_returns_list(self):
        result = prereqs.check_prereqs()
        assert isinstance(result, list)

    def test_missing_joern_reported(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda x: None)
        prereqs.reset_path_cache()
        try:
            result = prereqs.check_prereqs()
            assert any("joern" in m for m in result)
        finally:
            prereqs.reset_path_cache()


class TestVersion:
    def test_returns_none_when_unavailable(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda x: None)
        prereqs.reset_path_cache()
        try:
            assert prereqs.version() is None
        finally:
            prereqs.reset_path_cache()

    def test_version_tuple_none_when_unavailable(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda x: None)
        prereqs.reset_path_cache()
        try:
            assert prereqs.version_tuple() is None
        finally:
            prereqs.reset_path_cache()

    def test_version_from_dist_jar(self, tmp_path):
        """Version read from lib/ jar names — no JVM boot needed."""
        lib = tmp_path / "lib"
        lib.mkdir()
        (lib / "io.joern.joern-cli-4.0.601.jar").touch()
        (lib / "io.joern.console-4.0.601.jar").touch()
        joern = tmp_path / "joern"
        joern.touch()
        assert prereqs._version_from_dist(str(joern)) == "4.0.601"

    def test_version_from_bin_launcher_does_not_boot_jvm(self, tmp_path, monkeypatch):
        library = tmp_path / "lib"
        library.mkdir()
        (library / "io.joern.joern-cli-4.0.601.jar").touch()
        launcher = tmp_path / "bin" / "joern"
        launcher.parent.mkdir()
        launcher.touch()
        monkeypatch.setattr(prereqs, "is_available", lambda: True)
        monkeypatch.setattr(prereqs, "_joern_path", lambda: str(launcher))
        with patch.object(prereqs.subprocess, "run") as process:
            assert prereqs.version() == "4.0.601"
            process.assert_not_called()

    def test_version_from_dist_missing_lib(self, tmp_path):
        joern = tmp_path / "joern"
        joern.touch()
        assert prereqs._version_from_dist(str(joern)) is None

    def test_version_prefers_dist_over_repl(self, monkeypatch, tmp_path):
        """The static jar read wins — the REPL fallback (a full JVM
        boot) must not be reached when lib/ carries the version."""
        lib = tmp_path / "lib"
        lib.mkdir()
        (lib / "io.joern.joern-cli-4.0.599.jar").touch()
        joern = tmp_path / "joern"
        joern.touch()
        monkeypatch.setattr(prereqs, "is_available", lambda: True)
        monkeypatch.setattr(prereqs, "_joern_path", lambda: str(joern))
        with patch.object(prereqs.subprocess, "run") as mock_run:
            assert prereqs.version() == "4.0.599"
            mock_run.assert_not_called()

    def test_version_tuple_parses_patch(self, monkeypatch):
        monkeypatch.setattr(prereqs, "version", lambda: "4.0.458")
        assert prereqs.version_tuple() == (4, 0, 458)

    def test_version_tuple_defaults_missing_patch(self, monkeypatch):
        monkeypatch.setattr(prereqs, "version", lambda: "v4.1")
        assert prereqs.version_tuple() == (4, 1, 0)


class TestMeetsMinVersion:
    def test_floor_is_first_2026_release(self):
        assert prereqs.MIN_JOERN_VERSION == (4, 0, 458)

    def test_at_floor_passes(self, monkeypatch):
        monkeypatch.setattr(prereqs, "version", lambda: "4.0.458")
        assert prereqs.meets_min_version()

    def test_below_floor_fails(self, monkeypatch):
        monkeypatch.setattr(prereqs, "version", lambda: "4.0.457")
        assert not prereqs.meets_min_version()

    def test_v3_fails(self, monkeypatch):
        monkeypatch.setattr(prereqs, "version", lambda: "3.2.100")
        assert not prereqs.meets_min_version()

    def test_false_when_unavailable(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda x: None)
        prereqs.reset_path_cache()
        try:
            assert not prereqs.meets_min_version()
        finally:
            prereqs.reset_path_cache()


class TestPathCache:
    def test_reset_clears(self):
        prereqs.reset_path_cache()
        assert prereqs._joern_resolved is False
        assert prereqs._joern_parse_resolved is False


class TestResolverRealpath:
    """_joern_path / _joern_parse_path cache the REAL path: symlink
    launchers on PATH otherwise fail the sandbox's mount-ns visibility
    check and silently downgrade CPG builds to Landlock-only."""

    def test_joern_path_resolves_symlink(self, tmp_path, monkeypatch):
        from packages.joern import prereqs
        real = tmp_path / "joern-cli" / "joern"
        real.parent.mkdir()
        real.write_text("#!/bin/sh\n")
        link = tmp_path / "bin" / "joern"
        link.parent.mkdir()
        link.symlink_to(real)
        monkeypatch.setattr(
            prereqs.shutil, "which",
            lambda name: str(link) if name == "joern" else None,
        )
        prereqs.reset_path_cache()
        try:
            assert prereqs._joern_path() == str(real.resolve())
        finally:
            prereqs.reset_path_cache()

    def test_joern_parse_path_resolves_symlink(self, tmp_path, monkeypatch):
        from packages.joern import prereqs
        real = tmp_path / "joern-cli" / "joern-parse"
        real.parent.mkdir()
        real.write_text("#!/bin/sh\n")
        link = tmp_path / "bin" / "joern-parse"
        link.parent.mkdir()
        link.symlink_to(real)
        monkeypatch.setattr(
            prereqs.shutil, "which",
            lambda name: str(link) if name == "joern-parse" else None,
        )
        prereqs.reset_path_cache()
        try:
            assert prereqs._joern_parse_path() == str(real.resolve())
        finally:
            prereqs.reset_path_cache()


def _mac_jdk(tmp_path):
    root = tmp_path / "JDK with spaces/Contents/Home"
    (root / "bin").mkdir(parents=True)
    (root / "release").write_text("JDK fixture")
    java = root / "bin/java"
    java.write_text("#!/bin/sh\nexit 0\n")
    java.chmod(0o755)
    return root, java


def test_macos_system_stub_resolves_configured_real_jdk(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    root, java = _mac_jdk(tmp_path)
    monkeypatch.setattr(prereqs, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setenv("JAVA_HOME", str(root))
    monkeypatch.setattr(prereqs.shutil, "which", lambda name: "/usr/bin/java")
    launch = Mock()
    monkeypatch.setattr(prereqs.subprocess, "run", launch)
    prereqs.reset_path_cache()
    try:
        assert prereqs._java_path() == str(java)
        assert prereqs._java_path() == str(java)
        launch.assert_not_called()
    finally:
        prereqs.reset_path_cache()


def test_macos_system_stub_resolves_default_jdk_once(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    root, java = _mac_jdk(tmp_path)
    monkeypatch.setattr(prereqs, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.delenv("JAVA_HOME", raising=False)
    monkeypatch.setattr(prereqs.shutil, "which", lambda name: "/usr/bin/java")
    launch = Mock(return_value=SimpleNamespace(returncode=0, stdout=str(root) + "\n"))
    monkeypatch.setattr(prereqs.subprocess, "run", launch)
    prereqs.reset_path_cache()
    try:
        assert prereqs._java_path() == str(java)
        assert prereqs._java_path() == str(java)
        launch.assert_called_once()
        assert launch.call_args.args[0] == ["/usr/libexec/java_home"]
        assert launch.call_args.kwargs["timeout"] == 5
    finally:
        prereqs.reset_path_cache()


def test_macos_invalid_explicit_jdk_is_not_silently_replaced(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    monkeypatch.setattr(prereqs, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setenv("JAVA_HOME", str(tmp_path / "missing-jdk"))
    monkeypatch.setattr(prereqs.shutil, "which", lambda name: "/usr/bin/java")
    launch = Mock()
    monkeypatch.setattr(prereqs.subprocess, "run", launch)
    prereqs.reset_path_cache()
    try:
        assert prereqs._java_path() is None
        launch.assert_not_called()
    finally:
        prereqs.reset_path_cache()


def test_macos_real_java_on_path_does_not_probe_or_use_other_java_home(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    _, java = _mac_jdk(tmp_path)
    monkeypatch.setattr(prereqs, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.setenv("JAVA_HOME", str(tmp_path / "other"))
    monkeypatch.setattr(prereqs.shutil, "which", lambda name: str(java))
    launch = Mock()
    monkeypatch.setattr(prereqs.subprocess, "run", launch)
    prereqs.reset_path_cache()
    try:
        assert prereqs._java_path() == str(java)
        launch.assert_not_called()
    finally:
        prereqs.reset_path_cache()


def test_macos_failed_default_jdk_probe_never_uses_system_stub(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    import subprocess
    monkeypatch.setattr(prereqs, "sys", SimpleNamespace(platform="darwin"))
    monkeypatch.delenv("JAVA_HOME", raising=False)
    monkeypatch.setattr(prereqs.shutil, "which", lambda name: "/usr/bin/java")
    launch = Mock(side_effect=subprocess.TimeoutExpired("java_home", 5))
    monkeypatch.setattr(prereqs.subprocess, "run", launch)
    prereqs.reset_path_cache()
    try:
        assert prereqs._java_path() is None
    finally:
        prereqs.reset_path_cache()


def test_java_version_probe_uses_the_selected_runtime(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock
    monkeypatch.setattr(prereqs, "_java_path", lambda: "/selected/jdk/bin/java")
    run = Mock(return_value=SimpleNamespace(stdout="", stderr='openjdk version "25.0.1"'))
    monkeypatch.setattr(prereqs, "probe", run)
    assert prereqs._java_version() == 25
    assert run.call_args.args == ("/selected/jdk/bin/java",)


def _brew_joern(tmp_path, monkeypatch, prefix_name='opt/homebrew', expose_parser=True):
    import json
    from types import SimpleNamespace
    prefix = tmp_path / prefix_name
    keg = prefix / 'Cellar/joern/4.0.660'
    (keg / 'libexec/bin').mkdir(parents=True)
    (keg / 'libexec/lib').mkdir()
    (keg / 'bin').mkdir()
    (prefix / 'bin').mkdir()
    (keg / 'libexec/lib/io.joern.joern-cli-HEAD+20261019-1730.jar').touch()
    for name in ('repl-bridge', 'joern-parse'):
        file = keg / 'libexec/bin' / name
        file.write_text("#!/bin/bash\ndeclare -a app_mainclass=('example.Main')\n")
        file.chmod(0o755)
    for name in ('joern', 'joern-parse'):
        wrapper = keg / 'bin' / name
        wrapper.write_text('#!/bin/bash\nJAVA_HOME="${JAVA_HOME:-' + str(prefix / 'opt/openjdk@25/libexec') + '}" exec "' + str(keg / 'libexec' / name) + '" "$@"\n')
        wrapper.chmod(0o755)
        (prefix / 'bin' / name).symlink_to(wrapper)
    home = prefix / 'opt/openjdk@25/libexec/openjdk.jdk/Contents/Home'
    (home / 'bin').mkdir(parents=True)
    (home / 'release').write_text('JDK fixture')
    java = home / 'bin/java'
    java.write_text('#!/bin/sh\nexit 0\n')
    java.chmod(0o755)
    receipt = {'source': {'spec': 'stable', 'versions': {'stable': '4.0.660'}},
               'runtime_dependencies': [{'full_name': 'coreutils', 'declared_directly': True},
                                        {'full_name': 'openjdk@25', 'declared_directly': True}]}
    (keg / 'INSTALL_RECEIPT.json').write_text(json.dumps(receipt))
    choices = {'joern': str(prefix / 'bin/joern'),
               'joern-parse': str(prefix / 'bin/joern-parse') if expose_parser else None,
               'java': '/usr/bin/java'}
    monkeypatch.setattr(prereqs.shutil, 'which', choices.get)
    monkeypatch.setattr(prereqs, 'sys', SimpleNamespace(platform='darwin'))
    monkeypatch.delenv('JAVA_HOME', raising=False)
    prereqs.reset_path_cache()
    return keg, home, receipt


def test_homebrew_wrappers_resolve_real_cli_parser_and_unregistered_jdk(tmp_path, monkeypatch):
    from unittest.mock import Mock
    keg, home, _ = _brew_joern(tmp_path, monkeypatch)
    launch = Mock(side_effect=AssertionError('discovery must not execute wrappers or the REPL'))
    monkeypatch.setattr(prereqs.subprocess, 'run', launch)
    try:
        assert prereqs.is_available()
        assert prereqs._joern_path() == str(keg / 'libexec/bin/repl-bridge')
        assert prereqs._joern_parse_path() == str(keg / 'libexec/bin/joern-parse')
        assert prereqs._java_path() == str(home / 'bin/java')
        assert prereqs.version() == '4.0.660'
        assert prereqs.meets_min_version()
        launch.assert_not_called()
        roots = prereqs.joern_tool_paths()
        assert str(keg / 'libexec') in roots and str(home) in roots
        assert str(keg.parents[2]) not in roots  # never grant the Homebrew prefix
    finally:
        prereqs.reset_path_cache()


def test_intel_homebrew_finds_parser_inside_keg_when_not_on_path(tmp_path, monkeypatch):
    keg, _, _ = _brew_joern(tmp_path, monkeypatch, 'usr/local', expose_parser=False)
    try:
        assert prereqs.is_available()
        assert prereqs._joern_parse_path() == str(keg / 'libexec/bin/joern-parse')
    finally:
        prereqs.reset_path_cache()


def test_homebrew_java_home_override_is_preserved_and_invalid_override_refused(tmp_path, monkeypatch):
    _brew_joern(tmp_path, monkeypatch)
    _, java = _mac_jdk(tmp_path)
    monkeypatch.setenv('JAVA_HOME', str(java.parent.parent))
    try:
        assert prereqs._java_path() == str(java)
        prereqs.reset_path_cache()
        monkeypatch.setenv('JAVA_HOME', str(tmp_path / 'missing'))
        assert prereqs._java_path() is None
    finally:
        prereqs.reset_path_cache()


def test_homebrew_snapshot_version_requires_stable_receipt_not_directory_guess(tmp_path, monkeypatch):
    import json
    keg, _, receipt = _brew_joern(tmp_path, monkeypatch)
    try:
        receipt['source']['versions']['stable'] = '4.0.457'
        (keg / 'INSTALL_RECEIPT.json').write_text(json.dumps(receipt))
        assert prereqs.version() == '4.0.457'
        assert not prereqs.meets_min_version()
        receipt['source']['spec'] = 'head'
        (keg / 'INSTALL_RECEIPT.json').write_text(json.dumps(receipt))
        assert prereqs._version_from_dist(prereqs._joern_path()) is None
    finally:
        prereqs.reset_path_cache()


def test_homebrew_semantic_jar_version_precedes_receipt(tmp_path, monkeypatch):
    keg, _, _ = _brew_joern(tmp_path, monkeypatch)
    (keg / 'libexec/lib/io.joern.joern-cli-4.0.659.jar').touch()
    try:
        assert prereqs.version() == '4.0.659'
    finally:
        prereqs.reset_path_cache()


def test_homebrew_receipt_refuses_redirects_and_malformed_metadata(tmp_path, monkeypatch):
    keg, _, _ = _brew_joern(tmp_path, monkeypatch)
    try:
        receipt = keg / 'INSTALL_RECEIPT.json'
        receipt.write_text('[]')
        assert prereqs._homebrew_receipt(keg) == {}
        receipt.write_text('{broken')
        assert prereqs._homebrew_receipt(keg) == {}
        receipt.unlink()
        receipt.symlink_to(tmp_path / 'not-a-receipt')
        assert prereqs._homebrew_receipt(keg) == {}
    finally:
        prereqs.reset_path_cache()


def test_homebrew_dependency_name_cannot_escape_prefix(tmp_path, monkeypatch):
    import json
    keg, _, receipt = _brew_joern(tmp_path, monkeypatch)
    receipt['runtime_dependencies'] = [{'full_name': '../../outside', 'declared_directly': True}]
    (keg / 'INSTALL_RECEIPT.json').write_text(json.dumps(receipt))
    try:
        assert prereqs._homebrew_java_home(prereqs._joern_path()) is None
    finally:
        prereqs.reset_path_cache()


def test_linux_homebrew_uses_flat_packaged_jdk_and_exact_tool_roots(tmp_path, monkeypatch):
    import shutil
    from types import SimpleNamespace
    keg, mac_home, _ = _brew_joern(tmp_path, monkeypatch, 'home/linuxbrew/.linuxbrew')
    home = mac_home.parents[2]  # libexec, with a flat Linux JDK layout
    shutil.move(str(mac_home / 'bin'), home / 'bin')
    shutil.move(str(mac_home / 'release'), home / 'release')
    monkeypatch.setattr(prereqs, 'sys', SimpleNamespace(platform='linux'))
    try:
        assert prereqs._java_path() == str(home / 'bin/java')
        roots = prereqs.joern_tool_paths()
        assert str(home) in roots and str(keg / 'libexec') in roots
        assert str(keg.parents[2]) not in roots
    finally:
        prereqs.reset_path_cache()


def test_homebrew_roots_fit_existing_seatbelt_read_policy_without_write_grants(tmp_path, monkeypatch):
    from core.sandbox.seatbelt import build_profile
    keg, home, _ = _brew_joern(tmp_path, monkeypatch)
    try:
        roots = prereqs.joern_tool_paths()
        output = tmp_path / 'output'
        output.mkdir()
        profile = build_profile(output=str(output), block_network=False,
                                restrict_reads=True, readable_paths=roots,
                                exclude_tmp_baseline=True)
        for root in (keg / 'libexec', home):
            assert f'(subpath "{root}")' in profile
            assert f'(allow file-write* (subpath "{root}"))' not in profile
        assert f'(subpath "{keg.parents[2]}")' not in profile
    finally:
        prereqs.reset_path_cache()


def test_homebrew_ambiguous_jdk_dependencies_require_explicit_selection(tmp_path, monkeypatch):
    import json
    keg, _, receipt = _brew_joern(tmp_path, monkeypatch)
    receipt['runtime_dependencies'].append({'full_name': 'openjdk@21', 'declared_directly': True})
    (keg / 'INSTALL_RECEIPT.json').write_text(json.dumps(receipt))
    try:
        assert prereqs._homebrew_java_home(prereqs._joern_path()) is None
        assert prereqs._java_path() is None
    finally:
        prereqs.reset_path_cache()
