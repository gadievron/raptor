"""Discovery overrides keep borrowed stdlib namespaces and captured dispatch intact."""

import ast
import builtins
import importlib
import importlib.metadata
import importlib.util
from pathlib import Path
import shutil
from types import ModuleType
from unittest.mock import Mock

import pytest

from core.testing.module_bindings import mock_module_attribute, patch_module_attribute
from core.testing.module_views import scoped_function_imports


CASES = [('core.llm.tests.test_config_file',
  'test_182_8_causes_system_exit',
  '_discovery_imports',
  'importlib.metadata',
  'version',
  0),
 ('core.llm.tests.test_config_file',
  'test_182_7_causes_system_exit',
  '_discovery_imports',
  'importlib.metadata',
  'version',
  0),
 ('core.llm.tests.test_config_file',
  'test_safe_version_no_exit',
  '_discovery_imports',
  'importlib.metadata',
  'version',
  0),
 ('core.llm.tests.test_config_file',
  'test_182_8_shows_shell_removal',
  '_discovery_imports',
  'importlib.metadata',
  'version',
  0),
 ('core.llm.tests.test_config_file',
  'test_182_7_shows_pip_removal',
  '_discovery_imports',
  'importlib.metadata',
  'version',
  0),
 ('core.llm.tests.test_config_file',
  'test_auto_migrates_when_litellm_installed',
  '_discovery_imports',
  'importlib.metadata',
  'version',
  0),
 ('core.llm.tests.test_config_file',
  'test_no_migration_when_new_config_exists',
  '_discovery_imports',
  'importlib.metadata',
  'version',
  0),
 ('core.startup.tests.test_analyzer_probe',
  'test_z3_version_reported_when_installed',
  '_discovery_imports',
  'importlib.metadata',
  'version',
  0),
 ('core.startup.tests.test_analyzer_probe',
  'test_z3_absent_no_part',
  '_discovery_imports',
  'importlib.metadata',
  'version',
  0),
 ('core.llm.tests.test_cc_adapter',
  'test_none_when_not_found',
  '_discovery_imports',
  'shutil',
  'which',
  0),
 ('core.llm.tests.test_cc_adapter',
  'test_path_lookup_result_is_realpathed',
  '_discovery_imports',
  'shutil',
  'which',
  0),
 ('packages.frida.tests.test_probe_import_hygiene',
  'test_cli_interpreter_discovery_supports_linux_and_macos_paths',
  '_discovery_imports',
  'shutil',
  'which',
  0),
 ('packages.ghidra.tests.test_session',
  'test_pyghidra_unavailable',
  '_discovery_imports',
  'importlib.util',
  'find_spec',
  0),
 ('packages.codeql.tests.test_curated_queries',
  'test_bundled_empty_when_no_cli',
  '_discovery_imports',
  'shutil',
  'which',
  0),
 ('core.llm.tests.test_provider_preference',
  'no_claudecode',
  '_discovery_imports',
  'shutil',
  'which',
  0),
 ('core.llm.tests.test_provider_preference',
  'test_claudecode_fallthrough_when_no_external_llm',
  '_discovery_imports',
  'shutil',
  'which',
  0),
 ('core.llm.tests.test_provider_preference',
  'test_claudecode_only_used_as_last_resort',
  '_discovery_imports',
  'shutil',
  'which',
  0),
 ('core.llm.tests.test_provider_preference',
  'test_prefer_falls_through_to_claudecode',
  '_discovery_imports',
  'shutil',
  'which',
  0),
 ('core.llm.tests.test_pinned_model',
  'test_pinned_llm_config_provider_name_uses_provider_builder',
  '_discovery_imports',
  'shutil',
  'which',
  0),
 ('core.llm.tests.test_pinned_model',
  'test_pinned_llm_config_provider_name_unavailable_raises',
  '_discovery_imports',
  'shutil',
  'which',
  0),
 ('core.llm.tests.test_offline_resolution',
  'clean_resolution',
  '_discovery_imports',
  'shutil',
  'which',
  0),
 ('core.startup.tests.test_llm_transport_line',
  'isolated_home',
  '_discovery_imports',
  'shutil',
  'which',
  0),
 ('packages.joern.tests.test_prereqs',
  'test_missing_joern_reported',
  'prereqs',
  'shutil',
  'which',
  0),
 ('packages.joern.tests.test_prereqs',
  'test_returns_none_when_unavailable',
  'prereqs',
  'shutil',
  'which',
  0),
 ('packages.joern.tests.test_prereqs',
  'test_version_tuple_none_when_unavailable',
  'prereqs',
  'shutil',
  'which',
  0),
 ('packages.joern.tests.test_prereqs',
  'test_false_when_unavailable',
  'prereqs',
  'shutil',
  'which',
  0),
 ('packages.joern.tests.test_tool_paths',
  'test_returns_launcher_parent_deduplicated',
  'prereqs',
  'shutil',
  'which',
  0),
 ('packages.joern.tests.test_tool_paths',
  'test_flat_install_returns_cli_dir',
  'prereqs',
  'shutil',
  'which',
  0),
 ('packages.joern.tests.test_tool_paths',
  'test_flat_install_ignores_grandparent_lib',
  'prereqs',
  'shutil',
  'which',
  0),
 ('packages.joern.tests.test_tool_paths',
  'test_home_bin_joern_never_declares_home',
  'prereqs',
  'shutil',
  'which',
  0),
 ('packages.joern.tests.test_tool_paths',
  'test_system_installs_need_no_declaration',
  'prereqs',
  'shutil',
  'which',
  0),
 ('packages.joern.tests.test_tool_paths',
  'test_nothing_resolved_returns_empty',
  'prereqs',
  'shutil',
  'which',
  0),
 ('packages.joern.tests.test_tool_paths',
  'test_user_local_jdk_root_included_when_jdk_shaped',
  'prereqs',
  'shutil',
  'which',
  0),
 ('packages.joern.tests.test_tool_paths',
  'test_home_bin_java_never_declares_home',
  'prereqs',
  'shutil',
  'which',
  0),
 ('packages.joern.tests.test_tool_paths',
  'test_jdk_shaped_home_still_refused',
  'prereqs',
  'shutil',
  'which',
  0),
 ('packages.joern.tests.test_tool_paths',
  'test_dotlocal_shim_declares_bin_dir_only',
  'prereqs',
  'shutil',
  'which',
  0),
 ('packages.joern.tests.test_tool_paths',
  'test_symlinked_launcher_resolves_to_real_parent',
  'prereqs',
  'shutil',
  'which',
  0),
 ('packages.joern.tests.test_tool_paths',
  'test_build_cpg_passes_tool_paths',
  'prereqs',
  'shutil',
  'which',
  0),
 ('packages.joern.tests.test_tool_paths',
  'test_run_query_passes_tool_paths',
  'prereqs',
  'shutil',
  'which',
  0),
 ('packages.codeql.tests.test_is_available',
  'test_false_when_not_on_path',
  'codeql',
  'shutil',
  'which',
  0),
 ('packages.codeql.tests.test_is_available',
  'test_returns_none_when_unavailable',
  'codeql',
  'shutil',
  'which',
  0),
 ('packages.codeql.tests.test_is_available',
  'test_constructs_from_env_only',
  'codeql',
  'shutil',
  'which',
  0),
 ('packages.codeql.tests.test_is_available',
  'test_raises_with_actionable_message_when_absent',
  'codeql',
  'shutil',
  'which',
  0),
 ('packages.codeql.tests.test_is_available',
  'test_agreement_with_availability_probe',
  'codeql',
  'shutil',
  'which',
  0),
 ('packages.fuzzing.tests.test_atheris_runner',
  'test_venv_symlink_python_counts_as_other_interpreter',
  '_discovery_owner',
  'importlib.util',
  'find_spec',
  0)]


@pytest.mark.parametrize("module_name,anchor,owner_name,binding_name,attribute,index", CASES)
@pytest.mark.parametrize("finish", ["normal", "error", "interrupt"])
def test_native_discovery_binding_is_private(module_name, anchor, owner_name, binding_name, attribute, index, finish):
    native = importlib.import_module(module_name)
    tree = ast.parse(Path(native.__file__).read_text())
    function = next(node for node in ast.walk(tree)
                    if isinstance(node, ast.FunctionDef) and node.name == anchor)
    calls = []
    for node in ast.walk(function):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id not in ("patch_module_attribute", "mock_module_attribute"):
            continue
        offset = int(node.func.id == "patch_module_attribute")
        args = node.args[offset:offset + 3]
        if (len(args) == 3 and isinstance(args[0], ast.Name) and args[0].id == owner_name
                and all(isinstance(arg, ast.Constant) for arg in args[1:])
                and (args[1].value, args[2].value) == (binding_name, attribute)):
            calls.append(node)
    calls.sort(key=lambda node: (node.lineno, node.col_offset))
    call = calls[index]
    scope = pytest.MonkeyPatch()
    fixture = getattr(native, "_owned_discovery_imports", None)
    generator = None
    borrowed = (shutil.which, importlib.metadata.version, importlib.util.find_spec)
    try:
        if fixture is not None:
            generator = fixture.__wrapped__(scope)
            next(generator)
        namespace = dict(vars(native), monkeypatch=scope)
        monkey = call.func.id == "patch_module_attribute"
        start = 1 if monkey else 0
        owner = eval(compile(ast.Expression(call.args[start]), native.__file__, "eval"), namespace)
        binding = ast.literal_eval(call.args[start + 1])
        name = ast.literal_eval(call.args[start + 2])
        root_key = binding if binding in vars(owner) else binding.split(".")[0]
        original_root = vars(owner)[root_key]
        sentinel = Mock(name="private discovery")
        with pytest.MonkeyPatch.context() as local:
            if monkey:
                patch_module_attribute(local, owner, binding, name, sentinel)
                from contextlib import nullcontext
                context = nullcontext(sentinel)
            else:
                context = mock_module_attribute(owner, binding, name, new=sentinel)
            with context:
                private = getattr(owner, binding) if binding in vars(owner) else owner
                if binding not in vars(owner):
                    for part in binding.split("."):
                        private = getattr(private, part)
                assert getattr(private, name) is sentinel
                assert (shutil.which, importlib.metadata.version, importlib.util.find_spec) == borrowed
                if finish == "error":
                    raise RuntimeError("owned exit")
                if finish == "interrupt":
                    raise KeyboardInterrupt("owned exit")
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {"error": RuntimeError, "interrupt": KeyboardInterrupt}.get(finish)
    finally:
        if "original_root" in locals():
            assert vars(owner)[root_key] is original_root
        if generator is not None:
            generator.close()
        scope.undo()
        assert (shutil.which, importlib.metadata.version, importlib.util.find_spec) == borrowed


@pytest.mark.parametrize("finish", ["normal", "error", "interrupt"])
@pytest.mark.parametrize("builtins_kind", ["dict", "module"])
def test_registry_aliases_follow_private_imports_and_restore(finish, builtins_kind):
    owner = ModuleType("registry_owner")
    owner.__builtins__ = vars(builtins).copy() if builtins_kind == "dict" else builtins
    exec("def build():\n import shutil\n return shutil.which('owned'), token\n", vars(owner))
    owner.token = "before"
    original = owner.build
    foreign = Mock(name="foreign builder")
    registry = owner.builders = {"selected": original, "alias": original, "foreign": foreign, "data": []}
    try:
        with scoped_function_imports(owner, ("build",), {"shutil": shutil}, registries=("builders",)) as imports:
            assert owner.builders is not registry
            assert registry["selected"] is original
            assert owner.builders["selected"] is owner.build
            assert owner.builders["alias"] is owner.build
            assert owner.builders["foreign"] is foreign
            assert owner.builders["data"] is registry["data"]
            imports.shutil.which = lambda name: "private/" + name
            owner.token = "late"
            assert owner.builders["selected"]() == ("private/owned", "late")
            replacement = Mock(return_value="late registry override")
            owner.builders["selected"] = replacement
            assert owner.builders["selected"]() == "late registry override"
            assert owner.builders["alias"]() == ("private/owned", "late")
            if finish == "error":
                raise RuntimeError("owned exit")
            if finish == "interrupt":
                raise KeyboardInterrupt("owned exit")
    except (RuntimeError, KeyboardInterrupt) as error:
        assert type(error) is {"error": RuntimeError, "interrupt": KeyboardInterrupt}.get(finish)
    assert owner.builders is registry
    assert owner.build is original
    assert registry["selected"] is original


@pytest.mark.parametrize("value", [[], None, 4])
def test_invalid_registry_is_rejected_before_publication(value):
    owner = ModuleType("invalid_registry")
    exec("def build(): return 1", vars(owner))
    original = owner.build
    owner.builders = value
    with pytest.raises(TypeError, match="dictionaries"):
        with scoped_function_imports(owner, ("build",), {}, registries=("builders",)):
            pytest.fail("invalid registry was published")
    assert owner.build is original
    assert owner.builders is value


def test_partial_registry_publication_unwinds(monkeypatch):
    owner = ModuleType("partial_registry")
    exec("def build(): return 1", vars(owner))
    original = owner.build
    first = owner.first = {"builder": original}
    second = owner.second = {"builder": original}
    setitem = pytest.MonkeyPatch.setitem

    def fail(self, mapping, key, value):
        if mapping is vars(owner) and key == "build":
            raise KeyboardInterrupt("publication interrupted")
        return setitem(self, mapping, key, value)

    monkeypatch.setattr(pytest.MonkeyPatch, "setitem", fail)
    with pytest.raises(KeyboardInterrupt, match="publication interrupted"):
        with scoped_function_imports(owner, ("build",), {}, registries=("first", "second")):
            pytest.fail("publication succeeded")
    assert owner.build is original
    assert owner.first is first
    assert owner.second is second


def test_real_claudecode_registry_uses_owned_discovery(monkeypatch):
    from core.llm import config, detection
    from core.testing.llm_state import scoped_claudecode_discovery

    registry, builder, borrowed = config._PROVIDER_BUILDERS, config._build_claudecode_config, shutil.which
    monkeypatch.setattr(config, "_resolve_claudecode_model", lambda: config.CLAUDECODE_SESSION_MODEL)
    with scoped_claudecode_discovery(config, detection) as imports:
        patch_module_attribute(monkeypatch, imports, "shutil", "which", lambda name: "/owned/" + name)
        # A global negative guard makes a cached original callable observable.
        with pytest.MonkeyPatch.context() as guard:
            guard.setattr(shutil, "which", Mock(side_effect=AssertionError("borrowed PATH lookup")))
            model = config._PROVIDER_BUILDERS["claudecode"]()
            assert isinstance(model, config.ModelConfig)
            assert model.provider == "claudecode"
            assert detection.shutil.which("claude") == "/owned/claude"
            assert config._entry_auth_resolvable(model)
    assert config._PROVIDER_BUILDERS is registry
    assert config._build_claudecode_config is builder
    assert shutil.which is borrowed


@pytest.mark.parametrize("module_name", ['core.llm.tests.test_cc_adapter', 'core.llm.tests.test_config_file', 'core.llm.tests.test_offline_resolution', 'core.llm.tests.test_pinned_model', 'core.llm.tests.test_provider_preference', 'core.startup.tests.test_analyzer_probe', 'core.startup.tests.test_llm_transport_line', 'packages.codeql.tests.test_curated_queries', 'packages.frida.tests.test_probe_import_hygiene', 'packages.ghidra.tests.test_session'])
@pytest.mark.parametrize("published", [False, True])
def test_native_discovery_fixture_setup_failure_restores_bindings(module_name, published):
    native = importlib.import_module(module_name)
    from core.llm import config, detection, cc_adapter
    from core.startup import init
    from packages.codeql import query_runner
    from packages.frida import sandboxed
    from packages.ghidra import detect

    targets = [(config, "_entry_auth_resolvable"), (config, "_build_claudecode_config"),
               (config, "_PROVIDER_BUILDERS"), (detection, "shutil"),
               (detection, "_check_litellm_installed"), (cc_adapter, "resolve_claude_cli"),
               (init, "_check_analyzer_capabilities"), (query_runner, "_bundled_stdlib_roots"),
               (sandboxed, "_find_frida_site"), (detect, "pyghidra_available"),
               (native, "_discovery_imports")]
    before = [getattr(owner, name) for owner, name in targets]
    scope = pytest.MonkeyPatch()
    original_setitem = scope.setitem

    def fail(mapping, key, value):
        if mapping is vars(native) and key == "_discovery_imports":
            if published:
                original_setitem(mapping, key, value)
            raise RuntimeError("fixture publication interrupted")
        return original_setitem(mapping, key, value)

    scope.setitem = fail
    try:
        generator = native._owned_discovery_imports.__wrapped__(scope)
        with pytest.raises(RuntimeError, match="fixture publication interrupted"):
            next(generator)
        assert all(getattr(owner, name) is value for (owner, name), value in zip(targets, before))
    finally:
        scope.undo()
