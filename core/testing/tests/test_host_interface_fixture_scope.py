"""Host-interface mocks stay on actual native consumers and restore borrowed views."""
import ast
import copy
from contextlib import ExitStack, contextmanager
from functools import lru_cache
import importlib
import importlib.machinery
import importlib.util
import inspect
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

from core.testing.module_bindings import mock_module_attribute, patch_module_attribute

_REPO = Path(__file__).resolve().parents[3]
_SITES = [{'anchor': ['TestCheckerProvenance', 'test_build_lands_in_raptor_owned_scratch_not_coverage_dir'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "patch.object(bl.subprocess, 'run', side_effect=fake_build)",
  'file': 'packages/binary_analysis/tests/test_blamed_lines.py',
  'kind': 'object',
  'line': 170,
  'receiver': 'bl'},
 {'anchor': ['test_missing_history_and_fetch_failure_build'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(changes.subprocess, 'run', failed)",
  'file': '.github/scripts/tests/test_ci_publish_scope.py',
  'kind': 'monkey',
  'line': 115,
  'receiver': 'changes'},
 {'anchor': ['TestLaunchGate', 'test_demoted_pin_withholds_the_launch'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch.object(edges_mod.shutil, 'which', lambda _name: '/usr/bin/r2')",
  'file': 'core/analysis/tests/test_binary_oracle_edges_pins.py',
  'kind': 'object',
  'line': 77,
  'receiver': 'edges_mod'},
 {'anchor': ['TestLaunchGate', 'test_stale_pin_withholds_the_launch'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch.object(edges_mod.shutil, 'which', lambda _name: '/usr/bin/r2')",
  'file': 'core/analysis/tests/test_binary_oracle_edges_pins.py',
  'kind': 'object',
  'line': 92,
  'receiver': 'edges_mod'},
 {'anchor': ['TestLaunchGate', 'test_verified_pin_still_launches'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch.object(edges_mod.shutil, 'which', lambda _name: '/usr/bin/r2')",
  'file': 'core/analysis/tests/test_binary_oracle_edges_pins.py',
  'kind': 'object',
  'line': 107,
  'receiver': 'edges_mod'},
 {'anchor': ['TestLaunchGate', 'test_unpinned_path_passes_through'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch.object(edges_mod.shutil, 'which', lambda _name: '/usr/bin/r2')",
  'file': 'core/analysis/tests/test_binary_oracle_edges_pins.py',
  'kind': 'object',
  'line': 120,
  'receiver': 'edges_mod'},
 {'anchor': ['test_spawn_worker_env_none_defaults_to_safe_env'],
  'attribute': 'Popen',
  'binding': 'subprocess',
  'call': "patch.object(spawn_mod.subprocess, 'Popen', FakePopen)",
  'file': 'core/llm/dispatcher/tests/test_f085_spawn_default_env.py',
  'kind': 'object',
  'line': 54,
  'receiver': 'spawn_mod'},
 {'anchor': ['test_spawn_worker_env_none_preserves_operator_proxy'],
  'attribute': 'Popen',
  'binding': 'subprocess',
  'call': "patch.object(spawn_mod.subprocess, 'Popen', FakePopen)",
  'file': 'core/llm/dispatcher/tests/test_f085_spawn_default_env.py',
  'kind': 'object',
  'line': 98,
  'receiver': 'spawn_mod'},
 {'anchor': ['test_spawn_worker_env_none_carries_routing_family_not_secrets'],
  'attribute': 'Popen',
  'binding': 'subprocess',
  'call': "patch.object(spawn_mod.subprocess, 'Popen', FakePopen)",
  'file': 'core/llm/dispatcher/tests/test_f085_spawn_default_env.py',
  'kind': 'object',
  'line': 141,
  'receiver': 'spawn_mod'},
 {'anchor': ['test_spawn_worker_explicit_env_not_overlaid'],
  'attribute': 'Popen',
  'binding': 'subprocess',
  'call': "patch.object(spawn_mod.subprocess, 'Popen', FakePopen)",
  'file': 'core/llm/dispatcher/tests/test_f085_spawn_default_env.py',
  'kind': 'object',
  'line': 176,
  'receiver': 'spawn_mod'},
 {'anchor': ['test_unchanged_journal_allocates_no_rewrite_temp'],
  'attribute': 'mkstemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(compact.tempfile, 'mkstemp', forbidden)",
  'file': 'core/coverage/tests/test_compaction_storage_lifecycle.py',
  'kind': 'monkey',
  'line': 98,
  'receiver': 'compact'},
 {'anchor': ['test_global_writer_lock_prevents_active_temp_reaping_and_redundant_generation'],
  'attribute': 'mkstemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(compact.tempfile, 'mkstemp', held_temp)",
  'file': 'core/coverage/tests/test_compaction_storage_lifecycle.py',
  'kind': 'monkey',
  'line': 174,
  'receiver': 'compact'},
 {'anchor': ['test_regular_cli_never_invokes_bootstrap'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(_bootstrap.subprocess, 'run', lambda *a, **k: "
          "pytest.fail('unexpected subprocess'))",
  'file': 'packages/codeql/tests/test_first_use_install.py',
  'kind': 'monkey',
  'line': 202,
  'receiver': '_bootstrap'},
 {'anchor': ['test_shared_probe_keeps_resolved_path_safe_env_root_cwd_and_temporary_wrapper'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(toolprobe.subprocess, 'run', run)",
  'file': 'packages/codeql/tests/test_version_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 89,
  'receiver': 'toolprobe'},
 {'anchor': ['test_failed_probe_banner_is_not_a_usable_version'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(toolprobe.subprocess, 'run', lambda command, **kwargs: "
          "subprocess.CompletedProcess(command, 1, stdout='CodeQL command-line toolchain release "
          "9.0.0.\\n', stderr='failed'))",
  'file': 'packages/codeql/tests/test_version_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 100,
  'receiver': 'toolprobe'},
 {'anchor': ['installation'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(NODE.subprocess, 'run', lambda *args, **kwargs: calls.append((args, "
          'kwargs)))',
  'file': '.github/tests/test_use_system_node.py',
  'kind': 'monkey',
  'line': 47,
  'receiver': 'NODE'},
 {'anchor': ['test_failed_runtime_validation_preserves_bundle'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(NODE.subprocess, 'run', fail)",
  'file': '.github/tests/test_use_system_node.py',
  'kind': 'monkey',
  'line': 103,
  'receiver': 'NODE'},
 {'anchor': ['TestSandboxedCampaign', 'test_campaign_routed_through_sandbox'],
  'attribute': 'Popen',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(mod.subprocess, 'Popen', popen_tripwire)",
  'file': 'packages/fuzzing/tests/test_afl_runner.py',
  'kind': 'monkey',
  'line': 514,
  'receiver': 'mod'},
 {'anchor': ['test_probe_success_leaves_no_scratch'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(capability.subprocess, 'run', _fake_run(record))",
  'file': 'packages/fuzzing/tests/test_capability_probe_scratch.py',
  'kind': 'monkey',
  'line': 43,
  'receiver': 'capability'},
 {'anchor': ['test_probe_compile_failure_leaves_no_scratch'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(capability.subprocess, 'run', _fake_run(record, returncode=1))",
  'file': 'packages/fuzzing/tests/test_capability_probe_scratch.py',
  'kind': 'monkey',
  'line': 56,
  'receiver': 'capability'},
 {'anchor': ['test_probe_timeout_leaves_no_scratch'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(capability.subprocess, 'run', _fake_run(record, "
          'raise_timeout=True))',
  'file': 'packages/fuzzing/tests/test_capability_probe_scratch.py',
  'kind': 'monkey',
  'line': 66,
  'receiver': 'capability'},
 {'anchor': ['test_probe_source_matches_sanitizer_mode'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(capability.subprocess, 'run', _fake_run(record))",
  'file': 'packages/fuzzing/tests/test_capability_probe_scratch.py',
  'kind': 'monkey',
  'line': 77,
  'receiver': 'capability'},
 {'added_module': 'core.security.python_probe',
  'anchor': ['test_probe_child_module_rides_as_argv'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "mp.setattr(_availability.subprocess, 'run', _spy_run)",
  'file': 'core/symbolic/tests/test_availability_probe_isolation.py',
  'kind': 'monkey',
  'line': 181,
  'receiver': '_python_probe_consumer'},
 {'anchor': ['TestFetchSourceEnv', 'test_fetch_uses_proxy_env'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(run_corpus.subprocess, 'run', fake_run)",
  'file': 'core/audit/corpus/tests/test_run_corpus.py',
  'kind': 'monkey',
  'line': 975,
  'receiver': 'run_corpus'},
 {'anchor': ['test_breakdown_comes_from_run_result_not_findings_json_reread'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(stress_mod.subprocess, 'run', fake_clone)",
  'file': 'packages/sca/calibration/tests/test_stress_eco_breakdown.py',
  'kind': 'monkey',
  'line': 87,
  'receiver': 'stress_mod'},
 {'anchor': ['TestRunScriptFallback', 'test_fallback_announces_and_records'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "patch.object(raptor.subprocess, 'run', fake_run)",
  'file': 'core/run/tests/test_env_direct_downgrade_banner.py',
  'kind': 'object',
  'line': 128,
  'receiver': 'raptor'},
 {'anchor': ['test_joern_matrix_resolves_host_launcher_symlink'],
  'attribute': 'which',
  'binding': 'shutil',
  'cache_fields': ['_resolved_joern',
                   '_joern_resolved',
                   '_resolved_joern_parse',
                   '_joern_parse_resolved',
                   '_resolved_java',
                   '_java_resolved'],
  'call': "monkeypatch.setattr(selftest.shutil, 'which', lambda name: str(alias) if name == "
          "'joern-parse' else None)",
  'delegate_module': 'packages.joern.prereqs',
  'file': 'core/testing/tests/test_selftest_harness.py',
  'kind': 'monkey',
  'line': 410,
  'receiver': 'selftest'},
 {'anchor': ['TestToolMatrixSkip', 'test_failed_afl_build_returns_skip_verdict'],
  'attribute': 'which',
  'binding': 'shutil',
  'cache_fields': ['_resolved_joern',
                   '_joern_resolved',
                   '_resolved_joern_parse',
                   '_joern_parse_resolved',
                   '_resolved_java',
                   '_java_resolved'],
  'call': "monkeypatch.setattr(selftest.shutil, 'which', lambda name, *a, **k: str(stub) if name "
          "in ('afl-clang-fast', 'afl-gcc') else None)",
  'delegate_module': 'packages.joern.prereqs',
  'file': 'core/testing/tests/test_selftest_harness.py',
  'kind': 'monkey',
  'line': 320,
  'receiver': 'selftest'},
 {'anchor': ['TestTargetSnapshot', 'test_target_git_uses_untrusted_safe_overrides'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "mock.patch.object(prov.subprocess, 'run', side_effect=spy)",
  'delegate': 'toolprobe',
  'delegate_module': 'core.run.toolprobe',
  'file': 'core/run/tests/test_provenance.py',
  'kind': 'object',
  'line': 294,
  'receiver': 'prov'},
 {'anchor': ['TestTargetSnapshot', 'test_source_control_uses_bare_git'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "mock.patch.object(prov.subprocess, 'run', side_effect=spy)",
  'delegate': 'toolprobe',
  'delegate_module': 'core.run.toolprobe',
  'file': 'core/run/tests/test_provenance.py',
  'kind': 'object',
  'line': 373,
  'receiver': 'prov'},
 {'anchor': ['TestToolVersion', 'test_semgrep_returns_version_string'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "mock.patch.object(toolprobe.shutil, 'which', return_value='/opt/probe/semgrep')",
  'file': 'core/run/tests/test_provenance.py',
  'kind': 'object',
  'line': 464,
  'receiver': 'toolprobe'},
 {'anchor': ['TestToolVersion', 'test_semgrep_returns_version_string'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "mock.patch.object(prov.subprocess, 'run', return_value=fake)",
  'delegate': 'toolprobe',
  'delegate_module': 'core.run.toolprobe',
  'file': 'core/run/tests/test_provenance.py',
  'kind': 'object',
  'line': 466,
  'receiver': 'prov'},
 {'anchor': ['TestToolVersion', 'test_probe_timeout_returns_none'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "mock.patch.object(toolprobe.shutil, 'which', return_value='/opt/probe/semgrep')",
  'file': 'core/run/tests/test_provenance.py',
  'kind': 'object',
  'line': 480,
  'receiver': 'toolprobe'},
 {'anchor': ['TestToolVersion', 'test_probe_timeout_returns_none'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "mock.patch.object(prov.subprocess, 'run', "
          "side_effect=subprocess.TimeoutExpired(cmd=['semgrep', '--version'], timeout=5.0))",
  'delegate': 'toolprobe',
  'delegate_module': 'core.run.toolprobe',
  'file': 'core/run/tests/test_provenance.py',
  'kind': 'object',
  'line': 482,
  'receiver': 'prov'},
 {'anchor': ['test_probe_retention_is_capped'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(toolprobe.subprocess, 'run', fake_run)",
  'file': 'core/run/tests/test_toolprobe_adoption_driftguard.py',
  'kind': 'monkey',
  'line': 90,
  'receiver': 'toolprobe'},
 {'anchor': ['test_failed_live_boot_retains_heap_and_scratch_until_death_is_verified'],
  'attribute': 'Popen',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(server.subprocess, 'Popen', lambda *args, **kwargs: process)",
  'file': 'packages/joern/tests/test_owned_artifact_cleanup.py',
  'kind': 'monkey',
  'line': 229,
  'receiver': 'server'},
 {'anchor': ['test_contended_controller_does_not_start_another_owner'],
  'attribute': 'Popen',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(broker.subprocess, 'Popen', start)",
  'file': 'packages/joern/tests/test_required_arbitration.py',
  'kind': 'monkey',
  'line': 19,
  'receiver': 'broker'},
 {'anchor': ['test_unsafe_controller_lock_never_starts_an_unconfined_fallback'],
  'attribute': 'Popen',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(broker.subprocess, 'Popen', start)",
  'file': 'packages/joern/tests/test_required_arbitration.py',
  'kind': 'monkey',
  'line': 34,
  'receiver': 'broker'},
 {'anchor': ['test_corpus_workload_dispatches_owned_build_through_sandbox'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(driver.subprocess, 'run', lambda *a, **k: "
          'subprocess.CompletedProcess(a, 0))',
  'file': 'core/binary/tests/test_additional_wrapper_contracts.py',
  'kind': 'monkey',
  'line': 64,
  'receiver': 'driver'},
 {'anchor': ['TestProbe', 'test_missing_binary_returns_none'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(cc_probe.shutil, 'which', lambda _: None)",
  'file': 'core/llm/tests/test_cc_probe.py',
  'kind': 'monkey',
  'line': 146,
  'receiver': 'cc_probe'},
 {'anchor': ['TestCachedRead', 'test_cold_cache_returns_none_without_probing'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(cc_probe.shutil, 'which', lambda name: '/usr/bin/claude')",
  'file': 'core/llm/tests/test_cc_probe.py',
  'kind': 'monkey',
  'line': 241,
  'receiver': 'cc_probe'},
 {'anchor': ['TestCachedRead', 'test_warm_cache_returns_model'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(cc_probe.shutil, 'which', lambda name: '/usr/bin/claude')",
  'file': 'core/llm/tests/test_cc_probe.py',
  'kind': 'monkey',
  'line': 249,
  'receiver': 'cc_probe'},
 {'anchor': ['TestCachedRead', 'test_no_claude_binary_returns_none'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(cc_probe.shutil, 'which', lambda name: None)",
  'file': 'core/llm/tests/test_cc_probe.py',
  'kind': 'monkey',
  'line': 263,
  'receiver': 'cc_probe'},
 {'anchor': ['TestReadablePathsForCCDispatch', 'test_binary_exec_paths_missing_binary_tolerated'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(mod.shutil, 'which', lambda _name: None)",
  'file': 'core/llm/tests/test_cc_proxy_hosts.py',
  'kind': 'monkey',
  'line': 501,
  'receiver': 'mod'},
 {'anchor': ['test_shim_math_is_retained_without_a_source_verdict'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(sweep.subprocess, 'run', lambda *a, **kw: "
          "subprocess.CompletedProcess(args=[], returncode=0, stdout=json.dumps({'feasible': "
          "feasible}), stderr=''))",
  'file': 'core/audit/tests/test_supplied_arithmetic_model.py',
  'kind': 'monkey',
  'line': 20,
  'receiver': 'sweep'},
 {'anchor': ['_stub_prep'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(_orch.subprocess, 'run', fake_run)",
  'file': 'core/audit/tests/test_study_consumer_multilang.py',
  'kind': 'monkey',
  'line': 580,
  'receiver': '_orch'},
 {'anchor': ['TestBinaryActivePhaseEnv', '_capture'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(cli.subprocess, 'run', fake_run)",
  'file': 'core/audit/tests/test_spawn_seam_llm_env.py',
  'kind': 'monkey',
  'line': 100,
  'receiver': 'cli'},
 {'anchor': ['TestAgenticPhase3Overlay', 'test_family_overlaid_keys_absent'],
  'attribute': 'Popen',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(raptor_agentic.subprocess, 'Popen', FakeProc)",
  'file': 'core/audit/tests/test_spawn_seam_llm_env.py',
  'kind': 'monkey',
  'line': 166,
  'receiver': 'raptor_agentic'},
 {'anchor': ['TestResolvedPackPointersImportGuard',
             'test_core_config_import_failure_returns_empty'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(dqb.shutil, 'which', lambda name: '/usr/bin/codeql')",
  'file': 'packages/llm_analysis/tests/test_dataflow_query_builder.py',
  'kind': 'monkey',
  'line': 1023,
  'receiver': 'dqb'},
 {'anchor': ['test_cli_adapter_caps_nullability_math'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(sweep.subprocess, 'run', lambda *a, **kw: "
          "SimpleNamespace(returncode=0, stdout=json.dumps({'feasible': feasible}), stderr=''))",
  'file': 'core/audit/tests/test_nullability_oracle_scope.py',
  'kind': 'monkey',
  'line': 105,
  'receiver': 'sweep'},
 {'anchor': ['TestRunFridaSession', 'test_script_tempfile_cleaned_up'],
  'attribute': 'mkstemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(fo.tempfile, 'mkstemp', _tracking_mkstemp)",
  'file': 'core/audit/tests/test_frida_observe.py',
  'kind': 'monkey',
  'line': 278,
  'receiver': 'fo'},
 {'anchor': ['TestSubprocessBoundaryTranslation', 'test_run_codeql_translates_engage_exit_code'],
  'attribute': 'Popen',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(scanner.subprocess, 'Popen', lambda *a, **k: _FakeProc())",
  'file': 'core/sandbox/tests/test_engagement_failloud.py',
  'kind': 'monkey',
  'line': 179,
  'receiver': 'scanner'},
 {'anchor': ['TestSubprocessBoundaryTranslation', 'test_run_codeql_translates_engage_exit_code'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(scanner.shutil, 'which', lambda name: '/usr/bin/codeql' if name == "
          "'codeql' else _real_which(name))",
  'file': 'core/sandbox/tests/test_engagement_failloud.py',
  'kind': 'monkey',
  'line': 185,
  'receiver': 'scanner'},
 {'anchor': ['test_stalled_manager_is_reaped_and_late_claim_is_revoked'],
  'attribute': 'Popen',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(supervisor.subprocess, 'Popen', manager)",
  'file': 'core/security/tests/test_scratch_supervisor.py',
  'kind': 'monkey',
  'line': 337,
  'receiver': 'supervisor'},
 {'anchor': ['test_non_linux_invocation_keeps_packages'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(tool.sys, 'platform', 'win32')",
  'file': '.github/tests/test_prune_linux_extras.py',
  'kind': 'monkey',
  'line': 89,
  'receiver': 'tool'},
 {'anchor': ['test_early_allocation_failure_reclaims_directory_and_pin'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "fault.setattr(server.sys, 'platform', 'linux')",
  'file': 'core/llm/dispatcher/tests/test_dispatcher_lifecycle_cleanup.py',
  'kind': 'monkey',
  'line': 152,
  'receiver': 'server'},
 {'anchor': ['test_early_allocation_failure_reclaims_directory_and_pin'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "fault.setattr(server.sys, 'platform', 'darwin')",
  'file': 'core/llm/dispatcher/tests/test_dispatcher_lifecycle_cleanup.py',
  'kind': 'monkey',
  'line': 176,
  'receiver': 'server'},
 {'anchor': ['test_compact_socket_uses_captured_service_base_not_later_environment'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(server.sys, 'platform', 'darwin')",
  'file': 'core/llm/dispatcher/tests/test_service_tmp_base.py',
  'kind': 'monkey',
  'line': 22,
  'receiver': 'server'},
 {'anchor': ['TestAnonymousFd', 'test_unlinked_tempfile_branch'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(ev.sys, 'platform', 'darwin')",
  'file': 'core/sandbox/tests/test_evidence.py',
  'kind': 'monkey',
  'line': 315,
  'receiver': 'ev'},
 {'anchor': ['TestSeatbeltParentProxy', 'child_env'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(egress_backend.sys, 'platform', 'darwin')",
  'file': 'core/http/tests/test_egress_backend.py',
  'kind': 'monkey',
  'line': 179,
  'receiver': 'egress_backend'},
 {'anchor': ['TestSeatbeltParentProxy', 'test_any_failed_condition_keeps_in_process_proxy'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "child_env.setattr(egress_backend.sys, 'platform', 'linux')",
  'file': 'core/http/tests/test_egress_backend.py',
  'kind': 'monkey',
  'line': 205,
  'receiver': 'egress_backend'},
 {'anchor': ['test_address_space_refusal_is_advisory_only_on_darwin'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(child.sys, 'platform', platform)",
  'file': 'core/binary/tests/test_elf_worker.py',
  'kind': 'monkey',
  'line': 172,
  'receiver': 'child'},
 {'anchor': ['test_cpu_refusal_still_aborts_worker'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(child.sys, 'platform', platform)",
  'file': 'core/binary/tests/test_elf_worker.py',
  'kind': 'monkey',
  'line': 194,
  'receiver': 'child'},
 {'anchor': ['TestProxyNetnsContextWiring', '_enforcement_with'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "mock.patch.object(ctx.sys, 'platform', platform)",
  'file': 'core/sandbox/tests/test_proxy_netns_enforcement.py',
  'kind': 'object',
  'line': 543,
  'receiver': 'ctx'},
 {'anchor': ['TestProxyNetnsContextWiring', '_enter_egress'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "mock.patch.object(ctx.sys, 'platform', platform)",
  'file': 'core/sandbox/tests/test_proxy_netns_enforcement.py',
  'kind': 'object',
  'line': 638,
  'receiver': 'ctx'},
 {'anchor': ['TestProxyNetnsContextWiring', 'test_tcp_path_when_netns_unavailable'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "mock.patch.object(ctx.sys, 'platform', 'linux')",
  'file': 'core/sandbox/tests/test_proxy_netns_enforcement.py',
  'kind': 'object',
  'line': 702,
  'receiver': 'ctx'},
 {'anchor': ['TestProxyNetnsContextWiring', 'test_tier2_port_pin_warns_and_records_evidence'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "mock.patch.object(ctx.sys, 'platform', 'linux')",
  'file': 'core/sandbox/tests/test_proxy_netns_enforcement.py',
  'kind': 'object',
  'line': 741,
  'receiver': 'ctx'},
 {'anchor': ['TestDarwinUntrustedTmpPosture',
             'test_run_untrusted_defaults_exclude_tmp_baseline_on_darwin'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "patch.object(ctx.sys, 'platform', 'darwin')",
  'file': 'core/sandbox/tests/test_run_surface_hardening.py',
  'kind': 'object',
  'line': 200,
  'receiver': 'ctx'},
 {'anchor': ['backends'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(preflight.sys, 'platform', 'linux')",
  'file': 'core/sandbox/tests/test_scan_preflight.py',
  'kind': 'monkey',
  'line': 14,
  'receiver': 'preflight'},
 {'anchor': ['test_macos_uses_seatbelt_without_linux_requirements'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(preflight.sys, 'platform', 'darwin')",
  'file': 'core/sandbox/tests/test_scan_preflight.py',
  'kind': 'monkey',
  'line': 77,
  'receiver': 'preflight'},
 {'anchor': ['TestDarwinUntrustedGate', 'test_darwin_with_seatbelt_available_is_exempt'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "patch.object(ctx.sys, 'platform', 'darwin')",
  'file': 'core/sandbox/tests/test_untrusted_failclosed_gates.py',
  'kind': 'object',
  'line': 34,
  'receiver': 'ctx'},
 {'anchor': ['TestDarwinUntrustedGate', 'test_darwin_without_seatbelt_fails_closed'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "patch.object(ctx.sys, 'platform', 'darwin')",
  'file': 'core/sandbox/tests/test_untrusted_failclosed_gates.py',
  'kind': 'object',
  'line': 40,
  'receiver': 'ctx'},
 {'anchor': ['TestDarwinUntrustedGate', 'test_darwin_operator_override_engages_degraded_mode'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "patch.object(ctx.sys, 'platform', 'darwin')",
  'file': 'core/sandbox/tests/test_untrusted_failclosed_gates.py',
  'kind': 'object',
  'line': 49,
  'receiver': 'ctx'},
 {'anchor': ['TestUntrustedRequiresSeccomp', 'test_darwin_arm_untouched_by_seccomp_gate'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "patch.object(ctx.sys, 'platform', 'darwin')",
  'file': 'core/sandbox/tests/test_untrusted_failclosed_gates.py',
  'kind': 'object',
  'line': 168,
  'receiver': 'ctx'},
 {'anchor': ['test_unavailable_kernel_fails_closed'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(guard.sys, 'platform', 'darwin')",
  'file': 'core/startup/tests/test_install_guard.py',
  'kind': 'monkey',
  'line': 82,
  'receiver': 'guard'},
 {'anchor': ['TestSessionHumanTerminal', 'test_true_when_terminal_ancestor'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(r2.sys, 'platform', 'linux')",
  'file': 'core/security/tests/test_rule_of_two.py',
  'kind': 'monkey',
  'line': 304,
  'receiver': 'r2'},
 {'anchor': ['TestSessionHumanTerminal', 'test_falls_back_to_stdin_tty_when_no_ancestor'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(r2.sys, 'platform', 'linux')",
  'file': 'core/security/tests/test_rule_of_two.py',
  'kind': 'monkey',
  'line': 316,
  'receiver': 'r2'},
 {'anchor': ['TestSessionHumanTerminal', 'test_fail_closed_on_error'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(r2.sys, 'platform', 'linux')",
  'file': 'core/security/tests/test_rule_of_two.py',
  'kind': 'monkey',
  'line': 325,
  'receiver': 'r2'},
 {'anchor': ['TestSandboxWillContain', 'test_true_when_enabled_and_capable'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(r2.sys, 'platform', 'linux')",
  'file': 'core/security/tests/test_rule_of_two.py',
  'kind': 'monkey',
  'line': 350,
  'receiver': 'r2'},
 {'anchor': ['TestSandboxWillContain', 'test_false_when_platform_cannot_enforce'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(r2.sys, 'platform', 'linux')",
  'file': 'core/security/tests/test_rule_of_two.py',
  'kind': 'monkey',
  'line': 360,
  'receiver': 'r2'},
 {'anchor': ['TestSandboxWillContain', 'test_false_when_network_only_profile'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(r2.sys, 'platform', 'linux')",
  'file': 'core/security/tests/test_rule_of_two.py',
  'kind': 'monkey',
  'line': 374,
  'receiver': 'r2'},
 {'anchor': ['TestSandboxWillContain', 'test_true_for_debug_profile_when_capable'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(r2.sys, 'platform', 'linux')",
  'file': 'core/security/tests/test_rule_of_two.py',
  'kind': 'monkey',
  'line': 386,
  'receiver': 'r2'},
 {'anchor': ['test_macos_peer_pid_reuse_does_not_reuse_controller'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(broker.sys, 'platform', 'darwin')",
  'file': 'packages/joern/tests/test_broker.py',
  'kind': 'monkey',
  'line': 271,
  'receiver': 'broker'},
 {'anchor': ['test_macos_long_path_refuses_without_falling_back'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "monkeypatch.setattr(unix_socket.sys, 'platform', 'darwin')",
  'file': 'packages/joern/tests/test_unix_socket.py',
  'kind': 'monkey',
  'line': 30,
  'receiver': 'unix_socket'},
 {'added_module': 'core.startup.wsl',
  'anchor': ['TestIsWsl', 'test_filesystem_answer_cached'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "mock.patch.object(sys, 'platform', 'linux')",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'object',
  'line': 53,
  'receiver': '_host_platform_consumer'},
 {'added_module': 'core.startup.wsl',
  'anchor': ['TestIsWsl', 'test_probe_failure_reads_false'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "mock.patch.object(sys, 'platform', 'linux')",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'object',
  'line': 64,
  'receiver': '_host_platform_consumer'},
 {'added_module': 'core.startup.wsl',
  'anchor': ['TestIsWsl', 'test_non_linux_reads_false'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "mock.patch.object(sys, 'platform', 'darwin')",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'object',
  'line': 70,
  'receiver': '_host_platform_consumer'},
 {'added_module': 'core.startup.wsl',
  'anchor': ['TestWslFlavourDiscriminators', 'test_filesystem_answer_cached'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "mock.patch.object(sys, 'platform', 'linux')",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'object',
  'line': 154,
  'receiver': '_host_platform_consumer'},
 {'added_module': 'core.startup.wsl',
  'anchor': ['TestWslFlavourDiscriminators', 'test_probe_failure_reads_false'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "mock.patch.object(sys, 'platform', 'linux')",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'object',
  'line': 170,
  'receiver': '_host_platform_consumer'},
 {'added_module': 'core.startup.wsl',
  'anchor': ['TestWslFlavourDiscriminators', 'test_off_wsl_filesystem_answers'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "mock.patch.object(sys, 'platform', 'linux')",
  'file': 'core/startup/tests/test_wsl.py',
  'kind': 'object',
  'line': 178,
  'receiver': '_host_platform_consumer'},
 {'added_module': 'core.startup.init',
  'anchor': ['test_check_env_macos_seatbelt_available'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "mock.patch.object(sys, 'platform', 'darwin')",
  'file': 'core/startup/tests/test_check_env_macos.py',
  'kind': 'object',
  'line': 29,
  'receiver': '_host_platform_consumer'},
 {'added_module': 'core.startup.init',
  'anchor': ['test_check_env_macos_seatbelt_unavailable'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "mock.patch.object(sys, 'platform', 'darwin')",
  'file': 'core/startup/tests/test_check_env_macos.py',
  'kind': 'object',
  'line': 48,
  'receiver': '_host_platform_consumer'},
 {'added_module': 'core.startup.init',
  'anchor': ['_linux_sandbox_mocks'],
  'attribute': 'platform',
  'binding': 'sys',
  'call': "mock.patch.object(sys, 'platform', 'linux')",
  'file': 'core/startup/tests/test_check_env_wsl.py',
  'kind': 'object',
  'line': 26,
  'receiver': '_host_platform_consumer'},
 {'anchor': ['test_empty_output_cannot_become_a_successful_replacement_report'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch('shutil.which', return_value='/usr/bin/semgrep')",
  'file': 'packages/static-analysis/tests/test_scanner_semgrep.py',
  'kind': 'decorator',
  'line': 481,
  'mock_alias': '_raptor_scanner_semgrep_mock_target',
  'receiver': '_scanner_mod'},
 {'anchor': ['TestRunSingleSemgrep', 'test_creates_output_files'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch('shutil.which')",
  'file': 'packages/static-analysis/tests/test_scanner_semgrep.py',
  'kind': 'decorator',
  'line': 40,
  'mock_alias': '_raptor_scanner_semgrep_mock_target',
  'receiver': '_scanner_mod'},
 {'anchor': ['TestRunSingleSemgrep', 'test_sanitizes_name_with_slashes'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch('shutil.which')",
  'file': 'packages/static-analysis/tests/test_scanner_semgrep.py',
  'kind': 'decorator',
  'line': 62,
  'mock_alias': '_raptor_scanner_semgrep_mock_target',
  'receiver': '_scanner_mod'},
 {'anchor': ['TestRunSingleSemgrep', 'test_progress_callback_called'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch('shutil.which')",
  'file': 'packages/static-analysis/tests/test_scanner_semgrep.py',
  'kind': 'decorator',
  'line': 82,
  'mock_alias': '_raptor_scanner_semgrep_mock_target',
  'receiver': '_scanner_mod'},
 {'anchor': ['TestSandboxFakeHomeWiring', 'test_run_called_with_fake_home_true'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch('shutil.which')",
  'file': 'packages/static-analysis/tests/test_scanner_semgrep.py',
  'kind': 'decorator',
  'line': 127,
  'mock_alias': '_raptor_scanner_semgrep_mock_target',
  'receiver': '_scanner_mod'},
 {'anchor': ['TestSandboxFakeHomeWiring', 'test_run_called_with_target_and_output_for_fake_home'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch('shutil.which')",
  'file': 'packages/static-analysis/tests/test_scanner_semgrep.py',
  'kind': 'decorator',
  'line': 144,
  'mock_alias': '_raptor_scanner_semgrep_mock_target',
  'receiver': '_scanner_mod'},
 {'anchor': ['TestSandboxFakeHomeWiring', 'test_extra_config_paths_forwarded_as_readable_paths'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch('shutil.which')",
  'file': 'packages/static-analysis/tests/test_scanner_semgrep.py',
  'kind': 'decorator',
  'line': 168,
  'mock_alias': '_raptor_scanner_semgrep_mock_target',
  'receiver': '_scanner_mod'},
 {'anchor': ['TestChildJsonPromotion', 'test_child_json_is_promoted_to_out_dir'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch('shutil.which')",
  'file': 'packages/static-analysis/tests/test_scanner_semgrep.py',
  'kind': 'decorator',
  'line': 402,
  'mock_alias': '_raptor_scanner_semgrep_mock_target',
  'receiver': '_scanner_mod'},
 {'anchor': ['TestChildJsonPromotion', 'test_symlink_at_child_json_is_not_promoted'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch('shutil.which')",
  'file': 'packages/static-analysis/tests/test_scanner_semgrep.py',
  'kind': 'decorator',
  'line': 431,
  'mock_alias': '_raptor_scanner_semgrep_mock_target',
  'receiver': '_scanner_mod'},
 {'anchor': ['TestChildJsonPromotion', 'test_stale_child_json_from_previous_run_is_cleared'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch('shutil.which')",
  'file': 'packages/static-analysis/tests/test_scanner_semgrep.py',
  'kind': 'decorator',
  'line': 459,
  'mock_alias': '_raptor_scanner_semgrep_mock_target',
  'receiver': '_scanner_mod'},
 {'anchor': ['TestCleanEnvironment', 'test_virtual_env_stripped_from_env'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch('shutil.which', return_value='/usr/bin/semgrep')",
  'file': 'packages/static-analysis/tests/test_scanner_semgrep_parallel.py',
  'kind': 'decorator',
  'line': 453,
  'mock_alias': '_raptor_scanner_semgrep_parallel_mock_target',
  'receiver': '_scanner_mod'},
 {'anchor': ['TestCleanEnvironment', 'test_venv_paths_stripped_from_PATH'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch('shutil.which', return_value='/usr/bin/semgrep')",
  'file': 'packages/static-analysis/tests/test_scanner_semgrep_parallel.py',
  'kind': 'decorator',
  'line': 473,
  'mock_alias': '_raptor_scanner_semgrep_parallel_mock_target',
  'receiver': '_scanner_mod'},
 {'anchor': ['install'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(shutil, 'which', lambda *a, **k: None)",
  'file': 'packages/ghidra/tests/test_ebpf_capability.py',
  'kind': 'monkey',
  'line': 60,
  'receiver': 'cap'},
 {'anchor': ['TestDiscovery', 'test_install_root_absent'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(shutil, 'which', lambda *a, **k: None)",
  'file': 'packages/ghidra/tests/test_ebpf_capability.py',
  'kind': 'monkey',
  'line': 87,
  'receiver': 'cap'},
 {'anchor': ['TestDiscovery', 'test_env_dir_without_headless_rejected'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(shutil, 'which', lambda *a, **k: None)",
  'file': 'packages/ghidra/tests/test_ebpf_capability.py',
  'kind': 'monkey',
  'line': 93,
  'receiver': 'cap'},
 {'anchor': ['TestDiscovery', 'test_which_resolves_support_parent'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(shutil, 'which', lambda name: str(headless) if name == "
          "'analyzeHeadless' else None)",
  'file': 'packages/ghidra/tests/test_ebpf_capability.py',
  'kind': 'monkey',
  'line': 100,
  'receiver': 'cap'},
 {'anchor': ['TestConsult', 'test_no_ghidra_downgraded'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(shutil, 'which', lambda *a, **k: None)",
  'file': 'packages/ghidra/tests/test_ebpf_capability.py',
  'kind': 'monkey',
  'line': 192,
  'receiver': 'cap'},
 {'anchor': ['TestToolDiscovery', 'test_plain_name_preferred'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(shutil, 'which', lambda name: f'/usr/bin/{name}' if name in "
          "('clang', 'clang-21') else None)",
  'delegate': 'cap_mod',
  'delegate_module': 'packages.ghidra.ebpf_capability',
  'file': 'packages/ghidra/tests/test_ebpf_probe.py',
  'kind': 'monkey',
  'line': 373,
  'receiver': 'probe_mod'},
 {'anchor': ['TestToolDiscovery', 'test_versioned_suffix_found'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(shutil, 'which', lambda name: '/usr/bin/clang-19' if name == "
          "'clang-19' else None)",
  'delegate': 'cap_mod',
  'delegate_module': 'packages.ghidra.ebpf_capability',
  'file': 'packages/ghidra/tests/test_ebpf_probe.py',
  'kind': 'monkey',
  'line': 381,
  'receiver': 'probe_mod'},
 {'anchor': ['TestToolDiscovery', 'test_suffix_range_two_directions'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(shutil, 'which', lambda name: f'/usr/bin/{name}' if name == "
          "f'clang-{floor}' else None)",
  'delegate': 'cap_mod',
  'delegate_module': 'packages.ghidra.ebpf_capability',
  'file': 'packages/ghidra/tests/test_ebpf_probe.py',
  'kind': 'monkey',
  'line': 391,
  'receiver': 'probe_mod'},
 {'anchor': ['TestToolDiscovery', 'test_suffix_range_two_directions'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(shutil, 'which', lambda name: f'/usr/bin/{name}' if name == "
          "f'clang-{floor - 1}' else None)",
  'delegate': 'cap_mod',
  'delegate_module': 'packages.ghidra.ebpf_capability',
  'file': 'packages/ghidra/tests/test_ebpf_probe.py',
  'kind': 'monkey',
  'line': 399,
  'receiver': 'probe_mod'},
 {'anchor': ['TestToolDiscovery', 'test_absent_everywhere'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(shutil, 'which', lambda *a, **k: None)",
  'delegate': 'cap_mod',
  'delegate_module': 'packages.ghidra.ebpf_capability',
  'file': 'packages/ghidra/tests/test_ebpf_probe.py',
  'kind': 'monkey',
  'line': 407,
  'receiver': 'probe_mod'},
 {'added_module': 'packages.autonomous.exploit_validator',
  'anchor': ['test_detection_prefers_c_plus_plus_when_present'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch.object(shutil, 'which', side_effect=lambda name: f'/usr/bin/{name}' if name == "
          "'c++' else None)",
  'file': 'packages/autonomous/tests/test_exploit_validator_compiler_detect.py',
  'kind': 'object',
  'line': 60,
  'receiver': '_compiler_probe_consumer'},
 {'added_module': 'packages.autonomous.exploit_validator',
  'anchor': ['test_detection_falls_back_to_g_plus_plus'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch.object(shutil, 'which', side_effect=lambda name: f'/usr/bin/{name}' if name == "
          "'g++' else None)",
  'file': 'packages/autonomous/tests/test_exploit_validator_compiler_detect.py',
  'kind': 'object',
  'line': 69,
  'receiver': '_compiler_probe_consumer'},
 {'added_module': 'packages.autonomous.exploit_validator',
  'anchor': ['test_detection_falls_back_to_clang_plus_plus'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch.object(shutil, 'which', side_effect=lambda name: f'/usr/bin/{name}' if name == "
          "'clang++' else None)",
  'file': 'packages/autonomous/tests/test_exploit_validator_compiler_detect.py',
  'kind': 'object',
  'line': 78,
  'receiver': '_compiler_probe_consumer'},
 {'added_module': 'packages.autonomous.exploit_validator',
  'anchor': ['test_detection_raises_when_nothing_available'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch.object(shutil, 'which', return_value=None)",
  'file': 'packages/autonomous/tests/test_exploit_validator_compiler_detect.py',
  'kind': 'object',
  'line': 87,
  'receiver': '_compiler_probe_consumer'},
 {'added_module': 'packages.autonomous.exploit_validator',
  'anchor': ['test_validator_surfaces_missing_compiler_as_validation_result'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "patch.object(shutil, 'which', return_value=None)",
  'file': 'packages/autonomous/tests/test_exploit_validator_compiler_detect.py',
  'kind': 'object',
  'line': 101,
  'receiver': '_compiler_probe_consumer'},
 {'anchor': ['TestIsInteractive', 'test_true_when_tty'],
  'attribute': 'stdin',
  'binding': 'sys',
  'call': "patch('sys.stdin')",
  'file': 'core/security/tests/test_rule_of_two.py',
  'kind': 'string',
  'line': 39,
  'receiver': 'r2'},
 {'anchor': ['TestIsInteractive', 'test_false_when_not_tty'],
  'attribute': 'stdin',
  'binding': 'sys',
  'call': "patch('sys.stdin')",
  'file': 'core/security/tests/test_rule_of_two.py',
  'kind': 'string',
  'line': 44,
  'receiver': 'r2'},
 {'anchor': ['TestIsInteractive', 'test_false_when_no_isatty'],
  'attribute': 'stdin',
  'binding': 'sys',
  'call': "patch('sys.stdin', new=io.StringIO())",
  'file': 'core/security/tests/test_rule_of_two.py',
  'kind': 'string',
  'line': 49,
  'receiver': 'r2'},
 {'anchor': ['TestIsInteractive', 'test_false_when_tty_but_ci_env_set'],
  'attribute': 'stdin',
  'binding': 'sys',
  'call': "patch('sys.stdin')",
  'file': 'core/security/tests/test_rule_of_two.py',
  'kind': 'string',
  'line': 58,
  'receiver': 'r2'},
 {'anchor': ['TestSessionHumanTerminal', 'test_falls_back_to_stdin_tty_when_no_ancestor'],
  'attribute': 'stdin',
  'binding': 'sys',
  'call': "patch('sys.stdin')",
  'file': 'core/security/tests/test_rule_of_two.py',
  'kind': 'string',
  'line': 318,
  'receiver': 'r2'},
 {'anchor': ['TestSessionHumanTerminal', 'test_fail_closed_on_error'],
  'attribute': 'stdin',
  'binding': 'sys',
  'call': "patch('sys.stdin')",
  'file': 'core/security/tests/test_rule_of_two.py',
  'kind': 'string',
  'line': 328,
  'receiver': 'r2'}]


@lru_cache(maxsize=None)
def _tree(file):
    return ast.parse((_REPO / file).read_text())


def _expected(row):
    node = copy.deepcopy(ast.parse(row["call"], mode="eval").body)
    owner = ast.parse(row["receiver"], mode="eval").body
    if row["kind"] == "qualified_string":
        node.args[0] = ast.Constant("core.security.rule_of_two.sys.stdin")
    elif row["kind"] == "decorator":
        node.args[0] = ast.Constant(row["mock_alias"] + ".shutil.which")
    elif row["kind"] == "monkey":
        scope = node.func.value
        node.func = ast.Name(id="patch_module_attribute", ctx=ast.Load())
        node.args = [scope, owner, ast.Constant(row["binding"]), *node.args[1:]]
    else:
        node.func = ast.Name(id="mock_module_attribute", ctx=ast.Load())
        node.args = [owner, ast.Constant(row["binding"]), ast.Constant(row["attribute"]), *node.args[1 if row["kind"] == "string" else 2:]]
    return node


@lru_cache(maxsize=None)
def _node(index):
    row = _SITES[index]
    tree = _tree(row["file"])
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    fingerprints = {ast.dump(ast.parse(row["call"], mode="eval").body), ast.dump(_expected(row))}
    matches = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or ast.dump(node) not in fingerprints:
            continue
        anchor = []
        parent = parents.get(node)
        while parent:
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                anchor.append(parent.name)
            parent = parents.get(parent)
        if list(reversed(anchor)) == row["anchor"]:
            matches.append(node)
    assert matches, (row["file"], row["line"], row["anchor"])
    rank = sum(previous["file"] == row["file"] and previous["anchor"] == row["anchor"] and previous["call"] == row["call"] and previous["line"] < row["line"] for previous in _SITES)
    return sorted(matches, key=lambda node: (node.lineno, node.col_offset))[rank]


@lru_cache(maxsize=None)
def _native(file):
    name = "owned_host_native_" + file.replace("/", "_").replace(".", "_")
    loader = importlib.machinery.SourceFileLoader(name, str(_REPO / file))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()), pytest.MonkeyPatch.context() as scope:
        scope.setitem(sys.modules, name, module)
        scope.setenv("_RAPTOR_TRUSTED", "1")
        loader.exec_module(module)
    return module


@lru_cache(maxsize=None)
def _consumer(index):
    row = _SITES[index]
    namespace = dict(vars(_native(row["file"])))
    expression = row["receiver"]
    names = {node.id for node in ast.walk(ast.parse(expression, mode="eval")) if isinstance(node, ast.Name)}
    with patch.object(sys, "path", sys.path.copy()):
        for name in names:
            if name not in namespace:
                if row.get("added_module"):
                    namespace[name] = importlib.import_module(row["added_module"])
                    continue
                imports = [node for node in ast.walk(_tree(row["file"])) if isinstance(node, (ast.Import, ast.ImportFrom)) and any((alias.asname or alias.name.split(".")[0]) == name for alias in node.names)]
                if imports:
                    exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(imports[0])], type_ignores=[])), row["file"], "exec"), namespace)
                else:
                    aliases = [node.value.id for node in ast.walk(_tree(row["file"])) if isinstance(node, ast.Assign) and isinstance(node.value, ast.Name) and any(isinstance(target, ast.Name) and target.id == name for target in node.targets) and isinstance(namespace.get(node.value.id), ModuleType)]
                    if not aliases and name == "scanner" and row["file"].endswith("test_engagement_failloud.py"):
                        function = next(node for node in ast.walk(_tree(row["file"])) if isinstance(node, ast.FunctionDef) and node.name == row["anchor"][-1])
                        for statement in function.body:
                            if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant):
                                continue
                            assert isinstance(statement, (ast.Import, ast.ImportFrom, ast.Assign, ast.With)), ast.unparse(statement)
                            exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(statement)], type_ignores=[])), row["file"], "exec"), namespace)
                            candidate = namespace.get(name)
                            if isinstance(candidate, ModuleType) and hasattr(candidate, row["binding"]):
                                break
                        assert isinstance(namespace.get(name), ModuleType), (row["file"], name)
                        continue
                    assert aliases, (row["file"], name)
                    namespace[name] = namespace[aliases[0]]
            value = namespace[name]
            if not isinstance(value, ModuleType) and hasattr(value, "__wrapped__"):
                factory = value.__wrapped__
                assert not inspect.signature(factory).parameters, (row["file"], name)
                value = factory()
                if inspect.isgenerator(value):
                    try:
                        namespace[name] = next(value)
                    finally:
                        value.close()
                else:
                    namespace[name] = value
        owner = eval(expression, namespace)
    assert isinstance(owner, ModuleType), (row["file"], expression, owner)
    return owner


def _assert_namespace(owner, before):
    current = vars(owner)
    changed = [name for name, value in before.items() if name not in current or current[name] is not value]
    added = sorted(current.keys() - before.keys())
    assert changed == [] and added == [], (owner.__name__, changed, added)


@contextmanager
def _snapshots(index, borrowed):
    row = _SITES[index]
    primary = _consumer(index)
    owners = [primary]
    if row.get("delegate_module"):
        owners.append(importlib.import_module(row["delegate_module"]))
    with pytest.MonkeyPatch.context() as inherited:
        if borrowed:
            for owner in owners:
                original = getattr(owner, row["binding"])
                view = ModuleType(original.__name__)
                vars(view).update(vars(original))
                inherited.setitem(vars(owner), row["binding"], view)
        if row.get("cache_fields") and borrowed:
            delegated = owners[-1]
            for name in row["cache_fields"]:
                inherited.setitem(vars(delegated), name, "borrowed-" + name if name.startswith("_resolved_") else True)
        if row.get("mock_alias") and borrowed:
            inherited.setitem(sys.modules, row["mock_alias"], ModuleType("inherited_mock_target"))
        alias_before = (row.get("mock_alias") in sys.modules, sys.modules.get(row.get("mock_alias")))
        raw = [(owner, dict(vars(owner))) for owner in owners]
        values = [subprocess, shutil, sys, tempfile] + [getattr(owner, row["binding"]) for owner in owners]
        snapshots = [(value, dict(vars(value))) for value in values]
        try:
            yield primary, raw, snapshots
        finally:
            if row.get("mock_alias"):
                assert (row["mock_alias"] in sys.modules) == alias_before[0]
                assert sys.modules.get(row["mock_alias"]) is alias_before[1]


def _forward_fixture(file, scope, owner):
    namespace = dict(vars(_native(file)))
    namespace["patch_module_attribute"] = patch_module_attribute
    for original in _tree(file).body:
        if not isinstance(original, ast.FunctionDef) or original.name not in ("_forward_host_interface_mock", "_private_discovery_patch_target", "_forward_selftest_tool_lookup"):
            continue
        node = copy.deepcopy(original)
        node.decorator_list = []
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), file, "exec"), namespace)
        if node.name == "_forward_selftest_tool_lookup":
            namespace[node.name](owner, scope)
        else:
            namespace[node.name](scope)


def _exercise(index, borrowed, exit_mode, mock=True):
    row = _SITES[index]
    with _snapshots(index, borrowed) as (owner, raw, snapshots):
        token = object()
        fake = MagicMock(name="owned_host_mock", return_value=token)
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope, ExitStack() as contexts:
                _forward_fixture(row["file"], scope, owner)
                if mock:
                    if row.get("prerequisite_call"):
                        dependency = next(i for i, site in enumerate(_SITES) if site["file"] == row["file"] and site["call"] == row["prerequisite_call"])
                        prerequisite = copy.deepcopy(_node(dependency))
                        setup = {"patch_module_attribute": patch_module_attribute, "monkeypatch": scope, "r2": owner}
                        eval(compile(ast.fix_missing_locations(ast.Expression(prerequisite)), row["file"], "eval"), setup)
                    node = copy.deepcopy(_node(index))
                    namespace = {"_owner": owner, "_scope": scope, "_fake": fake, "patch_module_attribute": patch_module_attribute, "mock_module_attribute": mock_module_attribute}
                    if getattr(node.func, "id", "") == "patch_module_attribute":
                        node.args[0] = ast.Name(id="_scope", ctx=ast.Load())
                        node.args[1] = ast.Name(id="_owner", ctx=ast.Load())
                        node.args[-1] = ast.Name(id="_fake", ctx=ast.Load())
                        eval(compile(ast.fix_missing_locations(ast.Expression(node)), row["file"], "eval"), namespace)
                    elif getattr(node.func, "id", "") == "mock_module_attribute":
                        node.args = [ast.Name(id="_owner", ctx=ast.Load()), *node.args[1:3], ast.Name(id="_fake", ctx=ast.Load())]
                        node.keywords = []
                        contexts.enter_context(eval(compile(ast.fix_missing_locations(ast.Expression(node)), row["file"], "eval"), namespace))
                    elif row["kind"] in ("decorator", "qualified_string"):
                        contexts.enter_context(patch(node.args[0].value, fake))
                    else:
                        # Original-source control: use the actual original receiver.
                        target = {"sys": sys, "shutil": shutil, "tempfile": tempfile, "subprocess": subprocess}[row["binding"]] if row.get("added_module") or row["kind"] == "string" else getattr(owner, row["binding"])
                        if row["kind"] == "monkey":
                            scope.setattr(target, row["attribute"], fake)
                        else:
                            contexts.enter_context(patch.object(target, row["attribute"], fake))
                    for shared, before in snapshots:
                        _assert_namespace(shared, before)
                    assert getattr(getattr(owner, row["binding"]), row["attribute"]) is fake
                    if row.get("delegate_module"):
                        delegated = importlib.import_module(row["delegate_module"])
                        assert getattr(getattr(delegated, row["binding"]), row["attribute"])(token, owned=token) is token
                        fake.assert_called_once_with(token, owned=token)
                else:
                    for shared, before in snapshots:
                        _assert_namespace(shared, before)
                if exit_mode != "normal":
                    raise RuntimeError("owned scope exit") if exit_mode == "error" else KeyboardInterrupt("owned scope exit")
        except BaseException as error:
            caught = error
        for shared, before in raw + snapshots:
            _assert_namespace(shared, before)
        if exit_mode == "normal":
            assert caught is None, repr(caught)
        else:
            assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)
            assert str(caught) == "owned scope exit"


@pytest.mark.parametrize("index", range(len(_SITES)), ids=lambda index: _SITES[index]["file"] + ":" + str(_SITES[index]["line"]))
@pytest.mark.parametrize("borrowed", [False, True], ids=["ordinary", "borrowed"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_native_host_mock_is_owned(index, borrowed, exit_mode):
    _exercise(index, borrowed, exit_mode)


@pytest.mark.parametrize("index", list({row["file"]: index for index, row in enumerate(_SITES)}.values()), ids=lambda index: _SITES[index]["file"])
@pytest.mark.parametrize("borrowed", [False, True])
def test_unmodified_host_control(index, borrowed):
    _exercise(index, borrowed, "normal", mock=False)


@pytest.mark.parametrize("slot", ["absent", "none", "module"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_real_selftest_fixture_restores_registry_and_trust_marker(slot, exit_mode):
    fixture = _native("core/testing/tests/test_selftest_harness.py").selftest.__wrapped__
    with pytest.MonkeyPatch.context() as inherited, patch.object(sys, "path", sys.path.copy()):
        if slot == "absent":
            inherited.delitem(sys.modules, "raptor_self_test", raising=False)
            inherited.delenv("_RAPTOR_TRUSTED", raising=False)
        else:
            inherited.setitem(sys.modules, "raptor_self_test", None if slot == "none" else ModuleType("borrowed_selftest"))
            inherited.setenv("_RAPTOR_TRUSTED", "" if slot == "none" else "inherited-trust")
        before = ("raptor_self_test" in sys.modules, sys.modules.get("raptor_self_test"))
        trust = ("_RAPTOR_TRUSTED" in os.environ, os.environ.get("_RAPTOR_TRUSTED"))
        generator = fixture()
        owner = next(generator)
        assert sys.modules["raptor_self_test"] is owner
        assert os.environ["_RAPTOR_TRUSTED"] == "1"
        caught = None
        try:
            if exit_mode == "normal":
                generator.close()
            else:
                generator.throw(RuntimeError("selftest exit") if exit_mode == "error" else KeyboardInterrupt("selftest exit"))
        except BaseException as error:
            caught = error
        finally:
            generator.close()
        assert ("raptor_self_test" in sys.modules) == before[0]
        assert sys.modules.get("raptor_self_test") is before[1]
        assert ("_RAPTOR_TRUSTED" in os.environ, os.environ.get("_RAPTOR_TRUSTED")) == trust
        if exit_mode == "normal":
            assert caught is None, repr(caught)
        else:
            assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)
            assert str(caught) == "selftest exit"
