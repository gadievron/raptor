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
import signal
import socket
import threading
import time
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

from core.testing.module_bindings import mock_module_attribute, patch_module_attribute

_REPO = Path(__file__).resolve().parents[3]
_SITES = [{'anchor': ['test_version_probe_uses_sanitised_env'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "monkeypatch.setattr(detect.shutil, 'which', lambda _n: '/opt/ghidra/analyzeHeadless')",
  'file': 'packages/ghidra/tests/test_detect_env_hygiene.py',
  'kind': 'monkey',
  'line': 23,
  'raising': True,
  'receiver': 'detect'},
 {'anchor': ['test_copy_failure_cleans_server_and_allows_retry'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(server.tempfile, 'mkdtemp', lambda **kw: str(work))",
  'file': 'packages/ghidra/tests/test_setup_cleanup.py',
  'kind': 'monkey',
  'line': 12,
  'raising': True,
  'receiver': 'server'},
 {'anchor': ['_run_main'],
  'attribute': 'signal',
  'binding': 'signal',
  'call': "monkeypatch.setattr(nf.signal, 'signal', lambda *_a: None)",
  'file': 'packages/joern/tests/test_orphan_ttl_plumbing.py',
  'kind': 'monkey',
  'line': 72,
  'raising': True,
  'receiver': 'nf'},
 {'anchor': ['_run_main'],
  'attribute': 'Popen',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(nf.subprocess, 'Popen', lambda cmd, **kwargs: "
          'SimpleNamespace(wait=lambda **kwargs: 0))',
  'file': 'packages/joern/tests/test_orphan_ttl_plumbing.py',
  'kind': 'monkey',
  'line': 73,
  'raising': True,
  'receiver': 'nf'},
 {'anchor': ['TestPidnsRefusalFailsClosed', 'test_refusal_exits_before_listener_and_child'],
  'attribute': 'Popen',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(nf.subprocess, 'Popen', lambda cmd: spawned.append(list(cmd)))",
  'file': 'packages/joern/tests/test_pidns_forwarder.py',
  'kind': 'monkey',
  'line': 138,
  'raising': True,
  'receiver': 'nf'},
 {'anchor': ['TestServerAuthSupportProbe', 'test_probe_uses_selected_jdk_without_homebrew_wrapper'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(server.subprocess, 'run', launch)",
  'file': 'packages/joern/tests/test_server.py',
  'kind': 'monkey',
  'line': 992,
  'raising': True,
  'receiver': 'server'},
 {'anchor': ['TestMakeUdsDir', 'test_long_tmpdir_preserves_operator_base'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(server_mod.tempfile, 'mkdtemp', fake_mkdtemp)",
  'file': 'packages/joern/tests/test_server_uds.py',
  'kind': 'monkey',
  'line': 352,
  'raising': True,
  'receiver': 'server_mod'},
 {'anchor': ['TestMakeUdsDir', 'test_multibyte_tmpdir_budgeted_in_bytes'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(server_mod.tempfile, 'mkdtemp', fake_mkdtemp)",
  'file': 'packages/joern/tests/test_server_uds.py',
  'kind': 'monkey',
  'line': 397,
  'raising': True,
  'receiver': 'server_mod'},
 {'anchor': ['TestMakeUdsDir', 'test_surrogate_escaped_tmpdir_does_not_crash'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(server_mod.tempfile, 'mkdtemp', fake_mkdtemp)",
  'file': 'packages/joern/tests/test_server_uds.py',
  'kind': 'monkey',
  'line': 448,
  'raising': True,
  'receiver': 'server_mod'},
 {'anchor': ['test_mask_case_failure_releases_sockets_and_directory'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "patcher.setattr(module.tempfile, 'mkdtemp', lambda **kw: str(root))",
  'file': 'packages/joern/tests/test_sigmask_fixture_ownership.py',
  'kind': 'monkey',
  'line': 149,
  'raising': True,
  'receiver': 'module'},
 {'anchor': ['test_resolution_failure_cleans_before_ownership_transfer'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(cli.tempfile, 'mkdtemp', track)",
  'file': 'packages/describe/tests/test_archive_ownership_cleanup.py',
  'kind': 'monkey',
  'line': 37,
  'raising': True,
  'receiver': 'cli'},
 {'anchor': ['TestSandboxedProbeEnvHygiene', 'test_find_frida_site_probe_uses_sanitised_env'],
  'attribute': 'executable',
  'binding': 'sys',
  'call': "monkeypatch.setattr(sandboxed.sys, 'executable', str(py))",
  'file': 'packages/frida/tests/test_active.py',
  'kind': 'monkey',
  'line': 644,
  'raising': True,
  'receiver': 'sandboxed'},
 {'anchor': ['test_user_site_discovery_never_imports_package_init'],
  'attribute': 'executable',
  'binding': 'sys',
  'call': "monkeypatch.setattr(sandboxed.sys, 'executable', executable)",
  'file': 'packages/frida/tests/test_probe_import_hygiene.py',
  'kind': 'monkey',
  'line': 38,
  'raising': True,
  'receiver': 'sandboxed'},
 {'anchor': ['test_cli_interpreter_discovery_supports_linux_and_macos_paths'],
  'attribute': 'executable',
  'binding': 'sys',
  'call': "monkeypatch.setattr(sandboxed.sys, 'executable', '/nonexistent-fixture-python')",
  'file': 'packages/frida/tests/test_probe_import_hygiene.py',
  'kind': 'monkey',
  'line': 87,
  'raising': True,
  'receiver': 'sandboxed'},
 {'anchor': ['TestTimeoutElapsedMs', 'test_run_rule_timeout_carries_elapsed'],
  'attribute': 'monotonic',
  'binding': 'time',
  'call': "patch.object(runner_mod.time, 'monotonic', side_effect=self._ticker())",
  'file': 'packages/coccinelle/tests/test_runner.py',
  'kind': 'object',
  'line': 2372,
  'raising': True,
  'receiver': 'runner_mod'},
 {'anchor': ['TestTimeoutElapsedMs', 'test_batched_timeout_carries_elapsed'],
  'attribute': 'monotonic',
  'binding': 'time',
  'call': "patch.object(runner_mod.time, 'monotonic', side_effect=self._ticker())",
  'file': 'packages/coccinelle/tests/test_runner.py',
  'kind': 'object',
  'line': 2395,
  'raising': True,
  'receiver': 'runner_mod'},
 {'anchor': ['test_rule_write_failure_closes_sandbox_scratch'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(scratch.tempfile, 'mkdtemp', lambda **kw: str(allocated))",
  'file': 'packages/code_understanding/tests/dispatch/test_cocci_setup_cleanup.py',
  'kind': 'monkey',
  'line': 20,
  'raising': True,
  'receiver': 'scratch'},
 {'anchor': ['test_rule_write_failure_closes_sandbox_scratch'],
  'attribute': 'NamedTemporaryFile',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(scratch.tempfile, 'NamedTemporaryFile', failed_write)",
  'file': 'packages/code_understanding/tests/dispatch/test_cocci_setup_cleanup.py',
  'kind': 'monkey',
  'line': 25,
  'raising': True,
  'receiver': 'scratch'},
 {'anchor': ['TestOwnedDirFailureCleanup', 'test_write_failure_removes_owned_dir'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(mod.tempfile, 'mkdtemp', _tracking_mkdtemp)",
  'delegate_module': 'core.run.scratch',
  'file': 'packages/sca/bump/tests/test_image_binary_extract.py',
  'kind': 'monkey',
  'line': 633,
  'raising': True,
  'receiver': 'mod'},
 {'anchor': ['test_wheel_inspection_scratch_is_contained_and_cleaned'],
  'attribute': 'TemporaryDirectory',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(PRUNE.tempfile, 'TemporaryDirectory', contained)",
  'file': '.github/tests/test_prune_windows_helpers.py',
  'kind': 'monkey',
  'line': 272,
  'raising': True,
  'receiver': 'PRUNE'},
 {'anchor': ['test_probe_dns_success'],
  'attribute': 'gethostbyname',
  'binding': 'socket',
  'call': "monkeypatch.setattr(service_health.socket, 'gethostbyname', lambda host: '1.2.3.4')",
  'file': 'packages/cve_diff/tests/unit/infra/test_service_health.py',
  'kind': 'monkey',
  'line': 470,
  'raising': True,
  'receiver': 'service_health'},
 {'anchor': ['test_probe_dns_failure_on_gaierror'],
  'attribute': 'gethostbyname',
  'binding': 'socket',
  'call': "monkeypatch.setattr(service_health.socket, 'gethostbyname', fail)",
  'file': 'packages/cve_diff/tests/unit/infra/test_service_health.py',
  'kind': 'monkey',
  'line': 479,
  'raising': True,
  'receiver': 'service_health'},
 {'anchor': ['test_fused_build_exception_respects_context_ownership'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(tools.tempfile, 'mkdtemp', lambda **kw: str(context))",
  'file': 'packages/cve_env/tests/unit/test_fused_build_cleanup.py',
  'kind': 'monkey',
  'line': 16,
  'raising': True,
  'receiver': 'tools'},
 {'anchor': ['test_successful_fused_build_keeps_automatic_context'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(tools.tempfile, 'mkdtemp', lambda **kw: str(context))",
  'file': 'packages/cve_env/tests/unit/test_fused_build_cleanup.py',
  'kind': 'monkey',
  'line': 31,
  'raising': True,
  'receiver': 'tools'},
 {'anchor': ['test_docker_run_strips_dangerous_env'],
  'attribute': 'sleep',
  'binding': 'time',
  'call': "patch.object(cc.time, 'sleep')",
  'file': 'packages/cve_env/tests/unit/test_subprocess_env_hygiene.py',
  'kind': 'object',
  'line': 141,
  'raising': True,
  'receiver': 'cc'},
 {'anchor': ['_fetch'],
  'attribute': 'getaddrinfo',
  'binding': 'socket',
  'call': "patch.object(wf.socket, 'getaddrinfo', return_value=addrinfo)",
  'file': 'packages/cve_env/tests/unit/test_web_fetch.py',
  'kind': 'object',
  'line': 83,
  'raising': True,
  'receiver': 'wf'},
 {'anchor': ['test_resolve_hostname_safe_resolution_failure_blocks'],
  'attribute': 'getaddrinfo',
  'binding': 'socket',
  'call': "patch.object(wf.socket, 'getaddrinfo', side_effect=OSError('no dns'))",
  'file': 'packages/cve_env/tests/unit/test_web_fetch.py',
  'kind': 'object',
  'line': 155,
  'raising': True,
  'receiver': 'wf'},
 {'anchor': ['test_resolve_hostname_safe_unicode_error_blocks'],
  'attribute': 'getaddrinfo',
  'binding': 'socket',
  'call': "patch.object(wf.socket, 'getaddrinfo', side_effect=UnicodeError('label too long'))",
  'file': 'packages/cve_env/tests/unit/test_web_fetch.py',
  'kind': 'object',
  'line': 162,
  'raising': True,
  'receiver': 'wf'},
 {'anchor': ['test_resolve_hostname_safe_empty_sockaddr_skipped'],
  'attribute': 'getaddrinfo',
  'binding': 'socket',
  'call': "patch.object(wf.socket, 'getaddrinfo', return_value=infos)",
  'file': 'packages/cve_env/tests/unit/test_web_fetch.py',
  'kind': 'object',
  'line': 169,
  'raising': True,
  'receiver': 'wf'},
 {'anchor': ['test_resolve_hostname_safe_unparseable_ip_fails_closed'],
  'attribute': 'getaddrinfo',
  'binding': 'socket',
  'call': "patch.object(wf.socket, 'getaddrinfo', return_value=infos)",
  'file': 'packages/cve_env/tests/unit/test_web_fetch.py',
  'kind': 'object',
  'line': 179,
  'raising': True,
  'receiver': 'wf'},
 {'anchor': ['test_fetch_post_redirect_to_private_hostname_rejected'],
  'attribute': 'getaddrinfo',
  'binding': 'socket',
  'call': "patch.object(wf.socket, 'getaddrinfo', side_effect=per_host)",
  'file': 'packages/cve_env/tests/unit/test_web_fetch.py',
  'kind': 'object',
  'line': 295,
  'raising': True,
  'receiver': 'wf'},
 {'anchor': ['test_payload_includes_reason_class_field'],
  'attribute': 'getaddrinfo',
  'binding': 'socket',
  'call': "patch.object(wf.socket, 'getaddrinfo', return_value=PUBLIC_ADDRINFO)",
  'file': 'packages/cve_env/tests/unit/test_web_fetch.py',
  'kind': 'object',
  'line': 360,
  'raising': True,
  'receiver': 'wf'},
 {'anchor': ['test_vet_hostname_unparseable_resolved_address_fails_closed'],
  'attribute': 'getaddrinfo',
  'binding': 'socket',
  'call': "patch.object(wf.socket, 'getaddrinfo', return_value=fake_infos)",
  'file': 'packages/cve_env/tests/unit/test_web_fetch.py',
  'kind': 'object',
  'line': 558,
  'raising': True,
  'receiver': 'wf'},
 {'anchor': ['test_setup_failure_removes_allocation'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(scratch.tempfile, 'mkdtemp', lambda **kw: str(allocated))",
  'file': 'core/run/tests/test_scratch_setup_failures.py',
  'kind': 'monkey',
  'line': 14,
  'raising': True,
  'receiver': 'scratch'},
 {'anchor': ['test_temp_text_failure_removes_partial_file'],
  'attribute': 'NamedTemporaryFile',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(scratch.tempfile, 'NamedTemporaryFile', Broken)",
  'file': 'core/run/tests/test_scratch_setup_failures.py',
  'kind': 'monkey',
  'line': 71,
  'raising': True,
  'receiver': 'scratch'},
 {'anchor': ['allocation'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(scratch.tempfile, 'mkdtemp', lambda **kw: str(path))",
  'file': 'core/run/tests/test_scratch_teardown.py',
  'kind': 'monkey',
  'line': 14,
  'raising': True,
  'receiver': 'scratch'},
 {'anchor': ['test_temp_unlink_cancellation_preserves_write_error'],
  'attribute': 'NamedTemporaryFile',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(scratch.tempfile, 'NamedTemporaryFile', lambda **kw: Broken())",
  'file': 'core/run/tests/test_scratch_teardown.py',
  'kind': 'monkey',
  'line': 63,
  'raising': True,
  'receiver': 'scratch'},
 {'anchor': ['test_failed_write_still_unlinks_when_close_fails'],
  'attribute': 'NamedTemporaryFile',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(scratch.tempfile, 'NamedTemporaryFile', lambda **kw: Broken())",
  'file': 'core/run/tests/test_scratch_teardown.py',
  'kind': 'monkey',
  'line': 163,
  'raising': True,
  'receiver': 'scratch'},
 {'anchor': ['test_failed_temp_allocation_has_no_cleanup_target'],
  'attribute': 'NamedTemporaryFile',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(scratch.tempfile, 'NamedTemporaryFile', fail_allocate)",
  'file': 'core/run/tests/test_scratch_teardown.py',
  'kind': 'monkey',
  'line': 181,
  'raising': True,
  'receiver': 'scratch'},
 {'anchor': ['TestScratchLifetime', '_run_interrupted'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(mod.tempfile, 'mkdtemp', recording_mkdtemp)",
  'factory_call': '_load_selftest()',
  'file': 'core/run/tests/test_selftest_scratch_lifetime.py',
  'kind': 'monkey',
  'line': 46,
  'raising': True,
  'receiver': 'mod'},
 {'anchor': ['test_stream_closes_owned_descriptor_and_scratch'],
  'attribute': 'NamedTemporaryFile',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(oracle.tempfile, 'NamedTemporaryFile', temporary)",
  'file': 'core/analysis/tests/test_binary_oracle_output.py',
  'kind': 'monkey',
  'line': 81,
  'raising': True,
  'receiver': 'oracle'},
 {'anchor': ['test_launch_failure_removes_labeled_artifacts_and_workdir'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(pv.tempfile, 'mkdtemp', lambda prefix='': str(owned))",
  'file': 'core/env/tests/test_provision.py',
  'kind': 'monkey',
  'line': 209,
  'raising': True,
  'receiver': 'pv'},
 {'anchor': ['test_validation_refusals_leave_no_workdir'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(pv.tempfile, 'mkdtemp', lambda prefix='': calls.append(prefix) or "
          "'/nonexistent')",
  'file': 'core/env/tests/test_provision.py',
  'kind': 'monkey',
  'line': 263,
  'raising': True,
  'receiver': 'pv'},
 {'anchor': ['test_teardown_removes_owned_workdir'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(pv.tempfile, 'mkdtemp', lambda prefix='': str(owned))",
  'file': 'core/env/tests/test_provision.py',
  'kind': 'monkey',
  'line': 273,
  'raising': True,
  'receiver': 'pv'},
 {'anchor': ['test_owned_workdir_keepalive_live_then_released_on_fail'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(pv.tempfile, 'mkdtemp', lambda prefix='': str(owned))",
  'file': 'core/env/tests/test_provision.py',
  'kind': 'monkey',
  'line': 301,
  'raising': True,
  'receiver': 'pv'},
 {'anchor': ['test_verify_plan_exception_tears_down_and_reraises'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(pv.tempfile, 'mkdtemp', lambda prefix='': str(owned))",
  'file': 'core/env/tests/test_provision.py',
  'kind': 'monkey',
  'line': 395,
  'raising': True,
  'receiver': 'pv'},
 {'anchor': ['provision_setup'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(pv.tempfile, 'mkdtemp', lambda **kwargs: str(resources.work))",
  'file': 'core/env/tests/test_teardown_isolation.py',
  'kind': 'monkey',
  'line': 117,
  'raising': True,
  'receiver': 'pv'},
 {'anchor': ['tracked_listeners'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "fault.setattr(server.tempfile, 'mkdtemp', directory)",
  'file': 'core/llm/dispatcher/tests/test_dispatcher_lifecycle_cleanup.py',
  'kind': 'monkey',
  'line': 50,
  'raising': True,
  'receiver': 'server'},
 {'anchor': ['test_early_allocation_failure_reclaims_directory_and_pin'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "fault.setattr(server.tempfile, 'mkdtemp', failed_compact)",
  'file': 'core/llm/dispatcher/tests/test_dispatcher_lifecycle_cleanup.py',
  'kind': 'monkey',
  'line': 195,
  'raising': True,
  'receiver': 'server'},
 {'anchor': ['staging_case'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(cco.tempfile, 'mkdtemp', allocate)",
  'file': 'core/container/tests/test_compose_staging_lifecycle.py',
  'kind': 'monkey',
  'line': 28,
  'raising': True,
  'receiver': 'cco'},
 {'anchor': ['test_staging_inside_source_is_refused_and_removed'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(cco.tempfile, 'mkdtemp', allocate)",
  'file': 'core/container/tests/test_compose_staging_lifecycle.py',
  'kind': 'monkey',
  'line': 195,
  'raising': True,
  'receiver': 'cco'},
 {'anchor': ['test_compose_setup_failure_cleans_tree'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(compose.tempfile, 'mkdtemp', lambda **kw: str(staging))",
  'delegate_module': 'core.run.scratch',
  'file': 'core/container/tests/test_setup_cleanup.py',
  'kind': 'monkey',
  'line': 21,
  'raising': True,
  'receiver': 'compose'},
 {'anchor': ['test_resolver_home_mkdir_failure_cleans_tree'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(compose.tempfile, 'mkdtemp', lambda **kw: str(scratch))",
  'delegate_module': 'core.run.scratch',
  'file': 'core/container/tests/test_setup_cleanup.py',
  'kind': 'monkey',
  'line': 51,
  'raising': True,
  'receiver': 'compose'},
 {'anchor': ['test_decompilation_write_failure_removes_directory'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(orchestrator.tempfile, 'mkdtemp', lambda **kw: str(allocated))",
  'file': 'core/audit/tests/test_temp_setup_cleanup.py',
  'kind': 'monkey',
  'line': 13,
  'raising': True,
  'receiver': 'orchestrator'},
 {'anchor': ['TestRunSmtSweepVacuityPolicy', '_patch_shim'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(sweep_mod.subprocess, 'run', lambda *a, **kw: _Proc())",
  'file': 'core/audit/tests/test_sweep.py',
  'kind': 'monkey',
  'line': 2211,
  'raising': True,
  'receiver': 'sweep_mod'},
 {'anchor': ['test_vocab_memo_hits_create_no_additional_rule_files'],
  'attribute': 'NamedTemporaryFile',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(renderer.tempfile, 'NamedTemporaryFile', forbidden)",
  'file': 'core/audit/tests/test_cocci_file_scope_memo.py',
  'kind': 'monkey',
  'line': 388,
  'raising': True,
  'receiver': 'renderer'},
 {'anchor': ['test_cold_materialization_failure_keeps_unmemoized_render_retry'],
  'attribute': 'NamedTemporaryFile',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(renderer.tempfile, 'NamedTemporaryFile', fail_first)",
  'file': 'core/audit/tests/test_cocci_file_scope_memo.py',
  'kind': 'monkey',
  'line': 412,
  'raising': True,
  'receiver': 'renderer'},
 {'anchor': ['test_vocab_checkpoint_replay_needs_no_temporary_rule'],
  'attribute': 'NamedTemporaryFile',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(renderer.tempfile, 'NamedTemporaryFile', forbidden)",
  'file': 'core/audit/tests/test_cocci_file_scope_memo.py',
  'kind': 'monkey',
  'line': 439,
  'raising': True,
  'receiver': 'renderer'},
 {'anchor': ['TestRuleCompatibilityDisplay', 'test_new_version_displays_use_existing_probe_cache'],
  'attribute': 'which',
  'binding': 'shutil',
  'call': "mock.patch.object(startup_init.shutil, 'which', return_value='/tools/codeql')",
  'file': 'core/startup/tests/test_check_tools.py',
  'kind': 'object',
  'line': 437,
  'raising': True,
  'receiver': 'startup_init'},
 {'anchor': ['test_busy_lock_skips_instead_of_writing_unlocked'],
  'attribute': 'stdin',
  'binding': 'sys',
  'call': "monkeypatch.setattr(hook.sys, 'stdin', "
          'io.TextIOWrapper(io.BytesIO(json.dumps(event()).encode())))',
  'file': 'core/startup/tests/test_session_title.py',
  'kind': 'monkey',
  'line': 150,
  'raising': True,
  'receiver': 'hook'},
 {'anchor': ['test_corrupt_state_cannot_be_replaced_as_a_fresh_automatic_session'],
  'attribute': 'stdin',
  'binding': 'sys',
  'call': "monkeypatch.setattr(hook.sys, 'stdin', "
          'io.TextIOWrapper(io.BytesIO(json.dumps(event()).encode())))',
  'file': 'core/startup/tests/test_session_title.py',
  'kind': 'monkey',
  'line': 218,
  'raising': True,
  'receiver': 'hook'},
 {'anchor': ['test_successful_hook_main_emits_only_native_title_json'],
  'attribute': 'stdin',
  'binding': 'sys',
  'call': "monkeypatch.setattr(hook.sys, 'stdin', "
          'io.TextIOWrapper(io.BytesIO(json.dumps(event()).encode())))',
  'file': 'core/startup/tests/test_session_title.py',
  'kind': 'monkey',
  'line': 255,
  'raising': True,
  'receiver': 'hook'},
 {'anchor': ['test_state_write_failure_is_nonfatal_and_can_retry'],
  'attribute': 'stdin',
  'binding': 'sys',
  'call': "patch.setattr(hook.sys, 'stdin', "
          'io.TextIOWrapper(io.BytesIO(json.dumps(event()).encode())))',
  'file': 'core/startup/tests/test_session_title.py',
  'kind': 'monkey',
  'line': 134,
  'raising': True,
  'receiver': 'hook'},
 {'anchor': ['test_failed_private_scratch_never_starts_worker'],
  'attribute': 'mkdtemp',
  'binding': 'tempfile',
  'call': "monkeypatch.setattr(isolate.tempfile, 'mkdtemp', fail)",
  'file': 'core/symbolic/tests/test_worker_sandbox_policy.py',
  'kind': 'monkey',
  'line': 81,
  'raising': True,
  'receiver': 'isolate'},
 {'anchor': ['test_stopped_status_does_not_complete_reaping'],
  'attribute': 'pidfd_send_signal',
  'binding': 'signal',
  'call': "monkeypatch.setattr(spawn.signal, 'pidfd_send_signal', Mock(), raising=False)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 65,
  'raising': False,
  'receiver': 'spawn'},
 {'anchor': ['test_pinned_process_gone_preserves_group_sweep_without_pid_fallback'],
  'attribute': 'pidfd_send_signal',
  'binding': 'signal',
  'call': "monkeypatch.setattr(spawn.signal, 'pidfd_send_signal', "
          "Mock(side_effect=ProcessLookupError(errno.ESRCH, 'gone')), raising=False)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 92,
  'raising': False,
  'receiver': 'spawn'},
 {'anchor': ['test_same_group_child_is_killed_after_pidfd_failure'],
  'attribute': 'pidfd_send_signal',
  'binding': 'signal',
  'call': "monkeypatch.setattr(spawn.signal, 'pidfd_send_signal', "
          "Mock(side_effect=PermissionError(errno.EPERM, 'blocked')), raising=False)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 24,
  'raising': False,
  'receiver': 'spawn'},
 {'anchor': ['test_signal_failure_falls_back_only_after_child_check'],
  'attribute': 'pidfd_send_signal',
  'binding': 'signal',
  'call': "monkeypatch.setattr(probe.signal, 'pidfd_send_signal', Mock(side_effect=error), "
          'raising=False)',
  'file': 'core/sandbox/tests/test_ptrace_pidfd_signal_fallback.py',
  'kind': 'monkey',
  'line': 27,
  'raising': False,
  'receiver': 'probe'},
 {'anchor': ['test_lost_or_terminal_child_is_not_signalled'],
  'attribute': 'pidfd_send_signal',
  'binding': 'signal',
  'call': "monkeypatch.setattr(probe.signal, 'pidfd_send_signal', "
          "Mock(side_effect=OSError(errno.ENOSYS, 'unsupported')), raising=False)",
  'file': 'core/sandbox/tests/test_ptrace_pidfd_signal_fallback.py',
  'kind': 'monkey',
  'line': 39,
  'raising': False,
  'receiver': 'probe'},
 {'anchor': ['test_pinned_process_gone_does_not_fall_back'],
  'attribute': 'pidfd_send_signal',
  'binding': 'signal',
  'call': "monkeypatch.setattr(probe.signal, 'pidfd_send_signal', "
          "Mock(side_effect=ProcessLookupError(errno.ESRCH, 'gone')), raising=False)",
  'file': 'core/sandbox/tests/test_ptrace_pidfd_signal_fallback.py',
  'kind': 'monkey',
  'line': 49,
  'raising': False,
  'receiver': 'probe'},
 {'anchor': ['test_interrupted_ownership_check_retries_before_signal'],
  'attribute': 'pidfd_send_signal',
  'binding': 'signal',
  'call': "monkeypatch.setattr(probe.signal, 'pidfd_send_signal', "
          "Mock(side_effect=OSError(errno.ENOSYS, 'unsupported')), raising=False)",
  'file': 'core/sandbox/tests/test_ptrace_pidfd_signal_fallback.py',
  'kind': 'monkey',
  'line': 97,
  'raising': False,
  'receiver': 'probe'},
 {'anchor': ['test_ownership_check_respects_cleanup_deadline'],
  'attribute': 'pidfd_send_signal',
  'binding': 'signal',
  'call': "monkeypatch.setattr(probe.signal, 'pidfd_send_signal', "
          "Mock(side_effect=OSError(errno.ENOSYS, 'unsupported')), raising=False)",
  'file': 'core/sandbox/tests/test_ptrace_pidfd_signal_fallback.py',
  'kind': 'monkey',
  'line': 107,
  'raising': False,
  'receiver': 'probe'},
 {'anchor': ['test_real_child_is_reaped_when_pidfd_signalling_is_blocked'],
  'attribute': 'pidfd_send_signal',
  'binding': 'signal',
  'call': "monkeypatch.setattr(probe.signal, 'pidfd_send_signal', sender, raising=False)",
  'file': 'core/sandbox/tests/test_ptrace_pidfd_signal_fallback.py',
  'kind': 'monkey',
  'line': 79,
  'raising': False,
  'receiver': 'probe'},
 {'anchor': ['test_pidfd_is_released_and_binds_cleanup_signal'],
  'attribute': 'pidfd_send_signal',
  'binding': 'signal',
  'call': "monkeypatch.setattr(probes.signal, 'pidfd_send_signal', lambda fd, sig: "
          'signals.append((fd, sig)), raising=False)',
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 243,
  'raising': False,
  'receiver': 'probes'},
 {'anchor': ['test_missing_pidfd_signal_api_uses_verified_pid_fallback'],
  'attribute': 'pidfd_send_signal',
  'binding': 'signal',
  'call': "monkeypatch.delattr(probes.signal, 'pidfd_send_signal', raising=False)",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'delete',
  'line': 277,
  'raising': False,
  'receiver': 'probes'},
 {'anchor': ['test_pidfd_is_used_and_closed'],
  'attribute': 'pidfd_send_signal',
  'binding': 'signal',
  'call': "monkeypatch.setattr(audit.signal, 'pidfd_send_signal', send, raising=False)",
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 99,
  'raising': False,
  'receiver': 'audit'},
 {'anchor': ['test_wedged_tracer_is_killed_not_awaited'],
  'attribute': 'executable',
  'binding': 'sys',
  'call': "monkeypatch.setattr(mod.sys, 'executable', str(wedge))",
  'file': 'core/sandbox/tests/test_landlock_audit_tracer_wedge.py',
  'kind': 'monkey',
  'line': 48,
  'raising': True,
  'receiver': 'mod'},
 {'anchor': ['fallback'],
  'attribute': 'run',
  'binding': 'subprocess',
  'call': "monkeypatch.setattr(context.subprocess, 'run', lambda cmd, **kwargs: "
          "subprocess.CompletedProcess(cmd, 0, '', ''))",
  'file': 'core/sandbox/tests/test_dns_egress_fallback.py',
  'kind': 'monkey',
  'line': 37,
  'raising': True,
  'receiver': 'context'},
 {'anchor': ['_drive_main_hermetic'],
  'attribute': 'stdin',
  'binding': 'sys',
  'call': "monkeypatch.setattr(_nc.sys, 'stdin', io.StringIO(json.dumps(request)))",
  'file': 'core/sandbox/tests/test_coordinator_rpc_validation.py',
  'kind': 'monkey',
  'line': 128,
  'raising': True,
  'receiver': '_nc'},
 {'anchor': ['_drive_main_hermetic'],
  'attribute': 'Thread',
  'binding': 'threading',
  'call': "monkeypatch.setattr(_nc.threading, 'Thread', FakeThread)",
  'file': 'core/sandbox/tests/test_coordinator_rpc_validation.py',
  'kind': 'monkey',
  'line': 129,
  'raising': True,
  'receiver': '_nc'},
 {'anchor': ['test_failed_signals_cannot_leave_an_unbounded_wait'],
  'attribute': 'waitid',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'waitid', Mock(return_value=None))",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 34,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_failed_signals_cannot_leave_an_unbounded_wait'],
  'attribute': 'getpgid',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'getpgid', lambda pid: 123)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 35,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_failed_signals_cannot_leave_an_unbounded_wait'],
  'attribute': 'getpgrp',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'getpgrp', lambda: 123)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 36,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_failed_signals_cannot_leave_an_unbounded_wait'],
  'attribute': 'pidfd_open',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'pidfd_open', Mock(side_effect=OSError(errno.EMFILE, "
          "'full')), raising=False)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 37,
  'raising': False,
  'receiver': 'spawn'},
 {'anchor': ['test_failed_signals_cannot_leave_an_unbounded_wait'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'kill', Mock(side_effect=PermissionError(errno.EPERM, "
          "'blocked')))",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 38,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_failed_signals_cannot_leave_an_unbounded_wait'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'waitpid', Mock(return_value=(0, 0)))",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 39,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_lost_ownership_during_fallback_prevents_numeric_signals'],
  'attribute': 'waitid',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'waitid', Mock(side_effect=[None, "
          "ChildProcessError(errno.ECHILD, 'lost')]))",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 49,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_lost_ownership_during_fallback_prevents_numeric_signals'],
  'attribute': 'getpgid',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'getpgid', lambda pid: 123)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 50,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_lost_ownership_during_fallback_prevents_numeric_signals'],
  'attribute': 'pidfd_open',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'pidfd_open', Mock(side_effect=OSError(errno.EMFILE, "
          "'full')), raising=False)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 51,
  'raising': False,
  'receiver': 'spawn'},
 {'anchor': ['test_lost_ownership_during_fallback_prevents_numeric_signals'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'kill', kill)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 53,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_lost_ownership_during_fallback_prevents_numeric_signals'],
  'attribute': 'killpg',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'killpg', killpg)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 54,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_stopped_status_does_not_complete_reaping'],
  'attribute': 'waitid',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'waitid', Mock(return_value=None))",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 61,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_stopped_status_does_not_complete_reaping'],
  'attribute': 'getpgid',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'getpgid', lambda pid: 123)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 62,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_stopped_status_does_not_complete_reaping'],
  'attribute': 'getpgrp',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'getpgrp', lambda: 123)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 63,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_stopped_status_does_not_complete_reaping'],
  'attribute': 'pidfd_open',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'pidfd_open', Mock(return_value=42), raising=False)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 64,
  'raising': False,
  'receiver': 'spawn'},
 {'anchor': ['test_stopped_status_does_not_complete_reaping'],
  'attribute': 'close',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'close', Mock())",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 66,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_stopped_status_does_not_complete_reaping'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'waitpid', wait)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 69,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_interrupted_ownership_check_retries'],
  'attribute': 'waitid',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'waitid', Mock(side_effect=[InterruptedError(), None, "
          'None]))',
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 76,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_interrupted_ownership_check_retries'],
  'attribute': 'getpgid',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'getpgid', lambda pid: 123)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 77,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_interrupted_ownership_check_retries'],
  'attribute': 'getpgrp',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'getpgrp', lambda: 123)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 78,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_interrupted_ownership_check_retries'],
  'attribute': 'pidfd_open',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'pidfd_open', Mock(side_effect=OSError(errno.EMFILE, "
          "'full')), raising=False)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 79,
  'raising': False,
  'receiver': 'spawn'},
 {'anchor': ['test_interrupted_ownership_check_retries'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'kill', killed)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 81,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_interrupted_ownership_check_retries'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'waitpid', Mock(return_value=(123, 0)))",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 82,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_pinned_process_gone_preserves_group_sweep_without_pid_fallback'],
  'attribute': 'waitid',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'waitid', Mock(return_value=None))",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 88,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_pinned_process_gone_preserves_group_sweep_without_pid_fallback'],
  'attribute': 'getpgid',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'getpgid', lambda pid: 456)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 89,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_pinned_process_gone_preserves_group_sweep_without_pid_fallback'],
  'attribute': 'getpgrp',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'getpgrp', lambda: 789)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 90,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_pinned_process_gone_preserves_group_sweep_without_pid_fallback'],
  'attribute': 'pidfd_open',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'pidfd_open', Mock(return_value=42), raising=False)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 91,
  'raising': False,
  'receiver': 'spawn'},
 {'anchor': ['test_pinned_process_gone_preserves_group_sweep_without_pid_fallback'],
  'attribute': 'close',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'close', Mock())",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 93,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_pinned_process_gone_preserves_group_sweep_without_pid_fallback'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'kill', killed)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 95,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_pinned_process_gone_preserves_group_sweep_without_pid_fallback'],
  'attribute': 'killpg',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'killpg', groups)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 96,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_pinned_process_gone_preserves_group_sweep_without_pid_fallback'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'waitpid', Mock(return_value=(123, 0)))",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 97,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_same_group_child_is_killed_after_pidfd_failure'],
  'attribute': 'pidfd_open',
  'binding': 'os',
  'call': "monkeypatch.setattr(spawn.os, 'pidfd_open', Mock(side_effect=OSError(errno.EMFILE, 'fd "
          "pressure')), raising=False)",
  'file': 'core/sandbox/tests/test_spawn_pidfd_fallback.py',
  'kind': 'monkey',
  'line': 22,
  'raising': False,
  'receiver': 'spawn'},
 {'anchor': ['calls'],
  'attribute': 'pidfd_open',
  'binding': 'os',
  'call': "monkeypatch.setattr(probe.os, 'pidfd_open', opened, raising=False)",
  'file': 'core/sandbox/tests/test_ptrace_pidfd_signal_fallback.py',
  'kind': 'monkey',
  'line': 17,
  'raising': False,
  'receiver': 'probe'},
 {'anchor': ['calls'],
  'attribute': 'close',
  'binding': 'os',
  'call': "monkeypatch.setattr(probe.os, 'close', closed)",
  'file': 'core/sandbox/tests/test_ptrace_pidfd_signal_fallback.py',
  'kind': 'monkey',
  'line': 18,
  'raising': True,
  'receiver': 'probe'},
 {'anchor': ['calls'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(probe.os, 'kill', killed)",
  'file': 'core/sandbox/tests/test_ptrace_pidfd_signal_fallback.py',
  'kind': 'monkey',
  'line': 19,
  'raising': True,
  'receiver': 'probe'},
 {'anchor': ['test_signal_failure_falls_back_only_after_child_check'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probe.os, 'waitpid', wait)",
  'file': 'core/sandbox/tests/test_ptrace_pidfd_signal_fallback.py',
  'kind': 'monkey',
  'line': 29,
  'raising': True,
  'receiver': 'probe'},
 {'anchor': ['test_lost_or_terminal_child_is_not_signalled'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probe.os, 'waitpid', wait)",
  'file': 'core/sandbox/tests/test_ptrace_pidfd_signal_fallback.py',
  'kind': 'monkey',
  'line': 41,
  'raising': True,
  'receiver': 'probe'},
 {'anchor': ['test_pinned_process_gone_does_not_fall_back'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probe.os, 'waitpid', Mock(return_value=(123, 0)))",
  'file': 'core/sandbox/tests/test_ptrace_pidfd_signal_fallback.py',
  'kind': 'monkey',
  'line': 50,
  'raising': True,
  'receiver': 'probe'},
 {'anchor': ['test_interrupted_ownership_check_retries_before_signal'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probe.os, 'waitpid', wait)",
  'file': 'core/sandbox/tests/test_ptrace_pidfd_signal_fallback.py',
  'kind': 'monkey',
  'line': 99,
  'raising': True,
  'receiver': 'probe'},
 {'anchor': ['test_ownership_check_respects_cleanup_deadline'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probe.os, 'waitpid', Mock(side_effect=InterruptedError()))",
  'file': 'core/sandbox/tests/test_ptrace_pidfd_signal_fallback.py',
  'kind': 'monkey',
  'line': 108,
  'raising': True,
  'receiver': 'probe'},
 {'anchor': ['synthetic_pid_never_opens_a_real_pidfd'],
  'attribute': 'pidfd_open',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'pidfd_open', open_pidfd, raising=False)",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 29,
  'raising': False,
  'receiver': 'probes'},
 {'anchor': ['test_terminal_status_is_collected_without_signalling'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'waitpid', lambda pid, options: (pid, status))",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 45,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_terminal_status_is_collected_without_signalling'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'kill', lambda *args: kills.append(args))",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 46,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_echild_is_unavailable_without_signalling'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'waitpid', reaped)",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 57,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_echild_is_unavailable_without_signalling'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'kill', lambda *args: kills.append(args))",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 58,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_timeout_kills_and_reaps_child'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'waitpid', wait)",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 73,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_timeout_kills_and_reaps_child'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'kill', lambda *args: killed.append(args))",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 74,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_cancellation_cleans_up_and_propagates'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'waitpid', wait)",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 94,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_cancellation_cleans_up_and_propagates'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'kill', lambda *args: killed.append(args))",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 95,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_cleanup_rechecks_terminal_status_hidden_by_cancellation'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'waitpid', wait)",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 116,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_cleanup_rechecks_terminal_status_hidden_by_cancellation'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'kill', lambda *args: kills.append(args))",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 117,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_wait_and_cleanup_have_separate_bounded_budgets'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'waitpid', lambda *args: (0, 0))",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 126,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_wait_and_cleanup_have_separate_bounded_budgets'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'kill', lambda *args: kills.append(args))",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 127,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_eintr_retries_cannot_extend_probe_deadline'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'waitpid', interrupted)",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 142,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_cleanup_does_not_signal_when_ownership_cannot_be_verified'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'waitpid', interrupted)",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 155,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_cleanup_does_not_signal_when_ownership_cannot_be_verified'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'kill', lambda *args: kills.append(args))",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 156,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_fork_failure_returns_unavailable'],
  'attribute': 'fork',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'fork', exhausted)",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 168,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_real_stalled_namespace_probe_is_killed_and_reaped'],
  'attribute': 'fork',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'fork', fork)",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 192,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_real_stalled_namespace_probe_is_killed_and_reaped'],
  'attribute': 'unshare',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'unshare', stalled_unshare)",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 193,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_cleanup_wait_errors_remain_visible'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'waitpid', wait)",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 222,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_cleanup_wait_errors_remain_visible'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'kill', lambda *args: kills.append(args))",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 223,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_pidfd_is_released_and_binds_cleanup_signal'],
  'attribute': 'pidfd_open',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'pidfd_open', lambda pid: read_fd)",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 241,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_pidfd_is_released_and_binds_cleanup_signal'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'waitpid', wait)",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 242,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_missing_pidfd_signal_api_uses_verified_pid_fallback'],
  'attribute': 'pidfd_open',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'pidfd_open', unusable_pidfd)",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 278,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_missing_pidfd_signal_api_uses_verified_pid_fallback'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'waitpid', wait)",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 279,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['test_missing_pidfd_signal_api_uses_verified_pid_fallback'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(probes.os, 'kill', lambda *args: kills.append(args))",
  'file': 'core/sandbox/tests/test_namespace_probe_lifecycle.py',
  'kind': 'monkey',
  'line': 280,
  'raising': True,
  'receiver': 'probes'},
 {'anchor': ['pid_fallback'],
  'attribute': 'pidfd_open',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'pidfd_open', Mock(side_effect=OSError(errno.ENOSYS, 'no "
          "pidfd')), raising=False)",
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 22,
  'raising': False,
  'receiver': 'audit'},
 {'anchor': ['test_invalid_pid_never_signals'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'kill', kill)",
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 31,
  'raising': True,
  'receiver': 'audit'},
 {'anchor': ['test_reaped_or_lost_child_is_not_signaled'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'waitpid', wait)",
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 47,
  'raising': True,
  'receiver': 'audit'},
 {'anchor': ['test_reaped_or_lost_child_is_not_signaled'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'kill', kill)",
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 48,
  'raising': True,
  'receiver': 'audit'},
 {'anchor': ['test_signal_race_still_collects_terminal_status'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'waitpid', wait)",
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 55,
  'raising': True,
  'receiver': 'audit'},
 {'anchor': ['test_signal_race_still_collects_terminal_status'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'kill', Mock(side_effect=ProcessLookupError()))",
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 56,
  'raising': True,
  'receiver': 'audit'},
 {'anchor': ['test_interrupted_ownership_check_retries_before_signaling'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'waitpid', wait)",
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 65,
  'raising': True,
  'receiver': 'audit'},
 {'anchor': ['test_interrupted_ownership_check_retries_before_signaling'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'kill', kill)",
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 66,
  'raising': True,
  'receiver': 'audit'},
 {'anchor': ['test_unreapable_child_stops_after_both_budgets'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'waitpid', wait)",
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 77,
  'raising': True,
  'receiver': 'audit'},
 {'anchor': ['test_unreapable_child_stops_after_both_budgets'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'kill', kill)",
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 78,
  'raising': True,
  'receiver': 'audit'},
 {'anchor': ['test_pidfd_is_used_and_closed'],
  'attribute': 'pidfd_open',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'pidfd_open', lambda pid: read_fd, raising=False)",
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 98,
  'raising': False,
  'receiver': 'audit'},
 {'anchor': ['test_pidfd_is_used_and_closed'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'waitpid', Mock(side_effect=KeyboardInterrupt() if cancel "
          'else [(0, 0), (PID, 0)]))',
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 100,
  'raising': True,
  'receiver': 'audit'},
 {'anchor': ['test_pidfd_is_used_and_closed'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'kill', Mock(side_effect=AssertionError('use pinned "
          "handle')))",
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 104,
  'raising': True,
  'receiver': 'audit'},
 {'anchor': ['test_repeated_interruptions_are_bounded_without_signaling'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'waitpid', Mock(side_effect=InterruptedError()))",
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 151,
  'raising': True,
  'receiver': 'audit'},
 {'anchor': ['test_repeated_interruptions_are_bounded_without_signaling'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'kill', kill)",
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 152,
  'raising': True,
  'receiver': 'audit'},
 {'anchor': ['test_stopped_child_is_not_mistaken_for_a_terminal_status'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'waitpid', Mock(side_effect=[(PID, stopped), (PID, 0)]))",
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 161,
  'raising': True,
  'receiver': 'audit'},
 {'anchor': ['test_stopped_child_is_not_mistaken_for_a_terminal_status'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'kill', kill)",
  'file': 'core/sandbox/tests/test_landlock_audit_reap.py',
  'kind': 'monkey',
  'line': 162,
  'raising': True,
  'receiver': 'audit'}]


@lru_cache(maxsize=None)
def _tree(file):
    return ast.parse((_REPO / file).read_text())


def _expected(row):
    node = copy.deepcopy(ast.parse(row["call"], mode="eval").body)
    owner = ast.parse(row["receiver"], mode="eval").body
    if row["kind"] == "delete":
        node.args[0] = ast.Call(func=ast.Name(id="patch_module_attribute", ctx=ast.Load()), args=[node.func.value, owner, ast.Constant(row["binding"]), ast.Constant("__name__"), ast.parse(row["receiver"] + "." + row["binding"] + ".__name__", mode="eval").body], keywords=[])
    elif row["kind"] == "qualified_string":
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
                    if row.get("factory_call"):
                        factory = ast.parse(row["factory_call"], mode="eval").body
                        assert any(isinstance(node, ast.Call) and ast.dump(node) == ast.dump(factory) for node in ast.walk(_tree(row["file"])))
                        namespace[name] = eval(compile(ast.Expression(factory), row["file"], "eval"), namespace)
                        continue
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
        if row["kind"] == "delete":
            inherited.setattr(getattr(primary, row["binding"]), row["attribute"], object(), raising=False)
        elif borrowed and not row.get("raising", True):
            inherited.delattr(getattr(primary, row["binding"]), row["attribute"], raising=False)
        raw = [(owner, dict(vars(owner))) for owner in owners]
        values = [os, subprocess, shutil, sys, tempfile, signal, socket, threading, time] + [getattr(owner, row["binding"]) for owner in owners]
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
                    if row["kind"] == "delete":
                        if isinstance(node.args[0], ast.Call):
                            node.func.value = ast.Name(id="_scope", ctx=ast.Load())
                            inner = node.args[0]
                            inner.args[0] = ast.Name(id="_scope", ctx=ast.Load())
                            inner.args[1] = ast.Name(id="_owner", ctx=ast.Load())
                            inner.args[-1] = ast.Attribute(value=ast.Attribute(value=ast.Name(id="_owner", ctx=ast.Load()), attr=row["binding"], ctx=ast.Load()), attr="__name__", ctx=ast.Load())
                            eval(compile(ast.fix_missing_locations(ast.Expression(node)), row["file"], "eval"), namespace)
                        else:
                            scope.delattr(getattr(owner, row["binding"]), row["attribute"], raising=row.get("raising", True))
                    elif getattr(node.func, "id", "") == "patch_module_attribute":
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
                            scope.setattr(target, row["attribute"], fake, raising=row.get("raising", True))
                        else:
                            contexts.enter_context(patch.object(target, row["attribute"], fake))
                    for shared, before in snapshots:
                        _assert_namespace(shared, before)
                    if row["kind"] == "delete":
                        assert not hasattr(getattr(owner, row["binding"]), row["attribute"])
                    else:
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


@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("present", [False, True])
@pytest.mark.parametrize("raising", [False, True])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_attribute_presence_policy_restores_binding(borrowed, present, raising, exit_mode):
    original = ModuleType("runtime_feature")
    sentinel, replacement = object(), object()
    if present:
        original.feature = sentinel
    view = ModuleType(original.__name__)
    vars(view).update(vars(original))
    owner = ModuleType("runtime_consumer")
    owner.runtime = view if borrowed else original
    before_binding = owner.runtime
    before = dict(vars(before_binding))
    caught = None
    try:
        with pytest.MonkeyPatch.context() as scope:
            if raising and not present:
                with pytest.raises(AttributeError):
                    patch_module_attribute(scope, owner, "runtime", "feature", replacement, raising=raising)
                assert owner.runtime is before_binding
            else:
                private = patch_module_attribute(scope, owner, "runtime", "feature", replacement, raising=raising)
                assert owner.runtime is private and private is not before_binding
                assert private.feature is replacement
                _assert_namespace(before_binding, before)
            if exit_mode != "normal":
                raise RuntimeError("feature exit") if exit_mode == "error" else KeyboardInterrupt("feature exit")
    except BaseException as error:
        caught = error
    assert owner.runtime is before_binding
    _assert_namespace(before_binding, before)
    if exit_mode == "normal":
        assert caught is None, repr(caught)
    else:
        assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)
        assert str(caught) == "feature exit"


@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_native_cleanup_fixture_denies_unmocked_launches(exit_mode):
    from core.container import containers, lifecycle
    import core.container.exec as container_exec

    owners = [containers, lifecycle]
    before = [(owner, dict(vars(owner))) for owner in owners + [container_exec]]
    fixture = _native("core/env/tests/test_provision.py")._owned_container_cleanup.__wrapped__
    caught = None
    try:
        with pytest.MonkeyPatch.context() as scope:
            fixture(scope)
            native = _native("core/env/tests/test_provision.py")
            assert containers.stop_container(native._CID, required_label=(native.pv.OWNER_LABEL, "fixture-owner"))
            with pytest.raises(AssertionError):
                containers.stop_container("unexpected-container", required_label=(native.pv.OWNER_LABEL, "fixture-owner"))
            for owner in owners:
                assert owner.run_cli(["docker", "stop", "owned-test-container"]).returncode == 0
                assert owner.run_cli(["docker", "network", "ls"]).returncode == 0
                for command in (["docker", "run", "image"], ["docker", "build", "."], ["docker", "network", "create", "unexpected"]):
                    with pytest.raises(AssertionError, match="unexpected unmocked container operation"):
                        owner.run_cli(command)
            if exit_mode != "normal":
                raise RuntimeError("cleanup fixture exit") if exit_mode == "error" else KeyboardInterrupt("cleanup fixture exit")
    except BaseException as error:
        caught = error
    for owner, snapshot in before:
        _assert_namespace(owner, snapshot)
    if exit_mode == "normal":
        assert caught is None, repr(caught)
    else:
        assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)
        assert str(caught) == "cleanup fixture exit"


@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_native_pack_fixture_owns_discovery_and_restores_caches(borrowed, exit_mode):
    from core.audit import codeql_query_resolver as resolver, orchestrator

    with pytest.MonkeyPatch.context() as inherited:
        if borrowed:
            inherited.setattr(resolver, "_PACK_INDEX_CACHE", {"codeql/cpp-queries": {"cpp/inherited": "/owned-fixture/Caller.ql"}})
            inherited.setattr(resolver, "_PACK_LOCKS", {"codeql/cpp-queries": threading.Lock()})
            inherited.setattr(orchestrator, "_CODEQL_UNSUPPORTED_IDS_LOGGED", {"cpp/inherited"})
        snapshots = [(owner, dict(vars(owner))) for owner in (resolver, orchestrator)]
        index, locks, logged = resolver._PACK_INDEX_CACHE, resolver._PACK_LOCKS, orchestrator._CODEQL_UNSUPPORTED_IDS_LOGGED
        values = copy.deepcopy(index), dict(locks), set(logged)
        fixture = _native("core/audit/tests/test_sweep.py")._owned_codeql_pack_discovery.__wrapped__
        generator = fixture()
        next(generator)
        caught = None
        try:
            assert resolver._pack_roots("codeql/cpp-queries") == []
            assert orchestrator._codeql_query_file("cpp/overflow-buffer") is None
            assert resolver._PACK_INDEX_CACHE == {"codeql/cpp-queries": None}
            assert resolver._PACK_LOCKS is not locks
            assert orchestrator._CODEQL_UNSUPPORTED_IDS_LOGGED is not logged
            if exit_mode == "normal":
                generator.close()
            else:
                generator.throw(RuntimeError("pack fixture exit") if exit_mode == "error" else KeyboardInterrupt("pack fixture exit"))
        except BaseException as error:
            caught = error
        finally:
            generator.close()
        for owner, snapshot in snapshots:
            _assert_namespace(owner, snapshot)
        assert index == values[0] and locks == values[1] and logged == values[2]
        if exit_mode == "normal":
            assert caught is None, repr(caught)
        else:
            assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)
            assert str(caught) == "pack fixture exit"
