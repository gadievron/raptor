"""Remaining module-interface mocks stay on actual native consumers and restore borrowed views."""
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
import platform
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest

from core.testing.module_bindings import mock_module_attribute, patch_module_attribute

_REPO = Path(__file__).resolve().parents[3]
_SITES = [{'file': 'core/binary/tests/test_elf_worker.py', 'line': 214, 'receiver': 'child', 'binding': 'sys', 'attribute': 'argv', 'kind': 'monkey', 'call': "monkeypatch.setattr(child.sys, 'argv', ['worker', 'fixture', '', '1024'])", 'anchor': ['test_dependency_failure_is_distinct_from_parser_failure'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, child, 'sys', 'argv', ['worker', 'fixture', '', '1024'])"}, {'file': 'core/binary/tests/test_elf_worker.py', 'line': 226, 'receiver': 'child', 'binding': 'sys', 'attribute': 'argv', 'kind': 'monkey', 'call': "monkeypatch.setattr(child.sys, 'argv', ['worker', 'fixture', '', '1024'])", 'anchor': ['test_parser_failure_does_not_claim_missing_dependency'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, child, 'sys', 'argv', ['worker', 'fixture', '', '1024'])"}, {'file': 'core/sandbox/tests/test_sandbox.py', 'line': 2907, 'receiver': 'observe', 'binding': 'sys', 'attribute': 'platform', 'kind': 'monkey', 'call': "monkeypatch.setattr(observe.sys, 'platform', platform)", 'anchor': ['test_eperm_is_not_misattributed_to_seccomp_on_darwin'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, observe, 'sys', 'platform', platform)"}, {'file': 'core/sandbox/tests/test_sandbox.py', 'line': 1865, 'receiver': 'probes', 'binding': 'subprocess', 'attribute': 'run', 'kind': 'object', 'call': "mock.patch.object(probes.subprocess, 'run', fake_run)", 'anchor': ['TestNetProbeLockDiscipline', 'test_probe_subprocess_runs_outside_cache_lock'], 'raising': True, 'expected': "mock_module_attribute(probes, 'subprocess', 'run', fake_run)"}, {'file': 'core/sandbox/tests/test_sandbox.py', 'line': 2669, 'receiver': 'seccomp_mod', 'binding': 'sys', 'attribute': 'platform', 'kind': 'object', 'call': "patch.object(seccomp_mod.sys, 'platform', 'linux')", 'anchor': ['TestSeccompFilterLostWarning', 'test_requested_profile_unavailable_warns_once'], 'raising': True, 'expected': "mock_module_attribute(seccomp_mod, 'sys', 'platform', 'linux')"}, {'file': 'core/sandbox/tests/test_sandbox.py', 'line': 2691, 'receiver': 'seccomp_mod', 'binding': 'sys', 'attribute': 'platform', 'kind': 'object', 'call': "patch.object(seccomp_mod.sys, 'platform', 'linux')", 'anchor': ['TestSeccompFilterLostWarning', 'test_no_profile_requested_stays_silent'], 'raising': True, 'expected': "mock_module_attribute(seccomp_mod, 'sys', 'platform', 'linux')"}, {'file': 'core/sandbox/tests/test_sandbox.py', 'line': 2706, 'receiver': 'seccomp_mod', 'binding': 'sys', 'attribute': 'platform', 'kind': 'object', 'call': "patch.object(seccomp_mod.sys, 'platform', 'darwin')", 'anchor': ['TestSeccompFilterLostWarning', 'test_darwin_does_not_probe_or_consume_linux_warning'], 'raising': True, 'expected': "mock_module_attribute(seccomp_mod, 'sys', 'platform', 'darwin')"}, {'file': 'core/audit/tests/test_dark_verify.py', 'line': 3562, 'receiver': 'ex', 'binding': 'subprocess', 'attribute': 'run', 'kind': 'monkey', 'call': "monkeypatch.setattr(ex.subprocess, 'run', _boom)", 'anchor': ['_forbid_bare_subprocess'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, ex, 'subprocess', 'run', _boom)"}, {'file': 'core/audit/tests/test_dark_verify.py', 'line': 2421, 'receiver': 'ex', 'binding': 'subprocess', 'attribute': 'run', 'kind': 'monkey', 'call': "monkeypatch.setattr(ex.subprocess, 'run', spy_run)", 'anchor': ['TestResolveRustc', 'test_sysroot_probe_uses_safe_env'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, ex, 'subprocess', 'run', spy_run)"}, {'file': 'core/audit/tests/test_compiler_sweep.py', 'line': 471, 'receiver': 'compiler_sweep', 'binding': 'subprocess', 'attribute': 'run', 'kind': 'monkey', 'call': "monkeypatch.setattr(compiler_sweep.subprocess, 'run', boom)", 'anchor': ['TestToolchainFallback', 'test_probe_is_cached'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, compiler_sweep, 'subprocess', 'run', boom)"}, {'file': 'core/forensics/tests/test_bq_query.py', 'line': 586, 'receiver': 'mod', 'binding': 'sys', 'attribute': 'stderr', 'kind': 'monkey', 'call': "monkeypatch.setattr(mod.sys, 'stderr', err)", 'anchor': ['TestEmptyOverridePolicyRefusal', 'test_empty_override_is_a_policy_error_not_a_sandbox_valueerror'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, mod, 'sys', 'stderr', err)"}, {'file': 'packages/binary_analysis/tests/test_crash_analyser_parsers.py', 'line': 204, 'call': "patch('packages.binary_analysis.crash_analyser.platform.system', return_value='Linux')", 'target': 'packages.binary_analysis.crash_analyser.platform.system', 'receiver': '_mock_consumer_platform', 'added_module': 'packages.binary_analysis.crash_analyser', 'binding': 'platform', 'attribute': 'system', 'kind': 'string', 'anchor': ['TestAslrEnabledStringConvention', '_layout_info'], 'raising': True, 'expected': "mock_module_attribute(_mock_consumer_platform, 'platform', 'system', return_value='Linux')"}, {'file': 'core/project/tests/test_create_archive_detection.py', 'line': 79, 'call': "patch('packages.describe.cli.tempfile.mkdtemp', tracking)", 'target': 'packages.describe.cli.tempfile.mkdtemp', 'receiver': '_mock_consumer_tempfile', 'added_module': 'packages.describe.cli', 'binding': 'tempfile', 'attribute': 'mkdtemp', 'kind': 'string', 'anchor': ['TestCreateArchiveDetection', 'test_tmp_extraction_cleaned_up'], 'raising': True, 'expected': "mock_module_attribute(_mock_consumer_tempfile, 'tempfile', 'mkdtemp', tracking)"}, {'file': 'packages/fuzzing/tests/test_orchestrator.py', 'line': 137, 'call': "patch('packages.fuzzing.target_detector.platform.system', return_value='Darwin')", 'target': 'packages.fuzzing.target_detector.platform.system', 'receiver': '_mock_consumer_platform', 'added_module': 'packages.fuzzing.target_detector', 'binding': 'platform', 'attribute': 'system', 'kind': 'string', 'anchor': ['TestOrchestratorPlanning', 'test_macos_with_broken_afl_does_not_run_plain_macho_as_libfuzzer'], 'raising': True, 'expected': "mock_module_attribute(_mock_consumer_platform, 'platform', 'system', return_value='Darwin')"}, {'file': 'packages/fuzzing/tests/test_orchestrator.py', 'line': 156, 'call': "patch('packages.fuzzing.target_detector.platform.system', return_value='Darwin')", 'target': 'packages.fuzzing.target_detector.platform.system', 'receiver': '_mock_consumer_platform', 'added_module': 'packages.fuzzing.target_detector', 'binding': 'platform', 'attribute': 'system', 'kind': 'string', 'anchor': ['TestOrchestratorPlanning', 'test_instrumented_unix_binary_can_use_libfuzzer'], 'raising': True, 'expected': "mock_module_attribute(_mock_consumer_platform, 'platform', 'system', return_value='Darwin')"}, {'file': 'packages/cve_diff/tests/unit/cli/test_main.py', 'line': 158, 'call': "monkeypatch.setattr('cve_diff.infra.disk_budget.shutil.disk_usage', lambda _path: SimpleNamespace(total=100 * gib, used=80 * gib, free=20 * gib))", 'target': 'cve_diff.infra.disk_budget.shutil.disk_usage', 'receiver': '_mock_consumer_shutil', 'added_module': 'cve_diff.infra.disk_budget', 'binding': 'shutil', 'attribute': 'disk_usage', 'kind': 'string_monkey', 'anchor': ['test_run_distinguishes_default_policy_from_explicit_limit'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'disk_usage', lambda _path: SimpleNamespace(total=100 * gib, used=80 * gib, free=20 * gib))"}, {'file': 'packages/cve_diff/tests/unit/test_llm_client.py', 'line': 160, 'call': "monkeypatch.setattr('cve_diff.llm.client.time.sleep', sleeps.append)", 'target': 'cve_diff.llm.client.time.sleep', 'receiver': '_mock_consumer_time', 'added_module': 'cve_diff.llm.client', 'binding': 'time', 'attribute': 'sleep', 'kind': 'string_monkey', 'anchor': ['test_non_retryable_error_fails_fast'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_time, 'time', 'sleep', sleeps.append)"}, {'file': 'packages/cve_diff/tests/unit/test_llm_client.py', 'line': 174, 'call': "monkeypatch.setattr('cve_diff.llm.client.time.sleep', sleeps.append)", 'target': 'cve_diff.llm.client.time.sleep', 'receiver': '_mock_consumer_time', 'added_module': 'cve_diff.llm.client', 'binding': 'time', 'attribute': 'sleep', 'kind': 'string_monkey', 'anchor': ['test_transient_error_retries_then_succeeds'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_time, 'time', 'sleep', sleeps.append)"}, {'file': 'packages/cve_diff/tests/unit/test_llm_client.py', 'line': 189, 'call': "monkeypatch.setattr('cve_diff.llm.client.time.sleep', lambda _s: None)", 'target': 'cve_diff.llm.client.time.sleep', 'receiver': '_mock_consumer_time', 'added_module': 'cve_diff.llm.client', 'binding': 'time', 'attribute': 'sleep', 'kind': 'string_monkey', 'anchor': ['test_transient_error_exhausts_retries'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_time, 'time', 'sleep', lambda _s: None)"}, {'file': 'packages/describe/tests/test_cli_archive.py', 'line': 166, 'call': "monkeypatch.setattr('packages.describe.cli.tempfile.mkdtemp', _tracking_mkdtemp)", 'target': 'packages.describe.cli.tempfile.mkdtemp', 'receiver': '_mock_consumer_tempfile', 'added_module': 'packages.describe.cli', 'binding': 'tempfile', 'attribute': 'mkdtemp', 'kind': 'string_monkey', 'anchor': ['TestArchiveHandling', 'test_temp_dir_cleaned_up_after_archive_describe'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_tempfile, 'tempfile', 'mkdtemp', _tracking_mkdtemp)"}, {'file': 'packages/describe/tests/test_cli_archive.py', 'line': 282, 'call': "monkeypatch.setattr('packages.describe.cli.tempfile.mkdtemp', _tracking_mkdtemp)", 'target': 'packages.describe.cli.tempfile.mkdtemp', 'receiver': '_mock_consumer_tempfile', 'added_module': 'packages.describe.cli', 'binding': 'tempfile', 'attribute': 'mkdtemp', 'kind': 'string_monkey', 'anchor': ['TestArchiveCacheHit', 'test_cache_hit_skips_extraction'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_tempfile, 'tempfile', 'mkdtemp', _tracking_mkdtemp)"}, {'file': 'core/sandbox/tests/test_host_rpc.py', 'line': 345, 'call': "patch('core.sandbox.host.os.write', side_effect=_dribble)", 'target': 'core.sandbox.host.os.write', 'receiver': '_mock_consumer_os', 'added_module': 'core.sandbox.host', 'binding': 'os', 'attribute': 'write', 'kind': 'string', 'anchor': ['TestWriteFrameCompletes', 'test_partial_os_write_still_delivers_full_frame'], 'raising': True, 'expected': "mock_module_attribute(_mock_consumer_os, 'os', 'write', side_effect=_dribble)"}, {'file': 'core/coverage/tests/test_reader_fd_discipline.py', 'line': 244, 'call': "monkeypatch.setattr('core.coverage.journal.os.fstat', lambda fd: _shrink(real_fstat(fd)))", 'target': 'core.coverage.journal.os.fstat', 'receiver': '_mock_consumer_os', 'added_module': 'core.coverage.journal', 'binding': 'os', 'attribute': 'fstat', 'kind': 'string_monkey', 'anchor': ['TestJournalReader', 'test_budget_holds_at_line_granularity'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_os, 'os', 'fstat', lambda fd: _shrink(real_fstat(fd)))"}, {'file': 'core/llm/tool_use/tests/test_openai_compat.py', 'line': 497, 'call': "monkeypatch.setattr('core.llm.providers.time.sleep', lambda _s: None)", 'target': 'core.llm.providers.time.sleep', 'receiver': '_mock_consumer_time', 'added_module': 'core.llm.providers', 'binding': 'time', 'attribute': 'sleep', 'kind': 'string_monkey', 'anchor': ['test_api_error_returns_error_stop_reason'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_time, 'time', 'sleep', lambda _s: None)"}, {'file': 'core/llm/tool_use/tests/test_openai_compat.py', 'line': 518, 'call': "monkeypatch.setattr('core.llm.providers.time.sleep', lambda _s: None)", 'target': 'core.llm.providers.time.sleep', 'receiver': '_mock_consumer_time', 'added_module': 'core.llm.providers', 'binding': 'time', 'attribute': 'sleep', 'kind': 'string_monkey', 'anchor': ['test_transient_then_recovers'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_time, 'time', 'sleep', lambda _s: None)"}, {'file': 'core/llm/tool_use/tests/test_openai_compat.py', 'line': 548, 'call': "monkeypatch.setattr('core.llm.providers.time.sleep', lambda _s: None)", 'target': 'core.llm.providers.time.sleep', 'receiver': '_mock_consumer_time', 'added_module': 'core.llm.providers', 'binding': 'time', 'attribute': 'sleep', 'kind': 'string_monkey', 'anchor': ['test_permanent_4xx_fails_fast'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_time, 'time', 'sleep', lambda _s: None)"}, {'file': 'core/llm/tool_use/tests/test_openai_compat.py', 'line': 675, 'call': "monkeypatch.setattr('core.llm.providers.time.sleep', lambda _s: None)", 'target': 'core.llm.providers.time.sleep', 'receiver': '_mock_consumer_time', 'added_module': 'core.llm.providers', 'binding': 'time', 'attribute': 'sleep', 'kind': 'string_monkey', 'anchor': ['test_turn_falls_back_to_synthesis_on_tool_unsupported'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_time, 'time', 'sleep', lambda _s: None)"}, {'file': 'core/llm/tool_use/tests/test_openai_compat.py', 'line': 713, 'call': "monkeypatch.setattr('core.llm.providers.time.sleep', lambda _s: None)", 'target': 'core.llm.providers.time.sleep', 'receiver': '_mock_consumer_time', 'added_module': 'core.llm.providers', 'binding': 'time', 'attribute': 'sleep', 'kind': 'string_monkey', 'anchor': ['test_turn_subsequent_calls_skip_native_when_unsupported'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_time, 'time', 'sleep', lambda _s: None)"}, {'file': 'core/llm/tool_use/tests/test_openai_compat.py', 'line': 768, 'call': "monkeypatch.setattr('core.llm.providers.time.sleep', lambda _s: None)", 'target': 'core.llm.providers.time.sleep', 'receiver': '_mock_consumer_time', 'added_module': 'core.llm.providers', 'binding': 'time', 'attribute': 'sleep', 'kind': 'string_monkey', 'anchor': ['test_turn_unrelated_4xx_does_not_flip_flag'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_time, 'time', 'sleep', lambda _s: None)"}, {'file': 'packages/web/tests/test_external_validators.py', 'line': 59, 'call': "monkeypatch.setattr('packages.web.external_validators.shutil.which', lambda _b: None)", 'target': 'packages.web.external_validators.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.external_validators', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_missing_binary_reports_unavailable'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _b: None)"}, {'file': 'packages/web/tests/test_external_validators.py', 'line': 77, 'call': "monkeypatch.setattr('packages.web.external_validators.shutil.which', lambda _b: '/usr/bin/nuclei')", 'target': 'packages.web.external_validators.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.external_validators', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_missing_pinned_templates_refuses_to_run'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _b: '/usr/bin/nuclei')"}, {'file': 'packages/web/tests/test_external_validators.py', 'line': 97, 'call': "monkeypatch.setattr('packages.web.external_validators.shutil.which', lambda _b: '/usr/bin/nuclei')", 'target': 'packages.web.external_validators.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.external_validators', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_batch_invocation_shape_and_scope'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _b: '/usr/bin/nuclei')"}, {'file': 'packages/web/tests/test_external_validators.py', 'line': 146, 'call': "monkeypatch.setattr('packages.web.external_validators.shutil.which', lambda _b: '/usr/bin/nuclei')", 'target': 'packages.web.external_validators.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.external_validators', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_loopback_target_skips_lna'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _b: '/usr/bin/nuclei')"}, {'file': 'packages/web/tests/test_external_validators.py', 'line': 175, 'call': "monkeypatch.setattr('packages.web.external_validators.shutil.which', lambda _b: '/usr/bin/nuclei')", 'target': 'packages.web.external_validators.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.external_validators', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_policy_denied_target_is_recorded_and_excluded'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _b: '/usr/bin/nuclei')"}, {'file': 'packages/web/tests/test_external_validators.py', 'line': 206, 'call': "monkeypatch.setattr('packages.web.external_validators.shutil.which', lambda _b: '/usr/bin/nuclei')", 'target': 'packages.web.external_validators.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.external_validators', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_credential_headers_ride_a_private_file_not_argv'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _b: '/usr/bin/nuclei')"}, {'file': 'packages/web/tests/test_external_validators.py', 'line': 236, 'call': "monkeypatch.setattr('packages.web.external_validators.shutil.which', lambda _b: '/usr/bin/nuclei')", 'target': 'packages.web.external_validators.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.external_validators', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_jsonl_matches_attributed_per_target'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _b: '/usr/bin/nuclei')"}, {'file': 'packages/web/tests/test_external_validators.py', 'line': 281, 'call': "monkeypatch.setattr('packages.web.external_validators.shutil.which', lambda _b: '/usr/bin/nuclei')", 'target': 'packages.web.external_validators.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.external_validators', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_backstop_timeout_keeps_partial_output'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _b: '/usr/bin/nuclei')"}, {'file': 'packages/web/tests/test_external_validators.py', 'line': 321, 'call': "monkeypatch.setattr('packages.web.external_validators.shutil.which', lambda _b: '/usr/bin/nuclei')", 'target': 'packages.web.external_validators.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.external_validators', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_denied_target_yields_one_row_across_many_findings'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _b: '/usr/bin/nuclei')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 260, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_redacts_body_in_logs'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 722, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_grants_file_granular_read_scope_to_wordlists'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 764, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_resolves_symlinked_wordlists_for_argv_and_scope'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 839, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_warns_when_wordlist_symlink_escapes_its_directory'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 1175, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_removes_stale_report_before_spawning'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 1203, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_refuses_to_parse_oversized_report'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 1235, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_scrubs_ffuf_config_block_from_kept_report'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 1275, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_keeps_report_config_block_with_reveal_secrets'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 1301, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_redacts_ffuf_banner_values_in_stderr'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 1545, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_delivers_credentials_via_config_file_not_argv'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 1592, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_refuses_preplanted_symlink_at_config_path'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 1635, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_keeps_config_file_only_with_reveal_secrets'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 1658, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_removes_config_file_on_backstop_timeout'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 1677, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_grants_grace_beyond_ffuf_maxtime'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 1710, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_survives_backstop_timeout_and_keeps_partial_results'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 1739, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_warns_once_on_extreme_thread_counts'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 1823, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_redacts_authenticated_ffuf_options_from_logs'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 1881, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: None)", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_requires_explicit_ffuf_binary'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: None)"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 1892, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_uses_subprocess_argv_and_summarizes_json'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 1955, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_limits_embedded_report_results_but_keeps_raw_count'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 2126, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: str(link))", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_execs_realpath_and_binds_resolved_tool_dir'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: str(link))"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 2157, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _binary: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_refuses_oversize_results_file'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _binary: '/usr/bin/ffuf')"}, {'file': 'packages/web/tests/test_ffuf.py', 'line': 2300, 'call': "monkeypatch.setattr('packages.web.ffuf.shutil.which', lambda _b: '/usr/bin/ffuf')", 'target': 'packages.web.ffuf.shutil.which', 'receiver': '_mock_consumer_shutil', 'added_module': 'packages.web.ffuf', 'binding': 'shutil', 'attribute': 'which', 'kind': 'string_monkey', 'anchor': ['test_run_grants_read_scope_to_request_file'], 'raising': True, 'expected': "patch_module_attribute(monkeypatch, _mock_consumer_shutil, 'shutil', 'which', lambda _b: '/usr/bin/ffuf')"}]


@lru_cache(maxsize=None)
def _tree(file):
    return ast.parse((_REPO / file).read_text())


def _expected(row):
    return ast.parse(row["expected"], mode="eval").body


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
    active = _node(index)
    transformed = getattr(active.func, "id", "") in {"patch_module_attribute", "mock_module_attribute"}
    expression = row["receiver"] if transformed else row.get("original_receiver", row["receiver"])
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
                    if not aliases and row["file"] == "core/forensics/tests/test_bq_query.py" and name == "mod":
                        function = next(node for node in ast.walk(_tree(row["file"])) if isinstance(node, ast.FunctionDef) and node.name == row["anchor"][-1])
                        with pytest.MonkeyPatch.context() as loading:
                            namespace["monkeypatch"] = loading
                            for statement in function.body:
                                exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(statement)], type_ignores=[])), row["file"], "exec"), namespace)
                                candidate = namespace.get(name)
                                if isinstance(candidate, ModuleType) and hasattr(candidate, row["binding"]):
                                    break
                        assert isinstance(namespace.get(name), ModuleType) and hasattr(namespace[name], row["binding"])
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
        values = [os, subprocess, shutil, sys, tempfile, signal, socket, threading, time, platform] + [getattr(owner, row["binding"]) for owner in owners]
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
                        target = getattr(owner, row["binding"])
                        if row["kind"] in ("monkey", "string_monkey"):
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
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_compiler_chain_fixture_restores_query_resolver(borrowed, exit_mode):
    from core.audit import orchestrator

    native = _native("core/audit/tests/test_compiler_sweep.py")
    original = orchestrator._resolved_codeql_query
    with pytest.MonkeyPatch.context() as inherited:
        token = lambda query: "inherited.ql"
        if borrowed:
            inherited.setattr(orchestrator, "_resolved_codeql_query", token)
        before = orchestrator._resolved_codeql_query
        fixture = getattr(native.TestIntegration, "_no_incidental_codeql_resolution", None)
        assert fixture is not None
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope:
                fixture.__wrapped__(native.TestIntegration(), scope)
                assert orchestrator._resolved_codeql_query("cpp/use-after-free") is None
                if exit_mode != "normal":
                    raise RuntimeError("compiler fixture exit") if exit_mode == "error" else KeyboardInterrupt("compiler fixture exit")
        except BaseException as error:
            caught = error
        assert orchestrator._resolved_codeql_query is before
        if exit_mode == "normal":
            assert caught is None
        else:
            assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt)
            assert str(caught) == "compiler fixture exit"
    assert orchestrator._resolved_codeql_query is original


def test_native_macho_planning_avoids_incidental_binary_inspection():
    from packages.fuzzing import orchestrator

    native = _native("packages/fuzzing/tests/test_orchestrator.py")
    with pytest.MonkeyPatch.context() as scope:
        def refuse(*args, **kwargs):
            pytest.fail("planning fixture attempted binary inspection")
        scope.setattr(orchestrator, "_inspect_binary", refuse)
        native.TestOrchestratorPlanning().test_macos_with_broken_afl_does_not_run_plain_macho_as_libfuzzer()
