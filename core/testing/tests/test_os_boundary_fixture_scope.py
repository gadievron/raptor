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
_SITES = [{'anchor': ['summary_io'],
 'attribute': 'replace',
 'binding': 'os',
 'call': "monkeypatch.setattr(os, 'replace', io.replace)",
 'file': 'core/sandbox/tests/test_summary_exception_formatting.py',
 'kind': 'monkey',
 'line': 84,
 'raising': True,
 'receiver': 'summary',
 'original_receiver': 'os'},
 {'anchor': ['summary_io'],
 'attribute': 'open',
 'binding': 'os',
 'call': "monkeypatch.setattr(os, 'open', io.open)",
 'file': 'core/sandbox/tests/test_summary_exception_formatting.py',
 'kind': 'monkey',
 'line': 85,
 'raising': True,
 'receiver': 'summary',
 'original_receiver': 'os'},
 {'anchor': ['summary_io'],
 'attribute': 'read',
 'binding': 'os',
 'call': "monkeypatch.setattr(os, 'read', io.read)",
 'file': 'core/sandbox/tests/test_summary_exception_formatting.py',
 'kind': 'monkey',
 'line': 86,
 'raising': True,
 'receiver': 'summary',
 'original_receiver': 'os'},
 {'anchor': ['summary_io'],
 'attribute': 'close',
 'binding': 'os',
 'call': "monkeypatch.setattr(os, 'close', io.close)",
 'file': 'core/sandbox/tests/test_summary_exception_formatting.py',
 'kind': 'monkey',
 'line': 87,
 'raising': True,
 'receiver': 'summary',
 'original_receiver': 'os'},
 {'anchor': ['native_faults'],
 'attribute': 'open',
 'binding': 'os',
 'call': "monkeypatch.setattr(os, 'open', faults.open)",
 'file': 'core/sandbox/tests/test_persistence_exception_formatting.py',
 'kind': 'monkey',
 'line': 49,
 'raising': True,
 'receiver': 'context',
 'original_receiver': 'os'},
 {'anchor': ['native_faults'],
 'attribute': 'write',
 'binding': 'os',
 'call': "monkeypatch.setattr(os, 'write', faults.write)",
 'file': 'core/sandbox/tests/test_persistence_exception_formatting.py',
 'kind': 'monkey',
 'line': 50,
 'raising': True,
 'receiver': 'evidence',
 'original_receiver': 'os'},
 {'anchor': ['native_faults'],
 'attribute': 'lseek',
 'binding': 'os',
 'call': "monkeypatch.setattr(os, 'lseek', faults.lseek)",
 'file': 'core/sandbox/tests/test_persistence_exception_formatting.py',
 'kind': 'monkey',
 'line': 51,
 'raising': True,
 'receiver': 'evidence',
 'original_receiver': 'os'},
 {'anchor': ['native_faults'],
 'attribute': 'close',
 'binding': 'os',
 'call': "monkeypatch.setattr(os, 'close', faults.close)",
 'file': 'core/sandbox/tests/test_persistence_exception_formatting.py',
 'kind': 'monkey',
 'line': 52,
 'raising': True,
 'receiver': 'evidence',
 'original_receiver': 'os'},
 {'anchor': ['resources'],
 'attribute': 'open',
 'binding': 'os',
 'call': "monkeypatch.setattr(os, 'open', owner.open)",
 'file': 'core/sandbox/tests/test_fake_home_intake_bounds.py',
 'kind': 'monkey',
 'line': 97,
 'raising': True,
 'receiver': 'context',
 'original_receiver': 'os'},
 {'anchor': ['resources'],
 'attribute': 'close',
 'binding': 'os',
 'call': "monkeypatch.setattr(os, 'close', owner.close)",
 'file': 'core/sandbox/tests/test_fake_home_intake_bounds.py',
 'kind': 'monkey',
 'line': 98,
 'raising': True,
 'receiver': 'context',
 'original_receiver': 'os'},
 {'anchor': ['resources'],
 'attribute': 'scandir',
 'binding': 'os',
 'call': "monkeypatch.setattr(os, 'scandir', owner.scan)",
 'file': 'core/sandbox/tests/test_fake_home_intake_bounds.py',
 'kind': 'monkey',
 'line': 99,
 'raising': True,
 'receiver': 'context',
 'original_receiver': 'os'},
 {'anchor': ['intake_ops'],
  'attribute': 'open',
  'binding': 'os',
  'call': "monkeypatch.setattr(os, 'open', ops.open)",
  'file': 'core/sandbox/tests/test_fake_home_intake_cleanup.py',
  'kind': 'monkey',
  'line': 67,
  'raising': True,
  'receiver': 'context',
  'original_receiver': 'os'},
 {'anchor': ['intake_ops'],
  'attribute': 'read',
  'binding': 'os',
  'call': "monkeypatch.setattr(os, 'read', ops.read)",
  'file': 'core/sandbox/tests/test_fake_home_intake_cleanup.py',
  'kind': 'monkey',
  'line': 68,
  'raising': True,
  'receiver': 'context',
  'original_receiver': 'os'},
 {'anchor': ['intake_ops'],
  'attribute': 'close',
  'binding': 'os',
  'call': "monkeypatch.setattr(os, 'close', ops.close)",
  'file': 'core/sandbox/tests/test_fake_home_intake_cleanup.py',
  'kind': 'monkey',
  'line': 69,
  'raising': True,
  'receiver': 'context',
  'original_receiver': 'os'},
 {'anchor': ['TestBinaryDominant', 'test_fifo_refused_before_open'],
  'attribute': 'open',
  'binding': 'os',
  'call': "monkeypatch.setattr(tt.os, 'open', spy)",
  'file': 'core/run/target_types/tests/test_target_types.py',
  'kind': 'monkey',
  'line': 546,
  'raising': True,
  'receiver': 'tt'},
 {'anchor': ['TestFindClaudeAncestor', '_patch_tree'],
  'attribute': 'getpid',
  'binding': 'os',
  'call': "mock.patch.object(md.os, 'getpid', lambda: self_pid)",
  'file': 'core/run/tests/test_metadata.py',
  'kind': 'object',
  'line': 351,
  'raising': True,
  'receiver': 'md'},
 {'anchor': ['TestFindClaudeAncestor', '_patch_tree'],
  'attribute': 'getppid',
  'binding': 'os',
  'call': "mock.patch.object(md.os, 'getppid', lambda: parents[self_pid])",
  'file': 'core/run/tests/test_metadata.py',
  'kind': 'object',
  'line': 353,
  'raising': True,
  'receiver': 'md'},
 {'anchor': ['test_invalid_inode_threshold_keeps_default_pressure_warning'],
  'attribute': 'statvfs',
  'binding': 'os',
  'call': "monkeypatch.setattr(scratch.os, 'statvfs', lambda path: SimpleNamespace(f_files=100, "
          'f_ffree=free))',
  'file': 'core/run/tests/test_retention_inputs.py',
  'kind': 'monkey',
  'line': 122,
  'raising': True,
  'receiver': 'scratch'},
 {'anchor': ['TestInodeCeilingAdvisory', 'test_below_ceiling_is_silent'],
  'attribute': 'statvfs',
  'binding': 'os',
  'call': "monkeypatch.setattr(scratch_mod.os, 'statvfs', self._statvfs(1000, 500))",
  'file': 'core/run/tests/test_scratch.py',
  'kind': 'monkey',
  'line': 380,
  'raising': True,
  'receiver': 'scratch_mod'},
 {'anchor': ['TestInodeCeilingAdvisory', 'test_past_ceiling_warns_loudly_once'],
  'attribute': 'statvfs',
  'binding': 'os',
  'call': "monkeypatch.setattr(scratch_mod.os, 'statvfs', self._statvfs(1000, 50))",
  'file': 'core/run/tests/test_scratch.py',
  'kind': 'monkey',
  'line': 390,
  'raising': True,
  'receiver': 'scratch_mod'},
 {'anchor': ['TestInodeCeilingAdvisory', 'test_env_moves_the_ceiling'],
  'attribute': 'statvfs',
  'binding': 'os',
  'call': "monkeypatch.setattr(scratch_mod.os, 'statvfs', self._statvfs(1000, 500))",
  'file': 'core/run/tests/test_scratch.py',
  'kind': 'monkey',
  'line': 401,
  'raising': True,
  'receiver': 'scratch_mod'},
 {'anchor': ['TestInodeCeilingAdvisory', 'test_env_zero_disables'],
  'attribute': 'statvfs',
  'binding': 'os',
  'call': "monkeypatch.setattr(scratch_mod.os, 'statvfs', self._statvfs(1000, 0))",
  'file': 'core/run/tests/test_scratch.py',
  'kind': 'monkey',
  'line': 410,
  'raising': True,
  'receiver': 'scratch_mod'},
 {'anchor': ['TestInodeCeilingAdvisory', 'test_non_numeric_env_keeps_default'],
  'attribute': 'statvfs',
  'binding': 'os',
  'call': "monkeypatch.setattr(scratch_mod.os, 'statvfs', self._statvfs(1000, 20))",
  'file': 'core/run/tests/test_scratch.py',
  'kind': 'monkey',
  'line': 421,
  'raising': True,
  'receiver': 'scratch_mod'},
 {'anchor': ['TestInodeCeilingAdvisory', 'test_no_inode_accounting_is_silent'],
  'attribute': 'statvfs',
  'binding': 'os',
  'call': "monkeypatch.setattr(scratch_mod.os, 'statvfs', self._statvfs(0, 0))",
  'file': 'core/run/tests/test_scratch.py',
  'kind': 'monkey',
  'line': 432,
  'raising': True,
  'receiver': 'scratch_mod'},
 {'anchor': ['TestInodeCeilingAdvisory', 'test_statvfs_failure_never_breaks_lane_creation'],
  'attribute': 'statvfs',
  'binding': 'os',
  'call': "monkeypatch.setattr(scratch_mod.os, 'statvfs', _boom)",
  'file': 'core/run/tests/test_scratch.py',
  'kind': 'monkey',
  'line': 446,
  'raising': True,
  'receiver': 'scratch_mod'},
 {'anchor': ['TestInodeCeilingAdvisory', 'test_run_output_shape_not_probed'],
  'attribute': 'statvfs',
  'binding': 'os',
  'call': "monkeypatch.setattr(scratch_mod.os, 'statvfs', self._statvfs(1000, 0))",
  'file': 'core/run/tests/test_scratch.py',
  'kind': 'monkey',
  'line': 456,
  'raising': True,
  'receiver': 'scratch_mod'},
 {'anchor': ['TestDeadPidDirReaping', 'test_foreign_owner_kept'],
  'attribute': 'geteuid',
  'binding': 'os',
  'call': "monkeypatch.setattr(tmp_reaper.os, 'geteuid', lambda: os.getuid() + 1)",
  'file': 'core/run/tests/test_tmp_reaper.py',
  'kind': 'monkey',
  'line': 1009,
  'raising': True,
  'receiver': 'tmp_reaper'},
 {'anchor': ['TestDeadPidDirReaping', 'test_never_raises'],
  'attribute': 'listdir',
  'binding': 'os',
  'call': "monkeypatch.setattr(tmp_reaper.os, 'listdir', _boom)",
  'file': 'core/run/tests/test_tmp_reaper.py',
  'kind': 'monkey',
  'line': 1022,
  'raising': True,
  'receiver': 'tmp_reaper'},
 {'anchor': ['TestMultiRootSweep', 'test_foreign_owned_root_stray_kept'],
  'attribute': 'geteuid',
  'binding': 'os',
  'call': "monkeypatch.setattr(reaper_mod.os, 'geteuid', lambda: os.getuid() + 1)",
  'file': 'core/run/tests/test_tmp_reaper.py',
  'kind': 'monkey',
  'line': 1092,
  'raising': True,
  'receiver': 'reaper_mod'},
 {'anchor': ['TestPidFileReaping', 'test_pid_one_pair_kept_without_probing'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(reaper_mod.os, 'kill', recording_kill)",
  'file': 'core/run/tests/test_tmp_reaper.py',
  'kind': 'monkey',
  'line': 1334,
  'raising': True,
  'receiver': 'reaper_mod'},
 {'anchor': ['TestUnverifiableOwnerDirs', 'test_no_kill_call_ever_probes_pid_one'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(reaper_mod.os, 'kill', recording_kill)",
  'file': 'core/run/tests/test_tmp_reaper.py',
  'kind': 'monkey',
  'line': 1443,
  'raising': True,
  'receiver': 'reaper_mod'},
 {'anchor': ['TestUnverifiableOwnerDirs', 'test_eperm_owner_age_governed'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(reaper_mod.os, 'kill', eperm_kill)",
  'file': 'core/run/tests/test_tmp_reaper.py',
  'kind': 'monkey',
  'line': 1464,
  'raising': True,
  'receiver': 'reaper_mod'},
 {'anchor': ['TestUnverifiableOwnerDirs', 'test_foreign_owned_dirs_skipped_quietly'],
  'attribute': 'geteuid',
  'binding': 'os',
  'call': "monkeypatch.setattr(reaper_mod.os, 'geteuid', lambda: os.getuid() + 1)",
  'file': 'core/run/tests/test_tmp_reaper.py',
  'kind': 'monkey',
  'line': 1484,
  'raising': True,
  'receiver': 'reaper_mod'},
 {'anchor': ['TestMidSweepVanish', 'test_vanish_after_classification_not_reported_sweep_continues'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(reaper_mod.os, 'kill', vanishing_kill)",
  'file': 'core/run/tests/test_tmp_reaper.py',
  'kind': 'monkey',
  'line': 1560,
  'raising': True,
  'receiver': 'reaper_mod'},
 {'anchor': ['TestPidNamespaceRefusal', 'test_live_owner_looks_dead_from_child_ns_dir_survives'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(reaper_mod.os, 'kill', ns_blind_kill)",
  'file': 'core/run/tests/test_tmp_reaper.py',
  'kind': 'monkey',
  'line': 1677,
  'raising': True,
  'receiver': 'reaper_mod'},
  {'anchor': ['test_unreadable_metadata_identity_is_retained'],
  'attribute': 'lstat',
  'binding': 'os',
  'call': "monkeypatch.setattr(workdir.os, 'lstat', unavailable)",
  'file': 'core/run/tests/test_workdir.py',
  'kind': 'monkey',
  'line': 325,
  'raising': True,
  'receiver': 'workdir'},
  {'anchor': ['TestReadyBudget', 'test_spawn_time_sampling_feeds_the_derater'],
  'attribute': 'sched_getaffinity',
  'binding': 'os',
  'call': "monkeypatch.setattr(usage_scan_jail.os, 'sched_getaffinity', lambda pid: {0, 1, 2, 3}, "
          'raising=False)',
  'file': 'core/llm/dispatcher/tests/test_usage_scan_jail.py',
  'kind': 'monkey',
  'line': 944,
  'raising': False,
  'receiver': 'usage_scan_jail'},
 {'anchor': ['TestReadyBudget', 'test_spawn_time_sampling_feeds_the_derater'],
  'attribute': 'getloadavg',
  'binding': 'os',
  'call': "monkeypatch.setattr(usage_scan_jail.os, 'getloadavg', lambda: (64.0, 0.0, 0.0))",
  'file': 'core/llm/dispatcher/tests/test_usage_scan_jail.py',
  'kind': 'monkey',
  'line': 947,
  'raising': True,
  'receiver': 'usage_scan_jail'},
 {'anchor': ['TestReadyBudget', 'test_unknowable_load_falls_back_to_the_floor'],
  'attribute': 'getloadavg',
  'binding': 'os',
  'call': "monkeypatch.setattr(usage_scan_jail.os, 'getloadavg', _no_load)",
  'file': 'core/llm/dispatcher/tests/test_usage_scan_jail.py',
  'kind': 'monkey',
  'line': 963,
  'raising': True,
  'receiver': 'usage_scan_jail'},
 {'anchor': ['TestReadyBudget', 'test_missing_loadavg_symbol_falls_back_to_the_floor'],
  'attribute': 'getloadavg',
  'binding': 'os',
  'call': "monkeypatch.delattr(usage_scan_jail.os, 'getloadavg')",
  'file': 'core/llm/dispatcher/tests/test_usage_scan_jail.py',
  'kind': 'delete',
  'line': 973,
  'raising': True,
  'receiver': 'usage_scan_jail'},
 {'anchor': ['TestReadyBudget', 'test_unknowable_cpus_under_high_load_gets_the_floor'],
  'attribute': 'sched_getaffinity',
  'binding': 'os',
  'call': "monkeypatch.setattr(usage_scan_jail.os, 'sched_getaffinity', _no_affinity, "
          'raising=False)',
  'file': 'core/llm/dispatcher/tests/test_usage_scan_jail.py',
  'kind': 'monkey',
  'line': 989,
  'raising': False,
  'receiver': 'usage_scan_jail'},
 {'anchor': ['TestReadyBudget', 'test_unknowable_cpus_under_high_load_gets_the_floor'],
  'attribute': 'cpu_count',
  'binding': 'os',
  'call': "monkeypatch.setattr(usage_scan_jail.os, 'cpu_count', lambda: None)",
  'file': 'core/llm/dispatcher/tests/test_usage_scan_jail.py',
  'kind': 'monkey',
  'line': 991,
  'raising': True,
  'receiver': 'usage_scan_jail'},
 {'anchor': ['TestReadyBudget', 'test_unknowable_cpus_under_high_load_gets_the_floor'],
  'attribute': 'getloadavg',
  'binding': 'os',
  'call': "monkeypatch.setattr(usage_scan_jail.os, 'getloadavg', lambda: (4096.0, 0.0, 0.0))",
  'file': 'core/llm/dispatcher/tests/test_usage_scan_jail.py',
  'kind': 'monkey',
  'line': 992,
  'raising': True,
  'receiver': 'usage_scan_jail'},
 {'anchor': ['TestReadyBudget', 'test_affinity_unknowable_still_derates_via_cpu_count'],
  'attribute': 'sched_getaffinity',
  'binding': 'os',
  'call': "monkeypatch.setattr(usage_scan_jail.os, 'sched_getaffinity', _no_affinity, "
          'raising=False)',
  'file': 'core/llm/dispatcher/tests/test_usage_scan_jail.py',
  'kind': 'monkey',
  'line': 1007,
  'raising': False,
  'receiver': 'usage_scan_jail'},
 {'anchor': ['TestReadyBudget', 'test_affinity_unknowable_still_derates_via_cpu_count'],
  'attribute': 'cpu_count',
  'binding': 'os',
  'call': "monkeypatch.setattr(usage_scan_jail.os, 'cpu_count', lambda: 4)",
  'file': 'core/llm/dispatcher/tests/test_usage_scan_jail.py',
  'kind': 'monkey',
  'line': 1009,
  'raising': True,
  'receiver': 'usage_scan_jail'},
 {'anchor': ['TestReadyBudget', 'test_affinity_unknowable_still_derates_via_cpu_count'],
  'attribute': 'getloadavg',
  'binding': 'os',
  'call': "monkeypatch.setattr(usage_scan_jail.os, 'getloadavg', lambda: (12.0, 0.0, 0.0))",
  'file': 'core/llm/dispatcher/tests/test_usage_scan_jail.py',
  'kind': 'monkey',
  'line': 1010,
  'raising': True,
  'receiver': 'usage_scan_jail'},
 {'anchor': ['_lose_creation_race'],
  'attribute': 'open',
  'binding': 'os',
  'call': "monkeypatch.setattr(cache_integrity.os, 'open', fake_open)",
  'file': 'core/llm/tests/test_cache_integrity_key_race.py',
  'kind': 'monkey',
  'line': 48,
  'original_receiver': 'cache_integrity',
  'raising': True,
  'receiver': 'mac_key'},
 {'anchor': ['test_root_mappings_do_not_share_a_uid_only_discovery_family'],
  'attribute': 'geteuid',
  'binding': 'os',
  'call': "monkeypatch.setattr(broker.os, 'geteuid', lambda: 0)",
  'file': 'packages/joern/tests/test_broker.py',
  'kind': 'monkey',
  'line': 314,
  'raising': True,
  'receiver': 'broker'},
 {'anchor': ['test_unset_macos_temp_uses_private_os_directory'],
  'attribute': 'confstr',
  'binding': 'os',
  'call': "monkeypatch.setattr(client.os, 'confstr', lambda name: str(tmp_path))",
  'file': 'packages/joern/tests/test_graph_artifacts.py',
  'kind': 'monkey',
  'line': 107,
  'raising': True,
  'receiver': 'client'},
 {'anchor': ['test_reaped_worker_keeps_files_and_never_signals_a_recycled_group'],
  'attribute': 'killpg',
  'binding': 'os',
  'call': "monkeypatch.setattr(server.os, 'killpg', signal_group)",
  'file': 'packages/joern/tests/test_owned_process_signals.py',
  'kind': 'monkey',
  'line': 24,
  'raising': True,
  'receiver': 'server'},
 {'anchor': ['test_reaped_parser_never_signals_a_recycled_group'],
  'attribute': 'killpg',
  'binding': 'os',
  'call': "monkeypatch.setattr(server.os, 'killpg', signal_group)",
  'file': 'packages/joern/tests/test_owned_process_signals.py',
  'kind': 'monkey',
  'line': 44,
  'raising': True,
  'receiver': 'server'},
 {'anchor': ['test_pidns_unshare_is_a_single_combined_call'],
  'attribute': 'unshare',
  'binding': 'os',
  'call': "monkeypatch.setattr(nf.os, 'unshare', record)",
  'file': 'packages/joern/tests/test_pidns_contract.py',
  'kind': 'monkey',
  'line': 371,
  'raising': True,
  'receiver': 'nf'},
 {'anchor': ['test_supervisor_never_forwards_to_a_reaped_pid'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(nf.os, 'kill', lambda p, s: kills.append((p, s)))",
  'file': 'packages/joern/tests/test_pidns_contract.py',
  'kind': 'monkey',
  'line': 309,
  'raising': True,
  'receiver': 'nf'},
 {'anchor': ['TestCPGCaching', 'test_content_hash_ignores_directory_order'],
  'attribute': 'walk',
  'binding': 'os',
  'call': "monkeypatch.setattr(runner_mod.os, 'walk', shuffled_walk)",
  'file': 'packages/joern/tests/test_runner.py',
  'kind': 'monkey',
  'line': 786,
  'raising': True,
  'receiver': 'runner_mod'},
 {'anchor': ['TestStopFastRealProcesses', 'test_uncorroborated_group_is_never_signalled'],
  'attribute': 'killpg',
  'binding': 'os',
  'call': "monkeypatch.setattr(server_mod.os, 'killpg', _recording_killpg)",
  'file': 'packages/joern/tests/test_server_stop_fast.py',
  'kind': 'monkey',
  'line': 161,
  'raising': True,
  'receiver': 'server_mod'},
 {'anchor': ['TestStopFastRealProcesses', 'test_no_proc_is_a_noop'],
  'attribute': 'killpg',
  'binding': 'os',
  'call': "monkeypatch.setattr(server_mod.os, 'killpg', lambda pgid, sig: sent.append((pgid, "
          'sig)))',
  'file': 'packages/joern/tests/test_server_stop_fast.py',
  'kind': 'monkey',
  'line': 178,
  'raising': True,
  'receiver': 'server_mod'},
 {'anchor': ['TestSentinelPgidRefusal', '_fake_killpg'],
  'attribute': 'killpg',
  'binding': 'os',
  'call': "monkeypatch.setattr(server_mod.os, 'killpg', lambda pgid, sig: self.sent.append((pgid, "
          'sig)))',
  'file': 'packages/joern/tests/test_server_stop_fast.py',
  'kind': 'monkey',
  'line': 260,
  'raising': True,
  'receiver': 'server_mod'},
 {'anchor': ['TestSentinelPgidRefusal', 'test_stop_still_group_signals_real_leader'],
  'attribute': 'getpgid',
  'binding': 'os',
  'call': "monkeypatch.setattr(server_mod.os, 'getpgid', lambda p: p)",
  'file': 'packages/joern/tests/test_server_stop_fast.py',
  'kind': 'monkey',
  'line': 326,
  'raising': True,
  'receiver': 'server_mod'},
 {'anchor': ['TestEnsureGroupDead', 'test_never_signals_own_group'],
  'attribute': 'killpg',
  'binding': 'os',
  'call': "monkeypatch.setattr(server_mod.os, 'killpg', lambda *args: signalled.append(args))",
  'file': 'packages/joern/tests/test_stop_group_escalation.py',
  'kind': 'monkey',
  'line': 169,
  'raising': True,
  'receiver': 'server_mod'},
 {'anchor': ['TestEnsureGroupDead', 'test_non_int_pgid_is_a_clean_no_op'],
  'attribute': 'killpg',
  'binding': 'os',
  'call': "monkeypatch.setattr(server_mod.os, 'killpg', lambda *args: signalled.append(args))",
  'file': 'packages/joern/tests/test_stop_group_escalation.py',
  'kind': 'monkey',
  'line': 215,
  'raising': True,
  'receiver': 'server_mod'},
 {'anchor': ['TestEnsureGroupDead', 'test_never_signals_own_group'],
  'attribute': 'getpgrp',
  'binding': 'os',
  'call': "monkeypatch.setattr(server_mod.os, 'getpgrp', lambda: own)",
  'file': 'packages/joern/tests/test_stop_group_escalation.py',
  'kind': 'monkey',
  'line': 182,
  'raising': True,
  'receiver': 'server_mod'},
 {'anchor': ['test_growth_past_cap_is_not_accepted_as_a_partial_log'],
  'attribute': 'fstat',
  'binding': 'os',
  'call': "monkeypatch.setattr(capped_read.os, 'fstat', grow)",
  'file': 'core/sandbox/tests/test_egress_summary_bounds.py',
  'kind': 'monkey',
  'line': 93,
  'raising': True,
  'receiver': 'capped_read'},
 {'anchor': ['test_stat_failure_closes_descriptor_and_returns_no_summary'],
  'attribute': 'open',
  'binding': 'os',
  'call': "patch.setattr(capped_read.os, 'open', open_fd)",
  'file': 'core/sandbox/tests/test_egress_summary_bounds.py',
  'kind': 'monkey',
  'line': 72,
  'raising': True,
  'receiver': 'capped_read'},
 {'anchor': ['test_stat_failure_closes_descriptor_and_returns_no_summary'],
  'attribute': 'fstat',
  'binding': 'os',
  'call': "patch.setattr(capped_read.os, 'fstat', Mock(side_effect=OSError('stat failed')))",
  'file': 'core/sandbox/tests/test_egress_summary_bounds.py',
  'kind': 'monkey',
  'line': 73,
  'raising': True,
  'receiver': 'capped_read'},
 {'anchor': ['TestTracerFdConfigConsumption', 'test_trace_falls_back_when_evidence_fd_invalid'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(tracer_mod.os, 'waitpid', no_children)",
  'file': 'core/sandbox/tests/test_evidence.py',
  'kind': 'monkey',
  'line': 457,
  'raising': True,
  'receiver': 'tracer_mod'},
 {'anchor': ['TestTracerFdConfigConsumption', 'test_trace_adopts_valid_evidence_fd'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(tracer_mod.os, 'waitpid', no_children)",
  'file': 'core/sandbox/tests/test_evidence.py',
  'kind': 'monkey',
  'line': 482,
  'raising': True,
  'receiver': 'tracer_mod'},
 {'anchor': ['test_high_descriptor_drain_preserves_bytes'],
  'attribute': 'waitid',
  'binding': 'os',
  'call': "monkeypatch.setattr(audit.os, 'waitid', lambda *args: object())",
  'file': 'core/sandbox/tests/test_landlock_audit_high_fds.py',
  'kind': 'monkey',
  'line': 65,
  'raising': True,
  'receiver': 'audit'},
 {'anchor': ['test_engagement_failure_not_pinned_to_sibling_lifetime'],
  'attribute': 'unshare',
  'binding': 'os',
  'call': "monkeypatch.setattr(_spawn.os, 'unshare', flaky_unshare)",
  'file': 'core/sandbox/tests/test_p_ready_cross_spawn_pin.py',
  'kind': 'monkey',
  'line': 136,
  'raising': True,
  'receiver': '_spawn'},
 {'anchor': ['parent_probe'],
  'attribute': 'fork',
  'binding': 'os',
  'call': "monkeypatch.setattr(probe.os, 'fork', lambda: PID)",
  'file': 'core/sandbox/tests/test_ptrace_probe_deadline.py',
  'kind': 'monkey',
  'line': 33,
  'raising': True,
  'receiver': 'probe'},
 {'anchor': ['test_nonblocking_wait_honors_deadline'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probe.os, 'waitpid', wait)",
  'file': 'core/sandbox/tests/test_ptrace_probe_deadline.py',
  'kind': 'monkey',
  'line': 124,
  'raising': True,
  'receiver': 'probe'},
 {'anchor': ['test_eintr_retries_cannot_extend_deadline'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probe.os, 'waitpid', wait)",
  'file': 'core/sandbox/tests/test_ptrace_probe_deadline.py',
  'kind': 'monkey',
  'line': 144,
  'raising': True,
  'receiver': 'probe'},
 {'anchor': ['test_terminal_result_can_be_collected_without_waiting'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probe.os, 'waitpid', lambda pid, flags: (pid, 0))",
  'file': 'core/sandbox/tests/test_ptrace_probe_deadline.py',
  'kind': 'monkey',
  'line': 153,
  'raising': True,
  'receiver': 'probe'},
 {'anchor': ['cleanup_probe'],
  'attribute': 'pidfd_open',
  'binding': 'os',
  'call': "monkeypatch.setattr(probe.os, 'pidfd_open', no_pidfd)",
  'file': 'core/sandbox/tests/test_ptrace_probe_deadline.py',
  'kind': 'monkey',
  'line': 165,
  'raising': True,
  'receiver': 'probe'},
 {'anchor': ['cleanup_probe'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(probe.os, 'waitpid', lambda pid, flags: (0, 0))",
  'file': 'core/sandbox/tests/test_ptrace_probe_deadline.py',
  'kind': 'monkey',
  'line': 169,
  'raising': True,
  'receiver': 'probe'},
 {'anchor': ['cleanup_probe'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(probe.os, 'kill', lambda pid, sig: signals.append((pid, sig)))",
  'file': 'core/sandbox/tests/test_ptrace_probe_deadline.py',
  'kind': 'monkey',
  'line': 170,
  'raising': True,
  'receiver': 'probe'},
 {'anchor': ['test_real_stalled_probe_child_is_killed_and_reaped'],
  'attribute': 'fork',
  'binding': 'os',
  'call': "monkeypatch.setattr(probe.os, 'fork', fork)",
  'file': 'core/sandbox/tests/test_ptrace_probe_deadline.py',
  'kind': 'monkey',
  'line': 252,
  'raising': True,
  'receiver': 'probe'},
 {'anchor': ['test_read_error_never_returns_exec_success'],
  'attribute': 'read',
  'binding': 'os',
  'call': "monkeypatch.setattr(_spawn.os, 'read', read)",
  'file': 'core/sandbox/tests/test_setup_status_read_errors.py',
  'kind': 'monkey',
  'line': 20,
  'raising': True,
  'receiver': '_spawn'},
 {'anchor': ['test_read_error_never_returns_exec_success'],
  'attribute': 'close',
  'binding': 'os',
  'call': "monkeypatch.setattr(_spawn.os, 'close', closed.append)",
  'file': 'core/sandbox/tests/test_setup_status_read_errors.py',
  'kind': 'monkey',
  'line': 21,
  'raising': True,
  'receiver': '_spawn'},
 {'anchor': ['test_successful_or_nonblocking_drain_preserves_confirmation'],
  'attribute': 'read',
  'binding': 'os',
  'call': "monkeypatch.setattr(_spawn.os, 'read', read)",
  'file': 'core/sandbox/tests/test_setup_status_read_errors.py',
  'kind': 'monkey',
  'line': 46,
  'raising': True,
  'receiver': '_spawn'},
 {'anchor': ['test_successful_or_nonblocking_drain_preserves_confirmation'],
  'attribute': 'close',
  'binding': 'os',
  'call': "monkeypatch.setattr(_spawn.os, 'close', lambda fd: None)",
  'file': 'core/sandbox/tests/test_setup_status_read_errors.py',
  'kind': 'monkey',
  'line': 47,
  'raising': True,
  'receiver': '_spawn'},
 {'anchor': ['test_group_query_failure_still_kills_and_reaps_child'],
  'attribute': 'killpg',
  'binding': 'os',
  'call': "scoped.setattr(spawn.os, 'killpg', groups)",
  'file': 'core/sandbox/tests/test_spawn_cleanup_query_errors.py',
  'kind': 'monkey',
  'line': 20,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_cleanup_error_does_not_replace_allocation_error'],
  'attribute': 'pipe',
  'binding': 'os',
  'call': "patch.setattr(spawn.os, 'pipe', pipe)",
  'file': 'core/sandbox/tests/test_spawn_pipe_allocation.py',
  'kind': 'monkey',
  'line': 131,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_cleanup_error_does_not_replace_allocation_error'],
  'attribute': 'close',
  'binding': 'os',
  'call': "patch.setattr(spawn.os, 'close', close)",
  'file': 'core/sandbox/tests/test_spawn_pipe_allocation.py',
  'kind': 'monkey',
  'line': 132,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_second_capture_pipe_failure_closes_first_pair'],
  'attribute': 'pipe',
  'binding': 'os',
  'call': "patch.setattr(spawn.os, 'pipe', pipe)",
  'file': 'core/sandbox/tests/test_spawn_pipe_allocation.py',
  'kind': 'monkey',
  'line': 39,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_second_capture_pipe_failure_closes_first_pair'],
  'attribute': 'close',
  'binding': 'os',
  'call': "patch.setattr(spawn.os, 'close', close)",
  'file': 'core/sandbox/tests/test_spawn_pipe_allocation.py',
  'kind': 'monkey',
  'line': 40,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_failed_death_registration_rolls_back_and_closes'],
  'attribute': 'pipe',
  'binding': 'os',
  'call': "patch.setattr(spawn.os, 'pipe', pipe)",
  'file': 'core/sandbox/tests/test_spawn_pipe_allocation.py',
  'kind': 'monkey',
  'line': 98,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_failed_death_registration_rolls_back_and_closes'],
  'attribute': 'close',
  'binding': 'os',
  'call': "patch.setattr(spawn.os, 'close', close)",
  'file': 'core/sandbox/tests/test_spawn_pipe_allocation.py',
  'kind': 'monkey',
  'line': 99,
  'raising': True,
  'receiver': 'spawn'},
 {'anchor': ['test_descriptor_identity_cannot_alias_a_protected_root'],
  'attribute': 'readlink',
  'binding': 'os',
  'call': "monkeypatch.setattr(guard.os, 'readlink', lambda _: str(tmp_path / 'apparent-state'))",
  'file': 'core/startup/tests/test_install_guard.py',
  'kind': 'monkey',
  'line': 278,
  'raising': True,
  'receiver': 'guard'},
 {'anchor': ['test_stdio_cannot_hide_registered_file_handles_in_an_anon_inode'],
  'attribute': 'listdir',
  'binding': 'os',
  'call': "monkeypatch.setattr(guard.os, 'listdir', lambda _: ['0'])",
  'file': 'core/startup/tests/test_install_guard.py',
  'kind': 'monkey',
  'line': 383,
  'raising': True,
  'receiver': 'guard'},
 {'anchor': ['test_stdio_cannot_hide_registered_file_handles_in_an_anon_inode'],
  'attribute': 'readlink',
  'binding': 'os',
  'call': "monkeypatch.setattr(guard.os, 'readlink', lambda _: 'anon_inode:[io_uring]')",
  'file': 'core/startup/tests/test_install_guard.py',
  'kind': 'monkey',
  'line': 384,
  'raising': True,
  'receiver': 'guard'},
 {'anchor': ['test_parallel_bytecode_matches_serial_and_refreshes_changed_sources'],
  'attribute': 'sched_getaffinity',
  'binding': 'os',
  'call': "monkeypatch.setattr(guard.os, 'sched_getaffinity', lambda _: {0, 1}, raising=False)",
  'file': 'core/startup/tests/test_install_guard.py',
  'kind': 'monkey',
  'line': 392,
  'raising': False,
  'receiver': 'guard'},
 {'anchor': ['test_bytecode_worker_initialization_failure_stops_preparation'],
  'attribute': 'sched_getaffinity',
  'binding': 'os',
  'call': "monkeypatch.setattr(guard.os, 'sched_getaffinity', lambda _: {0, 1}, raising=False)",
  'file': 'core/startup/tests/test_install_guard.py',
  'kind': 'monkey',
  'line': 460,
  'raising': False,
  'receiver': 'guard'},
 {'anchor': ['test_restricted_worker_ipc_still_performs_full_serial_validation'],
  'attribute': 'sched_getaffinity',
  'binding': 'os',
  'call': "monkeypatch.setattr(guard.os, 'sched_getaffinity', lambda _: {0, 1}, raising=False)",
  'file': 'core/startup/tests/test_install_guard.py',
  'kind': 'monkey',
  'line': 475,
  'raising': False,
  'receiver': 'guard'},
 {'anchor': ['test_precompile_without_affinity_validates_all_sources_serially'],
  'attribute': 'sched_getaffinity',
  'binding': 'os',
  'call': "monkeypatch.delattr(guard.os, 'sched_getaffinity', raising=False)",
  'file': 'core/startup/tests/test_install_guard.py',
  'kind': 'delete',
  'line': 865,
  'raising': False,
  'receiver': 'guard'},
 {'anchor': ['test_loop_backing_beneath_a_device_mapper_layer_is_refused'],
  'attribute': 'scandir',
  'binding': 'os',
  'call': "patch.setattr(guard.os, 'scandir', slaves)",
  'file': 'core/startup/tests/test_install_guard.py',
  'kind': 'monkey',
  'line': 699,
  'raising': True,
  'receiver': 'guard'},
 {'anchor': ['test_raw_device_stdio_cannot_bypass_file_mounts'],
  'attribute': 'listdir',
  'binding': 'os',
  'call': "patch.setattr(guard.os, 'listdir', lambda path: ['0'])",
  'file': 'core/startup/tests/test_install_guard.py',
  'kind': 'monkey',
  'line': 712,
  'raising': True,
  'receiver': 'guard'},
 {'anchor': ['test_raw_device_stdio_cannot_bypass_file_mounts'],
  'attribute': 'readlink',
  'binding': 'os',
  'call': "patch.setattr(guard.os, 'readlink', lambda path: '/dev/fake-block')",
  'file': 'core/startup/tests/test_install_guard.py',
  'kind': 'monkey',
  'line': 713,
  'raising': True,
  'receiver': 'guard'},
 {'anchor': ['test_raw_device_stdio_cannot_bypass_file_mounts'],
  'attribute': 'fstat',
  'binding': 'os',
  'call': "patch.setattr(guard.os, 'fstat', lambda fd: SimpleNamespace(st_mode=stat.S_IFBLK) if fd "
          '== 0 else original(fd))',
  'file': 'core/startup/tests/test_install_guard.py',
  'kind': 'monkey',
  'line': 714,
  'raising': True,
  'receiver': 'guard'},
 {'anchor': ['test_metadata_walk_tolerates_retired_atomic_files_without_skipping_other_entries'],
  'attribute': 'scandir',
  'binding': 'os',
  'call': "patch.setattr(guard.os, 'scandir', retiring)",
  'file': 'core/startup/tests/test_install_guard.py',
  'kind': 'monkey',
  'line': 780,
  'raising': True,
  'receiver': 'guard'},
 {'anchor': ['test_only_private_devices_clear_nodev'],
  'attribute': 'statvfs',
  'binding': 'os',
  'call': "monkeypatch.setattr(native.os, 'statvfs', lambda _: SimpleNamespace(f_flag=0))",
  'file': 'core/startup/tests/test_install_namespace.py',
  'kind': 'monkey',
  'line': 35,
  'raising': True,
  'receiver': 'native'},
 {'anchor': ['test_state_is_not_advertised_writable_when_source_is_readonly'],
  'attribute': 'statvfs',
  'binding': 'os',
  'call': "monkeypatch.setattr(native.os, 'statvfs', lambda _: "
          'SimpleNamespace(f_flag=native.os.ST_RDONLY))',
  'file': 'core/startup/tests/test_install_namespace.py',
  'kind': 'monkey',
  'line': 48,
  'raising': True,
  'receiver': 'native'},
 {'anchor': ['test_install_output_and_metadata_are_mounted_in_hierarchical_order'],
  'attribute': 'statvfs',
  'binding': 'os',
  'call': "monkeypatch.setattr(native.os, 'statvfs', lambda path: "
          'SimpleNamespace(f_flag=native.os.ST_RDONLY if str(path) in readonly else 0))',
  'file': 'core/startup/tests/test_install_namespace.py',
  'kind': 'monkey',
  'line': 152,
  'raising': True,
  'receiver': 'native'},
 {'anchor': ['test_parent_pins_cannot_reopen_writable_holes_beneath_installation'],
  'attribute': 'statvfs',
  'binding': 'os',
  'call': "monkeypatch.setattr(native.os, 'statvfs', lambda path: "
          'SimpleNamespace(f_flag=native.os.ST_RDONLY if str(path) in readonly else 0))',
  'file': 'core/startup/tests/test_install_namespace.py',
  'kind': 'monkey',
  'line': 184,
  'raising': True,
  'receiver': 'native'},
 {'anchor': ['test_cleanup_consumes_traced_stops_before_final_status'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(helper.os, 'kill', lambda child, sig: calls.append(('kill', child, "
          'sig)))',
  'file': 'core/testing/tests/test_expected_crash.py',
  'kind': 'monkey',
  'line': 104,
  'raising': True,
  'receiver': 'helper'},
 {'anchor': ['test_cleanup_consumes_traced_stops_before_final_status'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(helper.os, 'waitpid', lambda child, flags: next(waits))",
  'file': 'core/testing/tests/test_expected_crash.py',
  'kind': 'monkey',
  'line': 105,
  'raising': True,
  'receiver': 'helper'},
 {'anchor': ['test_cleanup_wait_has_a_deadline'],
  'attribute': 'kill',
  'binding': 'os',
  'call': "monkeypatch.setattr(helper.os, 'kill', lambda child, sig: None)",
  'file': 'core/testing/tests/test_expected_crash.py',
  'kind': 'monkey',
  'line': 120,
  'raising': True,
  'receiver': 'helper'},
 {'anchor': ['test_cleanup_wait_has_a_deadline'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(helper.os, 'waitpid', lambda child, flags: (0, 0))",
  'file': 'core/testing/tests/test_expected_crash.py',
  'kind': 'monkey',
  'line': 121,
  'raising': True,
  'receiver': 'helper'},
 {'anchor': ['test_expired_entry_precedes_older_valid_entry'],
  'attribute': 'O_NOATIME',
  'binding': 'os',
  'call': "monkeypatch.delattr(budget.os, 'O_NOATIME', raising=False)",
  'file': 'packages/sca/tests/test_cache_budget.py',
  'kind': 'delete',
  'line': 39,
  'raising': False,
  'receiver': 'budget'},
 {'anchor': ['test_stat_failure_does_not_hide_later_files'],
  'attribute': 'scandir',
  'binding': 'os',
  'call': "patch.setattr(budget.os, 'scandir', scan)",
  'file': 'packages/sca/tests/test_cache_scan_failures.py',
  'kind': 'monkey',
  'line': 96,
  'raising': True,
  'receiver': 'budget'},
 {'anchor': ['test_short_header_reads_do_not_misclassify_real_database'],
  'attribute': 'read',
  'binding': 'os',
  'call': "monkeypatch.setattr(budget.os, 'read', lambda fd, n: read(fd, min(n, 3)))",
  'file': 'packages/sca/tests/test_cache_scan_failures.py',
  'kind': 'monkey',
  'line': 178,
  'raising': True,
  'receiver': 'budget'},
 {'anchor': ['test_walk_error_refuses_incomplete_source_copy'],
  'attribute': 'walk',
  'binding': 'os',
  'call': "monkeypatch.setattr(verify.os, 'walk', failed_walk)",
  'file': 'packages/sca/tests/test_verify_overlay_lifecycle.py',
  'kind': 'monkey',
  'line': 328,
  'raising': True,
  'receiver': 'verify'},
 {'anchor': ['TestRunCodeqlDelegation', 'test_subprocess_timeout_killpgs_and_returns_empty'],
  'attribute': 'killpg',
  'binding': 'os',
  'call': "patch.object(_scanner_mod.os, 'killpg')",
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 195,
  'raising': True,
  'receiver': '_scanner_mod'},
 {'anchor': ['TestRunCodeqlDelegation', 'test_subprocess_timeout_killpgs_and_returns_empty'],
  'attribute': 'getpgid',
  'binding': 'os',
  'call': "patch.object(_scanner_mod.os, 'getpgid', return_value=12345)",
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 196,
  'raising': True,
  'receiver': '_scanner_mod'},
 {'anchor': ['TestRunCodeqlDelegation',
             'test_killpg_swallows_processlookup_when_child_already_died'],
  'attribute': 'killpg',
  'binding': 'os',
  'call': "patch.object(_scanner_mod.os, 'killpg', side_effect=ProcessLookupError())",
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 222,
  'raising': True,
  'receiver': '_scanner_mod'},
 {'anchor': ['TestRunCodeqlDelegation',
             'test_killpg_swallows_processlookup_when_child_already_died'],
  'attribute': 'getpgid',
  'binding': 'os',
  'call': "patch.object(_scanner_mod.os, 'getpgid', return_value=12345)",
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 224,
  'raising': True,
  'receiver': '_scanner_mod'},
 {'anchor': ['TestJoinCodeQLStage',
             'test_run_codeql_interrupt_mid_communicate_killpgs_and_reraises'],
  'attribute': 'killpg',
  'binding': 'os',
  'call': "patch.object(_scanner_mod.os, 'killpg')",
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 600,
  'raising': True,
  'receiver': '_scanner_mod'},
 {'anchor': ['TestJoinCodeQLStage',
             'test_run_codeql_interrupt_mid_communicate_killpgs_and_reraises'],
  'attribute': 'getpgid',
  'binding': 'os',
  'call': "patch.object(_scanner_mod.os, 'getpgid', return_value=12345)",
  'file': 'packages/static-analysis/tests/test_scanner.py',
  'kind': 'object',
  'line': 601,
  'raising': True,
  'receiver': '_scanner_mod'},
 {'anchor': ['test_browser_backend_refuses_host_proc_and_fallback_lanes'],
  'attribute': 'getuid',
  'binding': 'os',
  'call': "monkeypatch.setattr(_spawn.os, 'getuid', lambda: 1001)",
  'file': 'packages/web/tests/test_browser_sandbox_policy.py',
  'kind': 'monkey',
  'line': 159,
  'raising': True,
  'receiver': '_spawn'},
 {'anchor': ['TestDbFreshness', 'test_skip_dirs_are_pruned_not_visited'],
  'attribute': 'walk',
  'binding': 'os',
  'call': "monkeypatch.setattr(dv.os, 'walk', spy_walk)",
  'file': 'packages/llm_analysis/tests/test_dataflow_validation.py',
  'kind': 'monkey',
  'line': 291,
  'raising': True,
  'receiver': 'dv'},
 {'anchor': ['TestAppendHardening', 'test_short_write_rolls_back_whole_line'],
  'attribute': 'write',
  'binding': 'os',
  'call': "monkeypatch.setattr(journal_mod.os, 'write', flaky_write)",
  'file': 'core/coverage/tests/test_journal_append.py',
  'kind': 'monkey',
  'line': 163,
  'raising': True,
  'receiver': 'journal_mod'},
 {'anchor': ['TestAppendHardening', 'test_persistent_short_write_raises_and_stays_intact'],
  'attribute': 'write',
  'binding': 'os',
  'call': "monkeypatch.setattr(journal_mod.os, 'write', always_short)",
  'file': 'core/coverage/tests/test_journal_append.py',
  'kind': 'monkey',
  'line': 186,
  'raising': True,
  'receiver': 'journal_mod'},
 {'anchor': ['test_walk_failure_does_not_publish_partial_database'],
  'attribute': 'walk',
  'binding': 'os',
  'call': "monkeypatch.setattr(util.os, 'walk', failed)",
  'file': 'packages/ghidra/tests/test_project_copy_lifecycle.py',
  'kind': 'monkey',
  'line': 265,
  'raising': True,
  'receiver': 'util'},
 {'anchor': ['test_failed_publication_preserves_canonical'],
  'attribute': 'replace',
  'binding': 'os',
  'call': "fault.setattr(atomic_fs.os, 'replace', fail_replace)",
  'file': 'core/concepts/tests/test_promotion_storage.py',
  'kind': 'monkey',
  'line': 155,
  'raising': True,
  'receiver': 'atomic_fs'},
 {'anchor': ['_run_probe_with'],
  'attribute': 'fork',
  'binding': 'os',
  'call': "monkeypatch.setattr(os, 'fork', lambda: _FAKE_PID)",
  'file': 'core/sandbox/tests/test_ptrace_probe.py',
  'kind': 'monkey',
  'line': 266,
  'raising': True,
  'receiver': 'ptrace_probe',
  'original_receiver': 'os'},
 {'anchor': ['TestEintrSafe', 'test_waitpid_retries_on_interrupted_error'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(os, 'waitpid', fake_waitpid)",
  'file': 'core/sandbox/tests/test_ptrace_probe.py',
  'kind': 'monkey',
  'line': 181,
  'raising': True,
  'receiver': 'ptrace_probe',
  'original_receiver': 'os'},
 {'anchor': ['TestEintrSafe', 'test_waitpid_propagates_non_eintr_oserror'],
  'attribute': 'waitpid',
  'binding': 'os',
  'call': "monkeypatch.setattr(os, 'waitpid', fake_waitpid)",
  'file': 'core/sandbox/tests/test_ptrace_probe.py',
  'kind': 'monkey',
  'line': 193,
  'raising': True,
  'receiver': 'ptrace_probe',
  'original_receiver': 'os'},
 {'anchor': ['test_grant_pin_refuses_simulated_inode_recycling'],
  'attribute': 'stat',
  'binding': 'os',
  'call': "monkeypatch.setattr(os, 'stat', forger)",
  'file': 'core/sandbox/tests/test_context_decision_pins.py',
  'kind': 'monkey',
  'line': 1478,
  'raising': True,
  'receiver': 'context',
  'original_receiver': 'os'},
 {'anchor': ['TestBirthTimeWitness', 'test_pinned_birthtime_that_vanishes_fails_closed'],
  'attribute': 'stat',
  'binding': 'os',
  'call': "monkeypatch.setattr(os, 'stat', stat_with_birthtime)",
  'file': 'core/sandbox/tests/test_macos_grant_pinning.py',
  'kind': 'monkey',
  'line': 485,
  'raising': True,
  'receiver': '_macos_spawn',
  'original_receiver': 'os'},
 {'anchor': ['ops'],
  'attribute': 'open',
  'binding': 'os',
  'call': "monkeypatch.setattr(os, 'open', ledger.open)",
  'file': 'core/sandbox/tests/test_fake_home_cleanup.py',
  'kind': 'monkey',
  'line': 71,
  'raising': True,
  'receiver': 'home',
  'original_receiver': 'os'},
 {'anchor': ['ops'],
  'attribute': 'close',
  'binding': 'os',
  'call': "monkeypatch.setattr(os, 'close', ledger.close)",
  'file': 'core/sandbox/tests/test_fake_home_cleanup.py',
  'kind': 'monkey',
  'line': 72,
  'raising': True,
  'receiver': 'home',
  'original_receiver': 'os'},
 {'anchor': ['ops'],
  'attribute': 'dup',
  'binding': 'os',
  'call': "monkeypatch.setattr(os, 'dup', ledger.dup)",
  'file': 'core/sandbox/tests/test_fake_home_cleanup.py',
  'kind': 'monkey',
  'line': 73,
  'raising': True,
  'receiver': 'home',
  'original_receiver': 'os'}]


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
        for owner in owners:
            original = getattr(owner, row["binding"])
            missing = not hasattr(original, row["attribute"]) and row.get("raising", True)
            if borrowed or missing:
                view = ModuleType(original.__name__)
                vars(view).update(vars(original))
                # Feature presence is fixture input for these ownership checks,
                # not a requirement that the host supplies Linux-only calls.
                if missing:
                    setattr(view, row["attribute"], object())
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


@pytest.mark.parametrize("index", [i for i, row in enumerate(_SITES)
                                   if row["binding"] == "os" and row["attribute"] in {"unshare", "pidfd_open"}])
@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_native_mock_owns_absent_platform_attribute(index, borrowed, exit_mode):
    row = _SITES[index]
    owner = _consumer(index)
    original = getattr(owner, row["binding"])
    view = ModuleType(original.__name__)
    vars(view).update(vars(original))
    vars(view).pop(row["attribute"], None)
    before = dict(vars(view))
    with pytest.MonkeyPatch.context() as scope:
        scope.setitem(vars(owner), row["binding"], view)
        _exercise(index, borrowed, exit_mode)
        assert getattr(owner, row["binding"]) is view
        _assert_namespace(view, before)
    assert getattr(owner, row["binding"]) is original


@pytest.mark.parametrize("index", list({row["file"]: index for index, row in enumerate(_SITES)}.values()), ids=lambda index: _SITES[index]["file"])
@pytest.mark.parametrize("borrowed", [False, True])
def test_unmodified_host_control(index, borrowed):
    _exercise(index, borrowed, "normal", mock=False)


# Load before per-test session-lookup neutralizers run, exactly as native
# collection captures the real ancestry walk for the factory under test.
_ANCESTRY_NATIVE = _native("core/run/tests/test_metadata.py")


@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_native_ancestry_stack_keeps_both_consumers_private(borrowed, exit_mode):
    from core.run import metadata
    from core.project import sessions

    with pytest.MonkeyPatch.context() as inherited:
        if borrowed:
            for owner in (metadata, sessions):
                view = ModuleType(os.__name__)
                vars(view).update(vars(os))
                inherited.setitem(vars(owner), "os", view)
        before = [(owner, dict(vars(owner))) for owner in (metadata, sessions)]
        modules = [os, metadata.os, sessions.os]
        namespaces = [(module, dict(vars(module))) for module in modules]
        case = _ANCESTRY_NATIVE.TestFindClaudeAncestor()
        caught = None
        scratch = None
        try:
            with case._patch_tree(case._TREE, case._COMMS):
                scratch = Path(case._sessions_tmp)
                for module, snapshot in namespaces:
                    _assert_namespace(module, snapshot)
                assert metadata._find_claude_ancestor() == 40
                assert sessions.resolve_session_pid() == 40
                if exit_mode != "normal":
                    raise RuntimeError("ancestry stack exit") if exit_mode == "error" else KeyboardInterrupt("ancestry stack exit")
        except BaseException as error:
            caught = error
        for owner, snapshot in before + namespaces:
            _assert_namespace(owner, snapshot)
        assert scratch is not None and not scratch.exists()
        if exit_mode == "normal":
            assert caught is None, repr(caught)
        else:
            assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)
            assert str(caught) == "ancestry stack exit"


@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("stage", ["allocate", "after_allocate"])
@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt, SystemExit])
def test_ancestry_setup_failure_restores_bindings_and_resources(borrowed, stage, error_type):
    from core.run import metadata
    from core.project import sessions

    failure = error_type("ancestry setup failed")
    temporary = []
    with pytest.MonkeyPatch.context() as inherited:
        if borrowed:
            for owner in (metadata, sessions):
                view = ModuleType(os.__name__)
                vars(view).update(vars(os))
                inherited.setitem(vars(owner), "os", view)
        before = [(owner, dict(vars(owner))) for owner in (metadata, sessions, os, metadata.os, sessions.os)]
        platform = sys.platform
        native = _ANCESTRY_NATIVE
        real_directory = native.TemporaryDirectory

        def allocate(*args, **kwargs):
            if stage == "allocate":
                raise failure
            owned = real_directory(*args, **kwargs)
            temporary.append(owned)
            return owned

        def refuse_path(*args, **kwargs):
            raise failure

        try:
            # Register exact inherited values before exercising an unfixed
            # source tree, so a failing counterfactual cannot poison pytest.
            with pytest.MonkeyPatch.context() as backup:
                for owner, names in ((metadata, ("os", "Path", "_read_ppid")),
                                     (sessions, ("os", "_comm", "_walk_session_pid"))):
                    for name in names:
                        backup.setitem(vars(owner), name, getattr(owner, name))
                for module in (os, metadata.os, sessions.os):
                    for name in ("getpid", "getppid"):
                        backup.setattr(module, name, getattr(module, name))
                backup.setattr(sys, "platform", platform)
                backup.setattr(native, "TemporaryDirectory", allocate)
                if stage == "after_allocate":
                    backup.setattr(native, "Path", refuse_path)
                caught = None
                try:
                    native.TestFindClaudeAncestor()._patch_tree({100: 50, 50: 40, 40: 1}, {50: "bash", 40: "claude"})
                except BaseException as error:
                    caught = error
                assert caught is failure
                for owner, snapshot in before:
                    _assert_namespace(owner, snapshot)
                assert sys.platform is platform
                assert all(not Path(owned.name).exists() for owned in temporary)
        finally:
            for owned in temporary:
                owned.cleanup()
