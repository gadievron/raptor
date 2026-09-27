"""Tests for the sandbox denial triage classification."""

import unittest

from core.sandbox.summary import _triage_denials


class TestTriageDenials(unittest.TestCase):
    def test_empty_records(self):
        result = _triage_denials([])
        for cat in ("escape_primitives", "network_probing", "udp_egress",
                     "filesystem_escape", "routine"):
            self.assertEqual(result[cat]["count"], 0)
            self.assertEqual(result[cat]["examples"], [])
        self.assertEqual(result["severity"], "routine")

    def test_escape_primitives_ptrace(self):
        records = [
            {"type": "seccomp", "cmd": "gdb ptrace attach", "returncode": 1},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["escape_primitives"]["count"], 1)
        self.assertIn("ptrace", result["escape_primitives"]["examples"])
        self.assertEqual(result["severity"], "critical")

    def test_escape_primitives_bpf(self):
        records = [
            {"type": "seccomp", "cmd": "bpf prog load", "returncode": 1},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["escape_primitives"]["count"], 1)
        self.assertEqual(result["severity"], "critical")

    def test_escape_primitives_io_uring(self):
        records = [
            {"type": "seccomp", "cmd": "test io_uring setup", "returncode": 1},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["escape_primitives"]["count"], 1)
        self.assertEqual(result["severity"], "critical")

    def test_escape_keyword_in_path_is_not_escape_primitive(self):
        """A write denial to a path containing an escape keyword must
        NOT be classified as an escape primitive — only seccomp-type
        denials carry syscall-level signal."""
        records = [
            {"type": "write", "cmd": "touch /home/user/ptrace_test/out.txt",
             "path": "/home/user/ptrace_test/out.txt", "returncode": 1},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["escape_primitives"]["count"], 0)
        self.assertEqual(result["routine"]["count"], 1)
        self.assertEqual(result["severity"], "routine")

    def test_escape_keyword_in_non_seccomp_type_is_routine(self):
        """A network denial whose cmd mentions 'mount' is not an escape
        primitive — type must be seccomp."""
        records = [
            {"type": "network", "cmd": "curl mount.example.com",
             "returncode": 1},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["escape_primitives"]["count"], 0)
        self.assertEqual(result["network_probing"]["count"], 1)

    def test_udp_egress(self):
        records = [
            {"type": "udp", "cmd": "dig example.com", "returncode": 1},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["udp_egress"]["count"], 1)
        self.assertEqual(result["severity"], "elevated")

    def test_filesystem_escape(self):
        records = [
            {"type": "write", "cmd": "touch /etc/passwd",
             "path": "/etc/passwd", "returncode": 1},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["filesystem_escape"]["count"], 1)
        self.assertIn("/etc/passwd", result["filesystem_escape"]["examples"])
        self.assertEqual(result["severity"], "elevated")

    def test_filesystem_write_inside_workspace_is_routine(self):
        records = [
            {"type": "write", "cmd": "touch /home/user/work/out.txt",
             "path": "/home/user/work/out.txt", "returncode": 1},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["filesystem_escape"]["count"], 0)
        self.assertEqual(result["routine"]["count"], 1)
        self.assertEqual(result["severity"], "routine")

    def test_network_probing_threshold(self):
        records = [
            {"type": "network", "cmd": f"curl h{i}", "returncode": 1}
            for i in range(5)
        ]
        result = _triage_denials(records)
        self.assertEqual(result["network_probing"]["count"], 5)
        self.assertEqual(result["severity"], "routine")

        records.append(
            {"type": "network", "cmd": "curl h5", "returncode": 1})
        result = _triage_denials(records)
        self.assertEqual(result["network_probing"]["count"], 6)
        self.assertEqual(result["severity"], "elevated")

    def test_mixed_severity_critical_wins(self):
        records = [
            {"type": "udp", "cmd": "dns query", "returncode": 1},
            {"type": "seccomp", "cmd": "userfaultfd call", "returncode": 1},
            {"type": "network", "cmd": "curl x", "returncode": 1},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["severity"], "critical")

    def test_routine_only(self):
        records = [
            {"type": "network", "cmd": "pip install foo", "returncode": 1},
            {"type": "write", "cmd": "touch /home/u/x",
             "path": "/home/u/x", "returncode": 1},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["severity"], "routine")

    def test_examples_capped(self):
        records = [
            {"type": "udp", "cmd": f"probe-{i}", "returncode": 1}
            for i in range(20)
        ]
        result = _triage_denials(records)
        self.assertEqual(result["udp_egress"]["count"], 20)
        self.assertLessEqual(len(result["udp_egress"]["examples"]), 5)

    def test_proc_sys_dev_are_escape(self):
        for prefix in ("/proc/self/mem", "/sys/kernel/security",
                       "/dev/mem", "/root/.ssh/id_rsa"):
            records = [
                {"type": "write", "cmd": f"cat {prefix}",
                 "path": prefix, "returncode": 1},
            ]
            result = _triage_denials(records)
            self.assertGreater(result["filesystem_escape"]["count"], 0,
                               f"{prefix} should be filesystem_escape")


class TestAuditModeEnrichment(unittest.TestCase):
    """Tracer-format records (audit: True) carry decoded socket/ioctl
    fields. The triage classifier should use them for refined
    classification."""

    def test_docker_sock_is_escape_primitive(self):
        records = [
            {"type": "network", "cmd": "<sandbox audit: connect>",
             "audit": True, "syscall": "connect",
             "path": "/var/run/docker.sock", "returncode": 0},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["escape_primitives"]["count"], 1)
        self.assertIn("connect:/var/run/docker.sock",
                       result["escape_primitives"]["examples"])
        self.assertEqual(result["severity"], "critical")

    def test_containerd_sock_is_escape_primitive(self):
        records = [
            {"type": "network", "cmd": "<sandbox audit: connect>",
             "audit": True, "syscall": "connect",
             "path": "/run/containerd/containerd.sock", "returncode": 0},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["escape_primitives"]["count"], 1)

    def test_run_symlink_form_of_docker_sock(self):
        records = [
            {"type": "network", "cmd": "<sandbox audit: connect>",
             "audit": True, "syscall": "connect",
             "path": "/run/docker.sock", "returncode": 0},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["escape_primitives"]["count"], 1)

    def test_af_packet_is_escape_primitive(self):
        records = [
            {"type": "seccomp", "cmd": "<sandbox audit: socket>",
             "audit": True, "syscall": "socket",
             "socket_family": "AF_PACKET", "socket_type": "SOCK_RAW",
             "returncode": 0},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["escape_primitives"]["count"], 1)
        self.assertEqual(result["severity"], "critical")

    def test_sock_raw_is_escape_primitive(self):
        records = [
            {"type": "seccomp", "cmd": "<sandbox audit: socket>",
             "audit": True, "syscall": "socket",
             "socket_family": "AF_INET", "socket_type": "SOCK_RAW",
             "returncode": 0},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["escape_primitives"]["count"], 1)

    def test_tiocsti_is_escape_primitive(self):
        records = [
            {"type": "seccomp", "cmd": "<sandbox audit: ioctl>",
             "audit": True, "syscall": "ioctl",
             "ioctl_cmd": "TIOCSTI", "returncode": 0},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["escape_primitives"]["count"], 1)

    def test_tiocsctty_is_escape_primitive(self):
        records = [
            {"type": "seccomp", "cmd": "<sandbox audit: ioctl>",
             "audit": True, "syscall": "ioctl",
             "ioctl_cmd": "TIOCSCTTY", "returncode": 0},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["escape_primitives"]["count"], 1)
        self.assertEqual(result["severity"], "critical")

    def test_ordinary_audit_connect_is_network(self):
        records = [
            {"type": "network", "cmd": "<sandbox audit: connect>",
             "audit": True, "syscall": "connect",
             "path": "/tmp/ordinary.sock", "returncode": 0},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["escape_primitives"]["count"], 0)
        self.assertEqual(result["network_probing"]["count"], 1)

    def test_audit_and_enforcement_records_coexist(self):
        records = [
            {"type": "seccomp", "cmd": "ptrace call", "returncode": 1},
            {"type": "network", "cmd": "<sandbox audit: connect>",
             "audit": True, "syscall": "connect",
             "path": "/var/run/docker.sock", "returncode": 0},
        ]
        result = _triage_denials(records)
        self.assertEqual(result["escape_primitives"]["count"], 2)
        self.assertEqual(result["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
