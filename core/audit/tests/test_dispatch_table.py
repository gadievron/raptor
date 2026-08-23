"""Tests for core.audit.dispatch_table — dispatch-table capability displacement."""

from __future__ import annotations

from core.audit.dispatch_table import (
    CapabilityDisplacement,
    check_capability_displacement,
    find_capability_checks,
    find_dispatch_members,
    format_displacement_context,
)


def _gap(name, file, source):
    return {"name": name, "file": file, "source": source}


class TestFindDispatchMembers:

    def test_file_operations(self):
        gaps = [
            _gap("my_read", "drivers/my.c",
                 "static ssize_t my_read(struct file *f) { return 0; }"),
            _gap("my_write", "drivers/my.c",
                 "static ssize_t my_write(struct file *f) { return 0; }"),
            _gap("my_open", "drivers/my.c",
                 "static int my_open(struct inode *i) { return 0; }"),
            _gap("my_setup", "drivers/my.c",
                 "static const struct file_operations fops = {\n"
                 "    .read = my_read,\n"
                 "    .write = my_write,\n"
                 "    .open = my_open,\n"
                 "};"),
        ]
        result = find_dispatch_members(gaps)
        assert "drivers/my.c" in result
        names = {m.name for m in result["drivers/my.c"]}
        assert "my_read" in names
        assert "my_write" in names
        assert "my_open" in names
        assert "my_setup" not in names

    def test_ioctl_case_dispatch(self):
        gaps = [
            _gap("do_get_info", "net/netfilter.c",
                 "static int do_get_info(void) { return 0; }"),
            _gap("nf_ioctl", "net/netfilter.c",
                 "switch (cmd) {\n"
                 "    case GET_INFO: return do_get_info(ctx);\n"
                 "}"),
        ]
        result = find_dispatch_members(gaps)
        assert "net/netfilter.c" in result
        names = {m.name for m in result["net/netfilter.c"]}
        assert "do_get_info" in names

    def test_no_dispatch_tables(self):
        gaps = [
            _gap("helper", "lib/util.c", "int helper(void) { return 0; }"),
        ]
        assert find_dispatch_members(gaps) == {}

    def test_function_not_in_gaps_skipped(self):
        gaps = [
            _gap("setup", "drivers/x.c",
                 ".read = unknown_func,\n.write = unknown_func2,"),
        ]
        result = find_dispatch_members(gaps)
        assert result == {}

    def test_proto_ops_patterns(self):
        gaps = [
            _gap("my_connect", "net/proto.c",
                 "static int my_connect(struct socket *s) { return 0; }"),
            _gap("my_sendmsg", "net/proto.c",
                 "static int my_sendmsg(struct socket *s) { return 0; }"),
            _gap("proto_init", "net/proto.c",
                 "static const struct proto_ops my_ops = {\n"
                 "    .connect = my_connect,\n"
                 "    .sendmsg = my_sendmsg,\n"
                 "};"),
        ]
        result = find_dispatch_members(gaps)
        names = {m.name for m in result["net/proto.c"]}
        assert "my_connect" in names
        assert "my_sendmsg" in names


class TestFindCapabilityChecks:

    def test_capable_call(self):
        gaps = [
            _gap("setup", "io_uring.c",
                 "if (!capable(CAP_SYS_ADMIN)) return -EPERM;"),
        ]
        result = find_capability_checks(gaps)
        assert "io_uring.c" in result
        assert "setup" in result["io_uring.c"]
        assert "CAP_SYS_ADMIN" in result["io_uring.c"]["setup"]

    def test_ns_capable(self):
        gaps = [
            _gap("do_thing", "net/sock.c",
                 "if (!ns_capable(ns, CAP_NET_RAW)) return -EPERM;"),
        ]
        result = find_capability_checks(gaps)
        assert "CAP_NET_RAW" in result["net/sock.c"]["do_thing"]

    def test_no_capability_check(self):
        gaps = [
            _gap("helper", "lib/util.c", "int helper(void) { return 0; }"),
        ]
        assert find_capability_checks(gaps) == {}

    def test_multiple_capabilities(self):
        gaps = [
            _gap("init", "kern.c",
                 "capable(CAP_SYS_ADMIN) && capable(CAP_NET_ADMIN)"),
        ]
        result = find_capability_checks(gaps)
        caps = result["kern.c"]["init"]
        assert "CAP_SYS_ADMIN" in caps
        assert "CAP_NET_ADMIN" in caps


class TestCheckCapabilityDisplacement:

    def test_displaced_capability(self):
        """Setup function checks CAP, dispatch members don't."""
        gaps = [
            _gap("io_uring_setup", "io_uring.c",
                 "if (!capable(CAP_SYS_ADMIN)) return -EPERM;\n"
                 "return do_setup();"),
            _gap("io_uring_enter", "io_uring.c",
                 "static int io_uring_enter(void) {\n"
                 "    return submit_sqes();\n"
                 "}"),
            _gap("io_uring_register", "io_uring.c",
                 "static int io_uring_register(void) {\n"
                 "    return do_register();\n"
                 "}"),
            _gap("io_uring_ops", "io_uring.c",
                 "static const struct file_operations io_uring_fops = {\n"
                 "    .read = io_uring_enter,\n"
                 "    .ioctl = io_uring_register,\n"
                 "};"),
        ]
        result = check_capability_displacement(gaps)
        assert len(result) == 1
        d = result[0]
        assert d.capability == "CAP_SYS_ADMIN"
        assert "io_uring_setup" in d.check_functions
        assert "io_uring_enter" in d.dispatch_members_without
        assert "io_uring_register" in d.dispatch_members_without

    def test_no_displacement_when_dispatch_checks(self):
        """Dispatch members check the capability — no displacement."""
        gaps = [
            _gap("my_read", "drv.c",
                 "if (!capable(CAP_SYS_ADMIN)) return -EPERM;\n"
                 "return do_read();"),
            _gap("my_write", "drv.c",
                 "if (!capable(CAP_SYS_ADMIN)) return -EPERM;\n"
                 "return do_write();"),
            _gap("drv_ops", "drv.c",
                 ".read = my_read,\n.write = my_write,"),
        ]
        result = check_capability_displacement(gaps)
        assert result == []

    def test_no_displacement_without_cap_checks(self):
        """No capability checks at all — nothing to report."""
        gaps = [
            _gap("my_read", "drv.c", "return 0;"),
            _gap("my_write", "drv.c", "return 0;"),
            _gap("ops", "drv.c", ".read = my_read,\n.write = my_write,"),
        ]
        result = check_capability_displacement(gaps)
        assert result == []

    def test_too_few_dispatch_members(self):
        """Need min_dispatch_members (default 2) to trigger."""
        gaps = [
            _gap("setup", "x.c", "capable(CAP_SYS_ADMIN);"),
            _gap("handler", "x.c", "return 0;"),
            _gap("ops", "x.c", ".read = handler,"),
        ]
        result = check_capability_displacement(gaps)
        assert result == []

    def test_mixed_some_dispatch_members_check(self):
        """Some dispatch members check, some don't — not displacement,
        just inconsistency (existing negative-space handles this)."""
        gaps = [
            _gap("setup", "x.c", "capable(CAP_SYS_ADMIN);"),
            _gap("my_read", "x.c", "capable(CAP_SYS_ADMIN);\nreturn 0;"),
            _gap("my_write", "x.c", "return 0;"),
            _gap("ops", "x.c", ".read = my_read,\n.write = my_write,"),
        ]
        result = check_capability_displacement(gaps)
        assert result == []

    def test_different_files_independent(self):
        """Displacements are per-file."""
        gaps = [
            _gap("setup_a", "a.c", "capable(CAP_NET_RAW);"),
            _gap("handler_b", "b.c", "return 0;"),
            _gap("handler_b2", "b.c", "return 0;"),
            _gap("ops_b", "b.c", ".read = handler_b,\n.write = handler_b2,"),
        ]
        result = check_capability_displacement(gaps)
        assert result == []


class TestFormatDisplacementContext:

    def test_none_when_empty(self):
        assert format_displacement_context([]) is None

    def test_formats_displacement(self):
        d = CapabilityDisplacement(
            capability="CAP_SYS_ADMIN",
            check_functions=["io_uring_setup"],
            dispatch_members_without=["io_uring_enter", "io_uring_register"],
            file="io_uring.c",
        )
        result = format_displacement_context([d])
        assert result is not None
        assert "[Capability displacement analysis]" in result
        assert "CAP_SYS_ADMIN" in result
        assert "io_uring_setup" in result
        assert "io_uring_enter" in result

    def test_description_property(self):
        d = CapabilityDisplacement(
            capability="CAP_NET_RAW",
            check_functions=["sock_create"],
            dispatch_members_without=["sock_sendmsg", "sock_recvmsg"],
            file="net/socket.c",
        )
        desc = d.description
        assert "CAP_NET_RAW" in desc
        assert "sock_create" in desc
        assert "sock_sendmsg" in desc
