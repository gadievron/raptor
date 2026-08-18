"""Tests for ops_struct — function-pointer-table reachability (Lever 9)."""

from core.audit.ops_struct import extract_ops_registrations, collect_ops_entry_points


class TestExtractOpsRegistrations:
    """Designated-initialiser extraction."""

    def test_basic_ops_struct(self):
        src = (
            "static const struct xfrm_type esp_type = {\n"
            "    .owner = THIS_MODULE,\n"
            "    .proto = IPPROTO_ESP,\n"
            "    .flags = XFRM_TYPE_REPLAY_PROT,\n"
            "    .init_state = esp_init_state,\n"
            "    .destructor = esp_destroy,\n"
            "    .input = esp_input,\n"
            "    .output = esp_output_head,\n"
            "};\n"
        )
        regs = extract_ops_registrations(src, "net/ipv4/esp4.c")
        funcs = {r["function"] for r in regs}
        assert "esp_init_state" in funcs
        assert "esp_input" in funcs
        assert "esp_output_head" in funcs
        assert "THIS_MODULE" not in funcs
        assert all(r["struct_type"] == "xfrm_type" for r in regs)
        assert all(r["file"] == "net/ipv4/esp4.c" for r in regs)

    def test_file_operations(self):
        src = (
            "static const struct file_operations my_fops = {\n"
            "    .open = my_open,\n"
            "    .release = my_release,\n"
            "    .read = my_read,\n"
            "    .write = my_write,\n"
            "    .llseek = no_llseek,\n"
            "};\n"
        )
        regs = extract_ops_registrations(src, "drivers/misc/foo.c")
        funcs = {r["function"] for r in regs}
        assert len(funcs) == 5
        assert "my_open" in funcs
        assert "no_llseek" in funcs

    def test_null_assignments_skipped(self):
        src = (
            "static struct proto_ops my_ops = {\n"
            "    .connect = my_connect,\n"
            "    .accept = NULL,\n"
            "    .sendmsg = my_sendmsg,\n"
            "};\n"
        )
        regs = extract_ops_registrations(src, "net/foo.c")
        funcs = {r["function"] for r in regs}
        assert "my_connect" in funcs
        assert "my_sendmsg" in funcs
        assert "NULL" not in funcs

    def test_constant_macros_skipped(self):
        src = (
            "static struct foo_ops ops = {\n"
            "    .flags = MY_FLAGS_CONSTANT,\n"
            "    .handler = real_handler,\n"
            "};\n"
        )
        regs = extract_ops_registrations(src, "test.c")
        funcs = {r["function"] for r in regs}
        assert "real_handler" in funcs
        assert "MY_FLAGS_CONSTANT" not in funcs

    def test_no_struct_init(self):
        src = (
            "void foo(void) {\n"
            "    bar();\n"
            "}\n"
        )
        regs = extract_ops_registrations(src, "test.c")
        assert regs == []

    def test_nested_braces_skipped(self):
        src = (
            "static struct ops my_ops = {\n"
            "    .handler = my_handler,\n"
            "    .config = {\n"
            "        .timeout = 30,\n"
            "        .retries = 3,\n"
            "    },\n"
            "    .cleanup = my_cleanup,\n"
            "};\n"
        )
        regs = extract_ops_registrations(src, "test.c")
        funcs = {r["function"] for r in regs}
        assert "my_handler" in funcs
        assert "my_cleanup" in funcs
        assert "30" not in funcs
        assert "3" not in funcs

    def test_multiple_structs(self):
        src = (
            "static struct a_ops ops_a = {\n"
            "    .run = run_a,\n"
            "};\n"
            "\n"
            "static struct b_ops ops_b = {\n"
            "    .run = run_b,\n"
            "};\n"
        )
        regs = extract_ops_registrations(src, "test.c")
        assert len(regs) == 2
        types = {r["struct_type"] for r in regs}
        assert types == {"a_ops", "b_ops"}


class TestCollectOpsEntryPoints:
    """Integration: scanning source texts."""

    def test_collects_from_c_files(self):
        sources = {
            "net/esp4.c": (
                "static struct xfrm_type t = {\n"
                "    .output = esp_output,\n"
                "};\n"
            ),
            "lib/util.py": "def foo(): pass\n",
        }
        eps = collect_ops_entry_points(sources)
        assert "net/esp4.c:esp_output" in eps
        assert len(eps) == 1

    def test_empty_sources(self):
        assert collect_ops_entry_points({}) == set()

    def test_h_files_included(self):
        sources = {
            "include/ops.h": (
                "static const struct ops o = {\n"
                "    .probe = my_probe,\n"
                "};\n"
            ),
        }
        eps = collect_ops_entry_points(sources)
        assert "include/ops.h:my_probe" in eps
