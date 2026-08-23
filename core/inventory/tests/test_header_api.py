"""Tests for core.inventory.header_api — public API detection from C/C++ headers."""

from pathlib import Path

from core.inventory.header_api import scan_public_api


def _write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


class TestScanPublicApi:

    def test_standard_declaration(self, tmp_path: Path):
        _write(tmp_path / "api.h",
               "int process(char *buf, size_t len);\n"
               "void cleanup(void);\n")
        api = scan_public_api(str(tmp_path))
        assert "process" in api
        assert "cleanup" in api

    def test_ignores_definitions(self, tmp_path: Path):
        _write(tmp_path / "impl.h",
               "static int helper(int x) { return x + 1; }\n")
        api = scan_public_api(str(tmp_path))
        assert "helper" not in api

    def test_macro_qualified_declaration(self, tmp_path: Path):
        _write(tmp_path / "xml.h",
               "XMLPUBFUN xmlIDPtr xmlAddID(xmlValidCtxtPtr ctxt, xmlDocPtr doc);\n"
               "XMLPUBFUN xmlRefPtr xmlAddRef(xmlValidCtxtPtr ctxt, xmlDocPtr doc);\n")
        api = scan_public_api(str(tmp_path))
        assert "xmlAddID" in api
        assert "xmlAddRef" in api

    def test_of_macro_declaration(self, tmp_path: Path):
        _write(tmp_path / "zlib.h",
               "ZEXTERN int ZEXPORT inflate OF((z_streamp strm, int flush));\n"
               "ZEXTERN int ZEXPORT deflateEnd OF((z_streamp strm));\n")
        api = scan_public_api(str(tmp_path))
        assert "inflate" in api
        assert "deflateEnd" in api

    def test_export_macro_declaration(self, tmp_path: Path):
        _write(tmp_path / "png.h",
               "PNG_EXPORT(1, png_uint_32, png_access_version_number, (void));\n"
               "PNG_EXPORT(2, void, png_set_sig_bytes, (png_structrp png_ptr, int n));\n")
        api = scan_public_api(str(tmp_path))
        assert "png_access_version_number" in api
        assert "png_set_sig_bytes" in api

    def test_declspec_declaration(self, tmp_path: Path):
        _write(tmp_path / "win_api.h",
               "__declspec(dllexport) int win_func(int x);\n")
        api = scan_public_api(str(tmp_path))
        assert "win_func" in api

    def test_extern_declaration(self, tmp_path: Path):
        _write(tmp_path / "lib.h",
               "extern int public_fn(void);\n"
               "extern void another(int x, int y);\n")
        api = scan_public_api(str(tmp_path))
        assert "public_fn" in api
        assert "another" in api

    def test_skips_keywords(self, tmp_path: Path):
        _write(tmp_path / "control.h",
               "int if(int x);\n"
               "void return(void);\n"
               "int real_func(void);\n")
        api = scan_public_api(str(tmp_path))
        assert "if" not in api
        assert "return" not in api
        assert "real_func" in api

    def test_skips_underscore_prefixed(self, tmp_path: Path):
        _write(tmp_path / "internal.h",
               "int _private_impl(void);\n"
               "int public_fn(void);\n")
        api = scan_public_api(str(tmp_path))
        assert "_private_impl" not in api
        assert "public_fn" in api

    def test_skips_excluded_dirs(self, tmp_path: Path):
        _write(tmp_path / "include" / "pub.h",
               "int public_fn(void);\n")
        _write(tmp_path / "test" / "test.h",
               "int test_helper(void);\n")
        _write(tmp_path / "internal" / "priv.h",
               "int internal_fn(void);\n")
        api = scan_public_api(str(tmp_path))
        assert "public_fn" in api
        assert "test_helper" not in api
        assert "internal_fn" not in api

    def test_empty_dir(self, tmp_path: Path):
        api = scan_public_api(str(tmp_path))
        assert api == frozenset()

    def test_no_headers(self, tmp_path: Path):
        _write(tmp_path / "main.c", "int main() { return 0; }\n")
        api = scan_public_api(str(tmp_path))
        assert api == frozenset()

    def test_nonexistent_path(self):
        api = scan_public_api("/nonexistent/path")
        assert api == frozenset()

    def test_returns_frozenset(self, tmp_path: Path):
        _write(tmp_path / "api.h", "int f(void);\n")
        api = scan_public_api(str(tmp_path))
        assert isinstance(api, frozenset)

    def test_hpp_extension(self, tmp_path: Path):
        _write(tmp_path / "api.hpp",
               "int cpp_func(int x);\n")
        api = scan_public_api(str(tmp_path))
        assert "cpp_func" in api

    def test_include_dirs_filter(self, tmp_path: Path):
        _write(tmp_path / "include" / "pub.h",
               "int public_fn(void);\n")
        _write(tmp_path / "src" / "impl.h",
               "int impl_fn(void);\n")
        api = scan_public_api(str(tmp_path), include_dirs=["include"])
        assert "public_fn" in api
        assert "impl_fn" not in api


class TestReachabilityIntegration:

    def test_header_api_narrows_entry_points(self):
        from core.analysis.reachability import _item_is_entry

        public = frozenset({"xmlAddID", "xmlAddRef"})

        public_item = {"name": "xmlAddID", "kind": "function",
                        "metadata": {"visibility": None}}
        internal_item = {"name": "xmlFreeRef", "kind": "function",
                         "metadata": {"visibility": None}}
        static_item = {"name": "helper", "kind": "function",
                       "metadata": {"visibility": "static"}}

        assert _item_is_entry(public_item, "c", header_api=public)
        assert not _item_is_entry(internal_item, "c", header_api=public)
        assert not _item_is_entry(static_item, "c", header_api=public)

    def test_without_header_api_falls_back_to_non_static(self):
        from core.analysis.reachability import _item_is_entry

        non_static = {"name": "xmlFreeRef", "kind": "function",
                      "metadata": {"visibility": None}}
        static = {"name": "helper", "kind": "function",
                  "metadata": {"visibility": "static"}}

        assert _item_is_entry(non_static, "c", header_api=None)
        assert not _item_is_entry(static, "c", header_api=None)
