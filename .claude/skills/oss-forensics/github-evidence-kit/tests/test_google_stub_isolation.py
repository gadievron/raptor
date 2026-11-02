"""Missing BigQuery must not replace an installed Google auth module."""

import builtins
import sys
import types


def test_partial_google_install_preserves_real_parent_bindings(
    monkeypatch, google_module_stubber,
):
    names = (
        "google", "google.auth", "google.auth.exceptions", "google.oauth2",
        "google.oauth2.service_account", "google.cloud",
    )
    modules = {name: types.ModuleType(name) for name in names}
    for name, module in modules.items():
        module.__path__ = []
        monkeypatch.setitem(sys.modules, name, module)
        if "." in name:
            parent, attr = name.rsplit(".", 1)
            setattr(modules[parent], attr, module)
    monkeypatch.delitem(sys.modules, "google.cloud.bigquery", raising=False)
    real_import = builtins.__import__

    def without_bigquery(name, *args, **kwargs):
        if name == "google.cloud.bigquery":
            raise ImportError("BigQuery absent in partial SDK install")
        return real_import(name, *args, **kwargs)

    # Track the stubber's direct write too, even if the module was absent
    # initially, so this regression test cannot leak its own BigQuery stub.
    monkeypatch.setitem(sys.modules, "google.cloud.bigquery", None)
    monkeypatch.delitem(sys.modules, "google.cloud.bigquery")
    monkeypatch.setattr(builtins, "__import__", without_bigquery)
    google_module_stubber()

    for name in names:
        assert sys.modules[name] is modules[name]
        if "." in name:
            parent, attr = name.rsplit(".", 1)
            assert getattr(modules[parent], attr) is modules[name]
    assert modules["google.cloud"].bigquery is sys.modules["google.cloud.bigquery"]
