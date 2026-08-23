"""packages.cve_env — namespace anchor.

Runtime imports use the bare ``cve_env`` package (pytest.ini pythonpath
/ the libexec shim's sys.path entry); this file exists so pytest's
importlib mode resolves the test tree as ``packages.cve_env.tests``
instead of the bare ``tests`` — which collided with cve_diff's
identically-rooted test package when both are collected in one run.
"""
