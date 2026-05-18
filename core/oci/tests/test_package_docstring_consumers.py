"""Regression test for `core.oci` package docstring consumer claims.

F057: the package docstring at `core/oci/__init__.py` claimed five
``packages/*`` consumers wired up to `core.oci` (sca, cve_diff,
llm_analysis, oss_forensics, code_understanding). Reality:

  * `packages/oss_forensics` does not exist in the tree.
  * None of the four real `packages/*` directories import any module
    under `core.oci`.

The substrate is shipped + tested but not yet wired into any consumer.
The docstring was aspirational and read as a misleading claim of
existing integrations.

The test below enforces docstring-vs-reality consistency in both
directions:

  1. Every `packages/<name>` mentioned in the consumer list of the
     `core/oci/__init__.py` docstring must exist as a directory.
  2. Every `packages/<name>` listed as a consumer must actually import
     something under `core.oci.*`, OR be flagged as planned/aspirational
     under an explicit "Planned consumers" subheading.

The current convention is to keep the consumer list empty until a real
import lands, with a "Planned consumers" subsection documenting intent.
"""

from __future__ import annotations

import ast
import pathlib
import re
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
OCI_INIT = REPO_ROOT / "core" / "oci" / "__init__.py"


def _imports_core_oci(py_file: pathlib.Path) -> bool:
    """Return True if `py_file` imports any `core.oci` submodule."""
    try:
        source = py_file.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    try:
        tree = ast.parse(source, filename=str(py_file))
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and (
                node.module == "core.oci"
                or node.module.startswith("core.oci.")
            ):
                return True
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "core.oci" or alias.name.startswith("core.oci."):
                    return True
    return False


def _read_package_docstring() -> str:
    tree = ast.parse(OCI_INIT.read_text(encoding="utf-8"))
    docstring = ast.get_docstring(tree)
    assert docstring is not None, "core/oci/__init__.py missing module docstring"
    return docstring


def _extract_active_consumers(docstring: str) -> list[str]:
    """Find `packages/<name>` mentions in the *active* consumer list.

    A "Planned consumers" subheading separates aspirational from active.
    Anything BEFORE that heading is treated as a present-tense claim.
    """
    active_section = docstring.split("Planned consumers")[0]
    return sorted(set(re.findall(r"packages/([a-z_]+)", active_section)))


class OciDocstringConsumerConsistencyTest(unittest.TestCase):

    def test_no_active_consumers_claimed_without_a_real_import(self) -> None:
        """F057: docstring active-consumer claims must match real imports."""
        docstring = _read_package_docstring()
        claimed = _extract_active_consumers(docstring)

        unwired: list[str] = []
        missing_dirs: list[str] = []
        for name in claimed:
            pkg_dir = REPO_ROOT / "packages" / name
            if not pkg_dir.is_dir():
                missing_dirs.append(name)
                continue
            has_import = any(
                _imports_core_oci(f) for f in pkg_dir.rglob("*.py")
            )
            if not has_import:
                unwired.append(name)

        self.assertEqual(
            missing_dirs,
            [],
            "core/oci docstring claims consumers that do not exist as "
            f"`packages/` directories: {missing_dirs}. Move under a "
            "'Planned consumers:' subheading or remove.",
        )
        self.assertEqual(
            unwired,
            [],
            "core/oci docstring lists active consumers that don't import "
            f"`core.oci.*`: {unwired}. Move under 'Planned consumers:' or "
            "remove until the import lands.",
        )


if __name__ == "__main__":
    unittest.main()
