"""Structural regression pin for run_sca's stage nesting.

The firmware ELF stage (1d) was once inserted mid-body of the
Dockerfile-FROM stage (1c), silently re-parenting the image-drift
substage (and its ``else``) under ``if options.firmware_root`` —
non-firmware runs lost drift detection entirely and firmware runs
NameError'd on ``oci_client``. The wiring is invisible to functional
tests without live registry mocks, so this pins the AST shape: drift
belongs to 1c, and the firmware stage must not contain it.
"""

from __future__ import annotations

import ast
from pathlib import Path

_PIPELINE = Path(__file__).parent.parent / "pipeline.py"


def _run_sca_ifs():
    tree = ast.parse(_PIPELINE.read_text())
    run_sca = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "run_sca"
    )
    return [node for node in ast.walk(run_sca) if isinstance(node, ast.If)]


def _if_testing(ifs, needle: str):
    return [n for n in ifs if needle in ast.unparse(n.test)]


def test_image_drift_nested_in_dockerfile_stage_not_firmware():
    ifs = _run_sca_ifs()
    dockerfile_if = _if_testing(ifs, "enable_dockerfile_from")[0]
    firmware_if = _if_testing(ifs, "firmware_root is not None")[0]

    def contains_drift(node) -> bool:
        return any(
            isinstance(sub, ast.If)
            and "enable_image_drift" in ast.unparse(sub.test)
            for sub in ast.walk(node)
        )

    assert contains_drift(dockerfile_if), (
        "image-drift substage must live inside the Dockerfile-FROM stage"
    )
    assert not contains_drift(firmware_if), (
        "firmware ELF stage must not contain the image-drift substage "
        "(re-parenting regression)"
    )
    # Drift's offline fallback (`else: image_drift_findings = []`)
    # belongs to the dockerfile stage too.
    assert dockerfile_if.orelse, (
        "Dockerfile-FROM stage lost its else branch (drift fallback)"
    )
