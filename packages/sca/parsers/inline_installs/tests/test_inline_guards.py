"""Guards for inline-install extraction surfaced by the calibration run:

  * GHA ``${{ ... }}`` template expressions must not become phantom
    packages (``npm i ${{ matrix.npm-i }}`` produced a bogus
    "matrix.npm-i" dep that 404'd).
  * devcontainer.json is JSONC; the comment stripper must not eat ``//``
    inside string values (a ``https://`` URL would corrupt the JSON and
    the whole file failed to parse).
"""

from __future__ import annotations

from pathlib import Path

from packages.sca.parsers.inline_installs import (
    parse_devcontainer_json,
    parse_gha_workflow,
    parse_shell_script,
)


def test_gha_expression_not_emitted_as_package(tmp_path: Path) -> None:
    wf = tmp_path / "ci.yml"
    wf.write_text(
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - run: npm i ${{ matrix.npm-i }} lodash@4.17.21\n",
        encoding="utf-8",
    )
    deps = parse_gha_workflow(wf)
    names = {d.name for d in deps}
    # The real package is extracted...
    assert "lodash" in names
    # ...but the GHA template expression is not a phantom package.
    assert not any("matrix" in n for n in names)


def test_devcontainer_jsonc_url_not_mangled(tmp_path: Path) -> None:
    dc = tmp_path / "devcontainer.json"
    dc.write_text(
        "{\n"
        "  // base devcontainer\n"
        '  "image": "ubuntu:22.04",\n'
        '  "postCreateCommand": "pip install requests==2.31.0",\n'
        '  "metadata": {"repo": "https://github.com/owner/repo"},\n'
        "}\n",
        encoding="utf-8",
    )
    # Old stripper ate the ``//`` in the URL → JSONDecodeError → no deps.
    deps = parse_devcontainer_json(dc)
    by = {d.name: d for d in deps}
    assert "requests" in by
    assert by["requests"].version == "2.31.0"


def test_shell_redirect_not_emitted_as_package(tmp_path: Path) -> None:
    """``2>&1`` and ``>> file`` are shell redirects, not package names.

    Without the redirect filter ``2>&1`` looks like package "2" with
    a ``>`` PEP 508 comparator, producing spurious ``PyPI:2@`` findings.
    """
    sh = tmp_path / "setup.sh"
    sh.write_text(
        "#!/bin/bash\n"
        'pip install --no-cache-dir uv==0.12.6 >> "$LOG" 2>&1\n'
        "pip install requests > /dev/null\n"
        "pip install flask 2>/dev/null\n"
        "pip install numpy &> /tmp/out.log\n",
        encoding="utf-8",
    )
    deps = parse_shell_script(sh)
    names = {d.name for d in deps}
    assert names == {"uv", "requests", "flask", "numpy"}
