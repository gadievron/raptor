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


def test_pipe_tail_not_emitted_as_packages(tmp_path: Path) -> None:
    """Everything after an unquoted ``|`` is a separate command, not
    install arguments — ``tee`` and ``grep`` are REAL registry names,
    so the leak produced live SBOM rows and registry/OSV queries."""
    sh = tmp_path / "setup.sh"
    sh.write_text(
        "pip install requests==2.31.0 | tee build.log\n"
        "pip install flask 2>&1 | grep -v warning\n"
        "apt-get install nginx | tee -a apt.log\n",
        encoding="utf-8",
    )
    deps = parse_shell_script(sh)
    names = {d.name for d in deps}
    assert {"requests", "flask", "nginx"} <= names
    for phantom in ("tee", "grep", "warning", "build-log", "apt.log"):
        assert phantom not in names, names


def test_append_all_and_clobber_redirect_spellings_stripped(
    tmp_path: Path,
) -> None:
    """``&>>`` (append-all) and ``>|`` (noclobber override) are
    redirection operators; their target words must not surface as
    packages. Both leaked through the enumerated-spelling stripper."""
    sh = tmp_path / "setup.sh"
    sh.write_text(
        "pip install numpy &>> out.log\n"
        "pip install pandas >| capture.txt\n",
        encoding="utf-8",
    )
    deps = parse_shell_script(sh)
    names = {d.name for d in deps}
    assert names == {"numpy", "pandas"}, names


def test_quoted_pipe_and_comparators_stay_intact(tmp_path: Path) -> None:
    """Two-direction guard: an unquoted pipe splits, but the same
    characters INSIDE quotes are argument text — a quoted PEP 508
    range spec keeps its comparators and never loses its tail to the
    redirect stripper."""
    sh = tmp_path / "setup.sh"
    sh.write_text(
        "pip install 'requests>=2.0,<3.0'\n"
        'echo "a | b" && pip install uv==0.12.6\n',
        encoding="utf-8",
    )
    deps = parse_shell_script(sh)
    by = {d.name: d for d in deps}
    assert "requests" in by
    assert by["requests"].version_floor == "2.0"
    assert by["requests"].version_ceiling == "3.0"
    assert "uv" in by and by["uv"].version == "0.12.6"


def test_post_pipe_install_command_still_scanned(tmp_path: Path) -> None:
    """Splitting (rather than truncating) at the pipe keeps a genuine
    install on the pipeline's right-hand side visible."""
    sh = tmp_path / "setup.sh"
    sh.write_text(
        "curl -s https://example.invalid/reqs | pip install uv==0.12.6\n",
        encoding="utf-8",
    )
    deps = parse_shell_script(sh)
    by = {d.name: d for d in deps}
    assert "uv" in by and by["uv"].version == "0.12.6"


def test_devcontainer_array_form_command_extracted(tmp_path: Path) -> None:
    """The spec's primary lifecycle-command shape is an exec ARGV
    array — one command, not one command per element. Element-wise
    scanning never saw verb+args together, so every dep declared in
    array form was silently lost."""
    dc = tmp_path / "devcontainer.json"
    dc.write_text(
        '{"postCreateCommand": ["pip", "install", "requests==2.31.0"]}',
        encoding="utf-8",
    )
    deps = parse_devcontainer_json(dc)
    assert [(d.name, d.version) for d in deps] == [("requests", "2.31.0")]


def test_devcontainer_dict_of_arrays_extracted(tmp_path: Path) -> None:
    """The named-parallel-commands object form allows each value to be
    a string OR an argv array; array values join per-value."""
    dc = tmp_path / "devcontainer.json"
    dc.write_text(
        '{"postCreateCommand": {'
        '  "py": ["pip", "install", "flask==3.0.3"],'
        '  "js": "npm install lodash@4.17.21"'
        "}}",
        encoding="utf-8",
    )
    deps = parse_devcontainer_json(dc)
    got = {(d.name, d.version) for d in deps}
    assert ("flask", "3.0.3") in got
    assert ("lodash", "4.17.21") in got
