"""Shell quoting requires a separately verified argument context."""
import json
import shlex

import pytest

from core.dataflow import tier1_llm as t1, smt_barrier as sb


@pytest.mark.parametrize("prefix,suffix", [('printf "%s" ', "\n"), ('printf "%s" "', '"\n'), ("printf '%s' '", "'\n")], ids=("token", "double-quoted", "single-quoted"))
def test_quoted_shell_script_context(tmp_path, prefix, suffix):
    line = '    safe = shlex.quote(raw)'
    source = ('import shlex, subprocess\ndef handle(raw):\n'
              '    proc = subprocess.Popen(["/bin/sh"], stdin=subprocess.PIPE, text=True)\n'
              '    proc.stdin.write(' + repr(prefix) + ')\n'
              '    if type(raw) is not str: return\n' + line + '\n'
              '    proc.stdin.write(safe)\n    proc.stdin.write(' + repr(suffix) + ')\n')
    compile(source, 'owned-shell-stream.py', 'exec')
    # Only stdlib quote executes; the source shell process is never launched.
    payload = '$(printf owned_marker)'
    quoted = shlex.quote(payload)
    assert quoted == "'$(printf owned_marker)'"
    assert payload in prefix + quoted + suffix
    (tmp_path/'app.py').write_bytes(source.encode())
    reply=json.dumps({'kind':'known_safe_call','validator_source_line':line,'variable_name':'raw',
                      'charset':'','forbidden':'','library_call':'shlex.quote'})
    result=t1.try_tier1b(fix_diff='+'+line+'\n',repo_root=tmp_path,sink_uri='app.py',sink_line=7,
                       sink_class='cmdi',language='python',complete=lambda *_:reply)
    assert result.status is sb.Tier0Status.NOT_APPLICABLE
    assert result.artifact is None
    assert result.extras["unverified_source_contracts"] == ["posix_shell_argument_sink_context"]


def test_shell_argument_requirement_keeps_argv_and_language_scope():
    from core.dataflow import known_safe_calls as ksc
    from core.dataflow.sanitizer_catalog import source_contracts_for_callable

    assert source_contracts_for_callable("shlex.quote", "CWE-78", "python") == frozenset({
        ksc.EXACT_STR_DEFAULT_CALL, ksc.POSIX_SHELL_ARGUMENT_CONTEXT,
    })
    assert source_contracts_for_callable("shlex.quote", "CWE-88", "python") == frozenset()
    assert source_contracts_for_callable("shlex.quote", "CWE-78", "java") == frozenset()
