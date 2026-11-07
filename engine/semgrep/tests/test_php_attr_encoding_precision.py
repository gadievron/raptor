"""Quote-bit checks must bind the encoder to its actual HTML attribute context."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

_RULE = Path(__file__).resolve().parents[1] / 'rules/php/attr-encoding.yaml'
pytestmark = [pytest.mark.slow, pytest.mark.skipif(
    shutil.which('semgrep') is None, reason='semgrep not installed')]


def _location(text, offset):
    return text.count('\n', 0, offset) + 1, offset - text.rfind('\n', 0, offset)


def test_quote_bits_context_and_encoded_concat_scaling(tmp_path):
    flags = [(str(n), n) for n in (*range(16), 48, 49, 50, 51, 128, 129, 130, 131,
                                 255, 256, 257, 258, 259)]
    flags += [
        ('ENT_COMPAT', 2), ('ENT_QUOTES', 3), ('ENT_NOQUOTES', 0),
        ('ENT_IGNORE', 4), ('ENT_SUBSTITUTE', 8), ('ENT_DISALLOWED', 128),
        ('ENT_HTML401', 0), ('ENT_XML1', 16), ('ENT_XHTML', 32), ('ENT_HTML5', 48),
        ('ENT_QUOTES | ENT_HTML5', 51), ('ENT_COMPAT | ENT_SUBSTITUTE', 10),
        ('ENT_NOQUOTES | ENT_HTML5', 48), ('ENT_HTML5 | ENT_SUBSTITUTE', 56),
        ('ENT_COMPAT | ENT_NOQUOTES', 2), ('ENT_QUOTES | ENT_NOQUOTES', 3),
        (r'\ENT_COMPAT | \ENT_HTML5', 50),
    ]
    suffixes = {1: 'single-quote-attr', 2: 'noquotes-double-attr'}
    expected = set()
    targets = []
    lines = ['<?php']
    for reader in ('htmlspecialchars', r'\htmlspecialchars', 'htmlentities', r'\HTMLENTITIES'):
        for bit, opener, closer in (
            (1, '"<a title=\'"', '"\'>x</a>"'),
            (2, "'<a title=\"'", "'\">x</a>'"),
        ):
            for expression, value in flags:
                lines.append(f'function case_{len(lines)}($value) {{')
                statement = f'  echo {opener} . {reader}($value, {expression}) . {closer};'
                lines.append(statement)
                if not value & bit:
                    expected.add(('flags.php', len(lines), statement.index(reader) + 1,
                                  suffixes[bit]))
                lines.append('}')
    target = tmp_path / 'flags.php'
    target.write_text('\n'.join(lines) + '\n')
    targets.append(target)
    controls = r'''<?php
function controls($value, $obj, $flags) {
 echo "setting='" . htmlspecialchars($value, ENT_COMPAT);
 echo '<p>' . htmlentities($value, ENT_NOQUOTES) . '</p>';
 echo "<a title='fixed'>" . htmlspecialchars($value, ENT_COMPAT);
 echo '<a title="fixed">' . htmlentities($value, ENT_NOQUOTES);
 echo "<a title='" . htmlspecialchars($value, ENT_QUOTES) . "'>";
 echo "<a title='" . htmlspecialchars($value) . "'>";
 echo "<a title='" . $obj->htmlspecialchars($value, ENT_COMPAT) . "'>";
 echo "<a title='" . htmlspecialchars($value, ENT_UNKNOWN) . "'>";
 echo "<a title='" . htmlspecialchars($value, $flags) . "'>";
 // One call must not borrow a different call's literal or flags.
 echo "<a title='" . htmlspecialchars($value, ENT_QUOTES) . "'>"; echo "setting='" . htmlentities($value, ENT_COMPAT);
 echo "<a title='" . htmlspecialchars(htmlentities($value, ENT_COMPAT), ENT_QUOTES) . "'>";
}
'''
    target = tmp_path / 'controls.php'
    target.write_text(controls)
    targets.append(target)
    escaped = r'''<?php
function escaped_prefix($value) {
 echo "<a href=\"/fixed\" title='prefix-" . \htmlspecialchars($value, ENT_COMPAT) . "'>";
 echo '<a data-x=\'fixed\' title="prefix-' . htmlentities($value, ENT_NOQUOTES) . '">';
}
'''
    target = tmp_path / 'escaped.php'
    target.write_text(escaped)
    targets.append(target)
    for reader, bit in ((r'\htmlspecialchars', 1), ('htmlentities', 2)):
        expected.add((target.name, *_location(escaped, escaped.index(reader + '(')), suffixes[bit]))
    # Both long-encoding chains and long rejected literal prefixes must finish
    # without Semgrep dropping a rule at its normal per-file timeout.
    segment = '"<a title=\'" . htmlspecialchars($value, ENT_COMPAT) . "\'>"'
    chain = '<?php\nfunction chain($value) {\n echo ' + ' . '.join([segment] * 120) + ';\n}\n'
    target = tmp_path / 'chain.php'
    target.write_text(chain)
    targets.append(target)
    start = 0
    while (start := chain.find('htmlspecialchars(', start)) >= 0:
        line, column = _location(chain, start)
        expected.add((target.name, line, column, suffixes[1]))
        start += 1
    assert sum(row[0] == target.name for row in expected) == 120
    extra = ('<?php\nfunction spacing($value) {\n echo "<a title = \'prefix-"'
             + ' ' * 16000 + '.\n' + ' ' * 16000
             + '\\htmlentities($value, ENT_SUBSTITUTE) . "\'>";\n}\n')
    target = tmp_path / 'spacing.php'
    target.write_text(extra)
    targets.append(target)
    expected.add((target.name, *_location(extra, extra.index('\\htmlentities(')), suffixes[1]))
    target = tmp_path / 'rejected.php'
    target.write_text('<?php\nfunction rejected($value) {\n echo "' + '<a ' * 5000
                      + '" . htmlspecialchars($value, ENT_COMPAT);\n}\n')
    targets.append(target)
    for args in (['git', 'init', '-q'], ['git', 'add', '--', *[p.name for p in targets]]):
        subprocess.run(args, cwd=tmp_path, check=True, capture_output=True, timeout=20)
    result = subprocess.run(
        ['semgrep', 'scan', '--config', str(_RULE), '--metrics', 'off',
         '--disable-version-check', '--jobs', '1', '--json', *map(str, targets)],
        cwd=tmp_path, capture_output=True, text=True, timeout=180, check=False,
        env={**os.environ, 'SEMGREP_SETTINGS_FILE': str(tmp_path / 'settings.yml'),
             'SEMGREP_LOG_FILE': str(tmp_path / 'semgrep.log')},
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert not data.get('errors'), data.get('errors')
    assert {Path(p).name for p in data['paths']['scanned']} == {p.name for p in targets}
    actual = set()
    for row in data['results']:
        suffix = next((suffix for suffix in suffixes.values()
                       if row['check_id'].endswith('raptor.php.attr-encoding.' + suffix)), None)
        assert suffix is not None, row['check_id']
        actual.add((Path(row['path']).name, row['start']['line'], row['start']['col'], suffix))
    assert actual == expected, {'missing': sorted(expected - actual),
                                'unexpected': sorted(actual - expected)}
